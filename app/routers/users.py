"""
User management API endpoints.
Implements user endpoints as specified in SPEC.md Section 3.1.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.services.user import UserService

router = APIRouter()


# Pydantic models for request/response
class UserResponse(BaseModel):
    """Response model for user information."""

    id: int = Field(
        ...,
        description="Unique identifier for the user",
        example=1
    )
    cpf: str = Field(
        ...,
        description="User's CPF (Cadastro de Pessoa Física) - Brazilian tax ID",
        example="12345678901",
        pattern="^[0-9]{11}$"
    )
    display_name: str | None = Field(
        None,
        description="User's display name from JWT token (name, given_name, or email)",
        example="João Silva"
    )
    groups: list[str] = Field(
        default_factory=list,
        description="List of groups the user belongs to",
        example=["engineering_team:backend", "data_analysts:read"]
    )
    roles: list[str] = Field(
        default_factory=list,
        description="List of roles assigned to the user (both direct and through groups)",
        example=["superadmin", "data-analyst"]
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "cpf": "12345678901",
                "display_name": "João Silva",
                "groups": ["engineering_team:backend", "data_analysts:read"],
                "roles": ["superadmin", "data-analyst"]
            }
        }


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user information",
    description="""
Retrieve detailed information about the currently authenticated user based on their JWT token.

**Authentication**: Uses the JWT token to automatically identify the user by their CPF
from the `preferred_username` field in the Keycloak token.

**Auto-Retrieval**: No need to specify the CPF - it's automatically extracted from the JWT token.

**Auto-Creation**: If the user doesn't exist in the system, they are automatically created
during the authentication process.

**Role Aggregation**: The response includes both direct roles assigned to the user and
roles inherited through group memberships.

**Use Cases**:
- User profile display in self-service applications
- Current user context for frontend applications
- Session management and user state tracking
- Self-service user information retrieval
- Profile settings and preferences display

**Security**: Only returns information about the authenticated user - no access to other users' data.
    """,
    responses={
        200: {
            "description": "Current user information retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": 1,
                        "cpf": "12345678901",
                        "display_name": "João Silva",
                        "groups": ["engineering_team:backend", "data_analysts:read"],
                        "roles": ["superadmin", "data_analyst:read"]
                    }
                }
            }
        },
        401: {
            "description": "Unauthorized - Invalid or missing JWT token",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Could not validate credentials"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to retrieve user information: Database connection error"
                    }
                }
            }
        }
    }
)
async def get_current_user_info(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
) -> UserResponse:
    """Get information about the currently authenticated user."""
    try:
        # Get user's groups and roles
        user_groups = user_service.get_user_groups(db, current_user)
        user_roles = user_service.get_user_roles(db, current_user)

        return UserResponse(
            id=current_user.id,
            cpf=current_user.subject,  # CPF is stored in the subject field
            display_name=current_user.display_name,
            groups=[group["name"] for group in user_groups],  # Extract group names
            roles=user_roles,
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve user information: {str(e)}"
        )


@router.get(
    "/{cpf}",
    response_model=UserResponse,
    summary="Get user by CPF",
    description="""
Retrieve detailed information about a user by their CPF (Brazilian tax ID).

**User Identification**: Users are identified by their CPF (Cadastro de Pessoa Física),
which is extracted from the `preferred_username` field in Keycloak JWT tokens.

**Authorization**: All authenticated users can retrieve user information.

**Auto-Creation**: Users are automatically created when they first authenticate with a valid JWT token.

**Role Aggregation**: The response includes both direct roles assigned to the user and
roles inherited through group memberships.

**Use Cases**:
- User profile display in applications
- Administrative user management
- Role and permission verification
- Group membership tracking
- Integration with external systems requiring user data
    """,
    responses={
        200: {
            "description": "User information retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": 1,
                        "cpf": "12345678901",
                        "display_name": "João Silva",
                        "groups": ["engineering_team:backend", "data_analysts:read"],
                        "roles": ["superadmin", "data-analyst"]
                    }
                }
            }
        },
        401: {
            "description": "Unauthorized - Invalid or missing JWT token",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Could not validate credentials"
                    }
                }
            }
        },
        404: {
            "description": "User not found - CPF does not exist in the system",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User with CPF '12345678901' not found"
                    }
                }
            }
        },
        422: {
            "description": "Validation error - Invalid CPF format",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Validation error",
                        "errors": [
                            {
                                "loc": ["path", "cpf"],
                                "msg": "string does not match regex",
                                "type": "value_error.regex"
                            }
                        ]
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An unexpected error occurred while retrieving user information"
                    }
                }
            }
        }
    }
)
async def get_user_by_cpf(
    cpf: str,
    _current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    # Get the requested user by CPF (preferred_username is stored as subject)
    user = user_service.get_user_by_subject(db, cpf)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with CPF '{cpf}' not found",
        )

    # Get user's roles and groups
    user_roles = user_service.get_user_roles(db, user)
    user_groups = user_service.get_user_groups(db, user)

    # Extract just the group names for the response
    group_names = [group["name"] for group in user_groups]

    return UserResponse(
        id=user.id,
        cpf=user.subject,  # subject contains the CPF (preferred_username)
        display_name=user.display_name,
        groups=group_names,
        roles=user_roles,
    )
