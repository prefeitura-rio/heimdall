"""
User management API endpoints.
Implements user endpoints as specified in SPEC.md Section 3.1.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.common.pagination import PaginatedResponse
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
    "/",
    response_model=PaginatedResponse[UserResponse],
    summary="List all users",
    description="""
Retrieve a paginated list of all users in the system.

**Pagination**: Uses `skip` and `limit` query parameters for pagination.
Default limit is 50 users per page, maximum is 100.

**Authentication**: Requires a valid JWT token.

**Role Aggregation**: Each user in the response includes both direct roles
and roles inherited through group memberships.

**Use Cases**:
- User management dashboards
- Administrative user listing
- User directory
- Bulk user operations
- Reporting and analytics

**Response Fields**:
- `items`: Array of user objects for the current page
- `total`: Total number of users in the system
- `skip`: Number of users skipped (offset)
- `limit`: Maximum number of users returned in this page
- `has_more`: Whether there are more users available
    """,
    responses={
        200: {
            "description": "Users retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "items": [
                            {
                                "id": 1,
                                "cpf": "12345678901",
                                "display_name": "João Silva",
                                "groups": ["engineering_team:backend"],
                                "roles": ["superadmin"]
                            },
                            {
                                "id": 2,
                                "cpf": "98765432109",
                                "display_name": "Maria Santos",
                                "groups": ["data_analysts:read"],
                                "roles": ["data-analyst"]
                            }
                        ],
                        "total": 150,
                        "skip": 0,
                        "limit": 50,
                        "has_more": True
                    }
                }
            }
        },
        401: {
            "description": "Unauthorized - Invalid or missing JWT token"
        },
        500: {
            "description": "Internal server error"
        }
    }
)
async def list_users(
    _current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of users to return"),
) -> PaginatedResponse[UserResponse]:
    """List all users with pagination."""
    try:
        # Get total count
        total = db.query(User).count()

        # Get paginated users
        users = db.query(User).offset(skip).limit(limit).all()

        # Build response items
        items = []
        for user in users:
            # Refresh user to get fresh data
            db.refresh(user)

            user_roles = user_service.get_user_roles(db, user)
            user_groups = user_service.get_user_groups(db, user)

            items.append(
                UserResponse(
                    id=user.id,
                    cpf=user.subject,
                    display_name=user.display_name,
                    groups=[group["name"] for group in user_groups],
                    roles=user_roles,
                )
            )

        return PaginatedResponse.create(
            items=items,
            total=total,
            skip=skip,
            limit=limit
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list users: {str(e)}"
        )


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
        # Refresh user from database to get fresh data
        db.refresh(current_user)

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

    # Refresh user from database to get absolutely fresh data
    # This is critical for preventing stale data after membership/role changes
    db.refresh(user)

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
