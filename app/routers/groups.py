"""
Group management API endpoints.
Implements group endpoints as specified in SPEC.md Section 3.2.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.services.cerbos import CerbosService
from app.services.group import GroupService
from app.services.user import UserService

router = APIRouter()


# Pydantic models for request/response
class GroupCreateRequest(BaseModel):
    """Request model for creating a new group."""

    name: str = Field(
        ...,
        description="Unique name for the group (lowercase letters, numbers, underscores, and colons only)",
        example="engineering_team:backend",
        min_length=1,
        max_length=100,
        pattern="^[a-z0-9_:]+$"
    )
    description: str = Field(
        ...,
        description="Human-readable description of the group's purpose",
        example="Engineering team with access to development resources",
        min_length=1,
        max_length=500
    )

    class Config:
        json_schema_extra = {
            "example": {
                "name": "engineering_team:backend",
                "description": "Engineering team with access to development resources"
            }
        }


class GroupResponse(BaseModel):
    """Response model for group information."""

    id: int = Field(
        ...,
        description="Unique identifier for the group",
        example=1
    )
    name: str = Field(
        ...,
        description="Group name",
        example="engineering_team:backend"
    )
    description: str = Field(
        ...,
        description="Group description",
        example="Engineering team with access to development resources"
    )
    created_by: str | None = Field(
        None,
        description="CPF of the user who created this group",
        example="12345678901"
    )
    created_at: str = Field(
        ...,
        description="ISO timestamp when the group was created",
        example="2024-01-15T10:30:00Z"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "name": "engineering_team:backend",
                "description": "Engineering team with access to development resources",
                "created_by": "12345678901",
                "created_at": "2024-01-15T10:30:00Z"
            }
        }


@router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=GroupResponse,
    summary="Create a new group",
    description="""
Create a new group in the system.

**Authorization Required**: Users must have permission to create groups via Cerbos policies.

**Notes**:
- Group names must be unique across the system
- Names can only contain alphanumeric characters, hyphens, and underscores
- The creating user becomes the group owner
- Group creation is audited and logged

**Common Use Cases**:
- Creating departmental groups (e.g., "engineering", "marketing")
- Setting up project teams with specific access requirements
- Organizing users by geographical location or business unit
    """,
    responses={
        201: {
            "description": "Group created successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": 1,
                        "name": "engineering_team:backend",
                        "description": "Engineering team with access to development resources",
                        "created_by": "12345678901",
                        "created_at": "2024-01-15T10:30:00Z"
                    }
                }
            }
        },
        400: {
            "description": "Bad request - Invalid input data",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Group name contains invalid characters"
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
        403: {
            "description": "Forbidden - Insufficient permissions to create groups",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to create group 'engineering_team:backend'"
                    }
                }
            }
        },
        409: {
            "description": "Conflict - Group with this name already exists",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Group with name 'engineering_team:backend' already exists"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An unexpected error occurred while creating the group"
                    }
                }
            }
        }
    }
)
async def create_group(
    group_data: GroupCreateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    group_service: Annotated[GroupService, Depends(lambda: GroupService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    # Get caller's roles for Cerbos permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to create this group using Cerbos
    can_create = cerbos_service.can_create_group(
        caller_subject=current_user.subject,
        caller_roles=caller_roles,
        group_name=group_data.name,
    )

    if not can_create:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied to create group '{group_data.name}'",
        )

    # Create the group
    try:
        group = group_service.create_group(
            db=db,
            name=group_data.name,
            description=group_data.description,
            created_by=current_user,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    # Invalidate policy version to trigger near real-time sync
    from app.services.policy_invalidator import invalidate_policy_version
    invalidate_policy_version(db)

    return GroupResponse(
        id=group.id,
        name=group.name,
        description=group.description,
        created_by=group.creator.subject if group.creator else None,
        created_at=group.created_at.isoformat(),
    )


@router.get(
    "/",
    response_model=list[GroupResponse],
    summary="List all groups",
    description="""
List all groups in the system with optional filtering.

**Filtering**: Use the `prefix` query parameter to filter groups by name prefix.

**Authorization**: All authenticated users can list groups.

**Performance**: Results are cached for optimal performance. Large result sets
may be paginated in future versions.

**Use Cases**:
- Display all available groups in admin interfaces
- Search for specific groups by name prefix
- Export group information for reporting
    """,
    responses={
        200: {
            "description": "List of groups retrieved successfully",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "id": 1,
                            "name": "engineering_team:backend",
                            "description": "Engineering team with access to development resources",
                            "created_by": "12345678901",
                            "created_at": "2024-01-15T10:30:00Z"
                        },
                        {
                            "id": 2,
                            "name": "marketing_team:frontend",
                            "description": "Marketing team for campaign management",
                            "created_by": "98765432109",
                            "created_at": "2024-01-16T14:20:00Z"
                        }
                    ]
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
                        "detail": "An unexpected error occurred while retrieving groups"
                    }
                }
            }
        }
    }
)
async def list_groups(
    prefix: Annotated[
        str | None,
        Query(
            description="Filter groups by name prefix (case-insensitive)",
            example="eng"
        )
    ] = None,
    _current_user: Annotated[User, Depends(get_current_user)] = None,
    db: Annotated[Session, Depends(get_db)] = None,
    group_service: Annotated[GroupService, Depends(lambda: GroupService())] = None,
):
    groups = group_service.list_groups(db=db, prefix=prefix)

    return [
        GroupResponse(
            id=group.id,
            name=group.name,
            description=group.description,
            created_by=group.creator.subject if group.creator else None,
            created_at=group.created_at.isoformat(),
        )
        for group in groups
    ]


@router.delete(
    "/{group_name}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a group",
    description="""
Delete a group from the system with cascading cleanup.

**Authorization**: Users can delete groups they have permission to manage.
Permissions are checked via Cerbos policies.

**Cascade Effects**:
- Removes all group members
- Removes all role assignments from the group
- Updates Cerbos policies to reflect the group deletion

**Use Cases**:
- Remove obsolete or unused groups
- Administrative group cleanup
- System reorganization

**Safety**: Group deletion is irreversible. Ensure the group is no longer needed before deletion.
    """,
    responses={
        204: {
            "description": "Group deleted successfully"
        },
        401: {
            "description": "Unauthorized - Invalid or missing JWT token",
            "content": {
                "application/json": {
                    "example": {
                        "error": "Invalid authentication credentials",
                        "status_code": 401
                    }
                }
            }
        },
        403: {
            "description": "Forbidden - Insufficient permissions to delete group",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to delete group 'engineering_team'"
                    }
                }
            }
        },
        404: {
            "description": "Group not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Group 'unknown-group' not found"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to delete group: Database transaction error"
                    }
                }
            }
        }
    }
)
async def delete_group(
    group_name: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    group_service: Annotated[GroupService, Depends(lambda: GroupService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    """
    Delete a group with cascading cleanup.
    Implements DELETE /groups/{groupName} as specified in SPEC.md Section 3.2.
    """
    # Get caller's roles for Cerbos permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to delete this group using Cerbos
    can_delete = cerbos_service.can_delete_group(
        caller_subject=current_user.subject,
        caller_roles=caller_roles,
        group_name=group_name,
    )

    if not can_delete:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied to delete group '{group_name}'",
        )

    # Delete the group with cascading cleanup
    deleted = group_service.delete_group(
        db=db, group_name=group_name, deleted_by=current_user
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Group '{group_name}' not found",
        )

    # Invalidate policy version to trigger near real-time sync
    from app.services.policy_invalidator import invalidate_policy_version
    invalidate_policy_version(db)
