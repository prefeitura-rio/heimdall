"""
Membership management API endpoints.
Implements membership endpoints as specified in SPEC.md Section 3.3.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.services.membership import MembershipService
from app.services.user import UserService

router = APIRouter()


# Pydantic models for request/response
class AddMemberRequest(BaseModel):
    """Request model for adding a member to a group."""

    subject: str = Field(
        ...,
        description="User's CPF (Brazilian tax ID) to add to the group",
        example="12345678901",
        pattern="^[0-9]{11}$"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "subject": "12345678901"
            }
        }


class MembershipResponse(BaseModel):
    """Response model for membership operations."""

    status: str = Field(
        ...,
        description="Status of the membership operation",
        example="member_added"
    )
    group: str = Field(
        ...,
        description="Name of the group",
        example="engineering_team:backend"
    )
    subject: str = Field(
        ...,
        description="CPF of the user involved in the operation",
        example="12345678901"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "status": "member_added",
                "group": "engineering_team:backend",
                "subject": "12345678901"
            }
        }


class GroupMemberResponse(BaseModel):
    """Response model for a group member."""

    subject: str = Field(
        ...,
        description="User's CPF (Brazilian tax ID)",
        example="12345678901"
    )
    display_name: str | None = Field(
        None,
        description="User's display name if available",
        example="João Silva"
    )
    joined_at: str = Field(
        ...,
        description="ISO timestamp when the user joined the group",
        example="2024-01-15T10:30:00Z"
    )
    added_by: str | None = Field(
        None,
        description="CPF of the user who added this member",
        example="98765432109"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "subject": "12345678901",
                "display_name": "João Silva",
                "joined_at": "2024-01-15T10:30:00Z",
                "added_by": "98765432109"
            }
        }


@router.get(
    "/groups/{group_name}/members",
    response_model=list[GroupMemberResponse],
    summary="List group members",
    description="""
List all members of a specific group with their membership details.

**Authorization**: Users can view members of groups they have permission to access.
Permissions are checked via Cerbos policies.

**Member Information**: Returns each member's CPF, display name (if available),
join timestamp, and who added them to the group.

**Use Cases**:
- View team composition
- Audit group membership
- Administrative oversight
- Access control verification

**Sorting**: Members are returned sorted by join date (newest first).
    """,
    responses={
        200: {
            "description": "List of group members retrieved successfully",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "subject": "12345678901",
                            "display_name": "João Silva",
                            "joined_at": "2024-01-15T10:30:00Z",
                            "added_by": "98765432109"
                        },
                        {
                            "subject": "23456789012",
                            "display_name": "Maria Santos",
                            "joined_at": "2024-01-10T09:15:00Z",
                            "added_by": "98765432109"
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
        403: {
            "description": "Forbidden - Insufficient permissions to view group members",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to view members of group 'engineering_team:backend'"
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
                        "detail": "Failed to retrieve group members: Database connection error"
                    }
                }
            }
        }
    }
)
async def list_group_members(
    group_name: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    membership_service: Annotated[
        MembershipService, Depends(lambda: MembershipService())
    ],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
) -> list[GroupMemberResponse]:
    """List all members of a specific group."""
    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to view group members
    try:
        members = membership_service.list_group_members(
            db=db,
            group_name=group_name,
            caller_subject=current_user.subject,
            caller_roles=caller_roles,
        )

        # Convert to response model
        member_responses = []
        for membership in members:
            member_responses.append(
                GroupMemberResponse(
                    subject=membership.user.subject,
                    display_name=membership.user.display_name,
                    joined_at=membership.granted_at.isoformat(),
                    added_by=membership.granter.subject if membership.granter else None,
                )
            )

        return member_responses

    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PermissionError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied to view members of group '{group_name}'"
        )


@router.post(
    "/groups/{group_name}/members",
    response_model=MembershipResponse,
    summary="Add member to group",
    description="""
Add a user to a group with automatic user creation and authorization checks.

**Authorization**: Users can add members to groups they have permission to manage.
Permissions are checked via Cerbos policies.

**Auto-Creation**: If the user being added doesn't exist in the system, they will
be automatically created with their CPF as the identifier.

**Member Identification**: Users are identified by their CPF (Brazilian tax ID),
which serves as the unique subject identifier.

**Use Cases**:
- Add team members to project groups
- Grant users access to specific resources
- Administrative user management
- Bulk user provisioning workflows

**Role Inheritance**: Users automatically inherit all roles assigned to groups
they're members of.
    """,
    responses={
        200: {
            "description": "Member added to group successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "member_added",
                        "group": "engineering_team:backend",
                        "subject": "12345678901"
                    }
                }
            }
        },
        400: {
            "description": "Bad request - Invalid CPF format or user already in group",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User is already a member of this group"
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
            "description": "Forbidden - Insufficient permissions to add members to this group",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to add member to group 'engineering_team:backend'"
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
        422: {
            "description": "Validation error - Invalid CPF format",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Validation error",
                        "errors": [
                            {
                                "loc": ["body", "subject"],
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
                        "detail": "Failed to add member: Database connection error"
                    }
                }
            }
        }
    }
)
async def add_member_to_group(
    group_name: str,
    member_data: AddMemberRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    membership_service: Annotated[
        MembershipService, Depends(lambda: MembershipService())
    ],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Ensure target user exists (auto-create if needed)
    target_user = user_service.get_user_by_subject(db, member_data.subject)
    if not target_user:
        # Auto-create user if they don't exist
        target_user = User(subject=member_data.subject)
        db.add(target_user)
        db.commit()
        db.refresh(target_user)

    # Add member to group with complete flow
    try:
        success = membership_service.add_member_to_group(
            db=db,
            group_name=group_name,
            member_subject=member_data.subject,
            caller_subject=current_user.subject,
            caller_roles=caller_roles,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied to add member to group '{group_name}'",
            )

        # Invalidate policy version to trigger near real-time sync
        from app.services.policy_invalidator import invalidate_policy_version
        invalidate_policy_version(db)

        return MembershipResponse(
            status="member_added", group=group_name, subject=member_data.subject
        )

    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete(
    "/groups/{group_name}/members/{subject}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove member from group",
    description="""
Remove a user from a group, revoking their access to group-based permissions.

**Authorization**: Users can remove members from groups they have permission to manage.
Permissions are checked via Cerbos policies.

**Member Identification**: Users are identified by their CPF (Brazilian tax ID).

**Impact**: Removing a user from a group will revoke all roles and permissions
they inherited through that group membership.

**Use Cases**:
- Remove users who no longer need access
- Administrative user management
- Security incidents requiring immediate access revocation
- Team restructuring

**Cache Invalidation**: User role caches are automatically invalidated to ensure
immediate effect of permission changes.
    """,
    responses={
        204: {
            "description": "Member removed from group successfully"
        },
        400: {
            "description": "Bad request - User not a member of the group",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User is not a member of this group"
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
            "description": "Forbidden - Insufficient permissions to remove members from this group",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to remove member from group 'engineering_team:backend'"
                    }
                }
            }
        },
        404: {
            "description": "Group or user not found",
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
                        "detail": "Failed to remove member: Database connection error"
                    }
                }
            }
        }
    }
)
async def remove_member_from_group(
    group_name: str,
    subject: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    membership_service: Annotated[
        MembershipService, Depends(lambda: MembershipService())
    ],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Remove member from group
    try:
        success = membership_service.remove_member_from_group(
            db=db,
            group_name=group_name,
            member_subject=subject,
            caller_subject=current_user.subject,
            caller_roles=caller_roles,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied to remove member from group '{group_name}'",
            )

        # Invalidate policy version to trigger near real-time sync
        from app.services.policy_invalidator import invalidate_policy_version
        invalidate_policy_version(db)

    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
