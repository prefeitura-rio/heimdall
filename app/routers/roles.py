"""
Role management API endpoints.
Implements role endpoints as specified in SPEC.md Section 3.4.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.common.pagination import PaginatedResponse
from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.services.action import ActionService
from app.services.cerbos import CerbosService
from app.services.role import RoleService
from app.services.user import UserService

router = APIRouter()


# Import ActionResponse from actions router
class ActionResponse(BaseModel):
    """Response model for action information."""

    id: int = Field(
        ...,
        description="Unique identifier for the action",
        example=1
    )
    name: str = Field(
        ...,
        description="Action name",
        example="user:read"
    )
    description: str | None = Field(
        None,
        description="Action description",
        example="Read user information"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "name": "user:read",
                "description": "Read user information"
            }
        }


class RoleActionRequest(BaseModel):
    """Request model for role-action operations."""

    action_name: str = Field(
        ...,
        description="Name of the action to assign/remove (lowercase letters, numbers, underscores, and colons only)",
        example="user:read",
        pattern="^[a-z0-9_:]+$"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "action_name": "user:read"
            }
        }


class RoleActionResponse(BaseModel):
    """Response model for role-action operations."""

    status: str = Field(
        ...,
        description="Status of the operation",
        example="action_assigned"
    )
    role: str = Field(
        ...,
        description="Role name",
        example="data_analyst:read"
    )
    action: str = Field(
        ...,
        description="Action name",
        example="user:read"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "status": "action_assigned",
                "role": "data_analyst:read",
                "action": "user:read"
            }
        }


# Pydantic models for request/response
class RoleCreateRequest(BaseModel):
    """Request model for creating a new role."""

    name: str = Field(
        ...,
        description="Unique name for the role (lowercase letters, numbers, underscores, and colons only)",
        example="data_analyst:read",
        min_length=1,
        max_length=100,
        pattern="^[a-z0-9_:]+$"
    )
    description: str = Field(
        ...,
        description="Human-readable description of the role's purpose and permissions",
        example="Data analysts with read access to analytics dashboards",
        min_length=1,
        max_length=500
    )

    class Config:
        json_schema_extra = {
            "example": {
                "name": "data_analyst:read",
                "description": "Data analysts with read access to analytics dashboards"
            }
        }


class RoleResponse(BaseModel):
    """Response model for role information."""

    id: int = Field(
        ...,
        description="Unique identifier for the role",
        example=1
    )
    name: str = Field(
        ...,
        description="Role name",
        example="data_analyst:read"
    )
    description: str = Field(
        ...,
        description="Role description",
        example="Data analysts with read access to analytics dashboards"
    )
    created_by: str | None = Field(
        None,
        description="CPF of the user who created this role (null for system roles)",
        example="12345678901"
    )
    created_at: str | None = Field(
        None,
        description="ISO timestamp when the role was created (null for system roles)",
        example="2024-01-15T10:30:00Z"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "name": "data_analyst:read",
                "description": "Data analysts with read access to analytics dashboards",
                "created_by": "12345678901",
                "created_at": "2024-01-15T10:30:00Z"
            }
        }


class RoleAssignRequest(BaseModel):
    """Request model for assigning a role to a group."""

    role_name: str = Field(
        ...,
        description="Name of the role to assign to the group (lowercase letters, numbers, underscores, and colons only)",
        example="data_analyst:read",
        pattern="^[a-z0-9_:]+$"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "role_name": "data_analyst:read"
            }
        }


class RoleAssignmentResponse(BaseModel):
    """Response model for role assignment operations."""

    status: str = Field(
        ...,
        description="Status of the role assignment operation",
        example="success"
    )
    group: str = Field(
        ...,
        description="Name of the group the role was assigned to",
        example="engineering_team:backend"
    )
    role: str = Field(
        ...,
        description="Name of the role that was assigned",
        example="data_analyst:read"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "group": "engineering_team:backend",
                "role": "data_analyst:read"
            }
        }


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=RoleResponse)
async def create_role(
    role_data: RoleCreateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    role_service: Annotated[RoleService, Depends(lambda: RoleService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    """
    Create a role (admin-only).
    Implements POST /roles as specified in SPEC.md Section 3.4.
    """
    # Get caller's roles for admin permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check if user has admin privileges (simplified check)
    has_admin = any(role in ["admin", "superadmin"] for role in caller_roles)
    if not has_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required to create roles",
        )

    # Create the role
    try:
        role = role_service.create_role(
            db=db,
            name=role_data.name,
            description=role_data.description,
            created_by=current_user,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    # Invalidate policy version to trigger near real-time sync
    from app.services.policy_invalidator import invalidate_policy_version
    invalidate_policy_version(db)

    return RoleResponse(
        id=role.id,
        name=role.name,
        description=role.description,
        created_by=None,  # Role model doesn't track creator
        created_at=None,  # Role model doesn't track created_at
    )


@router.get(
    "/",
    response_model=PaginatedResponse[RoleResponse],
    summary="List all roles",
    description="""
List all roles available in the system.

**Authorization**: All authenticated users can list roles.

**Pagination**: Use `skip` and `limit` parameters to control pagination.
Maximum limit is 100 roles per request.

**Use Cases**:
- Display available roles in user interfaces
- Role selection during group or user management
- Administrative overview of system roles
- Integration with external systems requiring role information

**System Roles**: The system includes built-in roles like `superadmin` which cannot be deleted.
    """,
    responses={
        200: {
            "description": "List of roles retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "items": [
                            {
                                "id": 1,
                                "name": "superadmin",
                                "description": "Super administrator with full system access",
                                "created_by": None,
                                "created_at": None
                            },
                            {
                                "id": 2,
                                "name": "data_analyst:read",
                                "description": "Data analysts with read access to analytics dashboards",
                                "created_by": "12345678901",
                                "created_at": "2024-01-15T10:30:00Z"
                            }
                        ],
                        "total": 25,
                        "skip": 0,
                        "limit": 50,
                        "has_more": False
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
                        "detail": "An unexpected error occurred while retrieving roles"
                    }
                }
            }
        }
    }
)
async def list_roles(
    _current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    role_service: Annotated[RoleService, Depends(lambda: RoleService())],
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of items to return"),
):
    roles, total_count = role_service.list_roles(db=db, skip=skip, limit=limit)

    role_responses = [
        RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            created_by=None,  # Role model doesn't have creator field
            created_at=None,  # Role model doesn't have created_at field
        )
        for role in roles
    ]

    return PaginatedResponse.create(
        items=role_responses,
        total=total_count,
        skip=skip,
        limit=limit
    )


@router.get(
    "/groups/{group_name}/roles",
    response_model=list[RoleResponse],
    summary="List roles assigned to a group",
    description="""
List all roles assigned to a specific group.

**Authorization**: Users can view roles of groups they have permission to access.
Permissions are checked via Cerbos policies.

**Role Information**: Returns each role's ID, name, and description.

**Use Cases**:
- View group permissions and capabilities
- Audit group role assignments
- Administrative oversight of access control
- Verify role inheritance for group members

**Sorting**: Roles are returned sorted by name (alphabetical order).
    """,
    responses={
        200: {
            "description": "List of group roles retrieved successfully",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "id": 1,
                            "name": "data_analyst:read",
                            "description": "Data analysis and reporting access",
                            "created_by": None,
                            "created_at": None
                        },
                        {
                            "id": 2,
                            "name": "team_lead:manage",
                            "description": "Team leadership and management permissions",
                            "created_by": None,
                            "created_at": None
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
            "description": "Forbidden - Insufficient permissions to view group roles",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to view roles of group 'engineering_team:backend'"
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
                        "detail": "Failed to retrieve group roles: Database connection error"
                    }
                }
            }
        }
    }
)
async def list_group_roles(
    group_name: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    role_service: Annotated[RoleService, Depends(lambda: RoleService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
) -> list[RoleResponse]:
    """List all roles assigned to a specific group."""
    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to view group roles
    can_view = cerbos_service.check_permission(
        caller_subject=current_user.subject,
        caller_roles=caller_roles,
        action="group:view_roles",
        resource_type="group",
        resource_attrs={"name": group_name},
    )

    if not can_view:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied to view roles of group '{group_name}'"
        )

    # Get group roles
    try:
        roles = role_service.list_group_roles(db=db, group_name=group_name)

        return [
            RoleResponse(
                id=role.id,
                name=role.name,
                description=role.description,
                created_by=None,  # Role model doesn't have creator field
                created_at=None,  # Role model doesn't have created_at field
            )
            for role in roles
        ]

    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/groups/{group_name}/roles", response_model=RoleAssignmentResponse)
async def assign_role_to_group(
    group_name: str,
    assign_data: RoleAssignRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    role_service: Annotated[RoleService, Depends(lambda: RoleService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    """
    Assign role to group.
    Implements POST /groups/{groupName}/roles as specified in SPEC.md Section 3.4.
    """
    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to assign roles to this group using Cerbos
    can_assign = cerbos_service.can_assign_role(
        caller_subject=current_user.subject,
        caller_roles=caller_roles,
        group_name=group_name,
    )

    if not can_assign:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied to assign roles to group '{group_name}'",
        )

    # Assign role to group
    try:
        success = role_service.assign_role_to_group(
            db=db,
            group_name=group_name,
            role_name=assign_data.role_name,
            assigned_by=current_user,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to assign role to group",
            )

        # Invalidate policy version to trigger near real-time sync
        from app.services.policy_invalidator import invalidate_policy_version
        invalidate_policy_version(db)

        return RoleAssignmentResponse(
            status="role_assigned", group=group_name, role=assign_data.role_name
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.delete(
    "/groups/{group_name}/roles/{role_name}", status_code=status.HTTP_204_NO_CONTENT
)
async def remove_role_from_group(
    group_name: str,
    role_name: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    role_service: Annotated[RoleService, Depends(lambda: RoleService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    """
    Remove role from group.
    Implements DELETE /groups/{groupName}/roles/{roleName} as specified in SPEC.md Section 3.4.
    """
    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to remove roles from this group using Cerbos
    can_remove = cerbos_service.can_remove_role(
        caller_subject=current_user.subject,
        caller_roles=caller_roles,
        group_name=group_name,
    )

    if not can_remove:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied to remove roles from group '{group_name}'",
        )

    # Remove role from group
    try:
        success = role_service.remove_role_from_group(
            db=db, group_name=group_name, role_name=role_name, removed_by=current_user
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to remove role from group",
            )

        # Invalidate policy version to trigger near real-time sync
        from app.services.policy_invalidator import invalidate_policy_version
        invalidate_policy_version(db)

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))



# Role-Action Management Endpoints added programmatically
# Role-Action Management Endpoints

@router.get(
    "/{role_name}/actions",
    response_model=list[ActionResponse],
    summary="List actions allowed for a role",
    description="""
List all actions that a specific role can perform.

**Authorization**: Users can view actions for roles they have permission to access.
Permissions are checked via Cerbos policies.

**Action Information**: Returns each action's ID, name, and description.

**Use Cases**:
- Audit role permissions and capabilities
- Verify role-based access control configuration
- Administrative oversight of security policies
- Integration with external systems requiring permission information

**Sorting**: Actions are returned sorted by name (alphabetical order).

**Note**: This endpoint returns actions based on current Cerbos policy configuration.
    """,
    responses={
        200: {
            "description": "List of role actions retrieved successfully",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "id": 1,
                            "name": "user:read",
                            "description": "Read user information"
                        },
                        {
                            "id": 2,
                            "name": "user:list",
                            "description": "List users in the system"
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
            "description": "Forbidden - Insufficient permissions to view role actions",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to view actions for role 'data_analyst:read'"
                    }
                }
            }
        },
        404: {
            "description": "Role not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Role 'unknown-role' not found"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to retrieve role actions: Policy service error"
                    }
                }
            }
        }
    }
)
async def list_role_actions(
    role_name: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    role_service: Annotated[RoleService, Depends(lambda: RoleService())],
    _action_service: Annotated[ActionService, Depends(lambda: ActionService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
) -> list[ActionResponse]:
    """List all actions allowed for a specific role."""
    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to view role actions
    can_view = cerbos_service.check_permission(
        caller_subject=current_user.subject,
        caller_roles=caller_roles,
        action="role:view_actions",
        resource_type="role",
        resource_attrs={"name": role_name},
    )

    if not can_view:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied to view actions for role '{role_name}'"
        )

    # Check if role exists
    try:
        roles, _ = role_service.list_roles(db)
        role_exists = any(role.name == role_name for role in roles)
        if not role_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role '{role_name}' not found"
            )

        # Get role-specific actions from the database
        actions = role_service.list_role_actions(db, role_name)

        return [
            ActionResponse(
                id=action.id,
                name=action.name,
                description=action.description,
            )
            for action in actions
        ]

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve role actions: {str(e)}"
        )


@router.post(
    "/{role_name}/actions",
    response_model=RoleActionResponse,
    summary="Add action permission to a role",
    description="""
Grant a specific action permission to a role.

**Authorization**: Users can modify role permissions they have access to manage.
Permissions are checked via Cerbos policies.

**Action Assignment**: Adds the specified action to the role's allowed permissions.

**Use Cases**:
- Grant new permissions to existing roles
- Administrative role management
- Dynamic permission assignment
- Security policy updates

**Policy Updates**: Changes are propagated to Cerbos policy engine for immediate effect.

**Note**: This endpoint manages role permissions through Cerbos policy configuration.
    """,
    responses={
        200: {
            "description": "Action permission added to role successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "action_assigned",
                        "role": "data_analyst:read",
                        "action": "user:read"
                    }
                }
            }
        },
        400: {
            "description": "Bad request - Invalid action name or role already has permission",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Role already has permission for this action"
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
            "description": "Forbidden - Insufficient permissions to modify role actions",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to modify actions for role 'data_analyst:read'"
                    }
                }
            }
        },
        404: {
            "description": "Role or action not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Role 'unknown-role' not found"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to assign action to role: Policy service error"
                    }
                }
            }
        }
    }
)
async def assign_action_to_role(
    role_name: str,
    action_data: RoleActionRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    role_service: Annotated[RoleService, Depends(lambda: RoleService())],
    action_service: Annotated[ActionService, Depends(lambda: ActionService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
) -> RoleActionResponse:
    """Add action permission to a role."""
    # Protect superadmin role from modification
    if role_name == "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify superadmin role: it is protected and has wildcard permissions"
        )

    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to modify role actions
    can_modify = cerbos_service.check_permission(
        caller_subject=current_user.subject,
        caller_roles=caller_roles,
        action="role:modify_actions",
        resource_type="role",
        resource_attrs={"name": role_name},
    )

    if not can_modify:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied to modify actions for role '{role_name}'"
        )

    try:
        # Verify role exists
        roles, _ = role_service.list_roles(db)
        role_exists = any(role.name == role_name for role in roles)
        if not role_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role '{role_name}' not found"
            )

        # Verify action exists
        actions = action_service.list_actions(db)
        action_exists = any(action.name == action_data.action_name for action in actions)
        if not action_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Action '{action_data.action_name}' not found"
            )

        # Assign action to role using the database
        success = role_service.assign_action_to_role(
            db=db,
            role_name=role_name,
            action_name=action_data.action_name,
            assigned_by=current_user
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to assign action to role"
            )

        # Invalidate policy version to trigger near real-time sync
        from app.services.policy_invalidator import invalidate_policy_version
        invalidate_policy_version(db)

        return RoleActionResponse(
            status="action_assigned",
            role=role_name,
            action=action_data.action_name
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to assign action to role: {str(e)}"
        )


@router.delete(
    "/{role_name}/actions/{action_name}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove action permission from a role",
    description="""
Revoke a specific action permission from a role.

**Authorization**: Users can modify role permissions they have access to manage.
Permissions are checked via Cerbos policies.

**Action Removal**: Removes the specified action from the role's allowed permissions.

**Use Cases**:
- Revoke unnecessary permissions from roles
- Administrative role management
- Security incident response
- Policy tightening and least-privilege enforcement

**Policy Updates**: Changes are propagated to Cerbos policy engine for immediate effect.

**Note**: This endpoint manages role permissions through Cerbos policy configuration.
    """,
    responses={
        204: {
            "description": "Action permission removed from role successfully"
        },
        400: {
            "description": "Bad request - Role doesn't have this action permission",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Role doesn't have permission for this action"
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
            "description": "Forbidden - Insufficient permissions to modify role actions",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to modify actions for role 'data_analyst:read'"
                    }
                }
            }
        },
        404: {
            "description": "Role or action not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Role 'unknown-role' not found"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to remove action from role: Policy service error"
                    }
                }
            }
        }
    }
)
async def remove_action_from_role(
    role_name: str,
    action_name: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    role_service: Annotated[RoleService, Depends(lambda: RoleService())],
    action_service: Annotated[ActionService, Depends(lambda: ActionService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    """Remove action permission from a role."""
    # Protect superadmin role from modification
    if role_name == "superadmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify superadmin role: it is protected and has wildcard permissions"
        )

    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to modify role actions
    can_modify = cerbos_service.check_permission(
        caller_subject=current_user.subject,
        caller_roles=caller_roles,
        action="role:modify_actions",
        resource_type="role",
        resource_attrs={"name": role_name},
    )

    if not can_modify:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied to modify actions for role '{role_name}'"
        )

    try:
        # Verify role exists
        roles, _ = role_service.list_roles(db)
        role_exists = any(role.name == role_name for role in roles)
        if not role_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role '{role_name}' not found"
            )

        # Verify action exists
        actions = action_service.list_actions(db)
        action_exists = any(action.name == action_name for action in actions)
        if not action_exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Action '{action_name}' not found"
            )

        # Remove action from role using the database
        success = role_service.remove_action_from_role(
            db=db,
            role_name=role_name,
            action_name=action_name,
            removed_by=current_user
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to remove action from role"
            )

        # Invalidate policy version to trigger near real-time sync
        from app.services.policy_invalidator import invalidate_policy_version
        invalidate_policy_version(db)

        # No return value for 204 status code

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove action from role: {str(e)}"
        )


@router.delete(
    "/{role_name}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a role",
    description="""
Delete a role from the system.

**Authorization**: Users can delete roles they have permission to manage.
Permissions are checked via Cerbos policies.

**Cascade Effects**:
- Removes the role from all groups that have it assigned
- Removes all action permissions associated with the role
- Updates Cerbos policies to reflect the role deletion

**Use Cases**:
- Remove obsolete or unused roles
- Administrative role cleanup
- Security compliance and role minimization
- System reorganization

**Safety**: Role deletion is irreversible. Ensure the role is no longer needed before deletion.
    """,
    responses={
        204: {
            "description": "Role deleted successfully"
        },
        403: {
            "description": "Forbidden - Insufficient permissions to delete role",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to delete role 'data_analyst:read'"
                    }
                }
            }
        },
        404: {
            "description": "Role not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Role 'unknown-role' not found"
                    }
                }
            }
        },
        409: {
            "description": "Conflict - Role is still in use",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Cannot delete role 'superadmin': still assigned to 3 groups"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to delete role: Database transaction error"
                    }
                }
            }
        }
    }
)
async def delete_role(
    role_name: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    role_service: Annotated[RoleService, Depends(lambda: RoleService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    """Delete a role from the system."""
    try:
        # Get caller's roles for permission check
        caller_roles = user_service.get_user_roles(db, current_user)

        # Check if role exists
        role = role_service.get_role_by_name(db, role_name)
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role '{role_name}' not found"
            )

        # Protect superadmin role from deletion
        if role_name == "superadmin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot delete superadmin role: it is protected and immutable"
            )

        # Check permission to delete this role
        is_allowed = cerbos_service.check_permission(
            caller_subject=current_user.subject,
            caller_roles=caller_roles,
            action="role:delete",
            resource_type="role",
            resource_attrs={"name": role_name}
        )

        if not is_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied to delete role '{role_name}'"
            )

        # Check if role is still assigned to groups (safety check)
        groups_with_role = role_service.get_groups_with_role(db, role_name)
        if groups_with_role:
            group_names = [group["name"] for group in groups_with_role]
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot delete role '{role_name}': still assigned to groups: {', '.join(group_names)}"
            )

        # Delete the role
        role_service.delete_role(db, role_name)

        # Invalidate policy version to trigger near real-time sync
        from app.services.policy_invalidator import invalidate_policy_version
        invalidate_policy_version(db)

        # No return value for 204 status code

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete role: {str(e)}"
        )
