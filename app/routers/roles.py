"""
Role management API endpoints.
Implements role endpoints as specified in SPEC.md Section 3.4.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.services.cerbos import CerbosService
from app.services.role import RoleService
from app.services.user import UserService

router = APIRouter()


# Pydantic models for request/response
class RoleCreateRequest(BaseModel):
    name: str
    description: str


class RoleResponse(BaseModel):
    id: int
    name: str
    description: str
    created_by: str | None = None
    created_at: str


class RoleAssignRequest(BaseModel):
    role_name: str


class RoleAssignmentResponse(BaseModel):
    status: str
    group: str
    role: str


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

    return RoleResponse(
        id=role.id,
        name=role.name,
        description=role.description,
        created_by=role.creator.subject if role.creator else None,
        created_at=role.created_at.isoformat(),
    )


@router.get("/", response_model=list[RoleResponse])
async def list_roles(
    _current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    role_service: Annotated[RoleService, Depends(lambda: RoleService())],
):
    """
    List all roles.
    Implements GET /roles as specified in SPEC.md Section 3.4.
    """
    roles = role_service.list_roles(db=db)

    return [
        RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            created_by=role.creator.subject if role.creator else None,
            created_at=role.created_at.isoformat(),
        )
        for role in roles
    ]


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

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
