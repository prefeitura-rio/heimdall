"""
Group management API endpoints.
Implements group endpoints as specified in SPEC.md Section 3.2.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
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
    name: str
    description: str


class GroupResponse(BaseModel):
    id: int
    name: str
    description: str
    created_by: str | None = None
    created_at: str


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=GroupResponse)
async def create_group(
    group_data: GroupCreateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    group_service: Annotated[GroupService, Depends(lambda: GroupService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    """
    Create a group with Cerbos permission check.
    Implements POST /groups as specified in SPEC.md Section 3.2.
    """
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

    return GroupResponse(
        id=group.id,
        name=group.name,
        description=group.description,
        created_by=group.creator.subject if group.creator else None,
        created_at=group.created_at.isoformat(),
    )


@router.get("/", response_model=list[GroupResponse])
async def list_groups(
    prefix: Annotated[str | None, Query()] = None,
    _current_user: Annotated[User, Depends(get_current_user)] = None,
    db: Annotated[Session, Depends(get_db)] = None,
    group_service: Annotated[GroupService, Depends(lambda: GroupService())] = None,
):
    """
    List groups with optional prefix filtering.
    Implements GET /groups as specified in SPEC.md Section 3.2.
    """
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


@router.delete("/{group_name}", status_code=status.HTTP_204_NO_CONTENT)
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
