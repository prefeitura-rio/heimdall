"""
Membership management API endpoints.
Implements membership endpoints as specified in SPEC.md Section 3.3.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.services.membership import MembershipService
from app.services.user import UserService

router = APIRouter()


# Pydantic models for request/response
class AddMemberRequest(BaseModel):
    subject: str


class MembershipResponse(BaseModel):
    status: str
    group: str
    subject: str


@router.post("/groups/{group_name}/members", response_model=MembershipResponse)
async def add_member_to_group(
    group_name: str,
    member_data: AddMemberRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    membership_service: Annotated[MembershipService, Depends(lambda: MembershipService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())]
):
    """
    Add member to group with complete flow.
    Implements POST /groups/{groupName}/members as specified in SPEC.md Section 3.3.
    """
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
            caller_roles=caller_roles
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied to add member to group '{group_name}'"
            )

        return MembershipResponse(
            status="member_added",
            group=group_name,
            subject=member_data.subject
        )

    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e)
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.delete("/groups/{group_name}/members/{subject}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member_from_group(
    group_name: str,
    subject: str,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    membership_service: Annotated[MembershipService, Depends(lambda: MembershipService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())]
):
    """
    Remove member from group.
    Implements DELETE /groups/{groupName}/members/{subject} as specified in SPEC.md Section 3.3.
    """
    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Remove member from group
    try:
        success = membership_service.remove_member_from_group(
            db=db,
            group_name=group_name,
            member_subject=subject,
            caller_subject=current_user.subject,
            caller_roles=caller_roles
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied to remove member from group '{group_name}'"
            )

    except ValueError as e:
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e)
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
