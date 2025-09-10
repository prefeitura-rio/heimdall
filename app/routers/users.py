"""
User management API endpoints.
Implements user endpoints as specified in SPEC.md Section 3.1.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.services.user import UserService

router = APIRouter()


@router.get("/{cpf}")
async def get_user_by_cpf(
    cpf: str,
    _current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    """
    Get user by CPF (preferred_username) with groups and roles.
    Implements GET /users/{cpf} as specified in SPEC.md Section 3.1.
    """
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

    return {
        "id": user.id,
        "cpf": user.subject,  # subject contains the CPF (preferred_username)
        "display_name": user.display_name,
        "groups": group_names,
        "roles": user_roles,
    }
