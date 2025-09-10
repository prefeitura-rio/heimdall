"""
Action management API endpoints.
Implements action CRUD operations with proper authorization and auditing.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user
from app.models import User
from app.services.action import ActionService
from app.services.cerbos import CerbosService
from app.services.user import UserService

router = APIRouter()


# Pydantic models for request/response
class ActionCreateRequest(BaseModel):
    name: str
    description: str


class ActionUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None


class ActionResponse(BaseModel):
    id: int
    name: str
    description: str | None
    endpoint_count: int = 0


class ActionListResponse(BaseModel):
    actions: list[ActionResponse]
    total: int
    skip: int
    limit: int


def get_action_service() -> ActionService:
    """Dependency to get ActionService instance."""
    return ActionService()


def get_cerbos_service() -> CerbosService:
    """Dependency to get CerbosService instance."""
    return CerbosService()


def get_user_service() -> UserService:
    """Dependency to get UserService instance."""
    return UserService()


@router.post("/", status_code=status.HTTP_201_CREATED, response_model=ActionResponse)
async def create_action(
    action_data: ActionCreateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    action_service: Annotated[ActionService, Depends(get_action_service)],
    cerbos_service: Annotated[CerbosService, Depends(get_cerbos_service)],
    user_service: Annotated[UserService, Depends(get_user_service)],
):
    """
    Create a new action.
    Requires authorization to perform action:create operations.
    """
    try:
        # Get user roles for authorization
        user_roles = user_service.get_user_roles(db, current_user)

        # Check authorization with Cerbos
        can_create = cerbos_service.can_create_mapping(
            caller_subject=current_user.subject,
            caller_roles=user_roles,
            action_name=action_data.name,
        )

        if not can_create:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to create actions",
            )

        # Create the action
        action = action_service.create_action(
            db=db,
            name=action_data.name,
            description=action_data.description,
            created_by=current_user,
        )

        return ActionResponse(
            id=action.id,
            name=action.name,
            description=action.description,
            endpoint_count=len(action.endpoints),
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create action: {str(e)}",
        )


@router.get("/", response_model=ActionListResponse)
async def list_actions(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    action_service: Annotated[ActionService, Depends(get_action_service)],
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
):
    """
    List all actions with pagination.
    No special authorization required for listing.
    """
    try:
        actions = action_service.list_actions(db=db, skip=skip, limit=limit)

        action_responses = [
            ActionResponse(
                id=action.id,
                name=action.name,
                description=action.description,
                endpoint_count=len(action.endpoints),
            )
            for action in actions
        ]

        # Get total count for pagination info  
        from app.models import Action
        total_count = db.query(Action).count()

        return ActionListResponse(
            actions=action_responses,
            total=total_count,
            skip=skip,
            limit=limit,
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list actions: {str(e)}",
        )


@router.get("/{action_id}", response_model=ActionResponse)
async def get_action(
    action_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    action_service: Annotated[ActionService, Depends(get_action_service)],
):
    """
    Get a specific action by ID.
    No special authorization required for reading.
    """
    try:
        action = action_service.get_action(db=db, action_id=action_id)

        if not action:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Action with ID {action_id} not found",
            )

        return ActionResponse(
            id=action.id,
            name=action.name,
            description=action.description,
            endpoint_count=len(action.endpoints),
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get action: {str(e)}",
        )


@router.put("/{action_id}", response_model=ActionResponse)
async def update_action(
    action_id: int,
    action_data: ActionUpdateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    action_service: Annotated[ActionService, Depends(get_action_service)],
    cerbos_service: Annotated[CerbosService, Depends(get_cerbos_service)],
    user_service: Annotated[UserService, Depends(get_user_service)],
):
    """
    Update an existing action.
    Requires authorization to perform action:update operations.
    """
    try:
        # Get user roles for authorization
        user_roles = user_service.get_user_roles(db, current_user)

        # Check authorization with Cerbos
        can_update = cerbos_service.can_update_mapping(
            caller_subject=current_user.subject,
            caller_roles=user_roles,
            mapping_id=action_id,
        )

        if not can_update:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to update actions",
            )

        # Update the action
        action = action_service.update_action(
            db=db,
            action_id=action_id,
            name=action_data.name,
            description=action_data.description,
            updated_by=current_user,
        )

        return ActionResponse(
            id=action.id,
            name=action.name,
            description=action.description,
            endpoint_count=len(action.endpoints),
        )

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update action: {str(e)}",
        )


@router.delete("/{action_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_action(
    action_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    action_service: Annotated[ActionService, Depends(get_action_service)],
    cerbos_service: Annotated[CerbosService, Depends(get_cerbos_service)],
    user_service: Annotated[UserService, Depends(get_user_service)],
):
    """
    Delete an action.
    Requires authorization to perform action:delete operations.
    """
    try:
        # Get user roles for authorization
        user_roles = user_service.get_user_roles(db, current_user)

        # Check authorization with Cerbos
        can_delete = cerbos_service.can_delete_mapping(
            caller_subject=current_user.subject,
            caller_roles=user_roles,
            mapping_id=action_id,
        )

        if not can_delete:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions to delete actions",
            )

        # Delete the action
        action_service.delete_action(
            db=db, action_id=action_id, deleted_by=current_user
        )

        return  # 204 No Content

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete action: {str(e)}",
        )