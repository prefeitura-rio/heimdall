"""
Mapping management API endpoints.
Implements mapping endpoints as specified in SPEC.md Section 3.5.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_api_user, get_current_user
from app.models import User
from app.services.cerbos import CerbosService
from app.services.mapping import MappingService
from app.services.user import UserService

router = APIRouter()


# Pydantic models for request/response
class MappingCreateRequest(BaseModel):
    path_pattern: str
    method: str
    action_id: int
    description: str | None = None


class MappingUpdateRequest(BaseModel):
    path_pattern: str | None = None
    method: str | None = None
    action_id: int | None = None
    description: str | None = None


class MappingResponse(BaseModel):
    mapping_id: int
    action: str
    path_pattern: str
    method: str
    description: str | None = None


class MappingDetailResponse(BaseModel):
    id: int
    path_pattern: str
    method: str
    action: str
    description: str | None = None
    created_by: str | None = None
    created_at: str
    updated_at: str | None = None


@router.get("/", response_model=MappingResponse | None)
async def resolve_mapping(
    path: Annotated[str, Query(description="The path to resolve")],
    method: Annotated[str, Query(description="The HTTP method")],
    _current_user: Annotated[dict, Depends(get_api_user)],
    db: Annotated[Session, Depends(get_db)],
    mapping_service: Annotated[MappingService, Depends(lambda: MappingService())],
):
    """
    Resolve path and method to action.
    Implements GET /mappings as specified in SPEC.md Section 3.5.
    """
    mapping = mapping_service.resolve_mapping(db=db, path=path, method=method)

    if not mapping:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No mapping found for path '{path}' and method '{method}'",
        )

    return MappingResponse(**mapping)


@router.post(
    "/", status_code=status.HTTP_201_CREATED, response_model=MappingDetailResponse
)
async def create_mapping(
    mapping_data: MappingCreateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    mapping_service: Annotated[MappingService, Depends(lambda: MappingService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    """
    Create a new mapping.
    Implements POST /mappings as specified in SPEC.md Section 3.5.
    """
    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to create mappings using Cerbos
    can_create = cerbos_service.can_create_mapping(
        caller_subject=current_user.subject,
        caller_roles=caller_roles,
        action_name=f"action_{mapping_data.action_id}",  # Use action_id for permission check
    )

    if not can_create:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied to create mappings",
        )

    # Create the mapping
    try:
        mapping = mapping_service.create_mapping(
            db=db,
            path_pattern=mapping_data.path_pattern,
            method=mapping_data.method,
            action_id=mapping_data.action_id,
            description=mapping_data.description,
            created_by=current_user,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    return MappingDetailResponse(
        id=mapping.id,
        path_pattern=mapping.path_pattern,
        method=mapping.method,
        action=mapping.action.name,
        description=mapping.description,
        created_by=mapping.creator.subject if mapping.creator else None,
        created_at=mapping.created_at.isoformat(),
        updated_at=mapping.updated_at.isoformat() if mapping.updated_at else None,
    )


@router.put("/{mapping_id}", response_model=MappingDetailResponse)
async def update_mapping(
    mapping_id: int,
    mapping_data: MappingUpdateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    mapping_service: Annotated[MappingService, Depends(lambda: MappingService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    """
    Update an existing mapping.
    Implements PUT /mappings/{id} as specified in SPEC.md Section 3.5.
    """
    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to update mappings using Cerbos
    can_update = cerbos_service.can_update_mapping(
        caller_subject=current_user.subject,
        caller_roles=caller_roles,
        mapping_id=mapping_id,
    )

    if not can_update:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied to update mapping {mapping_id}",
        )

    # Update the mapping
    try:
        mapping = mapping_service.update_mapping(
            db=db,
            mapping_id=mapping_id,
            path_pattern=mapping_data.path_pattern,
            method=mapping_data.method,
            action_id=mapping_data.action_id,
            description=mapping_data.description,
            updated_by=current_user,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    return MappingDetailResponse(
        id=mapping.id,
        path_pattern=mapping.path_pattern,
        method=mapping.method,
        action=mapping.action.name,
        description=mapping.description,
        created_by=mapping.creator.subject if mapping.creator else None,
        created_at=mapping.created_at.isoformat(),
        updated_at=mapping.updated_at.isoformat() if mapping.updated_at else None,
    )


@router.delete("/{mapping_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mapping(
    mapping_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    mapping_service: Annotated[MappingService, Depends(lambda: MappingService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
    """
    Delete a mapping.
    Implements DELETE /mappings/{id} as specified in SPEC.md Section 3.5.
    """
    # Get caller's roles for permission check
    caller_roles = user_service.get_user_roles(db, current_user)

    # Check permission to delete mappings using Cerbos
    can_delete = cerbos_service.can_delete_mapping(
        caller_subject=current_user.subject,
        caller_roles=caller_roles,
        mapping_id=mapping_id,
    )

    if not can_delete:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied to delete mapping {mapping_id}",
        )

    # Delete the mapping
    try:
        success = mapping_service.delete_mapping(
            db=db, mapping_id=mapping_id, deleted_by=current_user
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete mapping",
            )

    except ValueError:
        # For idempotent operations, treat not found as success
        pass


@router.get("/list", response_model=list[MappingDetailResponse])
async def list_mappings(
    _current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    mapping_service: Annotated[MappingService, Depends(lambda: MappingService())],
    action_filter: Annotated[
        str | None, Query(description="Filter by action name")
    ] = None,
):
    """
    List all mappings with optional filtering.
    Additional endpoint for management interface.
    """
    mappings = mapping_service.list_mappings(db=db, action_filter=action_filter)

    return [
        MappingDetailResponse(
            id=mapping.id,
            path_pattern=mapping.path_pattern,
            method=mapping.method,
            action=mapping.action.name,
            description=mapping.description,
            created_by=mapping.creator.subject if mapping.creator else None,
            created_at=mapping.created_at.isoformat(),
            updated_at=mapping.updated_at.isoformat() if mapping.updated_at else None,
        )
        for mapping in mappings
    ]
