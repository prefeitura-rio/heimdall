"""
Mapping management API endpoints.
Implements mapping endpoints as specified in SPEC.md Section 3.5.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
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
    """Request model for creating a new endpoint-to-action mapping."""

    path_pattern: str = Field(
        ...,
        description="URL path pattern (supports wildcards and path parameters)",
        example="/api/v1/users/{user_id}",
        min_length=1,
        max_length=255
    )
    method: str = Field(
        ...,
        description="HTTP method",
        example="GET",
        pattern="^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$"
    )
    action_id: int = Field(
        ...,
        description="ID of the action to map to this endpoint",
        example=1,
        gt=0
    )
    description: str | None = Field(
        None,
        description="Optional description of this mapping",
        example="Get user profile information",
        max_length=500
    )

    class Config:
        json_schema_extra = {
            "example": {
                "path_pattern": "/api/v1/users/{user_id}",
                "method": "GET",
                "action_id": 1,
                "description": "Get user profile information"
            }
        }


class MappingUpdateRequest(BaseModel):
    """Request model for updating an existing endpoint-to-action mapping."""

    path_pattern: str | None = Field(
        None,
        description="Updated URL path pattern",
        example="/api/v1/users/{user_id}",
        min_length=1,
        max_length=255
    )
    method: str | None = Field(
        None,
        description="Updated HTTP method",
        example="GET",
        pattern="^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$"
    )
    action_id: int | None = Field(
        None,
        description="Updated action ID",
        example=2,
        gt=0
    )
    description: str | None = Field(
        None,
        description="Updated description",
        example="Get detailed user profile information",
        max_length=500
    )

    class Config:
        json_schema_extra = {
            "example": {
                "path_pattern": "/api/v1/users/{user_id}/profile",
                "description": "Get detailed user profile information"
            }
        }


class MappingResponse(BaseModel):
    """Response model for mapping resolution (used by authorization middleware)."""

    mapping_id: int = Field(
        ...,
        description="Unique identifier of the mapping",
        example=1
    )
    action: str = Field(
        ...,
        description="Action name mapped to this endpoint",
        example="user:read"
    )
    path_pattern: str = Field(
        ...,
        description="URL path pattern that matched",
        example="/api/v1/users/{user_id}"
    )
    method: str = Field(
        ...,
        description="HTTP method",
        example="GET"
    )
    description: str | None = Field(
        None,
        description="Mapping description",
        example="Get user profile information"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "mapping_id": 1,
                "action": "user:read",
                "path_pattern": "/api/v1/users/{user_id}",
                "method": "GET",
                "description": "Get user profile information"
            }
        }


class MappingDetailResponse(BaseModel):
    """Detailed response model for mapping information."""

    id: int = Field(
        ...,
        description="Unique identifier of the mapping",
        example=1
    )
    path_pattern: str = Field(
        ...,
        description="URL path pattern",
        example="/api/v1/users/{user_id}"
    )
    method: str = Field(
        ...,
        description="HTTP method",
        example="GET"
    )
    action: str = Field(
        ...,
        description="Action name",
        example="user:read"
    )
    description: str | None = Field(
        None,
        description="Mapping description",
        example="Get user profile information"
    )
    created_by: str | None = Field(
        None,
        description="CPF of the user who created this mapping",
        example="12345678901"
    )
    created_at: str = Field(
        ...,
        description="ISO timestamp when the mapping was created",
        example="2024-01-15T10:30:00Z"
    )
    updated_at: str | None = Field(
        None,
        description="ISO timestamp when the mapping was last updated",
        example="2024-01-16T14:20:00Z"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "path_pattern": "/api/v1/users/{user_id}",
                "method": "GET",
                "action": "user:read",
                "description": "Get user profile information",
                "created_by": "12345678901",
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-16T14:20:00Z"
            }
        }


@router.get(
    "/",
    response_model=MappingResponse | None,
    summary="Resolve endpoint to action",
    description="""
Resolve an API endpoint (path + method) to its corresponding action for authorization.

**Authorization Middleware**: This endpoint is primarily used by authorization middleware
to determine which action should be checked for a given API request.

**Path Matching**: Supports exact matches and pattern matching with path parameters
(e.g., `/api/v1/users/{user_id}` matches `/api/v1/users/123`).

**Method Matching**: HTTP method must match exactly (case-sensitive).

**Use Cases**:
- Authorization middleware determining required permissions
- API gateway integration for access control
- Dynamic permission checking in applications
- Audit logging of permission requirements
    """,
    responses={
        200: {
            "description": "Mapping found and resolved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "mapping_id": 1,
                        "action": "user:read",
                        "path_pattern": "/api/v1/users/{user_id}",
                        "method": "GET",
                        "description": "Get user profile information"
                    }
                }
            }
        },
        404: {
            "description": "No mapping found for the specified path and method",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "No mapping found for path '/api/v1/unknown' and method 'GET'"
                    }
                }
            }
        },
        422: {
            "description": "Validation error - Missing or invalid query parameters",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Validation error",
                        "errors": [
                            {
                                "loc": ["query", "path"],
                                "msg": "field required",
                                "type": "value_error.missing"
                            }
                        ]
                    }
                }
            }
        }
    }
)
async def resolve_mapping(
    path: Annotated[str, Query(description="The API path to resolve (e.g., '/api/v1/users/123')", example="/api/v1/users/123")],
    method: Annotated[str, Query(description="The HTTP method", example="GET")],
    _current_user: Annotated[dict, Depends(get_api_user)],
    db: Annotated[Session, Depends(get_db)],
    mapping_service: Annotated[MappingService, Depends(lambda: MappingService())],
):
    mapping = mapping_service.resolve_mapping(db=db, path=path, method=method)

    if not mapping:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No mapping found for path '{path}' and method '{method}'",
        )

    return MappingResponse(**mapping)


@router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=MappingDetailResponse,
    summary="Create endpoint-to-action mapping",
    description="""
Create a new mapping between an API endpoint pattern and an action.

**Authorization**: Requires admin privileges to create mappings.

**Path Patterns**: Support exact paths and parameterized paths using curly braces
(e.g., `/api/v1/users/{user_id}`, `/api/v1/groups/{group_name}/members`).

**Method Mapping**: Each combination of path pattern and HTTP method can only
be mapped to one action.

**Action Reference**: The action must exist before creating a mapping. Use the
actions API to create actions first.

**Use Cases**:
- Configure authorization for new API endpoints
- Map existing endpoints to granular permissions
- Set up fine-grained access control
- Administrative configuration of API security
    """,
    responses={
        201: {
            "description": "Mapping created successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": 1,
                        "path_pattern": "/api/v1/users/{user_id}",
                        "method": "GET",
                        "action": "user:read",
                        "description": "Get user profile information",
                        "created_by": "12345678901",
                        "created_at": "2024-01-15T10:30:00Z",
                        "updated_at": None
                    }
                }
            }
        },
        400: {
            "description": "Bad request - Invalid action ID",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Action with ID 999 does not exist"
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
            "description": "Forbidden - Insufficient permissions to create mappings",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to create mappings"
                    }
                }
            }
        },
        409: {
            "description": "Conflict - Mapping already exists for this path and method",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Mapping already exists for path '/api/v1/users/{user_id}' and method 'GET'"
                    }
                }
            }
        },
        422: {
            "description": "Validation error - Invalid request data",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Validation error",
                        "errors": [
                            {
                                "loc": ["body", "method"],
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
                        "detail": "Failed to create mapping: Database connection error"
                    }
                }
            }
        }
    }
)
async def create_mapping(
    mapping_data: MappingCreateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    mapping_service: Annotated[MappingService, Depends(lambda: MappingService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
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


@router.put(
    "/{mapping_id}",
    response_model=MappingDetailResponse,
    summary="Update endpoint mapping",
    description="""
Update an existing endpoint-to-action mapping.

**Authorization**: Requires admin privileges to update mappings.

**Partial Updates**: You can update individual fields (path_pattern, method, action_id, description)
without affecting others. Provide only the fields you want to change.

**Validation**: The new path pattern and method combination must not conflict
with existing mappings (unless it's the same mapping being updated).

**Action Reference**: If updating action_id, the new action must exist.

**Use Cases**:
- Update endpoint patterns when API paths change
- Change the action associated with an endpoint
- Update descriptions for better documentation
- Administrative maintenance of authorization configuration
    """,
    responses={
        200: {
            "description": "Mapping updated successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": 1,
                        "path_pattern": "/api/v1/users/{user_id}/profile",
                        "method": "GET",
                        "action": "user:read",
                        "description": "Get detailed user profile information",
                        "created_by": "12345678901",
                        "created_at": "2024-01-15T10:30:00Z",
                        "updated_at": "2024-01-16T14:20:00Z"
                    }
                }
            }
        },
        400: {
            "description": "Bad request - Invalid action ID or conflicting mapping",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Action with ID 999 does not exist"
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
            "description": "Forbidden - Insufficient permissions to update mappings",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to update mapping 1"
                    }
                }
            }
        },
        404: {
            "description": "Mapping not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Mapping with ID 999 not found"
                    }
                }
            }
        },
        422: {
            "description": "Validation error - Invalid request data",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Validation error",
                        "errors": [
                            {
                                "loc": ["body", "method"],
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
                        "detail": "Failed to update mapping: Database connection error"
                    }
                }
            }
        }
    }
)
async def update_mapping(
    mapping_id: int,
    mapping_data: MappingUpdateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    mapping_service: Annotated[MappingService, Depends(lambda: MappingService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
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


@router.delete(
    "/{mapping_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete endpoint mapping",
    description="""
Delete an endpoint-to-action mapping from the system.

**Authorization**: Requires admin privileges to delete mappings.

**Impact**: Deleting a mapping will remove authorization requirements for the
corresponding endpoint. Requests to that endpoint will no longer be checked
against the associated action.

**Idempotent Operation**: Attempting to delete a non-existent mapping returns
success (204) for idempotent behavior.

**Use Cases**:
- Remove authorization for deprecated endpoints
- Clean up unused or incorrect mappings
- Administrative maintenance of authorization configuration

**Warning**: Ensure the endpoint should no longer require authorization before
deleting its mapping.
    """,
    responses={
        204: {
            "description": "Mapping deleted successfully"
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
            "description": "Forbidden - Insufficient permissions to delete mappings",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied to delete mapping 1"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to delete mapping: Database connection error"
                    }
                }
            }
        }
    }
)
async def delete_mapping(
    mapping_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    mapping_service: Annotated[MappingService, Depends(lambda: MappingService())],
    cerbos_service: Annotated[CerbosService, Depends(lambda: CerbosService())],
    user_service: Annotated[UserService, Depends(lambda: UserService())],
):
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


@router.get(
    "/list",
    response_model=list[MappingDetailResponse],
    summary="List all endpoint mappings",
    description="""
Retrieve a list of all endpoint-to-action mappings with optional filtering.

**Authorization**: All authenticated users can list mappings.

**Filtering**: Use the action_filter parameter to show only mappings for
a specific action (exact match on action name).

**Management Interface**: This endpoint is designed for administrative
interfaces and configuration management tools.

**Use Cases**:
- Display current authorization configuration
- Administrative overview of endpoint mappings
- Audit and compliance reporting
- Integration with external configuration management
- Troubleshooting authorization issues
    """,
    responses={
        200: {
            "description": "Mappings retrieved successfully",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "id": 1,
                            "path_pattern": "/api/v1/users/{user_id}",
                            "method": "GET",
                            "action": "user:read",
                            "description": "Get user profile information",
                            "created_by": "12345678901",
                            "created_at": "2024-01-15T10:30:00Z",
                            "updated_at": None
                        },
                        {
                            "id": 2,
                            "path_pattern": "/api/v1/groups",
                            "method": "POST",
                            "action": "group:create",
                            "description": "Create new group",
                            "created_by": "12345678901",
                            "created_at": "2024-01-15T11:00:00Z",
                            "updated_at": "2024-01-16T09:15:00Z"
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
                        "detail": "Failed to list mappings: Database connection error"
                    }
                }
            }
        }
    }
)
async def list_mappings(
    _current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    mapping_service: Annotated[MappingService, Depends(lambda: MappingService())],
    action_filter: Annotated[
        str | None, Query(description="Filter mappings by specific action name (exact match)", example="user:read")
    ] = None,
):
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
