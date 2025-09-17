"""
Action management API endpoints.
Implements action CRUD operations with proper authorization and auditing.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
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
    """Request model for creating a new action."""

    name: str = Field(
        ...,
        description="Unique name for the action (lowercase letters, numbers, underscores, and colons only)",
        example="user:read",
        min_length=1,
        max_length=100,
        pattern="^[a-z0-9_:]+$"
    )
    description: str = Field(
        ...,
        description="Human-readable description of the action's purpose",
        example="Read user information",
        min_length=1,
        max_length=500
    )

    class Config:
        json_schema_extra = {
            "example": {
                "name": "user:read",
                "description": "Read user information"
            }
        }


class ActionUpdateRequest(BaseModel):
    """Request model for updating an existing action."""

    name: str | None = Field(
        None,
        description="Updated name for the action",
        example="user:read",
        min_length=1,
        max_length=100,
        pattern="^[a-zA-Z0-9_:-]+$"
    )
    description: str | None = Field(
        None,
        description="Updated description of the action's purpose",
        example="Read user information and profile data",
        min_length=1,
        max_length=500
    )

    class Config:
        json_schema_extra = {
            "example": {
                "name": "user:read",
                "description": "Read user information and profile data"
            }
        }


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
    endpoint_count: int = Field(
        default=0,
        description="Number of API endpoints mapped to this action",
        example=3
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "name": "user:read",
                "description": "Read user information",
                "endpoint_count": 3
            }
        }


class ActionListResponse(BaseModel):
    """Response model for paginated action lists."""

    actions: list[ActionResponse] = Field(
        ...,
        description="List of actions for the current page"
    )
    total: int = Field(
        ...,
        description="Total number of actions in the system",
        example=25
    )
    skip: int = Field(
        ...,
        description="Number of actions skipped (pagination offset)",
        example=0
    )
    limit: int = Field(
        ...,
        description="Maximum number of actions per page",
        example=50
    )

    class Config:
        json_schema_extra = {
            "example": {
                "actions": [
                    {
                        "id": 1,
                        "name": "user:read",
                        "description": "Read user information",
                        "endpoint_count": 3
                    },
                    {
                        "id": 2,
                        "name": "group:create",
                        "description": "Create new groups",
                        "endpoint_count": 1
                    }
                ],
                "total": 25,
                "skip": 0,
                "limit": 50
            }
        }


def get_action_service() -> ActionService:
    """Dependency to get ActionService instance."""
    return ActionService()


def get_cerbos_service() -> CerbosService:
    """Dependency to get CerbosService instance."""
    return CerbosService()


def get_user_service() -> UserService:
    """Dependency to get UserService instance."""
    return UserService()


@router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
    response_model=ActionResponse,
    summary="Create a new action",
    description="""
Create a new action that can be used in authorization policies and endpoint mappings.

**Actions**: Define granular permissions available in the system. Examples include
`user:read`, `group:create`, `data:export`, etc.

**Authorization**: Requires admin privileges to create actions.

**Naming Convention**: Use colon-separated format like `resource:operation`
(e.g., `user:read`, `group:create`, `data:export`).

**Use Cases**:
- Define new permissions for application features
- Create fine-grained access controls
- Integrate with external authorization systems
- Map API endpoints to specific actions

**Endpoint Mapping**: Actions can be mapped to API endpoints using the mappings API.
    """,
    responses={
        201: {
            "description": "Action created successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": 1,
                        "name": "user:read",
                        "description": "Read user information",
                        "endpoint_count": 0
                    }
                }
            }
        },
        400: {
            "description": "Bad request - Invalid input data or duplicate action name",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Action with name 'user:read' already exists"
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
            "description": "Forbidden - Insufficient permissions to create actions",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Insufficient permissions to create actions"
                    }
                }
            }
        },
        422: {
            "description": "Validation error - Invalid action data format",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Validation error",
                        "errors": [
                            {
                                "loc": ["body", "name"],
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
                        "detail": "Failed to create action: Database connection error"
                    }
                }
            }
        }
    }
)
async def create_action(
    action_data: ActionCreateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    action_service: Annotated[ActionService, Depends(get_action_service)],
    cerbos_service: Annotated[CerbosService, Depends(get_cerbos_service)],
    user_service: Annotated[UserService, Depends(get_user_service)],
):
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

        # Invalidate policy version to trigger near real-time sync
        from app.services.policy_invalidator import invalidate_policy_version
        invalidate_policy_version(db)

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


@router.get(
    "/",
    response_model=ActionListResponse,
    summary="List all actions",
    description="""
Retrieve a paginated list of all actions available in the system.

**Authorization**: All authenticated users can list actions.

**Pagination**: Use `skip` and `limit` parameters to control pagination.
Maximum limit is 100 actions per request.

**Action Information**: Each action includes its name, description, and the
number of API endpoints currently mapped to it.

**Use Cases**:
- Display available actions in administrative interfaces
- Integration with external authorization systems
- Action selection during endpoint mapping configuration
- Audit and compliance reporting
- Permission management workflows
    """,
    responses={
        200: {
            "description": "Actions retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "actions": [
                            {
                                "id": 1,
                                "name": "user:read",
                                "description": "Read user information",
                                "endpoint_count": 3
                            },
                            {
                                "id": 2,
                                "name": "group:create",
                                "description": "Create new groups",
                                "endpoint_count": 1
                            }
                        ],
                        "total": 25,
                        "skip": 0,
                        "limit": 50
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
        422: {
            "description": "Validation error - Invalid pagination parameters",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Validation error",
                        "errors": [
                            {
                                "loc": ["query", "limit"],
                                "msg": "ensure this value is less than or equal to 100",
                                "type": "value_error.number.not_le"
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
                        "detail": "Failed to list actions: Database connection error"
                    }
                }
            }
        }
    }
)
async def list_actions(
    _current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    action_service: Annotated[ActionService, Depends(get_action_service)],
    skip: Annotated[int, Query(ge=0, description="Number of actions to skip (pagination offset)", example=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100, description="Maximum number of actions to return", example=50)] = 50,
):
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


@router.get(
    "/{action_id}",
    response_model=ActionResponse,
    summary="Get action by ID",
    description="""
Retrieve detailed information about a specific action by its ID.

**Authorization**: All authenticated users can read action information.

**Action Details**: Returns the action's name, description, and number of
API endpoints currently mapped to this action.

**Use Cases**:
- Display action details in administrative interfaces
- Validate action existence before creating mappings
- Integration with external systems
- Audit and compliance workflows
    """,
    responses={
        200: {
            "description": "Action information retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": 1,
                        "name": "user:read",
                        "description": "Read user information",
                        "endpoint_count": 3
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
        404: {
            "description": "Action not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Action with ID 999 not found"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to get action: Database connection error"
                    }
                }
            }
        }
    }
)
async def get_action(
    action_id: int,
    _current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    action_service: Annotated[ActionService, Depends(get_action_service)],
):
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


@router.put(
    "/{action_id}",
    response_model=ActionResponse,
    summary="Update action",
    description="""
Update an existing action's name and/or description.

**Authorization**: Requires admin privileges to update actions.

**Partial Updates**: You can update just the name, just the description, or both.
Provide only the fields you want to update.

**Impact**: Updating an action name may affect existing endpoint mappings and
authorization policies that reference this action.

**Use Cases**:
- Refine action descriptions for better clarity
- Rename actions to follow updated naming conventions
- Administrative maintenance of the action catalog
    """,
    responses={
        200: {
            "description": "Action updated successfully",
            "content": {
                "application/json": {
                    "example": {
                        "id": 1,
                        "name": "user:read",
                        "description": "Read user information and profile data",
                        "endpoint_count": 3
                    }
                }
            }
        },
        400: {
            "description": "Bad request - Invalid input data or duplicate action name",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Action with name 'user:read' already exists"
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
            "description": "Forbidden - Insufficient permissions to update actions",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Insufficient permissions to update actions"
                    }
                }
            }
        },
        404: {
            "description": "Action not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Action with ID 999 not found"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to update action: Database connection error"
                    }
                }
            }
        }
    }
)
async def update_action(
    action_id: int,
    action_data: ActionUpdateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    action_service: Annotated[ActionService, Depends(get_action_service)],
    cerbos_service: Annotated[CerbosService, Depends(get_cerbos_service)],
    user_service: Annotated[UserService, Depends(get_user_service)],
):
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


@router.delete(
    "/{action_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete action",
    description="""
Delete an action from the system.

**Authorization**: Requires admin privileges to delete actions.

**Impact**: Deleting an action will also remove all endpoint mappings that
reference this action. This may affect authorization policies.

**Cascading Deletion**: The system will automatically clean up related
mappings and update authorization policies.

**Use Cases**:
- Remove obsolete actions
- Clean up unused permissions
- Administrative maintenance of the action catalog

**Warning**: This operation cannot be undone. Ensure the action is no longer
needed before deletion.
    """,
    responses={
        204: {
            "description": "Action deleted successfully"
        },
        400: {
            "description": "Bad request - Action cannot be deleted (e.g., still in use)",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Cannot delete action: still referenced by active mappings"
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
            "description": "Forbidden - Insufficient permissions to delete actions",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Insufficient permissions to delete actions"
                    }
                }
            }
        },
        404: {
            "description": "Action not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Action with ID 999 not found"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to delete action: Database connection error"
                    }
                }
            }
        }
    }
)
async def delete_action(
    action_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    action_service: Annotated[ActionService, Depends(get_action_service)],
    cerbos_service: Annotated[CerbosService, Depends(get_cerbos_service)],
    user_service: Annotated[UserService, Depends(get_user_service)],
):
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

        # Invalidate policy version to trigger near real-time sync
        from app.services.policy_invalidator import invalidate_policy_version
        invalidate_policy_version(db)

        return  # 204 No Content

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete action: {str(e)}",
        )
