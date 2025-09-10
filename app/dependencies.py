"""
FastAPI dependencies for authentication and user management.
Implements authentication dependencies with auto-user creation.
"""

from typing import Annotated, Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.services.auth import AuthService
from app.services.user import UserService

# Security scheme for JWT/API token authentication
security = HTTPBearer()


def get_auth_service() -> AuthService:
    """Get authentication service instance."""
    return AuthService()


def get_user_service() -> UserService:
    """Get user service instance."""
    return UserService()


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: Annotated[Session, Depends(get_db)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    user_service: Annotated[UserService, Depends(get_user_service)],
) -> User:
    """
    Get current authenticated user with JWT authentication and auto-user creation.
    Implements the complete authentication flow from SPEC.md Section 5.1.
    """
    # Build authorization header
    auth_header = f"{credentials.scheme} {credentials.credentials}"

    # Authenticate request
    auth_result = auth_service.authenticate_request(auth_header)

    if not auth_result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Handle static API token authentication
    if auth_result.get("type") == "static_api":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT token required for this endpoint",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create or get user from JWT payload
    try:
        user = user_service.get_or_create_user(db, auth_result)
        return user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"User creation failed: {str(e)}",
        )


def get_api_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: Annotated[Session, Depends(get_db)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    user_service: Annotated[UserService, Depends(get_user_service)],
) -> dict[str, Any]:
    """
    Get authenticated user/client for API endpoints (supports both JWT and static tokens).
    Used for mapping endpoints that adapters call with static tokens.
    """
    # Build authorization header
    auth_header = f"{credentials.scheme} {credentials.credentials}"

    # Authenticate request
    auth_result = auth_service.authenticate_request(auth_header)

    if not auth_result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Handle static API token authentication
    if auth_result.get("type") == "static_api":
        return {
            "type": "static_api",
            "valid": True,
            "subject": "system:api_client",
            "roles": ["api_client"],
        }

    # Handle JWT authentication with auto-user creation
    try:
        user = user_service.get_or_create_user(db, auth_result)
        user_roles = user_service.get_user_roles(db, user)

        return {
            "type": "jwt",
            "user": user,
            "subject": user.subject,
            "roles": user_roles,
            "jwt_payload": auth_result,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"User authentication failed: {str(e)}",
        )


def get_current_user_with_roles(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    user_service: Annotated[UserService, Depends(get_user_service)],
) -> dict[str, Any]:
    """Get current user with their roles aggregated."""
    roles = user_service.get_user_roles(db, current_user)
    groups = user_service.get_user_groups(db, current_user)

    return {
        "user": current_user,
        "subject": current_user.subject,
        "roles": roles,
        "groups": groups,
    }
