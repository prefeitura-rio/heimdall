"""
Authorization denial helper for the admin routers.
SPEC.md: "If EFFECT_DENY -> return 403 to the caller and audit the attempt".
"""

from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, status

from app.services.audit import AuditService
from app.services.cerbos import admin_action

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from app.models import User
    from app.services.cerbos import CerbosService
    from app.services.user import UserService


def forbidden(
    db: "Session",
    current_user: "User",
    operation: str,
    detail: str,
    target_type: str | None = None,
    target_id: str | None = None,
    request_payload: dict[str, Any] | None = None,
) -> HTTPException:
    """
    Write the denied attempt to admin_audit (success=false) and return the
    403 HTTPException for the caller to raise. A failure to write the audit
    entry never changes the response: the caller still gets its 403.
    """
    AuditService().log_authorization_denied(
        db=db,
        actor_subject=current_user.subject,
        operation=operation,
        reason=detail,
        target_type=target_type,
        target_id=target_id,
        request_payload=request_payload,
        actor_user_id=getattr(current_user, "id", None),
    )
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def require_admin_permission(
    db: "Session",
    current_user: "User",
    user_service: "UserService",
    cerbos_service: "CerbosService",
    action: str,
    resource_type: str,
    operation: str,
    detail: str,
    resource_attrs: dict[str, Any] | None = None,
    target_id: str | None = None,
) -> None:
    """
    Check the reserved admin action `heimdall:<action>` in Cerbos before any
    read (DEV-556), raising the audited 403 of `forbidden` when it is denied.
    """
    allowed = cerbos_service.check_permission(
        caller_subject=current_user.subject,
        caller_roles=user_service.get_user_roles(db, current_user),
        action=admin_action(action),
        resource_type=resource_type,
        resource_attrs=resource_attrs or {},
    )
    if not allowed:
        raise forbidden(
            db,
            current_user,
            operation=operation,
            detail=detail,
            target_type=resource_type,
            target_id=target_id,
        )
