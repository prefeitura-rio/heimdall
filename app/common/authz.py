"""
Authorization denial helper for the admin routers.
SPEC.md: "If EFFECT_DENY -> return 403 to the caller and audit the attempt".
"""

from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, status

from app.services.audit import AuditService

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from app.models import User


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
