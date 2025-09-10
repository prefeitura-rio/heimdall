"""
Audit service for logging admin operations with OpenTelemetry tracing.
Implements comprehensive audit logging as specified in SPEC.md.
"""

from datetime import datetime
from typing import Any

from opentelemetry import trace
from sqlalchemy.orm import Session

from app.models import AdminAudit, User
from app.services.base import BaseService


class AuditService(BaseService):
    """Service for audit logging operations with distributed tracing."""

    def __init__(self):
        super().__init__("audit")

    def log_operation(
        self,
        db: Session,
        actor_subject: str,
        operation: str,
        target_type: str | None = None,
        target_id: str | None = None,
        request_payload: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        success: bool = True,
        actor_user_id: int | None = None,
    ) -> AdminAudit:
        """
        Log an admin operation to the audit table.
        Implements audit logging as specified in SPEC.md.
        """
        with self.trace_operation("log_operation", {
            "audit.actor_subject": actor_subject,
            "audit.operation": operation,
            "audit.target_type": target_type,
            "audit.target_id": target_id,
            "audit.success": success
        }) as span:
            try:
                # Get actor user ID if not provided
                if not actor_user_id and actor_subject:
                    actor_user = db.query(User).filter(User.subject == actor_subject).first()
                    actor_user_id = actor_user.id if actor_user else None

                # Create audit entry
                audit_entry = AdminAudit(
                    actor_user_id=actor_user_id,
                    actor_subject=actor_subject,
                    operation=operation,
                    target_type=target_type,
                    target_id=target_id,
                    request_payload=request_payload,
                    result=result,
                    success=success,
                    timestamp=datetime.utcnow()
                )

                db.add(audit_entry)
                db.commit()
                db.refresh(audit_entry)

                span.set_attribute("audit.entry_id", audit_entry.id)
                span.set_attribute("audit.logged", True)

                return audit_entry

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("audit.error", str(e))
                span.set_attribute("audit.logged", False)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                # Don't rollback as this might be in a different transaction
                # Log the error but don't fail the main operation
                raise

    def log_success(
        self,
        db: Session,
        actor_subject: str,
        operation: str,
        target_type: str | None = None,
        target_id: str | None = None,
        request_payload: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        actor_user_id: int | None = None,
    ) -> AdminAudit:
        """Log a successful operation."""
        return self.log_operation(
            db=db,
            actor_subject=actor_subject,
            operation=operation,
            target_type=target_type,
            target_id=target_id,
            request_payload=request_payload,
            result=result,
            success=True,
            actor_user_id=actor_user_id,
        )

    def log_failure(
        self,
        db: Session,
        actor_subject: str,
        operation: str,
        error_message: str,
        target_type: str | None = None,
        target_id: str | None = None,
        request_payload: dict[str, Any] | None = None,
        actor_user_id: int | None = None,
    ) -> AdminAudit:
        """Log a failed operation."""
        return self.log_operation(
            db=db,
            actor_subject=actor_subject,
            operation=operation,
            target_type=target_type,
            target_id=target_id,
            request_payload=request_payload,
            result={"error": error_message},
            success=False,
            actor_user_id=actor_user_id,
        )

    def log_group_operation(
        self,
        db: Session,
        actor_subject: str,
        operation: str,
        group_name: str,
        request_payload: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        success: bool = True,
        actor_user_id: int | None = None,
    ) -> AdminAudit:
        """Log a group-related operation."""
        return self.log_operation(
            db=db,
            actor_subject=actor_subject,
            operation=operation,
            target_type="group",
            target_id=f"group:{group_name}",
            request_payload=request_payload,
            result=result,
            success=success,
            actor_user_id=actor_user_id,
        )

    def log_membership_operation(
        self,
        db: Session,
        actor_subject: str,
        operation: str,
        group_name: str,
        member_subject: str,
        request_payload: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        success: bool = True,
        actor_user_id: int | None = None,
    ) -> AdminAudit:
        """Log a membership-related operation."""
        return self.log_operation(
            db=db,
            actor_subject=actor_subject,
            operation=operation,
            target_type="membership",
            target_id=f"group:{group_name}:member:{member_subject}",
            request_payload=request_payload,
            result=result,
            success=success,
            actor_user_id=actor_user_id,
        )

    def log_role_operation(
        self,
        db: Session,
        actor_subject: str,
        operation: str,
        role_name: str | None = None,
        group_name: str | None = None,
        request_payload: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        success: bool = True,
        actor_user_id: int | None = None,
    ) -> AdminAudit:
        """Log a role-related operation."""
        if group_name and role_name:
            target_id = f"group:{group_name}:role:{role_name}"
        elif role_name:
            target_id = f"role:{role_name}"
        else:
            target_id = None

        return self.log_operation(
            db=db,
            actor_subject=actor_subject,
            operation=operation,
            target_type="role",
            target_id=target_id,
            request_payload=request_payload,
            result=result,
            success=success,
            actor_user_id=actor_user_id,
        )

    def log_mapping_operation(
        self,
        db: Session,
        actor_subject: str,
        operation: str,
        mapping_id: int | None = None,
        path_pattern: str | None = None,
        method: str | None = None,
        request_payload: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        success: bool = True,
        actor_user_id: int | None = None,
    ) -> AdminAudit:
        """Log a mapping-related operation."""
        if mapping_id:
            target_id = f"mapping:{mapping_id}"
        elif path_pattern and method:
            target_id = f"mapping:{method}:{path_pattern}"
        else:
            target_id = None

        return self.log_operation(
            db=db,
            actor_subject=actor_subject,
            operation=operation,
            target_type="mapping",
            target_id=target_id,
            request_payload=request_payload,
            result=result,
            success=success,
            actor_user_id=actor_user_id,
        )

    def log_auth_operation(
        self,
        db: Session,
        actor_subject: str,
        operation: str,
        target_resource: str | None = None,
        request_payload: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        success: bool = True,
        actor_user_id: int | None = None,
    ) -> AdminAudit:
        """Log an authentication/authorization operation."""
        return self.log_operation(
            db=db,
            actor_subject=actor_subject,
            operation=operation,
            target_type="auth",
            target_id=target_resource,
            request_payload=request_payload,
            result=result,
            success=success,
            actor_user_id=actor_user_id,
        )

    def safe_log_operation(
        self,
        db: Session,
        actor_subject: str,
        operation: str,
        target_type: str | None = None,
        target_id: str | None = None,
        request_payload: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        success: bool = True,
        actor_user_id: int | None = None,
    ) -> bool:
        """
        Safely log an operation without failing if audit logging fails.
        Returns True if logging succeeded, False otherwise.
        """
        try:
            self.log_operation(
                db=db,
                actor_subject=actor_subject,
                operation=operation,
                target_type=target_type,
                target_id=target_id,
                request_payload=request_payload,
                result=result,
                success=success,
                actor_user_id=actor_user_id,
            )
            return True
        except Exception:
            # Audit logging should never fail the main operation
            # In production, this should be logged to a separate logging system
            return False

    def get_audit_entries(
        self,
        db: Session,
        actor_subject: str | None = None,
        operation: str | None = None,
        target_type: str | None = None,
        success: bool | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AdminAudit]:
        """
        Retrieve audit entries with filtering.
        For audit trail review and compliance.
        """
        with self.trace_operation("get_audit_entries", {
            "audit.actor_subject": actor_subject,
            "audit.operation": operation,
            "audit.target_type": target_type,
            "audit.success": success,
            "audit.limit": limit,
            "audit.offset": offset
        }) as span:
            try:
                query = db.query(AdminAudit)

                if actor_subject:
                    query = query.filter(AdminAudit.actor_subject == actor_subject)
                if operation:
                    query = query.filter(AdminAudit.operation == operation)
                if target_type:
                    query = query.filter(AdminAudit.target_type == target_type)
                if success is not None:
                    query = query.filter(AdminAudit.success == success)

                entries = (
                    query.order_by(AdminAudit.timestamp.desc())
                    .offset(offset)
                    .limit(limit)
                    .all()
                )

                span.set_attribute("audit.entries_found", len(entries))
                return entries

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("audit.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def _sanitize_request_payload(self, payload: dict[str, Any] | None) -> dict[str, Any] | None:
        """
        Sanitize request payload to remove sensitive information.
        Never log passwords, tokens, or other sensitive data.
        """
        if not payload:
            return None

        sanitized = payload.copy()
        sensitive_fields = ["password", "token", "secret", "key", "authorization"]

        def _sanitize_dict(d: dict[str, Any]) -> dict[str, Any]:
            result = {}
            for k, v in d.items():
                key_lower = k.lower()
                if any(field in key_lower for field in sensitive_fields):
                    result[k] = "[REDACTED]"
                elif isinstance(v, dict):
                    result[k] = _sanitize_dict(v)
                elif isinstance(v, list):
                    result[k] = [_sanitize_dict(item) if isinstance(item, dict) else item for item in v]
                else:
                    result[k] = v
            return result

        return _sanitize_dict(sanitized)
