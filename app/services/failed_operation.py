"""
Failed operation service for managing operation retries.
Implements retry logic for failed Cerbos operations.
"""

from datetime import datetime, timedelta
from typing import Any

from opentelemetry import trace
from sqlalchemy.orm import Session

from app.models import FailedOperation
from app.services.base import BaseService


class FailedOperationService(BaseService):
    """Service for managing failed operations and retries."""

    def __init__(self):
        super().__init__("failed_operation")

    def log_failed_operation(
        self,
        db: Session,
        operation_type: str,
        operation_data: dict[str, Any],
        error_message: str,
        error_details: dict[str, Any] | None = None,
        max_retries: int = 5,
    ) -> FailedOperation:
        """
        Log a failed operation for later retry.

        Args:
            db: Database session
            operation_type: Type of operation (e.g., "cerbos_policy_push")
            operation_data: Data needed to retry the operation
            error_message: Human-readable error message
            error_details: Additional error details (stack trace, etc.)
            max_retries: Maximum number of retry attempts

        Returns:
            The created FailedOperation record
        """
        with self.trace_operation(
            "log_failed_operation",
            {
                "operation_type": operation_type,
                "error_message": error_message[:100],  # Truncate for tracing
            },
        ) as span:
            try:
                # Calculate initial next retry time (30 seconds from now)
                next_retry_at = datetime.utcnow() + timedelta(seconds=30)

                failed_op = FailedOperation(
                    operation_type=operation_type,
                    operation_data=operation_data,
                    error_message=error_message,
                    error_details=error_details,
                    max_retries=max_retries,
                    status="pending",
                    next_retry_at=next_retry_at,
                )

                db.add(failed_op)
                db.commit()
                db.refresh(failed_op)

                span.set_attribute("failed_operation.id", failed_op.id)
                span.set_attribute("failed_operation.logged", True)

                return failed_op

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("failed_operation.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()
                raise

    def mark_operation_succeeded(
        self, db: Session, operation_id: int
    ) -> bool:
        """
        Mark a failed operation as succeeded.
        Used when an operation succeeds on retry.
        """
        with self.trace_operation(
            "mark_operation_succeeded", {"operation_id": operation_id}
        ) as span:
            try:
                failed_op = db.query(FailedOperation).filter(
                    FailedOperation.id == operation_id
                ).first()

                if not failed_op:
                    span.set_attribute("operation.found", False)
                    return False

                failed_op.status = "succeeded"
                failed_op.succeeded_at = datetime.utcnow()
                db.commit()

                span.set_attribute("operation.found", True)
                span.set_attribute("operation.marked_succeeded", True)

                return True

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("operation.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()
                raise

    def get_pending_retries(
        self, db: Session, limit: int = 50
    ) -> list[FailedOperation]:
        """
        Get failed operations that are ready for retry.
        """
        with self.trace_operation(
            "get_pending_retries", {"limit": limit}
        ) as span:
            try:
                now = datetime.utcnow()

                operations = (
                    db.query(FailedOperation)
                    .filter(
                        FailedOperation.status.in_(["pending", "retrying"]),
                        FailedOperation.retry_count < FailedOperation.max_retries,
                        (FailedOperation.next_retry_at.is_(None)) |
                        (FailedOperation.next_retry_at <= now)
                    )
                    .order_by(FailedOperation.failed_at)
                    .limit(limit)
                    .all()
                )

                span.set_attribute("operations.count", len(operations))
                return operations

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("operation.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def cleanup_old_operations(
        self, db: Session, days_old: int = 30
    ) -> int:
        """
        Clean up old completed or permanently failed operations.
        Returns the number of operations cleaned up.
        """
        with self.trace_operation(
            "cleanup_old_operations", {"days_old": days_old}
        ) as span:
            try:
                cutoff_date = datetime.utcnow() - timedelta(days=days_old)

                # Delete old succeeded or permanently failed operations
                deleted_count = (
                    db.query(FailedOperation)
                    .filter(
                        FailedOperation.status.in_(["succeeded", "failed"]),
                        FailedOperation.failed_at < cutoff_date
                    )
                    .delete(synchronize_session=False)
                )

                db.commit()

                span.set_attribute("operations.deleted", deleted_count)
                return deleted_count

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("operation.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()
                raise
