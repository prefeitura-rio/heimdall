"""
Background tasks entry point for Heimdall Admin Service.
Implements reconciliation and sync retry tasks using APScheduler.
"""

import asyncio
import signal
import sys
from datetime import datetime, timedelta
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from dotenv import load_dotenv
from opentelemetry import trace

# Load environment variables from .env file before importing app modules
load_dotenv()

# Import app modules after load_dotenv() to ensure environment is set
from app.database import get_db_session  # noqa: E402
from app.logging_config import (  # noqa: E402
    get_structured_logger,
    setup_structured_logging,
)
from app.models import FailedOperation, User  # noqa: E402
from app.services.audit import AuditService  # noqa: E402
from app.services.base import BaseService  # noqa: E402
from app.services.cerbos import CerbosService  # noqa: E402
from app.services.user import UserService  # noqa: E402
from app.settings import settings, validate_environment  # noqa: E402
from app.tracing import setup_tracing  # noqa: E402

# Configure structured logging
setup_structured_logging()
logger = get_structured_logger(__name__)


class BackgroundTaskService(BaseService):
    """Service for managing background tasks with OpenTelemetry tracing."""

    def __init__(self):
        super().__init__("background_tasks")
        self.scheduler = AsyncIOScheduler()
        self.cerbos_service = CerbosService()
        self.user_service = UserService()
        self.audit_service = AuditService()

        # Configuration from centralized settings
        self.reconcile_interval = settings.get_reconcile_interval()
        self.sync_retry_interval = settings.get_sync_retry_interval()

        # Shutdown flag
        self.shutdown_requested = False

        # Track last known policy version for efficient change detection
        self.last_known_policy_version = None

    async def reconcile_cerbos_policies(self) -> None:
        """
        Reconciliation task that walks all users and ensures Cerbos policies reflect DB state.
        Uses change detection to only sync when policy-relevant data has changed.
        Implements reconciliation as specified in SPEC.md Section 3.6.
        """
        with self.trace_operation(
            "reconcile_cerbos_policies",
            {"task.type": "reconciliation", "task.scheduled": True},
        ) as span:
            try:
                logger.log_operation(
                    level=20,  # INFO
                    message="Starting Cerbos policy reconciliation",
                    operation="reconcile_start",
                )

                # Get database session
                session = get_db_session()

                try:
                    # Check if policy version has changed (much more efficient than hash-based approach)
                    from app.services.policy_version_tracker import PolicyVersionTracker
                    version_tracker = PolicyVersionTracker()

                    # Ensure settings table exists
                    version_tracker.create_settings_table_if_not_exists(session)

                    has_changed = version_tracker.has_version_changed(session, self.last_known_policy_version)
                    span.set_attribute("reconciliation.version_changed", has_changed)

                    if not has_changed:
                        logger.log_operation(
                            level=20,  # INFO
                            message="No policy version changes detected, skipping reconciliation",
                            operation="reconcile_skipped",
                        )
                        span.set_attribute("reconciliation.skipped", True)
                        return

                    logger.log_operation(
                        level=20,  # INFO
                        message="Policy version changes detected, starting full reconciliation",
                        operation="reconcile_changes_detected",
                    )

                    # Get all users from database
                    users = session.query(User).all()
                    span.set_attribute("reconciliation.total_users", len(users))

                    users_processed = 0
                    users_updated = 0
                    users_failed = 0

                    for user in users:
                        try:
                            # Get user's current roles from database
                            user_roles = self.user_service.get_user_roles(session, user)

                            # Update Cerbos policy for this user
                            if user_roles:
                                policy_pushed = self.cerbos_service.push_user_policy(
                                    user_subject=user.subject, user_roles=user_roles
                                )
                                if policy_pushed:
                                    users_updated += 1
                                else:
                                    users_failed += 1
                                    logger.log_operation(
                                        level=30,  # WARNING
                                        message="Failed to update policy for user",
                                        operation="reconcile_policy_update_failed",
                                        extra_fields={"user_subject": user.subject},
                                    )
                            else:
                                # User has no roles, delete their policy if it exists
                                self.cerbos_service.delete_user_policy(user.subject)
                                users_updated += 1

                            users_processed += 1

                        except Exception as e:
                            users_failed += 1
                            logger.log_operation(
                                level=50,  # ERROR
                                message="Error processing user during reconciliation",
                                operation="reconcile_user_error",
                                extra_fields={
                                    "user_subject": user.subject,
                                    "error": str(e),
                                    "exception_type": type(e).__name__,
                                },
                            )
                            span.record_exception(e)

                    # Log reconciliation results
                    span.set_attribute(
                        "reconciliation.users_processed", users_processed
                    )
                    span.set_attribute("reconciliation.users_updated", users_updated)
                    span.set_attribute("reconciliation.users_failed", users_failed)

                    # Audit the reconciliation operation
                    self.audit_service.safe_log_operation(
                        db=session,
                        actor_subject="system:background_tasks",
                        operation="reconcile_cerbos_policies",
                        target_type="system",
                        target_id="cerbos_policies",
                        request_payload={"interval_seconds": self.reconcile_interval},
                        result={
                            "total_users": len(users),
                            "users_processed": users_processed,
                            "users_updated": users_updated,
                            "users_failed": users_failed,
                        },
                        success=users_failed == 0,
                    )

                    logger.log_operation(
                        level=20,  # INFO
                        message="Reconciliation completed",
                        operation="reconcile_complete",
                        extra_fields={
                            "users_processed": users_processed,
                            "users_updated": users_updated,
                            "users_failed": users_failed,
                        },
                    )

                    # Update last known version if reconciliation was successful (no failures)
                    if users_failed == 0:
                        try:
                            current_version = version_tracker.get_current_version(session)
                            self.last_known_policy_version = current_version
                            span.set_attribute("reconciliation.version_updated", True)
                            logger.log_operation(
                                level=20,  # INFO
                                message=f"Policy version marked as synced: {current_version[:8]}",
                                operation="reconcile_version_synced",
                            )
                        except Exception as version_error:
                            logger.log_operation(
                                level=30,  # WARNING
                                message="Error updating synced policy version",
                                operation="reconcile_version_error",
                                extra_fields={"error": str(version_error)},
                            )
                    else:
                        logger.log_operation(
                            level=30,  # WARNING
                            message="Reconciliation had failures, not updating version",
                            operation="reconcile_had_failures",
                        )

                finally:
                    session.close()

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("reconciliation.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                logger.log_operation(
                    level=50,  # ERROR
                    message="Reconciliation failed",
                    operation="reconcile_failed",
                    extra_fields={"error": str(e), "exception_type": type(e).__name__},
                )

    async def retry_failed_syncs(self) -> None:
        """
        Sync retry task that handles failed Cerbos operations with exponential backoff.
        Implements sync retry logic as specified in SPEC.md Section 3.6.
        """
        with self.trace_operation(
            "retry_failed_syncs", {"task.type": "sync_retry", "task.scheduled": True}
        ) as span:
            try:
                logger.log_operation(
                    level=20,  # INFO
                    message="Starting failed sync retry",
                    operation="sync_retry_start",
                )

                # Get database session
                session = get_db_session()

                try:
                    # Query failed operations that are ready for retry
                    now = datetime.utcnow()
                    failed_operations = (
                        session.query(FailedOperation)
                        .filter(
                            FailedOperation.status.in_(["pending", "retrying"]),
                            FailedOperation.retry_count < FailedOperation.max_retries,
                            (FailedOperation.next_retry_at.is_(None)) |
                            (FailedOperation.next_retry_at <= now)
                        )
                        .order_by(FailedOperation.failed_at)
                        .limit(50)  # Process max 50 operations per run
                        .all()
                    )

                    operations_found = len(failed_operations)
                    operations_retried = 0
                    operations_succeeded = 0
                    operations_permanently_failed = 0

                    span.set_attribute("sync_retry.operations_found", operations_found)

                    for failed_op in failed_operations:
                        try:
                            # Update status to retrying
                            failed_op.status = "retrying"
                            failed_op.last_attempted_at = now
                            failed_op.retry_count += 1
                            session.commit()

                            # Perform the retry based on operation type
                            success = await self._retry_operation(failed_op, session)
                            operations_retried += 1

                            if success:
                                # Mark as succeeded
                                failed_op.status = "succeeded"
                                failed_op.succeeded_at = now
                                operations_succeeded += 1
                                logger.log_operation(
                                    level=20,  # INFO
                                    message="Failed operation retry succeeded",
                                    operation="retry_operation_success",
                                    extra_fields={
                                        "operation_id": failed_op.id,
                                        "operation_type": failed_op.operation_type,
                                        "retry_count": failed_op.retry_count,
                                    },
                                )
                            else:
                                # Calculate next retry time with exponential backoff
                                if failed_op.retry_count >= failed_op.max_retries:
                                    # Mark as permanently failed
                                    failed_op.status = "failed"
                                    operations_permanently_failed += 1
                                    logger.log_operation(
                                        level=40,  # ERROR
                                        message="Failed operation permanently failed after max retries",
                                        operation="retry_operation_max_retries",
                                        extra_fields={
                                            "operation_id": failed_op.id,
                                            "operation_type": failed_op.operation_type,
                                            "retry_count": failed_op.retry_count,
                                            "max_retries": failed_op.max_retries,
                                        },
                                    )
                                else:
                                    # Schedule next retry with exponential backoff
                                    backoff_seconds = min(
                                        300,  # Max 5 minutes
                                        30 * (2 ** (failed_op.retry_count - 1))
                                    )
                                    failed_op.next_retry_at = now + timedelta(seconds=backoff_seconds)
                                    failed_op.status = "pending"
                                    logger.log_operation(
                                        level=30,  # WARNING
                                        message="Failed operation retry failed, scheduled for retry",
                                        operation="retry_operation_failed",
                                        extra_fields={
                                            "operation_id": failed_op.id,
                                            "operation_type": failed_op.operation_type,
                                            "retry_count": failed_op.retry_count,
                                            "next_retry_in_seconds": backoff_seconds,
                                        },
                                    )

                            session.commit()

                        except Exception as retry_error:
                            session.rollback()
                            logger.log_operation(
                                level=50,  # ERROR
                                message="Error during operation retry",
                                operation="retry_operation_error",
                                extra_fields={
                                    "operation_id": failed_op.id,
                                    "operation_type": failed_op.operation_type,
                                    "error": str(retry_error),
                                    "exception_type": type(retry_error).__name__,
                                },
                            )
                            span.record_exception(retry_error)

                    span.set_attribute("sync_retry.operations_retried", operations_retried)
                    span.set_attribute("sync_retry.operations_succeeded", operations_succeeded)
                    span.set_attribute("sync_retry.operations_permanently_failed", operations_permanently_failed)

                    # Audit the sync retry operation
                    self.audit_service.safe_log_operation(
                        db=session,
                        actor_subject="system:background_tasks",
                        operation="retry_failed_syncs",
                        target_type="system",
                        target_id="failed_syncs",
                        request_payload={"interval_seconds": self.sync_retry_interval},
                        result={
                            "operations_found": operations_found,
                            "operations_retried": operations_retried,
                            "operations_succeeded": operations_succeeded,
                            "operations_permanently_failed": operations_permanently_failed,
                        },
                        success=True,
                    )

                    logger.log_operation(
                        level=20,  # INFO
                        message="Sync retry completed",
                        operation="sync_retry_complete",
                        extra_fields={
                            "operations_found": operations_found,
                            "operations_retried": operations_retried,
                            "operations_succeeded": operations_succeeded,
                            "operations_permanently_failed": operations_permanently_failed,
                        },
                    )

                finally:
                    session.close()

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("sync_retry.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                logger.log_operation(
                    level=50,  # ERROR
                    message="Sync retry failed",
                    operation="sync_retry_failed",
                    extra_fields={"error": str(e), "exception_type": type(e).__name__},
                )

    def setup_scheduler(self) -> None:
        """Setup APScheduler with reconciliation and sync retry tasks."""
        logger.log_operation(
            level=20,  # INFO
            message="Setting up background task scheduler",
            operation="scheduler_setup",
        )

        # Add reconciliation task
        self.scheduler.add_job(
            self.reconcile_cerbos_policies,
            trigger=IntervalTrigger(seconds=self.reconcile_interval),
            id="reconcile_cerbos_policies",
            name="Reconcile Cerbos Policies",
            replace_existing=True,
            max_instances=1,  # Ensure only one instance runs at a time
        )

        # Add sync retry task
        self.scheduler.add_job(
            self.retry_failed_syncs,
            trigger=IntervalTrigger(seconds=self.sync_retry_interval),
            id="retry_failed_syncs",
            name="Retry Failed Syncs",
            replace_existing=True,
            max_instances=1,  # Ensure only one instance runs at a time
        )

        logger.log_operation(
            level=20,  # INFO
            message="Background tasks scheduled successfully",
            operation="scheduler_ready",
            extra_fields={
                "reconcile_interval_seconds": self.reconcile_interval,
                "sync_retry_interval_seconds": self.sync_retry_interval,
            },
        )

    def signal_handler(self, signum: int, _frame: Any) -> None:
        """Handle shutdown signals gracefully."""
        logger.log_operation(
            level=20,  # INFO
            message="Received shutdown signal, initiating graceful shutdown",
            operation="shutdown_signal",
            extra_fields={"signal_number": signum},
        )
        self.shutdown_requested = True

    async def run(self) -> None:
        """Main entry point for background tasks."""
        logger.log_operation(
            level=20,  # INFO
            message="Starting Heimdall background tasks service",
            operation="service_start",
        )

        # Validate environment configuration
        try:
            validate_environment()
            logger.log_operation(
                level=20,  # INFO
                message="Environment configuration validation successful",
                operation="config_validation",
            )
        except Exception as e:
            logger.log_operation(
                level=50,  # ERROR
                message="Environment configuration validation failed",
                operation="config_validation",
                extra_fields={"error": str(e), "exception_type": type(e).__name__},
            )
            sys.exit(1)

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        try:
            # Setup and start scheduler
            self.setup_scheduler()
            self.scheduler.start()

            logger.log_operation(
                level=20,  # INFO
                message="Background tasks service started successfully",
                operation="service_ready",
            )

            # Keep running until shutdown is requested
            while not self.shutdown_requested:
                await asyncio.sleep(1)

        except Exception as e:
            logger.log_operation(
                level=50,  # ERROR
                message="Background tasks service failed",
                operation="service_error",
                extra_fields={"error": str(e), "exception_type": type(e).__name__},
            )
            sys.exit(1)

        finally:
            logger.log_operation(
                level=20,  # INFO
                message="Shutting down background tasks service",
                operation="service_shutdown",
            )
            self.scheduler.shutdown()
            logger.log_operation(
                level=20,  # INFO
                message="Background tasks service stopped",
                operation="service_stopped",
            )

    async def start_background_tasks(self) -> None:
        """Start background tasks for FastAPI application."""
        try:
            logger.log_operation(
                level=20,  # INFO
                message="Starting background tasks scheduler",
                operation="scheduler_start",
            )

            # Setup and start scheduler
            self.setup_scheduler()
            self.scheduler.start()

            logger.log_operation(
                level=20,  # INFO
                message="Background tasks scheduler started successfully",
                operation="scheduler_started",
            )

        except Exception as e:
            logger.log_operation(
                level=50,  # ERROR
                message="Failed to start background tasks scheduler",
                operation="scheduler_start_error",
                extra_fields={"error": str(e), "exception_type": type(e).__name__},
            )
            raise

    async def stop_background_tasks(self) -> None:
        """Stop background tasks for FastAPI application."""
        try:
            logger.log_operation(
                level=20,  # INFO
                message="Stopping background tasks scheduler",
                operation="scheduler_stop",
            )

            if hasattr(self, 'scheduler') and self.scheduler:
                self.scheduler.shutdown(wait=False)

            logger.log_operation(
                level=20,  # INFO
                message="Background tasks scheduler stopped successfully",
                operation="scheduler_stopped",
            )

        except Exception as e:
            logger.log_operation(
                level=50,  # ERROR
                message="Failed to stop background tasks scheduler",
                operation="scheduler_stop_error",
                extra_fields={"error": str(e), "exception_type": type(e).__name__},
            )

    async def _retry_operation(self, failed_op: FailedOperation, session) -> bool:
        """
        Retry a failed operation based on its type.
        Returns True if the operation succeeded, False otherwise.
        """
        operation_type = failed_op.operation_type
        operation_data = failed_op.operation_data

        try:
            if operation_type == "cerbos_policy_push":
                # Retry pushing user policy to Cerbos
                return self.cerbos_service.push_user_policy(
                    user_subject=operation_data["user_subject"],
                    user_roles=operation_data["user_roles"]
                )

            elif operation_type == "cerbos_policy_delete":
                # Retry deleting user policy from Cerbos
                return self.cerbos_service.delete_user_policy(
                    user_subject=operation_data["user_subject"]
                )

            elif operation_type == "user_policy_sync":
                # Retry full user policy synchronization
                user_id = operation_data["user_id"]
                user = session.query(User).filter(User.id == user_id).first()
                if user:
                    user_roles = self.user_service.get_user_roles(session, user)
                    if user_roles:
                        return self.cerbos_service.push_user_policy(
                            user_subject=user.subject,
                            user_roles=user_roles
                        )
                    else:
                        return self.cerbos_service.delete_user_policy(user.subject)
                return False

            else:
                logger.log_operation(
                    level=40,  # ERROR
                    message="Unknown operation type for retry",
                    operation="retry_unknown_operation",
                    extra_fields={
                        "operation_id": failed_op.id,
                        "operation_type": operation_type,
                    },
                )
                return False

        except Exception as e:
            logger.log_operation(
                level=50,  # ERROR
                message="Exception during operation retry",
                operation="retry_operation_exception",
                extra_fields={
                    "operation_id": failed_op.id,
                    "operation_type": operation_type,
                    "error": str(e),
                    "exception_type": type(e).__name__,
                },
            )
            return False


async def main() -> None:
    """Main entry point for the background tasks container."""
    # Initialize OpenTelemetry tracing (optional)
    tracing_enabled = setup_tracing()

    if tracing_enabled:
        logger.log_operation(
            level=20,  # INFO
            message="OpenTelemetry tracing enabled for background tasks",
            operation="tracing_setup",
            extra_fields={"tracing_enabled": True},
        )
    else:
        logger.log_operation(
            level=20,  # INFO
            message="OpenTelemetry tracing disabled - OTEL_EXPORTER_OTLP_ENDPOINT not set",
            operation="tracing_setup",
            extra_fields={"tracing_enabled": False},
        )

    service = BackgroundTaskService()
    await service.run()


if __name__ == "__main__":
    asyncio.run(main())
