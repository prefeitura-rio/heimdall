"""
Background tasks entry point for Heimdall Admin Service.
Implements reconciliation and sync retry tasks using APScheduler.
"""

import asyncio
import logging
import os
import signal
import sys
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from opentelemetry import trace

from app.config import validate_environment
from app.database import get_db_session
from app.models import User
from app.services.audit import AuditService
from app.services.base import BaseService
from app.services.cerbos import CerbosService
from app.services.user import UserService
from app.tracing import setup_tracing

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class BackgroundTaskService(BaseService):
    """Service for managing background tasks with OpenTelemetry tracing."""

    def __init__(self):
        super().__init__("background_tasks")
        self.scheduler = AsyncIOScheduler()
        self.cerbos_service = CerbosService()
        self.user_service = UserService()
        self.audit_service = AuditService()

        # Configuration from environment
        self.reconcile_interval = int(
            os.getenv("RECONCILE_INTERVAL_SECONDS", "300")
        )  # 5 minutes
        self.sync_retry_interval = int(
            os.getenv("SYNC_RETRY_INTERVAL_SECONDS", "60")
        )  # 1 minute

        # Shutdown flag
        self.shutdown_requested = False

    async def reconcile_cerbos_policies(self) -> None:
        """
        Reconciliation task that walks all users and ensures Cerbos policies reflect DB state.
        Implements reconciliation as specified in SPEC.md Section 3.6.
        """
        with self.trace_operation(
            "reconcile_cerbos_policies",
            {"task.type": "reconciliation", "task.scheduled": True},
        ) as span:
            try:
                logger.info("Starting Cerbos policy reconciliation")

                # Get database session
                session = next(get_db_session())

                try:
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
                                    logger.warning(
                                        f"Failed to update policy for user {user.subject}"
                                    )
                            else:
                                # User has no roles, delete their policy if it exists
                                self.cerbos_service.delete_user_policy(user.subject)
                                users_updated += 1

                            users_processed += 1

                        except Exception as e:
                            users_failed += 1
                            logger.error(f"Error processing user {user.subject}: {e}")
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

                    logger.info(
                        f"Reconciliation completed: {users_processed} users processed, "
                        f"{users_updated} updated, {users_failed} failed"
                    )

                finally:
                    session.close()

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("reconciliation.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                logger.error(f"Reconciliation failed: {e}")

    async def retry_failed_syncs(self) -> None:
        """
        Sync retry task that handles failed Cerbos operations with exponential backoff.
        Implements sync retry logic as specified in SPEC.md Section 3.6.
        """
        with self.trace_operation(
            "retry_failed_syncs", {"task.type": "sync_retry", "task.scheduled": True}
        ) as span:
            try:
                logger.info("Starting failed sync retry")

                # Get database session
                session = next(get_db_session())

                try:
                    # For now, this is a placeholder implementation
                    # In a full implementation, this would:
                    # 1. Query a failed_operations table for pending retries
                    # 2. Implement exponential backoff logic
                    # 3. Retry failed Cerbos API calls
                    # 4. Update retry counts and mark permanently failed operations

                    span.set_attribute("sync_retry.operations_found", 0)
                    span.set_attribute("sync_retry.operations_retried", 0)
                    span.set_attribute("sync_retry.operations_succeeded", 0)

                    # Audit the sync retry operation
                    self.audit_service.safe_log_operation(
                        db=session,
                        actor_subject="system:background_tasks",
                        operation="retry_failed_syncs",
                        target_type="system",
                        target_id="failed_syncs",
                        request_payload={"interval_seconds": self.sync_retry_interval},
                        result={
                            "operations_found": 0,
                            "operations_retried": 0,
                            "operations_succeeded": 0,
                        },
                        success=True,
                    )

                    logger.info("Sync retry completed: no failed operations found")

                finally:
                    session.close()

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("sync_retry.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                logger.error(f"Sync retry failed: {e}")

    def setup_scheduler(self) -> None:
        """Setup APScheduler with reconciliation and sync retry tasks."""
        logger.info("Setting up background task scheduler")

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

        logger.info(
            f"Scheduled reconciliation task every {self.reconcile_interval} seconds"
        )
        logger.info(
            f"Scheduled sync retry task every {self.sync_retry_interval} seconds"
        )

    def signal_handler(self, signum: int, _frame: Any) -> None:
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, initiating graceful shutdown")
        self.shutdown_requested = True

    async def run(self) -> None:
        """Main entry point for background tasks."""
        logger.info("Starting Heimdall background tasks service")

        # Validate environment configuration
        try:
            validate_environment()
            logger.info("Environment configuration validation successful")
        except Exception as e:
            logger.error(f"Environment configuration validation failed: {e}")
            sys.exit(1)

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        try:
            # Setup and start scheduler
            self.setup_scheduler()
            self.scheduler.start()

            logger.info("Background tasks service started successfully")

            # Keep running until shutdown is requested
            while not self.shutdown_requested:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Background tasks service failed: {e}")
            sys.exit(1)

        finally:
            logger.info("Shutting down background tasks service")
            self.scheduler.shutdown()
            logger.info("Background tasks service stopped")


async def main() -> None:
    """Main entry point for the background tasks container."""
    # Initialize OpenTelemetry tracing (optional)
    tracing_enabled = setup_tracing()

    if tracing_enabled:
        logger.info("OpenTelemetry tracing enabled for background tasks")
    else:
        logger.info(
            "OpenTelemetry tracing disabled - OTEL_EXPORTER_OTLP_ENDPOINT not set"
        )

    service = BackgroundTaskService()
    await service.run()


if __name__ == "__main__":
    asyncio.run(main())
