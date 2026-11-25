"""
Background tasks entry point for Heimdall Admin Service.
Implements the Cerbos policy reconciliation task using APScheduler.
"""

import asyncio
import hashlib
import json
import random
import signal
import sys
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
from app.models import Action, Role, RoleAction, User  # noqa: E402
from app.services.audit import AuditService  # noqa: E402
from app.services.base import BaseService  # noqa: E402
from app.services.cache import CacheService  # noqa: E402
from app.services.cerbos import CerbosService  # noqa: E402
from app.services.health_monitor import HealthMonitor  # noqa: E402
from app.services.user import UserService  # noqa: E402
from app.settings import settings, validate_environment  # noqa: E402
from app.tracing import setup_tracing  # noqa: E402

# Configure structured logging
setup_structured_logging()
logger = get_structured_logger(__name__)

# Incremental reconciliation: per-user cache of "what we last successfully
# pushed to Cerbos", so reconcile_cerbos_policies() only calls Cerbos for
# users whose effective policy actually changed, instead of all users on
# every policy-version bump.
#
# Bump _POLICY_HASH_SCHEMA whenever the hash inputs below change, so old
# cached hashes are treated as unknown (safe -> re-push) rather than
# compared against a differently-computed value.
_POLICY_HASH_SCHEMA = "v3"  # v3: principal policy rules per admin resource (DEV-556)
_NO_POLICY_SENTINEL = "__no_policy__"
_POLICY_HASH_TTL_SECONDS = 7 * 24 * 3600  # 7 days
_POLICY_HASH_TTL_JITTER_SECONDS = 24 * 3600  # +0-1 day, avoids mass-expiry


def _role_action_fingerprint(session) -> str:
    """
    Fingerprint of the entire role -> action mapping table.

    CerbosService.build_principal_policy() resolves each user's roles into
    Cerbos rules by joining Role -> RoleAction -> Action fresh from the DB on
    every push, so a user's effective policy can change even when their own
    role list doesn't (e.g. an action gets revoked from a role they hold).
    Note: there is no immediate per-role or per-group policy sync, so this
    reconciliation loop is the ONLY path that propagates role/action mapping
    changes to Cerbos - the per-user hash below MUST be sensitive to this
    table, not just to each user's own role names, or privilege revocations
    would be silently skipped forever.

    Any role/action mapping change flips this fingerprint for every user in
    the current run, forcing a full re-push - identical to today's
    behavior for that case - while membership-only changes still invalidate
    just the affected users, which is where the performance win comes from.
    """
    rows = (
        session.query(Role.name, Action.name)
        .join(RoleAction, RoleAction.role_id == Role.id)
        .join(Action, Action.id == RoleAction.action_id)
        .all()
    )
    role_to_actions: dict[str, list[str]] = {}
    for role_name, action_name in rows:
        role_to_actions.setdefault(role_name, []).append(action_name)
    canonical = json.dumps(
        {role: sorted(actions) for role, actions in sorted(role_to_actions.items())},
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compute_policy_hash(fingerprint: str, user_roles: list[str]) -> str:
    """Hash of everything that determines this user's pushed policy content."""
    canonical = json.dumps(
        {"fp": fingerprint, "roles": sorted(user_roles)}, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _policy_hash_cache_key(user_subject: str) -> str:
    return f"policy_hash:{_POLICY_HASH_SCHEMA}:user:{user_subject}"


class BackgroundTaskService(BaseService):
    """Service for managing background tasks with OpenTelemetry tracing."""

    def __init__(self):
        super().__init__("background_tasks")
        self.scheduler = AsyncIOScheduler()
        self.cerbos_service = CerbosService()
        self.user_service = UserService()
        self.audit_service = AuditService()
        self.health_monitor = HealthMonitor()
        self.cache_service = CacheService()

        # Configuration from centralized settings
        self.reconcile_interval = settings.get_reconcile_interval()

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

                    has_changed = version_tracker.has_version_changed(
                        session, self.last_known_policy_version
                    )
                    span.set_attribute("reconciliation.version_changed", has_changed)

                    if not has_changed:
                        logger.log_operation(
                            level=20,  # INFO
                            message="No policy version changes detected, skipping reconciliation",
                            operation="reconcile_skipped",
                        )
                        span.set_attribute("reconciliation.skipped", True)
                        return

                    # Capture the version we're reconciling *against* now, before
                    # the (potentially long-running) loop below - not after it.
                    # A change that lands mid-run must still be detected on the
                    # next tick; reading the version again after the loop would
                    # silently mark that change as already synced.
                    version_at_start = version_tracker.get_current_version(session)

                    logger.log_operation(
                        level=20,  # INFO
                        message="Policy version changes detected, starting full reconciliation",
                        operation="reconcile_changes_detected",
                    )

                    # Fingerprint of the shared role->action mapping table,
                    # computed once per run (see _role_action_fingerprint
                    # docstring for why this is required for correctness).
                    fingerprint = _role_action_fingerprint(session)

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

                            cache_key = _policy_hash_cache_key(user.subject)
                            desired_hash = (
                                _compute_policy_hash(fingerprint, user_roles)
                                if user_roles
                                else _NO_POLICY_SENTINEL
                            )

                            try:
                                cached_raw = self.cache_service.redis_client.get(
                                    cache_key
                                )
                                cached_hash = (
                                    cached_raw.decode("utf-8") if cached_raw else None
                                )
                            except Exception:
                                # Cache unreadable - treat as unknown, never as
                                # "unchanged". Only a confirmed hash match may
                                # skip the Cerbos call; anything else falls
                                # through and does the work.
                                cached_hash = None

                            if cached_hash == desired_hash:
                                # Nothing relevant changed for this user since
                                # the last successful sync - skip the Cerbos
                                # call entirely.
                                users_processed += 1
                                continue

                            # Update Cerbos policy for this user
                            push_succeeded = True
                            if user_roles:
                                policy_pushed = await asyncio.to_thread(
                                    self.cerbos_service.push_user_policy,
                                    user_subject=user.subject,
                                    user_roles=user_roles,
                                )
                                if policy_pushed:
                                    users_updated += 1
                                else:
                                    push_succeeded = False
                                    users_failed += 1
                                    logger.log_operation(
                                        level=30,  # WARNING
                                        message="Failed to update policy for user",
                                        operation="reconcile_policy_update_failed",
                                        extra_fields={"user_id": user.id},
                                    )
                            else:
                                # User has no roles, delete their policy if it exists
                                await asyncio.to_thread(
                                    self.cerbos_service.delete_user_policy, user.subject
                                )
                                users_updated += 1

                            if push_succeeded:
                                # Only remember success: if the process crashes
                                # before this write, the next run just repeats
                                # a redundant (idempotent) push/delete instead
                                # of silently skipping a real one.
                                try:
                                    jitter = random.randint(
                                        0, _POLICY_HASH_TTL_JITTER_SECONDS
                                    )
                                    await asyncio.to_thread(
                                        self.cache_service.redis_client.set,
                                        cache_key,
                                        desired_hash,
                                        _POLICY_HASH_TTL_SECONDS + jitter,
                                    )
                                except Exception:
                                    # Cache write failed but the push/delete
                                    # above already succeeded - worst case is
                                    # one redundant re-push next cycle, which
                                    # is safe.
                                    pass

                            users_processed += 1

                        except Exception as e:
                            users_failed += 1
                            logger.log_operation(
                                level=50,  # ERROR
                                message="Error processing user during reconciliation",
                                operation="reconcile_user_error",
                                extra_fields={
                                    "user_id": user.id,
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
                        self.last_known_policy_version = version_at_start
                        span.set_attribute("reconciliation.version_updated", True)
                        logger.log_operation(
                            level=20,  # INFO
                            message=f"Policy version marked as synced: {version_at_start[:8]}",
                            operation="reconcile_version_synced",
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

    def setup_scheduler(self) -> None:
        """Setup APScheduler with the reconciliation and health monitoring tasks."""
        logger.log_operation(
            level=20,  # INFO
            message="Setting up background task scheduler",
            operation="scheduler_setup",
        )

        # Start health monitoring
        self.health_monitor.start_monitoring()
        logger.log_operation(
            level=20,  # INFO
            message="Health monitoring started",
            operation="health_monitor_started",
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

        logger.log_operation(
            level=20,  # INFO
            message="Background tasks scheduled successfully",
            operation="scheduler_ready",
            extra_fields={
                "reconcile_interval_seconds": self.reconcile_interval,
                "health_monitoring_enabled": True,
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

            # Stop health monitoring
            try:
                await self.health_monitor.stop_monitoring()
                logger.log_operation(
                    level=20,  # INFO
                    message="Health monitoring stopped",
                    operation="health_monitor_stopped",
                )
            except Exception as e:
                logger.log_operation(
                    level=30,  # WARNING
                    message="Error stopping health monitoring",
                    operation="health_monitor_stop_error",
                    extra_fields={"error": str(e)},
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

            # Setup and start scheduler (includes health monitoring)
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

            # Stop health monitoring
            try:
                await self.health_monitor.stop_monitoring()
                logger.log_operation(
                    level=20,  # INFO
                    message="Health monitoring stopped",
                    operation="health_monitor_stopped",
                )
            except Exception as e:
                logger.log_operation(
                    level=30,  # WARNING
                    message="Error stopping health monitoring",
                    operation="health_monitor_stop_error",
                    extra_fields={"error": str(e)},
                )

            if hasattr(self, "scheduler") and self.scheduler:
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
