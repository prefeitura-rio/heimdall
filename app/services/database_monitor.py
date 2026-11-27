"""
Database performance monitoring service for Heimdall Admin Service.
Tracks query performance and logs slow queries.
"""

import time
from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import Engine

from app.logging_config import get_structured_logger

logger = get_structured_logger(__name__)


class DatabaseMonitor:
    """Database performance monitoring service."""

    def __init__(self):
        self.slow_query_threshold = 1.0  # seconds
        self.query_stats = {
            "total_queries": 0,
            "slow_queries": 0,
            "total_execution_time": 0.0,
            "average_execution_time": 0.0,
            "slowest_query_time": 0.0,
        }

    def setup_monitoring(self, engine: Engine) -> None:
        """Set up database monitoring for the given engine."""

        @event.listens_for(engine, "before_cursor_execute")
        def receive_before_cursor_execute(
            _conn, _cursor, _statement, _parameters, context, _executemany
        ):
            """Track query start time."""
            context._query_start_time = time.time()

        @event.listens_for(engine, "after_cursor_execute")
        def receive_after_cursor_execute(
            _conn, _cursor, statement, parameters, context, _executemany
        ):
            """Track query completion and log performance."""
            if hasattr(context, "_query_start_time"):
                execution_time = time.time() - context._query_start_time
                self._log_query_performance(statement, execution_time, parameters)

    def _log_query_performance(
        self, statement: str, execution_time: float, _parameters: Any = None
    ) -> None:
        """Log query performance metrics."""
        self.query_stats["total_queries"] += 1
        self.query_stats["total_execution_time"] += execution_time
        self.query_stats["average_execution_time"] = (
            self.query_stats["total_execution_time"] / self.query_stats["total_queries"]
        )

        if execution_time > self.query_stats["slowest_query_time"]:
            self.query_stats["slowest_query_time"] = execution_time

        if execution_time > self.slow_query_threshold:
            self.query_stats["slow_queries"] += 1

            # Log slow query with details
            logger.log_database_operation(
                message=f"Slow query detected: {execution_time:.3f}s",
                query_type="slow_query",
                execution_time_ms=execution_time * 1000,
            )

            # Log the actual query (be careful with sensitive data)
            safe_statement = self._sanitize_query(statement)
            logger.log_operation(
                level=30,  # WARNING
                message="Slow database query detected",
                operation="slow_query",
                extra_fields={
                    "execution_time_ms": execution_time * 1000,
                    "query_statement": safe_statement[:500],  # Truncate long queries
                    "query_type": self._classify_query(statement),
                    "slow_query_threshold_ms": self.slow_query_threshold * 1000,
                },
            )

    def _sanitize_query(self, statement: str) -> str:
        """Sanitize query statement for logging (remove sensitive data patterns)."""
        # Remove potential sensitive data patterns
        sensitive_patterns = [
            "password",
            "token",
            "secret",
            "key",
        ]

        safe_statement = statement
        for pattern in sensitive_patterns:
            if pattern in safe_statement.lower():
                # Replace values that might be sensitive
                safe_statement = safe_statement.replace("'", "'***'")
                break

        return safe_statement

    def _classify_query(self, statement: str) -> str:
        """Classify query type for monitoring."""
        statement_lower = statement.lower().strip()

        if statement_lower.startswith("select"):
            return "SELECT"
        elif statement_lower.startswith("insert"):
            return "INSERT"
        elif statement_lower.startswith("update"):
            return "UPDATE"
        elif statement_lower.startswith("delete"):
            return "DELETE"
        elif statement_lower.startswith("create"):
            return "CREATE"
        elif statement_lower.startswith("alter"):
            return "ALTER"
        elif statement_lower.startswith("drop"):
            return "DROP"
        else:
            return "OTHER"


# Global database monitor instance
_db_monitor_instance: DatabaseMonitor | None = None


def get_database_monitor() -> DatabaseMonitor:
    """Get the global database monitor instance."""
    global _db_monitor_instance
    if _db_monitor_instance is None:
        _db_monitor_instance = DatabaseMonitor()
    return _db_monitor_instance


def setup_database_monitoring(engine: Engine) -> None:
    """Set up database monitoring for the given engine."""
    monitor = get_database_monitor()
    monitor.setup_monitoring(engine)

    logger.log_operation(
        level=20,  # INFO
        message="Database monitoring enabled",
        operation="database_monitoring_setup",
        extra_fields={
            "slow_query_threshold_ms": monitor.slow_query_threshold * 1000,
            "monitoring_features": [
                "query_performance_tracking",
                "slow_query_detection",
            ],
        },
    )
