"""
Database performance monitoring service for Heimdall Admin Service.
Tracks query performance, slow queries, and database health metrics.
"""

import time
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

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

    @contextmanager
    def monitor_query(self, query_name: str) -> Generator[None, None, None]:
        """Context manager for monitoring specific query performance."""
        start_time = time.time()
        try:
            yield
        finally:
            execution_time = time.time() - start_time
            logger.log_database_operation(
                message=f"Query '{query_name}' completed",
                query_type=query_name,
                execution_time_ms=execution_time * 1000,
            )

    def get_performance_stats(self) -> dict[str, Any]:
        """Get current database performance statistics."""
        return {
            "query_stats": self.query_stats.copy(),
            "slow_query_threshold_ms": self.slow_query_threshold * 1000,
            "performance_ratios": {
                "slow_query_percentage": (
                    (
                        self.query_stats["slow_queries"]
                        / max(self.query_stats["total_queries"], 1)
                    )
                    * 100
                ),
                "average_execution_time_ms": self.query_stats["average_execution_time"]
                * 1000,
                "slowest_query_time_ms": self.query_stats["slowest_query_time"] * 1000,
            },
        }

    def check_database_health(self, db: Session) -> dict[str, Any]:
        """Check database health and performance indicators."""
        health_info = {
            "connection_status": "unknown",
            "performance_stats": self.get_performance_stats(),
            "database_size": None,
            "active_connections": None,
            "table_stats": {},
        }

        try:
            # Test basic connectivity
            with self.monitor_query("health_check"):
                result = db.execute(text("SELECT 1")).scalar()
                health_info["connection_status"] = (
                    "healthy" if result == 1 else "unhealthy"
                )

            # Get database size (PostgreSQL specific)
            try:
                with self.monitor_query("database_size"):
                    size_result = db.execute(
                        text("""
                        SELECT pg_size_pretty(pg_database_size(current_database())) as size
                    """)
                    ).fetchone()
                    if size_result:
                        health_info["database_size"] = size_result[0]
            except Exception as e:
                logger.log_operation(
                    level=30,  # WARNING
                    message="Could not retrieve database size",
                    operation="database_health_check",
                    extra_fields={"error": str(e)},
                )

            # Get active connections (PostgreSQL specific)
            try:
                with self.monitor_query("active_connections"):
                    conn_result = db.execute(
                        text("""
                        SELECT count(*) as active_connections
                        FROM pg_stat_activity
                        WHERE state = 'active'
                    """)
                    ).fetchone()
                    if conn_result:
                        health_info["active_connections"] = conn_result[0]
            except Exception as e:
                logger.log_operation(
                    level=30,  # WARNING
                    message="Could not retrieve active connections",
                    operation="database_health_check",
                    extra_fields={"error": str(e)},
                )

            # Get table statistics
            try:
                with self.monitor_query("table_stats"):
                    table_results = db.execute(
                        text("""
                        SELECT
                            schemaname,
                            tablename,
                            n_tup_ins as inserts,
                            n_tup_upd as updates,
                            n_tup_del as deletes,
                            n_live_tup as live_rows,
                            n_dead_tup as dead_rows
                        FROM pg_stat_user_tables
                        ORDER BY n_live_tup DESC
                        LIMIT 10
                    """)
                    ).fetchall()

                    health_info["table_stats"] = [
                        {
                            "schema": row[0],
                            "table": row[1],
                            "inserts": row[2],
                            "updates": row[3],
                            "deletes": row[4],
                            "live_rows": row[5],
                            "dead_rows": row[6],
                        }
                        for row in table_results
                    ]
            except Exception as e:
                logger.log_operation(
                    level=30,  # WARNING
                    message="Could not retrieve table statistics",
                    operation="database_health_check",
                    extra_fields={"error": str(e)},
                )

        except Exception as e:
            health_info["connection_status"] = "failed"
            logger.log_operation(
                level=50,  # ERROR
                message="Database health check failed",
                operation="database_health_check",
                extra_fields={"error": str(e)},
            )

        return health_info

    def suggest_optimizations(self) -> list[str]:
        """Suggest database optimizations based on performance stats."""
        suggestions = []
        stats = self.query_stats

        if stats["total_queries"] > 0:
            slow_percentage = (stats["slow_queries"] / stats["total_queries"]) * 100

            if slow_percentage > 10:
                suggestions.append(
                    f"High slow query percentage ({slow_percentage:.1f}%). "
                    "Consider adding indexes to frequently queried columns."
                )

            if stats["average_execution_time"] > 0.5:
                suggestions.append(
                    f"Average query time is high ({stats['average_execution_time']:.3f}s). "
                    "Review query patterns and consider database tuning."
                )

            if stats["slowest_query_time"] > 5.0:
                suggestions.append(
                    f"Extremely slow query detected ({stats['slowest_query_time']:.3f}s). "
                    "Investigate and optimize the slowest queries."
                )

        if not suggestions:
            suggestions.append(
                "Database performance looks good! No optimizations needed."
            )

        return suggestions


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
                "database_health_checks",
                "optimization_suggestions",
            ],
        },
    )
