"""
Structured logging configuration for Heimdall Admin Service.
Implements JSON structured logging with OpenTelemetry trace context.
"""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from opentelemetry import trace


class StructuredFormatter(logging.Formatter):
    """
    Custom JSON formatter that includes OpenTelemetry trace context.
    Implements structured logging as specified in SPEC.md Section 6.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.service_name = "heimdall-admin-service"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        # Get current span context
        span = trace.get_current_span()
        span_context = span.get_span_context()

        # Base log entry
        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
        }

        # Add trace context if available
        if span_context.is_valid:
            log_entry.update({
                "trace_id": format(span_context.trace_id, "032x"),
                "span_id": format(span_context.span_id, "016x"),
                "trace_flags": span_context.trace_flags,
            })

        # Add extra fields from record
        if hasattr(record, "extra_fields"):
            log_entry.update(record.extra_fields)

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info),
            }

        # Add operation context if available
        if hasattr(record, "operation"):
            log_entry["operation"] = record.operation

        if hasattr(record, "actor_subject"):
            log_entry["actor_subject"] = record.actor_subject

        if hasattr(record, "target"):
            log_entry["target"] = record.target

        if hasattr(record, "request_id"):
            log_entry["request_id"] = record.request_id

        if hasattr(record, "user_id"):
            log_entry["user_id"] = record.user_id

        # Add HTTP context if available
        if hasattr(record, "http_method"):
            log_entry["http"] = {
                "method": record.http_method,
                "path": getattr(record, "http_path", None),
                "status_code": getattr(record, "http_status_code", None),
                "duration_ms": getattr(record, "http_duration_ms", None),
                "user_agent": getattr(record, "http_user_agent", None),
            }

        # Add database context if available
        if hasattr(record, "db_query_type"):
            log_entry["database"] = {
                "query_type": record.db_query_type,
                "execution_time_ms": getattr(record, "db_execution_time_ms", None),
                "affected_rows": getattr(record, "db_affected_rows", None),
            }

        # Add Cerbos context if available
        if hasattr(record, "cerbos_operation"):
            log_entry["cerbos"] = {
                "operation": record.cerbos_operation,
                "response_status": getattr(record, "cerbos_response_status", None),
                "duration_ms": getattr(record, "cerbos_duration_ms", None),
                "action": getattr(record, "cerbos_action", None),
                "resource_type": getattr(record, "cerbos_resource_type", None),
            }

        return json.dumps(log_entry, ensure_ascii=False)


class StructuredLogger:
    """Helper class for structured logging with context."""

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

    def log_operation(
        self,
        level: int,
        message: str,
        operation: str | None = None,
        actor_subject: str | None = None,
        target: str | None = None,
        request_id: str | None = None,
        user_id: int | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> None:
        """Log an operation with structured context."""
        extra = {}

        if operation:
            extra["operation"] = operation
        if actor_subject:
            extra["actor_subject"] = actor_subject
        if target:
            extra["target"] = target
        if request_id:
            extra["request_id"] = request_id
        if user_id:
            extra["user_id"] = user_id
        if extra_fields:
            extra["extra_fields"] = extra_fields

        self.logger.log(level, message, extra=extra)

    def log_http_request(
        self,
        message: str,
        method: str,
        path: str,
        status_code: int,
        duration_ms: float,
        user_agent: str | None = None,
        actor_subject: str | None = None,
    ) -> None:
        """Log HTTP request with structured context."""
        extra = {
            "http_method": method,
            "http_path": path,
            "http_status_code": status_code,
            "http_duration_ms": duration_ms,
        }

        if user_agent:
            extra["http_user_agent"] = user_agent
        if actor_subject:
            extra["actor_subject"] = actor_subject

        self.logger.info(message, extra=extra)

    def log_database_operation(
        self,
        message: str,
        query_type: str,
        execution_time_ms: float,
        affected_rows: int | None = None,
    ) -> None:
        """Log database operation with structured context."""
        extra = {
            "db_query_type": query_type,
            "db_execution_time_ms": execution_time_ms,
        }

        if affected_rows is not None:
            extra["db_affected_rows"] = affected_rows

        self.logger.info(message, extra=extra)

    def log_cerbos_operation(
        self,
        message: str,
        operation: str,
        response_status: int,
        duration_ms: float,
        action: str | None = None,
        resource_type: str | None = None,
    ) -> None:
        """Log Cerbos operation with structured context."""
        extra = {
            "cerbos_operation": operation,
            "cerbos_response_status": response_status,
            "cerbos_duration_ms": duration_ms,
        }

        if action:
            extra["cerbos_action"] = action
        if resource_type:
            extra["cerbos_resource_type"] = resource_type

        self.logger.info(message, extra=extra)

    def log_auth_event(
        self,
        message: str,
        event_type: str,
        actor_subject: str | None = None,
        success: bool | None = None,
        error: str | None = None,
    ) -> None:
        """Log authentication event with structured context."""
        extra_fields = {
            "auth_event_type": event_type,
        }

        if success is not None:
            extra_fields["auth_success"] = success
        if error:
            extra_fields["auth_error"] = error

        self.log_operation(
            level=logging.INFO if success else logging.WARNING,
            message=message,
            operation="authentication",
            actor_subject=actor_subject,
            extra_fields=extra_fields,
        )


def setup_structured_logging() -> None:
    """
    Configure structured JSON logging for the application.
    Sets up formatters, handlers, and log levels.
    """
    # Create formatter
    formatter = StructuredFormatter()

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # Remove default handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add console handler with structured formatter
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    root_logger.addHandler(console_handler)

    # Set specific logger levels
    logging.getLogger("app").setLevel(logging.INFO)
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)  # Reduce SQL query noise

    # Silence health check logs in production
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_structured_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance."""
    return StructuredLogger(name)


# Module-level logger for convenience
structured_logger = get_structured_logger(__name__)
