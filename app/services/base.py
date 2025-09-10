"""
Base service class with OpenTelemetry tracing utilities.
Provides common tracing functionality for all services.
"""

from typing import Any

from app.tracing import create_span, get_tracer


class BaseService:
    """Base service class with tracing support."""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.tracer = get_tracer(f"heimdall.services.{service_name}")

    def trace_operation(
        self, operation_name: str, attributes: dict[str, Any] | None = None
    ):
        """Create a traced operation context manager."""
        span_name = f"{self.service_name}.{operation_name}"
        return create_span(self.tracer, span_name, attributes)
