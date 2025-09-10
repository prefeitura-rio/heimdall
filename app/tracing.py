"""
OpenTelemetry tracing configuration for Heimdall Admin Service.
Implements distributed tracing with gRPC OTLP exporter as specified in SPEC.md Section 6.
"""

import os
from typing import Any

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def get_service_name() -> str:
    """Get service name from environment variables."""
    return os.getenv("OTEL_SERVICE_NAME", "heimdall-admin-service")


def get_otlp_endpoint() -> str | None:
    """Get OTLP exporter endpoint from environment variables. Returns None if not set."""
    return os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")


def is_tracing_enabled() -> bool:
    """Check if OpenTelemetry tracing is enabled via environment configuration."""
    return get_otlp_endpoint() is not None


def get_resource_attributes() -> dict[str, Any]:
    """Parse resource attributes from environment variables."""
    default_attrs = f"service.name={get_service_name()},service.version=1.0.0"
    attrs_str = os.getenv("OTEL_RESOURCE_ATTRIBUTES", default_attrs)

    attrs = {}
    for pair in attrs_str.split(","):
        if "=" in pair:
            key, value = pair.split("=", 1)
            attrs[key.strip()] = value.strip()

    return attrs


def setup_tracing() -> bool:
    """
    Configure OpenTelemetry tracing with gRPC OTLP exporter.
    Only enables tracing if OTEL_EXPORTER_OTLP_ENDPOINT is set.
    Returns True if tracing was enabled, False otherwise.
    """
    if not is_tracing_enabled():
        # Set up a no-op tracer provider when tracing is disabled
        trace.set_tracer_provider(TracerProvider())
        return False

    otlp_endpoint = get_otlp_endpoint()

    # Create resource with service information
    resource = Resource.create(get_resource_attributes())

    # Set up tracer provider
    provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(provider)

    # Configure OTLP exporter
    otlp_exporter = OTLPSpanExporter(
        endpoint=otlp_endpoint,
        insecure=True,  # Use insecure connection for development
    )

    # Add batch span processor
    span_processor = BatchSpanProcessor(otlp_exporter)
    provider.add_span_processor(span_processor)

    return True


def instrument_fastapi(app) -> None:
    """Instrument FastAPI application for automatic HTTP tracing."""
    if is_tracing_enabled():
        FastAPIInstrumentor.instrument_app(app)


def instrument_sqlalchemy(engine) -> None:
    """Instrument SQLAlchemy engine for automatic database tracing."""
    if is_tracing_enabled():
        SQLAlchemyInstrumentor().instrument(engine=engine)


def get_tracer(name: str = __name__):
    """Get a tracer instance for creating custom spans."""
    return trace.get_tracer(name)


def get_current_span():
    """Get the current active span."""
    return trace.get_current_span()


def get_trace_context() -> dict[str, str]:
    """Get current trace context for logging."""
    span = get_current_span()
    if span and span.is_recording():
        span_context = span.get_span_context()
        return {
            "trace_id": format(span_context.trace_id, "032x"),
            "span_id": format(span_context.span_id, "016x"),
        }
    return {"trace_id": "", "span_id": ""}


def create_span(tracer, name: str, attributes: dict[str, Any] | None = None):
    """Create a custom span with optional attributes."""
    span = tracer.start_span(name)
    if attributes:
        for key, value in attributes.items():
            span.set_attribute(key, value)
    return span
