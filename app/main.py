"""
FastAPI application entry point for Heimdall Admin Service.
Implements OpenTelemetry tracing setup as specified in SPEC.md Section 6.
"""

import os
import time

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from opentelemetry import trace

# Load environment variables from .env file before importing app modules
load_dotenv()

# Import app modules after load_dotenv() to ensure environment is set
from app.background_tasks import BackgroundTaskService  # noqa: E402
from app.database import engine  # noqa: E402
from app.exceptions import CerbosUnavailableError  # noqa: E402
from app.logging_config import (  # noqa: E402
    get_structured_logger,
    setup_structured_logging,
)
from app.routers import (  # noqa: E402
    actions,
    groups,
    health,
    mappings,
    memberships,
    roles,
    users,
)
from app.services.cerbos import CerbosService  # noqa: E402
from app.services.database_monitor import setup_database_monitoring  # noqa: E402
from app.services.health_monitor import HealthMonitor  # noqa: E402
from app.settings import validate_environment  # noqa: E402
from app.tracing import (  # noqa: E402
    instrument_fastapi,
    instrument_sqlalchemy,
    setup_tracing,
)

# Initialize OpenTelemetry tracing before creating the FastAPI app (optional)
tracing_enabled = setup_tracing()

# Configure structured logging
setup_structured_logging()
logger = get_structured_logger(__name__)

# Log tracing status
if tracing_enabled:
    logger.log_operation(
        level=20,  # INFO
        message="OpenTelemetry tracing enabled",
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

# Validate environment configuration on startup

try:
    validate_environment()
    logger.log_operation(
        level=20,  # INFO
        message="Environment configuration validation successful",
        operation="startup_validation",
    )
except Exception as e:
    logger.log_operation(
        level=50,  # ERROR
        message=f"Environment configuration validation failed: {e}",
        operation="startup_validation",
        extra_fields={"error": str(e)},
    )
    raise

# Initialize Cerbos policy setup
def setup_cerbos_policies():
    """Setup required Cerbos policies at application startup."""
    cerbos_service = CerbosService()

    # Try to ensure superadmin policy exists
    policy_created = cerbos_service.ensure_superadmin_policy()

    if policy_created:
        logger.log_operation(
            level=20,  # INFO
            message="Superadmin Cerbos policy created successfully",
            operation="cerbos_policy_setup",
            extra_fields={"policy_type": "superadmin", "status": "created"}
        )
    else:
        # Get policy template for manual application
        policy_template = cerbos_service.get_superadmin_policy_template()

        logger.log_operation(
            level=30,  # WARNING
            message="Could not create superadmin Cerbos policy automatically. Manual configuration required.",
            operation="cerbos_policy_setup",
            extra_fields={
                "policy_type": "superadmin",
                "status": "manual_required",
                "instructions": "Cerbos admin API is disabled. Apply the policy template manually.",
                "policy_template": policy_template
            }
        )

# Setup Cerbos policies
setup_cerbos_policies()

# Lifespan context manager for startup/shutdown events
from contextlib import asynccontextmanager  # noqa: E402


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Lifespan context manager for startup and shutdown events."""
    # Check if background tasks should be enabled
    enable_background_tasks = os.getenv("ENABLE_BACKGROUND_TASKS", "true").lower() == "true"

    # Startup
    if enable_background_tasks:
        logger.log_operation(
            level=20,  # INFO
            message="Starting background services",
            operation="startup_background_services",
        )

        # Start health monitoring
        health_monitor.start_monitoring()

        # Start background task scheduler
        await background_task_service.start_background_tasks()
    else:
        logger.log_operation(
            level=20,  # INFO
            message="Background tasks disabled via ENABLE_BACKGROUND_TASKS=false",
            operation="startup_background_services_disabled",
        )

    # Sync mappings to Redis on startup (always, regardless of background tasks)
    try:
        from app.database import get_db_session
        from app.services.mapping import MappingService

        logger.log_operation(
            level=20,  # INFO
            message="Syncing endpoint mappings to Redis",
            operation="startup_redis_mapping_sync",
        )

        mapping_service = MappingService()
        with get_db_session() as db:
            success = mapping_service.sync_all_mappings_to_redis(db)

        if success:
            logger.log_operation(
                level=20,  # INFO
                message="Redis mapping sync completed successfully",
                operation="startup_redis_mapping_sync_success",
            )
        else:
            logger.log_operation(
                level=30,  # WARNING
                message="Redis mapping sync failed",
                operation="startup_redis_mapping_sync_failed",
            )
    except Exception as e:
        logger.log_operation(
            level=40,  # ERROR
            message=f"Redis mapping sync error: {e}",
            operation="startup_redis_mapping_sync_error",
        )

    yield

    # Shutdown
    if enable_background_tasks:
        logger.log_operation(
            level=20,  # INFO
            message="Stopping background services",
            operation="shutdown_background_services",
        )

        # Stop background task scheduler
        await background_task_service.stop_background_tasks()

        # Stop health monitoring
        await health_monitor.stop_monitoring()


# Create FastAPI application
app = FastAPI(
    title="Heimdall Admin Service",
    lifespan=lifespan,
    description="""
# Heimdall Admin Service API

A comprehensive admin service for user and group management with authorization powered by Cerbos.

## Features

- **User Management**: Automatic user creation from JWT tokens with role-based access control
- **Group Management**: Create, manage, and assign users to groups with hierarchical permissions
- **Role Management**: Define and assign roles to users and groups
- **Mapping Management**: Configure API endpoint to action mappings for authorization
- **Action Management**: Define available actions for fine-grained permission control
- **Cerbos Integration**: Policy-based authorization with external Cerbos service
- **Audit Logging**: Comprehensive audit trail for all administrative operations
- **Redis Caching**: High-performance caching for frequently accessed data
    """.strip(),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "Heimdall Admin Service",
        "url": "https://github.com/your-org/heimdall",
        "email": "admin@yourorg.com"
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
)

# Add CORS middleware if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure as needed for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Add request/response logging middleware
@app.middleware("http")
async def logging_middleware(request: Request, call_next) -> Response:
    """Middleware for structured HTTP request/response logging."""
    start_time = time.time()

    # Extract user agent
    user_agent = request.headers.get("user-agent", "unknown")

    # Get actor subject from authorization if present
    actor_subject = None
    if "authorization" in request.headers:
        # This is a simplified extraction - in practice you'd parse the JWT
        actor_subject = "authenticated_user"  # Would extract from JWT

    response = await call_next(request)

    # Calculate duration
    duration_ms = (time.time() - start_time) * 1000

    # Log the request/response
    logger.log_http_request(
        message=f"{request.method} {request.url.path} -> {response.status_code}",
        method=request.method,
        path=str(request.url.path),
        status_code=response.status_code,
        duration_ms=duration_ms,
        user_agent=user_agent,
        actor_subject=actor_subject,
    )

    return response


# Instrument FastAPI for automatic HTTP tracing
instrument_fastapi(app)

# Instrument SQLAlchemy for automatic database tracing
instrument_sqlalchemy(engine)

# Setup database performance monitoring
setup_database_monitoring(engine)

# Initialize health monitor
health_monitor = HealthMonitor()

# Initialize background task service
background_task_service = BackgroundTaskService()


# Global exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with structured logging."""
    tracer = trace.get_tracer(__name__)
    with tracer.start_span("http_exception_handler") as span:
        span.set_attribute("http.status_code", exc.status_code)
        span.set_attribute("error.message", exc.detail)
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.url", str(request.url))

        logger.log_operation(
            level=40,  # WARNING level
            message="HTTP exception occurred",
            operation="http_exception",
            extra_fields={
                "status_code": exc.status_code,
                "detail": exc.detail,
                "method": request.method,
                "url": str(request.url),
                "exception_type": "HTTPException",
            },
        )

        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail, "status_code": exc.status_code},
        )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors."""
    tracer = trace.get_tracer(__name__)
    with tracer.start_span("validation_exception_handler") as span:
        span.set_attribute("http.status_code", 422)
        span.set_attribute("error.type", "validation_error")
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.url", str(request.url))

        logger.log_operation(
            level=40,  # WARNING level
            message="Request validation error",
            operation="validation_exception",
            extra_fields={
                "validation_errors": exc.errors(),
                "method": request.method,
                "url": str(request.url),
                "exception_type": "RequestValidationError",
            },
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "Validation error", "details": exc.errors()},
        )


@app.exception_handler(CerbosUnavailableError)
async def cerbos_unavailable_handler(request: Request, exc: CerbosUnavailableError):
    """Handle Cerbos service unavailable errors with 503 status."""
    tracer = trace.get_tracer(__name__)
    with tracer.start_span("cerbos_unavailable_handler") as span:
        span.set_attribute("http.status_code", 503)
        span.set_attribute("error.type", "CerbosUnavailableError")
        span.set_attribute("error.service", exc.service_name)
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.url", str(request.url))
        span.record_exception(exc)

        logger.log_operation(
            level=40,  # WARNING level - service dependency issue, not application error
            message="Authorization service unavailable",
            operation="service_unavailable",
            extra_fields={
                "service_name": exc.service_name,
                "exception_type": "CerbosUnavailableError",
                "method": request.method,
                "url": str(request.url),
                "original_error": str(exc.original_error) if exc.original_error else None,
            },
        )

        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "Authorization service temporarily unavailable",
                "status_code": 503,
                "service": exc.service_name,
                "retry_after": "Please try again in a few moments"
            },
        )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    tracer = trace.get_tracer(__name__)
    with tracer.start_span("general_exception_handler") as span:
        span.set_attribute("http.status_code", 500)
        span.set_attribute("error.type", type(exc).__name__)
        span.set_attribute("error.message", str(exc))
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.url", str(request.url))
        span.record_exception(exc)

        logger.log_operation(
            level=50,  # ERROR level
            message="Unhandled exception occurred",
            operation="general_exception",
            extra_fields={
                "exception_type": type(exc).__name__,
                "exception_message": str(exc),
                "method": request.method,
                "url": str(request.url),
                "has_traceback": True,
            },
        )

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Internal server error", "status_code": 500},
        )


# Security scheme for JWT authentication
security = HTTPBearer(
    scheme_name="JWT Bearer",
    description="JWT token from Keycloak. Format: Bearer <token>"
)

# Custom OpenAPI schema configuration
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # FastAPI automatically generates security schemes from HTTPBearer dependencies
    # No manual security scheme configuration needed

    # Add tags with descriptions
    openapi_schema["tags"] = [
        {
            "name": "health",
            "description": "Service health and readiness checks"
        },
        {
            "name": "users",
            "description": "User management operations. Users are automatically created from JWT tokens."
        },
        {
            "name": "groups",
            "description": "Group management operations. Groups organize users and can have roles assigned."
        },
        {
            "name": "memberships",
            "description": "Group membership management. Assign and remove users from groups."
        },
        {
            "name": "roles",
            "description": "Role management operations. Roles define permissions that can be assigned to users or groups."
        },
        {
            "name": "actions",
            "description": "Action management operations. Actions define the granular permissions available in the system."
        },
        {
            "name": "mappings",
            "description": "API endpoint to action mapping configuration. Maps HTTP endpoints to authorization actions."
        }
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Router registration
app.include_router(health.router, tags=["health"])
app.include_router(users.router, prefix="/api/v1/users", tags=["users"])
app.include_router(groups.router, prefix="/api/v1/groups", tags=["groups"])
app.include_router(memberships.router, prefix="/api/v1", tags=["memberships"])
app.include_router(roles.router, prefix="/api/v1/roles", tags=["roles"])
app.include_router(actions.router, prefix="/api/v1/actions", tags=["actions"])
app.include_router(mappings.router, prefix="/api/v1/mappings", tags=["mappings"])
