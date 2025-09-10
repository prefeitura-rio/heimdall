"""
FastAPI application entry point for Heimdall Admin Service.
Implements OpenTelemetry tracing setup as specified in SPEC.md Section 6.
"""

import logging
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from opentelemetry import trace

from app.database import engine, get_db
from app.dependencies import get_current_user_with_roles
from app.routers import groups, memberships, roles, users
from app.tracing import instrument_fastapi, instrument_sqlalchemy, setup_tracing

# Initialize OpenTelemetry tracing before creating the FastAPI app
setup_tracing()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI application
app = FastAPI(
    title="Heimdall Admin Service",
    description="Admin service for group and role management with Cerbos integration",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure as needed for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instrument FastAPI for automatic HTTP tracing
instrument_fastapi(app)

# Instrument SQLAlchemy for automatic database tracing
instrument_sqlalchemy(engine)


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

        logger.warning(
            "HTTP exception occurred",
            extra={
                "status_code": exc.status_code,
                "detail": exc.detail,
                "method": request.method,
                "url": str(request.url),
            }
        )

        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail, "status_code": exc.status_code}
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

        logger.warning(
            "Request validation error",
            extra={
                "errors": exc.errors(),
                "method": request.method,
                "url": str(request.url),
            }
        )

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": "Validation error", "details": exc.errors()}
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

        logger.error(
            "Unhandled exception occurred",
            extra={
                "exception_type": type(exc).__name__,
                "exception_message": str(exc),
                "method": request.method,
                "url": str(request.url),
            },
            exc_info=True
        )

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "Internal server error", "status_code": 500}
        )


# Health and readiness endpoints
@app.get("/healthz")
async def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "heimdall-admin-service"}


@app.get("/readyz")
async def readiness_check(db = Depends(get_db)):
    """Readiness check with database connectivity test."""
    tracer = trace.get_tracer(__name__)
    with tracer.start_span("readiness_check") as span:
        try:
            # Test database connectivity
            db.execute("SELECT 1")
            span.set_attribute("db.connection", "healthy")

            return {
                "status": "ready",
                "service": "heimdall-admin-service",
                "database": "connected",
                "version": "1.0.0"
            }
        except Exception as e:
            span.record_exception(e)
            span.set_attribute("db.connection", "failed")

            logger.error("Database connection failed in readiness check", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database connection failed"
            )


@app.get("/version")
async def version_info():
    """Service version information."""
    return {
        "service": "heimdall-admin-service",
        "version": "1.0.0",
        "description": "Admin service for group and role management with Cerbos integration"
    }


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Heimdall Admin Service", "version": "1.0.0"}


# Router registration
app.include_router(users.router, prefix="/api/v1/users", tags=["users"])
app.include_router(groups.router, prefix="/api/v1/groups", tags=["groups"])
app.include_router(memberships.router, prefix="/api/v1", tags=["memberships"])
app.include_router(roles.router, prefix="/api/v1/roles", tags=["roles"])

# TODO: Additional routers will be added as API endpoints are implemented
# from app.routers import mappings
# app.include_router(mappings.router, prefix="/api/v1/mappings", tags=["mappings"])


@app.get("/test-tracing")
async def test_tracing():
    """Test endpoint for custom tracing spans."""
    from app.services.auth import AuthService
    from app.tracing import get_tracer

    tracer = get_tracer("heimdall.test")

    with tracer.start_span("test_custom_tracing") as span:
        span.set_attribute("test.endpoint", "/test-tracing")
        span.set_attribute("test.custom_spans", True)

        # Test authentication service tracing
        auth_service = AuthService()
        result = auth_service.verify_static_token("invalid_token")

        span.set_attribute("test.auth_result", result)

        return {
            "message": "Custom tracing test completed",
            "auth_test_result": result,
            "tracing_active": True,
        }


@app.get("/test-auth")
async def test_auth():
    """Test endpoint for authentication system."""
    from typing import Annotated

    from fastapi import Depends

    from app.dependencies import get_api_user

    def _auth_test(auth_info: Annotated[dict, Depends(get_api_user)]):
        return {
            "message": "Authentication test successful",
            "auth_type": auth_info.get("type"),
            "subject": auth_info.get("subject"),
            "roles": auth_info.get("roles", []),
            "authenticated": True,
        }

    # This will return a function that requires authentication
    return _auth_test


@app.get("/profile")
async def get_user_profile(
    current_user_info: Annotated[dict, Depends(get_current_user_with_roles)],
):
    """Get current user profile with auto-user creation."""
    return {
        "subject": current_user_info["subject"],
        "display_name": current_user_info["user"].display_name,
        "created_at": current_user_info["user"].created_at.isoformat(),
        "roles": current_user_info["roles"],
        "groups": current_user_info["groups"],
    }
