"""
FastAPI application entry point for Heimdall Admin Service.
Implements OpenTelemetry tracing setup as specified in SPEC.md Section 6.
"""

from typing import Annotated

from fastapi import Depends, FastAPI

from app.database import engine
from app.dependencies import get_current_user_with_roles
from app.tracing import instrument_fastapi, instrument_sqlalchemy, setup_tracing

# Initialize OpenTelemetry tracing before creating the FastAPI app
setup_tracing()

# Create FastAPI application
app = FastAPI(
    title="Heimdall Admin Service",
    description="Admin service for group and role management with Cerbos integration",
    version="1.0.0",
)

# Instrument FastAPI for automatic HTTP tracing
instrument_fastapi(app)

# Instrument SQLAlchemy for automatic database tracing
instrument_sqlalchemy(engine)


@app.get("/healthz")
async def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy"}


@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Heimdall Admin Service", "version": "1.0.0"}


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
