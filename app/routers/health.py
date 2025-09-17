"""
Health and monitoring endpoints for Heimdall Admin Service.
Implements health checks as specified in SPEC.md Section 3.7.
"""

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.cache import CacheService
from app.services.cerbos import CerbosService

router = APIRouter(prefix="/api/v1", tags=["health"])


def get_cache_service() -> CacheService:
    """Get cache service instance."""
    return CacheService()


def get_cerbos_service() -> CerbosService:
    """Get Cerbos service instance."""
    return CerbosService()


@router.get(
    "/healthz",
    summary="Health check",
    description="Basic health check endpoint that returns 200 if the service is running.",
    responses={
        200: {
            "description": "Service is healthy",
            "content": {
                "application/json": {
                    "example": {
                        "status": "healthy",
                        "service": "heimdall-admin-service",
                        "timestamp": "2024-01-01T12:00:00.000Z"
                    }
                }
            }
        }
    }
)
async def health_check() -> dict[str, Any]:
    """
    Basic health check endpoint.
    Returns 200 if the service is running.
    """
    return {
        "status": "healthy",
        "service": "heimdall-admin-service",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@router.get(
    "/readyz",
    summary="Readiness check",
    description="""
Comprehensive readiness check that verifies all system dependencies are available.

**Dependencies Checked**:
- Database connectivity
- Redis cache connectivity
- Cerbos authorization service connectivity

**Use Cases**:
- Kubernetes readiness probes
- Load balancer health checks
- Service mesh health verification
- Deployment validation
    """,
    responses={
        200: {
            "description": "Service is ready and all dependencies are healthy",
            "content": {
                "application/json": {
                    "example": {
                        "status": "ready",
                        "service": "heimdall-admin-service",
                        "timestamp": "2024-01-01T12:00:00.000Z",
                        "dependencies": {
                            "database": "healthy",
                            "redis": "healthy",
                            "cerbos": "healthy"
                        }
                    }
                }
            }
        },
        503: {
            "description": "Service unavailable - one or more dependencies are unhealthy",
            "content": {
                "application/json": {
                    "example": {
                        "status": "not_ready",
                        "service": "heimdall-admin-service",
                        "timestamp": "2024-01-01T12:00:00.000Z",
                        "dependencies": {
                            "database": "healthy",
                            "redis": "unhealthy",
                            "cerbos": "healthy"
                        },
                        "errors": ["Redis connection failed: Connection refused"]
                    }
                }
            }
        }
    }
)
async def readiness_check(
    db: Session = Depends(get_db),
    cache_service: CacheService = Depends(get_cache_service),
    cerbos_service: CerbosService = Depends(get_cerbos_service),
) -> dict[str, Any]:
    """
    Readiness check endpoint.
    Verifies that all dependencies are ready and accessible.
    Returns 200 if ready, 503 if not ready.
    """
    checks = {"database": False, "cache": False, "cerbos": False, "overall": False}

    errors = []

    # Database connectivity check
    try:
        # Simple query to test database connection
        db.execute(text("SELECT 1")).scalar()
        checks["database"] = True
    except Exception as e:
        checks["database"] = False
        errors.append(f"Database check failed: {str(e)}")

    # Redis cache connectivity check
    try:
        cache_healthy = cache_service.health_check()
        checks["cache"] = cache_healthy
        if not cache_healthy:
            errors.append("Cache health check failed")
    except Exception as e:
        checks["cache"] = False
        errors.append(f"Cache check failed: {str(e)}")

    # Cerbos API connectivity check
    try:
        # Test Cerbos connectivity with a simple check call
        cerbos_healthy = cerbos_service.health_check()
        checks["cerbos"] = cerbos_healthy
        if not cerbos_healthy:
            errors.append("Cerbos health check failed")
    except Exception as e:
        checks["cerbos"] = False
        errors.append(f"Cerbos check failed: {str(e)}")

    # Overall readiness
    checks["overall"] = all([checks["database"], checks["cache"], checks["cerbos"]])

    response = {
        "status": "ready" if checks["overall"] else "not_ready",
        "checks": checks,
        "service": "heimdall-admin-service",
        "timestamp": datetime.now(UTC).isoformat(),
    }

    if errors:
        response["errors"] = errors

    if not checks["overall"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=response
        )

    return response


@router.get(
    "/cerbos-policy-template",
    summary="Get Cerbos superadmin policy template",
    description="""
Get the Cerbos policy template for granting superadmin permissions.

This endpoint provides the policy configuration that should be applied to Cerbos
when the admin API is disabled and manual policy configuration is required.

**Use Case**: When Heimdall cannot automatically create the superadmin policy
(e.g., Cerbos admin API is disabled), use this template to manually configure
the policy in your Cerbos deployment.

**Instructions**:
1. Get the policy template from this endpoint
2. Save it as a YAML or JSON file in your Cerbos configuration
3. Apply it via your Cerbos deployment method (ConfigMap, file system, etc.)
    """,
    responses={
        200: {
            "description": "Cerbos policy template retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "apiVersion": "api.cerbos.dev/v1",
                        "kind": "RolePolicy",
                        "metadata": {
                            "storeIdentifier": "role_superadmin"
                        },
                        "rolePolicy": {
                            "role": "superadmin",
                            "version": "default",
                            "rules": [
                                {
                                    "resource": "*",
                                    "actions": [
                                        {
                                            "action": "*",
                                            "effect": "EFFECT_ALLOW"
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
)
async def get_cerbos_policy_template(
    cerbos_service: Annotated[CerbosService, Depends(get_cerbos_service)]
):
    """Get the Cerbos superadmin policy template for manual configuration."""
    return cerbos_service.get_superadmin_policy_template()
