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
from app.logging_config import get_structured_logger
from app.services.cache import CacheService
from app.services.cerbos import CerbosService

logger = get_structured_logger(__name__)

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
        logger.log_operation(
            level=10,  # DEBUG
            message="Database readiness check passed",
            operation="readiness_check_database",
        )
    except Exception as e:
        checks["database"] = False
        error_msg = f"Database check failed: {str(e)}"
        errors.append(error_msg)
        logger.log_operation(
            level=40,  # ERROR
            message="Database readiness check failed",
            operation="readiness_check_database",
            extra_fields={"error": str(e), "exception_type": type(e).__name__},
        )

    # Redis cache connectivity check
    try:
        cache_healthy = cache_service.health_check()
        checks["cache"] = cache_healthy
        if not cache_healthy:
            error_msg = "Cache health check failed"
            errors.append(error_msg)
            logger.log_operation(
                level=40,  # ERROR
                message="Redis cache readiness check failed",
                operation="readiness_check_cache",
                extra_fields={"cache_healthy": cache_healthy},
            )
        else:
            logger.log_operation(
                level=10,  # DEBUG
                message="Redis cache readiness check passed",
                operation="readiness_check_cache",
            )
    except Exception as e:
        checks["cache"] = False
        error_msg = f"Cache check failed: {str(e)}"
        errors.append(error_msg)
        logger.log_operation(
            level=40,  # ERROR
            message="Redis cache readiness check exception",
            operation="readiness_check_cache",
            extra_fields={"error": str(e), "exception_type": type(e).__name__},
        )

    # Cerbos API connectivity check
    try:
        # Test Cerbos connectivity with a simple check call
        cerbos_healthy = cerbos_service.health_check()
        checks["cerbos"] = cerbos_healthy
        if not cerbos_healthy:
            error_msg = "Cerbos health check failed"
            errors.append(error_msg)
            logger.log_operation(
                level=40,  # ERROR
                message="Cerbos readiness check failed",
                operation="readiness_check_cerbos",
                extra_fields={"cerbos_healthy": cerbos_healthy},
            )
        else:
            logger.log_operation(
                level=10,  # DEBUG
                message="Cerbos readiness check passed",
                operation="readiness_check_cerbos",
            )
    except Exception as e:
        checks["cerbos"] = False
        error_msg = f"Cerbos check failed: {str(e)}"
        errors.append(error_msg)
        logger.log_operation(
            level=40,  # ERROR
            message="Cerbos readiness check exception",
            operation="readiness_check_cerbos",
            extra_fields={"error": str(e), "exception_type": type(e).__name__},
        )

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
        logger.log_operation(
            level=40,  # ERROR
            message="Readiness check failed - service not ready",
            operation="readiness_check_overall",
            extra_fields={
                "checks": checks,
                "errors": errors,
                "failed_checks": [check for check, status in checks.items() if not status and check != "overall"],
            },
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=response
        )

    logger.log_operation(
        level=20,  # INFO
        message="Readiness check passed - service ready",
        operation="readiness_check_overall",
        extra_fields={"checks": checks},
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
