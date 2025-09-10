"""
Health and monitoring endpoints for Heimdall Admin Service.
Implements health checks as specified in SPEC.md Section 3.7.
"""

from datetime import UTC, datetime
from typing import Any

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


@router.get("/healthz")
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


@router.get("/readyz")
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
