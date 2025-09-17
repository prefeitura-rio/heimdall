"""
Health monitoring service for external dependencies.
Implements background health checks with Redis caching for fast availability checks.
"""

import asyncio
import contextlib
import time

from app.services.base import BaseService
from app.services.cache import CacheService
from app.services.cerbos import CerbosService


class HealthMonitor(BaseService):
    """Service for monitoring health of external dependencies."""

    def __init__(self):
        super().__init__("health_monitor")
        self.cache_service = CacheService()
        self.cerbos_service = CerbosService()
        self._monitoring_task: asyncio.Task | None = None

        # Health check configuration
        self.check_interval = 30  # seconds
        self.cache_ttl = 60  # seconds - cache expires if not updated

    def start_monitoring(self):
        """Start background health monitoring tasks."""
        if self._monitoring_task is None or self._monitoring_task.done():
            self._monitoring_task = asyncio.create_task(self._monitor_services())

    async def stop_monitoring(self):
        """Stop background health monitoring tasks."""
        if self._monitoring_task and not self._monitoring_task.done():
            self._monitoring_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._monitoring_task

    async def _monitor_services(self):
        """Background task to continuously monitor service health."""
        with self.trace_operation("monitor_services", {"monitor.operation": "background_monitoring"}) as span:
            span.set_attribute("monitor.check_interval", self.check_interval)
            span.set_attribute("monitor.cache_ttl", self.cache_ttl)

            while True:
                try:
                    # Check Cerbos health
                    await self._check_cerbos_health()

                    # Wait for next check
                    await asyncio.sleep(self.check_interval)

                except asyncio.CancelledError:
                    span.set_attribute("monitor.cancelled", True)
                    break
                except Exception as e:
                    span.record_exception(e)
                    span.set_attribute("monitor.error", str(e))
                    # Continue monitoring even if a check fails
                    await asyncio.sleep(self.check_interval)

    async def _check_cerbos_health(self):
        """Check Cerbos health and update cache."""
        with self.trace_operation("check_cerbos_health", {"monitor.service": "cerbos"}) as span:
            try:
                # Use the synchronous health check method
                is_healthy = self.cerbos_service.health_check()

                health_data = {
                    "healthy": is_healthy,
                    "last_check": time.time(),
                    "service": "cerbos"
                }

                # Cache the health status
                cache_key = "service_health:cerbos"
                self.cache_service.redis_client.setex(
                    cache_key,
                    self.cache_ttl,
                    str(health_data)
                )

                span.set_attribute("monitor.cerbos_healthy", is_healthy)
                span.set_attribute("monitor.cache_updated", True)

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("monitor.cerbos_healthy", False)
                span.set_attribute("monitor.error", str(e))

                # Cache the unhealthy status
                health_data = {
                    "healthy": False,
                    "last_check": time.time(),
                    "service": "cerbos",
                    "error": str(e)
                }

                cache_key = "service_health:cerbos"
                self.cache_service.redis_client.setex(
                    cache_key,
                    self.cache_ttl,
                    str(health_data)
                )

    def is_cerbos_available(self) -> bool:
        """
        Fast check if Cerbos is available based on cached health status.
        Returns False if cache has expired (indicating monitoring task issues).
        """
        with self.trace_operation("is_cerbos_available", {"monitor.operation": "availability_check"}) as span:
            try:
                cache_key = "service_health:cerbos"
                cached_health = self.cache_service.redis_client.get(cache_key)

                if cached_health is None:
                    # Cache expired or doesn't exist - service unavailable
                    span.set_attribute("monitor.cache_expired", True)
                    span.set_attribute("monitor.available", False)
                    return False

                # Parse cached health data (simplified - in production use JSON)
                health_str = cached_health.decode('utf-8')
                is_healthy = "'healthy': True" in health_str

                span.set_attribute("monitor.cache_hit", True)
                span.set_attribute("monitor.available", is_healthy)
                span.set_attribute("monitor.cached_health", health_str)

                return is_healthy

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("monitor.error", str(e))
                span.set_attribute("monitor.available", False)
                # On any error checking cache, assume service unavailable
                return False

    def get_service_health_summary(self) -> dict[str, any]:
        """Get health summary of all monitored services."""
        with self.trace_operation("get_service_health_summary", {"monitor.operation": "health_summary"}) as span:
            try:
                cache_key = "service_health:cerbos"
                cached_health = self.cache_service.redis_client.get(cache_key)

                if cached_health is None:
                    health_data = {
                        "cerbos": {
                            "available": False,
                            "status": "cache_expired",
                            "last_check": None
                        }
                    }
                else:
                    health_str = cached_health.decode('utf-8')
                    is_healthy = "'healthy': True" in health_str

                    health_data = {
                        "cerbos": {
                            "available": is_healthy,
                            "status": "healthy" if is_healthy else "unhealthy",
                            "cached_data": health_str
                        }
                    }

                span.set_attribute("monitor.services_checked", 1)
                return health_data

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("monitor.error", str(e))
                return {
                    "cerbos": {
                        "available": False,
                        "status": "error",
                        "error": str(e)
                    }
                }
