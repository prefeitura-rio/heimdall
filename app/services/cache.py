"""
Redis caching service with OpenTelemetry tracing.
Implements server-side caching as specified in SPEC.md Section 6.
"""

import json
import os
from typing import Any

import redis
from redis.connection import ConnectionPool

from app.services.base import BaseService


class CacheService(BaseService):
    """Service for Redis caching operations with distributed tracing."""

    def __init__(self):
        super().__init__("cache")

        # Redis configuration from environment
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.mapping_ttl = int(os.getenv("REDIS_MAPPING_TTL", "60"))
        self.user_roles_ttl = int(os.getenv("REDIS_USER_ROLES_TTL", "30"))
        self.jwks_ttl = int(os.getenv("REDIS_JWKS_TTL", "300"))

        # Initialize Redis connection pool
        self.pool = ConnectionPool.from_url(
            self.redis_url,
            max_connections=10,
            retry_on_timeout=True,
            socket_timeout=5,
            socket_connect_timeout=5
        )
        self.redis_client = redis.Redis(connection_pool=self.pool)

    def _get_redis_connection(self) -> redis.Redis:
        """Get Redis connection with error handling."""
        try:
            # Test connection
            self.redis_client.ping()
            return self.redis_client
        except redis.ConnectionError:
            # Create new connection if current one failed
            self.redis_client = redis.Redis(connection_pool=self.pool)
            return self.redis_client

    def get_mapping_cache(self, path: str, method: str) -> dict[str, Any] | None:
        """
        Get mapping resolution from cache.
        Implements mapping resolution cache with 60s TTL.
        """
        cache_key = f"mapping:{method}:{path}"

        with self.trace_operation("get_mapping_cache", {
            "cache.key": cache_key,
            "cache.type": "mapping",
            "cache.operation": "get"
        }) as span:
            try:
                redis_conn = self._get_redis_connection()
                cached_value = redis_conn.get(cache_key)

                if cached_value:
                    mapping_data = json.loads(cached_value)
                    span.set_attribute("cache.hit", True)
                    span.set_attribute("cache.mapping_id", mapping_data.get("mapping_id"))
                    return mapping_data
                else:
                    span.set_attribute("cache.hit", False)
                    return None

            except (redis.RedisError, json.JSONDecodeError) as e:
                span.record_exception(e)
                span.set_attribute("cache.error", str(e))
                span.set_attribute("cache.hit", False)
                # Return None on cache errors - fallback to database
                return None

    def set_mapping_cache(self, path: str, method: str, mapping_data: dict[str, Any]) -> bool:
        """
        Set mapping resolution in cache with TTL.
        """
        cache_key = f"mapping:{method}:{path}"

        with self.trace_operation("set_mapping_cache", {
            "cache.key": cache_key,
            "cache.type": "mapping",
            "cache.operation": "set",
            "cache.ttl": self.mapping_ttl
        }) as span:
            try:
                redis_conn = self._get_redis_connection()
                redis_conn.setex(
                    cache_key,
                    self.mapping_ttl,
                    json.dumps(mapping_data)
                )

                span.set_attribute("cache.set_successful", True)
                return True

            except (redis.RedisError, TypeError) as e:
                span.record_exception(e)
                span.set_attribute("cache.error", str(e))
                span.set_attribute("cache.set_successful", False)
                # Don't fail operations on cache errors
                return False

    def invalidate_mapping_cache(self, path_pattern: str | None = None) -> bool:
        """
        Invalidate mapping cache entries.
        If path_pattern is None, invalidates all mapping cache.
        """
        with self.trace_operation("invalidate_mapping_cache", {
            "cache.type": "mapping",
            "cache.operation": "invalidate",
            "cache.pattern": path_pattern
        }) as span:
            try:
                redis_conn = self._get_redis_connection()

                pattern = f"mapping:*:{path_pattern}" if path_pattern else "mapping:*"

                keys = redis_conn.keys(pattern)
                if keys:
                    deleted_count = redis_conn.delete(*keys)
                    span.set_attribute("cache.keys_deleted", deleted_count)
                else:
                    span.set_attribute("cache.keys_deleted", 0)

                span.set_attribute("cache.invalidation_successful", True)
                return True

            except redis.RedisError as e:
                span.record_exception(e)
                span.set_attribute("cache.error", str(e))
                span.set_attribute("cache.invalidation_successful", False)
                return False

    def get_user_roles_cache(self, user_subject: str) -> list[str] | None:
        """
        Get user roles from cache.
        Implements user role aggregation cache with 30s TTL.
        """
        cache_key = f"user_roles:{user_subject}"

        with self.trace_operation("get_user_roles_cache", {
            "cache.key": cache_key,
            "cache.type": "user_roles",
            "cache.operation": "get"
        }) as span:
            try:
                redis_conn = self._get_redis_connection()
                cached_value = redis_conn.get(cache_key)

                if cached_value:
                    roles = json.loads(cached_value)
                    span.set_attribute("cache.hit", True)
                    span.set_attribute("cache.roles_count", len(roles))
                    return roles
                else:
                    span.set_attribute("cache.hit", False)
                    return None

            except (redis.RedisError, json.JSONDecodeError) as e:
                span.record_exception(e)
                span.set_attribute("cache.error", str(e))
                span.set_attribute("cache.hit", False)
                return None

    def set_user_roles_cache(self, user_subject: str, roles: list[str]) -> bool:
        """
        Set user roles in cache with TTL.
        """
        cache_key = f"user_roles:{user_subject}"

        with self.trace_operation("set_user_roles_cache", {
            "cache.key": cache_key,
            "cache.type": "user_roles",
            "cache.operation": "set",
            "cache.ttl": self.user_roles_ttl
        }) as span:
            try:
                redis_conn = self._get_redis_connection()
                redis_conn.setex(
                    cache_key,
                    self.user_roles_ttl,
                    json.dumps(roles)
                )

                span.set_attribute("cache.set_successful", True)
                return True

            except (redis.RedisError, TypeError) as e:
                span.record_exception(e)
                span.set_attribute("cache.error", str(e))
                span.set_attribute("cache.set_successful", False)
                return False

    def invalidate_user_roles_cache(self, user_subject: str | None = None) -> bool:
        """
        Invalidate user roles cache.
        If user_subject is None, invalidates all user roles cache.
        """
        with self.trace_operation("invalidate_user_roles_cache", {
            "cache.type": "user_roles",
            "cache.operation": "invalidate",
            "cache.user_subject": user_subject
        }) as span:
            try:
                redis_conn = self._get_redis_connection()

                if user_subject:
                    # Invalidate specific user
                    cache_key = f"user_roles:{user_subject}"
                    deleted_count = redis_conn.delete(cache_key)
                else:
                    # Invalidate all user roles
                    keys = redis_conn.keys("user_roles:*")
                    deleted_count = redis_conn.delete(*keys) if keys else 0

                span.set_attribute("cache.keys_deleted", deleted_count)
                span.set_attribute("cache.invalidation_successful", True)
                return True

            except redis.RedisError as e:
                span.record_exception(e)
                span.set_attribute("cache.error", str(e))
                span.set_attribute("cache.invalidation_successful", False)
                return False

    def get_jwks_cache(self, jwks_url: str) -> dict[str, Any] | None:
        """
        Get JWKS from cache.
        Implements Keycloak JWKS cache with 300s TTL.
        """
        cache_key = f"jwks:{jwks_url}"

        with self.trace_operation("get_jwks_cache", {
            "cache.key": cache_key,
            "cache.type": "jwks",
            "cache.operation": "get"
        }) as span:
            try:
                redis_conn = self._get_redis_connection()
                cached_value = redis_conn.get(cache_key)

                if cached_value:
                    jwks_data = json.loads(cached_value)
                    span.set_attribute("cache.hit", True)
                    span.set_attribute("cache.keys_count", len(jwks_data.get("keys", [])))
                    return jwks_data
                else:
                    span.set_attribute("cache.hit", False)
                    return None

            except (redis.RedisError, json.JSONDecodeError) as e:
                span.record_exception(e)
                span.set_attribute("cache.error", str(e))
                span.set_attribute("cache.hit", False)
                return None

    def set_jwks_cache(self, jwks_url: str, jwks_data: dict[str, Any]) -> bool:
        """
        Set JWKS in cache with TTL.
        """
        cache_key = f"jwks:{jwks_url}"

        with self.trace_operation("set_jwks_cache", {
            "cache.key": cache_key,
            "cache.type": "jwks",
            "cache.operation": "set",
            "cache.ttl": self.jwks_ttl
        }) as span:
            try:
                redis_conn = self._get_redis_connection()
                redis_conn.setex(
                    cache_key,
                    self.jwks_ttl,
                    json.dumps(jwks_data)
                )

                span.set_attribute("cache.set_successful", True)
                return True

            except (redis.RedisError, TypeError) as e:
                span.record_exception(e)
                span.set_attribute("cache.error", str(e))
                span.set_attribute("cache.set_successful", False)
                return False

    def health_check(self) -> bool:
        """
        Check Redis connection health.
        """
        with self.trace_operation("health_check", {
            "cache.operation": "health_check"
        }) as span:
            try:
                redis_conn = self._get_redis_connection()
                response = redis_conn.ping()

                span.set_attribute("cache.healthy", response)
                return response

            except redis.RedisError as e:
                span.record_exception(e)
                span.set_attribute("cache.error", str(e))
                span.set_attribute("cache.healthy", False)
                return False

    def get_cache_stats(self) -> dict[str, Any]:
        """
        Get cache statistics for monitoring.
        """
        with self.trace_operation("get_cache_stats", {
            "cache.operation": "stats"
        }) as span:
            try:
                redis_conn = self._get_redis_connection()
                info = redis_conn.info()

                stats = {
                    "connected_clients": info.get("connected_clients", 0),
                    "used_memory": info.get("used_memory", 0),
                    "used_memory_human": info.get("used_memory_human", "0B"),
                    "keyspace_hits": info.get("keyspace_hits", 0),
                    "keyspace_misses": info.get("keyspace_misses", 0),
                    "total_commands_processed": info.get("total_commands_processed", 0),
                }

                # Calculate hit rate
                hits = stats["keyspace_hits"]
                misses = stats["keyspace_misses"]
                total = hits + misses
                stats["hit_rate"] = hits / total if total > 0 else 0.0

                span.set_attribute("cache.stats_retrieved", True)
                return stats

            except redis.RedisError as e:
                span.record_exception(e)
                span.set_attribute("cache.error", str(e))
                span.set_attribute("cache.stats_retrieved", False)
                return {"error": str(e)}

