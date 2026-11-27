"""
Redis mapping persistence service with OpenTelemetry tracing.
Implements permanent mapping storage with configurable lookup cache as specified in
REDIS_MAPPING_QUERY_GUIDE.md.
"""

import json
import re
from typing import Any

import redis

from app.services.base import BaseService
from app.services.path_pattern import convert_pattern_to_regex
from app.settings import settings

# Key of the raw database path_pattern inside a stored mapping. The stored
# "path_pattern" is the anchored regex (DEV-680), because every reader of
# heimdall:mappings:all matches it as is: this service and the edge
# (cerbos-ext-authz, regexp.MatchString), as REDIS_MAPPING_QUERY_GUIDE.md says.
SOURCE_PATTERN_KEY = "source_path_pattern"


def to_stored_mapping(mapping_data: dict[str, Any]) -> dict[str, Any]:
    """Mapping as written to Redis: path_pattern anchored, raw kept aside."""
    # Idempotent: a mapping read back from Redis already carries the raw one.
    raw = mapping_data.get(SOURCE_PATTERN_KEY) or mapping_data["path_pattern"]
    return {
        **mapping_data,
        "path_pattern": convert_pattern_to_regex(raw),
        SOURCE_PATTERN_KEY: raw,
    }


def from_stored_mapping(stored: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """
    Mapping as the database has it, and the regex to match a path with.

    An entry written before DEV-680 has only the raw path_pattern: it is
    converted here, so it matches by the same rule until the next sync.
    """
    if SOURCE_PATTERN_KEY in stored:
        mapping = {k: v for k, v in stored.items() if k != SOURCE_PATTERN_KEY}
        mapping["path_pattern"] = stored[SOURCE_PATTERN_KEY]
        regex = stored.get("path_pattern")
        return mapping, regex
    raw = stored.get("path_pattern")
    return stored, convert_pattern_to_regex(raw) if raw else None


class RedisMappingService(BaseService):
    """Service for Redis mapping persistence operations with permanent storage and configurable cache."""

    def __init__(self):
        super().__init__("redis_mapping")

        # Import here to avoid circular dependency
        from app.services.cache import CacheService
        self._cache_service = CacheService()

        # Configuration
        self.cache_ttl = settings.REDIS_MAPPING_CACHE_TTL

    @property
    def redis_client(self) -> redis.Redis:
        """Get Redis client from cache service to reuse connection."""
        return self._cache_service._get_redis_connection()

    def store_mapping(self, mapping_data: dict[str, Any]) -> bool:
        """
        Store mapping in permanent Redis storage and update pattern lists.

        Args:
            mapping_data: Complete mapping information including id, method, path_pattern, etc.

        Returns:
            bool: True if successful, False otherwise
        """
        with self.trace_operation(
            "store_mapping",
            {
                "redis_mapping.operation": "store",
                "redis_mapping.id": mapping_data.get("id"),
                "redis_mapping.method": mapping_data.get("method"),
                "redis_mapping.path_pattern": mapping_data.get("path_pattern"),
            },
        ) as span:
            try:
                redis_conn = self.redis_client
                mapping_id = mapping_data["id"]
                method = mapping_data["method"]

                # Store mapping details in permanent hash (no TTL)
                mapping_key = f"mapping_{mapping_id}"
                redis_conn.hset(
                    "heimdall:mappings:all",
                    mapping_key,
                    json.dumps(to_stored_mapping(mapping_data)),
                )

                # Update pattern list for the method (maintain order by specificity)
                pattern_key = f"heimdall:mappings:patterns:{method}"

                # Remove from list if already exists (in case of update)
                redis_conn.lrem(pattern_key, 0, mapping_key)

                # Add to front of list (most specific patterns should be first)
                # For now, we'll add new patterns at the beginning
                # TODO: Implement proper specificity ordering if needed
                redis_conn.lpush(pattern_key, mapping_key)

                span.set_attribute("redis_mapping.stored", True)
                span.set_attribute("redis_mapping.pattern_list_updated", True)
                return True

            except (redis.RedisError, KeyError, TypeError) as e:
                span.record_exception(e)
                span.set_attribute("redis_mapping.error", str(e))
                span.set_attribute("redis_mapping.stored", False)
                return False

    def remove_mapping(self, mapping_id: int, method: str) -> bool:
        """
        Remove mapping from permanent Redis storage and pattern lists.

        Args:
            mapping_id: The mapping ID to remove
            method: HTTP method for pattern list cleanup

        Returns:
            bool: True if successful, False otherwise
        """
        with self.trace_operation(
            "remove_mapping",
            {
                "redis_mapping.operation": "remove",
                "redis_mapping.id": mapping_id,
                "redis_mapping.method": method,
            },
        ) as span:
            try:
                redis_conn = self.redis_client
                mapping_key = f"mapping_{mapping_id}"

                # Remove from main storage
                removed_count = redis_conn.hdel("heimdall:mappings:all", mapping_key)

                # Remove from pattern list
                pattern_key = f"heimdall:mappings:patterns:{method}"
                redis_conn.lrem(pattern_key, 0, mapping_key)

                # Invalidate any cached lookups that might reference this mapping
                self.invalidate_lookup_cache()

                span.set_attribute("redis_mapping.removed", removed_count > 0)
                span.set_attribute("redis_mapping.pattern_list_updated", True)
                span.set_attribute("redis_mapping.cache_invalidated", True)
                return removed_count > 0

            except redis.RedisError as e:
                span.record_exception(e)
                span.set_attribute("redis_mapping.error", str(e))
                span.set_attribute("redis_mapping.removed", False)
                return False

    def resolve_mapping_fast(self, method: str, path: str) -> dict[str, Any] | None:
        """
        Resolve mapping using fast path (cache) + pattern matching fallback.
        Implements the algorithm documented in REDIS_MAPPING_QUERY_GUIDE.md.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path to match

        Returns:
            dict: Mapping data if found, None otherwise
        """
        with self.trace_operation(
            "resolve_mapping_fast",
            {
                "redis_mapping.operation": "resolve",
                "redis_mapping.method": method,
                "redis_mapping.path": path,
            },
        ) as span:
            try:
                redis_conn = self.redis_client

                # Step 1: Check cache for exact path match
                if self.cache_ttl > 0:  # Only use cache if TTL > 0
                    cache_key = f"heimdall:mappings:lookup:{method}:{path}"
                    cached_mapping_id = redis_conn.get(cache_key)

                    if cached_mapping_id:
                        # Get mapping details from permanent storage
                        mapping_data = redis_conn.hget("heimdall:mappings:all", cached_mapping_id.decode())
                        if mapping_data:
                            mapping, regex = from_stored_mapping(json.loads(mapping_data))
                            # The lookup cache is shared with the edge, which
                            # writes it too: trust an entry only if its pattern
                            # matches the path by the anchored rule (DEV-680).
                            if regex and self._matches(regex, path, span):
                                span.set_attribute("redis_mapping.cache_hit", True)
                                span.set_attribute("redis_mapping.mapping_id", cached_mapping_id.decode())
                                return mapping
                            redis_conn.delete(cache_key)
                            span.set_attribute("redis_mapping.stale_cache_dropped", True)

                span.set_attribute("redis_mapping.cache_hit", False)

                # Step 2: Pattern matching fallback
                pattern_key = f"heimdall:mappings:patterns:{method}"
                mapping_ids = redis_conn.lrange(pattern_key, 0, -1)

                span.set_attribute("redis_mapping.patterns_to_check", len(mapping_ids))

                for mapping_id_bytes in mapping_ids:
                    mapping_id = mapping_id_bytes.decode()

                    # Get mapping details
                    mapping_data_str = redis_conn.hget("heimdall:mappings:all", mapping_id)
                    if not mapping_data_str:
                        continue

                    mapping_data, regex = from_stored_mapping(json.loads(mapping_data_str))

                    if not regex:
                        continue

                    # Match by the same anchored rule as the database fallback
                    # (DEV-680): the raw pattern has no end anchor and would
                    # match any longer path by prefix.
                    if self._matches(regex, path, span):
                        span.set_attribute("redis_mapping.matched_pattern", mapping_data.get("path_pattern"))
                        span.set_attribute("redis_mapping.mapping_id", mapping_id)

                        # Cache the result for future lookups (if caching enabled)
                        if self.cache_ttl > 0:
                            cache_key = f"heimdall:mappings:lookup:{method}:{path}"
                            redis_conn.setex(cache_key, self.cache_ttl, mapping_id)
                            span.set_attribute("redis_mapping.result_cached", True)

                        return mapping_data

                span.set_attribute("redis_mapping.no_match", True)
                return None

            except (redis.RedisError, json.JSONDecodeError) as e:
                span.record_exception(e)
                span.set_attribute("redis_mapping.error", str(e))
                return None

    @staticmethod
    def _matches(regex: str, path: str, span) -> bool:
        """Whether path matches the anchored regex; an invalid regex never matches."""
        try:
            return re.match(regex, path) is not None
        except re.error as regex_error:
            span.record_exception(regex_error)
            span.set_attribute("redis_mapping.regex_error", str(regex_error))
            return False

    def get_all_mappings(self) -> list[dict[str, Any]]:
        """
        Get all mappings from permanent storage.

        Returns:
            list: All mapping data
        """
        with self.trace_operation(
            "get_all_mappings",
            {"redis_mapping.operation": "get_all"},
        ) as span:
            try:
                redis_conn = self.redis_client
                all_mappings_data = redis_conn.hgetall("heimdall:mappings:all")

                mappings = []
                for mapping_data_str in all_mappings_data.values():
                    try:
                        mapping_data, _ = from_stored_mapping(json.loads(mapping_data_str))
                        mappings.append(mapping_data)
                    except json.JSONDecodeError:
                        continue

                span.set_attribute("redis_mapping.mappings_count", len(mappings))
                return mappings

            except redis.RedisError as e:
                span.record_exception(e)
                span.set_attribute("redis_mapping.error", str(e))
                return []

    def invalidate_lookup_cache(self) -> bool:
        """
        Invalidate all lookup cache entries (with TTL).
        Preserves permanent data, only clears the cache layer.

        Returns:
            bool: True if successful, False otherwise
        """
        with self.trace_operation(
            "invalidate_lookup_cache",
            {"redis_mapping.operation": "invalidate_cache"},
        ) as span:
            try:
                redis_conn = self.redis_client

                # Find and delete all lookup cache keys
                cache_keys = redis_conn.keys("heimdall:mappings:lookup:*")
                if cache_keys:
                    deleted_count = redis_conn.delete(*cache_keys)
                    span.set_attribute("redis_mapping.cache_keys_deleted", deleted_count)
                else:
                    span.set_attribute("redis_mapping.cache_keys_deleted", 0)

                span.set_attribute("redis_mapping.cache_invalidated", True)
                return True

            except redis.RedisError as e:
                span.record_exception(e)
                span.set_attribute("redis_mapping.error", str(e))
                span.set_attribute("redis_mapping.cache_invalidated", False)
                return False

    def sync_all_mappings_from_db(self, mappings: list[dict[str, Any]]) -> bool:
        """
        Sync all mappings from database to Redis.
        This rebuilds the entire Redis mapping storage.

        Args:
            mappings: List of mapping data from database

        Returns:
            bool: True if successful, False otherwise
        """
        with self.trace_operation(
            "sync_all_mappings_from_db",
            {
                "redis_mapping.operation": "sync_all",
                "redis_mapping.mappings_count": len(mappings),
            },
        ) as span:
            try:
                redis_conn = self.redis_client

                # Clear existing data
                redis_conn.delete("heimdall:mappings:all")

                # Clear pattern lists for all methods
                pattern_keys = redis_conn.keys("heimdall:mappings:patterns:*")
                if pattern_keys:
                    redis_conn.delete(*pattern_keys)

                # Store all mappings
                for mapping_data in mappings:
                    if not self.store_mapping(mapping_data):
                        span.set_attribute("redis_mapping.sync_failed", True)
                        return False

                # Invalidate lookup cache
                self.invalidate_lookup_cache()

                span.set_attribute("redis_mapping.sync_successful", True)
                span.set_attribute("redis_mapping.synced_count", len(mappings))
                return True

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("redis_mapping.error", str(e))
                span.set_attribute("redis_mapping.sync_failed", True)
                return False

    def health_check(self) -> bool:
        """
        Check Redis mapping storage health.

        Returns:
            bool: True if healthy, False otherwise
        """
        with self.trace_operation(
            "health_check",
            {"redis_mapping.operation": "health_check"},
        ) as span:
            try:
                redis_conn = self.redis_client

                # Test basic operations
                test_key = "heimdall:mappings:health_check"
                redis_conn.set(test_key, "ok", ex=10)  # 10 second TTL
                result = redis_conn.get(test_key)
                redis_conn.delete(test_key)

                is_healthy = result is not None
                span.set_attribute("redis_mapping.healthy", is_healthy)
                return is_healthy

            except redis.RedisError as e:
                span.record_exception(e)
                span.set_attribute("redis_mapping.error", str(e))
                span.set_attribute("redis_mapping.healthy", False)
                return False
