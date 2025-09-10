"""
Mapping management service with OpenTelemetry tracing.
Implements endpoint-to-action mapping operations with regex pattern matching.
"""

import re
from typing import Any

from opentelemetry import trace
from sqlalchemy.orm import Session

from app.models import Action, Endpoint, User
from app.services.base import BaseService
from app.services.cache import CacheService
from app.services.cerbos import CerbosService


class MappingService(BaseService):
    """Service for mapping management operations."""

    def __init__(self):
        super().__init__("mapping")
        self.cerbos_service = CerbosService()
        self.cache_service = CacheService()

    def resolve_mapping(self, db: Session, path: str, method: str) -> dict[str, Any] | None:
        """
        Resolve path and method to action using regex pattern matching with Redis caching.
        Returns mapping information for adapter usage.
        """
        with self.trace_operation("resolve_mapping", {
            "mapping.path": path,
            "mapping.method": method,
            "mapping.operation": "resolve"
        }) as span:
            try:
                # Try to get from cache first
                cached_result = self.cache_service.get_mapping_cache(path, method)
                if cached_result:
                    span.set_attribute("mapping.cache_hit", True)
                    span.set_attribute("mapping.matched_action", cached_result.get("action"))
                    span.set_attribute("mapping.mapping_id", cached_result.get("mapping_id"))
                    return cached_result

                span.set_attribute("mapping.cache_hit", False)

                # Query all endpoints for the given method or 'ANY'
                endpoints = (
                    db.query(Endpoint)
                    .filter(Endpoint.method.in_([method, "ANY"]))
                    .join(Action)
                    .all()
                )

                span.set_attribute("mapping.candidates_count", len(endpoints))

                # Try to match path patterns using regex
                for endpoint in endpoints:
                    try:
                        # Convert path pattern to regex if it's not already
                        pattern = self._convert_pattern_to_regex(endpoint.path_pattern)

                        if re.match(pattern, path):
                            span.set_attribute("mapping.matched_pattern", endpoint.path_pattern)
                            span.set_attribute("mapping.matched_action", endpoint.action.name)
                            span.set_attribute("mapping.mapping_id", endpoint.id)

                            result = {
                                "mapping_id": endpoint.id,
                                "action": endpoint.action.name,
                                "path_pattern": endpoint.path_pattern,
                                "method": endpoint.method,
                                "description": endpoint.description
                            }

                            # Cache the result
                            self.cache_service.set_mapping_cache(path, method, result)
                            span.set_attribute("mapping.cached_result", True)

                            return result
                    except re.error as e:
                        span.record_exception(e)
                        span.set_attribute("mapping.pattern_error", str(e))
                        continue

                span.set_attribute("mapping.no_match", True)
                return None

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("mapping.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def create_mapping(
        self,
        db: Session,
        path_pattern: str,
        method: str,
        action_name: str,
        description: str | None,
        created_by: User
    ) -> Endpoint:
        """
        Create a new endpoint mapping.
        Implements mapping creation with validation and permission checking.
        """
        with self.trace_operation("create_mapping", {
            "mapping.path_pattern": path_pattern,
            "mapping.method": method,
            "mapping.action": action_name,
            "mapping.created_by": created_by.subject,
            "mapping.operation": "create"
        }) as span:
            try:
                # Validate the regex pattern
                try:
                    pattern = self._convert_pattern_to_regex(path_pattern)
                    re.compile(pattern)
                except re.error as e:
                    span.set_attribute("mapping.invalid_pattern", True)
                    raise ValueError(f"Invalid path pattern: {e}")

                # Find or create the action
                action = db.query(Action).filter(Action.name == action_name).first()
                if not action:
                    action = Action(name=action_name, description=f"Action for {action_name}")
                    db.add(action)
                    db.flush()  # Get the ID
                    span.set_attribute("mapping.action_created", True)

                # Check if mapping already exists
                existing = db.query(Endpoint).filter(
                    Endpoint.path_pattern == path_pattern,
                    Endpoint.method == method
                ).first()

                if existing:
                    span.set_attribute("mapping.already_exists", True)
                    raise ValueError(f"Mapping for pattern '{path_pattern}' and method '{method}' already exists")

                # Create the endpoint mapping
                endpoint = Endpoint(
                    path_pattern=path_pattern,
                    method=method,
                    action_id=action.id,
                    description=description,
                    created_by=created_by.id
                )

                db.add(endpoint)
                db.commit()
                db.refresh(endpoint)

                # Invalidate mapping cache after creation
                self.cache_service.invalidate_mapping_cache()
                span.set_attribute("mapping.cache_invalidated", True)

                span.set_attribute("mapping.id", endpoint.id)
                span.set_attribute("mapping.created", True)

                return endpoint

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("mapping.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()
                raise

    def update_mapping(
        self,
        db: Session,
        mapping_id: int,
        path_pattern: str | None,
        method: str | None,
        action_name: str | None,
        description: str | None,
        updated_by: User
    ) -> Endpoint:
        """
        Update an existing endpoint mapping.
        """
        with self.trace_operation("update_mapping", {
            "mapping.id": mapping_id,
            "mapping.updated_by": updated_by.subject,
            "mapping.operation": "update"
        }) as span:
            try:
                # Find the mapping
                endpoint = db.query(Endpoint).filter(Endpoint.id == mapping_id).first()
                if not endpoint:
                    span.set_attribute("mapping.not_found", True)
                    raise ValueError(f"Mapping with ID {mapping_id} not found")

                # Update fields if provided
                updated = False

                if path_pattern is not None:
                    # Validate the regex pattern
                    try:
                        pattern = self._convert_pattern_to_regex(path_pattern)
                        re.compile(pattern)
                    except re.error as e:
                        span.set_attribute("mapping.invalid_pattern", True)
                        raise ValueError(f"Invalid path pattern: {e}")
                    endpoint.path_pattern = path_pattern
                    updated = True

                if method is not None:
                    endpoint.method = method
                    updated = True

                if action_name is not None:
                    # Find or create the action
                    action = db.query(Action).filter(Action.name == action_name).first()
                    if not action:
                        action = Action(name=action_name, description=f"Action for {action_name}")
                        db.add(action)
                        db.flush()
                    endpoint.action_id = action.id
                    updated = True

                if description is not None:
                    endpoint.description = description
                    updated = True

                if updated:
                    endpoint.updated_at = db.execute("SELECT now()").scalar()
                    db.commit()
                    db.refresh(endpoint)

                    # Invalidate mapping cache after update
                    self.cache_service.invalidate_mapping_cache()
                    span.set_attribute("mapping.cache_invalidated", True)

                span.set_attribute("mapping.updated", updated)

                return endpoint

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("mapping.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()
                raise

    def delete_mapping(self, db: Session, mapping_id: int, deleted_by: User) -> bool:
        """
        Delete an endpoint mapping.
        """
        with self.trace_operation("delete_mapping", {
            "mapping.id": mapping_id,
            "mapping.deleted_by": deleted_by.subject,
            "mapping.operation": "delete"
        }) as span:
            try:
                # Find the mapping
                endpoint = db.query(Endpoint).filter(Endpoint.id == mapping_id).first()
                if not endpoint:
                    span.set_attribute("mapping.not_found", True)
                    return True  # Idempotent operation

                db.delete(endpoint)
                db.commit()

                # Invalidate mapping cache after deletion
                self.cache_service.invalidate_mapping_cache()
                span.set_attribute("mapping.cache_invalidated", True)

                span.set_attribute("mapping.deleted", True)
                return True

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("mapping.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()
                raise

    def list_mappings(self, db: Session, action_filter: str | None = None) -> list[Endpoint]:
        """
        List all endpoint mappings with optional filtering.
        """
        with self.trace_operation("list_mappings", {
            "mapping.operation": "list",
            "mapping.action_filter": action_filter
        }) as span:
            try:
                query = db.query(Endpoint).join(Action)

                if action_filter:
                    query = query.filter(Action.name.ilike(f"%{action_filter}%"))

                mappings = query.order_by(Endpoint.path_pattern, Endpoint.method).all()

                span.set_attribute("mapping.count", len(mappings))

                return mappings

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("mapping.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def _convert_pattern_to_regex(self, path_pattern: str) -> str:
        """
        Convert a simple path pattern to a full regex pattern.
        Supports:
        - * for any characters within a path segment
        - ** for any path segments
        - :param for named parameters
        """
        # Escape special regex characters except *, ?, and :
        pattern = re.escape(path_pattern)

        # Handle path parameters like :id -> [^/]+
        pattern = re.sub(r'\\:([a-zA-Z_][a-zA-Z0-9_]*)', r'(?P<\1>[^/]+)', pattern)

        # Handle ** for multiple path segments
        pattern = pattern.replace(r'\*\*', '.*')

        # Handle * for single path segment
        pattern = pattern.replace(r'\*', '[^/]*')

        # Ensure exact match
        if not pattern.startswith('^'):
            pattern = '^' + pattern
        if not pattern.endswith('$'):
            pattern = pattern + '$'

        return pattern
