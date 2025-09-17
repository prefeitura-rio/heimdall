"""
Policy Change Detection Service

Tracks changes to policy-relevant data using a hash-based approach.
This enables efficient background synchronization and deployment separation.
"""

import hashlib
import json
from typing import Any

from sqlalchemy.orm import Session

from app.models import Action, Group, GroupRole, Membership, Role, RoleAction, User
from app.services.base import BaseService


class PolicyChangeDetector(BaseService):
    """Service for detecting changes to policy-relevant data."""

    def __init__(self):
        super().__init__("policy_change_detector")
        # Redis key for storing the current policy state hash
        self.redis_key = "heimdall:policy_state_hash"

    def _get_policy_relevant_data(self, db: Session) -> dict[str, Any]:
        """
        Extract all policy-relevant data from the database.
        This includes all data that affects Cerbos policies.
        """
        try:
            # Get all users with their subjects (policy principals)
            users = db.query(User.id, User.subject).all()
            users_data = [{"id": u.id, "subject": u.subject} for u in users]

            # Get all groups
            groups = db.query(Group.id, Group.name).all()
            groups_data = [{"id": g.id, "name": g.name} for g in groups]

            # Get all roles
            roles = db.query(Role.id, Role.name).all()
            roles_data = [{"id": r.id, "name": r.name} for r in roles]

            # Get all actions
            actions = db.query(Action.id, Action.name).all()
            actions_data = [{"id": a.id, "name": a.name} for a in actions]

            # Get all memberships (user-group relationships)
            memberships = db.query(Membership.user_id, Membership.group_id).all()
            memberships_data = [{"user_id": m.user_id, "group_id": m.group_id} for m in memberships]

            # Get all group-role assignments
            group_roles = db.query(GroupRole.group_id, GroupRole.role_id).all()
            group_roles_data = [{"group_id": gr.group_id, "role_id": gr.role_id} for gr in group_roles]

            # Get all role-action assignments
            role_actions = db.query(RoleAction.role_id, RoleAction.action_id).all()
            role_actions_data = [{"role_id": ra.role_id, "action_id": ra.action_id} for ra in role_actions]

            return {
                "users": users_data,
                "groups": groups_data,
                "roles": roles_data,
                "actions": actions_data,
                "memberships": memberships_data,
                "group_roles": group_roles_data,
                "role_actions": role_actions_data
            }

        except Exception as e:
            # Log error using base service logger
            logger = getattr(self, 'logger', None)
            if logger:
                logger.error(f"Error extracting policy data: {str(e)}")
            raise

    def _calculate_state_hash(self, policy_data: dict[str, Any]) -> str:
        """
        Calculate a hash of the policy-relevant data.
        Uses SHA-256 for consistency and performance.
        """
        try:
            # Convert to deterministic JSON string
            json_str = json.dumps(policy_data, sort_keys=True, separators=(',', ':'))

            # Calculate SHA-256 hash
            hash_obj = hashlib.sha256(json_str.encode('utf-8'))
            return hash_obj.hexdigest()

        except Exception as e:
            # Log error using base service logger
            logger = getattr(self, 'logger', None)
            if logger:
                logger.error(f"Error calculating state hash: {str(e)}")
            raise

    def get_current_state_hash(self, db: Session) -> str:
        """
        Get the current state hash of policy-relevant data.
        """
        with self.trace_operation("get_current_state_hash") as span:
            try:
                policy_data = self._get_policy_relevant_data(db)
                current_hash = self._calculate_state_hash(policy_data)

                span.set_attribute("data_entities_count", len(policy_data))
                span.set_attribute("state_hash", current_hash[:16])  # Log first 16 chars for debugging

                return current_hash

            except Exception as e:
                span.record_exception(e)
                # Log error using base service logger
                logger = getattr(self, 'logger', None)
                if logger:
                    logger.error(f"Error getting current state hash: {str(e)}")
                raise

    def get_stored_state_hash(self) -> str | None:
        """
        Get the stored state hash from Redis.
        Returns None if no hash is stored.
        """
        with self.trace_operation("get_stored_state_hash") as span:
            try:
                # Try to get from Redis if available
                try:
                    from app.services.cache import CacheService
                    cache_service = CacheService()
                    stored_hash = cache_service.get(self.redis_key)

                    span.set_attribute("stored_hash_found", stored_hash is not None)
                    if stored_hash:
                        span.set_attribute("stored_hash", stored_hash[:16])

                    return stored_hash

                except ImportError:
                    # Cache service not available, return None
                    span.set_attribute("cache_unavailable", True)
                    return None

            except Exception as e:
                span.record_exception(e)
                # Log warning using base service logger
                logger = getattr(self, 'logger', None)
                if logger:
                    logger.warning(f"Error getting stored state hash: {str(e)}")
                return None

    def update_stored_state_hash(self, new_hash: str) -> bool:
        """
        Update the stored state hash in Redis.
        Returns True if successful, False otherwise.
        """
        with self.trace_operation("update_stored_state_hash") as span:
            try:
                span.set_attribute("new_hash", new_hash[:16])

                # Try to store in Redis if available
                try:
                    from app.services.cache import CacheService
                    cache_service = CacheService()
                    success = cache_service.set(self.redis_key, new_hash)

                    span.set_attribute("update_successful", success)
                    return success

                except ImportError:
                    # Cache service not available
                    span.set_attribute("cache_unavailable", True)
                    return False

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("update_successful", False)
                # Log warning using base service logger
                logger = getattr(self, 'logger', None)
                if logger:
                    logger.warning(f"Error updating stored state hash: {str(e)}")
                return False

    def has_policy_data_changed(self, db: Session) -> bool:
        """
        Check if policy-relevant data has changed since last check.
        Returns True if data has changed or if no previous hash exists.
        """
        with self.trace_operation("has_policy_data_changed") as span:
            try:
                current_hash = self.get_current_state_hash(db)
                stored_hash = self.get_stored_state_hash()

                has_changed = stored_hash is None or current_hash != stored_hash

                span.set_attribute("current_hash", current_hash[:16])
                span.set_attribute("stored_hash", stored_hash[:16] if stored_hash else "none")
                span.set_attribute("has_changed", has_changed)

                if has_changed:
                    # Log info using base service logger
                    logger = getattr(self, 'logger', None)
                    if logger:
                        logger.info(f"Policy data changed - Current: {current_hash[:16]}, Stored: {stored_hash[:16] if stored_hash else 'none'}")

                return has_changed

            except Exception as e:
                span.record_exception(e)
                # Log error using base service logger
                logger = getattr(self, 'logger', None)
                if logger:
                    logger.error(f"Error checking policy data changes: {str(e)}")
                # On error, assume data changed to trigger sync
                return True

    def mark_policy_data_synced(self, db: Session) -> bool:
        """
        Mark the current policy data as synced by updating the stored hash.
        Should be called after successful policy synchronization.
        """
        with self.trace_operation("mark_policy_data_synced") as span:
            try:
                current_hash = self.get_current_state_hash(db)
                success = self.update_stored_state_hash(current_hash)

                span.set_attribute("sync_marked", success)

                # Log info/warning using base service logger
                logger = getattr(self, 'logger', None)
                if success:
                    if logger:
                        logger.info(f"Policy data marked as synced - Hash: {current_hash[:16]}")
                else:
                    if logger:
                        logger.warning("Failed to mark policy data as synced")

                return success

            except Exception as e:
                span.record_exception(e)
                # Log error using base service logger
                logger = getattr(self, 'logger', None)
                if logger:
                    logger.error(f"Error marking policy data as synced: {str(e)}")
                return False

    def get_change_summary(self, db: Session) -> dict[str, Any]:
        """
        Get a summary of current policy data for debugging/monitoring.
        """
        with self.trace_operation("get_change_summary") as span:
            try:
                policy_data = self._get_policy_relevant_data(db)
                current_hash = self._calculate_state_hash(policy_data)
                stored_hash = self.get_stored_state_hash()

                summary = {
                    "current_hash": current_hash,
                    "stored_hash": stored_hash,
                    "has_changed": stored_hash is None or current_hash != stored_hash,
                    "entity_counts": {
                        "users": len(policy_data["users"]),
                        "groups": len(policy_data["groups"]),
                        "roles": len(policy_data["roles"]),
                        "actions": len(policy_data["actions"]),
                        "memberships": len(policy_data["memberships"]),
                        "group_roles": len(policy_data["group_roles"]),
                        "role_actions": len(policy_data["role_actions"])
                    }
                }

                span.set_attribute("total_entities", sum(summary["entity_counts"].values()))

                return summary

            except Exception as e:
                span.record_exception(e)
                # Log error using base service logger
                logger = getattr(self, 'logger', None)
                if logger:
                    logger.error(f"Error getting change summary: {str(e)}")
                return {"error": str(e)}
