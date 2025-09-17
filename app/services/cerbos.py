"""
Cerbos integration service with OpenTelemetry tracing.
Implements Cerbos Check and Admin API calls as specified in SPEC.md Section 4.
"""

import time
import uuid
from typing import Any

import requests
from opentelemetry import trace

from app.exceptions import CerbosUnavailableError
from app.services.base import BaseService
from app.settings import settings


class CerbosService(BaseService):
    """Service for Cerbos API interactions with distributed tracing."""

    def __init__(self):
        super().__init__("cerbos")
        self.base_url = settings.get_cerbos_base_url()
        self.check_url = f"{self.base_url}/api/check/resources"
        self.admin_url = f"{self.base_url}/admin/policy"
        self.server_info_url = f"{self.base_url}/api/server_info"
        self.admin_user = settings.CERBOS_ADMIN_USER
        self.admin_password = settings.CERBOS_ADMIN_PASSWORD
        self.max_retries = 3
        self.base_retry_delay = 1.0  # seconds

    def _retry_with_backoff(self, operation_func, *args, **kwargs):
        """Execute operation with exponential backoff retry logic."""
        last_exception = None

        for attempt in range(self.max_retries + 1):
            try:
                return operation_func(*args, **kwargs)
            except requests.RequestException as e:
                last_exception = e
                if attempt < self.max_retries:
                    delay = self.base_retry_delay * (2**attempt)
                    time.sleep(delay)
                    continue
                raise
            except Exception:
                # Don't retry for non-network errors
                raise

        raise last_exception

    def build_check_payload(
        self,
        caller_subject: str,
        caller_roles: list[str],
        action: str,
        resource_type: str,
        resource_attrs: dict[str, Any],
    ) -> dict[str, Any]:
        """Build Cerbos check payload as specified in SPEC.md Section 7."""
        # Cerbos requires at least one role, so provide a default if empty
        effective_roles = caller_roles if caller_roles else ["user"]

        return {
            "requestId": f"admin-{uuid.uuid4()}",
            "principal": {
                "id": caller_subject,
                "roles": effective_roles,
                "policyVersion": "default",
                "attr": {},
            },
            "resources": [
                {
                    "resource": {
                        "kind": resource_type,
                        "id": resource_type,
                        "attr": resource_attrs
                    },
                    "actions": [action],
                }
            ],
        }

    def check_permission(
        self,
        caller_subject: str,
        caller_roles: list[str],
        action: str,
        resource_type: str,
        resource_attrs: dict[str, Any],
    ) -> bool:
        """Check permission using Cerbos Check API with tracing."""
        with self.trace_operation(
            "check_permission",
            {
                "cerbos.action": action,
                "cerbos.resource_type": resource_type,
                "cerbos.caller_subject": caller_subject,
                "cerbos.caller_roles_count": len(caller_roles),
            },
        ) as span:
            # Fast availability check using health monitor
            # Note: We'll inject this dependency later to avoid circular imports
            try:
                from app.services.health_monitor import HealthMonitor
                health_monitor = HealthMonitor()
                if not health_monitor.is_cerbos_available():
                    span.set_attribute("cerbos.service_unavailable", True)
                    raise CerbosUnavailableError()
            except ImportError:
                # Health monitor not available, proceed with normal check
                pass
            try:
                # Build check payload
                check_payload = self.build_check_payload(
                    caller_subject, caller_roles, action, resource_type, resource_attrs
                )

                # Add request details to span
                span.set_attribute("cerbos.request_id", check_payload["requestId"])
                span.set_attribute("cerbos.check_url", self.check_url)

                # Make API call with retry logic
                def _make_check_request():
                    response = requests.post(
                        self.check_url, json=check_payload, timeout=5
                    )
                    response.raise_for_status()
                    return response

                response = self._retry_with_backoff(_make_check_request)

                # Parse response
                resp_data = response.json()

                # Debug: Log the actual response to understand what Cerbos is returning
                span.set_attribute("cerbos.response_data", str(resp_data))

                # Check if response has expected structure (Cerbos uses "results" not "responses")
                if "results" not in resp_data:
                    span.set_attribute("cerbos.missing_results_field", True)
                    if "error" in resp_data:
                        span.set_attribute("cerbos.error_response", resp_data["error"])
                        raise ValueError(f"Cerbos error: {resp_data['error']}")
                    else:
                        raise ValueError(f"Unexpected Cerbos response format: {resp_data}")

                # Cerbos API returns results[0].actions[action] format
                result = resp_data["results"][0]["actions"][action]
                is_allowed = result == "EFFECT_ALLOW"

                # Add result to span
                span.set_attribute("cerbos.result", result)
                span.set_attribute("cerbos.allowed", is_allowed)
                span.set_attribute("http.status_code", response.status_code)

                return is_allowed

            except requests.RequestException as e:
                span.record_exception(e)
                span.set_attribute("cerbos.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                # Convert connection errors to service unavailable
                if "Connection" in str(e) or "timeout" in str(e).lower():
                    raise CerbosUnavailableError(e)
                raise
            except Exception as e:
                span.record_exception(e)
                span.set_attribute("cerbos.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def push_policy(self, policy_id: str, policy_data: dict[str, Any]) -> bool:
        """Push policy to Cerbos Admin API with tracing."""
        with self.trace_operation(
            "push_policy",
            {"cerbos.policy_id": policy_id, "cerbos.admin_url": self.admin_url},
        ) as span:
            try:
                # Make authenticated API call using correct Cerbos format
                response = requests.put(
                    self.admin_url,  # Use base URL
                    json={"policies": [policy_data]},  # Wrap in policies array
                    auth=(self.admin_user, self.admin_password),
                    timeout=5,
                )
                response.raise_for_status()

                # Add result to span
                span.set_attribute("http.status_code", response.status_code)
                span.set_attribute("cerbos.policy_pushed", True)

                return True

            except requests.RequestException as e:
                span.record_exception(e)
                span.set_attribute("cerbos.error", str(e))
                span.set_attribute("cerbos.policy_pushed", False)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise
            except Exception as e:
                span.record_exception(e)
                span.set_attribute("cerbos.error", str(e))
                span.set_attribute("cerbos.policy_pushed", False)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    # Specific permission checking methods for admin operations

    def can_create_group(
        self, caller_subject: str, caller_roles: list[str], group_name: str
    ) -> bool:
        """Check if caller can create a group."""
        return self.check_permission(
            caller_subject=caller_subject,
            caller_roles=caller_roles,
            action="group:create",
            resource_type="group",
            resource_attrs={"name": group_name},
        )

    def can_delete_group(
        self, caller_subject: str, caller_roles: list[str], group_name: str
    ) -> bool:
        """Check if caller can delete a group."""
        return self.check_permission(
            caller_subject=caller_subject,
            caller_roles=caller_roles,
            action="group:delete",
            resource_type="group",
            resource_attrs={"name": group_name},
        )

    def can_add_member(
        self, caller_subject: str, caller_roles: list[str], group_name: str
    ) -> bool:
        """Check if caller can add members to a group."""
        return self.check_permission(
            caller_subject=caller_subject,
            caller_roles=caller_roles,
            action="group:add_member",
            resource_type="group",
            resource_attrs={"name": group_name},
        )

    def can_remove_member(
        self, caller_subject: str, caller_roles: list[str], group_name: str
    ) -> bool:
        """Check if caller can remove members from a group."""
        return self.check_permission(
            caller_subject=caller_subject,
            caller_roles=caller_roles,
            action="group:remove_member",
            resource_type="group",
            resource_attrs={"name": group_name},
        )

    def can_assign_role(
        self, caller_subject: str, caller_roles: list[str], group_name: str
    ) -> bool:
        """Check if caller can assign roles to a group."""
        return self.check_permission(
            caller_subject=caller_subject,
            caller_roles=caller_roles,
            action="group:assign_role",
            resource_type="group",
            resource_attrs={"name": group_name},
        )

    def can_remove_role(
        self, caller_subject: str, caller_roles: list[str], group_name: str
    ) -> bool:
        """Check if caller can remove roles from a group."""
        return self.check_permission(
            caller_subject=caller_subject,
            caller_roles=caller_roles,
            action="group:remove_role",
            resource_type="group",
            resource_attrs={"name": group_name},
        )

    def can_create_mapping(
        self, caller_subject: str, caller_roles: list[str], action_name: str
    ) -> bool:
        """Check if caller can create mappings."""
        return self.check_permission(
            caller_subject=caller_subject,
            caller_roles=caller_roles,
            action="mapping:create",
            resource_type="mapping",
            resource_attrs={"action": action_name},
        )

    def can_update_mapping(
        self, caller_subject: str, caller_roles: list[str], mapping_id: int
    ) -> bool:
        """Check if caller can update mappings."""
        return self.check_permission(
            caller_subject=caller_subject,
            caller_roles=caller_roles,
            action="mapping:update",
            resource_type="mapping",
            resource_attrs={"id": str(mapping_id)},
        )

    def can_delete_mapping(
        self, caller_subject: str, caller_roles: list[str], mapping_id: int
    ) -> bool:
        """Check if caller can delete mappings."""
        return self.check_permission(
            caller_subject=caller_subject,
            caller_roles=caller_roles,
            action="mapping:delete",
            resource_type="mapping",
            resource_attrs={"id": str(mapping_id)},
        )

    # Transparent Policy Management Methods

    def build_principal_policy(
        self, user_subject: str, user_roles: list[str]
    ) -> dict[str, Any]:
        """
        Build principal policy for a user from their roles.
        Superadmin users get wildcard access, others get specific role-action assignments.
        Implements policy format as specified in SPEC.md Section 4.2.
        """
        from app.database import get_db_session
        from app.models import Action, Role, RoleAction

        policy_id = f"principal_{user_subject.replace(':', '_').replace('@', '_at_')}"

        # Check if user has superadmin role - if so, grant everything
        if "superadmin" in user_roles:
            action_rules = [
                {
                    "action": "*",
                    "effect": "EFFECT_ALLOW"
                }
            ]
        else:
            # For non-superadmin users, collect actions from role assignments
            all_actions = set()
            session = get_db_session()

            try:
                for role_name in user_roles:
                    role = session.query(Role).filter(Role.name == role_name).first()
                    if role:
                        # Get actions assigned to this role
                        role_actions = session.query(Action).join(RoleAction).filter(
                            RoleAction.role_id == role.id
                        ).all()
                        for action in role_actions:
                            all_actions.add(action.name)
            finally:
                session.close()

            # Convert actions to Cerbos rule format
            if all_actions:
                action_rules = [
                    {
                        "action": action_name,
                        "effect": "EFFECT_ALLOW"
                    }
                    for action_name in sorted(all_actions)
                ]
            else:
                # If no actions assigned, deny everything
                action_rules = [
                    {
                        "action": "*",
                        "effect": "EFFECT_DENY"
                    }
                ]

        return {
            "apiVersion": "api.cerbos.dev/v1",
            "principalPolicy": {
                "principal": user_subject,
                "version": "default",
                "rules": [
                    {
                        "resource": "*",
                        "actions": action_rules
                    }
                ]
            },
            "metadata": {"storeIdentifier": policy_id},
        }

    def push_user_policy(self, user_subject: str, user_roles: list[str]) -> bool:
        """
        Push user policy to Cerbos Admin API.
        Implements transparent policy management as specified in SPEC.md Section 4.2.
        """
        with self.trace_operation(
            "push_user_policy",
            {
                "cerbos.user_subject": user_subject,
                "cerbos.roles_count": len(user_roles),
                "cerbos.operation": "push_policy",
            },
        ) as span:
            try:
                # Build policy
                policy_data = self.build_principal_policy(user_subject, user_roles)
                policy_id = policy_data["metadata"]["storeIdentifier"]

                span.set_attribute("cerbos.policy_id", policy_id)
                span.set_attribute("cerbos.user_roles", user_roles)

                # Push policy with retry using correct Cerbos format
                def _make_policy_request():
                    response = requests.put(
                        self.admin_url,  # Use base URL
                        json={"policies": [policy_data]},  # Wrap in policies array
                        auth=(self.admin_user, self.admin_password),
                        timeout=10,
                    )
                    response.raise_for_status()
                    return response

                response = self._retry_with_backoff(_make_policy_request)

                span.set_attribute("http.status_code", response.status_code)
                span.set_attribute("cerbos.policy_pushed", True)
                span.set_attribute("cerbos.policy_push_successful", True)

                return True

            except requests.RequestException as e:
                span.record_exception(e)
                span.set_attribute("cerbos.error", str(e))
                span.set_attribute("cerbos.policy_pushed", False)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise
            except Exception as e:
                span.record_exception(e)
                span.set_attribute("cerbos.error", str(e))
                span.set_attribute("cerbos.policy_pushed", False)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def ensure_superadmin_policy(self) -> bool:
        """
        Ensure that a policy exists to grant superadmin role all permissions.
        This should be called at application startup.
        """
        with self.trace_operation(
            "ensure_superadmin_policy",
            {"cerbos.operation": "ensure_policy"},
        ) as span:
            try:
                # Create resource policies for each resource type to grant superadmin full access
                # Cannot use wildcard "*" in resource field, so create policies for each resource
                policies_to_create = []

                resource_types = ["group", "user", "role", "action", "mapping", "membership"]
                for resource_type in resource_types:
                    policy = {
                        "apiVersion": "api.cerbos.dev/v1",
                        "metadata": {
                            "storeIdentifier": f"resource_{resource_type}_superadmin"
                        },
                        "resourcePolicy": {
                            "resource": resource_type,
                            "version": "default",
                            "rules": [
                                {
                                    "actions": ["*"],
                                    "roles": ["superadmin"],
                                    "effect": "EFFECT_ALLOW"
                                }
                            ]
                        }
                    }
                    policies_to_create.append(policy)

                # Try to push all policies using correct Cerbos API format
                def _make_policy_request():
                    response = requests.put(
                        self.admin_url,  # Use base URL, not with policy_id
                        json={"policies": policies_to_create},  # Send all policies at once
                        auth=(self.admin_user, self.admin_password),
                        timeout=10,
                    )
                    response.raise_for_status()
                    return response

                response = self._retry_with_backoff(_make_policy_request)

                span.set_attribute("cerbos.policy_created", True)
                span.set_attribute("http.status_code", response.status_code)

                return True

            except requests.RequestException as e:
                span.record_exception(e)
                span.set_attribute("cerbos.policy_creation_failed", True)
                span.set_attribute("cerbos.error", str(e))

                # Log detailed instructions for manual policy creation
                error_msg = str(e)
                if "Admin service is disabled" in error_msg:
                    span.set_attribute("cerbos.admin_disabled", True)
                    # This is expected - log instructions but don't fail
                    return False
                else:
                    # Unexpected error - log but don't fail startup
                    span.set_attribute("cerbos.unexpected_error", True)
                    return False
            except Exception as e:
                span.record_exception(e)
                span.set_attribute("cerbos.policy_creation_error", str(e))
                return False

    def get_superadmin_policy_template(self) -> dict:
        """
        Get the superadmin policy template for external configuration.
        Users can apply this policy manually when Cerbos admin API is disabled.
        """
        return {
            "apiVersion": "api.cerbos.dev/v1",
            "metadata": {
                "storeIdentifier": "resource_superadmin_all"
            },
            "resourcePolicy": {
                "resource": "*",
                "version": "default",
                "rules": [
                    {
                        "actions": ["*"],
                        "roles": ["superadmin"],
                        "effect": "EFFECT_ALLOW"
                    }
                ]
            }
        }

    def delete_user_policy(self, user_subject: str) -> bool:
        """Delete user policy from Cerbos Admin API."""
        with self.trace_operation(
            "delete_user_policy",
            {"cerbos.user_subject": user_subject, "cerbos.operation": "delete_policy"},
        ) as span:
            try:
                policy_id = (
                    f"principal_{user_subject.replace(':', '_').replace('@', '_at_')}"
                )
                span.set_attribute("cerbos.policy_id", policy_id)

                # Delete policy with retry
                def _make_delete_request():
                    response = requests.delete(
                        f"{self.admin_url}/{policy_id}",
                        auth=(self.admin_user, self.admin_password),
                        timeout=10,
                    )
                    response.raise_for_status()
                    return response

                response = self._retry_with_backoff(_make_delete_request)

                span.set_attribute("http.status_code", response.status_code)
                span.set_attribute("cerbos.policy_deleted", True)

                return True

            except requests.RequestException as e:
                span.record_exception(e)
                span.set_attribute("cerbos.error", str(e))
                span.set_attribute("cerbos.policy_deleted", False)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise
            except Exception as e:
                span.record_exception(e)
                span.set_attribute("cerbos.error", str(e))
                span.set_attribute("cerbos.policy_deleted", False)
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def sync_affected_users_policies(self, db_session, role_name: str) -> int:
        """
        Sync Cerbos policies for all users affected by changes to a specific role.
        Returns the number of users whose policies were successfully synced.
        """
        from app.models import GroupRole, Membership, Role, User
        from app.services.user import UserService

        with self.trace_operation(
            "sync_affected_users_policies",
            {"role_name": role_name, "operation": "immediate_policy_sync"}
        ) as span:
            try:
                user_service = UserService()

                # Find all users who have this role (through group membership)
                affected_users = (
                    db_session.query(User)
                    .join(Membership, User.id == Membership.user_id)
                    .join(GroupRole, Membership.group_id == GroupRole.group_id)
                    .join(Role, GroupRole.role_id == Role.id)
                    .filter(Role.name == role_name)
                    .distinct()
                    .all()
                )

                span.set_attribute("affected_users_count", len(affected_users))

                synced_count = 0
                failed_count = 0

                for user in affected_users:
                    try:
                        # Get user's current roles
                        user_roles = user_service.get_user_roles(db_session, user)

                        # Sync the user's policy to Cerbos
                        success = self.push_user_policy(
                            user_subject=user.subject,
                            user_roles=user_roles
                        )

                        if success:
                            synced_count += 1
                        else:
                            failed_count += 1

                    except Exception as e:
                        failed_count += 1
                        span.record_exception(e)

                span.set_attribute("users_synced", synced_count)
                span.set_attribute("users_failed", failed_count)

                return synced_count

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("sync_error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                return 0

    def sync_group_users_policies(self, db_session, group_name: str) -> int:
        """
        Sync Cerbos policies for all users who are members of a specific group.
        Returns the number of users whose policies were successfully synced.
        """
        from app.models import Membership, User
        from app.services.user import UserService

        with self.trace_operation(
            "sync_group_users_policies",
            {"group_name": group_name, "operation": "immediate_policy_sync"}
        ) as span:
            try:
                user_service = UserService()

                # Find all users who are members of this group
                affected_users = (
                    db_session.query(User)
                    .join(Membership, User.id == Membership.user_id)
                    .join(Membership.group)
                    .filter(Membership.group.has(name=group_name))
                    .distinct()
                    .all()
                )

                span.set_attribute("affected_users_count", len(affected_users))

                synced_count = 0
                failed_count = 0

                for user in affected_users:
                    try:
                        # Get user's current roles
                        user_roles = user_service.get_user_roles(db_session, user)

                        # Sync the user's policy to Cerbos
                        success = self.push_user_policy(
                            user_subject=user.subject,
                            user_roles=user_roles
                        )

                        if success:
                            synced_count += 1
                        else:
                            failed_count += 1

                    except Exception as e:
                        failed_count += 1
                        span.record_exception(e)

                span.set_attribute("users_synced", synced_count)
                span.set_attribute("users_failed", failed_count)

                return synced_count

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("sync_error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                return 0

    def health_check(self) -> bool:
        """
        Check Cerbos API health.
        Returns True if Cerbos is reachable and responding.
        """
        with self.trace_operation(
            "health_check", {"cerbos.operation": "health_check"}
        ) as span:
            try:
                span.set_attribute("cerbos.server_info_url", self.server_info_url)

                def _make_health_request():
                    return requests.get(self.server_info_url, timeout=5)

                response = self._retry_with_backoff(_make_health_request)

                # Cerbos is healthy if server_info returns 200
                is_healthy = response.status_code == 200
                span.set_attribute("cerbos.healthy", is_healthy)
                span.set_attribute("http.status_code", response.status_code)

                if is_healthy:
                    # Log server info for debugging
                    try:
                        server_info = response.json()
                        span.set_attribute("cerbos.version", server_info.get("version", "unknown"))
                    except Exception:
                        pass  # Ignore JSON parsing errors

                return is_healthy

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("cerbos.healthy", False)
                span.set_attribute("cerbos.error", str(e))
                return False
