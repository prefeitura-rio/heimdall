"""
Cerbos integration service with OpenTelemetry tracing.
Implements Cerbos Check and Admin API calls as specified in SPEC.md Section 4.
"""

import os
import time
import uuid
from typing import Any

import requests
from opentelemetry import trace

from app.services.base import BaseService


class CerbosService(BaseService):
    """Service for Cerbos API interactions with distributed tracing."""

    def __init__(self):
        super().__init__("cerbos")
        self.check_url = os.getenv(
            "CERBOS_CHECK_URL", "http://cerbos:3593/api/check/resources"
        )
        self.admin_url = os.getenv(
            "CERBOS_ADMIN_URL", "http://cerbos:3592/admin/policy"
        )
        self.admin_user = os.getenv("CERBOS_ADMIN_USER", "admin")
        self.admin_password = os.getenv("CERBOS_ADMIN_PASSWORD", "password")
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
        return {
            "requestId": f"admin-{uuid.uuid4()}",
            "principal": {
                "id": caller_subject,
                "roles": caller_roles,
                "policyVersion": "default",
                "attr": {},
            },
            "resources": [
                {
                    "resource": {"id": resource_type, "attr": resource_attrs},
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
                result = resp_data["responses"][0]["actions"][action]["result"]
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
                # Make authenticated API call
                response = requests.put(
                    f"{self.admin_url}/{policy_id}",
                    json=policy_data,
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
        Implements policy format as specified in SPEC.md Section 4.2.
        """
        policy_id = f"principal_{user_subject.replace(':', '_').replace('@', '_at_')}"

        return {
            "apiVersion": "api.cerbos.dev/v1",
            "kind": "PrincipalPolicy",
            "metadata": {"storeIdentifier": policy_id},
            "principalPolicy": {
                "principal": user_subject,
                "version": "default",
                "rules": [
                    {
                        "resource": "*",
                        "actions": [
                            {
                                "action": "*",
                                "effect": "EFFECT_ALLOW",
                                "condition": {
                                    "match": {
                                        "expr": f"P.roles.exists(r, r in {user_roles})"
                                    }
                                },
                            }
                        ],
                    }
                ],
            },
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

                # Push policy with retry
                def _make_policy_request():
                    response = requests.put(
                        f"{self.admin_url}/{policy_id}",
                        json=policy_data,
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
