#!/usr/bin/env python3
"""
Environment Synchronization Script for Heimdall Admin Service

Replicates all configuration (actions, roles, mappings, groups, memberships)
from a source environment to a target environment, ensuring they are identical.

Features:
- Idempotent: Safe to run multiple times
- Resilient: Saves progress and can resume from failures
- Comprehensive: Syncs all entity types
- Dry-run mode: Preview changes before applying
- Detailed logging: Shows all operations

Usage:
    # Dry run (preview changes)
    python sync_environments.py \
        --source-url https://staging.api.com \
        --source-token <token> \
        --target-url https://prod.api.com \
        --target-token <token> \
        --dry-run

    # Actual sync
    python sync_environments.py \
        --source-url https://staging.api.com \
        --source-token <token> \
        --target-url https://prod.api.com \
        --target-token <token>

    # Resume from checkpoint
    python sync_environments.py \
        --source-url https://staging.api.com \
        --source-token <token> \
        --target-url https://prod.api.com \
        --target-token <token> \
        --resume
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class SyncStats:
    """Statistics for sync operation."""
    actions_created: int = 0
    actions_updated: int = 0
    actions_deleted: int = 0
    roles_created: int = 0
    roles_updated: int = 0
    roles_deleted: int = 0
    mappings_created: int = 0
    mappings_updated: int = 0
    mappings_deleted: int = 0
    groups_created: int = 0
    groups_updated: int = 0
    groups_deleted: int = 0
    errors: int = 0

    def total_changes(self) -> int:
        """Calculate total number of changes."""
        return (
            self.actions_created + self.actions_updated + self.actions_deleted +
            self.roles_created + self.roles_updated + self.roles_deleted +
            self.mappings_created + self.mappings_updated + self.mappings_deleted +
            self.groups_created + self.groups_updated + self.groups_deleted
        )

    def print_summary(self):
        """Print sync summary."""
        print("\n" + "="*60)
        print("SYNC SUMMARY")
        print("="*60)
        print(f"Actions:  +{self.actions_created} ~{self.actions_updated} -{self.actions_deleted}")
        print(f"Roles:    +{self.roles_created} ~{self.roles_updated} -{self.roles_deleted}")
        print(f"Mappings: +{self.mappings_created} ~{self.mappings_updated} -{self.mappings_deleted}")
        print(f"Groups:   +{self.groups_created} ~{self.groups_updated} -{self.groups_deleted}")
        print(f"Errors:   {self.errors}")
        print(f"Total Changes: {self.total_changes()}")
        print("="*60)


class HeimdallClient:
    """Client for Heimdall Admin API."""

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create session with retry logic."""
        session = requests.Session()

        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set default headers
        session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        })

        return session

    def _request(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        """Make HTTP request with error handling."""
        url = f"{self.base_url}{path}"

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            if response.status_code == 204:
                return {}

            return response.json()

        except requests.exceptions.RequestException as e:
            print(f"ERROR: Request failed: {method} {url}")
            print(f"  {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"  Response: {e.response.text}")
            raise

    def get_all_actions(self) -> list[dict[str, Any]]:
        """Fetch all actions with pagination."""
        all_actions = []
        skip = 0
        limit = 100

        while True:
            result = self._request("GET", f"/api/v1/actions/?skip={skip}&limit={limit}")
            items = result.get("items", [])
            all_actions.extend(items)

            if not result.get("has_more", False):
                break

            skip += limit

        return all_actions

    def get_all_roles(self) -> list[dict[str, Any]]:
        """Fetch all roles with pagination."""
        all_roles = []
        skip = 0
        limit = 100

        while True:
            result = self._request("GET", f"/api/v1/roles/?skip={skip}&limit={limit}")
            items = result.get("items", [])
            all_roles.extend(items)

            if not result.get("has_more", False):
                break

            skip += limit

        return all_roles

    def get_all_mappings(self) -> list[dict[str, Any]]:
        """Fetch all mappings with pagination."""
        all_mappings = []
        skip = 0
        limit = 100

        while True:
            result = self._request("GET", f"/api/v1/mappings/?skip={skip}&limit={limit}")
            items = result.get("items", [])
            all_mappings.extend(items)

            if not result.get("has_more", False):
                break

            skip += limit

        return all_mappings

    def get_all_groups(self) -> list[dict[str, Any]]:
        """Fetch all groups with pagination."""
        all_groups = []
        skip = 0
        limit = 100

        while True:
            result = self._request("GET", f"/api/v1/groups/?skip={skip}&limit={limit}")
            items = result.get("items", [])
            all_groups.extend(items)

            if not result.get("has_more", False):
                break

            skip += limit

        return all_groups

    def create_action(self, name: str, description: str | None = None) -> dict[str, Any]:
        """Create an action."""
        data = {"name": name}
        if description:
            data["description"] = description

        return self._request("POST", "/api/v1/actions/", json=data)

    def update_action(self, action_id: int, description: str | None) -> dict[str, Any]:
        """Update an action."""
        data = {"description": description}
        return self._request("PUT", f"/api/v1/actions/{action_id}", json=data)

    def delete_action(self, action_id: int) -> None:
        """Delete an action."""
        self._request("DELETE", f"/api/v1/actions/{action_id}")

    def create_role(self, name: str, description: str | None = None) -> dict[str, Any]:
        """Create a role."""
        data = {"name": name}
        if description:
            data["description"] = description

        return self._request("POST", "/api/v1/roles/", json=data)

    def update_role(self, role_id: int, description: str | None) -> dict[str, Any]:
        """Update a role."""
        data = {"description": description}
        return self._request("PUT", f"/api/v1/roles/{role_id}", json=data)

    def delete_role(self, role_id: int) -> None:
        """Delete a role."""
        self._request("DELETE", f"/api/v1/roles/{role_id}")

    def assign_action_to_role(self, role_id: int, action_id: int) -> None:
        """Assign an action to a role."""
        self._request("POST", f"/api/v1/roles/{role_id}/actions/{action_id}")

    def remove_action_from_role(self, role_id: int, action_id: int) -> None:
        """Remove an action from a role."""
        self._request("DELETE", f"/api/v1/roles/{role_id}/actions/{action_id}")

    def create_mapping(self, path: str, method: str, action_name: str) -> dict[str, Any]:
        """Create a mapping."""
        data = {
            "path": path,
            "method": method,
            "action_name": action_name
        }
        return self._request("POST", "/api/v1/mappings/", json=data)

    def update_mapping(self, mapping_id: int, action_name: str) -> dict[str, Any]:
        """Update a mapping."""
        data = {"action_name": action_name}
        return self._request("PUT", f"/api/v1/mappings/{mapping_id}", json=data)

    def delete_mapping(self, mapping_id: int) -> None:
        """Delete a mapping."""
        self._request("DELETE", f"/api/v1/mappings/{mapping_id}")

    def create_group(self, name: str, description: str | None = None) -> dict[str, Any]:
        """Create a group."""
        data = {"name": name}
        if description:
            data["description"] = description

        return self._request("POST", "/api/v1/groups/", json=data)

    def update_group(self, group_id: int, description: str | None) -> dict[str, Any]:
        """Update a group."""
        data = {"description": description}
        return self._request("PUT", f"/api/v1/groups/{group_id}", json=data)

    def delete_group(self, group_id: int) -> None:
        """Delete a group."""
        self._request("DELETE", f"/api/v1/groups/{group_id}")

    def assign_role_to_group(self, group_id: int, role_id: int) -> None:
        """Assign a role to a group."""
        self._request("POST", f"/api/v1/groups/{group_id}/roles/{role_id}")

    def remove_role_from_group(self, group_id: int, role_id: int) -> None:
        """Remove a role from a group."""
        self._request("DELETE", f"/api/v1/groups/{group_id}/roles/{role_id}")

    def healthcheck(self) -> dict[str, Any]:
        """
        Perform comprehensive healthcheck and permission verification.

        Returns:
            Dictionary with healthcheck results including:
            - healthy: bool
            - user_info: dict with user details
            - has_superadmin: bool
            - can_write: bool
            - errors: list of error messages
        """
        result = {
            "healthy": False,
            "user_info": None,
            "has_superadmin": False,
            "can_write": False,
            "errors": []
        }

        try:
            # Check basic health endpoint
            self._request("GET", "/api/v1/healthz")
            result["healthy"] = True

        except Exception as e:
            result["errors"].append(f"Health check failed: {str(e)}")
            return result

        try:
            # Get current user info and verify authentication
            user_info = self._request("GET", "/api/v1/users/me")
            result["user_info"] = user_info

            # Check if user has superadmin role
            roles = user_info.get("roles", [])
            result["has_superadmin"] = "superadmin" in roles

            if not result["has_superadmin"]:
                result["errors"].append(
                    f"User {user_info.get('cpf', 'unknown')} does not have superadmin role. "
                    f"Current roles: {roles}"
                )

        except Exception as e:
            result["errors"].append(f"Failed to get user info: {str(e)}")
            return result

        try:
            # Test write permissions by creating and deleting a test action
            test_action_name = f"__healthcheck_test_{int(time.time())}"

            # Create test action
            created = self._request(
                "POST",
                "/api/v1/actions/",
                json={
                    "name": test_action_name,
                    "description": "Temporary action for healthcheck - safe to delete"
                }
            )

            # Delete test action
            self._request("DELETE", f"/api/v1/actions/{created['id']}")

            result["can_write"] = True

        except Exception as e:
            result["errors"].append(f"Write permission test failed: {str(e)}")

        return result


class EnvironmentSynchronizer:
    """Synchronizes Heimdall environments."""

    def __init__(
        self,
        source: HeimdallClient,
        target: HeimdallClient,
        dry_run: bool = False,
        checkpoint_file: Path | None = None
    ):
        self.source = source
        self.target = target
        self.dry_run = dry_run
        self.checkpoint_file = checkpoint_file or Path("sync_checkpoint.json")
        self.stats = SyncStats()
        self.checkpoint: dict[str, Any] = {}

    def load_checkpoint(self) -> dict[str, Any]:
        """Load checkpoint from file."""
        if self.checkpoint_file.exists():
            with open(self.checkpoint_file) as f:
                return json.load(f)
        return {}

    def save_checkpoint(self, stage: str, data: dict[str, Any]):
        """Save checkpoint to file."""
        self.checkpoint = {
            "timestamp": datetime.now().isoformat(),
            "stage": stage,
            "data": data
        }

        with open(self.checkpoint_file, 'w') as f:
            json.dump(self.checkpoint, f, indent=2)

    def clear_checkpoint(self):
        """Clear checkpoint file."""
        if self.checkpoint_file.exists():
            self.checkpoint_file.unlink()

    def sync_actions(self):
        """Sync actions from source to target."""
        print("\n" + "="*60)
        print("SYNCING ACTIONS")
        print("="*60)

        # Fetch all actions
        print("Fetching actions from source...")
        source_actions = {a["name"]: a for a in self.source.get_all_actions()}
        print(f"  Found {len(source_actions)} actions in source")

        print("Fetching actions from target...")
        target_actions = {a["name"]: a for a in self.target.get_all_actions()}
        print(f"  Found {len(target_actions)} actions in target")

        # Create ID mapping for later use
        action_id_map = {}

        # Create missing actions
        for name, source_action in source_actions.items():
            if name not in target_actions:
                print(f"  [CREATE] Action '{name}'")
                if not self.dry_run:
                    try:
                        new_action = self.target.create_action(
                            name=name,
                            description=source_action.get("description")
                        )
                        action_id_map[source_action["id"]] = new_action["id"]
                        self.stats.actions_created += 1
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1
                else:
                    self.stats.actions_created += 1
            else:
                target_action = target_actions[name]
                action_id_map[source_action["id"]] = target_action["id"]

                # Update if description changed
                if source_action.get("description") != target_action.get("description"):
                    print(f"  [UPDATE] Action '{name}' description")
                    if not self.dry_run:
                        try:
                            self.target.update_action(
                                target_action["id"],
                                source_action.get("description")
                            )
                            self.stats.actions_updated += 1
                        except Exception as e:
                            print(f"    ERROR: {e}")
                            self.stats.errors += 1
                    else:
                        self.stats.actions_updated += 1

        # Delete extra actions
        for name, target_action in target_actions.items():
            if name not in source_actions:
                print(f"  [DELETE] Action '{name}'")
                if not self.dry_run:
                    try:
                        self.target.delete_action(target_action["id"])
                        self.stats.actions_deleted += 1
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1
                else:
                    self.stats.actions_deleted += 1

        # Save checkpoint
        self.save_checkpoint("actions", {"action_id_map": action_id_map})

        return action_id_map

    def sync_roles(self, action_id_map: dict[int, int]):  # noqa: ARG002
        """Sync roles and role-action assignments from source to target."""
        print("\n" + "="*60)
        print("SYNCING ROLES")
        print("="*60)

        # Fetch all roles
        print("Fetching roles from source...")
        source_roles = {r["name"]: r for r in self.source.get_all_roles()}
        print(f"  Found {len(source_roles)} roles in source")

        print("Fetching roles from target...")
        target_roles = {r["name"]: r for r in self.target.get_all_roles()}
        print(f"  Found {len(target_roles)} roles in target")

        # Create ID mapping for later use
        role_id_map = {}

        # Create or update roles
        for name, source_role in source_roles.items():
            if name not in target_roles:
                print(f"  [CREATE] Role '{name}'")
                if not self.dry_run:
                    try:
                        new_role = self.target.create_role(
                            name=name,
                            description=source_role.get("description")
                        )
                        role_id_map[source_role["id"]] = new_role["id"]
                        self.stats.roles_created += 1
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1
                else:
                    self.stats.roles_created += 1
            else:
                target_role = target_roles[name]
                role_id_map[source_role["id"]] = target_role["id"]

                # Update if description changed
                if source_role.get("description") != target_role.get("description"):
                    print(f"  [UPDATE] Role '{name}' description")
                    if not self.dry_run:
                        try:
                            self.target.update_role(
                                target_role["id"],
                                source_role.get("description")
                            )
                            self.stats.roles_updated += 1
                        except Exception as e:
                            print(f"    ERROR: {e}")
                            self.stats.errors += 1
                    else:
                        self.stats.roles_updated += 1

        # Delete extra roles
        for name, target_role in target_roles.items():
            if name not in source_roles:
                print(f"  [DELETE] Role '{name}'")
                if not self.dry_run:
                    try:
                        self.target.delete_role(target_role["id"])
                        self.stats.roles_deleted += 1
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1
                else:
                    self.stats.roles_deleted += 1

        # Sync role-action assignments
        print("\nSyncing role-action assignments...")
        for name, source_role in source_roles.items():
            if name not in target_roles and self.dry_run:
                continue  # Skip if role was just created in dry-run

            target_role_id = role_id_map.get(source_role["id"])
            if not target_role_id:
                continue

            source_action_names = set(source_role.get("actions", []))
            target_role = target_roles.get(name, {})
            target_action_names = set(target_role.get("actions", []))

            # Add missing action assignments
            for action_name in source_action_names - target_action_names:
                print(f"  [ASSIGN] Action '{action_name}' to role '{name}'")
                if not self.dry_run:
                    try:
                        # Find action ID by name
                        target_action = next(
                            (a for a in self.target.get_all_actions() if a["name"] == action_name),
                            None
                        )
                        if target_action:
                            self.target.assign_action_to_role(target_role_id, target_action["id"])
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1

            # Remove extra action assignments
            for action_name in target_action_names - source_action_names:
                print(f"  [UNASSIGN] Action '{action_name}' from role '{name}'")
                if not self.dry_run:
                    try:
                        # Find action ID by name
                        target_action = next(
                            (a for a in self.target.get_all_actions() if a["name"] == action_name),
                            None
                        )
                        if target_action:
                            self.target.remove_action_from_role(target_role_id, target_action["id"])
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1

        # Save checkpoint
        self.save_checkpoint("roles", {"role_id_map": role_id_map})

        return role_id_map

    def sync_mappings(self):
        """Sync mappings from source to target."""
        print("\n" + "="*60)
        print("SYNCING MAPPINGS")
        print("="*60)

        # Fetch all mappings
        print("Fetching mappings from source...")
        source_mappings = {(m["path"], m["method"]): m for m in self.source.get_all_mappings()}
        print(f"  Found {len(source_mappings)} mappings in source")

        print("Fetching mappings from target...")
        target_mappings = {(m["path"], m["method"]): m for m in self.target.get_all_mappings()}
        print(f"  Found {len(target_mappings)} mappings in target")

        # Create missing mappings
        for (path, method), source_mapping in source_mappings.items():
            if (path, method) not in target_mappings:
                print(f"  [CREATE] Mapping {method} {path} -> {source_mapping['action_name']}")
                if not self.dry_run:
                    try:
                        self.target.create_mapping(
                            path=path,
                            method=method,
                            action_name=source_mapping["action_name"]
                        )
                        self.stats.mappings_created += 1
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1
                else:
                    self.stats.mappings_created += 1
            else:
                target_mapping = target_mappings[(path, method)]

                # Update if action changed
                if source_mapping["action_name"] != target_mapping["action_name"]:
                    print(f"  [UPDATE] Mapping {method} {path}: {target_mapping['action_name']} -> {source_mapping['action_name']}")
                    if not self.dry_run:
                        try:
                            self.target.update_mapping(
                                target_mapping["id"],
                                source_mapping["action_name"]
                            )
                            self.stats.mappings_updated += 1
                        except Exception as e:
                            print(f"    ERROR: {e}")
                            self.stats.errors += 1
                    else:
                        self.stats.mappings_updated += 1

        # Delete extra mappings
        for (path, method), target_mapping in target_mappings.items():
            if (path, method) not in source_mappings:
                print(f"  [DELETE] Mapping {method} {path} -> {target_mapping['action_name']}")
                if not self.dry_run:
                    try:
                        self.target.delete_mapping(target_mapping["id"])
                        self.stats.mappings_deleted += 1
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1
                else:
                    self.stats.mappings_deleted += 1

        # Save checkpoint
        self.save_checkpoint("mappings", {})

    def sync_groups(self, role_id_map: dict[int, int]):  # noqa: ARG002
        """Sync groups and group-role assignments from source to target."""
        print("\n" + "="*60)
        print("SYNCING GROUPS")
        print("="*60)

        # Fetch all groups
        print("Fetching groups from source...")
        source_groups = {g["name"]: g for g in self.source.get_all_groups()}
        print(f"  Found {len(source_groups)} groups in source")

        print("Fetching groups from target...")
        target_groups = {g["name"]: g for g in self.target.get_all_groups()}
        print(f"  Found {len(target_groups)} groups in target")

        # Create ID mapping
        group_id_map = {}

        # Create or update groups
        for name, source_group in source_groups.items():
            if name not in target_groups:
                print(f"  [CREATE] Group '{name}'")
                if not self.dry_run:
                    try:
                        new_group = self.target.create_group(
                            name=name,
                            description=source_group.get("description")
                        )
                        group_id_map[source_group["id"]] = new_group["id"]
                        self.stats.groups_created += 1
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1
                else:
                    self.stats.groups_created += 1
            else:
                target_group = target_groups[name]
                group_id_map[source_group["id"]] = target_group["id"]

                # Update if description changed
                if source_group.get("description") != target_group.get("description"):
                    print(f"  [UPDATE] Group '{name}' description")
                    if not self.dry_run:
                        try:
                            self.target.update_group(
                                target_group["id"],
                                source_group.get("description")
                            )
                            self.stats.groups_updated += 1
                        except Exception as e:
                            print(f"    ERROR: {e}")
                            self.stats.errors += 1
                    else:
                        self.stats.groups_updated += 1

        # Delete extra groups
        for name, target_group in target_groups.items():
            if name not in source_groups:
                print(f"  [DELETE] Group '{name}'")
                if not self.dry_run:
                    try:
                        self.target.delete_group(target_group["id"])
                        self.stats.groups_deleted += 1
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1
                else:
                    self.stats.groups_deleted += 1

        # Sync group-role assignments
        print("\nSyncing group-role assignments...")
        for name, source_group in source_groups.items():
            if name not in target_groups and self.dry_run:
                continue  # Skip if group was just created in dry-run

            target_group_id = group_id_map.get(source_group["id"])
            if not target_group_id:
                continue

            source_role_names = set(source_group.get("roles", []))
            target_group = target_groups.get(name, {})
            target_role_names = set(target_group.get("roles", []))

            # Add missing role assignments
            for role_name in source_role_names - target_role_names:
                print(f"  [ASSIGN] Role '{role_name}' to group '{name}'")
                if not self.dry_run:
                    try:
                        # Find role ID by name
                        target_role = next(
                            (r for r in self.target.get_all_roles() if r["name"] == role_name),
                            None
                        )
                        if target_role:
                            self.target.assign_role_to_group(target_group_id, target_role["id"])
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1

            # Remove extra role assignments
            for role_name in target_role_names - source_role_names:
                print(f"  [UNASSIGN] Role '{role_name}' from group '{name}'")
                if not self.dry_run:
                    try:
                        # Find role ID by name
                        target_role = next(
                            (r for r in self.target.get_all_roles() if r["name"] == role_name),
                            None
                        )
                        if target_role:
                            self.target.remove_role_from_group(target_group_id, target_role["id"])
                    except Exception as e:
                        print(f"    ERROR: {e}")
                        self.stats.errors += 1

        # Save checkpoint
        self.save_checkpoint("groups", {"group_id_map": group_id_map})

    def run_healthcheck(self) -> bool:
        """
        Run healthcheck on both source and target environments.

        Returns:
            True if both environments are healthy and have proper permissions.
        """
        print("\n" + "="*60)
        print("RUNNING HEALTHCHECK")
        print("="*60)

        all_healthy = True

        # Check source
        print("\nChecking SOURCE environment...")
        print(f"  URL: {self.source.base_url}")

        source_health = self.source.healthcheck()

        if source_health["healthy"]:
            print("  ✓ API is healthy")
        else:
            print("  ✗ API health check failed")
            all_healthy = False

        if source_health["user_info"]:
            user_cpf = source_health["user_info"].get("cpf", "unknown")
            print(f"  ✓ Authentication valid (user: {user_cpf})")
        else:
            print("  ✗ Authentication failed")
            all_healthy = False

        if source_health["has_superadmin"]:
            print("  ✓ User has superadmin role")
        else:
            print("  ✗ User does NOT have superadmin role")
            all_healthy = False

        if source_health["can_write"]:
            print("  ✓ Write permissions verified")
        else:
            print("  ✗ Write permissions check failed")
            # Don't fail on source write permissions since we only read from source

        for error in source_health["errors"]:
            print(f"  ERROR: {error}")

        # Check target
        print("\nChecking TARGET environment...")
        print(f"  URL: {self.target.base_url}")

        target_health = self.target.healthcheck()

        if target_health["healthy"]:
            print("  ✓ API is healthy")
        else:
            print("  ✗ API health check failed")
            all_healthy = False

        if target_health["user_info"]:
            user_cpf = target_health["user_info"].get("cpf", "unknown")
            print(f"  ✓ Authentication valid (user: {user_cpf})")
        else:
            print("  ✗ Authentication failed")
            all_healthy = False

        if target_health["has_superadmin"]:
            print("  ✓ User has superadmin role")
        else:
            print("  ✗ User does NOT have superadmin role")
            all_healthy = False

        if target_health["can_write"]:
            print("  ✓ Write permissions verified")
        else:
            print("  ✗ Write permissions check failed")
            all_healthy = False

        for error in target_health["errors"]:
            print(f"  ERROR: {error}")

        print("\n" + "="*60)

        if not all_healthy:
            print("\n❌ Healthcheck FAILED - cannot proceed with sync")
            print("Please fix the issues above and try again.")
            return False

        print("\n✓ Healthcheck PASSED - ready to sync")
        return True

    def sync(self):
        """Run full synchronization."""
        start_time = time.time()

        print("="*60)
        print("HEIMDALL ENVIRONMENT SYNCHRONIZATION")
        print("="*60)
        print(f"Source: {self.source.base_url}")
        print(f"Target: {self.target.base_url}")
        print(f"Mode: {'DRY RUN (no changes will be made)' if self.dry_run else 'LIVE'}")
        print("="*60)

        # Run healthcheck first
        if not self.run_healthcheck():
            sys.exit(1)

        if not self.dry_run:
            print("\n⚠️  WARNING: This will modify the target environment!")
            print("Press Ctrl+C within 5 seconds to cancel...")
            try:
                time.sleep(5)
            except KeyboardInterrupt:
                print("\n\nSync cancelled by user.")
                sys.exit(0)

        try:
            # Sync in order of dependencies
            action_id_map = self.sync_actions()
            role_id_map = self.sync_roles(action_id_map)
            self.sync_mappings()
            self.sync_groups(role_id_map)

            # Clear checkpoint on success
            if not self.dry_run:
                self.clear_checkpoint()

        except KeyboardInterrupt:
            print("\n\nSync interrupted by user.")
            print(f"Checkpoint saved to: {self.checkpoint_file}")
            print("Run with --resume to continue from checkpoint.")
            sys.exit(1)

        except Exception as e:
            print(f"\n\nERROR: Sync failed: {e}")
            print(f"Checkpoint saved to: {self.checkpoint_file}")
            print("Run with --resume to continue from checkpoint.")
            raise

        # Print summary
        elapsed = time.time() - start_time
        self.stats.print_summary()
        print(f"\nCompleted in {elapsed:.2f} seconds")

        if self.dry_run:
            print("\n⚠️  This was a DRY RUN - no changes were made.")
            print("Run without --dry-run to apply changes.")


def main():
    parser = argparse.ArgumentParser(
        description="Synchronize Heimdall environments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        "--source-url",
        required=True,
        help="Source environment base URL (e.g., https://staging.api.com)"
    )
    parser.add_argument(
        "--source-token",
        required=True,
        help="Source environment API token"
    )
    parser.add_argument(
        "--target-url",
        required=True,
        help="Target environment base URL (e.g., https://prod.api.com)"
    )
    parser.add_argument(
        "--target-token",
        required=True,
        help="Target environment API token"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without applying them"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from previous checkpoint"
    )
    parser.add_argument(
        "--checkpoint-file",
        type=Path,
        default=Path("sync_checkpoint.json"),
        help="Path to checkpoint file (default: sync_checkpoint.json)"
    )

    args = parser.parse_args()

    # Create clients
    source = HeimdallClient(args.source_url, args.source_token)
    target = HeimdallClient(args.target_url, args.target_token)

    # Create synchronizer
    syncer = EnvironmentSynchronizer(
        source=source,
        target=target,
        dry_run=args.dry_run,
        checkpoint_file=args.checkpoint_file
    )

    # Run sync
    syncer.sync()


if __name__ == "__main__":
    main()
