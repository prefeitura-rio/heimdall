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
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from urllib3.util.retry import Retry

# Initialize rich console
console = Console()


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
        table = Table(title="📊 Sync Summary", show_header=True, header_style="bold magenta")

        table.add_column("Entity", style="cyan", no_wrap=True)
        table.add_column("Created", style="green", justify="right")
        table.add_column("Updated", style="yellow", justify="right")
        table.add_column("Deleted", style="red", justify="right")
        table.add_column("Total", style="bold", justify="right")

        table.add_row(
            "Actions",
            str(self.actions_created),
            str(self.actions_updated),
            str(self.actions_deleted),
            str(self.actions_created + self.actions_updated + self.actions_deleted),
        )
        table.add_row(
            "Roles",
            str(self.roles_created),
            str(self.roles_updated),
            str(self.roles_deleted),
            str(self.roles_created + self.roles_updated + self.roles_deleted),
        )
        table.add_row(
            "Mappings",
            str(self.mappings_created),
            str(self.mappings_updated),
            str(self.mappings_deleted),
            str(self.mappings_created + self.mappings_updated + self.mappings_deleted),
        )
        table.add_row(
            "Groups",
            str(self.groups_created),
            str(self.groups_updated),
            str(self.groups_deleted),
            str(self.groups_created + self.groups_updated + self.groups_deleted),
        )

        table.add_section()
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold green]{self.actions_created + self.roles_created + self.mappings_created + self.groups_created}[/bold green]",
            f"[bold yellow]{self.actions_updated + self.roles_updated + self.mappings_updated + self.groups_updated}[/bold yellow]",
            f"[bold red]{self.actions_deleted + self.roles_deleted + self.mappings_deleted + self.groups_deleted}[/bold red]",
            f"[bold]{self.total_changes()}[/bold]",
        )

        if self.errors > 0:
            table.add_section()
            table.add_row("[bold red]ERRORS[/bold red]", "", "", "", f"[bold red]{self.errors}[/bold red]")

        console.print("\n")
        console.print(table)


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
            items = result.get("actions", [])  # Actions use "actions" not "items"
            all_actions.extend(items)

            # Check if we've fetched everything
            if skip + len(items) >= result.get("total", 0):
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
        """Fetch all mappings (no pagination - returns all)."""
        return self._request("GET", "/api/v1/mappings/list")

    def get_all_groups(self) -> list[dict[str, Any]]:
        """Fetch all groups (no pagination - returns all)."""
        return self._request("GET", "/api/v1/groups/")

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

    def get_action_by_name(self, action_name: str) -> dict[str, Any] | None:
        """Get action by name."""
        # Fetch all actions and find by name
        actions = self.get_all_actions()
        for action in actions:
            if action["name"] == action_name:
                return action
        return None

    def create_mapping(self, path_pattern: str, method: str, action_name: str) -> dict[str, Any]:
        """Create a mapping."""
        # Look up action ID by name
        action = self.get_action_by_name(action_name)
        if not action:
            raise ValueError(f"Action '{action_name}' not found")

        data = {
            "path_pattern": path_pattern,
            "method": method,
            "action_id": action["id"]
        }
        return self._request("POST", "/api/v1/mappings/", json=data)

    def update_mapping(self, mapping_id: int, action_name: str) -> dict[str, Any]:
        """Update a mapping."""
        # Look up action ID by name
        action = self.get_action_by_name(action_name)
        if not action:
            raise ValueError(f"Action '{action_name}' not found")

        data = {"action_id": action["id"]}
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

    def create_progress(self) -> Progress:
        """Create a rich progress bar."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        )

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
        console.print("\n")
        console.print(Panel.fit("🎬 Syncing Actions", style="bold blue"))

        # Fetch all actions
        with console.status("[bold green]Fetching actions from source..."):
            source_actions = {a["name"]: a for a in self.source.get_all_actions()}
        console.print(f"  ✓ Found [bold]{len(source_actions)}[/bold] actions in source", style="green")

        with console.status("[bold green]Fetching actions from target..."):
            target_actions = {a["name"]: a for a in self.target.get_all_actions()}
        console.print(f"  ✓ Found [bold]{len(target_actions)}[/bold] actions in target", style="green")

        # Create ID mapping for later use
        action_id_map = {}

        # Calculate operations
        to_create = [name for name in source_actions if name not in target_actions]
        to_update = [
            name for name in source_actions
            if name in target_actions and source_actions[name].get("description") != target_actions[name].get("description")
        ]
        to_delete = [name for name in target_actions if name not in source_actions]

        total_ops = len(to_create) + len(to_update) + len(to_delete)

        if total_ops == 0:
            console.print("  ℹ No changes needed", style="dim")
        else:
            console.print(f"\n  [green]+{len(to_create)}[/green] to create | [yellow]~{len(to_update)}[/yellow] to update | [red]-{len(to_delete)}[/red] to delete\n")

            # Create missing actions with progress
            if to_create:
                with self.create_progress() as progress:
                    task = progress.add_task("[green]Creating actions...", total=len(to_create))
                    for name in to_create:
                        source_action = source_actions[name]
                        console.print(f"  [green]+[/green] Creating action '[cyan]{name}[/cyan]'")
                        if not self.dry_run:
                            try:
                                new_action = self.target.create_action(
                                    name=name,
                                    description=source_action.get("description")
                                )
                                action_id_map[source_action["id"]] = new_action["id"]
                                self.stats.actions_created += 1
                            except Exception as e:
                                console.print(f"    [red]✗ ERROR: {e}[/red]")
                                self.stats.errors += 1
                        else:
                            self.stats.actions_created += 1
                        progress.update(task, advance=1)

            # Update actions with progress
            if to_update:
                with self.create_progress() as progress:
                    task = progress.add_task("[yellow]Updating actions...", total=len(to_update))
                    for name in to_update:
                        source_action = source_actions[name]
                        target_action = target_actions[name]
                        action_id_map[source_action["id"]] = target_action["id"]

                        console.print(f"  [yellow]~[/yellow] Updating action '[cyan]{name}[/cyan]' description")
                        if not self.dry_run:
                            try:
                                self.target.update_action(
                                    target_action["id"],
                                    source_action.get("description")
                                )
                                self.stats.actions_updated += 1
                            except Exception as e:
                                console.print(f"    [red]✗ ERROR: {e}[/red]")
                                self.stats.errors += 1
                        else:
                            self.stats.actions_updated += 1
                        progress.update(task, advance=1)

            # Delete extra actions with progress
            if to_delete:
                with self.create_progress() as progress:
                    task = progress.add_task("[red]Deleting actions...", total=len(to_delete))
                    for name in to_delete:
                        target_action = target_actions[name]
                        console.print(f"  [red]-[/red] Deleting action '[cyan]{name}[/cyan]'")
                        if not self.dry_run:
                            try:
                                self.target.delete_action(target_action["id"])
                                self.stats.actions_deleted += 1
                            except Exception as e:
                                console.print(f"    [red]✗ ERROR: {e}[/red]")
                                self.stats.errors += 1
                        else:
                            self.stats.actions_deleted += 1
                        progress.update(task, advance=1)

            # Map IDs for unchanged actions
            for name, source_action in source_actions.items():
                if name in target_actions and name not in to_update:
                    target_action = target_actions[name]
                    action_id_map[source_action["id"]] = target_action["id"]

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
        console.print("\n")
        console.print(Panel.fit("🗺️  Syncing Mappings", style="bold blue"))

        # Fetch all mappings
        with console.status("[bold green]Fetching mappings from source..."):
            source_mappings = {(m["path_pattern"], m["method"]): m for m in self.source.get_all_mappings()}
        console.print(f"  ✓ Found [bold]{len(source_mappings)}[/bold] mappings in source", style="green")

        with console.status("[bold green]Fetching mappings from target..."):
            target_mappings = {(m["path_pattern"], m["method"]): m for m in self.target.get_all_mappings()}
        console.print(f"  ✓ Found [bold]{len(target_mappings)}[/bold] mappings in target", style="green")

        # Calculate operations
        to_create = [(path, method) for (path, method) in source_mappings if (path, method) not in target_mappings]
        to_update = [
            (path, method) for (path, method) in source_mappings
            if (path, method) in target_mappings and source_mappings[(path, method)]["action"] != target_mappings[(path, method)]["action"]
        ]
        to_delete = [(path, method) for (path, method) in target_mappings if (path, method) not in source_mappings]

        total_ops = len(to_create) + len(to_update) + len(to_delete)

        if total_ops == 0:
            console.print("  ℹ No changes needed", style="dim")
        else:
            console.print(f"\n  [green]+{len(to_create)}[/green] to create | [yellow]~{len(to_update)}[/yellow] to update | [red]-{len(to_delete)}[/red] to delete\n")

            # Create missing mappings
            if to_create:
                with self.create_progress() as progress:
                    task = progress.add_task("[green]Creating mappings...", total=len(to_create))
                    for (path, method) in to_create:
                        source_mapping = source_mappings[(path, method)]
                        console.print(f"  [green]+[/green] Creating mapping [cyan]{method} {path}[/cyan] → [yellow]{source_mapping['action']}[/yellow]")
                        if not self.dry_run:
                            try:
                                self.target.create_mapping(
                                    path_pattern=path,
                                    method=method,
                                    action_name=source_mapping["action"]
                                )
                                self.stats.mappings_created += 1
                            except Exception as e:
                                console.print(f"    [red]✗ ERROR: {e}[/red]")
                                self.stats.errors += 1
                        else:
                            self.stats.mappings_created += 1
                        progress.update(task, advance=1)

            # Update mappings
            if to_update:
                with self.create_progress() as progress:
                    task = progress.add_task("[yellow]Updating mappings...", total=len(to_update))
                    for (path, method) in to_update:
                        source_mapping = source_mappings[(path, method)]
                        target_mapping = target_mappings[(path, method)]
                        console.print(f"  [yellow]~[/yellow] Updating mapping [cyan]{method} {path}[/cyan]: [dim]{target_mapping['action']}[/dim] → [yellow]{source_mapping['action']}[/yellow]")
                        if not self.dry_run:
                            try:
                                self.target.update_mapping(
                                    target_mapping["id"],
                                    source_mapping["action"]
                                )
                                self.stats.mappings_updated += 1
                            except Exception as e:
                                console.print(f"    [red]✗ ERROR: {e}[/red]")
                                self.stats.errors += 1
                        else:
                            self.stats.mappings_updated += 1
                        progress.update(task, advance=1)

            # Delete extra mappings
            if to_delete:
                with self.create_progress() as progress:
                    task = progress.add_task("[red]Deleting mappings...", total=len(to_delete))
                    for (path, method) in to_delete:
                        target_mapping = target_mappings[(path, method)]
                        console.print(f"  [red]-[/red] Deleting mapping [cyan]{method} {path}[/cyan] → [dim]{target_mapping['action']}[/dim]")
                        if not self.dry_run:
                            try:
                                self.target.delete_mapping(target_mapping["id"])
                                self.stats.mappings_deleted += 1
                            except Exception as e:
                                console.print(f"    [red]✗ ERROR: {e}[/red]")
                                self.stats.errors += 1
                        else:
                            self.stats.mappings_deleted += 1
                        progress.update(task, advance=1)

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
        console.print("\n")
        console.print(Panel.fit("🏥 Running Healthcheck", style="bold magenta"))

        all_healthy = True

        # Check source
        console.print("\n[bold]Checking SOURCE environment[/bold]")
        console.print(f"  URL: [cyan]{self.source.base_url}[/cyan]")

        with console.status("[bold yellow]Running healthcheck on source..."):
            source_health = self.source.healthcheck()

        if source_health["healthy"]:
            console.print("  [green]✓[/green] API is healthy")
        else:
            console.print("  [red]✗[/red] API health check failed")
            all_healthy = False

        if source_health["user_info"]:
            user_cpf = source_health["user_info"].get("cpf", "unknown")
            console.print(f"  [green]✓[/green] Authentication valid (user: [cyan]{user_cpf}[/cyan])")
        else:
            console.print("  [red]✗[/red] Authentication failed")
            all_healthy = False

        if source_health["has_superadmin"]:
            console.print("  [green]✓[/green] User has superadmin role")
        else:
            console.print("  [red]✗[/red] User does NOT have superadmin role")
            all_healthy = False

        if source_health["can_write"]:
            console.print("  [green]✓[/green] Write permissions verified")
        else:
            console.print("  [yellow]⚠[/yellow] Write permissions check failed")
            # Don't fail on source write permissions since we only read from source

        for error in source_health["errors"]:
            console.print(f"  [red]ERROR: {error}[/red]")

        # Check target
        console.print("\n[bold]Checking TARGET environment[/bold]")
        console.print(f"  URL: [cyan]{self.target.base_url}[/cyan]")

        with console.status("[bold yellow]Running healthcheck on target..."):
            target_health = self.target.healthcheck()

        if target_health["healthy"]:
            console.print("  [green]✓[/green] API is healthy")
        else:
            console.print("  [red]✗[/red] API health check failed")
            all_healthy = False

        if target_health["user_info"]:
            user_cpf = target_health["user_info"].get("cpf", "unknown")
            console.print(f"  [green]✓[/green] Authentication valid (user: [cyan]{user_cpf}[/cyan])")
        else:
            console.print("  [red]✗[/red] Authentication failed")
            all_healthy = False

        if target_health["has_superadmin"]:
            console.print("  [green]✓[/green] User has superadmin role")
        else:
            console.print("  [red]✗[/red] User does NOT have superadmin role")
            all_healthy = False

        if target_health["can_write"]:
            console.print("  [green]✓[/green] Write permissions verified")
        else:
            console.print("  [red]✗[/red] Write permissions check failed")
            all_healthy = False

        for error in target_health["errors"]:
            console.print(f"  [red]ERROR: {error}[/red]")

        console.print()

        if not all_healthy:
            console.print(Panel.fit("❌ Healthcheck FAILED - cannot proceed with sync\nPlease fix the issues above and try again.", style="bold red"))
            return False

        console.print(Panel.fit("✅ Healthcheck PASSED - ready to sync", style="bold green"))
        return True

    def sync(self):
        """Run full synchronization."""
        start_time = time.time()

        # Print header
        header_lines = [
            "🔄 HEIMDALL ENVIRONMENT SYNCHRONIZATION",
            "",
            f"Source:  [cyan]{self.source.base_url}[/cyan]",
            f"Target:  [cyan]{self.target.base_url}[/cyan]",
            f"Mode:    [{'yellow' if self.dry_run else 'green'}]{'DRY RUN (no changes will be made)' if self.dry_run else 'LIVE'}[/{'yellow' if self.dry_run else 'green'}]",
        ]
        console.print(Panel("\n".join(header_lines), style="bold blue", expand=False))

        # Run healthcheck first
        if not self.run_healthcheck():
            sys.exit(1)

        if not self.dry_run:
            console.print("\n")
            console.print(Panel.fit(
                "⚠️  WARNING: This will modify the target environment!\n"
                "Press Ctrl+C within 5 seconds to cancel...",
                style="bold yellow"
            ))
            try:
                for i in range(5, 0, -1):
                    console.print(f"  Starting in {i}...", style="yellow")
                    time.sleep(1)
                console.print()
            except KeyboardInterrupt:
                console.print("\n")
                console.print(Panel.fit("❌ Sync cancelled by user", style="bold red"))
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
            console.print("\n")
            console.print(Panel.fit(
                f"⏸️  Sync interrupted by user\n\n"
                f"Checkpoint saved to: [cyan]{self.checkpoint_file}[/cyan]\n"
                f"Run with [yellow]--resume[/yellow] to continue from checkpoint.",
                style="bold yellow"
            ))
            sys.exit(1)

        except Exception as e:
            console.print("\n")
            console.print(Panel.fit(
                f"❌ Sync failed: [red]{e}[/red]\n\n"
                f"Checkpoint saved to: [cyan]{self.checkpoint_file}[/cyan]\n"
                f"Run with [yellow]--resume[/yellow] to continue from checkpoint.",
                style="bold red"
            ))
            raise

        # Print summary
        elapsed = time.time() - start_time
        self.stats.print_summary()

        console.print(f"\n⏱️  Completed in [bold]{elapsed:.2f}[/bold] seconds", style="dim")

        if self.dry_run:
            console.print("\n")
            console.print(Panel.fit(
                "⚠️  This was a DRY RUN - no changes were made.\n"
                "Run without [yellow]--dry-run[/yellow] to apply changes.",
                style="bold yellow"
            ))
        else:
            console.print("\n")
            console.print(Panel.fit("✅ Sync completed successfully!", style="bold green"))


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
