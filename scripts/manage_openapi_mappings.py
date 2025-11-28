#!/usr/bin/env python3
"""
OpenAPI-based Mapping Management Tool

Terraform-like declarative management of Heimdall endpoint-to-action mappings
from OpenAPI v3 specifications.

Workflow:
    1. Create config.json with your API OpenAPI spec URLs
    2. Run 'init' to generate state file with FILL_HERE placeholders
    3. Edit state file and replace FILL_HERE with actual action names
    4. Run 'plan' to see what would change
    5. Run 'apply' to create mappings in Heimdall

Usage:
    # Generate initial state file from OpenAPI specs
    python manage_openapi_mappings.py init --config config.json

    # Validate configuration and OpenAPI specs
    python manage_openapi_mappings.py validate --config config.json

    # Show what changes would be applied (dry-run)
    python manage_openapi_mappings.py plan --config config.json --state state.json

    # Apply changes with confirmation prompt
    python manage_openapi_mappings.py apply --config config.json --state state.json

    # Apply changes without confirmation (CI/CD mode)
    python manage_openapi_mappings.py apply --config config.json --state state.json --auto-approve

State File:
    The state file (JSON) maps each endpoint pattern to an action name. You must
    manually edit this file to replace 'FILL_HERE' with actual action names before
    running plan/apply. The file is re-generated each time you run 'init', so keep
    a backup if you've filled in action names.

Example State Entry:
    {
      "api_name": "RMI",
      "openapi_path": "/users/{id}",
      "method": "GET",
      "action_name": "rmi:users:read",  # <- Replace FILL_HERE with this
      "description": "Get user by ID",
      "path_patterns": [
        "/users/([^/]+)$",
        "/rmi/users/([^/]+)$"  # If additional_prefixes configured
      ]
    }
"""

import json
import os
import re
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import click
import requests
from pydantic import BaseModel, Field, HttpUrl, field_validator
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

console = Console()


# ============================================================================
# Configuration Models
# ============================================================================


class APIConfig(BaseModel):
    """Configuration for a single API's OpenAPI spec."""

    name: str = Field(..., description="API name (used for action prefixes)")
    openapi_url: HttpUrl = Field(..., description="URL to OpenAPI v3 JSON spec")
    additional_prefixes: list[str] = Field(
        default_factory=list,
        description="Additional path prefixes to duplicate mappings under",
    )
    action_prefix: str | None = Field(
        None, description="Action name prefix (defaults to lowercase name)"
    )
    include_patterns: list[str] | None = Field(
        None, description="Regex patterns for paths to include"
    )
    exclude_patterns: list[str] | None = Field(
        None, description="Regex patterns for paths to exclude"
    )

    @field_validator("additional_prefixes")
    @classmethod
    def validate_prefixes(cls, v: list[str]) -> list[str]:
        """Ensure prefixes start with / and don't end with /."""
        validated = []
        for prefix in v:
            if not prefix.startswith("/"):
                prefix = f"/{prefix}"
            if prefix.endswith("/"):
                prefix = prefix[:-1]
            validated.append(prefix)
        return validated


class HeimdallConfig(BaseModel):
    """Heimdall API connection configuration."""

    api_url: str = Field(..., description="Heimdall API base URL")
    token_env_var: str = Field(
        default="HEIMDALL_TOKEN", description="Environment variable for auth token"
    )


class OptionsConfig(BaseModel):
    """Tool behavior options."""

    auto_create_actions: bool = Field(
        default=True, description="Auto-create actions if they don't exist"
    )
    delete_unmanaged: bool = Field(
        default=False, description="Delete mappings not in OpenAPI specs"
    )


class Config(BaseModel):
    """Root configuration model."""

    apis: list[APIConfig] = Field(..., description="List of APIs to manage")
    heimdall: HeimdallConfig = Field(..., description="Heimdall connection config")
    options: OptionsConfig = Field(
        default_factory=OptionsConfig, description="Tool options"
    )


# ============================================================================
# Data Models
# ============================================================================


class ChangeType(str, Enum):
    """Type of change for a mapping."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    NO_OP = "no-op"


@dataclass
class Mapping:
    """Represents a single endpoint-to-action mapping."""

    path_pattern: str
    method: str
    action_name: str
    description: str | None = None
    api_name: str | None = None
    existing_id: int | None = None
    action_id: int | None = None
    openapi_path: str | None = None  # Original OpenAPI path for reference

    def key(self) -> tuple[str, str]:
        """Unique key for mapping comparison."""
        return (self.path_pattern, self.method)


@dataclass
class StateMappingEntry:
    """Entry in the state file for a mapping."""

    path_pattern: str
    method: str
    action_name: str
    openapi_path: str
    description: str | None = None
    api_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "path_pattern": self.path_pattern,
            "method": self.method,
            "action_name": self.action_name,
            "openapi_path": self.openapi_path,
            "description": self.description,
            "api_name": self.api_name,
        }


@dataclass
class MappingChange:
    """Represents a change to be applied."""

    change_type: ChangeType
    mapping: Mapping
    old_mapping: Mapping | None = None


# ============================================================================
# OpenAPI Processing
# ============================================================================


class OpenAPIProcessor:
    """Processes OpenAPI specs into Heimdall mappings."""

    def __init__(self, api_config: APIConfig):
        self.api_config = api_config
        self.action_prefix = api_config.action_prefix or api_config.name.lower()

    def fetch_spec(self) -> dict[str, Any]:
        """Fetch OpenAPI spec from URL."""
        response = requests.get(str(self.api_config.openapi_url), timeout=30)
        response.raise_for_status()
        return response.json()

    def should_include_path(self, path: str) -> bool:
        """Check if path should be included based on filters."""
        if self.api_config.include_patterns:
            if not any(
                re.match(pattern, path)
                for pattern in self.api_config.include_patterns
            ):
                return False

        if self.api_config.exclude_patterns:
            if any(
                re.match(pattern, path)
                for pattern in self.api_config.exclude_patterns
            ):
                return False

        return True

    def openapi_path_to_regex(self, path: str) -> str:
        """
        Convert OpenAPI path to regex pattern.

        Examples:
            /users -> /users$
            /users/{id} -> /users/([^/]+)$
            /users/{id}/posts/{pid} -> /users/([^/]+)/posts/([^/]+)$
        """
        # Replace {param} with ([^/]+) to match existing Heimdall format
        regex = re.sub(r"\{[^}]+\}", "([^/]+)", path)
        # Add only end anchor (existing mappings don't have ^ at start)
        return f"{regex}$"

    def extract_resource_from_path(self, path: str) -> str:
        """
        Extract resource name from path.

        Examples:
            /users -> users
            /users/{id} -> users
            /users/{id}/posts -> posts
            /api/v1/health -> health
        """
        # Remove leading/trailing slashes
        path = path.strip("/")
        # Split by slashes
        parts = [p for p in path.split("/") if not p.startswith("{")]
        # Return last non-parameter segment, or first if none
        return parts[-1] if parts else "unknown"

    def method_to_operation(self, method: str) -> str:
        """Map HTTP method to CRUD operation."""
        method = method.upper()
        mapping = {
            "GET": "read",
            "POST": "create",
            "PUT": "update",
            "PATCH": "update",
            "DELETE": "delete",
            "HEAD": "read",
            "OPTIONS": "options",
        }
        return mapping.get(method, method.lower())

    def generate_action_name(
        self, path: str, method: str, operation_id: str | None = None
    ) -> str:
        """
        Generate action name from path and method.

        Format: {action_prefix}:{resource}:{operation}
        Example: rmi:users:read
        """
        resource = self.extract_resource_from_path(path)
        operation = self.method_to_operation(method)
        return f"{self.action_prefix}:{resource}:{operation}"

    def generate_mappings(
        self, spec: dict[str, Any], default_action: str = "FILL_HERE"
    ) -> list[Mapping]:
        """Generate all mappings from OpenAPI spec with placeholder action names."""
        mappings = []

        paths = spec.get("paths", {})
        for path, path_item in paths.items():
            if not self.should_include_path(path):
                continue

            # Process each HTTP method
            for method in ["get", "post", "put", "patch", "delete", "head", "options"]:
                if method not in path_item:
                    continue

                operation = path_item[method]
                operation_id = operation.get("operationId")
                summary = operation.get("summary")
                description = operation.get("description") or summary

                # Generate base mapping with placeholder action
                regex_pattern = self.openapi_path_to_regex(path)

                base_mapping = Mapping(
                    path_pattern=regex_pattern,
                    method=method.upper(),
                    action_name=default_action,  # Placeholder
                    description=description,
                    api_name=self.api_config.name,
                    openapi_path=path,  # Store original path
                )
                mappings.append(base_mapping)

                # Duplicate for additional prefixes
                for prefix in self.api_config.additional_prefixes:
                    # Insert prefix before the path (no ^ anchor at start)
                    prefixed_pattern = f"{prefix}{regex_pattern}"
                    prefixed_mapping = Mapping(
                        path_pattern=prefixed_pattern,
                        method=method.upper(),
                        action_name=default_action,  # Placeholder
                        description=description,
                        api_name=self.api_config.name,
                        openapi_path=path,  # Store original path
                    )
                    mappings.append(prefixed_mapping)

        return mappings


# ============================================================================
# State File Management
# ============================================================================


class StateFileManager:
    """Manages the state file for mapping-to-action assignments."""

    def __init__(self, state_file_path: str):
        self.state_file_path = state_file_path

    def load_state(self) -> dict[tuple[str, str, str], str]:
        """
        Load state file and return mapping key -> action_name dict.

        Returns:
            Dict mapping (api_name, openapi_path, method) -> action_name
        """
        if not os.path.exists(self.state_file_path):
            return {}

        with open(self.state_file_path) as f:
            data = json.load(f)

        state = {}

        # Support both old format (mappings) and new format (endpoints)
        if "endpoints" in data:
            # New format: use stable key (api_name, openapi_path, method)
            for entry in data["endpoints"]:
                api_name = entry["api_name"]
                openapi_path = entry["openapi_path"]
                method = entry["method"]
                action_name = entry["action_name"]
                key = (api_name, openapi_path, method)
                state[key] = action_name
        elif "mappings" in data:
            # Old format: one entry per path_pattern
            for entry in data["mappings"]:
                key = (entry["path_pattern"], entry["method"])
                state[key] = entry["action_name"]

        return state

    def save_state(self, mappings: list[Mapping]) -> None:
        """
        Save mappings to state file, grouped by OpenAPI path to avoid duplication.

        Args:
            mappings: List of mappings to save
        """
        # Group mappings by (api_name, openapi_path, method)
        # This way duplicates from additional_prefixes share one action definition
        grouped: dict[tuple[str, str, str], list[Mapping]] = {}

        for mapping in mappings:
            key = (
                mapping.api_name or "unknown",
                mapping.openapi_path or mapping.path_pattern,
                mapping.method,
            )
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(mapping)

        entries = []
        for (api_name, openapi_path, method), mapping_group in grouped.items():
            # Use first mapping's data, but collect all path_patterns
            first = mapping_group[0]
            path_patterns = [m.path_pattern for m in mapping_group]

            entry = {
                "api_name": api_name,
                "openapi_path": openapi_path,
                "method": method,
                "action_name": first.action_name,
                "description": first.description,
                "path_patterns": path_patterns,  # All regex patterns for this endpoint
            }
            entries.append(entry)

        # Sort by API name, then openapi path for readability
        entries.sort(key=lambda x: (x["api_name"], x["openapi_path"], x["method"]))

        data = {
            "_comment": "This file maps OpenAPI endpoints to Heimdall actions. Fill in action_name once per endpoint - it applies to all path_patterns.",
            "endpoints": entries,
        }

        with open(self.state_file_path, "w") as f:
            json.dump(data, f, indent=2)

    def apply_state_to_mappings(
        self, mappings: list[Mapping], state: dict[tuple[str, str, str], str]
    ) -> list[Mapping]:
        """
        Apply action names from state to mappings.

        Args:
            mappings: List of mappings with placeholder actions
            state: State dict from load_state() keyed by (api_name, openapi_path, method)

        Returns:
            Updated mappings with action names from state
        """
        for mapping in mappings:
            # Use stable key (api_name, openapi_path, method)
            key = (mapping.api_name, mapping.openapi_path, mapping.method)
            if key in state:
                mapping.action_name = state[key]

        return mappings


# ============================================================================
# Heimdall API Client
# ============================================================================


class HeimdallClient:
    """Client for interacting with Heimdall Admin API."""

    def __init__(self, config: HeimdallConfig):
        # Normalize API URL
        api_url = config.api_url.rstrip("/")

        # Auto-append /api/v1 if not present
        if not api_url.endswith("/api/v1"):
            api_url = f"{api_url}/api/v1"

        self.api_url = api_url

        token = os.getenv(config.token_env_var)
        if not token:
            raise ValueError(
                f"Environment variable {config.token_env_var} not set"
            )
        self.headers = {"Authorization": f"Bearer {token}"}

    def get_actions(self) -> dict[str, int]:
        """Fetch all actions and return name->id mapping."""
        # GET /actions/ - list actions (paginated, so fetch all)
        all_actions = []
        skip = 0
        limit = 100

        while True:
            response = requests.get(
                f"{self.api_url}/actions/",
                headers=self.headers,
                params={"skip": skip, "limit": limit},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            # Handle paginated response format
            if isinstance(data, dict) and "actions" in data:
                actions = data["actions"]
                total = data.get("total", 0)
            else:
                actions = data
                total = len(actions)

            all_actions.extend(actions)

            # Check if we've fetched all
            if len(all_actions) >= total:
                break

            skip += limit

        return {action["name"]: action["id"] for action in all_actions}

    def create_action(self, name: str, description: str | None = None) -> int:
        """Create a new action and return its ID."""
        # POST /actions/ - create action
        # Description is required by the API
        if not description:
            description = f"Auto-created action: {name}"

        data = {"name": name, "description": description}
        response = requests.post(
            f"{self.api_url}/actions/",
            headers=self.headers,
            json=data,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()["id"]

    def get_mappings(self) -> list[Mapping]:
        """Fetch all existing mappings."""
        # GET /mappings/list (no trailing slash!)
        response = requests.get(
            f"{self.api_url}/mappings/list", headers=self.headers, timeout=30
        )
        response.raise_for_status()
        data = response.json()

        # Get actions to map action names to IDs
        actions_map = self.get_actions()

        mappings = []
        for item in data:
            action_name = item["action"]  # action is a string, not object
            mapping = Mapping(
                path_pattern=item["path_pattern"],
                method=item["method"],
                action_name=action_name,
                description=item.get("description"),
                existing_id=item["id"],
                action_id=actions_map.get(action_name),  # Look up action ID
            )
            mappings.append(mapping)

        return mappings

    def create_mapping(self, mapping: Mapping) -> None:
        """Create a new mapping."""
        # POST /mappings/
        if not mapping.action_id:
            raise ValueError(f"Mapping {mapping.key()} missing action_id")

        # Truncate description if too long (max 500 chars)
        description = mapping.description
        if description and len(description) > 500:
            description = description[:497] + "..."

        data = {
            "path_pattern": mapping.path_pattern,
            "method": mapping.method,
            "action_id": mapping.action_id,
            "description": description,
        }
        response = requests.post(
            f"{self.api_url}/mappings/",
            headers=self.headers,
            json=data,
            timeout=30,
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            # Include response body in error for debugging
            error_msg = str(e)
            try:
                error_detail = response.json()
                error_msg = f"{error_msg}. Response: {error_detail}"
            except Exception:
                error_msg = f"{error_msg}. Response text: {response.text}"
            raise requests.HTTPError(error_msg, response=response)

    def update_mapping(self, mapping: Mapping) -> None:
        """Update an existing mapping."""
        # PUT /mappings/{id} (no trailing slash)
        if not mapping.existing_id:
            raise ValueError(f"Mapping {mapping.key()} missing existing_id")
        if not mapping.action_id:
            raise ValueError(f"Mapping {mapping.key()} missing action_id")

        # Truncate description if too long (max 500 chars)
        description = mapping.description
        if description and len(description) > 500:
            description = description[:497] + "..."

        data = {
            "action_id": mapping.action_id,
            "description": description,
        }
        response = requests.put(
            f"{self.api_url}/mappings/{mapping.existing_id}",
            headers=self.headers,
            json=data,
            timeout=30,
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            # Include response body in error for debugging
            error_msg = str(e)
            try:
                error_detail = response.json()
                error_msg = f"{error_msg}. Response: {error_detail}"
            except Exception:
                error_msg = f"{error_msg}. Response text: {response.text}"
            raise requests.HTTPError(error_msg, response=response)

    def delete_mapping(self, mapping_id: int) -> None:
        """Delete a mapping."""
        # DELETE /mappings/{id} (no trailing slash)
        response = requests.delete(
            f"{self.api_url}/mappings/{mapping_id}",
            headers=self.headers,
            timeout=30,
        )
        response.raise_for_status()


# ============================================================================
# Diff Calculator
# ============================================================================


class DiffCalculator:
    """Calculate differences between generated and existing mappings."""

    def __init__(self, options: OptionsConfig):
        self.options = options

    def calculate_changes(
        self, generated: list[Mapping], existing: list[Mapping]
    ) -> list[MappingChange]:
        """Calculate all changes needed to sync mappings."""
        changes = []

        # Build lookup maps
        generated_map = {m.key(): m for m in generated}
        existing_map = {m.key(): m for m in existing}

        # Find creates and updates
        for key, gen_mapping in generated_map.items():
            if key not in existing_map:
                # CREATE
                changes.append(
                    MappingChange(change_type=ChangeType.CREATE, mapping=gen_mapping)
                )
            else:
                # Check for UPDATE
                exist_mapping = existing_map[key]
                if (
                    gen_mapping.action_name != exist_mapping.action_name
                    or gen_mapping.description != exist_mapping.description
                ):
                    # UPDATE - merge existing_id and action_id
                    updated_mapping = Mapping(
                        path_pattern=gen_mapping.path_pattern,
                        method=gen_mapping.method,
                        action_name=gen_mapping.action_name,
                        description=gen_mapping.description,
                        api_name=gen_mapping.api_name,
                        existing_id=exist_mapping.existing_id,
                        action_id=None,  # Will be resolved later
                    )
                    changes.append(
                        MappingChange(
                            change_type=ChangeType.UPDATE,
                            mapping=updated_mapping,
                            old_mapping=exist_mapping,
                        )
                    )
                else:
                    # NO-OP
                    changes.append(
                        MappingChange(
                            change_type=ChangeType.NO_OP, mapping=exist_mapping
                        )
                    )

        # Find deletes
        if self.options.delete_unmanaged:
            for key, exist_mapping in existing_map.items():
                if key not in generated_map:
                    # DELETE
                    changes.append(
                        MappingChange(
                            change_type=ChangeType.DELETE, mapping=exist_mapping
                        )
                    )

        return changes


# ============================================================================
# Display Functions
# ============================================================================


def display_plan(changes: list[MappingChange], actions_to_create: list[str]) -> None:
    """Display plan in Terraform-like format."""
    creates = [c for c in changes if c.change_type == ChangeType.CREATE]
    updates = [c for c in changes if c.change_type == ChangeType.UPDATE]
    deletes = [c for c in changes if c.change_type == ChangeType.DELETE]
    no_ops = [c for c in changes if c.change_type == ChangeType.NO_OP]

    # Actions to create
    if actions_to_create:
        console.print("\n[bold yellow]Actions to be created:[/bold yellow]")
        for action_name in sorted(actions_to_create):
            console.print(f"  [yellow]+[/yellow] {action_name}")

    # Group changes by API
    changes_by_api = {}
    for change in creates + updates + deletes:
        api_name = change.mapping.api_name or "Unknown"
        if api_name not in changes_by_api:
            changes_by_api[api_name] = []
        changes_by_api[api_name].append(change)

    # Display changes by API
    for api_name, api_changes in sorted(changes_by_api.items()):
        console.print(f"\n[bold]Changes for API: {api_name}[/bold]\n")

        for change in api_changes:
            if change.change_type == ChangeType.CREATE:
                console.print(f"  [green]+[/green] CREATE mapping")
                console.print(f"      path_pattern: {change.mapping.path_pattern}")
                console.print(f"      method:       {change.mapping.method}")
                console.print(f"      action:       {change.mapping.action_name}")
                if change.mapping.description:
                    console.print(f"      description:  {change.mapping.description}")
                console.print()

            elif change.change_type == ChangeType.UPDATE:
                console.print(
                    f"  [yellow]~[/yellow] UPDATE mapping (id: {change.mapping.existing_id})"
                )
                console.print(f"      path_pattern: {change.mapping.path_pattern}")
                console.print(f"      method:       {change.mapping.method}")
                if change.old_mapping:
                    if (
                        change.old_mapping.action_name
                        != change.mapping.action_name
                    ):
                        console.print(
                            f"    [yellow]~[/yellow] action:       {change.old_mapping.action_name} → {change.mapping.action_name}"
                        )
                    if (
                        change.old_mapping.description
                        != change.mapping.description
                    ):
                        console.print(
                            f'    [yellow]~[/yellow] description:  "{change.old_mapping.description}" → "{change.mapping.description}"'
                        )
                console.print()

            elif change.change_type == ChangeType.DELETE:
                console.print(
                    f"  [red]-[/red] DELETE mapping (id: {change.mapping.existing_id})"
                )
                console.print(f"      path_pattern: {change.mapping.path_pattern}")
                console.print(f"      method:       {change.mapping.method}")
                console.print(f"      action:       {change.mapping.action_name}")
                console.print()

    # Summary footer
    summary = (
        f"Plan: {len(creates)} to create, {len(updates)} to update, "
        f"{len(deletes)} to delete, {len(no_ops)} unchanged"
    )
    console.print(Panel(summary, style="bold blue"))


def display_apply_summary(
    created: int, updated: int, deleted: int, failed: int
) -> None:
    """Display apply summary."""
    style = "bold green" if failed == 0 else "bold yellow"
    summary = (
        f"Apply complete! {created} created, {updated} updated, "
        f"{deleted} deleted, {failed} failed"
    )
    console.print(Panel(summary, style=style))


# ============================================================================
# CLI Commands
# ============================================================================


@click.group()
def cli():
    """OpenAPI-based mapping management for Heimdall."""
    pass


@cli.command()
@click.option(
    "--config",
    type=click.Path(exists=True),
    required=True,
    help="Path to configuration JSON file",
)
def validate(config: str) -> None:
    """Validate configuration and OpenAPI specs."""
    try:
        # Load config
        with open(config) as f:
            config_data = json.load(f)
        cfg = Config(**config_data)

        console.print("[bold]Validating configuration...[/bold]")
        console.print(f"✓ Configuration valid: {len(cfg.apis)} APIs configured")

        # Validate each OpenAPI spec
        for api_config in cfg.apis:
            with console.status(f"Fetching {api_config.name} OpenAPI spec..."):
                processor = OpenAPIProcessor(api_config)
                spec = processor.fetch_spec()
                console.print(f"✓ {api_config.name}: OpenAPI spec fetched")

                # Validate structure
                if "openapi" not in spec:
                    raise ValueError(f"{api_config.name}: Missing 'openapi' field")
                if "paths" not in spec:
                    raise ValueError(f"{api_config.name}: Missing 'paths' field")

                paths_count = len(spec.get("paths", {}))
                console.print(f"  → {paths_count} paths defined")

        console.print("\n[bold green]✓ All validations passed[/bold green]")

    except Exception as e:
        console.print(f"[bold red]✗ Validation failed: {e}[/bold red]")
        sys.exit(1)


@cli.command()
@click.option(
    "--config",
    type=click.Path(exists=True),
    required=True,
    help="Path to configuration JSON file",
)
@click.option(
    "--output",
    type=click.Path(),
    default="openapi_mappings.state.json",
    help="Output path for state file",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing state file without confirmation",
)
def init(config: str, output: str, force: bool) -> None:
    """Generate initial state file with FILL_HERE placeholders, preserving existing action names."""
    try:
        # Load existing state if present
        existing_state = {}
        if os.path.exists(output):
            console.print(f"[bold]Existing state file found: {output}[/bold]")
            console.print("[yellow]Merging with existing action names...[/yellow]\n")

            state_mgr = StateFileManager(output)
            existing_state = state_mgr.load_state()

            # Create backup
            backup_path = f"{output}.backup"
            import shutil
            shutil.copy(output, backup_path)
            console.print(f"✓ Backup created: {backup_path}\n")

        # Load config
        with open(config) as f:
            config_data = json.load(f)
        cfg = Config(**config_data)

        console.print("[bold]Generating state file from OpenAPI specs...[/bold]\n")

        # Generate mappings from OpenAPI specs
        all_mappings = []
        for api_config in cfg.apis:
            with console.status(f"Processing {api_config.name} OpenAPI spec..."):
                processor = OpenAPIProcessor(api_config)
                spec = processor.fetch_spec()
                mappings = processor.generate_mappings(spec)  # Uses FILL_HERE default
                all_mappings.extend(mappings)
            console.print(
                f"✓ Generated {len(mappings)} mappings for {api_config.name}"
            )

        # Apply existing action names to preserve user work
        if existing_state:
            preserved_count = 0
            for mapping in all_mappings:
                # Use stable key (api_name, openapi_path, method)
                key = (mapping.api_name, mapping.openapi_path, mapping.method)
                if key in existing_state and existing_state[key] != "FILL_HERE":
                    mapping.action_name = existing_state[key]
                    preserved_count += 1

            if preserved_count > 0:
                console.print(
                    f"\n[bold green]✓ Preserved {preserved_count} existing action names[/bold green]"
                )

        # Save to state file
        state_mgr = StateFileManager(output)
        state_mgr.save_state(all_mappings)

        console.print(
            f"\n[bold green]✓ State file created: {output}[/bold green]"
        )
        console.print(
            f"\n[yellow]Next steps:[/yellow]"
            f"\n  1. Edit {output} and replace 'FILL_HERE' with actual action names"
            f"\n  2. Run 'plan' to see what changes would be applied"
            f"\n  3. Run 'apply' to create the mappings in Heimdall"
        )

        # Show unfilled count
        unfilled = sum(1 for m in all_mappings if m.action_name == "FILL_HERE")
        console.print(
            f"\n[bold]Total mappings: {len(all_mappings)}[/bold]"
            f"\n[bold yellow]Mappings needing action names: {unfilled}[/bold yellow]"
        )

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        import traceback

        traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option(
    "--config",
    type=click.Path(exists=True),
    required=True,
    help="Path to configuration JSON file",
)
@click.option(
    "--state",
    type=click.Path(exists=True),
    required=True,
    help="Path to state file with action mappings",
)
def plan(config: str, state: str) -> None:
    """Show what changes would be applied."""
    try:
        # Load config
        with open(config) as f:
            config_data = json.load(f)
        cfg = Config(**config_data)

        # Load state file
        state_mgr = StateFileManager(state)
        state_data = state_mgr.load_state()
        console.print(f"✓ Loaded state file: {state}\n")

        # Initialize clients
        client = HeimdallClient(cfg.heimdall)
        diff_calc = DiffCalculator(cfg.options)

        # Fetch existing state
        with console.status("Fetching existing mappings from Heimdall..."):
            try:
                existing_mappings = client.get_mappings()
            except Exception as e:
                console.print(f"[red]Error fetching mappings: {e}[/red]")
                import traceback
                traceback.print_exc()
                raise

            try:
                existing_actions = client.get_actions()
            except Exception as e:
                console.print(f"[red]Error fetching actions: {e}[/red]")
                import traceback
                traceback.print_exc()
                raise

        console.print(
            f"✓ Fetched {len(existing_mappings)} existing mappings, {len(existing_actions)} actions\n"
        )

        # Generate mappings from OpenAPI specs
        all_generated = []
        for api_config in cfg.apis:
            with console.status(f"Processing {api_config.name} OpenAPI spec..."):
                processor = OpenAPIProcessor(api_config)
                spec = processor.fetch_spec()
                mappings = processor.generate_mappings(spec)
                # Apply action names from state file
                mappings = state_mgr.apply_state_to_mappings(mappings, state_data)
                all_generated.extend(mappings)
            console.print(f"✓ Generated {len(mappings)} mappings for {api_config.name}")

        # Validate no FILL_HERE or empty action names
        unfilled = [m for m in all_generated if m.action_name == "FILL_HERE" or not m.action_name or m.action_name.strip() == ""]
        if unfilled:
            console.print(
                f"\n[bold red]✗ Error: {len(unfilled)} mappings have invalid action names[/bold red]"
            )
            console.print(
                "\n[yellow]Please edit the state file and fill in action names for:[/yellow]"
            )
            for m in unfilled[:10]:  # Show first 10
                action_desc = "FILL_HERE" if m.action_name == "FILL_HERE" else "(empty)"
                console.print(f"  - {m.method} {m.path_pattern} -> {action_desc}")
            if len(unfilled) > 10:
                console.print(f"  ... and {len(unfilled) - 10} more")
            sys.exit(1)

        # Calculate changes
        changes = diff_calc.calculate_changes(all_generated, existing_mappings)

        # Find actions that need to be created
        actions_to_create = []
        for change in changes:
            if change.change_type in [ChangeType.CREATE, ChangeType.UPDATE]:
                if change.mapping.action_name not in existing_actions:
                    if change.mapping.action_name not in actions_to_create:
                        actions_to_create.append(change.mapping.action_name)

        # Display plan
        console.print()
        display_plan(changes, actions_to_create)

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        sys.exit(1)


@cli.command()
@click.option(
    "--config",
    type=click.Path(exists=True),
    required=True,
    help="Path to configuration JSON file",
)
@click.option(
    "--state",
    type=click.Path(exists=True),
    required=True,
    help="Path to state file with action mappings",
)
@click.option(
    "--auto-approve",
    is_flag=True,
    help="Skip confirmation prompt",
)
def apply(config: str, state: str, auto_approve: bool) -> None:
    """Apply changes to Heimdall mappings."""
    try:
        # Load config
        with open(config) as f:
            config_data = json.load(f)
        cfg = Config(**config_data)

        # Load state file
        state_mgr = StateFileManager(state)
        state_data = state_mgr.load_state()
        console.print(f"✓ Loaded state file: {state}\n")

        # Initialize clients
        client = HeimdallClient(cfg.heimdall)
        diff_calc = DiffCalculator(cfg.options)

        # Fetch existing state
        with console.status("Fetching existing state from Heimdall..."):
            existing_mappings = client.get_mappings()
            existing_actions = client.get_actions()
        console.print(
            f"✓ Fetched {len(existing_mappings)} mappings, {len(existing_actions)} actions\n"
        )

        # Generate mappings from OpenAPI specs
        all_generated = []
        for api_config in cfg.apis:
            with console.status(f"Processing {api_config.name} OpenAPI spec..."):
                processor = OpenAPIProcessor(api_config)
                spec = processor.fetch_spec()
                mappings = processor.generate_mappings(spec)
                # Apply action names from state file
                mappings = state_mgr.apply_state_to_mappings(mappings, state_data)
                all_generated.extend(mappings)
            console.print(f"✓ Generated {len(mappings)} mappings for {api_config.name}")

        # Validate no FILL_HERE or empty action names
        unfilled = [m for m in all_generated if m.action_name == "FILL_HERE" or not m.action_name or m.action_name.strip() == ""]
        if unfilled:
            console.print(
                f"\n[bold red]✗ Error: {len(unfilled)} mappings have invalid action names[/bold red]"
            )
            console.print(
                "\n[yellow]Please edit the state file and fill in action names for:[/yellow]"
            )
            for m in unfilled[:10]:  # Show first 10
                action_desc = "FILL_HERE" if m.action_name == "FILL_HERE" else "(empty)"
                console.print(f"  - {m.method} {m.path_pattern} -> {action_desc}")
            if len(unfilled) > 10:
                console.print(f"  ... and {len(unfilled) - 10} more")
            sys.exit(1)

        # Calculate changes
        changes = diff_calc.calculate_changes(all_generated, existing_mappings)

        # Find actions that need to be created
        actions_to_create = []
        for change in changes:
            if change.change_type in [ChangeType.CREATE, ChangeType.UPDATE]:
                if change.mapping.action_name not in existing_actions:
                    if change.mapping.action_name not in actions_to_create:
                        actions_to_create.append(change.mapping.action_name)

        # Display plan
        console.print()
        display_plan(changes, actions_to_create)

        # Check if there are any changes
        actionable_changes = [
            c
            for c in changes
            if c.change_type in [ChangeType.CREATE, ChangeType.UPDATE, ChangeType.DELETE]
        ]
        if not actionable_changes and not actions_to_create:
            console.print("\n[bold green]No changes to apply.[/bold green]")
            return

        # Confirm
        if not auto_approve:
            console.print()
            response = click.prompt(
                "Apply these changes?",
                type=click.Choice(["yes", "no"], case_sensitive=False),
                default="no",
            )
            if response.lower() != "yes":
                console.print("[yellow]Apply cancelled.[/yellow]")
                return

        # Apply changes
        console.print("\n[bold]Applying changes...[/bold]\n")

        created_count = 0
        updated_count = 0
        deleted_count = 0
        failed_count = 0

        # Create actions first
        if actions_to_create and cfg.options.auto_create_actions:
            console.print("[bold]Creating actions...[/bold]")
            for action_name in actions_to_create:
                try:
                    action_id = client.create_action(action_name)
                    existing_actions[action_name] = action_id
                    console.print(f"  ✓ Created action: {action_name} (id: {action_id})")
                except Exception as e:
                    console.print(f"  ✗ Failed to create action {action_name}: {e}")
                    failed_count += 1

        # Resolve action IDs for all changes
        for change in changes:
            if change.change_type in [ChangeType.CREATE, ChangeType.UPDATE]:
                action_id = existing_actions.get(change.mapping.action_name)
                if not action_id:
                    console.print(
                        f"[red]✗ Action not found: {change.mapping.action_name}[/red]"
                    )
                    failed_count += 1
                    continue
                change.mapping.action_id = action_id

        # Apply creates
        creates = [c for c in changes if c.change_type == ChangeType.CREATE]
        if creates:
            console.print(f"\n[bold]Creating {len(creates)} mappings...[/bold]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Creating mappings...", total=len(creates))
                for change in creates:
                    try:
                        client.create_mapping(change.mapping)
                        created_count += 1
                    except Exception as e:
                        console.print(
                            f"  ✗ Failed to create {change.mapping.method} {change.mapping.path_pattern}: {e}"
                        )
                        failed_count += 1
                    progress.advance(task)

        # Apply updates
        updates = [c for c in changes if c.change_type == ChangeType.UPDATE]
        if updates:
            console.print(f"\n[bold]Updating {len(updates)} mappings...[/bold]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Updating mappings...", total=len(updates))
                for change in updates:
                    try:
                        client.update_mapping(change.mapping)
                        updated_count += 1
                    except Exception as e:
                        console.print(
                            f"  ✗ Failed to update {change.mapping.method} {change.mapping.path_pattern}: {e}"
                        )
                        failed_count += 1
                    progress.advance(task)

        # Apply deletes
        deletes = [c for c in changes if c.change_type == ChangeType.DELETE]
        if deletes:
            console.print(f"\n[bold]Deleting {len(deletes)} mappings...[/bold]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Deleting mappings...", total=len(deletes))
                for change in deletes:
                    try:
                        if change.mapping.existing_id:
                            client.delete_mapping(change.mapping.existing_id)
                            deleted_count += 1
                    except Exception as e:
                        console.print(
                            f"  ✗ Failed to delete {change.mapping.method} {change.mapping.path_pattern}: {e}"
                        )
                        failed_count += 1
                    progress.advance(task)

        # Summary
        console.print()
        display_apply_summary(created_count, updated_count, deleted_count, failed_count)

        if failed_count > 0:
            sys.exit(1)

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    cli()
