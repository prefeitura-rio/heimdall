"""
Declarative, versioned endpoint-to-action mappings (DEV-650).

The mappings of an application (for example the go-api) live in a JSON file in
this repository (``mappings/<application>.json``) instead of only in the
database. This module compares the file with the database and either shows
what would change (``plan``, read-only) or applies it (``apply``), through
``MappingService``: the same path the admin API uses, so Redis (read by the
ext_authz at the edge) and the audit log are updated as well.

Usage (DB_DSN and REDIS_URL of the target Heimdall in the environment):

    uv run python -m app.mappings_sync plan --file mappings/go-api.json
    uv run python -m app.mappings_sync apply --file mappings/go-api.json

Guarantees:

- ``plan`` never writes. ``apply`` prints the same plan and then applies it.
- Idempotent: applying twice leaves the second run with nothing to change.
- Scope: only the patterns of the routes declared in the file are created or
  changed, and every declared path must start with the file's ``path_prefix``
  (``/go/`` for the go-api). The only other pattern touched is the one the
  OpenAPI tool also generates for the same route without the prefix (alias),
  and only when it already exists. Nothing is deleted unless the file lists it
  under ``remove``, which is also limited to ``path_prefix``.
- Fail closed: an unknown action, a reference that resolves to no action or to
  two different ones, or an existing pattern of another route that matches a
  declared route with a different action (it could win at the edge) aborts
  the whole run before any write, with the reason in the output.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from sqlalchemy import Engine, text

from app.models import Action, Endpoint, User

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.orm import Session

# Subject recorded in the audit log for the changes made by this tool. The user
# is never persisted (created_by stays empty), so no login can turn into it.
SYNC_SUBJECT = "system:mappings_sync"

# Key of the Postgres advisory lock that serializes concurrent runs (several
# heimdall-admin pods starting at once run the initContainer in parallel).
ADVISORY_LOCK_KEY = 650_650_650

# Value put in place of each {param} to test which existing patterns match a
# route. Eleven zeros match "([^/]+)", "(\\d+)" and "(\\d{11})" alike, and are
# not a valid CPF.
SAMPLE_PARAM = "00000000000"

HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

_SEGMENT = re.compile(r"^(?:[A-Za-z0-9._~-]+|\{[A-Za-z_][A-Za-z0-9_]*\})$")
_PARAM = re.compile(r"\{[^}]+\}")


# ============================================================================
# File format
# ============================================================================


def _validate_route_path(path: str) -> str:
    if not path.startswith("/") or path == "/" or path.endswith("/"):
        raise ValueError(f"path must start with '/' and not end with '/': {path!r}")
    segments = path[1:].split("/")
    for segment in segments:
        if not _SEGMENT.match(segment):
            raise ValueError(
                f"path segment {segment!r} of {path!r} must be a literal "
                "([A-Za-z0-9._~-]) or a {param}; regex is generated, not written"
            )
    return path


class RouteRef(BaseModel):
    """A route (method + OpenAPI-style path) whose current action is reused."""

    model_config = ConfigDict(extra="forbid")

    method: HttpMethod
    path: str

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        return _validate_route_path(v)


class MappingEntry(BaseModel):
    """One route of the application and the action it must resolve to."""

    model_config = ConfigDict(extra="forbid")

    method: HttpMethod
    path: str
    action: str | None = Field(None, description="Action name, e.g. 'public'")
    same_as: RouteRef | None = Field(
        None, description="Reuse the action the database maps to this route today"
    )
    description: str | None = Field(None, max_length=500)
    source: str | None = Field(None, description="Issue that asked for it")

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        return _validate_route_path(v)

    @field_validator("action")
    @classmethod
    def _action(cls, v: str | None) -> str | None:
        if v is not None and (not v.strip() or v != v.strip() or " " in v):
            raise ValueError(f"invalid action name: {v!r}")
        return v

    @model_validator(mode="after")
    def _one_action(self) -> MappingEntry:
        if (self.action is None) == (self.same_as is None):
            raise ValueError(
                f"{self.method} {self.path}: give exactly one of 'action' or 'same_as'"
            )
        return self


class RemovedRoute(BaseModel):
    """A route whose mapping must not exist."""

    model_config = ConfigDict(extra="forbid")

    method: HttpMethod
    path: str
    source: str | None = None

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        return _validate_route_path(v)


class MappingFile(BaseModel):
    """Root of ``mappings/<application>.json``."""

    model_config = ConfigDict(extra="forbid")

    comment: str | None = Field(None, alias="_comment")
    application: str = Field(..., min_length=1)
    path_prefix: str
    mappings: list[MappingEntry] = Field(default_factory=list)
    remove: list[RemovedRoute] = Field(default_factory=list)

    @field_validator("path_prefix")
    @classmethod
    def _prefix(cls, v: str) -> str:
        if not re.fullmatch(r"(/[A-Za-z0-9._~-]+)+/", v):
            raise ValueError(
                f"path_prefix must look like '/go/' (a non-empty path ending in '/'): {v!r}"
            )
        return v

    @model_validator(mode="after")
    def _scope(self) -> MappingFile:
        declared: set[tuple[str, str]] = set()
        for entry in self.mappings:
            key = (entry.method, entry.path)
            if key in declared:
                raise ValueError(f"route declared twice: {entry.method} {entry.path}")
            declared.add(key)
        for entry in self.mappings:
            if not entry.path.startswith(self.path_prefix):
                raise ValueError(
                    f"{entry.method} {entry.path} is outside path_prefix {self.path_prefix!r}"
                )
            ref = entry.same_as
            if ref is not None:
                if not ref.path.startswith(self.path_prefix):
                    raise ValueError(
                        f"same_as of {entry.method} {entry.path} points outside "
                        f"path_prefix {self.path_prefix!r}"
                    )
                if (ref.method, ref.path) in declared:
                    raise ValueError(
                        f"same_as of {entry.method} {entry.path} points to a route "
                        "declared in this file; give the action instead"
                    )
        removed: set[tuple[str, str]] = set()
        for route in self.remove:
            key = (route.method, route.path)
            if not route.path.startswith(self.path_prefix):
                raise ValueError(
                    f"remove {route.method} {route.path} is outside path_prefix "
                    f"{self.path_prefix!r}"
                )
            if key in declared:
                raise ValueError(
                    f"route both declared and removed: {route.method} {route.path}"
                )
            if key in removed:
                raise ValueError(f"route removed twice: {route.method} {route.path}")
            removed.add(key)
        return self


def load_mapping_file(path: str | Path) -> MappingFile:
    """Read and validate a mapping file (raises ValueError with the reason)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read {path}: {e}") from e
    try:
        return MappingFile.model_validate(data)
    except ValidationError as e:
        raise ValueError(f"invalid mapping file {path}: {e}") from e


# ============================================================================
# Patterns
# ============================================================================


def route_pattern(path: str) -> str:
    """
    Pattern stored for a route, in the format scripts/manage_openapi_mappings.py
    generates and the existing mappings use: each {param} becomes "([^/]+)" and
    only an end anchor "$" is appended.
    """
    return _PARAM.sub("([^/]+)", path) + "$"


def sample_path(path: str) -> str:
    """A concrete request path for the route, to test which patterns match it."""
    return _PARAM.sub(SAMPLE_PARAM, path)


def _matches(pattern: str, path: str) -> bool:
    # The ext_authz (Go regexp.MatchString) searches the pattern anywhere in the
    # path; re.search reproduces that, so a pattern without "^" counts too.
    try:
        return re.search(pattern, path) is not None
    except re.error:
        return False


# ============================================================================
# Plan
# ============================================================================


class ChangeKind(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    UNCHANGED = "unchanged"


@dataclass(frozen=True)
class ExistingMapping:
    id: int
    method: str
    path_pattern: str
    action_name: str


@dataclass
class Change:
    kind: ChangeKind
    method: str
    path_pattern: str
    route: str
    action_name: str | None = None
    old_action_name: str | None = None
    mapping_id: int | None = None
    description: str | None = None
    note: str | None = None


@dataclass
class Plan:
    changes: list[Change] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def count(self, kind: ChangeKind) -> int:
        return sum(1 for c in self.changes if c.kind == kind)

    @property
    def has_writes(self) -> bool:
        return any(c.kind != ChangeKind.UNCHANGED for c in self.changes)


def _load_existing(db: Session) -> list[ExistingMapping]:
    rows = (
        db.query(Endpoint.id, Endpoint.method, Endpoint.path_pattern, Action.name)
        .join(Action, Action.id == Endpoint.action_id)
        .order_by(Endpoint.id)
        .all()
    )
    return [ExistingMapping(r[0], r[1], r[2], r[3]) for r in rows]


def _resolve_reference(
    ref: RouteRef, existing: list[ExistingMapping], alias_strip: str
) -> tuple[str | None, str | None]:
    """Action the database maps to the referenced route, or (None, reason)."""
    by_key = {(m.method, m.path_pattern): m for m in existing}
    # The route's own pattern first, then the same route without the prefix.
    for pattern in (
        route_pattern(ref.path),
        route_pattern(ref.path[len(alias_strip) :]),
    ):
        own = by_key.get((ref.method, pattern))
        if own is not None:
            return own.action_name, None
    # Otherwise whatever pattern matches the route today, if they all agree.
    sample = sample_path(ref.path)
    candidates = [
        m
        for m in existing
        if m.method == ref.method and _matches(m.path_pattern, sample)
    ]
    if not candidates:
        return None, f"same_as {ref.method} {ref.path}: no mapping for that route"
    actions = sorted({m.action_name for m in candidates})
    if len(actions) > 1:
        return None, (
            f"same_as {ref.method} {ref.path}: patterns disagree on the action "
            f"({', '.join(actions)}); declare the action explicitly"
        )
    return actions[0], None


def build_plan(db: Session, spec: MappingFile) -> Plan:
    """Compare the file with the database. Never writes."""
    plan = Plan()
    existing = _load_existing(db)
    by_key = {(m.method, m.path_pattern): m for m in existing}
    known_actions = {name for (name,) in db.query(Action.name).all()}
    alias_strip = spec.path_prefix.rstrip("/")

    for entry in spec.mappings:
        route = f"{entry.method} {entry.path}"
        if entry.action is not None:
            desired: str | None = entry.action
            if desired not in known_actions:
                plan.errors.append(f"{route}: action {desired!r} does not exist")
                continue
        else:
            assert entry.same_as is not None
            desired, reason = _resolve_reference(entry.same_as, existing, alias_strip)
            if desired is None:
                plan.errors.append(f"{route}: {reason}")
                continue

        pattern = route_pattern(entry.path)
        alias = route_pattern(entry.path[len(alias_strip) :])
        sample = sample_path(entry.path)
        source = f" ({entry.source})" if entry.source else ""
        create_note = (
            f"same_as {entry.same_as.method} {entry.same_as.path}{source}"
            if entry.same_as
            else entry.source
        )

        current = by_key.get((entry.method, pattern))
        if current is None:
            plan.changes.append(
                Change(
                    ChangeKind.CREATE,
                    entry.method,
                    pattern,
                    route,
                    action_name=desired,
                    description=entry.description,
                    note=create_note,
                )
            )
        elif current.action_name != desired:
            plan.changes.append(
                Change(
                    ChangeKind.UPDATE,
                    entry.method,
                    pattern,
                    route,
                    action_name=desired,
                    old_action_name=current.action_name,
                    mapping_id=current.id,
                    note=entry.source,
                )
            )
        else:
            plan.changes.append(
                Change(
                    ChangeKind.UNCHANGED,
                    entry.method,
                    pattern,
                    route,
                    action_name=desired,
                    mapping_id=current.id,
                )
            )

        alias_mapping = by_key.get((entry.method, alias))
        if alias_mapping is not None and alias_mapping.action_name != desired:
            plan.changes.append(
                Change(
                    ChangeKind.UPDATE,
                    entry.method,
                    alias,
                    route,
                    action_name=desired,
                    old_action_name=alias_mapping.action_name,
                    mapping_id=alias_mapping.id,
                    note=f"same route without {alias_strip}",
                )
            )

        for other in existing:
            if other.method != entry.method or other.path_pattern in (pattern, alias):
                continue
            if other.action_name != desired and _matches(other.path_pattern, sample):
                plan.errors.append(
                    f"{route}: pattern {other.path_pattern!r} (id {other.id}) of another "
                    f"route also matches it with action {other.action_name!r} and can "
                    "win at the edge; fix or remove that mapping first"
                )

    for removed in spec.remove:
        pattern = route_pattern(removed.path)
        route = f"{removed.method} {removed.path}"
        current = by_key.get((removed.method, pattern))
        if current is not None:
            plan.changes.append(
                Change(
                    ChangeKind.DELETE,
                    removed.method,
                    pattern,
                    route,
                    old_action_name=current.action_name,
                    mapping_id=current.id,
                    note=removed.source,
                )
            )

    return plan


def format_plan(plan: Plan, spec: MappingFile) -> str:
    lines = [f"Mappings of {spec.application} (prefix {spec.path_prefix}):"]
    symbols = {
        ChangeKind.CREATE: "+",
        ChangeKind.UPDATE: "~",
        ChangeKind.DELETE: "-",
        ChangeKind.UNCHANGED: "=",
    }
    for change in plan.changes:
        head = f"  {symbols[change.kind]} {change.kind.value:<9} {change.method:<6} {change.path_pattern}"
        if change.kind == ChangeKind.CREATE:
            detail = f"action={change.action_name}"
        elif change.kind == ChangeKind.UPDATE:
            detail = f"id={change.mapping_id} action={change.old_action_name} -> {change.action_name}"
        elif change.kind == ChangeKind.DELETE:
            detail = f"id={change.mapping_id} action={change.old_action_name}"
        else:
            detail = f"id={change.mapping_id} action={change.action_name}"
        note = f" [{change.note}]" if change.note else ""
        lines.append(f"{head}  {detail}{note}")
    for error in plan.errors:
        lines.append(f"  ! error: {error}")
    lines.append(
        f"Plan: {plan.count(ChangeKind.CREATE)} to create, "
        f"{plan.count(ChangeKind.UPDATE)} to update, "
        f"{plan.count(ChangeKind.DELETE)} to delete, "
        f"{plan.count(ChangeKind.UNCHANGED)} unchanged, "
        f"{len(plan.errors)} error(s)"
    )
    return "\n".join(lines)


# ============================================================================
# Apply
# ============================================================================


def _sync_actor() -> User:
    # Transient: never added to the session, so id stays None and the mappings
    # are created without created_by; the audit log records SYNC_SUBJECT.
    return User(subject=SYNC_SUBJECT, display_name="Versioned mappings sync")


def apply_plan(db: Session, plan: Plan, mapping_service: Any) -> list[str]:
    """Apply a plan without errors. Returns the failures (empty on success)."""
    if plan.errors:
        raise ValueError("refusing to apply a plan with errors")
    actor = _sync_actor()
    action_ids = {
        name: action_id for action_id, name in db.query(Action.id, Action.name).all()
    }
    failures: list[str] = []
    for change in plan.changes:
        label = f"{change.kind.value} {change.method} {change.path_pattern}"
        try:
            if change.kind == ChangeKind.CREATE:
                mapping_service.create_mapping(
                    db=db,
                    path_pattern=change.path_pattern,
                    method=change.method,
                    action_id=action_ids[change.action_name],
                    description=change.description,
                    created_by=actor,
                )
            elif change.kind == ChangeKind.UPDATE:
                mapping_service.update_mapping(
                    db=db,
                    mapping_id=change.mapping_id,
                    path_pattern=None,
                    method=None,
                    action_id=action_ids[change.action_name],
                    description=None,
                    updated_by=actor,
                )
            elif change.kind == ChangeKind.DELETE:
                mapping_service.delete_mapping(
                    db=db, mapping_id=change.mapping_id, deleted_by=actor
                )
        except Exception as e:  # report and continue: a rerun converges
            db.rollback()
            failures.append(f"{label}: {type(e).__name__}: {e}")
    return failures


@contextlib.contextmanager
def advisory_lock(engine: Engine) -> Iterator[None]:
    """Serialize concurrent runs on Postgres; a no-op on other databases."""
    if engine.dialect.name != "postgresql":
        yield
        return
    with engine.connect() as conn:
        conn.execute(text("SELECT pg_advisory_lock(:key)"), {"key": ADVISORY_LOCK_KEY})
        try:
            yield
        finally:
            conn.execute(
                text("SELECT pg_advisory_unlock(:key)"), {"key": ADVISORY_LOCK_KEY}
            )
            conn.commit()


# ============================================================================
# CLI
# ============================================================================

EXIT_OK = 0
EXIT_INVALID_FILE = 1
EXIT_PLAN_ERRORS = 2
EXIT_APPLY_FAILED = 3


def run(
    command: str, file_path: str, db: Session, engine: Engine, mapping_service: Any
) -> int:
    try:
        spec = load_mapping_file(file_path)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_INVALID_FILE

    with advisory_lock(engine):
        plan = build_plan(db, spec)
        print(format_plan(plan, spec))
        if plan.errors:
            print("Nothing applied: fix the errors above.", file=sys.stderr)
            return EXIT_PLAN_ERRORS
        if command == "plan":
            print("Dry run (plan): nothing was written.")
            return EXIT_OK
        if not plan.has_writes:
            print("No changes to apply.")
            return EXIT_OK
        failures = apply_plan(db, plan, mapping_service)
        for failure in failures:
            print(f"  ! failed: {failure}", file=sys.stderr)
        if failures:
            print(
                f"Apply finished with {len(failures)} failure(s); rerun to converge.",
                file=sys.stderr,
            )
            return EXIT_APPLY_FAILED
        print("Apply complete.")
        return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.mappings_sync",
        description="Plan or apply the versioned endpoint-to-action mappings of an application.",
    )
    parser.add_argument("command", choices=["plan", "apply"])
    parser.add_argument(
        "--file", required=True, help="Mapping file, e.g. mappings/go-api.json"
    )
    args = parser.parse_args(argv)

    # The sync actor has no user id (see _sync_actor), which MappingService puts
    # in span attributes; OpenTelemetry drops a None attribute with a warning per
    # write. Only that logger is quieted, and only in this command.
    logging.getLogger("opentelemetry.attributes").setLevel(logging.ERROR)

    # Imported here: they connect to the configured database and Redis.
    from app.database import SessionLocal, engine
    from app.services.mapping import MappingService

    db = SessionLocal()
    try:
        return run(args.command, args.file, db, engine, MappingService())
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
