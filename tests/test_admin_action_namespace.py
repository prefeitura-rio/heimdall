"""Admin actions live in the reserved "heimdall:" namespace (DEV-556)."""

import ast
import inspect
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models import Action, Role, RoleAction, User
from app.services import admin_actions as admin_actions_module
from app.services.admin_actions import backfill_admin_actions
from app.services.cerbos import (
    ADMIN_ACTIONS,
    ADMIN_RESOURCE_TYPES,
    CerbosService,
    admin_action,
)

APP_DIR = Path(__file__).resolve().parent.parent / "app"


def _policy(role_actions, user_roles):
    """Principal policy Heimdall builds, with the role -> actions from a dict."""

    def _session():
        session = MagicMock()

        def _query(model):
            query = MagicMock()
            if model is Role:

                def _role_filter(criterion):
                    name = criterion.right.value
                    role = MagicMock() if name in role_actions else None
                    if role is not None:
                        role.id = name
                    result = MagicMock()
                    result.first.return_value = role
                    return result

                query.filter.side_effect = _role_filter
            elif model is Action:

                def _action_filter(criterion):
                    actions = []
                    for name in role_actions.get(criterion.right.value, []):
                        action = MagicMock()
                        action.name = name
                        actions.append(action)
                    result = MagicMock()
                    result.all.return_value = actions
                    return result

                query.join.return_value.filter.side_effect = _action_filter
            return query

        session.query.side_effect = _query
        return session

    service = CerbosService.__new__(CerbosService)
    with patch("app.database.get_db_session", side_effect=_session):
        return service.build_principal_policy("11111111111", user_roles)


def _effect(policy, resource_type, action):
    """Cerbos semantics: no matching rule denies, and DENY wins over ALLOW."""
    effects = {
        entry["effect"]
        for rule in policy["principalPolicy"]["rules"]
        if rule["resource"] in ("*", resource_type)
        for entry in rule["actions"]
        if entry["action"] in ("*", action)
    }
    return "EFFECT_ALLOW" if effects == {"EFFECT_ALLOW"} else "EFFECT_DENY"


# Principal policy -----------------------------------------------------------


@pytest.mark.parametrize("legacy_name", ADMIN_ACTIONS)
@pytest.mark.parametrize("resource_type", ADMIN_RESOURCE_TYPES)
def test_app_role_holding_an_admin_name_gets_no_admin_access(
    legacy_name, resource_type
):
    policy = _policy(
        {"go:cursos:editor": ["cursos:edit", legacy_name]}, ["go:cursos:editor"]
    )

    assert _effect(policy, resource_type, legacy_name) == "EFFECT_DENY"
    assert _effect(policy, resource_type, admin_action(legacy_name)) == "EFFECT_DENY"


def test_app_actions_still_allowed_on_application_resources():
    policy = _policy(
        {"go:cursos:editor": ["cursos:edit", "user:read"]}, ["go:cursos:editor"]
    )

    for resource_type in ("generic", "proposta", "document", "resource"):
        assert _effect(policy, resource_type, "cursos:edit") == "EFFECT_ALLOW"
        assert _effect(policy, resource_type, "user:read") == "EFFECT_ALLOW"
        assert _effect(policy, resource_type, "cursos:delete") == "EFFECT_DENY"


def test_app_actions_are_denied_on_every_admin_resource():
    policy = _policy(
        {"go:cursos:editor": ["cursos:edit", "user:read"]}, ["go:cursos:editor"]
    )

    for resource_type in ADMIN_RESOURCE_TYPES:
        assert _effect(policy, resource_type, "cursos:edit") == "EFFECT_DENY"
        assert _effect(policy, resource_type, "user:read") == "EFFECT_DENY"


def test_prefixed_admin_action_allowed_only_on_admin_resources():
    policy = _policy({"go:admin": ["heimdall:group:add_member"]}, ["go:admin"])

    for resource_type in ADMIN_RESOURCE_TYPES:
        assert (
            _effect(policy, resource_type, "heimdall:group:add_member")
            == "EFFECT_ALLOW"
        )
        assert _effect(policy, resource_type, "heimdall:group:delete") == "EFFECT_DENY"
    assert _effect(policy, "generic", "heimdall:group:add_member") == "EFFECT_DENY"
    assert not any(
        rule["resource"] == "*" for rule in policy["principalPolicy"]["rules"]
    )


def test_admin_plus_app_role_keeps_both_kinds_of_access():
    policy = _policy(
        {"go:admin": ["heimdall:user:list"], "go:cursos:editor": ["cursos:edit"]},
        ["go:admin", "go:cursos:editor"],
    )

    assert _effect(policy, "user", "heimdall:user:list") == "EFFECT_ALLOW"
    assert _effect(policy, "user", "cursos:edit") == "EFFECT_DENY"
    assert _effect(policy, "generic", "cursos:edit") == "EFFECT_ALLOW"


def test_superadmin_policy_is_unchanged():
    policy = _policy({}, ["superadmin"])

    assert policy["principalPolicy"]["rules"] == [
        {"resource": "*", "actions": [{"action": "*", "effect": "EFFECT_ALLOW"}]}
    ]


def test_user_without_actions_is_denied_everything():
    policy = _policy({"empty": []}, ["empty"])

    assert policy["principalPolicy"]["rules"] == [
        {"resource": "*", "actions": [{"action": "*", "effect": "EFFECT_DENY"}]}
    ]


# Names the admin routes check -----------------------------------------------


def test_admin_action_prefixes_known_names_and_rejects_others():
    assert admin_action("user:list") == "heimdall:user:list"
    with pytest.raises(ValueError):
        admin_action("user:read")


@pytest.mark.parametrize(
    "method_name",
    sorted(
        name
        for name, _ in inspect.getmembers(CerbosService, inspect.isfunction)
        if name.startswith("can_")
    ),
)
def test_every_cerbos_helper_checks_a_prefixed_action(method_name):
    service = CerbosService.__new__(CerbosService)
    method = getattr(service, method_name)
    with patch.object(CerbosService, "check_permission", return_value=True) as check:
        params = list(inspect.signature(method).parameters)
        method(*["x"] * len(params))

    action = check.call_args.kwargs["action"]
    assert action.startswith("heimdall:")
    assert action.removeprefix("heimdall:") in ADMIN_ACTIONS


def test_no_check_permission_call_uses_a_literal_un_prefixed_action():
    offenders = []
    for path in APP_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and getattr(node.func, "attr", None) == "check_permission"
            ):
                continue
            for keyword in node.keywords:
                if keyword.arg == "action" and isinstance(keyword.value, ast.Constant):
                    offenders.append(f"{path.name}:{node.lineno} {keyword.value.value}")
    assert offenders == []


# Startup backfill (expand phase) ----------------------------------------------


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    tables = [User.__table__, Role.__table__, Action.__table__, RoleAction.__table__]
    User.metadata.create_all(engine, tables=tables)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _grant(db, role_name, action_name, granted_by=None):
    role_id = db.execute(
        text("SELECT id FROM roles WHERE name = :n"), {"n": role_name}
    ).scalar()
    if role_id is None:
        role_id = db.execute(
            text("INSERT INTO roles (name) VALUES (:n) RETURNING id"), {"n": role_name}
        ).scalar()
    action_id = db.execute(
        text("SELECT id FROM actions WHERE name = :n"), {"n": action_name}
    ).scalar()
    if action_id is None:
        action_id = db.execute(
            text("INSERT INTO actions (name) VALUES (:n) RETURNING id"),
            {"n": action_name},
        ).scalar()
    db.execute(
        text(
            "INSERT INTO role_actions (role_id, action_id, granted_by) VALUES (:r, :a, :g)"
        ),
        {"r": role_id, "a": action_id, "g": granted_by},
    )
    db.commit()


def _role_actions(db):
    rows = db.execute(
        text(
            "SELECT r.name, a.name FROM role_actions ra "
            "JOIN roles r ON r.id = ra.role_id JOIN actions a ON a.id = ra.action_id"
        )
    ).all()
    return {(role, action) for role, action in rows}


def _action_names(db):
    return {name for (name,) in db.execute(text("SELECT name FROM actions")).all()}


@pytest.fixture
def version_bump():
    with patch.object(admin_actions_module, "PolicyVersionTracker") as tracker_cls:
        yield tracker_cls.return_value.increment_version


def test_backfill_creates_every_prefixed_action_and_copies_legacy_grants(
    db, version_bump
):
    db.execute(text("INSERT INTO users (subject) VALUES ('admin-synthetic')"))
    db.commit()
    _grant(db, "go:admin", "group:add_member", granted_by=1)
    _grant(db, "go:admin", "user:list")
    _grant(db, "go:cursos:editor", "cursos:edit")

    created = backfill_admin_actions(db)

    assert sorted(created) == sorted(admin_action(name) for name in ADMIN_ACTIONS)
    assert {admin_action(name) for name in ADMIN_ACTIONS} <= _action_names(db)
    assert _role_actions(db) == {
        ("go:admin", "group:add_member"),
        ("go:admin", "user:list"),
        ("go:admin", "heimdall:group:add_member"),
        ("go:admin", "heimdall:user:list"),
        ("go:cursos:editor", "cursos:edit"),
    }
    granted_by = db.execute(
        text(
            "SELECT ra.granted_by FROM role_actions ra JOIN actions a ON a.id = ra.action_id "
            "WHERE a.name = 'heimdall:group:add_member'"
        )
    ).scalar()
    assert granted_by == 1
    version_bump.assert_called_once()


def test_backfill_runs_once_and_never_restores_a_revoked_grant(db, version_bump):
    _grant(db, "go:admin", "group:create")
    backfill_admin_actions(db)
    db.execute(
        text(
            "DELETE FROM role_actions WHERE action_id = "
            "(SELECT id FROM actions WHERE name = 'heimdall:group:create')"
        )
    )
    db.commit()
    version_bump.reset_mock()

    created = backfill_admin_actions(db)

    assert created == []
    assert ("go:admin", "heimdall:group:create") not in _role_actions(db)
    version_bump.assert_not_called()


@pytest.mark.usefixtures("version_bump")
def test_backfill_keeps_an_existing_prefixed_action_as_is(db):
    _grant(db, "go:admin", "user:list")
    _grant(db, "auditor", "heimdall:user:list")

    backfill_admin_actions(db)

    assert ("go:admin", "heimdall:user:list") not in _role_actions(db)
    assert ("auditor", "heimdall:user:list") in _role_actions(db)


def test_backfill_rolls_back_on_error(db, version_bump):
    _grant(db, "go:admin", "group:create")
    real_execute = db.execute
    calls = {"n": 0}

    def _failing_execute(statement, params=None):
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("synthetic failure")
        return real_execute(statement, params)

    with (
        patch.object(db, "execute", side_effect=_failing_execute),
        pytest.raises(RuntimeError),
    ):
        backfill_admin_actions(db)

    assert not any(name.startswith("heimdall:") for name in _action_names(db))
    version_bump.assert_not_called()


# Startup wiring -----------------------------------------------------------------


def _lifespan_with(backfill, monkeypatch):
    import asyncio
    import importlib
    import sys

    from app.settings import settings

    monkeypatch.setenv("ENABLE_BACKGROUND_TASKS", "false")
    sys.modules.pop("app.main", None)
    with (
        patch.object(settings, "validate"),
        patch.object(CerbosService, "ensure_superadmin_policy", return_value=True),
    ):
        main = importlib.import_module("app.main")
    sys.modules.pop("app.main", None)

    session = MagicMock()
    session.__enter__.return_value = session
    events = []

    async def _run():
        async with main.lifespan(main.app):
            events.append("serving")

    with (
        patch("app.database.get_db_session", return_value=session),
        patch(
            "app.services.admin_actions.backfill_admin_actions", side_effect=backfill
        ) as spy,
        patch("app.services.mapping.MappingService"),
    ):
        asyncio.run(_run())
    return spy, session, events


def test_startup_runs_the_backfill_before_serving(monkeypatch):
    order = []

    def _backfill(_db):
        order.append("backfill")
        return ["heimdall:user:list"]

    spy, session, events = _lifespan_with(_backfill, monkeypatch)

    spy.assert_called_once_with(session)
    assert order + events == ["backfill", "serving"]


def test_startup_still_serves_when_the_backfill_fails(monkeypatch):
    def _boom(_db):
        raise RuntimeError("synthetic database failure")

    spy, _session, events = _lifespan_with(_boom, monkeypatch)

    spy.assert_called_once()
    assert events == ["serving"]
