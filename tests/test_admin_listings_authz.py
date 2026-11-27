"""The admin listings check a reserved "heimdall:" action in Cerbos (DEV-556).

GET /actions/, GET /actions/{id}, GET /groups/, GET /mappings/list and
GET /roles/ used to rely only on the gateway (ext_authz), which resolves the
route to an un-prefixed action that an application role can hold by accident.
"""

import ast
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.routers.actions import get_action, list_actions
from app.routers.groups import list_groups
from app.routers.mappings import list_mappings
from app.routers.roles import list_roles

CALLER_CPF = "11111111111"  # synthetic
ROUTERS_DIR = Path(__file__).resolve().parent.parent / "app" / "routers"


def _caller():
    user = MagicMock()
    user.subject = CALLER_CPF
    user.id = 7
    return user


def _user_service():
    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["go:cursos:editor"]
    return user_service


def _cerbos(allowed):
    cerbos_service = MagicMock()
    cerbos_service.check_permission.return_value = allowed
    return cerbos_service


def _run(coro):
    with patch("app.common.authz.AuditService") as audit_cls:
        try:
            result = asyncio.run(coro)
        except HTTPException as exc:
            return None, exc, audit_cls.return_value.log_authorization_denied
        return result, None, audit_cls.return_value.log_authorization_denied


def _call(name, allowed):
    """Run one listing handler; returns (result, exc, audit, cerbos, reader)."""
    db = MagicMock()
    db.query.return_value.count.return_value = 0
    reader = MagicMock()
    user_service = _user_service()
    cerbos_service = _cerbos(allowed)
    common = {
        "current_user": _caller(),
        "db": db,
        "user_service": user_service,
        "cerbos_service": cerbos_service,
    }
    if name == "list_actions":
        reader.list_actions.return_value = []
        coro = list_actions(action_service=reader, skip=0, limit=50, **common)
    elif name == "get_action":
        reader.get_action.return_value = None
        coro = get_action(action_id=42, action_service=reader, **common)
    elif name == "list_groups":
        reader.list_groups.return_value = []
        coro = list_groups(prefix=None, group_service=reader, **common)
    elif name == "list_mappings":
        reader.list_mappings.return_value = []
        coro = list_mappings(mapping_service=reader, action_filter=None, **common)
    else:
        reader.list_roles.return_value = ([], 0)
        coro = list_roles(role_service=reader, skip=0, limit=50, **common)
    result, exc, audit = _run(coro)
    return result, exc, audit, cerbos_service, reader


LISTINGS = [
    ("list_actions", "heimdall:action:list", "action", "list_actions"),
    ("get_action", "heimdall:action:read", "action", "get_action"),
    ("list_groups", "heimdall:group:list", "group", "list_groups"),
    ("list_mappings", "heimdall:mapping:list", "mapping", "list_mappings"),
    ("list_roles", "heimdall:role:list", "role", "list_roles"),
]


@pytest.mark.parametrize(("name", "action", "resource_type", "reader_method"), LISTINGS)
def test_denied_caller_gets_audited_403_before_any_read(
    name, action, resource_type, reader_method
):
    result, exc, audit, cerbos_service, reader = _call(name, allowed=False)

    assert result is None
    assert exc.status_code == 403
    kwargs = cerbos_service.check_permission.call_args.kwargs
    assert kwargs["action"] == action
    assert kwargs["resource_type"] == resource_type
    assert kwargs["caller_roles"] == ["go:cursos:editor"]
    audit.assert_called_once()
    assert audit.call_args.kwargs["operation"] == name
    assert audit.call_args.kwargs["target_type"] == resource_type
    getattr(reader, reader_method).assert_not_called()


@pytest.mark.parametrize(
    ("name", "action", "reader_method"), [(n, a, m) for n, a, _r, m in LISTINGS]
)
def test_allowed_caller_reads(name, action, reader_method):
    _result, exc, audit, cerbos_service, reader = _call(name, allowed=True)

    assert cerbos_service.check_permission.call_args.kwargs["action"] == action
    audit.assert_not_called()
    getattr(reader, reader_method).assert_called_once()
    if name == "get_action":
        assert exc.status_code == 404
    else:
        assert exc is None


def test_get_action_denied_answers_the_same_for_any_id():
    _r, exc, _a, cerbos_service, reader = _call("get_action", allowed=False)

    assert exc.detail == "Permission denied to view actions"
    assert cerbos_service.check_permission.call_args.kwargs["resource_attrs"] == {
        "id": "42"
    }
    reader.get_action.assert_not_called()


# Every admin route checks Cerbos ---------------------------------------------

# Routes open to any caller on purpose: the adapters resolve a mapping, and a
# user reads their own profile.
UNCHECKED_BY_DESIGN = {
    ("mappings", "resolve_mapping"),
    ("users", "get_current_user_info"),
}
# Handlers whose check lives in the service they call (MembershipService).
CHECKED_IN_SERVICE = {
    ("memberships", "list_group_members"),
    ("memberships", "add_member_to_group"),
    ("memberships", "remove_member_from_group"),
}
ADMIN_ROUTERS = ("actions", "groups", "mappings", "memberships", "roles", "users")
_CHECK_CALLS = {"check_permission", "require_admin_permission"}


def _route_handlers():
    for router in ADMIN_ROUTERS:
        tree = ast.parse((ROUTERS_DIR / f"{router}.py").read_text())
        for node in tree.body:
            if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
                continue
            is_route = any(
                isinstance(d, ast.Call)
                and getattr(d.func, "attr", None)
                in {"get", "post", "put", "delete", "patch"}
                for d in node.decorator_list
            )
            if is_route:
                yield router, node


def test_every_admin_route_checks_cerbos():
    unchecked = []
    for router, handler in _route_handlers():
        key = (router, handler.name)
        if key in UNCHECKED_BY_DESIGN or key in CHECKED_IN_SERVICE:
            continue
        calls = {
            getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            for node in ast.walk(handler)
            if isinstance(node, ast.Call)
        }
        if not (calls & _CHECK_CALLS or any(str(c).startswith("can_") for c in calls)):
            unchecked.append(f"{router}.{handler.name}")
    assert unchecked == []
