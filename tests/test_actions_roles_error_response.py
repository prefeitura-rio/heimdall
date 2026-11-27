"""500 responses of the action and role routes never carry the error (DEV-626).

The ``except Exception`` blocks of ``app/routers/actions.py`` (create, list,
get, update and delete action) and of ``app/routers/roles.py`` (list, assign and
remove role actions, delete role) answered 500 with ``detail=f"...: {str(e)}"``:
the SQLAlchemy/psycopg2 message with the driver type, the constraint, the SQL
and the ``DETAIL: Key (...)=(<value>)`` line. The response now carries a fixed
message and the error stays only in the masked structured log (DEV-554), as
DEV-560 did for the authentication dependencies and the users router.
Synthetic data only.
"""

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import psycopg2.errors
import pytest
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from app.logging_config import KEY_VALUE_PLACEHOLDER, StructuredFormatter
from app.routers import actions as actions_router
from app.routers import roles as roles_router
from app.routers.actions import ActionCreateRequest, ActionUpdateRequest
from app.routers.roles import RoleActionRequest

KEY_VALUE = "valor-sintetico-626"  # synthetic key value quoted by the driver
CONSTRAINT = "uq_sintetico_626"
ROLE = "role:sintetico"
ACTION = "report:read"

# Anything from the driver message that must never reach the response body
LEAKS = (
    KEY_VALUE,
    CONSTRAINT,
    "INSERT",
    "psycopg2",
    "IntegrityError",
    "UniqueViolation",
    "DETAIL",
    "Key (",
)


def _unique_violation() -> IntegrityError:
    """What SQLAlchemy raises on a unique constraint violation."""
    orig = psycopg2.errors.UniqueViolation(
        f'duplicate key value violates unique constraint "{CONSTRAINT}"\n'
        f"DETAIL:  Key (name)=({KEY_VALUE}) already exists.\n"
    )
    return IntegrityError(
        "INSERT INTO actions (name, description) VALUES (%(name)s, %(description)s)",
        {"name": KEY_VALUE, "description": "x"},
        orig,
        hide_parameters=True,
    )


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.setFormatter(StructuredFormatter())
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


@pytest.fixture
def captured():
    handler = _Capture()
    target = logging.getLogger("app")
    previous = target.level
    target.addHandler(handler)
    target.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        target.removeHandler(handler)
        target.setLevel(previous)


def _user() -> MagicMock:
    user = MagicMock()
    user.subject = "uuid-caller-sintetico"
    user.id = 7
    return user


def _user_service() -> MagicMock:
    service = MagicMock()
    service.get_user_roles.return_value = ["heimdall-admin"]
    return service


def _cerbos_allowing() -> MagicMock:
    cerbos = MagicMock()
    cerbos.check_permission.return_value = True
    cerbos.can_create_action.return_value = True
    cerbos.can_update_action.return_value = True
    cerbos.can_delete_action.return_value = True
    return cerbos


def _role_service(failing: str) -> MagicMock:
    service = MagicMock()
    service.get_role_by_name.return_value = MagicMock(name=ROLE)
    service.get_groups_with_role.return_value = []
    getattr(service, failing).side_effect = _unique_violation()
    return service


def _action_service(failing: str) -> MagicMock:
    service = MagicMock()
    service.get_action_by_name.return_value = MagicMock(name=ACTION)
    getattr(service, failing).side_effect = _unique_violation()
    return service


# Each case: (operation logged, fixed detail, call that fails in the database)
Case = tuple[str, str, Callable[[], Any]]


def _create_action() -> Any:
    return actions_router.create_action(
        action_data=ActionCreateRequest(name=ACTION, description="Read reports"),
        current_user=_user(),
        db=MagicMock(),
        action_service=_action_service("create_action"),
        cerbos_service=_cerbos_allowing(),
        user_service=_user_service(),
    )


def _list_actions() -> Any:
    return actions_router.list_actions(
        current_user=_user(),
        db=MagicMock(),
        action_service=_action_service("list_actions"),
        user_service=_user_service(),
        cerbos_service=_cerbos_allowing(),
        skip=0,
        limit=50,
    )


def _get_action() -> Any:
    return actions_router.get_action(
        action_id=1,
        current_user=_user(),
        db=MagicMock(),
        action_service=_action_service("get_action"),
        user_service=_user_service(),
        cerbos_service=_cerbos_allowing(),
    )


def _update_action() -> Any:
    return actions_router.update_action(
        action_id=1,
        action_data=ActionUpdateRequest(name=ACTION),
        current_user=_user(),
        db=MagicMock(),
        action_service=_action_service("update_action"),
        cerbos_service=_cerbos_allowing(),
        user_service=_user_service(),
    )


def _delete_action() -> Any:
    return actions_router.delete_action(
        action_id=1,
        current_user=_user(),
        db=MagicMock(),
        action_service=_action_service("delete_action"),
        cerbos_service=_cerbos_allowing(),
        user_service=_user_service(),
    )


def _list_role_actions() -> Any:
    return roles_router.list_role_actions(
        role_name=ROLE,
        current_user=_user(),
        db=MagicMock(),
        role_service=_role_service("list_role_actions"),
        _action_service=MagicMock(),
        cerbos_service=_cerbos_allowing(),
        user_service=_user_service(),
    )


def _assign_action_to_role() -> Any:
    return roles_router.assign_action_to_role(
        role_name=ROLE,
        action_data=RoleActionRequest(action_name=ACTION),
        current_user=_user(),
        db=MagicMock(),
        role_service=_role_service("assign_action_to_role"),
        action_service=_action_service("get_action"),
        cerbos_service=_cerbos_allowing(),
        user_service=_user_service(),
    )


def _remove_action_from_role() -> Any:
    return roles_router.remove_action_from_role(
        role_name=ROLE,
        action_name=ACTION,
        current_user=_user(),
        db=MagicMock(),
        role_service=_role_service("remove_action_from_role"),
        action_service=_action_service("get_action"),
        cerbos_service=_cerbos_allowing(),
        user_service=_user_service(),
    )


def _delete_role() -> Any:
    return roles_router.delete_role(
        role_name=ROLE,
        current_user=_user(),
        db=MagicMock(),
        role_service=_role_service("delete_role"),
        cerbos_service=_cerbos_allowing(),
        user_service=_user_service(),
    )


CASES: list[Case] = [
    ("create_action", "Failed to create action", _create_action),
    ("list_actions", "Failed to list actions", _list_actions),
    ("get_action", "Failed to get action", _get_action),
    ("update_action", "Failed to update action", _update_action),
    ("delete_action", "Failed to delete action", _delete_action),
    ("list_role_actions", "Failed to retrieve role actions", _list_role_actions),
    (
        "assign_action_to_role",
        "Failed to assign action to role",
        _assign_action_to_role,
    ),
    (
        "remove_action_from_role",
        "Failed to remove action from role",
        _remove_action_from_role,
    ),
    ("delete_role", "Failed to delete role", _delete_role),
]


def test_driver_message_carries_the_leaks():
    """Guard for the fixture: the raw error really quotes the value, SQL and constraint."""
    raw = str(_unique_violation())
    for leak in (KEY_VALUE, CONSTRAINT, "INSERT", "psycopg2", "DETAIL", "Key ("):
        assert leak in raw


@pytest.mark.parametrize(
    ("operation", "expected", "call"), CASES, ids=[case[0] for case in CASES]
)
def test_database_failure_answers_fixed_500(operation, expected, call, captured):
    with pytest.raises(HTTPException) as raised:
        asyncio.run(call())

    exc = raised.value
    assert exc.status_code == 500
    assert exc.detail == expected
    for leak in LEAKS:
        assert leak not in exc.detail, f"{leak!r} leaked into the 500 detail"
    # The driver error is not chained into the HTTPException either
    assert exc.__cause__ is None
    assert exc.__suppress_context__ is True

    # The error stays in the log for diagnosis, with the key value masked
    assert captured.lines, "expected the failure to be logged"
    for line in captured.lines:
        assert KEY_VALUE not in line, f"key value leaked into log line: {line}"
    entries = [json.loads(line) for line in captured.lines]
    error = next(e for e in entries if e["level"] == "ERROR")
    assert error["operation"] == operation
    assert error["exception"]["type"] == "IntegrityError"
    assert CONSTRAINT in error["exception"]["message"]
    assert f"Key (name)=({KEY_VALUE_PLACEHOLDER})" in error["exception"]["message"]


@pytest.mark.parametrize(
    ("router_module", "path", "method"),
    [
        (actions_router, "/actions/", "get"),
        (roles_router, f"/roles/{ROLE}/actions", "get"),
    ],
)
def test_database_failure_over_http_has_no_driver_message_in_body(
    router_module, path, method
):
    """The body FastAPI sends for the 500 carries only the fixed text."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.database import get_db
    from app.dependencies import get_current_user

    app = FastAPI()
    prefix = "/actions" if router_module is actions_router else "/roles"
    app.include_router(router_module.router, prefix=prefix)
    app.dependency_overrides[get_db] = lambda: MagicMock()
    app.dependency_overrides[get_current_user] = _user

    if router_module is actions_router:
        app.dependency_overrides[actions_router.get_action_service] = lambda: (
            _action_service("list_actions")
        )
        app.dependency_overrides[actions_router.get_cerbos_service] = _cerbos_allowing
        app.dependency_overrides[actions_router.get_user_service] = _user_service
        expected = "Failed to list actions"
    else:
        route = next(
            r
            for r in roles_router.router.routes
            if r.path == "/{role_name}/actions" and "GET" in r.methods
        )
        dependants = {d.name: d.call for d in route.dependant.dependencies}
        app.dependency_overrides[dependants["role_service"]] = lambda: _role_service(
            "list_role_actions"
        )
        app.dependency_overrides[dependants["cerbos_service"]] = _cerbos_allowing
        app.dependency_overrides[dependants["user_service"]] = _user_service
        app.dependency_overrides[dependants["_action_service"]] = lambda: MagicMock()
        expected = "Failed to retrieve role actions"

    response = getattr(TestClient(app), method)(path)

    assert response.status_code == 500
    assert response.json() == {"detail": expected}
    for leak in LEAKS:
        assert leak not in response.text
