"""Role action routes find the role by name, not in the first page of roles (DEV-618).

GET/POST /roles/{name}/actions and DELETE /roles/{name}/actions/{action} used to
check "does the role exist?" against ``list_roles(db)``, which returns only the
first 50 roles in alphabetical order. A role past that page got a false 404.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy import JSON, create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Action, Base, Role, RoleAction, User
from app.routers.roles import (
    RoleActionRequest,
    assign_action_to_role,
    list_role_actions,
    remove_action_from_role,
)
from app.services.action import ActionService
from app.services.audit import AuditService
from app.services.base import BaseService
from app.services.role import RoleService

CALLER = "uuid-caller-sintetico"
# 60 roles: "role:00" .. "role:59". list_roles() pages 50 by name, so
# "role:55" is outside the first page.
ROLE_COUNT = 60
LATE_ROLE = "role:55"
ACTION = "report:read"


@compiles(JSONB, "sqlite")
def _jsonb_as_json(element, compiler, **kw):  # noqa: ARG001
    return compiler.visit_JSON(JSON(), **kw)


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(User(subject=CALLER))
    session.add_all(Role(name=f"role:{i:02d}") for i in range(ROLE_COUNT))
    session.add(Action(name=ACTION))
    session.commit()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _audit_service() -> AuditService:
    with patch.object(AuditService, "__init__", return_value=None):
        service = AuditService()
    BaseService.__init__(service, "audit")
    return service


def _role_service() -> RoleService:
    with patch.object(RoleService, "__init__", return_value=None):
        service = RoleService()
    BaseService.__init__(service, "role")
    service.cerbos_service = MagicMock()
    service.cache_service = MagicMock()
    service.audit_service = _audit_service()
    return service


def _action_service() -> ActionService:
    with patch.object(ActionService, "__init__", return_value=None):
        service = ActionService()
    BaseService.__init__(service, "action")
    service.audit_service = _audit_service()
    return service


def _deps(db, allowed=True):
    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["some_role"]
    cerbos_service = MagicMock()
    cerbos_service.check_permission.return_value = allowed
    return {
        "current_user": db.query(User).filter(User.subject == CALLER).one(),
        "db": db,
        "role_service": _role_service(),
        "cerbos_service": cerbos_service,
        "user_service": user_service,
    }


def _run(coro):
    with (
        patch("app.services.policy_invalidator.invalidate_policy_version"),
        patch("app.common.authz.AuditService"),
    ):
        return asyncio.run(coro)


def _role_actions(db, role_name):
    return (
        db.query(Action.name)
        .join(RoleAction)
        .join(Role)
        .filter(Role.name == role_name)
        .all()
    )


def test_late_role_is_outside_the_first_page_of_list_roles(db):
    roles, total = _role_service().list_roles(db)

    assert total == ROLE_COUNT
    assert len(roles) == 50
    assert LATE_ROLE not in {role.name for role in roles}


def test_list_actions_of_role_past_first_page(db):
    role = db.query(Role).filter(Role.name == LATE_ROLE).one()
    action = db.query(Action).filter(Action.name == ACTION).one()
    db.add(RoleAction(role_id=role.id, action_id=action.id))
    db.commit()

    result = _run(
        list_role_actions(
            role_name=LATE_ROLE, _action_service=_action_service(), **_deps(db)
        )
    )

    assert [a.name for a in result] == [ACTION]


def test_assign_action_to_role_past_first_page(db):
    result = _run(
        assign_action_to_role(
            role_name=LATE_ROLE,
            action_data=RoleActionRequest(action_name=ACTION),
            action_service=_action_service(),
            **_deps(db),
        )
    )

    assert result.status == "action_assigned"
    assert result.role == LATE_ROLE
    assert _role_actions(db, LATE_ROLE) == [(ACTION,)]


def test_remove_action_from_role_past_first_page(db):
    role = db.query(Role).filter(Role.name == LATE_ROLE).one()
    action = db.query(Action).filter(Action.name == ACTION).one()
    db.add(RoleAction(role_id=role.id, action_id=action.id))
    db.commit()

    _run(
        remove_action_from_role(
            role_name=LATE_ROLE,
            action_name=ACTION,
            action_service=_action_service(),
            **_deps(db),
        )
    )

    assert _role_actions(db, LATE_ROLE) == []


def _call_route(route, db, role_name, allowed=True):
    deps = _deps(db, allowed=allowed)
    if route == "list":
        coro = list_role_actions(
            role_name=role_name, _action_service=_action_service(), **deps
        )
    elif route == "assign":
        coro = assign_action_to_role(
            role_name=role_name,
            action_data=RoleActionRequest(action_name=ACTION),
            action_service=_action_service(),
            **deps,
        )
    else:
        coro = remove_action_from_role(
            role_name=role_name,
            action_name=ACTION,
            action_service=_action_service(),
            **deps,
        )
    with pytest.raises(HTTPException) as exc_info:
        _run(coro)
    return exc_info.value, deps["role_service"]


ROUTES = ["list", "assign", "remove"]


@pytest.mark.parametrize("route", ROUTES)
def test_missing_role_is_still_404(db, route):
    exc, _ = _call_route(route, db, "ghost:role")

    assert exc.status_code == 404
    assert exc.detail == "Role 'ghost:role' not found"
    assert db.query(RoleAction).count() == 0


@pytest.mark.parametrize("route", ROUTES)
def test_denied_caller_gets_403_before_role_lookup(db, route):
    with patch.object(RoleService, "get_role_by_name") as lookup:
        exc, _ = _call_route(route, db, LATE_ROLE, allowed=False)

    assert exc.status_code == 403
    lookup.assert_not_called()
    assert db.query(RoleAction).count() == 0
