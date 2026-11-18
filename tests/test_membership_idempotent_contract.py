"""The membership endpoints are idempotent and their OpenAPI says so (DEV-603).

Adding a user who is already a member, or removing one who is not, succeeds
(200 ``member_added`` / 204). The published contract must not promise a
400 "already a member" / "not a member" that the code never produces.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from sqlalchemy import JSON, create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import AdminAudit, Base, Group, Membership, User
from app.routers import memberships
from app.routers.memberships import remove_member_from_group
from app.services.audit import AuditService
from app.services.base import BaseService
from app.services.membership import MembershipService

CALLER = "uuid-caller-sintetico"
TARGET = "00000000191"  # synthetic CPF-shaped subject, not a real person
MEMBERS_PATH = "/groups/{group_name}/members"
MEMBER_PATH = "/groups/{group_name}/members/{subject}"


@compiles(JSONB, "sqlite")
def _jsonb_as_json(element, compiler, **kw):  # noqa: ARG001
    return compiler.visit_JSON(JSON(), **kw)


def _openapi() -> dict:
    app = FastAPI()
    app.include_router(memberships.router)
    return app.openapi()


@pytest.mark.parametrize(
    ("path", "method", "success"),
    [(MEMBERS_PATH, "post", "200"), (MEMBER_PATH, "delete", "204")],
)
def test_openapi_documents_idempotent_success_without_400(path, method, success):
    operation = _openapi()["paths"][path][method]

    assert "400" not in operation["responses"]
    assert "idempotent" in operation["responses"][success]["description"].lower()
    assert "**Idempotency**" in operation["description"]
    documented = repr(operation)
    assert "already a member of this group" not in documented
    assert "not a member of this group" not in documented


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
    session.add(User(subject=TARGET))
    session.add(Group(name="eng:backend"))
    session.commit()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _membership_service() -> MembershipService:
    with patch.object(MembershipService, "__init__", return_value=None):
        service = MembershipService()
    BaseService.__init__(service, "membership")
    service.cerbos_service = MagicMock()
    service.cerbos_service.check_permission.return_value = True
    service.cache_service = MagicMock()
    with patch.object(AuditService, "__init__", return_value=None):
        service.audit_service = AuditService()
    BaseService.__init__(service.audit_service, "audit")
    return service


def _remove(db, service):
    current_user = db.query(User).filter(User.subject == CALLER).one()
    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["some_role"]
    with patch("app.services.policy_invalidator.invalidate_policy_version"):
        return asyncio.run(
            remove_member_from_group(
                group_name="eng:backend",
                subject=TARGET,
                current_user=current_user,
                db=db,
                membership_service=service,
                user_service=user_service,
            )
        )


def test_removing_a_non_member_succeeds_without_changes(db):
    service = _membership_service()

    assert _remove(db, service) is None  # the route answers 204 No Content

    assert db.query(Membership).count() == 0
    service.cerbos_service.push_user_policy.assert_not_called()
    service.cerbos_service.delete_user_policy.assert_not_called()


def test_removing_the_same_member_twice_is_idempotent(db):
    group = db.query(Group).filter(Group.name == "eng:backend").one()
    target = db.query(User).filter(User.subject == TARGET).one()
    caller = db.query(User).filter(User.subject == CALLER).one()
    db.add(Membership(group_id=group.id, user_id=target.id, granted_by=caller.id))
    db.commit()
    service = _membership_service()

    assert _remove(db, service) is None
    assert _remove(db, service) is None

    assert db.query(Membership).count() == 0
    service.cerbos_service.delete_user_policy.assert_called_once_with(TARGET)
    removed = (
        db.query(AdminAudit)
        .filter(AdminAudit.operation == "remove_member", AdminAudit.success.is_(True))
        .count()
    )
    assert removed == 1
