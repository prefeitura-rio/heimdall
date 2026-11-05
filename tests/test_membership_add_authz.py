"""Tests for POST /groups/{name}/members ordering and errors (DEV-273).

The permission check must run before any write, and a missing group must be a
404 recorded in admin_audit instead of a 403 "Permission denied".
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

from app.models import AdminAudit, Base, Group, Membership, User
from app.routers.memberships import AddMemberRequest, add_member_to_group
from app.services.audit import AuditService
from app.services.base import BaseService
from app.services.membership import MembershipService

CALLER = "uuid-caller-sintetico"
TARGET = "00000000191"  # synthetic CPF-shaped subject, not a real person


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
    session.commit()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _membership_service(allowed: bool) -> MembershipService:
    with patch.object(MembershipService, "__init__", return_value=None):
        service = MembershipService()
    BaseService.__init__(service, "membership")
    service.cerbos_service = MagicMock()
    service.cerbos_service.check_permission.return_value = allowed
    service.cerbos_service.push_user_policy.return_value = True
    service.cache_service = MagicMock()
    with patch.object(AuditService, "__init__", return_value=None):
        service.audit_service = AuditService()
    BaseService.__init__(service.audit_service, "audit")
    return service


def _call(db, service, group_name="eng:backend", subject=TARGET):
    current_user = db.query(User).filter(User.subject == CALLER).one()
    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["some_role"]
    user_service.get_user_by_subject.side_effect = lambda s, subj: (
        s.query(User).filter(User.subject == subj).first()
    )
    with patch("app.services.policy_invalidator.invalidate_policy_version"):
        return asyncio.run(
            add_member_to_group(
                group_name=group_name,
                member_data=AddMemberRequest(subject=subject),
                current_user=current_user,
                db=db,
                membership_service=service,
                user_service=user_service,
            )
        )


def _target_rows(db) -> int:
    db.rollback()  # discard anything left only flushed, see what was committed
    return db.query(User).filter(User.subject == TARGET).count()


def _audits(db) -> list[AdminAudit]:
    return db.query(AdminAudit).filter(AdminAudit.operation == "add_member").all()


def test_denied_caller_gets_403_and_no_user_is_created(db):
    db.add(Group(name="eng:backend"))
    db.commit()
    service = _membership_service(allowed=False)

    with pytest.raises(HTTPException) as exc:
        _call(db, service)

    assert exc.value.status_code == 403
    assert _target_rows(db) == 0
    assert db.query(Membership).count() == 0
    service.cerbos_service.check_permission.assert_called_once()
    audits = _audits(db)
    assert len(audits) == 1
    assert audits[0].success is False
    assert audits[0].result == {"error": "Permission denied"}


def test_missing_group_gets_404_audited_and_no_user_is_created(db):
    service = _membership_service(allowed=True)

    with pytest.raises(HTTPException) as exc:
        _call(db, service, group_name="nao:existe")

    assert exc.value.status_code == 404
    assert "nao:existe" in exc.value.detail
    assert _target_rows(db) == 0
    audits = _audits(db)
    assert len(audits) == 1
    assert audits[0].success is False
    assert audits[0].target_id == f"group:nao:existe:member:{TARGET}"
    assert "not found" in audits[0].result["error"]
    service.cerbos_service.push_user_policy.assert_not_called()


def test_denied_caller_on_missing_group_still_gets_403(db):
    service = _membership_service(allowed=False)

    with pytest.raises(HTTPException) as exc:
        _call(db, service, group_name="nao:existe")

    assert exc.value.status_code == 403
    assert _target_rows(db) == 0


def test_allowed_caller_adds_new_user_to_existing_group(db):
    db.add(Group(name="eng:backend"))
    db.commit()
    service = _membership_service(allowed=True)

    response = _call(db, service)

    assert response.status == "member_added"
    assert response.group == "eng:backend"
    assert response.subject == TARGET
    assert _target_rows(db) == 1
    membership = db.query(Membership).one()
    assert membership.user.subject == TARGET
    assert membership.granter.subject == CALLER
    audits = _audits(db)
    assert len(audits) == 1
    assert audits[0].success is True
    service.cerbos_service.push_user_policy.assert_called_once()


def test_adding_existing_member_again_is_idempotent(db):
    db.add(Group(name="eng:backend"))
    db.commit()
    service = _membership_service(allowed=True)

    _call(db, service)
    response = _call(db, service)

    assert response.status == "member_added"
    assert _target_rows(db) == 1
    assert db.query(Membership).count() == 1
