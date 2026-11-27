"""The citizen's CPF (JWT ``subject``) never reaches the logs of UserService (DEV-486).

``get_or_create_user`` runs on every JWT-authenticated request, so any log line it
emits is multiplied by the request volume. These tests capture what the
``StructuredFormatter`` would write to stdout for each branch of the user/admin
role flow and assert the (synthetic) CPF is absent.
"""

import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from app.logging_config import StructuredFormatter
from app.services.user import UserService

CPF = "98765432100"  # synthetic
CLIENT_ID = "heimdall-admin"
ADMIN_ROLE = "heimdall-admin"


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
    target = logging.getLogger("app.services.user")
    previous_level = target.level
    target.addHandler(handler)
    target.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        target.removeHandler(handler)
        target.setLevel(previous_level)


@pytest.fixture
def service():
    with patch("app.services.user.CacheService"):
        svc = UserService()
    svc.keycloak_client_id = CLIENT_ID
    svc.admin_role_name = ADMIN_ROLE
    return svc


def _payload(admin: bool, name: str = "Fulana de Tal") -> dict:
    roles = [ADMIN_ROLE] if admin else ["viewer"]
    return {
        "subject": CPF,
        "name": name,
        "resource_access": {CLIENT_ID: {"roles": roles}},
    }


def _existing_user(display_name: str = "Fulana de Tal") -> MagicMock:
    user = MagicMock()
    user.id = 42
    user.subject = CPF
    user.display_name = display_name
    return user


def _db(existing_user, superadmin_link) -> MagicMock:
    """Session mock: ``query().filter().first()`` answers the user (and Role)
    lookup, ``query().join().filter().first()`` the superadmin UserRole lookup."""
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = existing_user
    db.query.return_value.join.return_value.filter.return_value.first.return_value = (
        superadmin_link
    )
    db.is_modified.return_value = True
    return db


def _assert_no_cpf(lines: list[str]) -> None:
    assert lines, "expected the flow to emit at least one log line"
    for line in lines:
        assert CPF not in line, f"CPF leaked into log line: {line}"
        json.loads(line)  # still valid structured JSON


def test_has_admin_role_does_not_log_cpf_when_admin(service, captured):
    assert service._has_admin_role(_payload(admin=True)) is True
    _assert_no_cpf(captured.lines)


def test_has_admin_role_does_not_log_cpf_when_not_admin(service, captured):
    assert service._has_admin_role(_payload(admin=False)) is False
    _assert_no_cpf(captured.lines)


def test_existing_non_admin_with_superadmin_removed_and_name_change(service, captured):
    user = _existing_user(display_name="Nome Antigo")
    db = _db(existing_user=user, superadmin_link=MagicMock())

    assert service.get_or_create_user(db, _payload(admin=False)) is user

    db.delete.assert_called_once()
    _assert_no_cpf(captured.lines)


def test_existing_non_admin_without_superadmin(service, captured):
    user = _existing_user(display_name="Nome Antigo")
    db = _db(existing_user=user, superadmin_link=None)

    assert service.get_or_create_user(db, _payload(admin=False)) is user

    db.delete.assert_not_called()
    _assert_no_cpf(captured.lines)


def test_existing_admin_already_superadmin(service, captured):
    user = _existing_user(display_name="Nome Antigo")
    db = _db(existing_user=user, superadmin_link=MagicMock())

    assert service.get_or_create_user(db, _payload(admin=True)) is user

    _assert_no_cpf(captured.lines)


def test_new_admin_user_gets_superadmin(service, captured):
    db = _db(existing_user=None, superadmin_link=None)

    user = service.get_or_create_user(db, _payload(admin=True))

    assert user.subject == CPF
    _assert_no_cpf(captured.lines)


def test_superadmin_assignment_failure_does_not_log_cpf(service, captured):
    user = _existing_user()
    db = _db(existing_user=user, superadmin_link=None)
    db.add.side_effect = RuntimeError("db unavailable")

    assert service.get_or_create_user(db, _payload(admin=True)) is user

    db.rollback.assert_called()
    _assert_no_cpf(captured.lines)
    assert any('"level": "ERROR"' in line for line in captured.lines)


def test_superadmin_removal_failure_does_not_log_cpf(service, captured):
    user = _existing_user()
    db = _db(existing_user=user, superadmin_link=MagicMock())
    db.delete.side_effect = RuntimeError("db unavailable")

    assert service.get_or_create_user(db, _payload(admin=False)) is user

    db.rollback.assert_called()
    _assert_no_cpf(captured.lines)
    assert any('"level": "ERROR"' in line for line in captured.lines)
