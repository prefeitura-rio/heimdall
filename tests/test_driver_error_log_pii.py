"""Database driver messages never bring the citizen's CPF into the logs (DEV-554).

With ``hide_parameters=True`` SQLAlchemy stops appending the bound parameters,
but the PostgreSQL message itself still quotes the key value of a violated
constraint (``DETAIL:  Key (subject)=(<CPF>) already exists.``), and it reaches
the logs through ``str(e)`` and ``exc_info`` tracebacks. These tests raise a
real ``sqlalchemy.exc.IntegrityError`` wrapping a ``psycopg2`` unique violation
with a synthetic CPF and assert that what the ``StructuredFormatter`` writes
keeps the error type and the constraint for diagnosis, but neither the CPF nor
the key value.
"""

import json
import logging
from unittest.mock import MagicMock, patch

import psycopg2.errors
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.exc import IntegrityError

from app.dependencies import get_api_user, get_current_user
from app.logging_config import (
    KEY_VALUE_PLACEHOLDER,
    StructuredFormatter,
    get_structured_logger,
    redact_log_value,
)
from app.services.user import UserService

CPF = "98765432100"  # synthetic
CPF_FORMATTED = "987.654.321-00"  # synthetic
CONSTRAINT = "users_subject_key"
CLIENT_ID = "heimdall-admin"
ADMIN_ROLE = "heimdall-admin"


def _unique_violation(value: str = CPF, column: str = "subject") -> IntegrityError:
    """The error SQLAlchemy raises on a duplicate ``users.subject`` insert."""
    orig = psycopg2.errors.UniqueViolation(
        f'duplicate key value violates unique constraint "{CONSTRAINT}"\n'
        f"DETAIL:  Key ({column})=({value}) already exists.\n"
    )
    return IntegrityError(
        "INSERT INTO users (subject, display_name) VALUES (%(subject)s, %(display_name)s)",
        {"subject": value, "display_name": "Fulana de Tal"},
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
    targets = [logging.getLogger(name) for name in ("app", "tests")]
    previous = [target.level for target in targets]
    for target in targets:
        target.addHandler(handler)
        target.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        for target, level in zip(targets, previous, strict=True):
            target.removeHandler(handler)
            target.setLevel(level)


def _assert_no_personal_data(lines: list[str]) -> list[dict]:
    assert lines, "expected the flow to emit at least one log line"
    entries = []
    for line in lines:
        assert CPF not in line, f"CPF leaked into log line: {line}"
        assert CPF_FORMATTED not in line, f"CPF leaked into log line: {line}"
        entries.append(json.loads(line))
    return entries


def _payload(admin: bool) -> dict:
    roles = [ADMIN_ROLE] if admin else ["viewer"]
    return {
        "subject": CPF,
        "name": "Fulana de Tal",
        "resource_access": {CLIENT_ID: {"roles": roles}},
    }


@pytest.fixture
def service():
    with patch("app.services.user.CacheService"):
        svc = UserService()
    svc.keycloak_client_id = CLIENT_ID
    svc.admin_role_name = ADMIN_ROLE
    return svc


def _existing_user() -> MagicMock:
    user = MagicMock()
    user.id = 42
    user.subject = CPF
    user.display_name = "Fulana de Tal"
    return user


def _db(existing_user, superadmin_link) -> MagicMock:
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = existing_user
    db.query.return_value.join.return_value.filter.return_value.first.return_value = (
        superadmin_link
    )
    db.is_modified.return_value = True
    return db


def test_driver_message_carries_the_cpf_before_redaction():
    """Guard for the fixture: the raw error really quotes the CPF."""
    assert CPF in str(_unique_violation())


def test_superadmin_assignment_integrity_error_does_not_log_cpf(service, captured):
    user = _existing_user()
    db = _db(existing_user=user, superadmin_link=None)
    db.commit.side_effect = _unique_violation()

    assert service.get_or_create_user(db, _payload(admin=True)) is user

    entries = _assert_no_personal_data(captured.lines)
    error = next(e for e in entries if e["level"] == "ERROR")
    assert error["exception"]["type"] == "IntegrityError"
    assert f"Key (subject)=({KEY_VALUE_PLACEHOLDER})" in error["exception"]["message"]
    assert "Traceback" in error["exception"]["traceback"]
    assert CONSTRAINT in error["exception"]["traceback"]


def test_superadmin_removal_integrity_error_does_not_log_cpf(service, captured):
    user = _existing_user()
    db = _db(existing_user=user, superadmin_link=MagicMock())
    db.commit.side_effect = _unique_violation()

    assert service.get_or_create_user(db, _payload(admin=False)) is user

    entries = _assert_no_personal_data(captured.lines)
    error = next(e for e in entries if e["level"] == "ERROR")
    assert error["exception"]["type"] == "IntegrityError"
    assert f"Key (subject)=({KEY_VALUE_PLACEHOLDER})" in error["exception"]["message"]


def _jwt_auth() -> tuple[MagicMock, HTTPAuthorizationCredentials]:
    auth_service = MagicMock()
    auth_service.authenticate_request.return_value = {"type": "jwt", **_payload(False)}
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="t")
    return auth_service, credentials


@pytest.mark.parametrize("dependency", [get_current_user, get_api_user])
def test_first_login_race_does_not_log_cpf_in_auth_error(dependency, service, captured):
    """Two concurrent first logins: the loser's insert hits ``users_subject_key``."""
    db = _db(existing_user=None, superadmin_link=None)
    db.commit.side_effect = _unique_violation()
    auth_service, credentials = _jwt_auth()

    with pytest.raises(HTTPException) as raised:
        dependency(credentials, db, auth_service, service)

    assert raised.value.status_code == 500
    entries = [json.loads(line) for line in captured.lines]
    failed = next(e for e in entries if e.get("auth_success") is False)
    assert CPF not in failed["auth_error"]
    assert CONSTRAINT in failed["auth_error"]
    assert f"Key (subject)=({KEY_VALUE_PLACEHOLDER})" in failed["auth_error"]
    assert CPF not in failed["message"]


def test_cpf_in_log_message_and_args_is_masked(captured):
    logger = logging.getLogger("tests.driver_error")
    logger.error("insert failed: %s", _unique_violation())

    entry = _assert_no_personal_data(captured.lines)[0]
    assert f"Key (subject)=({KEY_VALUE_PLACEHOLDER})" in entry["message"]


def test_exc_info_traceback_is_masked(captured):
    logger = get_structured_logger("tests.driver_error")
    try:
        raise _unique_violation(value=CPF_FORMATTED)
    except IntegrityError:
        logger.logger.exception("unexpected database error")

    entry = _assert_no_personal_data(captured.lines)[0]
    assert entry["exception"]["type"] == "IntegrityError"
    assert CONSTRAINT in entry["exception"]["traceback"]


def test_nested_extra_fields_are_masked(captured):
    logger = get_structured_logger("tests.driver_error")
    logger.log_operation(
        level=logging.ERROR,
        message="sync failed",
        operation="sync",
        user_id=42,
        extra_fields={
            "error": str(_unique_violation()),
            "details": [{"cause": f"subject {CPF_FORMATTED}"}],
            "attempt": 3,
        },
    )

    entry = _assert_no_personal_data(captured.lines)[0]
    assert entry["attempt"] == 3
    assert entry["user_id"] == 42
    assert entry["operation"] == "sync"


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "DETAIL:  Key (subject)=(98765432100) already exists.",
            f"DETAIL:  Key (subject)=({KEY_VALUE_PLACEHOLDER}) already exists.",
        ),
        (
            "DETAIL:  Key (group_id, user_id)=(7, 42) already exists.",
            f"DETAIL:  Key (group_id, user_id)=({KEY_VALUE_PLACEHOLDER}) already exists.",
        ),
        (
            'DETAIL:  Key (granted_by)=(5) is not present in table "users".',
            f'DETAIL:  Key (granted_by)=({KEY_VALUE_PLACEHOLDER}) is not present in table "users".',
        ),
        (
            "DETAIL:  Key (name)=(grupo (antigo)) already exists.",
            f"DETAIL:  Key (name)=({KEY_VALUE_PLACEHOLDER}) already exists.",
        ),
        (
            "DETAIL:  Key (subject)=(abc)",
            f"DETAIL:  Key (subject)=({KEY_VALUE_PLACEHOLDER})",
        ),
        ("no key value here", "no key value here"),
    ],
)
def test_redact_log_value_hides_postgres_key_values(message, expected):
    assert redact_log_value(message) == expected


def test_redact_log_value_keeps_non_string_values():
    assert redact_log_value(42) == 42
    assert redact_log_value(None) is None
    assert redact_log_value(True) is True
    assert redact_log_value({"cpf": CPF, "n": 1.5}) == {"cpf": "[cpf]", "n": 1.5}
