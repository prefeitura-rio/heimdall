"""500 responses never carry the database error to the client (DEV-560).

A failure in ``get_or_create_user`` on a first login (two concurrent requests of
the same new user hit ``users_subject_key``) used to answer 500 with
``detail=f"User creation failed: {str(e)}"``: the driver type, the constraint,
the INSERT and ``DETAIL: Key (subject)=(<CPF>) already exists.``. The same
happened in ``GET /users/`` and ``GET /users/me``. The response now carries a
fixed message and the error stays only in the masked log (DEV-554). Synthetic
CPF only.
"""

import asyncio
import json
import logging
from unittest.mock import MagicMock, patch

import psycopg2.errors
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.exc import IntegrityError

from app.dependencies import (
    USER_AUTHENTICATION_FAILED_DETAIL,
    USER_CREATION_FAILED_DETAIL,
    get_api_user,
    get_current_user,
)
from app.logging_config import KEY_VALUE_PLACEHOLDER, StructuredFormatter
from app.routers.users import (
    LIST_USERS_FAILED_DETAIL,
    USER_INFO_FAILED_DETAIL,
    get_current_user_info,
    list_users,
)
from app.services.user import UserService

CPF = "98765432100"  # synthetic
CONSTRAINT = "users_subject_key"
CLIENT_ID = "heimdall-admin"
ADMIN_ROLE = "heimdall-admin"

# Anything from the driver message that must never reach the response body
LEAKS = (CPF, CONSTRAINT, "INSERT", "psycopg2", "IntegrityError", "DETAIL", "Key (")


def _unique_violation() -> IntegrityError:
    """The error SQLAlchemy raises on a duplicate ``users.subject`` insert."""
    orig = psycopg2.errors.UniqueViolation(
        f'duplicate key value violates unique constraint "{CONSTRAINT}"\n'
        f"DETAIL:  Key (subject)=({CPF}) already exists.\n"
    )
    return IntegrityError(
        "INSERT INTO users (subject, display_name) VALUES (%(subject)s, %(display_name)s)",
        {"subject": CPF, "display_name": "Fulana de Tal"},
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


def _assert_generic(exc: HTTPException, expected: str) -> None:
    assert exc.status_code == 500
    assert exc.detail == expected
    for leak in LEAKS:
        assert leak not in exc.detail, f"{leak!r} leaked into the 500 detail"
    # The driver error is not chained into the HTTPException either
    assert exc.__cause__ is None
    assert exc.__suppress_context__ is True


def _assert_masked_log(lines: list[str]) -> dict:
    """The error stays in the log for diagnosis, without the CPF."""
    assert lines, "expected the failure to be logged"
    for line in lines:
        assert CPF not in line, f"CPF leaked into log line: {line}"
    entries = [json.loads(line) for line in lines]
    return next(e for e in entries if e["level"] == "ERROR")


def test_driver_message_carries_the_leaks_before_the_fix():
    """Guard for the fixture: the raw error really quotes CPF, SQL and constraint."""
    raw = str(_unique_violation())
    for leak in (CPF, CONSTRAINT, "INSERT", "psycopg2", "DETAIL"):
        assert leak in raw


# Authentication dependencies (first-login race) -----------------------------


@pytest.fixture
def service():
    with patch("app.services.user.CacheService"):
        svc = UserService()
    svc.keycloak_client_id = CLIENT_ID
    svc.admin_role_name = ADMIN_ROLE
    return svc


def _first_login_race_db() -> MagicMock:
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.query.return_value.join.return_value.filter.return_value.first.return_value = None
    db.commit.side_effect = _unique_violation()
    return db


def _jwt_auth() -> tuple[MagicMock, HTTPAuthorizationCredentials]:
    auth_service = MagicMock()
    auth_service.authenticate_request.return_value = {
        "type": "jwt",
        "subject": CPF,
        "name": "Fulana de Tal",
        "resource_access": {CLIENT_ID: {"roles": ["viewer"]}},
    }
    return auth_service, HTTPAuthorizationCredentials(scheme="Bearer", credentials="t")


@pytest.mark.parametrize(
    ("dependency", "expected"),
    [
        (get_current_user, USER_CREATION_FAILED_DETAIL),
        (get_api_user, USER_AUTHENTICATION_FAILED_DETAIL),
    ],
)
def test_first_login_race_answers_generic_500(dependency, expected, service, captured):
    auth_service, credentials = _jwt_auth()

    with pytest.raises(HTTPException) as raised:
        dependency(credentials, _first_login_race_db(), auth_service, service)

    _assert_generic(raised.value, expected)
    entries = [json.loads(line) for line in captured.lines]
    failed = next(e for e in entries if e.get("auth_success") is False)
    assert CPF not in failed["auth_error"]
    assert CONSTRAINT in failed["auth_error"]
    assert f"Key (subject)=({KEY_VALUE_PLACEHOLDER})" in failed["auth_error"]


def test_first_login_race_over_http_has_no_driver_message_in_body(service):
    """The body FastAPI sends for the dependency's 500 carries only the fixed text."""
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from app.database import get_db
    from app.dependencies import get_auth_service, get_user_service

    app = FastAPI()

    @app.get("/probe")
    def probe(user=Depends(get_current_user)):  # noqa: B008
        return {"id": user.id}

    auth_service, _ = _jwt_auth()
    app.dependency_overrides[get_db] = _first_login_race_db
    app.dependency_overrides[get_auth_service] = lambda: auth_service
    app.dependency_overrides[get_user_service] = lambda: service

    response = TestClient(app).get("/probe", headers={"Authorization": "Bearer t"})

    assert response.status_code == 500
    assert response.json() == {"detail": USER_CREATION_FAILED_DETAIL}
    for leak in LEAKS:
        assert leak not in response.text


# Users router ---------------------------------------------------------------


def _user() -> MagicMock:
    user = MagicMock()
    user.subject = "11111111111"  # synthetic
    user.id = 7
    return user


def _cerbos_allowing() -> MagicMock:
    cerbos = MagicMock()
    cerbos.check_permission.return_value = True
    return cerbos


def test_list_users_db_failure_answers_generic_500(captured):
    db = MagicMock()
    db.query.return_value.count.side_effect = _unique_violation()
    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["superadmin"]

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            list_users(
                current_user=_user(),
                db=db,
                user_service=user_service,
                cerbos_service=_cerbos_allowing(),
                skip=0,
                limit=50,
                has_groups=False,
            )
        )

    _assert_generic(raised.value, LIST_USERS_FAILED_DETAIL)
    error = _assert_masked_log(captured.lines)
    assert error["operation"] == "list_users"
    assert error["exception"]["type"] == "IntegrityError"
    assert CONSTRAINT in error["exception"]["message"]
    assert f"Key (subject)=({KEY_VALUE_PLACEHOLDER})" in error["exception"]["message"]


def test_users_me_db_failure_answers_generic_500(captured):
    db = MagicMock()
    db.refresh.side_effect = _unique_violation()

    with pytest.raises(HTTPException) as raised:
        asyncio.run(
            get_current_user_info(
                current_user=_user(), db=db, user_service=MagicMock()
            )
        )

    _assert_generic(raised.value, USER_INFO_FAILED_DETAIL)
    error = _assert_masked_log(captured.lines)
    assert error["operation"] == "get_current_user_info"
    assert error["exception"]["type"] == "IntegrityError"
    assert CONSTRAINT in error["exception"]["traceback"]
