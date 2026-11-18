"""The structured fields outside ``extra_fields`` never carry the CPF (DEV-636).

``StructuredLogger.log_operation`` passes ``operation``, ``actor_subject``,
``target``, ``request_id`` and ``user_id`` as loose keys of the stdlib
``logging`` ``extra=``, and ``log_http_request``/``log_cerbos_operation`` do the
same for the ``http``/``cerbos`` blocks. The ``StructuredFormatter`` masked the
message, the exception and ``extra_fields``, but copied these fields as they
were: every JWT-authenticated request logged "JWT authentication successful"
with the citizen's CPF in clear in ``actor_subject``. These tests capture what
the formatter writes and assert the (synthetic) CPF is absent while the field
and its non-personal values are still logged.
"""

import json
import logging
from unittest.mock import MagicMock, patch

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from app.dependencies import get_api_user, get_current_user
from app.logging_config import StructuredFormatter, get_structured_logger
from app.services.user import UserService
from app.tracing import CPF_PLACEHOLDER

CPF = "98765432100"  # synthetic
CPF_FORMATTED = "987.654.321-00"  # synthetic
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


def _entries(lines: list[str]) -> list[dict]:
    assert lines, "expected at least one log line"
    for line in lines:
        assert CPF not in line, f"CPF leaked into log line: {line}"
        assert CPF_FORMATTED not in line, f"CPF leaked into log line: {line}"
    return [json.loads(line) for line in lines]


@pytest.mark.parametrize("cpf", [CPF, CPF_FORMATTED])
def test_auth_event_masks_actor_subject(captured, cpf):
    get_structured_logger("tests.structured").log_auth_event(
        message="JWT authentication successful",
        event_type="jwt_auth_success",
        actor_subject=cpf,
        success=True,
    )

    (entry,) = _entries(captured.lines)
    assert entry["actor_subject"] == CPF_PLACEHOLDER
    assert entry["operation"] == "authentication"
    assert entry["auth_event_type"] == "jwt_auth_success"
    assert entry["auth_success"] is True


def test_log_operation_masks_every_loose_field(captured):
    get_structured_logger("tests.structured").log_operation(
        level=logging.INFO,
        message="Member added",
        operation=f"add_member:{CPF}",
        actor_subject=CPF_FORMATTED,
        target=f"group:prefeitura/members/{CPF}",
        request_id=f"req-{CPF}",
        user_id=42,
        extra_fields={"subject": CPF},
    )

    (entry,) = _entries(captured.lines)
    assert entry["operation"] == f"add_member:{CPF_PLACEHOLDER}"
    assert entry["actor_subject"] == CPF_PLACEHOLDER
    assert entry["target"] == f"group:prefeitura/members/{CPF_PLACEHOLDER}"
    assert entry["request_id"] == f"req-{CPF_PLACEHOLDER}"
    assert entry["user_id"] == 42
    assert entry["subject"] == CPF_PLACEHOLDER


def test_log_operation_keeps_service_principals_and_plain_values(captured):
    get_structured_logger("tests.structured").log_operation(
        level=logging.INFO,
        message="Static API token authentication successful",
        operation="authentication",
        actor_subject="system:api_client",
        target="mapping:7",
        request_id="0f6c2a9e-1b2d-4c3e-8f4a-5b6c7d8e9f00",
        user_id=12345678901,
    )

    (entry,) = _entries(captured.lines)
    assert entry["actor_subject"] == "system:api_client"
    assert entry["operation"] == "authentication"
    assert entry["target"] == "mapping:7"
    assert entry["request_id"] == "0f6c2a9e-1b2d-4c3e-8f4a-5b6c7d8e9f00"
    # A non-string value is not CPF-shaped text and stays as it is.
    assert entry["user_id"] == 12345678901


def test_raw_record_attribute_is_masked(captured):
    """A plain ``logger.info(..., extra={"actor_subject": ...})`` is masked too."""
    logging.getLogger("tests.structured").info(
        "raw extra", extra={"actor_subject": CPF, "target": CPF_FORMATTED}
    )

    (entry,) = _entries(captured.lines)
    assert entry["actor_subject"] == CPF_PLACEHOLDER
    assert entry["target"] == CPF_PLACEHOLDER


def test_http_request_fields_are_masked(captured):
    get_structured_logger("tests.structured").log_http_request(
        message="GET /api/v1/users/{subject} -> 200",
        method="GET",
        path=f"/api/v1/users/{CPF}",
        status_code=200,
        duration_ms=1.5,
        user_agent=f"client/{CPF_FORMATTED}",
        actor_subject=CPF,
    )

    (entry,) = _entries(captured.lines)
    assert entry["actor_subject"] == CPF_PLACEHOLDER
    assert entry["http"] == {
        "method": "GET",
        "path": f"/api/v1/users/{CPF_PLACEHOLDER}",
        "status_code": 200,
        "duration_ms": 1.5,
        "user_agent": f"client/{CPF_PLACEHOLDER}",
    }


def test_cerbos_fields_are_masked(captured):
    get_structured_logger("tests.structured").log_cerbos_operation(
        message="Cerbos check",
        operation="check",
        response_status=200,
        duration_ms=2.0,
        action=f"read:{CPF}",
        resource_type="group",
    )

    (entry,) = _entries(captured.lines)
    assert entry["cerbos"] == {
        "operation": "check",
        "response_status": 200,
        "duration_ms": 2.0,
        "action": f"read:{CPF_PLACEHOLDER}",
        "resource_type": "group",
    }


@pytest.fixture
def service():
    with patch("app.services.user.CacheService"):
        svc = UserService()
    svc.keycloak_client_id = CLIENT_ID
    svc.admin_role_name = ADMIN_ROLE
    return svc


def _db() -> MagicMock:
    user = MagicMock()
    user.id = 42
    user.subject = CPF
    user.display_name = "Fulana de Tal"
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = user
    db.query.return_value.join.return_value.filter.return_value.first.return_value = (
        None
    )
    return db


@pytest.mark.parametrize("dependency", [get_current_user, get_api_user])
def test_jwt_authentication_success_does_not_log_cpf(dependency, service, captured):
    """The staging leak: "JWT authentication successful" on every request."""
    auth_service = MagicMock()
    auth_service.authenticate_request.return_value = {
        "type": "jwt",
        "subject": CPF,
        "name": "Fulana de Tal",
        "resource_access": {CLIENT_ID: {"roles": ["viewer"]}},
    }
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="t")

    with patch.object(service, "get_user_roles", return_value=[]):
        dependency(credentials, _db(), auth_service, service)

    entries = _entries(captured.lines)
    success = next(e for e in entries if e.get("auth_success") is True)
    assert success["actor_subject"] == CPF_PLACEHOLDER
    assert success["operation"] == "authentication"
