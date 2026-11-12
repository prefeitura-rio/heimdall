"""The citizen's CPF never reaches the request and exception logs (DEV-542).

The HTTP logging middleware and the global exception handlers of ``app.main``
used to write the raw request path/URL (``/api/v1/users/<cpf>``,
``/api/v1/groups/<group>/members/<subject>``) and the exception detail
(``User with CPF '<cpf>' not found``) to the structured logs. These tests drive
the real app through a ``TestClient``, capture what the ``StructuredFormatter``
writes for the ``app.main`` logger, and assert the (synthetic) CPF is absent
while method, status, duration and the route template are still logged.
"""

import importlib
import json
import logging
import sys
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.exceptions import CerbosUnavailableError
from app.logging_config import StructuredFormatter
from app.settings import settings
from app.tracing import CPF_PLACEHOLDER

CPF = "98765432100"  # synthetic
CPF_FORMATTED = "987.654.321-00"


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.setFormatter(StructuredFormatter())
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))

    def entries(self) -> list[dict]:
        return [json.loads(line) for line in self.lines]


class _Body(BaseModel):
    count: int
    subject: str | None = None


@pytest.fixture(scope="module")
def main():
    """A fresh app.main (no lifespan, no I/O) with probe routes for each handler."""
    sys.modules.pop("app.main", None)
    with patch.object(settings, "validate"):
        module = importlib.import_module("app.main")
    sys.modules.pop("app.main", None)

    app = module.app

    @app.get("/__test_dev_542/http/{cpf}")
    async def _http(cpf: str):
        raise HTTPException(status_code=404, detail=f"User with CPF '{cpf}' not found")

    @app.post("/__test_dev_542/validation/{cpf}")
    async def _validation(cpf: str, body: _Body):
        return {"cpf_length": len(cpf), "count": body.count}

    @app.get("/__test_dev_542/cerbos/{cpf}")
    async def _cerbos(cpf: str):
        raise CerbosUnavailableError(RuntimeError(f"check failed for {cpf}"))

    @app.get("/__test_dev_542/boom/{cpf}")
    async def _boom(cpf: str):
        raise RuntimeError(f"lookup failed for principal {cpf}")

    return module


@pytest.fixture
def client(main):
    return TestClient(main.app, raise_server_exceptions=False)


@pytest.fixture
def captured():
    handler = _Capture()
    target = logging.getLogger("app.main")
    previous_level = target.level
    target.addHandler(handler)
    target.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        target.removeHandler(handler)
        target.setLevel(previous_level)


def _assert_no_cpf(captured: _Capture) -> None:
    assert captured.lines, "expected the request to be logged"
    for line in captured.lines:
        assert CPF not in line, f"CPF leaked into a log line: {line}"
        assert CPF_FORMATTED not in line, f"CPF leaked into a log line: {line}"


def _request_entry(captured: _Capture) -> dict:
    entries = [entry for entry in captured.entries() if "http" in entry]
    assert len(entries) == 1, captured.lines
    return entries[0]


def _exception_entry(captured: _Capture, operation: str) -> dict:
    entries = [e for e in captured.entries() if e.get("operation") == operation]
    assert len(entries) == 1, captured.lines
    return entries[0]


def test_user_by_cpf_logs_the_route_template_not_the_cpf(client, captured):
    response = client.get(f"/api/v1/users/{CPF}")

    assert response.status_code in (401, 403)
    _assert_no_cpf(captured)
    entry = _request_entry(captured)
    assert entry["http"]["path"] == "/api/v1/users/{cpf}"
    assert entry["http"]["method"] == "GET"
    assert entry["http"]["status_code"] == response.status_code
    assert isinstance(entry["http"]["duration_ms"], float)
    assert entry["message"] == f"GET /api/v1/users/{{cpf}} -> {response.status_code}"

    exception = _exception_entry(captured, "http_exception")
    assert exception["route"] == "/api/v1/users/{cpf}"
    assert CPF_PLACEHOLDER in exception["url"]


def test_member_removal_logs_the_route_template_not_the_subject(client, captured):
    response = client.delete(f"/api/v1/groups/time:backend/members/{CPF}")

    assert response.status_code in (401, 403)
    _assert_no_cpf(captured)
    entry = _request_entry(captured)
    assert entry["http"]["path"] == "/api/v1/groups/{group_name}/members/{subject}"
    assert entry["http"]["method"] == "DELETE"
    assert entry["http"]["status_code"] == response.status_code


def test_unmatched_path_is_logged_with_the_cpf_masked(client, captured):
    response = client.get(f"/api/v1/nao-existe/{CPF_FORMATTED}?cpf={CPF}")

    assert response.status_code == 404
    _assert_no_cpf(captured)
    entry = _request_entry(captured)
    assert entry["http"]["path"] == f"/api/v1/nao-existe/{CPF_PLACEHOLDER}"
    assert entry["http"]["status_code"] == 404


def test_http_exception_detail_and_url_are_masked(client, captured):
    response = client.get(f"/__test_dev_542/http/{CPF}?q={CPF}")

    assert response.status_code == 404
    _assert_no_cpf(captured)
    fields = _exception_entry(captured, "http_exception")
    assert fields["status_code"] == 404
    assert fields["method"] == "GET"
    assert fields["detail"] == f"User with CPF '{CPF_PLACEHOLDER}' not found"
    assert fields["route"] == "/__test_dev_542/http/{cpf}"
    assert fields["url"].endswith(
        f"/__test_dev_542/http/{CPF_PLACEHOLDER}?q={CPF_PLACEHOLDER}"
    )
    assert _request_entry(captured)["http"]["path"] == "/__test_dev_542/http/{cpf}"


def test_validation_error_input_and_url_are_masked(client, captured):
    response = client.post(
        f"/__test_dev_542/validation/{CPF}", json={"count": CPF_FORMATTED}
    )

    assert response.status_code == 422
    _assert_no_cpf(captured)
    fields = _exception_entry(captured, "validation_exception")
    assert fields["route"] == "/__test_dev_542/validation/{cpf}"
    assert fields["validation_errors"][0]["input"] == CPF_PLACEHOLDER


def test_validation_error_masks_a_cpf_sent_as_number_or_as_key(client, captured):
    response = client.post(
        f"/__test_dev_542/validation/{CPF}",
        json={"count": 1, "subject": int(CPF)},
    )
    numeric = client.post(f"/__test_dev_542/validation/{CPF}", json=int(CPF))
    keyed = client.post(f"/__test_dev_542/validation/{CPF}", json={CPF: "x"})

    assert response.status_code == numeric.status_code == keyed.status_code == 422
    _assert_no_cpf(captured)
    entries = [
        e for e in captured.entries() if e.get("operation") == "validation_exception"
    ]
    assert len(entries) == 3
    assert entries[0]["validation_errors"][0]["loc"] == ["body", "subject"]
    assert entries[0]["validation_errors"][0]["input"] == CPF_PLACEHOLDER
    assert entries[1]["validation_errors"][0]["input"] == CPF_PLACEHOLDER
    assert entries[2]["validation_errors"][0]["input"] == {CPF_PLACEHOLDER: "x"}


def test_masking_keeps_non_cpf_numbers_and_booleans(main):
    redact = main._redact_for_log
    assert redact({"count": 42, "ok": True, "id": 12345678901234}) == {
        "count": 42,
        "ok": True,
        "id": 12345678901234,
    }
    assert redact({"subject": int(CPF)}) == {"subject": CPF_PLACEHOLDER}


def test_percent_encoded_cpf_in_the_query_is_masked(client, captured):
    response = client.get(
        "/__test_dev_542/http/x?q=987%2E654%2E321-00&r=98765%34%332100"
    )

    assert response.status_code == 404
    _assert_no_cpf(captured)
    for line in captured.lines:
        assert "987%2E654%2E321-00" not in line
        assert "98765%34%332100" not in line
    fields = _exception_entry(captured, "http_exception")
    assert fields["url"].endswith(f"?q={CPF_PLACEHOLDER}&r={CPF_PLACEHOLDER}")


def test_cerbos_unavailable_original_error_and_url_are_masked(client, captured):
    response = client.get(f"/__test_dev_542/cerbos/{CPF}")

    assert response.status_code == 503
    _assert_no_cpf(captured)
    fields = _exception_entry(captured, "service_unavailable")
    assert fields["route"] == "/__test_dev_542/cerbos/{cpf}"
    assert fields["original_error"] == f"check failed for {CPF_PLACEHOLDER}"


def test_unhandled_exception_message_and_url_are_masked(client, captured):
    response = client.get(f"/__test_dev_542/boom/{CPF}")

    assert response.status_code == 500
    _assert_no_cpf(captured)
    fields = _exception_entry(captured, "general_exception")
    assert fields["route"] == "/__test_dev_542/boom/{cpf}"
    assert fields["exception_type"] == "RuntimeError"
    assert (
        fields["exception_message"] == f"lookup failed for principal {CPF_PLACEHOLDER}"
    )
