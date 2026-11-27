"""The traceback uvicorn writes for a 500 never brings the citizen's CPF (DEV-553).

On an unhandled exception the ``general_exception_handler`` of ``app.main`` logs
a masked entry, but Starlette's ``ServerErrorMiddleware`` re-raises the exception
afterwards and uvicorn writes ``Exception in ASGI application`` with the full
traceback to the ``uvicorn.error`` logger. uvicorn configures its loggers (own
handlers, ``propagate=False``) before it imports the app, so that traceback used
to bypass the ``StructuredFormatter`` and its masking.

These tests run a real uvicorn server in the production order (uvicorn logging
configured first, then ``app.main`` imported) with a probe route whose exception
message carries a synthetic CPF, and assert that nothing written to stdout or
stderr carries the CPF while the uvicorn entry keeps the exception type and the
stack for diagnosis.
"""

import importlib
import json
import logging
import socket
import sys
import threading
import time
from collections.abc import Iterator
from unittest.mock import patch

import httpx
import pytest
import uvicorn

from app.settings import settings
from app.tracing import CPF_PLACEHOLDER

CPF = "98765432100"  # synthetic
CPF_FORMATTED = "987.654.321-00"  # synthetic
PROBE_PATH = "/__test_dev_553/boom"
UVICORN_LOGGER_NAMES = ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi")


def _fresh_app():
    """``app.main`` imported the way uvicorn imports it, plus a failing probe route."""
    sys.modules.pop("app.main", None)
    with patch.object(settings, "validate"):
        module = importlib.import_module("app.main")
    sys.modules.pop("app.main", None)

    @module.app.get(PROBE_PATH)
    async def _dev_553_boom():
        raise RuntimeError(f"lookup failed for {CPF} ({CPF_FORMATTED})")

    return module.app


@pytest.fixture
def restore_logging() -> Iterator[None]:
    """Put back the root and uvicorn loggers that uvicorn and the app reconfigure."""
    names = ("", *UVICORN_LOGGER_NAMES)
    saved = []
    for name in names:
        target = logging.getLogger(name)
        saved.append(
            (
                target,
                target.handlers[:],
                target.level,
                target.propagate,
                target.disabled,
            )
        )
    try:
        yield
    finally:
        for target, handlers, level, propagate, disabled in saved:
            target.handlers[:] = handlers
            target.setLevel(level)
            target.propagate = propagate
            target.disabled = disabled


def _serve_one_failing_request() -> int:
    """Run uvicorn like the Deployment does and return the probe's status code."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    # Config() applies uvicorn's LOGGING_CONFIG now; the app is imported later,
    # inside server.run(), exactly as `uvicorn app.main:app` does.
    config = uvicorn.Config(_fresh_app, factory=True, lifespan="off")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]})
    thread.start()
    try:
        deadline = time.monotonic() + 15
        while not server.started:
            assert thread.is_alive(), "uvicorn stopped before serving"
            assert time.monotonic() < deadline, "uvicorn did not start in time"
            time.sleep(0.05)
        response = httpx.get(f"http://127.0.0.1:{port}{PROBE_PATH}", timeout=10)
        return response.status_code
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        sock.close()


def _json_entries(text: str) -> list[dict]:
    entries = []
    for line in text.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


def test_probe_exception_carries_the_cpf_before_redaction():
    """Guard for the probe: the raw exception text really holds the CPF."""
    assert CPF in f"lookup failed for {CPF} ({CPF_FORMATTED})"


@pytest.mark.usefixtures("restore_logging")
def test_uvicorn_traceback_of_a_500_does_not_log_cpf(capsys):
    status_code = _serve_one_failing_request()
    out, err = capsys.readouterr()

    assert status_code == 500
    written = out + err
    assert "Exception in ASGI application" in written
    assert CPF not in written, f"CPF leaked into the logs: {written}"
    assert CPF_FORMATTED not in written, f"CPF leaked into the logs: {written}"

    entries = _json_entries(out)
    uvicorn_errors = [
        entry
        for entry in entries
        if entry.get("logger") == "uvicorn.error"
        and "Exception in ASGI application" in entry.get("message", "")
    ]
    assert len(uvicorn_errors) == 1, out
    exception = uvicorn_errors[0]["exception"]
    assert exception["type"] == "RuntimeError"
    assert exception["message"] == (
        f"lookup failed for {CPF_PLACEHOLDER} ({CPF_PLACEHOLDER})"
    )
    assert "Traceback" in exception["traceback"]
    assert "_dev_553_boom" in exception["traceback"]

    handler_entries = [
        entry for entry in entries if entry.get("operation") == "general_exception"
    ]
    assert len(handler_entries) == 1, out
    assert handler_entries[0]["exception_type"] == "RuntimeError"


@pytest.mark.usefixtures("restore_logging")
def test_uvicorn_loggers_go_through_the_structured_handler():
    """After the app sets up logging, uvicorn's loggers keep no handler of their own."""
    uvicorn.Config(_fresh_app, factory=True, lifespan="off")
    assert logging.getLogger("uvicorn").handlers, "uvicorn configures its handlers"

    _fresh_app()

    for name in UVICORN_LOGGER_NAMES:
        target = logging.getLogger(name)
        assert target.handlers == [], name
        assert target.propagate is True, name
