"""Tests for the CORS origin allowlist (DEV-197)."""

import importlib
import sys
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.settings import Settings, parse_cors_allowed_origins, settings

ALLOWED = "https://admin.example.test"
OTHER_ALLOWED = "https://app.example.test"
UNKNOWN = "https://evil.example.test"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, []),
        ("", []),
        ("   ", []),
        ("*", []),
        (" * , ", []),
        (f"{ALLOWED}", [ALLOWED]),
        (f" {ALLOWED}/ , {OTHER_ALLOWED} ", [ALLOWED, OTHER_ALLOWED]),
        (f"*,{ALLOWED},,{ALLOWED}", [ALLOWED]),
    ],
)
def test_parse_cors_allowed_origins(raw, expected):
    assert parse_cors_allowed_origins(raw) == expected


def test_settings_default_allows_no_origin(monkeypatch):
    monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)
    assert Settings().CORS_ALLOWED_ORIGINS == []


def test_settings_reads_env_and_drops_wildcard(monkeypatch):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", f"*,{ALLOWED},{OTHER_ALLOWED}/")
    assert Settings().CORS_ALLOWED_ORIGINS == [ALLOWED, OTHER_ALLOWED]


def _client_for(origins: list[str]) -> TestClient:
    """Import a fresh app.main with the given allowlist (no lifespan, no I/O)."""
    sys.modules.pop("app.main", None)
    with (
        patch.object(settings, "CORS_ALLOWED_ORIGINS", origins),
        patch.object(settings, "validate"),
    ):
        main = importlib.import_module("app.main")
    sys.modules.pop("app.main", None)
    return TestClient(main.app)


@pytest.fixture(scope="module")
def client():
    return _client_for([ALLOWED, OTHER_ALLOWED])


@pytest.fixture(scope="module")
def client_without_allowlist():
    return _client_for([])


def _preflight(client: TestClient, origin: str):
    return client.options(
        "/api/v1/users/me",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )


def test_unknown_origin_gets_no_allow_origin_header(client):
    response = client.get("/cors-probe", headers={"Origin": UNKNOWN})
    assert "access-control-allow-origin" not in response.headers


def test_unknown_origin_preflight_is_rejected(client):
    response = _preflight(client, UNKNOWN)
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_allowed_origin_is_echoed_not_wildcard(client):
    for origin in (ALLOWED, OTHER_ALLOWED):
        response = client.get("/cors-probe", headers={"Origin": origin})
        assert response.headers["access-control-allow-origin"] == origin
        assert response.headers["access-control-allow-credentials"] == "true"
        assert "Origin" in response.headers.get("vary", "")


def test_allowed_origin_preflight_succeeds(client):
    response = _preflight(client, ALLOWED)
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == ALLOWED
    assert "GET" in response.headers["access-control-allow-methods"]
    assert "authorization" in response.headers["access-control-allow-headers"]


def test_empty_allowlist_never_returns_wildcard(client_without_allowlist):
    response = client_without_allowlist.get("/cors-probe", headers={"Origin": ALLOWED})
    assert "access-control-allow-origin" not in response.headers
    assert _preflight(client_without_allowlist, ALLOWED).status_code == 400


def test_request_without_origin_is_unaffected(client):
    response = client.get("/cors-probe")
    assert "access-control-allow-origin" not in response.headers
