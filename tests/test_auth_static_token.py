"""Tests for the static API token check in AuthService (DEV-236)."""

import secrets
from unittest.mock import MagicMock, patch

import pytest

from app.services.auth import AuthService

STATIC_TOKEN = "static-token-for-tests-0123456789"


@pytest.fixture
def service():
    with patch("app.services.auth.CacheService"):
        svc = AuthService()
    svc.static_api_token = STATIC_TOKEN
    # No JWT path in these tests: force JWT verification to fail.
    svc.verify_jwt_token = MagicMock(return_value=None)
    return svc


def test_correct_token_accepted(service):
    assert service.verify_static_token(STATIC_TOKEN) is True


def test_wrong_token_rejected(service):
    assert service.verify_static_token("another-token-of-similar-size") is False


def test_prefix_of_token_rejected(service):
    assert service.verify_static_token(STATIC_TOKEN[:-1]) is False


def test_token_with_extra_suffix_rejected(service):
    assert service.verify_static_token(STATIC_TOKEN + "x") is False


def test_empty_token_rejected(service):
    assert service.verify_static_token("") is False


def test_non_ascii_token_rejected_without_error(service):
    assert service.verify_static_token("tokén-ç-não-ascii") is False


def test_unconfigured_static_token_rejects_everything(service):
    service.static_api_token = ""
    assert service.verify_static_token("") is False
    assert service.verify_static_token(STATIC_TOKEN) is False
    service.static_api_token = None
    assert service.verify_static_token("") is False


def test_comparison_uses_constant_time_compare_digest(service):
    with patch(
        "app.services.auth.secrets.compare_digest", wraps=secrets.compare_digest
    ) as compare:
        assert service.verify_static_token(STATIC_TOKEN) is True
        assert service.verify_static_token("wrong") is False
    assert compare.call_count == 2


def test_authenticate_request_with_static_token(service):
    result = service.authenticate_request(f"Bearer {STATIC_TOKEN}")
    assert result == {"type": "static_api", "valid": True}


def test_authenticate_request_with_wrong_static_token(service):
    assert service.authenticate_request("Bearer wrong-token") is None
    assert service.authenticate_request("Bearer ") is None
