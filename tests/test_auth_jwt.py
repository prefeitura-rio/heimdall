"""Tests for JWT signature verification via JWKS (INFRAVPIA-314)."""

import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwk, jwt

from app.dependencies import get_current_user
from app.services.auth import AuthService

KID = "test-kid"


def _make_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_jwk = jwk.construct(pub_pem, "RS256").to_dict()
    public_jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return pem, public_jwk


PRIVATE_PEM, PUBLIC_JWK = _make_key()
OTHER_PEM, _ = _make_key()


def _token(exp_delta=3600, pem=PRIVATE_PEM, kid=KID, aud=None):
    now = int(time.time())
    claims = {
        "sub": "uuid-1",
        "preferred_username": "12345678901",
        "email": "a@b.c",
        "iat": now,
        "exp": now + exp_delta,
    }
    if aud is not None:
        claims["aud"] = aud
    headers = {"kid": kid} if kid else {}
    return jwt.encode(claims, pem, algorithm="RS256", headers=headers)


@pytest.fixture
def service():
    with patch("app.services.auth.CacheService"):
        svc = AuthService()
    svc.jwt_audience = None
    svc._fetch_jwks = MagicMock(return_value={"keys": [PUBLIC_JWK]})
    return svc


def test_valid_token_passes(service):
    result = service.verify_jwt_token(_token())
    assert result is not None
    assert result["subject"] == "12345678901"
    assert result["sub"] == "uuid-1"


def test_tampered_signature_rejected(service):
    header, payload, sig = _token().split(".")
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    assert service.verify_jwt_token(f"{header}.{payload}.{flipped}") is None


def test_signed_by_other_key_rejected(service):
    assert service.verify_jwt_token(_token(pem=OTHER_PEM)) is None


def test_expired_token_rejected(service):
    assert service.verify_jwt_token(_token(exp_delta=-60)) is None


def test_missing_kid_rejected(service):
    assert service.verify_jwt_token(_token(kid=None)) is None


def test_unknown_kid_rejected(service):
    assert service.verify_jwt_token(_token(kid="nope")) is None


def test_unsigned_claims_rejected(service):
    assert service.verify_jwt_token("e30.e30.") is None


def test_audience_not_enforced_when_configured(service):
    service.jwt_audience = "heimdall"
    assert service.verify_jwt_token(_token()) is not None
    assert service.verify_jwt_token(_token(aud="account")) is not None
    assert service.verify_jwt_token(_token(aud="heimdall")) is not None
    assert service.verify_jwt_token(_token(exp_delta=-60, aud="heimdall")) is None


def _creds(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_get_current_user_rejects_tampered_token(service):
    header, payload, sig = _token().split(".")
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    with pytest.raises(HTTPException) as exc:
        get_current_user(
            _creds(f"{header}.{payload}.{flipped}"),
            MagicMock(),
            service,
            MagicMock(),
        )
    assert exc.value.status_code == 401


def test_get_current_user_rejects_expired_token(service):
    with pytest.raises(HTTPException) as exc:
        get_current_user(
            _creds(_token(exp_delta=-60)), MagicMock(), service, MagicMock()
        )
    assert exc.value.status_code == 401


def test_get_current_user_accepts_valid_token(service):
    user_service = MagicMock()
    user_service.get_or_create_user.return_value = MagicMock()
    try:
        get_current_user(_creds(_token()), MagicMock(), service, user_service)
    except HTTPException as e:
        assert e.status_code != 401, e.detail
