import pytest
from pydantic import ValidationError

from app.routers.mappings import ResolveRequest


def test_resolve_request_accepts_endpoint_method_pair() -> None:
    request = ResolveRequest(path="/api/v1/users/123", method="GET")

    assert request.path == "/api/v1/users/123"
    assert request.method == "GET"


def test_resolve_request_rejects_unknown_method() -> None:
    with pytest.raises(ValidationError):
        ResolveRequest(path="/api/v1/users/123", method="TRACE")
