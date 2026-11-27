"""Error classification in the membership routers (DEV-276).

A missing group is signalled by its own exception type (404), and a Cerbos
failure is a dependency error (503), regardless of the text of the message.
"""

import asyncio
import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.exceptions import (
    CerbosResponseError,
    CerbosUnavailableError,
    GroupNotFoundError,
)
from app.routers.memberships import (
    AddMemberRequest,
    add_member_to_group,
    list_group_members,
    remove_member_from_group,
)
from app.services.base import BaseService
from app.services.cerbos import CerbosService
from app.settings import settings

CALLER = "uuid-caller-sintetico"
TARGET = "00000000191"  # synthetic CPF-shaped subject, not a real person
GROUP = "eng:backend"


def _user():
    user = MagicMock()
    user.subject = CALLER
    return user


def _user_service():
    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["some_role"]
    return user_service


def _add(service):
    with patch("app.services.policy_invalidator.invalidate_policy_version"):
        return asyncio.run(
            add_member_to_group(
                group_name=GROUP,
                member_data=AddMemberRequest(subject=TARGET),
                current_user=_user(),
                db=MagicMock(),
                membership_service=service,
                user_service=_user_service(),
            )
        )


def _remove(service):
    with patch("app.services.policy_invalidator.invalidate_policy_version"):
        return asyncio.run(
            remove_member_from_group(
                group_name=GROUP,
                subject=TARGET,
                current_user=_user(),
                db=MagicMock(),
                membership_service=service,
                user_service=_user_service(),
            )
        )


def _list(service):
    return asyncio.run(
        list_group_members(
            group_name=GROUP,
            current_user=_user(),
            db=MagicMock(),
            membership_service=service,
            user_service=_user_service(),
        )
    )


HANDLERS = {
    "add": ("add_member_to_group", _add),
    "remove": ("remove_member_from_group", _remove),
    "list": ("list_group_members", _list),
}


def _service_raising(method: str, exc: Exception) -> MagicMock:
    service = MagicMock()
    getattr(service, method).side_effect = exc
    return service


@pytest.mark.parametrize("handler", sorted(HANDLERS))
def test_group_not_found_error_becomes_404(handler):
    method, call = HANDLERS[handler]
    service = _service_raising(method, GroupNotFoundError(GROUP))

    with pytest.raises(HTTPException) as exc:
        call(service)

    assert exc.value.status_code == 404
    assert exc.value.detail == f"Group '{GROUP}' not found"


@pytest.mark.parametrize("handler", sorted(HANDLERS))
def test_value_error_with_not_found_text_is_not_a_404(handler):
    """The router no longer classifies errors by the text of the message."""
    method, call = HANDLERS[handler]
    service = _service_raising(method, ValueError("policy not found"))

    with pytest.raises(HTTPException) as exc:
        call(service)

    assert exc.value.status_code == 400


@pytest.mark.parametrize("handler", sorted(HANDLERS))
@pytest.mark.parametrize(
    "cerbos_error",
    ["policy not found", "internal error"],
)
def test_cerbos_failure_is_not_turned_into_4xx(handler, cerbos_error):
    """A Cerbos failure escapes the router as a dependency error (503 handler)."""
    method, call = HANDLERS[handler]
    service = _service_raising(method, CerbosResponseError(f"Cerbos error: {cerbos_error}"))

    with pytest.raises(CerbosUnavailableError):
        call(service)


def test_group_not_found_error_is_not_a_value_error():
    """Callers that map ValueError to 400 must not swallow a missing group."""
    assert not isinstance(GroupNotFoundError(GROUP), ValueError)


def _cerbos_service_answering(payload: dict) -> CerbosService:
    with patch.object(CerbosService, "__init__", return_value=None):
        service = CerbosService()
    BaseService.__init__(service, "cerbos")
    service.check_url = "http://cerbos.invalid/api/check/resources"
    service.max_retries = 0
    service.base_retry_delay = 0.0

    response = MagicMock()
    response.status_code = 200
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    patcher = patch("app.services.cerbos.requests.post", return_value=response)
    patcher.start()
    service._patcher = patcher
    return service


@pytest.mark.parametrize(
    "payload",
    [
        {"error": "policy not found"},
        {"error": "internal error"},
        {"unexpected": True},
    ],
)
def test_check_permission_raises_cerbos_response_error(payload):
    service = _cerbos_service_answering(payload)
    health = MagicMock()
    health.is_cerbos_available.return_value = True
    try:
        with (
            patch("app.services.health_monitor.HealthMonitor", return_value=health),
            pytest.raises(CerbosResponseError) as exc,
        ):
            service.check_permission(
                caller_subject=CALLER,
                caller_roles=["some_role"],
                action="group:add_member",
                resource_type="group",
                resource_attrs={"name": GROUP},
            )
    finally:
        service._patcher.stop()

    assert not isinstance(exc.value, ValueError)
    assert isinstance(exc.value, CerbosUnavailableError)


def test_check_permission_still_returns_decision():
    service = _cerbos_service_answering(
        {"results": [{"actions": {"group:add_member": "EFFECT_ALLOW"}}]}
    )
    health = MagicMock()
    health.is_cerbos_available.return_value = True
    try:
        with patch("app.services.health_monitor.HealthMonitor", return_value=health):
            allowed = service.check_permission(
                caller_subject=CALLER,
                caller_roles=["some_role"],
                action="group:add_member",
                resource_type="group",
                resource_attrs={"name": GROUP},
            )
    finally:
        service._patcher.stop()

    assert allowed is True


@pytest.mark.parametrize("handler", sorted(HANDLERS))
@pytest.mark.parametrize("cerbos_error", ["policy not found", "internal error"])
def test_cerbos_error_payload_through_service_and_router_is_not_4xx(
    handler, cerbos_error
):
    """The scenario of the issue, end to end below the app: Cerbos answers an
    `error` without `results` while handling a membership request."""
    from app.services.membership import MembershipService

    cerbos = _cerbos_service_answering({"error": cerbos_error})
    with patch.object(MembershipService, "__init__", return_value=None):
        service = MembershipService()
    BaseService.__init__(service, "membership")
    service.cerbos_service = cerbos
    service.cache_service = MagicMock()
    service.audit_service = MagicMock()
    health = MagicMock()
    health.is_cerbos_available.return_value = True
    _, call = HANDLERS[handler]
    try:
        with (
            patch("app.services.health_monitor.HealthMonitor", return_value=health),
            pytest.raises(CerbosUnavailableError),
        ):
            call(service)
    finally:
        cerbos._patcher.stop()


def test_cerbos_response_error_answers_503_through_the_app():
    """The app-level CerbosUnavailableError handler turns it into a 503."""
    sys.modules.pop("app.main", None)
    with patch.object(settings, "validate"):
        main = importlib.import_module("app.main")
    sys.modules.pop("app.main", None)

    @main.app.get("/__test_dev_276_cerbos_failure")
    async def _boom():
        raise CerbosResponseError("Cerbos error: policy not found")

    client = TestClient(main.app, raise_server_exceptions=False)
    response = client.get("/__test_dev_276_cerbos_failure")

    assert response.status_code == 503
    assert "policy not found" not in response.text
