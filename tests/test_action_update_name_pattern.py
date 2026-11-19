"""``PUT /actions/{action_id}`` enforces the same name pattern as creation (DEV-664).

``ActionCreateRequest.name`` only accepts ``^[a-z0-9_:]+$`` (lowercase letters,
numbers, underscores and colons), but ``ActionUpdateRequest.name`` accepted
``^[a-zA-Z0-9_:-]+$``: an action created as ``user:read`` could be renamed to
``User:Read-x``, a name the API itself refuses on ``POST``. Both models now
share one pattern. Synthetic data only.
"""

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.database import get_db
from app.dependencies import get_current_user
from app.routers import actions as actions_router
from app.routers.actions import (
    ACTION_NAME_PATTERN,
    ACTION_NAME_RULE,
    ActionCreateRequest,
    ActionUpdateRequest,
)

ACTION_ID = 42

# Names outside the convention: uppercase, hyphen, whitespace, control
# characters, unicode look-alikes, path and injection-like input.
INVALID_NAMES = [
    "User:Read-x",
    "User:Read",
    "user-read",
    "USER",
    "user read",
    "user:read\n",
    "user:read\t",
    "usér:read",
    "user：read",  # fullwidth colon
    "user/read",
    "../user",
    "user;drop",
    "user*",
    "user:read'",
    "",
]

VALID_NAMES = ["user:read", "group_admin:create", "a", "v2:report:read_all"]


def _user() -> MagicMock:
    user = MagicMock()
    user.subject = "uuid-caller-sintetico-664"
    user.id = 7
    return user


def _user_service() -> MagicMock:
    service = MagicMock()
    service.get_user_roles.return_value = ["heimdall-admin"]
    return service


def _cerbos(allow: bool) -> MagicMock:
    cerbos = MagicMock()
    cerbos.can_update_action.return_value = allow
    return cerbos


def _action_service() -> MagicMock:
    service = MagicMock()

    def update_action(*, action_id, name, description, **_):
        action = MagicMock()
        action.id = action_id
        action.name = name or "user:read"
        action.description = description or "Ler dados sinteticos"
        action.endpoints = []
        return action

    service.update_action.side_effect = update_action
    return service


@pytest.fixture
def services():
    return {
        "action": _action_service(),
        "cerbos": _cerbos(allow=True),
        "user": _user_service(),
    }


def _client(services, *, authenticated: bool = True) -> TestClient:
    app = FastAPI()
    app.include_router(actions_router.router, prefix="/actions")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    if authenticated:
        app.dependency_overrides[get_current_user] = _user
    app.dependency_overrides[actions_router.get_action_service] = lambda: services[
        "action"
    ]
    app.dependency_overrides[actions_router.get_cerbos_service] = lambda: services[
        "cerbos"
    ]
    app.dependency_overrides[actions_router.get_user_service] = lambda: services["user"]
    return TestClient(app)


def test_create_and_update_share_the_same_name_pattern():
    create = ActionCreateRequest.model_fields["name"].metadata
    update = ActionUpdateRequest.model_fields["name"].metadata
    create_patterns = {getattr(m, "pattern", None) for m in create} - {None}
    update_patterns = {getattr(m, "pattern", None) for m in update} - {None}

    assert ACTION_NAME_PATTERN == "^[a-z0-9_:]+$"
    assert create_patterns == {ACTION_NAME_PATTERN}
    assert update_patterns == {ACTION_NAME_PATTERN}


@pytest.mark.parametrize("name", INVALID_NAMES)
def test_update_model_rejects_names_the_create_model_rejects(name):
    with pytest.raises(ValidationError):
        ActionCreateRequest(name=name, description="x")
    with pytest.raises(ValidationError):
        ActionUpdateRequest(name=name)


@pytest.mark.parametrize("name", INVALID_NAMES)
def test_put_rejects_name_outside_convention_with_422(services, name):
    response = _client(services).put(f"/actions/{ACTION_ID}", json={"name": name})

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "name"]
    services["action"].update_action.assert_not_called()


@pytest.mark.parametrize("name", VALID_NAMES)
def test_put_accepts_name_inside_convention(services, name):
    response = _client(services).put(f"/actions/{ACTION_ID}", json={"name": name})

    assert response.status_code == 200
    assert response.json()["name"] == name
    services["action"].update_action.assert_called_once()
    assert services["action"].update_action.call_args.kwargs["name"] == name


def test_put_with_description_only_is_still_accepted(services):
    response = _client(services).put(
        f"/actions/{ACTION_ID}", json={"description": "Ler dados sinteticos"}
    )

    assert response.status_code == 200
    kwargs = services["action"].update_action.call_args.kwargs
    assert kwargs["name"] is None
    assert kwargs["description"] == "Ler dados sinteticos"


def test_put_still_requires_authentication(services):
    response = _client(services, authenticated=False).put(
        f"/actions/{ACTION_ID}", json={"name": "user:read"}
    )

    assert response.status_code in (401, 403)
    services["action"].update_action.assert_not_called()


def test_put_with_valid_name_still_denied_without_permission(services, monkeypatch):
    services["cerbos"] = _cerbos(allow=False)
    monkeypatch.setattr(actions_router, "forbidden", _forbidden_stub)

    response = _client(services).put(
        f"/actions/{ACTION_ID}", json={"name": "user:read"}
    )

    assert response.status_code == 403
    services["action"].update_action.assert_not_called()


def _forbidden_stub(*_, detail: str, **__) -> HTTPException:
    return HTTPException(status_code=403, detail=detail)


def test_openapi_documents_the_update_name_pattern():
    app = FastAPI()
    app.include_router(actions_router.router)
    schema = app.openapi()["components"]["schemas"]["ActionUpdateRequest"]
    name = schema["properties"]["name"]
    options = name.get("anyOf", [name])
    patterns = {o.get("pattern") for o in options} - {None}

    assert patterns == {ACTION_NAME_PATTERN}
    assert ACTION_NAME_RULE in name["description"]
    assert (
        ACTION_NAME_RULE == "lowercase letters, numbers, underscores, and colons only"
    )
