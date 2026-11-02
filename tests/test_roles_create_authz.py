"""Tests for POST /roles authorization via Cerbos (DEV-154)."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.routers.roles import RoleCreateRequest, create_role
from app.services.cerbos import CerbosService


def _role_data(name="data_analyst:read"):
    return RoleCreateRequest(name=name, description="Synthetic role for tests")


def _user(subject="uuid-caller"):
    user = MagicMock()
    user.subject = subject
    return user


def _services(caller_roles, allowed):
    role_service = MagicMock()
    created = MagicMock()
    created.id = 42
    created.name = "data_analyst:read"
    created.description = "Synthetic role for tests"
    role_service.create_role.return_value = created

    user_service = MagicMock()
    user_service.get_user_roles.return_value = caller_roles

    cerbos_service = MagicMock()
    cerbos_service.can_create_role.return_value = allowed
    return role_service, user_service, cerbos_service


def _call(role_data, user, role_service, user_service, cerbos_service):
    with patch("app.services.policy_invalidator.invalidate_policy_version"):
        return asyncio.run(
            create_role(
                role_data=role_data,
                current_user=user,
                db=MagicMock(),
                role_service=role_service,
                user_service=user_service,
                cerbos_service=cerbos_service,
            )
        )


def test_role_manager_allowed_by_cerbos_creates_role():
    role_service, user_service, cerbos_service = _services(["role_manager"], True)
    user = _user()

    response = _call(_role_data(), user, role_service, user_service, cerbos_service)

    assert response.id == 42
    assert response.name == "data_analyst:read"
    cerbos_service.can_create_role.assert_called_once_with(
        caller_subject="uuid-caller",
        caller_roles=["role_manager"],
        role_name="data_analyst:read",
    )
    role_service.create_role.assert_called_once()


def test_admin_denied_by_cerbos_gets_403_and_nothing_is_created():
    role_service, user_service, cerbos_service = _services(["admin"], False)

    with pytest.raises(HTTPException) as exc:
        _call(_role_data(), _user(), role_service, user_service, cerbos_service)

    assert exc.value.status_code == 403
    assert "data_analyst:read" in exc.value.detail
    role_service.create_role.assert_not_called()


def test_caller_without_roles_denied_by_cerbos_gets_403():
    role_service, user_service, cerbos_service = _services([], False)

    with pytest.raises(HTTPException) as exc:
        _call(_role_data(), _user(), role_service, user_service, cerbos_service)

    assert exc.value.status_code == 403
    role_service.create_role.assert_not_called()


def test_existing_role_still_returns_409_when_allowed():
    role_service, user_service, cerbos_service = _services(["role_manager"], True)
    role_service.create_role.side_effect = ValueError("Role already exists")

    with pytest.raises(HTTPException) as exc:
        _call(_role_data(), _user(), role_service, user_service, cerbos_service)

    assert exc.value.status_code == 409


def test_can_create_role_checks_role_create_with_role_name():
    with patch.object(CerbosService, "__init__", return_value=None):
        service = CerbosService()
    with patch.object(service, "check_permission", return_value=True) as check:
        assert service.can_create_role("uuid-caller", ["role_manager"], "x:y")

    check.assert_called_once_with(
        caller_subject="uuid-caller",
        caller_roles=["role_manager"],
        action="role:create",
        resource_type="role",
        resource_attrs={"name": "x:y"},
    )
