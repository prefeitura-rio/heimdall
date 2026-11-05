"""DELETE /roles/{name} checks authorization before revealing whether the role exists (DEV-274)."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.routers.roles import delete_role


def _user(subject="uuid-caller", user_id=7):
    user = MagicMock()
    user.subject = subject
    user.id = user_id
    return user


def _services(allowed, role_exists, groups_with_role=None):
    role_service = MagicMock()
    role_service.get_role_by_name.return_value = MagicMock() if role_exists else None
    role_service.get_groups_with_role.return_value = groups_with_role or []

    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["viewer"]

    cerbos_service = MagicMock()
    cerbos_service.check_permission.return_value = allowed
    return role_service, user_service, cerbos_service


def _call(role_name, role_service, user_service, cerbos_service):
    with (
        patch("app.services.policy_invalidator.invalidate_policy_version"),
        patch("app.common.authz.AuditService") as audit_cls,
    ):
        try:
            asyncio.run(
                delete_role(
                    role_name=role_name,
                    current_user=_user(),
                    db=MagicMock(),
                    role_service=role_service,
                    cerbos_service=cerbos_service,
                    user_service=user_service,
                )
            )
        except HTTPException as exc:
            return exc, audit_cls.return_value.log_authorization_denied
        return None, audit_cls.return_value.log_authorization_denied


@pytest.mark.parametrize("role_exists", [True, False], ids=["existing", "missing"])
def test_denied_caller_gets_audited_403_whether_or_not_the_role_exists(role_exists):
    role_service, user_service, cerbos_service = _services(
        allowed=False, role_exists=role_exists
    )

    exc, audit = _call("data_analyst:read", role_service, user_service, cerbos_service)

    assert exc is not None
    assert exc.status_code == 403
    assert exc.detail == "Permission denied to delete role 'data_analyst:read'"
    audit.assert_called_once()
    assert audit.call_args.kwargs["operation"] == "delete_role"
    assert audit.call_args.kwargs["target_id"] == "role:data_analyst:read"
    cerbos_service.check_permission.assert_called_once_with(
        caller_subject="uuid-caller",
        caller_roles=["viewer"],
        action="role:delete",
        resource_type="role",
        resource_attrs={"name": "data_analyst:read"},
    )
    role_service.get_role_by_name.assert_not_called()
    role_service.get_groups_with_role.assert_not_called()
    role_service.delete_role.assert_not_called()


def test_denied_responses_are_identical_for_existing_and_missing_roles():
    existing = _call("x:y", *_services(allowed=False, role_exists=True))[0]
    missing = _call("x:y", *_services(allowed=False, role_exists=False))[0]

    assert (existing.status_code, existing.detail) == (
        missing.status_code,
        missing.detail,
    )


def test_allowed_caller_gets_404_for_missing_role_without_denial_audit():
    role_service, user_service, cerbos_service = _services(
        allowed=True, role_exists=False
    )

    exc, audit = _call("ghost:role", role_service, user_service, cerbos_service)

    assert exc is not None
    assert exc.status_code == 404
    assert exc.detail == "Role 'ghost:role' not found"
    audit.assert_not_called()
    role_service.delete_role.assert_not_called()


def test_allowed_caller_deletes_existing_role():
    role_service, user_service, cerbos_service = _services(
        allowed=True, role_exists=True
    )

    exc, audit = _call("data_analyst:read", role_service, user_service, cerbos_service)

    assert exc is None
    audit.assert_not_called()
    role_service.delete_role.assert_called_once()
    assert role_service.delete_role.call_args.args[1] == "data_analyst:read"


def test_allowed_caller_gets_409_when_role_is_still_assigned():
    role_service, user_service, cerbos_service = _services(
        allowed=True, role_exists=True, groups_with_role=[{"name": "team:backend"}]
    )

    exc, _ = _call("data_analyst:read", role_service, user_service, cerbos_service)

    assert exc is not None
    assert exc.status_code == 409
    role_service.delete_role.assert_not_called()


@pytest.mark.parametrize("allowed", [True, False], ids=["allowed", "denied"])
def test_superadmin_is_protected_before_any_lookup(allowed):
    role_service, user_service, cerbos_service = _services(
        allowed=allowed, role_exists=True
    )

    exc, audit = _call("superadmin", role_service, user_service, cerbos_service)

    assert exc is not None
    assert exc.status_code == 403
    assert "superadmin" in exc.detail
    audit.assert_called_once()
    role_service.get_role_by_name.assert_not_called()
    role_service.delete_role.assert_not_called()
