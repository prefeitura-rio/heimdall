"""Authorization denials (403) are written to admin_audit (DEV-272).

SPEC.md: "If EFFECT_DENY -> return 403 to the caller and audit the attempt".
"""

import asyncio
import inspect
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.common.authz import forbidden
from app.routers import actions, groups, mappings, roles
from app.services.audit import AuditService
from app.services.membership import MembershipService


def _user(subject="uuid-caller", user_id=7):
    user = MagicMock()
    user.subject = subject
    user.id = user_id
    return user


def _cerbos(allowed):
    cerbos = MagicMock()
    for name in (
        "can_create_group",
        "can_delete_group",
        "can_create_role",
        "can_assign_role",
        "can_remove_role",
        "can_create_mapping",
        "can_update_mapping",
        "can_delete_mapping",
        "can_create_action",
        "can_update_action",
        "can_delete_action",
        "check_permission",
    ):
        getattr(cerbos, name).return_value = allowed
    return cerbos


def _call(endpoint, cerbos, **explicit):
    """Call a router endpoint, filling every service dependency with a mock."""
    kwargs = dict(explicit)
    services = {}
    for name in inspect.signature(endpoint).parameters:
        if name in kwargs:
            continue
        if name == "cerbos_service":
            kwargs[name] = cerbos
        elif name == "current_user":
            kwargs[name] = _user()
        else:
            kwargs[name] = MagicMock()
            services[name] = kwargs[name]
    kwargs["user_service"].get_user_roles.return_value = ["viewer"]
    with patch("app.services.policy_invalidator.invalidate_policy_version"):
        return asyncio.run(endpoint(**kwargs)), services


def _mapping_create():
    return mappings.MappingCreateRequest(
        path_pattern="/api/v1/things", method="GET", action_id=3
    )


# (endpoint, explicit args, operation, target_type, target_id, mutating service call)
DENIED_CASES = [
    (
        groups.create_group,
        {
            "group_data": groups.GroupCreateRequest(
                name="team:backend", description="Synthetic group"
            )
        },
        "create_group",
        "group",
        "group:team:backend",
        ("group_service", "create_group"),
    ),
    (
        groups.delete_group,
        {"group_name": "team:backend"},
        "delete_group",
        "group",
        "group:team:backend",
        ("group_service", "delete_group"),
    ),
    (
        roles.create_role,
        {
            "role_data": roles.RoleCreateRequest(
                name="data:read", description="Synthetic role"
            )
        },
        "create_role",
        "role",
        "role:data:read",
        ("role_service", "create_role"),
    ),
    (
        roles.list_group_roles,
        {"group_name": "team:backend"},
        "view_group_roles",
        "group",
        "group:team:backend",
        ("role_service", "get_group_roles"),
    ),
    (
        roles.assign_role_to_group,
        {
            "group_name": "team:backend",
            "assign_data": roles.RoleAssignRequest(role_name="data:read"),
        },
        "assign_role_to_group",
        "role",
        "group:team:backend:role:data:read",
        ("role_service", "assign_role_to_group"),
    ),
    (
        roles.remove_role_from_group,
        {"group_name": "team:backend", "role_name": "data:read"},
        "remove_role_from_group",
        "role",
        "group:team:backend:role:data:read",
        ("role_service", "remove_role_from_group"),
    ),
    (
        roles.list_role_actions,
        {"role_name": "data:read"},
        "view_role_actions",
        "role",
        "role:data:read",
        ("role_service", "get_role_actions"),
    ),
    (
        roles.assign_action_to_role,
        {
            "role_name": "data:read",
            "action_data": roles.RoleActionRequest(action_name="user:read"),
        },
        "assign_action_to_role",
        "role",
        "role:data:read:action:user:read",
        ("role_service", "assign_action_to_role"),
    ),
    (
        roles.remove_action_from_role,
        {"role_name": "data:read", "action_name": "user:read"},
        "remove_action_from_role",
        "role",
        "role:data:read:action:user:read",
        ("role_service", "remove_action_from_role"),
    ),
    (
        roles.delete_role,
        {"role_name": "data:read"},
        "delete_role",
        "role",
        "role:data:read",
        ("role_service", "delete_role"),
    ),
    (
        mappings.create_mapping,
        {"mapping_data": _mapping_create()},
        "create_mapping",
        "mapping",
        "mapping:GET:/api/v1/things",
        ("mapping_service", "create_mapping"),
    ),
    (
        mappings.update_mapping,
        {
            "mapping_id": 11,
            "mapping_data": mappings.MappingUpdateRequest(description="x"),
        },
        "update_mapping",
        "mapping",
        "mapping:11",
        ("mapping_service", "update_mapping"),
    ),
    (
        mappings.delete_mapping,
        {"mapping_id": 11},
        "delete_mapping",
        "mapping",
        "mapping:11",
        ("mapping_service", "delete_mapping"),
    ),
    (
        actions.create_action,
        {
            "action_data": actions.ActionCreateRequest(
                name="user:read", description="Synthetic action"
            )
        },
        "action_create",
        "action",
        "user:read",
        ("action_service", "create_action"),
    ),
    (
        actions.update_action,
        {
            "action_id": 5,
            "action_data": actions.ActionUpdateRequest(description="x"),
        },
        "action_update",
        "action",
        "5",
        ("action_service", "update_action"),
    ),
    (
        actions.delete_action,
        {"action_id": 5},
        "action_delete",
        "action",
        "5",
        ("action_service", "delete_action"),
    ),
]


@pytest.mark.parametrize(
    ("endpoint", "explicit", "operation", "target_type", "target_id"),
    [case[:5] for case in DENIED_CASES],
    ids=[case[0].__name__ for case in DENIED_CASES],
)
def test_cerbos_denial_returns_403_and_is_audited(
    endpoint, explicit, operation, target_type, target_id
):
    with (
        patch("app.common.authz.AuditService") as audit_cls,
        pytest.raises(HTTPException) as exc,
    ):
        _call(endpoint, _cerbos(False), **explicit)

    assert exc.value.status_code == 403
    audit = audit_cls.return_value.log_authorization_denied
    audit.assert_called_once()
    kwargs = audit.call_args.kwargs
    assert kwargs["actor_subject"] == "uuid-caller"
    assert kwargs["actor_user_id"] == 7
    assert kwargs["operation"] == operation
    assert kwargs["target_type"] == target_type
    assert kwargs["target_id"] == target_id
    assert kwargs["reason"] == exc.value.detail
    assert isinstance(kwargs["request_payload"], dict)


@pytest.mark.parametrize(
    ("endpoint", "explicit", "mutation"),
    [(case[0], case[1], case[5]) for case in DENIED_CASES],
    ids=[case[0].__name__ for case in DENIED_CASES],
)
def test_cerbos_denial_never_reaches_the_service(endpoint, explicit, mutation):
    service_name, method = mutation
    service = MagicMock()

    with patch("app.common.authz.AuditService"), pytest.raises(HTTPException):
        _call(endpoint, _cerbos(False), **explicit, **{service_name: service})

    getattr(service, method).assert_not_called()


def test_allowed_request_writes_no_denial_entry():
    with patch("app.common.authz.AuditService") as audit_cls:
        _call(
            groups.delete_group,
            _cerbos(True),
            group_name="team:backend",
        )

    audit_cls.return_value.log_authorization_denied.assert_not_called()


@pytest.mark.parametrize(
    ("endpoint", "explicit"),
    [
        (roles.assign_action_to_role, DENIED_CASES[7][1]),
        (roles.remove_action_from_role, DENIED_CASES[8][1]),
        (roles.delete_role, DENIED_CASES[9][1]),
    ],
    ids=["assign_action_to_role", "remove_action_from_role", "delete_role"],
)
def test_superadmin_protection_denial_is_audited(endpoint, explicit):
    explicit = {**explicit, "role_name": "superadmin"}
    with (
        patch("app.common.authz.AuditService") as audit_cls,
        pytest.raises(HTTPException) as exc,
    ):
        _call(endpoint, _cerbos(True), **explicit)

    assert exc.value.status_code == 403
    assert "superadmin" in exc.value.detail
    kwargs = audit_cls.return_value.log_authorization_denied.call_args.kwargs
    assert kwargs["target_id"].startswith("role:superadmin")


def test_action_denial_is_403_not_500():
    """The generic `except Exception` used to turn the 403 into a 500."""
    with (
        patch("app.common.authz.AuditService"),
        pytest.raises(HTTPException) as exc,
    ):
        _call(actions.delete_action, _cerbos(False), action_id=5)

    assert exc.value.status_code == 403
    assert exc.value.detail == "Insufficient permissions to delete actions"


def test_log_authorization_denied_writes_failed_entry_with_sanitized_payload():
    db = MagicMock()
    service = AuditService()

    logged = service.log_authorization_denied(
        db=db,
        actor_subject="uuid-caller",
        operation="create_group",
        reason="Permission denied to create group 'g'",
        target_type="group",
        target_id="group:g",
        request_payload={"name": "g", "api_token": "synthetic-value"},
        actor_user_id=7,
    )

    assert logged is True
    entry = db.add.call_args.args[0]
    assert entry.success is False
    assert entry.actor_subject == "uuid-caller"
    assert entry.actor_user_id == 7
    assert entry.operation == "create_group"
    assert entry.target_type == "group"
    assert entry.target_id == "group:g"
    assert entry.result == {
        "error": "Permission denied to create group 'g'",
        "status_code": 403,
        "authorization": "denied",
    }
    assert entry.request_payload == {"name": "g", "api_token": "[REDACTED]"}
    db.commit.assert_called_once()
    db.rollback.assert_not_called()


def test_audit_write_failure_rolls_back_and_still_returns_403():
    db = MagicMock()
    db.commit.side_effect = RuntimeError("database unavailable")

    error = forbidden(
        db,
        _user(),
        operation="delete_group",
        detail="Permission denied to delete group 'g'",
        target_type="group",
        target_id="group:g",
    )

    assert isinstance(error, HTTPException)
    assert error.status_code == 403
    assert error.detail == "Permission denied to delete group 'g'"
    db.rollback.assert_called_once()


@pytest.mark.parametrize(
    ("method", "operation", "kwargs"),
    [
        ("add_member_to_group", "add_member", {"member_subject": "uuid-member"}),
        (
            "remove_member_from_group",
            "remove_member",
            {"member_subject": "uuid-member"},
        ),
        ("list_group_members", "list_members", {}),
    ],
)
def test_membership_denials_are_audited_by_the_service(method, operation, kwargs):
    """Membership 403s are already audited in MembershipService."""
    service = MembershipService()
    service.cerbos_service = MagicMock()
    service.cerbos_service.check_permission.return_value = False
    service.audit_service = MagicMock()

    call = getattr(service, method)
    try:
        result = call(
            db=MagicMock(),
            group_name="team:backend",
            caller_subject="uuid-caller",
            caller_roles=["viewer"],
            **kwargs,
        )
        assert result is False
    except PermissionError:
        pass

    entries = service.audit_service.safe_log_operation.call_args_list
    assert entries, "denial must be audited"
    last = entries[-1].kwargs
    assert last["operation"] == operation
    assert last["actor_subject"] == "uuid-caller"
    assert last["success"] is False


def test_nul_from_caller_input_never_reaches_the_audit_entry():
    """PostgreSQL rejects NUL in text/JSONB: a denied caller must not skip the trail."""
    db = MagicMock()

    logged = AuditService().log_authorization_denied(
        db=db,
        actor_subject="uuid-caller",
        operation="delete_group",
        reason="Permission denied to delete group 'x\x00y'",
        target_type="group",
        target_id="group:x\x00y",
        request_payload={"group_name": "x\x00y", "tags": ["a\x00"], "k\x00": 1},
    )

    assert logged is True
    entry = db.add.call_args.args[0]
    stored = repr(
        (
            entry.actor_subject,
            entry.operation,
            entry.target_type,
            entry.target_id,
            entry.request_payload,
            entry.result,
        )
    )
    assert "\x00" not in stored
    assert "\\x00" not in stored
    assert entry.target_id == "group:x\ufffdy"
    assert entry.request_payload == {
        "group_name": "x\ufffdy",
        "tags": ["a\ufffd"],
        "k\ufffd": 1,
    }


def test_audit_write_failure_is_logged_without_payload(caplog):
    db = MagicMock()
    db.commit.side_effect = RuntimeError("database unavailable")

    with caplog.at_level("WARNING", logger="app.services.audit"):
        logged = AuditService().log_authorization_denied(
            db=db,
            actor_subject="uuid-caller",
            operation="create_group",
            reason="Permission denied to create group 'g'",
            target_type="group",
            target_id="group:g",
            request_payload={"description": "synthetic-payload-marker"},
        )

    assert logged is False
    messages = [r for r in caplog.records if r.name == "app.services.audit"]
    assert len(messages) == 1
    assert "admin_audit" in messages[0].getMessage()
    assert "synthetic-payload-marker" not in caplog.text
