"""DELETE /roles/{name} audits the admin who deleted the role, not "system" (DEV-617)."""

import asyncio
from unittest.mock import MagicMock, patch

from app.routers.roles import delete_role
from app.services.role import RoleService


def _user(subject="uuid-admin-who-deleted", user_id=42):
    user = MagicMock()
    user.subject = subject
    user.id = user_id
    return user


def _service():
    with (
        patch("app.services.role.CerbosService"),
        patch("app.services.role.CacheService"),
        patch("app.services.role.AuditService"),
    ):
        service = RoleService()
    return service


def _db_with_role(role):
    db = MagicMock()
    query = db.query.return_value.filter.return_value
    query.first.return_value = role
    query.count.return_value = 2
    return db


def test_service_audits_the_deleting_admin_as_actor():
    service = _service()
    role = MagicMock()
    role.id = 9
    db = _db_with_role(role)
    admin = _user()

    assert service.delete_role(db, "data_analyst:read", deleted_by=admin) is True

    db.delete.assert_called_once_with(role)
    service.audit_service.log_role_operation.assert_called_once()
    kwargs = service.audit_service.log_role_operation.call_args.kwargs
    assert kwargs["actor_subject"] == "uuid-admin-who-deleted"
    assert kwargs["actor_subject"] != "system"
    assert kwargs["actor_user_id"] == 42
    assert kwargs["operation"] == "delete"
    assert kwargs["role_name"] == "data_analyst:read"
    assert kwargs["result"] == {"role_id": 9, "group_roles_removed": 2}
    assert kwargs["success"] is True


def test_service_actor_follows_whoever_deleted():
    service = _service()
    role = MagicMock()
    role.id = 3
    db = _db_with_role(role)

    service.delete_role(db, "x:y", deleted_by=_user(subject="uuid-other-admin", user_id=5))

    kwargs = service.audit_service.log_role_operation.call_args.kwargs
    assert kwargs["actor_subject"] == "uuid-other-admin"
    assert kwargs["actor_user_id"] == 5


def test_service_missing_role_deletes_nothing_and_writes_no_audit():
    service = _service()
    db = _db_with_role(None)

    assert service.delete_role(db, "ghost:role", deleted_by=_user()) is False

    db.delete.assert_not_called()
    db.commit.assert_not_called()
    service.audit_service.log_role_operation.assert_not_called()


def test_router_passes_the_authenticated_caller_as_deleter():
    role_service = MagicMock()
    role_service.get_role_by_name.return_value = MagicMock()
    role_service.get_groups_with_role.return_value = []
    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["role-admin"]
    cerbos_service = MagicMock()
    cerbos_service.check_permission.return_value = True
    caller = _user(subject="uuid-caller", user_id=7)
    db = MagicMock()

    with patch("app.services.policy_invalidator.invalidate_policy_version"):
        asyncio.run(
            delete_role(
                role_name="data_analyst:read",
                current_user=caller,
                db=db,
                role_service=role_service,
                cerbos_service=cerbos_service,
                user_service=user_service,
            )
        )

    role_service.delete_role.assert_called_once_with(
        db, "data_analyst:read", deleted_by=caller
    )
