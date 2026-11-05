"""Error classification in GET /groups/{group_name}/roles (DEV-303).

A missing group is signalled by GroupNotFoundError and answered with 404 by
its type; any other ValueError is a 400, whatever the text of its message.
"""

import asyncio
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.exceptions import (
    CerbosResponseError,
    CerbosUnavailableError,
    GroupNotFoundError,
)
from app.routers.roles import list_group_roles
from app.services.base import BaseService
from app.services.role import RoleService

CALLER = "uuid-caller-sintetico"
GROUP = "eng:backend"


def _user():
    user = MagicMock()
    user.subject = CALLER
    return user


def _user_service():
    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["some_role"]
    return user_service


def _cerbos(allowed=True):
    cerbos = MagicMock()
    cerbos.check_permission.return_value = allowed
    return cerbos


def _call(role_service, cerbos=None, db=None):
    return asyncio.run(
        list_group_roles(
            group_name=GROUP,
            current_user=_user(),
            db=db if db is not None else MagicMock(),
            role_service=role_service,
            cerbos_service=cerbos if cerbos is not None else _cerbos(),
            user_service=_user_service(),
        )
    )


def _service_raising(exc: Exception) -> MagicMock:
    service = MagicMock()
    service.list_group_roles.side_effect = exc
    return service


def _real_role_service() -> RoleService:
    service = RoleService.__new__(RoleService)
    BaseService.__init__(service, "role")
    return service


def _db_with_group(group):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = group
    return db


def test_group_not_found_error_becomes_404():
    with pytest.raises(HTTPException) as exc:
        _call(_service_raising(GroupNotFoundError(GROUP)))

    assert exc.value.status_code == 404
    assert exc.value.detail == f"Group '{GROUP}' not found"


@pytest.mark.parametrize(
    "message",
    ["policy not found", "Role 'x' NOT FOUND", "invalid group name"],
)
def test_value_error_is_400_regardless_of_text(message):
    """The router no longer classifies errors by the text of the message."""
    with pytest.raises(HTTPException) as exc:
        _call(_service_raising(ValueError(message)))

    assert exc.value.status_code == 400
    assert exc.value.detail == message


def test_cerbos_failure_in_service_is_not_turned_into_4xx():
    """A Cerbos failure escapes the router as a dependency error (503 handler)."""
    service = _service_raising(CerbosResponseError("Cerbos error: policy not found"))

    with pytest.raises(CerbosUnavailableError):
        _call(service)


def test_permission_denied_is_403_before_looking_up_the_group():
    """A caller without group:view_roles learns nothing about the group."""
    service = _service_raising(GroupNotFoundError(GROUP))
    db = MagicMock()

    with pytest.raises(HTTPException) as exc:
        _call(service, cerbos=_cerbos(allowed=False), db=db)

    assert exc.value.status_code == 403
    service.list_group_roles.assert_not_called()


def test_cerbos_unavailable_on_permission_check_propagates():
    cerbos = MagicMock()
    cerbos.check_permission.side_effect = CerbosUnavailableError(RuntimeError("down"))
    service = MagicMock()

    with pytest.raises(CerbosUnavailableError):
        _call(service, cerbos=cerbos)

    service.list_group_roles.assert_not_called()


def test_service_raises_group_not_found_error_for_missing_group():
    service = _real_role_service()

    with pytest.raises(GroupNotFoundError) as exc:
        service.list_group_roles(db=_db_with_group(None), group_name=GROUP)

    assert exc.value.group_name == GROUP
    assert not isinstance(exc.value, ValueError)


def test_missing_group_through_service_and_router_is_404():
    service = _real_role_service()

    with pytest.raises(HTTPException) as exc:
        _call(service, db=_db_with_group(None))

    assert exc.value.status_code == 404
    assert exc.value.detail == f"Group '{GROUP}' not found"


def test_existing_group_lists_roles():
    role = MagicMock()
    role.id = 7
    role.name = "viewer"
    role.description = "Read only"
    group = MagicMock()
    group.id = 3
    db = _db_with_group(group)
    (
        db.query.return_value.join.return_value.filter.return_value.order_by.return_value.all.return_value
    ) = [role]

    result = _call(_real_role_service(), db=db)

    assert [(r.id, r.name, r.description) for r in result] == [
        (7, "viewer", "Read only")
    ]
