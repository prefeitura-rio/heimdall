"""GET /users/ and GET /users/{cpf} check Cerbos before exposing any user (DEV-550)."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.database import get_db
from app.dependencies import get_current_user
from app.exceptions import CerbosUnavailableError
from app.routers import users as users_router
from app.routers.users import get_user_by_cpf, list_users
from app.services.cerbos import CerbosService

# Synthetic CPFs only (never real personal data in tests)
CALLER_CPF = "11111111111"
OTHER_CPF = "22222222222"


def _user(subject=CALLER_CPF, user_id=7, display_name="Caller"):
    user = MagicMock()
    user.subject = subject
    user.id = user_id
    user.display_name = display_name
    return user


def _user_service(target=None):
    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["go:cursos:editor"]
    user_service.get_user_groups.return_value = [{"name": "team:backend"}]
    user_service.get_user_by_subject.return_value = target
    return user_service


def _cerbos(allowed=None, error=None):
    cerbos_service = MagicMock()
    if error is not None:
        cerbos_service.check_permission.side_effect = error
    else:
        cerbos_service.check_permission.return_value = allowed
    return cerbos_service


def _db_with_users(users):
    db = MagicMock()
    query = db.query.return_value
    query.count.return_value = len(users)
    query.offset.return_value.limit.return_value.all.return_value = users
    return db


def _run(coro_factory):
    with patch("app.common.authz.AuditService") as audit_cls:
        try:
            result = asyncio.run(coro_factory())
        except HTTPException as exc:
            return None, exc, audit_cls.return_value.log_authorization_denied
        return result, None, audit_cls.return_value.log_authorization_denied


# GET /users/ ---------------------------------------------------------------


def _list(db, user_service, cerbos_service):
    return _run(
        lambda: list_users(
            current_user=_user(),
            db=db,
            user_service=user_service,
            cerbos_service=cerbos_service,
            skip=0,
            limit=50,
            has_groups=False,
        )
    )


def test_list_denied_caller_gets_audited_403_without_reading_users():
    db = _db_with_users([_user(OTHER_CPF, 8)])
    user_service = _user_service()
    cerbos_service = _cerbos(allowed=False)

    result, exc, audit = _list(db, user_service, cerbos_service)

    assert result is None
    assert exc.status_code == 403
    assert exc.detail == "Permission denied to list users"
    cerbos_service.check_permission.assert_called_once_with(
        caller_subject=CALLER_CPF,
        caller_roles=["go:cursos:editor"],
        action="user:list",
        resource_type="user",
        resource_attrs={},
    )
    audit.assert_called_once()
    assert audit.call_args.kwargs["operation"] == "list_users"
    assert audit.call_args.kwargs["target_type"] == "user"
    db.query.assert_not_called()
    user_service.get_user_groups.assert_not_called()


def test_list_allowed_caller_gets_the_page():
    db = _db_with_users([_user(OTHER_CPF, 8, "Other")])
    cerbos_service = _cerbos(allowed=True)

    result, exc, audit = _list(db, _user_service(), cerbos_service)

    assert exc is None
    audit.assert_not_called()
    assert result.total == 1
    assert [item.cpf for item in result.items] == [OTHER_CPF]
    assert result.items[0].roles == ["go:cursos:editor"]
    assert result.items[0].groups == ["team:backend"]


def test_list_with_cerbos_unavailable_never_returns_users():
    db = _db_with_users([_user(OTHER_CPF, 8)])
    cerbos_service = _cerbos(error=CerbosUnavailableError())

    with pytest.raises(CerbosUnavailableError):
        asyncio.run(
            list_users(
                current_user=_user(),
                db=db,
                user_service=_user_service(),
                cerbos_service=cerbos_service,
                skip=0,
                limit=50,
                has_groups=False,
            )
        )
    db.query.assert_not_called()


# GET /users/{cpf} ----------------------------------------------------------


def _get(cpf, user_service, cerbos_service, current_user=None):
    return _run(
        lambda: get_user_by_cpf(
            cpf=cpf,
            current_user=current_user or _user(),
            db=MagicMock(),
            user_service=user_service,
            cerbos_service=cerbos_service,
        )
    )


@pytest.mark.parametrize("target_exists", [True, False], ids=["existing", "missing"])
def test_get_other_denied_caller_gets_identical_403_before_lookup(target_exists):
    target = _user(OTHER_CPF, 8) if target_exists else None
    user_service = _user_service(target)
    cerbos_service = _cerbos(allowed=False)

    result, exc, audit = _get(OTHER_CPF, user_service, cerbos_service)

    assert result is None
    assert exc.status_code == 403
    assert exc.detail == "Permission denied to view this user"
    assert OTHER_CPF not in exc.detail
    cerbos_service.check_permission.assert_called_once_with(
        caller_subject=CALLER_CPF,
        caller_roles=["go:cursos:editor"],
        action="user:list",
        resource_type="user",
        resource_attrs={},
    )
    audit.assert_called_once()
    assert audit.call_args.kwargs["operation"] == "view_user"
    assert audit.call_args.kwargs["target_type"] == "user"
    assert OTHER_CPF not in repr(audit.call_args)
    user_service.get_user_by_subject.assert_not_called()


def test_get_other_allowed_caller_reads_the_user():
    user_service = _user_service(_user(OTHER_CPF, 8, "Other"))
    cerbos_service = _cerbos(allowed=True)

    result, exc, audit = _get(OTHER_CPF, user_service, cerbos_service)

    assert exc is None
    audit.assert_not_called()
    assert result.cpf == OTHER_CPF
    assert result.display_name == "Other"
    assert result.roles == ["go:cursos:editor"]


def test_get_other_allowed_caller_gets_404_for_missing_user():
    user_service = _user_service(None)
    cerbos_service = _cerbos(allowed=True)

    result, exc, audit = _get(OTHER_CPF, user_service, cerbos_service)

    assert result is None
    assert exc.status_code == 404
    audit.assert_not_called()


def test_get_own_record_needs_no_cerbos_permission():
    caller = _user()
    user_service = _user_service(caller)
    cerbos_service = _cerbos(allowed=False)

    result, exc, audit = _get(CALLER_CPF, user_service, cerbos_service, caller)

    assert exc is None
    assert result.cpf == CALLER_CPF
    cerbos_service.check_permission.assert_not_called()
    audit.assert_not_called()


def test_get_other_with_cerbos_unavailable_never_returns_the_user():
    user_service = _user_service(_user(OTHER_CPF, 8))
    cerbos_service = _cerbos(error=CerbosUnavailableError())

    with pytest.raises(CerbosUnavailableError):
        asyncio.run(
            get_user_by_cpf(
                cpf=OTHER_CPF,
                current_user=_user(),
                db=MagicMock(),
                user_service=user_service,
                cerbos_service=cerbos_service,
            )
        )
    user_service.get_user_by_subject.assert_not_called()


# HTTP wiring ---------------------------------------------------------------


@pytest.fixture
def client_factory():
    def _make(allowed):
        app = FastAPI()
        app.include_router(users_router.router, prefix="/api/v1/users")
        caller = _user()
        app.dependency_overrides[get_current_user] = lambda: caller
        app.dependency_overrides[get_db] = lambda: _db_with_users(
            [_user(OTHER_CPF, 8, "Other")]
        )
        user_service = _user_service(_user(OTHER_CPF, 8, "Other"))
        user_service.get_user_by_subject.side_effect = lambda _db, cpf: (
            caller if cpf == CALLER_CPF else _user(OTHER_CPF, 8, "Other")
        )
        cerbos_service = _cerbos(allowed=allowed)
        return app, user_service, cerbos_service

    return _make


@pytest.mark.parametrize(
    ("path", "allowed", "expected"),
    [
        ("/api/v1/users/", False, 403),
        ("/api/v1/users/", True, 200),
        (f"/api/v1/users/{OTHER_CPF}", False, 403),
        (f"/api/v1/users/{OTHER_CPF}", True, 200),
        (f"/api/v1/users/{CALLER_CPF}", False, 200),
        ("/api/v1/users/me", False, 200),
    ],
)
def test_http_routes_enforce_authorization(client_factory, path, allowed, expected):
    app, user_service, cerbos_service = client_factory(allowed)
    with (
        patch.object(users_router, "UserService", return_value=user_service),
        patch.object(users_router, "CerbosService", return_value=cerbos_service),
        patch("app.common.authz.AuditService"),
    ):
        response = TestClient(app).get(path)

    assert response.status_code == expected
    if expected == 403:
        assert OTHER_CPF not in response.text


# Real principal policies ----------------------------------------------------
# Heimdall grants every action of a caller's roles on every resource kind
# (principal policy with resource "*"). Application roles carry generic action
# names such as "user:read" (mapped to app routes), so the admin check on the
# user resource must not use an action an app role can hold by accident.
# Staging regression: the Editor — Cursos profile (app roles only) was denied
# GET /users/ but could read any other user, superadmins included.


def _policy_cerbos(role_actions):
    """Cerbos double that decides from the principal policy Heimdall builds."""
    from app.models import Action, Role

    def _session():
        session = MagicMock()

        def _query(model):
            query = MagicMock()
            if model is Role:
                def _role_filter(criterion):
                    name = criterion.right.value
                    role = MagicMock() if name in role_actions else None
                    if role is not None:
                        role.id = name
                    result = MagicMock()
                    result.first.return_value = role
                    return result

                query.filter.side_effect = _role_filter
            elif model is Action:
                def _action_filter(criterion):
                    role_id = criterion.right.value
                    actions = []
                    for name in role_actions.get(role_id, []):
                        action = MagicMock()
                        action.name = name
                        actions.append(action)
                    result = MagicMock()
                    result.all.return_value = actions
                    return result

                query.join.return_value.filter.side_effect = _action_filter
            return query

        session.query.side_effect = _query
        return session

    real = CerbosService.__new__(CerbosService)

    def _check(caller_subject, caller_roles, action, resource_type, **_resource):
        with patch("app.database.get_db_session", side_effect=_session):
            policy = real.build_principal_policy(caller_subject, caller_roles)
        effect = "EFFECT_DENY"
        for rule in policy["principalPolicy"]["rules"]:
            if rule["resource"] not in ("*", resource_type):
                continue
            for entry in rule["actions"]:
                if entry["action"] in ("*", action):
                    effect = entry["effect"]
        return effect == "EFFECT_ALLOW"

    cerbos_service = MagicMock()
    cerbos_service.check_permission.side_effect = _check
    return cerbos_service


APP_ROLE_ACTIONS = {"go:cursos:editor": ["cursos:edit", "user:read"]}


def test_app_role_with_generic_user_read_action_cannot_read_other_users():
    target = _user(OTHER_CPF, 8, "Superadmin")
    user_service = _user_service(target)
    cerbos_service = _policy_cerbos(APP_ROLE_ACTIONS)

    result, exc, _audit = _get(OTHER_CPF, user_service, cerbos_service)

    assert result is None
    assert exc.status_code == 403
    user_service.get_user_by_subject.assert_not_called()


def test_app_role_with_generic_user_read_action_cannot_list_users():
    db = _db_with_users([_user(OTHER_CPF, 8)])
    cerbos_service = _policy_cerbos(APP_ROLE_ACTIONS)

    result, exc, _audit = _list(db, _user_service(), cerbos_service)

    assert result is None
    assert exc.status_code == 403
    db.query.assert_not_called()


@pytest.mark.parametrize(
    ("roles", "role_actions"),
    [
        (["superadmin"], {}),
        (["user-admin"], {"user-admin": ["user:list"]}),
    ],
    ids=["superadmin", "role-with-user-list"],
)
def test_user_list_permission_reads_other_users(roles, role_actions):
    user_service = _user_service(_user(OTHER_CPF, 8, "Other"))
    user_service.get_user_roles.return_value = roles
    cerbos_service = _policy_cerbos(role_actions)

    result, exc, _audit = _get(OTHER_CPF, user_service, cerbos_service)

    assert exc is None
    assert result.cpf == OTHER_CPF
