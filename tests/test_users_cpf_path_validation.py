"""``GET /users/{cpf}`` validates the CPF format it documents (DEV-793).

The route documented a ``422 Validation error - Invalid CPF format`` but declared
the path parameter as a bare ``str``: a malformed CPF went straight to
``get_user_by_subject`` and came back as 404 (or 403), never 422. The parameter
now carries the same ``^[0-9]{11}$`` pattern as ``UserResponse.cpf`` and the
membership subject, so a malformed value is refused before Cerbos and the
database are reached. Synthetic CPFs only.
"""

import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.database import get_db
from app.dependencies import get_current_user
from app.routers import users as users_router
from app.routers.users import CPF_PATTERN
from app.settings import settings

CALLER_CPF = "11111111111"
OTHER_CPF = "22222222222"

MALFORMED_CPFS = [
    "abcdefghijk",  # letters
    "111.111.111-11",  # punctuation
    "1111111111",  # 10 digits
    "111111111111",  # 12 digits
    "1111111111a",
    "1",
    "%20" + CALLER_CPF,  # leading whitespace
    CALLER_CPF + "%0A",  # trailing newline must not slip past "$"
    "١١١١١١١١١١١",  # Arabic-Indic digits are not ASCII digits
    "' OR '1'='1",
]


def _user(subject=CALLER_CPF, user_id=7, display_name="Caller"):
    user = MagicMock()
    user.subject = subject
    user.id = user_id
    user.display_name = display_name
    return user


@pytest.fixture(scope="module")
def main_app():
    """A fresh app.main (no lifespan, no I/O): its real router and 422 handler."""
    sys.modules.pop("app.main", None)
    with patch.object(settings, "validate"):
        module = importlib.import_module("app.main")
    sys.modules.pop("app.main", None)
    return module.app


@pytest.fixture
def wiring(main_app):
    caller = _user()
    db = MagicMock()
    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["go:cursos:editor"]
    user_service.get_user_groups.return_value = [{"name": "team:backend"}]
    user_service.get_user_by_subject.side_effect = lambda _db, cpf: (
        caller if cpf == CALLER_CPF else _user(OTHER_CPF, 8, "Other")
    )
    cerbos_service = MagicMock()
    cerbos_service.check_permission.return_value = False

    app = main_app
    app.dependency_overrides[get_current_user] = lambda: caller
    app.dependency_overrides[get_db] = lambda: db

    with (
        patch.object(users_router, "UserService", return_value=user_service),
        patch.object(users_router, "CerbosService", return_value=cerbos_service),
        patch("app.common.authz.AuditService") as audit_cls,
    ):
        yield {
            "client": TestClient(app),
            "user_service": user_service,
            "cerbos": cerbos_service,
            "audit": audit_cls.return_value.log_authorization_denied,
            "db": db,
        }
    app.dependency_overrides.clear()


@pytest.mark.parametrize("cpf", MALFORMED_CPFS)
def test_malformed_cpf_gets_the_documented_422_before_cerbos_and_lookup(wiring, cpf):
    response = wiring["client"].get(f"/api/v1/users/{cpf}")

    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "Validation error"
    assert body["details"][0]["loc"] == ["path", "cpf"]
    assert body["details"][0]["type"] == "string_pattern_mismatch"
    wiring["cerbos"].check_permission.assert_not_called()
    wiring["user_service"].get_user_by_subject.assert_not_called()
    wiring["audit"].assert_not_called()


@pytest.mark.parametrize("cpf", ["abcdefghijk", OTHER_CPF])
def test_unauthenticated_caller_gets_401_whatever_the_cpf_format(wiring, main_app, cpf):
    def _reject():
        raise HTTPException(status_code=401, detail="Could not validate credentials")

    main_app.dependency_overrides[get_current_user] = _reject

    response = wiring["client"].get(f"/api/v1/users/{cpf}")

    assert response.status_code == 401
    wiring["cerbos"].check_permission.assert_not_called()
    wiring["user_service"].get_user_by_subject.assert_not_called()


def test_own_well_formed_cpf_still_reads_the_record(wiring):
    response = wiring["client"].get(f"/api/v1/users/{CALLER_CPF}")

    assert response.status_code == 200
    assert response.json()["cpf"] == CALLER_CPF
    wiring["cerbos"].check_permission.assert_not_called()


def test_other_well_formed_cpf_without_permission_still_gets_403(wiring):
    response = wiring["client"].get(f"/api/v1/users/{OTHER_CPF}")

    assert response.status_code == 403
    assert OTHER_CPF not in response.text
    wiring["cerbos"].check_permission.assert_called_once()
    wiring["user_service"].get_user_by_subject.assert_not_called()


def test_me_route_is_not_caught_by_the_cpf_pattern(wiring):
    response = wiring["client"].get("/api/v1/users/me")

    assert response.status_code == 200


def test_openapi_documents_the_pattern_on_the_path_parameter():
    app = FastAPI()
    app.include_router(users_router.router, prefix="/api/v1/users")
    operation = app.openapi()["paths"]["/api/v1/users/{cpf}"]["get"]
    (param,) = [p for p in operation["parameters"] if p["name"] == "cpf"]

    assert CPF_PATTERN == "^[0-9]{11}$"
    assert param["in"] == "path"
    assert param["schema"]["pattern"] == CPF_PATTERN
    example = operation["responses"]["422"]["content"]["application/json"]["example"]
    assert example["error"] == "Validation error"
    assert example["details"][0]["loc"] == ["path", "cpf"]
    assert example["details"][0]["type"] == "string_pattern_mismatch"
