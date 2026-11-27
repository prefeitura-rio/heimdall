"""The four listing endpoints are admin-only and their OpenAPI says so (DEV-128).

``GET /mappings/list``, ``GET /roles/``, ``GET /groups/`` and ``GET /actions/``
are restricted to admins by the authorization gateway (Istio ext_authz +
Cerbos): any other authenticated user gets a 403. The published contract must
not promise that every authenticated user can list them.
"""

import pytest
from fastapi import FastAPI

from app.routers import actions, groups, mappings, roles

LISTINGS = [
    (mappings.router, "/list", "mappings"),
    (roles.router, "/", "roles"),
    (groups.router, "/", "groups"),
    (actions.router, "/", "actions"),
]


def _list_operation(router, path: str) -> dict:
    app = FastAPI()
    app.include_router(router)
    return app.openapi()["paths"][path]["get"]


@pytest.mark.parametrize(("router", "path", "resource"), LISTINGS)
def test_listing_documents_admin_only_authorization(router, path, resource):
    operation = _list_operation(router, path)

    assert (
        f"**Authorization**: Requires admin privileges to list {resource}."
        in operation["description"]
    )
    assert "All authenticated users" not in operation["description"]


@pytest.mark.parametrize(("router", "path", "resource"), LISTINGS)
def test_listing_documents_forbidden_for_non_admins(router, path, resource):
    responses = _list_operation(router, path)["responses"]

    assert "403" in responses
    assert f"list {resource}" in responses["403"]["description"]
