"""``GET /actions/{action_id}`` is admin-only and its OpenAPI says so (DEV-651).

The authorization gateway (Istio ext_authz + Cerbos) denies the read of an
action by id with 403 to any authenticated user who is not an admin, exactly
as it does for the listing (DEV-128). The published contract must not promise
that every authenticated user can read action information.
"""

from fastapi import FastAPI

from app.routers import actions


def _get_action_operation() -> dict:
    app = FastAPI()
    app.include_router(actions.router)
    return app.openapi()["paths"]["/{action_id}"]["get"]


def test_get_action_documents_admin_only_authorization():
    description = _get_action_operation()["description"]

    assert (
        "**Authorization**: Requires admin privileges to read actions." in description
    )
    assert "All authenticated users" not in description


def test_get_action_documents_forbidden_for_non_admins():
    responses = _get_action_operation()["responses"]

    assert "403" in responses
    assert "read actions" in responses["403"]["description"]
