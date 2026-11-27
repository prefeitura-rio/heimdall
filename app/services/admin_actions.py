"""
Expand phase of the reserved "heimdall:" admin action namespace (DEV-556).

The admin routes check "heimdall:<action>" instead of the legacy un-prefixed
names. On startup, each prefixed action that does not exist yet is created and
granted, once, to every role holding the legacy name, so delegated
administrators keep their access. An action that already exists is never
touched again: a later revocation of it is not undone on the next startup.

This runs at startup instead of as an Alembic revision so that a revert of
the deploy still boots: the previous code's `alembic upgrade head` would fail
on a revision it does not know.
"""

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.cerbos import ADMIN_ACTIONS, admin_action
from app.services.policy_version_tracker import PolicyVersionTracker

_CREATE_ACTION = text(
    "INSERT INTO actions (name, description) VALUES (:name, :description) "
    "ON CONFLICT (name) DO NOTHING RETURNING id"
)

_COPY_GRANTS = text(
    "INSERT INTO role_actions (role_id, action_id, granted_by) "
    "SELECT ra.role_id, :action_id, ra.granted_by "
    "FROM role_actions ra JOIN actions a ON a.id = ra.action_id "
    "WHERE a.name = :legacy_name "
    "ON CONFLICT DO NOTHING"
)


def backfill_admin_actions(db: Session) -> list[str]:
    """
    Create the missing "heimdall:" admin actions, copying the legacy grants.

    Returns the names created by this call. Concurrent replicas are safe: the
    unique name makes only one of them create (and copy) each action. The
    policy version is bumped when anything was created, so the reconciliation
    pushes the new principal policies.
    """
    created: list[str] = []
    try:
        for legacy_name in ADMIN_ACTIONS:
            name = admin_action(legacy_name)
            row = db.execute(
                _CREATE_ACTION,
                {
                    "name": name,
                    "description": f"Heimdall admin permission ({legacy_name})",
                },
            ).fetchone()
            if row is None:
                continue
            db.execute(_COPY_GRANTS, {"action_id": row[0], "legacy_name": legacy_name})
            created.append(name)
        db.commit()
    except Exception:
        db.rollback()
        raise

    if created:
        PolicyVersionTracker().increment_version(db)
    return created
