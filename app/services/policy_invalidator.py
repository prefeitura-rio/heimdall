"""
Policy Invalidation Service

Provides a simple way to invalidate the policy version when data changes.
This triggers background reconciliation to sync changes to Cerbos.
"""

from sqlalchemy.orm import Session

from app.services.policy_version_tracker import PolicyVersionTracker


def invalidate_policy_version(db: Session) -> None:
    """
    Invalidate the current policy version to trigger reconciliation.

    This should be called whenever any policy-relevant data changes:
    - User operations (create, delete)
    - Group operations (create, delete)
    - Role operations (create, delete)
    - Action operations (create, delete)
    - Membership changes (add/remove users from groups)
    - Group-role assignments (assign/remove roles from groups)
    - Role-action assignments (assign/remove actions from roles)

    Args:
        db: Database session
    """
    try:
        version_tracker = PolicyVersionTracker()
        version_tracker.increment_version(db)
    except Exception:
        # Don't fail the main operation if version invalidation fails
        # The background job will still work, just less efficiently
        pass
