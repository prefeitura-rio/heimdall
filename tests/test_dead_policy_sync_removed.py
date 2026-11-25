"""The dead immediate policy sync of CerbosService is gone (DEV-792).

sync_affected_users_policies() and sync_group_users_policies() had no callers
since they were added. Role/action and membership changes reach Cerbos only
through the reconciliation job (reconcile_cerbos_policies), which pushes each
user's policy with push_user_policy()/delete_user_policy().
"""

import pytest

from app.services.cerbos import CerbosService


@pytest.mark.parametrize(
    "method", ["sync_affected_users_policies", "sync_group_users_policies"]
)
def test_dead_policy_sync_methods_are_removed(method):
    assert not hasattr(CerbosService, method)


@pytest.mark.parametrize(
    "method", ["push_user_policy", "delete_user_policy", "build_principal_policy"]
)
def test_policy_push_used_by_the_reconciliation_stays(method):
    assert callable(getattr(CerbosService, method, None))
