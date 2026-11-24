"""The dead sync-retry mechanism is gone (DEV-777).

Nothing ever wrote a FailedOperation row, so the scheduled retry_failed_syncs
job always found zero rows. Recovery from a failed Cerbos push is the
version-driven reconciliation (reconcile_cerbos_policies), which is the only
background job left.
"""

import importlib.util
from unittest.mock import MagicMock, patch

import pytest

from app import background_tasks
from app.settings import Settings


def _service() -> background_tasks.BackgroundTaskService:
    with (
        patch.object(background_tasks, "CerbosService"),
        patch.object(background_tasks, "UserService"),
        patch.object(background_tasks, "AuditService"),
        patch.object(background_tasks, "HealthMonitor"),
        patch.object(background_tasks, "CacheService"),
    ):
        return background_tasks.BackgroundTaskService()


def test_scheduler_only_runs_the_reconciliation():
    service = _service()
    service.scheduler = MagicMock()

    service.setup_scheduler()

    job_ids = [call.kwargs["id"] for call in service.scheduler.add_job.call_args_list]
    assert job_ids == ["reconcile_cerbos_policies"]
    service.health_monitor.start_monitoring.assert_called_once_with()


def test_retry_job_and_helper_are_removed():
    service = _service()

    assert not hasattr(service, "retry_failed_syncs")
    assert not hasattr(service, "_retry_operation")
    assert not hasattr(service, "sync_retry_interval")


@pytest.mark.parametrize(
    "module", ["app.services.failed_operation", "app.services.policy_change_detector"]
)
def test_dead_services_are_removed(module):
    assert importlib.util.find_spec(module) is None


def test_sync_retry_interval_setting_is_removed(monkeypatch):
    monkeypatch.setenv("SYNC_RETRY_INTERVAL_SECONDS", "5")
    settings = Settings()

    assert not hasattr(settings, "SYNC_RETRY_INTERVAL_SECONDS")
    assert not hasattr(settings, "get_sync_retry_interval")
    # A leftover value in the environment is ignored, not rejected: the old
    # 10..3600 range check would have failed validation on "5".
    assert not any(
        "SYNC_RETRY_INTERVAL_SECONDS" in error
        for error in settings._validate_numeric_values()
    )
    assert "SYNC_RETRY_INTERVAL_SECONDS" not in settings.get_config_summary()
