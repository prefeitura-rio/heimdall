"""The dead statistics readers of the cache and the database monitor are gone (DEV-819).

CacheService.get_cache_stats() and DatabaseMonitor.check_database_health(),
suggest_optimizations(), get_performance_stats() and monitor_query() had no
callers: no router, script, CLI or test read those statistics, and the
readiness probe (/readyz) does its own checks in app/routers/health.py.
Startup keeps calling setup_database_monitoring(), which still tracks and logs
slow queries.
"""

import pytest

import app.services.database_monitor as database_monitor_module
from app.services.cache import CacheService
from app.services.database_monitor import DatabaseMonitor


def test_dead_get_cache_stats_is_removed():
    assert not hasattr(CacheService, "get_cache_stats")


def test_cache_health_check_stays():
    assert callable(getattr(CacheService, "health_check", None))


@pytest.mark.parametrize(
    "method",
    [
        "check_database_health",
        "suggest_optimizations",
        "get_performance_stats",
        "monitor_query",
    ],
)
def test_dead_database_monitor_methods_are_removed(method):
    assert not hasattr(DatabaseMonitor, method)


@pytest.mark.parametrize(
    "method", ["setup_monitoring", "_log_query_performance", "_sanitize_query"]
)
def test_used_database_monitor_methods_stay(method):
    assert callable(getattr(DatabaseMonitor, method, None))


def test_setup_database_monitoring_used_at_startup_stays():
    assert callable(getattr(database_monitor_module, "setup_database_monitoring", None))


def test_slow_queries_are_still_counted():
    monitor = DatabaseMonitor()
    monitor._log_query_performance("SELECT 1", monitor.slow_query_threshold + 1)
    monitor._log_query_performance("SELECT 1", 0.0)
    assert monitor.query_stats["total_queries"] == 2
    assert monitor.query_stats["slow_queries"] == 1
