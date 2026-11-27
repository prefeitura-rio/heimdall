"""The dead runtime connectivity checks of app.settings are gone (DEV-804).

Settings.validate_runtime_connectivity() (with its five _test_*_connection
helpers and _log_connectivity_error) and the module-level get_env_var() had no
callers: startup only runs validate_environment(), which checks the format and
presence of the variables, and the readiness probe (/readyz) does its own
checks in app/routers/health.py.
"""

import pytest

import app.settings as settings_module
from app.settings import Settings


@pytest.mark.parametrize(
    "method",
    [
        "validate_runtime_connectivity",
        "_test_database_connection",
        "_test_redis_connection",
        "_test_cerbos_connection",
        "_test_keycloak_jwks_connection",
        "_test_otel_connection",
        "_log_connectivity_error",
    ],
)
def test_dead_connectivity_methods_are_removed(method):
    assert not hasattr(Settings, method)


def test_dead_get_env_var_is_removed():
    assert not hasattr(settings_module, "get_env_var")


@pytest.mark.parametrize("method", ["validate", "get_config_summary"])
def test_used_settings_methods_stay(method):
    assert callable(getattr(Settings, method, None))


def test_validate_environment_used_at_startup_stays():
    assert callable(getattr(settings_module, "validate_environment", None))
