"""
Environment configuration validation for Heimdall Admin Service.
Validates all required environment variables as specified in SPEC.md Section 4.
"""

import os
import re
from typing import Any
from urllib.parse import urlparse

import psycopg2
import redis
import requests

from app.logging_config import get_structured_logger
from app.settings import settings

logger = get_structured_logger(__name__)


class ConfigValidationError(Exception):
    """Raised when environment configuration validation fails."""

    pass


class Config:
    """Environment configuration validator and container."""

    def __init__(self):
        """Initialize and validate all environment configuration."""
        self.errors: list[str] = []
        self._validate_all()

        if self.errors:
            error_msg = "Environment configuration validation failed:\n" + "\n".join(
                f"  - {error}" for error in self.errors
            )
            logger.log_operation(
                level=50,  # ERROR
                message="Environment configuration validation failed",
                operation="config_validation",
                extra_fields={
                    "validation_errors": self.errors,
                    "total_errors": len(self.errors),
                },
            )
            raise ConfigValidationError(error_msg)

        logger.log_operation(
            level=20,  # INFO
            message="Environment configuration validation successful",
            operation="config_validation",
            extra_fields={
                "total_variables": len(self._get_all_variables()),
                "optional_variables_set": len(
                    [v for v in self._get_optional_variables() if os.getenv(v[0])]
                ),
            },
        )

    def _validate_all(self) -> None:
        """Validate all environment variables."""
        # Required variables
        self._validate_required_variables()

        # URL format validation
        self._validate_url_formats()

        # Database connection
        self._validate_database_config()

        # Redis configuration
        self._validate_redis_config()

        # JWT configuration
        self._validate_jwt_config()

        # Cerbos configuration
        self._validate_cerbos_config()

        # OpenTelemetry configuration
        self._validate_otel_config()

        # Numeric values
        self._validate_numeric_values()

    def _get_required_variables(self) -> list[tuple[str, str]]:
        """Get list of required environment variables with descriptions."""
        return [
            ("DATABASE_URL", "PostgreSQL database connection string"),
            ("CERBOS_BASE_URL", "Cerbos Base URL"),
            ("CERBOS_ADMIN_USER", "Cerbos Admin API username"),
            ("CERBOS_ADMIN_PASSWORD", "Cerbos Admin API password"),
            ("KEYCLOAK_JWKS_URL", "Keycloak JWKS endpoint URL"),
            ("JWT_ALGORITHM", "JWT signature algorithm"),
            ("JWT_AUDIENCE", "JWT audience claim"),
            ("KEYCLOAK_CLIENT_ID", "Keycloak client ID for role extraction"),
            ("STATIC_API_TOKEN", "Static API token for adapter authentication"),
        ]

    def _get_optional_variables(self) -> list[tuple[str, str, str]]:
        """Get list of optional environment variables with descriptions and defaults."""
        return [
            ("KEYCLOAK_ADMIN_ROLE", "Keycloak client role name that grants superadmin privileges", "heimdall-admin"),
            ("REDIS_URL", "Redis connection URL", "redis://redis:6379/0"),
            ("REDIS_MAPPING_TTL", "Mapping cache TTL in seconds", "60"),
            ("REDIS_USER_ROLES_TTL", "User roles cache TTL in seconds", "30"),
            ("REDIS_JWKS_TTL", "JWKS cache TTL in seconds", "300"),
            (
                "OTEL_EXPORTER_OTLP_ENDPOINT",
                "OpenTelemetry OTLP exporter endpoint (enables tracing)",
                "",
            ),
            (
                "OTEL_SERVICE_NAME",
                "OpenTelemetry service name",
                "heimdall-admin-service",
            ),
            ("OTEL_RESOURCE_ATTRIBUTES", "OpenTelemetry resource attributes", ""),
            ("RECONCILE_INTERVAL_SECONDS", "Background reconciliation interval (with UUID change detection)", "2"),
            ("SYNC_RETRY_INTERVAL_SECONDS", "Sync retry interval", "60"),
            ("HOST", "Server host address", "0.0.0.0"),
            ("PORT", "Server port", "8080"),
        ]

    def _get_all_variables(self) -> list[str]:
        """Get all environment variable names."""
        required = [var[0] for var in self._get_required_variables()]
        optional = [var[0] for var in self._get_optional_variables()]
        return required + optional

    def _validate_required_variables(self) -> None:
        """Validate that all required environment variables are present."""
        for var_name, description in self._get_required_variables():
            value = os.getenv(var_name)
            if not value:
                self.errors.append(
                    f"Required environment variable '{var_name}' is not set ({description})"
                )
            elif value.strip() == "":
                self.errors.append(
                    f"Required environment variable '{var_name}' is empty ({description})"
                )

    def _validate_url_formats(self) -> None:
        """Validate URL format for URL environment variables."""
        url_variables = [
            "CERBOS_BASE_URL",
            "KEYCLOAK_JWKS_URL",
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "REDIS_URL",
        ]

        for var_name in url_variables:
            value = os.getenv(var_name)
            if value:
                try:
                    parsed = urlparse(value)
                    if not parsed.scheme:
                        self.errors.append(
                            f"'{var_name}' must include URL scheme (http:// or https://): {value}"
                        )
                    if not parsed.netloc:
                        self.errors.append(
                            f"'{var_name}' must include host/netloc: {value}"
                        )

                    # Specific validations
                    if var_name == "KEYCLOAK_JWKS_URL" and parsed.scheme not in [
                        "http",
                        "https",
                    ]:
                        self.errors.append(
                            f"'{var_name}' must use http:// or https:// scheme: {value}"
                        )
                    if var_name == "REDIS_URL" and parsed.scheme != "redis":
                        self.errors.append(
                            f"'{var_name}' must use redis:// scheme: {value}"
                        )
                    if var_name == "CERBOS_BASE_URL" and parsed.scheme not in ["http", "https"]:
                        self.errors.append(
                            f"'{var_name}' must use http:// or https:// scheme: {value}"
                        )

                except Exception as e:
                    self.errors.append(
                        f"'{var_name}' is not a valid URL: {value} (error: {e})"
                    )

    def _validate_database_config(self) -> None:
        """Validate database connection string format."""
        db_url = settings.get_database_url()
        if db_url:
            try:
                parsed = urlparse(db_url)
                if parsed.scheme != "postgresql":
                    self.errors.append(
                        f"DATABASE_URL must use postgresql:// scheme: {db_url}"
                    )
                if not parsed.hostname:
                    self.errors.append(f"DATABASE_URL must include database host: {db_url}")
                if not parsed.path or parsed.path == "/":
                    self.errors.append(f"DATABASE_URL must include database name: {db_url}")
                if not parsed.username:
                    self.errors.append(f"DATABASE_URL must include username: {db_url}")
                # Note: password is optional for some PostgreSQL auth methods
            except Exception as e:
                self.errors.append(
                    f"DATABASE_URL is not a valid PostgreSQL connection string: {db_url} (error: {e})"
                )

    def _validate_redis_config(self) -> None:
        """Validate Redis configuration."""
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            try:
                parsed = urlparse(redis_url)
                if parsed.scheme != "redis":
                    self.errors.append(
                        f"REDIS_URL must use redis:// scheme: {redis_url}"
                    )
                if not parsed.hostname:
                    self.errors.append(
                        f"REDIS_URL must include Redis host: {redis_url}"
                    )
            except Exception as e:
                self.errors.append(
                    f"REDIS_URL is not a valid Redis connection string: {redis_url} (error: {e})"
                )

    def _validate_jwt_config(self) -> None:
        """Validate JWT configuration."""
        algorithm = os.getenv("JWT_ALGORITHM")
        if algorithm:
            valid_algorithms = [
                "RS256",
                "RS384",
                "RS512",
                "ES256",
                "ES384",
                "ES512",
                "HS256",
                "HS384",
                "HS512",
            ]
            if algorithm not in valid_algorithms:
                self.errors.append(
                    f"JWT_ALGORITHM must be one of {valid_algorithms}: {algorithm}"
                )

        audience = os.getenv("JWT_AUDIENCE")
        if audience and len(audience.strip()) == 0:
            self.errors.append("JWT_AUDIENCE cannot be empty string")

        client_id = os.getenv("KEYCLOAK_CLIENT_ID")
        if client_id and len(client_id.strip()) == 0:
            self.errors.append("KEYCLOAK_CLIENT_ID cannot be empty string")

    def _validate_cerbos_config(self) -> None:
        """Validate Cerbos configuration."""
        admin_user = os.getenv("CERBOS_ADMIN_USER")
        admin_password = os.getenv("CERBOS_ADMIN_PASSWORD")

        if admin_user and len(admin_user.strip()) == 0:
            self.errors.append("CERBOS_ADMIN_USER cannot be empty string")
        if admin_password and len(admin_password.strip()) == 0:
            self.errors.append("CERBOS_ADMIN_PASSWORD cannot be empty string")

    def _validate_otel_config(self) -> None:
        """Validate OpenTelemetry configuration."""
        service_name = os.getenv("OTEL_SERVICE_NAME")
        if service_name and not re.match(
            r"^[a-z0-9]([a-z0-9\-._]*[a-z0-9])?$", service_name
        ):
            self.errors.append(
                f"OTEL_SERVICE_NAME should follow naming conventions (lowercase, alphanumeric, hyphens, dots, underscores): {service_name}"
            )

        resource_attrs = os.getenv("OTEL_RESOURCE_ATTRIBUTES")
        if resource_attrs:
            # Validate format: key1=value1,key2=value2
            try:
                pairs = resource_attrs.split(",")
                for pair in pairs:
                    if "=" not in pair:
                        self.errors.append(
                            f"OTEL_RESOURCE_ATTRIBUTES must be in format 'key=value,key2=value2': {resource_attrs}"
                        )
                        break
            except Exception:
                self.errors.append(
                    f"OTEL_RESOURCE_ATTRIBUTES format validation failed: {resource_attrs}"
                )

    def _validate_numeric_values(self) -> None:
        """Validate numeric environment variables."""
        numeric_vars = [
            ("REDIS_MAPPING_TTL", 1, 86400),  # 1 second to 1 day
            ("REDIS_USER_ROLES_TTL", 1, 3600),  # 1 second to 1 hour
            ("REDIS_JWKS_TTL", 60, 86400),  # 1 minute to 1 day
            ("RECONCILE_INTERVAL_SECONDS", 1, 86400),  # 1 second to 1 day (UUID change detection allows very frequent checks)
            ("SYNC_RETRY_INTERVAL_SECONDS", 10, 3600),  # 10 seconds to 1 hour
            ("PORT", 1, 65535),  # Valid port range
        ]

        for var_name, min_val, max_val in numeric_vars:
            value = os.getenv(var_name)
            if value:
                try:
                    num_value = int(value)
                    if num_value < min_val or num_value > max_val:
                        self.errors.append(
                            f"'{var_name}' must be between {min_val} and {max_val}: {value}"
                        )
                except ValueError:
                    self.errors.append(f"'{var_name}' must be a valid integer: {value}")

    def get_config_summary(self) -> dict[str, Any]:
        """Get a summary of the current configuration (safe for logging)."""
        config_summary = {}

        # Required variables (mask sensitive values)
        for var_name, _ in self._get_required_variables():
            value = os.getenv(var_name)
            if value:
                if "password" in var_name.lower() or "token" in var_name.lower():
                    config_summary[var_name] = "***MASKED***"
                elif "url" in var_name.lower():
                    # Show URL without credentials
                    try:
                        parsed = urlparse(value)
                        safe_url = f"{parsed.scheme}://{parsed.hostname}"
                        if parsed.port:
                            safe_url += f":{parsed.port}"
                        if parsed.path:
                            safe_url += parsed.path
                        config_summary[var_name] = safe_url
                    except Exception:
                        config_summary[var_name] = "***PARSE_ERROR***"
                else:
                    config_summary[var_name] = value
            else:
                config_summary[var_name] = "***NOT_SET***"

        # Optional variables with defaults
        for var_name, _, default in self._get_optional_variables():
            value = os.getenv(var_name, default)
            config_summary[var_name] = value

        return config_summary

    def validate_runtime_connectivity(self) -> dict[str, bool]:
        """
        Validate runtime connectivity to external services.
        Returns dict of service -> connectivity status.
        """
        connectivity_status = {}

        # Test database connection
        connectivity_status["database"] = self._test_database_connection()

        # Test Redis connection
        connectivity_status["redis"] = self._test_redis_connection()

        # Test Cerbos connection
        connectivity_status["cerbos"] = self._test_cerbos_connection()

        # Test Keycloak JWKS endpoint
        connectivity_status["keycloak_jwks"] = self._test_keycloak_jwks_connection()

        # Test OTEL collector (if configured)
        connectivity_status["otel_collector"] = self._test_otel_connection()

        return connectivity_status

    def _test_database_connection(self) -> bool:
        """Test PostgreSQL database connectivity."""
        try:
            db_url = settings.get_database_url()
            if not db_url:
                return False

            # Parse URL and test connection
            conn = psycopg2.connect(db_url)
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            conn.close()
            return True

        except Exception as e:
            logger.log_operation(
                level=30,  # WARNING
                message="Database connectivity test failed",
                operation="connectivity_test_database",
                extra_fields={"error": str(e), "exception_type": type(e).__name__},
            )
            return False

    def _test_redis_connection(self) -> bool:
        """Test Redis connectivity."""
        try:
            redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")

            # Create Redis client and test connection
            r = redis.from_url(redis_url)
            r.ping()
            r.close()
            return True

        except Exception as e:
            logger.log_operation(
                level=30,  # WARNING
                message="Redis connectivity test failed",
                operation="connectivity_test_redis",
                extra_fields={"error": str(e), "exception_type": type(e).__name__},
            )
            return False

    def _test_cerbos_connection(self) -> bool:
        """Test Cerbos connectivity."""
        try:
            cerbos_base_url = os.getenv("CERBOS_BASE_URL")
            if not cerbos_base_url:
                return False

            # Test Cerbos health endpoint
            health_url = f"{cerbos_base_url.rstrip('/')}/api/cerbos/version"
            response = requests.get(health_url, timeout=5)
            response.raise_for_status()
            return True

        except Exception as e:
            logger.log_operation(
                level=30,  # WARNING
                message="Cerbos connectivity test failed",
                operation="connectivity_test_cerbos",
                extra_fields={"error": str(e), "exception_type": type(e).__name__},
            )
            return False

    def _test_keycloak_jwks_connection(self) -> bool:
        """Test Keycloak JWKS endpoint connectivity."""
        try:
            jwks_url = os.getenv("KEYCLOAK_JWKS_URL")
            if not jwks_url:
                return False

            # Test JWKS endpoint
            response = requests.get(jwks_url, timeout=5)
            response.raise_for_status()

            # Verify it returns valid JSON with keys
            jwks_data = response.json()
            return "keys" in jwks_data

        except Exception as e:
            logger.log_operation(
                level=30,  # WARNING
                message="Keycloak JWKS connectivity test failed",
                operation="connectivity_test_keycloak_jwks",
                extra_fields={"error": str(e), "exception_type": type(e).__name__},
            )
            return False

    def _test_otel_connection(self) -> bool:
        """Test OpenTelemetry collector connectivity."""
        try:
            otel_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
            if not otel_endpoint:
                # OTEL is optional, so return True if not configured
                return True

            # Test OTEL collector endpoint (usually HTTP)
            # Note: This is a basic connectivity test, not a full OTLP export
            response = requests.get(otel_endpoint, timeout=5)
            # Don't raise_for_status() as OTEL endpoints may return different codes
            return response.status_code < 500

        except Exception as e:
            logger.log_operation(
                level=30,  # WARNING
                message="OTEL collector connectivity test failed",
                operation="connectivity_test_otel",
                extra_fields={"error": str(e), "exception_type": type(e).__name__},
            )
            return False


# Global configuration instance
_config_instance: Config | None = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance


def validate_environment() -> None:
    """Validate environment configuration and raise if invalid."""
    get_config()  # This will validate and raise if invalid


def get_env_var(
    name: str, default: str | None = None, required: bool = False
) -> str | None:
    """
    Get environment variable with validation.

    Args:
        name: Environment variable name
        default: Default value if not set
        required: Whether the variable is required

    Returns:
        Environment variable value or default

    Raises:
        ConfigValidationError: If required variable is not set
    """
    value = os.getenv(name, default)

    if required and not value:
        raise ConfigValidationError(
            f"Required environment variable '{name}' is not set"
        )

    return value
