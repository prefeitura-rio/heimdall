"""
Centralized configuration settings for Heimdall Admin Service.
All environment variables are defined, accessed, and validated through this module.
"""

import os
import re
from typing import Any
from urllib.parse import urlparse

import psycopg2
import redis
import requests


class ConfigValidationError(Exception):
    """Raised when environment configuration validation fails."""

    pass


class Settings:
    """Centralized configuration settings with validation."""

    def __init__(self):
        """Initialize settings from environment variables."""
        # Database Configuration
        self.DATABASE_URL: str = os.getenv(
            "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/heimdall_dev"
        )
        self.SQL_DEBUG: bool = os.getenv("SQL_DEBUG", "false").lower() == "true"

        # Cerbos Authorization Service
        self.CERBOS_BASE_URL: str = os.getenv("CERBOS_BASE_URL", "http://localhost:3592")
        self.CERBOS_ADMIN_USER: str = os.getenv("CERBOS_ADMIN_USER", "cerbos")
        self.CERBOS_ADMIN_PASSWORD: str = os.getenv("CERBOS_ADMIN_PASSWORD", "cerbos")

        # Keycloak Authentication
        self.KEYCLOAK_JWKS_URL: str | None = os.getenv("KEYCLOAK_JWKS_URL")
        self.KEYCLOAK_CLIENT_ID: str = os.getenv("KEYCLOAK_CLIENT_ID", "superapp")
        self.KEYCLOAK_ADMIN_ROLE: str = os.getenv("KEYCLOAK_ADMIN_ROLE", "heimdall-admin")

        # JWT Configuration
        self.JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "RS256")
        self.JWT_AUDIENCE: str | None = os.getenv("JWT_AUDIENCE")

        # Static API Token
        self.STATIC_API_TOKEN: str | None = os.getenv("STATIC_API_TOKEN")

        # Redis Caching
        self.REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.REDIS_MAPPING_TTL: int = int(os.getenv("REDIS_MAPPING_TTL", "60"))
        self.REDIS_USER_ROLES_TTL: int = int(os.getenv("REDIS_USER_ROLES_TTL", "30"))
        self.REDIS_JWKS_TTL: int = int(os.getenv("REDIS_JWKS_TTL", "300"))

        # Redis Sentinel (optional for HA)
        self.REDIS_SENTINEL_HOSTS: str = os.getenv("REDIS_SENTINEL_HOSTS", "")
        self.REDIS_SENTINEL_SERVICE_NAME: str = os.getenv("REDIS_SENTINEL_SERVICE_NAME", "mymaster")
        self.REDIS_PASSWORD: str = os.getenv("REDIS_PASSWORD", "")

        # Background Task Configuration
        self.RECONCILE_INTERVAL_SECONDS: int = int(os.getenv("RECONCILE_INTERVAL_SECONDS", "300"))
        self.SYNC_RETRY_INTERVAL_SECONDS: int = int(os.getenv("SYNC_RETRY_INTERVAL_SECONDS", "60"))

        # Server Configuration
        self.HOST: str = os.getenv("HOST", "0.0.0.0")
        self.PORT: int = int(os.getenv("PORT", "8080"))

        # OpenTelemetry Tracing
        self.OTEL_SERVICE_NAME: str = os.getenv("OTEL_SERVICE_NAME", "heimdall-admin-service")
        self.OTEL_EXPORTER_OTLP_ENDPOINT: str | None = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        self.OTEL_RESOURCE_ATTRIBUTES: str | None = os.getenv("OTEL_RESOURCE_ATTRIBUTES")

    @property
    def DATABASE_DSN(self) -> str:
        """Alias for DATABASE_URL for backward compatibility."""
        return self.DATABASE_URL

    def get_database_url(self) -> str:
        """Get the database connection URL."""
        return self.DATABASE_URL

    def get_redis_url(self) -> str:
        """Get the Redis connection URL."""
        return self.REDIS_URL

    def get_redis_sentinel_hosts(self) -> list[tuple[str, int]] | None:
        """Get Redis Sentinel hosts for HA setup."""
        if not self.REDIS_SENTINEL_HOSTS:
            return None

        hosts = []
        for host_port in self.REDIS_SENTINEL_HOSTS.split(","):
            host_port = host_port.strip()
            if ":" in host_port:
                host, port = host_port.split(":", 1)
                hosts.append((host.strip(), int(port.strip())))
            else:
                hosts.append((host_port, 26379))  # Default Sentinel port
        return hosts

    def get_redis_sentinel_service_name(self) -> str:
        """Get Redis Sentinel service name."""
        return self.REDIS_SENTINEL_SERVICE_NAME

    def get_redis_password(self) -> str | None:
        """Get Redis password."""
        return self.REDIS_PASSWORD if self.REDIS_PASSWORD else None

    def get_cerbos_base_url(self) -> str:
        """Get the Cerbos base URL."""
        return self.CERBOS_BASE_URL

    def get_keycloak_jwks_url(self) -> str | None:
        """Get the Keycloak JWKS URL."""
        return self.KEYCLOAK_JWKS_URL

    def is_debug_mode(self) -> bool:
        """Check if SQL debug mode is enabled."""
        return self.SQL_DEBUG

    def get_reconcile_interval(self) -> int:
        """Get the reconciliation interval in seconds."""
        return self.RECONCILE_INTERVAL_SECONDS

    def get_sync_retry_interval(self) -> int:
        """Get the sync retry interval in seconds."""
        return self.SYNC_RETRY_INTERVAL_SECONDS

    def validate(self) -> None:
        """
        Validate all environment configuration.
        Raises ConfigValidationError if validation fails.
        """
        errors: list[str] = []

        # Required variables validation
        errors.extend(self._validate_required_variables())

        # URL format validation
        errors.extend(self._validate_url_formats())

        # Database connection validation
        errors.extend(self._validate_database_config())

        # Redis configuration validation
        errors.extend(self._validate_redis_config())

        # JWT configuration validation
        errors.extend(self._validate_jwt_config())

        # Cerbos configuration validation
        errors.extend(self._validate_cerbos_config())

        # OpenTelemetry configuration validation
        errors.extend(self._validate_otel_config())

        # Numeric values validation
        errors.extend(self._validate_numeric_values())

        if errors:
            error_msg = "Environment configuration validation failed:\n" + "\n".join(
                f"  - {error}" for error in errors
            )
            self._log_validation_result(False, errors)
            raise ConfigValidationError(error_msg)

        self._log_validation_result(True, [])

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

    def _validate_required_variables(self) -> list[str]:
        """Validate that all required environment variables are present."""
        errors = []
        for var_name, description in self._get_required_variables():
            value = getattr(self, var_name.replace("DATABASE_URL", "DATABASE_URL"), None)
            if var_name == "DATABASE_URL":
                value = self.DATABASE_URL
            elif var_name == "CERBOS_BASE_URL":
                value = self.CERBOS_BASE_URL
            elif var_name == "CERBOS_ADMIN_USER":
                value = self.CERBOS_ADMIN_USER
            elif var_name == "CERBOS_ADMIN_PASSWORD":
                value = self.CERBOS_ADMIN_PASSWORD
            elif var_name == "KEYCLOAK_JWKS_URL":
                value = self.KEYCLOAK_JWKS_URL
            elif var_name == "JWT_ALGORITHM":
                value = self.JWT_ALGORITHM
            elif var_name == "JWT_AUDIENCE":
                value = self.JWT_AUDIENCE
            elif var_name == "KEYCLOAK_CLIENT_ID":
                value = self.KEYCLOAK_CLIENT_ID
            elif var_name == "STATIC_API_TOKEN":
                value = self.STATIC_API_TOKEN

            if not value:
                errors.append(
                    f"Required environment variable '{var_name}' is not set ({description})"
                )
            elif isinstance(value, str) and value.strip() == "":
                errors.append(
                    f"Required environment variable '{var_name}' is empty ({description})"
                )
        return errors

    def _validate_url_formats(self) -> list[str]:
        """Validate URL format for URL environment variables."""
        errors = []
        url_variables = [
            ("CERBOS_BASE_URL", self.CERBOS_BASE_URL),
            ("KEYCLOAK_JWKS_URL", self.KEYCLOAK_JWKS_URL),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", self.OTEL_EXPORTER_OTLP_ENDPOINT),
            ("REDIS_URL", self.REDIS_URL),
        ]

        for var_name, value in url_variables:
            if value:
                try:
                    parsed = urlparse(value)
                    if not parsed.scheme:
                        errors.append(
                            f"'{var_name}' must include URL scheme (http:// or https://): {value}"
                        )
                    if not parsed.netloc:
                        errors.append(
                            f"'{var_name}' must include host/netloc: {value}"
                        )

                    # Specific validations
                    if var_name == "KEYCLOAK_JWKS_URL" and parsed.scheme not in [
                        "http",
                        "https",
                    ]:
                        errors.append(
                            f"'{var_name}' must use http:// or https:// scheme: {value}"
                        )
                    if var_name == "REDIS_URL" and parsed.scheme != "redis":
                        errors.append(
                            f"'{var_name}' must use redis:// scheme: {value}"
                        )
                    if var_name == "CERBOS_BASE_URL" and parsed.scheme not in ["http", "https"]:
                        errors.append(
                            f"'{var_name}' must use http:// or https:// scheme: {value}"
                        )

                except Exception as e:
                    errors.append(
                        f"'{var_name}' is not a valid URL: {value} (error: {e})"
                    )
        return errors

    def _validate_database_config(self) -> list[str]:
        """Validate database connection string format."""
        errors = []
        db_url = self.DATABASE_URL
        if db_url:
            try:
                parsed = urlparse(db_url)
                if parsed.scheme != "postgresql":
                    errors.append(
                        f"DATABASE_URL must use postgresql:// scheme: {db_url}"
                    )
                if not parsed.hostname:
                    errors.append(f"DATABASE_URL must include database host: {db_url}")
                if not parsed.path or parsed.path == "/":
                    errors.append(f"DATABASE_URL must include database name: {db_url}")
                if not parsed.username:
                    errors.append(f"DATABASE_URL must include username: {db_url}")
                # Note: password is optional for some PostgreSQL auth methods
            except Exception as e:
                errors.append(
                    f"DATABASE_URL is not a valid PostgreSQL connection string: {db_url} (error: {e})"
                )
        return errors

    def _validate_redis_config(self) -> list[str]:
        """Validate Redis configuration."""
        errors = []
        redis_url = self.REDIS_URL
        if redis_url:
            try:
                parsed = urlparse(redis_url)
                if parsed.scheme != "redis":
                    errors.append(
                        f"REDIS_URL must use redis:// scheme: {redis_url}"
                    )
                if not parsed.hostname:
                    errors.append(
                        f"REDIS_URL must include Redis host: {redis_url}"
                    )
            except Exception as e:
                errors.append(
                    f"REDIS_URL is not a valid Redis connection string: {redis_url} (error: {e})"
                )
        return errors

    def _validate_jwt_config(self) -> list[str]:
        """Validate JWT configuration."""
        errors = []
        algorithm = self.JWT_ALGORITHM
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
                errors.append(
                    f"JWT_ALGORITHM must be one of {valid_algorithms}: {algorithm}"
                )

        audience = self.JWT_AUDIENCE
        if audience and len(audience.strip()) == 0:
            errors.append("JWT_AUDIENCE cannot be empty string")

        client_id = self.KEYCLOAK_CLIENT_ID
        if client_id and len(client_id.strip()) == 0:
            errors.append("KEYCLOAK_CLIENT_ID cannot be empty string")

        return errors

    def _validate_cerbos_config(self) -> list[str]:
        """Validate Cerbos configuration."""
        errors = []
        admin_user = self.CERBOS_ADMIN_USER
        admin_password = self.CERBOS_ADMIN_PASSWORD

        if admin_user and len(admin_user.strip()) == 0:
            errors.append("CERBOS_ADMIN_USER cannot be empty string")
        if admin_password and len(admin_password.strip()) == 0:
            errors.append("CERBOS_ADMIN_PASSWORD cannot be empty string")

        return errors

    def _validate_otel_config(self) -> list[str]:
        """Validate OpenTelemetry configuration."""
        errors = []
        service_name = self.OTEL_SERVICE_NAME
        if service_name and not re.match(
            r"^[a-z0-9]([a-z0-9\-._]*[a-z0-9])?$", service_name
        ):
            errors.append(
                f"OTEL_SERVICE_NAME should follow naming conventions (lowercase, alphanumeric, hyphens, dots, underscores): {service_name}"
            )

        resource_attrs = self.OTEL_RESOURCE_ATTRIBUTES
        if resource_attrs:
            # Validate format: key1=value1,key2=value2
            try:
                pairs = resource_attrs.split(",")
                for pair in pairs:
                    if "=" not in pair:
                        errors.append(
                            f"OTEL_RESOURCE_ATTRIBUTES must be in format 'key=value,key2=value2': {resource_attrs}"
                        )
                        break
            except Exception:
                errors.append(
                    f"OTEL_RESOURCE_ATTRIBUTES format validation failed: {resource_attrs}"
                )

        return errors

    def _validate_numeric_values(self) -> list[str]:
        """Validate numeric environment variables."""
        errors = []
        numeric_vars = [
            ("REDIS_MAPPING_TTL", self.REDIS_MAPPING_TTL, 1, 86400),  # 1 second to 1 day
            ("REDIS_USER_ROLES_TTL", self.REDIS_USER_ROLES_TTL, 1, 3600),  # 1 second to 1 hour
            ("REDIS_JWKS_TTL", self.REDIS_JWKS_TTL, 60, 86400),  # 1 minute to 1 day
            ("RECONCILE_INTERVAL_SECONDS", self.RECONCILE_INTERVAL_SECONDS, 1, 86400),  # 1 second to 1 day (UUID change detection allows very frequent checks)
            ("SYNC_RETRY_INTERVAL_SECONDS", self.SYNC_RETRY_INTERVAL_SECONDS, 10, 3600),  # 10 seconds to 1 hour
            ("PORT", self.PORT, 1, 65535),  # Valid port range
        ]

        for var_name, value, min_val, max_val in numeric_vars:
            if value is not None:
                try:
                    if value < min_val or value > max_val:
                        errors.append(
                            f"'{var_name}' must be between {min_val} and {max_val}: {value}"
                        )
                except (ValueError, TypeError):
                    errors.append(f"'{var_name}' must be a valid integer: {value}")

        return errors

    def _log_validation_result(self, success: bool, errors: list[str]) -> None:
        """Log validation result using structured logging if available."""
        try:
            from app.logging_config import get_structured_logger
            logger = get_structured_logger(__name__)

            if success:
                logger.log_operation(
                    level=20,  # INFO
                    message="Environment configuration validation successful",
                    operation="config_validation",
                    extra_fields={
                        "total_variables": len(self._get_required_variables()) + len(self._get_optional_variables()),
                        "optional_variables_set": len(
                            [v for v in self._get_optional_variables() if getattr(self, v[0].replace("OTEL_", "OTEL_").replace("RECONCILE_", "RECONCILE_").replace("SYNC_", "SYNC_").replace("REDIS_", "REDIS_").replace("KEYCLOAK_", "KEYCLOAK_"), None)]
                        ),
                    },
                )
            else:
                logger.log_operation(
                    level=50,  # ERROR
                    message="Environment configuration validation failed",
                    operation="config_validation",
                    extra_fields={
                        "validation_errors": errors,
                        "total_errors": len(errors),
                    },
                )
        except ImportError:
            # Fallback to basic logging if structured logging not available
            import logging
            logging.basicConfig(level=logging.INFO)
            logger = logging.getLogger(__name__)
            if success:
                logger.info("Environment configuration validation successful")
            else:
                logger.error(f"Environment configuration validation failed: {errors}")

    def get_config_summary(self) -> dict[str, Any]:
        """Get a summary of the current configuration (safe for logging)."""
        config_summary = {}

        # Required variables (mask sensitive values)
        for var_name, _ in self._get_required_variables():
            if var_name == "DATABASE_URL":
                value = self.DATABASE_URL
            elif var_name == "CERBOS_BASE_URL":
                value = self.CERBOS_BASE_URL
            elif var_name == "CERBOS_ADMIN_USER":
                value = self.CERBOS_ADMIN_USER
            elif var_name == "CERBOS_ADMIN_PASSWORD":
                value = self.CERBOS_ADMIN_PASSWORD
            elif var_name == "KEYCLOAK_JWKS_URL":
                value = self.KEYCLOAK_JWKS_URL
            elif var_name == "JWT_ALGORITHM":
                value = self.JWT_ALGORITHM
            elif var_name == "JWT_AUDIENCE":
                value = self.JWT_AUDIENCE
            elif var_name == "KEYCLOAK_CLIENT_ID":
                value = self.KEYCLOAK_CLIENT_ID
            elif var_name == "STATIC_API_TOKEN":
                value = self.STATIC_API_TOKEN
            else:
                value = None

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
        optional_vars_values = {
            "KEYCLOAK_ADMIN_ROLE": self.KEYCLOAK_ADMIN_ROLE,
            "REDIS_URL": self.REDIS_URL,
            "REDIS_MAPPING_TTL": self.REDIS_MAPPING_TTL,
            "REDIS_USER_ROLES_TTL": self.REDIS_USER_ROLES_TTL,
            "REDIS_JWKS_TTL": self.REDIS_JWKS_TTL,
            "OTEL_EXPORTER_OTLP_ENDPOINT": self.OTEL_EXPORTER_OTLP_ENDPOINT,
            "OTEL_SERVICE_NAME": self.OTEL_SERVICE_NAME,
            "OTEL_RESOURCE_ATTRIBUTES": self.OTEL_RESOURCE_ATTRIBUTES,
            "RECONCILE_INTERVAL_SECONDS": self.RECONCILE_INTERVAL_SECONDS,
            "SYNC_RETRY_INTERVAL_SECONDS": self.SYNC_RETRY_INTERVAL_SECONDS,
            "HOST": self.HOST,
            "PORT": self.PORT,
        }

        for var_name, _, default in self._get_optional_variables():
            value = optional_vars_values.get(var_name, default)
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
            db_url = self.DATABASE_URL
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
            self._log_connectivity_error("database", e)
            return False

    def _test_redis_connection(self) -> bool:
        """Test Redis connectivity."""
        try:
            redis_url = self.REDIS_URL

            # Create Redis client and test connection
            r = redis.from_url(redis_url)
            r.ping()
            r.close()
            return True

        except Exception as e:
            self._log_connectivity_error("redis", e)
            return False

    def _test_cerbos_connection(self) -> bool:
        """Test Cerbos connectivity."""
        try:
            cerbos_base_url = self.CERBOS_BASE_URL
            if not cerbos_base_url:
                return False

            # Test Cerbos health endpoint
            health_url = f"{cerbos_base_url.rstrip('/')}/api/cerbos/version"
            response = requests.get(health_url, timeout=5)
            response.raise_for_status()
            return True

        except Exception as e:
            self._log_connectivity_error("cerbos", e)
            return False

    def _test_keycloak_jwks_connection(self) -> bool:
        """Test Keycloak JWKS endpoint connectivity."""
        try:
            jwks_url = self.KEYCLOAK_JWKS_URL
            if not jwks_url:
                return False

            # Test JWKS endpoint
            response = requests.get(jwks_url, timeout=5)
            response.raise_for_status()

            # Verify it returns valid JSON with keys
            jwks_data = response.json()
            return "keys" in jwks_data

        except Exception as e:
            self._log_connectivity_error("keycloak_jwks", e)
            return False

    def _test_otel_connection(self) -> bool:
        """Test OpenTelemetry collector connectivity."""
        try:
            otel_endpoint = self.OTEL_EXPORTER_OTLP_ENDPOINT
            if not otel_endpoint:
                # OTEL is optional, so return True if not configured
                return True

            # Test OTEL collector endpoint (usually HTTP)
            # Note: This is a basic connectivity test, not a full OTLP export
            response = requests.get(otel_endpoint, timeout=5)
            # Don't raise_for_status() as OTEL endpoints may return different codes
            return response.status_code < 500

        except Exception as e:
            self._log_connectivity_error("otel_collector", e)
            return False

    def _log_connectivity_error(self, service: str, error: Exception) -> None:
        """Log connectivity errors using structured logging if available."""
        try:
            from app.logging_config import get_structured_logger
            logger = get_structured_logger(__name__)
            logger.log_operation(
                level=30,  # WARNING
                message=f"{service.title()} connectivity test failed",
                operation=f"connectivity_test_{service}",
                extra_fields={"error": str(error), "exception_type": type(error).__name__},
            )
        except ImportError:
            # Fallback to basic logging if structured logging not available
            import logging
            logging.basicConfig(level=logging.INFO)
            logger = logging.getLogger(__name__)
            logger.warning(f"{service} connectivity test failed: {error}")


# Global settings instance
settings = Settings()


# Convenience functions for backward compatibility
def validate_environment() -> None:
    """Validate environment configuration and raise if invalid."""
    settings.validate()


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
