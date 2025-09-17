"""
Centralized configuration settings for Heimdall Admin Service.
All environment variables are defined and accessed through this module.
"""

import os


class Settings:
    """Centralized configuration settings loaded from environment variables."""

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


# Global settings instance
settings = Settings()
