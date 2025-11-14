"""
Authentication service with OpenTelemetry tracing.
Implements JWT verification and user management with distributed tracing.
"""

from typing import Any

import requests
from jose import JWTError, jwk, jwt
from opentelemetry import trace

from app.services.base import BaseService
from app.services.cache import CacheService
from app.settings import settings


class AuthService(BaseService):
    """Authentication service with distributed tracing."""

    def __init__(self):
        super().__init__("auth")
        self.jwks_url = settings.get_keycloak_jwks_url()
        self.jwt_algorithm = settings.JWT_ALGORITHM
        self.jwt_audience = settings.JWT_AUDIENCE
        self.static_api_token = settings.STATIC_API_TOKEN
        self.cache_service = CacheService()

    def _fetch_jwks(self) -> dict[str, Any]:
        """Fetch JWKS from Keycloak with Redis caching."""
        with self.trace_operation(
            "fetch_jwks", {"auth.jwks_url": self.jwks_url}
        ) as span:
            try:
                if not self.jwks_url:
                    raise ValueError("KEYCLOAK_JWKS_URL not configured")

                # Try to get from cache first
                cached_jwks = self.cache_service.get_jwks_cache(self.jwks_url)
                if cached_jwks:
                    span.set_attribute("auth.jwks_cache_hit", True)
                    span.set_attribute(
                        "auth.jwks_keys_count", len(cached_jwks.get("keys", []))
                    )
                    return cached_jwks

                span.set_attribute("auth.jwks_cache_hit", False)

                # Fetch from Keycloak
                response = requests.get(self.jwks_url, timeout=10)
                response.raise_for_status()
                jwks_data = response.json()

                # Cache the result
                self.cache_service.set_jwks_cache(self.jwks_url, jwks_data)
                span.set_attribute("auth.jwks_cached", True)

                span.set_attribute("auth.jwks_fetched", True)
                span.set_attribute(
                    "auth.jwks_keys_count", len(jwks_data.get("keys", []))
                )

                return jwks_data

            except requests.RequestException as e:
                span.record_exception(e)
                span.set_attribute("auth.jwks_fetch_error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise ValueError(f"Failed to fetch JWKS: {e}") from e

    def _get_signing_key(self, token: str) -> str:
        """Get the signing key for JWT verification."""
        try:
            # Decode JWT header to get the key ID
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")

            if not kid:
                raise ValueError("JWT token missing 'kid' in header")

            # Fetch JWKS
            jwks_data = self._fetch_jwks()

            # Find the matching key
            for key_data in jwks_data.get("keys", []):
                if key_data.get("kid") == kid:
                    return jwk.construct(key_data).to_pem()

            raise ValueError(f"Unable to find signing key with kid: {kid}")

        except (JWTError, ValueError) as e:
            raise ValueError(f"Failed to get signing key: {e}")

    def verify_jwt_token(self, token: str) -> dict[str, Any] | None:
        """Extract JWT token claims without verification (validation handled upstream)."""
        with self.trace_operation(
            "verify_jwt_token",
            {
                "auth.token_type": "jwt",
                "auth.algorithm": self.jwt_algorithm,
                "auth.jwks_url": self.jwks_url,
            },
        ) as span:
            try:
                # Decode JWT without verification (validated upstream at gateway/ingress)
                payload = jwt.get_unverified_claims(token)

                # Extract user information - use preferred_username (CPF) as subject
                user_info = {
                    "subject": payload.get(
                        "preferred_username"
                    ),  # CPF as primary identifier
                    "sub": payload.get("sub"),  # Keep original sub for reference
                    "preferred_username": payload.get("preferred_username"),
                    "email": payload.get("email"),
                    "name": payload.get("name"),
                    "given_name": payload.get("given_name"),
                    "family_name": payload.get("family_name"),
                    "roles": payload.get("roles", []),
                    "realm_access": payload.get("realm_access", {}),
                    "resource_access": payload.get("resource_access", {}),
                    "exp": payload.get("exp"),
                    "iat": payload.get("iat"),
                    "iss": payload.get("iss"),
                    "aud": payload.get("aud"),
                }

                span.set_attribute("auth.token_valid", True)
                span.set_attribute("auth.user_subject", user_info["subject"])
                span.set_attribute("auth.verification_skipped", True)

                return user_info

            except JWTError as e:
                span.record_exception(e)
                span.set_attribute("auth.jwt_error", str(e))
                span.set_attribute("auth.token_valid", False)
                span.set_status(
                    trace.Status(
                        trace.StatusCode.ERROR, f"JWT decoding failed: {e}"
                    )
                )
                return None
            except Exception as e:
                span.record_exception(e)
                span.set_attribute("auth.unexpected_error", str(e))
                span.set_attribute("auth.token_valid", False)
                span.set_status(
                    trace.Status(trace.StatusCode.ERROR, f"Unexpected error: {e}")
                )
                return None

    def verify_static_token(self, token: str) -> bool:
        """Verify static API token with tracing."""
        with self.trace_operation(
            "verify_static_token", {"auth.token_type": "static_api"}
        ) as span:
            try:
                if not self.static_api_token:
                    span.set_attribute("auth.static_token_not_configured", True)
                    return False

                is_valid = token == self.static_api_token
                span.set_attribute("auth.token_valid", is_valid)

                return is_valid

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("auth.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                return False

    def authenticate_request(
        self, authorization_header: str | None
    ) -> dict[str, Any] | None:
        """Authenticate request with either JWT or static token."""
        with self.trace_operation("authenticate_request") as span:
            if not authorization_header:
                span.set_attribute("auth.no_authorization_header", True)
                return None

            try:
                if authorization_header.startswith("Bearer "):
                    token = authorization_header[7:]
                    span.set_attribute("auth.token_type", "bearer")

                    # Try JWT first
                    jwt_result = self.verify_jwt_token(token)
                    if jwt_result:
                        span.set_attribute("auth.method", "jwt")
                        return jwt_result

                    # Try static token
                    if self.verify_static_token(token):
                        span.set_attribute("auth.method", "static_api")
                        return {"type": "static_api", "valid": True}

                span.set_attribute("auth.authentication_failed", True)
                return None

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("auth.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                return None
