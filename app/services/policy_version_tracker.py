"""
Policy Version Tracking Service

Simple and efficient policy change detection using a version counter.
Much more performant than hash-based approach.
"""

import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.base import BaseService


class PolicyVersionTracker(BaseService):
    """Service for tracking policy changes using a simple version system."""

    def __init__(self):
        super().__init__("policy_version_tracker")
        self.version_key = "policy_version"

    def get_current_version(self, db: Session) -> str:
        """
        Get the current policy version from the database.
        Uses a simple key-value approach stored in a settings table.
        """
        with self.trace_operation("get_current_version") as span:
            try:
                # Try to get version from a simple key-value table
                # We'll store it as a database setting
                result = db.execute(
                    text("SELECT value FROM app_settings WHERE key = :key"),
                    {"key": self.version_key}
                ).fetchone()

                if result:
                    version = result[0]
                    span.set_attribute("current_version", version[:8])  # Log first 8 chars
                    return version
                else:
                    # No version exists, create initial one
                    initial_version = str(uuid.uuid4())
                    self._set_version(db, initial_version)
                    span.set_attribute("initial_version_created", True)
                    span.set_attribute("current_version", initial_version[:8])
                    return initial_version

            except Exception as e:
                span.record_exception(e)
                # On error, return a unique version to trigger sync
                fallback_version = str(uuid.uuid4())
                span.set_attribute("fallback_version", fallback_version[:8])
                return fallback_version

    def _set_version(self, db: Session, version: str) -> bool:
        """Set the current policy version in the database."""
        try:
            # Use UPSERT to set the version
            db.execute(
                text("""
                    INSERT INTO app_settings (key, value, updated_at)
                    VALUES (:key, :value, CURRENT_TIMESTAMP)
                    ON CONFLICT (key)
                    DO UPDATE SET value = :value, updated_at = CURRENT_TIMESTAMP
                """),
                {"key": self.version_key, "value": version}
            )
            db.commit()
            return True
        except Exception:
            db.rollback()
            return False

    def increment_version(self, db: Session) -> str:
        """
        Increment the policy version to indicate changes.
        This should be called whenever policy-relevant data changes.
        """
        with self.trace_operation("increment_version") as span:
            try:
                new_version = str(uuid.uuid4())
                success = self._set_version(db, new_version)

                span.set_attribute("new_version", new_version[:8])
                span.set_attribute("increment_successful", success)

                if success:
                    logger = getattr(self, 'logger', None)
                    if logger:
                        logger.info(f"Policy version incremented to {new_version[:8]}")

                return new_version

            except Exception as e:
                span.record_exception(e)
                # Return unique version even on error
                return str(uuid.uuid4())

    def has_version_changed(self, db: Session, last_known_version: str | None) -> bool:
        """
        Check if the policy version has changed since the last known version.
        Much more efficient than hash comparison.
        """
        with self.trace_operation("has_version_changed") as span:
            try:
                current_version = self.get_current_version(db)
                has_changed = last_known_version is None or current_version != last_known_version

                span.set_attribute("current_version", current_version[:8])
                span.set_attribute("last_known_version", last_known_version[:8] if last_known_version else "none")
                span.set_attribute("has_changed", has_changed)

                if has_changed:
                    logger = getattr(self, 'logger', None)
                    if logger:
                        logger.info(f"Policy version changed - Current: {current_version[:8]}, Last known: {last_known_version[:8] if last_known_version else 'none'}")

                return has_changed

            except Exception as e:
                span.record_exception(e)
                # On error, assume version changed to trigger sync
                return True

    def create_settings_table_if_not_exists(self, db: Session) -> bool:
        """
        Create the app_settings table if it doesn't exist.
        This is a simple key-value table for storing application settings.
        """
        with self.trace_operation("create_settings_table") as span:
            try:
                db.execute(text("""
                    CREATE TABLE IF NOT EXISTS app_settings (
                        key VARCHAR(255) PRIMARY KEY,
                        value TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))
                db.commit()

                span.set_attribute("table_created", True)
                return True

            except Exception as e:
                span.record_exception(e)
                db.rollback()
                return False
