"""
User management service with OpenTelemetry tracing.
Implements auto-user creation and user management with distributed tracing.
"""

from typing import Any

from opentelemetry import trace
from sqlalchemy.orm import Session

from app.models import User
from app.services.base import BaseService


class UserService(BaseService):
    """Service for user management with auto-creation functionality."""

    def __init__(self):
        super().__init__("user")

    def get_or_create_user(self, db: Session, jwt_payload: dict[str, Any]) -> User:
        """
        Get or create user from JWT payload.
        Implements auto-user creation as specified in SPEC.md Section 3.1.
        Uses preferred_username (CPF) as the user identifier.
        """
        # Use subject field (which contains preferred_username/CPF) as the user identifier
        subject = jwt_payload.get("subject")
        if not subject:
            raise ValueError("JWT payload missing 'subject' field (should contain CPF from preferred_username)")

        with self.trace_operation(
            "get_or_create_user",
            {"user.subject": subject, "user.operation": "get_or_create"},
        ) as span:
            try:
                # Try to find existing user
                user = db.query(User).filter(User.subject == subject).first()

                if user:
                    # User exists, check if display_name needs updating
                    display_name = self._extract_display_name(jwt_payload)
                    if display_name and user.display_name != display_name:
                        user.display_name = display_name
                        db.commit()
                        span.set_attribute("user.display_name_updated", True)

                    span.set_attribute("user.found_existing", True)
                    span.set_attribute("user.user_id", user.id)
                    return user

                # Create new user
                display_name = self._extract_display_name(jwt_payload)
                user = User(subject=subject, display_name=display_name)

                db.add(user)
                db.commit()
                db.refresh(user)

                span.set_attribute("user.created_new", True)
                span.set_attribute("user.user_id", user.id)
                span.set_attribute("user.display_name", display_name or "")

                return user

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("user.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()
                raise

    def _extract_display_name(self, jwt_payload: dict[str, Any]) -> str | None:
        """
        Extract display name from JWT payload.
        Uses name field for display purposes (preferred_username is used for identification).
        """
        # Try display name fields in priority order
        display_name_fields = ["name", "given_name", "email"]

        for field in display_name_fields:
            value = jwt_payload.get(field)
            if value and isinstance(value, str):
                return value

        return None

    def get_user_by_subject(self, db: Session, subject: str) -> User | None:
        """Get user by subject with tracing."""
        with self.trace_operation(
            "get_user_by_subject",
            {"user.subject": subject, "user.operation": "get_by_subject"},
        ) as span:
            try:
                user = db.query(User).filter(User.subject == subject).first()

                if user:
                    span.set_attribute("user.found", True)
                    span.set_attribute("user.user_id", user.id)
                else:
                    span.set_attribute("user.found", False)

                return user

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("user.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def get_user_roles(self, _db: Session, user: User) -> list[str]:
        """
        Get all roles for a user from both group_roles and user_roles.
        Implements role aggregation as specified in SPEC.md.
        """
        with self.trace_operation(
            "get_user_roles",
            {
                "user.user_id": user.id,
                "user.subject": user.subject,
                "user.operation": "get_roles",
            },
        ) as span:
            try:
                roles = set()

                # Get roles from group memberships
                for membership in user.memberships:
                    for group_role in membership.group.group_roles:
                        roles.add(group_role.role.name)

                # Get direct user roles
                for user_role in user.user_roles:
                    roles.add(user_role.role.name)

                role_list = list(roles)
                span.set_attribute("user.roles_count", len(role_list))
                span.set_attribute("user.roles", role_list)

                return role_list

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("user.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def get_user_groups(self, _db: Session, user: User) -> list[dict[str, Any]]:
        """Get all groups for a user with membership details."""
        with self.trace_operation(
            "get_user_groups",
            {
                "user.user_id": user.id,
                "user.subject": user.subject,
                "user.operation": "get_groups",
            },
        ) as span:
            try:
                groups = []

                for membership in user.memberships:
                    group_info = {
                        "id": membership.group.id,
                        "name": membership.group.name,
                        "description": membership.group.description,
                        "granted_at": membership.granted_at.isoformat(),
                        "granted_by": membership.granter.subject
                        if membership.granter
                        else None,
                        "roles": [gr.role.name for gr in membership.group.group_roles],
                    }
                    groups.append(group_info)

                span.set_attribute("user.groups_count", len(groups))

                return groups

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("user.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise
