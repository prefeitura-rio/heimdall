"""
User management service with OpenTelemetry tracing.
Implements auto-user creation and user management with distributed tracing.
"""

import os
from typing import Any

from opentelemetry import trace
from sqlalchemy.orm import Session

from app.models import Role, User, UserRole
from app.services.base import BaseService


class UserService(BaseService):
    """Service for user management with auto-creation functionality."""

    def __init__(self):
        super().__init__("user")
        self.keycloak_client_id = os.getenv("KEYCLOAK_CLIENT_ID", "superapp")

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

                    # Check and update superadmin role if needed
                    self._ensure_superadmin_role(db, user, jwt_payload, span)

                    span.set_attribute("user.found_existing", True)
                    span.set_attribute("user.user_id", user.id)
                    return user

                # Create new user
                display_name = self._extract_display_name(jwt_payload)
                user = User(subject=subject, display_name=display_name)

                db.add(user)
                db.commit()
                db.refresh(user)

                # Check and assign superadmin role if user has heimdall-admin
                self._ensure_superadmin_role(db, user, jwt_payload, span)

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

    def _ensure_superadmin_role(self, db: Session, user: User, jwt_payload: dict[str, Any], span: trace.Span) -> None:
        """
        Check if user has heimdall-admin client role and automatically assign superadmin role.
        Implements automatic role assignment as specified in SPEC.md Section 3.1.
        """
        try:
            # Check if user has heimdall-admin role in resource_access
            has_heimdall_admin = self._has_heimdall_admin_role(jwt_payload)
            span.set_attribute("user.has_heimdall_admin", has_heimdall_admin)

            if not has_heimdall_admin:
                # User doesn't have heimdall-admin role, check if they have superadmin and remove it
                self._remove_superadmin_if_exists(db, user, span)
                return

            # User has heimdall-admin role, ensure they have superadmin
            existing_superadmin = (
                db.query(UserRole)
                .join(Role)
                .filter(UserRole.user_id == user.id, Role.name == "superadmin")
                .first()
            )

            if existing_superadmin:
                span.set_attribute("user.already_has_superadmin", True)
                return

            # Create superadmin role if it doesn't exist
            superadmin_role = db.query(Role).filter(Role.name == "superadmin").first()
            if not superadmin_role:
                superadmin_role = Role(
                    name="superadmin",
                    description="Super administrator with full system access"
                )
                db.add(superadmin_role)
                db.flush()  # Get the ID
                span.set_attribute("user.created_superadmin_role", True)

            # Assign superadmin role to user
            user_role = UserRole(
                user_id=user.id,
                role_id=superadmin_role.id,
                granted_by=user.id  # Self-granted through JWT
            )
            db.add(user_role)
            db.commit()

            span.set_attribute("user.assigned_superadmin", True)
            span.set_attribute("user.superadmin_role_id", superadmin_role.id)

        except Exception as e:
            span.record_exception(e)
            span.set_attribute("user.superadmin_assignment_error", str(e))
            # Don't fail user creation if role assignment fails
            db.rollback()

    def _has_heimdall_admin_role(self, jwt_payload: dict[str, Any]) -> bool:
        """Check if user has heimdall-admin role in Keycloak client roles."""
        resource_access = jwt_payload.get("resource_access", {})
        client_access = resource_access.get(self.keycloak_client_id, {})
        client_roles = client_access.get("roles", [])

        return "heimdall-admin" in client_roles

    def _remove_superadmin_if_exists(self, db: Session, user: User, span: trace.Span) -> None:
        """Remove superadmin role if user no longer has heimdall-admin role."""
        try:
            existing_superadmin = (
                db.query(UserRole)
                .join(Role)
                .filter(UserRole.user_id == user.id, Role.name == "superadmin")
                .first()
            )

            if existing_superadmin:
                db.delete(existing_superadmin)
                db.commit()
                span.set_attribute("user.removed_superadmin", True)
            else:
                span.set_attribute("user.no_superadmin_to_remove", True)

        except Exception as e:
            span.record_exception(e)
            span.set_attribute("user.superadmin_removal_error", str(e))
            db.rollback()

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
