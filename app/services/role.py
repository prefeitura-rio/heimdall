"""
Role management service with OpenTelemetry tracing.
Implements role management operations with Cerbos policy synchronization.
"""

from opentelemetry import trace
from sqlalchemy.orm import Session

from app.models import Group, GroupRole, Role, User
from app.services.audit import AuditService
from app.services.base import BaseService
from app.services.cache import CacheService
from app.services.cerbos import CerbosService


class RoleService(BaseService):
    """Service for role management operations."""

    def __init__(self):
        super().__init__("role")
        self.cerbos_service = CerbosService()
        self.cache_service = CacheService()
        self.audit_service = AuditService()

    def create_role(
        self, db: Session, name: str, description: str, created_by: User
    ) -> Role:
        """
        Create a new role.
        Implements role creation with proper validation.
        """
        with self.trace_operation(
            "create_role",
            {
                "role.name": name,
                "role.created_by": created_by.subject,
                "role.operation": "create",
            },
        ) as span:
            try:
                # Check if role already exists
                existing_role = db.query(Role).filter(Role.name == name).first()
                if existing_role:
                    span.set_attribute("role.already_exists", True)
                    raise ValueError(f"Role '{name}' already exists")

                # Create new role
                role = Role(
                    name=name, description=description, created_by=created_by.id
                )

                db.add(role)
                db.commit()
                db.refresh(role)

                span.set_attribute("role.id", role.id)
                span.set_attribute("role.created", True)

                # Log successful role creation
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=created_by.subject,
                    operation="create_role",
                    target_type="role",
                    target_id=f"role:{name}",
                    request_payload={"name": name, "description": description},
                    result={"role_id": role.id, "name": name},
                    success=True,
                    actor_user_id=created_by.id,
                )

                return role

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("role.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()

                # Log failed role creation
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=created_by.subject,
                    operation="create_role",
                    target_type="role",
                    target_id=f"role:{name}",
                    request_payload={"name": name, "description": description},
                    result={"error": str(e)},
                    success=False,
                    actor_user_id=created_by.id,
                )
                raise

    def list_roles(self, db: Session) -> list[Role]:
        """
        List all roles.
        Implements role listing with efficient database queries.
        """
        with self.trace_operation("list_roles", {"role.operation": "list"}) as span:
            try:
                roles = db.query(Role).order_by(Role.name).all()

                span.set_attribute("role.count", len(roles))

                return roles

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("role.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def assign_role_to_group(
        self, db: Session, group_name: str, role_name: str, assigned_by: User
    ) -> bool:
        """
        Assign role to group with member policy updates.
        Updates all group members' Cerbos policies.
        """
        with self.trace_operation(
            "assign_role_to_group",
            {
                "role.group_name": group_name,
                "role.role_name": role_name,
                "role.assigned_by": assigned_by.subject,
                "role.operation": "assign_to_group",
            },
        ) as span:
            try:
                # Find group and role
                group = db.query(Group).filter(Group.name == group_name).first()
                if not group:
                    span.set_attribute("role.group_not_found", True)
                    raise ValueError(f"Group '{group_name}' not found")

                role = db.query(Role).filter(Role.name == role_name).first()
                if not role:
                    span.set_attribute("role.role_not_found", True)
                    raise ValueError(f"Role '{role_name}' not found")

                # Check if assignment already exists
                existing = (
                    db.query(GroupRole)
                    .filter(
                        GroupRole.group_id == group.id, GroupRole.role_id == role.id
                    )
                    .first()
                )

                if existing:
                    span.set_attribute("role.already_assigned", True)
                    return True  # Idempotent operation

                # Create group role assignment
                group_role = GroupRole(group_id=group.id, role_id=role.id)
                db.add(group_role)
                db.commit()

                span.set_attribute("role.assigned", True)
                span.set_attribute("role.group_id", group.id)
                span.set_attribute("role.role_id", role.id)

                # Update policies for all group members
                self._update_member_policies_after_role_change(db, group, span)

                # Invalidate user roles cache for all group members
                for membership in group.memberships:
                    self.cache_service.invalidate_user_roles_cache(
                        membership.user.subject
                    )
                span.set_attribute(
                    "role.cache_invalidated_members", len(group.memberships)
                )

                # Log successful role assignment
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=assigned_by.subject,
                    operation="assign_role_to_group",
                    target_type="role",
                    target_id=f"group:{group_name}:role:{role_name}",
                    request_payload={"group_name": group_name, "role_name": role_name},
                    result={
                        "role_assigned": True,
                        "group_id": group.id,
                        "role_id": role.id,
                        "members_affected": len(group.memberships),
                    },
                    success=True,
                    actor_user_id=assigned_by.id,
                )

                return True

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("role.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()

                # Log failed role assignment
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=assigned_by.subject,
                    operation="assign_role_to_group",
                    target_type="role",
                    target_id=f"group:{group_name}:role:{role_name}",
                    request_payload={"group_name": group_name, "role_name": role_name},
                    result={"error": str(e)},
                    success=False,
                    actor_user_id=assigned_by.id,
                )
                raise

    def remove_role_from_group(
        self, db: Session, group_name: str, role_name: str, removed_by: User
    ) -> bool:
        """
        Remove role from group with policy cleanup.
        Updates all group members' Cerbos policies.
        """
        with self.trace_operation(
            "remove_role_from_group",
            {
                "role.group_name": group_name,
                "role.role_name": role_name,
                "role.removed_by": removed_by.subject,
                "role.operation": "remove_from_group",
            },
        ) as span:
            try:
                # Find the group role assignment
                group_role = (
                    db.query(GroupRole)
                    .join(Group)
                    .join(Role)
                    .filter(Group.name == group_name, Role.name == role_name)
                    .first()
                )

                if not group_role:
                    span.set_attribute("role.assignment_not_found", True)
                    return True  # Idempotent operation

                # Get group for policy updates
                group = group_role.group

                db.delete(group_role)
                db.commit()

                span.set_attribute("role.removed", True)

                # Update policies for all group members
                self._update_member_policies_after_role_change(db, group, span)

                # Invalidate user roles cache for all group members
                for membership in group.memberships:
                    self.cache_service.invalidate_user_roles_cache(
                        membership.user.subject
                    )
                span.set_attribute(
                    "role.cache_invalidated_members", len(group.memberships)
                )

                # Log successful role removal
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=removed_by.subject,
                    operation="remove_role_from_group",
                    target_type="role",
                    target_id=f"group:{group_name}:role:{role_name}",
                    request_payload={"group_name": group_name, "role_name": role_name},
                    result={
                        "role_removed": True,
                        "members_affected": len(group.memberships),
                    },
                    success=True,
                    actor_user_id=removed_by.id,
                )

                return True

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("role.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()

                # Log failed role removal
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=removed_by.subject,
                    operation="remove_role_from_group",
                    target_type="role",
                    target_id=f"group:{group_name}:role:{role_name}",
                    request_payload={"group_name": group_name, "role_name": role_name},
                    result={"error": str(e)},
                    success=False,
                    actor_user_id=removed_by.id,
                )
                raise

    def _update_member_policies_after_role_change(
        self, db: Session, group: Group, span: trace.Span
    ) -> None:
        """Update Cerbos policies for all group members after role changes."""
        try:
            members_updated = 0
            members_failed = 0

            for membership in group.memberships:
                try:
                    # Get user's updated roles
                    user_roles = self._get_user_roles(db, membership.user)

                    # Push updated policy to Cerbos
                    if user_roles:
                        policy_pushed = self.cerbos_service.push_user_policy(
                            user_subject=membership.user.subject, user_roles=user_roles
                        )
                        if policy_pushed:
                            members_updated += 1
                        else:
                            members_failed += 1
                    else:
                        # User has no roles left, delete their policy
                        self.cerbos_service.delete_user_policy(membership.user.subject)
                        members_updated += 1

                except Exception as e:
                    members_failed += 1
                    span.record_exception(e)

            span.set_attribute("role.members_updated", members_updated)
            span.set_attribute("role.members_failed", members_failed)
            span.set_attribute("role.policy_update_completed", True)

        except Exception as e:
            span.record_exception(e)
            span.set_attribute("role.policy_update_error", str(e))

    def _get_user_roles(self, db: Session, user: User) -> list[str]:
        """Get user's roles from both group memberships and direct assignments."""
        roles = set()

        # Refresh user to get latest data
        db.refresh(user)

        # Get roles from group memberships
        for membership in user.memberships:
            for group_role in membership.group.group_roles:
                roles.add(group_role.role.name)

        # Get direct user roles
        for user_role in user.user_roles:
            roles.add(user_role.role.name)

        return list(roles)
