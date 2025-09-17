"""
Role management service with OpenTelemetry tracing.
Implements role management operations with Cerbos policy synchronization.
"""

from opentelemetry import trace
from sqlalchemy.orm import Session

from app.models import Action, Group, GroupRole, Role, RoleAction, User
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
                role = Role(name=name, description=description)

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

    def list_roles(self, db: Session, skip: int = 0, limit: int = 50) -> tuple[list[Role], int]:
        """
        List roles with pagination.
        Implements role listing with efficient database queries.

        Returns:
            Tuple of (roles, total_count)
        """
        with self.trace_operation(
            "list_roles",
            {"role.operation": "list", "skip": skip, "limit": limit}
        ) as span:
            try:
                # Get total count
                total_count = db.query(Role).count()

                # Get paginated roles
                roles = (
                    db.query(Role)
                    .order_by(Role.name)
                    .offset(skip)
                    .limit(limit)
                    .all()
                )

                span.set_attribute("role.count", len(roles))
                span.set_attribute("role.total_count", total_count)
                span.set_attribute("role.skip", skip)
                span.set_attribute("role.limit", limit)

                return roles, total_count

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("role.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def list_group_roles(self, db: Session, group_name: str) -> list[Role]:
        """
        List all roles assigned to a specific group.
        Implements group role listing with efficient database queries.
        """
        with self.trace_operation(
            "list_group_roles",
            {
                "role.group_name": group_name,
                "role.operation": "list_group_roles",
            },
        ) as span:
            try:
                # Find the group
                group = db.query(Group).filter(Group.name == group_name).first()
                if not group:
                    span.set_attribute("role.group_not_found", True)
                    raise ValueError(f"Group '{group_name}' not found")

                span.set_attribute("role.group_id", group.id)

                # Get all roles assigned to this group, sorted by role name
                roles = (
                    db.query(Role)
                    .join(GroupRole)
                    .filter(GroupRole.group_id == group.id)
                    .order_by(Role.name)
                    .all()
                )

                span.set_attribute("role.group_roles_count", len(roles))
                span.set_attribute("role.group_found", True)

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

    def get_role_by_name(self, db: Session, role_name: str) -> Role | None:
        """
        Get a role by its name.
        Returns None if the role doesn't exist.
        """
        with self.trace_operation("get_role_by_name", {"role_name": role_name}) as span:
            try:
                role = db.query(Role).filter(Role.name == role_name).first()

                if role:
                    span.set_attribute("role.found", True)
                    span.set_attribute("role.id", role.id)
                else:
                    span.set_attribute("role.found", False)

                return role

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("operation.error", str(e))
                raise

    def get_groups_with_role(self, db: Session, role_name: str) -> list[dict[str, any]]:
        """
        Get all groups that have a specific role assigned.
        Used for safety checks before role deletion.
        """
        with self.trace_operation("get_groups_with_role", {"role_name": role_name}) as span:
            try:
                # Get role by name
                role = db.query(Role).filter(Role.name == role_name).first()
                if not role:
                    span.set_attribute("role.found", False)
                    return []

                span.set_attribute("role.found", True)
                span.set_attribute("role.id", role.id)

                # Get all groups that have this role
                group_roles = (
                    db.query(GroupRole)
                    .filter(GroupRole.role_id == role.id)
                    .all()
                )

                groups = []
                for group_role in group_roles:
                    group = group_role.group
                    groups.append({
                        "id": group.id,
                        "name": group.name,
                        "description": group.description
                    })

                span.set_attribute("groups.count", len(groups))
                return groups

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("operation.error", str(e))
                raise

    def delete_role(self, db: Session, role_name: str) -> bool:
        """
        Delete a role from the system.
        Also removes the role from all groups and user assignments.
        """
        with self.trace_operation("delete_role", {"role_name": role_name}) as span:
            try:
                # Get role by name
                role = db.query(Role).filter(Role.name == role_name).first()
                if not role:
                    span.set_attribute("role.found", False)
                    return False

                span.set_attribute("role.found", True)
                span.set_attribute("role.id", role.id)

                # Remove role from all groups (cascade should handle this)
                group_roles_count = db.query(GroupRole).filter(GroupRole.role_id == role.id).count()
                db.query(GroupRole).filter(GroupRole.role_id == role.id).delete()

                # Delete the role itself
                db.delete(role)
                db.commit()

                span.set_attribute("group_roles.removed", group_roles_count)
                span.set_attribute("role.deleted", True)

                # Log audit event
                self.audit_service.log_role_operation(
                    db=db,
                    operation="delete",
                    role_name=role_name,
                    actor_subject="system",  # Will be updated with actual user in future
                    result={
                        "role_id": role.id,
                        "group_roles_removed": group_roles_count
                    },
                    success=True
                )

                return True

            except Exception as e:
                db.rollback()
                span.record_exception(e)
                span.set_attribute("operation.error", str(e))
                raise

    def list_role_actions(self, db: Session, role_name: str) -> list[Action]:
        """
        Get all actions assigned to a specific role.
        Returns actions from the role_actions table.
        """
        with self.trace_operation("list_role_actions", {"role_name": role_name}) as span:
            try:
                # Get role by name
                role = db.query(Role).filter(Role.name == role_name).first()
                if not role:
                    span.set_attribute("role.found", False)
                    raise ValueError(f"Role '{role_name}' not found")

                span.set_attribute("role.found", True)
                span.set_attribute("role.id", role.id)

                # Get all actions assigned to this role
                actions = (
                    db.query(Action)
                    .join(RoleAction)
                    .filter(RoleAction.role_id == role.id)
                    .order_by(Action.name)
                    .all()
                )

                span.set_attribute("role.actions_count", len(actions))
                return actions

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("operation.error", str(e))
                raise

    def assign_action_to_role(
        self, db: Session, role_name: str, action_name: str, assigned_by: User
    ) -> bool:
        """
        Assign an action to a role.
        Creates a role-action relationship if it doesn't exist.
        """
        with self.trace_operation(
            "assign_action_to_role",
            {
                "role_name": role_name,
                "action_name": action_name,
                "assigned_by": assigned_by.subject,
            },
        ) as span:
            try:
                # Find role and action
                role = db.query(Role).filter(Role.name == role_name).first()
                if not role:
                    span.set_attribute("role.found", False)
                    raise ValueError(f"Role '{role_name}' not found")

                action = db.query(Action).filter(Action.name == action_name).first()
                if not action:
                    span.set_attribute("action.found", False)
                    raise ValueError(f"Action '{action_name}' not found")

                span.set_attribute("role.found", True)
                span.set_attribute("action.found", True)
                span.set_attribute("role.id", role.id)
                span.set_attribute("action.id", action.id)

                # Check if assignment already exists
                existing = (
                    db.query(RoleAction)
                    .filter(
                        RoleAction.role_id == role.id,
                        RoleAction.action_id == action.id
                    )
                    .first()
                )

                if existing:
                    span.set_attribute("assignment.already_exists", True)
                    return True  # Idempotent operation

                # Create role-action assignment
                role_action = RoleAction(
                    role_id=role.id,
                    action_id=action.id,
                    granted_by=assigned_by.id
                )
                db.add(role_action)
                db.commit()

                span.set_attribute("assignment.created", True)

                # Log successful assignment
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=assigned_by.subject,
                    operation="assign_action_to_role",
                    target_type="role_action",
                    target_id=f"role:{role_name}:action:{action_name}",
                    request_payload={"role_name": role_name, "action_name": action_name},
                    result={
                        "action_assigned": True,
                        "role_id": role.id,
                        "action_id": action.id,
                    },
                    success=True,
                    actor_user_id=assigned_by.id,
                )

                return True

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("operation.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()

                # Log failed assignment
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=assigned_by.subject,
                    operation="assign_action_to_role",
                    target_type="role_action",
                    target_id=f"role:{role_name}:action:{action_name}",
                    request_payload={"role_name": role_name, "action_name": action_name},
                    result={"error": str(e)},
                    success=False,
                    actor_user_id=assigned_by.id,
                )
                raise

    def remove_action_from_role(
        self, db: Session, role_name: str, action_name: str, removed_by: User
    ) -> bool:
        """
        Remove an action from a role.
        Deletes the role-action relationship if it exists.
        """
        with self.trace_operation(
            "remove_action_from_role",
            {
                "role_name": role_name,
                "action_name": action_name,
                "removed_by": removed_by.subject,
            },
        ) as span:
            try:
                # Find the role-action assignment
                role_action = (
                    db.query(RoleAction)
                    .join(Role)
                    .join(Action)
                    .filter(Role.name == role_name, Action.name == action_name)
                    .first()
                )

                if not role_action:
                    span.set_attribute("assignment.not_found", True)
                    return True  # Idempotent operation

                # Store info for logging before deletion
                role_id = role_action.role_id
                action_id = role_action.action_id

                db.delete(role_action)
                db.commit()

                span.set_attribute("assignment.removed", True)
                span.set_attribute("role.id", role_id)
                span.set_attribute("action.id", action_id)

                # Log successful removal
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=removed_by.subject,
                    operation="remove_action_from_role",
                    target_type="role_action",
                    target_id=f"role:{role_name}:action:{action_name}",
                    request_payload={"role_name": role_name, "action_name": action_name},
                    result={
                        "action_removed": True,
                        "role_id": role_id,
                        "action_id": action_id,
                    },
                    success=True,
                    actor_user_id=removed_by.id,
                )

                return True

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("operation.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()

                # Log failed removal
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=removed_by.subject,
                    operation="remove_action_from_role",
                    target_type="role_action",
                    target_id=f"role:{role_name}:action:{action_name}",
                    request_payload={"role_name": role_name, "action_name": action_name},
                    result={"error": str(e)},
                    success=False,
                    actor_user_id=removed_by.id,
                )
                raise
