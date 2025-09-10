"""
Membership management service with OpenTelemetry tracing.
Implements group membership operations with distributed tracing.
"""

from opentelemetry import trace
from sqlalchemy.orm import Session

from app.models import Group, Membership, User
from app.services.base import BaseService
from app.services.cerbos import CerbosService


class MembershipService(BaseService):
    """Service for managing group memberships with tracing."""

    def __init__(self):
        super().__init__("membership")
        self.cerbos_service = CerbosService()

    def add_member_to_group(
        self,
        db: Session,
        group_name: str,
        member_subject: str,
        caller_subject: str,
        caller_roles: list[str],
    ) -> bool:
        """Add member to group with complete tracing flow."""
        with self.trace_operation(
            "add_member_to_group",
            {
                "membership.group_name": group_name,
                "membership.member_subject": member_subject,
                "membership.caller_subject": caller_subject,
                "membership.operation": "add_member",
            },
        ) as span:
            try:
                # Step 1: Check permissions with Cerbos
                with self.tracer.start_span("check_add_member_permission") as perm_span:
                    perm_span.set_attribute("cerbos.action", "group:add_member")
                    perm_span.set_attribute("cerbos.resource", group_name)

                    can_add = self.cerbos_service.check_permission(
                        caller_subject=caller_subject,
                        caller_roles=caller_roles,
                        action="group:add_member",
                        resource_type="group",
                        resource_attrs={"name": group_name},
                    )

                    if not can_add:
                        span.set_attribute("membership.permission_denied", True)
                        span.set_status(
                            trace.Status(trace.StatusCode.ERROR, "Permission denied")
                        )
                        return False

                # Step 2: Database operations
                with self.tracer.start_span("database_operations") as db_span:
                    # Find or create user
                    user = db.query(User).filter(User.subject == member_subject).first()
                    if not user:
                        user = User(subject=member_subject)
                        db.add(user)
                        db.flush()  # Get user ID
                        db_span.set_attribute("membership.user_created", True)

                    # Find group
                    group = db.query(Group).filter(Group.name == group_name).first()
                    if not group:
                        span.set_attribute("membership.group_not_found", True)
                        span.set_status(
                            trace.Status(trace.StatusCode.ERROR, "Group not found")
                        )
                        return False

                    # Check if membership already exists
                    existing = (
                        db.query(Membership)
                        .filter(
                            Membership.group_id == group.id,
                            Membership.user_id == user.id,
                        )
                        .first()
                    )

                    if existing:
                        span.set_attribute("membership.already_exists", True)
                        return True  # Idempotent operation

                    # Create membership
                    membership = Membership(
                        group_id=group.id,
                        user_id=user.id,
                        granted_by=db.query(User)
                        .filter(User.subject == caller_subject)
                        .first()
                        .id,
                    )
                    db.add(membership)
                    db.commit()

                    db_span.set_attribute("membership.created", True)
                    db_span.set_attribute("membership.group_id", group.id)
                    db_span.set_attribute("membership.user_id", user.id)

                # Step 3: Update Cerbos policies
                with self.tracer.start_span("update_cerbos_policies") as policy_span:
                    # This would trigger policy regeneration for the user
                    # Implementation details depend on the specific policy structure
                    policy_span.set_attribute("cerbos.policy_update_triggered", True)
                    # TODO: Implement actual policy push in later phases

                span.set_attribute("membership.success", True)
                return True

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("membership.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()
                raise

    def remove_member_from_group(
        self,
        db: Session,
        group_name: str,
        member_subject: str,
        caller_subject: str,
        caller_roles: list[str],
    ) -> bool:
        """Remove member from group with tracing."""
        with self.trace_operation(
            "remove_member_from_group",
            {
                "membership.group_name": group_name,
                "membership.member_subject": member_subject,
                "membership.caller_subject": caller_subject,
                "membership.operation": "remove_member",
            },
        ) as span:
            try:
                # Check permissions
                can_remove = self.cerbos_service.check_permission(
                    caller_subject=caller_subject,
                    caller_roles=caller_roles,
                    action="group:remove_member",
                    resource_type="group",
                    resource_attrs={"name": group_name},
                )

                if not can_remove:
                    span.set_attribute("membership.permission_denied", True)
                    span.set_status(
                        trace.Status(trace.StatusCode.ERROR, "Permission denied")
                    )
                    return False

                # Find and remove membership
                membership = (
                    db.query(Membership)
                    .join(Group)
                    .join(User)
                    .filter(Group.name == group_name, User.subject == member_subject)
                    .first()
                )

                if not membership:
                    span.set_attribute("membership.not_found", True)
                    return True  # Idempotent operation

                db.delete(membership)
                db.commit()

                span.set_attribute("membership.removed", True)
                return True

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("membership.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()
                raise
