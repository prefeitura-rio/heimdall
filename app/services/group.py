"""
Group management service with OpenTelemetry tracing.
Implements group management operations with transaction safety and Cerbos integration.
"""


from opentelemetry import trace
from sqlalchemy.orm import Session

from app.models import Group, User
from app.services.base import BaseService


class GroupService(BaseService):
    """Service for group management operations."""

    def __init__(self):
        super().__init__("group")

    def create_group(
        self, db: Session, name: str, description: str, created_by: User
    ) -> Group:
        """
        Create a new group.
        Implements group creation with proper transaction management.
        """
        with self.trace_operation("create_group", {
            "group.name": name,
            "group.created_by": created_by.subject,
            "group.operation": "create"
        }) as span:
            try:
                # Check if group already exists
                existing_group = db.query(Group).filter(Group.name == name).first()
                if existing_group:
                    span.set_attribute("group.already_exists", True)
                    raise ValueError(f"Group '{name}' already exists")

                # Create new group
                group = Group(
                    name=name,
                    description=description,
                    created_by=created_by.id
                )

                db.add(group)
                db.commit()
                db.refresh(group)

                span.set_attribute("group.id", group.id)
                span.set_attribute("group.created", True)

                return group

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("group.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()
                raise

    def list_groups(self, db: Session, prefix: str | None = None) -> list[Group]:
        """
        List groups with optional prefix filtering.
        Implements group listing with efficient database queries.
        """
        with self.trace_operation("list_groups", {
            "group.prefix": prefix or "",
            "group.operation": "list"
        }) as span:
            try:
                query = db.query(Group)

                if prefix:
                    query = query.filter(Group.name.like(f"{prefix}%"))

                groups = query.order_by(Group.name).all()

                span.set_attribute("group.count", len(groups))
                span.set_attribute("group.filtered", bool(prefix))

                return groups

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("group.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise

    def delete_group(
        self, db: Session, group_name: str, deleted_by: User
    ) -> bool:
        """
        Delete a group with cascading cleanup of memberships and roles.
        Implements group deletion with proper transaction management.
        """
        with self.trace_operation("delete_group", {
            "group.name": group_name,
            "group.deleted_by": deleted_by.subject,
            "group.operation": "delete"
        }) as span:
            try:
                # Find the group
                group = db.query(Group).filter(Group.name == group_name).first()
                if not group:
                    span.set_attribute("group.found", False)
                    return False

                span.set_attribute("group.id", group.id)
                span.set_attribute("group.found", True)

                # Count related records for tracing
                memberships_count = len(group.memberships)
                group_roles_count = len(group.group_roles)

                span.set_attribute("group.memberships_count", memberships_count)
                span.set_attribute("group.group_roles_count", group_roles_count)

                # Delete the group (cascading will handle related records due to DB constraints)
                db.delete(group)
                db.commit()

                span.set_attribute("group.deleted", True)

                return True

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("group.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                db.rollback()
                raise

    def get_group_by_name(self, db: Session, name: str) -> Group | None:
        """Get group by name with tracing."""
        with self.trace_operation("get_group_by_name", {
            "group.name": name,
            "group.operation": "get_by_name"
        }) as span:
            try:
                group = db.query(Group).filter(Group.name == name).first()

                if group:
                    span.set_attribute("group.found", True)
                    span.set_attribute("group.id", group.id)
                else:
                    span.set_attribute("group.found", False)

                return group

            except Exception as e:
                span.record_exception(e)
                span.set_attribute("group.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                raise
