"""
Action management service with OpenTelemetry tracing.
Implements action management operations with transaction safety and audit logging.
"""

from opentelemetry import trace
from sqlalchemy.orm import Session

from app.models import Action, User
from app.services.audit import AuditService
from app.services.base import BaseService


class ActionService(BaseService):
    """Service for action management operations."""

    def __init__(self):
        super().__init__("action")
        self.audit_service = AuditService()

    def create_action(
        self, db: Session, name: str, description: str, created_by: User
    ) -> Action:
        """
        Create a new action.
        Implements action creation with proper transaction management.
        """
        with self.trace_operation(
            "create_action",
            {
                "action.name": name,
                "action.created_by": created_by.subject,
                "action.operation": "create",
            },
        ) as span:
            try:
                # Check if action already exists
                existing_action = db.query(Action).filter(Action.name == name).first()
                if existing_action:
                    span.set_attribute("action.already_exists", True)
                    raise ValueError(f"Action '{name}' already exists")

                # Create new action
                action = Action(name=name, description=description)

                db.add(action)
                db.commit()
                db.refresh(action)

                # Audit the operation
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=created_by.subject,
                    operation="action_create",
                    target_type="action",
                    target_id=str(action.id),
                    request_payload={"name": name, "description": description},
                    result={"action_id": action.id, "name": action.name},
                    success=True,
                )

                span.set_attribute("action.id", action.id)
                span.set_attribute("action.created", True)

                return action

            except Exception as e:
                db.rollback()
                span.record_exception(e)
                span.set_attribute("action.created", False)
                span.set_attribute("action.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))

                # Audit the failed operation
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=created_by.subject,
                    operation="action_create",
                    target_type="action",
                    target_id=name,
                    request_payload={"name": name, "description": description},
                    result={"error": str(e)},
                    success=False,
                )

                raise

    def get_action(self, db: Session, action_id: int) -> Action | None:
        """Get action by ID."""
        with self.trace_operation(
            "get_action", {"action.id": action_id, "action.operation": "get"}
        ) as span:
            action = db.query(Action).filter(Action.id == action_id).first()
            span.set_attribute("action.found", action is not None)
            if action:
                span.set_attribute("action.name", action.name)
            return action

    def get_action_by_name(self, db: Session, name: str) -> Action | None:
        """Get action by name."""
        with self.trace_operation(
            "get_action_by_name", {"action.name": name, "action.operation": "get_by_name"}
        ) as span:
            action = db.query(Action).filter(Action.name == name).first()
            span.set_attribute("action.found", action is not None)
            return action

    def list_actions(self, db: Session, skip: int = 0, limit: int = 100) -> list[Action]:
        """List actions with pagination."""
        with self.trace_operation(
            "list_actions",
            {"action.skip": skip, "action.limit": limit, "action.operation": "list"},
        ) as span:
            actions = db.query(Action).offset(skip).limit(limit).all()
            span.set_attribute("action.count", len(actions))
            return actions

    def update_action(
        self,
        db: Session,
        action_id: int,
        name: str | None = None,
        description: str | None = None,
        updated_by: User | None = None,
    ) -> Action:
        """
        Update an existing action.
        Implements action update with proper transaction management.
        """
        with self.trace_operation(
            "update_action",
            {
                "action.id": action_id,
                "action.operation": "update",
                "action.updated_by": updated_by.subject if updated_by else None,
            },
        ) as span:
            try:
                # Get existing action
                action = db.query(Action).filter(Action.id == action_id).first()
                if not action:
                    span.set_attribute("action.found", False)
                    raise ValueError(f"Action with ID {action_id} not found")

                span.set_attribute("action.found", True)
                span.set_attribute("action.current_name", action.name)

                # Store original values for audit
                original_data = {"name": action.name, "description": action.description}

                # Update fields if provided
                if name is not None:
                    # Check if new name conflicts with existing action
                    if name != action.name:
                        existing_action = (
                            db.query(Action).filter(Action.name == name).first()
                        )
                        if existing_action:
                            span.set_attribute("action.name_conflict", True)
                            raise ValueError(f"Action '{name}' already exists")
                    action.name = name

                if description is not None:
                    action.description = description

                db.commit()
                db.refresh(action)

                # Audit the operation
                if updated_by:
                    self.audit_service.safe_log_operation(
                        db=db,
                        actor_subject=updated_by.subject,
                        operation="action_update",
                        target_type="action",
                        target_id=str(action.id),
                        request_payload={
                            "name": name,
                            "description": description,
                            "original": original_data,
                        },
                        result={"action_id": action.id, "name": action.name},
                        success=True,
                    )

                span.set_attribute("action.updated", True)
                span.set_attribute("action.new_name", action.name)

                return action

            except Exception as e:
                db.rollback()
                span.record_exception(e)
                span.set_attribute("action.updated", False)
                span.set_attribute("action.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))

                # Audit the failed operation
                if updated_by:
                    self.audit_service.safe_log_operation(
                        db=db,
                        actor_subject=updated_by.subject,
                        operation="action_update",
                        target_type="action",
                        target_id=str(action_id),
                        request_payload={"name": name, "description": description},
                        result={"error": str(e)},
                        success=False,
                    )

                raise

    def delete_action(self, db: Session, action_id: int, deleted_by: User) -> bool:
        """
        Delete an action.
        Implements action deletion with proper transaction management and constraint checking.
        """
        with self.trace_operation(
            "delete_action",
            {
                "action.id": action_id,
                "action.operation": "delete",
                "action.deleted_by": deleted_by.subject,
            },
        ) as span:
            try:
                # Get existing action
                action = db.query(Action).filter(Action.id == action_id).first()
                if not action:
                    span.set_attribute("action.found", False)
                    raise ValueError(f"Action with ID {action_id} not found")

                span.set_attribute("action.found", True)
                span.set_attribute("action.name", action.name)

                # Check if action is referenced by endpoints
                if action.endpoints:
                    span.set_attribute("action.has_endpoints", True)
                    span.set_attribute("action.endpoint_count", len(action.endpoints))
                    raise ValueError(
                        f"Cannot delete action '{action.name}' - it is referenced by {len(action.endpoints)} endpoint(s)"
                    )

                span.set_attribute("action.has_endpoints", False)

                # Store action data for audit before deletion
                action_data = {"name": action.name, "description": action.description}

                db.delete(action)
                db.commit()

                # Audit the operation
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=deleted_by.subject,
                    operation="action_delete",
                    target_type="action",
                    target_id=str(action_id),
                    request_payload={},
                    result={"deleted_action": action_data},
                    success=True,
                )

                span.set_attribute("action.deleted", True)

                return True

            except Exception as e:
                db.rollback()
                span.record_exception(e)
                span.set_attribute("action.deleted", False)
                span.set_attribute("action.error", str(e))
                span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))

                # Audit the failed operation
                self.audit_service.safe_log_operation(
                    db=db,
                    actor_subject=deleted_by.subject,
                    operation="action_delete",
                    target_type="action",
                    target_id=str(action_id),
                    request_payload={},
                    result={"error": str(e)},
                    success=False,
                )

                raise
