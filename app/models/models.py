"""
SQLAlchemy models for Heimdall Admin Service.
Implements all tables from SPEC.md Section 2 exactly as specified.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class Action(Base):
    """Actions table - represents available actions in the system."""

    __tablename__ = "actions"

    # Performance indexes for action queries
    __table_args__ = (
        # Index for action name lookups (frequent in mapping resolution)
        Index("ix_actions_name", "name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    endpoints: Mapped[list["Endpoint"]] = relationship(
        "Endpoint", back_populates="action"
    )
    role_actions: Mapped[list["RoleAction"]] = relationship(
        "RoleAction", back_populates="action"
    )


class Role(Base):
    """Roles table - represents roles that can be assigned."""

    __tablename__ = "roles"

    # Performance indexes for role queries
    __table_args__ = (
        # Index for role name lookups (very frequent)
        Index("ix_roles_name", "name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    group_roles: Mapped[list["GroupRole"]] = relationship(
        "GroupRole", back_populates="role"
    )
    user_roles: Mapped[list["UserRole"]] = relationship(
        "UserRole", back_populates="role"
    )
    role_actions: Mapped[list["RoleAction"]] = relationship(
        "RoleAction", back_populates="role"
    )


class User(Base):
    """Users table - Keycloak subject storage."""

    __tablename__ = "users"

    # Performance indexes for frequently queried columns
    __table_args__ = (
        # Index for subject lookups (most frequent query)
        Index("ix_users_subject", "subject"),
        # Index for display_name searches (if needed for user lookups)
        Index("ix_users_display_name", "display_name"),
        # Index for created_at for chronological queries
        Index("ix_users_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    created_groups: Mapped[list["Group"]] = relationship(
        "Group", foreign_keys="Group.created_by", back_populates="creator"
    )
    created_endpoints: Mapped[list["Endpoint"]] = relationship(
        "Endpoint", foreign_keys="Endpoint.created_by", back_populates="creator"
    )
    created_group_management_rights: Mapped[list["GroupManagementRight"]] = (
        relationship(
            "GroupManagementRight",
            foreign_keys="GroupManagementRight.created_by",
            back_populates="creator",
        )
    )
    memberships: Mapped[list["Membership"]] = relationship(
        "Membership", foreign_keys="Membership.user_id", back_populates="user"
    )
    granted_memberships: Mapped[list["Membership"]] = relationship(
        "Membership", foreign_keys="Membership.granted_by", back_populates="granter"
    )
    user_roles: Mapped[list["UserRole"]] = relationship(
        "UserRole", foreign_keys="UserRole.user_id", back_populates="user"
    )
    granted_user_roles: Mapped[list["UserRole"]] = relationship(
        "UserRole", foreign_keys="UserRole.granted_by", back_populates="granter"
    )
    audit_entries: Mapped[list["AdminAudit"]] = relationship(
        "AdminAudit", back_populates="actor_user"
    )


class Group(Base):
    """Groups table - represents groups that users can be members of."""

    __tablename__ = "groups"

    # Performance indexes for frequently queried columns
    __table_args__ = (
        # Index for name lookups (very frequent query)
        Index("ix_groups_name", "name"),
        # Index for prefix searches (GET /groups?prefix=)
        Index(
            "ix_groups_name_prefix",
            "name",
            postgresql_ops={"name": "varchar_pattern_ops"},
        ),
        # Index for created_by foreign key lookups
        Index("ix_groups_created_by", "created_by"),
        # Index for created_at for chronological queries
        Index("ix_groups_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    creator: Mapped[User | None] = relationship(
        "User", foreign_keys=[created_by], back_populates="created_groups"
    )
    group_roles: Mapped[list["GroupRole"]] = relationship(
        "GroupRole", back_populates="group", cascade="all, delete-orphan"
    )
    memberships: Mapped[list["Membership"]] = relationship(
        "Membership", back_populates="group", cascade="all, delete-orphan"
    )
    manager_rights: Mapped[list["GroupManagementRight"]] = relationship(
        "GroupManagementRight",
        foreign_keys="GroupManagementRight.manager_group_id",
        back_populates="manager_group",
        cascade="all, delete-orphan",
    )


class Endpoint(Base):
    """Endpoints table - mapping many endpoint patterns to one action."""

    __tablename__ = "endpoints"

    # Performance indexes for mapping resolution
    __table_args__ = (
        # Composite index for path/method mapping resolution (most critical)
        Index("ix_endpoints_method_path", "method", "path_pattern"),
        # Index for method filtering in resolution
        Index("ix_endpoints_method", "method"),
        # Index for action_id lookups
        Index("ix_endpoints_action_id", "action_id"),
        # Index for path pattern searches
        Index("ix_endpoints_path_pattern", "path_pattern"),
        # Index for created_by auditing
        Index("ix_endpoints_created_by", "created_by"),
        # Index for chronological queries
        Index("ix_endpoints_created_at", "created_at"),
        # Index for updated_at queries
        Index("ix_endpoints_updated_at", "updated_at"),
        # Unique constraint for path_pattern + method combination
        UniqueConstraint("path_pattern", "method", name="uq_endpoints_path_method"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    path_pattern: Mapped[str] = mapped_column(String, nullable=False)
    method: Mapped[str] = mapped_column(String, nullable=False)
    action_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("actions.id", ondelete="RESTRICT"), nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    action: Mapped[Action] = relationship("Action", back_populates="endpoints")
    creator: Mapped[User | None] = relationship(
        "User", foreign_keys=[created_by], back_populates="created_endpoints"
    )


class GroupRole(Base):
    """Group roles table - group to role mapping."""

    __tablename__ = "group_roles"

    # Performance indexes for role aggregation
    __table_args__ = (
        # Index for group_id lookups (get all roles for a group)
        Index("ix_group_roles_group_id", "group_id"),
        # Index for role_id lookups (get all groups with a role)
        Index("ix_group_roles_role_id", "role_id"),
        # Composite index for specific role checks
        Index("ix_group_roles_group_role", "group_id", "role_id"),
    )

    group_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )

    # Relationships
    group: Mapped[Group] = relationship("Group", back_populates="group_roles")
    role: Mapped[Role] = relationship("Role", back_populates="group_roles")


class Membership(Base):
    """Memberships table - group membership."""

    __tablename__ = "memberships"

    # Performance indexes for role aggregation queries
    __table_args__ = (
        # Index for user_id lookups (get all groups for a user)
        Index("ix_memberships_user_id", "user_id"),
        # Index for group_id lookups (get all users in a group)
        Index("ix_memberships_group_id", "group_id"),
        # Composite index for membership checks
        Index("ix_memberships_group_user", "group_id", "user_id"),
        # Index for granted_by auditing
        Index("ix_memberships_granted_by", "granted_by"),
        # Index for chronological queries
        Index("ix_memberships_granted_at", "granted_at"),
    )

    group_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    granted_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    group: Mapped[Group] = relationship("Group", back_populates="memberships")
    user: Mapped[User] = relationship(
        "User", foreign_keys=[user_id], back_populates="memberships"
    )
    granter: Mapped[User | None] = relationship(
        "User", foreign_keys=[granted_by], back_populates="granted_memberships"
    )


class UserRole(Base):
    """User roles table - direct user to role assignments if needed."""

    __tablename__ = "user_roles"

    # Performance indexes for direct role assignments
    __table_args__ = (
        # Index for user_id lookups (get all direct roles for a user)
        Index("ix_user_roles_user_id", "user_id"),
        # Index for role_id lookups (get all users with a direct role)
        Index("ix_user_roles_role_id", "role_id"),
        # Composite index for specific user-role checks (e.g., superadmin lookup)
        Index("ix_user_roles_user_role", "user_id", "role_id"),
        # Index for granted_by auditing
        Index("ix_user_roles_granted_by", "granted_by"),
        # Index for chronological queries
        Index("ix_user_roles_granted_at", "granted_at"),
    )

    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    granted_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    user: Mapped[User] = relationship(
        "User", foreign_keys=[user_id], back_populates="user_roles"
    )
    role: Mapped[Role] = relationship("Role", back_populates="user_roles")
    granter: Mapped[User | None] = relationship(
        "User", foreign_keys=[granted_by], back_populates="granted_user_roles"
    )


class RoleAction(Base):
    """Role actions table - maps roles to actions they can perform."""

    __tablename__ = "role_actions"

    # Performance indexes for role-action queries
    __table_args__ = (
        # Index for role_id lookups (get all actions for a role)
        Index("ix_role_actions_role_id", "role_id"),
        # Index for action_id lookups (get all roles with an action)
        Index("ix_role_actions_action_id", "action_id"),
        # Composite index for specific role-action checks
        Index("ix_role_actions_role_action", "role_id", "action_id"),
        # Index for granted_by auditing
        Index("ix_role_actions_granted_by", "granted_by"),
        # Index for chronological queries
        Index("ix_role_actions_granted_at", "granted_at"),
    )

    role_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    action_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("actions.id", ondelete="CASCADE"), primary_key=True
    )
    granted_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    role: Mapped[Role] = relationship("Role", back_populates="role_actions")
    action: Mapped[Action] = relationship("Action", back_populates="role_actions")
    granter: Mapped[User | None] = relationship("User")


class GroupManagementRight(Base):
    """Group management rights table."""

    __tablename__ = "group_management_rights"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    manager_group_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False
    )
    target_group_pattern: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # Performance indexes for group management right queries
        Index("ix_group_mgmt_rights_manager_group_id", "manager_group_id"),
        Index("ix_group_mgmt_rights_target_pattern", "target_group_pattern"),
        Index("ix_group_mgmt_rights_created_by", "created_by"),
        Index("ix_group_mgmt_rights_created_at", "created_at"),
        # Unique constraint for manager_group_id + target_group_pattern
        UniqueConstraint(
            "manager_group_id",
            "target_group_pattern",
            name="uq_group_management_rights_manager_pattern",
        ),
    )

    # Relationships
    manager_group: Mapped[Group] = relationship(
        "Group", foreign_keys=[manager_group_id], back_populates="manager_rights"
    )
    creator: Mapped[User | None] = relationship(
        "User",
        foreign_keys=[created_by],
        back_populates="created_group_management_rights",
    )


class AdminAudit(Base):
    """Admin audit table - audit log for admin operations."""

    __tablename__ = "admin_audit"

    # Performance indexes for audit queries
    __table_args__ = (
        # Index for actor_subject filtering (most common audit query)
        Index("ix_admin_audit_actor_subject", "actor_subject"),
        # Index for operation filtering
        Index("ix_admin_audit_operation", "operation"),
        # Index for target_type filtering
        Index("ix_admin_audit_target_type", "target_type"),
        # Index for success filtering (error analysis)
        Index("ix_admin_audit_success", "success"),
        # Index for timestamp (chronological queries, very important)
        Index("ix_admin_audit_timestamp", "timestamp"),
        # Index for actor_user_id foreign key
        Index("ix_admin_audit_actor_user_id", "actor_user_id"),
        # Composite index for common filtering combinations
        Index("ix_admin_audit_actor_operation", "actor_subject", "operation"),
        Index("ix_admin_audit_operation_timestamp", "operation", "timestamp"),
        Index("ix_admin_audit_target_type_timestamp", "target_type", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    actor_subject: Mapped[str | None] = mapped_column(String, nullable=True)
    operation: Mapped[str] = mapped_column(String, nullable=False)
    target_type: Mapped[str | None] = mapped_column(String, nullable=True)
    target_id: Mapped[str | None] = mapped_column(String, nullable=True)
    request_payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    actor_user: Mapped[User | None] = relationship(
        "User", back_populates="audit_entries"
    )


class FailedOperation(Base):
    """Failed operations table - tracks operations that failed and need retry."""

    __tablename__ = "failed_operations"

    # Performance indexes for retry queries
    __table_args__ = (
        # Index for operation_type filtering (retry logic)
        Index("ix_failed_operations_operation_type", "operation_type"),
        # Index for status filtering (get pending retries)
        Index("ix_failed_operations_status", "status"),
        # Index for next_retry_at (scheduled retries)
        Index("ix_failed_operations_next_retry_at", "next_retry_at"),
        # Index for failed_at (chronological ordering)
        Index("ix_failed_operations_failed_at", "failed_at"),
        # Index for retry_count (exponential backoff)
        Index("ix_failed_operations_retry_count", "retry_count"),
        # Composite index for active retry queries
        Index("ix_failed_operations_status_next_retry", "status", "next_retry_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    operation_type: Mapped[str] = mapped_column(String, nullable=False)
    operation_data: Mapped[dict] = mapped_column(JSONB, nullable=False)
    error_message: Mapped[str] = mapped_column(Text, nullable=False)
    error_details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_retries: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    status: Mapped[str] = mapped_column(
        String, default="pending", nullable=False
    )  # pending, retrying, failed, succeeded
    failed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_attempted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    succeeded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
