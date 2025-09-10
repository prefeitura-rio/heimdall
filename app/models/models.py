"""
SQLAlchemy models for Heimdall Admin Service.
Implements all tables from SPEC.md Section 2 exactly as specified.
"""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
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

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    endpoints: Mapped[list["Endpoint"]] = relationship(
        "Endpoint", back_populates="action"
    )


class Role(Base):
    """Roles table - represents roles that can be assigned."""

    __tablename__ = "roles"

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


class User(Base):
    """Users table - Keycloak subject storage."""

    __tablename__ = "users"

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

    __table_args__ = (
        UniqueConstraint("path_pattern", "method", name="uq_endpoints_path_method"),
    )

    # Relationships
    action: Mapped[Action] = relationship("Action", back_populates="endpoints")
    creator: Mapped[User | None] = relationship(
        "User", foreign_keys=[created_by], back_populates="created_endpoints"
    )


class GroupRole(Base):
    """Group roles table - group to role mapping."""

    __tablename__ = "group_roles"

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
