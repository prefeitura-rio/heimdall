"""
Database connection layer for Heimdall Admin Service.
Implements SQLAlchemy engine configuration and session management.
"""

import os
from collections.abc import AsyncGenerator

from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.models import Base


def get_database_url() -> str:
    """Get database URL from environment variables."""
    return os.getenv(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/heimdall_dev"
    )


def create_database_engine() -> Engine:
    """Create SQLAlchemy engine with proper configuration."""
    database_url = get_database_url()

    # Configure engine with connection pooling and settings
    engine = create_engine(
        database_url,
        # Connection pool settings
        pool_pre_ping=True,  # Verify connections before use
        pool_recycle=3600,  # Recycle connections after 1 hour
        # For development, use a smaller pool
        pool_size=5,
        max_overflow=10,
        # Echo SQL queries in debug mode
        echo=os.getenv("SQL_DEBUG", "false").lower() == "true",
    )

    return engine


# Global engine instance
engine = create_database_engine()

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db_session() -> Session:
    """Get database session for dependency injection."""
    db = SessionLocal()
    try:
        return db
    except SQLAlchemyError:
        db.close()
        raise


def get_db() -> AsyncGenerator[Session, None]:
    """Async generator for FastAPI dependency injection."""
    db = SessionLocal()
    try:
        yield db
    except SQLAlchemyError:
        db.rollback()
        raise
    finally:
        db.close()


def test_database_connection() -> bool:
    """Test database connectivity for health checks."""
    try:
        with engine.connect() as connection:
            # Simple query to test connection
            from sqlalchemy import text

            result = connection.execute(text("SELECT 1"))
            return result.scalar() == 1
    except SQLAlchemyError:
        return False


def create_all_tables() -> None:
    """Create all tables (for testing/development only)."""
    Base.metadata.create_all(bind=engine)


def drop_all_tables() -> None:
    """Drop all tables (for testing only)."""
    Base.metadata.drop_all(bind=engine)
