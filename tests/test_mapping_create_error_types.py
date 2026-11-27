"""Status codes of POST /mappings/ by error type (DEV-577).

A reference to an action that does not exist is a bad request (400), as the
endpoint documents; 409 is kept for a mapping that already exists for the same
path and method. The router tells them apart by exception type, not by text.
"""

import asyncio
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.exceptions import ActionNotFoundError, MappingAlreadyExistsError
from app.models import Action, Endpoint, User
from app.routers.mappings import MappingCreateRequest, create_mapping
from app.services.mapping import MappingService
from app.tracing import setup_tracing

MISSING_ACTION_ID = 9999999


@pytest.fixture(scope="module", autouse=True)
def _tracing():
    # create_mapping reads recorded span attributes, so it needs the app's
    # tracer provider (no exporter without OTEL_EXPORTER_OTLP_ENDPOINT).
    setup_tracing()


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    tables = [User.__table__, Action.__table__, Endpoint.__table__]
    User.metadata.create_all(engine, tables=tables)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def service():
    svc = MappingService()
    svc.redis_mapping_service = MagicMock()
    svc.redis_mapping_service.store_mapping.return_value = True
    svc.cache_service = MagicMock()
    svc.audit_service = MagicMock()
    return svc


@pytest.fixture
def creator(db):
    user = User(subject="synthetic-admin", display_name="Synthetic Admin")
    action = Action(name="qa:read", description="Synthetic action")
    db.add_all([user, action])
    db.commit()
    return user, action


def _post(service, db, user, path_pattern, action_id, method="GET"):
    cerbos_service = MagicMock()
    cerbos_service.can_create_mapping.return_value = True
    user_service = MagicMock()
    user_service.get_user_roles.return_value = ["heimdall_admin"]
    return asyncio.run(
        create_mapping(
            mapping_data=MappingCreateRequest(
                path_pattern=path_pattern,
                method=method,
                action_id=action_id,
                description="Synthetic mapping",
            ),
            current_user=user,
            db=db,
            mapping_service=service,
            cerbos_service=cerbos_service,
            user_service=user_service,
        )
    )


def test_missing_action_returns_400(service, db, creator):
    user, _ = creator

    with pytest.raises(HTTPException) as exc:
        _post(service, db, user, "/qa/fake", MISSING_ACTION_ID)

    assert exc.value.status_code == 400
    assert exc.value.detail == f"Action with ID {MISSING_ACTION_ID} not found"
    assert db.query(Endpoint).count() == 0


def test_duplicate_mapping_still_returns_409(service, db, creator):
    user, action = creator
    created = _post(service, db, user, "/qa/fake", action.id)
    assert created.action == action.name

    with pytest.raises(HTTPException) as exc:
        _post(service, db, user, "/qa/fake", action.id)

    assert exc.value.status_code == 409
    assert "already exists" in exc.value.detail
    assert db.query(Endpoint).count() == 1


def test_same_path_with_other_method_is_not_a_conflict(service, db, creator):
    user, action = creator
    _post(service, db, user, "/qa/fake", action.id, method="GET")

    created = _post(service, db, user, "/qa/fake", action.id, method="POST")

    assert created.method == "POST"
    assert db.query(Endpoint).count() == 2


@pytest.mark.parametrize("path_pattern", ["/users/:id", "/qa/(a))"])
def test_invalid_path_pattern_returns_400_not_409(service, db, creator, path_pattern):
    user, action = creator

    with pytest.raises(HTTPException) as exc:
        _post(service, db, user, path_pattern, action.id)

    assert exc.value.status_code == 400
    assert exc.value.detail.startswith("Invalid path pattern")
    assert db.query(Endpoint).count() == 0


def test_missing_action_on_a_duplicate_path_is_still_400(service, db, creator):
    # The action reference is checked before the path+method conflict.
    user, action = creator
    _post(service, db, user, "/qa/fake", action.id)

    with pytest.raises(HTTPException) as exc:
        _post(service, db, user, "/qa/fake", MISSING_ACTION_ID)

    assert exc.value.status_code == 400


def test_service_raises_typed_errors(service, db, creator):
    user, action = creator
    kwargs = {"db": db, "method": "GET", "description": None, "created_by": user}

    with pytest.raises(ActionNotFoundError) as missing:
        service.create_mapping(
            path_pattern="/qa/fake", action_id=MISSING_ACTION_ID, **kwargs
        )
    assert missing.value.action_id == MISSING_ACTION_ID

    service.create_mapping(path_pattern="/qa/fake", action_id=action.id, **kwargs)
    with pytest.raises(MappingAlreadyExistsError):
        service.create_mapping(path_pattern="/qa/fake", action_id=action.id, **kwargs)

    # Both stay ValueError, so callers that catch ValueError keep working.
    assert issubclass(ActionNotFoundError, ValueError)
    assert issubclass(MappingAlreadyExistsError, ValueError)
