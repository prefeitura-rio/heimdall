"""Tests for the database fallback of mapping resolution (DEV-185)."""

import re
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Action, Endpoint, User
from app.services.mapping import MappingService
from app.tracing import setup_tracing

# Patterns exactly as scripts/manage_openapi_mappings.py generates them:
# "{param}" becomes "([^/]+)" and only an end anchor "$" is appended.
OPENAPI_NO_PARAM = "/health$"
OPENAPI_WITH_PARAM = "/users/([^/]+)$"


@pytest.fixture(scope="module", autouse=True)
def _tracing():
    # Same tracer provider the app installs at startup (no exporter without
    # OTEL_EXPORTER_OTLP_ENDPOINT): create_mapping reads recorded span attributes.
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
    # Redis lost the pattern entries: the fast path never finds a mapping.
    svc.redis_mapping_service.resolve_mapping_fast.return_value = None
    svc.redis_mapping_service.store_mapping.return_value = True
    svc.cache_service = MagicMock()
    svc.audit_service = MagicMock()
    return svc


@pytest.fixture
def creator(db):
    user = User(subject="synthetic-admin", display_name="Synthetic Admin")
    action = Action(name="health:read", description="Synthetic action")
    db.add_all([user, action])
    db.commit()
    return user, action


def _create(service, db, creator, path_pattern, method="GET"):
    user, action = creator
    return service.create_mapping(
        db=db,
        path_pattern=path_pattern,
        method=method,
        action_id=action.id,
        description=None,
        created_by=user,
    )


def test_route_without_param_resolves_from_db_when_redis_lost_it(service, db, creator):
    endpoint = _create(service, db, creator, OPENAPI_NO_PARAM)

    result = service.resolve_mapping(db, "/health", "GET")

    assert result is not None
    assert result["mapping_id"] == endpoint.id
    assert result["action"] == "health:read"
    assert result["path_pattern"] == OPENAPI_NO_PARAM
    service.redis_mapping_service.resolve_mapping_fast.assert_called_with(
        "GET", "/health"
    )
    stored = service.redis_mapping_service.store_mapping.call_args.args[0]
    assert stored["id"] == endpoint.id


@pytest.mark.parametrize(
    "path", ["/health/", "/health/x", "/healthz", "/health$", "/api/health"]
)
def test_route_without_param_does_not_match_other_paths(service, db, creator, path):
    _create(service, db, creator, OPENAPI_NO_PARAM)

    assert service.resolve_mapping(db, path, "GET") is None


def test_route_without_param_does_not_match_other_method(service, db, creator):
    _create(service, db, creator, OPENAPI_NO_PARAM)

    assert service.resolve_mapping(db, "/health", "POST") is None


def test_route_with_param_still_resolves_from_db(service, db, creator):
    _create(service, db, creator, OPENAPI_WITH_PARAM)

    assert service.resolve_mapping(db, "/users/123", "GET") is not None
    assert service.resolve_mapping(db, "/users/123/posts", "GET") is None


@pytest.mark.parametrize(
    ("path_pattern", "path", "expected"),
    [
        (OPENAPI_NO_PARAM, "/health", True),
        (OPENAPI_NO_PARAM, "/health/x", False),
        (OPENAPI_NO_PARAM, "/healthz", False),
        ("/api/v1/status$", "/api/v1/status", True),
        ("/api/v1/status$", "/api/v1/status/extra", False),
        (OPENAPI_WITH_PARAM, "/users/1", True),
        (OPENAPI_WITH_PARAM, "/users/1/x", False),
    ],
)
def test_db_fallback_agrees_with_redis_fast_path(path_pattern, path, expected):
    # The Redis fast path matches the raw stored pattern with re.match.
    assert bool(re.match(path_pattern, path)) is expected
    regex = MappingService()._convert_pattern_to_regex(path_pattern)
    assert bool(re.match(regex, path)) is expected


@pytest.mark.parametrize(
    ("path_pattern", "matches", "rejects"),
    [
        ("/health", ["/health"], ["/health/x", "/healthz"]),
        ("^/health$", ["/health"], ["/health/x", "/^/health"]),
        ("^/health", ["/health"], ["/healthz"]),
        ("/api/*", ["/api/x"], ["/api/x/y"]),
        ("/api/**", ["/api/x/y"], ["/other"]),
        ("/a.b", ["/a.b"], ["/axb"]),
    ],
)
def test_simple_patterns_keep_their_meaning(path_pattern, matches, rejects):
    regex = MappingService()._convert_pattern_to_regex(path_pattern)
    for path in matches:
        assert re.match(regex, path), (path_pattern, path, regex)
    for path in rejects:
        assert not re.match(regex, path), (path_pattern, path, regex)


def test_escaped_literal_dollar_is_not_taken_as_anchor():
    regex = MappingService()._convert_pattern_to_regex(r"/price\$")

    assert re.match(regex, "/price\\$")
    assert not re.match(regex, "/price")
    assert not re.match(regex, "/price\\$extra")
