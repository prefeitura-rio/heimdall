"""The Redis fast path matches a path_pattern by the database rule (DEV-680).

RedisMappingService.resolve_mapping_fast used re.match on the raw path_pattern,
which has no end anchor: a mapping created through POST /mappings/ as
"/api/v1/actions" also matched "/api/v1/actionsEXPORTALL" and "/api/v1/actions/1",
while the database fallback (MappingService._convert_pattern_to_regex) anchors
every pattern with "^...$" and refuses them.
"""

import json
import re
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Action, Endpoint, User
from app.services.mapping import MappingService
from app.services.redis_mapping import SOURCE_PATTERN_KEY, RedisMappingService
from app.tracing import setup_tracing


@pytest.fixture(scope="module", autouse=True)
def _tracing():
    setup_tracing()


class FakeRedis:
    """In-memory subset of the redis client used by RedisMappingService."""

    def __init__(self):
        self.hashes: dict[str, dict[str, str]] = {}
        self.lists: dict[str, list[str]] = {}
        self.values: dict[str, str] = {}

    def hset(self, name, key, value):
        self.hashes.setdefault(name, {})[key] = value

    def hget(self, name, key):
        value = self.hashes.get(name, {}).get(key)
        return value.encode() if value is not None else None

    def hgetall(self, name):
        return {k.encode(): v.encode() for k, v in self.hashes.get(name, {}).items()}

    def lrem(self, name, _count, value):
        self.lists[name] = [v for v in self.lists.get(name, []) if v != value]

    def lpush(self, name, value):
        self.lists.setdefault(name, []).insert(0, value)

    def lrange(self, name, _start, _end):
        return [v.encode() for v in self.lists.get(name, [])]

    def get(self, key):
        value = self.values.get(key)
        return value.encode() if value is not None else None

    def setex(self, key, _ttl, value):
        self.values[key] = value

    def delete(self, *keys):
        for key in keys:
            self.values.pop(key, None)


@pytest.fixture
def redis_service():
    svc = RedisMappingService()
    fake = FakeRedis()
    svc._cache_service = MagicMock()
    svc._cache_service._get_redis_connection.return_value = fake
    svc.cache_ttl = 300
    return svc


def _store(
    svc, path_pattern, method="GET", mapping_id=1, action="heimdall:actions:list"
):
    assert svc.store_mapping(
        {
            "id": mapping_id,
            "method": method,
            "path_pattern": path_pattern,
            "action_id": mapping_id,
            "action_name": action,
            "description": None,
        }
    )


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/actionsEXPORTALL",
        "/api/v1/actions/",
        "/api/v1/actions/1",
        "/api/v1/actions/1/delete",
    ],
)
def test_pattern_without_end_anchor_does_not_match_longer_path(redis_service, path):
    _store(redis_service, "/api/v1/actions")

    assert redis_service.resolve_mapping_fast("GET", path) is None


def test_pattern_without_end_anchor_matches_exact_path(redis_service):
    _store(redis_service, "/api/v1/actions")

    result = redis_service.resolve_mapping_fast("GET", "/api/v1/actions")

    assert result is not None
    assert result["id"] == 1
    assert result["path_pattern"] == "/api/v1/actions"


def test_longer_path_falls_through_to_its_own_mapping(redis_service):
    # The shorter mapping is pushed last, so it is checked first.
    _store(
        redis_service,
        "/api/v1/actions/([^/]+)$",
        mapping_id=2,
        action="heimdall:actions:read",
    )
    _store(
        redis_service, "/api/v1/actions", mapping_id=1, action="heimdall:actions:list"
    )

    result = redis_service.resolve_mapping_fast("GET", "/api/v1/actions/7")

    assert result is not None
    assert result["action_name"] == "heimdall:actions:read"


def test_prefix_match_is_not_cached(redis_service):
    _store(redis_service, "/api/v1/actions")

    redis_service.resolve_mapping_fast("GET", "/api/v1/actionsEXPORTALL")

    fake = redis_service.redis_client
    assert "heimdall:mappings:lookup:GET:/api/v1/actionsEXPORTALL" not in fake.values


@pytest.mark.parametrize(
    ("path_pattern", "path", "expected"),
    [
        # go-api pipeline format (scripts/manage_openapi_mappings.py, app/mappings_sync.py)
        ("/health$", "/health", True),
        ("/health$", "/healthz", False),
        ("/health$", "/health/x", False),
        ("/users/([^/]+)$", "/users/123", True),
        ("/users/([^/]+)$", "/users/123/posts", False),
        ("^/users/([^/]+)$", "/users/123", True),
        # POST /mappings/ format, without "$"
        ("/api/v1/actions", "/api/v1/actions", True),
        ("/api/v1/actions", "/api/v1/actionsEXPORTALL", False),
        ("/api/v1/users/([^/]+)", "/api/v1/users/abc", True),
        ("/api/v1/users/([^/]+)", "/api/v1/users/abc/roles", False),
        # "." is a literal path character, not "any character"
        ("/api/v1.0/x", "/api/v1.0/x", True),
        ("/api/v1.0/x", "/api/v1X0/x", False),
        # glob segments
        ("/files/*", "/files/a", True),
        ("/files/*", "/files/a/b", False),
        ("/files/**", "/files/a/b", True),
    ],
)
def test_redis_matches_like_database_fallback(
    redis_service, path_pattern, path, expected
):
    _store(redis_service, path_pattern)

    db_regex = MappingService()._convert_pattern_to_regex(path_pattern)

    assert bool(re.match(db_regex, path)) is expected
    assert (redis_service.resolve_mapping_fast("GET", path) is not None) is expected


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


def test_mapping_created_by_api_resolves_the_same_from_redis_and_db(redis_service, db):
    """End to end through create_mapping: Redis and the database agree."""
    user = User(subject="synthetic-admin", display_name="Synthetic Admin")
    action = Action(name="heimdall:actions:list", description="Synthetic action")
    db.add_all([user, action])
    db.commit()

    service = MappingService()
    service.redis_mapping_service = redis_service
    service.cache_service = MagicMock()
    service.audit_service = MagicMock()

    endpoint = service.create_mapping(
        db=db,
        path_pattern="/api/v1/actions",
        method="GET",
        action_id=action.id,
        description=None,
        created_by=user,
    )
    stored = json.loads(
        redis_service.redis_client.hashes["heimdall:mappings:all"][
            f"mapping_{endpoint.id}"
        ]
    )
    # Redis keeps the anchored regex every reader matches, and the raw column.
    assert stored["path_pattern"] == "^/api/v1/actions$"
    assert stored[SOURCE_PATTERN_KEY] == "/api/v1/actions"

    # Redis hit for the exact route; the response shows the database pattern.
    result = service.resolve_mapping(db, "/api/v1/actions", "GET")
    assert result["mapping_id"] == endpoint.id
    assert result["path_pattern"] == "/api/v1/actions"
    # Longer route: Redis no longer matches by prefix, and the database refuses it too.
    assert service.resolve_mapping(db, "/api/v1/actionsEXPORTALL", "GET") is None
    assert service.resolve_mapping(db, "/api/v1/actions/1", "GET") is None


def _stored(svc, mapping_id=1):
    return json.loads(
        svc.redis_client.hashes["heimdall:mappings:all"][f"mapping_{mapping_id}"]
    )


@pytest.mark.parametrize(
    ("path_pattern", "matching", "not_matching"),
    [
        (
            "/api/v1/actions",
            "/api/v1/actions",
            ["/api/v1/actionsEXPORTALL", "/api/v1/actions/1", "/x/api/v1/actions"],
        ),
        ("/health$", "/health", ["/healthz", "/x/health"]),
        ("/users/([^/]+)$", "/users/1", ["/users/1/roles", "/x/users/1"]),
        ("/api/v1.0/x", "/api/v1.0/x", ["/api/v1X0/x"]),
    ],
)
def test_stored_pattern_is_anchored_for_the_edge(
    redis_service, path_pattern, matching, not_matching
):
    """
    The edge (cerbos-ext-authz) reads heimdall:mappings:all directly and runs
    regexp.MatchString(path_pattern, path), an unanchored search. re.search is
    the same semantics: the stored pattern must refuse prefixes by itself.
    """
    _store(redis_service, path_pattern)

    stored = _stored(redis_service)

    assert stored[SOURCE_PATTERN_KEY] == path_pattern
    assert re.search(stored["path_pattern"], matching)
    for path in not_matching:
        assert re.search(stored["path_pattern"], path) is None


def test_store_is_idempotent_on_a_mapping_read_back(redis_service):
    _store(redis_service, "/api/v1.0/x")
    read_back = redis_service.get_all_mappings()[0]
    assert read_back["path_pattern"] == "/api/v1.0/x"
    assert SOURCE_PATTERN_KEY not in read_back

    assert redis_service.store_mapping(read_back)

    assert _stored(redis_service)["path_pattern"] == "^/api/v1\\.0/x$"


def test_legacy_entry_with_raw_pattern_matches_by_the_anchored_rule(redis_service):
    """An entry written before DEV-680 (raw pattern, no source key) until the next sync."""
    fake = redis_service.redis_client
    legacy = {
        "id": 9,
        "method": "GET",
        "path_pattern": "/api/v1/actions",
        "action_name": "a",
    }
    fake.hset("heimdall:mappings:all", "mapping_9", json.dumps(legacy))
    fake.lpush("heimdall:mappings:patterns:GET", "mapping_9")

    assert redis_service.resolve_mapping_fast("GET", "/api/v1/actionsEXPORTALL") is None
    result = redis_service.resolve_mapping_fast("GET", "/api/v1/actions")
    assert result is not None
    assert result["path_pattern"] == "/api/v1/actions"


def test_cache_entry_that_does_not_match_is_dropped(redis_service):
    """
    The lookup cache is shared with the edge: an entry it wrote for a prefix
    match (before its patterns were anchored) must not be trusted.
    """
    _store(redis_service, "/api/v1/actions")
    fake = redis_service.redis_client
    cache_key = "heimdall:mappings:lookup:GET:/api/v1/actionsEXPORTALL"
    fake.setex(cache_key, 300, "mapping_1")

    assert redis_service.resolve_mapping_fast("GET", "/api/v1/actionsEXPORTALL") is None
    assert cache_key not in fake.values


def test_cache_entry_that_matches_is_used(redis_service):
    _store(redis_service, "/api/v1/actions")

    first = redis_service.resolve_mapping_fast("GET", "/api/v1/actions")
    assert (
        "heimdall:mappings:lookup:GET:/api/v1/actions"
        in redis_service.redis_client.values
    )
    second = redis_service.resolve_mapping_fast("GET", "/api/v1/actions")

    assert first == second
    assert second["path_pattern"] == "/api/v1/actions"
    assert SOURCE_PATTERN_KEY not in second
