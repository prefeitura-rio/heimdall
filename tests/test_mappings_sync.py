"""Tests for the versioned endpoint-to-action mappings (DEV-650)."""

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sqlalchemy import DateTime, create_engine, literal, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.mappings_sync import (
    EXIT_INVALID_FILE,
    EXIT_OK,
    EXIT_PLAN_ERRORS,
    SYNC_SUBJECT,
    ChangeKind,
    MappingFile,
    build_plan,
    load_mapping_file,
    route_pattern,
    run,
)
from app.models import Action, Endpoint, User
from app.services.mapping import MappingService
from app.tracing import setup_tracing

REPO_FILE = Path(__file__).resolve().parent.parent / "mappings" / "go-api.json"

# Action names that exist only in the staging database; the tests use synthetic
# ones, the real file only relies on "public" and on same_as references.
WRITE_ACTION = "synthetic:catalog:write"
CITIZEN_ACTION = "authenticated"
OTHER_ACTION = "synthetic:other"


@pytest.fixture(scope="module", autouse=True)
def _tracing():
    setup_tracing()


@pytest.fixture
def engine():
    eng = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )

    tables = [User.__table__, Action.__table__, Endpoint.__table__]
    User.metadata.create_all(eng, tables=tables)
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine):
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def service(monkeypatch):
    # update_mapping stamps updated_at with Postgres "SELECT now()"; SQLite has
    # no now(), so give it the portable equivalent.
    monkeypatch.setattr(
        "app.services.mapping.text",
        lambda sql: (
            select(literal(datetime.now(UTC), DateTime))
            if sql == "SELECT now()"
            else text(sql)
        ),
    )
    svc = MappingService()
    svc.redis_mapping_service = MagicMock()
    svc.redis_mapping_service.store_mapping.return_value = True
    svc.redis_mapping_service.remove_mapping.return_value = True
    svc.cache_service = MagicMock()
    svc.audit_service = MagicMock()
    return svc


def _action(db, name):
    action = db.query(Action).filter(Action.name == name).first()
    if action is None:
        action = Action(name=name, description="synthetic")
        db.add(action)
        db.commit()
    return action


def _mapping(db, method, pattern, action_name):
    endpoint = Endpoint(
        path_pattern=pattern, method=method, action_id=_action(db, action_name).id
    )
    db.add(endpoint)
    db.commit()
    return endpoint


def _actions_by_key(db):
    return {(e.method, e.path_pattern): e.action.name for e in db.query(Endpoint).all()}


@pytest.fixture
def staging_like(db):
    """The state the issue describes: siblings mapped, the four cases not."""
    for name in ("public", WRITE_ACTION, CITIZEN_ACTION, OTHER_ACTION):
        _action(db, name)
    go = "/go/api/v1"
    _mapping(db, "GET", f"{go}/empregabilidade/zonas$", "public")
    _mapping(db, "GET", f"{go}/categorias$", "public")
    _mapping(db, "POST", f"{go}/categorias$", WRITE_ACTION)
    _mapping(db, "PUT", f"{go}/categorias/([^/]+)$", WRITE_ACTION)
    _mapping(db, "DELETE", f"{go}/categorias/([^/]+)$", WRITE_ACTION)
    _mapping(
        db, "GET", f"{go}/empregabilidade/candidaturas/usuario/([^/]+)$", CITIZEN_ACTION
    )
    _mapping(db, "POST", f"{go}/typesense/multi-search$", "public")
    for catalog in (
        "modelos-trabalho",
        "tipos-pcd",
        "escolaridades",
        "tipos-conquista",
        "disponibilidades",
    ):
        _mapping(db, "GET", f"{go}/empregabilidade/{catalog}$", CITIZEN_ACTION)
        _mapping(db, "GET", f"{go}/empregabilidade/{catalog}/([^/]+)$", CITIZEN_ACTION)
    # DEV-659: idiomas and situacoes-atual are listed publicly, but their GET by
    # id is unmapped (idiomas) or mapped to an authenticated action
    # (situacoes-atual); their writes stay with the admin action.
    for catalog in ("idiomas", "situacoes-atual"):
        _mapping(db, "GET", f"{go}/empregabilidade/{catalog}$", "public")
        _mapping(db, "POST", f"{go}/empregabilidade/{catalog}$", WRITE_ACTION)
        _mapping(db, "PUT", f"{go}/empregabilidade/{catalog}/([^/]+)$", WRITE_ACTION)
    _mapping(
        db, "GET", f"{go}/empregabilidade/situacoes-atual/([^/]+)$", CITIZEN_ACTION
    )
    # Same route without "/go", as the OpenAPI tool also generates it.
    _mapping(db, "GET", "/api/v1/empregabilidade/tipos-pcd$", CITIZEN_ACTION)
    # A mapping of another application, never to be touched.
    _mapping(db, "GET", "/rmi/v1/citizen/([^/]+)$", OTHER_ACTION)
    return db


def _spec(**overrides):
    data = {
        "application": "go-api",
        "path_prefix": "/go/",
        "mappings": [
            {"method": "GET", "path": "/go/api/v1/empresas", "action": "public"},
        ],
    }
    data.update(overrides)
    return MappingFile.model_validate(data)


def test_route_pattern_matches_openapi_tool_format():
    assert route_pattern("/go/api/v1/empresas") == "/go/api/v1/empresas$"
    assert (
        route_pattern(
            "/go/api/v1/empregabilidade/candidaturas/usuario/{cpf}/visualizar"
        )
        == "/go/api/v1/empregabilidade/candidaturas/usuario/([^/]+)/visualizar$"
    )


def test_versioned_file_covers_the_four_cases_of_the_issue():
    spec = load_mapping_file(REPO_FILE)
    entries = {(e.method, e.path): e for e in spec.mappings}

    visualizar = entries[
        ("PUT", "/go/api/v1/empregabilidade/candidaturas/usuario/{cpf}/visualizar")
    ]
    assert visualizar.same_as is not None
    assert (visualizar.same_as.method, visualizar.same_as.path) == (
        "GET",
        "/go/api/v1/empregabilidade/candidaturas/usuario/{cpf}",
    )

    for catalog in (
        "modelos-trabalho",
        "tipos-pcd",
        "escolaridades",
        "tipos-conquista",
        "disponibilidades",
    ):
        for path in (
            f"/go/api/v1/empregabilidade/{catalog}",
            f"/go/api/v1/empregabilidade/{catalog}/{{id}}",
        ):
            assert entries[("GET", path)].action == "public"

    for resource in ("instituicoes", "empresas"):
        base = f"/go/api/v1/{resource}"
        assert entries[("GET", base)].action == "public"
        assert entries[("GET", f"{base}/{{id}}")].action == "public"
        refs = {
            m: (entries[(m, p)].same_as.method, entries[(m, p)].same_as.path)
            for m, p in (
                ("POST", base),
                ("PUT", f"{base}/{{id}}"),
                ("DELETE", f"{base}/{{id}}"),
            )
        }
        assert refs == {
            "POST": ("POST", "/go/api/v1/categorias"),
            "PUT": ("PUT", "/go/api/v1/categorias/{id}"),
            "DELETE": ("DELETE", "/go/api/v1/categorias/{id}"),
        }

    for kind in ("cursos", "empregos"):
        assert (
            entries[("POST", f"/go/api/v1/typesense/{kind}/search")].action == "public"
        )

    assert len(spec.mappings) == 29
    assert spec.remove == []


def test_plan_on_staging_like_db_shows_what_enters_and_changes(staging_like):
    db = staging_like
    before = _actions_by_key(db)
    plan = build_plan(db, load_mapping_file(REPO_FILE))

    assert plan.errors == []
    assert _actions_by_key(db) == before  # plan never writes
    creates = {
        (c.method, c.path_pattern): c.action_name
        for c in plan.changes
        if c.kind == ChangeKind.CREATE
    }
    updates = {
        (c.method, c.path_pattern): (c.old_action_name, c.action_name)
        for c in plan.changes
        if c.kind == ChangeKind.UPDATE
    }

    assert (
        creates[
            (
                "PUT",
                "/go/api/v1/empregabilidade/candidaturas/usuario/([^/]+)/visualizar$",
            )
        ]
        == CITIZEN_ACTION
    )
    assert creates[("POST", "/go/api/v1/empresas$")] == WRITE_ACTION
    assert creates[("DELETE", "/go/api/v1/instituicoes/([^/]+)$")] == WRITE_ACTION
    assert creates[("GET", "/go/api/v1/instituicoes$")] == "public"
    assert creates[("POST", "/go/api/v1/typesense/cursos/search$")] == "public"
    assert len(creates) == 18
    assert updates[("GET", "/go/api/v1/empregabilidade/tipos-pcd/([^/]+)$")] == (
        CITIZEN_ACTION,
        "public",
    )
    # The alias without "/go" is aligned too, so it cannot win at the edge.
    assert updates[("GET", "/api/v1/empregabilidade/tipos-pcd$")] == (
        CITIZEN_ACTION,
        "public",
    )
    assert len(updates) == 12
    assert not any(c.kind == ChangeKind.DELETE for c in plan.changes)


def test_versioned_file_makes_idiomas_and_situacoes_atual_by_id_public():
    spec = load_mapping_file(REPO_FILE)
    entries = {(e.method, e.path): e for e in spec.mappings}
    for catalog in ("idiomas", "situacoes-atual"):
        entry = entries[("GET", f"/go/api/v1/empregabilidade/{catalog}/{{id}}")]
        assert entry.action == "public"
        assert entry.source == "DEV-659"
    # Only the GET by id is declared: no write route of these catalogs is in
    # the file, so the sync never touches their admin action.
    declared = {
        (e.method, e.path)
        for e in spec.mappings
        if "/idiomas" in e.path or "/situacoes-atual" in e.path
    }
    assert declared == {
        ("GET", "/go/api/v1/empregabilidade/idiomas/{id}"),
        ("GET", "/go/api/v1/empregabilidade/situacoes-atual/{id}"),
    }


def test_apply_makes_idiomas_and_situacoes_atual_by_id_public_keeping_writes(
    staging_like, engine, service
):
    db = staging_like
    go = "/go/api/v1/empregabilidade"
    plan = build_plan(db, load_mapping_file(REPO_FILE))
    assert plan.errors == []
    changes = {
        (c.method, c.path_pattern): (c.kind, c.old_action_name, c.action_name)
        for c in plan.changes
    }
    assert changes[("GET", f"{go}/idiomas/([^/]+)$")] == (
        ChangeKind.CREATE,
        None,
        "public",
    )
    assert changes[("GET", f"{go}/situacoes-atual/([^/]+)$")] == (
        ChangeKind.UPDATE,
        CITIZEN_ACTION,
        "public",
    )

    assert run("apply", str(REPO_FILE), db, engine, service) == EXIT_OK
    after = _actions_by_key(db)
    for catalog in ("idiomas", "situacoes-atual"):
        assert after[("GET", f"{go}/{catalog}/([^/]+)$")] == "public"
        assert after[("GET", f"{go}/{catalog}$")] == "public"
        assert after[("POST", f"{go}/{catalog}$")] == WRITE_ACTION
        assert after[("PUT", f"{go}/{catalog}/([^/]+)$")] == WRITE_ACTION


def test_versioned_file_makes_the_public_course_catalog_public():
    spec = load_mapping_file(REPO_FILE)
    entries = {(e.method, e.path): e for e in spec.mappings}
    for path in ("/go/api/public/courses", "/go/api/public/courses/{id}"):
        entry = entries[("GET", path)]
        assert entry.action == "public"
        assert entry.source == "DEV-705"
    # Only the two reads of the citizen catalog are declared: the course writes
    # live under /api/v1/courses and keep their own mappings.
    declared = {(e.method, e.path) for e in spec.mappings if "courses" in e.path}
    assert declared == {
        ("GET", "/go/api/public/courses"),
        ("GET", "/go/api/public/courses/{id}"),
    }


def test_apply_maps_the_public_course_catalog_despite_a_prefix_leftover(
    staging_like, engine, service
):
    # DEV-705: the catalog only resolved by inheriting, by prefix, the action of
    # a shorter pattern without "$". Since DEV-680 the edge matches the anchored
    # pattern, so that leftover no longer wins and must not abort the sync.
    db = staging_like
    _mapping(db, "GET", "/go/api/public", OTHER_ACTION)
    _mapping(db, "GET", "/api/public/courses", OTHER_ACTION)
    plan = build_plan(db, load_mapping_file(REPO_FILE))
    assert plan.errors == []
    changes = {
        (c.method, c.path_pattern): (c.kind, c.action_name)
        for c in plan.changes
        if "/public/" in c.path_pattern
    }
    assert changes == {
        ("GET", "/go/api/public/courses$"): (ChangeKind.CREATE, "public"),
        ("GET", "/go/api/public/courses/([^/]+)$"): (ChangeKind.CREATE, "public"),
        ("GET", "/go/api/public/oportunidades-mei$"): (ChangeKind.CREATE, "public"),
        ("GET", "/go/api/public/oportunidades-mei/([^/]+)$"): (
            ChangeKind.CREATE,
            "public",
        ),
    }

    assert run("apply", str(REPO_FILE), db, engine, service) == EXIT_OK
    after = _actions_by_key(db)
    assert after[("GET", "/go/api/public/courses$")] == "public"
    assert after[("GET", "/go/api/public/courses/([^/]+)$")] == "public"
    # The leftovers are not declared in the file, so they are left alone.
    assert after[("GET", "/go/api/public")] == OTHER_ACTION
    assert after[("GET", "/api/public/courses")] == OTHER_ACTION


def test_versioned_file_makes_the_public_mei_opportunities_public():
    spec = load_mapping_file(REPO_FILE)
    entries = {(e.method, e.path): e for e in spec.mappings}
    for path in (
        "/go/api/public/oportunidades-mei",
        "/go/api/public/oportunidades-mei/{id}",
    ):
        entry = entries[("GET", path)]
        assert entry.action == "public"
        assert entry.source == "DEV-707"
    # Only the two reads of the public group are declared: the management of
    # the opportunities and their proposals live under /api/v1/oportunidades-mei
    # and keep their own mappings (DEV-478).
    declared = {
        (e.method, e.path) for e in spec.mappings if "oportunidades-mei" in e.path
    }
    assert declared == {
        ("GET", "/go/api/public/oportunidades-mei"),
        ("GET", "/go/api/public/oportunidades-mei/{id}"),
    }


def test_apply_maps_the_public_mei_opportunities_keeping_the_v1_group(
    staging_like, engine, service
):
    db = staging_like
    v1 = "/go/api/v1/oportunidades-mei"
    _mapping(db, "GET", f"{v1}/drafts$", WRITE_ACTION)
    _mapping(db, "PUT", f"{v1}/([^/]+)$", WRITE_ACTION)
    _mapping(db, "GET", f"{v1}/([^/]+)/propostas$", CITIZEN_ACTION)
    plan = build_plan(db, load_mapping_file(REPO_FILE))
    assert plan.errors == []
    changes = {
        (c.method, c.path_pattern): (c.kind, c.action_name)
        for c in plan.changes
        if "oportunidades-mei" in c.path_pattern
    }
    assert changes == {
        ("GET", "/go/api/public/oportunidades-mei$"): (ChangeKind.CREATE, "public"),
        ("GET", "/go/api/public/oportunidades-mei/([^/]+)$"): (
            ChangeKind.CREATE,
            "public",
        ),
    }

    assert run("apply", str(REPO_FILE), db, engine, service) == EXIT_OK
    after = _actions_by_key(db)
    assert after[("GET", "/go/api/public/oportunidades-mei$")] == "public"
    assert after[("GET", "/go/api/public/oportunidades-mei/([^/]+)$")] == "public"
    assert after[("GET", f"{v1}/drafts$")] == WRITE_ACTION
    assert after[("PUT", f"{v1}/([^/]+)$")] == WRITE_ACTION
    assert after[("GET", f"{v1}/([^/]+)/propostas$")] == CITIZEN_ACTION


@pytest.mark.parametrize(
    "pattern",
    [
        "/go/api/public/([^/]+)/([^/]+)$",
        "/go/api/public/**",
        "/go/api/public/courses/*",
    ],
)
def test_pattern_that_still_wins_at_the_edge_is_an_error(db, pattern):
    _action(db, "public")
    _mapping(db, "GET", pattern, OTHER_ACTION)
    plan = build_plan(
        db,
        _spec(
            mappings=[
                {
                    "method": "GET",
                    "path": "/go/api/public/courses/{id}",
                    "action": "public",
                }
            ]
        ),
    )
    assert len(plan.errors) == 1
    assert "can win at the edge" in plan.errors[0]


def test_apply_is_idempotent_and_leaves_other_mappings_alone(
    staging_like, engine, service, capsys
):
    db = staging_like
    rmi_before = _actions_by_key(db)[("GET", "/rmi/v1/citizen/([^/]+)$")]

    assert run("apply", str(REPO_FILE), db, engine, service) == EXIT_OK
    after = _actions_by_key(db)
    assert (
        after[
            (
                "PUT",
                "/go/api/v1/empregabilidade/candidaturas/usuario/([^/]+)/visualizar$",
            )
        ]
        == CITIZEN_ACTION
    )
    assert after[("GET", "/go/api/v1/empregabilidade/disponibilidades$")] == "public"
    assert after[("PUT", "/go/api/v1/instituicoes/([^/]+)$")] == WRITE_ACTION
    assert after[("POST", "/go/api/v1/typesense/empregos/search$")] == "public"
    assert after[("GET", "/rmi/v1/citizen/([^/]+)$")] == rmi_before
    assert after[("POST", "/go/api/v1/categorias$")] == WRITE_ACTION
    created = (
        db.query(Endpoint).filter(Endpoint.path_pattern == "/go/api/v1/empresas$").all()
    )
    assert {e.method for e in created} == {"GET", "POST"}
    assert all(e.created_by is None for e in created)
    assert db.query(User).count() == 0  # the sync actor is never persisted
    assert service.redis_mapping_service.store_mapping.called
    actors = {
        c.kwargs["actor_subject"]
        for c in service.audit_service.safe_log_operation.call_args_list
    }
    assert actors == {SYNC_SUBJECT}

    count = db.query(Endpoint).count()
    capsys.readouterr()
    assert run("apply", str(REPO_FILE), db, engine, service) == EXIT_OK
    out = capsys.readouterr().out
    assert "0 to create, 0 to update, 0 to delete, 29 unchanged" in out
    assert "No changes to apply." in out
    assert db.query(Endpoint).count() == count


def test_plan_command_never_writes(staging_like, engine, service, capsys):
    db = staging_like
    before = _actions_by_key(db)
    assert run("plan", str(REPO_FILE), db, engine, service) == EXIT_OK
    assert _actions_by_key(db) == before
    out = capsys.readouterr().out
    assert "18 to create, 12 to update, 0 to delete" in out
    assert "Dry run (plan): nothing was written." in out
    service.redis_mapping_service.store_mapping.assert_not_called()


def test_reference_without_mapping_aborts_before_any_write(
    db, engine, service, tmp_path
):
    _action(db, "public")
    _mapping(db, "GET", "/go/api/v1/categorias$", "public")
    spec_file = tmp_path / "go.json"
    spec_file.write_text(
        json.dumps(
            {
                "application": "go-api",
                "path_prefix": "/go/",
                "mappings": [
                    {
                        "method": "GET",
                        "path": "/go/api/v1/empresas",
                        "action": "public",
                    },
                    {
                        "method": "POST",
                        "path": "/go/api/v1/empresas",
                        "same_as": {"method": "POST", "path": "/go/api/v1/categorias"},
                    },
                ],
            }
        )
    )
    before = _actions_by_key(db)
    assert run("apply", str(spec_file), db, engine, service) == EXIT_PLAN_ERRORS
    assert _actions_by_key(db) == before


def test_unknown_action_is_an_error(db):
    _action(db, "public")
    plan = build_plan(
        db,
        _spec(mappings=[{"method": "GET", "path": "/go/api/v1/x", "action": "nope"}]),
    )
    assert plan.errors and "does not exist" in plan.errors[0]


def test_shadowing_pattern_of_another_route_is_an_error(db):
    _action(db, "public")
    _mapping(db, "GET", "/go/api/v1/([^/]+)$", OTHER_ACTION)
    plan = build_plan(db, _spec())
    assert len(plan.errors) == 1
    assert "can win at the edge" in plan.errors[0]


def test_ambiguous_reference_is_an_error(db):
    _action(db, "public")
    _mapping(db, "POST", "/go/api/v1/([^/]+)$", OTHER_ACTION)
    _mapping(db, "POST", "/v1/categorias$", WRITE_ACTION)
    plan = build_plan(
        db,
        _spec(
            mappings=[
                {
                    "method": "POST",
                    "path": "/go/api/v1/empresas",
                    "same_as": {"method": "POST", "path": "/go/api/v1/categorias"},
                },
            ]
        ),
    )
    assert any("disagree" in e for e in plan.errors)


def test_remove_deletes_only_the_declared_route(db, engine, service, tmp_path, capsys):
    _action(db, "public")
    _mapping(db, "GET", "/go/api/v1/legado$", "public")
    _mapping(db, "GET", "/api/v1/legado$", "public")
    spec_file = tmp_path / "go.json"
    spec_file.write_text(
        json.dumps(
            {
                "application": "go-api",
                "path_prefix": "/go/",
                "mappings": [],
                "remove": [{"method": "GET", "path": "/go/api/v1/legado"}],
            }
        )
    )
    assert run("plan", str(spec_file), db, engine, service) == EXIT_OK
    assert "- delete    GET    /go/api/v1/legado$" in capsys.readouterr().out
    assert len(_actions_by_key(db)) == 2
    assert run("apply", str(spec_file), db, engine, service) == EXIT_OK
    assert set(_actions_by_key(db)) == {("GET", "/api/v1/legado$")}


@pytest.mark.parametrize(
    "overrides, reason",
    [
        (
            {"mappings": [{"method": "GET", "path": "/rmi/v1/x", "action": "public"}]},
            "outside path_prefix",
        ),
        (
            {"remove": [{"method": "GET", "path": "/rmi/v1/citizen/{cpf}"}]},
            "outside path_prefix",
        ),
        (
            {
                "mappings": [
                    {"method": "GET", "path": "/go/api/v1/(.*)", "action": "public"}
                ]
            },
            "regex is generated",
        ),
        (
            {
                "mappings": [
                    {
                        "method": "GET",
                        "path": "/go/x",
                        "action": "public",
                        "same_as": {"method": "GET", "path": "/go/y"},
                    }
                ]
            },
            "exactly one",
        ),
        ({"mappings": [{"method": "GET", "path": "/go/x"}]}, "exactly one"),
        (
            {
                "mappings": [
                    {"method": "GET", "path": "/go/x", "action": "public"},
                    {"method": "GET", "path": "/go/x", "action": "public"},
                ]
            },
            "declared twice",
        ),
        ({"path_prefix": "/"}, "path_prefix"),
        (
            {"mappings": [{"method": "TRACE", "path": "/go/x", "action": "public"}]},
            "method",
        ),
    ],
)
def test_invalid_files_are_refused(tmp_path, overrides, reason, db, engine, service):
    data = {
        "application": "go-api",
        "path_prefix": "/go/",
        "mappings": [
            {"method": "GET", "path": "/go/api/v1/empresas", "action": "public"}
        ],
    }
    data.update(overrides)
    spec_file = tmp_path / "bad.json"
    spec_file.write_text(json.dumps(data))
    with pytest.raises(ValueError, match=reason):
        load_mapping_file(spec_file)
    assert run("apply", str(spec_file), db, engine, service) == EXIT_INVALID_FILE
