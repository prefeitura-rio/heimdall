"""Tests for the versioned endpoint-to-action mappings (DEV-650)."""

import json
import re
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
from app.services.path_pattern import convert_pattern_to_regex
from app.tracing import setup_tracing

REPO_FILE = Path(__file__).resolve().parent.parent / "mappings" / "go-api.json"

# Action names that exist only in the staging database; the tests use synthetic
# ones, the real file only relies on "public" and on same_as references.
WRITE_ACTION = "synthetic:catalog:write"
CITIZEN_ACTION = "authenticated"
OTHER_ACTION = "synthetic:other"
VAGA_ACTION = "synthetic:vaga:edit"


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
    for name in ("public", WRITE_ACTION, CITIZEN_ACTION, OTHER_ACTION, VAGA_ACTION):
        _action(db, name)
    go = "/go/api/v1"
    # DEV-749: the zonas catalog has no mapping at all (no action mapping).
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
    # DEV-659: the GET by id of idiomas and situacoes-atual is unmapped
    # (idiomas) or mapped to an authenticated action (situacoes-atual); their
    # writes stay with the admin action. DEV-748: situacoes-atual is listed
    # publicly, but the listing of idiomas is mapped to an authenticated action.
    for catalog in ("idiomas", "situacoes-atual"):
        listing = CITIZEN_ACTION if catalog == "idiomas" else "public"
        _mapping(db, "GET", f"{go}/empregabilidade/{catalog}$", listing)
        _mapping(db, "POST", f"{go}/empregabilidade/{catalog}$", WRITE_ACTION)
        _mapping(db, "PUT", f"{go}/empregabilidade/{catalog}/([^/]+)$", WRITE_ACTION)
        _mapping(db, "DELETE", f"{go}/empregabilidade/{catalog}/([^/]+)$", WRITE_ACTION)
    _mapping(
        db, "GET", f"{go}/empregabilidade/situacoes-atual/([^/]+)$", CITIZEN_ACTION
    )
    # DEV-748: the edition of a vacancy is mapped, its idiomas-requisito is not.
    _mapping(db, "PUT", f"{go}/empregabilidade/vagas/([^/]+)$", VAGA_ACTION)
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

    assert len(spec.mappings) == 36
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
    assert len(creates) == 24
    assert updates[("GET", "/go/api/v1/empregabilidade/tipos-pcd/([^/]+)$")] == (
        CITIZEN_ACTION,
        "public",
    )
    # The alias without "/go" is aligned too, so it cannot win at the edge.
    assert updates[("GET", "/api/v1/empregabilidade/tipos-pcd$")] == (
        CITIZEN_ACTION,
        "public",
    )
    assert len(updates) == 13
    assert not any(c.kind == ChangeKind.DELETE for c in plan.changes)


def test_versioned_file_makes_idiomas_and_situacoes_atual_by_id_public():
    spec = load_mapping_file(REPO_FILE)
    entries = {(e.method, e.path): e for e in spec.mappings}
    for catalog in ("idiomas", "situacoes-atual"):
        entry = entries[("GET", f"/go/api/v1/empregabilidade/{catalog}/{{id}}")]
        assert entry.action == "public"
        assert entry.source == "DEV-659"
    # Only reads are declared (the GET by id, and since DEV-748 the listing of
    # idiomas): no write route of these catalogs is in the file, so the sync
    # never touches their admin action.
    declared = {
        (e.method, e.path)
        for e in spec.mappings
        if e.path.startswith(
            (
                "/go/api/v1/empregabilidade/idiomas",
                "/go/api/v1/empregabilidade/situacoes-atual",
            )
        )
    }
    assert declared == {
        ("GET", "/go/api/v1/empregabilidade/idiomas"),
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


def test_versioned_file_maps_idiomas_listing_and_vaga_idiomas_requisito():
    spec = load_mapping_file(REPO_FILE)
    entries = {(e.method, e.path): e for e in spec.mappings}
    listing = entries[("GET", "/go/api/v1/empregabilidade/idiomas")]
    assert listing.action == "public"
    assert listing.same_as is None
    assert listing.source == "DEV-748"
    requisito = entries[
        ("PUT", "/go/api/v1/empregabilidade/vagas/{id}/idiomas-requisito")
    ]
    assert requisito.action is None
    assert requisito.same_as is not None
    assert (requisito.same_as.method, requisito.same_as.path) == (
        "PUT",
        "/go/api/v1/empregabilidade/vagas/{id}",
    )
    assert requisito.source == "DEV-748"
    # The only vacancy route in the file: the edition of the vacancy itself and
    # the ownership check (vagaAuth, vagaOwnership) stay with the go-api.
    assert {(e.method, e.path) for e in spec.mappings if "/vagas" in e.path} == {
        ("PUT", "/go/api/v1/empregabilidade/vagas/{id}/idiomas-requisito")
    }


def test_apply_makes_idiomas_listing_public_and_maps_vaga_idiomas_requisito(
    staging_like, engine, service
):
    db = staging_like
    go = "/go/api/v1/empregabilidade"
    requisito = f"{go}/vagas/([^/]+)/idiomas-requisito$"
    _mapping(db, "GET", "/api/v1/empregabilidade/idiomas$", CITIZEN_ACTION)
    plan = build_plan(db, load_mapping_file(REPO_FILE))
    assert plan.errors == []
    changes = {
        (c.method, c.path_pattern): (c.kind, c.old_action_name, c.action_name)
        for c in plan.changes
    }
    assert changes[("GET", f"{go}/idiomas$")] == (
        ChangeKind.UPDATE,
        CITIZEN_ACTION,
        "public",
    )
    # The alias without "/go" is aligned too, so it cannot win at the edge.
    assert changes[("GET", "/api/v1/empregabilidade/idiomas$")] == (
        ChangeKind.UPDATE,
        CITIZEN_ACTION,
        "public",
    )
    assert changes[("PUT", requisito)] == (ChangeKind.CREATE, None, VAGA_ACTION)

    assert run("apply", str(REPO_FILE), db, engine, service) == EXIT_OK
    after = _actions_by_key(db)
    assert after[("GET", f"{go}/idiomas$")] == "public"
    assert after[("GET", "/api/v1/empregabilidade/idiomas$")] == "public"
    assert after[("PUT", requisito)] == VAGA_ACTION
    # The edition of the vacancy and the writes of idiomas keep their actions.
    assert after[("PUT", f"{go}/vagas/([^/]+)$")] == VAGA_ACTION
    assert after[("POST", f"{go}/idiomas$")] == WRITE_ACTION
    assert after[("PUT", f"{go}/idiomas/([^/]+)$")] == WRITE_ACTION
    assert after[("DELETE", f"{go}/idiomas/([^/]+)$")] == WRITE_ACTION

    # At the edge (anchored regex) the PUT now resolves to the vacancy action
    # and the edition of the vacancy still resolves to its own mapping only.
    def edge(method, path):
        return {
            e.action.name
            for e in db.query(Endpoint).filter(Endpoint.method == method).all()
            if re.search(convert_pattern_to_regex(e.path_pattern), path)
        }

    vaga = f"{go}/vagas/00000000-0000-0000-0000-000000000000"
    assert edge("PUT", f"{vaga}/idiomas-requisito") == {VAGA_ACTION}
    assert edge("PUT", vaga) == {VAGA_ACTION}
    assert edge("GET", f"{go}/idiomas") == {"public"}
    assert edge("POST", f"{go}/idiomas") == {WRITE_ACTION}
    assert edge("DELETE", f"{go}/idiomas/1") == {WRITE_ACTION}


def test_vaga_idiomas_requisito_without_the_vaga_mapping_aborts_before_any_write(
    staging_like, engine, service
):
    # The PUT takes the action of the edition of the vacancy: if that route has
    # no mapping, the sync must not guess one, and nothing is written.
    db = staging_like
    db.query(Endpoint).filter(
        Endpoint.method == "PUT",
        Endpoint.path_pattern == "/go/api/v1/empregabilidade/vagas/([^/]+)$",
    ).delete()
    db.commit()
    plan = build_plan(db, load_mapping_file(REPO_FILE))
    assert any(
        "/vagas/{id}/idiomas-requisito" in e and "no mapping for that route" in e
        for e in plan.errors
    )
    before = _actions_by_key(db)
    assert run("apply", str(REPO_FILE), db, engine, service) == EXIT_PLAN_ERRORS
    assert _actions_by_key(db) == before


def test_versioned_file_makes_the_zonas_catalog_public():
    spec = load_mapping_file(REPO_FILE)
    entries = {(e.method, e.path): e for e in spec.mappings}
    for path in (
        "/go/api/v1/empregabilidade/zonas",
        "/go/api/v1/empregabilidade/zonas/{id}",
    ):
        entry = entries[("GET", path)]
        assert entry.action == "public"
        assert entry.same_as is None
        assert entry.source == "DEV-749"
    # Only the two reads of the lookup table are public: its writes (POST,
    # PUT, DELETE), declared since DEV-750, never take the public action.
    declared = {
        (e.method, e.path): e.action
        for e in spec.mappings
        if e.path.startswith("/go/api/v1/empregabilidade/zonas")
    }
    assert declared == {
        ("GET", "/go/api/v1/empregabilidade/zonas"): "public",
        ("GET", "/go/api/v1/empregabilidade/zonas/{id}"): "public",
        ("POST", "/go/api/v1/empregabilidade/zonas"): None,
        ("PUT", "/go/api/v1/empregabilidade/zonas/{id}"): None,
        ("DELETE", "/go/api/v1/empregabilidade/zonas/{id}"): None,
    }


def test_apply_makes_the_zonas_catalog_public_without_opening_its_writes(
    staging_like, engine, service
):
    db = staging_like
    go = "/go/api/v1/empregabilidade"
    plan = build_plan(db, load_mapping_file(REPO_FILE))
    assert plan.errors == []
    changes = {
        (c.method, c.path_pattern): (c.kind, c.old_action_name, c.action_name)
        for c in plan.changes
        if "/zonas" in c.path_pattern
    }
    assert changes == {
        ("GET", f"{go}/zonas$"): (ChangeKind.CREATE, None, "public"),
        ("GET", f"{go}/zonas/([^/]+)$"): (ChangeKind.CREATE, None, "public"),
        # DEV-750: the writes take the admin action of the idiomas writes.
        ("POST", f"{go}/zonas$"): (ChangeKind.CREATE, None, WRITE_ACTION),
        ("PUT", f"{go}/zonas/([^/]+)$"): (ChangeKind.CREATE, None, WRITE_ACTION),
        ("DELETE", f"{go}/zonas/([^/]+)$"): (ChangeKind.CREATE, None, WRITE_ACTION),
    }

    assert run("apply", str(REPO_FILE), db, engine, service) == EXIT_OK
    after = _actions_by_key(db)
    assert after[("GET", f"{go}/zonas$")] == "public"
    assert after[("GET", f"{go}/zonas/([^/]+)$")] == "public"

    # At the edge (anchored regex) the reads resolve to the public action and
    # the writes of the lookup table to the admin action only, never public.
    def edge(method, path):
        return {
            e.action.name
            for e in db.query(Endpoint).filter(Endpoint.method == method).all()
            if re.search(convert_pattern_to_regex(e.path_pattern), path)
        }

    zona = f"{go}/zonas/00000000-0000-0000-0000-000000000000"
    assert edge("GET", f"{go}/zonas") == {"public"}
    assert edge("GET", zona) == {"public"}
    assert edge("POST", f"{go}/zonas") == {WRITE_ACTION}
    assert edge("PUT", zona) == {WRITE_ACTION}
    assert edge("DELETE", zona) == {WRITE_ACTION}
    # A deeper path is not caught by the by-id pattern.
    assert edge("GET", f"{zona}/extra") == set()
    assert edge("PUT", f"{zona}/extra") == set()
    # Methods the go-api does not register for the collection stay unmapped.
    assert edge("PUT", f"{go}/zonas") == set()
    assert edge("DELETE", f"{go}/zonas") == set()
    assert edge("POST", zona) == set()


def test_versioned_file_maps_the_zonas_writes_like_the_idiomas_writes():
    spec = load_mapping_file(REPO_FILE)
    entries = {(e.method, e.path): e for e in spec.mappings}
    go = "/go/api/v1/empregabilidade"
    refs = {}
    for method, path in (
        ("POST", f"{go}/zonas"),
        ("PUT", f"{go}/zonas/{{id}}"),
        ("DELETE", f"{go}/zonas/{{id}}"),
    ):
        entry = entries[(method, path)]
        assert entry.action is None  # never an explicit action, never public
        assert entry.same_as is not None
        assert entry.source == "DEV-750"
        refs[method] = (entry.same_as.method, entry.same_as.path)
    assert refs == {
        "POST": ("POST", f"{go}/idiomas"),
        "PUT": ("PUT", f"{go}/idiomas/{{id}}"),
        "DELETE": ("DELETE", f"{go}/idiomas/{{id}}"),
    }


def test_zonas_writes_without_the_idiomas_write_mappings_abort_before_any_write(
    staging_like, engine, service
):
    # The writes of zonas take the action of the idiomas writes: if those
    # routes have no mapping, the sync must not guess one (nor fall back to
    # public), and nothing is written.
    db = staging_like
    go = "/go/api/v1/empregabilidade"
    for method, pattern in (
        ("POST", f"{go}/idiomas$"),
        ("PUT", f"{go}/idiomas/([^/]+)$"),
        ("DELETE", f"{go}/idiomas/([^/]+)$"),
    ):
        db.query(Endpoint).filter(
            Endpoint.method == method, Endpoint.path_pattern == pattern
        ).delete()
    db.commit()
    plan = build_plan(db, load_mapping_file(REPO_FILE))
    zonas_errors = [e for e in plan.errors if "/empregabilidade/zonas" in e]
    assert len(zonas_errors) == 3
    assert all("no mapping for that route" in e for e in zonas_errors)
    before = _actions_by_key(db)
    assert run("apply", str(REPO_FILE), db, engine, service) == EXIT_PLAN_ERRORS
    assert _actions_by_key(db) == before


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
    assert "0 to create, 0 to update, 0 to delete, 36 unchanged" in out
    assert "No changes to apply." in out
    assert db.query(Endpoint).count() == count


def test_plan_command_never_writes(staging_like, engine, service, capsys):
    db = staging_like
    before = _actions_by_key(db)
    assert run("plan", str(REPO_FILE), db, engine, service) == EXIT_OK
    assert _actions_by_key(db) == before
    out = capsys.readouterr().out
    assert "24 to create, 13 to update, 0 to delete" in out
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


# ============================================================================
# app-rmi: mobility routes (DEV-734)
# ============================================================================

RMI_FILE = REPO_FILE.parent / "app-rmi.json"
STAGING_MANIFEST = REPO_FILE.parent.parent / "k8s" / "staging" / "resources.yaml"
RMI = "/rmi/v1"
# Synthetic stand-ins for the actions the staging database gives today to the
# routes the file references; "authenticated" is real (cerbos-ext-authz).
RMI_CITIZEN_ACTION = "synthetic:rmi:citizen"
RMI_ADMIN_ACTIONS = {
    "GET": "synthetic:rmi:admin:read",
    "POST": "synthetic:rmi:admin:create",
    "PUT": "synthetic:rmi:admin:update",
    "DELETE": "synthetic:rmi:admin:delete",
}

RMI_CITIZEN_ROUTES = {
    ("GET", f"{RMI}/citizen/{{cpf}}/vehicles"),
    ("POST", f"{RMI}/citizen/{{cpf}}/vehicles"),
    ("GET", f"{RMI}/citizen/{{cpf}}/vehicles/{{vehicle_id}}"),
    ("PATCH", f"{RMI}/citizen/{{cpf}}/vehicles/{{vehicle_id}}"),
    ("DELETE", f"{RMI}/citizen/{{cpf}}/vehicles/{{vehicle_id}}"),
    ("GET", f"{RMI}/citizen/{{cpf}}/vehicle-invitations"),
    ("PATCH", f"{RMI}/citizen/{{cpf}}/vehicle-invitations/{{conductor_id}}"),
    ("GET", f"{RMI}/citizen/{{cpf}}/vehicles/{{vehicle_id}}/conductors"),
    ("POST", f"{RMI}/citizen/{{cpf}}/vehicles/{{vehicle_id}}/conductors"),
    (
        "DELETE",
        f"{RMI}/citizen/{{cpf}}/vehicles/{{vehicle_id}}/conductors/{{conductor_id}}",
    ),
}
RMI_CATALOG_ROUTES = {
    ("GET", f"{RMI}/mobilidade/vehicle-brands"),
    ("GET", f"{RMI}/mobilidade/vehicle-models"),
    ("GET", f"{RMI}/mobilidade/vehicle-colors"),
}
# Admin route -> the /admin/beta/groups route of the same verb it follows.
RMI_ADMIN_ROUTES = {
    ("GET", f"{RMI}/admin/mobilidade/vehicle-brands"): ("GET", "/admin/beta/groups"),
    ("POST", f"{RMI}/admin/mobilidade/vehicle-brands"): (
        "POST",
        "/admin/beta/groups",
    ),
    ("PATCH", f"{RMI}/admin/mobilidade/vehicle-brands/{{brand_id}}"): (
        "PUT",
        "/admin/beta/groups/{group_id}",
    ),
    ("DELETE", f"{RMI}/admin/mobilidade/vehicle-brands/{{brand_id}}"): (
        "DELETE",
        "/admin/beta/groups/{group_id}",
    ),
    ("GET", f"{RMI}/admin/mobilidade/vehicle-models"): ("GET", "/admin/beta/groups"),
    ("POST", f"{RMI}/admin/mobilidade/vehicle-models"): (
        "POST",
        "/admin/beta/groups",
    ),
    ("PATCH", f"{RMI}/admin/mobilidade/vehicle-models/{{model_id}}"): (
        "PUT",
        "/admin/beta/groups/{group_id}",
    ),
    ("DELETE", f"{RMI}/admin/mobilidade/vehicle-models/{{model_id}}"): (
        "DELETE",
        "/admin/beta/groups/{group_id}",
    ),
}


# DEV-796: the Salesforce/LGPD, auth/validate and cpf-secretaria routes.
# CPF in the path (RequireOwnCPF in the RMI) -> the citizen action of the pets.
RMI_OWN_CPF_ROUTES = {
    ("PATCH", f"{RMI}/salesforce/cidadao/{{cpf}}/consentimento"),
    ("GET", f"{RMI}/salesforce/cidadao/{{cpf}}/exportar"),
    ("POST", f"{RMI}/salesforce/cidadao/{{cpf}}/anonimizar"),
    ("GET", f"{RMI}/cpf-secretaria/{{cpf}}"),
}
# Authenticated, no CPF in the path -> "authenticated".
RMI_AUTHENTICATED_ROUTES = {
    ("GET", f"{RMI}/salesforce/chamados"),
    ("GET", f"{RMI}/salesforce/chamados/{{protocolo}}"),
    ("GET", f"{RMI}/salesforce/anonimizacao/{{numeroSolicitacao}}"),
    ("GET", f"{RMI}/auth/validate"),
}
# Admin route -> the /admin/beta/groups route of the same verb it follows.
RMI_CPF_SECRETARIA_ADMIN_ROUTES = {
    ("GET", f"{RMI}/admin/cpf-secretaria/{{cpf}}"): ("GET", "/admin/beta/groups"),
    ("POST", f"{RMI}/admin/cpf-secretaria/{{cpf}}"): ("POST", "/admin/beta/groups"),
    ("DELETE", f"{RMI}/admin/cpf-secretaria/{{cpf}}/{{cd_ua}}"): (
        "DELETE",
        "/admin/beta/groups/{group_id}",
    ),
}
RMI_DEV_796_ROUTES = (
    RMI_OWN_CPF_ROUTES | RMI_AUTHENTICATED_ROUTES | set(RMI_CPF_SECRETARIA_ADMIN_ROUTES)
)
# OPS-375: the Salesforce webhook. The RMI checks the Keycloak JWT and the
# Salesforce client (azp) itself; the edge only needs a valid JWT.
RMI_WEBHOOK_ROUTES = {("POST", f"{RMI}/webhooks/salesforce/cidadao")}
RMI_MOBILITY_ROUTES = RMI_CITIZEN_ROUTES | RMI_CATALOG_ROUTES | set(RMI_ADMIN_ROUTES)
RMI_ALL_ADMIN_ROUTES = {**RMI_ADMIN_ROUTES, **RMI_CPF_SECRETARIA_ADMIN_ROUTES}
RMI_FILE_ENTRIES = (
    len(RMI_MOBILITY_ROUTES) + len(RMI_DEV_796_ROUTES) + len(RMI_WEBHOOK_ROUTES)
)


def _expected_rmi_action(method, path):
    if (method, path) in RMI_CITIZEN_ROUTES | RMI_OWN_CPF_ROUTES:
        return RMI_CITIZEN_ACTION
    if (method, path) in (
        RMI_CATALOG_ROUTES | RMI_AUTHENTICATED_ROUTES | RMI_WEBHOOK_ROUTES
    ):
        return "authenticated"
    return RMI_ADMIN_ACTIONS[RMI_ALL_ADMIN_ROUTES[(method, path)][0]]


def _resolves_at_edge(db, method, path):
    """Actions of the stored patterns the edge (anchored regex) matches."""
    return {
        e.action.name
        for e in db.query(Endpoint).filter(Endpoint.method == method).all()
        if re.search(convert_pattern_to_regex(e.path_pattern), path)
    }


@pytest.fixture
def rmi_staging_like(db):
    """
    The RMI as staging has it: the sibling citizen and admin routes mapped (with
    and without /rmi/v1, as the OpenAPI tool creates them), mobility unmapped.
    """
    for name in (
        "public",
        "authenticated",
        RMI_CITIZEN_ACTION,
        OTHER_ACTION,
        *RMI_ADMIN_ACTIONS.values(),
    ):
        _action(db, name)
    for prefix in (RMI, ""):
        _mapping(db, "GET", f"{prefix}/citizen/([^/]+)/pets$", RMI_CITIZEN_ACTION)
        _mapping(db, "POST", f"{prefix}/citizen/([^/]+)/pets$", RMI_CITIZEN_ACTION)
        _mapping(
            db, "GET", f"{prefix}/citizen/([^/]+)/pets/([^/]+)$", RMI_CITIZEN_ACTION
        )
        _mapping(db, "GET", f"{prefix}/citizen/([^/]+)/avatar$", RMI_CITIZEN_ACTION)
        _mapping(db, "GET", f"{prefix}/admin/beta/groups$", RMI_ADMIN_ACTIONS["GET"])
        _mapping(db, "POST", f"{prefix}/admin/beta/groups$", RMI_ADMIN_ACTIONS["POST"])
        for verb in ("GET", "PUT", "DELETE"):
            _mapping(
                db,
                verb,
                f"{prefix}/admin/beta/groups/([^/]+)$",
                RMI_ADMIN_ACTIONS[verb],
            )
    _mapping(db, "GET", f"{RMI}/citizen/([^/]+)$", OTHER_ACTION)
    # A mapping of another application, never to be touched.
    _mapping(db, "GET", "/go/api/v1/categorias$", "public")
    return db


def test_app_rmi_file_maps_the_mobility_routes_of_the_issue():
    spec = load_mapping_file(RMI_FILE)
    assert spec.application == "app-rmi"
    assert spec.path_prefix == "/rmi/v1/"
    assert spec.remove == []
    entries = {(e.method, e.path): e for e in spec.mappings}
    assert set(entries) == RMI_MOBILITY_ROUTES | RMI_DEV_796_ROUTES | RMI_WEBHOOK_ROUTES
    assert len(spec.mappings) == RMI_FILE_ENTRIES == 33

    for key in RMI_CITIZEN_ROUTES:
        ref = entries[key].same_as
        assert ref is not None, key
        assert (ref.method, ref.path) == ("GET", f"{RMI}/citizen/{{cpf}}/pets")
    for key in RMI_CATALOG_ROUTES:
        assert entries[key].action == "authenticated"
    for key, (verb, path) in RMI_ADMIN_ROUTES.items():
        ref = entries[key].same_as
        assert ref is not None, key
        assert (ref.method, ref.path) == (verb, f"{RMI}{path}")
    # Nothing public: every mobility route needs at least a valid JWT.
    assert all(e.action != "public" for e in spec.mappings)
    assert {entries[key].source for key in RMI_MOBILITY_ROUTES} == {"DEV-734"}


def test_plan_on_rmi_staging_like_db_creates_the_mobility_mappings(
    rmi_staging_like,
):
    db = rmi_staging_like
    before = _actions_by_key(db)
    plan = build_plan(db, load_mapping_file(RMI_FILE))

    assert plan.errors == []
    assert _actions_by_key(db) == before  # plan never writes
    assert {c.kind for c in plan.changes} == {ChangeKind.CREATE}
    created = {(c.method, c.path_pattern): c.action_name for c in plan.changes}
    spec = load_mapping_file(RMI_FILE)
    assert created == {
        (e.method, route_pattern(e.path)): _expected_rmi_action(e.method, e.path)
        for e in spec.mappings
    }


def test_apply_makes_the_mobility_routes_resolve_at_the_edge(
    rmi_staging_like, engine, service, capsys
):
    db = rmi_staging_like
    cpf = "00000000000"
    vehicles = f"{RMI}/citizen/{cpf}/vehicles"
    invitations = f"{RMI}/citizen/{cpf}/vehicle-invitations"
    # The issue: no stored pattern resolves them (no action mapping).
    assert _resolves_at_edge(db, "GET", vehicles) == set()
    assert _resolves_at_edge(db, "GET", invitations) == set()
    before = _actions_by_key(db)

    assert run("apply", str(RMI_FILE), db, engine, service) == EXIT_OK
    assert _resolves_at_edge(db, "GET", vehicles) == {RMI_CITIZEN_ACTION}
    assert _resolves_at_edge(db, "GET", invitations) == {RMI_CITIZEN_ACTION}
    assert _resolves_at_edge(db, "DELETE", f"{vehicles}/v1/conductors/c1") == {
        RMI_CITIZEN_ACTION
    }
    assert _resolves_at_edge(db, "GET", f"{RMI}/mobilidade/vehicle-colors") == {
        "authenticated"
    }
    assert _resolves_at_edge(
        db, "PATCH", f"{RMI}/admin/mobilidade/vehicle-models/m1"
    ) == {RMI_ADMIN_ACTIONS["PUT"]}
    # Each admin verb follows the beta-groups route of the same verb.
    assert _resolves_at_edge(db, "POST", f"{RMI}/admin/mobilidade/vehicle-brands") == {
        RMI_ADMIN_ACTIONS["POST"]
    }

    after = _actions_by_key(db)
    assert {k: v for k, v in after.items() if k in before} == before  # untouched
    assert len(after) == len(before) + RMI_FILE_ENTRIES

    capsys.readouterr()
    assert run("apply", str(RMI_FILE), db, engine, service) == EXIT_OK
    out = capsys.readouterr().out
    assert f"0 to create, 0 to update, 0 to delete, {RMI_FILE_ENTRIES} unchanged" in out
    assert "No changes to apply." in out


def test_app_rmi_file_maps_the_salesforce_lgpd_and_cpf_secretaria_routes():
    spec = load_mapping_file(RMI_FILE)
    entries = {(e.method, e.path): e for e in spec.mappings}
    assert set(entries) >= RMI_DEV_796_ROUTES
    assert len(RMI_DEV_796_ROUTES) == 11

    for key in RMI_OWN_CPF_ROUTES:
        ref = entries[key].same_as
        assert ref is not None, key
        assert entries[key].action is None, key
        assert (ref.method, ref.path) == ("GET", f"{RMI}/citizen/{{cpf}}/pets")
    for key in RMI_AUTHENTICATED_ROUTES:
        assert entries[key].action == "authenticated", key
        assert entries[key].same_as is None, key
    for key, (verb, path) in RMI_CPF_SECRETARIA_ADMIN_ROUTES.items():
        ref = entries[key].same_as
        assert ref is not None, key
        assert (ref.method, ref.path) == (verb, f"{RMI}{path}")
    # Nothing public.
    assert all(entries[key].action != "public" for key in RMI_DEV_796_ROUTES)
    assert {entries[key].source for key in RMI_DEV_796_ROUTES} == {"DEV-796"}


def test_apply_makes_the_salesforce_and_cpf_secretaria_routes_resolve_at_the_edge(
    rmi_staging_like, engine, service
):
    db = rmi_staging_like
    cpf = "00000000000"
    probes = {
        ("PATCH", f"{RMI}/salesforce/cidadao/{cpf}/consentimento"): RMI_CITIZEN_ACTION,
        ("GET", f"{RMI}/salesforce/cidadao/{cpf}/exportar"): RMI_CITIZEN_ACTION,
        ("POST", f"{RMI}/salesforce/cidadao/{cpf}/anonimizar"): RMI_CITIZEN_ACTION,
        ("GET", f"{RMI}/cpf-secretaria/{cpf}"): RMI_CITIZEN_ACTION,
        ("GET", f"{RMI}/salesforce/chamados"): "authenticated",
        ("GET", f"{RMI}/salesforce/chamados/2026-0001"): "authenticated",
        ("GET", f"{RMI}/salesforce/anonimizacao/SOL-1"): "authenticated",
        ("GET", f"{RMI}/auth/validate"): "authenticated",
        ("GET", f"{RMI}/admin/cpf-secretaria/{cpf}"): RMI_ADMIN_ACTIONS["GET"],
        ("POST", f"{RMI}/admin/cpf-secretaria/{cpf}"): RMI_ADMIN_ACTIONS["POST"],
        ("DELETE", f"{RMI}/admin/cpf-secretaria/{cpf}/1234"): RMI_ADMIN_ACTIONS[
            "DELETE"
        ],
    }
    # The issue: no stored pattern resolves them (no action mapping).
    for method, path in probes:
        assert _resolves_at_edge(db, method, path) == set(), (method, path)

    assert run("apply", str(RMI_FILE), db, engine, service) == EXIT_OK

    # Each one resolves to exactly its action: the citizen cpf-secretaria route
    # never matches the admin one (anchored regex) nor the other way round.
    for (method, path), action in probes.items():
        assert _resolves_at_edge(db, method, path) == {action}, (method, path)
    # Only the declared verbs and shapes are mapped.
    assert _resolves_at_edge(db, "DELETE", f"{RMI}/cpf-secretaria/{cpf}") == set()
    assert _resolves_at_edge(db, "GET", f"{RMI}/cpf-secretaria/{cpf}/x") == set()
    assert _resolves_at_edge(db, "POST", f"{RMI}/auth/validate") == set()
    assert (
        _resolves_at_edge(db, "PUT", f"{RMI}/salesforce/cidadao/{cpf}/consentimento")
        == set()
    )


def test_app_rmi_file_maps_the_salesforce_webhook_as_authenticated():
    spec = load_mapping_file(RMI_FILE)
    entries = {(e.method, e.path): e for e in spec.mappings}
    webhook = entries[("POST", f"{RMI}/webhooks/salesforce/cidadao")]
    # A valid JWT at the edge, never public; the RMI checks the azp itself.
    assert webhook.action == "authenticated"
    assert webhook.same_as is None
    assert webhook.source == "OPS-375"
    # It is the only webhook of the file, and only with POST.
    assert {key for key in entries if "/webhooks/" in key[1]} == RMI_WEBHOOK_ROUTES


def test_apply_makes_the_salesforce_webhook_resolve_to_authenticated_at_the_edge(
    rmi_staging_like, engine, service
):
    db = rmi_staging_like
    webhook = f"{RMI}/webhooks/salesforce/cidadao"
    # The issue: no stored pattern resolves it (no action mapping found).
    assert _resolves_at_edge(db, "POST", webhook) == set()

    assert run("apply", str(RMI_FILE), db, engine, service) == EXIT_OK

    assert _resolves_at_edge(db, "POST", webhook) == {"authenticated"}
    # Only the declared verb and the exact path are mapped.
    for method in ("GET", "PUT", "PATCH", "DELETE"):
        assert _resolves_at_edge(db, method, webhook) == set(), method
    assert _resolves_at_edge(db, "POST", f"{webhook}/x") == set()
    assert _resolves_at_edge(db, "POST", f"{RMI}/webhooks/salesforce") == set()
    assert _resolves_at_edge(db, "POST", f"{RMI}/webhooks/salesforce/outro") == set()


def test_app_rmi_alias_without_prefix_follows_the_declared_action(rmi_staging_like):
    db = rmi_staging_like
    # The OpenAPI tool may have created the route without /rmi/v1 already.
    alias = _mapping(db, "GET", "/citizen/([^/]+)/vehicles$", OTHER_ACTION)
    plan = build_plan(db, load_mapping_file(RMI_FILE))
    assert plan.errors == []
    updates = [c for c in plan.changes if c.kind == ChangeKind.UPDATE]
    assert [(u.mapping_id, u.old_action_name, u.action_name) for u in updates] == [
        (alias.id, OTHER_ACTION, RMI_CITIZEN_ACTION)
    ]


def test_app_rmi_without_the_referenced_route_aborts_before_any_write(
    db, engine, service
):
    # A database where GET /citizen/{cpf}/pets has no mapping: nothing applied.
    for name in ("authenticated", *RMI_ADMIN_ACTIONS.values()):
        _action(db, name)
    assert run("apply", str(RMI_FILE), db, engine, service) == EXIT_PLAN_ERRORS
    assert db.query(Endpoint).count() == 0


def test_every_versioned_mapping_file_is_applied_on_the_staging_deploy():
    manifest = STAGING_MANIFEST.read_text(encoding="utf-8")
    for spec_file in sorted(REPO_FILE.parent.glob("*.json")):
        expected = (
            f'"app.mappings_sync", "apply", "--file", "mappings/{spec_file.name}"'
        )
        assert expected in manifest, spec_file.name
