"""The citizen's CPF (JWT ``subject``) never reaches the exported traces (DEV-487).

Every span attribute is exported over OTLP to the tracing backend. These tests
run each flow that used to put the subject in a span attribute (JWT auth, user
lookup and roles, roles cache, Cerbos, memberships, audit) against an in-memory
span exporter and assert that no attribute value carries the (synthetic) CPF,
while the internal ``user.user_id`` is still there for correlation. The last
tests cover the exporter filter that masks what the call sites cannot: the raw
request path recorded by the FastAPI instrumentation, error messages, exception
events and the status description.
"""

import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from jose import jwk, jwt
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import Status, StatusCode

from app.services.audit import AuditService
from app.services.auth import AuthService
from app.services.cache import CacheService
from app.services.cerbos import CerbosService
from app.services.membership import MembershipService
from app.services.user import UserService
from app.tracing import (
    CPF_PLACEHOLDER,
    CpfRedactingSpanExporter,
    create_span,
    redact_cpf,
    setup_tracing,
    subject_kind,
)

CPF = "98765432100"  # synthetic
CPF_FORMATTED = "987.654.321-00"
USER_ID = 42
ISSUER = "https://auth.example.test/realms/test"
KID = "test-kid"


@pytest.fixture
def exporter():
    return InMemorySpanExporter()


@pytest.fixture
def traced(exporter):
    """Point the given services at a tracer that exports into ``exporter``."""
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")

    def _attach(*services):
        for svc in services:
            svc.tracer = tracer
        return services[0] if len(services) == 1 else services

    return _attach


def _attributes(exporter) -> list[tuple[str, str, object]]:
    spans = exporter.get_finished_spans()
    assert spans, "expected the flow to export at least one span"
    return [
        (span.name, key, value)
        for span in spans
        for key, value in (span.attributes or {}).items()
    ]


def _assert_no_cpf(exporter) -> None:
    for span_name, key, value in _attributes(exporter):
        text = str(value)
        assert CPF not in text and CPF_FORMATTED not in text, (
            f"CPF leaked into span {span_name!r} attribute {key!r}"
        )
        assert not key.endswith("subject"), (
            f"span {span_name!r} still exports a subject attribute: {key!r}"
        )


def _attribute(exporter, span_name: str, key: str):
    for span in exporter.get_finished_spans():
        if span.name == span_name and key in (span.attributes or {}):
            return span.attributes[key]
    raise AssertionError(f"attribute {key!r} not found on span {span_name!r}")


def _user() -> MagicMock:
    user = MagicMock()
    user.id = USER_ID
    user.subject = CPF
    user.display_name = "Fulana de Tal"
    user.memberships = []
    user.user_roles = []
    return user


# --- create_span safety net -------------------------------------------------


def test_redact_cpf_masks_bare_and_formatted_cpf():
    assert redact_cpf(CPF) == CPF_PLACEHOLDER
    assert redact_cpf(CPF_FORMATTED) == CPF_PLACEHOLDER
    assert redact_cpf(f"user_roles:{CPF}") == f"user_roles:{CPF_PLACEHOLDER}"
    assert redact_cpf(f"principal_{CPF}") == f"principal_{CPF_PLACEHOLDER}"
    assert redact_cpf(["viewer", CPF]) == ["viewer", CPF_PLACEHOLDER]


def test_redact_cpf_keeps_values_that_are_not_cpf():
    assert redact_cpf("group:ops:role:viewer") == "group:ops:role:viewer"
    assert redact_cpf("1234567890") == "1234567890"  # 10 digits
    assert redact_cpf("123456789012") == "123456789012"  # 12 digits
    assert redact_cpf(USER_ID) == USER_ID
    assert redact_cpf(True) is True
    assert redact_cpf(None) is None


def test_subject_kind_never_returns_a_person_subject():
    assert subject_kind(CPF) == "user"
    assert subject_kind("system:background_tasks") == "system:background_tasks"
    assert subject_kind(None) == "none"
    assert subject_kind("") == "none"


def test_create_span_masks_cpf_in_attribute_values(exporter, traced):
    holder = traced(MagicMock())
    with create_span(
        holder.tracer, "t", {"audit.target_id": f"group:g:member:{CPF}", "n": 1}
    ):
        pass
    assert _attribute(exporter, "t", "audit.target_id") == (
        f"group:g:member:{CPF_PLACEHOLDER}"
    )
    assert _attribute(exporter, "t", "n") == 1


# --- JWT authentication -----------------------------------------------------


def _key_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = jwk.construct(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        "RS256",
    ).to_dict()
    public.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return pem, public


def test_verify_jwt_token_does_not_export_cpf(exporter, traced):
    pem, public = _key_pair()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "uuid-1",
            "preferred_username": CPF,
            "iss": ISSUER,
            "iat": now,
            "exp": now + 3600,
        },
        pem,
        algorithm="RS256",
        headers={"kid": KID},
    )
    with patch("app.services.auth.CacheService"):
        service = AuthService()
    service.jwt_issuer = ISSUER
    service._fetch_jwks = MagicMock(return_value={"keys": [public]})
    traced(service)

    user_info = service.verify_jwt_token(token)

    assert user_info is not None and user_info["subject"] == CPF  # still used
    assert _attribute(exporter, "auth.verify_jwt_token", "auth.token_valid") is True
    assert _attribute(exporter, "auth.verify_jwt_token", "auth.subject_present") is True
    _assert_no_cpf(exporter)


# --- users ------------------------------------------------------------------


@pytest.fixture
def user_service():
    with patch("app.services.user.CacheService"):
        svc = UserService()
    svc.keycloak_client_id = "heimdall-admin"
    svc.admin_role_name = "heimdall-admin"
    return svc


def test_get_or_create_user_does_not_export_cpf(exporter, traced, user_service):
    traced(user_service)
    user = _user()
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = user
    db.query.return_value.join.return_value.filter.return_value.first.return_value = (
        None
    )
    payload = {
        "subject": CPF,
        "name": "Fulana de Tal",
        "resource_access": {"heimdall-admin": {"roles": ["viewer"]}},
    }

    assert user_service.get_or_create_user(db, payload) is user

    assert _attribute(exporter, "user.get_or_create_user", "user.user_id") == USER_ID
    _assert_no_cpf(exporter)


NAME = "Fulana de Tal"  # synthetic
EMAIL = "fulana.sintetica@example.test"  # synthetic


@pytest.mark.parametrize(
    "claims",
    [
        {"name": NAME, "email": EMAIL},
        {"email": EMAIL},  # display name falls back to the e-mail
    ],
)
def test_get_or_create_user_new_user_does_not_export_name_or_email(
    exporter, traced, user_service, claims
):
    """DEV-544: creating a user must not export the display name (name/e-mail)."""
    traced(user_service)
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.query.return_value.join.return_value.filter.return_value.first.return_value = (
        None
    )
    payload = {"subject": CPF, "resource_access": {}, **claims}

    user = user_service.get_or_create_user(db, payload)

    assert user.display_name == claims.get("name", EMAIL)
    assert _attribute(exporter, "user.get_or_create_user", "user.created_new") is True
    assert (
        _attribute(exporter, "user.get_or_create_user", "user.display_name_present")
        is True
    )
    for span_name, key, value in _attributes(exporter):
        text = str(value)
        assert NAME not in text and EMAIL not in text, (
            f"name/e-mail leaked into span {span_name!r} attribute {key!r}"
        )
    _assert_no_cpf(exporter)


def _integrity_error_from_engine(tmp_path):
    """A real IntegrityError raised by the app's engine on a duplicate subject."""
    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    from app import database

    with patch.object(
        database, "get_database_url", return_value=f"sqlite:///{tmp_path / 'u.db'}"
    ):
        engine = database.create_database_engine()
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE u (subject TEXT UNIQUE, display_name TEXT)"))
        conn.execute(
            text("INSERT INTO u VALUES (:s, :n)"), {"s": CPF, "n": "Outra Pessoa"}
        )
    try:
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO u VALUES (:s, :n)"), {"s": CPF, "n": NAME})
    except IntegrityError as exc:
        return exc
    finally:
        engine.dispose()
    raise AssertionError("expected a duplicate-subject IntegrityError")


def test_database_errors_do_not_carry_query_parameters(tmp_path):
    exc = _integrity_error_from_engine(tmp_path)

    assert NAME not in str(exc) and CPF not in str(exc)


def test_get_or_create_user_db_error_does_not_export_name(
    exporter, traced, user_service, tmp_path
):
    """DEV-544: a failed insert must not ship the display name in the span."""
    traced(user_service)
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None
    db.commit.side_effect = _integrity_error_from_engine(tmp_path)
    payload = {"subject": CPF, "name": NAME, "email": EMAIL, "resource_access": {}}

    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        user_service.get_or_create_user(db, payload)

    spans = exporter.get_finished_spans()
    assert spans
    for span in spans:
        texts = [str(v) for v in (span.attributes or {}).values()]
        texts += [str(dict(e.attributes or {})) for e in span.events]
        texts.append(str(span.status.description))
        for text_value in texts:
            assert NAME not in text_value and EMAIL not in text_value, (
                f"name/e-mail leaked into span {span.name!r}: {text_value!r}"
            )


def test_get_user_by_subject_does_not_export_cpf(exporter, traced, user_service):
    traced(user_service)
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = _user()

    assert user_service.get_user_by_subject(db, CPF).id == USER_ID

    assert _attribute(exporter, "user.get_user_by_subject", "user.user_id") == USER_ID
    _assert_no_cpf(exporter)


def test_get_user_roles_and_roles_cache_do_not_export_cpf(exporter, traced):
    with patch.object(CacheService, "_create_redis_client", return_value=MagicMock()):
        cache = CacheService()
    redis_conn = MagicMock()
    redis_conn.get.return_value = None  # cache miss: read, compute, then write
    cache._get_redis_connection = MagicMock(return_value=redis_conn)
    with patch("app.services.user.CacheService", return_value=cache):
        service = UserService()
    traced(service, cache)

    assert service.get_user_roles(MagicMock(), _user()) == []

    assert _attribute(exporter, "user.get_user_roles", "user.user_id") == USER_ID
    assert _attribute(exporter, "cache.get_user_roles_cache", "cache.key") == (
        f"user_roles:{CPF_PLACEHOLDER}"
    )
    _assert_no_cpf(exporter)
    redis_conn.get.assert_called_once_with(f"user_roles:{CPF}")  # key unchanged


def test_get_user_groups_does_not_export_cpf(exporter, traced, user_service):
    traced(user_service)

    assert user_service.get_user_groups(MagicMock(), _user()) == []

    assert _attribute(exporter, "user.get_user_groups", "user.user_id") == USER_ID
    _assert_no_cpf(exporter)


def test_invalidate_user_roles_cache_does_not_export_cpf(exporter, traced):
    with patch.object(CacheService, "_create_redis_client", return_value=MagicMock()):
        cache = CacheService()
    redis_conn = MagicMock()
    redis_conn.delete.return_value = 1
    cache._get_redis_connection = MagicMock(return_value=redis_conn)
    traced(cache)

    assert cache.invalidate_user_roles_cache(CPF) is True

    assert (
        _attribute(exporter, "cache.invalidate_user_roles_cache", "cache.all_users")
        is False
    )
    _assert_no_cpf(exporter)
    redis_conn.delete.assert_called_once_with(f"user_roles:{CPF}")


# --- Cerbos -----------------------------------------------------------------


@pytest.fixture
def cerbos():
    svc = CerbosService()
    svc.base_retry_delay = 0
    return svc


def test_check_permission_does_not_export_cpf(exporter, traced, cerbos):
    traced(cerbos)
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "results": [{"actions": {"group:add_member": "EFFECT_ALLOW"}}]
    }
    with (
        patch(
            "app.services.health_monitor.HealthMonitor.is_cerbos_available",
            return_value=True,
        ),
        patch("app.services.cerbos.requests.post", return_value=response),
    ):
        assert cerbos.check_permission(
            caller_subject=CPF,
            caller_roles=["viewer"],
            action="group:add_member",
            resource_type="group",
            resource_attrs={"name": "ops"},
        )

    assert _attribute(exporter, "cerbos.check_permission", "cerbos.caller") == "user"
    _assert_no_cpf(exporter)


def test_push_and_delete_user_policy_do_not_export_cpf(exporter, traced, cerbos):
    traced(cerbos)
    response = MagicMock(status_code=200)
    with (
        patch("app.services.cerbos.requests.put", return_value=response) as put,
        patch("app.services.cerbos.requests.delete", return_value=response),
    ):
        # superadmin: build_principal_policy needs no database lookup
        assert cerbos.push_user_policy(CPF, ["superadmin"]) is True
        assert cerbos.delete_user_policy(CPF) is True

    assert put.called  # the policy itself still names the principal
    assert _attribute(exporter, "cerbos.push_user_policy", "cerbos.policy_id") == (
        f"principal_{CPF_PLACEHOLDER}"
    )
    _assert_no_cpf(exporter)


# --- memberships ------------------------------------------------------------


@pytest.fixture
def memberships():
    with (
        patch("app.services.membership.AuditService"),
        patch("app.services.membership.CacheService"),
        patch("app.services.membership.CerbosService"),
    ):
        svc = MembershipService()
    svc.cerbos_service.check_permission.return_value = False
    return svc


def test_add_member_does_not_export_cpf(exporter, traced, memberships):
    traced(memberships)
    added = memberships.add_member_to_group(MagicMock(), "ops", CPF, CPF, [])
    assert added is False  # denied by Cerbos

    assert (
        _attribute(exporter, "membership.add_member_to_group", "membership.caller")
        == "user"
    )
    _assert_no_cpf(exporter)


def test_remove_member_does_not_export_cpf(exporter, traced, memberships):
    traced(memberships)
    removed = memberships.remove_member_from_group(MagicMock(), "ops", CPF, CPF, [])
    assert removed is False  # denied by Cerbos
    _assert_no_cpf(exporter)


def test_list_members_does_not_export_cpf(exporter, traced, memberships):
    traced(memberships)
    with pytest.raises(PermissionError):
        memberships.list_group_members(MagicMock(), "ops", CPF, [])
    _assert_no_cpf(exporter)


# --- audit ------------------------------------------------------------------


def test_audit_log_operation_does_not_export_cpf(exporter, traced):
    audit = traced(AuditService())
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = _user()

    audit.log_operation(
        db=db,
        actor_subject=CPF,
        operation="add_member",
        target_type="membership",
        target_id=f"group:ops:member:{CPF}",
    )

    assert _attribute(exporter, "audit.log_operation", "audit.actor") == "user"
    assert _attribute(exporter, "audit.log_operation", "audit.target_id") == (
        f"group:ops:member:{CPF_PLACEHOLDER}"
    )
    _assert_no_cpf(exporter)
    entry = db.add.call_args.args[0]
    assert entry.actor_subject == CPF  # the audit table still records who acted


def test_audit_keeps_system_actor_in_span(exporter, traced):
    audit = traced(AuditService())
    audit.log_operation(
        db=MagicMock(),
        actor_subject="system:background_tasks",
        operation="reconcile",
        actor_user_id=None,
    )
    assert (
        _attribute(exporter, "audit.log_operation", "audit.actor")
        == "system:background_tasks"
    )


# --- exporter: request spans, errors and exception events --------------------


def _api() -> FastAPI:
    api = FastAPI()

    @api.get("/api/v1/users/{cpf}")
    def read_user(cpf: str):
        if cpf == CPF_FORMATTED:
            raise HTTPException(status_code=404, detail=f"User {cpf} not found")
        return {"ok": True}

    return api


def _instrumented_client(exporter, redacting: bool) -> TestClient:
    provider = TracerProvider()
    target = CpfRedactingSpanExporter(exporter) if redacting else exporter
    provider.add_span_processor(SimpleSpanProcessor(target))
    api = _api()
    FastAPIInstrumentor.instrument_app(api, tracer_provider=provider)
    return TestClient(api)


def _everything_exported(exporter) -> str:
    parts = []
    for span in exporter.get_finished_spans():
        parts.append(span.name)
        parts.append(str(dict(span.attributes or {})))
        parts.append(str(span.status.description))
        for event in span.events:
            parts.append(str(dict(event.attributes or {})))
    return "\n".join(parts)


def test_request_path_with_cpf_reaches_spans_without_the_filter(exporter):
    # Sanity check of the scenario: the FastAPI instrumentation records the raw
    # path (http.target / http.url), so without the exporter filter it leaks.
    client = _instrumented_client(exporter, redacting=False)
    assert client.get(f"/api/v1/users/{CPF}").status_code == 200
    assert CPF in _everything_exported(exporter)


def test_exporter_masks_cpf_in_request_path_and_query(exporter):
    client = _instrumented_client(exporter, redacting=True)

    assert client.get(f"/api/v1/users/{CPF}?cpf={CPF}").status_code == 200
    assert client.get(f"/api/v1/users/{CPF_FORMATTED}").status_code == 404

    exported = _everything_exported(exporter)
    assert CPF not in exported and CPF_FORMATTED not in exported
    assert CPF_PLACEHOLDER in exported
    server = [s for s in exporter.get_finished_spans() if s.kind.name == "SERVER"]
    assert server and all(
        s.attributes.get("http.route") == "/api/v1/users/{cpf}" for s in server
    )


def test_exporter_masks_cpf_in_error_status_and_exception_event(exporter):
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(CpfRedactingSpanExporter(exporter)))
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span(f"lookup {CPF}") as span:
        error = ValueError(f"duplicate key (subject)=({CPF})")
        span.record_exception(error)
        span.set_attribute("user.error", str(error))
        span.set_status(Status(StatusCode.ERROR, str(error)))

    exported = _everything_exported(exporter)
    assert CPF not in exported
    (finished,) = exporter.get_finished_spans()
    assert finished.name == f"lookup {CPF_PLACEHOLDER}"
    assert finished.events[0].attributes["exception.type"] == "ValueError"


def test_setup_tracing_wraps_the_otlp_exporter():
    with (
        patch("app.tracing.is_tracing_enabled", return_value=True),
        patch("app.tracing.get_otlp_endpoint", return_value="collector:4317"),
        patch("app.tracing.OTLPSpanExporter") as otlp,
        patch("app.tracing.BatchSpanProcessor") as batch,
        patch("app.tracing.trace.set_tracer_provider"),
    ):
        assert setup_tracing() is True

    (wrapped,), _ = batch.call_args
    assert isinstance(wrapped, CpfRedactingSpanExporter)
    assert wrapped._exporter is otlp.return_value
