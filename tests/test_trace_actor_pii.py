"""The acting user's subject never reaches the exported traces (DEV-543).

DEV-487 took the subject (the citizen's CPF) out of the user, auth, cache,
Cerbos, membership and audit spans, but the ``*_by`` attributes of the action,
group, mapping and role spans (``created_by``, ``updated_by``, ``deleted_by``,
``assigned_by``, ``removed_by``) still carried ``<user>.subject``. The exporter
filter only masks CPF-shaped values, so a subject in any other shape (an e-mail,
a CPF written ``ddddddddd-dd``) left the process in clear.

These tests run each of those flows against an in-memory span exporter with a
synthetic subject in several shapes and assert that the subject is not in any
exported attribute, that the ``*_by`` attribute is only the subject kind
(``user`` or the ``system:*`` principal) and that the user is still identified
by the internal id in ``*_by_user_id``.
"""

import contextlib
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from app.services.action import ActionService
from app.services.group import GroupService
from app.services.mapping import MappingService
from app.services.role import RoleService
from app.tracing import CPF_PLACEHOLDER, redact_cpf

USER_ID = 42

# Synthetic subjects, one per shape the subject can take.
EMAIL_SUBJECT = "fulana.de.tal@example.test"
CPF_DASHED_SUBJECT = "987654321-00"
CPF_BARE_SUBJECT = "98765432100"
SYSTEM_SUBJECT = "system:background_tasks"

PERSON_SUBJECTS = [EMAIL_SUBJECT, CPF_DASHED_SUBJECT, CPF_BARE_SUBJECT]
# A token can carry any preferred_username, including one shaped like a
# service principal that Heimdall does not act as (DEV-625).
FAKE_SYSTEM_SUBJECTS = [
    "system:unknown_service",
    f"system:{EMAIL_SUBJECT}",
    f"system:{CPF_DASHED_SUBJECT}",
]


@pytest.fixture
def exporter():
    return InMemorySpanExporter()


def _user(subject: str) -> MagicMock:
    user = MagicMock()
    user.id = USER_ID
    user.subject = subject
    user.display_name = "Fulana de Tal"
    return user


def _services(exporter) -> dict[str, Any]:
    """Each service with its collaborators mocked, tracing into ``exporter``."""
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")
    with (
        patch("app.services.action.AuditService"),
        patch("app.services.group.AuditService"),
        patch("app.services.mapping.AuditService"),
        patch("app.services.mapping.CacheService"),
        patch("app.services.mapping.CerbosService"),
        patch("app.services.mapping.RedisMappingService"),
        patch("app.services.role.AuditService"),
        patch("app.services.role.CacheService"),
        patch("app.services.role.CerbosService"),
    ):
        services = {
            "action": ActionService(),
            "group": GroupService(),
            "mapping": MappingService(),
            "role": RoleService(),
        }
    for svc in services.values():
        svc.tracer = tracer
    return services


# (service, span name, actor attribute, call with the acting user)
Flow = tuple[str, str, str, Callable[[Any, MagicMock], Any]]

FLOWS: list[Flow] = [
    (
        "action",
        "action.create_action",
        "action.created_by",
        lambda svc, u: svc.create_action(MagicMock(), "a:read", "d", u),
    ),
    (
        "action",
        "action.update_action",
        "action.updated_by",
        lambda svc, u: svc.update_action(MagicMock(), 1, name="a:x", updated_by=u),
    ),
    (
        "action",
        "action.delete_action",
        "action.deleted_by",
        lambda svc, u: svc.delete_action(MagicMock(), 1, u),
    ),
    (
        "group",
        "group.create_group",
        "group.created_by",
        lambda svc, u: svc.create_group(MagicMock(), "ops", "d", u),
    ),
    (
        "group",
        "group.delete_group",
        "group.deleted_by",
        lambda svc, u: svc.delete_group(MagicMock(), "ops", u),
    ),
    (
        "mapping",
        "mapping.create_mapping",
        "mapping.created_by",
        lambda svc, u: svc.create_mapping(MagicMock(), "/api/x", "GET", 1, None, u),
    ),
    (
        "mapping",
        "mapping.update_mapping",
        "mapping.updated_by",
        lambda svc, u: svc.update_mapping(MagicMock(), 1, None, None, None, None, u),
    ),
    (
        "mapping",
        "mapping.delete_mapping",
        "mapping.deleted_by",
        lambda svc, u: svc.delete_mapping(MagicMock(), 1, u),
    ),
    (
        "role",
        "role.create_role",
        "role.created_by",
        lambda svc, u: svc.create_role(MagicMock(), "viewer", "d", u),
    ),
    (
        "role",
        "role.assign_role_to_group",
        "role.assigned_by",
        lambda svc, u: svc.assign_role_to_group(MagicMock(), "ops", "viewer", u),
    ),
    (
        "role",
        "role.remove_role_from_group",
        "role.removed_by",
        lambda svc, u: svc.remove_role_from_group(MagicMock(), "ops", "viewer", u),
    ),
    (
        "role",
        "role.assign_action_to_role",
        "assigned_by",
        lambda svc, u: svc.assign_action_to_role(MagicMock(), "viewer", "a:read", u),
    ),
    (
        "role",
        "role.remove_action_from_role",
        "removed_by",
        lambda svc, u: svc.remove_action_from_role(MagicMock(), "viewer", "a:read", u),
    ),
]

FLOW_IDS = [span_name for _, span_name, _, _ in FLOWS]


def _run(exporter, flow: Flow, subject: str) -> dict[str, Any]:
    """Run ``flow`` as a user with ``subject``; the attributes of its span."""
    service, span_name, _, call = flow
    svc = _services(exporter)[service]
    # The database is a mock: the flow may fail half-way, but its span is
    # exported either way, with the attributes it was opened with.
    with contextlib.suppress(Exception):
        call(svc, _user(subject))
    for span in exporter.get_finished_spans():
        if span.name == span_name:
            return dict(span.attributes or {})
    raise AssertionError(f"span {span_name!r} was not exported")


def _assert_subject_not_exported(exporter, subject: str) -> None:
    spans = exporter.get_finished_spans()
    assert spans, "expected the flow to export at least one span"
    digits = subject.replace("-", "").replace(".", "")
    for span in spans:
        for key, value in (span.attributes or {}).items():
            text = str(value)
            assert subject not in text, (
                f"subject leaked into span {span.name!r} attribute {key!r}"
            )
            if digits.isdigit():
                assert digits[:9] not in text, (
                    f"CPF digits leaked into span {span.name!r} attribute {key!r}"
                )


@pytest.mark.parametrize("subject", PERSON_SUBJECTS)
@pytest.mark.parametrize("flow", FLOWS, ids=FLOW_IDS)
def test_actor_attribute_does_not_export_the_subject(exporter, flow, subject):
    attributes = _run(exporter, flow, subject)

    _, _, key, _ = flow
    assert attributes[key] == "user"
    assert attributes[f"{key}_user_id"] == USER_ID
    _assert_subject_not_exported(exporter, subject)


@pytest.mark.parametrize("flow", FLOWS, ids=FLOW_IDS)
def test_actor_attribute_keeps_the_system_principal(exporter, flow):
    attributes = _run(exporter, flow, SYSTEM_SUBJECT)

    _, _, key, _ = flow
    assert attributes[key] == SYSTEM_SUBJECT
    assert attributes[f"{key}_user_id"] == USER_ID


@pytest.mark.parametrize("subject", FAKE_SYSTEM_SUBJECTS)
@pytest.mark.parametrize("flow", FLOWS, ids=FLOW_IDS)
def test_actor_attribute_does_not_export_an_unknown_system_subject(
    exporter, flow, subject
):
    attributes = _run(exporter, flow, subject)

    _, _, key, _ = flow
    assert attributes[key] == "user"
    assert attributes[f"{key}_user_id"] == USER_ID
    _assert_subject_not_exported(exporter, subject)


def test_update_action_without_actor_reports_none(exporter):
    svc = _services(exporter)["action"]
    with contextlib.suppress(Exception):
        svc.update_action(MagicMock(), 1, name="a:x", updated_by=None)

    (span,) = [
        s for s in exporter.get_finished_spans() if s.name == "action.update_action"
    ]
    assert span.attributes["action.updated_by"] == "none"
    assert "action.updated_by_user_id" not in span.attributes


# --- exporter filter: CPF written ddddddddd-dd --------------------------------


def test_redact_cpf_masks_cpf_with_only_the_check_digit_dash():
    assert redact_cpf(CPF_DASHED_SUBJECT) == CPF_PLACEHOLDER
    assert redact_cpf(f"group:ops:member:{CPF_DASHED_SUBJECT}") == (
        f"group:ops:member:{CPF_PLACEHOLDER}"
    )
    assert redact_cpf(["viewer", CPF_DASHED_SUBJECT]) == ["viewer", CPF_PLACEHOLDER]


def test_redact_cpf_keeps_dashed_numbers_that_are_not_cpf():
    assert redact_cpf("12345678-90") == "12345678-90"  # 8 digits before the dash
    assert redact_cpf("1234567890-12") == "1234567890-12"  # 10 digits
    assert redact_cpf("123456789-012") == "123456789-012"  # 3 after the dash
    assert redact_cpf("2026-11-18") == "2026-11-18"
