"""The example config of scripts/manage_openapi_mappings.py must be safe (DEV-654).

Copying scripts/config.example.json and running 'apply' must not delete the
mappings that are not generated from the configured OpenAPI specs (the versioned
go-api mappings of mappings/go-api.json, applied by app.mappings_sync), and the
go-api spec must be read from a branch that exists (main).
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "manage_openapi_mappings.py"
EXAMPLE = REPO / "scripts" / "config.example.json"
GO_SPEC_URL = (
    "https://raw.githubusercontent.com/prefeitura-rio/app-go-api/"
    "refs/heads/main/docs/openapi-v3.json"
)


@pytest.fixture(scope="module")
def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("manage_openapi_mappings", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def example() -> dict:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def test_example_does_not_delete_unmanaged_mappings(example: dict) -> None:
    assert example["options"]["delete_unmanaged"] is False


def test_example_validates_with_delete_unmanaged_off(
    tool: ModuleType, example: dict
) -> None:
    config = tool.Config(**example)
    assert config.options.delete_unmanaged is False


def test_example_reads_go_spec_from_main(example: dict) -> None:
    go = [api for api in example["apis"] if api["name"] == "GO"]
    assert len(go) == 1
    assert go[0]["openapi_url"] == GO_SPEC_URL
    assert all(
        "app-go-api/refs/heads/staging/" not in api["openapi_url"]
        for api in example["apis"]
    )


def test_example_plan_keeps_mappings_outside_the_specs(
    tool: ModuleType, example: dict
) -> None:
    config = tool.Config(**example)
    generated = [
        tool.Mapping(
            path_pattern="/go/v1/cursos$", method="GET", action_name="go:cursos:list"
        )
    ]
    existing = [
        tool.Mapping(
            path_pattern="/go/v1/cursos$",
            method="GET",
            action_name="go:cursos:list",
            existing_id=1,
        ),
        # Versioned go-api route not documented in the go-api OpenAPI yet.
        tool.Mapping(
            path_pattern="/go/v1/instituicoes$",
            method="GET",
            action_name="go:instituicoes:list",
            existing_id=2,
        ),
        # Mapping of an application missing from 'apis'.
        tool.Mapping(
            path_pattern="/outra-app/v1/itens$",
            method="GET",
            action_name="outra:itens:list",
            existing_id=3,
        ),
    ]

    changes = tool.DiffCalculator(config.options).calculate_changes(generated, existing)

    assert [c.change_type for c in changes] == [tool.ChangeType.NO_OP]


def test_delete_unmanaged_on_would_delete_them(tool: ModuleType) -> None:
    """Guard of the test above: with the option on, the same input deletes."""
    options = tool.OptionsConfig(delete_unmanaged=True)
    generated = [tool.Mapping(path_pattern="/a$", method="GET", action_name="x:a")]
    existing = [
        tool.Mapping(path_pattern="/a$", method="GET", action_name="x:a"),
        tool.Mapping(path_pattern="/b$", method="GET", action_name="x:b"),
    ]

    changes = tool.DiffCalculator(options).calculate_changes(generated, existing)

    deleted = [c.mapping.path_pattern for c in changes if c.change_type == "delete"]
    assert deleted == ["/b$"]
