"""Execute admission shell and evaluate actual dispatch graph without custody or network."""

import ast
import itertools
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from guard_harness.c6_owner import document

_GUARD = Path(__file__).resolve().parents[2]
# Private source keeps the workflows in deploy/guard/github/workflows;
# the export moves them to .github/workflows.
WORKFLOW = (
    _GUARD / "github/workflows/install-matrix.yml"
    if (_GUARD / "github/workflows").is_dir()
    else _GUARD.parents[1] / ".github/workflows/install-matrix.yml"
)
SOURCE_FLAG = "${{ inputs.source_installer_diagnostic == true && 'true' || 'false' }}"
ALIASES = {
    "WORKFLOW_REF": "${{ github.workflow_ref }}",
    "CALLER_REF": "${{ github.ref }}",
    "CALLER_EVENT": "${{ github.event_name }}",
    "CALLER_REPOSITORY": "${{ github.repository }}",
    "CALLER_SHA": "${{ github.sha }}",
}


def jobs() -> dict[str, Any]:
    return cast(dict[str, Any], document(WORKFLOW.read_text())["jobs"])


def auth_step() -> dict[str, Any]:
    matches = [
        step
        for step in jobs()["subjects"]["steps"]
        if step.get("name") == "Authenticate original candidate and predecessor bytes"
    ]
    assert len(matches) == 1
    return cast(dict[str, Any], matches[0])


def admitted(**overrides: str) -> bool:
    # Only the existing admission prefix executes, before mkdir/authentication.
    script = auth_step()["run"].split("CHANNEL=staging", 1)[0]
    assert "native_release" not in script and "WALLET" not in script
    assert "SOURCE_INSTALLER_DIAGNOSTIC" in script
    env = {
        "PATH": os.environ["PATH"],
        "GITHUB_REPOSITORY": "zunderlabs/zunder-guard",
        "GITHUB_SHA": "a" * 40,
        "SOURCE": "a" * 40,
        "CALLER_REPOSITORY": "zunderlabs/zunder-guard",
        "CALLER_SHA": "a" * 40,
        "CALLER_EVENT": "workflow_dispatch",
        "CALLER_REF": "refs/heads/preview/source-installer",
        "WORKFLOW_REF": (
            "zunderlabs/zunder-guard/.github/workflows/install-matrix.yml"
            "@refs/heads/preview/source-installer"
        ),
        "INSTALL_MATRIX_PROFILE": "all",
        "INSTALL_MATRIX_TARGET": "unix",
        "INSTALL_MATRIX_SCENARIO": "fresh",
        "DIAGNOSTIC": "true",
        "SOURCE_INSTALLER_DIAGNOSTIC": "true",
        **overrides,
    }
    result = subprocess.run(
        ["bash", "-c", script], env=env, capture_output=True, timeout=5, check=False
    )
    return result.returncode == 0


def evaluate(
    expression: str,
    *,
    target: str = "unix",
    scenario: str = "fresh",
    profile: str = "all",
    diagnostic: bool = True,
) -> Any:
    expression = expression.removeprefix("${{").removesuffix("}}").strip()
    replacements = {
        "inputs.target": target,
        "inputs.scenario": scenario,
        "inputs.profile": profile,
        "inputs.diagnostic": diagnostic,
        "github.workflow_ref": "zunderlabs/zunder-guard/.github/workflows/install-matrix.yml@main",
        "github.event_name": "workflow_dispatch",
    }
    for name, value in replacements.items():
        expression = expression.replace(name, repr(value))
    expression = re.sub(r"needs\.[a-z0-9-]+\.result", "'success'", expression)
    expression = re.sub(r"\btrue\b", "True", expression)
    expression = re.sub(r"\bfalse\b", "False", expression)
    expression = re.sub(r"!(?!=)", " not ", expression)
    expression = expression.replace("&&", " and ").replace("||", " or ").strip()
    tree = ast.parse(expression, mode="eval")
    allowed = (
        ast.Expression,
        ast.Constant,
        ast.Name,
        ast.Load,
        ast.BoolOp,
        ast.And,
        ast.Or,
        ast.UnaryOp,
        ast.Not,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        ast.Call,
    )
    functions = {
        "fromJSON": json.loads,
        "contains": lambda container, item: item in container,
        "always": lambda: True,
    }
    for node in ast.walk(tree):
        assert isinstance(node, allowed), "unsupported workflow expression"
        if isinstance(node, ast.Name):
            assert node.id in functions
        if isinstance(node, ast.Call):
            assert isinstance(node.func, ast.Name) and node.func.id in functions
            assert not node.keywords
    return eval(
        compile(tree, "<actual-workflow-condition>", "eval"), {"__builtins__": {}}, functions
    )


def test_component_flag_is_dispatch_only_and_off_by_default() -> None:
    workflow = document(WORKFLOW.read_text())
    events = cast(dict[object, Any], workflow)[True]  # YAML 1.1 `on` key.
    assert events["workflow_dispatch"]["inputs"]["source_installer_diagnostic"] == {
        "type": "boolean",
        "default": False,
    }
    assert "source_installer_diagnostic" not in events["workflow_call"]["inputs"]
    assert workflow["concurrency"]["cancel-in-progress"] is False
    assert workflow["concurrency"]["queue"] == "max"


@pytest.mark.parametrize(
    "profile,target,scenario,diagnostic,event,owner",
    tuple(
        itertools.product(
            ("all", "nightly"),
            ("unix", "all", "native"),
            ("fresh", "upgrade", "all"),
            ("true", "false"),
            ("workflow_dispatch", "workflow_call", "schedule"),
            ("own", "verify"),
        )
    ),
)
def test_source_mode_admits_only_one_exact_standalone_tuple(
    profile: str, target: str, scenario: str, diagnostic: str, event: str, owner: str
) -> None:
    workflow_ref = (
        "zunderlabs/zunder-guard/.github/workflows/"
        + ("install-matrix.yml" if owner == "own" else "verify.yml")
        + "@refs/heads/preview/source-installer"
    )
    assert admitted(
        INSTALL_MATRIX_PROFILE=profile,
        INSTALL_MATRIX_TARGET=target,
        INSTALL_MATRIX_SCENARIO=scenario,
        DIAGNOSTIC=diagnostic,
        CALLER_EVENT=event,
        WORKFLOW_REF=workflow_ref,
    ) == (
        profile == "all"
        and target == "unix"
        and scenario == "fresh"
        and diagnostic == "true"
        and event == "workflow_dispatch"
        and owner == "own"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("SOURCE_INSTALLER_DIAGNOSTIC", "1"),
        ("SOURCE_INSTALLER_DIAGNOSTIC", ""),
        ("SOURCE_INSTALLER_DIAGNOSTIC", "TRUE"),
        ("CALLER_REPOSITORY", "other/repo"),
        ("CALLER_SHA", "b" * 40),
        ("CALLER_REF", "refs/heads/main"),
        ("WORKFLOW_REF", "other/repo/.github/workflows/install-matrix.yml@refs/heads/main"),
    ],
)
def test_malformed_flag_or_forged_context_refuses_before_authentication(
    field: str, value: str
) -> None:
    assert not admitted(**{field: value})


@pytest.mark.parametrize("profile,diagnostic", [("all", "false"), ("nightly", "false")])
def test_false_flag_keeps_full_reusable_and_nightly_admission(
    profile: str, diagnostic: str
) -> None:
    assert admitted(
        SOURCE_INSTALLER_DIAGNOSTIC="false",
        INSTALL_MATRIX_TARGET="all",
        INSTALL_MATRIX_SCENARIO="all",
        INSTALL_MATRIX_PROFILE=profile,
        DIAGNOSTIC=diagnostic,
        CALLER_EVENT="schedule",
        WORKFLOW_REF="caller/.github/workflows/nightly.yml@main",
    )


def test_unix_fresh_source_mode_selects_exactly_three_components() -> None:
    selected = {
        name
        for name, job in jobs().items()
        if name != "subjects" and evaluate(job.get("if", "${{ true }}"))
    }
    assert selected == {"linux-amd64", "linux-container", "native"}
    for name in selected:
        job = jobs()[name]
        assert job["needs"] == "subjects"
        assert evaluate(job["strategy"]["matrix"]["scenario"]) == ["fresh"]
        assert job["strategy"]["fail-fast"] is False
    native = jobs()["native"]["strategy"]["matrix"]
    assert evaluate(native["variant"]) == ["macos"]
    assert evaluate(native["include"]) == [
        {"os": "macos-15", "shell": "sh", "row": "I3", "variant": "macos"}
    ]


def test_source_flag_and_trusted_context_reach_only_subjects_and_three_runtime_steps() -> None:
    flagged = []
    for name, job in jobs().items():
        for step in job.get("steps", []):
            env = step.get("env", {})
            if "SOURCE_INSTALLER_DIAGNOSTIC" not in env:
                continue
            flagged.append(name)
            assert env["SOURCE_INSTALLER_DIAGNOSTIC"] == SOURCE_FLAG
            assert all(env.get(key) == expression for key, expression in ALIASES.items())
    assert sorted(flagged) == ["linux-amd64", "linux-container", "native", "subjects"]
    for workflow in ("verify.yml", "nightly.yml"):
        assert "source_installer_diagnostic" not in (WORKFLOW.parent / workflow).read_text()


def test_native_retains_exact_source_provenance_without_uploading_source_script() -> None:
    uploads = [
        step
        for step in jobs()["native"]["steps"]
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 1
    paths = uploads[0]["with"]["path"].splitlines()
    assert "${{ runner.temp }}/native-evidence/source-installer.json" in paths
    assert not any("source-install.sh" in path for path in paths)
