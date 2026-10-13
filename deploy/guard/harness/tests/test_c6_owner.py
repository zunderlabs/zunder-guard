from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from guard_harness import c6_owner


def workflow_directory(root: Path) -> Path:
    private = root / "deploy/guard/github/workflows"
    return private if private.is_dir() else root / ".github/workflows"


WORKFLOWS = workflow_directory(Path(__file__).resolve().parents[4])


def source(name: str) -> str:
    return (WORKFLOWS / name).read_text()


def sources() -> dict[str, str]:
    return {
        name: source(name)
        for name in ("verify.yml", "nightly.yml", "install-matrix.yml", "journey.yml")
    }


def check(caller: str, files: dict[str, str]) -> None:
    c6_owner.validate(caller, files[caller], files["install-matrix.yml"], files["journey.yml"])


@pytest.mark.parametrize("caller", ["verify.yml", "nightly.yml"])
def test_actual_default_graph_admits(caller: str) -> None:
    check(caller, sources())


@pytest.mark.parametrize("layout", ["deploy/guard/github/workflows", ".github/workflows"])
def test_actual_graph_lookup_admits_both_source_layouts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str
) -> None:
    original = sources()
    directory = tmp_path / layout
    directory.mkdir(parents=True)
    for name, text in original.items():
        (directory / name).write_text(text)
    assert workflow_directory(tmp_path) == directory
    monkeypatch.setattr(f"{__name__}.WORKFLOWS", workflow_directory(tmp_path))
    for caller in ("verify.yml", "nightly.yml"):
        check(caller, sources())


@pytest.mark.parametrize(
    "field,value",
    [
        ("group", "guard-release-lifecycle"),
        ("group", "guard-nightly"),
        ("group", "${{ github.run_id }}"),
        ("cancel-in-progress", True),
        ("cancel-in-progress", 0),
        ("cancel-in-progress", "false"),
        ("queue", "single"),
    ],
)
@pytest.mark.parametrize("caller", ["verify.yml", "nightly.yml"])
def test_legacy_or_dynamic_global_lock_refuses(caller: str, field: str, value: Any) -> None:
    files = sources()
    doc = c6_owner.document(files[caller])
    doc["concurrency"][field] = value
    files[caller] = yaml.safe_dump(doc)
    with pytest.raises(c6_owner.OwnerError):
        check(caller, files)


@pytest.mark.parametrize(
    "dependency,condition",
    [
        ("staging", "${{ !cancelled() && needs.staging.result == 'success' }}"),
        (["staging", "journeys"], "${{ always() }}"),
        (["staging", "journeys"], "${{ !cancelled() }}"),
        (["staging", "journeys"], "${{ needs.journeys.result != 'cancelled' }}"),
        (["staging", "journeys", "gate"], "${{ !cancelled() }}"),
    ],
)
def test_failed_or_skipped_traders_cannot_admit_readers(dependency: Any, condition: str) -> None:
    files = sources()
    doc = c6_owner.document(files["verify.yml"])
    doc["jobs"]["install-matrix"].update(needs=dependency, **{"if": condition})
    files["verify.yml"] = yaml.safe_dump(doc)
    with pytest.raises(c6_owner.OwnerError, match="completed journeys"):
        check("verify.yml", files)


@pytest.mark.parametrize(
    "callee",
    [
        "zunderlabs/zunder-guard/.github/workflows/install-matrix.yml@main",
        "zunderlabs/zunder-guard/.github/workflows/install-matrix.yml@" + "a" * 40,
        "./.github/workflows/alternate.yml",
    ],
)
def test_old_caller_invoking_new_explicit_callee_never_inherits_new_lock(callee: str) -> None:
    files = sources()
    doc = c6_owner.document(files["verify.yml"])
    doc["jobs"]["install-matrix"]["uses"] = callee
    files["verify.yml"] = yaml.safe_dump(doc)
    with pytest.raises(c6_owner.OwnerError, match="same-commit"):
        check("verify.yml", files)


def test_extra_reusable_call_refuses() -> None:
    files = sources()
    doc = c6_owner.document(files["verify.yml"])
    doc["jobs"]["extra"] = {"uses": "./.github/workflows/journey.yml"}
    files["verify.yml"] = yaml.safe_dump(doc)
    with pytest.raises(c6_owner.OwnerError):
        check("verify.yml", files)


@pytest.mark.parametrize("workflow", ["install-matrix.yml", "journey.yml"])
@pytest.mark.parametrize(
    "extra",
    [
        {"uses": "./.github/workflows/journey.yml", "with": {"profile": "all"}},
        {"runs-on": "ubuntu-24.04", "steps": [{"run": "trader", "env": {"KEY": "secret"}}]},
    ],
)
def test_extra_callee_trader_job_refuses(workflow: str, extra: dict[str, Any]) -> None:
    files = sources()
    doc = c6_owner.document(files[workflow])
    doc["jobs"]["extra-trader"] = extra
    files[workflow] = yaml.safe_dump(doc)
    with pytest.raises(c6_owner.OwnerError, match="callee job set"):
        check("verify.yml", files)


@pytest.mark.parametrize(
    "workflow,job", [("install-matrix.yml", "native"), ("journey.yml", "testnet-foreground")]
)
def test_existing_callee_job_cannot_be_replaced_by_alternate_call(workflow: str, job: str) -> None:
    files = sources()
    doc = c6_owner.document(files[workflow])
    doc["jobs"][job] = {"uses": "./.github/workflows/alternate.yml"}
    files[workflow] = yaml.safe_dump(doc)
    with pytest.raises(c6_owner.OwnerError, match="reusable call"):
        check("verify.yml", files)


@pytest.mark.parametrize(
    "workflow,job",
    [
        ("verify.yml", "journeys"),
        ("verify.yml", "install-matrix"),
        ("nightly.yml", "installs"),
        ("nightly.yml", "purchase"),
        ("journey.yml", "testnet-foreground"),
        ("journey.yml", "testnet-systemd"),
    ],
)
@pytest.mark.parametrize(
    "field,value",
    [
        ("strategy", {"matrix": {"copy": ["one", "two"]}}),
        ("continue-on-error", True),
        ("continue-on-error", "false"),
    ],
)
def test_trader_copy_matrix_or_failure_bypass_refuses(
    workflow: str, job: str, field: str, value: Any
) -> None:
    files = sources()
    doc = c6_owner.document(files[workflow])
    doc["jobs"][job][field] = value
    files[workflow] = yaml.safe_dump(doc)
    with pytest.raises(c6_owner.OwnerError, match="singular and fail closed"):
        check("nightly.yml" if workflow == "nightly.yml" else "verify.yml", files)


@pytest.mark.parametrize("profile", ["nightly", "unknown", "${{ inputs.profile }}", "checkout"])
def test_verify_profile_cannot_change_trading_ownership(profile: str) -> None:
    files = sources()
    doc = c6_owner.document(files["verify.yml"])
    doc["jobs"]["journeys"]["with"]["profile"] = profile
    files["verify.yml"] = yaml.safe_dump(doc)
    with pytest.raises(c6_owner.OwnerError, match="profile"):
        check("verify.yml", files)


@pytest.mark.parametrize(
    "source_text",
    [
        "jobs: {}\njobs: {}\n",
        "jobs:\n  job:\n    concurrency:\n      group: one\n      group: two\n",
        "jobs:\n  job:\n    steps:\n      - env: {WALLET: one, WALLET: two}\n",
        "jobs: {one: {with: {profile: all, profile: nightly}}}\n",
        "jobs: {one: {<<: {}, needs: []}}\n",
        "!!python/object/apply:os.system ['false']\n",
    ],
)
def test_duplicate_keys_unsafe_tags_and_merges_refuse_at_every_depth(source_text: str) -> None:
    with pytest.raises(c6_owner.OwnerError):
        c6_owner.document(source_text)


@pytest.mark.parametrize("leaf", c6_owner.READERS)
def test_inner_reader_account_lock_refuses(leaf: str) -> None:
    files = sources()
    doc = c6_owner.document(files["install-matrix.yml"])
    doc["jobs"][leaf]["concurrency"] = c6_owner.LOCK
    files["install-matrix.yml"] = yaml.safe_dump(doc)
    with pytest.raises(c6_owner.OwnerError, match="inner account lock"):
        check("verify.yml", files)


def test_t2_requires_successful_t1_and_no_trading_self_lock() -> None:
    files = sources()
    doc = c6_owner.document(files["journey.yml"])
    doc["jobs"]["testnet-systemd"]["needs"] = []
    files["journey.yml"] = yaml.safe_dump(doc)
    with pytest.raises(c6_owner.OwnerError, match="follow successful"):
        check("verify.yml", files)


@pytest.fixture
def caller_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    repo = tmp_path / "caller"
    repo.mkdir()
    target = repo / ".github/workflows"
    target.mkdir(parents=True)
    for name, text in sources().items():
        (target / name).write_text(text)
    commands = (
        ["init", "--quiet"],
        ["add", "."],
        [
            "-c",
            "user.name=Offline test",
            "-c",
            "user.email=offline@example.invalid",
            "commit",
            "--quiet",
            "--no-verify",
            "-m",
            "workflow fixture",
        ],
    )
    for command in commands:
        subprocess.run(["git", "-C", str(repo), *command], check=True, capture_output=True)
    sha = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    monkeypatch.chdir(repo)
    return {
        "WORKFLOW_REF": "zunderlabs/zunder-guard/.github/workflows/verify.yml@refs/heads/main",
        "WORKFLOW_SHA": sha,
        "CALLER_SHA": sha,
        "CALLER_REF": "refs/heads/main",
        "CALLER_REPOSITORY": "zunderlabs/zunder-guard",
        "CALLER_EVENT": "workflow_dispatch",
    }


def test_network_free_git_snapshot_admits_actual_caller(caller_git: dict[str, str]) -> None:
    c6_owner.admit(caller_git, callee="install-matrix.yml", profile="all")
    c6_owner.admit(caller_git, callee="journey.yml", profile="all")


def test_nightly_ownership_is_workflow_sha_not_promoted_binary_source(
    caller_git: dict[str, str],
) -> None:
    caller_git["WORKFLOW_REF"] = caller_git["WORKFLOW_REF"].replace("verify.yml", "nightly.yml")
    caller_git["SOURCE"] = "b" * 40  # Promoted release checkout is deliberately unrelated.
    c6_owner.admit(caller_git, callee="install-matrix.yml", profile="nightly")
    with pytest.raises(c6_owner.OwnerError):
        c6_owner.admit(caller_git, callee="journey.yml", profile="nightly")


@pytest.mark.parametrize(
    "field,value",
    [
        ("WORKFLOW_REF", "other/repo/.github/workflows/verify.yml@refs/heads/main"),
        ("WORKFLOW_REF", "zunderlabs/zunder-guard/.github/workflows/unknown.yml@refs/heads/main"),
        ("WORKFLOW_REF", "zunderlabs/zunder-guard/.github/workflows/journey.yml@refs/heads/main"),
        ("WORKFLOW_SHA", "a" * 40),
        ("CALLER_SHA", "a" * 40),
        ("WORKFLOW_SHA", "../HEAD"),
        ("CALLER_REPOSITORY", "other/repo"),
        ("CALLER_REF", "refs/heads/unknown"),
    ],
)
def test_forged_or_unknown_context_refuses(
    caller_git: dict[str, str], field: str, value: str
) -> None:
    caller_git[field] = value
    with pytest.raises(c6_owner.OwnerError):
        c6_owner.admit(caller_git, callee="install-matrix.yml", profile="all")


def test_standalone_diagnostic_global_owner_and_profiles(caller_git: dict[str, str]) -> None:
    caller_git["WORKFLOW_REF"] = caller_git["WORKFLOW_REF"].replace(
        "verify.yml", "install-matrix.yml"
    )
    caller_git["DIAGNOSTIC"] = "true"
    c6_owner.admit(caller_git, callee="install-matrix.yml", profile="all")
    for profile in ("nightly", "unknown", "checkout"):
        with pytest.raises(c6_owner.OwnerError):
            c6_owner.admit(caller_git, callee="install-matrix.yml", profile=profile)
    caller_git["DIAGNOSTIC"] = "false"
    with pytest.raises(c6_owner.OwnerError):
        c6_owner.admit(caller_git, callee="install-matrix.yml", profile="all")


def test_missing_git_object_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    sha = "a" * 40

    def missing(*args: str) -> str:
        if args == ("rev-parse", "HEAD"):
            return sha
        raise c6_owner.OwnerError("C6 immutable workflow snapshot unavailable")

    monkeypatch.setattr(c6_owner, "_git", missing)
    with pytest.raises(c6_owner.OwnerError, match="snapshot unavailable"):
        c6_owner.admit(
            {
                "WORKFLOW_REF": (
                    "zunderlabs/zunder-guard/.github/workflows/verify.yml@refs/heads/main"
                ),
                "WORKFLOW_SHA": sha,
                "CALLER_SHA": sha,
                "CALLER_REF": "refs/heads/main",
                "CALLER_REPOSITORY": "zunderlabs/zunder-guard",
            },
            callee="install-matrix.yml",
            profile="all",
        )


@pytest.mark.parametrize(
    "workflow,leaves",
    [
        ("install-matrix.yml", (*c6_owner.READERS, "operator-recovery")),
        ("journey.yml", ("testnet-foreground", "testnet-systemd")),
    ],
)
def test_actual_owner_admission_precedes_every_custody_step(
    workflow: str, leaves: tuple[str, ...]
) -> None:
    jobs = c6_owner.document(source(workflow))["jobs"]
    for name in leaves:
        steps = jobs[name]["steps"]
        admissions = [
            n for n, step in enumerate(steps) if "guard_harness.c6_owner" in step.get("run", "")
        ]
        assert len(admissions) == 1
        admission = admissions[0]
        assert steps[admission]["env"]["WORKFLOW_SHA"] == "${{ github.workflow_sha }}"
        assert steps[admission]["env"]["CALLER_SHA"] == "${{ github.sha }}"
        for n, step in enumerate(steps):
            env = step.get("env", {})
            if any("secrets.E2E_TESTNET_" in str(value) for value in env.values()):
                assert n > admission
            if n <= admission:
                assert "WALLET_FRAME" not in env and "WALLET_INPUT" not in env
        if workflow == "install-matrix.yml" and name != "operator-recovery":
            assert jobs[name]["strategy"]["fail-fast"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("if", "${{ always() }}"),
        ("needs", []),
        ("runs-on", "self-hosted"),
        ("environment", "production"),
        ("timeout-minutes", 121),
        ("concurrency", c6_owner.LOCK),
        ("strategy", {"matrix": {"copy": [1, 2]}}),
        ("continue-on-error", True),
    ],
)
def test_operator_recovery_never_inherits_formal_or_unbounded_custody(
    field: str, value: Any
) -> None:
    files = sources()
    doc = c6_owner.document(files["install-matrix.yml"])
    doc["jobs"]["operator-recovery"][field] = value
    files["install-matrix.yml"] = yaml.safe_dump(doc)
    with pytest.raises(c6_owner.OwnerError):
        check("verify.yml", files)
