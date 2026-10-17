"""M1/M2 admission selects each producer's latest attempt; attempts never mix."""

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from guard_harness import mainnet_observations as observations
from guard_harness.run_attempts import AttemptError

RUN = "4242"
GUARD = Path(__file__).resolve().parents[2]
# The public repository keeps the workflows at the root's .github/workflows.
WORKFLOWS = GUARD / "github/workflows"
WORKFLOW = (
    WORKFLOWS if WORKFLOWS.is_dir() else GUARD.parents[1] / ".github/workflows"
) / "install-matrix.yml"


def artifact(root: Path, prefix: str, attempt: int, files: dict[str, str], run: str = RUN) -> Path:
    directory = root / f"{prefix}-{run}-{attempt}"
    for name, body in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return directory


def m1(root: Path, attempt: int = 1) -> None:
    artifact(root, "install-matrix-M1-linux-native", attempt, {"M1/linux-systemd.json": "a"})
    artifact(
        root, "install-matrix-M1-linux-container", attempt, {"linux-container-native.json": "b"}
    )
    artifact(
        root,
        "install-matrix-M1-macos",
        attempt,
        {"macos-launchdaemon.json": "c", "homebrew-foreground.log": "d"},
    )
    artifact(
        root,
        "install-matrix-M1-windows",
        attempt,
        {"M1/windows-scm.json": "e", "windows-policy/policy.receipt.json": "f"},
    )
    artifact(
        root,
        "I7",
        attempt,
        {"I7/mainnet/M1/aws-template.json": "g", "I7/receipt.json": "not an M1 observation"},
    )


def m2(root: Path, attempt: int = 1) -> Path:
    artifact(root, "mainnet-setup-linux", attempt, {"missing-consent.json": "a", "x.log": "b"})
    artifact(root, "mainnet-setup-windows", attempt, {"windows-per-user.json": "c"})
    macos = root.parent / "macos"
    (macos / "upgrade/mainnet/M2").mkdir(parents=True, exist_ok=True)
    (macos / "upgrade/mainnet/M2/homebrew-services.json").write_text("d")
    return macos


def gather(root: Path, row: str, attempt: str = "1", macos: Path | None = None) -> dict[str, str]:
    return observations.gather(
        row, root, run_id=RUN, attempt=attempt, output=root.parent / "out" / row, macos=macos
    )


def names(root: Path, row: str) -> dict[str, str]:
    out = root.parent / "out" / row
    return {path.name: path.read_text() for path in out.iterdir()}


def test_m1_gathers_every_producer_without_relabelling(tmp_path: Path) -> None:
    root = tmp_path / "run-artifacts"
    m1(root)
    (root / "install-matrix-subjects").mkdir()  # other artifacts of the run are ignored
    selected = gather(root, "M1")
    assert selected == {prefix: "1" for prefix in observations.M1_PRODUCERS}
    assert names(root, "M1") == {
        "linux-systemd.json": "a",
        "linux-container-native.json": "b",
        "macos-launchdaemon.json": "c",
        "homebrew-foreground.log": "d",
        "windows-scm.json": "e",
        "policy.receipt.json": "f",
        "aws-template.json": "g",
    }


def test_rerun_admits_only_the_latest_attempt_of_each_producer(tmp_path: Path) -> None:
    root = tmp_path / "run-artifacts"
    m1(root, 1)
    # Attempt 2 reran only the Windows job: its earlier part must not be merged beside it.
    artifact(root, "install-matrix-M1-windows", 2, {"M1/windows-scm.json": "rerun"})
    # Attempt 4 follows this consumer (attempt 3) and is never admitted.
    artifact(root, "install-matrix-M1-macos", 4, {"macos-launchdaemon.json": "future"})
    selected = gather(root, "M1", attempt="3")
    assert selected["install-matrix-M1-windows"] == "2"
    assert selected["install-matrix-M1-macos"] == "1"
    found = names(root, "M1")
    assert found["windows-scm.json"] == "rerun"
    assert "policy.receipt.json" not in found  # only in the superseded attempt 1
    assert found["macos-launchdaemon.json"] == "c"


def test_m2_never_merges_an_old_part_with_a_new_one(tmp_path: Path) -> None:
    root = tmp_path / "run-artifacts"
    macos = m2(root, 1)
    artifact(root, "mainnet-setup-linux", 2, {"missing-consent.json": "new"})
    selected = gather(root, "M2", attempt="2", macos=macos)
    assert selected == {"mainnet-setup-linux": "2", "mainnet-setup-windows": "1"}
    assert names(root, "M2") == {
        "missing-consent.json": "new",
        "windows-per-user.json": "c",
        "homebrew-services.json": "d",
    }


def refusal_cases() -> dict[str, Any]:
    def missing(root: Path) -> None:
        for path in sorted((root / f"install-matrix-M1-macos-{RUN}-1").rglob("*"), reverse=True):
            path.unlink() if path.is_file() else path.rmdir()
        (root / f"install-matrix-M1-macos-{RUN}-1").rmdir()

    def flat(root: Path) -> None:
        (root / "linux-systemd.json").write_text("single-artifact download extracted flat")

    def foreign_run(root: Path) -> None:
        artifact(root, "install-matrix-M1-windows", 1, {"windows-scm.json": "x"}, run="999")

    def ambiguous_attempt(root: Path) -> None:
        artifact(root, "install-matrix-M1-windows", 1, {}).rename(
            root / f"install-matrix-M1-windows-{RUN}-01"
        )

    def duplicate(root: Path) -> None:
        artifact(root, "install-matrix-M1-macos", 1, {"nested/linux-systemd.json": "twice"})

    def link(root: Path) -> None:
        target = root.parent / "elsewhere.json"
        target.write_text("outside")
        (root / f"install-matrix-M1-macos-{RUN}-1" / "linked.json").symlink_to(target)

    def only_future(root: Path) -> None:
        directory = root / f"install-matrix-M1-linux-native-{RUN}-1"
        directory.rename(root / f"install-matrix-M1-linux-native-{RUN}-2")

    def output_exists(root: Path) -> None:
        (root.parent / "out" / "M1").mkdir(parents=True)

    return {
        "missing": missing,
        "flat": flat,
        "foreign-run": foreign_run,
        "malformed-attempt": ambiguous_attempt,
        "duplicate": duplicate,
        "link": link,
        "only-future": only_future,
        "output-exists": output_exists,
    }


@pytest.mark.parametrize("case", sorted(refusal_cases()))
def test_m1_refuses_incomplete_or_ambiguous_artifacts(tmp_path: Path, case: str) -> None:
    root = tmp_path / "run-artifacts"
    m1(root)
    refusal_cases()[case](root)
    with pytest.raises(AttemptError):
        gather(root, "M1")


@pytest.mark.parametrize("missing", ["macos", "mainnet-setup-windows"])
def test_m2_requires_every_producer(tmp_path: Path, missing: str) -> None:
    root = tmp_path / "run-artifacts"
    macos: Path | None = m2(root)
    if missing == "macos":
        macos = None
    else:
        directory = root / f"{missing}-{RUN}-1"
        for path in directory.iterdir():
            path.unlink()
        directory.rmdir()
    with pytest.raises(AttemptError):
        gather(root, "M2", macos=macos)


def test_m2_refuses_the_same_observation_from_two_producers(tmp_path: Path) -> None:
    root = tmp_path / "run-artifacts"
    macos = m2(root)
    artifact(root, "mainnet-setup-windows", 1, {"missing-consent.json": "also"})
    with pytest.raises(AttemptError, match="ambiguous"):
        gather(root, "M2", macos=macos)


def test_other_rows_refused(tmp_path: Path) -> None:
    with pytest.raises(AttemptError):
        gather(tmp_path, "M3")


def test_cli_moves_nothing_and_prints_each_selection(tmp_path: Path) -> None:
    root = tmp_path / "run-artifacts"
    m1(root)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "guard_harness.mainnet_observations",
            "--row",
            "M1",
            "--artifacts",
            str(root),
            "--run-id",
            RUN,
            "--attempt",
            "1",
            "--output",
            str(tmp_path / "out/M1"),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.count("attempt 1 of run " + RUN) == len(observations.M1_PRODUCERS)
    assert (root / f"I7-{RUN}-1").is_dir()


def test_workflow_producers_are_attempt_scoped_and_admission_selects_them() -> None:
    document: Any = yaml.safe_load(WORKFLOW.read_text())
    jobs = document["jobs"]
    suffix = "-${{ github.run_id }}-${{ github.run_attempt }}"
    produced: set[str] = set()
    for job, template in (
        ("linux-mainnet", "install-matrix-M1-linux-${{ matrix.mode }}"),
        ("native-mainnet", "install-matrix-M1-${{ matrix.variant }}"),
        ("mainnet-setup", "mainnet-setup-${{ matrix.variant }}"),
    ):
        uploads = [
            step["with"]
            for step in jobs[job]["steps"]
            if str(step.get("uses", "")).startswith("actions/upload-artifact@")
        ]
        assert len(uploads) == 1
        assert uploads[0]["name"] == template + suffix
        assert uploads[0]["if-no-files-found"] == "error"
        matrix = jobs[job]["strategy"]["matrix"]
        values = (
            matrix["mode"]
            if "mode" in matrix
            else [entry["variant"] for entry in matrix["include"]]
        )
        for value in values:
            produced.add(template.split("${{")[0] + value)
    assert produced == set(observations.M1_PRODUCERS[:-1]) | set(observations.M2_PRODUCERS)
    aws = [
        step["with"]["name"]
        for step in jobs["aws-stack"]["steps"]
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
        and str(step["with"].get("name", "")).startswith("I7-")
    ]
    assert aws == ["I7" + suffix]
    admission = jobs["mainnet-admission"]["steps"]
    downloads = [
        step for step in admission if str(step.get("uses", "")).startswith("actions/download-")
    ]
    for step in downloads:
        options = step.get("with", {})
        assert "merge-multiple" not in options
        assert "pattern" not in options
    everything = [step for step in downloads if set(step["with"]) == {"path"}]
    assert len(everything) == 1 and "if" not in everything[0]
    runs = "\n".join(str(step.get("run", "")) for step in admission)
    assert "python -m guard_harness.mainnet_observations" in runs
    assert '--attempt "$GITHUB_RUN_ATTEMPT"' in runs
    assert "run-artifacts" in everything[0]["with"]["path"]
