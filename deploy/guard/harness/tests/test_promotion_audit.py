"""Promote audit residuals: authenticated GitHub latest, lost promote runner."""

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from guard_harness import promotion_channels
from guard_harness.attestation import AttestationError
from guard_harness.homebrew_stage import Tap
from guard_harness.native_release import Release
from guard_harness.runner import RunError

COMMIT = "a" * 40
NOT_FOUND = (
    '{"message":"Not Found","documentation_url":"https://docs.github.com/rest/releases/'
    'releases#get-the-latest-release","status":"404"}'
)


def workflow() -> Any:
    guard = Path(__file__).resolve().parents[2]
    path = guard / "github/workflows/promote.yml"
    if not path.exists():
        path = guard.parents[1] / ".github/workflows/promote.yml"
    document: Any = yaml.safe_load(path.read_text())
    return document


def fake_gh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdout: str, stderr: str, code: int
) -> None:
    """gh 2.97's own shape on a 404: the body on stdout (no newline), the marker on stderr."""
    fakebin = tmp_path / "bin"
    fakebin.mkdir(exist_ok=True)
    (tmp_path / "stdout").write_text(stdout)
    (tmp_path / "stderr").write_text(stderr)
    script = fakebin / "gh"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        "base = pathlib.Path(sys.argv[0]).resolve().parent.parent\n"
        "with open(base / 'calls', 'a') as calls: calls.write(' '.join(sys.argv[1:]) + '\\n')\n"
        "sys.stdout.write((base / 'stdout').read_text())\n"
        "sys.stderr.write((base / 'stderr').read_text())\n"
        f"raise SystemExit({code})\n"
    )
    script.chmod(0o755)
    monkeypatch.setenv("PATH", str(fakebin) + os.pathsep + os.environ["PATH"])


def client(tmp_path: Path) -> promotion_channels.Channels:
    return promotion_channels.Channels(
        Release("v1.0.0", COMMIT, tmp_path), None, tmp_path, Tap(token="fixture", logs=tmp_path)
    )


def test_authenticated_latest_reads_the_api_not_the_public_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_gh(tmp_path, monkeypatch, '{"id": 7, "tag_name": "v0.9.0"}\n', "", 0)
    monkeypatch.setattr(promotion_channels, "public_get", lambda *a: pytest.fail("cached read"))
    assert client(tmp_path).github_latest() == {"id": 7, "tag_name": "v0.9.0"}
    assert (tmp_path / "calls").read_text() == (
        "api --method GET repos/zunderlabs/zunder-guard/releases/latest\n"
    )


def test_githubs_exact_404_means_no_latest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_gh(tmp_path, monkeypatch, NOT_FOUND, "gh: Not Found (HTTP 404)\n", 1)
    assert client(tmp_path).github_latest() is None


@pytest.mark.parametrize(
    ("stdout", "stderr", "code"),
    [
        ('{"message":"Server Error","status":"500"}', "gh: Server Error (HTTP 500)\n", 1),
        ('{"message":"Bad credentials","status":"401"}', "gh: Bad credentials (HTTP 401)\n", 1),
        ('{"message":"Forbidden","status":"403"}', "gh: Forbidden (HTTP 403)\n", 1),
        (NOT_FOUND, "", 1),  # a 404 body without gh's own marker
        ("", "gh: Not Found (HTTP 404)\n", 1),  # the marker without GitHub's body
        (NOT_FOUND, "gh: Not Found (HTTP 404)\nsomething else\n", 1),
        (NOT_FOUND.replace('"404"', '"410"'), "gh: Not Found (HTTP 404)\n", 1),
        ("", "error connecting to api.github.com\n", 1),
    ],
)
def test_every_other_failure_stays_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdout: str, stderr: str, code: int
) -> None:
    fake_gh(tmp_path, monkeypatch, stdout, stderr, code)
    with pytest.raises(RunError):
        client(tmp_path).github_latest()


class FakeTap:
    def request(self, method: str, endpoint: str, body: Any = None) -> dict[str, Any]:
        if endpoint == "git/ref/heads/main":
            return {"object": {"sha": "a" * 40}}
        if endpoint == "git/commits/" + "a" * 40:
            return {"tree": {"sha": "b" * 40}}
        raise AssertionError("unexpected tap mutation")


@pytest.mark.parametrize("latest", [None, {"id": 9, "tag_name": "v0.9.0"}])
def test_snapshot_reads_candidate_then_authenticated_latest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, latest: dict[str, Any] | None
) -> None:
    channels = client(tmp_path)
    monkeypatch.setattr(channels, "tap", FakeTap())
    monkeypatch.setattr(promotion_channels, "image_digest", lambda tag: None)
    monkeypatch.setattr(promotion_channels, "public_get", lambda *a: pytest.fail("cached read"))
    calls: list[str] = []

    def github(method: str, endpoint: str, body: Any = None) -> Any:
        assert method == "GET"
        calls.append(endpoint)
        return {"id": 5, "tag_name": "v1.0.0", "draft": False}

    def github_latest() -> Any:
        calls.append("latest")
        return latest

    monkeypatch.setattr(channels, "github", github)
    monkeypatch.setattr(channels, "github_latest", github_latest)
    if latest is None:
        assert channels.snapshot()["github_before"] is None
    else:
        # No prior canonical release, yet GitHub has a latest: refused.
        with pytest.raises(AttestationError, match="without a prior promoted"):
            channels.snapshot()
    assert calls == ["releases/tags/v1.0.0", "latest"]


def test_snapshot_refuses_before_latest_when_the_positive_control_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    channels = client(tmp_path)
    monkeypatch.setattr(channels, "tap", FakeTap())
    monkeypatch.setattr(promotion_channels, "image_digest", lambda tag: None)

    def unreadable(method: str, endpoint: str, body: Any = None) -> Any:
        raise RunError("candidate unreadable with this token")

    monkeypatch.setattr(channels, "github", unreadable)
    monkeypatch.setattr(channels, "github_latest", lambda: pytest.fail("latest read first"))
    with pytest.raises(RunError):
        channels.snapshot()


def test_rollback_reads_candidate_before_an_authenticated_latest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    channels = client(tmp_path)
    monkeypatch.setattr(channels, "rollback_tap", lambda snapshot: None)
    monkeypatch.setattr(promotion_channels, "image_digest", lambda tag: None)
    order: list[str] = []

    def github(method: str, endpoint: str, body: Any = None) -> Any:
        order.append(method + " " + endpoint)
        if method == "GET" and endpoint == "releases/latest":
            raise AssertionError("use github_latest")
        return {"id": 222, "tag_name": "v1.0.0"} if method == "GET" else {}

    def github_latest() -> Any:
        order.append("latest")
        return {"id": 222}

    monkeypatch.setattr(channels, "github", github)
    monkeypatch.setattr(channels, "github_latest", github_latest)
    monkeypatch.setattr(promotion_channels, "public_get", lambda url: None)
    snapshot = {
        "tap_before": "a" * 40,
        "image_before": None,
        "github_before": None,
        "candidate_release_id": 222,
    }
    assert channels.rollback(snapshot) == []
    assert order[:3] == ["GET releases/222", "latest", "PATCH releases/222"]


# A lost promote runner records no outputs; rollback must not start and then fail.


def recovery_step() -> Any:
    job = workflow()["jobs"]["recovery-inputs"]
    (step,) = job["steps"]
    return step


def run_recovery(tmp_path: Path, answer: str | None, attempt: str = "2") -> tuple[int, str]:
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    gh = fakebin / "gh"
    gh.write_text(
        "#!/bin/sh\n"
        'echo "$@" > "$CALLS"\n'
        + ("echo 'HTTP 502' >&2; exit 1\n" if answer is None else 'cat "$LISTING"\n')
    )
    gh.chmod(0o755)
    (tmp_path / "listing.json").write_text(answer or "")
    output = tmp_path / "output"
    output.write_text("")
    result = subprocess.run(
        ["bash", "-c", recovery_step()["run"]],
        env={
            "PATH": str(fakebin) + os.pathsep + os.environ["PATH"],
            "CALLS": str(tmp_path / "calls"),
            "LISTING": str(tmp_path / "listing.json"),
            "GITHUB_REPOSITORY": "zunderlabs/zunder-guard",
            "GITHUB_RUN_ID": "77",
            "GITHUB_RUN_ATTEMPT": attempt,
            "GITHUB_OUTPUT": str(output),
            "RUNNER_TEMP": str(tmp_path),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    if answer is not None:
        assert (tmp_path / "calls").read_text().split() == [
            "api",
            "--paginate",
            "--slurp",
            "repos/zunderlabs/zunder-guard/actions/runs/77/artifacts?per_page=100",
        ]
    return result.returncode, output.read_text()


def pages(*pages: list[str], total: int | None = None) -> str:
    """gh api --paginate --slurp: one listing object per page, each with the run's total."""
    count = sum(len(page) for page in pages) if total is None else total
    return json.dumps(
        [{"total_count": count, "artifacts": [{"name": name} for name in page]} for page in pages]
    )


def test_positive_absence_of_recovery_inputs_skips_rollback(tmp_path: Path) -> None:
    other = ["canonical-subjects-77-1", "promotion-recovery-78-1", "promotion-recovery-77-x"]
    assert run_recovery(tmp_path, pages(other, [])) == (0, "present=false\n")


def test_present_recovery_inputs_let_rollback_run(tmp_path: Path) -> None:
    answer = pages(["promotion-recovery-77-2"])
    assert run_recovery(tmp_path, answer) == (0, "present=true\n")


def test_rerun_of_the_finder_alone_still_sees_the_earlier_attempts_inputs(
    tmp_path: Path,
) -> None:
    # Promote mutated in attempt 1 and lost its runner; only this job reran, in attempt 2.
    answer = pages(["canonical-subjects-77-1"], ["promotion-recovery-77-1"])
    assert run_recovery(tmp_path, answer, attempt="2") == (0, "present=true\n")


@pytest.mark.parametrize(
    "answer",
    [
        None,  # API failure
        pages(["promotion-recovery-77-1"], total=101),  # a page is missing
        pages([], total=1),
        "[]",  # no page at all
        '[{"artifacts": []}]',  # no count
        '[{"total_count": 0}]',  # no list
        '{"total_count": 0, "artifacts": []}',  # not slurped
        "not json",
    ],
)
def test_any_doubt_leaves_present_unset(tmp_path: Path, answer: str | None) -> None:
    code, output = run_recovery(tmp_path, answer)
    assert code != 0 and output == ""


def test_rollback_is_skipped_only_on_positive_absence() -> None:
    jobs = workflow()["jobs"]
    finder = jobs["recovery-inputs"]
    assert finder["needs"] == "promote"
    assert finder["if"] == (
        "${{ always() && inputs.mode == 'promote' "
        "&& needs.promote.outputs.mutation_attempted == '' }}"
    )
    assert finder["permissions"] == {"actions": "read"}
    assert finder["outputs"] == {"present": "${{ steps.find.outputs.present }}"}
    # No attempt number is assumed: a rerun of the finder alone runs in a later attempt.
    assert set(recovery_step()["env"]) == {"GH_TOKEN"}
    assert "run_attempt" not in recovery_step()["run"].lower()
    rollback = jobs["rollback"]
    assert "recovery-inputs" in rollback["needs"]
    condition = rollback["if"]
    assert "inputs.mode == 'rollback' ||" in condition
    assert "needs.recovery-inputs.outputs.present != 'false'" in condition
    assert "needs.promote.outputs.mutation_attempted != 'false'" in condition
    # The recovery inputs are uploaded before any credential or mutation, as the
    # positive-absence argument requires.
    steps = jobs["promote"]["steps"]
    names = [str(step.get("name", "")) for step in steps]
    upload = next(
        i
        for i, step in enumerate(steps)
        if str(step.get("with", {}).get("name", "")).startswith("promotion-recovery-")
    )
    assert upload < names.index("Mint a short-lived token scoped only to the Homebrew tap")
    assert upload < next(i for i, step in enumerate(steps) if step.get("id") == "publication")
