"""One bounded trust-root fetch per job, passed explicitly to every verifier.

Fake gh and cosign; this proves the wiring and refusals, not Sigstore's TUF or a real
signature (the hosted gate run does).
"""

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

import guard_harness.attestation as attestation
import guard_harness.publication as publisher
from guard_harness.runner import RunResult

FETCH = Path(__file__).resolve().parents[2] / "github/fetch-trusted-root.sh"
MEDIA = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
PUBLIC = {
    "mediaType": MEDIA,
    "tlogs": [{"baseUrl": "https://rekor.sigstore.dev"}],
    "certificateAuthorities": [{"uri": "https://fulcio.sigstore.dev"}],
}
GITHUB = {"mediaType": MEDIA, "certificateAuthorities": [{"uri": "fulcio.githubapp.com"}]}
ROOTS = json.dumps(PUBLIC) + "\n" + json.dumps(GITHUB) + "\n"


def roots(temp: Path) -> Path:
    temp.mkdir(exist_ok=True)
    (temp / "trusted_root.jsonl").write_text(ROOTS)
    (temp / "trusted_root.json").write_text(json.dumps(PUBLIC, indent=2))
    return temp


def gh_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []
    response = [
        {
            "verificationResult": {
                "statement": {"predicateType": "https://example.com/p/v1", "predicate": {}},
                "signature": {
                    "certificate": {
                        "runInvocationURI": "https://github.com/zunderlabs/zunder-guard/actions/runs/1/attempts/1"
                    }
                },
            }
        }
    ]

    def fake_run(argv: list[str], *, log: Path, timeout: int) -> RunResult:
        calls.append(argv)
        return RunResult(0, json.dumps(response), log)

    monkeypatch.setattr(attestation, "run", fake_run)
    return calls


def verify(tmp_path: Path) -> None:
    attestation.verify_predicate(
        tmp_path / "manifest.json",
        tmp_path / "bundle.json",
        workflow="verify.yml",
        commit="a" * 40,
        tag="v1.0.0",
        predicate_type="https://example.com/p/v1",
        log=tmp_path / "verify.log",
    )


def test_without_runner_temp_or_files_gh_fetches_as_before(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = gh_call(tmp_path, monkeypatch)
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    verify(tmp_path)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path / "empty"))
    verify(tmp_path)
    assert len(calls) == 2
    assert all("--custom-trusted-root" not in argv for argv in calls)
    assert attestation.cosign_trust_arguments() == []


def test_fetched_root_is_passed_to_gh_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = gh_call(tmp_path, monkeypatch)
    temp = roots(tmp_path / "runner")
    monkeypatch.setenv("RUNNER_TEMP", str(temp))
    verify(tmp_path)
    (argv,) = calls
    assert argv.count("--custom-trusted-root") == 1
    assert argv[argv.index("--custom-trusted-root") + 1] == str(temp / "trusted_root.jsonl")
    # Every policy flag is still present: the root replaces only the transport.
    for flag in ("--cert-identity-regex", "--cert-oidc-issuer", "--source-digest"):
        assert flag in argv
    assert "--deny-self-hosted-runners" in argv
    assert attestation.cosign_trust_arguments() == [
        "--trusted-root",
        str(temp / "trusted_root.json"),
    ]


def damage_cases() -> dict[str, Any]:
    def symlink(temp: Path) -> None:
        (temp / "trusted_root.json").rename(temp / "real.json")
        (temp / "trusted_root.json").symlink_to(temp / "real.json")

    def wrong_type_bound(temp: Path) -> None:
        # Bound to a fetched line, but neither is a Sigstore TrustedRoot.
        other = PUBLIC | {"mediaType": "application/json"}
        (temp / "trusted_root.jsonl").write_text(json.dumps(other) + "\n")
        (temp / "trusted_root.json").write_text(json.dumps(other))

    def large(temp: Path) -> None:
        (temp / "trusted_root.jsonl").write_text(ROOTS + " " * attestation.TRUSTED_ROOT_LIMIT)

    return {
        "gh-only": lambda temp: (temp / "trusted_root.json").unlink(),
        "cosign-only": lambda temp: (temp / "trusted_root.jsonl").unlink(),
        "unbound": lambda temp: (temp / "trusted_root.json").write_text(
            json.dumps({"mediaType": MEDIA})
        ),
        "foreign": lambda temp: (temp / "trusted_root.json").write_text(
            json.dumps(PUBLIC | {"tlogs": []})
        ),
        "duplicated": lambda temp: (temp / "trusted_root.jsonl").write_text(ROOTS + ROOTS),
        "malformed": lambda temp: (temp / "trusted_root.jsonl").write_text("{not json\n"),
        "wrong-type": lambda temp: (temp / "trusted_root.json").write_text(
            json.dumps(PUBLIC | {"mediaType": "application/json"})
        ),
        "wrong-type-bound": wrong_type_bound,
        "not-object": lambda temp: (temp / "trusted_root.jsonl").write_text("[]\n"),
        "empty": lambda temp: (temp / "trusted_root.jsonl").write_text(""),
        "symlink": symlink,
        "directory": lambda temp: (
            (temp / "trusted_root.json").unlink(),
            (temp / "trusted_root.json").mkdir(),
        ),
        "large": large,
    }


@pytest.mark.parametrize("case", sorted(damage_cases()))
def test_partial_or_unbound_root_refuses_before_any_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    calls = gh_call(tmp_path, monkeypatch)
    temp = roots(tmp_path / "runner")
    damage_cases()[case](temp)
    monkeypatch.setenv("RUNNER_TEMP", str(temp))
    with pytest.raises(attestation.AttestationError):
        verify(tmp_path)
    with pytest.raises(attestation.AttestationError):
        attestation.cosign_trust_arguments()
    assert calls == []


def test_publication_passes_root_to_cosign(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    for name in ("release-manifest.json", "i", "i.ps1", "SHA256SUMS", "SHA256SUMS.sigstore.json"):
        (assets / name).write_text("")
    calls: list[list[str]] = []

    def stop(argv: list[str], **kwargs: Any) -> None:
        calls.append(argv)
        raise attestation.AttestationError("stop after the signature check")

    monkeypatch.setattr(publisher, "run", stop)
    temp = roots(tmp_path / "runner")
    for environment in (str(tmp_path / "empty"), str(temp)):
        monkeypatch.setenv("RUNNER_TEMP", environment)
        with pytest.raises(attestation.AttestationError, match="stop after"):
            publisher.prepare(
                assets,
                assets / "SHA256SUMS",
                assets / "SHA256SUMS",
                manifest_schema=tmp_path,
                state_schema=tmp_path,
                commit="a" * 40,
                tag="v1.0.0",
                workflow="verify.yml",
                previous=None,
                expected=None,
                journeys={},
                logs=tmp_path,
            )
    without, explicit = calls
    assert without[:2] == explicit[:2] == ["cosign", "verify-blob"]
    assert "--trusted-root" not in without
    assert explicit.count("--trusted-root") == 1
    assert explicit[explicit.index("--trusted-root") + 1] == str(temp / "trusted_root.json")

    # Identity, issuer, bundle and blob are unchanged; only the trust root is added.
    def policy(argv: list[str]) -> list[str]:
        trust = {"--trusted-root", str(temp / "trusted_root.json")}
        return [Path(a).name if "guard-publication-" in a else a for a in argv if a not in trust]

    assert policy(explicit) == policy(without)
    assert explicit[-1].endswith("SHA256SUMS")
    (temp / "trusted_root.json").unlink()
    with pytest.raises(attestation.AttestationError, match="incompletely"):
        publisher.prepare(
            assets,
            assets / "SHA256SUMS",
            assets / "SHA256SUMS",
            manifest_schema=tmp_path,
            state_schema=tmp_path,
            commit="a" * 40,
            tag="v1.0.0",
            workflow="verify.yml",
            previous=None,
            expected=None,
            journeys={},
            logs=tmp_path,
        )
    assert len(calls) == 2


# fetch-trusted-root.sh against a fake gh: bounded retry, validation, atomic pair.


def fetch(
    tmp_path: Path,
    plan: list[str],
    output: str = ROOTS,
    *,
    timeout: str | None = None,
    bash: str = "bash",
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """`plan` is gh's behaviour per attempt: "ok" (print `output`), "fail" (a reset) or
    "hang" (a stalled connection that never answers)."""
    fakebin = tmp_path / "bin"
    fakebin.mkdir(exist_ok=True)
    (tmp_path / "plan").write_text("\n".join(plan) + "\n")
    (tmp_path / "roots").write_text(output)
    gh = fakebin / "gh"
    gh.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, sys\n"
        "base = pathlib.Path(sys.argv[0]).resolve().parent.parent\n"
        "assert sys.argv[1:] == ['attestation', 'trusted-root'], sys.argv\n"
        "count = base / 'count'\n"
        "n = int(count.read_text()) if count.exists() else 0\n"
        "count.write_text(str(n + 1))\n"
        "step = (base / 'plan').read_text().split()[n]\n"
        "if step == 'fail':\n"
        "    sys.stdout.write('{\"partial\": ')\n"
        "    sys.stderr.write('tuf refresh failed: connection reset by peer\\n')\n"
        "    raise SystemExit(1)\n"
        "if step == 'hang':\n"
        "    import time\n"
        "    sys.stdout.write('{\"partial\": ')\n"
        "    sys.stdout.flush()\n"
        "    import os\n"
        "    (base / 'hung').write_text(str(os.getpid()))\n"
        "    time.sleep(600)\n"
        "sys.stdout.write((base / 'roots').read_text())\n"
    )
    gh.chmod(0o755)
    temp = tmp_path / "runner"
    temp.mkdir(exist_ok=True)
    env = dict(
        os.environ,
        PATH=str(fakebin) + os.pathsep + os.environ["PATH"],
        RUNNER_TEMP=str(temp),
        TRUSTED_ROOT_PAUSE="0",
    )
    if timeout is not None:
        env["TRUSTED_ROOT_TIMEOUT"] = timeout
    # The test's own bound is far above the script's: a hang here is a failure.
    result = subprocess.run(
        [bash, str(FETCH)], env=env, capture_output=True, text=True, check=False, timeout=90
    )
    return result, temp


def attempts(tmp_path: Path) -> int:
    count = tmp_path / "count"
    return int(count.read_text()) if count.exists() else 0


def test_fetch_writes_bound_read_only_pair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result, temp = fetch(tmp_path, ["ok"])
    assert result.returncode == 0, result.stderr
    assert attempts(tmp_path) == 1
    assert (temp / "trusted_root.jsonl").read_text() == ROOTS
    assert json.loads((temp / "trusted_root.json").read_text()) == PUBLIC
    for name in ("trusted_root.jsonl", "trusted_root.json"):
        assert not stat.S_IMODE((temp / name).stat().st_mode) & 0o222
    assert sorted(path.name for path in temp.iterdir()) == [
        "trusted_root.json",
        "trusted_root.jsonl",
    ]
    monkeypatch.setenv("RUNNER_TEMP", str(temp))
    assert attestation.trusted_roots() == attestation.TrustedRoots(
        temp / "trusted_root.jsonl", temp / "trusted_root.json"
    )


@pytest.mark.parametrize("failures", [1, 2])
def test_fetch_retries_a_reset_at_most_three_times(tmp_path: Path, failures: int) -> None:
    result, temp = fetch(tmp_path, ["fail"] * failures + ["ok"])
    assert result.returncode == 0, result.stderr
    assert attempts(tmp_path) == failures + 1
    assert (temp / "trusted_root.jsonl").read_text() == ROOTS


def test_fetch_gives_up_after_three_attempts_and_leaves_nothing(tmp_path: Path) -> None:
    result, temp = fetch(tmp_path, ["fail", "fail", "fail", "ok"])
    assert result.returncode != 0
    assert attempts(tmp_path) == 3
    assert "unavailable after 3 attempts" in result.stderr
    assert list(temp.iterdir()) == []


# macOS runners' /bin/bash is 3.2; Git Bash and Linux run a current bash.
SHELLS = ["bash"] + (["/bin/bash"] if Path("/bin/bash").exists() else [])


@pytest.mark.parametrize("bash", SHELLS)
def test_a_stalled_fetch_is_killed_and_retried(tmp_path: Path, bash: str) -> None:
    started = time.monotonic()
    result, temp = fetch(tmp_path, ["hang", "ok"], timeout="1", bash=bash)
    assert result.returncode == 0, result.stderr
    assert attempts(tmp_path) == 2
    assert "attempt 1 timed out after 1s" in result.stderr
    assert (temp / "trusted_root.jsonl").read_text() == ROOTS
    assert time.monotonic() - started < 30
    stalled = int((tmp_path / "hung").read_text())
    with pytest.raises(ProcessLookupError):  # killed and reaped, not left running
        os.kill(stalled, 0)


@pytest.mark.parametrize("bash", SHELLS)
def test_three_stalled_fetches_fail_closed_within_the_bound(tmp_path: Path, bash: str) -> None:
    started = time.monotonic()
    result, temp = fetch(tmp_path, ["hang", "hang", "hang", "ok"], timeout="1", bash=bash)
    assert result.returncode != 0
    assert attempts(tmp_path) == 3
    assert result.stderr.count("timed out after 1s") == 3
    assert "unavailable after 3 attempts" in result.stderr
    assert list(temp.iterdir()) == []
    # Three bounded attempts, not the 600 s each stub would otherwise hang.
    assert time.monotonic() - started < 45


@pytest.mark.parametrize("value", ["0", "-1", "abc", "10000", " 5"])
def test_fetch_refuses_an_unbounded_or_malformed_timeout(tmp_path: Path, value: str) -> None:
    result, temp = fetch(tmp_path, ["ok"], timeout=value)
    assert result.returncode != 0
    assert attempts(tmp_path) == 0
    assert list(temp.iterdir()) == []


@pytest.mark.parametrize(
    "output",
    [
        "bad",
        "[]",
        '{"mediaType":"application/json"}',
        json.dumps(GITHUB),
        json.dumps(PUBLIC) + "\n" + json.dumps(PUBLIC),
        # The public-good shape under another media type, beside a valid root.
        json.dumps(PUBLIC | {"mediaType": "application/json"}) + "\n" + json.dumps(GITHUB),
    ],
)
def test_fetch_refuses_malformed_or_ambiguous_roots_without_retry(
    tmp_path: Path, output: str
) -> None:
    result, temp = fetch(tmp_path, ["ok", "ok", "ok"], output + "\n")
    assert result.returncode != 0
    assert attempts(tmp_path) == 1
    assert list(temp.iterdir()) == []


def test_fetch_runs_once_per_job(tmp_path: Path) -> None:
    result, temp = fetch(tmp_path, ["ok", "ok"])
    assert result.returncode == 0, result.stderr
    again, _ = fetch(tmp_path, ["ok", "ok"])
    assert again.returncode != 0
    assert "once per job" in again.stderr
    assert attempts(tmp_path) == 1


def test_gate_and_promote_jobs_fetch_before_verifying() -> None:
    import yaml

    guard = Path(__file__).resolve().parents[2]
    workflows = guard / "github/workflows"
    if not workflows.is_dir():  # the public repository's layout
        workflows = guard.parents[1] / ".github/workflows"
    fetch_step = "bash deploy/guard/github/fetch-trusted-root.sh"
    # Every step that runs a gh or cosign verification (directly or through the asset
    # script); M1/M2 mainnet admission reads observations only.
    verifiers = (
        "verify-release-assets.sh",
        "-m guard_harness.gate_state",
        "-m guard_harness.gate_publish",
        "-m guard_harness.staging_publish",
        "-m guard_harness.staged_state",
        "-m guard_harness.promotion ",
        "-m guard_harness.promotion_smoke",
        "-m guard_harness.mainnet_evidence --row M3",
        "-m guard_harness.testnet_run",
        "-m guard_harness.testnet_recovery",
        "-m guard_harness.native_release",
        "-m guard_harness.docker_run",
        "-m guard_harness.homebrew_stage",
    )
    checked = 0
    for name in ("verify.yml", "install-matrix.yml", "journey.yml", "promote.yml"):
        document: Any = yaml.safe_load((workflows / name).read_text())
        for job_name, job in document["jobs"].items():
            steps = job.get("steps") or []
            runs = [str(step.get("run", "")) + " " for step in steps]
            fetches = [i for i, run in enumerate(runs) if fetch_step in run]
            verifying = [i for i, run in enumerate(runs) if any(v in run for v in verifiers)]
            if not verifying:
                continue
            checked += 1
            assert len(fetches) == 1, (name, job_name)
            assert fetches[0] < min(verifying), (name, job_name)
            step = steps[fetches[0]]
            assert step.get("shell") == "bash" and "if" not in step
            assert "env" not in step  # gh needs no credential for the trust root
            assert "continue-on-error" not in step
    assert checked >= 15


def ci_windows_step() -> Any:
    import yaml

    guard = Path(__file__).resolve().parents[2]
    workflows = guard / "github/workflows"
    if not workflows.is_dir():  # the public repository's layout
        workflows = guard.parents[1] / ".github/workflows"
    job = yaml.safe_load((workflows / "ci.yml").read_text())["jobs"]["windows-main"]
    assert str(job["runs-on"]).startswith("windows-")
    (step,) = [s for s in job["steps"] if "fetch-trusted-root.sh" in str(s.get("run", ""))]
    return step


def test_public_ci_proves_the_fetch_on_windows_git_bash_before_any_promote() -> None:
    step = ci_windows_step()
    assert step["shell"] == "bash" and "env" not in step
    assert "[A-Za-z]:\\\\*" in step["run"]  # a drive-letter RUNNER_TEMP, as on hosted Windows
    assert "trusted_roots()" in step["run"] and "assert roots is not None" in step["run"]


def test_the_windows_ci_step_admits_the_pair_and_refuses_a_second_fetch(tmp_path: Path) -> None:
    # The step's body, minus its drive-letter guard, against the fake gh and this Python.
    fetch(tmp_path, ["ok"])
    (tmp_path / "count").unlink()
    for name in ("trusted_root.jsonl", "trusted_root.json"):
        (tmp_path / "runner" / name).unlink()
    shim = tmp_path / "bin" / "python"
    shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    shim.chmod(0o755)
    body = "\n".join(
        line for line in ci_windows_step()["run"].splitlines() if not line.startswith("case ")
    )
    repository = Path(__file__).resolve().parents[4]
    result = subprocess.run(
        ["bash", "-c", body],
        cwd=repository,
        env=dict(
            os.environ,
            PATH=str(tmp_path / "bin") + os.pathsep + os.environ["PATH"],
            RUNNER_TEMP=str(tmp_path / "runner"),
            TRUSTED_ROOT_PAUSE="0",
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    assert result.returncode == 0, result.stderr
    assert "TrustedRoots" in result.stdout
    assert attempts(tmp_path) == 1  # the second fetch is refused before calling gh
