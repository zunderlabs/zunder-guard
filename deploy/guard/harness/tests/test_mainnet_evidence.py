import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

import guard_harness.mainnet_evidence as matrix
from guard_harness.attestation import AttestationError, VerifiedPredicate
from guard_harness.journey_evidence import MAINNET_COVERAGE
from guard_harness.native_release import Release


@pytest.fixture
def release(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Release:
    monkeypatch.setattr(Release, "asset", lambda self, name: b"authenticated manifest")
    monkeypatch.setattr(Release, "binary", lambda self, target: b"authenticated binary")
    result = Release("v1.0.0", "a" * 40, tmp_path)
    (tmp_path / "release-manifest.json").write_bytes(b"authenticated manifest")
    return result


def fixtures(root: Path, release: Release, row: str) -> None:
    directory = root / row
    directory.mkdir()
    for name in MAINNET_COVERAGE[row]:
        route = name if row == "M1" else matrix.M2_ROUTES[name]
        value: dict[str, Any] = dict(
            schema=1,
            journey=row,
            route=route,
            tag=release.tag,
            commit=release.commit,
            harness_commit=release.commit,
            diagnostic=False,
            manifest_sha256=hashlib.sha256(release.asset("release-manifest.json")).hexdigest(),
            binary_sha256=hashlib.sha256(release.binary(matrix.TARGETS[route])).hexdigest(),
            result="passed",
            tier="e2e",
            exchange_requests=0,
            coverage=sorted(matrix.M1_STAGES) if row == "M1" else [name],
        )
        if row == "M1":
            body = b"unapproved wallet is not an API wallet of account"
            (directory / f"{name}.log").write_bytes(body)
            value.update(
                mode="mainnet",
                wallet_role="unapproved",
                config_written=False,
                credential_written=False,
                service_enabled=False,
                service_started=False,
                exit_code=1,
                expected_refusal="is not an API wallet of",
                log_sha256=hashlib.sha256(body).hexdigest(),
            )
        else:
            if name == "homebrew-services":
                value.update(mechanism="supervisor-mode", observed_mode="paper")
            body = matrix.M2_LITERALS[name].encode()
            (directory / f"{name}.log").write_bytes(body)
            value.update(
                exit_code=1,
                expected_refusal=matrix.M2_LITERALS[name],
                log_sha256=hashlib.sha256(body).hexdigest(),
            )
        (directory / f"{name}.json").write_text(json.dumps(value))


@pytest.mark.parametrize("row", ["M1", "M2"])
def test_complete_exact_identity_coverage(release: Release, tmp_path: Path, row: str) -> None:
    fixtures(tmp_path, release, row)
    assert set(matrix.native_row(row, release, tmp_path)["coverage"]) == MAINNET_COVERAGE[row]


@pytest.mark.parametrize("row", ["M1", "M2"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("commit", "b" * 40),
        ("harness_commit", "b" * 40),
        ("diagnostic", True),
        ("diagnostic", 0),
        ("binary_sha256", "b" * 64),
        ("manifest_sha256", "b" * 64),
        ("result", "skipped"),
        ("exchange_requests", 1),
        ("exchange_requests", False),
        ("coverage", []),
    ],
)
def test_fail_closed_identity_partial_or_exchange(
    release: Release, tmp_path: Path, row: str, field: str, value: Any
) -> None:
    fixtures(tmp_path, release, row)
    path = next((tmp_path / row).glob("*.json"))
    body = json.loads(path.read_bytes())
    body[field] = value
    path.write_text(json.dumps(body))
    with pytest.raises(matrix.MatrixError):
        matrix.native_row(row, release, tmp_path)


@pytest.mark.parametrize("mutation", ["missing-route", "wrong-role", "wrong-mode", "symlink"])
def test_m1_requires_every_real_protected_route(
    release: Release, tmp_path: Path, mutation: str
) -> None:
    fixtures(tmp_path, release, "M1")
    path = tmp_path / "M1/windows-scm.json"
    body = json.loads(path.read_bytes())
    if mutation == "missing-route":
        path.unlink()
    elif mutation == "symlink":
        moved = path.with_suffix(".other")
        path.rename(moved)
        path.symlink_to(moved)
    else:
        body["wallet_role" if mutation == "wrong-role" else "mode"] = "approved"
        path.write_text(json.dumps(body))
    with pytest.raises(matrix.MatrixError):
        matrix.native_row("M1", release, tmp_path)


@pytest.mark.parametrize(
    "mutation", ["generic-error", "changed-log", "success-exit", "missing-case"]
)
def test_m2_does_not_credit_generic_or_missing_refusal(
    release: Release, tmp_path: Path, mutation: str
) -> None:
    fixtures(tmp_path, release, "M2")
    path = tmp_path / "M2/key-file-option.json"
    body = json.loads(path.read_bytes())
    log = path.with_suffix(".log")
    if mutation == "missing-case":
        path.unlink()
    elif mutation == "changed-log":
        log.write_bytes(b"tampered specific literal refusal")
    elif mutation == "generic-error":
        log.write_bytes(b"CLI option not understood")
        body["log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
        path.write_text(json.dumps(body))
    else:
        body["exit_code"] = 0
        path.write_text(json.dumps(body))
    with pytest.raises(matrix.MatrixError):
        matrix.native_row("M2", release, tmp_path)


RUN = "77"
# Each producer's latest attempt as the M3 step selects it; they differ after reruns.
SELECTED = {
    "signing-linux": "1",
    "signing-macos": "2",
    "signing-windows": "1",
    "T1": "3",
    "T2": "1",
}


def m3_verifier(
    release: Release,
    calls: list[str],
    *,
    mutation: str = "none",
    signed: dict[str, tuple[str, str]] | None = None,
) -> Any:
    """Stub of `verify_predicate` that honours the run binding like the real verifier.

    Each bundle is signed in `signed[name]` (default: this run at its selected attempt).
    An expected run or attempt that differs raises, as the real certificate check does.
    """
    digest = hashlib.sha256(release.asset("release-manifest.json")).hexdigest()

    def verify(subject: Path, bundle: Path, **kwargs: Any) -> VerifiedPredicate:
        calls.append(bundle.name)
        name = bundle.name.split(".")[0]
        run_id, attempt = (signed or {}).get(name, (RUN, SELECTED[name]))
        assert kwargs.get("latest_run_attempt") is None
        if kwargs.get("expected_run_id") is not None and (
            (kwargs["expected_run_id"], kwargs.get("expected_run_attempt")) != (run_id, attempt)
        ):
            raise AttestationError("authenticated workflow run or attempt differs")
        if "signing" in bundle.name:
            platform = name.split("-")[1]
            value = dict(
                schema=1,
                commit=release.commit,
                manifest_sha256=digest,
                result="passed",
                platform=platform,
                checks=sorted(matrix.SIGNING_CHECKS[platform]),
                networks=["mainnet", "testnet"],
            )
            if mutation == "missing-wrapper":
                value["checks"] = ["hl-protocol.sdk-vectors"]
            if mutation == "wrong-network":
                value["networks"] = ["testnet"]
        else:
            value = dict(
                schema=1,
                journey="T1" if mutation == "wrong-testnet-row" else name,
                commit=release.commit,
                manifest_sha256=digest,
                result="passed",
                tier="e2e",
                coverage=["signed-release", "protected-entry", "owned-cleanup", "all-dex-flat"],
            )
        return VerifiedPredicate(
            value,
            kwargs["workflow"],
            release.commit,
            f"https://github.com/zunderlabs/zunder-guard/actions/runs/{run_id}/attempts/{attempt}",
            run_id,
            attempt,
        )

    return verify


@pytest.mark.parametrize(
    "mutation", ["none", "missing-wrapper", "wrong-network", "wrong-testnet-row"]
)
def test_m3_requires_authenticated_vectors_and_both_live_journeys(
    release: Release, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(matrix, "verify_predicate", m3_verifier(release, calls, mutation=mutation))
    if mutation == "none":
        row = matrix.signing_row(release, tmp_path, tmp_path, run_id=RUN, attempts=SELECTED)
        assert row["journey"] == "M3"
        assert calls == [
            "signing-linux.sigstore.json",
            "signing-macos.sigstore.json",
            "signing-windows.sigstore.json",
            "T1.sigstore.json",
            "T2.sigstore.json",
        ]
    else:
        with pytest.raises(ValueError):
            matrix.signing_row(release, tmp_path, tmp_path, run_id=RUN, attempts=SELECTED)


@pytest.mark.parametrize("producer", matrix.M3_PRODUCERS)
@pytest.mark.parametrize("signer", ["another-run", "earlier-attempt", "later-attempt"])
def test_m3_binds_every_bundle_to_this_run_and_its_selected_attempt(
    release: Release, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, producer: str, signer: str
) -> None:
    selected = int(SELECTED[producer])
    signed = {
        "another-run": ("78", SELECTED[producer]),
        "earlier-attempt": (RUN, str(selected - 1)),
        "later-attempt": (RUN, str(selected + 1)),
    }[signer]
    if signed[1] == "0":
        signed = (RUN, "4")
    calls: list[str] = []
    verify = m3_verifier(release, calls, signed={producer: signed})
    monkeypatch.setattr(matrix, "verify_predicate", verify)
    with pytest.raises(AttestationError, match="run or attempt differs"):
        matrix.signing_row(release, tmp_path, tmp_path, run_id=RUN, attempts=SELECTED)
    assert calls[-1] == producer + ".sigstore.json"


@pytest.mark.parametrize(
    "run_id,attempts",
    [
        (RUN, {k: v for k, v in SELECTED.items() if k != "T2"}),
        (RUN, {**SELECTED, "T3": "1"}),
        (RUN, {**SELECTED, "T1": "0"}),
        (RUN, {**SELECTED, "T1": "01"}),
        ("", SELECTED),
        ("x", SELECTED),
    ],
)
def test_m3_refuses_incomplete_or_malformed_attempts_before_verifying(
    release: Release,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    run_id: str,
    attempts: dict[str, str],
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(matrix, "verify_predicate", m3_verifier(release, calls))
    with pytest.raises(ValueError):
        matrix.signing_row(release, tmp_path, tmp_path, run_id=run_id, attempts=attempts)
    assert calls == []


def m3_step() -> dict[str, Any]:
    guard = Path(__file__).resolve().parents[2]
    workflow = guard / "github/workflows/journey.yml"
    if not workflow.exists():
        workflow = guard.parents[1] / ".github/workflows/journey.yml"
    steps = yaml.safe_load(workflow.read_text())["jobs"]["signing-gate"]["steps"]
    step: dict[str, Any] = next(s for s in steps if "PY_M3" in s.get("run", ""))
    return step


def test_m3_step_passes_each_selected_attempt_and_this_run(tmp_path: Path) -> None:
    """Run the workflow's own selection script on a rerun's artifact layout."""
    script = m3_step()["run"]
    assert (
        '--run-id "$GITHUB_RUN_ID" --attempts "$RUNNER_TEMP/M3/attempts.json"'
        in script.splitlines()[-1]
    )
    body = script.split("<<'PY_M3'\n", 1)[1].split("\nPY_M3\n", 1)[0]
    root = tmp_path / "M3"
    # One download of every artifact of the run, one directory each (rc.20).
    layout = {
        "attempts": [
            "signing-linux-77-1",
            "signing-macos-77-1",
            "signing-macos-77-2",
            "signing-windows-77-1",
            "signing-windows-77-4",
            "signing-subjects-77-1",
            "T1-77-1",
            "T1-77-3",
            "T1-early-failure-77-1",
            "T2-77-1",
            "P1-77-1",
        ],
    }
    for parent, names in layout.items():
        for name in names:
            directory = root / parent / name
            directory.mkdir(parents=True)
            if name.startswith("signing-"):
                platform = name.split("-")[1]
                bundle = directory / f"signing-{platform}.sigstore.json"
                bundle.write_text(json.dumps({"attempt": name}))
            else:
                bundle = directory / "evidence.sigstore.json"
                envelope = {"dsseEnvelope": name, "verificationMaterial": {}}
                bundle.write_text(json.dumps(envelope))
    src = Path(matrix.__file__).resolve().parents[1]
    subprocess.run(
        [sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {str(src)!r})\n" + body],
        env={"RUNNER_TEMP": str(tmp_path), "GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": "3"},
        check=True,
    )
    # signing-windows-77-4 follows this attempt and is never admitted.
    assert json.loads((root / "attempts.json").read_text()) == SELECTED
    linux = json.loads((root / "evidence/signing-linux.sigstore.json").read_text())
    assert linux == {"attempt": "signing-linux-77-1"}
    assert json.loads((root / "evidence/T1.sigstore.json").read_text())["dsseEnvelope"] == (
        "T1-77-3"
    )


@pytest.mark.parametrize(
    "extra",
    [
        [],
        ["--run-id", RUN],
        ["--attempts", "attempts.json"],
    ],
)
def test_m3_cli_requires_run_and_attempts(
    release: Release, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: list[str]
) -> None:
    argv = ["mainnet_evidence", "--row", "M3", "--tag", release.tag, "--commit", release.commit]
    argv += ["--assets", str(tmp_path), "--evidence", str(tmp_path), "--output", str(tmp_path)]
    monkeypatch.setattr(sys, "argv", argv + extra)
    with pytest.raises(SystemExit):
        matrix.main()


def test_m1_cli_refuses_m3_inputs(
    release: Release, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = ["mainnet_evidence", "--row", "M1", "--tag", release.tag, "--commit", release.commit]
    argv += ["--assets", str(tmp_path), "--evidence", str(tmp_path), "--output", str(tmp_path)]
    monkeypatch.setattr(sys, "argv", argv + ["--run-id", RUN])
    with pytest.raises(SystemExit):
        matrix.main()


def test_m3_cli_passes_the_attempts_file(
    release: Release, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "attempts.json").write_text(json.dumps(SELECTED))
    calls: list[str] = []
    monkeypatch.setattr(matrix, "verify_predicate", m3_verifier(release, calls))
    argv = ["mainnet_evidence", "--row", "M3", "--tag", release.tag, "--commit", release.commit]
    argv += ["--assets", str(tmp_path), "--evidence", str(tmp_path), "--output", str(tmp_path)]
    argv += ["--run-id", RUN, "--attempts", str(tmp_path / "attempts.json")]
    monkeypatch.setattr(sys, "argv", argv)
    matrix.main()
    assert json.loads((tmp_path / "M3.predicate.json").read_text())["journey"] == "M3"
    assert len(calls) == 5
