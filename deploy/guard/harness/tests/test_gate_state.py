import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from test_staged_state import COMMIT, build_bytes

import guard_harness.attestation as attestation
from guard_harness import gate_state, staged_state
from guard_harness.attestation import AttestationError
from guard_harness.journey_evidence import JOURNEY_COVERAGE, PREDICATE_TYPE, authenticate_journeys
from guard_harness.release_state import GATE_JOURNEYS
from guard_harness.runner import RunResult
from guard_harness.state_verifier import VerifiedState


def test_gate_requires_complete_set_and_links_exact_staged_predecessor() -> None:
    raw = build_bytes("v1.0.0-rc.4")
    previous = staged_state.genesis(raw, commit=COMMIT, issued_at="2026-10-11T04:00:00Z")
    references = {
        row: "https://github.com/zunderlabs/zunder-guard/actions/runs/1" for row in GATE_JOURNEYS
    }
    state = gate_state.successor(
        previous, json.loads(raw), references, coverage=dict(JOURNEY_COVERAGE)
    )
    assert state["stage"] == "gated" and state["revision"] == 2
    assert state["previous"] is not None and state["evidence"] == references
    assert all(channel["status"] == "verified" for channel in state["channels"].values())
    del references["P8"]
    with pytest.raises(ValueError):
        gate_state.successor(previous, json.loads(raw), references, coverage=dict(JOURNEY_COVERAGE))


@pytest.mark.parametrize(
    "row,token", [("I3", "D1:curl-pipe"), ("I4", "D2:irm-iex"), ("I1", "D5:manual-archive")]
)
def test_channel_status_cannot_be_derived_from_install_row_alone(row: str, token: str) -> None:
    raw = build_bytes("v1.0.0-rc.4")
    previous = staged_state.genesis(raw, commit=COMMIT, issued_at="2026-10-11T04:00:00Z")
    references = {
        row: "https://github.com/zunderlabs/zunder-guard/actions/runs/1/attempts/1"
        for row in GATE_JOURNEYS
    }
    coverage = dict(JOURNEY_COVERAGE)
    coverage[row] = coverage[row] - {token}
    with pytest.raises(AttestationError, match="documented execution"):
        gate_state.successor(previous, json.loads(raw), references, coverage=coverage)


@pytest.mark.parametrize("missing,duplicate", [(False, False), (True, False), (False, True)])
def test_bundles_cannot_admit_missing_or_ambiguous_row(
    tmp_path: Path, missing: bool, duplicate: bool
) -> None:
    for row in GATE_JOURNEYS:
        directory = tmp_path / f"{row}-123-2"
        directory.mkdir()
        if not missing or row != "P8":
            (directory / "bundle.json").write_text(
                json.dumps({"dsseEnvelope": {}, "verificationMaterial": {}})
            )
        if duplicate and row == "P8":
            (directory / "other.json").write_text(
                json.dumps({"dsseEnvelope": {"other": True}, "verificationMaterial": {}})
            )
    if missing or duplicate:
        with pytest.raises(AttestationError):
            gate_state.bundles(tmp_path, run_id="123", attempt="2")
    else:
        assert set(gate_state.bundles(tmp_path, run_id="123", attempt="2")) == GATE_JOURNEYS
        # A later gate attempt admits the same rows, naming the attempt they came from.
        later = gate_state.bundles(tmp_path, run_id="123", attempt="3")
        assert {bundle.reference for bundle in later.values()} == {
            "https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/2"
        }
    with pytest.raises(AttestationError, match="another workflow run"):
        gate_state.bundles(tmp_path, run_id="124", attempt="2")
    with pytest.raises(AttestationError, match="at or before this attempt"):
        gate_state.bundles(tmp_path, run_id="123", attempt="1")


# Decision of 15 Oct 2026: each row's latest attempt within the gate's run. These tests
# drive the real bundle selection and the real `verify_predicate`; only the official
# `gh attestation verify` subprocess is faked, reporting the certificate invocation and
# predicate a fixture bundle carries.
RUN = "123"


def signed_bundle(row: str, *, signed_attempt: str, run_id: str = RUN) -> bytes:
    return json.dumps(
        {
            "dsseEnvelope": {},
            "verificationMaterial": {
                "fixture_uri": "https://github.com/zunderlabs/zunder-guard/actions/runs/"
                f"{run_id}/attempts/{signed_attempt}",
                "fixture_row": row,
            },
        }
    ).encode()


def evidence_tree(root: Path, attempts: dict[str, str]) -> Path:
    for row in GATE_JOURNEYS:
        directory = root / f"{row}-{RUN}-{attempts.get(row, '1')}"
        directory.mkdir(parents=True)
        (directory / "bundle.json").write_bytes(
            signed_bundle(row, signed_attempt=attempts.get(row, "1"))
        )
    return root


def install_gh(monkeypatch: pytest.MonkeyPatch, verified: list[tuple[str, str]]) -> None:
    def fake_run(argv: list[str], *, log: Path, timeout: int) -> RunResult:
        assert argv[:3] == ["gh", "attestation", "verify"]
        subject = Path(argv[3]).read_bytes()
        material = json.loads(Path(argv[argv.index("--bundle") + 1]).read_bytes())[
            "verificationMaterial"
        ]
        row = material["fixture_row"]
        verified.append((row, material["fixture_uri"]))
        predicate = {
            "schema": 1,
            "journey": row,
            "commit": COMMIT,
            "manifest_sha256": hashlib.sha256(subject).hexdigest(),
            "result": "passed",
            "tier": "guest" if row in {"I1", "I6", "M1"} else "e2e",
            "coverage": sorted(JOURNEY_COVERAGE[row]),
        }
        result = {
            "verificationResult": {
                "statement": {"predicateType": PREDICATE_TYPE, "predicate": predicate},
                "signature": {"certificate": {"runInvocationURI": material["fixture_uri"]}},
            }
        }
        return RunResult(0, json.dumps([result]), log)

    monkeypatch.setattr(attestation, "run", fake_run)


def gate(tmp_path: Path, evidence: Path, *, attempt: str) -> dict[str, frozenset[str]]:
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b"immutable build manifest\n")
    coverage: dict[str, frozenset[str]] = {}
    authenticate_journeys(
        manifest,
        gate_state.bundles(evidence, run_id=RUN, attempt=attempt),
        commit=COMMIT,
        tag="v1.0.0",
        logs=tmp_path / "logs",
        expected_run_id=RUN,
        latest_run_attempt=attempt,
        coverage_out=coverage,
    )
    return coverage


# The rc.17 shape (run 38656407765): journeys in attempt 1 (P2 rerun in 2), I3/I4/I7 in
# attempt 2, I1/I2/I5/I6 in attempt 3, gate in attempt 3.
MIXED = {"P2": "2", "I3": "2", "I4": "2", "I7": "2", "I1": "3", "I2": "3", "I5": "3", "I6": "3"}
BASE = f"https://github.com/zunderlabs/zunder-guard/actions/runs/{RUN}/attempts/"


def test_rows_from_different_attempts_admit_when_each_signature_matches_its_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = evidence_tree(tmp_path / "art", MIXED)
    verified: list[tuple[str, str]] = []
    install_gh(monkeypatch, verified)
    assert set(gate(tmp_path, evidence, attempt="3")) == GATE_JOURNEYS
    assert dict(verified) == {row: BASE + MIXED.get(row, "1") for row in GATE_JOURNEYS}
    assert len(verified) == len(GATE_JOURNEYS)
    references = gate_state.bundles(evidence, run_id=RUN, attempt="3")
    assert {row: bundle.reference for row, bundle in references.items()} == dict(verified)


def test_lower_attempt_is_ignored_even_when_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = evidence_tree(tmp_path / "art", MIXED)
    # P2's superseded attempt 1 is a complete, validly signed bundle; it is never used.
    superseded = evidence / f"P2-{RUN}-1"
    superseded.mkdir()
    (superseded / "bundle.json").write_bytes(signed_bundle("P2", signed_attempt="1"))
    verified: list[tuple[str, str]] = []
    install_gh(monkeypatch, verified)
    gate(tmp_path, evidence, attempt="3")
    assert [uri for row, uri in verified if row == "P2"] == [BASE + "2"]
    # A broken superseded attempt cannot block the gate either.
    (superseded / "other.json").write_bytes(signed_bundle("P2", signed_attempt="9"))
    gate(tmp_path, evidence, attempt="3")


def test_lower_attempt_is_never_a_fallback_for_a_broken_latest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = evidence_tree(tmp_path / "art", MIXED)
    superseded = evidence / f"P2-{RUN}-1"
    superseded.mkdir()
    (superseded / "bundle.json").write_bytes(signed_bundle("P2", signed_attempt="1"))
    (evidence / f"P2-{RUN}-2" / "bundle.json").unlink()
    install_gh(monkeypatch, [])
    with pytest.raises(AttestationError, match="P2 requires exactly one"):
        gate(tmp_path, evidence, attempt="3")


@pytest.mark.parametrize("signed", ["1", "3"])
def test_signed_attempt_differing_from_its_directory_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signed: str
) -> None:
    evidence = evidence_tree(tmp_path / "art", MIXED)
    (evidence / f"P2-{RUN}-2" / "bundle.json").write_bytes(
        signed_bundle("P2", signed_attempt=signed)
    )
    install_gh(monkeypatch, [])
    with pytest.raises(AttestationError, match="differs from expected invocation"):
        gate(tmp_path, evidence, attempt="3")


def test_signature_from_another_run_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = evidence_tree(tmp_path / "art", MIXED)
    (evidence / f"P2-{RUN}-2" / "bundle.json").write_bytes(
        signed_bundle("P2", signed_attempt="2", run_id="124")
    )
    install_gh(monkeypatch, [])
    with pytest.raises(AttestationError, match="differs from expected invocation"):
        gate(tmp_path, evidence, attempt="3")


def test_artifact_of_another_run_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = evidence_tree(tmp_path / "art", MIXED)
    other = evidence / "P2-124-3"
    other.mkdir()
    (other / "bundle.json").write_bytes(signed_bundle("P2", signed_attempt="3", run_id="124"))
    install_gh(monkeypatch, [])
    with pytest.raises(AttestationError, match="another workflow run"):
        gate(tmp_path, evidence, attempt="3")


def test_attempt_after_the_gate_is_never_admitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = evidence_tree(tmp_path / "art", MIXED)
    install_gh(monkeypatch, [])
    # I1's only attempt (3) follows a gate running in attempt 2.
    with pytest.raises(AttestationError, match="I1 has no artifact"):
        gate(tmp_path, evidence, attempt="2")
    later = evidence / f"P2-{RUN}-4"
    later.mkdir()
    (later / "bundle.json").write_bytes(signed_bundle("P2", signed_attempt="4"))
    references = gate_state.bundles(evidence, run_id=RUN, attempt="3")
    assert references["P2"].reference == BASE + "2"


def test_reference_attempt_after_the_gate_is_refused_before_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = evidence_tree(tmp_path / "art", MIXED)
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b"immutable build manifest\n")
    journeys = gate_state.bundles(evidence, run_id=RUN, attempt="3")
    monkeypatch.setattr(attestation, "run", lambda *args, **kwargs: pytest.fail())
    with pytest.raises(AttestationError, match="different requested run or attempt"):
        authenticate_journeys(
            manifest,
            journeys,
            commit=COMMIT,
            tag="v1.0.0",
            logs=tmp_path / "logs",
            expected_run_id=RUN,
            latest_run_attempt="2",
        )


def chain(evidence: Path, attempt: str, marker: str) -> None:
    directory = evidence / f"state-chain-{RUN}-{attempt}"
    directory.mkdir(parents=True)
    (directory / "staged.predicate.json").write_text(marker)
    (directory / "staged.sigstore.json").write_text(marker + "-bundle")


def test_staged_chain_is_the_latest_attempt_at_or_before_the_gate(tmp_path: Path) -> None:
    evidence, work = tmp_path / "art", tmp_path / "work"
    work.mkdir()
    (work / "staged.predicate.json").write_text("fresh genesis, not the signed staged state")
    chain(evidence, "1", "first")
    chain(evidence, "2", "second")
    chain(evidence, "4", "after-the-gate")
    assert gate_state.staged_chain(evidence, work, run_id=RUN, attempt="3") == "2"
    assert (work / "staged.predicate.json").read_text() == "second"
    assert (work / "staged.sigstore.json").read_text() == "second-bundle"


def test_staged_chain_refuses_links_and_missing_files(tmp_path: Path) -> None:
    evidence, work = tmp_path / "art", tmp_path / "work"
    work.mkdir()
    chain(evidence, "1", "first")
    source = evidence / f"state-chain-{RUN}-1" / "staged.sigstore.json"
    source.unlink()
    with pytest.raises(AttestationError, match="regular file"):
        gate_state.staged_chain(evidence, work, run_id=RUN, attempt="1")
    source.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(AttestationError, match="regular file"):
        gate_state.staged_chain(evidence, work, run_id=RUN, attempt="1")


def test_execute_binds_staged_and_rows_to_their_own_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence, work = tmp_path / "art", tmp_path / "work"
    (work / "assets").mkdir(parents=True)
    (work / "assets/release-manifest.json").write_bytes(build_bytes("v1.0.0-rc.4"))
    chain(evidence, "1", "staged")
    evidence_tree(evidence, MIXED)
    calls: dict[str, Any] = {}

    def state(*args: Any, **kwargs: Any) -> VerifiedState:
        calls["state"] = (kwargs["expected_run_id"], kwargs["expected_run_attempt"])
        return VerifiedState({"stage": "staged"}, "a" * 64)

    def journeys(manifest: Path, bundles: Any, **kwargs: Any) -> frozenset[str]:
        calls["journeys"] = (kwargs["expected_run_id"], kwargs["latest_run_attempt"])
        calls["references"] = {row: bundle.reference for row, bundle in bundles.items()}
        kwargs["coverage_out"].update(JOURNEY_COVERAGE)
        return GATE_JOURNEYS

    def successor(previous: Any, build: Any, references: dict[str, str], **kwargs: Any) -> Any:
        assert references == calls["references"]
        return {"stage": "gated"}

    monkeypatch.setattr(gate_state, "authenticate_state", state)
    monkeypatch.setattr(gate_state, "authenticate_journeys", journeys)
    monkeypatch.setattr(gate_state, "successor", successor)
    gate_state.execute(
        work=work, evidence=evidence, tag="v1.0.0-rc.4", commit=COMMIT, run_id=RUN, attempt="3"
    )
    assert calls["state"] == (RUN, "1") and calls["journeys"] == (RUN, "3")
    assert calls["references"] == {row: BASE + MIXED.get(row, "1") for row in GATE_JOURNEYS}
    assert (work / "gated.predicate.json").read_bytes() == b'{"stage":"gated"}'
