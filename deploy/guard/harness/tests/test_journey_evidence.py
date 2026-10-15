import hashlib
from pathlib import Path
from typing import Any

import pytest

import guard_harness.journey_evidence as evidence
from guard_harness.attestation import AttestationError, VerifiedPredicate
from guard_harness.lifecycle_coverage import LIFECYCLE_COVERAGE
from guard_harness.release_state import GATE_JOURNEYS
from guard_harness.state_verifier import VerifiedState


@pytest.fixture
def inputs(tmp_path: Path) -> tuple[Path, dict[str, evidence.JourneyBundle]]:
    subject = tmp_path / "manifest.json"
    subject.write_bytes(b"immutable build manifest\n")
    bundles = {}
    for journey in GATE_JOURNEYS:
        bundle = tmp_path / f"{journey}.json"
        bundle.write_text(journey)
        bundles[journey] = evidence.JourneyBundle(
            bundle, "https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/2"
        )
    return subject, bundles


def install_verifier(
    monkeypatch: pytest.MonkeyPatch,
    original: Path,
    *,
    changes: dict[str, Any] | None = None,
    bad_row: str = "M1",
    replace_original: bool = False,
    attempts: dict[str, str] | None = None,
) -> list[str]:
    expected = original.read_bytes()
    calls: list[str] = []

    def verify(subject: Path, bundle: Path, **kwargs: Any) -> VerifiedPredicate:
        assert subject.read_bytes() == expected
        row = bundle.read_text()
        assert subject != original and kwargs["predicate_type"] == evidence.PREDICATE_TYPE
        assert kwargs["commit"] == "b" * 40 and kwargs["tag"] == "v1.0.0"
        # Each row's signature is bound to exactly the attempt its own reference names.
        assert kwargs["expected_run_id"] == "123"
        assert kwargs["expected_run_attempt"] == (attempts or {}).get(row, "2")
        workflow = kwargs["workflow"]
        if row.startswith("I") or row in {"M1", "M2"}:
            assert workflow == "install-matrix.yml"
        else:
            assert workflow == "journey.yml"
        calls.append(row)
        if replace_original:
            original.write_bytes(b"download replaced during verification")
        predicate = {
            "schema": 1,
            "journey": row,
            "commit": "b" * 40,
            "manifest_sha256": hashlib.sha256(expected).hexdigest(),
            "result": "passed",
            "tier": "guest" if row in {"I1", "I6", "M1"} else "e2e",
            "coverage": sorted(evidence.JOURNEY_COVERAGE[row]),
        }
        if row == bad_row and changes:
            predicate.update(changes)
        return VerifiedPredicate(predicate, workflow, "b" * 40)

    monkeypatch.setattr(evidence, "verify_predicate", verify)
    return calls


def authenticate(inputs: tuple[Path, dict[str, evidence.JourneyBundle]]) -> frozenset[str]:
    return evidence.authenticate_journeys(
        inputs[0], inputs[1], commit="b" * 40, tag="v1.0.0", logs=inputs[0].parent / "logs"
    )


def test_every_row_verified_with_fixed_signer_and_captured_subject(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = install_verifier(monkeypatch, inputs[0], replace_original=True)
    assert authenticate(inputs) == GATE_JOURNEYS
    assert set(calls) == GATE_JOURNEYS and len(calls) == len(GATE_JOURNEYS)


@pytest.mark.parametrize(
    "missing",
    ["staging-approve", "testnet-owner-approval", "guard-builder-wire", "actual-builder-fee"],
)
def test_p8_requires_each_observed_approval_and_fee(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]],
    monkeypatch: pytest.MonkeyPatch,
    missing: str,
) -> None:
    coverage = {
        "signed-release",
        "protected-entry",
        "owned-cleanup",
        "all-dex-flat",
        "staging-approve",
        "testnet-owner-approval",
        "guard-builder-wire",
        "actual-builder-fee",
    }
    install_verifier(
        monkeypatch, inputs[0], bad_row="P8", changes={"coverage": sorted(coverage - {missing})}
    )
    with pytest.raises(AttestationError, match="builder approval coverage"):
        authenticate(inputs)


@pytest.mark.parametrize("row", sorted(GATE_JOURNEYS))
def test_no_missing_row_can_pass(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]], row: str
) -> None:
    del inputs[1][row]
    with pytest.raises(AttestationError, match="complete automated"):
        authenticate(inputs)


@pytest.mark.parametrize(
    "changes",
    [
        {"schema": True},
        {"schema": 2},
        {"journey": "M4"},
        {"commit": "a" * 40},
        {"manifest_sha256": "a" * 64},
        {"result": "skipped"},
        {"result": "failed"},
        {"tier": "contract"},
        {"tier": []},
        {"coverage": []},
        {"coverage": "passed"},
        {"coverage": ["linux-systemd", "linux-systemd"]},
        {"untrusted": True},
    ],
)
def test_authenticated_signature_does_not_excuse_invalid_result(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]],
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, Any],
) -> None:
    install_verifier(monkeypatch, inputs[0], changes=changes)
    with pytest.raises(AttestationError):
        authenticate(inputs)


@pytest.mark.parametrize(
    "row,check", [(r, c) for r, checks in evidence.MAINNET_COVERAGE.items() for c in sorted(checks)]
)
def test_mainnet_aggregate_requires_every_route_case_and_signing_check(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]],
    monkeypatch: pytest.MonkeyPatch,
    row: str,
    check: str,
) -> None:
    install_verifier(
        monkeypatch,
        inputs[0],
        bad_row=row,
        changes={"coverage": sorted(evidence.MAINNET_COVERAGE[row] - {check})},
    )
    with pytest.raises(AttestationError, match="required check"):
        authenticate(inputs)


@pytest.mark.parametrize("row", sorted(LIFECYCLE_COVERAGE))
@pytest.mark.parametrize("mutation", ["omit", "add"])
def test_install_aggregate_requires_exact_measured_coverage(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]],
    monkeypatch: pytest.MonkeyPatch,
    row: str,
    mutation: str,
) -> None:
    coverage = set(LIFECYCLE_COVERAGE[row])
    if mutation == "omit":
        coverage.remove(sorted(coverage)[0])
    else:
        coverage.add("unmeasured-install-claim")
    install_verifier(monkeypatch, inputs[0], bad_row=row, changes={"coverage": sorted(coverage)})
    with pytest.raises(AttestationError, match="install coverage"):
        authenticate(inputs)


def test_crypto_failure_propagates_without_accepting_partial_set(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]], monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*args: Any, **kwargs: Any) -> VerifiedPredicate:
        raise AttestationError("untrusted signature")

    monkeypatch.setattr(evidence, "verify_predicate", refuse)
    with pytest.raises(AttestationError, match="untrusted signature"):
        authenticate(inputs)


@pytest.mark.parametrize(
    "reference",
    ["http://example.com/P1", "https://key@example.com/P1", "https://example.com/P1#old"],
)
def test_untrusted_reference_refused(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]], reference: str
) -> None:
    inputs[1]["P1"] = evidence.JourneyBundle(inputs[1]["P1"].bundle, reference)
    with pytest.raises(AttestationError, match="public HTTPS"):
        authenticate(inputs)


@pytest.mark.parametrize("gate_attempt", ["2", "3"])
@pytest.mark.parametrize("wrong_reference", [False, True])
@pytest.mark.parametrize("workflow", ["verify.yml", "promote.yml"])
def test_gate_checks_lifecycle_against_same_manifest_and_authenticated_references(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]],
    monkeypatch: pytest.MonkeyPatch,
    wrong_reference: bool,
    workflow: str,
    gate_attempt: str,
) -> None:
    expected = inputs[0].read_bytes()
    install_verifier(monkeypatch, inputs[0], replace_original=True)
    previous = VerifiedState(
        {"stage": "staged" if workflow == "verify.yml" else "gated"},
        hashlib.sha256(expected).hexdigest(),
    )

    def state(subject: Path, *args: Any, **kwargs: Any) -> VerifiedState:
        assert subject.read_bytes() == expected
        assert kwargs["previous"] is previous and kwargs["verified_journeys"] == GATE_JOURNEYS
        # The gated state is bound to the gate's own attempt, not to its rows' attempts.
        expected_run = ("123", gate_attempt) if workflow == "verify.yml" else (None, None)
        assert (kwargs["expected_run_id"], kwargs["expected_run_attempt"]) == expected_run
        refs = {row: bundle.reference for row, bundle in inputs[1].items()}
        if wrong_reference:
            refs["P1"] = "https://example.com/unverified-other-bundle"
        return VerifiedState(
            {"stage": "gated" if workflow == "verify.yml" else "promoted", "evidence": refs},
            previous.manifest_sha256,
        )

    monkeypatch.setattr(evidence, "authenticate_state", state)

    def gate() -> VerifiedState:
        return evidence.authenticate_gate(
            inputs[0],
            Path("served.json"),
            Path("state-bundle.json"),
            inputs[1],
            manifest_schema=Path("build-schema.json"),
            state_schema=Path("state-schema.json"),
            commit="b" * 40,
            tag="v1.0.0",
            workflow=workflow,
            previous=previous,
            logs=inputs[0].parent / "logs",
            expected_run_id="123" if workflow == "verify.yml" else None,
            expected_run_attempt=gate_attempt if workflow == "verify.yml" else None,
        )

    if wrong_reference:
        with pytest.raises(AttestationError, match="lifecycle references"):
            gate()
    else:
        assert gate().predicate["stage"] == ("gated" if workflow == "verify.yml" else "promoted")


def test_gated_state_cannot_be_admitted_without_the_gates_exact_invocation(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evidence, "verify_predicate", lambda *args, **kwargs: pytest.fail())
    monkeypatch.setattr(evidence, "authenticate_state", lambda *args, **kwargs: pytest.fail())
    with pytest.raises(AttestationError, match="gate's exact run and attempt"):
        evidence.authenticate_gate(
            inputs[0],
            Path("served.json"),
            Path("state-bundle.json"),
            inputs[1],
            manifest_schema=Path("build-schema.json"),
            state_schema=Path("state-schema.json"),
            commit="b" * 40,
            tag="v1.0.0",
            workflow="verify.yml",
            previous=VerifiedState({"stage": "staged"}, "a" * 64),
            logs=inputs[0].parent / "logs",
        )


def test_rows_from_different_attempts_of_one_run_each_bind_their_own_attempt(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Decision of 15 Oct 2026: each row's latest attempt within the run.
    attempts = {"P2": "3", "I1": "1", "M3": "2"}
    for row, attempt in attempts.items():
        inputs[1][row] = evidence.JourneyBundle(
            inputs[1][row].bundle,
            f"https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/{attempt}",
        )
    calls = install_verifier(monkeypatch, inputs[0], attempts=attempts)
    assert (
        evidence.authenticate_journeys(
            inputs[0],
            inputs[1],
            commit="b" * 40,
            tag="v1.0.0",
            logs=inputs[0].parent / "logs",
            expected_run_id="123",
            latest_run_attempt="3",
        )
        == GATE_JOURNEYS
    )
    assert sorted(calls) == sorted(GATE_JOURNEYS)


def test_mixed_run_references_cannot_be_a_complete_gate(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inputs[1]["P1"] = evidence.JourneyBundle(
        inputs[1]["P1"].bundle,
        "https://github.com/zunderlabs/zunder-guard/actions/runs/124/attempts/2",
    )
    monkeypatch.setattr(evidence, "verify_predicate", lambda *args, **kwargs: pytest.fail())
    with pytest.raises(AttestationError, match="one exact workflow run"):
        authenticate(inputs)


@pytest.mark.parametrize("run_id,attempt", [("124", "2"), ("124", "3"), ("123", "1")])
def test_requested_gate_run_cannot_be_replaced_by_other_run_or_later_attempt_references(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]],
    run_id: str,
    attempt: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # References all name run 123 attempt 2: another run, or a gate attempt they follow.
    monkeypatch.setattr(evidence, "verify_predicate", lambda *args, **kwargs: pytest.fail())
    with pytest.raises(AttestationError, match="different requested run or attempt"):
        evidence.authenticate_journeys(
            inputs[0],
            inputs[1],
            commit="b" * 40,
            tag="v1.0.0",
            logs=inputs[0].parent / "logs",
            expected_run_id=run_id,
            latest_run_attempt=attempt,
        )


def test_later_gate_attempt_admits_rows_carried_over_from_an_earlier_attempt(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]], monkeypatch: pytest.MonkeyPatch
) -> None:
    install_verifier(monkeypatch, inputs[0])
    assert (
        evidence.authenticate_journeys(
            inputs[0],
            inputs[1],
            commit="b" * 40,
            tag="v1.0.0",
            logs=inputs[0].parent / "logs",
            expected_run_id="123",
            latest_run_attempt="3",
        )
        == GATE_JOURNEYS
    )
