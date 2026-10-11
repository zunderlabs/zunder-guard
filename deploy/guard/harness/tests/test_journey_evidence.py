import hashlib
from pathlib import Path
from typing import Any

import pytest

import guard_harness.journey_evidence as evidence
from guard_harness.attestation import AttestationError, VerifiedPredicate
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
        bundles[journey] = evidence.JourneyBundle(bundle, f"https://example.com/{journey}")
    return subject, bundles


def install_verifier(
    monkeypatch: pytest.MonkeyPatch,
    original: Path,
    *,
    changes: dict[str, Any] | None = None,
    bad_row: str = "M1",
    replace_original: bool = False,
) -> list[str]:
    expected = original.read_bytes()
    calls: list[str] = []

    def verify(subject: Path, bundle: Path, **kwargs: Any) -> VerifiedPredicate:
        assert subject.read_bytes() == expected
        row = bundle.read_text()
        assert subject != original and kwargs["predicate_type"] == evidence.PREDICATE_TYPE
        assert kwargs["commit"] == "b" * 40 and kwargs["tag"] == "v1.0.0"
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
            "coverage": sorted(evidence.MAINNET_COVERAGE.get(row, frozenset())),
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


@pytest.mark.parametrize("wrong_reference", [False, True])
def test_gate_checks_lifecycle_against_same_manifest_and_authenticated_references(
    inputs: tuple[Path, dict[str, evidence.JourneyBundle]],
    monkeypatch: pytest.MonkeyPatch,
    wrong_reference: bool,
) -> None:
    expected = inputs[0].read_bytes()
    install_verifier(monkeypatch, inputs[0], replace_original=True)
    previous = VerifiedState({"stage": "staged"}, hashlib.sha256(expected).hexdigest())

    def state(subject: Path, *args: Any, **kwargs: Any) -> VerifiedState:
        assert subject.read_bytes() == expected
        assert kwargs["previous"] is previous and kwargs["verified_journeys"] == GATE_JOURNEYS
        refs = {row: bundle.reference for row, bundle in inputs[1].items()}
        if wrong_reference:
            refs["P1"] = "https://example.com/unverified-other-bundle"
        return VerifiedState({"stage": "gated", "evidence": refs}, previous.manifest_sha256)

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
            workflow="verify.yml",
            previous=previous,
            logs=inputs[0].parent / "logs",
        )

    if wrong_reference:
        with pytest.raises(AttestationError, match="lifecycle references"):
            gate()
    else:
        assert gate().predicate["stage"] == "gated"
