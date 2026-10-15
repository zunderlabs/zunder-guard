"""Archive fixtures exercise selection only; official authentication remains mandatory."""

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from test_promotion import complete
from test_staged_state import COMMIT, build_bytes

from guard_harness import promotion_archive
from guard_harness.attestation import AttestationError, VerifiedPredicate
from guard_harness.gate_state import bundles
from guard_harness.promotion_archive import candidates, gate_attempt, reconstruct
from guard_harness.promotion_state import successor
from guard_harness.release_state import GATE_JOURNEYS, canonical_bytes
from guard_harness.staged_state import genesis

# Decision of 15 Oct 2026: rows may come from different attempts of the gate's run.
MIXED = {"P2": "2", "I3": "2", "I1": "3"}


@pytest.fixture(autouse=True)
def official_verifier_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub verifier boundary only; unsigned fixture recovery grants no gate admission.

    It applies the real verifier's invocation rules to the run and attempt a fixture
    bundle claims to be signed in (`fixture_run` and `fixture_attempt`, default 1): it
    returns that invocation and raises only when an expected run or attempt differs.
    """

    def verify(subject: Path, bundle: Path, **kwargs: Any) -> VerifiedPredicate:
        value = json.loads(bundle.read_bytes())
        material = value["verificationMaterial"]
        if material.get("fixture_wrong_run"):
            raise AttestationError("fixture other invocation")
        run_id = material.get("fixture_run", "1")
        attempt = material.get("fixture_attempt", "1")
        if kwargs["expected_run_id"] is not None and kwargs["expected_run_id"] != run_id:
            raise AttestationError("fixture signed in another workflow run")
        if kwargs["expected_run_attempt"] is not None:
            assert kwargs["latest_run_attempt"] is None
            if kwargs["expected_run_attempt"] != attempt:
                raise AttestationError("fixture differs from expected invocation")
        if kwargs["latest_run_attempt"] is not None and int(attempt) > int(
            kwargs["latest_run_attempt"]
        ):
            raise AttestationError("fixture attempt follows the expected one")
        predicate = json.loads(base64.b64decode(value["dsseEnvelope"]["payload"]))["predicate"]
        row = predicate.get("journey")
        expected_workflow = (
            "verify.yml"
            if row is None
            else "install-matrix.yml"
            if row.startswith("I") or row in {"M1", "M2"}
            else "journey.yml"
        )
        assert kwargs["workflow"] == expected_workflow
        if row is not None:
            # Journey rows are always bound to their exact referenced attempt.
            assert kwargs["expected_run_id"] == "1"
            assert kwargs["expected_run_attempt"] is not None
        return VerifiedPredicate(
            predicate,
            kwargs["workflow"],
            COMMIT,
            f"https://github.com/zunderlabs/zunder-guard/actions/runs/{run_id}/attempts/{attempt}",
            run_id,
            attempt,
        )

    monkeypatch.setattr(promotion_archive, "verify_predicate", verify)


def record(predicate: dict[str, Any], kind: str, *, attempt: str = "1", run: str = "1") -> bytes:
    statement = {"predicateType": f"https://zunderlabs.com/guard/{kind}/v1", "predicate": predicate}
    return canonical_bytes(
        {
            "verificationMaterial": {"fixture_run": run, "fixture_attempt": attempt},
            "dsseEnvelope": {
                "payload": base64.b64encode(canonical_bytes(statement)).decode(),
                "signatures": [],
            },
        }
    )


def fixture(
    tmp_path: Path,
    *,
    attempts: dict[str, str] | None = None,
    gated_attempt: str = "1",
    staged_attempt: str = "1",
    gated_run: str = "1",
) -> tuple[Path, Path, Path, dict[str, Any]]:
    gated, build = complete(attempts=attempts)
    manifest = tmp_path / "manifest"
    manifest.write_bytes(build_bytes("v1.0.0"))
    staged = genesis(manifest.read_bytes(), commit=COMMIT, issued_at="2026-10-11T04:00:00Z")
    promoted = successor(gated, build, stage="promoted")
    states = tmp_path / "state.jsonl"
    states.write_bytes(
        record(staged, "release-state", attempt=staged_attempt)
        + b"\n"
        + record(gated.predicate, "release-state", attempt=gated_attempt, run=gated_run)
        + b"\n"
    )
    journeys = tmp_path / "journey.jsonl"
    journeys.write_bytes(
        b"\n".join(
            record(
                {"journey": row, "commit": COMMIT, "manifest_sha256": promoted["manifest_sha256"]},
                "journey",
                attempt=(attempts or {}).get(row, "1"),
            )
            for row in sorted(GATE_JOURNEYS)
        )
    )
    return manifest, states, journeys, promoted


def test_recovery_preserves_bundle_selection_for_every_row(tmp_path: Path) -> None:
    manifest, states, journeys, promoted = fixture(tmp_path)
    root = tmp_path / "evidence"
    assert (
        reconstruct(root, states, journeys, promoted=promoted, manifest=manifest, run_id="1") == "1"
    )
    rows = bundles(root, run_id="1", attempt="1")
    assert set(rows) == GATE_JOURNEYS
    assert (
        json.loads((root / "complete-gate-1-1/gated.predicate.json").read_bytes())["stage"]
        == "gated"
    )
    assert all(
        not json.loads(item.bundle.read_bytes())["dsseEnvelope"]["signatures"]
        for item in rows.values()
    )
    assert gate_attempt(root, "1") == "1"


def test_recovery_rebuilds_each_rows_own_attempt_and_the_gates_attempt(tmp_path: Path) -> None:
    manifest, states, journeys, promoted = fixture(
        tmp_path, attempts=MIXED, gated_attempt="3", staged_attempt="1"
    )
    root = tmp_path / "evidence"
    assert (
        reconstruct(root, states, journeys, promoted=promoted, manifest=manifest, run_id="1") == "3"
    )
    assert gate_attempt(root, "1") == "3"
    rows = bundles(root, run_id="1", attempt="3")
    assert {row: bundle.reference for row, bundle in rows.items()} == promoted["evidence"]
    assert (root / "P2-1-2").is_dir() and not (root / "P2-1-1").exists()


def test_recovery_refuses_a_gate_that_precedes_a_referenced_row(tmp_path: Path) -> None:
    manifest, states, journeys, promoted = fixture(tmp_path, attempts=MIXED, gated_attempt="2")
    with pytest.raises(AttestationError, match="follows the gate's attempt"):
        reconstruct(
            tmp_path / "evidence",
            states,
            journeys,
            promoted=promoted,
            manifest=manifest,
            run_id="1",
        )


def test_recovery_refuses_a_gated_state_signed_in_another_run(tmp_path: Path) -> None:
    # The gated state is authenticated without an expected run (its attempt is what is
    # being learned), so only the post-check on the verified invocation binds its run.
    manifest, states, journeys, promoted = fixture(tmp_path, gated_run="2")
    with pytest.raises(AttestationError, match="exact workflow run and attempt"):
        reconstruct(
            tmp_path / "evidence",
            states,
            journeys,
            promoted=promoted,
            manifest=manifest,
            run_id="1",
        )


def test_recovery_refuses_a_row_signed_in_another_run(tmp_path: Path) -> None:
    manifest, states, journeys, promoted = fixture(tmp_path)
    records = [json.loads(line) for line in journeys.read_bytes().splitlines()]
    records[0]["verificationMaterial"]["fixture_run"] = "2"
    journeys.write_bytes(b"\n".join(canonical_bytes(value) for value in records))
    with pytest.raises(AttestationError, match="exact workflow run and attempt"):
        reconstruct(
            tmp_path / "evidence",
            states,
            journeys,
            promoted=promoted,
            manifest=manifest,
            run_id="1",
        )


def test_recovery_refuses_staging_after_the_gate(tmp_path: Path) -> None:
    manifest, states, journeys, promoted = fixture(tmp_path, gated_attempt="2", staged_attempt="3")
    with pytest.raises(AttestationError, match="exact workflow run and attempt"):
        reconstruct(
            tmp_path / "evidence",
            states,
            journeys,
            promoted=promoted,
            manifest=manifest,
            run_id="1",
        )


def test_recovery_binds_each_row_to_its_referenced_attempt(tmp_path: Path) -> None:
    manifest, states, journeys, promoted = fixture(tmp_path, attempts=MIXED, gated_attempt="3")
    # P2's archived signature is from attempt 1, but the promoted state references 2.
    records = [json.loads(line) for line in journeys.read_bytes().splitlines()]
    for value in records:
        statement = json.loads(base64.b64decode(value["dsseEnvelope"]["payload"]))
        if statement["predicate"]["journey"] == "P2":
            value["verificationMaterial"]["fixture_attempt"] = "1"
    journeys.write_bytes(b"\n".join(canonical_bytes(value) for value in records))
    with pytest.raises(AttestationError, match="exact workflow run and attempt"):
        reconstruct(
            tmp_path / "evidence",
            states,
            journeys,
            promoted=promoted,
            manifest=manifest,
            run_id="1",
        )


@pytest.mark.parametrize(
    "reference",
    [
        "https://github.com/zunderlabs/zunder-guard/actions/runs/2/attempts/1",
        "https://example.com/runs/1/attempts/1",
    ],
)
def test_recovery_refuses_references_outside_the_run(tmp_path: Path, reference: str) -> None:
    manifest, states, journeys, promoted = fixture(tmp_path)
    promoted["evidence"]["P2"] = reference
    with pytest.raises(AttestationError):
        reconstruct(
            tmp_path / "evidence",
            states,
            journeys,
            promoted=promoted,
            manifest=manifest,
            run_id="1",
        )


def test_recovered_gate_attempt_must_be_unique(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    (root / "complete-gate-1-2").mkdir(parents=True)
    assert gate_attempt(root, "1") == "2"
    (root / "complete-gate-1-3").mkdir()
    with pytest.raises(AttestationError, match="exactly one complete gate"):
        gate_attempt(root, "1")
    with pytest.raises(AttestationError, match="another workflow run"):
        gate_attempt(root, "2")


def test_recovery_refuses_missing_single_journey(tmp_path: Path) -> None:
    manifest, states, journeys, promoted = fixture(tmp_path)
    journeys.write_bytes(b"\n".join(journeys.read_bytes().splitlines()[:-1]))
    with pytest.raises(AttestationError, match="complete journey"):
        reconstruct(
            tmp_path / "evidence",
            states,
            journeys,
            promoted=promoted,
            manifest=manifest,
            run_id="1",
        )


def test_recovery_refuses_missing_exact_predecessor(tmp_path: Path) -> None:
    manifest, states, journeys, promoted = fixture(tmp_path)
    promoted["previous"] = "a" * 64
    with pytest.raises(AttestationError, match="exact lifecycle predecessor"):
        reconstruct(
            tmp_path / "evidence",
            states,
            journeys,
            promoted=promoted,
            manifest=manifest,
            run_id="1",
        )


def test_archive_refuses_symlink_and_non_bundle(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_text("{}")
    link = tmp_path / "link"
    link.symlink_to(source)
    with pytest.raises(AttestationError, match="missing or over limit"):
        candidates(link)
    with pytest.raises(AttestationError, match="Sigstore bundles"):
        candidates(source)


def test_archive_skips_other_run_candidate_before_matching_verified_invocation(
    tmp_path: Path,
) -> None:
    manifest, states, journeys, promoted = fixture(tmp_path)
    records = journeys.read_bytes().splitlines()
    wrong = json.loads(records[0])
    wrong["verificationMaterial"]["fixture_wrong_run"] = True
    journeys.write_bytes(canonical_bytes(wrong) + b"\n" + b"\n".join(records))
    root = tmp_path / "evidence"
    reconstruct(root, states, journeys, promoted=promoted, manifest=manifest, run_id="1")
    row = sorted(GATE_JOURNEYS)[0]
    captured = json.loads((root / f"{row}-1-1/bundle.json").read_bytes())
    assert "fixture_wrong_run" not in captured["verificationMaterial"]


def test_archive_with_only_wrong_invocation_never_relabels_receipt(tmp_path: Path) -> None:
    manifest, states, journeys, promoted = fixture(tmp_path)
    records = journeys.read_bytes().splitlines()
    wrong = json.loads(records[0])
    wrong["verificationMaterial"]["fixture_wrong_run"] = True
    journeys.write_bytes(canonical_bytes(wrong) + b"\n" + b"\n".join(records[1:]))
    with pytest.raises(AttestationError, match="exact workflow run and attempt"):
        reconstruct(
            tmp_path / "evidence",
            states,
            journeys,
            promoted=promoted,
            manifest=manifest,
            run_id="1",
        )
