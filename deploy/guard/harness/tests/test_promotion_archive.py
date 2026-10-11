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
from guard_harness.promotion_archive import candidates, reconstruct
from guard_harness.promotion_state import successor
from guard_harness.release_state import GATE_JOURNEYS, canonical_bytes
from guard_harness.staged_state import genesis


@pytest.fixture(autouse=True)
def official_verifier_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub verifier boundary only; unsigned fixture recovery grants no gate admission."""

    def verify(subject: Path, bundle: Path, **kwargs: Any) -> VerifiedPredicate:
        assert kwargs["expected_run_id"] == "1" and kwargs["expected_run_attempt"] == "1"
        value = json.loads(bundle.read_bytes())
        if value["verificationMaterial"].get("fixture_wrong_run"):
            raise AttestationError("fixture other invocation")
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
        return VerifiedPredicate(
            predicate,
            kwargs["workflow"],
            COMMIT,
            "https://github.com/zunderlabs/zunder-guard/actions/runs/1/attempts/1",
            "1",
            "1",
        )

    monkeypatch.setattr(promotion_archive, "verify_predicate", verify)


def record(predicate: dict[str, Any], kind: str) -> bytes:
    statement = {"predicateType": f"https://zunderlabs.com/guard/{kind}/v1", "predicate": predicate}
    return canonical_bytes(
        {
            "verificationMaterial": {},
            "dsseEnvelope": {
                "payload": base64.b64encode(canonical_bytes(statement)).decode(),
                "signatures": [],
            },
        }
    )


def fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, Any]]:
    gated, build = complete()
    manifest = tmp_path / "manifest"
    manifest.write_bytes(build_bytes("v1.0.0"))
    staged = genesis(manifest.read_bytes(), commit=COMMIT, issued_at="2026-10-11T04:00:00Z")
    promoted = successor(gated, build, stage="promoted")
    states = tmp_path / "state.jsonl"
    states.write_bytes(
        record(staged, "release-state") + b"\n" + record(gated.predicate, "release-state") + b"\n"
    )
    journeys = tmp_path / "journey.jsonl"
    journeys.write_bytes(
        b"\n".join(
            record(
                {"journey": row, "commit": COMMIT, "manifest_sha256": promoted["manifest_sha256"]},
                "journey",
            )
            for row in sorted(GATE_JOURNEYS)
        )
    )
    return manifest, states, journeys, promoted


def test_recovery_preserves_bundle_selection_for_every_row(tmp_path: Path) -> None:
    manifest, states, journeys, promoted = fixture(tmp_path)
    root = tmp_path / "evidence"
    reconstruct(
        root, states, journeys, promoted=promoted, manifest=manifest, run_id="1", attempt="1"
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
            attempt="1",
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
            attempt="1",
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
    reconstruct(
        root, states, journeys, promoted=promoted, manifest=manifest, run_id="1", attempt="1"
    )
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
            attempt="1",
        )
