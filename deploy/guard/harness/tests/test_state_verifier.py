import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import guard_harness.state_verifier as verifier
from guard_harness.attestation import AttestationError, VerifiedPredicate
from guard_harness.manifest import ManifestError
from guard_harness.release_state import GATE_JOURNEYS, predicate_digest

RELEASE = Path(__file__).resolve().parents[2] / "release"
COMMIT = "b" * 40


@pytest.fixture
def files(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes((RELEASE / "examples/build-v2.json").read_bytes())
    build = json.loads(manifest.read_bytes())
    predicate: dict[str, Any] = {
        "schema": 2,
        "version": build["version"],
        "tag": build["tag"],
        "commit": COMMIT,
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "stage": "staged",
        "revision": 1,
        "previous": None,
        "issued_at": "2026-10-10T10:00:00Z",
        "evidence": {},
        "channels": {
            name: {**descriptor, "status": "unavailable"}
            for name, descriptor in build["distribution"].items()
        },
    }
    served = tmp_path / "served.json"
    served.write_text(json.dumps(predicate))
    return manifest, served, predicate


def authenticate(
    files: tuple[Path, Path, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    *,
    previous: verifier.VerifiedState | None = None,
    expected_run: tuple[str | None, str | None] = (None, None),
) -> verifier.VerifiedState:
    manifest, served, predicate = files

    def verified(*args: Any, **kwargs: Any) -> VerifiedPredicate:
        assert args[0].read_bytes() == manifest.read_bytes()  # Verify the captured subject bytes.
        assert kwargs["commit"] == COMMIT and kwargs["tag"] == "v1.0.0"
        assert (kwargs["expected_run_id"], kwargs["expected_run_attempt"]) == expected_run
        return VerifiedPredicate(predicate, "verify.yml", COMMIT)

    monkeypatch.setattr(verifier, "verify_predicate", verified)
    return verifier.authenticate_state(
        manifest,
        served,
        served.parent / "bundle.json",
        manifest_schema=RELEASE / "manifest.schema.json",
        state_schema=RELEASE / "state.schema.json",
        commit=COMMIT,
        tag="v1.0.0",
        workflow="verify.yml",
        previous=previous,
        verified_journeys=GATE_JOURNEYS,
        log=served.parent / "verify.log",
        expected_run_id=expected_run[0],
        expected_run_attempt=expected_run[1],
    )


def test_authenticates_genesis_and_linked_gate(
    files: tuple[Path, Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    head = authenticate(files, monkeypatch)
    # A separate incoming object cannot mutate the already-verified predecessor.
    predicate = json.loads(json.dumps(files[2]))
    predicate.update(stage="gated", revision=2, previous=predicate_digest(head.predicate))
    predicate["evidence"] = {journey: f"https://example.com/{journey}" for journey in GATE_JOURNEYS}
    for descriptor in predicate["channels"].values():
        descriptor["status"] = "verified"
    files[1].write_text(json.dumps(predicate))
    result = authenticate((files[0], files[1], predicate), monkeypatch, previous=head)
    assert result.predicate["stage"] == "gated"
    assert result.manifest_sha256 == head.manifest_sha256


@pytest.mark.parametrize(
    "field,value", [("stage", "promoted"), ("revision", 2), ("commit", "a" * 40)]
)
def test_served_unsigned_change_refused(
    files: tuple[Path, Path, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: Any,
) -> None:
    received = {**files[2], field: value}
    files[1].write_text(json.dumps(received))
    with pytest.raises(AttestationError, match="differs from the authenticated"):
        authenticate(files, monkeypatch)


def test_manifest_byte_change_breaks_attested_digest(
    files: tuple[Path, Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    files[0].write_bytes(files[0].read_bytes() + b"\n")
    # In reality gh fails first. This tests defence in depth if its boundary is mocked.
    with pytest.raises(ManifestError, match="subject differs"):
        authenticate(files, monkeypatch)


def test_replay_of_genesis_against_durable_head_refused(
    files: tuple[Path, Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    head = authenticate(files, monkeypatch)
    with pytest.raises(ManifestError, match="immediately follow"):
        authenticate(files, monkeypatch, previous=head)


def test_cannot_bootstrap_from_non_genesis_claim(
    files: tuple[Path, Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    files[2]["stage"] = "promoted"
    files[1].write_text(json.dumps(files[2]))
    with pytest.raises(ManifestError, match="genesis"):
        authenticate(files, monkeypatch)


def test_download_path_replacement_cannot_change_verified_snapshot(
    files: tuple[Path, Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, served, predicate = files
    original = manifest.read_bytes()

    def verified(subject: Path, bundle: Path, **kwargs: Any) -> VerifiedPredicate:
        assert subject.read_bytes() == original
        manifest.write_bytes(b"{}")
        return VerifiedPredicate(predicate, "verify.yml", COMMIT)

    monkeypatch.setattr(verifier, "verify_predicate", verified)
    result = verifier.authenticate_state(
        manifest,
        served,
        served.parent / "bundle.json",
        manifest_schema=RELEASE / "manifest.schema.json",
        state_schema=RELEASE / "state.schema.json",
        commit=COMMIT,
        tag="v1.0.0",
        workflow="verify.yml",
        previous=None,
        verified_journeys=frozenset(),
        log=served.parent / "verify.log",
    )
    assert result.manifest_sha256 == hashlib.sha256(original).hexdigest()


def test_lifecycle_forwarding_binds_expected_run_and_attempt(
    files: tuple[Path, Path, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (
        authenticate(files, monkeypatch, expected_run=("123", "2")).predicate["stage"] == "staged"
    )
