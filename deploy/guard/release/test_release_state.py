"""C2 v2 revision/subject/gate contract tests. Fixtures are not signature evidence."""

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from guard_harness.manifest import ManifestError
from guard_harness.release_state import (
    GATE_JOURNEYS,
    predicate_digest,
    validate_build,
    validate_state,
)

ROOT = Path(__file__).parent
SUBJECT = hashlib.sha256((ROOT / "examples/build-v2.json").read_bytes()).hexdigest()


@pytest.fixture
def build() -> dict[str, Any]:
    result: dict[str, Any] = json.loads((ROOT / "examples/build-v2.json").read_text())
    return result


@pytest.fixture
def staged(build: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": 2,
        "version": build["version"],
        "tag": build["tag"],
        "commit": build["commit"],
        "manifest_sha256": SUBJECT,
        "revision": 1,
        "previous": None,
        "stage": "staged",
        "issued_at": "2026-10-10T10:01:00Z",
        "evidence": {},
        "channels": {
            name: {**descriptor, "status": "unavailable"}
            for name, descriptor in build["distribution"].items()
        },
    }


def next_state(previous: dict[str, Any], stage: str) -> dict[str, Any]:
    result = copy.deepcopy(previous)
    result.update(
        stage=stage, revision=previous["revision"] + 1, previous=predicate_digest(previous)
    )
    if stage in {"gated", "promoted"}:
        result["evidence"] = {
            journey: f"https://example.com/{journey}" for journey in GATE_JOURNEYS
        }
    for channel in result["channels"].values():
        channel["status"] = "verified" if stage in {"gated", "promoted"} else "unavailable"
    return result


def check(
    state: dict[str, Any],
    build: dict[str, Any],
    previous: dict[str, Any] | None,
    signer: str = "verify.yml",
    verified: frozenset[str] = GATE_JOURNEYS,
) -> None:
    validate_state(
        state,
        build,
        ROOT / "state.schema.json",
        manifest_sha256=SUBJECT,
        signer_workflow=signer,
        previous=previous,
        verified_journeys=verified,
    )


def test_immutable_build_contract(build: dict[str, Any]) -> None:
    validate_build(build, ROOT / "manifest.schema.json", expected_commit="b" * 40)


@pytest.mark.parametrize("field", ["stage", "evidence"])
def test_build_cannot_carry_mutable_fields(build: dict[str, Any], field: str) -> None:
    build[field] = "not immutable"
    with pytest.raises(ManifestError):
        validate_build(build, ROOT / "manifest.schema.json", expected_commit="b" * 40)


def test_whole_chain(build: dict[str, Any], staged: dict[str, Any]) -> None:
    check(staged, build, None)
    gated = next_state(staged, "gated")
    check(gated, build, staged)
    promoted = next_state(gated, "promoted")
    check(promoted, build, gated, "promote.yml")
    withdrawn = next_state(promoted, "withdrawn")
    check(withdrawn, build, promoted, "promote.yml")


@pytest.mark.parametrize("journey", sorted(GATE_JOURNEYS))
def test_gate_needs_every_authenticated_journey(
    build: dict[str, Any], staged: dict[str, Any], journey: str
) -> None:
    with pytest.raises(ManifestError):
        check(next_state(staged, "gated"), build, staged, verified=GATE_JOURNEYS - {journey})


@pytest.mark.parametrize(
    "field,value",
    [
        ("manifest_sha256", "a" * 64),
        ("previous", "a" * 64),
        ("revision", 3),
        ("issued_at", "2026-10-10T09:00:00Z"),
        ("issued_at", "2026-02-30T10:00:00Z"),
        ("version", "1.0.1"),
        ("commit", "a" * 40),
        ("stage", "promoted"),
    ],
)
def test_revision_tampering(
    build: dict[str, Any], staged: dict[str, Any], field: str, value: Any
) -> None:
    gated = next_state(staged, "gated")
    gated[field] = value
    with pytest.raises(ManifestError):
        check(gated, build, staged)


def test_competing_head_refused(build: dict[str, Any], staged: dict[str, Any]) -> None:
    gated = next_state(staged, "gated")
    other = copy.deepcopy(staged)
    other["issued_at"] = "2026-10-10T10:01:01Z"
    with pytest.raises(ManifestError, match="predecessor differs"):
        check(gated, build, other)


def test_accepted_revision_cannot_be_replayed(
    build: dict[str, Any], staged: dict[str, Any]
) -> None:
    gated = next_state(staged, "gated")
    with pytest.raises(ManifestError, match="immediately follow"):
        check(gated, build, gated)


def test_signer_bound_to_transition(build: dict[str, Any], staged: dict[str, Any]) -> None:
    with pytest.raises(ManifestError, match="wrong workflow"):
        check(staged, build, None, "promote.yml")
    gated = next_state(staged, "gated")
    with pytest.raises(ManifestError, match="wrong workflow"):
        check(next_state(gated, "promoted"), build, gated)


def test_channel_cannot_replace_signed_image(build: dict[str, Any], staged: dict[str, Any]) -> None:
    gated = next_state(staged, "gated")
    gated["channels"]["docker"]["digest"] = "sha256:" + "d" * 64
    with pytest.raises(ManifestError, match="signed distribution"):
        check(gated, build, staged)


def test_withdrawal_terminal(build: dict[str, Any], staged: dict[str, Any]) -> None:
    withdrawn = next_state(staged, "withdrawn")
    check(withdrawn, build, staged, "promote.yml")
    with pytest.raises(ManifestError, match="invalid lifecycle"):
        check(next_state(withdrawn, "gated"), build, withdrawn)


def test_rc_gate_allowed_promotion_refused(build: dict[str, Any], staged: dict[str, Any]) -> None:
    for value in [build, staged]:
        value.update(version="1.0.0-rc.1", tag="v1.0.0-rc.1")
    # Build validation is tested separately; state must match this supplied build.
    gated = next_state(staged, "gated")
    check(gated, build, staged)
    with pytest.raises(ManifestError, match="candidate promotion"):
        check(next_state(gated, "promoted"), build, gated, "promote.yml")


@pytest.mark.parametrize("journey", ["M1", "M2", "M3"])
def test_mainnet_evidence_link_alone_is_not_authenticated(
    build: dict[str, Any], staged: dict[str, Any], journey: str
) -> None:
    # Existing gate test removes authentication; this independently removes the reference.
    gated = next_state(staged, "gated")
    del gated["evidence"][journey]
    with pytest.raises(ManifestError, match="mainnet-check journey"):
        check(gated, build, staged)


def test_manual_mainnet_pilot_cannot_count_as_automated_gate_evidence(
    build: dict[str, Any], staged: dict[str, Any]
) -> None:
    gated = next_state(staged, "gated")
    gated["evidence"]["M4"] = "https://example.com/manual-pilot"
    with pytest.raises(ManifestError, match="evidence"):
        check(gated, build, staged)
