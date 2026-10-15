"""Authenticate complete C2 chains and produce stable promotion/withdrawal successors."""

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guard_harness.attestation import AttestationError
from guard_harness.gate_state import bundles
from guard_harness.journey_evidence import authenticate_gate
from guard_harness.native_release import Release, authenticate
from guard_harness.release_state import (
    GATE_JOURNEYS,
    canonical_bytes,
    predicate_digest,
    validate_state,
)
from guard_harness.state_verifier import VerifiedState, authenticate_state
from guard_harness.testnet_run import ROOT


def stable(tag: str, commit: str) -> None:
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise AttestationError("promotion requires an exact stable tag and release commit")


def successor(previous: VerifiedState, build: dict[str, Any], *, stage: str) -> dict[str, Any]:
    stable(build["tag"], build["commit"])
    if stage not in {"promoted", "withdrawn"}:
        raise AttestationError("promotion workflow may only promote or withdraw")
    if stage == "promoted" and (
        previous.predicate["stage"] != "gated" or previous.predicate["revision"] != 2
    ):
        raise AttestationError("promotion requires authenticated gated revision 2")
    state = dict(previous.predicate)
    state.update(
        stage=stage,
        revision=previous.predicate["revision"] + 1,
        previous=predicate_digest(previous.predicate),
        issued_at=max(
            previous.predicate["issued_at"], datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        ),
    )
    if stage == "withdrawn":
        state["channels"] = {
            name: dict(value, status="unavailable") for name, value in state["channels"].items()
        }
    validate_state(
        state,
        build,
        ROOT / "release/state.schema.json",
        manifest_sha256=previous.manifest_sha256,
        signer_workflow="promote.yml",
        previous=previous.predicate,
        verified_journeys=GATE_JOURNEYS if stage == "promoted" else frozenset(),
    )
    return state


def gate(
    release: Release, evidence: Path, *, run_id: str, attempt: str, logs: Path
) -> VerifiedState:
    """`attempt` is the gate job's own attempt; its rows and staging may be earlier."""
    chain = evidence / f"complete-gate-{run_id}-{attempt}"
    staged = authenticate_state(
        release.assets / "release-manifest.json",
        chain / "staged.predicate.json",
        chain / "staged.sigstore.json",
        manifest_schema=ROOT / "release/manifest.schema.json",
        state_schema=ROOT / "release/state.schema.json",
        commit=release.commit,
        tag=release.tag,
        workflow="verify.yml",
        # Staging may have passed in an earlier attempt of the gate's run; the gated
        # successor (exact attempt below) binds this predecessor by digest.
        expected_run_id=run_id,
        latest_run_attempt=attempt,
        previous=None,
        verified_journeys=frozenset(),
        log=logs / "staged.log",
    )
    return authenticate_gate(
        release.assets / "release-manifest.json",
        chain / "gated.predicate.json",
        chain / "gated.sigstore.json",
        bundles(evidence, run_id=run_id, attempt=attempt),
        manifest_schema=ROOT / "release/manifest.schema.json",
        state_schema=ROOT / "release/state.schema.json",
        commit=release.commit,
        tag=release.tag,
        workflow="verify.yml",
        expected_run_id=run_id,
        expected_run_attempt=attempt,
        previous=staged,
        logs=logs,
    )


def capture(bundle: Path, target: Path) -> None:
    if bundle.is_symlink() or not bundle.is_file():
        raise AttestationError("lifecycle bundle must be a regular file")
    with bundle.open("rb") as source:
        data = source.read(2 * 1024 * 1024 + 1)
    if not 0 < len(data) <= 2 * 1024 * 1024:
        raise AttestationError("lifecycle bundle size refused")
    with target.open("xb") as output:
        output.write(data)
    target.chmod(0o600)


def prepare(
    work: Path, evidence: Path, *, tag: str, commit: str, run_id: str, attempt: str
) -> None:
    stable(tag, commit)
    if work.exists() or not work.is_absolute():
        raise AttestationError("fresh absolute promotion workspace required")
    work.mkdir(mode=0o700)
    release = authenticate(tag, commit, work / "candidate")
    previous = gate(release, evidence, run_id=run_id, attempt=attempt, logs=work / "logs/gate")
    state = successor(
        previous, json.loads(release.asset("release-manifest.json")), stage="promoted"
    )
    (work / "promoted.predicate.json").write_bytes(canonical_bytes(state))
    (work / "subject.sha256").write_text(
        hashlib.sha256(release.asset("release-manifest.json")).hexdigest()
    )
