"""Require every signed journey before producing a C2 gated successor."""

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guard_harness.attestation import AttestationError
from guard_harness.journey_evidence import JourneyBundle, authenticate_journeys
from guard_harness.lifecycle_coverage import CHANNEL_COVERAGE
from guard_harness.release_state import GATE_JOURNEYS, canonical_bytes, validate_state
from guard_harness.state_verifier import authenticate_state
from guard_harness.testnet_run import ROOT


def bundles(evidence: Path, *, run_id: str, attempt: str) -> dict[str, JourneyBundle]:
    if not re.fullmatch(r"[1-9][0-9]*", run_id) or not re.fullmatch(r"[1-9][0-9]*", attempt):
        raise ValueError("exact workflow run and attempt required")
    result: dict[str, JourneyBundle] = {}
    for row in sorted(GATE_JOURNEYS):
        directory = evidence / f"{row}-{run_id}-{attempt}"
        # Artifact paths are extracted by the pinned Actions downloader. The
        # official verifier, not artifact names or unsigned predicates, admits them.
        candidates: dict[bytes, Path] = {}
        for path in directory.rglob("*.json"):
            if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
                raise AttestationError("unsafe journey bundle file")
            raw = path.read_bytes()
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                continue
            if (
                isinstance(value, dict)
                and "dsseEnvelope" in value
                and "verificationMaterial" in value
            ):
                candidates[raw] = path
        if len(candidates) != 1:
            raise AttestationError(f"{row} requires exactly one captured signed journey bundle")
        result[row] = JourneyBundle(
            next(iter(candidates.values())),
            f"https://github.com/zunderlabs/zunder-guard/actions/runs/{run_id}/attempts/{attempt}",
        )
    return result


def successor(
    previous: dict[str, Any],
    build: dict[str, Any],
    references: dict[str, str],
    *,
    coverage: dict[str, frozenset[str]],
) -> dict[str, Any]:
    if previous.get("stage") != "staged":
        raise AttestationError("gate must advance an authenticated staged release")
    if set(coverage) != GATE_JOURNEYS:
        raise AttestationError("complete authenticated measured journey coverage required")
    for channel in build["distribution"]:
        required = CHANNEL_COVERAGE.get(channel)
        if required is None or any(
            not checks <= coverage.get(row, frozenset()) for row, checks in required.items()
        ):
            raise AttestationError("distribution channel lacks measured documented execution")
    state = dict(previous)
    state.update(
        stage="gated",
        revision=previous["revision"] + 1,
        previous=hashlib.sha256(canonical_bytes(previous)).hexdigest(),
        issued_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        evidence=references,
        channels={
            name: dict(descriptor, status="verified")
            for name, descriptor in build["distribution"].items()
        },
    )
    validate_state(
        state,
        build,
        ROOT / "release/state.schema.json",
        manifest_sha256=previous["manifest_sha256"],
        signer_workflow="verify.yml",
        previous=previous,
        verified_journeys=GATE_JOURNEYS,
    )
    return state


def execute(
    *, work: Path, evidence: Path, tag: str, commit: str, run_id: str, attempt: str
) -> None:
    manifest = work / "assets/release-manifest.json"
    verified = authenticate_state(
        manifest,
        work / "staged.predicate.json",
        work / "staged.sigstore.json",
        manifest_schema=ROOT / "release/manifest.schema.json",
        state_schema=ROOT / "release/state.schema.json",
        commit=commit,
        tag=tag,
        workflow="verify.yml",
        previous=None,
        verified_journeys=frozenset(),
        log=work / "gate-logs/staged.log",
        expected_run_id=run_id,
        expected_run_attempt=attempt,
    )
    journeys = bundles(evidence, run_id=run_id, attempt=attempt)
    coverage: dict[str, frozenset[str]] = {}
    authenticate_journeys(
        manifest,
        journeys,
        commit=commit,
        tag=tag,
        logs=work / "gate-logs",
        expected_run_id=run_id,
        expected_run_attempt=attempt,
        coverage_out=coverage,
    )
    state = successor(
        verified.predicate,
        json.loads(manifest.read_bytes()),
        {row: bundle.reference for row, bundle in journeys.items()},
        coverage=coverage,
    )
    with (work / "gated.predicate.json").open("xb") as stream:
        stream.write(canonical_bytes(state))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("work", "evidence"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("tag", "commit", "run-id", "attempt"):
        parser.add_argument("--" + name, required=True)
    execute(**vars(parser.parse_args()))


if __name__ == "__main__":
    main()
