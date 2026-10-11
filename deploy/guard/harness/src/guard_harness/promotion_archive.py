"""Recover immutable C2 evidence from GitHub's attestation store after artifact expiry.

DSSE payload parsing selects candidate bundles only. The existing official verifiers
must authenticate the reconstructed chain and every journey before any admission.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from guard_harness.attestation import AttestationError, verify_predicate
from guard_harness.release_state import GATE_JOURNEYS, canonical_bytes, predicate_digest
from guard_harness.runner import RunError, run


def candidates(path: Path) -> list[tuple[bytes, dict[str, Any]]]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise AttestationError("attestation archive missing or over limit")
    result: list[tuple[bytes, dict[str, Any]]] = []
    for line in path.read_bytes().splitlines():
        if not line or len(line) > 2 * 1024 * 1024:
            raise AttestationError("attestation archive record refused")
        value = json.loads(line)
        bundle = value.get("bundle", value)
        if not isinstance(bundle, dict) or "verificationMaterial" not in bundle:
            raise AttestationError("attestation archive does not contain Sigstore bundles")
        envelope = bundle.get("dsseEnvelope")
        if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), str):
            raise AttestationError("attestation archive envelope refused")
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
        if not isinstance(statement, dict) or not isinstance(statement.get("predicate"), dict):
            raise AttestationError("attestation archive statement refused")
        result.append((canonical_bytes(bundle), statement))
        if len(result) >= 1000:
            raise AttestationError("attestation archive limit reached; completeness unknown")
    return result


def reconstruct(
    root: Path,
    state_records: Path,
    journey_records: Path,
    *,
    promoted: dict[str, Any],
    manifest: Path,
    run_id: str,
    attempt: str,
) -> None:
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    statements = candidates(state_records)

    def authenticated(
        matches: list[tuple[bytes, dict[str, Any]]], *, workflow: str, kind: str, label: str
    ) -> tuple[bytes, dict[str, Any]]:
        directory = root.parent / "archive-candidates" / label
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        for index, (bundle, predicate) in enumerate(sorted(matches, key=lambda item: item[0])):
            path = directory / f"{index}.json"
            path.write_bytes(bundle)
            try:
                verified = verify_predicate(
                    manifest,
                    path,
                    workflow=workflow,
                    commit=promoted["commit"],
                    tag=promoted["tag"],
                    predicate_type=f"https://zunderlabs.com/guard/{kind}/v1",
                    expected_run_id=run_id,
                    expected_run_attempt=attempt,
                    log=directory / f"{index}.log",
                )
            except (AttestationError, RunError):
                continue
            if verified.predicate == predicate:
                return bundle, predicate
        raise AttestationError("exact workflow run and attempt missing from attestation store")

    def select(expected: str, label: str) -> tuple[bytes, dict[str, Any]]:
        matches = [
            (bundle, statement["predicate"])
            for bundle, statement in statements
            if statement.get("predicateType") == "https://zunderlabs.com/guard/release-state/v1"
            and predicate_digest(statement["predicate"]) == expected
        ]
        if not matches:
            raise AttestationError("exact lifecycle predecessor missing from attestation store")
        return authenticated(matches, workflow="verify.yml", kind="release-state", label=label)

    gated_bundle, gated = select(promoted["previous"], "gated")
    staged_bundle, staged = select(gated["previous"], "staged")
    chain = root / f"complete-gate-{run_id}-{attempt}"
    chain.mkdir(parents=True, exist_ok=False)
    for stage, predicate, bundle in (
        ("staged", staged, staged_bundle),
        ("gated", gated, gated_bundle),
    ):
        (chain / f"{stage}.predicate.json").write_bytes(canonical_bytes(predicate))
        (chain / f"{stage}.sigstore.json").write_bytes(bundle)
    journeys = candidates(journey_records)
    for row in sorted(GATE_JOURNEYS):
        matches = [
            (bundle, statement["predicate"])
            for bundle, statement in journeys
            if statement.get("predicateType") == "https://zunderlabs.com/guard/journey/v1"
            and statement["predicate"].get("journey") == row
            and statement["predicate"].get("commit") == promoted["commit"]
            and statement["predicate"].get("manifest_sha256") == digest
        ]
        if not matches:
            raise AttestationError("complete journey evidence missing from attestation store")
        directory = root / f"{row}-{run_id}-{attempt}"
        directory.mkdir()
        bundle, _ = authenticated(
            matches,
            workflow="install-matrix.yml"
            if row.startswith("I") or row in {"M1", "M2"}
            else "journey.yml",
            kind="journey",
            label=row,
        )
        (directory / "bundle.json").write_bytes(bundle)


def recover(
    root: Path, *, manifest: Path, promoted: dict[str, Any], run_id: str, attempt: str, logs: Path
) -> None:
    sources: list[Path] = []
    for name, predicate in (("state", "release-state"), ("journeys", "journey")):
        directory = root.parent / ("attestation-store-" + name)
        directory.mkdir(mode=0o700)
        env = {key: os.environ[key] for key in ("PATH", "HOME", "GH_TOKEN") if key in os.environ}
        run(
            [
                "gh",
                "attestation",
                "download",
                str(manifest),
                "--repo",
                "zunderlabs/zunder-guard",
                "--predicate-type",
                f"https://zunderlabs.com/guard/{predicate}/v1",
                "--limit",
                "1000",
            ],
            cwd=directory,
            env=env,
            log=logs / f"{name}-download.log",
            timeout=180,
            secrets=[env.get("GH_TOKEN", "")],
        )
        files = list(directory.glob("*.jsonl"))
        if len(files) != 1:
            raise AttestationError("expected exactly one immutable subject attestation archive")
        sources.append(files[0])
    reconstruct(
        root,
        sources[0],
        sources[1],
        promoted=promoted,
        manifest=manifest,
        run_id=run_id,
        attempt=attempt,
    )
