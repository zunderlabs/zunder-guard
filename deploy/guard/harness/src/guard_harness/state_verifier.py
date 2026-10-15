"""Bind served C2 JSON to its authenticated bundle and a verified predecessor."""

import hashlib
import json
from collections.abc import Set
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from guard_harness.attestation import AttestationError, verify_predicate
from guard_harness.release_state import PREDICATE_TYPE, validate_build, validate_state


@dataclass(frozen=True)
class VerifiedState:
    predicate: dict[str, Any]
    manifest_sha256: str


def authenticate_state(
    manifest: Path,
    served: Path,
    bundle: Path,
    *,
    manifest_schema: Path,
    state_schema: Path,
    commit: str,
    tag: str,
    workflow: str,
    previous: VerifiedState | None,
    verified_journeys: Set[str],
    log: Path,
    expected_run_id: str | None = None,
    expected_run_attempt: str | None = None,
    latest_run_attempt: str | None = None,
) -> VerifiedState:
    """Verify before trusting any supplied JSON or predecessor links.

    Start from the authenticated staged genesis and check each revision. `previous`
    must be the caller's durable trusted head, never a predecessor from a request.
    The caller authenticates journey bundles independently before passing their IDs.
    First-time clients must obtain the chain; this does not discover a withdrawn
    successor or prevent replay when the caller loses its trusted head.
    """
    manifest_bytes = manifest.read_bytes()
    served_bytes = served.read_bytes()
    # Verification and parsing use one snapshot, not multiple reads of a caller's
    # replaceable download path. The private temporary directory isolates the copy.
    with TemporaryDirectory(prefix="guard-state-") as directory:
        subject = Path(directory) / "release-manifest.json"
        subject.write_bytes(manifest_bytes)
        subject.chmod(0o444)
        authenticated = verify_predicate(
            subject,
            bundle,
            workflow=workflow,
            commit=commit,
            tag=tag,
            predicate_type=PREDICATE_TYPE,
            log=log,
            expected_run_id=expected_run_id,
            expected_run_attempt=expected_run_attempt,
            latest_run_attempt=latest_run_attempt,
        )
    try:
        build: Any = json.loads(manifest_bytes)
        received: Any = json.loads(served_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise AttestationError("release metadata is not valid JSON") from error
    if not isinstance(build, dict) or not isinstance(received, dict):
        raise AttestationError("release metadata must be objects")
    if received != authenticated.predicate:
        raise AttestationError("served state differs from the authenticated predicate")
    validate_build(build, manifest_schema, expected_commit=commit)
    if build["tag"] != tag:
        raise AttestationError("manifest tag differs from the authenticated release tag")
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    if previous is not None and previous.manifest_sha256 != digest:
        raise AttestationError("trusted head belongs to another immutable manifest")
    validate_state(
        received,
        build,
        state_schema,
        manifest_sha256=digest,
        signer_workflow=authenticated.workflow,
        previous=previous.predicate if previous is not None else None,
        verified_journeys=verified_journeys,
    )
    return VerifiedState(received, digest)
