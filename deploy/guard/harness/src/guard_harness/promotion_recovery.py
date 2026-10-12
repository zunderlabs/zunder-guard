"""Authenticate immutable rollback inputs from an exact original promotion invocation."""

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from guard_harness.attestation import AttestationError, expected_invocation, verify_predicate
from guard_harness.release_state import canonical_bytes

PREDICATE = "https://zunderlabs.com/guard/promotion-snapshot/v1"
FILES = (
    "transaction.json",
    "channels.snapshot.json",
    "promoted.predicate.json",
    "subject.sha256",
    "candidate/assets/release-manifest.json",
    "candidate/assets/SHA256SUMS",
    "candidate/assets/zunder-guard.rb",
    "candidate/assets/.verified-release-source.json",
)


def bounded(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink() or path.stat().st_nlink != 1:
        raise AttestationError("rollback snapshot requires regular immutable files")
    if not 0 < path.stat().st_size <= 2 * 1024 * 1024:
        raise AttestationError("rollback snapshot file size refused")
    with path.open("rb") as stream:
        body = stream.read(2 * 1024 * 1024 + 1)
    if not 0 < len(body) <= 2 * 1024 * 1024:
        raise AttestationError("rollback snapshot file size refused")
    return body


def snapshot(work: Path, *, tag: str, commit: str, run_id: str, attempt: str) -> None:
    invocation = expected_invocation(
        os.environ.get("GITHUB_RUN_ID"), os.environ.get("GITHUB_RUN_ATTEMPT")
    )
    expected_invocation(run_id, attempt)
    if invocation is None:
        raise AttestationError("original promotion invocation required")
    (work / "channels.snapshot.json").write_bytes(bounded(work / "channels.json"))
    value = {
        "schema": 1,
        "tag": tag,
        "commit": commit,
        "verify_run": run_id,
        "verify_attempt": attempt,
        "promotion_run": invocation[0],
        "promotion_attempt": invocation[1],
        "files": {name: hashlib.sha256(bounded(work / name)).hexdigest() for name in FILES},
    }
    (work / "rollback-snapshot.json").write_bytes(canonical_bytes(value))


def authenticate(
    work: Path,
    *,
    tag: str,
    commit: str,
    run_id: str,
    attempt: str,
    source_run: str,
    source_attempt: str,
) -> dict[str, Any]:
    expected_invocation(source_run, source_attempt)
    value = json.loads(bounded(work / "rollback-snapshot.json"))
    expected = {
        "schema": 1,
        "tag": tag,
        "commit": commit,
        "verify_run": run_id,
        "verify_attempt": attempt,
        "promotion_run": source_run,
        "promotion_attempt": source_attempt,
        "files": {name: hashlib.sha256(bounded(work / name)).hexdigest() for name in FILES},
    }
    if value != expected:
        raise AttestationError("original signed rollback snapshot inputs differ")
    verified = verify_predicate(
        work / "rollback-snapshot.json",
        work / "rollback-snapshot.sigstore.json",
        workflow="promote.yml",
        commit=commit,
        tag=tag,
        predicate_type=PREDICATE,
        log=work / "logs/snapshot-admission.log",
        expected_run_id=source_run,
        expected_run_attempt=source_attempt,
    )
    if verified.predicate != value:
        raise AttestationError("verified rollback snapshot predicate differs")
    transaction: dict[str, Any] = json.loads(bounded(work / "transaction.json"))
    if set(transaction) != {"canonical_before", "prior"}:
        raise AttestationError("captured canonical transaction shape differs")
    prior = transaction["prior"]
    if prior is not None and (
        not isinstance(prior, dict)
        or set(prior) != {"tag", "commit", "digest"}
        or prior["digest"] != transaction["canonical_before"]
    ):
        raise AttestationError("captured prior canonical identity differs")
    return transaction
