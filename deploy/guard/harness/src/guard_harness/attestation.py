"""Use gh's Sigstore verifier; never implement certificate verification in the harness."""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guard_harness.runner import run

REPOSITORY = "zunderlabs/zunder-guard"
WORKFLOWS = frozenset(
    {"release.yml", "verify.yml", "promote.yml", "install-matrix.yml", "journey.yml"}
)


class AttestationError(ValueError):
    """Cryptographically verified evidence did not carry the expected statement."""


@dataclass(frozen=True)
class VerifiedPredicate:
    predicate: dict[str, Any]
    workflow: str
    source_commit: str


def verify_predicate(
    subject: Path,
    bundle: Path,
    *,
    workflow: str,
    commit: str,
    tag: str,
    predicate_type: str,
    log: Path,
) -> VerifiedPredicate:
    """Authenticate signer, issuer, hosted runner, source commit and predicate type.

    gh also checks the subject's digest against the file. This function does not
    accept a claimed predicate from an unverified bundle or a caller-provided JSON.
    """
    if workflow not in WORKFLOWS:
        raise AttestationError("untrusted signer workflow")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise AttestationError("expected full public commit")
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag):
        raise AttestationError("expected release tag")
    identity = re.escape(f"https://github.com/{REPOSITORY}/.github/workflows/{workflow}")
    identity += rf"@refs/(?:tags/{re.escape(tag)}|heads/main)$"
    result = run(
        [
            "gh",
            "attestation",
            "verify",
            str(subject),
            "--bundle",
            str(bundle),
            "--repo",
            REPOSITORY,
            # gh makes signer-workflow and certificate identity mutually exclusive.
            # The anchored SAN policy below binds both the workflow and allowed ref.
            "--cert-identity-regex",
            "^" + identity,
            "--cert-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--source-digest",
            commit,
            "--deny-self-hosted-runners",
            "--predicate-type",
            predicate_type,
            "--format",
            "json",
        ],
        log=log,
        timeout=60,
    )
    try:
        results: Any = json.loads(result.output)
    except json.JSONDecodeError as error:
        raise AttestationError("gh verifier returned invalid JSON") from error
    if not isinstance(results, list) or len(results) != 1:
        raise AttestationError("expected exactly one authenticated statement per bundle")
    entry = results[0]
    if not isinstance(entry, dict) or not isinstance(entry.get("verificationResult"), dict):
        raise AttestationError("missing gh verification result")
    statement = entry["verificationResult"].get("statement")
    if not isinstance(statement, dict) or statement.get("predicateType") != predicate_type:
        raise AttestationError("unexpected verified predicate type")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise AttestationError("verified predicate must be an object")
    return VerifiedPredicate(predicate, workflow, commit)
