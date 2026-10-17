"""Use gh's Sigstore verifier; never implement certificate verification in the harness."""

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guard_harness.runner import run

REPOSITORY = "zunderlabs/zunder-guard"
WORKFLOWS = frozenset(
    {"release.yml", "verify.yml", "promote.yml", "install-matrix.yml", "journey.yml"}
)
# Written once per job by deploy/guard/github/fetch-trusted-root.sh (bounded retry):
# gh's JSONL holds every Sigstore instance gh trusts; cosign takes exactly one
# TrustedRoot, the public-good instance, derived from the same fetch.
GH_TRUSTED_ROOT = "trusted_root.jsonl"
COSIGN_TRUSTED_ROOT = "trusted_root.json"
TRUSTED_ROOT_MEDIA = "application/vnd.dev.sigstore.trustedroot+json"
TRUSTED_ROOT_LIMIT = 1024 * 1024


class AttestationError(ValueError):
    """Cryptographically verified evidence did not carry the expected statement."""


@dataclass(frozen=True)
class TrustedRoots:
    gh: Path
    cosign: Path


def _root_object(text: str) -> dict[str, Any]:
    try:
        value: Any = json.loads(text)
    except json.JSONDecodeError as error:
        raise AttestationError("fetched Sigstore trusted root is not JSON") from error
    if not isinstance(value, dict):
        raise AttestationError("fetched Sigstore trusted root must be an object")
    media = value.get("mediaType")
    if not isinstance(media, str) or not media.startswith(TRUSTED_ROOT_MEDIA):
        raise AttestationError("fetched Sigstore trusted root has an unexpected type")
    return value


def trusted_roots() -> TrustedRoots | None:
    """The job's pre-fetched Sigstore trust roots, or None to let gh/cosign fetch them.

    Absent files keep the verifiers' own network fetch (local runs, unit tests). A
    partial or malformed pair is refused, never silently replaced by a network fetch.
    The roots only replace the transport: every verification still checks signer,
    issuer, subject and transparency evidence against them, exactly once.
    """
    temp = os.environ.get("RUNNER_TEMP")
    if not temp:
        return None
    gh = Path(temp) / GH_TRUSTED_ROOT
    cosign = Path(temp) / COSIGN_TRUSTED_ROOT
    present = [path.exists() or path.is_symlink() for path in (gh, cosign)]
    if not any(present):
        return None
    if not all(present):
        raise AttestationError("Sigstore trusted root was fetched incompletely")
    texts = []
    for path in (gh, cosign):
        if path.is_symlink() or not path.is_file():
            raise AttestationError("Sigstore trusted root must be a regular file")
        if path.stat().st_size > TRUSTED_ROOT_LIMIT:
            raise AttestationError("Sigstore trusted root exceeds its size limit")
        texts.append(path.read_text(encoding="utf-8"))
    lines = [_root_object(line) for line in texts[0].splitlines() if line.strip()]
    public = _root_object(texts[1])
    if not lines or lines.count(public) != 1:
        raise AttestationError("cosign trusted root is not exactly one fetched gh root")
    return TrustedRoots(gh, cosign)


def gh_trust_arguments() -> list[str]:
    roots = trusted_roots()
    return [] if roots is None else ["--custom-trusted-root", str(roots.gh)]


def cosign_trust_arguments() -> list[str]:
    roots = trusted_roots()
    return [] if roots is None else ["--trusted-root", str(roots.cosign)]


@dataclass(frozen=True)
class VerifiedPredicate:
    predicate: dict[str, Any]
    workflow: str
    source_commit: str
    invocation_uri: str = ""
    run_id: str = ""
    run_attempt: str = ""


def invocation_run(uri: str) -> tuple[str, str]:
    """Canonical public invocation identity, never an artifact-name or predicate claim."""
    match = re.fullmatch(
        re.escape(f"https://github.com/{REPOSITORY}/actions/runs/")
        + r"([1-9][0-9]*)/attempts/([1-9][0-9]*)",
        uri,
    )
    if match is None:
        raise AttestationError("expected exact public HTTPS workflow invocation URI")
    return match.group(1), match.group(2)


def expected_invocation(run_id: str | None, attempt: str | None) -> tuple[str, str] | None:
    if run_id is None and attempt is None:
        return None
    if (
        not isinstance(run_id, str)
        or not isinstance(attempt, str)
        or re.fullmatch(r"[1-9][0-9]*", run_id) is None
        or re.fullmatch(r"[1-9][0-9]*", attempt) is None
    ):
        raise AttestationError("expected run and attempt must be paired canonical positive IDs")
    return run_id, attempt


def verify_predicate(
    subject: Path,
    bundle: Path,
    *,
    workflow: str,
    commit: str,
    tag: str,
    predicate_type: str,
    log: Path,
    expected_run_id: str | None = None,
    expected_run_attempt: str | None = None,
    latest_run_attempt: str | None = None,
) -> VerifiedPredicate:
    """Authenticate signer, issuer, hosted runner, source commit and predicate type.

    gh also checks the subject's digest against the file. This function does not
    accept a claimed predicate from an unverified bundle or a caller-provided JSON.
    `expected_run_attempt` binds one exact attempt. `latest_run_attempt` instead admits
    any attempt up to it within `expected_run_id`, for a consumer that does not know
    which earlier attempt of its own run produced the bundle; never both.
    """
    if latest_run_attempt is not None:
        if expected_run_attempt is not None:
            raise AttestationError("exact and latest expected attempts are exclusive")
        ceiling = expected_invocation(expected_run_id, latest_run_attempt)
        expected = None
    else:
        ceiling = None
        expected = expected_invocation(expected_run_id, expected_run_attempt)
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
            *gh_trust_arguments(),
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
    # gh documents signature.certificate as authenticated OIDC metadata. Predicate
    # invocation claims and raw bundle/certificate bytes are never fallback sources.
    signature = entry["verificationResult"].get("signature")
    certificate = signature.get("certificate") if isinstance(signature, dict) else None
    uri = certificate.get("runInvocationURI") if isinstance(certificate, dict) else None
    if not isinstance(uri, str):
        raise AttestationError("verified certificate invocation URI missing")
    run_id, attempt = invocation_run(uri)
    if expected is not None and (run_id, attempt) != expected:
        raise AttestationError(
            "authenticated workflow run or attempt differs from expected invocation"
        )
    if ceiling is not None and (run_id != ceiling[0] or int(attempt) > int(ceiling[1])):
        raise AttestationError(
            "authenticated workflow run differs or its attempt follows the expected one"
        )
    return VerifiedPredicate(predicate, workflow, commit, uri, run_id, attempt)
