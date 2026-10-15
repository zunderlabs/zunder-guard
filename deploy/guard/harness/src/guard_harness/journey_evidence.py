"""Authenticate every release-gate journey against the immutable build manifest."""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from guard_harness.attestation import (
    AttestationError,
    expected_invocation,
    invocation_run,
    verify_predicate,
)
from guard_harness.lifecycle_coverage import LIFECYCLE_COVERAGE
from guard_harness.purchase_coverage import PURCHASE_COVERAGE
from guard_harness.release_state import GATE_JOURNEYS
from guard_harness.state_verifier import VerifiedState, authenticate_state

PREDICATE_TYPE = "https://zunderlabs.com/guard/journey/v1"
MAINNET_COVERAGE: Mapping[str, frozenset[str]] = {
    "M1": frozenset(
        {
            "linux-systemd",
            "linux-container-native",
            "macos-launchdaemon",
            "homebrew-foreground",
            "windows-scm",
            "aws-template",
        }
    ),
    "M2": frozenset(
        {
            "missing-consent",
            "wrong-account-consent",
            "plain-key-file",
            "missing-credential-store",
            "key-file-option",
            "environment-key",
            "plain-docker",
            "compose",
            "homebrew-services",
            "windows-per-user",
        }
    ),
    "M3": frozenset({"sdk-vectors", "key-wrappers", "testnet-order-path"}),
}
JOURNEY_COVERAGE: Mapping[str, frozenset[str]] = {
    **MAINNET_COVERAGE,
    **LIFECYCLE_COVERAGE,
    **PURCHASE_COVERAGE,
    "T1": frozenset({"signed-release", "protected-entry", "owned-cleanup", "all-dex-flat"}),
    "T2": frozenset({"signed-release", "protected-entry", "owned-cleanup", "all-dex-flat"}),
    "P8": frozenset(
        {
            "signed-release",
            "protected-entry",
            "owned-cleanup",
            "all-dex-flat",
            "staging-approve",
            "testnet-owner-approval",
            "guard-builder-wire",
            "actual-builder-fee",
        }
    ),
}


@dataclass(frozen=True)
class JourneyBundle:
    bundle: Path
    reference: str


def _check(predicate: dict[str, Any], journey: str, commit: str, digest: str) -> None:
    if set(predicate) != {
        "schema",
        "journey",
        "commit",
        "manifest_sha256",
        "result",
        "tier",
        "coverage",
    }:
        raise AttestationError("journey predicate fields differ from the contract")
    if type(predicate["schema"]) is not int or predicate["schema"] != 1:
        raise AttestationError("unexpected journey predicate schema")
    if predicate["journey"] != journey or predicate["commit"] != commit:
        raise AttestationError("journey predicate identifies another row or commit")
    if predicate["manifest_sha256"] != digest:
        raise AttestationError("journey predicate identifies other build bytes")
    if predicate["result"] != "passed":
        raise AttestationError("journey did not pass")
    tiers = {"guest", "e2e"} if journey in {"I1", "I6", "M1"} else {"e2e"}
    if not isinstance(predicate["tier"], str) or predicate["tier"] not in tiers:
        raise AttestationError("journey tier is below the release requirement")
    coverage = predicate["coverage"]
    if not isinstance(coverage, list) or any(not isinstance(item, str) for item in coverage):
        raise AttestationError("journey coverage must be a string list")
    if len(set(coverage)) != len(coverage):
        raise AttestationError("journey coverage contains duplicate checks")
    if journey in MAINNET_COVERAGE and set(coverage) != MAINNET_COVERAGE[journey]:
        raise AttestationError("mainnet coverage omits or changes a required check")
    if journey in LIFECYCLE_COVERAGE and set(coverage) != LIFECYCLE_COVERAGE[journey]:
        raise AttestationError("install coverage omits or changes a required check")
    if journey == "P8" and set(coverage) != JOURNEY_COVERAGE[journey]:
        raise AttestationError("builder approval coverage omits or changes a required check")
    if journey not in JOURNEY_COVERAGE or not JOURNEY_COVERAGE[journey] <= set(coverage):
        raise AttestationError("journey coverage omits measured required checks")
    if journey in {"I1", "I6"} and predicate["tier"] != "guest":
        raise AttestationError("Linux reboot rows require actual guest evidence")


def journey_attempts(bundles: Mapping[str, JourneyBundle]) -> tuple[str, dict[str, str]]:
    """One workflow run; each row's own attempt (rows may come from different attempts)."""
    identities = {
        journey: invocation_run(evidence.reference) for journey, evidence in bundles.items()
    }
    runs = {run_id for run_id, _ in identities.values()}
    if len(runs) != 1:
        raise AttestationError("journey references must identify one exact workflow run")
    return next(iter(runs)), {journey: attempt for journey, (_, attempt) in identities.items()}


def authenticate_journeys(
    manifest: Path,
    bundles: Mapping[str, JourneyBundle],
    *,
    commit: str,
    tag: str,
    logs: Path,
    expected_run_id: str | None = None,
    latest_run_attempt: str | None = None,
    coverage_out: dict[str, frozenset[str]] | None = None,
) -> frozenset[str]:
    """Return a complete set only after each bundle passes the official verifier.

    The attestation subject is the immutable manifest, not an arbitrary job artifact.
    Expected signer workflows and minimum tiers are derived from the journey ID.
    Fixture attestations cannot count as E2E. M4 cannot appear in this automated gate.
    Every row belongs to one workflow run; each row's signature must carry exactly the
    attempt its reference names, which may not follow `latest_run_attempt` (decision
    of 15 Oct 2026: each row's latest attempt within the run).
    """
    if set(bundles) != GATE_JOURNEYS:
        raise AttestationError("gate requires exactly the complete automated journey set")
    run_id, attempts = journey_attempts(bundles)
    expected = expected_invocation(expected_run_id, latest_run_attempt)
    if expected is not None and (
        run_id != expected[0] or any(int(k) > int(expected[1]) for k in attempts.values())
    ):
        raise AttestationError("journey references identify a different requested run or attempt")
    manifest_bytes = manifest.read_bytes()
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    authenticated_coverage: dict[str, frozenset[str]] = {}
    with TemporaryDirectory(prefix="guard-evidence-") as directory:
        subject = Path(directory) / "release-manifest.json"
        subject.write_bytes(manifest_bytes)
        subject.chmod(0o444)
        for journey in sorted(GATE_JOURNEYS):
            # Snapshot the bundle too; the caller's download paths remain replaceable.
            bundle = Path(directory) / f"{journey}.sigstore.json"
            bundle.write_bytes(bundles[journey].bundle.read_bytes())
            bundle.chmod(0o444)
            workflow = (
                "install-matrix.yml"
                if journey.startswith("I") or journey in {"M1", "M2"}
                else "journey.yml"
            )
            verified = verify_predicate(
                subject,
                bundle,
                workflow=workflow,
                commit=commit,
                tag=tag,
                predicate_type=PREDICATE_TYPE,
                log=logs / f"{journey}.log",
                expected_run_id=run_id,
                expected_run_attempt=attempts[journey],
            )
            _check(verified.predicate, journey, commit, digest)
            authenticated_coverage[journey] = frozenset(verified.predicate["coverage"])
    if coverage_out is not None:
        coverage_out.update(authenticated_coverage)
    return GATE_JOURNEYS


def authenticate_gate(
    manifest: Path,
    served: Path,
    state_bundle: Path,
    journey_bundles: Mapping[str, JourneyBundle],
    *,
    manifest_schema: Path,
    state_schema: Path,
    commit: str,
    tag: str,
    workflow: str,
    previous: VerifiedState,
    logs: Path,
    expected_run_id: str | None = None,
    expected_run_attempt: str | None = None,
) -> VerifiedState:
    """Authenticate journey evidence and lifecycle against the same captured bytes.

    A `verify.yml` (staged or gated) state is bound to the gate's exact run and attempt,
    which every journey row's attempt must not follow. Promotion is a separate
    invocation; its rows still share one run and carry their own signed attempts.
    """
    if (
        workflow == "verify.yml"
        and expected_invocation(expected_run_id, expected_run_attempt) is None
    ):
        raise AttestationError("gated state requires the gate's exact run and attempt")
    with TemporaryDirectory(prefix="guard-gate-") as directory:
        subject = Path(directory) / "release-manifest.json"
        subject.write_bytes(manifest.read_bytes())
        subject.chmod(0o444)
        journeys = authenticate_journeys(
            subject,
            journey_bundles,
            commit=commit,
            tag=tag,
            logs=logs,
            expected_run_id=expected_run_id,
            latest_run_attempt=expected_run_attempt,
        )
        state = authenticate_state(
            subject,
            served,
            state_bundle,
            manifest_schema=manifest_schema,
            state_schema=state_schema,
            commit=commit,
            tag=tag,
            workflow=workflow,
            previous=previous,
            verified_journeys=journeys,
            log=logs / "lifecycle.log",
            # Promotion is a separate invocation; verify staged/gated belongs to
            # the same verified caller run as its journey attestations.
            expected_run_id=expected_run_id if workflow == "verify.yml" else None,
            expected_run_attempt=expected_run_attempt if workflow == "verify.yml" else None,
        )
    references = {journey: evidence.reference for journey, evidence in journey_bundles.items()}
    if state.predicate["evidence"] != references:
        raise AttestationError("lifecycle references differ from the authenticated journey set")
    if state.predicate["stage"] not in {"gated", "promoted"}:
        raise AttestationError("authenticated gate must be gated or promoted")
    return state
