"""Authenticate every release-gate journey against the immutable build manifest."""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import urlsplit

from guard_harness.attestation import AttestationError, verify_predicate
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


def authenticate_journeys(
    manifest: Path,
    bundles: Mapping[str, JourneyBundle],
    *,
    commit: str,
    tag: str,
    logs: Path,
) -> frozenset[str]:
    """Return a complete set only after each bundle passes the official verifier.

    The attestation subject is the immutable manifest, not an arbitrary job artifact.
    Expected signer workflows and minimum tiers are derived from the journey ID.
    Fixture attestations cannot count as E2E. M4 cannot appear in this automated gate.
    """
    if set(bundles) != GATE_JOURNEYS:
        raise AttestationError("gate requires exactly the complete automated journey set")
    for evidence in bundles.values():
        url = urlsplit(evidence.reference)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.fragment
        ):
            raise AttestationError("journey reference must be a public HTTPS URL")
    manifest_bytes = manifest.read_bytes()
    digest = hashlib.sha256(manifest_bytes).hexdigest()
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
            )
            _check(verified.predicate, journey, commit, digest)
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
) -> VerifiedState:
    """Authenticate journey evidence and lifecycle against the same captured bytes."""
    with TemporaryDirectory(prefix="guard-gate-") as directory:
        subject = Path(directory) / "release-manifest.json"
        subject.write_bytes(manifest.read_bytes())
        subject.chmod(0o444)
        journeys = authenticate_journeys(
            subject, journey_bundles, commit=commit, tag=tag, logs=logs
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
        )
    references = {journey: evidence.reference for journey, evidence in journey_bundles.items()}
    if state.predicate["evidence"] != references:
        raise AttestationError("lifecycle references differ from the authenticated journey set")
    if state.predicate["stage"] not in {"gated", "promoted"}:
        raise AttestationError("authenticated gate must be gated or promoted")
    return state
