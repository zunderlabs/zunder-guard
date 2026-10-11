"""C2 v2: immutable build bytes and monotonic, authenticated lifecycle predicates.

Signature/attestation verification belongs to the caller. An expected previous state
must come from the publisher's durable trusted head, not from the incoming request.
"""

import hashlib
import json
from collections.abc import Mapping, Set
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

from guard_harness.manifest import (
    CHANNEL_JOURNEYS,
    IDENTITY_BASE,
    RELEASE_BASE,
    RELEASE_JOURNEYS,
    ManifestError,
)

# V1 remains unchanged; v2 follows the current release programme, including safe mainnet checks.
GATE_JOURNEYS = RELEASE_JOURNEYS | frozenset({"M1", "M2", "M3"})

PREDICATE_TYPE = "https://zunderlabs.com/guard/release-state/v1"
TRANSITIONS: Mapping[str, frozenset[str]] = {
    "staged": frozenset({"gated", "withdrawn"}),
    "gated": frozenset({"promoted", "withdrawn"}),
    "promoted": frozenset({"withdrawn"}),
    "withdrawn": frozenset(),
}


def canonical_bytes(predicate: Mapping[str, Any]) -> bytes:
    return json.dumps(predicate, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def predicate_digest(predicate: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(predicate)).hexdigest()


def _schema(value: Mapping[str, Any], schema: Path) -> None:
    definition = json.loads(schema.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(definition)
    validator = Draft202012Validator(definition, format_checker=FormatChecker())
    errors = list(validator.iter_errors(value))
    if errors:
        raise ManifestError("; ".join(f"{e.json_path}: {e.message}" for e in errors))


def _utc(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ManifestError("timestamp must be a real UTC date-time") from error


def validate_build(build: Mapping[str, Any], schema: Path, *, expected_commit: str) -> None:
    _schema(build, schema)
    if build["commit"] != expected_commit:
        raise ManifestError("build commit differs from release subject")
    tag = build["tag"]
    if tag != f"v{build['version']}":
        raise ManifestError("build tag differs from version")
    if build["signing"]["identity"] != f"{IDENTITY_BASE}@refs/tags/{tag}":
        raise ManifestError("build signer differs from release tag")
    _utc(build["published_at"])
    for name, asset in build["assets"].items():
        if name in {"release-manifest.json", "SHA256SUMS"}:
            raise ManifestError("self-referential asset map")
        if asset["url"] != f"{RELEASE_BASE}/{tag}/{name}":
            raise ManifestError("asset URL differs from release tag or name")
    template = build["distribution"]["aws_template"]["url"]
    parsed = urlsplit(template)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ManifestError("template URL cannot contain credentials or mutable query parameters")
    if not parsed.path.endswith(f"/guard/{tag}/cloudformation.yaml"):
        raise ManifestError("AWS template URL must be versioned")


def validate_state(
    state: Mapping[str, Any],
    build: Mapping[str, Any],
    schema: Path,
    *,
    manifest_sha256: str,
    signer_workflow: str,
    previous: Mapping[str, Any] | None,
    verified_journeys: Set[str] = frozenset(),
) -> None:
    """Validate after cryptographic verification of the build and state's bundle."""
    _schema(state, schema)
    for name in ["version", "tag", "commit"]:
        if state[name] != build[name]:
            raise ManifestError(f"state {name} differs from build")
    if state["manifest_sha256"] != manifest_sha256:
        raise ManifestError("state subject differs from signed build bytes")
    issued_at = _utc(state["issued_at"])
    if previous is None:
        if state["revision"] != 1 or state["previous"] is not None or state["stage"] != "staged":
            raise ManifestError("genesis must be staged revision 1 without a predecessor")
    else:
        if state["revision"] != previous["revision"] + 1:
            raise ManifestError("revision must immediately follow the trusted head")
        if state["previous"] != predicate_digest(previous):
            raise ManifestError("predecessor differs from the trusted head")
        if previous["manifest_sha256"] != manifest_sha256:
            raise ManifestError("predecessor belongs to another build")
        if state["stage"] not in TRANSITIONS[previous["stage"]]:
            raise ManifestError("invalid lifecycle transition")
        if issued_at < _utc(previous["issued_at"]):
            raise ManifestError("revision timestamp moved backwards")
    required_signer = "verify.yml" if state["stage"] in {"staged", "gated"} else "promote.yml"
    if signer_workflow != required_signer:
        raise ManifestError("wrong workflow for lifecycle transition")
    for name, descriptor in build["distribution"].items():
        received = {k: v for k, v in state["channels"][name].items() if k != "status"}
        if received != descriptor:
            raise ManifestError(f"channel {name} differs from signed distribution descriptor")
    _gate(state, verified_journeys)


def _gate(state: Mapping[str, Any], verified: Set[str]) -> None:
    available = verified & set(state["evidence"])
    for name, journeys in CHANNEL_JOURNEYS.items():
        if state["channels"][name]["status"] == "verified" and not journeys <= available:
            raise ManifestError(f"channel {name} lacks verified journeys")
    if state["stage"] in {"staged", "withdrawn"}:
        if any(c["status"] != "unavailable" for c in state["channels"].values()):
            raise ManifestError("staged and withdrawn channels must be unavailable")
    if state["stage"] in {"gated", "promoted"}:
        if not GATE_JOURNEYS <= available:
            raise ManifestError(
                "gate requires every purchase, install, trading and mainnet-check journey"
            )
        if any(c["status"] != "verified" for c in state["channels"].values()):
            raise ManifestError("gate requires every distribution channel")
    if state["stage"] == "promoted" and "-rc." in state["version"]:
        raise ManifestError("release candidate promotion is forbidden")
