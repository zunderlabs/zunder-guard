"""Authenticate captured release bytes before compare-and-swap publication."""

import hashlib
import json
import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from guard_harness.attestation import AttestationError
from guard_harness.journey_evidence import JourneyBundle, authenticate_gate
from guard_harness.release_state import canonical_bytes
from guard_harness.runner import run
from guard_harness.state_verifier import VerifiedState, authenticate_state


@dataclass(frozen=True)
class Publication:
    body: bytes = field(repr=False)
    digest: str


def prepare(
    assets: Path,
    served: Path,
    state_bundle: Path,
    *,
    manifest_schema: Path,
    state_schema: Path,
    commit: str,
    tag: str,
    workflow: str,
    previous: VerifiedState | None,
    expected: str | None,
    journeys: Mapping[str, JourneyBundle],
    logs: Path,
) -> Publication:
    """Snapshot, authenticate, then bind the same bytes into one publication body.

    `previous` is the retained authenticated build head; `expected` is the durable
    channel head. They differ when promoting a new build over an older canonical
    release. Neither comes from an unauthenticated incoming predicate.
    """
    if expected is not None and not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise AttestationError("expected channel head must be a SHA256 digest")
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag):
        raise AttestationError("expected release tag")
    names = ("release-manifest.json", "i", "i.ps1", "SHA256SUMS", "SHA256SUMS.sigstore.json")
    with TemporaryDirectory(prefix="guard-publication-") as directory:
        root = Path(directory)
        for name in names:
            (root / name).write_bytes((assets / name).read_bytes())
            (root / name).chmod(0o444)
        state = root / "state.json"
        state.write_bytes(served.read_bytes())
        bundle = root / "state.sigstore.json"
        bundle.write_bytes(state_bundle.read_bytes())
        run(
            [
                "cosign",
                "verify-blob",
                "--bundle",
                str(root / "SHA256SUMS.sigstore.json"),
                "--certificate-identity",
                f"https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/{tag}",
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                str(root / "SHA256SUMS"),
            ],
            log=logs / "checksums.log",
            timeout=60,
        )
        sums: dict[str, str] = {}
        for line in (root / "SHA256SUMS").read_text().splitlines():
            match = re.fullmatch(r"([0-9a-f]{64}) [ *](\S+)", line)
            if match is None or match[2] in sums:
                raise AttestationError("invalid or duplicate signed checksum entry")
            sums[match[2]] = match[1]
        for name in names[:3]:
            if hashlib.sha256((root / name).read_bytes()).hexdigest() != sums.get(name):
                raise AttestationError("publication bytes differ from signed checksums")
        incoming: Any = json.loads(state.read_bytes())
        if not isinstance(incoming, dict):
            raise AttestationError("release state must be an object")
        if incoming.get("stage") in {"gated", "promoted"}:
            if previous is None:
                raise AttestationError("gate requires an authenticated predecessor")
            verified = authenticate_gate(
                root / names[0],
                state,
                bundle,
                journeys,
                manifest_schema=manifest_schema,
                state_schema=state_schema,
                commit=commit,
                tag=tag,
                workflow=workflow,
                previous=previous,
                logs=logs,
            )
        else:
            if journeys:
                raise AttestationError("non-gated state cannot supply gate evidence")
            verified = authenticate_state(
                root / names[0],
                state,
                bundle,
                manifest_schema=manifest_schema,
                state_schema=state_schema,
                commit=commit,
                tag=tag,
                workflow=workflow,
                previous=previous,
                verified_journeys=frozenset(),
                log=logs / "lifecycle.log",
            )
        build: Any = json.loads((root / names[0]).read_bytes())
        for name in ("i", "i.ps1"):
            if build["assets"].get(name, {}).get("sha256") != sums[name]:
                raise AttestationError("loader differs from immutable build descriptor")
        predicate = canonical_bytes(verified.predicate)
        stage = verified.predicate["stage"]
        channel = "canonical" if stage == "promoted" else "staging"
        if stage == "withdrawn" and previous and previous.predicate["stage"] == "promoted":
            channel = "canonical"
        capsule = {
            "channel": channel,
            "expected": expected,
            "predicate": predicate.decode(),
            "bundle": bundle.read_bytes().decode("utf-8"),
            "unix": (root / "i").read_bytes().decode("utf-8"),
            "windows": (root / "i.ps1").read_bytes().decode("utf-8"),
        }
        body = canonical_bytes(capsule)
        if len(body) > 2 * 1024 * 1024:
            raise AttestationError("publication exceeds Worker request limit")
        return Publication(body, hashlib.sha256(predicate).hexdigest())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


def publish(publication: Publication, *, token: str) -> str:
    """Send only to the fixed TLS endpoint; never log request data or error bodies.

    Do not retry an unknown outcome automatically. Reconcile the durable channel
    head before preparing another publication. A redirect never forwards the token.
    """
    if not token or any(character.isspace() for character in token):
        raise ValueError("publication token is missing or malformed")
    request = urllib.request.Request(
        "https://zunderlabs.com/guard/publish",
        data=publication.body,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=45) as response:
            if response.status != 201:
                raise ValueError()
            receipt = json.loads(response.read(4097))
            if receipt != {"digest": publication.digest}:
                raise ValueError()
    except (urllib.error.URLError, OSError, ValueError):
        raise AttestationError(
            "publication refused or outcome unknown; reconcile durable head"
        ) from None
    return publication.digest
