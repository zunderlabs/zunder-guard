"""Withdraw first canonical OCI latest through an empty index, preserving release digests."""

import base64
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from guard_harness.attestation import AttestationError
from guard_harness.publication import USER_AGENT, _NoRedirect
from guard_harness.release_state import canonical_bytes


def sentinel(manifest_sha256: str, state_sha256: str) -> bytes:
    if any(
        re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (manifest_sha256, state_sha256)
    ):
        raise AttestationError("exact signed promotion identities required for OCI withdrawal")
    return canonical_bytes(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [],
            "annotations": {
                "com.zunderlabs.guard.withdrawn.manifest-sha256": manifest_sha256,
                "com.zunderlabs.guard.withdrawn.state-sha256": state_sha256,
            },
        }
    )


def body_digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


TOKEN_URL = (
    "https://ghcr.io/token?service=ghcr.io&scope=repository:zunderlabs/zunder-guard:pull,push"
)


def put_sentinel(body: bytes, *, reference: str) -> None:
    """Only a captured withdrawal digest or latest may receive the empty index."""
    digest = body_digest(body)
    parsed = json.loads(body)
    annotations = parsed.get("annotations", {})
    if body != sentinel(
        annotations.get("com.zunderlabs.guard.withdrawn.manifest-sha256", ""),
        annotations.get("com.zunderlabs.guard.withdrawn.state-sha256", ""),
    ):
        raise AttestationError("OCI withdrawal index bytes malformed")
    if reference not in {digest, "latest"}:
        raise AttestationError("OCI withdrawal target is not owned by this promotion")
    from guard_harness.promotion_channels import image_digest

    token = os.environ.get("GH_TOKEN", "")
    actor = os.environ.get("GITHUB_ACTOR", "")
    if not actor or not token or any(char in actor for char in ":\r\n"):
        raise AttestationError("scoped registry job credential required")
    opener = urllib.request.build_opener(_NoRedirect())
    authorization = base64.b64encode((actor + ":" + token).encode()).decode()
    try:
        request = urllib.request.Request(
            TOKEN_URL, headers={"User-Agent": USER_AGENT, "Authorization": "Basic " + authorization}
        )
        with opener.open(request, timeout=45) as response:
            payload = response.read(65537)
            if response.status != 200 or len(payload) > 65536:
                raise ValueError()
            bearer = json.loads(payload).get("token")
            if not isinstance(bearer, str) or not bearer or any(char.isspace() for char in bearer):
                raise ValueError()
        request = urllib.request.Request(
            "https://ghcr.io/v2/zunderlabs/zunder-guard/manifests/" + reference,
            method="PUT",
            data=body,
            headers={
                "User-Agent": USER_AGENT,
                "Authorization": "Bearer " + bearer,
                "Content-Type": "application/vnd.oci.image.index.v1+json",
            },
        )
        with opener.open(request, timeout=45) as response:
            if response.status != 201 or response.headers.get("docker-content-digest") != digest:
                raise ValueError()
    except (OSError, urllib.error.URLError, ValueError):
        # A possibly committed PUT is reconciled by one exact read, never repeated.
        if image_digest(reference) != digest:
            raise AttestationError(
                "OCI empty-index withdrawal refused or outcome unknown"
            ) from None
    if image_digest(reference) != digest:
        raise AttestationError("OCI empty-index withdrawal readback differs")


def prepare_sentinel(body: bytes, *, original: str) -> None:
    from guard_harness.promotion_channels import image_digest

    if image_digest(original) != original:
        raise AttestationError("immutable released image is absent")
    put_sentinel(body, reference=body_digest(body))
    if image_digest(original) != original:
        raise AttestationError("immutable release changed during withdrawal preflight")


def withdraw_latest(*, original: str, body: bytes, log: Path) -> None:
    from guard_harness.promotion_channels import image_digest

    digest = body_digest(body)
    if image_digest(original) != original or image_digest("latest") not in {original, digest}:
        raise AttestationError("OCI withdrawal identities differ from this promotion")
    put_sentinel(body, reference="latest")
    if image_digest(original) != original:
        raise AttestationError("immutable released image changed during withdrawal")
    env = {key: os.environ[key] for key in ("PATH", "HOME", "DOCKER_CONFIG") if key in os.environ}
    result = subprocess.run(
        ["docker", "pull", "--platform", "linux/amd64", "ghcr.io/zunderlabs/zunder-guard:latest"],
        capture_output=True,
        timeout=180,
        env=env,
    )
    output = (result.stdout + result.stderr).decode(errors="replace")[-65536:]
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(output.replace(os.environ.get("GH_TOKEN", "") or "\x00", "[REDACTED]"))
    if result.returncode == 0 or not any(
        literal in output.lower() for literal in ("no matching manifest", "no match for platform")
    ):
        raise AttestationError("withdrawn OCI latest did not produce the expected platform refusal")
