"""Compare C5 canonical endpoints with an authenticated publication snapshot.

Call publication.prepare first: readback does not authenticate a caller's capsule.
The caller retains the authenticated promotion chain and complete journey evidence.
One failed attempt is final; scheduling, alerting and rollback belong to the caller.
"""

import hashlib
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

from guard_harness.attestation import AttestationError
from guard_harness.publication import USER_AGENT, Publication, _NoRedirect

ORIGIN = "https://zunderlabs.com"
LIMIT = 2 * 1024 * 1024


@dataclass(frozen=True)
class Response:
    status: int
    digest: str
    body: bytes = field(repr=False)


def fetch(path: str) -> Response:
    """One bounded credential-free GET, with no redirects or retries."""
    if path not in {"/i", "/i.ps1", "/guard/release.json", "/guard/release.json.sigstore"}:
        raise AttestationError("canonical endpoint is outside C5")
    request = urllib.request.Request(
        ORIGIN + path, method="GET", headers={"User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=30) as response:
            body = response.read(LIMIT + 1)
            if len(body) > LIMIT:
                raise ValueError()
            return Response(
                response.status, response.headers.get("x-zunder-state-sha256", ""), body
            )
    except (urllib.error.URLError, OSError, ValueError):
        raise AttestationError("canonical read failed; no automatic retry") from None


def check(publication: Publication, *, read: Callable[[str], Response] = fetch) -> str:
    """Bind both loaders, served state and bundle to the exact authenticated bytes.

    Publication comes from prepare(), never from an unverified response or file.
    Header equality alone cannot prove release admission: each response must equal
    the corresponding bytes authenticated before publication. A changed channel
    between reads fails this attempt, even when the newer release is also valid.
    """
    capsule = json.loads(publication.body)
    state = json.loads(capsule["predicate"])
    if capsule["channel"] != "canonical" or state["stage"] != "promoted":
        raise AttestationError("canonical readback requires an authenticated promotion")
    if hashlib.sha256(capsule["predicate"].encode()).hexdigest() != publication.digest:
        raise AttestationError("publication digest differs from authenticated state bytes")
    for path, field_name in (
        ("/guard/release.json", "predicate"),
        ("/guard/release.json.sigstore", "bundle"),
        ("/i", "unix"),
        ("/i.ps1", "windows"),
    ):
        received = read(path)
        if (
            received.status != 200
            or received.digest != publication.digest
            or received.body != capsule[field_name].encode()
        ):
            raise AttestationError("canonical response differs from authenticated publication")
    return publication.digest
