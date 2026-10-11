"""Read an opaque compare-and-swap token, never release admission evidence."""

import hashlib
import json
import urllib.error
import urllib.request
from typing import Any

from guard_harness.attestation import AttestationError
from guard_harness.publication import USER_AGENT, _NoRedirect


def read(channel: str) -> tuple[str | None, dict[str, Any] | None]:
    if channel not in {"staging", "canonical"}:
        raise ValueError("unknown installer channel")
    suffix = "-staging" if channel == "staging" else ""
    request = urllib.request.Request(
        f"https://zunderlabs.com/guard/release{suffix}.json",
        method="GET",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=30) as response:
            body = response.read(65537)
            digest = response.headers.get("x-zunder-state-sha256", "")
            if response.status != 200 or len(body) > 65536:
                raise ValueError()
            if hashlib.sha256(body).hexdigest() != digest:
                raise ValueError()
            predicate: Any = json.loads(body)
            if not isinstance(predicate, dict):
                raise ValueError()
            return digest, predicate
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None, None
        raise AttestationError("installer channel head read failed") from None
    except (urllib.error.URLError, OSError, ValueError):
        raise AttestationError("installer channel head read failed") from None
