"""Read an opaque compare-and-swap token, never release admission evidence."""

import hashlib
import json
import re
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any

from guard_harness.attestation import AttestationError
from guard_harness.publication import USER_AGENT, _NoRedirect

REPOSITORY_API = "https://api.github.com/repos/zunderlabs/zunder-guard"


def _github_object(url: str, *, allow_missing: bool = False) -> dict[str, Any] | None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
        method="GET",
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=30) as response:
            body = response.read(2 * 1024 * 1024 + 1)
            if response.status != 200 or response.geturl() != url or len(body) > 2 * 1024 * 1024:
                raise ValueError()
            value: Any = json.loads(body)
            if not isinstance(value, dict):
                raise ValueError()
            return value
    except urllib.error.HTTPError as error:
        if error.code == 404 and allow_missing:
            return None
        raise AttestationError("public stable release signal unavailable") from None
    except (urllib.error.URLError, OSError, ValueError):
        raise AttestationError("public stable release signal unavailable") from None


def published_stable() -> str | None:
    """C7 public stable publication requires canonical availability from then on.

    This is an independent launch signal, never signed release admission. An API
    404 can mean prelaunch only after the same public repository is positively read.
    Network, rate-limit, redirect and malformed metadata outcomes remain unknown.
    GitHub latest excludes drafts/prereleases; no credential/settings change is used.
    """
    repository = _github_object(REPOSITORY_API)
    if (
        repository is None
        or repository.get("full_name") != "zunderlabs/zunder-guard"
        or repository.get("private") is not False
    ):
        raise AttestationError("public stable release repository identity differs")
    latest = _github_object(REPOSITORY_API + "/releases/latest", allow_missing=True)
    if latest is None:
        return None
    tag, published = latest.get("tag_name"), latest.get("published_at")
    if (
        not isinstance(tag, str)
        or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) is None
        or latest.get("draft") is not False
        or latest.get("prerelease") is not False
        or latest.get("html_url")
        != "https://github.com/zunderlabs/zunder-guard/releases/tag/" + tag
        or not isinstance(published, str)
    ):
        raise AttestationError("public latest stable metadata differs")
    try:
        if datetime.fromisoformat(published.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError()
    except ValueError:
        raise AttestationError("public latest stable publication time differs") from None
    return tag


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
