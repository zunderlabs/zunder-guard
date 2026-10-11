"""Read-only promoted-release admission and the single C5 failure alert seam."""

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from guard_harness.attestation import AttestationError
from guard_harness.native_release import authenticate
from guard_harness.predecessor import select
from guard_harness.publication import USER_AGENT, _NoRedirect
from guard_harness.release_state import canonical_bytes

ALERT_URL = "https://zunderlabs.com/api/licence/monitor/alert"


def alert(*, token: str, check: str, run_url: str) -> None:
    """One bounded alert POST; no redirect, response body logging or retry."""
    if (
        not token
        or any(character.isspace() for character in token)
        or not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", check)
        or not re.fullmatch(
            r"https://github.com/zunderlabs/zunder-guard/actions/runs/[1-9][0-9]*"
            r"(?:/attempts/[1-9][0-9]*)?",
            run_url,
        )
    ):
        raise AttestationError("C5 alert frame refused")
    request = urllib.request.Request(
        ALERT_URL,
        method="POST",
        headers={
            "User-Agent": USER_AGENT,
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        data=canonical_bytes({"check": check, "run_url": run_url}),
    )
    try:
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=30) as response:
            body = response.read(4097)
            if (
                response.status != 202
                or len(body) > 4096
                or json.loads(body)
                != {
                    "ok": True,
                    "sent": True,
                }
            ):
                raise ValueError()
    except (OSError, urllib.error.URLError, ValueError):
        raise AttestationError("C5 email alert refused or outcome unknown; no retry") from None


def admitted(
    work: Path, *, tag: str | None = None, commit: str | None = None, previous: bool = False
) -> dict[str, Any]:
    """Resolve metadata only after canonical complete-gate admission and readback."""
    # Import lazily: alert delivery does not require any release/network authentication.
    from guard_harness.promotion import admitted_canonical

    if (tag is None) != (commit is None):
        raise AttestationError("expected tag and source must be supplied together")
    if not work.is_absolute() or work.exists():
        raise AttestationError("fresh absolute monitor workspace required")
    release, capsule = admitted_canonical(work)
    digest = capsule.digest
    if tag is not None and (release.tag != tag or release.commit != commit):
        raise AttestationError("requested release differs from authenticated promoted head")
    values: dict[str, Any] = {
        "tag": release.tag,
        "commit": release.commit,
        "state_sha256": digest,
        "complete_gate_authenticated": True,
        "canonical_readback": True,
    }
    if previous:
        old_tag, old_commit = select(release.tag, work)
        older = authenticate(old_tag, old_commit, work / "upgrade-predecessor")
        values.update(previous_tag=older.tag, previous_commit=older.commit)
    (work / "receipt.json").write_bytes(canonical_bytes(values))
    (work / "receipt.json").chmod(0o600)
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--work", type=Path)
    parser.add_argument("--previous", action="store_true")
    parser.add_argument("--alert", action="store_true")
    parser.add_argument("--check", default="P9.monitor")
    parser.add_argument("--run-url", default="")
    args = parser.parse_args()
    old_mask = os.umask(0o077)
    try:
        if args.alert:
            token = os.environ.pop("MONITOR_ALERT_TOKEN", "")
            alert(token=token, check=args.check, run_url=args.run_url)
        else:
            if args.work is None:
                raise AttestationError("monitor workspace is required")
            values = admitted(args.work, tag=args.tag, commit=args.commit, previous=args.previous)
            target = os.environ.get("GITHUB_OUTPUT")
            if target:
                with Path(target).open("a") as stream:
                    for key in ("tag", "commit", "previous_tag", "previous_commit"):
                        if key in values:
                            stream.write(f"{key}={values[key]}\n")
    except (AttestationError, OSError, ValueError, RuntimeError):
        # Remote certificate, HTTP and subprocess exceptions can contain opaque
        # response data. The private workspace holds diagnostics; stdout does not.
        raise SystemExit("monitor admission or alert failed; inspect bounded diagnostics") from None
    finally:
        os.umask(old_mask)


if __name__ == "__main__":
    main()
