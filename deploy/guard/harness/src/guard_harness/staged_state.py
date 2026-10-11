"""Authenticate an assembled release and produce its unavailable C2 staged genesis."""

import argparse
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from guard_harness.release_state import canonical_bytes, validate_build, validate_state
from guard_harness.runner import run
from guard_harness.staged_subjects import _private
from guard_harness.testnet_run import ROOT, verified_asset


def genesis(manifest: bytes, *, commit: str, issued_at: str) -> dict[str, Any]:
    """Pure transformation; caller must authenticate these original manifest bytes."""
    build = json.loads(manifest)
    validate_build(build, ROOT / "release/manifest.schema.json", expected_commit=commit)
    state = {
        "schema": 2,
        "version": build["version"],
        "tag": build["tag"],
        "commit": commit,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "revision": 1,
        "previous": None,
        "issued_at": issued_at,
        "stage": "staged",
        "channels": {
            name: dict(descriptor, status="unavailable")
            for name, descriptor in build["distribution"].items()
        },
        "evidence": {},
    }
    validate_state(
        state,
        build,
        ROOT / "release/state.schema.json",
        manifest_sha256=state["manifest_sha256"],
        signer_workflow="verify.yml",
        previous=None,
    )
    return state


def execute(*, tag: str, commit: str, work: Path) -> None:
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag) or not re.fullmatch(
        r"[0-9a-f]{40}", commit
    ):
        raise ValueError("exact release identity required")
    _private(work.parent, directory=True)
    if not work.is_absolute() or work.exists() or work.is_symlink():
        raise ValueError("fresh private staging workspace required")
    work.mkdir(mode=0o700)
    old_mask = os.umask(0o077)
    try:
        env = {
            name: os.environ[name]
            for name in ("PATH", "HOME", "GH_TOKEN", "GITHUB_TOKEN")
            if name in os.environ
        }
        env["GITHUB_REPOSITORY"] = "zunderlabs/zunder-guard"
        run(
            ["bash", str(ROOT / "github/verify-release-assets.sh"), tag, str(work / "assets")],
            env=env,
            log=work / "assets.log",
            timeout=600,
            stdin=b"",
            secrets=[env.get("GH_TOKEN", ""), env.get("GITHUB_TOKEN", "")],
        )
        # Bind the signed loader and capture the build digest through the existing C2
        # verifier. A saved marker or caller-supplied manifest never skips admission.
        _, digest = verified_asset(work / "assets", "i", tag=tag, commit=commit)
        manifest = (work / "assets/release-manifest.json").read_bytes()
        if hashlib.sha256(manifest).hexdigest() != digest:
            raise ValueError("staged manifest changed after authentication")
        state = genesis(
            manifest, commit=commit, issued_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        with (work / "staged.predicate.json").open("xb") as stream:
            stream.write(canonical_bytes(state))
    finally:
        os.umask(old_mask)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--work", type=Path, required=True)
    execute(**vars(parser.parse_args()))


if __name__ == "__main__":
    main()
