"""Publish only the signed formula to the tap's staging branch, with no force update."""

import argparse
import base64
import json
import os
import re
from pathlib import Path
from typing import Any

from guard_harness.runner import run
from guard_harness.staged_subjects import _private
from guard_harness.testnet_run import ROOT, verified_asset

TAP = "zunderlabs/homebrew-tap"


def _sha(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("tap object identity refused")
    return value


class Tap:
    def __init__(self, *, token: str, logs: Path) -> None:
        if not token or any(char.isspace() for char in token):
            raise ValueError("tap credential required")
        self.token, self.logs, self.sequence = token, logs, 0

    def request(self, method: str, endpoint: str, body: dict[str, Any] | None = None) -> Any:
        self.sequence += 1
        argv = ["gh", "api", "--method", method, f"repos/{TAP}/{endpoint}"]
        if body is not None:
            argv += ["--input", "-"]
        env = {name: os.environ[name] for name in ("PATH", "HOME") if name in os.environ}
        env["GH_TOKEN"] = self.token
        result = run(
            argv,
            env=env,
            log=self.logs / f"tap-{self.sequence}.log",
            timeout=45,
            stdin=json.dumps(body).encode() if body is not None else b"",
            secrets=[self.token],
        )
        return json.loads(result.output)


def stage(tap: Tap, formula: bytes, *, tag: str) -> str:
    """Caller authenticates captured formula bytes before supplying a scoped write credential."""
    if (
        not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag)
        or not 0 < len(formula) <= 1024 * 1024
    ):
        raise ValueError("release formula/tag refused")
    # Positive successful inventory, not a failed read interpreted as branch absence.
    branches = tap.request("GET", "branches?per_page=100")
    if not isinstance(branches, list) or not 0 < len(branches) < 100:
        raise ValueError("tap branch inventory incomplete")
    heads: dict[str, str] = {}
    for branch in branches:
        name = branch["name"]
        if not isinstance(name, str) or name in heads:
            raise ValueError("ambiguous tap branch inventory")
        heads[name] = _sha(branch["commit"]["sha"])
    if "main" not in heads:
        raise ValueError("tap main positive control missing")
    head = heads.get("staging", heads["main"])
    old = tap.request("GET", f"git/commits/{head}")
    tree = _sha(old["tree"]["sha"])
    blob = tap.request(
        "POST",
        "git/blobs",
        {
            "encoding": "base64",
            "content": base64.b64encode(formula).decode("ascii"),
        },
    )
    replacement = tap.request(
        "POST",
        "git/trees",
        {
            "base_tree": tree,
            "tree": [
                {
                    "path": "Formula/zunder-guard.rb",
                    "mode": "100644",
                    "type": "blob",
                    "sha": _sha(blob["sha"]),
                }
            ],
        },
    )
    if _sha(replacement["sha"]) == tree and "staging" in heads:
        return head  # An identical staged formula needs no new commit/ref mutation.
    commit = tap.request(
        "POST",
        "git/commits",
        {
            "message": f"Stage zunder-guard {tag}",
            "tree": _sha(replacement["sha"]),
            "parents": [head],
        },
    )
    target = _sha(commit["sha"])
    if "staging" in heads:
        # Competing commits diverge from this parent; force=false refuses their replacement.
        published = tap.request("PATCH", "git/refs/heads/staging", {"sha": target, "force": False})
    else:
        published = tap.request("POST", "git/refs", {"ref": "refs/heads/staging", "sha": target})
    if published.get("ref") != "refs/heads/staging" or _sha(published["object"]["sha"]) != target:
        raise ValueError("tap staging update unconfirmed; reconcile before retry")
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", args.tag) or not re.fullmatch(
        r"[0-9a-f]{40}", args.commit
    ):
        raise ValueError("exact release identity required")
    _private(args.work.parent, directory=True)
    if not args.work.is_absolute() or args.work.exists() or args.work.is_symlink():
        raise ValueError("fresh private stage workspace required")
    args.work.mkdir(mode=0o700)
    env = {name: os.environ[name] for name in ("PATH", "HOME", "GH_TOKEN") if name in os.environ}
    env["GITHUB_REPOSITORY"] = "zunderlabs/zunder-guard"
    previous_mask = os.umask(0o077)
    try:
        run(
            [
                "bash",
                str(ROOT / "github/verify-release-assets.sh"),
                args.tag,
                str(args.work / "assets"),
            ],
            env=env,
            timeout=600,
            log=args.work / "assets.log",
            stdin=b"",
            secrets=[env.get("GH_TOKEN", "")],
        )
        formula, _ = verified_asset(
            args.work / "assets", "zunder-guard.rb", tag=args.tag, commit=args.commit
        )
        target = stage(
            Tap(token=os.environ.get("HOMEBREW_TAP_TOKEN", ""), logs=args.work),
            formula,
            tag=args.tag,
        )
        (args.work / "receipt.json").write_text(
            json.dumps({"tag": args.tag, "commit": args.commit, "staging_commit": target}) + "\n"
        )
    finally:
        os.umask(previous_mask)


if __name__ == "__main__":
    main()
