"""Admit complete signed-template lifecycle and owned cleanup before I7 attestation."""

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from guard_harness.lifecycle_coverage import LIFECYCLE_COVERAGE
from guard_harness.testnet_run import verified_asset

CONTEXT = frozenset({"owned-stack-and-retained-volume-cleanup", "D6:cloudformation"})


def predicate(receipt: dict[str, Any], manifest: bytes, *, tag: str, commit: str) -> dict[str, Any]:
    build = json.loads(manifest)
    coverage = receipt.get("coverage")
    expected = LIFECYCLE_COVERAGE["I7"] - CONTEXT
    launch = receipt.get("template_launch")
    if (
        receipt.get("result") != "passed"
        or receipt.get("cleanup_complete") is not True
        or receipt.get("commit") != commit
        or receipt.get("harness_commit") != commit
        or receipt.get("tag") != tag
        or receipt.get("diagnostic") is not False
        or build.get("commit") != commit
        or build.get("tag") != tag
        or not isinstance(launch, dict)
        or launch.get("stack_create_complete") is not True
        or launch.get("instance_online") is not True
        or not isinstance(launch.get("template_url"), str)
        or not launch["template_url"].startswith("https://")
        or not isinstance(launch.get("template_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", launch["template_sha256"]) is None
        or launch
        != dict(
            channel="cloudformation",
            template_url=build.get("distribution", {}).get("aws_template", {}).get("url"),
            template_sha256=build.get("assets", {}).get("cloudformation.yaml", {}).get("sha256"),
            installer_channel="staging",
            stack_create_complete=True,
            instance_online=True,
        )
        or not isinstance(coverage, list)
        or any(not isinstance(item, str) for item in coverage)
        or len(coverage) != len(expected)
        or set(coverage) != expected
    ):
        raise ValueError("I7 complete lifecycle and owned cleanup required")
    return dict(
        schema=1,
        journey="I7",
        commit=commit,
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        result="passed",
        tier="e2e",
        coverage=sorted(set(coverage) | CONTEXT),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    verified_asset(args.assets, "cloudformation.yaml", tag=args.tag, commit=args.commit)
    value = predicate(
        json.loads((args.work / "aws.receipt.json").read_bytes()),
        (args.assets / "release-manifest.json").read_bytes(),
        tag=args.tag,
        commit=args.commit,
    )
    with (args.work / "I7.predicate.json").open("x", encoding="utf-8") as output:
        output.write(json.dumps(value, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
