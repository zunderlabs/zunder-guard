"""Admit complete signed-template lifecycle and owned cleanup before I7 attestation."""

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from guard_harness.lifecycle_coverage import LIFECYCLE_COVERAGE
from guard_harness.native_release import Release
from guard_harness.staged_subjects import _private
from guard_harness.testnet_run import verified_asset

CONTEXT = frozenset({"owned-stack-and-retained-volume-cleanup", "D6:cloudformation"})


def admitted_manifest(assets: Path, work: Path, *, tag: str, commit: str) -> bytes:
    """Snapshot public artifact bytes privately without modifying the shared source."""
    _private(work, directory=True)
    if not assets.is_absolute() or ".." in assets.parts:
        raise ValueError("absolute public release snapshot required")
    with TemporaryDirectory(prefix="aws-evidence-", dir=work) as temporary:
        private = Path(temporary)
        for name, limit in (
            (".verified-release-source.json", 256),
            ("SHA256SUMS", 65536),
            ("release-manifest.json", 65536),
            ("cloudformation.yaml", 1024 * 1024),
        ):
            source = assets / name
            for parent in source.parents:
                info = parent.lstat()
                sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid not in (0, os.geteuid())
                    or (info.st_mode & 0o022 and not sticky_root)
                ):
                    raise ValueError("public snapshot ancestor refused")
            descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o022
                or not 0 < info.st_size <= limit
            ):
                os.close(descriptor)
                raise ValueError("public snapshot file refused")
            with os.fdopen(descriptor, "rb") as stream:
                body = stream.read(limit + 1)
            if not 0 < len(body) <= limit:
                raise ValueError("public snapshot size refused")
            with (private / name).open("xb") as output:
                os.chmod(output.name, 0o600)
                output.write(body)
        # Same-run subjects carry the authenticated public source marker; the
        # private verifier's stricter custody boundary is retained independently.
        release = Release(tag, commit, private)
        release.asset("cloudformation.yaml")
        verified_asset(private, "cloudformation.yaml", tag=tag, commit=commit)
        return release.asset("release-manifest.json")


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
    manifest = admitted_manifest(args.assets, args.work, tag=args.tag, commit=args.commit)
    value = predicate(
        json.loads((args.work / "aws.receipt.json").read_bytes()),
        manifest,
        tag=args.tag,
        commit=args.commit,
    )
    with (args.work / "I7.predicate.json").open("x", encoding="utf-8") as output:
        output.write(json.dumps(value, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
