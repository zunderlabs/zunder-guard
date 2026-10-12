"""Bind an environment-scoped S3 publisher to the authenticated build descriptor."""

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any


def validate(
    build: dict[str, Any], *, tag: str, role: str, bucket: str, region: str, base: str
) -> None:
    if (
        not role
        or re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag) is None
        or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) is None
        or re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-\d", region) is None
    ):
        raise ValueError("Environment-scoped template publishing configuration required")
    suffix = f"/guard/{tag}/cloudformation.yaml"
    expected = f"https://{bucket}.s3.{region}.amazonaws.com{suffix}"
    if (
        build.get("tag") != tag
        or expected != base.rstrip("/") + suffix
        or expected != build.get("distribution", {}).get("aws_template", {}).get("url")
    ):
        raise ValueError(
            "Template publishing target differs from the signed distribution descriptor"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    args = parser.parse_args()
    try:
        validate(
            json.loads((args.assets / "release-manifest.json").read_bytes()),
            tag=os.environ.get("TAG", ""),
            role=os.environ.get("ROLE", ""),
            bucket=os.environ.get("BUCKET", ""),
            region=os.environ.get("REGION", ""),
            base=os.environ.get("BASE", ""),
        )
    except (OSError, ValueError, TypeError, AttributeError):
        raise SystemExit(
            "Template publication configuration does not match authenticated release"
        ) from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
