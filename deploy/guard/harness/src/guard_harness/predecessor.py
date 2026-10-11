"""Select a published predecessor dynamically; its assets are authenticated by consumers."""

import argparse
import json
import os
import re
from pathlib import Path

from guard_harness.runner import run


def select(tag: str, work: Path) -> tuple[str, str]:
    pattern = r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?"
    if not re.fullmatch(pattern, tag):
        raise ValueError("release tag required")
    result = run(
        ["gh", "api", "repos/zunderlabs/zunder-guard/releases?per_page=100"],
        log=work / "predecessor-list.log",
        timeout=60,
    )
    releases = json.loads(result.output)
    current = [row for row in releases if row.get("tag_name") == tag and row.get("draft") is False]
    if len(current) != 1 or not isinstance(current[0].get("published_at"), str):
        raise ValueError("assembled candidate publication missing")
    candidates = [
        row
        for row in releases
        if row.get("draft") is False
        and isinstance(row.get("tag_name"), str)
        and re.fullmatch(pattern, row["tag_name"])
        and row["tag_name"] != tag
        and isinstance(row.get("published_at"), str)
        and row["published_at"] < current[0]["published_at"]
    ]
    if not candidates:
        raise ValueError("published predecessor missing")
    previous = max(candidates, key=lambda row: row["published_at"])["tag_name"]
    commit = json.loads(
        run(
            ["gh", "api", "repos/zunderlabs/zunder-guard/commits/" + previous],
            log=work / "predecessor-commit.log",
            timeout=60,
        ).output
    )["sha"]
    if not isinstance(commit, str) or not re.fullmatch("[0-9a-f]{40}", commit):
        raise ValueError("predecessor full commit missing")
    return previous, commit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    tag, commit = select(args.tag, args.work)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(f"previous_tag={tag}\nprevious_commit={commit}\n")


if __name__ == "__main__":
    main()
