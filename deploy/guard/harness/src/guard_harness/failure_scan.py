"""Bounded independent keyless C6 postfailure observation; never repairs exposure."""

import argparse
import json
import os
from pathlib import Path
from typing import Any

from guard_harness.staged_subjects import _private
from guard_harness.testnet_scan import SCAN_TIMEOUT, ScanError, TestnetReads, flat_scan


def observe(work: Path, account: str) -> None:
    if not work.is_absolute() or work.exists() or work.is_symlink():
        raise ScanError("fresh absolute postfailure observation required")
    work.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private(work.parent, directory=True)
    values: dict[str, Any] = {"flat": False, "network": "testnet", "repair_attempted": False}
    passed = False
    try:
        values["scan"] = flat_scan(TestnetReads(timeout=SCAN_TIMEOUT), account)
        values["flat"] = passed = True
    finally:
        descriptor = os.open(work, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(values, stream)
            stream.write("\n")
    if not passed:
        raise ScanError("failed journey exposure unknown; human review required")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    try:
        observe(args.work, os.environ["E2E_ACCOUNT"])
    except (Exception, KeyboardInterrupt):
        raise SystemExit("C6 postfailure flat scan incomplete; human review required") from None


if __name__ == "__main__":
    main()
