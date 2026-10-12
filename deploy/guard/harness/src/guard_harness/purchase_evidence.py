"""Admit purchase coverage only from exact executed successful browser scenarios."""

import argparse
import json
from pathlib import Path
from typing import Any

from guard_harness.attestation import AttestationError
from guard_harness.purchase_coverage import TITLES
from guard_harness.release_state import canonical_bytes
from guard_harness.testnet_run import verified_asset


def measured(row: str, proof: dict[str, Any]) -> list[str]:
    if row not in TITLES or set(proof) != {"status", "tests"} or proof["status"] != "passed":
        raise AttestationError("purchase execution proof refused")
    tests = proof["tests"]
    if not isinstance(tests, list) or any(
        not isinstance(test, dict)
        or set(test) != {"title", "status"}
        or test["status"] != "passed"
        or not isinstance(test["title"], str)
        for test in tests
    ):
        raise AttestationError("purchase scenario skipped, failed or malformed")
    titles = [test["title"] for test in tests]
    if len(titles) != len(set(titles)) or set(titles) != TITLES[row]:
        raise AttestationError("purchase executed scenario set differs")
    return sorted(titles)


def record(root: Path, *, row: str, tag: str, commit: str) -> None:
    _, digest = verified_asset(root / "assets", "install.sh", tag=tag, commit=commit)
    coverage = measured(row, json.loads((root / "browser-proof.json").read_bytes()))
    if row in {"P1", "P2", "P3", "P6"}:
        receipt = json.loads((root / row / "licensed/licence-receipt.json").read_bytes())
        if (
            receipt.get("commit") != commit
            or receipt.get("manifest_sha256") != digest
            or receipt.get("journey") != row
            or receipt.get("licensed") is not True
            or receipt.get("fee_free") is not True
            or receipt.get("mode") != "paper"
            or receipt.get("service_stopped") is not True
            or (row == "P6" and receipt.get("auto_updated") is not True)
        ):
            raise AttestationError("released-byte licence proof differs")
    predicate = dict(
        schema=1,
        journey=row,
        commit=commit,
        manifest_sha256=digest,
        result="passed",
        tier="e2e",
        coverage=coverage,
    )
    (root / "predicate.json").write_bytes(canonical_bytes(predicate))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    for key in ("row", "tag", "commit"):
        parser.add_argument("--" + key, required=True)
    args = parser.parse_args()
    record(args.work, row=args.row, tag=args.tag, commit=args.commit)


if __name__ == "__main__":
    main()
