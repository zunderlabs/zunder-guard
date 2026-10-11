"""Fail-closed full native row admission; diagnostic receipts never produce predicates."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from guard_harness.native_paper import LifecycleError
from guard_harness.release_state import validate_build
from guard_harness.testnet_run import ROOT

VARIANTS = {
    "I3": {"macos"},
    "I4": {"windows2022-ps51", "windows2022-ps7", "windows2025-ps51", "windows2025-ps7"},
}
PAPER = {
    "install",
    "init",
    "pair",
    "health",
    "paper-allow-resize-veto",
    "restart",
    "crash-recovery",
    "upgrade",
    "reinstall",
    "old-client-signature-after-upgrade",
    "uninstall",
    "documented-data-retained",
}
TESTNET = {
    "signed-release",
    "native-custody-readback",
    "health",
    "restart",
    "crash-recovery",
    "supervisor-reload",
    "upgrade",
    "reinstall",
    "pairing-config-retained",
    "journal-prefix",
    "uninstall",
    "no-exchange",
}
PERUSER = {
    "credential-manager",
    "candidate-loader-stdin",
    "stored-key-runtime",
    "read-only-health",
    "restart",
    "upgrade",
    "reinstall",
    "uninstall",
    "no-exchange",
}


def receipt(path: Path, required: set[str], *, mode: str) -> set[str]:
    value = json.loads(path.read_bytes())
    coverage = value.get("coverage")
    if (
        value.get("result") != "passed"
        or not isinstance(coverage, list)
        or any(not isinstance(item, str) for item in coverage)
    ):
        raise LifecycleError("native lifecycle receipt failed/malformed")
    if value.get("mode") != mode or len(set(coverage)) != len(coverage):
        raise LifecycleError("native receipt mode/coverage differs")
    observed = set(coverage)
    if not required <= observed:
        raise LifecycleError("native lifecycle receipt omits required behaviour")
    return observed


def predicate(row: str, evidence: Path, manifest: Path, commit: str) -> dict[str, Any]:
    if row not in VARIANTS:
        raise LifecycleError("native row refused")
    build_bytes = manifest.read_bytes()
    build = json.loads(build_bytes)
    validate_build(build, ROOT / "release/manifest.schema.json", expected_commit=commit)
    observed: set[str] = set()
    for variant in sorted(VARIANTS[row]):
        directory = evidence / variant
        identity = json.loads((directory / "identities.json").read_bytes())
        if (
            identity.get("diagnostic") is not False
            or identity.get("release_commit") != commit
            or identity.get("harness_commit") != commit
        ):
            raise LifecycleError(
                "diagnostic or another-source native result cannot enter release gate"
            )
        observed.update(receipt(directory / "paper/paper.receipt.json", PAPER, mode="paper"))
        observed.update(
            receipt(directory / "testnet/testnet.receipt.json", TESTNET, mode="testnet")
        )
        if row == "I4":
            observed.update(
                receipt(directory / "testnet/per-user/receipt.json", PERUSER, mode="testnet")
            )
        observed.add(variant)
    return {
        "schema": 1,
        "journey": row,
        "commit": commit,
        "manifest_sha256": hashlib.sha256(build_bytes).hexdigest(),
        "result": "passed",
        "tier": "e2e",
        "coverage": sorted(observed),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--row", choices=tuple(VARIANTS), required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = predicate(args.row, args.evidence, args.manifest, args.commit)
    args.output.write_text(json.dumps(value) + "\n")


if __name__ == "__main__":
    main()
