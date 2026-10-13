"""Fail-closed full native row admission; diagnostic receipts never produce predicates."""

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from guard_harness.channel_evidence import admit
from guard_harness.docker_run import _version
from guard_harness.install_evidence import read
from guard_harness.lifecycle_coverage import LIFECYCLE_COVERAGE
from guard_harness.native_paper import LifecycleError
from guard_harness.native_release import Release
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
    "journal-prefix",
    "pairing-retained",
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


def receipt(
    path: Path,
    required: set[str],
    *,
    mode: str,
    scenario: str,
    current: Release,
    previous: Release,
    target: str,
) -> set[str]:
    value = read(path)
    coverage = value.get("coverage")
    if (
        value.get("result") != "passed"
        or not isinstance(coverage, list)
        or any(not isinstance(item, str) for item in coverage)
    ):
        raise LifecycleError("native lifecycle receipt failed/malformed")
    manifest_sha = hashlib.sha256(current.asset("release-manifest.json")).hexdigest()
    releases = (current,) if scenario == "fresh" else (previous, current)
    expected = {
        release.tag: dict(
            commit=release.commit,
            version="zunder-guard " + release.tag.removeprefix("v"),
            binary_sha256=hashlib.sha256(release.binary(target)).hexdigest(),
        )
        for release in releases
    }
    if (
        value.get("schema") != 1
        or value.get("mode") != mode
        or value.get("scenario") != scenario
        or value.get("tag") != current.tag
        or value.get("commit") != current.commit
        or value.get("manifest_sha256") != manifest_sha
        or value.get("observed_releases") != expected
        or len(set(coverage)) != len(coverage)
    ):
        raise LifecycleError("native receipt mode/coverage differs")
    if mode == "testnet" and (
        value.get("no_exchange") is not True
        or not isinstance(value.get("decision_journal_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", value["decision_journal_sha256"]) is None
    ):
        raise LifecycleError("complete durable no-exchange journal evidence required")
    observed = set(coverage)
    if required != observed:
        raise LifecycleError("native lifecycle receipt omits required behaviour")
    return observed


def predicate(
    row: str, evidence: Path, manifest: Path, commit: str, subjects: Path
) -> dict[str, Any]:
    if row not in VARIANTS:
        raise LifecycleError("native row refused")
    inputs = read(subjects / "input.json")
    if (
        inputs.get("commit") != commit
        or inputs.get("harness_commit") != commit
        or inputs.get("diagnostic") is not False
        or inputs.get("loader_channel") != "staging"
    ):
        raise LifecycleError("official native row needs exact released staged source")
    current = Release(inputs["tag"], commit, subjects / "candidate/assets")
    previous = Release(
        inputs["previous_tag"], inputs["previous_commit"], subjects / "previous/assets"
    )
    build_bytes = current.asset("release-manifest.json")
    previous.asset("release-manifest.json")
    if (
        previous.commit == commit
        or _version(previous.tag) >= _version(current.tag)
        or manifest.is_symlink()
        or manifest.read_bytes() != build_bytes
    ):
        raise LifecycleError("native manifest/predecessor differs from authenticated C2")
    build = json.loads(build_bytes)
    validate_build(build, ROOT / "release/manifest.schema.json", expected_commit=commit)
    observed: set[str] = set()
    for variant in sorted(VARIANTS[row]):
        target = "darwin-arm64" if row == "I3" else "windows-amd64"
        for scenario in ("fresh", "upgrade"):
            directory = evidence / variant / scenario
            identity = read(directory / "identities.json")
            if identity != dict(
                diagnostic=False,
                release_commit=commit,
                harness_commit=commit,
                tag=current.tag,
                manifest_sha256=hashlib.sha256(build_bytes).hexdigest(),
                scenario=scenario,
                **(
                    dict(previous_tag=previous.tag, previous_commit=previous.commit)
                    if scenario == "upgrade"
                    else {}
                ),
            ):
                raise LifecycleError("native scenario source/release identity differs")
            paper = PAPER - {"upgrade"}
            testnet = TESTNET - {"upgrade"}
            peruser = PERUSER - {"upgrade", "candidate-loader-stdin"}
            marker = "fresh-candidate" if scenario == "fresh" else "upgrade"
            paper.add(marker)
            testnet.add(marker)
            peruser.update(
                {
                    marker,
                    "candidate-loader-stdin" if scenario == "fresh" else "previous-release-init",
                }
            )
            if row == "I4":
                paper = paper - {"crash-recovery"} | {"manual-crash-restart"}
                from guard_harness.windows_policy import REFUSAL_TOKEN, REMOVAL_TOKEN
                from guard_harness.windows_policy import admit as admit_policy

                testnet.update({REFUSAL_TOKEN, REMOVAL_TOKEN})
                admit_policy(
                    current,
                    directory / "testnet/windows-policy",
                    read(directory / "testnet/testnet.receipt.json"),
                )
            for mode, name, required in (
                ("paper", "paper/paper.receipt.json", paper),
                ("testnet", "testnet/testnet.receipt.json", testnet),
            ):
                observed.update(
                    receipt(
                        directory / name,
                        required,
                        mode=mode,
                        scenario=scenario,
                        current=current,
                        previous=previous,
                        target=target,
                    )
                )
                observed.add(
                    mode
                    + (":fresh-candidate" if scenario == "fresh" else ":previous-release-upgrade")
                )
            if row == "I4":
                receipt(
                    directory / "testnet/per-user/receipt.json",
                    peruser,
                    mode="testnet",
                    scenario=scenario,
                    current=current,
                    previous=previous,
                    target=target,
                )
                observed.add("per-user:credential-manager")
            if scenario == "fresh":
                observed.add(
                    admit(
                        directory / "channels" / ("D1.json" if row == "I3" else "D2.json"),
                        "D1" if row == "I3" else "D2",
                        current,
                        target,
                    )
                )
                if row == "I3":
                    if read(directory / "paper/paper.receipt.json").get("channel_coverage") != [
                        "D3:homebrew"
                    ]:
                        raise LifecycleError("measured fresh Homebrew route required")
                    observed.add("D3:homebrew")
        observed.add(variant)
    # These normalized tokens follow the admitted retained journal/config and actual
    # uninstall measurements above; they are never derived from generic result=passed.
    observed.update({"journal-history", "pairing-retained", "cleanup"})
    if not LIFECYCLE_COVERAGE[row] <= observed:
        raise LifecycleError("native row lacks pinned measured coverage")
    return {
        "schema": 1,
        "journey": row,
        "commit": commit,
        "manifest_sha256": hashlib.sha256(build_bytes).hexdigest(),
        "result": "passed",
        "tier": "e2e",
        "coverage": sorted(LIFECYCLE_COVERAGE[row]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--row", choices=tuple(VARIANTS), required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--subjects", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = predicate(args.row, args.evidence, args.manifest, args.commit, args.subjects)
    args.output.write_text(json.dumps(value) + "\n")


if __name__ == "__main__":
    main()
