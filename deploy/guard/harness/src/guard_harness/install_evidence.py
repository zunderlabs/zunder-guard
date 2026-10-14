"""Admit complete paper and Testnet install rows from authenticated runtime receipts."""

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from guard_harness import linux_policy
from guard_harness.channel_evidence import admit
from guard_harness.docker_run import _version
from guard_harness.lifecycle_coverage import LIFECYCLE_COVERAGE
from guard_harness.native_release import Release
from guard_harness.release_state import validate_build
from guard_harness.testnet_run import ROOT

ROWS = {"I1": ("native", "amd64"), "I2": ("native", "arm64"), "I6": ("container", "amd64")}
PAPER = {
    "install",
    "health",
    "pair",
    "paper-allow-resize-veto",
    "restart",
    "crash-recovery",
    "journal-history",
    "upgrade",
    "reinstall",
    "state-retained",
    "pairing-retained",
    "uninstall",
    "cleanup",
    "paper-post-upgrade-allow-resize-veto",
}
TESTNET = {
    "install",
    "native-custody-readback",
    "health",
    "restart",
    "crash-recovery",
    "journal-history",
    "upgrade",
    "reinstall",
    "state-retained",
    "pairing-retained",
    "uninstall",
    "cleanup",
    "no-exchange",
    "daemon-reload",
    "all-dex-flat",
}
DOCKER_PAPER = {
    "init",
    "pair",
    "health",
    "veto",
    "allow",
    "resize",
    "restart",
    "journal",
    "crash-recovery",
    "crash-journal",
    "upgrade",
    "upgrade-journal",
    "upgrade-pairing",
    "reinstall",
    "reinstall-journal",
    "reinstall-pairing",
    "cleanup",
}
DOCKER_TESTNET = {
    "init",
    "custody-readback",
    "health",
    "restart",
    "crash-recovery",
    "journal-history",
    "upgrade",
    "reinstall",
    "pairing-retained",
    "uninstall",
    "cleanup",
    "no-exchange",
}


class EvidenceError(ValueError):
    """A complete released-byte install row was not observed."""


def read(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError("regular runtime receipt required")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise EvidenceError("runtime receipt object required")
    return value


def completed(value: dict[str, Any], required: set[str], *, mode: str) -> set[str]:
    checks = value.get("coverage", value.get("checks"))
    if (
        value.get("schema") != 1
        or value.get("result") != "passed"
        or value.get("mode") != mode
        or not isinstance(checks, list)
        or any(not isinstance(item, str) for item in checks)
        or len(set(checks)) != len(checks)
        or required != set(checks)
        or any(
            value.get(name) is not True
            for name in (
                "cleanup_complete",
                "state_preserved",
                "pairing_preserved",
                "journal_preserved",
            )
        )
    ):
        raise EvidenceError("complete mode lifecycle, history and cleanup required")
    if mode == "testnet" and value.get("no_exchange") is not True:
        raise EvidenceError("Testnet lifecycle must execute no exchange requests")
    return set(checks)


def predicate(
    row: str, evidence: Path, subjects: Path, manifest: Path, commit: str
) -> dict[str, Any]:
    if row not in {*ROWS, "I5"}:
        raise EvidenceError("install row refused")
    identity = read(subjects / "input.json")
    if (
        identity.get("commit") != commit
        or identity.get("harness_commit") != commit
        or identity.get("diagnostic") is not False
    ):
        raise EvidenceError("released source and harness identity differ")
    if identity.get("loader_channel") != "staging":
        raise EvidenceError("official install admission requires staging loader")
    current = Release(identity["tag"], commit, subjects / "candidate/assets")
    previous = Release(
        identity["previous_tag"], identity["previous_commit"], subjects / "previous/assets"
    )
    build_bytes = current.asset("release-manifest.json")
    if manifest.is_symlink() or manifest.read_bytes() != build_bytes:
        raise EvidenceError("attestation manifest differs from authenticated C2")
    build = json.loads(build_bytes)
    validate_build(build, ROOT / "release/manifest.schema.json", expected_commit=commit)
    if previous.commit == commit or _version(previous.tag) >= _version(current.tag):
        raise EvidenceError("distinct authenticated predecessor required")
    previous.asset("release-manifest.json")
    observed: set[str] = set()
    tier = "guest" if row in {"I1", "I6"} else "e2e"
    if row == "I5":
        image = (
            build["distribution"]["docker"]["image"]
            + "@"
            + build["distribution"]["docker"]["digest"]
        )
        old_build = json.loads(previous.asset("release-manifest.json"))
        old_image = (
            old_build["distribution"]["docker"]["image"]
            + "@"
            + old_build["distribution"]["docker"]["digest"]
        )
        expected_previous = {
            "tag": previous.tag,
            "commit": previous.commit,
            "manifest_sha256": hashlib.sha256(previous.asset("release-manifest.json")).hexdigest(),
            "image": old_image,
        }
        for channel in ("docker", "compose"):
            for scenario in ("fresh", "upgrade"):
                root = read(evidence / scenario / channel / "receipt.json")
                if (
                    root.get("scenario") != scenario
                    or root.get("channel") != channel
                    or root.get("commit") != commit
                    or root.get("tag") != current.tag
                    or root.get("manifest_sha256") != hashlib.sha256(build_bytes).hexdigest()
                    or root.get("harness_commit") != commit
                    or root.get("diagnostic") is not False
                    or root.get("image") != image
                    or image == old_image
                    or root.get("compose_sha256")
                    != hashlib.sha256(current.asset("compose.yaml")).hexdigest()
                    or root.get("previous_release") != expected_previous
                ):
                    raise EvidenceError("Docker runtime subjects/source/scenario differ from C2")
                for mode, base in (("paper", DOCKER_PAPER), ("testnet", DOCKER_TESTNET)):
                    required = (
                        base
                        if scenario == "upgrade"
                        else base - {"upgrade", "upgrade-journal", "upgrade-pairing"}
                        | {"fresh-candidate-" + mode}
                    )
                    value = read(evidence / mode / scenario / channel / "receipt.json")
                    observed.update(completed(value, required, mode=mode))
                    if (
                        value.get("scenario") != scenario
                        or value.get("channel") != channel
                        or value.get("image") != image
                        or value.get("initial_image")
                        != (image if scenario == "fresh" else old_image)
                        or value.get("initial_version")
                        != (current.tag if scenario == "fresh" else previous.tag).removeprefix("v")
                        or value.get("previous_image")
                        != (None if scenario == "fresh" else old_image)
                    ):
                        raise EvidenceError("Docker lifecycle fresh/upgrade channel/image differs")
                    if mode == "testnet" and (
                        value.get("custody")
                        != ("documented-volume" if channel == "docker" else "compose-secret")
                        or not isinstance(value.get("decision_journal_sha256"), str)
                        or re.fullmatch(r"[0-9a-f]{64}", value["decision_journal_sha256"]) is None
                    ):
                        raise EvidenceError("documented Testnet container custody/journal required")
                    observed.add(
                        mode
                        + (
                            ":fresh-candidate"
                            if scenario == "fresh"
                            else ":previous-release-upgrade"
                        )
                    )
            observed.add("D4:" + channel)
        # Actual container deletion/volume cleanup and old-pair journal checks are
        # required above; normalize their row tokens only after all four executions.
        observed.update({"uninstall", "journal-history", "pairing-retained"})
    else:
        loader = subjects / "i-staging"
        if loader.is_symlink() or loader.read_bytes() != current.asset("i"):
            raise EvidenceError("runtime loader differs from authenticated staged bytes")
        route, architecture = ROWS[row]
        for mode, filename, base in (
            ("paper", "linux-lifecycle.json", PAPER),
            ("testnet", "testnet-lifecycle.json", TESTNET),
        ):
            for scenario in ("fresh", "upgrade"):
                required = (
                    base
                    if scenario == "upgrade"
                    else base - {"upgrade", "paper-post-upgrade-allow-resize-veto"}
                    | {"fresh-candidate-" + mode}
                )
                if row == "I6" and mode == "testnet":
                    required |= {
                        "uninstall-live-stop",
                        "uninstall-transaction-refusal",
                        "owned-software-inventory",
                    }
                value = read(evidence / mode / scenario / filename)
                if row in {"I1", "I6"}:
                    required = required | {"kernel-reboot"}
                mode_coverage = completed(value, required, mode=mode)
                if scenario == "fresh" and any(
                    value.get(key) is not None
                    for key in ("previous_binary_sha256", "previous_image")
                ):
                    raise EvidenceError(
                        "fresh lifecycle cannot claim unmeasured predecessor runtime"
                    )
                if row == "I6" and mode == "testnet":
                    inventory = value.get("owned_software_inventory")
                    if (
                        not isinstance(inventory, dict)
                        or len(inventory) < 6
                        or any(
                            not isinstance(name, str)
                            or not name.startswith(
                                (
                                    "/usr/local/libexec/zunder-guard-container/",
                                    "/etc/systemd/system/zunder-guard-",
                                )
                            )
                            or not isinstance(digest, str)
                            or not (digest == "directory" or re.fullmatch(r"[0-9a-f]{64}", digest))
                            for name, digest in inventory.items()
                            if name != "/usr/local/libexec/zunder-guard-container"
                        )
                    ):
                        raise EvidenceError(
                            "complete measured owned container software inventory required"
                        )
                observed.update(mode_coverage)
                initial = current if scenario == "fresh" else previous
                initial_hash = hashlib.sha256(
                    loader.read_bytes() if scenario == "fresh" else previous.asset("install.sh")
                ).hexdigest()
                if (
                    value.get("route") != route
                    or value.get("architecture") != architecture
                    or value.get("version") != current.tag
                    or value.get("previous_version") != previous.tag
                    or value.get("scenario") != scenario
                    or value.get("initial_release")
                    != dict(version=initial.tag, installer_sha256=initial_hash)
                    or value.get("installer_sha256")
                    != hashlib.sha256(loader.read_bytes()).hexdigest()
                    or value.get("previous_installer_sha256")
                    != hashlib.sha256(previous.asset("install.sh")).hexdigest()
                    or value.get("stage") != "passed"
                ):
                    raise EvidenceError("Linux fresh/upgrade runtime version/route/bytes differ")
                if mode == "testnet" and (
                    value.get("custody") != "systemd-creds"
                    or value.get("exchange_requests") != 0
                    or value.get("exchange_evidence") != "complete-durable-decision-journal"
                ):
                    raise EvidenceError(
                        "encrypted systemd Testnet custody and no-exchange journal required"
                    )
                if row in {"I1", "I2"} and mode == "testnet":
                    directory = evidence / mode / scenario
                    if any(
                        key in value for key in ("opt_policy", "linux_opt_receipt_sha256")
                    ) or any(
                        (directory / name).exists() or (directory / name).is_symlink()
                        for name in linux_policy.RECEIPTS
                    ):
                        linux_policy.admit(current, "linux-" + architecture, directory, value)
                if route == "native":
                    target = "linux-" + architecture
                    if (
                        value.get("binary_sha256")
                        != hashlib.sha256(current.binary(target)).hexdigest()
                    ):
                        raise EvidenceError("actual installed native binary differs from C2")
                    if mode == "testnet" and (
                        value.get("previous_binary_sha256")
                        != (
                            None
                            if scenario == "fresh"
                            else hashlib.sha256(previous.binary(target)).hexdigest()
                        )
                        or value.get("runtime_identity_evidence") != "native-file-sha256"
                    ):
                        raise EvidenceError("native Testnet predecessor identity differs")
                else:
                    old_build = json.loads(previous.asset("release-manifest.json"))
                    image = (
                        build["distribution"]["docker"]["image"]
                        + "@"
                        + build["distribution"]["docker"]["digest"]
                    )
                    old_image = (
                        old_build["distribution"]["docker"]["image"]
                        + "@"
                        + old_build["distribution"]["docker"]["digest"]
                    )
                    if value.get("image") != image or value.get("installer_route") != (
                        (
                            "curl -fsSL https://zunderlabs.com/i-staging | sh -s -- "
                            "--container --network paper"
                        )
                        if scenario == "fresh" and mode == "paper"
                        else "sh <authenticated-loader> --container --network " + mode
                    ):
                        raise EvidenceError("actual managed container image/entry route differs")
                    if mode == "paper" and value.get("initial_image") != (
                        image if scenario == "fresh" else old_image
                    ):
                        raise EvidenceError("managed paper initial image differs")
                    if mode == "testnet" and (
                        value.get("previous_image") != (None if scenario == "fresh" else old_image)
                        or value.get("runtime_identity_evidence")
                        != "signed-immutable-prebuilt-image"
                    ):
                        raise EvidenceError("managed Testnet image evidence differs")
                if row in {"I1", "I6"}:
                    if (
                        value.get("guest_acceleration") != "kvm"
                        or value.get("gate_eligible") is not True
                        or value.get("reboot_required") is not True
                        or "kernel-reboot" not in mode_coverage
                        or value.get("boot_id") == value.get("reboot_boot_id")
                        or any(
                            not isinstance(value.get(key), str)
                            or not re.fullmatch(
                                r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value[key]
                            )
                            for key in ("boot_id", "reboot_boot_id")
                        )
                    ):
                        raise EvidenceError(
                            "real KVM kernel reboot required for every scenario/mode"
                        )
                    observed.add(mode + ":kernel-reboot")
                elif value.get("reboot_required") is not False:
                    raise EvidenceError("arm64 native restart receipt required")
                observed.add(
                    mode
                    + (":fresh-candidate" if scenario == "fresh" else ":previous-release-upgrade")
                )
        if row in {"I1", "I2"}:
            target = "linux-" + architecture
            observed.add(admit(evidence / "channels/D1.json", "D1", current, target))
            if row == "I1":
                observed.add(admit(evidence / "channels/D5.json", "D5", current, target))
        else:
            if read(evidence / "paper/fresh/linux-lifecycle.json").get("channel_coverage") != [
                "D7:container-native"
            ]:
                raise EvidenceError("measured literal managed container entry route required")
            observed.add("D7:container-native")
    if not LIFECYCLE_COVERAGE[row] <= observed:
        raise EvidenceError("install row lacks pinned measured coverage")
    return dict(
        schema=1,
        journey=row,
        commit=commit,
        manifest_sha256=hashlib.sha256(build_bytes).hexdigest(),
        result="passed",
        tier=tier,
        coverage=sorted(LIFECYCLE_COVERAGE[row]),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--row", choices=(*ROWS, "I5"), required=True)
    for name in ("evidence", "subjects", "manifest", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(predicate(args.row, args.evidence, args.subjects, args.manifest, args.commit))
        + "\n"
    )


if __name__ == "__main__":
    main()
