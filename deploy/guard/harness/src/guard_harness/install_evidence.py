"""Admit complete paper and Testnet install rows from authenticated runtime receipts."""

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from guard_harness.docker_run import _version
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
        or not required <= set(checks)
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
        root = read(evidence / "receipt.json")
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
        if (
            root.get("commit") != commit
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
            raise EvidenceError("Docker runtime subjects/source differ from C2")
        for channel in ("docker", "compose"):
            for mode, required in (("paper", DOCKER_PAPER), ("testnet", DOCKER_TESTNET)):
                value = read(evidence / f"{channel}-{mode}/receipt.json")
                observed.update(completed(value, required, mode=mode))
                if (
                    value.get("channel") != channel
                    or value.get("image") != image
                    or value.get("previous_image") != old_image
                ):
                    raise EvidenceError("Docker lifecycle channel/image differs")
                if mode == "testnet" and value.get("custody") != (
                    "documented-volume" if channel == "docker" else "compose-secret"
                ):
                    raise EvidenceError("documented Testnet container custody required")
                observed.add(f"{channel}-{mode}")
    else:
        loader = subjects / "i-staging"
        if loader.is_symlink() or loader.read_bytes() != current.asset("i"):
            raise EvidenceError("runtime loader differs from authenticated staged bytes")
        route, architecture = ROWS[row]
        for mode, filename, required in (
            ("paper", "linux-lifecycle.json", PAPER),
            ("testnet", "testnet-lifecycle.json", TESTNET),
        ):
            value = read(evidence / mode / filename)
            mode_coverage = completed(value, required, mode=mode)
            observed.update(mode_coverage)
            if (
                value.get("route") != route
                or value.get("architecture") != architecture
                or value.get("version") != current.tag
                or value.get("previous_version") != previous.tag
                or value.get("installer_sha256") != hashlib.sha256(loader.read_bytes()).hexdigest()
                or value.get("previous_installer_sha256")
                != hashlib.sha256(previous.asset("install.sh")).hexdigest()
                or value.get("stage") != "passed"
            ):
                raise EvidenceError("Linux runtime version/route/bytes differ")
            if mode == "testnet" and value.get("custody") != "systemd-creds":
                raise EvidenceError("encrypted systemd Testnet custody required")
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
                    raise EvidenceError("real KVM kernel reboot required for each mode")
            elif value.get("reboot_required") is not False:
                raise EvidenceError("arm64 native restart receipt required")
            observed.add(mode)
    return dict(
        schema=1,
        journey=row,
        commit=commit,
        manifest_sha256=hashlib.sha256(build_bytes).hexdigest(),
        result="passed",
        tier=tier,
        coverage=sorted(observed),
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
