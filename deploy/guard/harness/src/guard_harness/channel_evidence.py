"""Admit measured documented channel executions against authenticated released bytes."""

import hashlib
import json
from pathlib import Path

from guard_harness.native_release import Release
from guard_harness.testnet_process import ProcessError

REQUIRED = {
    "D1": {
        "manifest-bare-form",
        "website-parameter-form",
        "literal-curl-pipe",
        "interactive-paper-init",
        "installed-binary-readback",
        "paper-allow-resize-veto",
        "uninstall",
        "cleanup",
    },
    "D2": {
        "manifest-bare-form",
        "website-parameter-form",
        "literal-irm-iex",
        "interactive-paper-init",
        "installed-binary-readback",
        "paper-allow-resize-veto",
        "uninstall",
        "cleanup",
    },
    "D5": {
        "manual-release-download",
        "signed-checksums",
        "archive-extract",
        "interactive-paper-init",
        "installed-binary-readback",
        "paper-allow-resize-veto",
        "owned-process-stop",
        "cleanup",
    },
}
TOKENS = {"D1": "D1:curl-pipe", "D2": "D2:irm-iex", "D5": "D5:manual-archive"}


def required(channel: str, target: str) -> set[str]:
    checks = set(REQUIRED[channel])
    if channel == "D1" and target.startswith("darwin-"):
        checks = checks - {"uninstall"} | {"owned-manual-cleanup"}
    return checks


def commands(channel: str, *, canonical: bool = False) -> dict[str, str]:
    url = "https://zunderlabs.com/" + ("i" if canonical else "i-staging")
    if channel == "D1":
        return {
            "manifest-bare": "curl -fsSL " + url + " | sh",
            "website-parameter": "curl -fsSL " + url + " | sh -s -- --network paper",
        }
    if channel == "D2":
        url += ".ps1"
        return {
            "manifest-bare": "irm " + url + " | iex",
            "website-parameter": "& ([scriptblock]::Create((irm " + url + "))) -Network paper",
        }
    raise ProcessError("documented loader channel required")


def admit(path: Path, channel: str, release: Release, target: str) -> str:
    if channel not in REQUIRED or path.is_symlink() or not path.is_file():
        raise ProcessError("regular measured documented channel receipt required")
    value = json.loads(path.read_bytes())
    checks = value.get("coverage")
    if (
        value.get("schema") != 1
        or value.get("result") != "passed"
        or value.get("channel") != channel
        or value.get("scenario") != "fresh"
        or value.get("mode") != "paper"
        or value.get("tag") != release.tag
        or value.get("commit") != release.commit
        or value.get("manifest_sha256")
        != hashlib.sha256(release.asset("release-manifest.json")).hexdigest()
        or value.get("installed_binary_sha256")
        != hashlib.sha256(release.binary(target)).hexdigest()
        or value.get("version") != release.tag.removeprefix("v")
        or value.get("cleanup_complete") is not True
        or not isinstance(checks, list)
        or any(not isinstance(item, str) for item in checks)
        or len(set(checks)) != len(checks)
        or required(channel, target) != set(checks)
    ):
        raise ProcessError("documented channel identity/runtime/cleanup differs")
    if channel in {"D1", "D2"}:
        forms = commands(channel)
        if (
            value.get("command") != forms["manifest-bare"]
            or value.get("loader_sha256")
            != hashlib.sha256(release.asset("i.ps1" if channel == "D2" else "i")).hexdigest()
        ):
            raise ProcessError("literal staged documented loader execution required")
        executions = value.get("executions")
        if not isinstance(executions, list) or len(executions) != len(forms):
            raise ProcessError("both independently executed documented loader forms required")
        for execution, (form, command) in zip(executions, forms.items(), strict=True):
            if (
                not isinstance(execution, dict)
                or execution.get("form") != form
                or execution.get("command") != command
                or execution.get("result") != "passed"
                or execution.get("installed_binary_sha256") != value["installed_binary_sha256"]
                or execution.get("version") != value["version"]
                or execution.get("mode") != "paper"
                or execution.get("account_network") != "testnet"
                or any(
                    execution.get(name) is not True
                    for name in (
                        "health",
                        "paper_roundtrip",
                        "owned_process_stopped",
                        "cleanup_complete",
                    )
                )
            ):
                raise ProcessError("documented loader form runtime/readback/cleanup differs")
            if target.startswith("darwin-") and (
                execution.get("setup_identity") != "runner-user"
                or execution.get("configuration_home") != "user-default"
                or execution.get("cleanup_method") != "owned-manual-cleanup"
            ):
                raise ProcessError("macOS loader must measure the documented user paper path")
            if (
                target.startswith("windows-")
                and execution.get("cleanup_method") != "released-per-user-uninstall"
            ):
                raise ProcessError("Windows documented per-user uninstall required")
            if (
                target.startswith("linux-")
                and execution.get("cleanup_method") != "released-native-uninstall"
            ):
                raise ProcessError("Linux documented native uninstall required")
    else:
        archive = f"zunder-guard-{release.tag}-{target}.tar.gz"
        if value.get("archive_sha256") != hashlib.sha256(release.asset(archive)).hexdigest():
            raise ProcessError("manual archive differs from authenticated release")
    return TOKENS[channel]
