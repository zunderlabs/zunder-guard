"""Run one real native fresh or upgrade scenario, with private Testnet stdin only."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from guard_harness.native_channels import execute as channel_execute
from guard_harness.native_release import Release, diagnostic_mode
from guard_harness.native_testnet import sanitize_logs
from guard_harness.source_installer import prepare, verify_file
from guard_harness.testnet_process import ProcessError
from guard_harness.testnet_scan import TestnetReads, flat_scan


def execute(*, subjects: Path, output: Path, scenario: str, account: str, shell: str) -> None:
    diagnostic = diagnostic_mode()
    identity = json.loads((subjects / "input.json").read_bytes())
    if not isinstance(identity, dict):
        raise ProcessError("authenticated subject identity object required")
    profile = os.environ.get("INSTALL_MATRIX_PROFILE", "all")
    harness_commit = os.environ.get("GITHUB_SHA", "")
    if (
        scenario not in {"fresh", "upgrade"}
        or profile not in {"all", "nightly"}
        or (diagnostic and profile != "all")
        or identity.get("diagnostic") is not diagnostic
        or re.fullmatch(r"[0-9a-f]{40}", harness_commit) is None
        or identity.get("harness_commit") != harness_commit
        or (profile == "all" and not diagnostic and identity.get("commit") != harness_commit)
        or identity.get("loader_channel") != ("canonical" if profile == "nightly" else "staging")
        or os.environ.get("GUARD_C6_SERIALIZED") != "1"
    ):
        raise ProcessError("authenticated serialized native scenario required")
    current = Release(identity["tag"], identity["commit"], subjects / "candidate/assets")
    previous = Release(
        identity["previous_tag"], identity["previous_commit"], subjects / "previous/assets"
    )
    manifest = current.asset("release-manifest.json")
    previous.asset("release-manifest.json")
    source = prepare(current.tag, current.commit, scenario=scenario, row="I3")
    if source is not None and sys.platform != "darwin":
        raise ProcessError("source installer component is Mac-only on native runners")
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ProcessError("fresh absolute native evidence directory required")
    source_path = None
    if source is not None:
        output.mkdir(mode=0o700)
        source_path = source.stage(output)
        verify_file(source_path, source.digest)
    key = os.environ.pop("WALLET_FRAME", "").strip().removeprefix("0x").encode() + b"\n"
    if not re.fullmatch(rb"[0-9a-fA-F]{64}\n", key):
        raise ProcessError("bounded private Testnet frame required")
    if source is None:
        output.mkdir(mode=0o700)
    clean = {
        name: value
        for name, value in os.environ.items()
        if name
        in {
            "PATH",
            "HOME",
            "USERPROFILE",
            "LOCALAPPDATA",
            "ProgramData",
            "ProgramFiles",
            "SystemRoot",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "LANG",
            "GITHUB_ACTIONS",
            "RUNNER_ENVIRONMENT",
            "INSTALL_MATRIX_PROFILE",
            "DIAGNOSTIC",
        }
        or (
            source is not None
            and name
            in {
                "SOURCE_INSTALLER_DIAGNOSTIC",
                "GITHUB_SHA",
                "WORKFLOW_REF",
                "CALLER_REF",
                "CALLER_EVENT",
                "CALLER_REPOSITORY",
                "CALLER_SHA",
                "INSTALL_MATRIX_TARGET",
                "SCENARIO",
            }
        )
    }
    common = [
        "--tag",
        current.tag,
        "--commit",
        current.commit,
        "--previous-tag",
        previous.tag,
        "--previous-commit",
        previous.commit,
        "--account",
        account,
        "--assets",
        str(subjects),
        "--shell",
        shell,
        "--scenario",
        scenario,
    ]

    def flat() -> None:
        flat_scan(TestnetReads(), account)

    try:
        flat()
        channel = (
            channel_execute(current, output / "channel-runtime", account=account, shell=shell)
            if scenario == "fresh" and source is None
            else None
        )
        modes = (("testnet", key),) if source is not None else (("paper", b""), ("testnet", key))
        for mode, frame in modes:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "guard_harness.native_" + mode,
                    *common,
                    "--work",
                    str(output / mode),
                    *(["--source-installer", str(source_path)] if source_path is not None else []),
                ],
                input=frame,
                check=True,
                env=clean,
            )
        if channel is not None:
            if channel["channel"] == "D1":
                subprocess.run(
                    [
                        "sudo",
                        "-n",
                        "/bin/sh",
                        "-c",
                        '[ ! -e "$1" ] && [ ! -L "$1" ]',
                        "channel-cleanup",
                        "/usr/local/bin/zunder-guard",
                    ],
                    input=b"",
                    check=True,
                    env=clean,
                )
                channel["cleanup_complete"] = True
            (output / "channels").mkdir()
            (output / "channels" / (channel["channel"] + ".json")).write_text(
                json.dumps(channel) + "\n"
            )
        (output / "identities.json").write_text(
            json.dumps(
                {
                    "diagnostic": diagnostic,
                    **({"gate_eligible": False} if diagnostic else {}),
                    "release_commit": current.commit,
                    "harness_commit": os.environ["GITHUB_SHA"],
                    "tag": current.tag,
                    "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                    "scenario": scenario,
                    **(source.record() if source is not None else {}),
                    **(
                        dict(previous_tag=previous.tag, previous_commit=previous.commit)
                        if scenario == "upgrade"
                        else {}
                    ),
                }
            )
            + "\n"
        )
    except (subprocess.SubprocessError, OSError):
        raise ProcessError("native lifecycle child failed; inspect sanitized diagnostics") from None
    finally:
        sanitize_logs(output, key)
        flat()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subjects", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", choices=("fresh", "upgrade"), required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--shell", default="powershell.exe")
    execute(**vars(parser.parse_args()))


if __name__ == "__main__":
    main()
