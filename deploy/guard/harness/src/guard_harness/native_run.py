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
from guard_harness.native_release import Release
from guard_harness.native_testnet import sanitize_logs
from guard_harness.testnet_process import ProcessError
from guard_harness.testnet_scan import TestnetReads, flat_scan


def execute(*, subjects: Path, output: Path, scenario: str, account: str, shell: str) -> None:
    identity = json.loads((subjects / "input.json").read_bytes())
    profile = os.environ.get("INSTALL_MATRIX_PROFILE", "all")
    if (
        scenario not in {"fresh", "upgrade"}
        or profile not in {"all", "nightly"}
        or identity.get("diagnostic") is not False
        or identity.get("harness_commit") != os.environ.get("GITHUB_SHA")
        or (profile == "all" and identity.get("commit") != os.environ.get("GITHUB_SHA"))
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
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ProcessError("fresh absolute native evidence directory required")
    key = os.environ.pop("WALLET_FRAME", "").strip().removeprefix("0x").encode() + b"\n"
    if not re.fullmatch(rb"[0-9a-fA-F]{64}\n", key):
        raise ProcessError("bounded private Testnet frame required")
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
        }
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
            if scenario == "fresh"
            else None
        )
        for mode, frame in (("paper", b""), ("testnet", key)):
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "guard_harness.native_" + mode,
                    *common,
                    "--work",
                    str(output / mode),
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
                dict(
                    diagnostic=False,
                    release_commit=current.commit,
                    harness_commit=os.environ["GITHUB_SHA"],
                    tag=current.tag,
                    manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                    scenario=scenario,
                    **(
                        dict(previous_tag=previous.tag, previous_commit=previous.commit)
                        if scenario == "upgrade"
                        else {}
                    ),
                )
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
