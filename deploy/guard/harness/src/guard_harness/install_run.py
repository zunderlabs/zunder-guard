"""Drive both Linux install modes from authenticated release snapshots."""

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

from guard_harness.native_release import Release
from guard_harness.testnet_process import ProcessError
from guard_harness.testnet_run import ROOT


def child(
    words: list[str],
    *,
    env: dict[str, str],
    input: bytes = b"",
    stdout: int | None = None,
    check: bool = True,
) -> None:
    """Keep child command arguments out of failure tracebacks."""
    try:
        subprocess.run(words, env=env, input=input, stdout=stdout, check=check)
    except subprocess.CalledProcessError as error:
        raise ProcessError(f"install lifecycle child failed (exit {error.returncode})") from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--row", choices=("I1", "I2", "I6"), required=True)
    parser.add_argument("--subjects", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--paper-account", required=True)
    parser.add_argument("--scenario", choices=("fresh", "upgrade", "both"), default="both")
    args = parser.parse_args()
    profile = os.environ.get("INSTALL_MATRIX_PROFILE", "all")
    if profile not in {"all", "nightly"}:
        raise ProcessError("known install profile required")
    identity = json.loads((args.subjects / "input.json").read_bytes())
    if (
        identity.get("diagnostic") is not False
        or identity.get("harness_commit") != os.environ.get("GITHUB_SHA")
        or (profile == "all" and identity.get("commit") != os.environ.get("GITHUB_SHA"))
    ):
        raise ProcessError("non-diagnostic authenticated harness identity required")
    if os.environ.get("GUARD_C6_SERIALIZED") != "1":
        raise ProcessError("serialized Testnet runtime required")
    framed = os.environ.pop("WALLET_FRAME", "").strip()
    key = framed.removeprefix("0x").encode() + b"\n"
    if args.row == "I2" and args.scenario == "both":
        raise ProcessError("I2 needs independently fresh runners for each explicit scenario")
    if re.fullmatch(rb"[0-9a-fA-F]{64}\n", key) is None:
        raise ProcessError("private framed Testnet key required")
    if not args.output.is_absolute() or args.output.exists():
        raise ProcessError("fresh absolute evidence directory required")
    args.output.mkdir(mode=0o700)
    current = Release(identity["tag"], identity["commit"], args.subjects / "candidate/assets")
    previous = Release(
        identity["previous_tag"], identity["previous_commit"], args.subjects / "previous/assets"
    )
    loader = args.subjects / "i-staging"
    if identity.get("loader_channel") != ("staging" if profile == "all" else "canonical"):
        raise ProcessError("known loader channel required")
    if loader.read_bytes() != current.asset("i"):
        raise ProcessError("loader snapshot differs from signed release")
    old_installer = previous.assets / "install.sh"
    previous.asset("install.sh")
    rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
    common = [
        "--version",
        current.tag,
        "--previous-version",
        previous.tag,
        "--rules",
        rules,
        "--scenario",
        args.scenario,
    ]
    target = "linux-arm64" if args.row == "I2" else "linux-amd64"
    archive_name = f"zunder-guard-{current.tag}-{target}.tar.gz"
    archive_digest = hashlib.sha256(current.asset(archive_name)).hexdigest()
    candidate_binary_digest = hashlib.sha256(current.binary(target)).hexdigest()
    paper_identity = [
        "--release-commit",
        current.commit,
        "--manifest-sha256",
        hashlib.sha256(current.asset("release-manifest.json")).hexdigest(),
        "--binary-sha256",
        candidate_binary_digest,
        "--loader-channel",
        identity["loader_channel"],
        "--archive-sha256",
        archive_digest,
    ]
    env = {
        name: os.environ[name]
        for name in ("PATH", "HOME", "GUARD_C6_SERIALIZED")
        if name in os.environ
    }
    if args.row in {"I1", "I6"}:
        base = [
            sys.executable,
            "-m",
            "guard_harness.linux_guest",
            "--harness-root",
            str(ROOT / "harness"),
            "--candidate",
            str(loader),
            "--previous",
            str(old_installer),
            *common,
        ]
        mode = "container" if args.row == "I6" else "native"
        child(
            [
                *base,
                "--mode",
                mode,
                "--account",
                args.paper_account,
                "--account-network",
                "testnet",
                "--output",
                str(
                    args.output / "paper"
                    if args.scenario == "both"
                    else args.output / "paper" / args.scenario
                ),
                *paper_identity,
                "--candidate-archive",
                str(current.assets / archive_name),
            ],
            check=True,
            env=env,
        )
        target = "linux-amd64"
        testnet = [
            *base,
            "--mode",
            mode,
            "--account",
            args.account,
            "--account-network",
            "testnet",
            "--output",
            str(
                args.output / "testnet"
                if args.scenario == "both"
                else args.output / "testnet" / args.scenario
            ),
            "--testnet-lifecycle",
        ]
        if mode == "container":
            for release, flag in (
                (current, "--release-image"),
                (previous, "--previous-release-image"),
            ):
                build = json.loads(release.asset("release-manifest.json"))
                descriptor = build["distribution"]["docker"]
                testnet.extend([flag, descriptor["image"] + "@" + descriptor["digest"]])
    else:
        marker = secrets.token_hex(16)
        child(
            ["sudo", "tee", "/etc/zunder-native-disposable"],
            input=marker.encode(),
            stdout=subprocess.DEVNULL,
            check=True,
            env=env,
        )
        base = ["sudo", "env", "PYTHONPATH=" + str(ROOT / "harness/src"), sys.executable, "-m"]
        flags = [
            "--installer",
            str(loader),
            "--installer-sha256",
            hashlib.sha256(loader.read_bytes()).hexdigest(),
            "--previous-installer",
            str(old_installer),
            "--previous-installer-sha256",
            hashlib.sha256(previous.asset("install.sh")).hexdigest(),
            *common,
            "--marker",
            marker,
            "--phase",
            "all-no-reboot",
        ]
        child(
            [
                *base,
                "guard_harness.linux_lifecycle",
                *flags,
                "--account",
                args.paper_account,
                "--account-network",
                "testnet",
                "--output",
                str(args.output / "paper" / args.scenario),
                *paper_identity,
                "--archive",
                str(current.assets / archive_name),
            ],
            check=True,
            env=env,
        )
        target = "linux-arm64"
        testnet = [
            *base,
            "guard_harness.linux_testnet_lifecycle",
            *flags,
            "--route",
            "native",
            "--account",
            args.account,
            "--output",
            str(args.output / "testnet" / args.scenario),
        ]
    if args.row in {"I1", "I2"} and args.scenario in {"fresh", "both"}:
        (args.output / "channels").mkdir()
        for channel in ("D1", "D5"):
            source = args.output / "paper/fresh/channels" / (channel + ".json")
            if source.is_symlink() or not source.is_file() or source.stat().st_size > 65536:
                raise ProcessError("actual fresh channel receipt required")
            body = source.read_bytes()
            receipt = json.loads(body)
            if (
                receipt.get("channel") != channel
                or receipt.get("result") != "passed"
                or receipt.get("tag") != current.tag
                or receipt.get("commit") != current.commit
            ):
                raise ProcessError("actual fresh channel identity differs")
            (args.output / "channels" / (channel + ".json")).write_bytes(body)
    testnet.extend(
        [
            "--binary-sha256",
            hashlib.sha256(current.binary(target)).hexdigest(),
            "--previous-binary-sha256",
            hashlib.sha256(previous.binary(target)).hexdigest(),
        ]
    )
    child(testnet, input=key, check=True, env=env)


if __name__ == "__main__":
    main()
