"""Drive both Linux install modes from authenticated release snapshots."""

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from pathlib import Path

from guard_harness.native_release import Release, diagnostic_mode
from guard_harness.testnet_process import ProcessError
from guard_harness.testnet_run import ROOT

I2_PRIVATE = Path("/root/.guard-install-I2")
EVIDENCE_FILES = (
    "linux-lifecycle.json",
    "testnet-lifecycle.json",
    "channels/D1.json",
    "channels/D5.json",
    "status.log",
    "service-journal.log",
    "testnet-service-install.log",
)


def receipt_identifier(value: object) -> bool:
    if isinstance(value, str):
        return re.search(r"0x[0-9a-f]{40,64}\b", value, re.IGNORECASE) is not None
    if isinstance(value, list):
        return any(receipt_identifier(item) for item in value)
    if isinstance(value, dict):
        return any(receipt_identifier(item) for item in (*value.keys(), *value.values()))
    return False


def evidence_payload(source: Path) -> dict[str, str]:
    """Read only fixed evidence files, leaving root custody and permissions untouched."""
    payload = {}
    for name in EVIDENCE_FILES:
        path = source / name
        for ancestor in (path.parent, *path.parent.parents):
            if ancestor.is_symlink():
                raise ProcessError("evidence ancestor is a symlink")
            if ancestor.exists():
                info = ancestor.stat()
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    # Shared ancestors such as /tmp are allowed only outside the source.
                    if ancestor == source or source in ancestor.parents:
                        raise ProcessError("untrusted evidence directory")
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            continue
        except OSError:
            raise ProcessError("unsafe evidence file") from None
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or info.st_size > 65536
        ):
            os.close(descriptor)
            raise ProcessError("unsafe evidence file")
        with os.fdopen(descriptor, "rb") as stream:
            body = stream.read(65537).decode("utf-8")
        if len(body.encode()) > 65536:
            raise ProcessError("evidence file exceeds bound")
        if name.endswith(".json"):
            if receipt_identifier(json.loads(body)):
                raise ProcessError("private identifier in factual receipt")
        else:
            body = "[sensitive command output withheld]\n"
        payload[name] = body
    return payload


def export_i2(source: Path, destination: Path, env: dict[str, str]) -> None:
    script = (
        "import json,sys; from pathlib import Path; "
        "from guard_harness.install_run import evidence_payload; "
        "print(json.dumps(evidence_payload(Path(sys.argv[1]))))"
    )
    try:
        result = subprocess.run(
            [
                "sudo",
                "env",
                "PYTHONPATH=" + str(ROOT / "harness/src"),
                sys.executable,
                "-c",
                script,
                str(source),
            ],
            env=env,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except subprocess.CalledProcessError:
        raise ProcessError("private lifecycle evidence export refused") from None
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict) or set(payload) - set(EVIDENCE_FILES):
        raise ProcessError("unexpected lifecycle evidence export")
    destination.mkdir(mode=0o700, parents=True)
    for name, body in payload.items():
        if not isinstance(body, str) or len(body.encode()) > 65536:
            raise ProcessError("invalid lifecycle evidence export")
        path = destination / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            os.chmod(path, 0o600)
            stream.write(body)


def i2_child(
    words: list[str], *, destination: Path, env: dict[str, str], input: bytes = b""
) -> None:
    source = Path(words[words.index("--output") + 1])
    failure = None
    try:
        child(words, env=env, input=input)
    except ProcessError as error:
        failure = error
    finally:
        try:
            export_i2(source, destination, env)
        except (ProcessError, OSError, ValueError):
            if failure is not None:
                raise ProcessError(f"{failure}; diagnostic export refused") from None
            raise ProcessError("private lifecycle evidence export refused") from None
    if failure is not None:
        raise failure


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
    diagnostic = diagnostic_mode()
    profile = os.environ.get("INSTALL_MATRIX_PROFILE", "all")
    if profile not in {"all", "nightly"} or (diagnostic and profile != "all"):
        raise ProcessError("known install profile required")
    identity = json.loads((args.subjects / "input.json").read_bytes())
    if not isinstance(identity, dict):
        raise ProcessError("authenticated subject identity object required")
    harness_commit = os.environ.get("GITHUB_SHA", "")
    if (
        identity.get("diagnostic") is not diagnostic
        or re.fullmatch(r"[0-9a-f]{40}", harness_commit) is None
        or identity.get("harness_commit") != harness_commit
        or (profile == "all" and not diagnostic and identity.get("commit") != harness_commit)
    ):
        raise ProcessError("explicit diagnostic mode and authenticated harness identity required")
    if identity.get("loader_channel") != ("staging" if profile == "all" else "canonical"):
        raise ProcessError("known loader channel required")
    if os.environ.get("GUARD_C6_SERIALIZED") != "1":
        raise ProcessError("serialized Testnet runtime required")
    if args.row == "I2" and args.scenario == "both":
        raise ProcessError("I2 needs independently fresh runners for each explicit scenario")
    if not args.output.is_absolute() or args.output.exists():
        raise ProcessError("fresh absolute evidence directory required")
    current = Release(identity["tag"], identity["commit"], args.subjects / "candidate/assets")
    previous = Release(
        identity["previous_tag"], identity["previous_commit"], args.subjects / "previous/assets"
    )
    loader = args.subjects / "i-staging"
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
    previous_binary_digest = hashlib.sha256(previous.binary(target)).hexdigest()
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
    framed = os.environ.pop("WALLET_FRAME", "").strip()
    key = framed.removeprefix("0x").encode() + b"\n"
    if re.fullmatch(rb"[0-9a-fA-F]{64}\n", key) is None:
        raise ProcessError("private framed Testnet key required")
    args.output.mkdir(mode=0o700)
    if diagnostic:
        (args.output / "diagnostic-only.json").write_text(
            json.dumps(
                {
                    "schema": 1,
                    "status": "diagnostic_only",
                    "diagnostic": True,
                    "row": args.row,
                    "scenario": args.scenario,
                    "commit": current.commit,
                    "harness_commit": harness_commit,
                }
            )
            + "\n"
        )
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
        if diagnostic:
            base.append("--diagnostic")
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
        i2_child(
            [
                *base,
                "guard_harness.linux_lifecycle",
                *flags,
                "--account",
                args.paper_account,
                "--account-network",
                "testnet",
                "--output",
                str(I2_PRIVATE / marker / "paper" / args.scenario),
                *paper_identity,
                "--archive",
                str(current.assets / archive_name),
            ],
            destination=args.output / "paper" / args.scenario,
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
            str(I2_PRIVATE / marker / "testnet" / args.scenario),
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
            candidate_binary_digest,
            "--previous-binary-sha256",
            previous_binary_digest,
        ]
    )
    if args.row == "I2":
        i2_child(testnet, destination=args.output / "testnet" / args.scenario, input=key, env=env)
    else:
        child(testnet, input=key, check=True, env=env)


if __name__ == "__main__":
    main()
