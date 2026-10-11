#!/usr/bin/python3
"""Signed paper-only Docker systemd installer. No wallet key or sending mode is admitted."""

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

BASE = Path("/etc/zunder-guard-container-paper")
HOME = Path("/var/lib/zunder-guard-container-paper")
LIB = Path("/usr/local/libexec/zunder-guard-container-paper")
UNIT = Path("/etc/systemd/system/zunder-guard-container-paper.service")
NAME = "zunder-guard-container-paper"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}


def require(value: object, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def trusted(path: Path, directory: bool = False) -> None:
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == 0
            and not info.st_mode & 0o022,
            "Untrusted paper service parent.",
        )
    info = path.lstat()
    require(
        info.st_uid == 0
        and not info.st_mode & 0o022
        and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)),
        "Untrusted paper service path.",
    )


def run(argv: list[str], *, display: bool = False) -> str:
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=ENV,
        check=False,
        timeout=180,
    )
    require(
        result.returncode == 0, "Paper service command failed; existing data retained."
    )
    if display:
        sys.stdout.buffer.write(result.stdout)
    return result.stdout.decode().strip()


def mkdir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    trusted(path, True)


def write(path: Path, data: bytes) -> None:
    trusted(path.parent, True)
    if path.exists() or path.is_symlink():
        trusted(path)
    descriptor, pending = tempfile.mkstemp(prefix=".paper-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def docker(image: str, arguments: list[str]) -> list[str]:
    return [
        "/usr/bin/docker",
        "--config",
        str(BASE / "docker-client"),
        "--host",
        "unix:///var/run/docker.sock",
        "run",
        "--rm",
        "--name",
        NAME,
        "--restart=no",
        "--network=host",
        "--label=org.zunder.guard.managed=container-paper",
        "--user=65532:65532",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=64",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=16m",
        "--mount",
        f"type=bind,src={HOME},dst=/data",
        "--env=ZUNDER_GUARD_CONTAINER=1",
        "--env=ZUNDER_GUARD_NETWORK=paper",
        "--env=ZUNDER_GUARD_LISTEN=127.0.0.1:8547",
        image,
        *arguments,
    ]


def unit(image: str) -> bytes:
    # Every argument is constant or a verified immutable digest, so no systemd quoting ambiguity.
    command = " ".join(docker(image, ["run", "--network", "paper", "--container"]))
    return (
        "[Unit]\nDescription=Zunder Guard container-native paper service\n"
        "After=network-online.target docker.service\nRequires=docker.service\n"
        "StartLimitIntervalSec=0\n[Service]\nType=simple\nUser=root\n"
        "ExecStartPre=/usr/bin/python3 -I " + str(LIB / "install.py") + " --recover\n"
        "ExecStart="
        + command
        + "\nExecStop=/usr/bin/docker --host unix:///var/run/docker.sock stop "
        + NAME
        + "\nExecStopPost=/usr/bin/python3 -I "
        + str(LIB / "install.py")
        + " --recover"
        + "\nRestart=on-failure\nRestartSec=10\nTimeoutStopSec=90\n"
        "LimitCORE=0\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n"
    ).encode()


def recover() -> None:
    names = run(
        [
            "/usr/bin/docker",
            "--host",
            "unix:///var/run/docker.sock",
            "ps",
            "-a",
            "--filter",
            "name=^" + NAME + "$",
            "--format",
            "{{.Names}}",
        ]
    )
    if not names:
        return
    require(names == NAME, "Container identity is ambiguous.")
    info = json.loads(
        run(
            [
                "/usr/bin/docker",
                "--host",
                "unix:///var/run/docker.sock",
                "container",
                "inspect",
                NAME,
            ]
        )
    )
    require(
        len(info) == 1
        and info[0].get("Config", {}).get("Labels", {}).get("org.zunder.guard.managed")
        == "container-paper",
        "Refusing another owner container.",
    )
    require(
        info[0].get("Config", {}).get("Cmd")
        == ["run", "--network", "paper", "--container"],
        "Refusing a container outside the paper route.",
    )
    mounts = info[0].get("Mounts", [])
    require(
        any(
            m.get("Source") == str(HOME) and m.get("Destination") == "/data"
            for m in mounts
        ),
        "Container persistent home differs.",
    )
    run(["/usr/bin/docker", "--host", "unix:///var/run/docker.sock", "rm", "-f", NAME])


def uninstall() -> None:
    require(os.geteuid() == 0, "Root is required.")
    trusted(UNIT.parent, True)
    if UNIT.exists() or UNIT.is_symlink():
        trusted(UNIT)
        run(["/usr/bin/systemctl", "disable", "--now", UNIT.name])
        active = run(
            [
                "/usr/bin/systemctl",
                "show",
                UNIT.name,
                "--property=ActiveState",
                "--value",
            ]
        )
        require(active in ("inactive", "failed"), "Paper service has not stopped.")
        UNIT.unlink()
        run(["/usr/bin/systemctl", "daemon-reload"])
    if (LIB / "install.py").exists():
        trusted(LIB / "install.py")
        (LIB / "install.py").unlink()
        LIB.rmdir()
    print(
        "Paper container service removed. Data and image kept; encrypted sending services unchanged."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--recover", action="store_true")
    parser.add_argument("--version")
    parser.add_argument("--network", choices=("paper",), default="paper")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument(
        "--account-network", choices=("mainnet", "testnet"), default="mainnet"
    )
    parser.add_argument("--account")
    parser.add_argument("--rules")
    args = parser.parse_args()
    require(
        os.geteuid() == 0 and Path("/run/systemd/system").is_dir(),
        "Root systemd is required.",
    )
    if args.recover:
        require(
            not any(
                (
                    args.uninstall,
                    args.version,
                    args.account,
                    args.rules,
                    args.non_interactive,
                )
            ),
            "Service recovery accepts no setup input.",
        )
        recover()
        return
    if args.uninstall:
        require(
            not any((args.version, args.account, args.rules, args.non_interactive)),
            "Uninstall accepts no setup input.",
        )
        uninstall()
        return
    require(
        args.non_interactive
        and re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", args.version or ""),
        "Explicit released version and non-interactive paper setup required.",
    )
    require(
        re.fullmatch(r"0x[0-9a-fA-F]{40}", args.account or "")
        and re.fullmatch(r"zr1_[A-Za-z0-9_-]+", args.rules or ""),
        "Explicit account and rules required.",
    )
    image = verified_image(args)
    prepare_home(args, image)
    register(image)


def verified_image(args: argparse.Namespace) -> str:
    stage = Path(__file__).resolve().parent
    trusted(stage, True)
    image_file = stage / ("zunder-guard-" + args.version + ".image.txt")
    trusted(image_file)
    image = image_file.read_text().strip()
    require(
        re.fullmatch(r"ghcr\.io/zunderlabs/zunder-guard@sha256:[0-9a-f]{64}", image),
        "Exact signed image digest required.",
    )
    mkdir(BASE)
    mkdir(BASE / "docker-client")
    ENV["DOCKER_CONFIG"] = str(BASE / "docker-client")
    run(
        [
            "/usr/local/bin/cosign",
            "verify",
            image,
            "--certificate-identity",
            "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/"
            + args.version,
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
        ]
    )
    run(
        [
            "/usr/bin/docker",
            "--config",
            str(BASE / "docker-client"),
            "--host",
            "unix:///var/run/docker.sock",
            "pull",
            image,
        ]
    )
    inspection = json.loads(
        run(
            [
                "/usr/bin/docker",
                "--host",
                "unix:///var/run/docker.sock",
                "image",
                "inspect",
                image,
            ]
        )
    )
    require(
        len(inspection) == 1
        and image in inspection[0].get("RepoDigests", [])
        and inspection[0].get("Config", {}).get("User") == "65532:65532",
        "Image runtime identity differs.",
    )
    return str(image)


def prepare_home(args: argparse.Namespace, image: str) -> None:
    config = HOME / "guard.toml"
    if HOME.exists() or HOME.is_symlink():
        require(
            HOME.is_dir()
            and not HOME.is_symlink()
            and HOME.stat().st_uid == 65532
            and stat.S_IMODE(HOME.stat().st_mode) == 0o700,
            "Existing paper home ownership differs.",
        )
        require(
            config.is_file() and not config.is_symlink(),
            "Existing paper config missing.",
        )
        value = tomllib.loads(config.read_text())
        require(
            value.get("mode") == "paper"
            and value.get("network") == args.account_network
            and value.get("account", "").lower() == args.account.lower(),
            "Cannot adopt another paper account or mode.",
        )
        require(
            not (HOME / "api-wallet-key").exists(),
            "Paper home must contain no wallet key.",
        )
        require(
            UNIT.exists(), "Existing paper home lacks its own service registration."
        )
        trusted(UNIT)
        run(["/usr/bin/systemctl", "stop", UNIT.name])
    else:
        require(
            not UNIT.exists() and not UNIT.is_symlink(),
            "Existing paper unit cannot be adopted.",
        )
        existing = run(
            [
                "/usr/bin/docker",
                "--host",
                "unix:///var/run/docker.sock",
                "ps",
                "-a",
                "--filter",
                "name=^" + NAME + "$",
                "--format",
                "{{.Names}}",
            ]
        )
        require(not existing, "Existing named container cannot be adopted.")
        trusted(HOME.parent, True)
        HOME.mkdir(mode=0o700)
        os.chown(HOME, 65532, 65532)
        run(
            docker(
                image,
                [
                    "init",
                    "--non-interactive",
                    "--network",
                    "paper",
                    "--account-network",
                    args.account_network,
                    "--account",
                    args.account,
                    "--rules",
                    args.rules,
                    "--no-key",
                ],
            )
        )
        run(docker(image, ["pair"]), display=True)


def register(image: str) -> None:
    mkdir(LIB)
    write(LIB / "install.py", Path(__file__).read_bytes())
    trusted(UNIT.parent, True)
    write(UNIT, unit(image))
    os.chmod(UNIT, 0o644)
    run(["/usr/bin/systemctl", "daemon-reload"])
    run(["/usr/bin/systemctl", "enable", "--now", UNIT.name])
    print(
        "Verified paper container-native service installed. No venue signing credential is stored."
    )


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("Paper container installation refused: " + str(error), file=sys.stderr)
        raise SystemExit(2) from None
