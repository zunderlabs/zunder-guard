"""Released protected installer refusal with a throwaway unapproved wallet; no orders.

Production installers check the wallet during setup, before writing its credential or
activating a service. This records that setup refusal, never claims service startup.
Run only in the disposable root systemd guest used by the install matrix.
"""

import argparse
import errno
import hashlib
import json
import os
import pty
import re
import secrets
import select
import signal
import subprocess
import termios
import time
from dataclasses import dataclass
from pathlib import Path

from guard_harness.linux_lifecycle import MARKER, ROOT_PATH, authenticated_file, require

PROMPTS = (
    (b"Keep these? [Y/edit]", b"\n"),
    (b"Type the account address again to confirm:", None),
    (b"API wallet private key (not shown while typing):", None),
)


@dataclass(frozen=True)
class Refusal:
    output: str
    exit_code: int


def terminal_refusal(
    argv: list[str],
    account: str,
    *,
    timeout: float = 900,
    log: Path | None = None,
    volume: str | None = None,
) -> Refusal:
    """Respond only to known setup prompts; admit the ephemeral key with echo disabled."""
    prompts = PROMPTS + (
        ()
        if volume is None
        else (
            (
                f"Type CREATE {volume} to create this NEW persistent volume:".encode(),
                f"CREATE {volume}\n".encode(),
            ),
        )
    )
    key = secrets.token_hex(32).encode()
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execve(argv[0], argv, {"PATH": ROOT_PATH, "HOME": "/root", "LANG": "C.UTF-8"})
    output = b""
    pending = b""
    seen: set[bytes] = set()
    deadline = time.monotonic() + timeout
    finished = False
    try:
        while time.monotonic() < deadline:
            readable, _, _ = select.select([descriptor], [], [], 0.2)
            if readable:
                try:
                    chunk = os.read(descriptor, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    chunk = b""
                output = (output + chunk)[-131072:]
                pending = (pending + chunk)[-131072:]
                for prompt, reply in prompts:
                    if prompt in pending and prompt not in seen:
                        if prompt.startswith(b"API wallet"):
                            require(
                                not termios.tcgetattr(descriptor)[3] & termios.ECHO,
                                "private key prompt did not disable terminal echo",
                            )
                            reply = key + b"\n"
                        elif reply is None:
                            reply = account.encode() + b"\n"
                        os.write(descriptor, reply)
                        seen.add(prompt)
                        pending = pending.split(prompt, 1)[1]
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                finished = True
                require(
                    os.waitstatus_to_exitcode(status) != 0, "unapproved setup unexpectedly passed"
                )
                break
        if not finished:
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                finished = True
                require(
                    os.waitstatus_to_exitcode(status) != 0, "unapproved setup unexpectedly passed"
                )
        require(finished, "protected setup refusal deadline exceeded")
        text = (
            output.replace(key, b"[REDACTED]")
            .replace(account.encode(), b"[ACCOUNT]")
            .decode(errors="replace")
        )
        require(len(seen) == len(prompts), "not all consent and hidden-key prompts were reached")
        require(
            "is not an API wallet of" in text, "venue unapproved-wallet refusal was not observed"
        )
        return Refusal(text, os.waitstatus_to_exitcode(status))
    finally:
        if log is not None:
            log.write_text(
                output.replace(key, b"[REDACTED]")
                .replace(account.encode(), b"[ACCOUNT]")
                .decode(errors="replace")
            )
        if not finished:
            os.killpg(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(descriptor)


def exercise(
    installer: Path,
    sha256: str,
    account: str,
    rules: str,
    marker: str,
    output: Path,
    *,
    container: bool = False,
    tag: str,
    commit: str,
    harness_commit: str,
    manifest_sha256: str,
    binary_sha256: str,
    image: str = "",
    diagnostic: bool = False,
) -> None:
    require(os.geteuid() == 0 and Path("/run/systemd/system").is_dir(), "root systemd required")
    require(re.fullmatch(r"[0-9a-f]{32}", marker) is not None, "marker shape refused")
    require(MARKER.is_file() and MARKER.read_text().strip() == marker, "disposable marker differs")
    require(re.fullmatch(r"0x[0-9a-fA-F]{40}", account) is not None, "account shape refused")
    require(
        re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?", tag) is not None,
        "release tag required",
    )
    require(
        all(re.fullmatch(r"[0-9a-f]{40}", value) is not None for value in (commit, harness_commit)),
        "exact release and harness commits required",
    )
    require(diagnostic or harness_commit == commit, "official harness source differs from release")
    require(
        all(
            re.fullmatch(r"[0-9a-f]{64}", value) is not None
            for value in (manifest_sha256, binary_sha256)
        ),
        "authenticated subject hashes required",
    )
    authenticated_file(installer, sha256)
    credential = Path(
        "/etc/zunder-guard-container/credential.cred"
        if container
        else "/etc/credstore.encrypted/zunder-guard-mainnet.hl-api-wallet-key"
    )
    unit = Path(
        "/etc/systemd/system/"
        + ("zunder-guard-container.service" if container else "zunder-guard-mainnet.service")
    )
    volume = "guard-refusal-" + marker
    config = Path(
        "/etc/zunder-guard-container/config.json"
        if container
        else "/var/lib/zunder-guard-mainnet/guard.toml"
    )

    def absent() -> None:
        for path in (
            credential,
            unit,
            config,
            Path("/etc/systemd/system/multi-user.target.wants") / unit.name,
        ):
            require(not path.exists() and not path.is_symlink(), "protected route already exists")

    absent()
    if container:
        require(
            re.fullmatch(r"ghcr\.io/zunderlabs/zunder-guard@sha256:[0-9a-f]{64}", image)
            is not None,
            "signed immutable image required",
        )
        names = subprocess.run(
            ["/usr/bin/docker", "volume", "ls", "--format", "{{.Name}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        require(volume not in names, "refusal volume must be fresh")
    args = [
        "/bin/sh",
        str(installer),
        "--network",
        "mainnet",
        "--account",
        account,
        "--rules",
        rules,
        "--equity-cap",
        "100",
    ]
    args += ["--ip-share", "0.1"]
    args += (
        ["--container", "--volume", volume]
        if container
        else ["--service-instance", "mainnet", "--listen", "127.0.0.1:18549"]
    )
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    log = output / "unapproved-wallet.log"
    refusal = terminal_refusal(args, account, log=log, volume=volume if container else None)
    absent()
    state = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            unit.name,
            "--property=ActiveState",
            "--property=LoadState",
            "--property=MainPID",
        ],
        check=False,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    require(
        set(state) == {"ActiveState=inactive", "LoadState=not-found", "MainPID=0"},
        "refused protected service is not positively absent and inactive",
    )
    if container:
        # Never start this observation container: copy only its released binary.
        name = "guard-refusal-inspect-" + marker
        subprocess.run(
            ["/usr/bin/docker", "create", "--name", name, image], check=True, capture_output=True
        )
        try:
            binary = output / "observed-guard"
            subprocess.run(
                ["/usr/bin/docker", "cp", name + ":/usr/local/bin/zunder-guard", str(binary)],
                check=True,
                capture_output=True,
            )
            locations = json.loads(
                subprocess.run(
                    ["/usr/bin/docker", "volume", "inspect", volume],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
            )
            require(
                len(locations) == 1
                and locations[0].get("Driver") == "local"
                and not locations[0].get("Options"),
                "unexpected volume driver",
            )
            volume_config = Path(locations[0]["Mountpoint"]) / "guard.toml"
            require(
                not volume_config.exists() and not volume_config.is_symlink(),
                "refusal wrote Guard volume config",
            )
        finally:
            subprocess.run(["/usr/bin/docker", "rm", name], check=True, capture_output=True)
    else:
        binary = Path("/opt/zunder-guard-mainnet/bin/zunder-guard")
    authenticated_file(binary, binary_sha256)
    (output / "mainnet-refusal.json").write_text(
        json.dumps(
            {
                "schema": 1,
                "journey": "M1",
                "tag": tag,
                "commit": commit,
                "harness_commit": harness_commit,
                "manifest_sha256": manifest_sha256,
                "binary_sha256": binary_sha256,
                "tier": "e2e",
                "diagnostic": diagnostic,
                "mode": "mainnet",
                "wallet_role": "unapproved",
                "exchange_requests": 0,
                "exit_code": refusal.exit_code,
                "expected_refusal": "is not an API wallet of",
                "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                "config_written": False,
                "service_enabled": False,
                "result": "passed",
                "coverage": ["protected-setup-unapproved-wallet"],
                "route": "linux-container-native" if container else "linux-systemd",
                "installer_sha256": sha256,
                "no_exchange": True,
                "credential_written": False,
                "service_started": False,
            }
        )
        + "\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--installer-sha256", required=True)
    parser.add_argument("--account", default=os.environ.get("E2E_PAPER_ACCOUNT", ""))
    parser.add_argument("--rules", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--container", action="store_true")
    for flag in ("tag", "commit", "harness-commit", "manifest-sha256", "binary-sha256"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--image", default="")
    parser.add_argument("--diagnostic", action="store_true")
    args = parser.parse_args()
    exercise(
        args.installer,
        args.installer_sha256,
        args.account,
        args.rules,
        args.marker,
        args.output,
        container=args.container,
        tag=args.tag,
        commit=args.commit,
        harness_commit=args.harness_commit,
        manifest_sha256=args.manifest_sha256,
        binary_sha256=args.binary_sha256,
        image=args.image,
        diagnostic=args.diagnostic,
    )


if __name__ == "__main__":
    main()
