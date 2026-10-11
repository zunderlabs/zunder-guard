"""Real native systemd lifecycle in a disposable Linux machine, with reboot phases.

Only paper decisions are sent. The caller authenticates installer files from the signed
release set; each installer independently verifies release archives with Sigstore.
"""

import argparse
import hashlib
import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guard_harness.cli import GuardCLI
from guard_harness.paper_bot import LocalGuard, PaperError
from guard_harness.paper_roundtrip import round_trip
from guard_harness.runner import run

HOME = Path("/var/lib/zunder-guard")
BINARY = Path("/usr/local/bin/zunder-guard")
UNIT = "zunder-guard.service"
MARKER = Path("/etc/zunder-native-disposable")
ROOT_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class LifecycleError(RuntimeError):
    """A required real lifecycle observation failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LifecycleError(message)


def authenticated_file(path: Path, sha256: str) -> None:
    require(re.fullmatch(r"[0-9a-f]{64}", sha256) is not None, "SHA256 shape refused")
    require(path.is_file() and not path.is_symlink(), "installer must be a regular file")
    with path.open("rb") as stream:
        require(
            hashlib.file_digest(stream, "sha256").hexdigest() == sha256, "installer digest differs"
        )


def wait_healthy(
    guard: LocalGuard, *, timeout: float = 90, pause: Callable[[float], None] = time.sleep
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        try:
            status: dict[str, Any] = guard.request("/guard/status")
            require(status.get("mode") == "paper", "paper lifecycle reached another mode")
            if status.get("last_sync_ms"):
                return status
        except PaperError:
            pass
        require(time.monotonic() < deadline, "service health deadline exceeded")
        pause(1)


def snapshot(home: Path) -> dict[str, str]:
    """Hash all persistent state; publish hashes only, never keys/configuration bytes."""
    require(home.is_dir() and not home.is_symlink(), "service home missing or symlinked")
    files = {}
    for path in sorted(home.rglob("*")):
        require(not path.is_symlink(), "persistent state has a symlink")
        if path.is_file():
            with path.open("rb") as stream:
                files[str(path.relative_to(home))] = hashlib.file_digest(
                    stream, "sha256"
                ).hexdigest()
    require("guard.toml" in files, "configuration missing")
    return files


def preserved(before: dict[str, str], after: dict[str, str]) -> None:
    require(before == after, "installer changed persistent state while service was stopped")


@dataclass(frozen=True)
class Inputs:
    installer: Path
    installer_sha256: str
    previous_installer: Path
    previous_installer_sha256: str
    version: str
    previous_version: str
    rules: str
    account: str
    output: Path
    marker: str
    account_network: str = "mainnet"

    def validate(self) -> None:
        require(os.geteuid() == 0 and Path("/run/systemd/system").is_dir(), "root systemd required")
        require(
            MARKER.is_file() and MARKER.read_text().strip() == self.marker,
            "disposable marker differs",
        )
        require(re.fullmatch(r"[0-9a-f]{32}", self.marker) is not None, "marker shape refused")
        require(
            re.fullmatch(r"0x[0-9a-fA-F]{40}", self.account) is not None, "account shape refused"
        )
        for version in (self.version, self.previous_version):
            require(
                re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.\d+)?", version) is not None, "version refused"
            )
        require(
            self.version != self.previous_version,
            "upgrade requires a distinct published predecessor",
        )
        require(self.account_network in ("mainnet", "testnet"), "paper account network refused")
        authenticated_file(self.installer, self.installer_sha256)
        authenticated_file(self.previous_installer, self.previous_installer_sha256)


class NativeLifecycle:
    def __init__(self, inputs: Inputs) -> None:
        inputs.validate()
        self.inputs = inputs
        inputs.output.mkdir(parents=True, exist_ok=True)
        self.guard = LocalGuard("http://127.0.0.1:8547")
        self.cli = GuardCLI(BINARY, inputs.output, HOME)

    def command(self, name: str, argv: list[str], *, sensitive: bool = False) -> str:
        return run(
            argv,
            log=self.inputs.output / f"{name}.log",
            timeout=600,
            sensitive_output=sensitive and "install" not in name,
            sensitive_stdout=sensitive and "install" in name,
            env={"PATH": ROOT_PATH, "HOME": "/root"},
        ).output.strip()

    def systemctl(self, name: str, *args: str) -> str:
        return self.command(name, ["systemctl", *args, UNIT])

    def install(self, name: str, installer: Path, *, files_only: bool = False) -> None:
        args = ["sh", str(installer), "--non-interactive"]
        if files_only:
            args.append("--install-only")
        else:
            args.extend(
                [
                    "--network",
                    "paper",
                    "--account",
                    self.inputs.account,
                    "--rules",
                    self.inputs.rules,
                ]
            )
        if not files_only and self.inputs.account_network == "testnet":
            args.extend(["--account-network", "testnet"])
        # Installer prints a new pairing key once. Never retain its stdout/stderr.
        self.command(name, args, sensitive=True)

    def version(self, expected: str) -> None:
        got = self.command("version-" + expected, [str(BINARY), "--version"])
        require(got == "zunder-guard " + expected.removeprefix("v"), "installed version differs")

    def healthy(self) -> None:
        wait_healthy(self.guard)
        status = self.cli.status(url=self.guard.url)
        require(
            status["mode"] == "paper" and status["journal"]["ok"] is True,
            "paper service journal not healthy",
        )
        require(status["account"].lower() == self.inputs.account.lower(), "service account differs")

    def before_reboot(self) -> None:
        require(
            not HOME.exists() and not BINARY.exists(),
            "lifecycle requires a fresh disposable machine",
        )
        self.install("previous-install", self.inputs.previous_installer)
        self.version(self.inputs.previous_version)
        self.healthy()
        self.systemctl("stop-pair", "stop")
        pair = self.cli.pair()
        self.command("pair-owner", ["chown", "-R", "zunder-guard:zunder-guard", str(HOME)])
        self.systemctl("start-pair", "start")
        self.healthy()
        decisions = round_trip(self.guard, pair)
        seqs = [decision.seq for decision in decisions]
        self.systemctl("restart", "restart")
        self.healthy()
        self.recover(seqs)
        pid = self.systemctl("pid-before-crash", "show", "--property=MainPID", "--value")
        require(pid.isdigit() and int(pid) > 1, "service PID missing")
        self.systemctl("crash", "kill", "--kill-whom=main", "--signal=SIGKILL")
        deadline = time.monotonic() + 90
        while self.systemctl("pid-after-crash", "show", "--property=MainPID", "--value") in (
            pid,
            "0",
        ):
            require(time.monotonic() < deadline, "systemd did not replace killed process")
            time.sleep(1)
        self.healthy()
        self.recover(seqs)
        self.systemctl("enabled", "is-enabled")
        record = {
            "stage": "awaiting-reboot",
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "decision_seqs": seqs,
            "installer_sha256": self.inputs.installer_sha256,
            "previous_installer_sha256": self.inputs.previous_installer_sha256,
        }
        self.write(record)

    def recover(self, seqs: list[int]) -> None:
        events = self.guard.request("/guard/events?since=0")
        require(
            all(any(event["seq"] == seq for event in events) for seq in seqs),
            "decision journal did not recover every paper decision",
        )

    def write(self, record: dict[str, Any]) -> None:
        (self.inputs.output / "linux-lifecycle.json").write_text(
            json.dumps(record, indent=2) + "\n"
        )

    def after_reboot(self, *, require_reboot: bool = True) -> None:
        record = json.loads((self.inputs.output / "linux-lifecycle.json").read_text())
        require(record["stage"] == "awaiting-reboot", "reboot phase receipt missing")
        require(
            record["installer_sha256"] == self.inputs.installer_sha256
            and record["previous_installer_sha256"] == self.inputs.previous_installer_sha256,
            "reboot phase release inputs changed",
        )
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if require_reboot:
            require(boot != record["boot_id"], "kernel reboot not observed")
        self.healthy()
        self.recover(record["decision_seqs"])
        self.systemctl("stop-upgrade", "stop")
        before = snapshot(HOME)
        for step in ("upgrade", "reinstall"):
            self.install(step, self.inputs.installer, files_only=True)
            self.version(self.inputs.version)
            preserved(before, snapshot(HOME))
            self.systemctl(step + "-start", "start")
            self.healthy()
            self.recover(record["decision_seqs"])
            self.systemctl(step + "-stop", "stop")
            before = snapshot(HOME)
        self.command(
            "uninstall", ["sh", str(self.inputs.installer), "--uninstall", "--non-interactive"]
        )
        preserved(before, snapshot(HOME))
        require(not BINARY.exists(), "uninstall left binary")
        require(
            not Path("/etc/systemd/system/zunder-guard.service").exists(),
            "uninstall left service unit",
        )
        require(
            not Path("/etc/systemd/system/zunder-guard.service.d").exists(),
            "uninstall left drop-ins",
        )
        for notice in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"):
            require(
                not (Path("/usr/local/share/licenses/zunder-guard") / notice).exists(),
                "uninstall left notice",
            )
        record.update(
            stage="passed",
            reboot_boot_id=boot,
            preserved_state=before,
            version=self.inputs.version,
            previous_version=self.inputs.previous_version,
        )
        self.write(record)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("installer", "previous-installer", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    for flag in (
        "installer-sha256",
        "previous-installer-sha256",
        "version",
        "previous-version",
        "rules",
        "account",
        "marker",
    ):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument(
        "--phase", choices=("before-reboot", "after-reboot", "all-no-reboot"), required=True
    )
    parser.add_argument("--mode", choices=("native", "container"), default="native")
    parser.add_argument("--account-network", choices=("mainnet", "testnet"), default="mainnet")
    parser.add_argument("--source-container-diagnostic", action="store_true")
    args = vars(parser.parse_args())
    phase = args.pop("phase")
    mode = args.pop("mode")
    source_diagnostic = args.pop("source_container_diagnostic")
    require(not source_diagnostic or mode == "container", "source diagnostic is container-only")
    lifecycle: NativeLifecycle
    if source_diagnostic:
        from guard_harness.linux_container_diagnostic import SourceContainerDiagnostic

        lifecycle = SourceContainerDiagnostic(Inputs(**args))
    elif mode == "container":
        from guard_harness.linux_container_lifecycle import ContainerLifecycle

        lifecycle = ContainerLifecycle(Inputs(**args))
    else:
        lifecycle = NativeLifecycle(Inputs(**args))
    try:
        if phase == "before-reboot":
            lifecycle.before_reboot()
        elif phase == "after-reboot":
            lifecycle.after_reboot()
        else:
            lifecycle.before_reboot()
            lifecycle.after_reboot(require_reboot=False)
    finally:
        lifecycle.command(
            "service-journal",
            [
                "journalctl",
                "-u",
                "zunder-guard-container-paper.service" if mode == "container" else UNIT,
                "--no-pager",
                "-n",
                "300",
            ],
        )


if __name__ == "__main__":
    main()
