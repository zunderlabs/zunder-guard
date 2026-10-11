"""Released protected Testnet service lifecycle without any bot or exchange request.

Only a complete independent flat scan permits a lifecycle mutation. Private snapshots
live outside the collected evidence tree; API wallet input is stdin-only in memory.
"""

import argparse
import base64
import hashlib
import json
import os
import platform
import pwd
import re
import sys
import time
from pathlib import Path
from typing import Any

from guard_harness.cli import PAIR_SCHEMA, decode_json
from guard_harness.linux_lifecycle import ROOT_PATH, Inputs, authenticated_file, require
from guard_harness.linux_testnet_service import TestnetService
from guard_harness.paper_bot import LocalGuard, PaperError
from guard_harness.runner import run
from guard_harness.testnet_scan import TestnetReads, flat_scan

JOURNALS = ("guard.toml", "risk.jsonl", "decisions.jsonl")
PRIVATE = Path("/root/.guard-testnet-lifecycle")


def no_exchange(home: Path) -> int:
    """Every sending path records an action-bearing event before sending.

    Reject emergency recovery, broken journals, all action-bearing events and every
    unknown event. Verify the complete decision hash chain including startup events.
    This is a durable-journal observation, not a claim of packet capture.
    """
    journal = home / "decisions.jsonl"
    require(journal.is_file() and not journal.is_symlink(), "decision journal missing")
    require(journal.stat().st_size <= 8 * 1024 * 1024, "decision journal exceeds audit bound")
    require(not any((home / "emergency").glob("**/*")), "emergency evidence needs human review")
    body = journal.read_bytes().rstrip(b"\x00")
    require(bool(body) and body.endswith(b"\n"), "decision journal incomplete")
    previous = ""
    sequence = 0
    started = 0
    for line in body.splitlines():
        record = json.loads(line)
        require(isinstance(record, dict), "decision record malformed")
        event = record.get("event")
        require(isinstance(event, dict), "decision event malformed")
        require(
            set(record) in ({"prev", "check", "event"}, {"prev", "check", "durable", "event"}),
            "decision record shape differs",
        )
        require(
            event.get("kind") in {"started", "risk", "stopped"},
            "action-bearing or unknown event; no exchange credit",
        )
        require(
            type(event.get("seq")) is int and event["seq"] == sequence + 1,
            "decision sequence incomplete",
        )
        require(record.get("prev") == previous, "decision chain differs")
        text = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        check = hashlib.sha3_256((previous + text).encode()).hexdigest()
        require(record.get("check") == check, "decision checksum differs")
        if event["kind"] == "started":
            require(event.get("mode") == "testnet", "journal contains another runtime mode")
            started += 1
        if event["kind"] == "risk":
            require(
                event.get("open_positions") == 0
                and event.get("discrepancies") == 0
                and event.get("journal_error") is None,
                "risk evidence not flat or journal unhealthy",
            )
        previous, sequence = check, event["seq"]
    require(started > 0, "startup audit positive control missing")
    return sequence


def retained(home: Path) -> dict[str, str]:
    values = {}
    for name in JOURNALS:
        source = home / name
        require(
            source.is_file()
            and not source.is_symlink()
            and source.stat().st_size <= 8 * 1024 * 1024,
            "private state snapshot missing or unsafe",
        )
        # Decision/risk writers may reserve zero-filled tails. Only populated
        # journal prefixes are retained; subsequent append consumes that reserve.
        body = source.read_bytes()
        if name.endswith(".jsonl"):
            body = body.rstrip(b"\x00")
        values[name] = base64.b64encode(body).decode()
    return values


def preserved(home: Path, before: dict[str, str]) -> None:
    require(set(before) == set(JOURNALS), "private snapshot shape differs")
    after = retained(home)
    for name, old in before.items():
        previous, current = base64.b64decode(old, validate=True), base64.b64decode(after[name])
        require(
            current == previous if name == "guard.toml" else current.startswith(previous),
            "pairing/configuration changed or journal prefix lost",
        )


class TestnetLifecycle:
    def __init__(
        self,
        inputs: Inputs,
        *,
        route: str,
        binary_sha256: str,
        previous_binary_sha256: str,
        image: str,
        previous_image: str,
    ) -> None:
        inputs.validate()
        require(route in {"native", "container"}, "protected route refused")
        require(inputs.account_network == "testnet", "Testnet read network required")
        self.inputs, self.route = inputs, route
        self.binary_sha256, self.previous_binary_sha256 = binary_sha256, previous_binary_sha256
        self.image, self.previous_image = image, previous_image
        for digest in (binary_sha256, previous_binary_sha256):
            require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "binary digest required")
        if route == "container":
            for descriptor in (image, previous_image):
                require(
                    re.fullmatch(r"ghcr.io/zunderlabs/zunder-guard@sha256:[0-9a-f]{64}", descriptor)
                    is not None,
                    "immutable released image required",
                )
        self.unit = (
            "zunder-guard-container.service"
            if route == "container"
            else "zunder-guard-testnet.service"
        )
        self.home = Path("/var/lib/zunder-guard-testnet")
        self.binary = Path("/opt/zunder-guard-testnet/bin/zunder-guard")
        self.port = 8547 if route == "container" else 18548
        self.guard = LocalGuard(f"http://127.0.0.1:{self.port}")
        self.read = TestnetReads()
        self.private = PRIVATE / inputs.marker
        self.record_path = inputs.output / "testnet-lifecycle.json"
        inputs.output.mkdir(mode=0o700, parents=True, exist_ok=True)

    def command(self, name: str, words: list[str]) -> str:
        return run(
            words,
            log=self.inputs.output / (name + ".log"),
            timeout=600,
            sensitive_output=True,
            env={"PATH": ROOT_PATH, "HOME": "/root"},
        ).output.strip()

    def flat(self) -> None:
        self.read.start_phase(timeout=720)
        flat_scan(self.read, self.inputs.account)

    def control(self, name: str, action: str) -> None:
        self.flat()
        self.command(name, ["systemctl", action, self.unit])

    def docker(self, words: list[str], *, writing: bool = False) -> list[str]:
        config = json.loads(Path("/etc/zunder-guard-container/config.json").read_bytes())
        return [
            "docker",
            "run",
            "--rm",
            "--network=host",
            "--user=65532:65532",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--mount",
            f"type=volume,src={config['volume']},dst=/data" + ("" if writing else ",readonly"),
            str(config["image"]),
            *words,
        ]

    def healthy(self, version: str, digest: str, image: str) -> None:
        deadline = time.monotonic() + 180
        while True:
            try:
                status = self.guard.request("/guard/status")
                require(
                    status.get("mode") == "testnet" and status.get("network") == "testnet",
                    "service network differs",
                )
                require(
                    status.get("account", "").lower() == self.inputs.account.lower(),
                    "service account differs",
                )
                if status.get("last_sync_ms"):
                    require(
                        not status.get("halted") and not status.get("kill_switch"),
                        "halted risk needs human review; never resume automatically",
                    )
                    require(
                        status.get("version") == version.removeprefix("v")
                        and status.get("journal", {}).get("ok") is True,
                        "service version or journal differs",
                    )
                    break
            except PaperError:
                pass
            require(time.monotonic() < deadline, "Testnet synchronization deadline")
            time.sleep(1)
        if self.route == "native":
            authenticated_file(self.binary, digest)
        else:
            config = json.loads(Path("/etc/zunder-guard-container/config.json").read_bytes())
            require(config.get("image") == image, "installed immutable image differs")
            require(
                self.command("container-binary-digest", self.docker(["--version"]))
                == "zunder-guard " + version.removeprefix("v"),
                "container executable version differs",
            )
        unit = Path("/etc/systemd/system") / self.unit
        require(unit.is_file() and not unit.is_symlink(), "owned service unit differs")
        credential = (
            Path("/etc/zunder-guard-container/credential.cred")
            if self.route == "container"
            else Path("/etc/credstore.encrypted/zunder-guard-testnet.hl-api-wallet-key")
        )
        require(
            credential.is_file()
            and not credential.is_symlink()
            and credential.stat().st_uid == 0
            and credential.stat().st_mode & 0o077 == 0,
            "private encrypted custody readback differs",
        )
        text = (
            unit.read_text()
            if self.route == "container"
            else Path(
                "/etc/systemd/system/zunder-guard-testnet.service.d/10-install.conf"
            ).read_text()
        )
        require(
            "LoadCredentialEncrypted=" in text and "LoadCredential=" not in text,
            "plaintext credential route refused",
        )
        no_exchange(self.home)

    def install(self, installer: Path, digest: str, key: bytes, *, initial: bool) -> None:
        self.flat()
        if self.route == "native" and not initial:
            authenticated_file(installer, digest)
            self.command(
                "released-files-install",
                [
                    "sh",
                    str(installer),
                    "--install-only",
                    "--non-interactive",
                    "--no-service",
                    "--prefix",
                    str(self.binary.parent),
                ],
            )
            return
        value = TestnetService(
            installer,
            digest,
            self.inputs.account,
            self.inputs.rules,
            self.port,
            self.inputs.output,
            self.inputs.marker,
            container=self.route == "container",
        ).setup(key)
        self.home = Path(value["home"])

    def write(self, value: dict[str, Any]) -> None:
        self.record_path.write_text(json.dumps(value) + "\n")

    def before(self, key: bytes) -> None:
        unit = Path("/etc/systemd/system") / self.unit
        require(not unit.exists() and not self.private.exists(), "fresh owned lifecycle required")
        if self.route == "native":
            require(
                not self.home.exists() and not self.binary.exists(), "native state already exists"
            )
        else:
            require(
                not Path("/etc/zunder-guard-container").exists(), "container state already exists"
            )
            require(
                not self.command(
                    "fresh-volume-inventory",
                    [
                        "docker",
                        "volume",
                        "ls",
                        "--filter",
                        "name=^zunder-guard-testnet-data$",
                        "--format",
                        "{{.Name}}",
                    ],
                ),
                "container volume already exists; no adoption",
            )
        self.private.mkdir(mode=0o700, parents=True)
        self.install(
            self.inputs.previous_installer, self.inputs.previous_installer_sha256, key, initial=True
        )
        self.healthy(self.inputs.previous_version, self.previous_binary_sha256, self.previous_image)
        self.control("pair-stop", "stop")
        self.flat()
        words = (
            self.docker(["pair", "--json"], writing=True)
            if self.route == "container"
            else [
                "runuser",
                "-u",
                pwd.getpwuid(self.home.stat().st_uid).pw_name,
                "--",
                str(self.binary),
                "--home",
                str(self.home),
                "pair",
                "--json",
            ]
        )
        decode_json(self.command("private-pair", words), PAIR_SCHEMA)
        snapshot = retained(self.home)
        (self.private / "snapshot.json").write_text(json.dumps(snapshot))
        (self.private / "snapshot.json").chmod(0o600)
        self.control("pair-start", "start")
        self.healthy(self.inputs.previous_version, self.previous_binary_sha256, self.previous_image)
        self.control("restart", "restart")
        self.healthy(self.inputs.previous_version, self.previous_binary_sha256, self.previous_image)
        self.flat()
        self.command("daemon-reload", ["systemctl", "daemon-reload"])
        self.control("reload-restart", "restart")
        pid = self.command(
            "old-pid", ["systemctl", "show", "--property=MainPID", "--value", self.unit]
        )
        require(pid.isdigit() and int(pid) > 1, "service PID missing")
        self.flat()
        self.command(
            "crash", ["systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", self.unit]
        )
        deadline = time.monotonic() + 120
        while self.command(
            "recovered-pid", ["systemctl", "show", "--property=MainPID", "--value", self.unit]
        ) in (pid, "0"):
            require(time.monotonic() < deadline, "service crash recovery deadline")
            time.sleep(1)
        self.healthy(self.inputs.previous_version, self.previous_binary_sha256, self.previous_image)
        preserved(self.home, snapshot)
        self.command("enabled", ["systemctl", "is-enabled", self.unit])
        self.flat()
        self.write(
            {
                "stage": "awaiting-reboot",
                "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "installer_sha256": self.inputs.installer_sha256,
                "previous_installer_sha256": self.inputs.previous_installer_sha256,
            }
        )

    def after(self, key: bytes, *, reboot_required: bool) -> None:
        record = json.loads(self.record_path.read_bytes())
        require(
            record.get("stage") == "awaiting-reboot"
            and record.get("installer_sha256") == self.inputs.installer_sha256
            and record.get("previous_installer_sha256") == self.inputs.previous_installer_sha256,
            "lifecycle inputs changed across boot",
        )
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        require(
            not reboot_required or boot != record["boot_id"], "actual guest reboot not observed"
        )
        if self.route == "container":
            config = json.loads(Path("/etc/zunder-guard-container/config.json").read_bytes())
            mount = self.command(
                "owned-volume",
                [
                    "docker",
                    "volume",
                    "inspect",
                    str(config["volume"]),
                    "--format",
                    "{{.Mountpoint}}",
                ],
            )
            require(
                mount.startswith("/var/lib/docker/volumes/") and mount.endswith("/_data"),
                "volume ownership path differs",
            )
            self.home = Path(mount)
        self.healthy(self.inputs.previous_version, self.previous_binary_sha256, self.previous_image)
        private_state = self.private / "snapshot.json"
        require(
            not self.private.is_symlink()
            and private_state.is_file()
            and not private_state.is_symlink()
            and private_state.stat().st_uid == 0
            and private_state.stat().st_mode & 0o077 == 0,
            "reboot snapshot is not private owned state",
        )
        snapshot = json.loads(private_state.read_bytes())
        preserved(self.home, snapshot)
        for step in ("upgrade", "reinstall"):
            self.control(step + "-stop", "stop")
            snapshot = retained(self.home)
            self.install(self.inputs.installer, self.inputs.installer_sha256, key, initial=False)
            preserved(self.home, snapshot)
            self.control(step + "-start", "start")
            self.healthy(self.inputs.version, self.binary_sha256, self.image)
            preserved(self.home, snapshot)
        self.control("cleanup-stop", "stop")
        no_exchange(self.home)
        self.flat()
        self.command("cleanup-disable", ["systemctl", "disable", self.unit])
        if self.route == "native":
            self.command(
                "uninstall",
                [
                    "sh",
                    str(self.inputs.installer),
                    "--uninstall",
                    "--non-interactive",
                    "--service-instance",
                    "testnet",
                ],
            )
            credential = Path("/etc/credstore.encrypted/zunder-guard-testnet.hl-api-wallet-key")
        else:
            recovery = {
                name: Path("/etc/zunder-guard-container", name).read_bytes()
                for name in ("config.json", "credential.cred")
            }
            self.flat()
            self.command(
                "uninstall",
                [
                    "sh",
                    str(self.inputs.installer),
                    "--container",
                    "--uninstall",
                    "--network",
                    "testnet",
                    "--non-interactive",
                ],
            )
            names = self.command(
                "remaining-container",
                [
                    "docker",
                    "ps",
                    "-a",
                    "--filter",
                    "name=^zunder-guard-container$",
                    "--format",
                    "{{.Names}}",
                ],
            )
            require(not names, "owned container survived cleanup")
            require(
                self.command(
                    "retained-volume",
                    [
                        "docker",
                        "volume",
                        "inspect",
                        str(config["volume"]),
                        "--format",
                        "{{.Mountpoint}}",
                    ],
                )
                == str(self.home),
                "documented recovery volume is no longer registered",
            )
            for name, before in recovery.items():
                path = Path("/etc/zunder-guard-container", name)
                require(
                    not path.is_symlink() and path.read_bytes() == before,
                    "documented recovery configuration or encrypted custody changed",
                )
            # Released uninstall keeps encrypted custody and the recovery volume.
            credential = None
        if credential is not None:
            require(
                credential.is_file() and not credential.is_symlink(),
                "owned encrypted credential differs",
            )
            require(
                credential.stat().st_uid == 0 and credential.stat().st_mode & 0o077 == 0,
                "credential custody differs",
            )
            credential.unlink()
            require(not (Path("/etc/systemd/system") / self.unit).exists(), "unit survived cleanup")
        else:
            for owned in (
                "/etc/systemd/system/zunder-guard-container.service",
                "/etc/systemd/system/zunder-guard-setup-guardian.service",
                "/usr/local/libexec/zunder-guard-container/supervisor.py",
                "/usr/local/libexec/zunder-guard-container/operations.py",
                "/usr/local/libexec/zunder-guard-container/zunder-guard-container.service",
                "/etc/systemd/system/zunder-guard-container.service.d/10-install-transaction.conf",
            ):
                path = Path(owned)
                require(
                    not path.exists() and not path.is_symlink(),
                    "owned container software survived uninstall",
                )
            require(
                Path("/etc/zunder-guard-container/credential.cred").is_file()
                and Path("/etc/zunder-guard-container/config.json").is_file(),
                "documented container recovery custody/configuration missing",
            )
        preserved(self.home, snapshot)
        (self.private / "snapshot.json").unlink()
        self.private.rmdir()
        record.update(
            schema=1,
            stage="passed",
            result="passed",
            mode="testnet",
            route=self.route,
            architecture="arm64" if platform.machine() in {"arm64", "aarch64"} else "amd64",
            version=self.inputs.version,
            previous_version=self.inputs.previous_version,
            reboot_boot_id=boot,
            reboot_required=reboot_required,
            cleanup_complete=True,
            state_preserved=True,
            pairing_preserved=True,
            journal_preserved=True,
            custody="systemd-creds",
            no_exchange=True,
            exchange_requests=0,
            exchange_evidence="complete-durable-decision-journal",
            coverage=[
                "install",
                "native-custody-readback",
                "health",
                "restart",
                "daemon-reload",
                "crash-recovery",
                "upgrade",
                "reinstall",
                "pairing-retained",
                "journal-history",
                "state-retained",
                "all-dex-flat",
                "no-exchange",
                "cleanup",
                "uninstall",
            ]
            + (["kernel-reboot"] if reboot_required else []),
        )
        self.write(record)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("installer", "previous-installer", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in (
        "installer-sha256",
        "previous-installer-sha256",
        "version",
        "previous-version",
        "rules",
        "account",
        "marker",
        "binary-sha256",
        "previous-binary-sha256",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--route", choices=("native", "container"), required=True)
    parser.add_argument("--image", default="")
    parser.add_argument("--previous-image", default="")
    parser.add_argument(
        "--phase",
        choices=("before-reboot", "after-reboot", "all-no-reboot", "check-flat"),
        required=True,
    )
    values = vars(parser.parse_args())
    phase, route = values.pop("phase"), values.pop("route")
    extras = {
        name: values.pop(name)
        for name in ("binary_sha256", "previous_binary_sha256", "image", "previous_image")
    }
    key = b"" if phase == "check-flat" else sys.stdin.buffer.read(66)
    if phase != "check-flat":
        require(
            re.fullmatch(rb"[0-9a-fA-F]{64}\n", key) is not None,
            "exact protected stdin frame required",
        )
    old = os.umask(0o077)
    try:
        lifecycle = TestnetLifecycle(
            Inputs(**values, account_network="testnet"), route=route, **extras
        )
        if phase == "check-flat":
            lifecycle.flat()
            print('{"flat":true}')
            return
        if phase in {"before-reboot", "all-no-reboot"}:
            lifecycle.before(key)
        if phase in {"after-reboot", "all-no-reboot"}:
            lifecycle.after(key, reboot_required=phase != "all-no-reboot")
    finally:
        os.umask(old)


if __name__ == "__main__":
    main()
