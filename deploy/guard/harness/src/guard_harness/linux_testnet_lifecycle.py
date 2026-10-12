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
import subprocess
import sys
import time
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

from guard_harness.cli import PAIR_SCHEMA, decode_json
from guard_harness.linux_lifecycle import (
    ROOT_PATH,
    Inputs,
    LifecycleError,
    authenticated_file,
    require,
)
from guard_harness.linux_testnet_service import TestnetService
from guard_harness.paper_bot import LocalGuard, PaperError
from guard_harness.runner import run
from guard_harness.testnet_scan import SCAN_TIMEOUT, TestnetReads, flat_scan

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
            type(event.get("seq")) is int and event["seq"] == sequence + 1,
            "decision sequence incomplete",
        )
        require(record.get("prev") == previous, "decision chain differs")
        text = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        check = hashlib.sha3_256((previous + text).encode()).hexdigest()
        require(record.get("check") == check, "decision checksum differs")
        kind = event.get("kind")
        category = (
            kind
            if isinstance(kind, str)
            and kind
            in {
                "started",
                "risk",
                "stopped",
                "decision",
                "sent",
                "intent",
                "done",
                "recovered",
                "flatten",
                "protect",
                "kill",
                "error",
            }
            else "unknown"
        )
        diagnostic_seq = str(sequence + 1) if sequence < 4096 else "unknown"
        require(
            category in {"started", "risk", "stopped"},
            "action-bearing or unknown event; no exchange credit "
            f"(kind={category}, seq={diagnostic_seq})",
        )
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
        self.read.start_phase(timeout=SCAN_TIMEOUT)
        flat_scan(self.read, self.inputs.account)

    def control(self, name: str, action: str) -> None:
        self.audit()
        self.command(name, ["systemctl", action, self.unit])

    def audit(self) -> None:
        """Same-scenario controls use durable no-exchange evidence, never venue-flat credit."""
        no_exchange(self.home)
        config = tomllib.loads((self.home / "guard.toml").read_text())
        require(
            config.get("mode") == config.get("network") == "testnet"
            and config.get("account", "").lower() == self.inputs.account.lower()
            and config.get("allow_mainnet", False) is False,
            "owned Testnet runtime config differs",
        )
        expected = getattr(self, "admitted_release", None)
        require(expected is not None, "runtime identity has not been admitted")
        assert expected is not None
        version, digest, image = expected
        if self.route == "native":
            authenticated_file(self.binary, digest)
        else:
            installed = json.loads(Path("/etc/zunder-guard-container/config.json").read_bytes())
            require(installed.get("image") == image, "owned Testnet image differs")
        require(
            self.command(
                "audit-version",
                self.docker(["--version"])
                if self.route == "container"
                else [str(self.binary), "--version"],
            )
            == "zunder-guard " + version.removeprefix("v"),
            "owned Testnet executable version differs",
        )

    def container_software(self) -> dict[str, str]:
        """Capture the actual managed receipt and complete owned software trees before removal."""
        receipt = json.loads(Path("/etc/zunder-guard-container/managed-install.json").read_bytes())
        allowed = receipt.get("allowed_files")
        require(isinstance(allowed, dict) and len(allowed) == 5, "managed software receipt differs")
        assert isinstance(allowed, dict)
        inventory: dict[str, str] = {}
        units = {self.unit, "zunder-guard-setup-guardian.service"}
        for filename in allowed:
            require(isinstance(filename, str), "managed software path malformed")
            path = Path(filename)
            declared = PurePosixPath(filename)
            require(
                str(declared.parent) == "/usr/local/libexec/zunder-guard-container"
                or (str(declared.parent) == "/etc/systemd/system" and declared.name in units),
                "managed software scope differs",
            )
            require(path.is_file() and not path.is_symlink(), "managed software missing or linked")
            inventory[filename] = hashlib.sha256(path.read_bytes()).hexdigest()
        for unit in units:
            fragment = self.command(
                "owned-fragment", ["systemctl", "show", "--property=FragmentPath", "--value", unit]
            )
            require(fragment in inventory, "loaded service fragment is not owned")
        for root in (
            Path("/usr/local/libexec/zunder-guard-container"),
            *(Path("/etc/systemd/system") / (unit + ".d") for unit in units),
        ):
            if not root.exists():
                continue
            require(root.is_dir() and not root.is_symlink(), "owned software tree differs")
            inventory[str(root)] = "directory"
            for path in root.rglob("*"):
                require(
                    not path.is_symlink() and (path.is_file() or path.is_dir()),
                    "owned software tree contains unsafe entry",
                )
                inventory[str(path)] = (
                    "directory" if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()
                )
        return inventory

    def refuse_pending_uninstall(self, words: list[str]) -> None:
        try:
            result = subprocess.run(
                words,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=120,
                check=False,
                env={"PATH": ROOT_PATH, "HOME": "/root"},
            )
        except (OSError, subprocess.SubprocessError):
            raise LifecycleError(
                "pending transaction uninstall outcome unknown; diagnostics withheld"
            ) from None
        output = result.stdout + result.stderr
        (self.inputs.output / "uninstall-refusal.log").write_text(
            "Sensitive uninstall diagnostics withheld.\n"
        )
        require(
            result.returncode > 0
            and len(output) <= 65536
            and b"Resolve installer transaction before uninstall." in output,
            "released uninstall did not prove the expected transaction refusal",
        )

    def live_container_uninstall(self, words: list[str]) -> dict[str, str]:
        self.audit()
        inventory = self.container_software()
        pid = self.command(
            "live-uninstall-pid", ["systemctl", "show", "--property=MainPID", "--value", self.unit]
        )
        require(pid.isdigit() and int(pid) > 1, "live supervisor PID missing before uninstall")
        for unit in (self.unit, "zunder-guard-setup-guardian.service"):
            require(
                self.command(
                    "live-uninstall-state",
                    ["systemctl", "show", "--property=ActiveState", "--value", unit],
                )
                == "active",
                "owned runtime/guardian not active before uninstall",
            )
        identity = self.command(
            "live-container-id",
            ["docker", "inspect", "--format", "{{.Id}}", "zunder-guard-container"],
        )
        require(
            re.fullmatch("[0-9a-f]{64}", identity) is not None,
            "live owned container identity missing",
        )
        retained_state = retained(self.home)
        recovery = {
            name: Path("/etc/zunder-guard-container", name).read_bytes()
            for name in ("config.json", "credential.cred", "managed-install.json")
        }
        gate = Path("/etc/zunder-guard-container/install-transaction.json")
        require(
            not gate.exists() and not gate.is_symlink(),
            "real installer transaction needs resolution",
        )
        marker = b'{"harness_uninstall_refusal":1}\n'
        with gate.open("xb") as stream:
            gate.chmod(0o600)
            stream.write(marker)
        self.refuse_pending_uninstall(words)
        require(
            gate.read_bytes() == marker and not gate.is_symlink(),
            "refusal transaction marker changed",
        )
        require(
            self.command(
                "refused-uninstall-pid",
                ["systemctl", "show", "--property=MainPID", "--value", self.unit],
            )
            == pid,
            "refused uninstall replaced/stopped runtime",
        )
        for unit in (self.unit, "zunder-guard-setup-guardian.service"):
            require(
                self.command(
                    "refused-uninstall-state",
                    ["systemctl", "show", "--property=ActiveState", "--value", unit],
                )
                == "active",
                "refused uninstall changed runtime/guardian protection",
            )
        require(
            self.command(
                "refused-container-id",
                ["docker", "inspect", "--format", "{{.Id}}", "zunder-guard-container"],
            )
            == identity,
            "refused uninstall replaced the owned container",
        )
        require(self.container_software() == inventory, "refused uninstall changed owned software")
        preserved(self.home, retained_state)
        for name, before in recovery.items():
            require(
                Path("/etc/zunder-guard-container", name).read_bytes() == before,
                "refused uninstall changed private recovery state",
            )
        self.audit()
        gate.unlink()  # Only the unchanged marker created above, never an adopted transaction.
        self.command("uninstall", words)  # Still-running Guard is stopped by the released product.
        for filename in inventory:
            path = Path(filename)
            require(
                not path.exists() and not path.is_symlink(),
                "owned software inventory survived uninstall",
            )
        for unit in (self.unit, "zunder-guard-setup-guardian.service"):
            require(
                self.command(
                    "removed-unit-state",
                    ["systemctl", "show", "--property=LoadState", "--value", unit],
                )
                == "not-found"
                and self.command(
                    "removed-unit-pid", ["systemctl", "show", "--property=MainPID", "--value", unit]
                )
                == "0",
                "owned service/process survived uninstall",
            )
        return inventory

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
        self.admitted_release = (version, digest, image)

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
            self.admitted_release = (self.inputs.version, self.binary_sha256, self.image)
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
        if not initial:
            self.admitted_release = (self.inputs.version, self.binary_sha256, self.image)

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
        installer, digest, version = self.inputs.initial
        self.install(installer, digest, key, initial=True)
        self.healthy(
            self.inputs.initial[2],
            self.binary_sha256 if self.inputs.scenario == "fresh" else self.previous_binary_sha256,
            self.image if self.inputs.scenario == "fresh" else self.previous_image,
        )
        self.control("pair-stop", "stop")
        self.audit()
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
        self.healthy(
            self.inputs.initial[2],
            self.binary_sha256 if self.inputs.scenario == "fresh" else self.previous_binary_sha256,
            self.image if self.inputs.scenario == "fresh" else self.previous_image,
        )
        self.control("restart", "restart")
        self.healthy(
            self.inputs.initial[2],
            self.binary_sha256 if self.inputs.scenario == "fresh" else self.previous_binary_sha256,
            self.image if self.inputs.scenario == "fresh" else self.previous_image,
        )
        self.audit()
        self.command("daemon-reload", ["systemctl", "daemon-reload"])
        self.control("reload-restart", "restart")
        pid = self.command(
            "old-pid", ["systemctl", "show", "--property=MainPID", "--value", self.unit]
        )
        require(pid.isdigit() and int(pid) > 1, "service PID missing")
        self.audit()
        self.command(
            "crash", ["systemctl", "kill", "--kill-whom=main", "--signal=SIGKILL", self.unit]
        )
        deadline = time.monotonic() + 120
        while self.command(
            "recovered-pid", ["systemctl", "show", "--property=MainPID", "--value", self.unit]
        ) in (pid, "0"):
            require(time.monotonic() < deadline, "service crash recovery deadline")
            time.sleep(1)
        self.healthy(
            self.inputs.initial[2],
            self.binary_sha256 if self.inputs.scenario == "fresh" else self.previous_binary_sha256,
            self.image if self.inputs.scenario == "fresh" else self.previous_image,
        )
        preserved(self.home, snapshot)
        self.command("enabled", ["systemctl", "is-enabled", self.unit])
        self.flat()
        self.write(
            {
                "scenario": self.inputs.scenario,
                "initial_release": {
                    "version": self.inputs.initial[2],
                    "installer_sha256": self.inputs.initial[1],
                },
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
            and record.get("scenario") == self.inputs.scenario
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
        self.healthy(
            self.inputs.initial[2],
            self.binary_sha256 if self.inputs.scenario == "fresh" else self.previous_binary_sha256,
            self.image if self.inputs.scenario == "fresh" else self.previous_image,
        )
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
        for step in (
            ("upgrade", "reinstall") if self.inputs.scenario == "upgrade" else ("reinstall",)
        ):
            self.control(step + "-stop", "stop")
            snapshot = retained(self.home)
            self.install(self.inputs.installer, self.inputs.installer_sha256, key, initial=False)
            preserved(self.home, snapshot)
            self.control(step + "-start", "start")
            self.healthy(self.inputs.version, self.binary_sha256, self.image)
            preserved(self.home, snapshot)
        if self.route == "native":
            self.control("cleanup-stop", "stop")
        no_exchange(self.home)
        self.flat()
        if self.route == "native":
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
            owned_inventory = self.live_container_uninstall(
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
            for owned in owned_inventory:
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
            channel_coverage=[],
            installer_route=(
                "sh <authenticated-loader> --container --network testnet"
                if self.route == "container"
                else "native-protected-service"
            ),
            architecture="arm64" if platform.machine() in {"arm64", "aarch64"} else "amd64",
            version=self.inputs.version,
            previous_version=self.inputs.previous_version,
            binary_sha256=self.binary_sha256,
            previous_binary_sha256=self.previous_binary_sha256,
            image=self.image,
            previous_image=self.previous_image,
            runtime_identity_evidence=(
                "native-file-sha256"
                if self.route == "native"
                else "signed-immutable-prebuilt-image"
            ),
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
                "reinstall",
                "pairing-retained",
                "journal-history",
                "state-retained",
                "all-dex-flat",
                "no-exchange",
                "cleanup",
                "uninstall",
            ]
            + (["upgrade"] if self.inputs.scenario == "upgrade" else ["fresh-candidate-testnet"])
            + (["kernel-reboot"] if reboot_required else []),
        )
        if self.route == "container":
            record["owned_software_inventory"] = owned_inventory
            record["coverage"].extend(
                ["uninstall-live-stop", "uninstall-transaction-refusal", "owned-software-inventory"]
            )
        if self.inputs.scenario == "fresh":
            record.pop("previous_binary_sha256", None)
            record.pop("previous_image", None)
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
    parser.add_argument("--scenario", choices=("fresh", "upgrade"), default="upgrade")
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
