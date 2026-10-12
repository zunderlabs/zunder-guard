"""I6 released paper-image lifecycle under its installed systemd supervisor.

Requires a prior release that actually offers the paper container route. No simulated
installer or substituted binary can stand in for the predecessor.
"""

import json
import platform
import re
import time
from pathlib import Path

from guard_harness.cli import PAIR_SCHEMA, STATUS_SCHEMA, Pair, decode_json
from guard_harness.linux_lifecycle import Inputs, NativeLifecycle, preserved, require, snapshot
from guard_harness.paper_bot import LocalGuard
from guard_harness.paper_roundtrip import round_trip

HOME = Path("/var/lib/zunder-guard-container-paper")
UNIT = "zunder-guard-container-paper.service"
UNIT_FILE = Path("/etc/systemd/system") / UNIT


class ContainerLifecycle(NativeLifecycle):
    def __init__(self, inputs: Inputs) -> None:
        inputs.validate()
        self.inputs = inputs
        inputs.output.mkdir(parents=True, exist_ok=True)
        self.guard = LocalGuard("http://127.0.0.1:8547")

    def systemctl(self, name: str, *args: str) -> str:
        return self.command(name, ["systemctl", *args, UNIT])

    def image(self) -> str:
        text = UNIT_FILE.read_text()
        images = re.findall(r"ghcr\.io/zunderlabs/zunder-guard@sha256:[0-9a-f]{64}", text)
        require(len(images) == 1, "installed paper unit image descriptor differs")
        return str(images[0])

    def docker(self, args: list[str]) -> list[str]:
        return [
            "docker",
            "--host",
            "unix:///var/run/docker.sock",
            "run",
            "--rm",
            "--network=host",
            "--user=65532:65532",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--mount",
            f"type=bind,src={HOME},dst=/data",
            self.image(),
            *args,
        ]

    def install(self, name: str, installer: Path, *, files_only: bool = False) -> None:
        require(not files_only, "container installer must run its real managed setup")
        if self.inputs.scenario == "fresh" and name == "fresh-install":
            from guard_harness.linux_channels import container_curl_install

            container_curl_install(self.inputs)
            return
        args = [
            "sh",
            str(installer),
            "--container",
            "--network",
            "paper",
            "--non-interactive",
            "--account",
            self.inputs.account,
            "--rules",
            self.inputs.rules,
        ]
        if self.inputs.account_network == "testnet":
            args.extend(["--account-network", "testnet"])
        self.command(name, args, sensitive=True)

    def version(self, expected: str) -> None:
        got = self.command("version-" + expected, self.docker(["--version"]))
        require(
            got == "zunder-guard " + expected.removeprefix("v"), "installed image version differs"
        )

    def healthy(self) -> None:
        from guard_harness.linux_lifecycle import wait_healthy

        wait_healthy(self.guard)
        raw = self.command("status", self.docker(["status", "--json", "--url", self.guard.url]))
        status = decode_json(raw, STATUS_SCHEMA)
        require(
            status["mode"] == "paper" and status["journal"]["ok"] is True,
            "container paper journal is not healthy",
        )
        require(
            status["account"].lower() == self.inputs.account.lower(), "container account differs"
        )

    def pair(self) -> Pair:
        raw = self.command("pair", self.docker(["pair", "--json"]), sensitive=True)
        paired = decode_json(raw, PAIR_SCHEMA)
        return Pair(paired["client_address"], paired["client_key"])

    def before_reboot(self) -> None:
        require(
            not HOME.exists() and not UNIT_FILE.exists(), "fresh container service machine required"
        )
        installer, _, version = self.inputs.initial
        self.install(self.inputs.scenario + "-install", installer)
        self.version(version)
        self.healthy()
        self.systemctl("stop-pair", "stop")
        pair = self.pair()
        self.keep_pair(pair)
        self.systemctl("start-pair", "start")
        self.healthy()
        seqs = [decision.seq for decision in round_trip(self.guard, pair)]
        self.systemctl("restart", "restart")
        self.healthy()
        self.recover(seqs)
        pid = self.systemctl("pid-before-crash", "show", "--property=MainPID", "--value")
        require(pid.isdigit() and int(pid) > 1, "container supervisor PID missing")
        self.systemctl("crash", "kill", "--kill-whom=main", "--signal=SIGKILL")
        deadline = time.monotonic() + 90
        while self.systemctl("pid-after-crash", "show", "--property=MainPID", "--value") in (
            pid,
            "0",
        ):
            require(time.monotonic() < deadline, "systemd did not recover killed Docker supervisor")
            time.sleep(1)
        self.healthy()
        self.recover(seqs)
        self.systemctl("enabled", "is-enabled")
        self.write(
            {
                "scenario": self.inputs.scenario,
                "initial_release": {
                    "version": self.inputs.initial[2],
                    "installer_sha256": self.inputs.initial[1],
                },
                "stage": "awaiting-reboot",
                "route": "container-paper",
                "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                "decision_seqs": seqs,
                "initial_image": self.image(),
                "installer_sha256": self.inputs.installer_sha256,
                "previous_installer_sha256": self.inputs.previous_installer_sha256,
            }
        )

    def after_reboot(self, *, require_reboot: bool = True) -> None:
        record = json.loads((self.inputs.output / "linux-lifecycle.json").read_text())
        require(
            record["stage"] == "awaiting-reboot"
            and record["route"] == "container-paper"
            and record.get("scenario") == self.inputs.scenario,
            "container reboot receipt missing",
        )
        require(
            record["installer_sha256"] == self.inputs.installer_sha256
            and record["previous_installer_sha256"] == self.inputs.previous_installer_sha256,
            "container release inputs changed across reboot",
        )
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if require_reboot:
            require(boot != record["boot_id"], "container kernel reboot not observed")
        self.healthy()
        self.recover(record["decision_seqs"])
        self.systemctl("stop-upgrade", "stop")
        before = snapshot(HOME)
        old_bytes = {path: (HOME / path).read_bytes() for path in before}
        pair = self.restored_pair()
        for step in (
            ("upgrade", "reinstall") if self.inputs.scenario == "upgrade" else ("reinstall",)
        ):
            self.install(step, self.inputs.installer)
            self.version(self.inputs.version)
            self.healthy()
            self.recover(record["decision_seqs"])
            record["decision_seqs"].extend(
                decision.seq for decision in round_trip(self.guard, pair)
            )
            self.recover(record["decision_seqs"])
            self.systemctl(step + "-stop", "stop")
            for path, contents in old_bytes.items():
                current = (HOME / path).read_bytes()
                require(
                    current.startswith(contents)
                    if path.endswith(".jsonl")
                    else current == contents,
                    "container upgrade changed config or truncated persistent journal",
                )
            before = snapshot(HOME)
            old_bytes = {path: (HOME / path).read_bytes() for path in before}
        if self.inputs.scenario == "upgrade":
            record["previous_image"] = record["initial_image"]
        record["image"] = self.image()
        self.command(
            "uninstall",
            ["sh", str(self.inputs.installer), "--container", "--network", "paper", "--uninstall"],
            sensitive=True,
        )
        preserved(before, snapshot(HOME))
        require(not UNIT_FILE.exists(), "container service uninstall left unit")
        require(
            not Path("/usr/local/libexec/zunder-guard-container-paper/install.py").exists(),
            "container uninstall left service management executable",
        )
        names = self.command(
            "uninstall-container",
            [
                "docker",
                "--host",
                "unix:///var/run/docker.sock",
                "ps",
                "-a",
                "--filter",
                "name=^zunder-guard-container-paper$",
                "--format",
                "{{.Names}}",
            ],
        )
        require(not names, "uninstall left managed container")
        self.private_pair().unlink()
        record.update(
            stage="passed",
            schema=1,
            result="passed",
            mode="paper",
            channel_coverage=["D7:container-native"],
            installer_route=(
                "curl -fsSL https://zunderlabs.com/"
                + ("i-staging" if self.inputs.loader_channel == "staging" else "i")
                + " | sh -s -- --container --network paper"
            )
            if self.inputs.scenario == "fresh"
            else "sh <authenticated-loader> --container --network paper",
            route="container",
            architecture={"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine()),
            reboot_required=require_reboot,
            cleanup_complete=True,
            state_preserved=True,
            pairing_preserved=True,
            journal_preserved=True,
            coverage=[
                "install",
                "health",
                "pair",
                "paper-allow-resize-veto",
                "restart",
                "crash-recovery",
                "journal-history",
                "reinstall",
                "state-retained",
                "pairing-retained",
                "uninstall",
                "cleanup",
            ]
            + (
                ["upgrade", "paper-post-upgrade-allow-resize-veto"]
                if self.inputs.scenario == "upgrade"
                else ["fresh-candidate-paper"]
            )
            + (["kernel-reboot"] if require_reboot else []),
            reboot_boot_id=boot,
            preserved_state=before,
            version=self.inputs.version,
            previous_version=self.inputs.previous_version,
        )
        self.write(record)
