"""Released Keychain, Windows per-user and Windows SCM testnet lifecycle. Read-only HTTP only.

Never /exchange. On Windows the per-user install is measured first, then the SCM service
with its hosted crash-policy step, from 1.0.2 (`WINDOWS_SERVICE`). An upgrade from a release
before the first working service measures the per-user scope only.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

from guard_harness.lifecycle_coverage import (
    WINDOWS_SERVICE_SCOPE,
    WINDOWS_SERVICE_SKIP,
    WINDOWS_TESTNET_SCOPE,
    windows_service_measured,
)
from guard_harness.native_paper import LifecycleError, Paper
from guard_harness.native_release import Release, staged_loader
from guard_harness.paper_bot import LocalGuard, PaperError
from guard_harness.runner import run
from guard_harness.source_installer import Candidate, prepare, verify_file
from guard_harness.testnet_run import ROOT
from guard_harness.testnet_scan import TestnetReads, flat_scan
from guard_harness.windows_diagnostics import observe as windows_observe

# The helper's transaction phases (install-windows-service.ps1, Read-ZgTransaction).
PHASES = frozenset(
    {
        "install-planned",
        "paths-created",
        "image-admitted",
        "service-created-disabled",
        "config-preparing",
        "config-prepared",
        "binding-prepared",
        "credential-provisioning",
        "credential-present",
        "admitted-disabled",
        "journal-requested",
        "journal-present",
        "upgrade-planned",
        "startup-disabled",
        "quiesced",
        "promoting-image",
        "promoting-binding",
        "activation-requested",
        "activation-committed",
        "stopped",
        "uninstalled",
        "rolled-back",
    }
)
# sc.exe query STATE and qc START_TYPE names.
SCM_VALUES = frozenset(
    {
        "STOPPED",
        "START_PENDING",
        "STOP_PENDING",
        "RUNNING",
        "CONTINUE_PENDING",
        "PAUSE_PENDING",
        "PAUSED",
        "BOOT_START",
        "SYSTEM_START",
        "AUTO_START",
        "DEMAND_START",
        "DISABLED",
    }
)
# The Windows service (SCM) route is measured from 1.0.2, after per-user custody.
WINDOWS_SERVICE = True


class NativeTestnet:
    def __init__(
        self,
        current: Release,
        previous: Release,
        work: Path,
        account: str,
        shell: str,
        scenario: str = "upgrade",
        source: Candidate | None = None,
        source_path: Path | None = None,
        *,
        windows_service: bool | None = None,
    ) -> None:
        self.current, self.previous, self.work, self.account = current, previous, work, account
        self.shell = shell
        if scenario not in {"fresh", "upgrade"}:
            raise LifecycleError("native lifecycle scenario refused")
        self.scenario = scenario
        self.mac = platform.system() == "Darwin"
        self.windows_service = (
            WINDOWS_SERVICE and not self.mac if windows_service is None else windows_service
        )
        if self.mac and self.windows_service:
            raise LifecycleError("Windows service route refused on macOS")
        if source is not None and (
            not self.mac
            or scenario != "fresh"
            or source.tag != current.tag
            or source.release_commit != current.commit
            or source_path is None
        ):
            raise LifecycleError("source installer must bind the current Mac component")
        self.source, self.source_path = source, source_path
        self.sequence = 0
        self.key: bytes = b""
        self.observed: dict[str, dict[str, str]] = {}
        self.journal_digest = ""
        self.env = {
            name: value for name, value in os.environ.items() if not name.startswith("ZUNDER_")
        }
        self.id = "testnet-install-matrix"
        self.url = "http://127.0.0.1:18547"
        if self.mac:
            self.base = Path("/Library/Application Support/Zunder Guard")
            self.home = self.base / "state-testnet"
            self.binding = self.base / "bindings-testnet/active.json"
            self.plist = Path("/Library/LaunchDaemons/com.zunderlabs.guard.testnet-native.plist")
            self.label = "system/com.zunderlabs.guard.testnet-native"
        else:
            self.base = Path(os.environ["ProgramData"]) / "ZunderGuard"
            self.home = self.base / self.id / "runtime"
            self.binding = self.base / self.id / "binding.json"
            self.transaction = self.base / "management" / f"{self.id}.json"

    def command(
        self,
        words: list[str],
        *,
        key: bool = False,
        sensitive: bool = False,
        failure_classifier: Callable[[str], str] | None = None,
    ) -> str:
        self.sequence += 1
        return run(
            words,
            env=self.env,
            log=self.work / f"step-{self.sequence}.log",
            timeout=600,
            stdin=self.key * 2 if key else b"",
            sensitive_output=sensitive,
            secrets=[self.key.decode().strip()],
            failure_classifier=failure_classifier,
        ).output.strip()

    def scm_state(self) -> list[str]:
        """After a failed Windows install: the owned transaction's phase and the SCM state,
        each from a closed set. No path, SID, account, argument or free text."""
        lines = []
        try:
            if self.transaction.is_file() and self.transaction.stat().st_size <= 65536:
                phase = json.loads(self.transaction.read_bytes()).get("phase")
                lines.append(f"transaction phase: {phase if phase in PHASES else 'other'}")
            else:
                lines.append("transaction phase: absent")
        except (OSError, ValueError, AttributeError):
            lines.append("transaction phase: unreadable")
        sc = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "sc.exe"
        for verb, field, name in (
            ("query", "STATE", "scm state"),
            ("qc", "START_TYPE", "scm start"),
        ):
            try:
                result = subprocess.run(
                    [str(sc), verb, f"ZunderGuard-{self.id}"],
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                lines.append(f"{name}: unavailable")
                continue
            if result.returncode == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
                lines.append(f"{name}: absent")
                continue
            text = result.stdout.decode("utf-8", errors="replace")
            match = re.search(rf"^\s*{field}\s*:\s*\d+\s+([A-Z_]+)", text, re.M)
            value = match[1] if match and match[1] in SCM_VALUES else f"exit {result.returncode}"
            lines.append(f"{name}: {value}")
        return lines

    def ps(self, words: list[str]) -> list[str]:
        return [self.shell, "-NoProfile", "-ExecutionPolicy", "Bypass", *words]

    def installed(self) -> Path:
        if self.mac:
            value = json.loads(self.command(["sudo", "cat", str(self.binding)], sensitive=True))
            return Path(value["executable"])
        return Path(os.environ["ProgramFiles"]) / "ZunderGuard" / self.id / "zunder-guard.exe"

    def identity(self, release: Release) -> None:
        binary = self.installed()
        if self.mac:
            value = self.command(["sudo", "shasum", "-a", "256", str(binary)], sensitive=True)
            digest = value.split()[0] if value.split() else ""
        else:
            if binary.is_symlink():
                raise LifecycleError("installed Testnet executable is a symlink")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        target = "darwin-arm64" if self.mac else "windows-amd64"
        version = self.command((["sudo"] if self.mac else []) + [str(binary), "--version"])
        if digest != hashlib.sha256(
            release.binary(target)
        ).hexdigest() or version != "zunder-guard " + release.tag.removeprefix("v"):
            raise LifecycleError("native Testnet version or installed bytes differ")
        self.observed[release.tag] = dict(
            commit=release.commit, binary_sha256=digest, version=version
        )

    def audit(self) -> None:
        from guard_harness.native_journal import audit

        journal = self.home / "decisions.jsonl"
        if self.mac:
            text = self.command(["sudo", "head", "-c", "8388609", str(journal)], sensitive=True)
            if len(text.encode()) > 8 * 1024 * 1024:
                raise LifecycleError("native decision journal exceeds audit bound")
            body = text.rstrip("\x00").rstrip("\n").encode() + b"\n"
            emergency = bool(
                self.command(
                    [
                        "sudo",
                        "/bin/sh",
                        "-c",
                        'test ! -L "$1" && { test ! -e "$1" || '
                        'find "$1" -mindepth 1 -print -quit; }',
                        "guard-emergency-probe",
                        str(self.home / "emergency"),
                    ],
                    sensitive=True,
                )
            )
        else:
            if journal.is_symlink():
                raise LifecycleError("native decision journal is a symlink")
            body = journal.read_bytes()
            emergency = any((self.home / "emergency").rglob("*"))
        self.journal_digest = audit(body, emergency_present=emergency)

    def snapshot(self) -> dict[str, bytes]:
        result: dict[str, bytes] = {}
        for name in ("guard.toml", "risk.jsonl", "decisions.jsonl"):
            path = self.home / name
            if self.mac:
                body = self.command(["sudo", "cat", str(path)], sensitive=True).encode()
            else:
                body = path.read_bytes()
            if name.endswith(".jsonl"):
                body = body.rstrip(b"\x00")
            if not body:
                raise LifecycleError("native configuration/journal missing")
            result[name] = body
        return result

    def retained(self, old: dict[str, bytes]) -> None:
        new = self.snapshot()
        if new["guard.toml"] != old["guard.toml"] or any(
            not new[name].startswith(old[name]) for name in ("risk.jsonl", "decisions.jsonl")
        ):
            raise LifecycleError("native upgrade lost configuration/pairings/journal prefix")

    def helper(self) -> Path:
        record = json.loads(self.transaction.read_bytes())
        helper = Path(record["release"]) / "install-windows-service.ps1"
        if hashlib.sha256(helper.read_bytes()).hexdigest() != record["helper_hash"]:
            raise LifecycleError("retained Windows service helper changed")
        return helper

    def action(self, action: str, *extra: str) -> None:
        self.command(
            self.ps(
                [
                    "-File",
                    str(self.helper()),
                    "-Action",
                    action,
                    "-Network",
                    "testnet",
                    "-Id",
                    self.id,
                    "-ConfirmAccount",
                    self.account,
                    *extra,
                ]
            )
        )

    def install(self, release: Release, *, fresh: bool = False) -> None:
        loader = self.work / (f"loader-{release.tag}" + ("" if self.mac else ".ps1"))
        if release == self.current:
            staged_loader(
                release,
                windows=not self.mac,
                output=loader,
                channel="canonical"
                if os.environ.get("INSTALL_MATRIX_PROFILE") == "nightly"
                else "staging",
            )
        else:
            loader.write_bytes(release.asset("i" if self.mac else "i.ps1"))
        rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
        if self.mac:
            if self.source is not None and release == self.current:
                if self.source_path is None:
                    raise LifecycleError("source installer path missing")
                verify_file(self.source_path, self.source.digest)
                loader = self.source_path
            words = [
                "sudo",
                "-n",
                "sh",
                str(loader),
                "--network",
                "testnet",
                "--non-interactive",
                "--key-stdin",
            ]
            if fresh:
                words += [
                    "--rules",
                    rules,
                    "--account",
                    self.account,
                    "--equity-cap",
                    "100",
                    "--listen",
                    "127.0.0.1:18547",
                ]
            self.command(words, key=fresh, sensitive=True)
        else:
            with windows_observe(
                self.work, "scm-install", installer=True, after_failure=self.scm_state
            ) as classifier:
                self.command(
                    self.ps(
                        [
                            "-File",
                            str(loader),
                            "-Network",
                            "testnet",
                            "-ManagedService",
                            "-NonInteractive",
                            "-KeyStdin",
                            "-Id",
                            self.id,
                            "-Rules",
                            rules,
                            "-Account",
                            self.account,
                            "-ConfirmAccount",
                            self.account,
                            "-EquityCap",
                            "100",
                        ]
                    ),
                    key=fresh,
                    sensitive=True,
                    failure_classifier=classifier,
                )
            if not fresh:
                # Loader authenticates and retains the new helper but never upgrades itself.
                candidates = list(
                    (self.base / "management/releases").glob("*/install-windows-service.ps1")
                )
                captured = release.asset("install-windows-service.ps1")
                matches = [
                    path
                    for path in candidates
                    if path.read_bytes() == captured
                    and (path.parent / f"zunder-guard-{release.tag}-windows-amd64.zip").is_file()
                ]
                if len(matches) != 1:
                    raise LifecycleError("exact authenticated next helper cache ambiguous")
                helper = matches[0]
                self.command(
                    self.ps(
                        [
                            "-File",
                            str(helper),
                            "-Action",
                            "Upgrade",
                            "-Network",
                            "testnet",
                            "-ReleaseDir",
                            str(helper.parent),
                            "-Tag",
                            release.tag,
                            "-Id",
                            self.id,
                            "-ConfirmAccount",
                            self.account,
                        ]
                    )
                )
        self.identity(release)
        binary = self.installed()
        check = [str(binary), "service", "check", "--binding", str(self.binding), "--json"]
        value = json.loads(self.command((["sudo"] if self.mac else []) + check))
        if (
            value.get("ok") is not True
            or value.get("mode") != "testnet"
            or value.get("account", "").lower() != self.account.lower()
        ):
            raise LifecycleError("native credential custody/readback not admitted")

    def launchctl_status(self, *words: str) -> int:
        """Keep status evidence without retaining launchd's private service details."""
        self.sequence += 1
        log = self.work / f"step-{self.sequence}.log"
        try:
            result = subprocess.run(
                ["sudo", "launchctl", *words],
                env=self.env,
                capture_output=True,
                timeout=10,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            log.write_text("[launchctl output withheld]\ncommand outcome: unavailable\n")
            raise LifecycleError("native launchctl command unavailable or timed out") from None
        log.write_text(f"[launchctl output withheld]\nexit status: {result.returncode}\n")
        return result.returncode

    def wait_unloaded(self) -> None:
        # bootout is asynchronous: only 113 proves this exact registration is absent.
        for attempt in range(30):
            status = self.launchctl_status("print", self.label)
            if status == 113:
                return
            if status != 0:
                raise LifecycleError(f"native launchctl print failed with exit {status}")
            if attempt < 29:
                time.sleep(1)
        raise LifecycleError("native launchd service did not unload before deadline")

    def start(self) -> None:
        if self.mac:
            for attempt in range(3):
                self.wait_unloaded()
                status = self.launchctl_status("bootstrap", "system", str(self.plist))
                if status == 0:
                    return
                if status != 5 or attempt == 2:
                    raise LifecycleError(f"native launchctl bootstrap failed with exit {status}")
                time.sleep(1)
        else:
            self.action("Start", "-Startup", "Manual")

    def stop(self) -> None:
        if self.mac:
            self.command(["sudo", "launchctl", "bootout", self.label])
            self.wait_unloaded()
        else:
            self.action("Stop")

    def healthy(self, release: Release) -> None:
        self.identity(release)
        guard = LocalGuard(self.url if self.mac else "http://127.0.0.1:8547")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                status = guard.request("/guard/status")
                if status.get("last_sync_ms") and status.get("version") == release.tag[1:]:
                    if (
                        status.get("mode") != "testnet"
                        or status.get("account", "").lower() != self.account.lower()
                    ):
                        raise LifecycleError("native sending runtime identity differs")
                    return
            except PaperError:
                pass
            time.sleep(1)
        raise LifecycleError("native service failed read-only testnet health deadline")

    def crash(self) -> None:
        if self.mac:
            self.command(["sudo", "launchctl", "kill", "SIGKILL", self.label])
        else:
            service = "ZunderGuard-" + self.id
            self.command(
                self.ps(
                    [
                        "-Command",
                        "$p=(Get-CimInstance Win32_Service -Filter \"Name='"
                        + service
                        + "'\").ProcessId; if($p -le 0){throw 'Missing owned service PID'};"
                        " Stop-Process -Id $p -Force",
                    ]
                )
            )

    def ensure_macos_journal(self) -> None:
        """Preserve setup's journal; absence alone permits the explicit Testnet init."""
        journal = self.home / "risk.jsonl"
        state = self.command(
            [
                "sudo",
                "/bin/sh",
                "-c",
                'if [ -L "$1" ]; then exit 2; '
                'elif [ -f "$1" ] && [ -s "$1" ]; then printf present; '
                'elif [ ! -e "$1" ]; then printf absent; else exit 2; fi',
                "guard-journal-probe",
                str(journal),
            ]
        )
        if state == "present":
            return
        if state != "absent":
            raise LifecycleError("cannot establish protected Testnet journal absence")
        self.command(
            [
                "sudo",
                "-u",
                "_zunder_guard_testnet",
                str(self.installed()),
                "--home",
                str(self.home),
                "journal-init",
                "--mode",
                "testnet",
                "--note",
                "released installer lifecycle read-only test",
            ]
        )

    def execute(self, key: bytes) -> dict[str, object]:
        self.key = key
        self.work.mkdir(mode=0o700)
        active = False
        try:
            windows_policy: dict[str, object] = {}
            if not self.mac:
                # Independent per-user custody must still be measured when SCM admission refuses.
                with windows_observe(self.work, "per-user-lifecycle"):
                    measured = per_user(self, self.work / "per-user", key)
                if not self.windows_service:
                    # Route switched off (diagnostics only): row admission refuses this receipt.
                    return {**measured, "scope": WINDOWS_TESTNET_SCOPE}
                if not windows_service_measured(self.scenario, self.previous.tag):
                    # An upgrade from a release without a working service: nothing to upgrade
                    # under SCM. The skip is named in the receipt, never silent.
                    return {
                        **measured,
                        "scope": WINDOWS_TESTNET_SCOPE,
                        "service_skipped": WINDOWS_SERVICE_SKIP,
                    }
                self.key = key  # Per-user cleanup clears its copy; SCM has a separate admission.
                from guard_harness.windows_policy import prepare as prepare_windows_policy

                with windows_observe(self.work, "crash-policy-prepare"):
                    windows_policy = prepare_windows_policy(
                        self.current, self.work / "windows-policy", self.env
                    )
            initial = self.current if self.scenario == "fresh" else self.previous
            self.install(initial, fresh=True)
            if self.mac:
                self.ensure_macos_journal()
            self.start()
            active = True
            self.healthy(initial)
            old = self.snapshot()
            self.crash()
            self.healthy(initial)
            self.stop()
            self.audit()
            active = False
            self.retained(old)
            self.start()
            active = True
            self.healthy(initial)
            self.stop()
            self.audit()
            active = False
            if self.scenario == "upgrade":
                flat_scan(TestnetReads(), self.account)
            self.install(self.current)
            self.retained(old)
            self.start()
            active = True
            self.healthy(self.current)
            self.stop()
            self.audit()
            active = False
            self.install(self.current)
            self.retained(old)
            self.start()
            active = True
            self.healthy(self.current)
            self.stop()
            self.audit()
            active = False
            if self.mac:
                from guard_harness.native_uninstall import (
                    assert_foreground_removed,
                    execute,
                    prepare_foreground,
                )

                foreground = prepare_foreground(self.current, self.work, self.env)
                (self.work / "foreground-cleanup.log").write_text(
                    f"foreground cleanup: {foreground}\n"
                )
                self.sequence += 1
                execute(self.current, self.work, self.env, self.work / f"step-{self.sequence}.log")
                if self.plist.exists():
                    raise LifecycleError("launchd registration survived removal")
                if foreground == "product-uninstall":
                    assert_foreground_removed()
            else:
                self.action("Uninstall")
                self.command(
                    self.ps(
                        [
                            "-Command",
                            "if(Get-Service -Name 'ZunderGuard-"
                            + self.id
                            + "' -ErrorAction SilentlyContinue)"
                            "{throw 'SCM service survived uninstall'}",
                        ]
                    )
                )
            self.retained(old)
            return {
                **windows_policy,
                **(self.source.record() if self.source is not None else {}),
                "schema": 1,
                "result": "passed",
                "mode": "testnet",
                "scenario": self.scenario,
                "tag": self.current.tag,
                "commit": self.current.commit,
                "manifest_sha256": hashlib.sha256(
                    self.current.asset("release-manifest.json")
                ).hexdigest(),
                "observed_releases": self.observed,
                "decision_journal_sha256": self.journal_digest,
                "no_exchange": True,
                **({"foreground_cleanup": foreground} if self.mac else {}),
                **({} if self.mac else {"scope": WINDOWS_SERVICE_SCOPE}),
                "coverage": [
                    *(
                        ["windows-crash-policy-refusal", "windows-crash-policy-removed"]
                        if not self.mac
                        else []
                    ),
                    "signed-release",
                    "native-custody-readback",
                    "health",
                    "restart",
                    "crash-recovery",
                    "supervisor-reload",
                    "fresh-candidate" if self.scenario == "fresh" else "upgrade",
                    "reinstall",
                    "pairing-config-retained",
                    "journal-prefix",
                    "uninstall",
                    "no-exchange",
                ],
            }
        finally:
            if active:
                self.stop()
            self.key = b""


def candidate_user_setup(native: NativeTestnet, paper: Paper, work: Path, rules: str) -> None:
    """Prove candidate loader custody, never substitute direct binary init."""
    paper.home = work / "candidate-loader-home"
    paper.home.mkdir(mode=0o700)
    native.env["ZUNDER_GUARD_HOME"] = str(paper.home)
    paper.env["ZUNDER_GUARD_HOME"] = str(paper.home)
    loader = work / "candidate-setup.ps1"
    staged_loader(
        native.current,
        windows=True,
        output=loader,
        channel="canonical" if os.environ.get("INSTALL_MATRIX_PROFILE") == "nightly" else "staging",
    )
    native.command(
        native.ps(
            [
                "-File",
                str(loader),
                "-Network",
                "testnet",
                "-NonInteractive",
                "-KeyStdin",
                "-Rules",
                rules,
                "-Account",
                native.account,
                "-InstallDir",
                str(paper.binary.parent),
            ]
        ),
        key=True,
        sensitive=True,
    )


def per_user(native: NativeTestnet, work: Path, key: bytes) -> dict[str, object]:
    """Ordinary Windows Credential Manager setup and stored-key startup, no orders."""
    work.mkdir(mode=0o700)
    paper = Paper(
        release=native.current,
        previous=native.previous,
        work=work,
        shell=native.shell,
        scenario=native.scenario,
    )
    paper.home.mkdir(mode=0o700)
    native.env["ZUNDER_GUARD_HOME"] = str(paper.home)
    rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
    loader = work / "previous.ps1"
    loader.write_bytes(native.previous.asset("i.ps1"))
    native.key = key
    try:
        # Per-user custody is a separate admission from the machine-service route.
        flat_scan(TestnetReads(), native.account)
        initial = native.current if native.scenario == "fresh" else native.previous
        paper.install(initial)
        if native.scenario == "fresh":
            candidate_user_setup(native, paper, work, rules)
        else:
            native.command(
                [
                    str(paper.binary),
                    "--home",
                    str(paper.home),
                    "init",
                    "--non-interactive",
                    "--network",
                    "testnet",
                    "--key-stdin",
                    "--key-store",
                    "credential-manager",
                    "--rules",
                    rules,
                    "--account",
                    native.account,
                ],
                key=True,
                sensitive=True,
            )
        journal_digest = ""
        for index, release in enumerate((initial, native.current, native.current)):
            if index > 0:
                if index == 1 and native.scenario == "upgrade":
                    flat_scan(TestnetReads(), native.account)
                paper.install(release, upgrade=True)
            if (
                hashlib.sha256(paper.binary.read_bytes()).digest()
                != hashlib.sha256(release.binary("windows-amd64")).digest()
            ):
                raise LifecycleError("per-user sending binary differs from authenticated release")
            # No key flag: real Guard must retrieve its stored Credential Manager key.
            with (work / "runtime.log").open("ab") as output:
                process = subprocess.Popen(
                    [
                        str(paper.binary),
                        "--home",
                        str(paper.home),
                        "run",
                        "--network",
                        "testnet",
                        "--listen",
                        "127.0.0.1:18548",
                    ],
                    env=paper.env,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=output,
                )
                try:
                    with windows_observe(native.work, "per-user-readiness"):
                        guard = LocalGuard("http://127.0.0.1:18548")
                        deadline = time.monotonic() + 120
                        while time.monotonic() < deadline:
                            if process.poll() is not None:
                                raise LifecycleError("stored-key per-user runtime exited")
                            try:
                                status = guard.request("/guard/status")
                                if (
                                    status.get("last_sync_ms")
                                    and status.get("version") == release.tag[1:]
                                ):
                                    if (
                                        status.get("mode") != "testnet"
                                        or status.get("account", "").lower()
                                        != native.account.lower()
                                    ):
                                        raise LifecycleError("per-user testnet identity mismatch")
                                    break
                            except PaperError:
                                pass
                            time.sleep(1)
                        else:
                            raise LifecycleError("per-user testnet readiness deadline")
                finally:
                    with windows_observe(native.work, "per-user-shutdown"):
                        process.terminate()
                        try:
                            process.wait(timeout=40)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=10)
            with windows_observe(native.work, "per-user-journal-audit"):
                from guard_harness.native_journal import audit

                journal_digest = audit(
                    (paper.home / "decisions.jsonl").read_bytes(),
                    emergency_present=any((paper.home / "emergency").rglob("*")),
                )
        native.command(
            native.ps(
                [
                    "-File",
                    str(work / f"loader-{native.current.tag}.ps1"),
                    "-Uninstall",
                    "-NonInteractive",
                    "-InstallDir",
                    str(paper.binary.parent),
                ]
            )
        )
        if paper.binary.exists():
            raise LifecycleError("released per-user uninstall retained executable")
        receipt: dict[str, object] = {
            "result": "passed",
            "schema": 1,
            "mode": "testnet",
            "scenario": native.scenario,
            "tag": native.current.tag,
            "commit": native.current.commit,
            "manifest_sha256": hashlib.sha256(
                native.current.asset("release-manifest.json")
            ).hexdigest(),
            "observed_releases": paper.observed,
            "decision_journal_sha256": journal_digest,
            "no_exchange": True,
            "coverage": [
                "credential-manager",
                "candidate-loader-stdin" if native.scenario == "fresh" else "previous-release-init",
                "stored-key-runtime",
                "read-only-health",
                "restart",
                "fresh-candidate" if native.scenario == "fresh" else "upgrade",
                "reinstall",
                "uninstall",
                "no-exchange",
            ],
        }
        (work / "receipt.json").write_text(json.dumps(receipt) + "\n")
        return receipt
    finally:
        native.key = b""
        native.env.pop("ZUNDER_GUARD_HOME", None)


def sanitize_logs(work: Path, key: bytes) -> None:
    """Keep diagnostics while removing runtime wallet/account identities on every exit."""
    frame = key.decode().strip()
    for log in work.rglob("*.log"):
        if log.is_symlink() or not log.is_file():
            raise LifecycleError("native artifact log is not a regular file")
        text = log.read_text(errors="replace")
        if frame:
            text = re.sub(re.escape(frame), "[REDACTED]", text, flags=re.IGNORECASE)
        text = re.sub(r"0x[0-9a-f]{40}\b", "[ADDRESS]", text, flags=re.IGNORECASE)
        log.write_text(text)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tag", "commit", "previous-tag", "previous-commit", "account"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--shell", default="powershell.exe")
    parser.add_argument("--scenario", choices=("fresh", "upgrade"), default="upgrade")
    parser.add_argument("--mode", choices=("testnet", "mainnet-refusal"), default="testnet")
    parser.add_argument("--source-installer", type=Path)
    args = parser.parse_args()
    source = prepare(args.tag, args.commit, scenario=args.scenario, row="I3")
    if source is not None:
        if args.mode != "testnet" or platform.system() != "Darwin" or args.source_installer is None:
            raise LifecycleError("source installer requires current Mac Testnet component")
        verify_file(args.source_installer, source.digest)
    elif args.source_installer is not None:
        raise LifecycleError("unexpected source installer override")
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise LifecycleError("disposable GitHub-hosted native runner required")
    if args.mode == "mainnet-refusal":
        from guard_harness.native_mainnet import exercise

        exercise(
            Release(args.tag, args.commit, args.assets / "candidate/assets"),
            account=args.account,
            work=args.work,
            shell=args.shell,
        )
        return
    key = sys.stdin.buffer.readline(68)
    if re.fullmatch(rb"(?:0x)?[0-9a-fA-F]{64}\n", key) is None:
        raise LifecycleError("one private bounded wallet frame required")
    native = NativeTestnet(
        Release(args.tag, args.commit, args.assets / "candidate/assets"),
        Release(args.previous_tag, args.previous_commit, args.assets / "previous/assets"),
        args.work,
        args.account,
        args.shell,
        args.scenario,
        source,
        args.source_installer,
    )
    try:
        receipt = native.execute(key)
        (args.work / "testnet.receipt.json").write_text(json.dumps(receipt) + "\n")
    finally:
        sanitize_logs(args.work, key)


if __name__ == "__main__":
    main()
