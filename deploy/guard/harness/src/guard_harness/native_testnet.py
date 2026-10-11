"""Released Keychain/SCM testnet lifecycle. Read-only HTTP only; never /exchange."""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

from guard_harness.native_paper import LifecycleError, Paper
from guard_harness.native_release import Release, staged_loader
from guard_harness.paper_bot import LocalGuard, PaperError
from guard_harness.runner import run
from guard_harness.testnet_run import ROOT


class NativeTestnet:
    def __init__(
        self, current: Release, previous: Release, work: Path, account: str, shell: str
    ) -> None:
        self.current, self.previous, self.work, self.account = current, previous, work, account
        self.shell = shell
        self.mac = platform.system() == "Darwin"
        self.sequence = 0
        self.key: bytes = b""
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

    def command(self, words: list[str], *, key: bool = False, sensitive: bool = False) -> str:
        self.sequence += 1
        return run(
            words,
            env=self.env,
            log=self.work / f"step-{self.sequence}.log",
            timeout=600,
            stdin=self.key * 2 if key else b"",
            sensitive_output=sensitive,
            secrets=[self.key.decode().strip()],
        ).output.strip()

    def ps(self, words: list[str]) -> list[str]:
        return [self.shell, "-NoProfile", "-ExecutionPolicy", "Bypass", *words]

    def installed(self) -> Path:
        if self.mac:
            value = json.loads(self.command(["sudo", "cat", str(self.binding)], sensitive=True))
            return Path(value["executable"])
        return Path(os.environ["ProgramFiles"]) / "ZunderGuard" / self.id / "zunder-guard.exe"

    def snapshot(self) -> dict[str, bytes]:
        result: dict[str, bytes] = {}
        for name in ("guard.toml", "risk.jsonl"):
            path = self.home / name
            if self.mac:
                body = self.command(["sudo", "cat", str(path)], sensitive=True).encode()
            else:
                body = path.read_bytes()
            if not body:
                raise LifecycleError("native configuration/journal missing")
            result[name] = body
        return result

    def retained(self, old: dict[str, bytes]) -> None:
        new = self.snapshot()
        if new["guard.toml"] != old["guard.toml"] or not new["risk.jsonl"].startswith(
            old["risk.jsonl"]
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
            words = ["sh", str(loader), "--network", "testnet", "--non-interactive", "--key-stdin"]
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
        target = "darwin-arm64" if self.mac else "windows-amd64"
        binary = self.installed()
        if (
            hashlib.sha256(binary.read_bytes()).digest()
            != hashlib.sha256(release.binary(target)).digest()
        ):
            raise LifecycleError("native service image differs from exact released binary")
        check = [str(binary), "service", "check", "--binding", str(self.binding), "--json"]
        value = json.loads(self.command((["sudo"] if self.mac else []) + check))
        if (
            value.get("ok") is not True
            or value.get("mode") != "testnet"
            or value.get("account", "").lower() != self.account.lower()
        ):
            raise LifecycleError("native credential custody/readback not admitted")

    def start(self) -> None:
        if self.mac:
            self.command(["sudo", "launchctl", "bootstrap", "system", str(self.plist)])
        else:
            self.action("Start", "-Startup", "Manual")

    def stop(self) -> None:
        if self.mac:
            self.command(["sudo", "launchctl", "bootout", self.label])
        else:
            self.action("Stop")

    def healthy(self, release: Release) -> None:
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
            self.install(self.previous, fresh=True)
            if self.mac:
                self.ensure_macos_journal()
            self.start()
            active = True
            self.healthy(self.previous)
            old = self.snapshot()
            self.crash()
            self.healthy(self.previous)
            self.stop()
            active = False
            self.retained(old)
            self.start()
            active = True
            self.healthy(self.previous)
            self.stop()
            active = False
            self.install(self.current)
            self.retained(old)
            self.start()
            active = True
            self.healthy(self.current)
            self.stop()
            active = False
            self.install(self.current)
            self.retained(old)
            self.start()
            active = True
            self.healthy(self.current)
            self.stop()
            active = False
            if self.mac:
                self.command(
                    [
                        "sudo",
                        str(self.installed()),
                        "service",
                        "remove-credential",
                        "--binding",
                        str(self.binding),
                    ]
                )
                self.command(["sudo", "rm", str(self.plist)])
                if self.plist.exists():
                    raise LifecycleError("launchd registration survived removal")
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
                "result": "passed",
                "mode": "testnet",
                "coverage": [
                    "signed-release",
                    "native-custody-readback",
                    "health",
                    "restart",
                    "crash-recovery",
                    "supervisor-reload",
                    "upgrade",
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


def per_user(native: NativeTestnet, work: Path, key: bytes) -> None:
    """Ordinary Windows Credential Manager setup and stored-key startup, no orders."""
    work.mkdir(mode=0o700)
    paper = Paper(release=native.current, previous=native.previous, work=work, shell=native.shell)
    paper.home.mkdir(mode=0o700)
    native.env["ZUNDER_GUARD_HOME"] = str(paper.home)
    rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
    loader = work / "previous.ps1"
    loader.write_bytes(native.previous.asset("i.ps1"))
    native.key = key
    try:
        paper.install(native.previous)
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
        for index, release in enumerate((native.previous, native.current, native.current)):
            if release == native.current:
                paper.install(release, upgrade=True)
            if (
                hashlib.sha256(paper.binary.read_bytes()).digest()
                != hashlib.sha256(release.binary("windows-amd64")).digest()
            ):
                raise LifecycleError("per-user sending binary differs from authenticated release")
            if index == 2:
                candidate_user_setup(native, paper, work, rules)
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
                                    or status.get("account", "").lower() != native.account.lower()
                                ):
                                    raise LifecycleError("per-user testnet identity mismatch")
                                break
                        except PaperError:
                            pass
                        time.sleep(1)
                    else:
                        raise LifecycleError("per-user testnet readiness deadline")
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=40)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
        paper.binary.unlink()
        (work / "receipt.json").write_text(
            json.dumps(
                {
                    "result": "passed",
                    "mode": "testnet",
                    "coverage": [
                        "credential-manager",
                        "candidate-loader-stdin",
                        "stored-key-runtime",
                        "read-only-health",
                        "restart",
                        "upgrade",
                        "reinstall",
                        "uninstall",
                        "no-exchange",
                    ],
                }
            )
            + "\n"
        )
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
    parser.add_argument("--mode", choices=("testnet", "mainnet-refusal"), default="testnet")
    args = parser.parse_args()
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
    )
    try:
        receipt = native.execute(key)
        (args.work / "testnet.receipt.json").write_text(json.dumps(receipt) + "\n")
        if not native.mac:
            per_user(native, args.work / "per-user", key)
    finally:
        sanitize_logs(args.work, key)


if __name__ == "__main__":
    main()
