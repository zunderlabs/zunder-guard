"""Released macOS/Homebrew and Windows per-user paper lifecycle, no venue key."""

import argparse
import hashlib
import json
import os
import platform
import plistlib
import re
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

from guard_harness.cli import GuardCLI, Pair
from guard_harness.native_release import Release, staged_loader
from guard_harness.paper_bot import LocalGuard, PaperError
from guard_harness.paper_roundtrip import round_trip
from guard_harness.runner import run
from guard_harness.testnet_run import ROOT


class LifecycleError(RuntimeError):
    """A released native lifecycle requirement was not observed."""


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def retained(home: Path) -> dict[str, bytes]:
    required = ("guard.toml", "risk-paper.jsonl", "decisions-paper.jsonl")
    if any(not (home / name).is_file() for name in required):
        raise LifecycleError("configuration or journal missing")
    return {
        name: (home / name).read_bytes().rstrip(b"\x00")
        if name.endswith(".jsonl")
        else (home / name).read_bytes()
        for name in required
    }


def verify_retained(before: dict[str, bytes], home: Path) -> None:
    after = retained(home)
    for name, original in before.items():
        if name == "guard.toml" and after[name] != original:
            raise LifecycleError("configuration/pairing changed across lifecycle")
        if name != "guard.toml" and not after[name].startswith(original):
            raise LifecycleError("journal history changed across lifecycle")


def healthy(guard: LocalGuard, *, version: str, timeout: float = 90) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = guard.request("/guard/status")
            if (
                isinstance(value, dict)
                and value.get("last_sync_ms")
                and value.get("version") == version
            ):
                if value.get("mode") != "paper":
                    raise LifecycleError("paper supervisor served another mode")
                return value
        except PaperError:
            pass
        time.sleep(0.5)
    raise LifecycleError("native service did not sync at the exact installed version")


class Paper:
    def __init__(
        self,
        *,
        release: Release,
        previous: Release,
        work: Path,
        shell: str,
        scenario: str = "upgrade",
    ) -> None:
        self.release, self.previous, self.work, self.shell = release, previous, work, shell
        self.sequence = 0
        self.child: subprocess.Popen[bytes] | None = None
        self.output: Any = None
        self.brew = platform.system() == "Darwin"
        self.brew_stop_required = False
        if scenario not in {"fresh", "upgrade"}:
            raise LifecycleError("native paper scenario refused")
        self.scenario = scenario
        self.observed: dict[str, dict[str, str]] = {}
        self.home = work / "home"
        self.binary = work / "bin/zunder-guard.exe"
        self.env = dict(os.environ)
        self.env["HOMEBREW_NO_AUTO_UPDATE"] = "1"
        self.env.pop("ZUNDER_MAINNET_CONFIRM", None)
        for key in tuple(self.env):
            if key.startswith("ZUNDER_"):
                self.env.pop(key)
        self.env["ZUNDER_GUARD_HOME"] = str(self.home)

    def command(self, words: list[str], *, sensitive: bool = False) -> str:
        self.sequence += 1
        return run(
            words,
            env=self.env,
            log=self.work / f"step-{self.sequence}.log",
            timeout=600,
            sensitive_output=sensitive,
        ).output.strip()

    def install(self, release: Release, *, upgrade: bool = False, reinstall: bool = False) -> None:
        target = "darwin-arm64" if self.brew else "windows-amd64"
        expected = hashlib.sha256(release.binary(target)).hexdigest()
        if self.brew:
            if not upgrade:
                self.command(["brew", "tap", "zunderlabs/tap"])
                self.tap = Path(self.command(["brew", "--repo", "zunderlabs/tap"]))
                branch = (
                    "main" if os.environ.get("INSTALL_MATRIX_PROFILE") == "nightly" else "staging"
                )
                self.command(["git", "-C", str(self.tap), "fetch", "origin", branch])
                self.command(
                    ["git", "-C", str(self.tap), "checkout", "-B", branch, "origin/" + branch]
                )
                staged = self.tap / "Formula/zunder-guard.rb"
                if staged.read_bytes() != self.release.asset("zunder-guard.rb"):
                    raise LifecycleError("tap staging formula differs from signed release")
                staged.write_bytes(release.asset("zunder-guard.rb"))
            else:
                self.command(["git", "-C", str(self.tap), "restore", "Formula/zunder-guard.rb"])
                if (self.tap / "Formula/zunder-guard.rb").read_bytes() != release.asset(
                    "zunder-guard.rb"
                ):
                    raise LifecycleError("staged formula changed before upgrade")
            self.command(
                [
                    "brew",
                    "reinstall" if reinstall else "upgrade" if upgrade else "install",
                    "zunderlabs/tap/zunder-guard",
                ]
            )
            prefix = Path(self.command(["brew", "--prefix"]))
            self.binary = prefix / "bin/zunder-guard"
            self.home = prefix / "var/zunder-guard"
            self.env["ZUNDER_GUARD_HOME"] = str(self.home)
        else:
            loader = self.work / f"loader-{release.tag}.ps1"
            if release == self.release:
                staged_loader(
                    release,
                    windows=True,
                    output=loader,
                    channel="canonical"
                    if os.environ.get("INSTALL_MATRIX_PROFILE") == "nightly"
                    else "staging",
                )
            else:
                loader.write_bytes(release.asset("i.ps1"))
            self.command(
                [
                    self.shell,
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(loader),
                    "-InstallOnly",
                    "-InstallDir",
                    str(self.binary.parent),
                ]
            )
        if digest(self.binary) != expected:
            raise LifecycleError("installed binary differs from authenticated released bytes")
        version = self.command([str(self.binary), "--version"])
        if version != "zunder-guard " + release.tag.removeprefix("v"):
            raise LifecycleError("installed paper version differs from release")
        self.observed[release.tag] = dict(
            commit=release.commit, version=version, binary_sha256=expected
        )

    def start(self) -> None:
        if self.brew:
            # A failed start may already have registered the service.
            self.brew_stop_required = True
            self.command(["brew", "services", "start", "zunder-guard"])
        else:
            self.output = (self.work / f"guard-{self.sequence}.log").open("ab")
            self.child = subprocess.Popen(
                [str(self.binary), "--home", str(self.home), "run", "--network", "paper"],
                env=self.env,
                stdin=subprocess.DEVNULL,
                stdout=self.output,
                stderr=self.output,
            )

    def stop(self) -> None:
        if self.brew:
            if self.brew_stop_required:
                self.command(["brew", "services", "stop", "zunder-guard"])
                self.brew_stop_required = False
        elif self.child is not None:
            self.child.terminate()
            try:
                self.child.wait(timeout=40)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=10)
            self.child = None
            self.output.close()

    def crash(self) -> None:
        if self.brew:
            self.command(["launchctl", "kill", "SIGKILL", self.brew_service_target()])
        elif self.child is not None:
            self.child.kill()
            self.child.wait(timeout=10)
            self.child = None
            self.output.close()
            self.start()  # The documented per-user route has no OS recovery manager.

    def brew_service_target(self) -> str:
        """Homebrew uses user/UID for SSH/sudo and gui/UID for GUI sessions."""
        try:
            return self._brew_service_target()
        except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            raise LifecycleError(
                "owned Homebrew service registration could not be admitted"
            ) from None

    def _brew_service_target(self) -> str:
        uid = os.getuid()
        if uid == 0:
            raise LifecycleError("paper Homebrew service must belong to a non-root user")
        user_home = Path(self.env["HOME"])
        agents = user_home / "Library/LaunchAgents"
        for directory in (user_home, agents.parent, agents):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
                raise LifecycleError("Homebrew service directory ownership differs")
        registrations = []
        for label in ("homebrew.mxcl.zunder-guard", "sh.brew.zunder-guard"):
            plist = agents / (label + ".plist")
            try:
                info = plist.lstat()
            except FileNotFoundError:
                continue
            registrations.append((label, plist, info))
        if len(registrations) != 1:
            raise LifecycleError("owned Homebrew service plist missing or ambiguous")
        label, plist, info = registrations[0]
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_nlink != 1
            or info.st_mode & 0o022
            or info.st_size > 65536
        ):
            raise LifecycleError("Homebrew service plist ownership differs")
        registration = plistlib.loads(plist.read_bytes())
        if not isinstance(registration, dict):
            raise LifecycleError("Homebrew service plist shape differs")
        arguments = registration.get("ProgramArguments")
        environment = registration.get("EnvironmentVariables")
        if (
            registration.get("Label") != label
            or not isinstance(arguments, list)
            or len(arguments) != 4
            or not isinstance(arguments[0], str)
            or Path(arguments[0]).resolve(strict=True) != self.binary.resolve(strict=True)
            or arguments[1:] != ["run", "--network", "paper"]
            or not isinstance(environment, dict)
            or environment.get("ZUNDER_GUARD_HOME") != str(self.home)
        ):
            raise LifecycleError("Homebrew service registration differs from owned paper runtime")
        found = []
        for domain in ("user", "gui"):
            target = f"{domain}/{uid}/{label}"
            result = subprocess.run(
                ["launchctl", "print", target],
                env=self.env,
                capture_output=True,
                check=False,
                timeout=30,
            )
            self.sequence += 1
            (self.work / f"step-{self.sequence}.log").write_text(
                "[owned launchd probe output withheld]\n"
            )
            if result.returncode == 113:  # Service not found in this exact user domain.
                continue
            if result.returncode != 0 or len(result.stdout) > 65536:
                raise LifecycleError("owned launchd service domain lookup failed")
            text = result.stdout.decode(errors="replace")
            paths = re.findall(r"^\s*path = (.+)$", text, re.M)
            programs = re.findall(r"^\s*program = (.+)$", text, re.M)
            homes = re.findall(r"^\s*ZUNDER_GUARD_HOME => (.+)$", text, re.M)
            pids = re.findall(r"^\s*pid = ([1-9][0-9]*)$", text, re.M)
            argument_blocks = re.findall(r"^\s*arguments = \{\n(.*?)^\s*\}", text, re.M | re.S)
            if (
                not text.startswith(target + " = {")
                or len(paths) != 1
                or Path(paths[0]).resolve(strict=True) != plist.resolve(strict=True)
                or len(programs) != 1
                or Path(programs[0]).resolve(strict=True) != self.binary.resolve(strict=True)
                or homes != [str(self.home)]
                or len(pids) != 1
                or len(argument_blocks) != 1
                or argument_blocks[0].split() != arguments
            ):
                raise LifecycleError("loaded launchd service differs from owned paper runtime")
            found.append(target)
        if len(found) != 1:
            raise LifecycleError("owned Homebrew service domain missing or ambiguous")
        return found[0]

    def execute(self, account: str) -> dict[str, object]:
        self.work.mkdir(mode=0o700)
        pair: Pair | None = None
        guard = LocalGuard("http://127.0.0.1:8547")
        checks: list[str] = []
        try:
            initial = self.release if self.scenario == "fresh" else self.previous
            self.install(initial)
            self.home.mkdir(mode=0o700, parents=True, exist_ok=False)
            rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
            self.command(
                [
                    str(self.binary),
                    "--home",
                    str(self.home),
                    "init",
                    "--non-interactive",
                    "--network",
                    "paper",
                    "--account-network",
                    "testnet",
                    "--no-key",
                    "--account",
                    account,
                    "--rules",
                    rules,
                ],
                sensitive=True,
            )
            pair = GuardCLI(self.binary, self.work, self.home).pair()
            self.start()
            healthy(guard, version=initial.tag[1:])
            round_trip(guard, pair)
            self.stop()
            before = retained(self.home)
            checks.extend(["install", "init", "pair", "health", "paper-allow-resize-veto"])
            self.start()
            healthy(guard, version=initial.tag[1:])
            self.crash()
            healthy(guard, version=initial.tag[1:])
            self.stop()
            verify_retained(before, self.home)
            checks += [
                "restart",
                "crash-recovery" if self.brew else "manual-crash-restart",
                "journal-prefix",
                "pairing-retained",
            ]
            self.install(self.release, upgrade=True)
            verify_retained(before, self.home)
            self.start()
            healthy(guard, version=self.release.tag[1:])
            round_trip(guard, pair)
            self.stop()
            self.install(self.release, upgrade=True, reinstall=True)
            verify_retained(before, self.home)
            self.start()
            healthy(guard, version=self.release.tag[1:])
            round_trip(guard, pair)
            self.stop()
            checks += [
                "fresh-candidate" if self.scenario == "fresh" else "upgrade",
                "reinstall",
                "old-client-signature-after-upgrade",
            ]
            # Refusals are separate from paper orders and never call /exchange.
            from guard_harness.native_refusals import setup_refusals

            refusals = setup_refusals(
                self.binary,
                sha256=digest(self.binary),
                account=account,
                rules=rules,
                work=self.work / "refusals",
                windows=not self.brew,
            )
            if self.brew:
                self.command(["launchctl", "setenv", "ZUNDER_GUARD_NETWORK", "mainnet"])
                try:
                    self.start()
                    status = healthy(guard, version=self.release.tag[1:])
                    from guard_harness.mainnet_refusals import record

                    record(
                        self.release,
                        case="homebrew-services",
                        route="homebrew-services",
                        target="darwin-arm64",
                        work=self.work / "mainnet/M2",
                        output=json.dumps(
                            {"mode": status["mode"], "version": status["version"]}
                        ).encode(),
                        exit_code=0,
                        literal='"mode": "paper"',
                        passed=True,
                        mechanism="supervisor-mode",
                        observed_mode=status["mode"],
                    )
                    refusals.append("homebrew-services")
                finally:
                    self.stop()
                    self.command(["launchctl", "unsetenv", "ZUNDER_GUARD_NETWORK"])
            (self.work / "refusals.receipt.json").write_text(
                json.dumps({"result": "passed", "coverage": refusals, "no_exchange": True}) + "\n"
            )
            if self.brew:
                self.command(["brew", "uninstall", "zunder-guard"])
            else:
                self.command(
                    [
                        self.shell,
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(self.work / f"loader-{self.release.tag}.ps1"),
                        "-Uninstall",
                        "-NonInteractive",
                        "-InstallDir",
                        str(self.binary.parent),
                    ]
                )
            if self.binary.exists():
                raise LifecycleError("uninstall retained executable")
            verify_retained(before, self.home)
            checks += ["uninstall", "documented-data-retained"]
            return {
                "schema": 1,
                "result": "passed",
                "coverage": checks,
                "mode": "paper",
                "scenario": self.scenario,
                "tag": self.release.tag,
                "commit": self.release.commit,
                "manifest_sha256": hashlib.sha256(
                    self.release.asset("release-manifest.json")
                ).hexdigest(),
                "observed_releases": self.observed,
                "channel_coverage": ["D3:homebrew"]
                if self.brew and self.scenario == "fresh"
                else [],
            }
        finally:
            self.stop()
            # Pairing output never enters evidence; retain only non-secret service logs.
            pair = None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("tag", "commit", "previous-tag", "previous-commit", "account"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--shell", default="powershell.exe")
    parser.add_argument("--scenario", choices=("fresh", "upgrade"), default="upgrade")
    args = parser.parse_args()
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        raise LifecycleError("disposable GitHub-hosted native runner required")
    paper = Paper(
        release=Release(args.tag, args.commit, args.assets / "candidate/assets"),
        previous=Release(args.previous_tag, args.previous_commit, args.assets / "previous/assets"),
        work=args.work,
        shell=args.shell,
        scenario=args.scenario,
    )
    receipt = paper.execute(args.account)
    # This receipt proves only paper; it cannot claim complete I3/I4 or testnet custody.
    (args.work / "paper.receipt.json").write_text(json.dumps(receipt) + "\n")


if __name__ == "__main__":
    main()
