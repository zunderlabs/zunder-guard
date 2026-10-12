"""Protected native setup reaches real userRole refusal with an unapproved throwaway wallet."""

import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path

from guard_harness.mainnet_terminal import TerminalError, refusal
from guard_harness.native_paper import Paper
from guard_harness.native_release import Release, staged_loader
from guard_harness.runner import run
from guard_harness.testnet_run import ROOT


def mac_absent(paths: tuple[Path, ...], log: Path) -> None:
    """Only the privileged owner can prove absence beneath protected installer roots."""
    run(
        [
            "sudo",
            "-n",
            "/bin/sh",
            "-c",
            'for path do [ ! -e "$path" ] && [ ! -L "$path" ] || exit 2; done',
            "guard-mainnet-absence",
            *map(str, paths),
        ],
        log=log,
        timeout=30,
        stdin=b"",
        sensitive_output=True,
    )


def receipt(release: Release, route: str, log: Path, code: int, work: Path) -> None:
    target = "darwin-arm64" if route != "windows-scm" else "windows-amd64"
    value = dict(
        schema=1,
        journey="M1",
        route=route,
        tag=release.tag,
        commit=release.commit,
        harness_commit=os.environ.get("GITHUB_SHA", ""),
        diagnostic=os.environ.get("DIAGNOSTIC") == "true",
        manifest_sha256=hashlib.sha256(release.asset("release-manifest.json")).hexdigest(),
        binary_sha256=hashlib.sha256(release.binary(target)).hexdigest(),
        result="passed",
        tier="e2e",
        exchange_requests=0,
        coverage=["protected-setup-unapproved-wallet"],
        mode="mainnet",
        wallet_role="unapproved",
        config_written=False,
        credential_written=False,
        service_enabled=False,
        service_started=False,
        exit_code=code,
        expected_refusal="is not an API wallet of",
        log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
    )
    (work / f"{route}.json").write_text(json.dumps(value) + "\n")


def exercise(release: Release, *, account: str, work: Path, shell: str) -> None:
    if not work.is_absolute() or work.exists() or work.is_symlink():
        raise TerminalError("fresh absolute native refusal workspace required")
    missing: list[Path] = []
    for parent in work.parents:
        if parent.is_symlink():
            raise TerminalError("native refusal workspace ancestor is a symlink")
        if not parent.exists():
            missing.append(parent)
        elif not parent.is_dir():
            raise TerminalError("native refusal workspace ancestor is not a directory")
    for parent in reversed(missing):
        parent.mkdir(mode=0o700)
    work.mkdir(mode=0o700)
    rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
    mac = platform.system() == "Darwin"
    loader = staged_loader(
        release, windows=not mac, output=work / ("loader" if mac else "loader.ps1")
    )
    if mac:
        base = Path("/Library/Application Support/Zunder Guard")
        config, binding = base / "state/guard.toml", base / "bindings/active.json"
        plist = Path("/Library/LaunchDaemons/com.zunderlabs.guard.mainnet.plist")
        mac_absent((config, binding, plist), work / "macos-before-absence.log")
        keychain = "/Library/Keychains/System.keychain"

        def absent() -> None:
            opened = subprocess.run(
                ["sudo", "-n", "security", "show-keychain-info", keychain],
                capture_output=True,
                check=False,
                timeout=30,
            )
            item = subprocess.run(
                [
                    "sudo",
                    "-n",
                    "security",
                    "find-generic-password",
                    "-s",
                    "com.zunderlabs.guard.mainnet.v2",
                    "-a",
                    "mainnet",
                    keychain,
                ],
                capture_output=True,
                check=False,
                timeout=30,
            )
            if opened.returncode != 0 or item.returncode != 44:
                raise TerminalError("System Keychain lookup did not confirm absent mainnet item")

        absent()
        log = work / "macos-launchdaemon.log"
        _, code = refusal(
            [
                "/usr/bin/sudo",
                "-n",
                "/bin/sh",
                str(loader),
                "--network",
                "mainnet",
                "--rules",
                rules,
                "--account",
                account,
                "--equity-cap",
                "100",
            ],
            account,
            log=log,
        )
        absent()
        mac_absent((config, binding, plist), work / "macos-after-absence.log")
        expected = release.binary("darwin-arm64")
        installed = base / "releases" / hashlib.sha256(expected).hexdigest() / "zunder-guard"
        if installed.is_symlink() or installed.read_bytes() != expected:
            raise TerminalError("protected macOS executable differs from signed release")
        receipt(release, "macos-launchdaemon", log, code, work)
        paper = Paper(release=release, previous=release, work=work / "brew", shell=shell)
        paper.work.mkdir(mode=0o700)
        paper.install(release)
        paper.home.mkdir(mode=0o700)
        log = work / "homebrew-foreground.log"
        _, code = refusal(
            [
                str(paper.binary),
                "--home",
                str(paper.home),
                "init",
                "--interactive",
                "--network",
                "mainnet",
                "--rules",
                rules,
                "--account",
                account,
                "--equity-cap",
                "100",
            ],
            account,
            log=log,
        )
        if list(paper.home.iterdir()):
            raise TerminalError("refused Homebrew foreground setup wrote state")
        if paper.binary.read_bytes() != release.binary("darwin-arm64"):
            raise TerminalError("Homebrew executable differs from signed release")
        receipt(release, "homebrew-foreground", log, code, work)
        paper.command(["brew", "uninstall", "zunder-guard"])
    else:
        identifier = "mainnet-install-matrix"
        base = Path(os.environ["ProgramData"]) / "ZunderGuard"
        home = base / identifier
        if home.exists():
            raise TerminalError("Windows mainnet instance already exists")
        log = work / "windows-scm.log"
        _, code = refusal(
            [
                shell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(loader),
                "-Network",
                "mainnet",
                "-ManagedService",
                "-Id",
                identifier,
                "-Rules",
                rules,
                "-Account",
                account,
                "-ConfirmAccount",
                account,
                "-EquityCap",
                "100",
            ],
            account,
            log=log,
            windows=True,
        )
        if (home / "runtime/guard.toml").exists() or (home / "credential.dpapi").exists():
            raise TerminalError("refused SCM setup wrote config or credential")
        query = (
            "$s=Get-CimInstance Win32_Service -Filter \"Name='ZunderGuard-"
            + identifier
            + "'\";if($s){if($s.State -ne 'Stopped' -or $s.StartMode -ne 'Disabled'){"
            "throw 'Mainnet service enabled or started'};sc.exe delete $s.Name | Out-Null;"
            "if($LASTEXITCODE -ne 0){throw 'Owned disabled service cleanup failed'}}"
        )
        result = subprocess.run(
            [shell, "-NoProfile", "-Command", query], capture_output=True, timeout=30, check=False
        )
        if result.returncode:
            raise TerminalError("Windows refused service did not remain disabled and stopped")
        installed = (
            Path(os.environ["ProgramFiles"]) / "ZunderGuard" / identifier / "zunder-guard.exe"
        )
        if installed.is_symlink() or installed.read_bytes() != release.binary("windows-amd64"):
            raise TerminalError("SCM executable differs from signed release")
        receipt(release, "windows-scm", log, code, work)
