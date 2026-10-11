"""T2 owns a protected systemd Guard; shares T1's exact bounded order/cleanup core."""

import hashlib
import os
import pwd
import subprocess
import time
import tomllib
from pathlib import Path
from typing import BinaryIO

from guard_harness.cli import PAIR_SCHEMA, Pair, decode_json
from guard_harness.linux_testnet_service import TestnetService
from guard_harness.native_release import Release, staged_loader
from guard_harness.runner import run
from guard_harness.testnet_process import Foreground, _need


class ServiceOwner(Foreground):
    """Only an independent flat scan may stop this owned service after entry."""

    def __init__(
        self,
        binary: Path,
        *,
        sha256: str,
        work: Path,
        account: str,
        api_wallet: str,
        port: int,
        key_stdin: BinaryIO,
        assets: Path,
        tag: str,
        commit: str,
        marker: str,
    ) -> None:
        _need(not work.exists() and work.is_absolute() and not work.is_symlink())
        _need(hashlib.sha256(binary.read_bytes()).hexdigest() == sha256)
        _need(not key_stdin.isatty())
        work.mkdir(mode=0o700)
        self.work, self.account, self.sha256 = work, account, sha256
        installer = staged_loader(
            Release(tag, commit, assets), windows=False, output=work / "i-staging"
        )
        key = key_stdin.read(68)
        if key.startswith(b"0x"):
            key = key[2:]
        _need(len(key) == 65 and key.endswith(b"\n"))
        installed = TestnetService(
            installer,
            hashlib.sha256(installer.read_bytes()).hexdigest(),
            account,
            "zr1_eyJ2IjoxfQ",
            port,
            work,
            marker,
        ).setup(key)
        key = b""
        self.binary, self.home = Path(installed["binary"]), Path(installed["home"])
        _need(hashlib.sha256(self.binary.read_bytes()).hexdigest() == sha256)
        self.url = installed["url"]
        self.unit = installed["unit"]
        self.env = {"PATH": os.defpath, "HOME": str(work), "LANG": "C.UTF-8"}
        self.log, self.client_key = work / "process.log", work / "client-key"
        self._control("stop")
        config = tomllib.loads((self.home / "guard.toml").read_text())
        _need(config.get("mode") == config.get("network") == "testnet")
        _need(config.get("account", "").lower() == account.lower())
        _need(config.get("api_wallet", "").lower() == api_wallet.lower())
        _need(config.get("allow_mainnet", False) is False)
        # Pair as the installed service user so its atomic config update preserves
        # custody/ownership. MCP uses a separate root-private client home, never a
        # permission relaxation of the service's protected data directory.
        service_user = pwd.getpwuid(self.home.stat().st_uid).pw_name
        paired = run(
            [
                "runuser",
                "-u",
                service_user,
                "--",
                str(self.binary),
                "--home",
                str(self.home),
                "pair",
                "--json",
            ],
            env=self.env,
            log=work / "pair.log",
            timeout=30,
            sensitive_output=True,
        )
        decoded = decode_json(paired.output, PAIR_SCHEMA)
        self.pair = Pair(decoded["client_address"], decoded["client_key"])
        service_config = (self.home / "guard.toml").read_bytes()
        self.home = work / "mcp-home"
        self.home.mkdir(mode=0o700)
        (self.home / "guard.toml").write_bytes(service_config)
        (self.home / "guard.toml").chmod(0o600)
        with self.client_key.open("xb") as stream:
            self.client_key.chmod(0o600)
            stream.write((self.pair.key + "\n").encode())
        self.started_ms = time.time_ns() // 1_000_000
        self._control("start")
        self.pid = self._pid()
        self.log.write_text("owned protected testnet service started; logs withheld\n")

    def _control(self, action: str) -> None:
        _need(action in {"start", "stop"})
        run(
            ["systemctl", action, self.unit],
            env=self.env,
            log=self.work / f"service-{action}.log",
            timeout=30,
            sensitive_output=True,
        )

    def _pid(self) -> int:
        result = subprocess.run(
            ["systemctl", "show", "--property=MainPID", "--value", self.unit],
            capture_output=True,
            timeout=10,
            check=True,
            env=self.env,
        )
        raw = result.stdout.strip()
        _need(raw.isdigit() and int(raw) > 1)
        return int(raw)

    def alive(self) -> None:
        _need(self._pid() == self.pid)
        _need(Path(f"/proc/{self.pid}/exe").resolve() == self.binary.resolve())
        _need(hashlib.sha256(self.binary.read_bytes()).hexdigest() == self.sha256)

    def stop_after_flat(self) -> None:
        self.alive()
        self._control("stop")
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", self.unit],
            capture_output=True,
            timeout=10,
            check=False,
            env=self.env,
        )
        _need(result.returncode == 3)
        self.log.write_text("owned service stopped only after independent all-DEX flat scan\n")
