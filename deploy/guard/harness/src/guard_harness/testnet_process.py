"""T1 foreground custody: fresh authenticated bytes/home, key on inherited stdin."""

import hashlib
import json
import math
import os
import re
import signal
import subprocess
import time
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from guard_harness.cli import PAIR_SCHEMA, Pair, decode_json
from guard_harness.mcp_client import MCP
from guard_harness.paper_bot import LocalGuard
from guard_harness.runner import run
from guard_harness.staged_subjects import _private
from guard_harness.testnet_journey import Journey, execute
from guard_harness.testnet_ownership import Ownership
from guard_harness.testnet_protection import Entry, _object, _orders, entry_plan
from guard_harness.testnet_scan import SCAN_TIMEOUT, TestnetReads

ENTRY_REMAINING = SCAN_TIMEOUT + 480


class ProcessError(RuntimeError):
    """Fixed diagnostics; subprocess output and wallet keys are withheld."""


def _need(value: bool) -> None:
    if not value:
        raise ProcessError("fresh authenticated testnet process prerequisite refused")


def _bind_wallet(home: Path, account: str, wallet: str, listen: str, client: str) -> None:
    path = home / "guard.toml"
    _private(path)
    _need(path.stat().st_size <= 131072)
    raw = path.read_text()
    before = tomllib.loads(raw)
    _need(before.get("mode") == before.get("network") == "testnet")
    _need(before.get("account") == account and before.get("listen") == listen)
    _need(before.get("allow_mainnet", False) is False and "api_wallet" not in before)
    _need(not (home / "api-wallet-key").exists())
    clients = before.get("auth", {}).get("clients")
    _need(isinstance(clients, list) and client in clients)
    # Only the approved public address changes; preserve policy/auth/journal settings.
    updated = "api_wallet = " + json.dumps(wallet) + "\n" + raw
    _need(tomllib.loads(updated) == dict(before, api_wallet=wallet))
    with path.open("w") as stream:
        stream.write(updated)
        stream.flush()
        os.fsync(stream.fileno())
    _need(tomllib.loads(path.read_text()) == dict(before, api_wallet=wallet))


class Foreground:
    """Own one fresh Guard child; failure never tears down protection automatically.

    Caller authenticates the digest from the signed release archive and holds global C6
    account serialization through cleanup. The key descriptor is inherited directly by
    Guard; Python never reads it. Runtime logs contain fixed markers only.
    """

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
    ) -> None:
        _need(re.fullmatch(r"[0-9a-f]{64}", sha256) is not None)
        _need(all(re.fullmatch(r"0x[0-9a-fA-F]{40}", a) is not None for a in (account, api_wallet)))
        _need(type(port) is int and 1024 <= port <= 65535)
        _private(binary)
        _private(work.parent, directory=True)
        _need(not work.exists() and not work.is_symlink() and work.is_absolute())
        _need(not key_stdin.isatty())
        with binary.open("rb") as stream:
            data = stream.read(256 * 1024 * 1024 + 1)
        _need(0 < len(data) <= 256 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == sha256)
        work.mkdir(mode=0o700)
        self.work, self.account, self.sha256 = work, account, sha256
        self.binary, self.home = work / "zunder-guard", work / "home"
        self.binary.write_bytes(data)
        self.binary.chmod(0o700)
        self.home.mkdir(mode=0o700)
        self.log, self.client_key = work / "process.log", work / "client-key"
        self.url = f"http://127.0.0.1:{port}"
        self.env = {"PATH": os.defpath, "HOME": str(work), "LANG": "C.UTF-8"}
        self._initialize(api_wallet, f"127.0.0.1:{port}")
        self.started_ms = time.time_ns() // 1_000_000
        self.child = subprocess.Popen(
            [
                str(self.binary),
                "--home",
                str(self.home),
                "run",
                "--network",
                "testnet",
                "--key-stdin",
            ],
            env=self.env,
            stdin=key_stdin,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.log.write_text("owned testnet Guard started; stdout/stderr withheld\n")

    def _initialize(self, wallet: str, listen: str) -> None:
        run(
            [
                str(self.binary),
                "--home",
                str(self.home),
                "init",
                "--non-interactive",
                "--no-key",
                "--network",
                "testnet",
                "--rules",
                "zr1_eyJ2IjoxfQ",
                "--account",
                self.account,
                "--listen",
                listen,
            ],
            env=self.env,
            timeout=60,
            log=self.work / "init.log",
            sensitive_output=True,
            stdin=b"",
        )
        result = run(
            [str(self.binary), "--home", str(self.home), "pair", "--json"],
            env=self.env,
            timeout=30,
            log=self.work / "pair.log",
            sensitive_output=True,
            stdin=b"",
        )
        decoded = decode_json(result.output, PAIR_SCHEMA)
        self.pair = Pair(decoded["client_address"], decoded["client_key"])
        with self.client_key.open("xb") as stream:
            self.client_key.chmod(0o600)
            stream.write((self.pair.key + "\n").encode())
        _private(self.client_key)
        _bind_wallet(self.home, self.account, wallet, listen, self.pair.address)

    def alive(self) -> None:
        _need(self.child.poll() is None)
        with self.binary.open("rb") as stream:
            _need(hashlib.file_digest(stream, "sha256").hexdigest() == self.sha256)

    def wait_ready(self, *, timeout: float = 90) -> None:
        _need(0 < timeout <= 90)
        guard = OwnedLocalGuard(self)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.alive()
            try:
                status = guard.request("/guard/status")
                if isinstance(status, dict) and status.get("mode") == "testnet":
                    _need(status.get("account", "").lower() == self.account.lower())
                    _need(type(status.get("started_at_ms")) is int)
                    _need(status["started_at_ms"] >= self.started_ms)
                    return
            except (OSError, ValueError, RuntimeError):
                pass
            time.sleep(0.25)
        raise ProcessError("owned testnet Guard readiness deadline")

    def stop_after_flat(self) -> None:
        """Only the journey's successful independent flat scan authorizes this callback."""
        self.alive()
        os.killpg(self.child.pid, signal.SIGTERM)
        self.child.wait(timeout=10)
        self.log.write_text("owned testnet Guard exit confirmed after independent flat scan\n")

    def journey(
        self,
        read: TestnetReads,
        entry: Entry | None = None,
        *,
        version: str,
        deadline: float,
        capture_entry: Callable[[Ownership, int, int], None] = lambda *_: None,
        observe_phase: Callable[[str], None] = lambda _: None,
    ) -> Journey:
        # Caller derives this monotonic deadline from the actual job's remaining lifetime.
        _need(math.isfinite(deadline) and deadline > time.monotonic())
        observe_phase("guard-readiness")
        self.wait_ready()

        def fresh_entry() -> Entry:
            markets = _orders(_object(read({"type": "meta"})).get("universe"))
            return entry_plan(markets, _object(read({"type": "allMids"})))

        def admit_entry() -> None:
            self.alive()
            # Full all-DEX cleanup plus 480 seconds for entry/proof and shutdown margin.
            _need(deadline - time.monotonic() >= ENTRY_REMAINING)
            read.start_phase(timeout=180)

        def begin_cleanup() -> None:
            read.start_phase(timeout=SCAN_TIMEOUT)

        observe_phase("mcp-initialize")
        with MCP(
            self.binary,
            sha256=self.sha256,
            home=self.home,
            client_key=self.client_key,
            url=self.url,
            log=self.work / "mcp.log",
        ) as mcp:
            return execute(
                OwnedLocalGuard(self),
                mcp,
                read,
                account=self.account,
                client=self.pair.address,
                entry=fresh_entry if entry is None else entry,
                version=version,
                process_started_ms=self.started_ms,
                stop_guard=self.stop_after_flat,
                admit_entry=admit_entry,
                begin_cleanup=begin_cleanup,
                capture_entry=capture_entry,
                observe_phase=observe_phase,
            )


class OwnedLocalGuard(LocalGuard):
    def __init__(self, owner: Foreground) -> None:
        super().__init__(owner.url)
        self.owner = owner

    def request(self, path: str, body: dict[str, object] | None = None) -> object:
        self.owner.alive()
        value: object = super().request(path, body)
        self.owner.alive()
        return value
