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
from typing import Any, BinaryIO

from guard_harness.cli import PAIR_SCHEMA, Pair, decode_json
from guard_harness.mcp_client import MCP
from guard_harness.paper_bot import GuardUnavailable, LocalGuard
from guard_harness.runner import run
from guard_harness.staged_subjects import _private
from guard_harness.testnet_journey import Journey, execute
from guard_harness.testnet_ownership import Ownership
from guard_harness.testnet_protection import Entry, _object, _orders, entry_plan
from guard_harness.testnet_scan import SCAN_TIMEOUT, TestnetReads
from guard_harness.testnet_snapshot import OwnershipStore

OWNED_WORK_TIMEOUT = 1280
ENTRY_REMAINING = OWNED_WORK_TIMEOUT + SCAN_TIMEOUT + 60


class ProcessError(RuntimeError):
    """Fixed diagnostics; subprocess output and wallet keys are withheld."""


def _need(value: bool) -> None:
    if not value:
        raise ProcessError("fresh authenticated testnet process prerequisite refused")


def _startup_object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProcessError("fresh authenticated testnet process prerequisite refused")
    return value


def _startup_ready(value: object, *, account: str, started_ms: int) -> bool:
    """Only absent initial observations may wait; observed refusals remain fatal."""
    status = _startup_object(value)
    for name in ("mode", "network"):
        if name in status:
            _need(status[name] == "testnet")
    if "account" in status:
        _need(isinstance(status["account"], str) and status["account"].lower() == account.lower())
    started = status.get("started_at_ms")
    if "started_at_ms" in status:
        _need(type(started) is int and started >= started_ms)
    for name, expected in (("killed", None), ("journal_broken", False), ("last_error", None)):
        if name in status:
            _need(status[name] is expected)
    capabilities = status.get("capabilities")
    if "capabilities" in status:
        capabilities = _startup_object(capabilities)
        if "exchange_expected_mode" in capabilities:
            _need(capabilities["exchange_expected_mode"] is True)
    journal = status.get("journal")
    if "journal" in status:
        journal = _startup_object(journal)
        _need(journal.get("ok") is True)
    synced = status.get("last_sync_ms")
    if synced is not None:
        now = time.time_ns() // 1_000_000
        _need(type(synced) is int and type(started) is int)
        _need(started <= synced <= now and now - synced <= 60000)
    risk = status.get("risk")
    if "risk" in status:
        risk = _startup_object(risk)
        if "state" in risk:
            _need(risk["state"] == "active")
        if "journal_ready" in risk:
            _need(type(risk["journal_ready"]) is bool)
            _need(risk["journal_ready"] or synced is None)
    fee = status.get("fee")
    fee_ready = False
    if "fee" in status:
        fee = _startup_object(fee)
        _need(fee.get("mode") in ("off", "builder"))
        if fee["mode"] == "off":
            fee_ready = True
        else:
            _need(isinstance(fee.get("address"), str))
            _need(re.fullmatch(r"0x[0-9a-fA-F]{40}", fee["address"]) is not None)
            _need(type(fee.get("fee_tenths_bp")) is int and fee["fee_tenths_bp"] == 20)
            _need(fee.get("paper") is False)
            approval = fee.get("approval")
            approval = _startup_object(approval)
            _need(approval.get("error") is None)
            _need(approval.get("state") in ("unchecked", "approved"))
            if approval["state"] == "approved":
                maximum = approval.get("max_tenths_bp")
                _need(type(maximum) is int and maximum >= 20)
                _need(fee.get("charged") is True and fee.get("entries_blocked") is False)
                fee_ready = True
            else:
                _need(approval.get("max_tenths_bp") is None)
                _need(fee.get("charged") is False and fee.get("entries_blocked") is True)
    return (
        status.get("mode") == status.get("network") == "testnet"
        and "account" in status
        and type(started) is int
        and isinstance(capabilities, dict)
        and capabilities.get("exchange_expected_mode") is True
        and isinstance(journal, dict)
        and journal.get("ok") is True
        and isinstance(risk, dict)
        and risk.get("state") == "active"
        and risk.get("journal_ready") is True
        and all(name in status for name in ("killed", "journal_broken", "last_error"))
        and synced is not None
        and fee_ready
    )


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
        admit_start: Callable[[], None] | None = None,
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
        if admit_start is not None:
            admit_start()
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
                "--ip-share",
                "0.4",
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
        _need(math.isfinite(timeout) and 0 < timeout <= 90)
        guard = OwnedLocalGuard(self)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.alive()
            try:
                status = guard.request("/guard/status")
            except GuardUnavailable:
                time.sleep(0.25)
                continue
            if time.monotonic() >= deadline:
                raise ProcessError("owned testnet Guard readiness deadline")
            if _startup_ready(status, account=self.account, started_ms=self.started_ms):
                return
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

        work_deadline: float | None = None
        store = OwnershipStore(
            self.work,
            account=self.account,
            client=self.pair.address,
            source=self.sha256,
            version=version,
        )

        def admit_entry() -> None:
            nonlocal work_deadline
            self.alive()
            # The single owned-work reserve plus independent all-DEX scan and shutdown.
            _need(deadline - time.monotonic() >= ENTRY_REMAINING)
            work_deadline = time.monotonic() + OWNED_WORK_TIMEOUT
            read.start_phase(timeout=OWNED_WORK_TIMEOUT)

        def begin_cleanup() -> None:
            _need(work_deadline is not None and time.monotonic() < work_deadline)
            # Preserve the same absolute deadline and rolling reservations.

        def begin_final_scan() -> None:
            _need(deadline - time.monotonic() >= SCAN_TIMEOUT + 60)
            read.start_phase(timeout=SCAN_TIMEOUT)

        def check_owned_work() -> None:
            _need(work_deadline is not None and time.monotonic() < work_deadline)

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
                begin_final_scan=begin_final_scan,
                check_owned_work=check_owned_work,
                record_attempt=store.begin,
                persist_ownership=store.capture,
                persist_response=store.response,
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
