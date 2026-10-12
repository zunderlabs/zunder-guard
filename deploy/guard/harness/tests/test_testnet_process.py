import hashlib
import io
import os
import signal
import subprocess
import time
import tomllib
from decimal import Decimal
from pathlib import Path
from typing import Any, BinaryIO

import pytest

import guard_harness.testnet_process as process
from guard_harness.cli import Pair
from guard_harness.paper_bot import LocalGuard
from guard_harness.testnet_journey import Journey
from guard_harness.testnet_protection import Entry
from guard_harness.testnet_scan import SCAN_TIMEOUT
from guard_harness.testnet_scan import TestnetReads as VenueReads

ACCOUNT = "0x" + "a" * 40
WALLET = "0x" + "b" * 40
CLIENT = "0x" + "c" * 40
SYNTHETIC_CLIENT_KEY = "0x" + "1" * 64


@pytest.fixture
def subject(tmp_path: Path) -> tuple[Path, str]:
    binary = tmp_path / "subject"
    binary.write_text("""#!/usr/bin/env python3
import json, pathlib, sys, time
home = pathlib.Path(sys.argv[sys.argv.index('--home') + 1])
if 'init' in sys.argv:
    account = sys.argv[sys.argv.index('--account') + 1]
    listen = sys.argv[sys.argv.index('--listen') + 1]
    (home / 'guard.toml').write_text('mode = "testnet"\\nnetwork = "testnet"\\n'
        + 'account = "' + account + '"\\nlisten = "' + listen + '"\\n'
        + 'allow_mainnet = false\\n[policy]\\nmax_notional = "40"\\n'
        + '[auth]\\nclients = ["0x' + 'c' * 40 + '"]\\n')
    (home / 'guard.toml').chmod(0o600)
    print('FIXTURE-INIT-PAIRING-SECRET')
elif 'pair' in sys.argv:
    print(json.dumps(dict(client_address='0x' + 'c' * 40, client_key='0x' + '1' * 64)))
elif 'run' in sys.argv:
    # Assert custody through stdin with no contents written to any file.
    assert sys.stdin.readline().strip() == 'FIXTURE-WALLET-INPUT'
    print('FIXTURE-WALLET-INPUT', file=sys.stderr)
    time.sleep(60)
""")
    binary.chmod(0o700)
    return binary, hashlib.sha256(binary.read_bytes()).hexdigest()


def start(
    subject: tuple[Path, str], tmp_path: Path, key: BinaryIO, **changes: Any
) -> process.Foreground:
    binary, digest = subject
    args: dict[str, Any] = dict(
        sha256=digest,
        work=tmp_path / "work",
        account=ACCOUNT,
        api_wallet=WALLET,
        port=18547,
        key_stdin=key,
    )
    args.update(changes)
    return process.Foreground(binary, **args)


def test_actual_child_custody_private_copy_and_config_preservation(
    subject: tuple[Path, str],
    tmp_path: Path,
) -> None:
    reader, writer = os.pipe()
    os.write(writer, b"FIXTURE-WALLET-INPUT\n")
    os.close(writer)
    with os.fdopen(reader, "rb") as key:
        owner = start(subject, tmp_path, key)
    try:
        owner.alive()
        assert owner.binary.read_bytes() == subject[0].read_bytes()
        assert owner.binary.stat().st_mode & 0o777 == 0o700
        config = tomllib.loads((owner.home / "guard.toml").read_text())
        assert config["api_wallet"] == WALLET and config["policy"] == {"max_notional": "40"}
        assert config["auth"]["clients"] == [CLIENT] and config["allow_mainnet"] is False
        assert owner.client_key.stat().st_mode & 0o777 == 0o600
        assert owner.client_key.read_text().strip() == SYNTHETIC_CLIENT_KEY
        for path in owner.work.glob("*.log"):
            assert (
                "FIXTURE-" not in path.read_text() and SYNTHETIC_CLIENT_KEY not in path.read_text()
            )
        owner.stop_after_flat()
        assert owner.child.poll() is not None
    finally:
        if owner.child.poll() is None:
            os.killpg(owner.child.pid, signal.SIGTERM)
            owner.child.wait(timeout=5)


@pytest.mark.parametrize(
    "change",
    [dict(sha256="0" * 64), dict(account="mainnet"), dict(port=1), dict(api_wallet="invalid")],
)
def test_refuses_before_init_or_key_read(
    subject: tuple[Path, str], tmp_path: Path, change: dict[str, Any]
) -> None:
    key = io.BytesIO(b"FIXTURE-WALLET-INPUT")
    with pytest.raises(process.ProcessError):
        start(subject, tmp_path, key, **change)
    assert key.tell() == 0 and not (tmp_path / "work").exists()


def test_refuses_existing_work(subject: tuple[Path, str], tmp_path: Path) -> None:
    (tmp_path / "work").mkdir()
    with pytest.raises(process.ProcessError):
        start(subject, tmp_path, io.BytesIO())


def test_replacement_or_dead_child_refuses_local_reads(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    owner = process.Foreground.__new__(process.Foreground)
    owner.binary = tmp_path / "binary"
    owner.binary.write_bytes(b"replacement")
    owner.sha256 = hashlib.sha256(b"original").hexdigest()
    owner.child = subprocess.Popen(["sleep", "30"], start_new_session=True)
    owner.url = "http://127.0.0.1:18547"
    called = False

    def request(*args: object) -> object:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(LocalGuard, "request", request)
    try:
        with pytest.raises(process.ProcessError):
            process.OwnedLocalGuard(owner).request("/guard/status")
        assert not called
        owner.child.terminate()
        owner.child.wait(timeout=5)
        with pytest.raises(process.ProcessError):
            process.OwnedLocalGuard(owner).request("/guard/status")
        assert not called
    finally:
        if owner.child.poll() is None:
            owner.child.terminate()
            owner.child.wait(timeout=5)


@pytest.mark.parametrize(
    "deadline", [process.ENTRY_REMAINING + 100.0, process.ENTRY_REMAINING + 99.999]
)
def test_journey_connects_owned_process_and_keeps_guard_on_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    deadline: float,
) -> None:
    owner = process.Foreground.__new__(process.Foreground)
    owner.binary, owner.home = tmp_path / "binary", tmp_path / "home"
    owner.sha256, owner.url, owner.work = "a" * 64, "http://127.0.0.1:18547", tmp_path
    owner.client_key, owner.account = tmp_path / "client", ACCOUNT
    owner.pair = Pair(CLIENT, SYNTHETIC_CLIENT_KEY)
    owner.started_ms = 1000
    monkeypatch.setattr(owner, "wait_ready", lambda: None)
    monkeypatch.setattr(owner, "alive", lambda: None)
    entered = False

    class FakeMCP:
        def __init__(self, binary: Path, **kwargs: Any) -> None:
            assert binary == owner.binary and kwargs["sha256"] == owner.sha256
            assert kwargs["home"] == owner.home and kwargs["client_key"] == owner.client_key

        def __enter__(self) -> "FakeMCP":
            return self

        def __exit__(self, *args: object) -> None:
            pass

    def execute(guard: process.OwnedLocalGuard, mcp: Any, read: Any, **kwargs: Any) -> Journey:
        nonlocal entered
        entered = True
        assert guard.owner is owner and kwargs["client"] == CLIENT
        assert (
            kwargs["stop_guard"] == owner.stop_after_flat and kwargs["process_started_ms"] == 1000
        )
        kwargs["admit_entry"]()
        assert read.deadline == 280
        kwargs["begin_cleanup"]()
        assert read.deadline == 100 + SCAN_TIMEOUT and read.next_read == 102
        return Journey(None, None, "cleanup_incomplete_keep_guard_running", False)

    monkeypatch.setattr(process, "MCP", FakeMCP)
    monkeypatch.setattr(process, "execute", execute)
    monkeypatch.setattr(time, "monotonic", lambda: 100.0)
    if deadline < 100 + process.ENTRY_REMAINING:
        with pytest.raises(process.ProcessError):
            owner.journey(
                VenueReads(clock=lambda: 100.0),
                Entry(0, Decimal("0.0002"), Decimal("100000"), 5),
                version="1.0.0-rc.1",
                deadline=deadline,
            )
        assert entered
    else:
        result = owner.journey(
            VenueReads(clock=lambda: 100.0),
            Entry(0, Decimal("0.0002"), Decimal("100000"), 5),
            version="1.0.0-rc.1",
            deadline=deadline,
        )
        assert entered and not result.guard_stopped and not result.passed
