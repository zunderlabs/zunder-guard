import copy
import errno
import hashlib
import io
import json
import os
import signal
import subprocess
import time
import tomllib
import urllib.error
import urllib.request
from decimal import Decimal
from email.message import Message
from pathlib import Path
from typing import Any, BinaryIO

import pytest

import guard_harness.paper_bot as paper
import guard_harness.testnet_process as process
from guard_harness.cli import Pair
from guard_harness.paper_bot import GuardUnavailable, LocalGuard
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


def test_recovery_admission_runs_after_setup_before_any_guard_runtime(
    subject: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = subprocess.Popen
    runtime_calls: list[object] = []

    def popen(args: Any, **kwargs: Any) -> Any:
        if "run" in args:
            runtime_calls.append(args)
            raise AssertionError("expired recovery must not start Guard")
        return original(args, **kwargs)

    def refuse_after_setup() -> None:
        assert (tmp_path / "work/home/guard.toml").exists()
        assert (tmp_path / "work/client-key").exists()
        raise process.ProcessError("recovery budget exhausted during setup")

    monkeypatch.setattr(subprocess, "Popen", popen)
    with pytest.raises(process.ProcessError, match="budget exhausted"):
        start(subject, tmp_path, io.BytesIO(b"unconsumed"), admit_start=refuse_after_setup)
    assert runtime_calls == []


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
        assert read.deadline == 100 + process.OWNED_WORK_TIMEOUT
        next_read, reservations = read.next_read, list(read.reservations)
        kwargs["begin_cleanup"]()
        assert read.deadline == 100 + process.OWNED_WORK_TIMEOUT
        kwargs["begin_final_scan"]()
        assert read.deadline == 100 + SCAN_TIMEOUT
        assert read.next_read == next_read and read.reservations == reservations
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


def test_production_driver_defers_market_reads_to_post_scan_planner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    owner = process.Foreground.__new__(process.Foreground)
    owner.binary, owner.home = tmp_path / "binary", tmp_path / "home"
    owner.sha256, owner.url, owner.work = "a" * 64, "http://127.0.0.1:18547", tmp_path
    owner.client_key, owner.account = tmp_path / "client", ACCOUNT
    owner.pair = Pair(CLIENT, SYNTHETIC_CLIENT_KEY)
    owner.started_ms = 1000
    monkeypatch.setattr(owner, "wait_ready", lambda: None)
    timeline: list[str] = []

    class FakeMCP:
        def __init__(self, binary: Path, **kwargs: Any) -> None:
            assert timeline == []

        def __enter__(self) -> "FakeMCP":
            return self

        def __exit__(self, *args: object) -> None:
            pass

    def read(payload: dict[str, Any]) -> dict[str, Any]:
        assert timeline and timeline[0] == "execute"
        timeline.append(payload["type"])
        return (
            {"universe": [{"name": "BTC", "szDecimals": 5, "isDelisted": False}]}
            if payload["type"] == "meta"
            else {"BTC": "60200"}
        )

    def execute(*args: Any, **kwargs: Any) -> Journey:
        assert timeline == [] and callable(kwargs["entry"])
        timeline.append("execute")
        planned = kwargs["entry"]()
        planned.validate()
        assert planned.limit == Decimal("60320")
        assert planned.size * planned.limit <= Decimal("15")
        return Journey(None, None, "offline", False)

    monkeypatch.setattr(process, "MCP", FakeMCP)
    monkeypatch.setattr(process, "execute", execute)
    owner.journey(read, version="1.0.0-rc.1", deadline=time.monotonic() + 10000)  # type: ignore[arg-type]
    assert timeline == ["execute", "meta", "allMids"]


def ready_status() -> dict[str, Any]:
    return dict(
        mode="testnet",
        network="testnet",
        account=ACCOUNT,
        started_at_ms=1000,
        capabilities={"exchange_expected_mode": True},
        journal={"ok": True},
        risk={"state": "active", "journal_ready": True},
        killed=None,
        journal_broken=False,
        last_error=None,
        last_sync_ms=1100,
        fee=dict(
            mode="builder",
            address=WALLET,
            fee_tenths_bp=20,
            paper=False,
            charged=True,
            entries_blocked=False,
            approval=dict(state="approved", max_tenths_bp=20, error=None),
        ),
    )


def readiness_fixture(
    monkeypatch: pytest.MonkeyPatch,
    statuses: list[object],
) -> tuple[process.Foreground, list[str], list[float]]:
    owner = process.Foreground.__new__(process.Foreground)
    owner.account, owner.started_ms, owner.url = ACCOUNT, 1000, "http://127.0.0.1:18547"
    calls: list[str] = []
    clock = [0.0]
    monkeypatch.setattr(owner, "alive", lambda: None)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "time_ns", lambda: 1200 * 1_000_000)

    def sleep(delay: float) -> None:
        clock[0] += delay

    def request(self: LocalGuard, path: str, body: object = None) -> object:
        assert path == "/guard/status" and body is None
        calls.append(path)
        item = statuses.pop(0) if len(statuses) > 1 else statuses[0]
        if isinstance(item, BaseException):
            raise item
        return item

    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(LocalGuard, "request", request)
    return owner, calls, clock


def test_readiness_waits_for_initial_observation_and_builder_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = dict(mode="testnet", network="testnet", account=ACCOUNT, started_at_ms=1000)
    unchecked = ready_status()
    unchecked["last_sync_ms"] = None
    unchecked["risk"]["journal_ready"] = False
    unchecked["fee"].update(charged=False, entries_blocked=True)
    unchecked["fee"]["approval"].update(state="unchecked", max_tenths_bp=None)
    synced_unchecked = copy.deepcopy(unchecked)
    synced_unchecked["last_sync_ms"] = 1100
    synced_unchecked["risk"]["journal_ready"] = True
    owner, calls, clock = readiness_fixture(
        monkeypatch, [identity, unchecked, synced_unchecked, ready_status()]
    )
    owner.wait_ready()
    assert len(calls) == 4 and clock[0] == 0.75


def test_readiness_off_compatibility_and_transport_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready = ready_status()
    ready["fee"] = {"mode": "off"}
    owner, calls, clock = readiness_fixture(
        monkeypatch, [GuardUnavailable("local Guard connection refused"), ready]
    )
    owner.wait_ready()
    assert len(calls) == 2 and clock[0] == 0.25


def test_readiness_initialization_deadline_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    owner, calls, clock = readiness_fixture(monkeypatch, [{}])
    with pytest.raises(process.ProcessError, match="readiness deadline"):
        owner.wait_ready(timeout=1)
    assert len(calls) == 4 and clock[0] == 1


@pytest.mark.parametrize(
    "path, value",
    [
        (("mode",), "mainnet"),
        (("network",), "mainnet"),
        (("account",), WALLET),
        (("account",), 7),
        (("started_at_ms",), 999),
        (("started_at_ms",), True),
        (("risk", "state"), "halted_for_day"),
        (("risk", "journal_ready"), False),
        (("risk", "journal_ready"), 1),
        (("killed",), "SECRET"),
        (("journal_broken",), True),
        (("journal", "ok"), False),
        (("last_error",), "SECRET"),
        (("last_sync_ms",), 999),
        (("last_sync_ms",), 1201),
        (("last_sync_ms",), True),
        (("capabilities", "exchange_expected_mode"), False),
        (("fee", "mode"), "fee_free"),
        (("fee", "mode"), []),
        (("fee", "address"), "SECRET"),
        (("fee", "fee_tenths_bp"), 21),
        (("fee", "fee_tenths_bp"), True),
        (("fee", "paper"), True),
        (("fee", "charged"), False),
        (("fee", "entries_blocked"), True),
        (("fee", "approval", "state"), "not_approved"),
        (("fee", "approval", "state"), "refused_by_venue"),
        (("fee", "approval", "state"), []),
        (("fee", "approval", "max_tenths_bp"), 19),
        (("fee", "approval", "max_tenths_bp"), True),
        (("fee", "approval", "error"), "SECRET"),
    ],
)
def test_observed_fatal_status_never_polls_into_health(
    monkeypatch: pytest.MonkeyPatch,
    path: tuple[str, ...],
    value: object,
) -> None:
    bad = ready_status()
    target = bad
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    owner, calls, clock = readiness_fixture(monkeypatch, [bad, ready_status()])
    with pytest.raises(process.ProcessError) as error:
        owner.wait_ready()
    assert str(error.value) == "fresh authenticated testnet process prerequisite refused"
    assert len(calls) == 1 and clock[0] == 0


def test_owned_child_failure_is_never_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    owner, calls, clock = readiness_fixture(
        monkeypatch,
        [process.ProcessError("fresh authenticated testnet process prerequisite refused")],
    )
    with pytest.raises(process.ProcessError):
        owner.wait_ready()
    assert len(calls) == 1 and clock[0] == 0


def test_readiness_checks_deadline_again_after_status_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, calls, clock = readiness_fixture(monkeypatch, [ready_status()])
    original = LocalGuard.request

    def delayed(self: LocalGuard, path: str, body: object = None) -> object:
        clock[0] = 1.0
        return original(self, path, body)  # type: ignore[arg-type]

    monkeypatch.setattr(LocalGuard, "request", delayed)
    with pytest.raises(process.ProcessError, match="readiness deadline"):
        owner.wait_ready(timeout=1)
    assert len(calls) == 1


@pytest.mark.parametrize("field,value", [("charged", True), ("entries_blocked", False)])
def test_unchecked_approval_must_have_consistent_pending_state(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: bool,
) -> None:
    bad = ready_status()
    bad["fee"].update(charged=False, entries_blocked=True)
    bad["fee"]["approval"].update(state="unchecked", max_tenths_bp=None)
    bad["fee"][field] = value
    owner, calls, clock = readiness_fixture(monkeypatch, [bad, ready_status()])
    with pytest.raises(process.ProcessError):
        owner.wait_ready()
    assert len(calls) == 1 and clock[0] == 0


@pytest.mark.parametrize(
    "failure",
    [
        b'{"private":"SECRET",',
        b"\xffSECRET",
        b"x" * 1_048_577,
        paper.PaperError("Guard redirected a local request"),
        urllib.error.HTTPError("http://127.0.0.1:18547", 401, "SECRET", Message(), None),
        urllib.error.URLError(TimeoutError("SECRET")),
        OSError(errno.ECONNRESET, "SECRET"),
    ],
)
def test_actual_guard_protocol_failure_never_polls_into_health(
    monkeypatch: pytest.MonkeyPatch,
    failure: object,
) -> None:
    original = LocalGuard.request
    owner, _, clock = readiness_fixture(monkeypatch, [ready_status()])
    monkeypatch.setattr(LocalGuard, "request", original)
    calls: list[str] = []

    class Opener:
        def open(self, request: Any, timeout: float) -> io.BytesIO:
            calls.append(request.full_url)
            if len(calls) == 1:
                if isinstance(failure, BaseException):
                    raise failure
                assert isinstance(failure, bytes)
                return io.BytesIO(failure)
            return io.BytesIO(json.dumps(ready_status()).encode())

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises((paper.PaperError, OSError)):
        owner.wait_ready()
    assert len(calls) == 1 and clock[0] == 0


def test_actual_connection_refusal_can_wait_for_owned_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = LocalGuard.request
    owner, _, clock = readiness_fixture(monkeypatch, [ready_status()])
    monkeypatch.setattr(LocalGuard, "request", original)
    calls: list[str] = []

    class Opener:
        def open(self, request: Any, timeout: float) -> io.BytesIO:
            calls.append(request.full_url)
            if len(calls) == 1:
                raise urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, "SECRET"))
            return io.BytesIO(json.dumps(ready_status()).encode())

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    owner.wait_ready()
    assert len(calls) == 2 and clock[0] == 0.25
