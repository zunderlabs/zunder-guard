"""Synthetic operator recovery counterexamples; never reads a key or calls a venue."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from guard_harness import testnet_recovery as recovery
from guard_harness.testnet_process import Foreground
from guard_harness.testnet_scan import digest

ACCOUNT = "0x" + "a" * 40
WALLET = "0x" + "b" * 40
SOURCE = "c" * 40
TAG = "v1.0.0-rc.1"
STOP = {
    "oid": 17,
    "cloid": "0x7a67" + "f" * 28,
    "coin": "BTC",
    "side": "A",
    "isTrigger": True,
    "reduceOnly": True,
    "orderType": "Stop Market",
    "sz": "0.0002",
    "triggerPx": "58800",
    "limitPx": "52920",
}
CONTEXT = recovery.Context(
    hashlib.sha256(ACCOUNT.encode()).hexdigest(),
    hashlib.sha256(WALLET.encode()).hexdigest(),
    "0.0002",
    17,
    digest(STOP),
    11,
    12,
    1,
    SOURCE,
    TAG,
    3,
)


class Fixture:
    def __init__(self) -> None:
        self.size = CONTEXT.expected_size
        self.stop: dict[str, Any] | None = copy.deepcopy(STOP)
        self.position: dict[str, Any] = {
            "coin": "BTC",
            "leverage": {"type": "isolated"},
            "positionValue": "12",
        }
        self.other = False
        self.inventory = [None, {"name": "synthetic"}]
        self.markets: list[dict[str, Any]] = [
            {"name": "SOL", "szDecimals": 2},
            {"name": "ETH", "szDecimals": 4},
            {"name": "AVAX", "szDecimals": 3},
            {"name": "BTC", "szDecimals": 5},
        ]
        self.reads: list[tuple[str, str]] = []
        self.mutations: list[tuple[str, dict[str, Any]]] = []
        self.phases: list[str] = []
        self.started = self.exited = False
        self.on_start: Callable[[], None] = lambda: None
        self.close_size = "0"
        self.refuse = self.unknown = False
        self.writes_bound = self.close_size_bound = True
        self.status = {
            "mode": "testnet",
            "network": "testnet",
            "account": ACCOUNT,
            "version": TAG[1:],
            "capabilities": {"exchange_expected_mode": True},
            "risk": {"state": "active", "journal_ready": True},
            "last_error": None,
            "killed": None,
            "journal_broken": False,
        }
        self.events: list[dict[str, Any]] = [
            {"seq": 1, "kind": "started", "mode": "testnet", "account": ACCOUNT}
        ]

    def read(self, payload: dict[str, Any]) -> object:
        kind, dex = payload["type"], payload.get("dex", "")
        self.reads.append((kind, dex))
        if kind == "userAbstraction":
            return "disabled"
        if kind == "meta":
            return {"universe": copy.deepcopy(self.markets)}
        if kind == "perpDexs":
            return self.inventory
        if kind == "frontendOpenOrders":
            return [copy.deepcopy(self.stop)] if not dex and self.stop is not None else []
        assert kind == "clearinghouseState"
        size = self.size if not dex else "1" if self.other else "0"
        position = {**self.position, "szi": size}
        return {
            "marginSummary": {"accountValue": "400"},
            "assetPositions": [{"position": position}] if size != "0" else [],
        }

    def request(self, path: str) -> object:
        return self.events if path.endswith("since=0") else self.status

    def tool(self, name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        assert name in {"close_position", "cancel_order"}, "entry and resume are forbidden"
        self.mutations.append((name, arguments))
        if self.refuse or self.unknown:
            return {"sent": True, "ok": not self.refuse, "outcome": "unknown"}, self.refuse
        if name == "close_position":
            self.size = self.close_size
        else:
            assert self.size == "0", "protection cannot be canceled while exposed"
            self.stop = None
        return {"sent": True, "ok": True, "outcome": "sent"}, False

    def start(self) -> tuple[Any, Any, Any]:
        assert self.reads[-1] == ("perpDexs", ""), "full scan must precede custody"
        self.started = True
        self.on_start()
        return self, self, self.exit

    def exit(self) -> None:
        assert self.size == "0" and self.stop is None
        assert self.phases[-1] == "guard-exit" and self.reads[-1] == ("perpDexs", "")
        self.exited = True

    def run(self) -> dict[str, object]:
        return recovery.recover(
            self.read,
            ACCOUNT,
            CONTEXT,
            start=self.start,
            phase=self.phases.append,
            check_work=lambda: None,
            check_mutation=lambda: None,
        )


def test_actual_orchestrator_one_exact_close_then_original_stop_cancel_fullscan_and_exit() -> None:
    f = Fixture()
    result = f.run()
    assert f.mutations == [
        ("close_position", {"coin": "BTC", "expected_size": CONTEXT.expected_size}),
        ("cancel_order", {"coin": "BTC", "order_id": CONTEXT.stop_oid}),
    ]
    assert result["operator_attributed"] is True and result["gate_eligible"] is False
    assert result["recovery_complete"] is True and f.exited
    assert ("clearinghouseState", "synthetic") in f.reads


@pytest.mark.parametrize(
    "field,value",
    [
        ("size", "0.0001"),
        ("size", "-0.0002"),
        ("coin", "ETH"),
        ("leverage", {"type": "cross"}),
        ("positionValue", "40.00001"),
    ],
)
def test_changed_quantity_side_market_or_notional_refuses_before_custody(
    field: str, value: Any
) -> None:
    f = Fixture()
    if field == "size":
        f.size = value
    else:
        f.position[field] = value
    with pytest.raises(recovery.RecoveryError):
        f.run()
    assert not f.started and not f.mutations


@pytest.mark.parametrize(
    "field,value",
    [
        ("oid", 18),
        ("triggerPx", "58799"),
        ("sz", "0.0001"),
        ("reduceOnly", False),
        ("isTrigger", False),
        ("orderType", "Take Profit Market"),
        ("cloid", "unknown"),
    ],
)
def test_changed_stop_whole_wire_refuses_before_custody(field: str, value: Any) -> None:
    f = Fixture()
    assert f.stop is not None
    f.stop[field] = value
    with pytest.raises(recovery.RecoveryError):
        f.run()
    assert not f.started and not f.mutations


def test_other_dex_exposure_refuses_before_custody() -> None:
    f = Fixture()
    f.other = True
    with pytest.raises(recovery.RecoveryError):
        f.run()
    assert not f.started and not f.mutations


@pytest.mark.parametrize("kind", ["partial", "unknown", "refused"])
def test_partial_unknown_or_refused_close_never_retries_or_cancels_protection(kind: str) -> None:
    f = Fixture()
    f.close_size = "0.0001" if kind == "partial" else "0"
    f.refuse, f.unknown = kind == "refused", kind == "unknown"
    with pytest.raises(recovery.RecoveryError):
        f.run()
    assert len(f.mutations) == 1 and f.mutations[0][0] == "close_position"
    assert f.stop == STOP and not f.exited


def test_stop_fills_before_new_guard_ready_no_close_or_cancel() -> None:
    f = Fixture()

    def filled() -> None:
        f.size, f.stop = "0", None

    f.on_start = filled
    result = f.run()
    assert not f.mutations and f.exited and result["recovery_complete"] is True


def test_already_flat_absence_uses_no_key_or_runtime_and_earns_no_formal_credit() -> None:
    f = Fixture()
    f.size, f.stop = "0", None
    result = f.run()
    assert not f.started and not f.mutations
    assert result["recovery_complete"] is True and result["gate_eligible"] is False
    assert result["new_guard_started"] is False and result["new_guard_exit_confirmed"] is False


@pytest.mark.parametrize(
    "field,value",
    [("mode", "mainnet"), ("network", "paper"), ("account", WALLET), ("version", "wrong")],
)
def test_fresh_guard_identity_refuses_without_mutation(field: str, value: str) -> None:
    f = Fixture()
    f.status[field] = value
    with pytest.raises(recovery.RecoveryError):
        f.run()
    assert not f.mutations and not f.exited


@pytest.mark.parametrize("capability", ["writes_bound", "close_size_bound"])
def test_missing_literal_mcp_capability_refuses(capability: str) -> None:
    f = Fixture()
    setattr(f, capability, False)
    with pytest.raises(recovery.RecoveryError):
        f.run()
    assert not f.mutations


def test_changed_stop_after_guard_starts_refuses_and_preserves_it() -> None:
    f = Fixture()

    def changed() -> None:
        assert f.stop is not None
        f.stop["triggerPx"] = "58799"

    f.on_start = changed
    with pytest.raises(recovery.RecoveryError):
        f.run()
    assert not f.mutations and not f.exited


def test_exit_failure_cannot_finish_recovery() -> None:
    f = Fixture()

    def failed() -> None:
        raise RuntimeError("PRIVATE-SENTINEL")

    f.exit = failed  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        f.run()
    assert not f.exited


@pytest.mark.parametrize(
    "field,value",
    [
        ("expected_size", "0"),
        ("expected_size", "-0.0002"),
        ("stop_oid", True),
        ("prior_attempt", 0),
        ("account_sha256", "bad"),
        ("api_wallet_sha256", "a" * 64),
    ],
)
def test_context_scope_and_strict_types_refuse(field: str, value: Any) -> None:
    context = asdict(CONTEXT)
    context[field] = value
    with pytest.raises(recovery.RecoveryError):
        recovery.Context.parse(json.dumps(context), digest(context), ACCOUNT, WALLET)


def test_context_identity_hash_and_duplicate_fields_refuse() -> None:
    body = json.dumps(asdict(CONTEXT))
    assert recovery.Context.parse(body, digest(asdict(CONTEXT)), ACCOUNT, WALLET) == CONTEXT
    for checksum, account, wallet in [
        ("0" * 64, ACCOUNT, WALLET),
        (digest(asdict(CONTEXT)), WALLET, ACCOUNT),
    ]:
        with pytest.raises(recovery.RecoveryError):
            recovery.Context.parse(body, checksum, account, wallet)
    with pytest.raises(recovery.RecoveryError):
        recovery.Context.parse(
            body[:-1] + ',"stop_oid":17}', digest(asdict(CONTEXT)), ACCOUNT, WALLET
        )


def metadata() -> tuple[dict[str, Any], dict[str, Any], datetime]:
    now = datetime.now(UTC)
    run = {
        "repository": {"full_name": recovery.REPOSITORY},
        "head_repository": {"full_name": recovery.REPOSITORY},
        "id": 11,
        "run_attempt": 1,
        "head_sha": SOURCE,
        "head_branch": TAG,
        "path": ".github/workflows/verify.yml",
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "failure",
    }
    job = {
        "id": 12,
        "run_id": 11,
        "run_attempt": 1,
        "head_sha": SOURCE,
        "name": "Released trading and purchase journeys / T1",
        "status": "completed",
        "conclusion": "failure",
        "labels": ["ubuntu-24.04"],
        "runner_group_name": "GitHub Actions",
        "runner_name": "GitHub Actions 1",
        "completed_at": (now - timedelta(minutes=2)).isoformat(),
    }
    return run, job, now


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "in_progress"),
        ("labels", ["self-hosted", "ubuntu-24.04"]),
        ("runner_group_name", "Default"),
        ("name", "T2"),
        ("head_sha", "d" * 40),
        ("run_attempt", 2),
    ],
)
def test_prior_wrong_or_live_runtime_cannot_admit(field: str, value: Any) -> None:
    run, job, now = metadata()
    job[field] = value
    with pytest.raises(recovery.RecoveryError):
        recovery.prior_teardown(CONTEXT, run, job, current_start=now)


def test_hosted_job_admission_is_provider_completion_not_forged_guard_stopped() -> None:
    run, job, now = metadata()
    recovery.prior_teardown(CONTEXT, run, job, current_start=now)
    job["completed_at"] = now.isoformat()
    with pytest.raises(recovery.RecoveryError):
        recovery.prior_teardown(CONTEXT, run, job, current_start=now)


def test_actual_cli_failure_never_leaks_key_account_or_exception_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(*args: object) -> None:
        raise RuntimeError(json.dumps({"body": "PRIVATE-SENTINEL", "account": ACCOUNT}))

    monkeypatch.setattr(recovery, "execute", fail)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "recovery",
            "--subjects",
            str(tmp_path),
            "--context",
            str(tmp_path / "context.json"),
            "--context-sha256",
            "a" * 64,
            "--output",
            str(tmp_path / "output"),
        ],
    )
    monkeypatch.setenv("WALLET_FRAME", "PRIVATE-KEY-SENTINEL")
    assert recovery.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert (
        captured.err
        == "Operator recovery incomplete; preserve protection and reconcile; never retry\n"
    )
    assert os.environ["WALLET_FRAME"] == "PRIVATE-KEY-SENTINEL"


def close_wire() -> dict[str, Any]:
    return {
        "type": "order",
        "grouping": "na",
        "orders": [
            {
                "a": CONTEXT.asset,
                "b": False,
                "p": "57000",
                "s": CONTEXT.expected_size,
                "r": True,
                "t": {"limit": {"tif": "Ioc"}},
                "c": "0x7a6d" + "e" * 28,
            }
        ],
    }


def event_trace(kind: str = "decision") -> list[dict[str, Any]]:
    wire = close_wire()
    intent: dict[str, Any] = {"seq": 2, "kind": kind}
    if kind == "decision":
        intent.update(verdict="allow", request=copy.deepcopy(wire), pre=[], forward=wire, post=[])
    else:
        intent.update(actions=[wire], sent=True, problems=[])
        if kind == "protect":
            intent["coins"] = ["BTC"]
    return [
        Fixture().events[0],
        intent,
        {
            "seq": 3,
            "kind": "sent",
            "decision": 2,
            "index": 0,
            "nonce": 123,
            "ok": True,
            "reply": {
                "status": "ok",
                "response": {
                    "type": "order",
                    "data": {
                        "statuses": [
                            {
                                "filled": {
                                    "totalSz": CONTEXT.expected_size,
                                    "avgPx": "58000",
                                    "oid": 18,
                                }
                            }
                        ],
                    },
                },
            },
        },
        {"seq": 4, "kind": "done", "intent": 2},
    ]


@pytest.mark.parametrize("kind", ["decision", "protect", "flatten"])
def test_complete_durable_journal_positive_named_send_paths(kind: str) -> None:
    recovery.audit_events(event_trace(kind), ACCOUNT, CONTEXT, STOP)


@pytest.mark.parametrize(
    "path",
    ["request", "pre", "forward", "post", "protect", "flatten", "intent", "sent", "recovered"],
)
@pytest.mark.parametrize("bad", ["buy", "opening", "foreign", "cancel", "quantity", "type"])
def test_every_alternate_action_path_refuses_unsafe_wire_before_tool(path: str, bad: str) -> None:
    events = event_trace(path if path in {"protect", "flatten"} else "decision")
    wire = close_wire()
    if bad == "buy":
        wire["orders"][0]["b"] = True
    elif bad == "opening":
        wire["orders"][0]["r"] = False
    elif bad == "foreign":
        wire["orders"][0]["a"] = 1
    elif bad == "cancel":
        wire = {"type": "cancel", "cancels": [{"a": CONTEXT.asset, "o": 999}]}
    elif bad == "quantity":
        wire["orders"][0]["s"] = "0.00021"
    else:
        wire = {"type": "usdSend", "destination": "PRIVATE-SENTINEL"}
    if path in {"pre", "post"}:
        events[1][path] = [wire]
    elif path in {"request", "forward"}:
        events[1][path] = wire
    elif path in {"protect", "flatten"}:
        events[1]["actions"] = [wire]
    elif path == "sent":
        events[2]["action"] = wire
    else:
        events = events[:2] + [
            {
                "seq": 3,
                "kind": path,
                "action": wire,
                "of": 2,
                "intent": 2,
                "index": 0,
                "outcome": "happened",
            }
        ]
    f = Fixture()
    f.events = events
    with pytest.raises(recovery.RecoveryError):
        f.run()
    assert not f.mutations and not f.exited


@pytest.mark.parametrize(
    "status",
    [
        {"error": "PRIVATE-SENTINEL"},
        {"resting": {"oid": 18}},
        {"filled": {"totalSz": "0.0001", "avgPx": "58000", "oid": 18}},
        {"filled": {"totalSz": CONTEXT.expected_size, "avgPx": "58000", "oid": True}},
        "waitingForFill",
        "PRIVATE-SENTINEL",
        None,
    ],
)
def test_sent_top_level_ok_cannot_mask_unknown_refused_partial_nested_status(
    status: object,
) -> None:
    events = event_trace()
    events[2]["reply"]["response"]["data"]["statuses"] = [status]
    with pytest.raises((recovery.RecoveryError, RuntimeError)):
        recovery.audit_events(events, ACCOUNT, CONTEXT, STOP)


@pytest.mark.parametrize(
    "field,value", [("decision", 999), ("index", True), ("index", 1), ("ok", 1), ("nonce", True)]
)
def test_sent_requires_exact_prior_intent_reference_and_literals(field: str, value: object) -> None:
    events = event_trace()
    events[2][field] = value
    with pytest.raises(recovery.RecoveryError):
        recovery.audit_events(events, ACCOUNT, CONTEXT, STOP)


@pytest.mark.parametrize("kind", ["protect", "flatten"])
@pytest.mark.parametrize(
    "field,value", [("sent", False), ("sent", 1), ("problems", ["PRIVATE-SENTINEL"])]
)
def test_autonomous_failed_sends_or_problem_events_refuse(
    kind: str, field: str, value: object
) -> None:
    events = event_trace(kind)
    events[1][field] = value
    with pytest.raises(recovery.RecoveryError):
        recovery.audit_events(events, ACCOUNT, CONTEXT, STOP)


def test_unbound_done_unknown_recovery_and_pending_intent_refuse() -> None:
    for event in (
        {"kind": "done", "intent": 999},
        {
            "kind": "recovered",
            "intent": 2,
            "index": 0,
            "action": close_wire(),
            "outcome": "unknown",
        },
    ):
        events = event_trace()[:2] + [{"seq": 3, **event}]
        with pytest.raises(recovery.RecoveryError):
            recovery.audit_events(events, ACCOUNT, CONTEXT, STOP)
    with pytest.raises(recovery.RecoveryError):
        recovery.audit_events(event_trace()[:2], ACCOUNT, CONTEXT, STOP)


@pytest.mark.parametrize("phase", ["preflight", "one-close", "original-stop-cancel", "guard-exit"])
def test_stalled_durable_phase_never_sends_or_starts_after_expiration(phase: str) -> None:
    f = Fixture()
    expired = False

    def observe(label: str) -> None:
        nonlocal expired
        f.phases.append(label)
        if label == phase:
            expired = True

    def check() -> None:
        recovery.need(not expired)

    with pytest.raises(recovery.RecoveryError):
        recovery.recover(
            f.read,
            ACCOUNT,
            CONTEXT,
            start=f.start,
            phase=observe,
            check_work=check,
            check_mutation=check,
        )
    if phase == "preflight":
        assert not f.started
    if phase in {"preflight", "one-close"}:
        assert not f.mutations
    if phase == "original-stop-cancel":
        assert len(f.mutations) == 1 and f.stop == STOP
    assert not f.exited


@pytest.mark.parametrize("exception", [False, True])
def test_immediate_outcome_retention_precedes_venue_reads_even_on_tool_exception(
    exception: bool,
) -> None:
    f = Fixture()
    f.unknown = True
    retained: list[tuple[str, bool, int]] = []
    if exception:

        def failed(*_: object) -> tuple[dict[str, Any], bool]:
            raise RuntimeError("PRIVATE-SENTINEL")

        f.tool = failed  # type: ignore[method-assign,assignment]

    def retain(
        name: str, reply: object, error: bool, guard: object, stop: object, baseline: int
    ) -> None:
        assert guard is f and stop == STOP and baseline == 1
        retained.append((name, error, len(f.reads)))

    with pytest.raises(RuntimeError):
        recovery.recover(
            f.read,
            ACCOUNT,
            CONTEXT,
            start=f.start,
            phase=f.phases.append,
            check_work=lambda: None,
            check_mutation=lambda: None,
            retain=retain,
        )
    assert len(retained) == 1 and retained[0][0] == "close_position"
    assert retained[0][2] == len(f.reads) and not f.exited


def test_finite_failure_evidence_contains_no_body_builder_account_or_arbitrary_text() -> None:
    events = event_trace()
    events[1]["text"] = "PRIVATE-SENTINEL"
    events[1]["forward"]["builder"] = {"b": WALLET, "f": 20}
    events[2]["reply"]["response"]["data"]["statuses"] = [{"error": "PRIVATE-SENTINEL"}]
    records = recovery.mutation_evidence(events, CONTEXT, STOP)
    body = json.dumps(records)
    assert "PRIVATE-SENTINEL" not in body and ACCOUNT not in body and WALLET not in body
    assert "builder" not in body and records[1]["acknowledgement"] == "venue-refused"
    assert records[0]["wires"][0]["orders"][0]["c"] == close_wire()["orders"][0]["c"]  # type: ignore[index]


def test_finite_evidence_retains_partial_fill_as_observation_never_completed_recovery() -> None:
    events = event_trace()
    events[2]["reply"]["response"]["data"]["statuses"][0]["filled"]["totalSz"] = "0.0001"
    records = recovery.mutation_evidence(events, CONTEXT, STOP)
    assert records[1]["filled_size"] == "0.0001" and records[1]["order_id"] == 18
    with pytest.raises(recovery.RecoveryError):
        recovery.audit_events(events, ACCOUNT, CONTEXT, STOP)


def test_final_full_scan_failure_leaves_guard_running_without_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    f = Fixture()

    def failed(*_: object) -> dict[str, object]:
        raise RuntimeError("PRIVATE-SENTINEL")

    monkeypatch.setattr(recovery, "flat_scan", failed)
    with pytest.raises(RuntimeError):
        f.run()
    assert f.started and not f.exited and len(f.mutations) == 2


def test_cancellation_unknown_never_repeats_or_grants_completion() -> None:
    f = Fixture()
    f.size = "0"
    f.unknown = True
    with pytest.raises(recovery.RecoveryError):
        f.run()
    assert f.mutations == [("cancel_order", {"coin": "BTC", "order_id": 17})]
    assert f.stop == STOP and not f.exited


def journal_file(tmp_path: Path, events: list[dict[str, Any]]) -> Path:
    path = tmp_path / "decisions.jsonl"
    previous = ""
    lines = []
    for event in events:
        body = json.dumps(event, separators=(",", ":"))
        checksum = hashlib.sha3_256((previous + body).encode()).hexdigest()
        lines.append(
            '{"check":'
            + json.dumps(checksum)
            + ',"prev":'
            + json.dumps(previous)
            + ',"event":'
            + body
            + "}\n"
        )
        previous = checksum
    path.write_text("".join(lines))
    path.chmod(0o600)
    return path


def test_actual_durable_chain_and_sync_refuse_corruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    owner = SimpleNamespace(home=tmp_path)
    events = event_trace()
    path = journal_file(tmp_path, events)
    assert recovery.durable_events(cast(Foreground, owner)) == events
    path.write_text(path.read_text().replace('"nonce":123', '"nonce":124'))
    with pytest.raises(recovery.RecoveryError):
        recovery.durable_events(cast(Foreground, owner))
    journal_file(tmp_path, events)

    def failed(_: int) -> None:
        raise OSError("PRIVATE-SENTINEL")

    monkeypatch.setattr(os, "fsync", failed)
    with pytest.raises(OSError):
        recovery.durable_events(cast(Foreground, owner))


def test_journal_guard_waits_for_complete_latest_sent_prefix_before_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    events = event_trace()
    owner = SimpleNamespace(alive=lambda: None)
    count = 0

    def durable(_: object) -> list[dict[str, Any]]:
        nonlocal count
        count += 1
        return events[:2] if count == 1 else events

    class Local:
        def request(self, _: str) -> object:
            return events

    monkeypatch.setattr(recovery, "OwnedLocalGuard", lambda _: Local())
    monkeypatch.setattr(recovery, "durable_events", durable)
    monkeypatch.setattr(time, "sleep", lambda _: None)
    guard = recovery.JournalGuard(cast(Foreground, owner), check_work=lambda: None)
    assert guard.request("/guard/events?since=0") == events and count == 2


def execute_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path, dict[str, Any]]:
    subjects = tmp_path / "subjects"
    subjects.mkdir(mode=0o700)
    identity: dict[str, Any] = {
        "diagnostic": True,
        "harness_commit": "d" * 40,
        "tag": TAG,
        "commit": SOURCE,
        "loader_channel": "staging",
    }
    (subjects / "input.json").write_text(json.dumps(identity))
    (subjects / "input.json").chmod(0o600)
    context = tmp_path / "context.json"
    context.write_text(json.dumps(asdict(CONTEXT)))
    context.chmod(0o600)
    tmp_path.chmod(0o700)
    for key, value in {
        "DIAGNOSTIC": "true",
        "INSTALL_MATRIX_PROFILE": "all",
        "INSTALL_MATRIX_TARGET": "operator-recovery",
        "INSTALL_MATRIX_SCENARIO": "fresh",
        "ACCOUNT": ACCOUNT,
        "API_WALLET": WALLET,
        "GITHUB_SHA": "d" * 40,
        "GITHUB_RUN_ID": "22",
        "GITHUB_RUN_ATTEMPT": "1",
        "RUNNER_NAME": "GitHub Actions 2",
        "WALLET_FRAME": "e" * 64,
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(recovery, "admit", lambda *_args, **_kwargs: None)
    run, job, now = metadata()
    job_now = {
        **job,
        "id": 23,
        "run_id": 22,
        "head_sha": "d" * 40,
        "name": "Operator-attributed C6 recovery (diagnostic only)",
        "status": "in_progress",
        "runner_name": "GitHub Actions 2",
        "started_at": now.isoformat(),
    }
    monkeypatch.setattr(
        recovery,
        "_api",
        lambda route: (
            {"total_count": 1, "jobs": [job_now]}
            if "/attempts/" in route
            else job
            if "/jobs/" in route
            else run
        ),
    )
    monkeypatch.setattr(recovery, "command", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(recovery, "signed_binary", lambda *_args, **_kwargs: ("f" * 64, "a" * 64))
    return subjects, context, tmp_path / "output", identity


@pytest.mark.parametrize(
    "field,value", [("diagnostic", False), ("harness_commit", SOURCE), ("commit", "e" * 40)]
)
def test_actual_execute_identity_refuses_before_key_pop_or_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    subjects, context, output, identity = execute_fixture(tmp_path, monkeypatch)
    identity[field] = value
    (subjects / "input.json").write_text(json.dumps(identity))
    monkeypatch.setattr(
        recovery, "_api", lambda _: pytest.fail("metadata transport before identity")
    )
    with pytest.raises(recovery.RecoveryError):
        recovery.execute(subjects, context, digest(asdict(CONTEXT)), output)
    assert os.environ["WALLET_FRAME"] == "e" * 64 and not output.exists()


@pytest.mark.parametrize("where", ["custody-persist", "before-process"])
def test_actual_execute_stalled_receipt_or_init_refuses_before_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    subjects, context, output, _ = execute_fixture(tmp_path, monkeypatch)
    clock = [100.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    fixture = Fixture()
    monkeypatch.setattr(recovery, "TestnetReads", lambda **_: fixture.read)
    persist = recovery._persist

    def stalled(path: Path, receipt: dict[str, object]) -> None:
        persist(path, receipt)
        if where == "custody-persist" and receipt.get("stage") == "custody":
            clock[0] += recovery.MAX_SECONDS

    monkeypatch.setattr(recovery, "_persist", stalled)

    class NoProcess:
        def __init__(self, *_: object, **kwargs: Any) -> None:
            assert where == "before-process"
            clock[0] += recovery.MAX_SECONDS
            kwargs["admit_start"]()
            pytest.fail("process custody after expired initialization")

    monkeypatch.setattr(recovery, "Foreground", NoProcess)
    with pytest.raises(recovery.RecoveryError):
        recovery.execute(subjects, context, digest(asdict(CONTEXT)), output)
    if where == "custody-persist":
        assert os.environ["WALLET_FRAME"] == "e" * 64
    assert json.loads((output / "receipt.json").read_text())["recovery_complete"] is False


@pytest.mark.parametrize("kind", ["protect", "flatten"])
def test_shipped_guard_7a69_autonomous_close_prefix_is_admitted(kind: str) -> None:
    events = event_trace(kind)
    events[1]["actions"][0]["orders"][0]["c"] = "0x7a69" + "e" * 28
    recovery.audit_events(events, ACCOUNT, CONTEXT, STOP)


@pytest.mark.parametrize("cloid", [None, "0x7a74" + "e" * 28, "0x7a68" + "e" * 28])
def test_missing_or_test_vector_close_identity_refuses(cloid: object) -> None:
    wire = close_wire()
    wire["orders"][0]["c"] = cloid
    with pytest.raises(recovery.RecoveryError):
        recovery._wire(wire, CONTEXT, STOP)


@pytest.mark.parametrize(
    "case",
    ["missing", "old", "autonomous", "other-client", "wrong-nonce", "wrong-operation", "multiple"],
)
def test_mutation_identity_never_claims_previous_or_autonomous_send(case: str) -> None:
    events = event_trace()
    events[1]["client"], events[1]["nonce"] = "paired", 123
    baseline, reply = 1, {"request_nonce": 123}
    if case == "missing":
        events = events[:1]
    if case == "old":
        baseline = 2
    if case == "autonomous":
        events[1]["kind"] = "protect"
    if case == "other-client":
        events[1]["client"] = "other"
    if case == "wrong-nonce":
        reply["request_nonce"] = 124
    if case == "wrong-operation":
        events[1]["request"] = {"type": "cancel", "cancels": [{"a": CONTEXT.asset, "o": 17}]}
    if case == "multiple":
        events.append({**events[1], "seq": 5})
    assert (
        recovery.mutation_identity(
            events,
            CONTEXT,
            STOP,
            baseline=baseline,
            client="paired",
            operation="close_position",
            reply=reply,
        )
        is None
    )


def test_current_paired_close_and_original_cancel_identity_is_finite() -> None:
    events = event_trace()
    events[1]["client"], events[1]["nonce"] = "paired", 123
    assert (
        recovery.mutation_identity(
            events,
            CONTEXT,
            STOP,
            baseline=1,
            client="paired",
            operation="close_position",
            reply={"request_nonce": 123},
        )
        == 2
    )
    events[1]["request"] = {"type": "cancel", "cancels": [{"a": CONTEXT.asset, "o": 17}]}
    assert (
        recovery.mutation_identity(
            events, CONTEXT, STOP, baseline=1, client="paired", operation="cancel_order", reply={}
        )
        == 2
    )


@pytest.mark.parametrize("phase", ["one-close", "original-stop-cancel"])
@pytest.mark.parametrize("boundary", ["owned-work", "final-reserve"])
def test_absolute_owned_window_and_reserved_full_scan_admit_every_mutation(
    monkeypatch: pytest.MonkeyPatch, phase: str, boundary: str
) -> None:
    f = Fixture()
    clock = [100.0]
    deadline, owned = 5000.0, 1000.0 if boundary == "owned-work" else 4000.0
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])

    def observe(label: str) -> None:
        f.phases.append(label)
        if label == phase:
            clock[0] = 970.0 if boundary == "owned-work" else 3200.0

    with pytest.raises(recovery.RecoveryError):
        recovery.recover(
            f.read,
            ACCOUNT,
            CONTEXT,
            start=f.start,
            phase=observe,
            check_work=lambda: recovery.need(clock[0] < deadline),
            check_mutation=lambda: recovery.mutation_budget(deadline, owned),
        )
    if phase == "one-close":
        assert not f.mutations
    else:
        assert len(f.mutations) == 1 and f.stop == STOP
    assert not f.exited


def test_atomic_receipt_directory_fsync_failure_refuses_before_any_custody(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import stat

    subjects, context, output, _ = execute_fixture(tmp_path, monkeypatch)
    sync = os.fsync

    def fail_directory(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("PRIVATE-SENTINEL")
        sync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_directory)
    monkeypatch.setattr(
        recovery,
        "Foreground",
        lambda *_args, **_kwargs: pytest.fail("custody after failed durable name"),
    )
    with pytest.raises(OSError):
        recovery.execute(subjects, context, digest(asdict(CONTEXT)), output)
    assert os.environ["WALLET_FRAME"] == "e" * 64
    assert json.loads((output / "receipt.json").read_text())["recovery_complete"] is False


def test_read_only_metadata_subprocess_never_inherits_wallet_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    monkeypatch.setenv("WALLET_FRAME", "PRIVATE-KEY-SENTINEL")

    def metadata(*args: object, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert "WALLET_FRAME" not in kwargs["env"] and "PRIVATE-KEY-SENTINEL" not in json.dumps(
            kwargs
        )
        return subprocess.CompletedProcess(["gh"], 0, b'{"id":1}', b"")

    monkeypatch.setattr(subprocess, "run", metadata)
    assert recovery._api("actions/runs/1") == {"id": 1}


def test_actual_shaped_testnet_btc_index_three_binds_every_order_and_cancel() -> None:
    f = Fixture()
    assert f.markets[0]["name"] == "SOL" and f.markets[3]["name"] == "BTC"
    result = f.run()
    assert result["recovery_complete"] is True and len(f.mutations) == 2
    recovery._wire(close_wire(), CONTEXT, STOP)
    recovery._wire({"type": "cancel", "cancels": [{"a": 3, "o": 17}]}, CONTEXT, STOP)
    wires: list[dict[str, Any]] = [close_wire(), {"type": "cancel", "cancels": [{"a": 0, "o": 17}]}]
    for wire in wires:
        if wire["type"] == "order":
            wire["orders"][0]["a"] = 0
        with pytest.raises(recovery.RecoveryError):
            recovery._wire(wire, CONTEXT, STOP)


@pytest.mark.parametrize("asset", [True, -1, 1000, "3", 3.0])
def test_context_asset_exact_integer_bounds_refuse(asset: object) -> None:
    context = {**asdict(CONTEXT), "asset": asset}
    with pytest.raises(recovery.RecoveryError):
        recovery.Context.parse(json.dumps(context), digest(context), ACCOUNT, WALLET)


@pytest.mark.parametrize(
    "case", ["wrong-asset", "duplicate", "moved", "delisted", "synthetic", "bad-precision"]
)
def test_btc_metadata_binding_refuses_before_custody(case: str) -> None:
    f = Fixture()
    context = CONTEXT
    if case == "wrong-asset":
        context = replace(CONTEXT, asset=0)
    if case == "duplicate":
        f.markets.append(copy.deepcopy(f.markets[3]))
    if case == "moved":
        f.markets[0], f.markets[3] = f.markets[3], f.markets[0]
    if case == "delisted":
        f.markets[3]["isDelisted"] = True
    if case == "synthetic":
        f.markets[3]["isSynthetic"] = True
    if case == "bad-precision":
        f.markets[3]["szDecimals"] = True
    with pytest.raises(recovery.RecoveryError):
        recovery.recover(
            f.read,
            ACCOUNT,
            context,
            start=f.start,
            phase=f.phases.append,
            check_work=lambda: None,
            check_mutation=lambda: None,
        )
    assert not f.started and not f.mutations


@pytest.mark.parametrize("case", ["moved", "duplicate", "precision", "delisted"])
def test_btc_binding_is_refreshed_after_full_scan_before_any_custody(case: str) -> None:
    f = Fixture()
    original = f.read
    calls = 0

    def read(payload: dict[str, Any]) -> object:
        nonlocal calls
        if payload["type"] == "meta":
            calls += 1
            if calls == 2:
                if case == "moved":
                    f.markets[0], f.markets[3] = f.markets[3], f.markets[0]
                if case == "duplicate":
                    f.markets.append(copy.deepcopy(f.markets[3]))
                if case == "precision":
                    f.markets[3]["szDecimals"] = 6
                if case == "delisted":
                    f.markets[3]["isDelisted"] = True
        return original(payload)

    with pytest.raises(recovery.RecoveryError):
        recovery.recover(
            read,
            ACCOUNT,
            CONTEXT,
            start=f.start,
            phase=f.phases.append,
            check_work=lambda: None,
            check_mutation=lambda: None,
        )
    assert calls == 2 and ("clearinghouseState", "synthetic") in f.reads
    assert not f.started and not f.mutations


def test_btc_moving_after_guard_starts_refuses_without_mutation() -> None:
    f = Fixture()

    def changed() -> None:
        f.markets[0], f.markets[3] = f.markets[3], f.markets[0]

    f.on_start = changed
    with pytest.raises(recovery.RecoveryError):
        f.run()
    assert f.started and not f.mutations and f.stop == STOP and not f.exited
