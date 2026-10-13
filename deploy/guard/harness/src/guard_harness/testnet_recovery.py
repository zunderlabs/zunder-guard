"""Operator-attributed C6 recovery only; never grants formal journey or release credit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from guard_harness.c6_owner import admit
from guard_harness.mcp_client import MCP
from guard_harness.native_release import diagnostic_mode
from guard_harness.runner import run as command
from guard_harness.staged_subjects import _private
from guard_harness.testnet_process import Foreground, OwnedLocalGuard
from guard_harness.testnet_protection import _object, _orders, _positive
from guard_harness.testnet_run import ROOT, signed_binary
from guard_harness.testnet_scan import (
    SCAN_TIMEOUT,
    Read,
    TestnetReads,
    amount,
    digest,
    flat_scan,
    inventory,
)

REPOSITORY = "zunderlabs/zunder-guard"
MAX_SECONDS = 7200
OUTSIDE_RESERVE = SCAN_TIMEOUT + 90


class RecoveryError(RuntimeError):
    """Fixed failure: preserve protection and reconcile, never repeat a mutation."""


def need(value: bool) -> None:
    if not value:
        raise RecoveryError("operator recovery refused; preserve protection and reconcile")


def _json(body: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            need(key not in result)
            result[key] = value
        return result

    value = json.loads(body, object_pairs_hook=unique)
    need(type(value) is dict)
    return dict(value)


@dataclass(frozen=True)
class Context:
    account_sha256: str
    api_wallet_sha256: str
    expected_size: str
    stop_oid: int
    stop_wire_sha256: str
    prior_run: int
    prior_job: int
    prior_attempt: int
    prior_commit: str
    prior_tag: str
    asset: int

    @property
    def quantity(self) -> Decimal:
        return amount(self.expected_size)

    @classmethod
    def parse(cls, body: str, checksum: str, account: str, wallet: str) -> Context:
        need(len(body.encode()) <= 4096 and bool(re.fullmatch(r"[0-9a-f]{64}", checksum)))
        value = _json(body)
        need(set(value) == set(cls.__dataclass_fields__) and digest(value) == checksum)
        need(type(value["asset"]) is int and 0 <= value["asset"] < 1000)
        need(
            all(
                type(value[name]) is int and 0 < value[name] < 2**63
                for name in ("stop_oid", "prior_run", "prior_job", "prior_attempt")
            )
        )
        need(
            all(
                type(value[name]) is str and bool(re.fullmatch(r"[0-9a-f]{64}", value[name]))
                for name in ("account_sha256", "api_wallet_sha256", "stop_wire_sha256")
            )
        )
        need(
            type(value["prior_commit"]) is str
            and bool(re.fullmatch(r"[0-9a-f]{40}", value["prior_commit"]))
        )
        need(
            type(value["prior_tag"]) is str
            and bool(re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", value["prior_tag"]))
        )
        need(
            type(value["expected_size"]) is str
            and bool(re.fullmatch(r"0\.[0-9]{1,6}", value["expected_size"]))
        )
        need(
            all(bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", address)) for address in (account, wallet))
        )
        need(account.lower() != wallet.lower())
        need(value["account_sha256"] == hashlib.sha256(account.lower().encode()).hexdigest())
        need(value["api_wallet_sha256"] == hashlib.sha256(wallet.lower().encode()).hexdigest())
        result = cls(**value)
        need(result.quantity > 0)
        return result


def prior_teardown(
    context: Context, run: dict[str, Any], job: dict[str, Any], *, current_start: datetime
) -> None:
    """Admit provider-hosted completed T1 metadata, not an invented Guard-exit receipt."""
    need(current_start.tzinfo is not None)
    for name in ("repository", "head_repository"):
        need(_object(run.get(name)).get("full_name") == REPOSITORY)
    need(run.get("id") == context.prior_run and run.get("run_attempt") == context.prior_attempt)
    need(
        run.get("head_sha") == context.prior_commit and run.get("head_branch") == context.prior_tag
    )
    need(
        run.get("path") == ".github/workflows/verify.yml"
        and run.get("event") == "workflow_dispatch"
    )
    need(run.get("status") == "completed" and run.get("conclusion") in {"failure", "cancelled"})
    need(job.get("id") == context.prior_job and job.get("run_id") == context.prior_run)
    need(
        job.get("run_attempt") == context.prior_attempt
        and job.get("head_sha") == context.prior_commit
    )
    need(job.get("name") in {"T1", "Released trading and purchase journeys / T1"})
    need(job.get("status") == "completed" and job.get("conclusion") in {"failure", "cancelled"})
    need(job.get("labels") == ["ubuntu-24.04"] and job.get("runner_group_name") == "GitHub Actions")
    need(type(job.get("runner_name")) is str and job["runner_name"].startswith("GitHub Actions "))
    completed = job.get("completed_at")
    need(type(completed) is str)
    assert isinstance(completed, str)
    finished = datetime.fromisoformat(completed.replace("Z", "+00:00"))
    need(finished.tzinfo is not None and finished < current_start)


@dataclass(frozen=True)
class Exposure:
    quantity: Decimal
    stop: dict[str, Any] | None


def main_exposure(read: Read, account: str, context: Context) -> Exposure:
    """Only exact isolated BTC long and the original whole-wire stop; absence may be flat."""
    state = _object(read({"type": "clearinghouseState", "user": account}))
    orders = _orders(read({"type": "frontendOpenOrders", "user": account}))
    need(amount(_object(state.get("marginSummary")).get("accountValue")) >= Decimal("200"))
    positions = []
    for item in _orders(state.get("assetPositions")):
        position = _object(item.get("position"))
        size = amount(position.get("szi"))
        need(type(position.get("coin")) is str and bool(position["coin"]))
        if size:
            positions.append(position)
    need(len(positions) <= 1 and len(orders) <= 1)
    size = Decimal(0)
    if positions:
        position = positions[0]
        size = amount(position["szi"])
        need(position.get("coin") == "BTC" and size == context.quantity and size > 0)
        need(_object(position.get("leverage")).get("type") == "isolated")
        need(0 < _positive(position.get("positionValue")) <= Decimal("40"))
    stop = orders[0] if orders else None
    if stop is not None:
        need(type(stop.get("oid")) is int and stop["oid"] == context.stop_oid)
        need(digest(stop) == context.stop_wire_sha256)
        need(stop.get("coin") == "BTC" and stop.get("side") == "A")
        need(stop.get("reduceOnly") is True and stop.get("isTrigger") is True)
        need(
            stop.get("orderType") == "Stop Market" and _positive(stop.get("sz")) == context.quantity
        )
        need(_positive(stop.get("triggerPx")) > _positive(stop.get("limitPx")))
        need(
            type(stop.get("cloid")) is str
            and bool(re.fullmatch(r"0x7a67[0-9a-f]{28}", stop["cloid"]))
        )
    need(not size or stop is not None)
    return Exposure(size, stop)


def btc_precision(read: Read, context: Context) -> int:
    """Bind the explicit main-DEX asset to one active BTC, never an assumed index."""
    need(type(context.asset) is int and 0 <= context.asset < 1000)
    markets = _orders(_object(read({"type": "meta"})).get("universe"))
    matches = [index for index, market in enumerate(markets) if market.get("name") == "BTC"]
    need(matches == [context.asset])
    market = markets[context.asset]
    need(market.get("isDelisted", False) is False and market.get("isSynthetic", False) is False)
    precision = market.get("szDecimals")
    need(type(precision) is int and 0 <= precision <= 6)
    assert isinstance(precision, int)
    need(context.quantity == context.quantity.quantize(Decimal(1).scaleb(-precision)))
    return precision


def preflight(read: Read, account: str, context: Context) -> Exposure:
    need(read({"type": "userAbstraction", "user": account}) == "disabled")
    precision = btc_precision(read, context)
    before = read({"type": "perpDexs"})
    dexes = inventory(before)
    first = main_exposure(read, account, context)
    for dex in dexes[1:]:
        fields = {"user": account, "dex": dex}
        state = _object(read({"type": "clearinghouseState", **fields}))
        need(not _orders(read({"type": "frontendOpenOrders", **fields})))
        for item in _orders(state.get("assetPositions")):
            need(amount(_object(item.get("position")).get("szi")) == 0)
        amount(_object(state.get("marginSummary")).get("accountValue"))
    last = main_exposure(read, account, context)
    need(first == last and btc_precision(read, context) == precision)
    need(inventory(read({"type": "perpDexs"})) == dexes)
    return last


def _wire(value: object, context: Context, original: dict[str, Any] | None) -> dict[str, Any]:
    """Every possible send is a main BTC reduction or the original stop/cancel."""
    wire = _object(value)
    if wire.get("type") == "cancel":
        need(set(wire) == {"type", "cancels"})
        cancels = _orders(wire.get("cancels"))
        need(len(cancels) == 1)
        cancel = cancels[0]
        need(set(cancel) == {"a", "o"})
        need(type(cancel.get("a")) is int and cancel["a"] == context.asset)
        need(type(cancel.get("o")) is int and cancel["o"] == context.stop_oid)
        return wire
    need(wire.get("type") == "order")
    need({"type", "orders", "grouping"} <= set(wire) <= {"type", "orders", "grouping", "builder"})
    need(wire.get("grouping") == "na")
    orders = _orders(wire.get("orders"))
    need(len(orders) == 1)
    order = orders[0]
    need({"a", "b", "p", "s", "r", "t"} <= set(order) <= {"a", "b", "p", "s", "r", "t", "c"})
    need(type(order.get("a")) is int and order["a"] == context.asset)
    need(order.get("r") is True and order.get("b") is False)
    size, price = _positive(order.get("s")), _positive(order.get("p"))
    need(0 < size <= context.quantity and size * price <= Decimal("40"))
    order_type = _object(order.get("t"))
    if "trigger" in order_type:
        need(original is not None)
        assert original is not None
        need(set(order_type) == {"trigger"} and order.get("c") == original.get("cloid"))
        trigger = _object(order_type["trigger"])
        need(set(trigger) == {"isMarket", "tpsl", "triggerPx"})
        need(trigger.get("isMarket") is True and trigger.get("tpsl") == "sl")
        need(trigger.get("triggerPx") == original["triggerPx"])
        need(price == amount(original.get("limitPx")) and size == context.quantity)
    else:
        need(order_type == {"limit": {"tif": "Ioc"}})
        need(
            type(order.get("c")) is str
            and bool(re.fullmatch(r"0x7a(?:6d|69)[0-9a-f]{28}", order["c"]))
        )
    return wire


def _ack(reply: object, wire: dict[str, Any], context: Context) -> None:
    """Top-level Sent.ok alone does not prove successful venue statuses."""
    value = _object(reply)
    need(value.get("status") == "ok")
    response = _object(value.get("response"))
    need(response.get("type") == wire["type"])
    statuses = _object(response.get("data")).get("statuses")
    need(type(statuses) is list and len(statuses) == 1)
    assert isinstance(statuses, list)
    if wire["type"] == "cancel":
        need(statuses == ["success"])
        return
    order = wire["orders"][0]
    status = _object(statuses[0])
    if "trigger" in order["t"]:
        need(set(status) == {"resting"})
        resting = _object(status["resting"])
        need(type(resting.get("oid")) is int and resting["oid"] == context.stop_oid)
    else:
        need(set(status) == {"filled"})
        filled = _object(status["filled"])
        need(type(filled.get("oid")) is int and filled["oid"] > 0)
        need(_positive(filled.get("totalSz")) == amount(order["s"]))
        need(0 < _positive(filled.get("avgPx")) * amount(order["s"]) <= Decimal("40"))


def audit_events(
    events: object, account: str, context: Context, original: dict[str, Any] | None
) -> None:
    """Validate every named/actual wire and successful acknowledgement; no pending sends."""
    values = _orders(events)
    need(bool(values) and values[0].get("kind") == "started")
    need(type(values[0].get("account")) is str)
    need(values[0]["account"].lower() == account.lower() and values[0].get("mode") == "testnet")
    need(all(type(event.get("seq")) is int for event in values))
    need([event.get("seq") for event in values] == list(range(1, len(values) + 1)))
    intents: dict[int, list[dict[str, Any]]] = {}
    answered: set[tuple[int, int]] = set()
    finished: set[int] = set()
    for event in values[1:]:
        seq, kind = event["seq"], event.get("kind")
        if kind == "decision":
            need(event.get("verdict") in {"allow", "resize"})
            _wire(event.get("request"), context, original)
            pre, post = _orders(event.get("pre")), _orders(event.get("post"))
            wires = [*pre, _object(event.get("forward")), *post]
            intents[seq] = [_wire(wire, context, original) for wire in wires]
        elif kind in {"protect", "flatten"}:
            need(event.get("sent") is True and event.get("problems") == [])
            if kind == "protect":
                need(
                    type(event.get("coins")) is list
                    and all(coin == "BTC" for coin in event["coins"])
                )
            intents[seq] = [
                _wire(wire, context, original) for wire in _orders(event.get("actions"))
            ]
        elif kind == "intent":
            of = event.get("of")
            need(type(of) is int and of in intents)
            intents[seq] = [_wire(event.get("action"), context, original)]
        elif kind in {"sent", "recovered"}:
            intent = event.get("decision" if kind == "sent" else "intent")
            index = event.get("index")
            need(type(intent) is int and intent in intents and intent not in finished)
            assert isinstance(intent, int)
            need(type(index) is int and 0 <= index < len(intents[intent]))
            assert isinstance(index, int)
            need((intent, index) not in answered)
            named = intents[intent][index]
            wire = _wire(event.get("action", named), context, original)
            # Only the producer's fee-field removal can differ from the named action.
            need(
                wire == named
                or (
                    "builder" in named
                    and wire == {k: v for k, v in named.items() if k != "builder"}
                )
            )
            if kind == "sent":
                need(event.get("ok") is True)
                need(type(event.get("nonce")) is int and event["nonce"] > 0)
                _ack(event.get("reply"), wire, context)
            else:
                need(event.get("outcome") == "happened")
                # Empty fresh home cannot contain historical recovery; refuse even happened.
                need(False)
            answered.add((intent, index))
        elif kind == "done":
            intent = event.get("intent")
            need(type(intent) is int and intent in intents and intent not in finished)
            assert isinstance(intent, int)
            finished.add(intent)
        elif kind == "fee_approval":
            need(event.get("approved") is True)
        elif kind == "risk":
            need(event.get("state") == "active" and event.get("journal_error") is None)
            need(type(event.get("discrepancies")) is int and event["discrepancies"] == 0)
            need(type(event.get("open_positions")) is int and 0 <= event["open_positions"] <= 1)
        else:
            need(False)
    need(
        all(
            seq in finished or all((seq, index) in answered for index in range(len(wires)))
            for seq, wires in intents.items()
        )
    )


def mutation_evidence(
    events: object, context: Context, original: dict[str, Any] | None
) -> list[dict[str, object]]:
    """Finite diagnostic observations only; unknown replies never earn acknowledgement credit."""
    values = _orders(events)
    need(0 < len(values) <= 4096)
    need(all(type(event.get("seq")) is int and event["seq"] > 0 for event in values))
    records: list[dict[str, object]] = []
    for event in values:
        kind = event.get("kind")
        if kind not in {"decision", "intent", "sent", "protect", "flatten", "recovered", "done"}:
            continue
        record: dict[str, object] = {"kind": kind, "seq": event["seq"]}
        if kind == "decision":
            wires = [
                *_orders(event.get("pre")),
                _object(event.get("forward")),
                *_orders(event.get("post")),
            ]
            _wire(event.get("request"), context, original)
        elif kind in {"protect", "flatten"}:
            wires = _orders(event.get("actions"))
        else:
            wires = [event["action"]] if "action" in event else []
        record["wires"] = [
            {k: v for k, v in _wire(wire, context, original).items() if k != "builder"}
            for wire in wires
        ]
        for reference in ("of", "decision", "intent", "index", "nonce"):
            if reference in event:
                value = event[reference]
                need(type(value) is int and 0 <= value < 2**63)
                record[reference] = value
        if kind == "sent":
            record["acknowledgement"] = "unknown"
            reply = event.get("reply")
            if type(reply) is dict:
                response = reply.get("response")
                data = response.get("data") if type(response) is dict else None
                statuses = data.get("statuses") if type(data) is dict else None
                if type(statuses) is list and len(statuses) == 1:
                    status = statuses[0]
                    if status == "success":
                        record["acknowledgement"] = "cancel-success"
                    elif type(status) is dict and set(status) == {"filled"}:
                        filled = _object(status["filled"])
                        need(type(filled.get("oid")) is int and 0 < filled["oid"] < 2**63)
                        size = _positive(filled.get("totalSz"))
                        need(0 < size <= context.quantity)
                        record.update(
                            acknowledgement="filled", order_id=filled["oid"], filled_size=str(size)
                        )
                    elif type(status) is dict and set(status) == {"resting"}:
                        oid = _object(status["resting"]).get("oid")
                        need(type(oid) is int and 0 < oid < 2**63)
                        record.update(acknowledgement="resting", order_id=oid)
                    elif type(status) is dict and "error" in status:
                        record["acknowledgement"] = "venue-refused"
        if kind == "recovered":
            outcome = event.get("outcome")
            record["outcome"] = (
                outcome if outcome in ("happened", "did_not_happen", "unknown") else "unknown"
            )
        records.append(record)
    return records


def mutation_identity(
    events: list[dict[str, Any]],
    context: Context,
    original: dict[str, Any] | None,
    *,
    baseline: int,
    client: str,
    operation: str,
    reply: object,
) -> int | None:
    """Only a new paired-client decision identifies this one attempt, never an autonomous send."""
    matching = [
        event
        for event in events
        if type(event.get("seq")) is int
        and event["seq"] > baseline
        and event.get("kind") == "decision"
        and event.get("client") == client
    ]
    if type(reply) is dict and type(reply.get("request_nonce")) is int:
        matching = [event for event in matching if event.get("nonce") == reply["request_nonce"]]
    if len(matching) != 1:
        return None
    wire = _wire(matching[0].get("request"), context, original)
    expected_type = "order" if operation == "close_position" else "cancel"
    need(operation in {"close_position", "cancel_order"})
    if wire["type"] != expected_type:
        return None
    if expected_type == "order" and (
        amount(wire["orders"][0]["s"]) != context.quantity
        or wire["orders"][0]["t"] != {"limit": {"tif": "Ioc"}}
    ):
        return None
    return int(matching[0]["seq"])


def mutation_budget(deadline: float, owned_deadline: float | None) -> None:
    """Reserve one bounded MCP call and the whole final scan/exit outside owned work."""
    need(owned_deadline is not None)
    assert owned_deadline is not None
    now = time.monotonic()
    need(now + 45 < owned_deadline and deadline - now > SCAN_TIMEOUT + 75)


def recover(
    read: Read,
    account: str,
    context: Context,
    *,
    start: Callable[[], tuple[Any, Any, Callable[[], None]]],
    phase: Callable[[str], None] = lambda _: None,
    check_work: Callable[[], None],
    check_mutation: Callable[[], None],
    retain: Callable[[str, object, bool, object, dict[str, Any] | None, int], None] = lambda *_: (
        None
    ),
) -> dict[str, object]:
    """One exact close only. Any partial/unknown/refused action preserves protection.

    Caller authenticates release/caller/old-hosted teardown before this pre-custody scan.
    A new Guard may act autonomously, so read its journal and fresh exact state before writes.
    No journal ownership is fabricated and this operator observation never earns gate credit.
    """

    def checked_phase(label: str) -> None:
        check_work()
        phase(label)
        check_work()  # Durable receipt writes may stall; recheck after they return.

    result: dict[str, object] = {
        "operator_attributed": True,
        "attribution_basis": "operator_exclusive_actor_inference",
        "gate_eligible": False,
        "recovery_complete": False,
        "close_attempted": False,
        "cancel_attempted": False,
        "new_guard_started": False,
        "new_guard_exit_confirmed": False,
    }
    checked_phase("preflight")
    before = preflight(read, account, context)
    if not before.quantity and before.stop is None:
        checked_phase("final-scan")
        result["scan"] = flat_scan(read, account)
        check_work()
        result["recovery_complete"] = True
        return result
    check_work()
    guard, tools, stop = start()
    check_work()
    result["new_guard_started"] = True

    def fresh() -> Exposure:
        check_work()
        btc_precision(read, context)
        audit_events(guard.request("/guard/events?since=0"), account, context, before.stop)
        status = _object(guard.request("/guard/status"))
        need(status.get("mode") == status.get("network") == "testnet")
        need(status.get("account", "").lower() == account.lower())
        need(status.get("version") == context.prior_tag[1:])
        need(all(name in status for name in ("last_error", "killed", "journal_broken")))
        need(_object(status.get("capabilities")).get("exchange_expected_mode") is True)
        need(_object(status.get("risk")).get("state") == "active")
        need(_object(status.get("risk")).get("journal_ready") is True)
        need(status.get("last_error") is None and status.get("killed") is None)
        need(status.get("journal_broken") is False)
        exposure = main_exposure(read, account, context)
        check_work()
        return exposure

    def mutate(name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        prefix = _orders(guard.request("/guard/events?since=0"))
        audit_events(prefix, account, context, before.stop)
        baseline = prefix[-1]["seq"]
        reply: dict[str, Any] = {}
        error = True
        try:
            check_mutation()
            reply, error = tools.tool(name, arguments)
            return reply, error
        finally:
            # Capture even unknown/exception outcomes before any paced venue read.
            retain(name, reply, error, guard, before.stop, baseline)
            check_work()

    checked_phase("fresh-close-proof")
    current = fresh()
    need(tools.writes_bound is True and tools.close_size_bound is True)
    if current.quantity:
        checked_phase("one-close")
        need(fresh() == current)
        check_work()
        check_mutation()
        result["close_attempted"] = True
        reply, error = mutate(
            "close_position", {"coin": "BTC", "expected_size": context.expected_size}
        )
        need(
            not error
            and reply.get("sent") is True
            and reply.get("ok") is True
            and reply.get("outcome") == "sent"
        )
        checked_phase("post-close-proof")
        current = fresh()  # Partial closes refuse here; there is never a second close.
        need(current.quantity == 0)
    if current.stop is not None:
        checked_phase("fresh-orphan-proof")
        current = fresh()
        need(current.quantity == 0)
        if current.stop is not None:
            checked_phase("original-stop-cancel")
            need(fresh() == current)
            check_work()
            check_mutation()
            result["cancel_attempted"] = True
            reply, error = mutate("cancel_order", {"coin": "BTC", "order_id": context.stop_oid})
            need(
                not error
                and reply.get("sent") is True
                and reply.get("ok") is True
                and reply.get("outcome") == "sent"
            )
            current = fresh()
            need(current.quantity == 0 and current.stop is None)
    checked_phase("final-scan")
    result["scan"] = flat_scan(read, account)
    audit_events(guard.request("/guard/events?since=0"), account, context, before.stop)
    checked_phase("guard-exit")
    check_work()
    stop()
    check_work()
    result["new_guard_exit_confirmed"] = True
    result["recovery_complete"] = True
    return result


def _api(route: str) -> dict[str, Any]:
    """Canonical read-only Actions metadata; stdout and transport errors remain private."""
    response = subprocess.run(
        ["gh", "api", f"repos/{REPOSITORY}/{route}"],
        capture_output=True,
        check=True,
        timeout=30,
        env={
            name: os.environ[name]
            for name in ("PATH", "HOME", "GH_TOKEN", "GITHUB_TOKEN")
            if name in os.environ
        },
    )
    need(0 < len(response.stdout) <= 2_000_000)
    return _json(response.stdout.decode())


def current_job(pages: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    jobs = _orders(pages.get("jobs"))
    need(type(pages.get("total_count")) is int and pages["total_count"] == len(jobs) <= 100)
    found = [
        job
        for job in jobs
        if job.get("runner_name") == env.get("RUNNER_NAME") and job.get("status") == "in_progress"
    ]
    need(len(found) == 1)
    job = found[0]
    need(job.get("name") == "Operator-attributed C6 recovery (diagnostic only)")
    need(job.get("run_id") == int(env["GITHUB_RUN_ID"]))
    need(job.get("run_attempt") == int(env["GITHUB_RUN_ATTEMPT"]))
    need(job.get("head_sha") == env["GITHUB_SHA"])
    need(job.get("labels") == ["ubuntu-24.04"] and job.get("runner_group_name") == "GitHub Actions")
    return job


def _persist(work: Path, receipt: dict[str, object]) -> None:
    with (work / "receipt.pending").open("w") as stream:
        (work / "receipt.pending").chmod(0o600)
        json.dump(receipt, stream, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    (work / "receipt.pending").replace(work / "receipt.json")
    descriptor = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)  # The durable attempt/evidence name must survive a crash too.
    finally:
        os.close(descriptor)


def durable_events(owner: Foreground) -> list[dict[str, Any]]:
    """Read the complete authenticated Guard's on-disk chain, never its truncated window."""
    path = owner.home / "decisions.jsonl"
    _private(path)
    need(0 < path.stat().st_size <= 16 * 1024 * 1024)
    with path.open("rb") as stream:
        body = stream.read().rstrip(b"\0")
        os.fsync(stream.fileno())  # Commit the complete observed prefix before retaining evidence.
    need(bool(body) and body.endswith(b"\n"))
    previous = ""
    events = []
    for line in body.decode().splitlines():
        record = _json(line)
        match = re.search(r'"event"\s*:\s*', line)
        need(match is not None)
        assert match is not None
        event, end = json.JSONDecoder().raw_decode(line, match.end())
        check = hashlib.sha3_256((previous + line[match.end() : end]).encode()).hexdigest()
        need(record.get("prev") == previous and record.get("check") == check)
        need(type(event) is dict)
        events.append(event)
        previous = check
    return events


class JournalGuard:
    def __init__(self, owner: Foreground, *, check_work: Callable[[], None]) -> None:
        self.owner, self.local = owner, OwnedLocalGuard(owner)
        self.check_work = check_work

    def request(self, path: str) -> object:
        if path != "/guard/events?since=0":
            return self.local.request(path)
        until = time.monotonic() + 3
        while True:
            self.check_work()
            self.owner.alive()
            memory = _orders(self.local.request(path))
            need(bool(memory))
            try:
                events = durable_events(self.owner)
                same = len(events) >= len(memory) and events[-len(memory) :] == memory
            except RecoveryError:
                same = False
            after = _orders(self.local.request(path))
            self.check_work()
            self.owner.alive()
            if same and after == memory:
                return events
            need(time.monotonic() < until)
            time.sleep(0.05)  # Read-only durability wait, never a send/cleanup retry.


def execute(subjects: Path, context_file: Path, context_hash: str, output: Path) -> None:
    """Admit reviewed standalone ownership, released bytes and prior teardown before custody."""
    names = {
        "PATH",
        "HOME",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "RUNNER_NAME",
        "WORKFLOW_REF",
        "WORKFLOW_SHA",
        "CALLER_SHA",
        "CALLER_REF",
        "CALLER_REPOSITORY",
        "CALLER_EVENT",
        "DIAGNOSTIC",
        "INSTALL_MATRIX_PROFILE",
        "INSTALL_MATRIX_TARGET",
        "INSTALL_MATRIX_SCENARIO",
        "ACCOUNT",
        "API_WALLET",
    }
    env = {name: os.environ[name] for name in names if name in os.environ}
    need(diagnostic_mode() is True)
    need(env.get("INSTALL_MATRIX_PROFILE") == "all")
    need(env.get("INSTALL_MATRIX_TARGET") == "operator-recovery")
    need(env.get("INSTALL_MATRIX_SCENARIO") == "fresh")
    admit(env, callee="install-matrix.yml", profile="all")
    _private(context_file)
    need(0 < context_file.stat().st_size <= 4096)
    account, wallet = env.get("ACCOUNT", ""), env.get("API_WALLET", "")
    context = Context.parse(context_file.read_text(), context_hash, account, wallet)
    _private(subjects / "input.json")
    identity = _json((subjects / "input.json").read_text())
    need(
        identity.get("diagnostic") is True
        and identity.get("harness_commit") == env.get("GITHUB_SHA")
    )
    need(
        identity.get("tag") == context.prior_tag and identity.get("commit") == context.prior_commit
    )
    need(identity.get("loader_channel") == "staging")
    pages = _api(
        f"actions/runs/{int(env['GITHUB_RUN_ID'])}/attempts/{int(env['GITHUB_RUN_ATTEMPT'])}/jobs?per_page=100"
    )
    job = current_job(pages, env)
    start = datetime.fromisoformat(job["started_at"].replace("Z", "+00:00"))
    elapsed = (datetime.now(UTC) - start).total_seconds()
    need(0 <= elapsed < MAX_SECONDS - OUTSIDE_RESERVE - 2 * SCAN_TIMEOUT - 900)
    deadline = time.monotonic() + MAX_SECONDS - OUTSIDE_RESERVE - elapsed
    prior_teardown(
        context,
        _api(f"actions/runs/{context.prior_run}"),
        _api(f"actions/jobs/{context.prior_job}"),
        current_start=start,
    )
    _private(output.parent, directory=True)
    need(output.is_absolute() and not output.exists() and not output.is_symlink())
    output.mkdir(mode=0o700)
    receipt: dict[str, object] = {
        "operator_attributed": True,
        "attribution_basis": "operator_exclusive_actor_inference",
        "gate_eligible": False,
        "recovery_complete": False,
        "prior_hosted_teardown_admitted": True,
        "context_sha256": context_hash,
        "harness_commit": env["GITHUB_SHA"],
        "released_commit": context.prior_commit,
        "close_attempted": False,
        "cancel_attempted": False,
        "stage": "authenticate",
    }
    _persist(output, receipt)
    tools: MCP | None = None
    try:
        auth_env = {
            name: env[name] for name in ("PATH", "HOME", "GH_TOKEN", "GITHUB_TOKEN") if name in env
        }
        auth_env["GITHUB_REPOSITORY"] = REPOSITORY
        command(
            [
                "bash",
                str(ROOT / "github/verify-release-assets.sh"),
                context.prior_tag,
                str(output / "assets"),
            ],
            env=auth_env,
            timeout=600,
            log=output / "authenticate.log",
            stdin=b"",
            secrets=[auth_env.get("GH_TOKEN", ""), auth_env.get("GITHUB_TOKEN", "")],
        )
        checksum, manifest = signed_binary(
            output / "assets",
            output / "subject",
            tag=context.prior_tag,
            commit=context.prior_commit,
        )
        receipt.update(binary_sha256=checksum, manifest_sha256=manifest)
        reads = TestnetReads(timeout=SCAN_TIMEOUT)

        owned_deadline: float | None = None

        def check_work() -> None:
            need(time.monotonic() < deadline)

        def check_mutation() -> None:
            mutation_budget(deadline, owned_deadline)

        def admit_custody() -> None:
            need(deadline - time.monotonic() > SCAN_TIMEOUT + 900)

        def phase(label: str) -> None:
            need(
                label
                in {
                    "preflight",
                    "custody",
                    "fresh-close-proof",
                    "one-close",
                    "post-close-proof",
                    "fresh-orphan-proof",
                    "original-stop-cancel",
                    "final-scan",
                    "guard-exit",
                }
            )
            receipt["stage"] = label
            if label == "one-close":
                receipt["close_attempted"] = True
            if label == "original-stop-cancel":
                receipt["cancel_attempted"] = True
            if label == "final-scan":
                need(deadline - time.monotonic() > SCAN_TIMEOUT + 30)
                reads.start_phase(timeout=SCAN_TIMEOUT)
            need(deadline > time.monotonic())
            _persist(output, receipt)  # Attempt boundary is durable before either mutation.
            check_work()

        def start_guard() -> tuple[Any, Any, Callable[[], None]]:
            nonlocal tools, owned_deadline
            phase("custody")
            admit_custody()
            owned_deadline = min(time.monotonic() + 900, deadline - SCAN_TIMEOUT - 30)
            key = os.environ.pop("WALLET_FRAME", "")
            need(bool(re.fullmatch(r"(?:0x)?[0-9a-fA-F]{64}", key)))
            descriptor, writer = os.pipe()
            try:
                os.write(writer, (key + "\n").encode())
            finally:
                os.close(writer)
                del key

            def admit_start() -> None:
                admit_custody()
                need(owned_deadline is not None)
                assert owned_deadline is not None
                # Initialization belongs to the same 900s work window; readiness/reads remain.
                need(time.monotonic() + 750 < owned_deadline)

            with os.fdopen(descriptor, "rb") as stream:
                owner = Foreground(
                    output / "subject",
                    sha256=checksum,
                    work=output / "runtime",
                    account=account,
                    api_wallet=wallet,
                    port=18549,
                    key_stdin=stream,
                    admit_start=admit_start,
                )
            receipt["new_guard_started"] = True
            owner.wait_ready()
            reads.start_phase(timeout=600)
            tools = MCP(
                owner.binary,
                sha256=checksum,
                home=owner.home,
                client_key=owner.client_key,
                url=owner.url,
                log=output / "mcp.log",
            )
            return JournalGuard(owner, check_work=check_work), tools, owner.stop_after_flat

        def retain(
            name: str,
            reply: object,
            error: bool,
            guard: object,
            original: dict[str, Any] | None,
            baseline: int,
        ) -> None:
            outcome = reply.get("outcome") if type(reply) is dict else None
            finite = (
                outcome
                if outcome
                in (
                    "sent",
                    "unknown",
                    "venue_refused",
                    "partly_refused",
                    "vetoed_by_guard",
                    "refused_or_unknown",
                    "paper_mode_not_sent",
                )
                else "unknown"
            )
            evidence: dict[str, object] = {
                "operator_attributed": True,
                "attribution_basis": "operator_exclusive_actor_inference",
                "gate_eligible": False,
                "context_sha256": context_hash,
                "account_sha256": context.account_sha256,
                "api_wallet_sha256": context.api_wallet_sha256,
                "harness_commit": env["GITHUB_SHA"],
                "released_commit": context.prior_commit,
                "run": int(env["GITHUB_RUN_ID"]),
                "attempt": int(env["GITHUB_RUN_ATTEMPT"]),
                "operation": name,
                "outcome": finite,
                "tool_error": error is not False,
                "evidence_unavailable": True,
                "mutation_identity_available": False,
                "before_seq": baseline,
            }
            available = False
            try:
                assert isinstance(guard, JournalGuard)
                events = _orders(guard.request("/guard/events?since=0"))
                evidence["events"] = mutation_evidence(events, context, original)
                mutation_seq = mutation_identity(
                    events,
                    context,
                    original,
                    baseline=baseline,
                    client=guard.owner.pair.address,
                    operation=name,
                    reply=reply,
                )
                available = mutation_seq is not None
                if available:
                    evidence["mutation_seq"] = mutation_seq
                evidence["mutation_identity_available"] = available
                evidence["evidence_unavailable"] = not available
            finally:
                # Atomic private receipt history; only strictly authored finite fields uploaded.
                history = receipt.setdefault("mutation_evidence", [])
                need(type(history) is list and len(history) < 2)
                assert isinstance(history, list)
                history.append(evidence)
                _persist(output, receipt)
            need(available)
            check_work()

        receipt.update(
            recover(
                reads,
                account,
                context,
                start=start_guard,
                phase=phase,
                check_work=check_work,
                check_mutation=check_mutation,
                retain=retain,
            )
        )
        receipt["stage"] = "complete"
    finally:
        if tools is not None:
            tools.stop()  # Never terminates Guard or withdraws protection on failure.
        _persist(output, receipt)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subjects", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--context-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        execute(args.subjects, args.context, args.context_sha256, args.output)
        print("Operator recovery complete; diagnostic only, no gate credit")
        return 0
    except (Exception, KeyboardInterrupt):
        print(
            "Operator recovery incomplete; preserve protection and reconcile; never retry",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
