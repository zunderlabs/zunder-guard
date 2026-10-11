"""Shared T1/T2 execution on an already authenticated, exclusively owned testnet Guard."""

import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from guard_harness.mcp_client import MCP
from guard_harness.paper_bot import LocalGuard
from guard_harness.testnet_cleanup import Cleaned, cleanup
from guard_harness.testnet_collect import collect_ownership
from guard_harness.testnet_ownership import Ownership
from guard_harness.testnet_protection import Entry, _need, _object, _orders
from guard_harness.testnet_reconcile import _oid
from guard_harness.testnet_scan import Read, flat_scan


@dataclass(frozen=True)
class Journey:
    protected_entry: Ownership | None
    cleaned: Cleaned | None
    failure: str | None
    guard_stopped: bool

    @property
    def passed(self) -> bool:
        return (
            self.failure is None
            and self.protected_entry is not None
            and self.cleaned is not None
            and self.guard_stopped
        )


def execute(
    guard: LocalGuard,
    mcp: MCP,
    read: Read,
    *,
    account: str,
    client: str,
    entry: Entry,
    version: str,
    process_started_ms: int,
    stop_guard: Callable[[], None],
    admit_entry: Callable[[], None] = lambda: None,
    begin_cleanup: Callable[[], None] = lambda: None,
    capture_entry: Callable[[Ownership, int, int], None] = lambda *_: None,
    now_ms: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
) -> Journey:
    """One entry attempt, actual protection readback, owned cleanup and independent scan.

    Caller must hold account serialization and authenticate Guard process/binary, MCP bytes,
    fresh paired client, and T1 owned process or T2 owned service. This core never initializes
    a wallet, reads its key or starts a service. Pre-entry failures send nothing. Once an entry
    is attempted, cleanup always runs; failed cleanup preserves the Guard and its protection.
    An exception message or response body never enters the returned diagnostic.
    """
    entry.validate()
    _need(mcp.writes_bound and mcp.close_size_bound)
    _need(type(process_started_ms) is int and process_started_ms > 0)
    status = _object(guard.request("/guard/status"))
    _need(status.get("mode") == "testnet" and status.get("network") == "testnet")
    _need(status.get("account", "").lower() == account.lower() and status.get("version") == version)
    _need(_object(status.get("capabilities")).get("exchange_expected_mode") is True)
    _need(_object(status.get("risk")).get("state") == "active")
    _need(_object(status.get("risk")).get("journal_ready") is True)
    _need(status.get("killed") is None and status.get("journal_broken") is False)
    _need(status.get("last_error") is None)
    fee = _object(status.get("fee"))
    if fee.get("mode") != "off":
        approval = _object(fee.get("approval"))
        maximum = approval.get("max_tenths_bp")
        _need(
            fee.get("mode") == "builder"
            and isinstance(fee.get("address"), str)
            and re.fullmatch(r"0x[0-9a-fA-F]{40}", fee["address"]) is not None
            and type(fee.get("fee_tenths_bp")) is int
            and fee["fee_tenths_bp"] == 20
            and fee.get("charged") is True
            and fee.get("paper") is False
            and fee.get("entries_blocked") is False
            and approval.get("state") == "approved"
            and type(maximum) is int
            and maximum >= 20
            and approval.get("error") is None
        )
    started, synced = _oid(status.get("started_at_ms")), _oid(status.get("last_sync_ms"))
    current = now_ms()
    _need(process_started_ms <= started <= synced <= current and current - synced <= 60000)
    initial = _orders(guard.request("/guard/events?since=0"))
    sequences = [_oid(event.get("seq")) for event in initial]
    _need(len(sequences) == len(set(sequences)))
    baseline = max(sequences, default=0)
    flat_scan(read, account)  # C6 floor and every DEX, before any entry attempt.
    preview, error = mcp.tool(
        "preview_order",
        {
            "coin": "BTC",
            "side": "buy",
            "stop": "guard_policy",
            "size": str(entry.size),
            "limit_price": str(entry.limit),
        },
    )
    _need(not error and _object(preview.get("preview")).get("verdict") == "allow")
    admit_entry()  # Reserve cleanup time after the potentially long preflight.
    begun = now_ms()
    _need(type(begun) is int and begun > 0)

    def observe(*, cleaning: bool) -> Ownership:
        events = _orders(guard.request(f"/guard/events?since={baseline}"))
        _need(all(type(event.get("seq")) is int and event["seq"] > baseline for event in events))
        return collect_ownership(
            read, account, events, client, entry, started_ms=begun, cleanup=cleaning
        )

    protected, cleaned, failure, stopped = None, None, None, False
    try:
        # Set the attempt boundary before transmission: timeout can mean the order arrived.
        result, error = mcp.tool(
            "place_order",
            {
                "coin": "BTC",
                "side": "buy",
                "stop": "guard_policy",
                "size": str(entry.size),
                "limit_price": str(entry.limit),
            },
        )
        _need(not error and result.get("sent") is True)
        protected = observe(cleaning=False)
        capture_entry(protected, begun, now_ms())
    except (Exception, KeyboardInterrupt):
        failure = "entry_or_protection"
    finally:
        try:
            begin_cleanup()  # Cleanup must not inherit an exhausted preflight window.
            cleaned = cleanup(lambda: observe(cleaning=True), mcp, lambda: flat_scan(read, account))
        except (Exception, KeyboardInterrupt):
            failure = "cleanup_incomplete_keep_guard_running"
        if cleaned is not None:
            try:
                stop_guard()
                stopped = True
            except (Exception, KeyboardInterrupt):
                failure = "guard_stop_unconfirmed"
    return Journey(protected, cleaned, failure, stopped)
