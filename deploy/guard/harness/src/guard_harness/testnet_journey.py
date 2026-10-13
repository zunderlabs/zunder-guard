"""Shared T1/T2 execution on an already authenticated, exclusively owned testnet Guard."""

import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from guard_harness.mcp_client import MCP
from guard_harness.paper_bot import LocalGuard
from guard_harness.testnet_cleanup import Cleaned, cleanup
from guard_harness.testnet_collect import collect_ownership
from guard_harness.testnet_ownership import Ownership
from guard_harness.testnet_protection import (
    Entry,
    ProtectionError,
    _need,
    _object,
    _orders,
    _positive,
    price_grid,
)
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


JOURNEY_PHASES = frozenset(
    {
        "guard-readiness",
        "mcp-initialize",
        "guard-status",
        "flat-scan",
        "entry-plan",
        "preview-response",
        "preview-identity",
        "preview-verdict",
        "preview-sizing",
        "preview-age",
        "preview-stop-quote",
        "preview-stop-price",
        "preview-price-bound",
        "entry-budget",
        "entry-attempt",
    }
)


def admit_preview(
    result: dict[str, Any],
    entry: Entry,
    *,
    observe_phase: Callable[[str], None] = lambda _: None,
) -> None:
    """Admit the unchanged planned entry with Guard's measured default stop."""
    observe_phase("preview-identity")
    _need(result.get("ok") is True and result.get("coin") == "BTC" and result.get("side") == "buy")
    preview = _object(result.get("preview"))
    observe_phase("preview-verdict")
    _need(
        preview.get("source") == "guard"
        and (preview.get("verdict"), preview.get("code"))
        in {("allow", "allowed"), ("resize", "resized")}
        and preview.get("size_cut") is False
        and preview.get("stop_source") == "guard_policy"
        and preview.get("time_in_force") == "ioc"
    )
    observe_phase("preview-sizing")
    _need(
        _positive(preview.get("requested_size")) == entry.size
        and _positive(preview.get("allowed_size")) == entry.size
        and _positive(preview.get("order_price")) == entry.limit
        and _positive(preview.get("worst_price")) == entry.limit
    )
    observe_phase("preview-age")
    age = preview.get("view_age_ms")
    _need(type(age) is int and 0 <= age <= 60000)
    observe_phase("preview-stop-quote")
    changes = preview.get("changes_quoted")
    if not isinstance(changes, list) or not all(isinstance(change, str) for change in changes):
        raise ProtectionError("preview protection changes required")
    references = [
        match
        for change in changes
        if (
            match := re.fullmatch(
                r"a reduce-only stop at ([0-9]+(?:\.[0-9]+)?) "
                r"\(2% from ([0-9]+(?:\.[0-9]+)?)\) is attached",
                change,
            )
        )
    ]
    _need(len(references) == 1)
    quoted_stop, reference = (_positive(value) for value in references[0].groups())
    observe_phase("preview-stop-price")
    stop = _positive(preview.get("stop_price"))
    _need(stop == quoted_stop == price_grid(reference * Decimal("0.98"), entry.precision, up=True))
    observe_phase("preview-price-bound")
    _need(
        stop < reference <= entry.limit
        and entry.limit <= price_grid(reference * Decimal("1.005"), entry.precision, up=False)
    )


def execute(
    guard: LocalGuard,
    mcp: MCP,
    read: Read,
    *,
    account: str,
    client: str,
    entry: Entry | Callable[[], Entry],
    version: str,
    process_started_ms: int,
    stop_guard: Callable[[], None],
    admit_entry: Callable[[], None] = lambda: None,
    begin_cleanup: Callable[[], None] = lambda: None,
    begin_final_scan: Callable[[], None] = lambda: None,
    check_owned_work: Callable[[], None] = lambda: None,
    record_attempt: Callable[[Entry, int], None] = lambda *_: None,
    persist_ownership: Callable[[list[dict[str, Any]], Entry, int], None] = lambda *_: None,
    capture_entry: Callable[[Ownership, int, int], None] = lambda *_: None,
    observe_phase: Callable[[str], None] = lambda _: None,
    now_ms: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
) -> Journey:
    """One entry attempt, actual protection readback, owned cleanup and independent scan.

    Caller must hold account serialization and authenticate Guard process/binary, MCP bytes,
    fresh paired client, and T1 owned process or T2 owned service. This core never initializes
    a wallet, reads its key or starts a service. Pre-entry failures send nothing. Once an entry
    is attempted, cleanup always runs; failed cleanup preserves the Guard and its protection.
    An exception message or response body never enters the returned diagnostic.
    """
    if isinstance(entry, Entry):
        entry.validate()
    observe_phase("guard-status")
    _need(mcp.writes_bound and mcp.close_size_bound and mcp.limit_price_ioc)
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
    observe_phase("flat-scan")
    flat_scan(read, account)  # C6 floor and every DEX, before any entry attempt.
    observe_phase("entry-plan")
    # Production planning reads fresh market data after the long mandatory scan.
    # Fixed explicit Entry values remain available for independent offline fixtures.
    if callable(entry):
        entry = entry()
    _need(isinstance(entry, Entry))
    entry.validate()
    observe_phase("preview-response")
    preview, error = mcp.tool(
        "preview_order",
        {
            "coin": "BTC",
            "side": "buy",
            "stop": "guard_policy",
            "size": str(entry.size),
            "limit_price": str(entry.limit),
            "time_in_force": "ioc",
        },
    )
    _need(not error)
    admit_preview(preview, entry, observe_phase=observe_phase)
    observe_phase("entry-budget")
    admit_entry()  # Reserve cleanup time after the potentially long preflight.
    begun = now_ms()
    _need(type(begun) is int and begun > 0)

    record_attempt(entry, begun)  # Exclusive fsync before the single attempted send.
    check_owned_work()  # Persistence cannot spend the reserve and still authorize a send.

    def observe(*, cleaning: bool) -> Ownership:
        check_owned_work()
        events = _orders(guard.request(f"/guard/events?since={baseline}"))
        _need(all(type(event.get("seq")) is int and event["seq"] > baseline for event in events))
        check_owned_work()
        # Preserve validated run ownership before expensive venue collection, including
        # the unknown-entry-response branch. Missing evidence still refuses mutation.
        persist_ownership(events, entry, begun)
        check_owned_work()
        observed = collect_ownership(
            read, account, events, client, entry, started_ms=begun, cleanup=cleaning
        )
        check_owned_work()
        return observed

    protected, cleaned, failure, stopped = None, None, None, False
    try:
        # Set the attempt boundary before transmission: timeout can mean the order arrived.
        observe_phase("entry-attempt")
        check_owned_work()  # Also recheck after the final receipt hook, immediately before send.
        result, error = mcp.tool(
            "place_order",
            {
                "coin": "BTC",
                "side": "buy",
                "stop": "guard_policy",
                "size": str(entry.size),
                "limit_price": str(entry.limit),
                "time_in_force": "ioc",
            },
        )
        check_owned_work()
        _need(not error and result.get("sent") is True)
        protected = observe(cleaning=False)
        capture_entry(protected, begun, now_ms())
        check_owned_work()
    except (Exception, KeyboardInterrupt):
        failure = "entry_or_protection"
    finally:
        try:
            begin_cleanup()  # Owned cleanup shares the absolute entry-work deadline.

            def final_scan() -> dict[str, object]:
                begin_final_scan()
                return flat_scan(read, account)

            cleaned = cleanup(
                lambda: observe(cleaning=True),
                mcp,
                final_scan,
                check_work=check_owned_work,
                timeout=1280,
            )
        except (Exception, KeyboardInterrupt):
            failure = "cleanup_incomplete_keep_guard_running"
        if cleaned is not None:
            try:
                stop_guard()
                stopped = True
            except (Exception, KeyboardInterrupt):
                failure = "guard_stop_unconfirmed"
    return Journey(protected, cleaned, failure, stopped)
