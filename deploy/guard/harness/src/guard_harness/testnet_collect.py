"""Fresh read-only testnet collection for the shared entry ownership reconciler."""

import json
import os
import re
from collections.abc import Callable, Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any

from guard_harness.testnet_exits import AccountingViewMismatch
from guard_harness.testnet_ownership import Ownership, reconcile_ownership
from guard_harness.testnet_protection import (
    Entry,
    ProtectionError,
    _need,
    _object,
    _orders,
    prove_stop,
)
from guard_harness.testnet_scan import Read, ScanError, amount, digest


class CollectionRace(ProtectionError):
    """Two complete read-only snapshots disagree; neither grants ownership."""


COLLECTION_PHASES = frozenset(
    {
        "admission",
        "account-mode",
        "markets",
        "entry-proof",
        "entry-status",
        "fills-first",
        "holdings-first",
        "stop-status",
        "exit-proof",
        "exit-status",
        "holdings-second",
        "stability",
        "reconcile",
        "owned-work",
        "unknown",
    }
)
COLLECTION_FAMILIES = frozenset(
    {
        "collection-race",
        "accounting-view",
        "protection",
        "scan",
        "timeout",
        "interrupted",
        "unknown",
    }
)
COLLECTION_STATUSES = frozenset({"open", "filled", "canceled", "reduceOnlyCanceled", "unknown"})


OWNED_SOURCES = {
    str((Path(__file__).resolve().parent / name).resolve()): name
    for name in (
        "testnet_collect.py",
        "testnet_ownership.py",
        "testnet_exits.py",
        "testnet_protection.py",
        "testnet_reconcile.py",
    )
}


def failure_origin(error: BaseException) -> list[dict[str, object]]:
    """Bounded source excerpt of the original failure, never a payload or authority."""
    trace = error.__traceback__
    frames: list[dict[str, object]] = []
    visited = 0
    while trace is not None:
        if visited == 128:
            return []
        visited += 1
        # Canonical source filenames are opaque identities; foreign/alias paths are skipped.
        name = OWNED_SOURCES.get(trace.tb_frame.f_code.co_filename)
        line = trace.tb_lineno
        if name is not None and type(line) is int and 1 <= line <= 2000:
            frames.append({"file": name, "line": line})
            frames = frames[-8:]
        trace = trace.tb_next
    return frames


def finite_origin(value: object) -> list[dict[str, object]]:
    """Revalidate the emitted excerpt, dropping malformed/unknown attribution entirely."""
    if type(value) is not list or len(value) > 8:
        return []
    result: list[dict[str, object]] = []
    for frame in value:
        if type(frame) is not dict or set(frame) != {"file", "line"}:
            return []
        name, line = frame["file"], frame["line"]
        if (
            type(name) is not str
            or name not in OWNED_SOURCES.values()
            or type(line) is not int
            or not 1 <= line <= 2000
        ):
            return []
        result.append({"file": name, "line": line})
    return result


def failure_family(error: BaseException) -> str:
    """Exact known exception types only; never retain arbitrary class names or messages."""
    return {
        CollectionRace: "collection-race",
        AccountingViewMismatch: "accounting-view",
        ProtectionError: "protection",
        ScanError: "scan",
        TimeoutError: "timeout",
        KeyboardInterrupt: "interrupted",
    }.get(type(error), "unknown")


def finite_failure(value: dict[str, object]) -> dict[str, object]:
    """Diagnostic projection only; no ownership or release authority."""

    def enum(name: str, allowed: frozenset[str]) -> str:
        item = value.get(name)
        return item if type(item) is str and item in allowed else "unknown"

    statuses = value.get("exit_statuses")
    attempt = value.get("attempt")
    return {
        "schema": 1,
        "diagnostic": True,
        "gate_eligible": False,
        "subphase": enum("subphase", COLLECTION_PHASES),
        "family": enum("family", COLLECTION_FAMILIES),
        "entry_status": enum("entry_status", COLLECTION_STATUSES),
        "stop_status": enum("stop_status", COLLECTION_STATUSES),
        "exit_statuses": [
            status if type(status) is str and status in COLLECTION_STATUSES else "unknown"
            for status in statuses
        ]
        if type(statuses) is list and len(statuses) <= 3
        else [],
        **{
            name: value.get(name) if type(value.get(name)) is bool else None
            for name in (
                "positions_empty",
                "orders_empty",
                "positions_equal",
                "orders_equal",
                "fills_equal",
                "net_vs_remaining",
                "settling_enabled",
            )
        },
        "attempt": attempt if type(attempt) is int and 1 <= attempt <= 3 else None,
        "source_frames": finite_origin(value.get("source_frames")),
    }


def retain_failure(work: Path, value: dict[str, object]) -> None:
    """Exclusive terminal diagnostic; caller suppresses recording failure, never a permit."""
    if not work.is_dir() or work.is_symlink() or work.stat().st_mode & 0o077:
        raise ValueError("private collection evidence directory required")
    body = json.dumps(finite_failure(value), allow_nan=False).encode() + b"\n"
    descriptor = os.open(
        work / "collection-failure.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(work, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def observed_status(value: dict[str, Any]) -> str:
    if type(value) is not dict:
        return "unknown"
    resolved = value.get("order")
    status = resolved.get("status") if type(resolved) is dict else None
    return status if type(status) is str and status in COLLECTION_STATUSES else "unknown"


def _holdings(
    read: Read, account: str, dex: str = ""
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    fields = {"user": account, **({"dex": dex} if dex else {})}
    state = _object(read({"type": "clearinghouseState", **fields}))
    positions = []
    for item in _orders(state.get("assetPositions")):
        position = _object(item.get("position"))
        _need(isinstance(position.get("coin"), str) and bool(position["coin"]))
        if amount(position.get("szi")) != 0:
            positions.append(position)
    orders = _orders(read({"type": "frontendOpenOrders", **fields}))
    return positions, orders


def _fills(read: Read, account: str, started_ms: int) -> list[dict[str, Any]]:
    fills = _orders(read({"type": "userFillsByTime", "user": account, "startTime": started_ms}))
    # Refuse at the general time-range pagination boundary (500), conservatively below the
    # fill endpoint's 2000 maximum. A small exclusive run cannot need that many executions.
    # https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint
    _need(len(fills) < 500)
    return fills


def collect_ownership(
    read: Read,
    account: str,
    events: Sequence[dict[str, Any]],
    client: str,
    entry: Entry,
    *,
    started_ms: int,
    cleanup: bool = False,
    observe_failure: Callable[[dict[str, object]], None] = lambda _: None,
) -> Ownership:
    """Collect twice-bound main-DEX fills/exposure; no whole-account flat credit.

    Run serialization and prior exclusive all-DEX flat preflight remain controller duties.
    Readbacks cannot form an atomic venue snapshot. Racing main fills/orders refuse,
    and the controller must recollect before each mutation. Cleanup accounts for owned exits.
    """
    facts: dict[str, object] = {"subphase": "admission"}
    try:
        _need(bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", account)))
        _need(type(started_ms) is int and started_ms > 0)
        facts["subphase"] = "account-mode"
        _need(read({"type": "userAbstraction", "user": account}) == "disabled")
        facts["subphase"] = "markets"
        markets = _orders(_object(read({"type": "meta"})).get("universe"))
        facts["subphase"] = "entry-proof"
        proof = prove_stop(
            events, client, entry, markets=markets, filled=Decimal(0), mark=entry.limit
        )
        facts["subphase"] = "entry-status"
        lookup = _object(read({"type": "orderStatus", "user": account, "oid": proof.entry_cloid}))
        facts["entry_status"] = observed_status(lookup)
        facts["subphase"] = "fills-first"
        fills = _fills(read, account, started_ms)
        facts["subphase"] = "holdings-first"
        positions, orders = _holdings(read, account)
        # First complete holdings snapshot only; never current/account-wide flat proof.
        facts.update(positions_empty=not positions, orders_empty=not orders)
        stop_lookup = None
        if fills or positions or any(order.get("cloid") == proof.cloid for order in orders):
            facts["subphase"] = "stop-status"
            stop_lookup = _object(
                read({"type": "orderStatus", "user": account, "oid": proof.cloid})
            )
            facts["stop_status"] = observed_status(stop_lookup)
        exit_lookups: dict[str, dict[str, Any]] = {}
        if cleanup and fills:
            facts["subphase"] = "exit-proof"
            for event in events:
                if (
                    event.get("kind") != "decision"
                    or str(event.get("client", "")).lower() != client.lower()
                ):
                    continue
                request = _object(event.get("request"))
                if request.get("type") != "order":
                    continue
                wires = _orders(request.get("orders"))
                if not any(wire.get("r") is True for wire in wires):
                    continue
                _need(len(wires) == 1)
                cloid = wires[0].get("c")
                if not isinstance(cloid, str) or not re.fullmatch(r"0x7a6d[0-9a-f]{28}", cloid):
                    raise ProtectionError("durable close cloid required")
                _need(cloid != proof.entry_cloid and cloid not in exit_lookups)
                _need(len(exit_lookups) < 3)
                facts["subphase"] = "exit-status"
                exit_lookups[cloid] = _object(
                    read({"type": "orderStatus", "user": account, "oid": cloid})
                )
                facts["exit_statuses"] = [observed_status(item) for item in exit_lookups.values()]
        facts["subphase"] = "holdings-second"
        after_positions, after_orders = _holdings(read, account)
        facts["subphase"] = "stability"

        def equal(name: str, condition: bool) -> bool:
            facts[name] = condition
            return condition

        # Marks/equity can change between reads without an execution; compare accounting exposure.
        if (
            not equal(
                "positions_equal",
                [(p["coin"], amount(p["szi"])) for p in positions]
                == [(p["coin"], amount(p["szi"])) for p in after_positions],
            )
            or not equal("orders_equal", digest(orders) == digest(after_orders))
            or not equal("fills_equal", digest(fills) == digest(_fills(read, account, started_ms)))
        ):
            raise CollectionRace("owned read-only snapshots changed")
        facts["subphase"] = "reconcile"
        return reconcile_ownership(
            events,
            client,
            entry,
            markets=markets,
            entry_lookup=lookup,
            fills=fills,
            positions=after_positions,
            orders=after_orders,
            stop_lookup=stop_lookup,
            started_ms=started_ms,
            cleanup=cleanup,
            exit_lookups=exit_lookups if cleanup and fills else None,
            observe_net=lambda matched: facts.update(net_vs_remaining=matched),
        )
    except (Exception, KeyboardInterrupt) as error:
        facts["family"] = failure_family(error)
        try:
            facts["source_frames"] = failure_origin(error)
        except (Exception, KeyboardInterrupt):
            facts["source_frames"] = []
        try:
            observe_failure(finite_failure(facts))
        except (Exception, KeyboardInterrupt):
            pass  # Diagnostic failure never masks the exact original exception.
        raise
