"""Fresh read-only testnet collection for the shared entry ownership reconciler."""

import re
from collections.abc import Sequence
from decimal import Decimal
from typing import Any

from guard_harness.testnet_ownership import Ownership, reconcile_ownership
from guard_harness.testnet_protection import (
    Entry,
    ProtectionError,
    _need,
    _object,
    _orders,
    prove_stop,
)
from guard_harness.testnet_scan import Read, amount, digest


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
) -> Ownership:
    """Collect twice-bound main-DEX fills/exposure; no whole-account flat credit.

    Run serialization and prior exclusive all-DEX flat preflight remain controller duties.
    Readbacks cannot form an atomic venue snapshot. Racing main fills/orders refuse,
    and the controller must recollect before each mutation. Cleanup accounts for owned exits.
    """
    _need(bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", account)))
    _need(type(started_ms) is int and started_ms > 0)
    _need(read({"type": "userAbstraction", "user": account}) == "disabled")
    markets = _orders(_object(read({"type": "meta"})).get("universe"))
    proof = prove_stop(events, client, entry, markets=markets, filled=Decimal(0), mark=entry.limit)
    lookup = _object(read({"type": "orderStatus", "user": account, "oid": proof.entry_cloid}))
    fills = _fills(read, account, started_ms)
    positions, orders = _holdings(read, account)
    stop_lookup = None
    if fills or positions or any(order.get("cloid") == proof.cloid for order in orders):
        stop_lookup = _object(read({"type": "orderStatus", "user": account, "oid": proof.cloid}))
    exit_lookups: dict[str, dict[str, Any]] = {}
    if cleanup and fills:
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
            exit_lookups[cloid] = _object(
                read({"type": "orderStatus", "user": account, "oid": cloid})
            )
    after_positions, after_orders = _holdings(read, account)
    # Marks/equity can change between reads without an execution; compare accounting exposure.
    _need(
        [(p["coin"], amount(p["szi"])) for p in positions]
        == [(p["coin"], amount(p["szi"])) for p in after_positions]
    )
    _need(digest(orders) == digest(after_orders))
    _need(digest(fills) == digest(_fills(read, account, started_ms)))
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
    )
