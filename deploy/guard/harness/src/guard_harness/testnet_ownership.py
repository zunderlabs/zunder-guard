"""Combine fresh readbacks into immutable run-owned exposure observations for T1/T2."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from guard_harness.testnet_exits import AccountingViewMismatch, Exit, owned_balance, prove_exits
from guard_harness.testnet_protection import (
    Entry,
    StopProof,
    _need,
    _object,
    _positive,
    prove_stop,
)
from guard_harness.testnet_reconcile import _oid, open_stop, owned_quantity, protected_ack


@dataclass(frozen=True)
class Ownership:
    entry_oid: int
    stop_oid: int | None
    filled: Decimal
    remaining: Decimal
    resting_entry: bool


def _entry_order(order: dict[str, Any], proof: StopProof, entry: Entry) -> int:
    _need(order.get("cloid") == proof.entry_cloid and order.get("coin") == "BTC")
    _need(order.get("side") == "B" and order.get("reduceOnly") is False)
    _need(order.get("isTrigger") is False and order.get("orderType") == "Limit")
    _need(_positive(order.get("limitPx")) == entry.limit)
    # Historical filled orderStatus may report remaining sz=0; origSz binds the wire.
    _need(_positive(order.get("origSz")) == proof.size)
    return _oid(order.get("oid"))


def _cleanup_stop(
    events: Sequence[dict[str, Any]],
    proof: StopProof,
    entry_oid: int,
    stop_lookup: dict[str, Any],
    exits: Mapping[int, Exit],
    orders: Sequence[dict[str, Any]],
    *,
    entry_status: object,
    needs_stop: bool,
) -> int | None:
    """The same pure protection checks gate valid cleanup and failed accounting views."""
    _need(entry_status in {"filled", "canceled"})
    historical = _object(_object(stop_lookup.get("order")).get("order"))
    acknowledged_stop = _oid(historical.get("oid"))
    _need(acknowledged_stop in exits)
    protected_ack(events, proof, entry_oid, acknowledged_stop, cleanup=True)
    if needs_stop:
        stop_oid = open_stop(orders, stop_lookup, proof)
        _need(all(type(order.get("oid")) is int and order["oid"] == stop_oid for order in orders))
        return stop_oid
    _need(
        _object(stop_lookup.get("order")).get("status")
        in {"filled", "canceled", "reduceOnlyCanceled"}
    )
    return None


def reconcile_ownership(
    events: Sequence[dict[str, Any]],
    client: str,
    entry: Entry,
    *,
    markets: Sequence[dict[str, Any]],
    entry_lookup: dict[str, Any],
    fills: Sequence[dict[str, Any]],
    positions: Sequence[dict[str, Any]],
    orders: Sequence[dict[str, Any]],
    stop_lookup: dict[str, Any] | None,
    started_ms: int,
    cleanup: bool = False,
    exit_lookups: Mapping[str, dict[str, Any]] | None = None,
    observe_net: Callable[[bool], None] = lambda _: None,
) -> Ownership:
    """Refuse unrelated orders and ambiguous entry ownership before any cleanup action.

    Inputs must be freshly collected from the fixed testnet account after exclusive all-DEX
    flat preflight. This observation is not a reusable mutation permit: the controller must
    recollect before each cancel/close and independently scan all DEXes at the end. No keys,
    venue calls or cleanup mutations occur here. A partial fill earns cleanup observation only.
    """
    _need(type(started_ms) is int and started_ms > 0)
    mark = entry.limit
    if positions:
        _need(len(positions) == 1)
        _need(_object(positions[0].get("leverage")).get("type") == "isolated")
        if not cleanup:
            mark = _positive(positions[0].get("positionValue")) / _positive(positions[0].get("szi"))
    proof = prove_stop(events, client, entry, markets=markets, filled=Decimal(0), mark=mark)
    _need(entry_lookup.get("status") == "order")
    resolved = _object(entry_lookup.get("order"))
    candidate = _object(resolved.get("order"))
    entry_oid = _entry_order(candidate, proof, entry)
    stamp = candidate.get("timestamp")
    _need(type(stamp) is int and stamp >= started_ms)
    if not fills:
        _need(cleanup and not positions and resolved.get("status") in {"open", "canceled"})
        resting = resolved["status"] == "open"
        if resting:
            _need(len(orders) == 1 and _entry_order(orders[0], proof, entry) == entry_oid)
            _need(_positive(candidate.get("sz")) == proof.size)
            _need(_positive(orders[0].get("sz")) == proof.size)
        else:
            _need(not orders and _positive(candidate.get("sz")) == proof.size)
        protected_ack(events, proof, entry_oid, None, cleanup=True, resting_only=True)
        return Ownership(entry_oid, None, Decimal(0), Decimal(0), resting)
    if cleanup and exit_lookups is not None:
        stop_lookup = _object(stop_lookup)
        lookups = dict(exit_lookups)
        _need(proof.cloid not in lookups)
        lookups[proof.cloid] = stop_lookup
        exits = prove_exits(
            events,
            client,
            proof,
            entry,
            lookups,
            started_ms=started_ms,
            allow_closed_stop=not positions and not orders,
        )
        try:
            quantity, remaining = owned_balance(
                positions,
                fills,
                entry_oid,
                entry,
                exits,
                started_ms=started_ms,
                observe_net=observe_net,
            )
        except AccountingViewMismatch:
            # A failed net view cannot hide foreign orders, invalid acknowledgements or
            # missing protection. Retain the same typed object only after these proofs.
            _cleanup_stop(
                events,
                proof,
                entry_oid,
                stop_lookup,
                exits,
                orders,
                entry_status=resolved.get("status"),
                needs_stop=bool(positions or orders),
            )
            raise
        _need(quantity > 0)
        stop_oid = _cleanup_stop(
            events,
            proof,
            entry_oid,
            stop_lookup,
            exits,
            orders,
            entry_status=resolved.get("status"),
            needs_stop=bool(remaining or orders),
        )
        return Ownership(entry_oid, stop_oid, quantity, remaining, False)
    # Ordinary journey success still requires the complete entry and its live stop.
    for fill in fills:
        _need(type(fill.get("oid")) is int and fill["oid"] == entry_oid)
        stamp = fill.get("time")
        _need(type(stamp) is int and stamp >= started_ms)
    _need(resolved.get("status") in {"filled", "canceled"})
    quantity = owned_quantity(positions, fills, entry_oid, entry)
    _need(quantity <= proof.size and (cleanup or quantity == proof.size))
    remaining = _positive(positions[0].get("szi")) if positions else Decimal(0)
    _need(remaining == quantity)
    _need(stop_lookup is not None)
    stop_oid = open_stop(orders, _object(stop_lookup), proof)
    protected_ack(events, proof, entry_oid, stop_oid, cleanup=cleanup)
    _need(all(type(order.get("oid")) is int and order["oid"] == stop_oid for order in orders))
    return Ownership(entry_oid, stop_oid, quantity, remaining, False)
