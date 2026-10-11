"""Read-only fill, acknowledgement and open-stop reconciliation for T1/T2."""

from collections.abc import Sequence
from decimal import Decimal
from typing import Any

from guard_harness.testnet_protection import (
    Entry,
    ProtectionError,
    StopProof,
    _need,
    _object,
    _orders,
    _positive,
    validate_stop_order,
)


def _oid(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ProtectionError("positive exact venue OID required")
    return value


def owned_quantity(
    positions: Sequence[dict[str, Any]],
    fills: Sequence[dict[str, Any]],
    entry_oid: int,
    entry: Entry,
) -> Decimal:
    """Sum unique actual buy fills; refuse unrelated exposure before any broad close."""
    entry.validate()
    _oid(entry_oid)
    matches = [fill for fill in fills if type(fill.get("oid")) is int and fill["oid"] == entry_oid]
    _need(bool(matches))
    trades: set[int] = set()
    quantity, cost = Decimal(0), Decimal(0)
    for fill in matches:
        _need(fill.get("coin") == "BTC" and fill.get("side") == "B")
        trade = fill.get("tid")
        if type(trade) is not int or trade < 0 or trade in trades:
            raise ProtectionError("unique integer owned fill trade ID required")
        trades.add(trade)
        size, price = _positive(fill.get("sz")), _positive(fill.get("px"))
        _need(price <= entry.limit)
        quantity += size
        cost += size * price
    _need(quantity <= entry.size and cost <= Decimal("40"))
    _need(len(positions) <= 1)
    for position in positions:
        _need(position.get("coin") == "BTC")
        _need(_positive(position.get("szi")) <= quantity)
    return quantity


def order_statuses(events: Sequence[dict[str, Any]], decision: int) -> list[Any]:
    """Require one successful order reply linked to an exact durable decision."""
    _oid(decision)
    sequences = [event.get("seq") for event in events]
    _need(all(type(seq) is int and seq > 0 for seq in sequences))
    _need(len(sequences) == len(set(sequences)))
    serving = {decision} | {
        event["seq"]
        for event in events
        if event.get("kind") == "intent"
        and type(event.get("of")) is int
        and event.get("of") == decision
    }
    sent = []
    for event in events:
        if (
            event.get("kind") == "sent"
            and type(event.get("decision")) is int
            and event.get("decision") in serving
        ):
            reply = _object(event.get("reply"))
            if _object(reply.get("response")).get("type") == "order":
                sent.append(event)
    _need(len(sent) == 1 and sent[0].get("ok") is True)
    reply = _object(sent[0].get("reply"))
    _need(reply.get("status") == "ok")
    statuses = _object(_object(reply.get("response")).get("data")).get("statuses")
    if not isinstance(statuses, list):
        raise ProtectionError("order statuses required")
    return statuses


def protected_ack(
    events: Sequence[dict[str, Any]],
    proof: StopProof,
    entry_oid: int,
    stop_oid: int | None,
    *,
    cleanup: bool = False,
    resting_only: bool = False,
) -> None:
    """Bind exactly one successful two-status reply, including deferred stop acknowledgements."""
    _oid(entry_oid)
    if stop_oid is not None:
        _oid(stop_oid)
        _need(stop_oid != entry_oid)
    decisions = [event for event in events if event.get("seq") == proof.decision]
    _need(len(decisions) == 1 and decisions[0].get("kind") == "decision")
    orders = _orders(_object(decisions[0].get("request")).get("orders"))
    _need(len(orders) == 1)
    _need(_object(orders[0]).get("c") == proof.entry_cloid)
    statuses = order_statuses(events, proof.decision)
    if len(statuses) != 2:
        raise ProtectionError("exact two-status protected acknowledgement required")
    first = _object(statuses[0])
    _need(set(first) == {"filled"} or cleanup and set(first) == {"resting"})
    _need(not resting_only or cleanup and set(first) == {"resting"})
    entry = _object(first.get("filled", first.get("resting")))
    _need(_oid(entry.get("oid")) == entry_oid)
    _need("cloid" not in entry or entry["cloid"] == proof.entry_cloid)
    stop = statuses[1]
    deferred = stop == "waitingForTrigger" or cleanup and stop == "waitingForFill"
    if not deferred:
        resting = _object(stop)
        _need(set(resting) == {"resting"} and stop_oid is not None)
        acknowledged = _object(resting["resting"])
        _need(_oid(acknowledged.get("oid")) == stop_oid)
        _need("cloid" not in acknowledged or acknowledged["cloid"] == proof.cloid)


def open_stop(orders: Sequence[dict[str, Any]], lookup: dict[str, Any], proof: StopProof) -> int:
    """Cross-check fresh frontend and cloid lookup against immutable durable stop fields."""
    matches = [order for order in orders if order.get("cloid") == proof.cloid]
    _need(len(matches) == 1)
    oid = validate_stop_order(matches[0], proof)
    _need(lookup.get("status") == "order")
    resolved = _object(lookup.get("order"))
    _need(resolved.get("status") == "open")
    _need(validate_stop_order(_object(resolved.get("order")), proof) == oid)
    return oid
