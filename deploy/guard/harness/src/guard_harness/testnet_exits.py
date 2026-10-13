"""Authenticate durable reduce-only exit identities and account for all run fills."""

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
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
from guard_harness.testnet_reconcile import _oid, order_statuses, owned_quantity
from guard_harness.testnet_scan import amount


class AccountingViewMismatch(ProtectionError):
    """Fully checked owned fills and isolated holdings disagree; grants no ownership."""


# Public compiled Testnet recipient for this default-fee E2E scope. Alternate
# licensed builders require a separately bound proof; syntax alone grants none.
TESTNET_BUILDER = "0x4d91ba8f33d2199045ff46dde384f2c49deb3a3f"


def validate_close_forward(request: object, forward: object) -> None:
    """Only Guard's exact default fee may differ from the builder-free MCP close.

    The shipped fee application clones the order action and replaces only builder.
    This checks the raw actions before privacy projection can omit that field; it
    neither grants fee approval nor changes any order, ownership or accounting proof.
    """
    original, sent = _object(request), _object(forward)
    fields = {"type", "orders", "grouping"}
    _need(set(original) == fields and original["type"] == "order")
    _need(set(sent) == fields or set(sent) == fields | {"builder"})
    for action in (original, sent):
        _need(type(action["type"]) is str and type(action["grouping"]) is str)
        _need(action["grouping"] == "na")
        wires = _orders(action["orders"])
        _need(len(wires) == 1)
        wire = wires[0]
        _need(set(wire) == {"a", "b", "r", "p", "s", "c", "t"})
        _need(type(wire["a"]) is int and type(wire["b"]) is bool and type(wire["r"]) is bool)
        _need(all(type(wire[name]) is str for name in ("p", "s", "c")))
        kind = _object(wire["t"])
        _need(set(kind) == {"limit"})
        limit = _object(kind["limit"])
        _need(set(limit) == {"tif"} and type(limit["tif"]) is str and limit["tif"] == "Ioc")
    if "builder" in sent:
        builder = _object(sent["builder"])
        _need(set(builder) == {"b", "f"})
        _need(
            isinstance(builder["b"], str)
            and builder["b"].lower() == TESTNET_BUILDER
            and type(builder["f"]) is int
            and builder["f"] == 20
        )
    _need({name: sent[name] for name in fields} == original)


@dataclass(frozen=True)
class Exit:
    oid: int
    size: Decimal
    limit: Decimal
    timestamp: int


def _lookup(
    value: dict[str, Any], cloid: str, started_ms: int, *, allow_closed_stop: bool = False
) -> tuple[dict[str, Any], str]:
    _need(value.get("status") == "order")
    resolved = _object(value.get("order"))
    status = resolved.get("status")
    _need(type(allow_closed_stop) is bool)
    _need(
        status in {"open", "filled", "canceled"}
        or allow_closed_stop
        and status == "reduceOnlyCanceled"
    )
    order = _object(resolved.get("order"))
    stamp = order.get("timestamp")
    _need(type(stamp) is int and stamp >= started_ms)
    _need(order.get("cloid") == cloid and order.get("coin") == "BTC")
    _need(order.get("side") == "A" and order.get("reduceOnly") is True)
    return order, str(status)


def prove_exits(
    events: Sequence[dict[str, Any]],
    client: str,
    proof: StopProof,
    entry: Entry,
    lookups: Mapping[str, dict[str, Any]],
    *,
    started_ms: int,
    allow_closed_stop: bool = False,
) -> dict[int, Exit]:
    """No caller-provided OID is trusted without durable wire and fresh cloid lookup.

    Only the entry's unchanged default stop and paired-client reduce-only BTC sell IOC
    decisions after the entry qualify: every close field remains exact, with only Guard's
    validated compiled default fee permitted on its forward. A close acknowledgement must
    agree with its lookup; every fill still requires net accounting below. Unknown exits
    refuse instead of permitting a broad account close. No venue calls or mutations.
    Only cleanup with empty positions/orders may opt in to the original stop's
    reduceOnlyCanceled status; owned_balance must still prove exact net zero.
    """
    _need(type(started_ms) is int and started_ms > 0 and type(allow_closed_stop) is bool)
    exits: dict[int, Exit] = {}
    if proof.cloid in lookups:
        order, _ = _lookup(
            lookups[proof.cloid], proof.cloid, started_ms, allow_closed_stop=allow_closed_stop
        )
        _need(_positive(order.get("origSz")) == proof.size)
        historical = dict(order, sz=order["origSz"])
        oid = validate_stop_order(historical, proof)
        exits[oid] = Exit(oid, proof.size, proof.limit, order["timestamp"])
    for event in events:
        observed = event.get("client")
        if (
            event.get("kind") != "decision"
            or not isinstance(observed, str)
            or observed.lower() != client.lower()
        ):
            continue
        request = _object(event.get("request"))
        if request.get("type") != "order":
            continue
        wires = _orders(request.get("orders"))
        if not any(wire.get("r") is True for wire in wires):
            continue
        sequence = _oid(event.get("seq"))
        _need(sequence > proof.decision and event.get("verdict") == "allow")
        _need(request.get("grouping") == "na" and len(wires) == 1)
        validate_close_forward(request, event.get("forward"))
        wire = wires[0]
        _need(type(wire.get("a")) is int and wire["a"] == entry.asset)
        _need(wire.get("b") is False and wire.get("r") is True)
        _need(wire.get("t") == {"limit": {"tif": "Ioc"}})
        cloid = wire.get("c")
        if not isinstance(cloid, str) or not re.fullmatch(r"0x7a6d[0-9a-f]{28}", cloid):
            raise ProtectionError("durable close cloid required")
        _need(cloid != proof.entry_cloid and cloid in lookups)
        size, limit = _positive(wire.get("s")), _positive(wire.get("p"))
        _need(size <= proof.size and size == size.quantize(Decimal(1).scaleb(-entry.precision)))
        order, status = _lookup(lookups[cloid], cloid, started_ms)
        _need(status in {"filled", "canceled"})
        _need(order.get("isTrigger") is False and order.get("orderType") == "Limit")
        _need(_positive(order.get("origSz")) == size and _positive(order.get("limitPx")) == limit)
        oid = _oid(order.get("oid"))
        statuses = order_statuses(events, sequence)
        _need(len(statuses) == 1 and set(_object(statuses[0])) == {"filled"})
        ack = _object(statuses[0]["filled"])
        _need(_oid(ack.get("oid")) == oid and ("cloid" not in ack or ack["cloid"] == cloid))
        _need(oid not in exits)
        exits[oid] = Exit(oid, size, limit, order["timestamp"])
    return exits


def _trade(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ProtectionError("unique nonnegative integer trade ID required")
    return value


def owned_balance(
    positions: Sequence[dict[str, Any]],
    fills: Sequence[dict[str, Any]],
    entry_oid: int,
    entry: Entry,
    exits: Mapping[int, Exit],
    *,
    started_ms: int,
    observe_net: Callable[[bool], None] = lambda _: None,
) -> tuple[Decimal, Decimal]:
    """Sum actual buys and authenticated sells; missing/foreign/duplicate fills refuse.

    From exclusive flat preflight, net quantity must never go negative or exceed the entry
    cap and must equal the observed isolated BTC remainder. No historical buy cap can
    authorize another trader's replacement exposure. Quantities/prices use Decimal strings.
    """
    _need(type(started_ms) is int and started_ms > 0 and entry_oid not in exits)
    bought = owned_quantity([], fills, entry_oid, entry)
    _need(len(positions) <= 1)
    trades: set[int] = set()
    sold_by_oid: dict[int, Decimal] = {}
    net = Decimal(0)
    for fill in sorted(fills, key=lambda item: (_oid(item.get("time")), _trade(item.get("tid")))):
        oid, trade = _oid(fill.get("oid")), _trade(fill.get("tid"))
        _need(trade not in trades and _oid(fill.get("time")) >= started_ms)
        trades.add(trade)
        _need(fill.get("coin") == "BTC")
        size, price = _positive(fill.get("sz")), _positive(fill.get("px"))
        if oid == entry_oid:
            _need(fill.get("side") == "B")
            net += size
        else:
            _need(oid in exits and fill.get("side") == "A" and price >= exits[oid].limit)
            _need(fill["time"] >= exits[oid].timestamp)
            sold_by_oid[oid] = sold_by_oid.get(oid, Decimal(0)) + size
            _need(sold_by_oid[oid] <= exits[oid].size)
            net -= size
        _need(Decimal(0) <= net <= entry.size)
    remaining = Decimal(0)
    if positions:
        position = positions[0]
        _need(position.get("coin") == "BTC")
        _need(_object(position.get("leverage")).get("type") == "isolated")
        remaining = amount(position.get("szi"))
        _need(remaining > 0)
    matched = net == remaining
    try:
        observe_net(matched)
    except (Exception, KeyboardInterrupt):
        pass  # Passive diagnostics cannot mask or change the accounting proof.
    if not matched:
        raise AccountingViewMismatch("owned accounting views disagree")
    return bought, remaining
