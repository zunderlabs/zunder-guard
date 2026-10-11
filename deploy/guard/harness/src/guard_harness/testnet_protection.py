"""Read-only durable ownership and unchanged default-stop checks for T1/T2."""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import ROUND_DOWN, ROUND_UP, Decimal
from typing import Any

from guard_harness.testnet_scan import amount


class ProtectionError(RuntimeError):
    """Missing or inconsistent protection never authorizes account-wide cleanup."""


def _need(condition: bool) -> None:
    if not condition:
        raise ProtectionError("durable testnet protection differs")


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtectionError("protection object required")
    return value


def _orders(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ProtectionError("protection orders required")
    return value


def _positive(value: object) -> Decimal:
    result = amount(value)
    _need(result > 0)
    return result


def price_grid(value: Decimal, precision: int, *, up: bool) -> Decimal:
    """Independent price-grid reference from the old journey; never float accounting."""
    _need(type(precision) is int and 0 <= precision <= 6 and value.is_finite() and value > 0)
    places = max(0, min(6 - precision, 4 - value.adjusted()))
    return value.quantize(Decimal(1).scaleb(-places), rounding=ROUND_UP if up else ROUND_DOWN)


@dataclass(frozen=True)
class Entry:
    asset: int
    size: Decimal
    limit: Decimal
    precision: int

    def validate(self) -> None:
        _need(type(self.asset) is int and self.asset >= 0)
        _need(self.size.is_finite() and self.limit.is_finite() and self.size > 0 and self.limit > 0)
        _need(Decimal("10") <= self.size * self.limit <= Decimal("40"))
        _need(type(self.precision) is int and 0 <= self.precision <= 6)
        _need(self.size == self.size.quantize(Decimal(1).scaleb(-self.precision)))


def entry_plan(markets: Sequence[dict[str, Any]], mids: dict[str, Any]) -> Entry:
    """Default-policy BTC IOC around 15 USDC; no entry when venue granularity exceeds bounds."""
    found = [(index, item) for index, item in enumerate(markets) if item.get("name") == "BTC"]
    _need(len(found) == 1 and found[0][1].get("isDelisted", False) is False)
    asset, market = found[0]
    precision = market.get("szDecimals")
    if type(precision) is not int or not 0 <= precision <= 6:
        raise ProtectionError("BTC quantity precision refused")
    mid = _positive(mids.get("BTC"))
    limit = price_grid(mid * Decimal("1.002"), precision, up=False)
    _need(mid <= limit <= mid * Decimal("1.005"))
    size = (Decimal("15") / limit).quantize(Decimal(1).scaleb(-precision), rounding=ROUND_DOWN)
    entry = Entry(asset, size, limit, precision)
    entry.validate()
    return entry


@dataclass(frozen=True)
class StopProof:
    decision: int
    entry_cloid: str
    asset: int
    coin: str
    cloid: str
    size: Decimal
    trigger: Decimal
    limit: Decimal

    @property
    def wire(self) -> dict[str, Any]:
        # Return a fresh rendering: changing it cannot change the admitted proof.
        return {
            "a": self.asset,
            "b": False,
            "r": True,
            "c": self.cloid,
            "s": format(self.size, "f"),
            "p": format(self.limit, "f"),
            "t": {
                "trigger": {"triggerPx": format(self.trigger, "f"), "tpsl": "sl", "isMarket": True}
            },
        }


def prove_stop(
    events: Sequence[dict[str, Any]],
    client: str,
    entry: Entry,
    *,
    markets: Sequence[dict[str, Any]],
    filled: Decimal,
    mark: Decimal,
) -> StopProof:
    """Match exactly one client entry and its journaled two-percent protective stop.

    This proves a durable wire only. Fresh fills, venue stop lookup and acknowledgement
    checks are also required before the journey or cleanup may claim owned exposure.
    """
    entry.validate()
    _need(entry.asset < len(markets))
    market = markets[entry.asset]
    _need(
        market.get("name") == "BTC"
        and market.get("isDelisted", False) is False
        and type(market.get("szDecimals")) is int
        and market["szDecimals"] == entry.precision
    )
    _need(sum(item.get("name") == "BTC" for item in markets) == 1)
    _need(bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", client)))
    _need(filled.is_finite() and Decimal(0) <= filled <= entry.size)
    _need(mark.is_finite() and mark > 0)
    candidates = []
    for event in events:
        observed_client = event.get("client")
        if (
            event.get("kind") != "decision"
            or not isinstance(observed_client, str)
            or observed_client.lower() != client.lower()
        ):
            continue
        if event.get("action") == "order" and any(
            order.get("r") is False
            for order in _orders(_object(event.get("request")).get("orders"))
        ):
            candidates.append(event)
    _need(len(candidates) == 1)
    decision = candidates[0]
    sequence = decision.get("seq")
    if type(sequence) is not int or sequence <= 0:
        raise ProtectionError("positive durable decision sequence required")
    _need(decision.get("verdict") in {"allow", "resize"})
    request = _object(decision.get("request"))
    _need(request.get("type") == "order" and request.get("grouping") == "na")
    requested = _orders(request.get("orders"))
    _need(len(requested) == 1)
    opening = requested[0]
    cloid = opening.get("c")
    if not isinstance(cloid, str) or not re.fullmatch(r"0x7a6d[0-9a-f]{28}", cloid):
        raise ProtectionError("durable entry cloid required")
    _need(
        opening.get("a") == entry.asset and opening.get("b") is True and opening.get("r") is False
    )
    _need(type(opening.get("a")) is int)
    _need(opening.get("t") == {"limit": {"tif": "Ioc"}})
    _need(_positive(opening.get("s")) == entry.size and _positive(opening.get("p")) == entry.limit)
    forward = _object(decision.get("forward"))
    _need(forward.get("type") == "order" and forward.get("grouping") == "normalTpsl")
    orders = _orders(forward.get("orders"))
    _need(len(orders) == 2)
    buy, stop = orders
    _need(
        buy.get("c") == cloid
        and type(buy.get("a")) is int
        and buy.get("a") == entry.asset
        and buy.get("b") is True
    )
    _need(buy.get("t") == opening.get("t"))
    _need(buy.get("r") is False and _positive(buy.get("p")) == entry.limit)
    trigger = _object(_object(stop.get("t")).get("trigger"))
    _need(
        type(stop.get("a")) is int
        and stop.get("a") == entry.asset
        and stop.get("b") is False
        and stop.get("r") is True
    )
    _need(trigger.get("tpsl") == "sl" and trigger.get("isMarket") is True)
    _need(isinstance(stop.get("c"), str) and bool(re.fullmatch(r"0x7a67[0-9a-f]{28}", stop["c"])))
    size, stop_price, limit = (
        _positive(stop.get("s")),
        _positive(trigger.get("triggerPx")),
        _positive(stop.get("p")),
    )
    _need(size == _positive(buy.get("s")) and filled <= size <= entry.size)
    changes = decision.get("changes")
    if not isinstance(changes, list) or not all(isinstance(text, str) for text in changes):
        raise ProtectionError("durable attachment reference required")
    references = [
        match
        for text in changes
        if (
            match := re.fullmatch(
                r"a reduce-only stop at ([0-9]+(?:\.[0-9]+)?) "
                r"\(2% from ([0-9]+(?:\.[0-9]+)?)\) is attached",
                text,
            )
        )
    ]
    _need(len(references) == 1)
    recorded, reference = (_positive(value) for value in references[0].groups())
    _need(
        recorded == stop_price == price_grid(reference * Decimal("0.98"), entry.precision, up=True)
    )
    _need(limit == price_grid(stop_price * Decimal("0.90"), entry.precision, up=False))
    _need(
        reference
        <= entry.limit
        <= price_grid(reference * Decimal("1.005"), entry.precision, up=False)
    )
    _need(stop_price < reference and stop_price < mark and stop_price < entry.limit)
    return StopProof(sequence, cloid, entry.asset, "BTC", stop["c"], size, stop_price, limit)


def validate_stop_order(order: dict[str, Any], proof: StopProof) -> int:
    """Match the actual venue stop to the durable wire; an OID alone grants no ownership."""
    wire = proof.wire
    trigger = _object(_object(wire.get("t")).get("trigger"))
    oid = order.get("oid")
    if type(oid) is not int or oid <= 0:
        raise ProtectionError("positive venue stop OID required")
    _need(order.get("cloid") == wire["c"])
    _need(order.get("coin") == proof.coin and order.get("side") == "A")
    _need(order.get("isTrigger") is True and order.get("reduceOnly") is True)
    _need(order.get("orderType") == "Stop Market")
    _need(_positive(order.get("sz")) == _positive(wire["s"]))
    _need(_positive(order.get("triggerPx")) == _positive(trigger["triggerPx"]))
    _need(_positive(order.get("limitPx")) == _positive(wire["p"]))
    if "triggerCondition" in order:
        condition = order["triggerCondition"]
        _need(isinstance(condition, str))
        direction = re.fullmatch(r"Price below ([0-9]+(?:\.[0-9]+)?)", condition)
        _need(direction is not None and _positive(direction[1]) == _positive(trigger["triggerPx"]))
    return int(oid)
