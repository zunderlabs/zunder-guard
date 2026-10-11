import copy
from decimal import Decimal
from typing import Any

import pytest

from guard_harness.testnet_protection import (
    Entry,
    ProtectionError,
    price_grid,
    prove_stop,
    validate_stop_order,
)


@pytest.fixture
def evidence() -> tuple[Entry, str, list[dict[str, Any]], dict[str, Any]]:
    # At a 60,000 reference, default 2% stop is 58,800; its 10% buffer is 52,920.
    # 0.0002 BTC at a 60,120 limit is 12.024 USDC, within the unchanged 40 USDC run cap.
    entry = Entry(0, Decimal("0.0002"), Decimal("60120"), 5)
    client = "0x" + "1" * 40
    opening = {
        "a": 0,
        "b": True,
        "p": "60120",
        "s": "0.0002",
        "r": False,
        "c": "0x7a6d" + "a" * 28,
        "t": {"limit": {"tif": "Ioc"}},
    }
    stop = {
        "a": 0,
        "b": False,
        "p": "52920",
        "s": "0.0002",
        "r": True,
        "c": "0x7a67" + "b" * 28,
        "t": {"trigger": {"triggerPx": "58800", "isMarket": True, "tpsl": "sl"}},
    }
    event = {
        "kind": "decision",
        "seq": 1,
        "client": client,
        "action": "order",
        "verdict": "allow",
        "request": {"type": "order", "orders": [copy.deepcopy(opening)], "grouping": "na"},
        "forward": {"type": "order", "orders": [opening, stop], "grouping": "normalTpsl"},
        "changes": ["a reduce-only stop at 58800 (2% from 60000) is attached"],
    }
    venue = {
        "oid": 42,
        "cloid": stop["c"],
        "coin": "BTC",
        "side": "A",
        "isTrigger": True,
        "reduceOnly": True,
        "orderType": "Stop Market",
        "sz": "0.0002",
        "triggerPx": "58800",
        "limitPx": "52920",
        "triggerCondition": "Price below 58800",
    }
    return entry, client, [event], venue


def proof(evidence: Any) -> Any:
    entry, client, events, _ = evidence
    return prove_stop(
        events,
        client,
        entry,
        markets=[{"name": "BTC", "szDecimals": 5}],
        filled=entry.size,
        mark=Decimal("60000"),
    )


def test_hand_computed_durable_stop_and_venue_match(evidence: Any) -> None:
    result = proof(evidence)
    assert result.entry_cloid == "0x7a6d" + "a" * 28
    assert result.wire["p"] == "52920"
    assert validate_stop_order(evidence[3], result) == 42


@pytest.mark.parametrize(
    "change",
    [
        "client",
        "duplicate",
        "veto",
        "quantity",
        "price",
        "asset",
        "group",
        "missing-stop",
        "extra-stop",
        "stop-size",
        "stop-side",
        "reduce-only",
        "trigger",
        "buffer",
        "reference",
    ],
)
def test_corrupt_durable_protection_refused(evidence: Any, change: str) -> None:
    entry, client, events, _ = evidence
    event = events[0]
    opening, stop = event["forward"]["orders"]
    if change == "client":
        event["client"] = "0x" + "2" * 40
    elif change == "duplicate":
        events.append(copy.deepcopy(event))
    elif change == "veto":
        event["verdict"] = "veto"
    elif change == "quantity":
        event["request"]["orders"][0]["s"] = "0.0003"
    elif change == "price":
        opening["p"] = "60121"
    elif change == "asset":
        stop["a"] = 1
    elif change == "group":
        event["forward"]["grouping"] = "na"
    elif change == "missing-stop":
        event["forward"]["orders"].pop()
    elif change == "extra-stop":
        event["forward"]["orders"].append(copy.deepcopy(stop))
    elif change == "stop-size":
        stop["s"] = "0.0003"
    elif change == "stop-side":
        stop["b"] = True
    elif change == "reduce-only":
        stop["r"] = False
    elif change == "trigger":
        stop["t"]["trigger"]["triggerPx"] = "58799"
    elif change == "buffer":
        stop["p"] = "52921"
    else:
        event["changes"] = ["a reduce-only stop at 58800 (2% from 61000) is attached"]
    with pytest.raises(ProtectionError):
        prove_stop(
            events,
            client,
            entry,
            markets=[{"name": "BTC", "szDecimals": 5}],
            filled=entry.size,
            mark=Decimal("60000"),
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("oid", True),
        ("oid", 0),
        ("cloid", "unrelated"),
        ("coin", "ETH"),
        ("side", "B"),
        ("reduceOnly", False),
        ("isTrigger", False),
        ("orderType", "Stop Limit"),
        ("sz", "0.0003"),
        ("triggerPx", "58799"),
        ("limitPx", "52921"),
        ("triggerCondition", "Price above 58800"),
    ],
)
def test_venue_stop_must_match_every_durable_field(evidence: Any, field: str, value: Any) -> None:
    result = proof(evidence)
    evidence[3][field] = value
    with pytest.raises(ProtectionError):
        validate_stop_order(evidence[3], result)


@pytest.mark.parametrize(
    "filled,mark", [("0.0003", "60000"), ("-1", "60000"), ("0.0002", "58000"), ("NaN", "60000")]
)
def test_unbounded_fill_or_already_crossed_stop_refused(
    evidence: Any, filled: str, mark: str
) -> None:
    entry, client, events, _ = evidence
    with pytest.raises(ProtectionError):
        prove_stop(
            events,
            client,
            entry,
            markets=[{"name": "BTC", "szDecimals": 5}],
            filled=Decimal(filled),
            mark=Decimal(mark),
        )


def test_partial_fill_can_validate_wire_without_granting_journey_credit(evidence: Any) -> None:
    entry, client, events, _ = evidence
    assert prove_stop(
        events,
        client,
        entry,
        markets=[{"name": "BTC", "szDecimals": 5}],
        filled=Decimal("0.0001"),
        mark=Decimal("60000"),
    )


@pytest.mark.parametrize(
    "size,limit,precision",
    [("0.001", "60120", 5), ("0.0001", "60120", 5), ("0.000201", "60120", 5), ("NaN", "60120", 5)],
)
def test_entry_bounds_and_precision(size: str, limit: str, precision: int) -> None:
    with pytest.raises(ProtectionError):
        Entry(0, Decimal(size), Decimal(limit), precision).validate()


def test_independent_price_grid_rounding() -> None:
    assert price_grid(Decimal("58800.1"), 5, up=True) == Decimal("58801")
    assert price_grid(Decimal("58800.9"), 5, up=False) == Decimal("58800")
    assert price_grid(Decimal("0.123456"), 2, up=True) == Decimal("0.1235")


@pytest.mark.parametrize("case", ["requested-tif", "forwarded-tif", "request-type", "bool-asset"])
def test_entry_wire_cannot_change_its_execution_semantics(evidence: Any, case: str) -> None:
    event = evidence[2][0]
    if case == "requested-tif":
        event["request"]["orders"][0]["t"]["limit"]["tif"] = "Gtc"
    elif case == "forwarded-tif":
        event["forward"]["orders"][0]["t"]["limit"]["tif"] = "Gtc"
    elif case == "request-type":
        event["request"]["type"] = "cancel"
    else:
        event["forward"]["orders"][1]["a"] = False
    with pytest.raises(ProtectionError):
        proof(evidence)


def test_proof_keeps_its_captured_nested_wire(evidence: Any) -> None:
    result = proof(evidence)
    evidence[2][0]["forward"]["orders"][1]["t"]["trigger"]["triggerPx"] = "1"
    assert validate_stop_order(evidence[3], result) == 42


def test_proof_rendering_mutation_cannot_admit_a_fifty_percent_stop(evidence: Any) -> None:
    result = proof(evidence)
    rendered = result.wire
    rendered["t"]["trigger"]["triggerPx"] = "30000"
    rendered["p"] = "27000"
    evidence[3].update(triggerPx="30000", limitPx="27000", triggerCondition="Price below 30000")
    with pytest.raises(ProtectionError):
        validate_stop_order(evidence[3], result)
    assert result.trigger == Decimal("58800")


def test_wrong_asset_cannot_borrow_btc_venue_readback(evidence: Any) -> None:
    entry, client, events, _ = evidence
    for order in events[0]["request"]["orders"] + events[0]["forward"]["orders"]:
        order["a"] = 1
    with pytest.raises(ProtectionError):
        prove_stop(
            events,
            client,
            Entry(1, entry.size, entry.limit, entry.precision),
            markets=[{"name": "BTC", "szDecimals": 5}, {"name": "ETH", "szDecimals": 5}],
            filled=entry.size,
            mark=Decimal("60000"),
        )


@pytest.mark.parametrize("case", ["both-gtc", "requested-bool-asset"])
def test_simultaneous_wire_change_or_boolean_asset_refused(evidence: Any, case: str) -> None:
    event = evidence[2][0]
    if case == "both-gtc":
        event["request"]["orders"][0]["t"] = {"limit": {"tif": "Gtc"}}
        event["forward"]["orders"][0]["t"] = {"limit": {"tif": "Gtc"}}
    else:
        event["request"]["orders"][0]["a"] = False
    with pytest.raises(ProtectionError):
        proof(evidence)
