import copy
from typing import Any

import pytest
import test_testnet_ownership as reference

from guard_harness.testnet_collect import collect_ownership
from guard_harness.testnet_scan import ScanError

ACCOUNT = "0x" + "12" * 20


class Reads:
    def __init__(self, fields: Any, mutation: str = "") -> None:
        self.fields, self.mutation = fields, mutation
        self.calls: list[dict[str, Any]] = []
        self.counts: dict[str, int] = {}

    def __call__(self, payload: dict[str, Any]) -> object:
        self.calls.append(payload)
        kind = payload["type"]
        self.counts[kind] = self.counts.get(kind, 0) + 1
        fields = self.fields
        if kind == "userAbstraction":
            return "unifiedAccount" if self.mutation == "abstraction" else "disabled"
        if kind == "perpDexs":
            name = (
                "changed" if self.mutation == "inventory" and self.counts[kind] == 2 else "fixture"
            )
            return [None, {"name": name}]
        if kind == "meta":
            return {"universe": copy.deepcopy(fields["markets"])}
        if kind == "orderStatus":
            if payload["oid"] in fields.get("exit_lookups", {}):
                return copy.deepcopy(fields["exit_lookups"][payload["oid"]])
            if payload["oid"] == fields["entry_lookup"]["order"]["order"]["cloid"]:
                return copy.deepcopy(fields["entry_lookup"])
            return copy.deepcopy(fields["stop_lookup"])
        if kind == "userFillsByTime":
            assert payload["user"] == ACCOUNT and payload["startTime"] == 1000
            fills = copy.deepcopy(fields["fills"])
            if self.mutation == "truncated":
                return fills * 500
            if self.mutation == "fills" and self.counts[kind] == 2:
                fills.append(dict(fills[0], tid=2, sz="0.0001"))
            return fills
        if kind == "clearinghouseState":
            positions = copy.deepcopy(fields["positions"])
            if payload.get("dex"):
                positions = (
                    positions
                    if self.mutation == "secondary-position"
                    or self.mutation == "secondary-position-race"
                    and self.counts[kind] == 4
                    else []
                )
            elif self.counts[kind] == 3:
                if self.mutation == "position":
                    positions[0]["szi"] = "0.0001"
                elif self.mutation == "mark":
                    positions[0]["positionValue"] = "12.1"
            return {"assetPositions": [{"position": p} for p in positions]}
        if kind == "frontendOpenOrders":
            orders = copy.deepcopy(fields["orders"])
            if payload.get("dex"):
                orders = (
                    orders
                    if self.mutation == "secondary-order"
                    or self.mutation == "secondary-order-race"
                    and self.counts[kind] == 4
                    else []
                )
            elif self.counts[kind] == 3 and self.mutation == "orders":
                orders = []
            return orders
        raise AssertionError("unexpected request")


@pytest.fixture
def case() -> Any:
    fixture: Any = reference.case
    return fixture.__wrapped__()


@pytest.mark.parametrize("mutation", ["", "mark"])
def test_fresh_complete_reads_bind_owned_exposure_without_keys(case: Any, mutation: str) -> None:
    reads = Reads(case[3], mutation)
    result = collect_ownership(reads, ACCOUNT, *case[:3], started_ms=1000)
    assert result.entry_oid == 41 and result.stop_oid == 42
    assert reads.counts["userFillsByTime"] == 2
    assert reads.counts["perpDexs"] == 2
    assert reads.counts["clearinghouseState"] == 4
    assert reads.counts["frontendOpenOrders"] == 4
    assert {
        call.get("dex", "") for call in reads.calls if call["type"] == "clearinghouseState"
    } == {"", "fixture"}


@pytest.mark.parametrize(
    "mutation",
    [
        "abstraction",
        "inventory",
        "truncated",
        "fills",
        "position",
        "orders",
        "secondary-position",
        "secondary-order",
        "secondary-order-race",
        "secondary-position-race",
    ],
)
def test_incomplete_racing_or_secondary_exposure_refuses_observation(
    case: Any, mutation: str
) -> None:
    with pytest.raises(RuntimeError):
        collect_ownership(Reads(case[3], mutation), ACCOUNT, *case[:3], started_ms=1000)


def test_invalid_account_or_window_refuses_before_read(case: Any) -> None:
    reads = Reads(case[3])
    for account, started in [("invalid", 1000), (ACCOUNT, True), (ACCOUNT, 0)]:
        with pytest.raises(RuntimeError):
            collect_ownership(reads, account, *case[:3], started_ms=started)
    assert reads.calls == []


def test_unreadable_response_never_becomes_empty_holdings(case: Any) -> None:
    reads = Reads(case[3])

    def broken(payload: dict[str, Any]) -> object:
        if payload["type"] == "clearinghouseState":
            return {"assetPositions": None}
        return reads(payload)

    with pytest.raises(RuntimeError):
        collect_ownership(broken, ACCOUNT, *case[:3], started_ms=1000)


def test_fixed_transport_reserves_full_fill_weight_even_when_read_fails() -> None:
    from unittest.mock import Mock

    from guard_harness.testnet_scan import TestnetReads as Transport

    now = [0.0]
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    transport = Transport(clock=lambda: now[0], sleep=sleep, timeout=100)
    transport.opener = Mock()
    transport.opener.open.side_effect = ValueError("body withheld")
    for _ in range(2):
        with pytest.raises(ScanError, match="HTTP/JSON"):
            transport({"type": "userFillsByTime", "user": ACCOUNT, "startTime": 1000})
    assert sleeps == [12, 12]


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "userFillsByTime", "user": ACCOUNT, "startTime": True},
        {"type": "userFillsByTime", "user": ACCOUNT, "startTime": 0},
        {"type": "orderStatus", "user": ACCOUNT, "oid": 41},
        {"type": "orderStatus", "user": ACCOUNT, "oid": "bad"},
        {"type": "frontendOpenOrders", "user": "invalid"},
    ],
)
def test_malformed_extended_reads_refuse_before_transport(payload: dict[str, Any]) -> None:
    from unittest.mock import Mock

    from guard_harness.testnet_scan import TestnetReads as Transport

    transport = Transport()
    transport.opener = Mock()
    with pytest.raises(ScanError):
        transport(payload)
    assert not transport.opener.open.called


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "meta"},
        {"type": "orderStatus", "user": ACCOUNT, "oid": "0x7a6d" + "a" * 28},
        {"type": "userFillsByTime", "user": ACCOUNT, "startTime": 1000},
    ],
)
def test_extended_transport_keeps_fixed_url_and_integer_fill_window(
    payload: dict[str, Any],
) -> None:
    import json
    from unittest.mock import MagicMock, Mock

    from guard_harness.testnet_scan import TestnetReads as Transport

    transport = Transport(sleep=lambda _: None)
    transport.opener = MagicMock()
    response = Mock()
    transport.opener.open.return_value.__enter__.return_value = response
    response.read.return_value = b"[]"
    assert transport(payload) == []
    request = transport.opener.open.call_args.args[0]
    assert request.full_url == "https://api.hyperliquid-testnet.xyz/info"
    assert json.loads(request.data) == payload
    response.read.assert_called_once_with(1_048_577)


def test_collector_preserves_unfilled_entry_only_cleanup_rule(case: Any) -> None:
    fields = case[3]
    opening = fields["entry_lookup"]["order"]["order"]
    opening["sz"] = "0.0002"
    fields["entry_lookup"]["order"]["status"] = "open"
    fields.update(fills=[], positions=[], orders=[copy.deepcopy(opening)], stop_lookup=None)
    case[0][-1]["reply"]["response"]["data"]["statuses"] = [
        {"resting": {"oid": 41}},
        "waitingForFill",
    ]
    result = collect_ownership(Reads(fields), ACCOUNT, *case[:3], started_ms=1000, cleanup=True)
    assert result.resting_entry and result.stop_oid is None


@pytest.fixture
def closed_case(case: Any) -> Any:
    fixture: Any = reference.closed_case
    return fixture.__wrapped__(case)


def test_collector_fetches_own_close_and_historical_stop_to_prove_flat(closed_case: Any) -> None:
    reads = Reads(closed_case[3])
    result = collect_ownership(reads, ACCOUNT, *closed_case[:3], started_ms=1000, cleanup=True)
    assert result.remaining == 0 and result.stop_oid is None
    assert reads.counts["orderStatus"] == 3
    assert {call["oid"] for call in reads.calls if call["type"] == "orderStatus"} == {
        closed_case[3]["entry_lookup"]["order"]["order"]["cloid"],
        closed_case[3]["stop_lookup"]["order"]["order"]["cloid"],
        *closed_case[3]["exit_lookups"],
    }


@pytest.mark.parametrize("mutation", ["missing-lookup", "missing-fill", "fills"])
def test_collector_cannot_credit_incomplete_or_racing_flat_close(
    closed_case: Any, mutation: str
) -> None:
    fields = closed_case[3]
    if mutation == "missing-lookup":
        fields["exit_lookups"].clear()
    elif mutation == "missing-fill":
        fields["fills"].pop()
    with pytest.raises(RuntimeError):
        collect_ownership(
            Reads(fields, mutation), ACCOUNT, *closed_case[:3], started_ms=1000, cleanup=True
        )
