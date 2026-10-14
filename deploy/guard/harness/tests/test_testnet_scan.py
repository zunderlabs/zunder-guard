"""Cleanup scan failures never return flat evidence or trigger repairs."""

import json
from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from guard_harness.testnet_scan import SCAN_TIMEOUT, ScanError, flat_scan, inventory
from guard_harness.testnet_scan import TestnetReads as VenueReads

ACCOUNT = "0x" + "12" * 20


class Fixture:
    def __init__(self) -> None:
        self.after: object = [None, {"name": "fixture"}]
        self.abstraction: object = "disabled"
        self.state: dict[str, Any] = {
            "assetPositions": [{"position": {"coin": "BTC", "szi": "0"}}],
            "marginSummary": {"accountValue": "200"},
        }
        self.orders: object = []
        self.calls: list[dict[str, str]] = []
        self.inventory_reads = 0

    def __call__(self, payload: dict[str, str]) -> object:
        self.calls.append(payload)
        if payload["type"] == "userAbstraction":
            return self.abstraction
        if payload["type"] == "perpDexs":
            self.inventory_reads += 1
            return [None, {"name": "fixture"}] if self.inventory_reads == 1 else self.after
        if payload["type"] == "clearinghouseState":
            return self.state
        if payload["type"] == "frontendOpenOrders":
            return self.orders
        raise AssertionError("unexpected endpoint")


def test_every_dex_is_checked_and_zero_positions_are_flat() -> None:
    fixture = Fixture()
    report = flat_scan(fixture, ACCOUNT)
    assert report["dexes"] == ["", "fixture"]
    assert [
        call.get("dex", "") for call in fixture.calls if call["type"] == "clearinghouseState"
    ] == ["", "fixture"]
    assert fixture.inventory_reads == 2
    assert ACCOUNT not in str(report)


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {},
        [{"name": "x"}],
        [None, None],
        [None, {"name": "x"}, {"name": "x"}],
        [None, {"name": "bad name"}],
        [None] * 513,
    ],
)
def test_incomplete_inventory_is_never_empty_success(value: object) -> None:
    with pytest.raises(ScanError):
        inventory(value)


@pytest.mark.parametrize("value", ["1", "-0.000001", "NaN", "Infinity", "bad", 0, None])
def test_nonzero_or_unreadable_position_refuses_cleanup(value: object) -> None:
    fixture = Fixture()
    fixture.state["assetPositions"][0]["position"]["szi"] = value
    with pytest.raises(ScanError):
        flat_scan(fixture, ACCOUNT)


@pytest.mark.parametrize("value", [None, {}, [{"oid": 1}]])
def test_open_or_unreadable_orders_refuse_cleanup(value: object) -> None:
    fixture = Fixture()
    fixture.orders = value
    with pytest.raises(ScanError):
        flat_scan(fixture, ACCOUNT)


def test_inventory_change_restarts_the_whole_scan_once_over_the_new_inventory() -> None:
    # A DEX appeared mid-scan (rc.16, 14 Oct): the first pass is discarded, the second pass
    # checks every DEX of the unchanged new inventory, and only that pass is reported.
    fixture = Fixture()
    fixture.after = [None, {"name": "fixture"}, {"name": "new-dex"}]
    report = flat_scan(fixture, ACCOUNT)
    assert report["dexes"] == ["", "fixture", "new-dex"]
    assert fixture.inventory_reads == 4
    second = fixture.calls[[c["type"] for c in fixture.calls].index("perpDexs", 2) :]
    assert [c.get("dex", "") for c in second if c["type"] == "clearinghouseState"] == [
        "",
        "fixture",
        "new-dex",
    ]
    observations = report["observations"]
    assert isinstance(observations, list)
    assert [o["dex"] for o in observations] == ["", "fixture", "new-dex"]


def test_inventory_that_keeps_changing_refuses_flat_credit() -> None:
    fixture = Fixture()
    original = fixture.__call__

    def churning(payload: dict[str, str]) -> object:
        # Every read adds one more DEX: additions only, but never one unchanged inventory.
        if payload["type"] == "perpDexs":
            fixture.inventory_reads += 1
            return [None, *({"name": f"dex-{n}"} for n in range(fixture.inventory_reads))]
        return original(payload)

    with pytest.raises(ScanError, match="inventory changed"):
        flat_scan(churning, ACCOUNT)
    assert fixture.inventory_reads == 4


def test_a_dex_added_then_removed_before_the_restart_refuses() -> None:
    # Independent review, 14 Oct: x appears at the end of the first pass and is gone before the
    # second; the second pass never reads x, so flat must not be reported.
    fixture = Fixture()
    inventories = iter(
        [
            [None, {"name": "a"}],
            [None, {"name": "a"}, {"name": "x"}],
            [None, {"name": "a"}],
            [None, {"name": "a"}],
        ]
    )
    original = fixture.__call__

    def read(payload: dict[str, str]) -> object:
        if payload["type"] == "perpDexs":
            fixture.inventory_reads += 1
            return next(inventories)
        return original(payload)

    with pytest.raises(ScanError, match="inventory changed"):
        flat_scan(read, ACCOUNT)
    assert fixture.inventory_reads == 4


def test_a_position_on_the_new_dex_in_the_second_pass_refuses() -> None:
    fixture = Fixture()
    fixture.after = [None, {"name": "fixture"}, {"name": "new-dex"}]
    original = fixture.__call__

    def read(payload: dict[str, str]) -> object:
        if payload["type"] == "clearinghouseState" and payload.get("dex") == "new-dex":
            return {
                "assetPositions": [{"position": {"coin": "new-dex:BTC", "szi": "0.001"}}],
                "marginSummary": {"accountValue": "200"},
            }
        return original(payload)

    with pytest.raises(ScanError, match="not flat"):
        flat_scan(read, ACCOUNT)


def test_a_removed_dex_refuses_without_a_restart() -> None:
    # A DEX that drops out of the list mid-scan could still hold state; never rescan without it.
    fixture = Fixture()
    fixture.after = [None]
    with pytest.raises(ScanError, match="inventory changed"):
        flat_scan(fixture, ACCOUNT)
    assert fixture.inventory_reads == 2


def test_restart_never_hides_a_position_found_in_the_first_pass() -> None:
    fixture = Fixture()
    fixture.after = [None, {"name": "new-dex"}]
    fixture.state = {
        "assetPositions": [{"position": {"coin": "BTC", "szi": "0.001"}}],
        "marginSummary": {"accountValue": "200"},
    }
    with pytest.raises(ScanError, match="not flat"):
        flat_scan(fixture, ACCOUNT)
    assert fixture.inventory_reads == 1


@pytest.mark.parametrize("value", ["199.999999", "NaN", 200, None])
def test_low_or_unknown_equity_is_refused_without_funding(value: object) -> None:
    fixture = Fixture()
    fixture.state["marginSummary"]["accountValue"] = value
    with pytest.raises(ScanError):
        flat_scan(fixture, ACCOUNT)
    assert {call["type"] for call in fixture.calls} <= {
        "userAbstraction",
        "perpDexs",
        "clearinghouseState",
        "frontendOpenOrders",
    }


@pytest.mark.parametrize("value", ["unifiedAccount", None, {}])
def test_nonstandard_account_refused_before_holdings(value: object) -> None:
    fixture = Fixture()
    fixture.abstraction = value
    with pytest.raises(ScanError):
        flat_scan(fixture, ACCOUNT)
    assert len(fixture.calls) == 1


def test_invalid_scope_refused_before_network() -> None:
    fixture = Fixture()
    for account, floor in (
        ("invalid", Decimal("200")),
        (ACCOUNT, Decimal("NaN")),
        (ACCOUNT, Decimal("0")),
    ):
        with pytest.raises(ScanError):
            flat_scan(fixture, account, minimum_equity=floor)
    assert fixture.calls == []


def test_transport_paces_failures_and_refuses_exhausted_deadline() -> None:
    now = [0.0]
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    reads = VenueReads(clock=lambda: now[0], sleep=sleep, timeout=15)
    opener = Mock()
    opener.open.side_effect = ValueError("private response details")
    reads.opener = opener
    for _ in range(2):
        with pytest.raises(ScanError, match="HTTP/JSON read failed"):
            reads({"type": "perpDexs"})
    assert sleeps == [2.0, 2.0]
    assert opener.open.call_count == 2
    with pytest.raises(ScanError, match="deadline"):
        reads({"type": "perpDexs"})
    assert opener.open.call_count == 2


@pytest.mark.parametrize(
    "payload",
    [{"type": "order"}, {"type": "perpDexs", "url": "mainnet"}, {"type": "clearinghouseState"}],
)
def test_only_bounded_read_only_requests_are_transmitted(payload: dict[str, str]) -> None:
    reads = VenueReads()
    opener = Mock()
    opener.open.side_effect = AssertionError("must not transmit")
    reads.opener = opener
    with pytest.raises(ScanError):
        reads(payload)


def test_position_on_secondary_dex_is_not_missed() -> None:
    fixture = Fixture()

    def read(payload: dict[str, str]) -> object:
        result = fixture(payload)
        if payload["type"] == "clearinghouseState" and payload.get("dex") == "fixture":
            return {
                "assetPositions": [{"position": {"coin": "fixture:COIN", "szi": "0.001"}}],
                "marginSummary": {"accountValue": "0"},
            }
        return result

    with pytest.raises(ScanError, match="not flat"):
        flat_scan(read, ACCOUNT)
    assert fixture.inventory_reads == 1


def test_successful_transport_has_fixed_testnet_endpoint_and_bounded_body() -> None:
    reads = VenueReads(sleep=lambda _: None)
    opener = MagicMock()
    response = Mock()
    opener.open.return_value.__enter__.return_value = response
    response.read.return_value = b"[null]"
    reads.opener = opener
    assert reads({"type": "perpDexs"}) == [None]
    request = opener.open.call_args.args[0]
    assert request.full_url == "https://api.hyperliquid-testnet.xyz/info"
    assert request.get_method() == "POST"
    assert request.data == b'{"type": "perpDexs"}'
    assert opener.open.call_args.kwargs["timeout"] == 10
    response.read.assert_called_once_with(1_048_577)


def test_new_phase_preserves_request_pacing_after_preflight_expires() -> None:
    now = [100.0]
    reads = VenueReads(clock=lambda: now[0], sleep=lambda _: None, timeout=15)
    reads.next_read = 118
    now[0] = 116
    reads.start_phase(timeout=SCAN_TIMEOUT)
    assert reads.deadline == 116 + SCAN_TIMEOUT and reads.next_read == 118
    with pytest.raises(ScanError):
        reads.start_phase(timeout=SCAN_TIMEOUT + 1)
    assert reads.deadline == 116 + SCAN_TIMEOUT and reads.next_read == 118


@pytest.mark.parametrize("timeout,passes", [(500, False), (720, True), (SCAN_TIMEOUT, True)])
def test_complete_270_dex_inventory_keeps_every_paced_read(timeout: int, passes: bool) -> None:
    now = [0.0]
    pauses: list[float] = []
    calls: list[dict[str, Any]] = []
    timings: list[tuple[float, int]] = []
    dexes: list[object] = [None, *({"name": f"fixture{index}"} for index in range(269))]

    def sleep(seconds: float) -> None:
        pauses.append(seconds)
        now[0] += seconds

    def opened(request: Any, *, timeout: float) -> MagicMock:
        assert timeout == 10
        payload = json.loads(request.data)
        calls.append(payload)
        kind = payload["type"]
        timings.append((now[0], 2 if kind == "clearinghouseState" else 20))
        value: object = (
            dexes
            if kind == "perpDexs"
            else "disabled"
            if kind == "userAbstraction"
            else []
            if kind == "frontendOpenOrders"
            else {"assetPositions": [], "marginSummary": {"accountValue": "200"}}
        )
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(value).encode()
        return response

    reads = VenueReads(clock=lambda: now[0], sleep=sleep, timeout=timeout)
    reads.opener = MagicMock()
    reads.opener.open.side_effect = opened
    if not passes:
        with pytest.raises(ScanError, match="deadline"):
            flat_scan(reads, ACCOUNT)
        assert len(calls) < 543
    else:
        report = flat_scan(reads, ACCOUNT)
        observations = report["observations"]
        assert isinstance(observations, list) and len(observations) == 270
        assert len(calls) == 543 and 600 <= now[0] < 620
        assert len([p for p in calls if p["type"] == "frontendOpenOrders"]) == 270
        assert calls[-1] == {"type": "perpDexs"}
        # 270 holdings×2 + 270 orders×20 + abstraction/inventory×20 = 6000.
        assert sum(cost for _, cost in timings) == 6000
    assert pauses and min(pauses) == pytest.approx(0.2)
    assert sum(cost for _, cost in reads.reservations) <= 600
    assert all(
        sum(cost for at, cost in timings if end - 60 < at <= end) <= 600 for end, _ in timings
    )


def test_weighted_failures_and_phase_changes_keep_rolling_minute_budget() -> None:
    now = [0.0]
    pauses: list[float] = []

    def sleep(seconds: float) -> None:
        pauses.append(seconds)
        now[0] += seconds

    reads = VenueReads(clock=lambda: now[0], sleep=sleep)
    reads.opener = Mock()
    reads.opener.open.side_effect = ValueError("withheld body")
    for _ in range(5):
        with pytest.raises(ScanError, match="HTTP/JSON"):
            reads({"type": "userFillsByTime", "user": ACCOUNT, "startTime": 1})
    # Five 120-weight failed requests exhaust 600 at 12,24,36,48,60s.
    # The next 2-weight read must wait until the first reservation leaves at 72s.
    reads.start_phase(timeout=SCAN_TIMEOUT)
    with pytest.raises(ScanError, match="HTTP/JSON"):
        reads({"type": "clearinghouseState", "user": ACCOUNT})
    assert now[0] == pytest.approx(72.001)
    assert pauses == pytest.approx([12] * 5 + [12.001])
    assert reads.reservations == [(24, 120), (36, 120), (48, 120), (60, 120), (72.001, 2)]
    with pytest.raises(ScanError, match="HTTP/JSON"):
        reads({"type": "perpDexs"})
    with pytest.raises(ScanError, match="HTTP/JSON"):
        reads({"type": "allMids"})
    with pytest.raises(ScanError, match="HTTP/JSON"):
        reads({"type": "orderStatus", "user": ACCOUNT, "oid": "0x" + "a" * 32})
    assert pauses[-3:] == pytest.approx([2, 0.2, 0.2])


def test_weighted_deadline_refuses_before_sleep_or_transmission() -> None:
    now = [0.0]
    reads = VenueReads(clock=lambda: now[0], sleep=lambda _: pytest.fail("no sleep"), timeout=11)
    reads.opener = Mock()
    with pytest.raises(ScanError, match="deadline"):
        reads({"type": "perpDexs"})
    assert reads.opener.open.call_count == 0 and reads.reservations == []


def test_pacing_sleep_overshoot_never_transmits_past_deadline() -> None:
    clock = [100.0]

    def oversleep(_: float) -> None:
        clock[0] = 122.0

    read = VenueReads(clock=lambda: clock[0], sleep=oversleep, timeout=15)
    opener = Mock()
    opener.open.side_effect = AssertionError("must refuse before transmission")
    read.opener = opener
    with pytest.raises(ScanError, match="nothing sent"):
        read({"type": "perpDexs"})
    assert read.reservations == [] and opener.open.call_count == 0
