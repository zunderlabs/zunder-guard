"""Cleanup scan failures never return flat evidence or trigger repairs."""

import email.message
import http.client
import json
import urllib.error
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


def http_error(code: int, retry_after: str | None = None) -> urllib.error.HTTPError:
    headers = email.message.Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError(
        "https://api.hyperliquid-testnet.xyz/info", code, "withheld", headers, None
    )


class Scripted:
    """A fake clock and opener; each try takes the next outcome (an exception or a body)."""

    def __init__(self, outcomes: list[object], *, timeout: float = SCAN_TIMEOUT) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []
        self.sent_at: list[float] = []
        self.outcomes = list(outcomes)
        self.reads = VenueReads(clock=lambda: self.now, sleep=self.sleep, timeout=timeout)
        self.opener = MagicMock()
        self.opener.open.side_effect = self.open
        self.reads.opener = self.opener

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def open(self, request: Any, *, timeout: float) -> MagicMock:
        assert timeout == 10 and json.loads(request.data)["type"]
        self.sent_at.append(self.now)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        assert isinstance(outcome, bytes)
        response = MagicMock()
        response.__enter__.return_value.read.return_value = outcome
        return response


HOLDINGS = {"type": "clearinghouseState", "user": ACCOUNT}


def test_a_429_then_success_returns_the_data() -> None:
    scripted = Scripted([http_error(429), b"[null]"])
    assert scripted.reads({"type": "perpDexs"}) == [None]
    assert scripted.opener.open.call_count == 2
    # 20-weight pacing (2 s) already covers the first 2 s backoff.
    assert scripted.sleeps == pytest.approx([2, 2])


def test_a_503_twice_then_success_returns_the_data() -> None:
    scripted = Scripted([http_error(503), http_error(503), b'{"ok": 1}'])
    assert scripted.reads(HOLDINGS) == {"ok": 1}
    assert scripted.opener.open.call_count == 3
    assert scripted.sleeps == pytest.approx([0.2, 2, 4])


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError("withheld"),
        urllib.error.URLError(TimeoutError("withheld")),
        urllib.error.URLError("bounded read failed"),
        ConnectionResetError("withheld"),
        http.client.RemoteDisconnected("withheld"),
        http.client.IncompleteRead(b"partial"),
        http_error(500),
        http_error(599),
    ],
)
def test_a_transient_failure_then_success_returns_the_data(error: BaseException) -> None:
    scripted = Scripted([error, b"[null]"])
    assert scripted.reads({"type": "perpDexs"}) == [None]
    assert scripted.opener.open.call_count == 2


def test_four_transient_failures_fail_after_exactly_four_paced_tries() -> None:
    # 2-weight reads prepay 0.2 s, so the 2/4/8 s backoff sets each retry's pause.
    scripted = Scripted([TimeoutError(), http_error(502), http_error(429), TimeoutError()])
    with pytest.raises(ScanError, match="^testnet HTTP/JSON read failed$") as caught:
        scripted.reads(HOLDINGS)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    assert scripted.opener.open.call_count == 4
    assert scripted.sleeps == pytest.approx([0.2, 2, 4, 8])
    assert scripted.sent_at == pytest.approx([0.2, 2.2, 6.2, 14.2])
    # Every retry is another reserved request against the same rolling budget.
    assert scripted.reads.reservations == pytest.approx([(0.2, 2), (2.2, 2), (6.2, 2), (14.2, 2)])


@pytest.mark.parametrize(
    "outcome",
    [
        http_error(400),
        http_error(403),
        http_error(404),
        b"{not json",
        b"\xff\xfe",
        ValueError("read refused"),
        OSError("not a connection failure"),
        http.client.BadStatusLine("withheld"),
    ],
)
def test_a_non_transient_failure_is_never_retried(outcome: object) -> None:
    scripted = Scripted([outcome, b"[null]"])
    with pytest.raises(ScanError, match="^testnet HTTP/JSON read failed$"):
        scripted.reads({"type": "perpDexs"})
    assert scripted.opener.open.call_count == 1


def test_an_oversized_body_is_never_retried() -> None:
    scripted = Scripted([b" " * 1_048_577, b"[null]"])
    with pytest.raises(ScanError, match="oversized"):
        scripted.reads({"type": "perpDexs"})
    assert scripted.opener.open.call_count == 1


@pytest.mark.parametrize(
    "payload", [{"type": "order"}, {"type": "perpDexs", "user": ACCOUNT}, {"type": "meta", "x": 1}]
)
def test_a_refused_request_is_never_sent_or_retried(payload: dict[str, Any]) -> None:
    scripted = Scripted([TimeoutError()])
    with pytest.raises(ScanError, match="unsupported|unexpected"):
        scripted.reads(payload)
    assert scripted.opener.open.call_count == 0 and scripted.sleeps == []


def test_a_deadline_after_the_response_is_never_retried() -> None:
    scripted = Scripted([b"[null]", b"[null]"], timeout=15)

    def late(request: Any, *, timeout: float) -> MagicMock:
        response = scripted.open(request, timeout=timeout)
        scripted.now = 15.0
        return response

    scripted.opener.open.side_effect = late
    with pytest.raises(ScanError, match="deadline exhausted after response"):
        scripted.reads({"type": "perpDexs"})
    assert scripted.opener.open.call_count == 1


def test_a_retry_that_would_cross_the_deadline_is_never_sent() -> None:
    # Deadline 15: tries at 2 s and 4 s; the third would start at 8 s and end past 15 s.
    scripted = Scripted([TimeoutError(), TimeoutError(), b"[null]"], timeout=15)
    with pytest.raises(ScanError, match="^scan deadline exhausted; no incomplete flat credit$"):
        scripted.reads({"type": "perpDexs"})
    assert scripted.opener.open.call_count == 2
    assert scripted.sleeps == pytest.approx([2, 2])
    assert len(scripted.reads.reservations) == 2


def test_a_retry_overslept_past_the_deadline_is_never_sent() -> None:
    scripted = Scripted([TimeoutError(), b"[null]"], timeout=15)

    def oversleep(seconds: float) -> None:
        scripted.sleep(seconds)
        if len(scripted.sleeps) == 2:
            scripted.now = 14.0

    scripted.reads.sleep = oversleep
    with pytest.raises(ScanError, match="after pacing; nothing sent"):
        scripted.reads({"type": "perpDexs"})
    assert scripted.opener.open.call_count == 1


def test_a_failed_try_keeps_its_weight_in_the_rolling_minute() -> None:
    # Four 120-weight fill reads at 12/24/36/48 s; the fifth fails at 60 s and its retry goes
    # at 72 s (12 s prepaid). Counting the failed try, (12, 72] holds 600, so the next 2-weight
    # read waits until the 24 s reservation leaves; without it, 480 would let it go at 72.2 s.
    fills = {"type": "userFillsByTime", "user": ACCOUNT, "startTime": 1}
    scripted = Scripted([b"[]"] * 4 + [TimeoutError(), b"[]", b"{}"])
    for _ in range(5):
        assert scripted.reads(fills) == []
    assert scripted.sent_at == pytest.approx([12, 24, 36, 48, 60, 72])
    assert scripted.reads.reservations == pytest.approx(
        [(24, 120), (36, 120), (48, 120), (60, 120), (72, 120)]
    )
    assert scripted.reads(HOLDINGS) == {}
    assert scripted.sent_at[-1] == pytest.approx(84.001)


@pytest.mark.parametrize(
    "retry_after,pause",
    [("7", 7), (" 12 ", 12), ("1", 2), ("30", 30), ("31", 30), ("86400", 30)],
)
def test_a_numeric_retry_after_is_honoured_and_capped(retry_after: str, pause: float) -> None:
    scripted = Scripted([http_error(429, retry_after), b"[null]"])
    assert scripted.reads(HOLDINGS) == [None]
    assert scripted.sleeps == pytest.approx([0.2, pause])


@pytest.mark.parametrize("retry_after", ["Wed, 21 Oct 2026 07:28:00 GMT", "-5", "1.5", "", "x"])
def test_a_non_numeric_retry_after_uses_the_base_backoff(retry_after: str) -> None:
    scripted = Scripted([http_error(429, retry_after), b"[null]"])
    assert scripted.reads(HOLDINGS) == [None]
    assert scripted.sleeps == pytest.approx([0.2, 2])


def test_retry_after_is_ignored_on_a_5xx() -> None:
    scripted = Scripted([http_error(503, "25"), b"[null]"])
    assert scripted.reads(HOLDINGS) == [None]
    assert scripted.sleeps == pytest.approx([0.2, 2])


def test_a_retry_after_that_crosses_the_deadline_is_never_sent() -> None:
    scripted = Scripted([http_error(429, "30"), b"[null]"], timeout=20)
    with pytest.raises(ScanError, match="^scan deadline exhausted; no incomplete flat credit$"):
        scripted.reads({"type": "perpDexs"})
    assert scripted.opener.open.call_count == 1
    assert scripted.sleeps == pytest.approx([2])


def test_a_retried_read_inside_the_flat_scan_never_restarts_it() -> None:
    dexes = json.dumps([None, {"name": "fixture"}]).encode()
    state = json.dumps({"assetPositions": [], "marginSummary": {"accountValue": "200"}}).encode()
    scripted = Scripted([b'"disabled"', dexes, state, b"[]", state, TimeoutError(), b"[]", dexes])
    report = flat_scan(scripted.reads, ACCOUNT)
    assert report["dexes"] == ["", "fixture"]
    # Seven reads, one of them retried once: eight tries, two inventory reads, no restart.
    assert scripted.opener.open.call_count == 8 and scripted.outcomes == []
