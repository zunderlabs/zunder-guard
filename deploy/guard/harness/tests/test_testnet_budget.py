"""Real pacer counterexample and conservative universal carry bound for owned work."""

import json
from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock

import pytest

from guard_harness.testnet_process import ENTRY_REMAINING, OWNED_WORK_TIMEOUT
from guard_harness.testnet_scan import SCAN_TIMEOUT, ScanError, flat_scan
from guard_harness.testnet_scan import TestnetReads as Reads

ACCOUNT = "0x" + "12" * 20
CLOID = "0x7a6d" + "a" * 28


def frame(prior: int) -> list[dict[str, object]]:
    return [
        {"type": "userAbstraction", "user": ACCOUNT},
        {"type": "meta"},
        {"type": "orderStatus", "user": ACCOUNT, "oid": CLOID},
        {"type": "userFillsByTime", "user": ACCOUNT, "startTime": 1000},
        {"type": "clearinghouseState", "user": ACCOUNT},
        {"type": "frontendOpenOrders", "user": ACCOUNT},
        {"type": "orderStatus", "user": ACCOUNT, "oid": CLOID},
        *({"type": "orderStatus", "user": ACCOUNT, "oid": CLOID} for _ in range(prior)),
        {"type": "clearinghouseState", "user": ACCOUNT},
        {"type": "frontendOpenOrders", "user": ACCOUNT},
        {"type": "userFillsByTime", "user": ACCOUNT, "startTime": 1000},
    ]


def transport(now: list[float], latency: float) -> Reads:
    def sleep(seconds: float) -> None:
        assert seconds >= 0
        now[0] += seconds

    def opened(request: Any, **kwargs: Any) -> MagicMock:
        assert kwargs["timeout"] == 10
        now[0] += latency
        kind = json.loads(request.data)["type"]
        value: object = (
            [None, *({"name": f"fixture{n}"} for n in range(269))]
            if kind == "perpDexs"
            else "disabled"
            if kind == "userAbstraction"
            else {"assetPositions": [], "marginSummary": {"accountValue": "200"}}
            if kind == "clearinghouseState"
            else []
        )
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(value).encode()
        return response

    reads = Reads(clock=lambda: now[0], sleep=sleep)
    reads.opener = MagicMock()
    reads.opener.open.side_effect = opened
    return reads


def trace() -> list[dict[str, object]]:
    result = frame(0)
    result.append({"type": "userFillsByTime", "user": ACCOUNT, "startTime": 1000})
    for prior in (0, 1, 2, 3, 3):
        result.extend(frame(prior))
    assert len(result) == 70
    return result


def test_exact_empty_prefix_trace_and_universal_shift_prove_1280_reserve() -> None:
    # Any valid retained reservation expires by t0+60.001. Shifting this empty-prefix
    # feasible greedy schedule by 60.001 dominates the actual pacer: by induction each
    # earlier own reservation also expires earlier. Extra HTTP/local/MCP delay cannot
    # increase the minimum wait; add their whole-response bounds conservatively.
    now = [0.0]
    reads = transport(now, 0)
    for payload in trace():
        reads(payload)
    assert now[0] == pytest.approx(242.403)
    paced_bound = Decimal("242.403") + Decimal("60.001")
    work_bound = paced_bound + Decimal(70 * 10 + 7 * 5 + 5 * 45)
    assert work_bound == Decimal("1262.404")
    assert work_bound < OWNED_WORK_TIMEOUT == 1280
    assert ENTRY_REMAINING == OWNED_WORK_TIMEOUT + SCAN_TIMEOUT + 60 == 3140
    assert SCAN_TIMEOUT + ENTRY_REMAINING + SCAN_TIMEOUT + 90 == 6830 < 7200


@pytest.mark.parametrize("latency", [0, 0.001, 1, 10])
@pytest.mark.parametrize("carry", [False, True])
def test_real_pacer_all_70_reads_keep_weight_and_shared_work_bound(
    latency: float, carry: bool
) -> None:
    now = [0.0]
    reads = transport(now, latency)
    if carry:
        # Deliberately dominating any sequential preflight's still-live reservations.
        reads.reservations = [(0, 120)] * 5
    reads.start_phase(timeout=OWNED_WORK_TIMEOUT)
    for payload in trace():
        reads(payload)
        assert sum(cost for _, cost in reads.reservations) <= 600
    assert now[0] <= 302.404 + 70 * latency + 0.01


def test_270_dex_preflight_and_final_scan_surround_bounded_main_work() -> None:
    now = [0.0]
    reads = transport(now, 0.001)
    preflight = flat_scan(reads, ACCOUNT)
    assert len(preflight["dexes"]) == 270  # type: ignore[arg-type]
    begin = now[0]
    reads.start_phase(timeout=OWNED_WORK_TIMEOUT)
    for payload in trace():
        reads(payload)
    assert now[0] - begin < OWNED_WORK_TIMEOUT
    reads.start_phase(timeout=SCAN_TIMEOUT)
    final = flat_scan(reads, ACCOUNT)
    assert len(final["observations"]) == 270  # type: ignore[arg-type]
    assert now[0] < 7200 - (SCAN_TIMEOUT + 90)


def test_old_full_inventory_180_second_post_entry_window_counterexample() -> None:
    now = [0.0]
    reads = transport(now, 0)
    flat_scan(reads, ACCOUNT)
    reads.start_phase(timeout=180)
    with pytest.raises(ScanError, match="deadline"):
        # The old collector repeated both holdings/order reads across all 270 DEXes.
        for dex in range(270):
            fields = {"user": ACCOUNT, **({"dex": f"fixture{dex}"} if dex else {})}
            reads({"type": "clearinghouseState", **fields})
            reads({"type": "frontendOpenOrders", **fields})
