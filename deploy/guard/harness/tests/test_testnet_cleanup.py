from decimal import Decimal
from typing import Any

import pytest

from guard_harness.mcp_client import Tool
from guard_harness.testnet_cleanup import CleanupError, cleanup
from guard_harness.testnet_ownership import Ownership


class Tools:
    def __init__(self, fail: str = "") -> None:
        self.calls: list[tuple[Tool, dict[str, Any] | None]] = []
        self.fail = fail

    def tool(
        self, name: Tool, arguments: dict[str, Any] | None = None
    ) -> tuple[dict[str, Any], bool]:
        self.calls.append((name, arguments))
        if self.fail == "timeout":
            raise TimeoutError("withheld response")
        return {"sent": self.fail != "unsent"}, self.fail == "error"


def observation(remaining: str, stop: int | None = 42) -> Ownership:
    return Ownership(41, stop, Decimal("0.0002"), Decimal(remaining), False)


def test_close_then_orphan_cancel_and_independent_scan_each_after_fresh_proof() -> None:
    # .0002 BTC owned -> .0001 after partial sell -> 0 after final sell. Never cancel
    # the stop before net exposure is exactly zero, never send a size from an old read.
    states = iter(
        [observation("0.0002"), observation("0.0001"), observation("0"), observation("0", None)]
    )
    calls: list[str] = []
    tools = Tools()

    def observe() -> Ownership:
        calls.append("observe")
        return next(states)

    def scan() -> dict[str, object]:
        calls.append("scan")
        assert len(tools.calls) == 3
        return {"network": "testnet", "complete": True}

    result = cleanup(observe, tools, scan)
    assert calls == ["observe"] * 4 + ["scan"]
    assert tools.calls == [
        ("close_position", {"coin": "BTC", "expected_size": "0.0002"}),
        ("close_position", {"coin": "BTC", "expected_size": "0.0001"}),
        ("cancel_order", {"coin": "BTC", "order_id": 42}),
    ]
    assert result.actions == ("close_position", "close_position", "cancel_order")


def test_unfilled_entry_is_canceled_only_by_proved_oid_then_independent_scan() -> None:
    states = iter(
        [
            Ownership(41, None, Decimal(0), Decimal(0), True),
            Ownership(41, None, Decimal(0), Decimal(0), False),
        ]
    )
    tools = Tools()
    assert cleanup(lambda: next(states), tools, lambda: {"complete": True}).actions == (
        "cancel_order",
    )
    assert tools.calls == [("cancel_order", {"coin": "BTC", "order_id": 41})]


@pytest.mark.parametrize("failure", ["error", "unsent", "timeout"])
def test_uncertain_write_is_never_retried_and_stop_is_preserved(failure: str) -> None:
    tools = Tools(failure)
    with pytest.raises((CleanupError, TimeoutError)):
        cleanup(lambda: observation("0.0002"), tools, lambda: pytest.fail("no flat credit"))
    assert len(tools.calls) == 1 and tools.calls[0][0] == "close_position"


@pytest.mark.parametrize("remaining,oid", [("0.0002", 41), ("0.0003", 41), ("0.0001", 99)])
def test_no_progress_or_changed_identity_never_cancels_stop(remaining: str, oid: int) -> None:
    after = observation(remaining)
    states = iter([observation("0.0002"), Ownership(oid, 42, after.filled, after.remaining, False)])
    tools = Tools()
    with pytest.raises(CleanupError):
        cleanup(lambda: next(states), tools, lambda: pytest.fail("no flat credit"))
    assert len(tools.calls) == 1 and tools.calls[0][0] == "close_position"


def test_three_successful_partial_closes_exhaust_budget_without_stop_cancel() -> None:
    states = iter([observation(n) for n in ("0.0002", "0.00015", "0.0001", "0.00005")])
    tools = Tools()
    with pytest.raises(CleanupError, match="exhausted"):
        cleanup(lambda: next(states), tools, lambda: pytest.fail("no flat credit"))
    assert [name for name, _ in tools.calls] == ["close_position"] * 3


def test_flat_observation_alone_never_replaces_independent_all_dex_scan() -> None:
    tools = Tools()

    def blocked() -> dict[str, object]:
        raise RuntimeError("secondary exposure")

    with pytest.raises(RuntimeError, match="secondary exposure"):
        cleanup(lambda: observation("0", None), tools, blocked)
    assert not tools.calls


def test_collection_deadline_prevents_mutation() -> None:
    ticks = iter([0.0, 0.0, 1.0])
    tools = Tools()
    with pytest.raises(CleanupError, match="deadline"):
        cleanup(
            lambda: observation("0.0002"), tools, lambda: {}, clock=lambda: next(ticks), timeout=1
        )
    assert not tools.calls


def test_orphan_cancel_must_be_observed_before_flat_credit() -> None:
    tools = Tools()
    with pytest.raises(CleanupError, match="orphan cancellation"):
        cleanup(lambda: observation("0"), tools, lambda: pytest.fail("no flat credit"))
    assert tools.calls == [("cancel_order", {"coin": "BTC", "order_id": 42})]
