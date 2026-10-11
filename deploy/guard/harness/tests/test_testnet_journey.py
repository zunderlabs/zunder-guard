import copy
from decimal import Decimal
from typing import Any, cast

import pytest
import test_testnet_collect as collector
import test_testnet_ownership as reference

from guard_harness.mcp_client import MCP, Tool
from guard_harness.paper_bot import LocalGuard
from guard_harness.testnet_journey import execute


class Scenario:
    def __init__(self, fail: str = "") -> None:
        fixture: Any = reference.case
        opening = fixture.__wrapped__()
        fixture = reference.closed_case
        closed = fixture.__wrapped__(copy.deepcopy(opening))
        opening[3]["stop_lookup"]["order"]["order"].update(origSz="0.0002", timestamp=1000)
        self.opening, self.closed, self.fail = opening, closed, fail
        self.fields = copy.deepcopy(opening[3])
        self.fields.update(fills=[], positions=[], orders=[])
        self.events: list[dict[str, Any]] = []
        self.writes_bound, self.close_size_bound = True, True
        self.calls: list[str] = []
        self.stopped = False

    def request(self, path: str) -> object:
        if path.startswith("/guard/events"):
            return copy.deepcopy(self.events)
        assert path == "/guard/status"
        if self.fail == "version":
            return {"mode": "mainnet"}
        return {
            "mode": "testnet",
            "network": "testnet",
            "account": collector.ACCOUNT,
            "version": "1.0.0-rc.1",
            "capabilities": {"exchange_expected_mode": True},
            "risk": {"state": "active", "journal_ready": True},
            "fee": {"mode": "off"},
            "killed": None,
            "journal_broken": False,
            "last_error": None,
            "started_at_ms": 1000,
            "last_sync_ms": 1000,
        }

    def read(self, payload: dict[str, Any]) -> object:
        value = collector.Reads(self.fields)(payload)
        if payload["type"] == "clearinghouseState":
            assert isinstance(value, dict)
            value["marginSummary"] = {"accountValue": "400"}
        return value

    def tool(
        self, name: Tool, arguments: dict[str, Any] | None = None
    ) -> tuple[dict[str, Any], bool]:
        self.calls.append(name)
        if name == "preview_order":
            return {"preview": {"verdict": "veto" if self.fail == "preview" else "allow"}}, False
        if name == "place_order":
            self.events, self.fields = (
                copy.deepcopy(self.opening[0]),
                copy.deepcopy(self.opening[3]),
            )
            if self.fail == "entry-timeout":
                raise TimeoutError("response contains a secret that must not escape")
            if self.fail == "unprotected":
                self.fields["orders"] = []
            return {"sent": True}, False
        assert name == "close_position"
        assert arguments == {"coin": "BTC", "expected_size": "0.0002"}
        if self.fail == "close-timeout":
            raise TimeoutError("response contains a secret that must not escape")
        self.events, self.fields = copy.deepcopy(self.closed[0]), copy.deepcopy(self.closed[3])
        return {"sent": True}, False

    def stop(self) -> None:
        assert self.fields["positions"] == self.fields["orders"] == []
        self.stopped = True

    def execute(self, **kwargs: Any) -> Any:
        return execute(
            cast(LocalGuard, self),
            cast(MCP, self),
            self.read,
            account=collector.ACCOUNT,
            client=self.opening[1],
            entry=self.opening[2],
            version="1.0.0-rc.1",
            process_started_ms=1000,
            stop_guard=self.stop,
            now_ms=lambda: 1000,
            **kwargs,
        )


def test_actual_collector_and_cleanup_core_prove_protection_then_flat() -> None:
    scenario = Scenario()
    result = scenario.execute()
    assert result.passed and result.guard_stopped and scenario.stopped
    assert result.protected_entry.filled == Decimal("0.0002")
    assert result.cleaned.actions == ("close_position",)
    assert scenario.calls == ["preview_order", "place_order", "close_position"]
    assert result.cleaned.flat_scan["dexes"] == ["", "fixture"]


def test_ambiguous_entry_still_cleans_owned_fills_without_retry_or_journey_credit() -> None:
    scenario = Scenario("entry-timeout")
    result = scenario.execute()
    assert not result.passed and result.guard_stopped and result.cleaned is not None
    assert result.failure == "entry_or_protection"
    assert scenario.calls.count("place_order") == 1


@pytest.mark.parametrize("failure", ["unprotected", "close-timeout"])
def test_unproved_cleanup_keeps_guard_and_never_earns_journey_credit(failure: str) -> None:
    scenario = Scenario(failure)
    result = scenario.execute()
    assert not result.passed and not result.guard_stopped and not scenario.stopped
    assert result.cleaned is None and result.failure == "cleanup_incomplete_keep_guard_running"
    assert scenario.calls.count("place_order") == 1
    assert scenario.calls.count("close_position") <= 1


@pytest.mark.parametrize("failure", ["mode-cap", "size-cap", "preview", "version"])
def test_pre_entry_refusals_send_no_orders(failure: str) -> None:
    scenario = Scenario(failure)
    if failure == "mode-cap":
        scenario.writes_bound = False
    elif failure == "size-cap":
        scenario.close_size_bound = False
    with pytest.raises(RuntimeError):
        scenario.execute()
    assert "place_order" not in scenario.calls and "close_position" not in scenario.calls
    assert not scenario.stopped


def test_no_entry_when_cleanup_budget_admission_fails_after_preview() -> None:
    scenario = Scenario()

    def refuse() -> None:
        raise RuntimeError("insufficient cleanup time")

    with pytest.raises(RuntimeError, match="insufficient cleanup time"):
        scenario.execute(admit_entry=refuse)
    assert scenario.calls == ["preview_order"]
    assert not scenario.stopped


def test_cleanup_transport_phase_starts_after_ambiguous_entry() -> None:
    scenario = Scenario("entry-timeout")
    phases: list[str] = []
    result = scenario.execute(
        admit_entry=lambda: phases.append("entry"), begin_cleanup=lambda: phases.append("cleanup")
    )
    assert phases == ["entry", "cleanup"]
    assert result.cleaned is not None and not result.passed
