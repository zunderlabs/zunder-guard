import copy
from decimal import Decimal
from typing import Any, cast

import pytest
import test_testnet_collect as collector
import test_testnet_ownership as reference

from guard_harness.mcp_client import MCP, Tool
from guard_harness.paper_bot import LocalGuard
from guard_harness.testnet_journey import admit_preview, execute
from guard_harness.testnet_protection import Entry, entry_plan


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
        self.writes_bound, self.close_size_bound, self.limit_price_ioc = True, True, True
        self.calls: list[str] = []
        self.stopped = False
        self.fee: dict[str, Any] = {"mode": "off"}
        # Public MCP preview::to_json schema: attaching Guard's default stop
        # reports resize/resized even when the planned quantity is unchanged.
        self.preview: dict[str, Any] = {
            "ok": True,
            "coin": "BTC",
            "side": "buy",
            "preview": {
                "source": "guard",
                "verdict": "resize",
                "code": "resized",
                "reason": "Guard would forward it with changes other than its size",
                "guard_quoted": "Guard attached its default stop",
                "changes_quoted": ["a reduce-only stop at 58800 (2% from 60000) is attached"],
                "requested_size": "0.0002",
                "allowed_size": "0.0002",
                "size_cut": False,
                "order_price": "60120",
                "worst_price": "60120",
                "stop_price": "58800",
                "stop_source": "guard_policy",
                "time_in_force": "ioc",
                "isolated_leverage": 3,
                "notional_usd": "12.024",
                "risk_at_stop_usd": "0.2772264",
                "risk_at_stop_pct_of_equity": "0.0693",
                "equity_usd": "400",
                "view_age_ms": 0,
                "caveats": [],
            },
        }

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
            "fee": self.fee,
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
        if name in {"preview_order", "place_order"}:
            assert arguments == {
                "coin": "BTC",
                "side": "buy",
                "stop": "guard_policy",
                "size": "0.0002",
                "limit_price": "60120",
                "time_in_force": "ioc",
            }
        if name == "preview_order":
            value = copy.deepcopy(self.preview)
            if self.fail == "preview":
                value["preview"].update(verdict="veto", code="risk", allowed_size=None)
            return value, False
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
            entry=kwargs.pop("entry", self.opening[2]),
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


@pytest.mark.parametrize("failure", ["mode-cap", "size-cap", "ioc-cap", "preview", "version"])
def test_pre_entry_refusals_send_no_orders(failure: str) -> None:
    scenario = Scenario(failure)
    if failure == "mode-cap":
        scenario.writes_bound = False
    elif failure == "size-cap":
        scenario.close_size_bound = False
    elif failure == "ioc-cap":
        scenario.limit_price_ioc = False
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


def builder_fee() -> dict[str, Any]:
    return {
        "mode": "builder",
        "address": "0x" + "2" * 40,
        "fee_tenths_bp": 20,
        "charged": True,
        "paper": False,
        "entries_blocked": False,
        "approval": {"state": "approved", "max_tenths_bp": 20, "error": None},
    }


def test_actual_approved_builder_mode_runs_same_owned_cleanup() -> None:
    scenario = Scenario()
    scenario.fee = builder_fee()
    assert scenario.execute().passed
    assert scenario.calls == ["preview_order", "place_order", "close_position"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("mode", "fee_free"),
        ("address", "invalid"),
        ("fee_tenths_bp", 21),
        ("fee_tenths_bp", True),
        ("charged", False),
        ("paper", True),
        ("entries_blocked", True),
    ],
)
def test_builder_fee_mismatch_refuses_before_any_order(field: str, value: Any) -> None:
    scenario = Scenario()
    scenario.fee = builder_fee()
    scenario.fee[field] = value
    with pytest.raises(RuntimeError):
        scenario.execute()
    assert scenario.calls == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "unchecked"),
        ("state", "not_approved"),
        ("max_tenths_bp", 19),
        ("max_tenths_bp", True),
        ("error", "unavailable"),
    ],
)
def test_unconfirmed_approval_never_reaches_preview_or_entry(field: str, value: Any) -> None:
    scenario = Scenario()
    scenario.fee = builder_fee()
    scenario.fee["approval"][field] = value
    with pytest.raises(RuntimeError):
        scenario.execute()
    assert scenario.calls == []


def test_failed_fee_observation_still_cleans_without_retry() -> None:
    scenario = Scenario()

    def fail(*args: Any) -> None:
        raise ValueError("fee not proved")

    result = scenario.execute(capture_entry=fail)
    assert not result.passed
    assert result.cleaned is not None and result.guard_stopped
    assert result.failure == "entry_or_protection"
    assert scenario.calls == ["preview_order", "place_order", "close_position"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "estimate"),
        ("verdict", "veto"),
        ("verdict", "other"),
        ("code", "allowed"),
        ("size_cut", True),
        ("size_cut", 0),
        ("size_cut", None),
        ("requested_size", "max"),
        ("requested_size", "0.0003"),
        ("allowed_size", "0.0001"),
        ("allowed_size", "0.0003"),
        ("allowed_size", 0.0002),
        ("allowed_size", "NaN"),
        ("allowed_size", None),
        ("order_price", "60121"),
        ("worst_price", "60119"),
        ("worst_price", "60121"),
        ("stop_source", "explicit"),
        ("time_in_force", "gtc"),
        ("time_in_force", None),
        ("time_in_force", "Ioc"),
        ("stop_price", "60120"),
        ("stop_price", "58799"),
        ("view_age_ms", True),
        ("view_age_ms", None),
        ("view_age_ms", -1),
        ("view_age_ms", 60001),
        ("changes_quoted", None),
        ("changes_quoted", []),
        ("changes_quoted", [3]),
        ("changes_quoted", ["a reduce-only stop at 58800 (2% from 60000) is attached"] * 2),
        ("changes_quoted", ["a reduce-only stop at 58800 (2% from 70000) is attached"]),
        ("changes_quoted", ["a reduce-only stop at 58800 (2% from 50000) is attached"]),
    ],
)
def test_protected_resize_never_admits_cut_malformed_or_unbounded_preview(
    field: str, value: Any
) -> None:
    scenario = Scenario()
    scenario.preview["preview"][field] = value
    with pytest.raises(RuntimeError):
        scenario.execute()
    assert scenario.calls == ["preview_order"] and not scenario.stopped


@pytest.mark.parametrize("field", ["ok", "coin", "side", "preview"])
def test_protected_resize_requires_exact_public_response_identity(field: str) -> None:
    scenario = Scenario()
    del scenario.preview[field]
    with pytest.raises(RuntimeError):
        scenario.execute()
    assert scenario.calls == ["preview_order"] and not scenario.stopped


def test_protected_resize_accepts_same_decimal_quantity_without_changing_entry() -> None:
    scenario = Scenario()
    scenario.preview["preview"].update(requested_size="0.00020", allowed_size="0.000200")
    result = scenario.execute()
    assert result.passed and result.protected_entry.filled == Decimal("0.0002")
    assert scenario.calls == ["preview_order", "place_order", "close_position"]


def test_preview_error_never_reaches_entry_or_cleanup_budget_admission() -> None:
    scenario = Scenario()
    original = scenario.tool

    def tool(name: Tool, arguments: dict[str, Any] | None = None) -> tuple[dict[str, Any], bool]:
        result, error = original(name, arguments)
        return result, True if name == "preview_order" else error

    scenario.tool = tool  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        scenario.execute(admit_entry=lambda: pytest.fail("no budget admission after preview error"))
    assert scenario.calls == ["preview_order"] and not scenario.stopped


@pytest.mark.parametrize(
    "field,value,phase",
    [
        ("ok", False, "preview-identity"),
        ("source", "private-body-fixture", "preview-verdict"),
        ("verdict", "veto", "preview-verdict"),
        ("allowed_size", "0", "preview-sizing"),
        ("view_age_ms", 60001, "preview-age"),
        ("changes_quoted", ["private-body-fixture"], "preview-stop-quote"),
        ("stop_price", "0", "preview-stop-price"),
    ],
)
def test_preview_failure_reports_only_its_fixed_admission_phase(
    field: str, value: Any, phase: str
) -> None:
    scenario = Scenario()
    (scenario.preview if field == "ok" else scenario.preview["preview"])[field] = value
    phases: list[str] = []
    with pytest.raises(RuntimeError):
        scenario.execute(observe_phase=phases.append)
    assert phases[-1] == phase
    assert "private-body-fixture" not in repr(phases)
    assert scenario.calls == ["preview_order"] and not scenario.stopped


def test_long_flat_scan_precedes_fresh_planning_and_stale_plan_remains_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = Scenario()
    clock = [1000]
    timeline: list[str] = []
    markets = [{"name": "BTC", "szDecimals": 5, "isDelisted": False}]
    old_entry = entry_plan(markets, {"BTC": "60000"})
    fresh = entry_plan(markets, {"BTC": "60200"})
    assert fresh.limit > old_entry.limit and fresh.size == old_entry.size

    def scan(read: Any, account: str) -> dict[str, Any]:
        assert timeline == [] and account == collector.ACCOUNT
        timeline.append("flat-scan")
        clock[0] += 12 * 60 * 1000
        return {"flat": True}

    def plan() -> Entry:
        assert timeline == ["flat-scan"] and clock[0] == 721000
        timeline.append("fresh-plan")
        return entry_plan(markets, {"BTC": "60200"})

    measured = copy.deepcopy(scenario.preview)
    measured["preview"].update(
        requested_size=str(fresh.size),
        allowed_size=str(fresh.size),
        order_price=str(old_entry.limit),
        worst_price=str(old_entry.limit),
        stop_price="58996",
        changes_quoted=["a reduce-only stop at 58996 (2% from 60200) is attached"],
    )
    phases: list[str] = []
    with pytest.raises(RuntimeError):
        admit_preview(measured, old_entry, observe_phase=phases.append)
    assert phases[-1] == "preview-price-bound"  # Preserve the original strict price predicate.
    measured["preview"].update(order_price=str(fresh.limit), worst_price=str(fresh.limit))

    def preview(name: Tool, arguments: dict[str, Any] | None = None) -> tuple[dict[str, Any], bool]:
        assert timeline == ["flat-scan", "fresh-plan"]
        assert name == "preview_order"
        assert arguments is not None
        assert arguments["limit_price"] == str(fresh.limit)
        assert arguments["size"] == str(fresh.size) and arguments["time_in_force"] == "ioc"
        scenario.calls.append(name)
        timeline.append("preview")
        return measured, False

    def stop_before_entry() -> None:
        raise RuntimeError("offline stop at the unchanged entry budget boundary")

    monkeypatch.setattr("guard_harness.testnet_journey.flat_scan", scan)
    scenario.tool = preview  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="unchanged entry budget boundary"):
        execute(
            cast(LocalGuard, scenario),
            cast(MCP, scenario),
            scenario.read,
            account=collector.ACCOUNT,
            client=scenario.opening[1],
            entry=plan,
            version="1.0.0-rc.1",
            process_started_ms=1000,
            stop_guard=scenario.stop,
            now_ms=lambda: clock[0],
            admit_entry=stop_before_entry,
        )
    assert timeline == ["flat-scan", "fresh-plan", "preview"]
    assert scenario.calls == ["preview_order"] and not scenario.stopped


def test_failed_flat_scan_never_invokes_planner_or_preview(monkeypatch: pytest.MonkeyPatch) -> None:
    scenario = Scenario()

    def refuse(*args: Any) -> dict[str, Any]:
        raise RuntimeError("offline scan refusal")

    monkeypatch.setattr("guard_harness.testnet_journey.flat_scan", refuse)
    with pytest.raises(RuntimeError, match="offline scan refusal"):
        scenario.execute(entry=lambda: pytest.fail("no market planning after unknown flat scan"))
    assert scenario.calls == [] and not scenario.stopped


@pytest.mark.parametrize("secondary", ["position", "unreadable", "inventory"])
def test_secondary_final_uncertainty_does_not_block_owned_main_reduce_but_refuses_guard_stop(
    secondary: str,
) -> None:
    scenario = Scenario()
    original = scenario.read
    inventories = 0

    def read(payload: dict[str, Any]) -> object:
        nonlocal inventories
        kind = payload["type"]
        if kind == "perpDexs":
            inventories += 1
            if inventories == 3 and secondary == "inventory":
                return [None, {"name": "fixture"}, {"name": "changed"}]
        if "close_position" in scenario.calls and payload.get("dex"):
            if secondary == "unreadable":
                return None
            if secondary == "position" and kind == "clearinghouseState":
                return {
                    "assetPositions": [{"position": {"coin": "fixture:OTHER", "szi": "1"}}],
                    "marginSummary": {"accountValue": "0"},
                }
        if "close_position" in scenario.calls and secondary == "inventory" and inventories >= 4:
            return [None] if kind == "perpDexs" else original(payload)
        return original(payload)

    scenario.read = read  # type: ignore[method-assign]
    result = scenario.execute()
    assert scenario.calls == ["preview_order", "place_order", "close_position"]
    assert not result.passed and not result.guard_stopped and not scenario.stopped
    assert scenario.fields["positions"] == []
    assert result.cleaned is None


def test_shared_work_deadline_response_overrun_never_attempts_next_mutation() -> None:
    scenario = Scenario()
    checks = [0]

    def exhausted() -> None:
        checks[0] += 1
        if checks[0] >= 3:
            raise RuntimeError("absolute owned-work deadline expired")

    result = scenario.execute(check_owned_work=exhausted)
    assert not result.passed and not result.guard_stopped
    assert scenario.calls == ["preview_order", "place_order"]


@pytest.mark.parametrize("stalled_hook", ["attempt", "phase"])
def test_durable_persistence_stall_expires_work_before_entry_send(stalled_hook: str) -> None:
    scenario = Scenario()
    clock = [0.0]
    absolute = 1280.0

    def check() -> None:
        if clock[0] >= absolute:
            raise RuntimeError("shared owned work expired")

    def record(entry: Entry, begun: int) -> None:
        assert "place_order" not in scenario.calls and begun == 1000
        if stalled_hook == "attempt":
            clock[0] = absolute

    def phase(value: str) -> None:
        if value == "entry-attempt" and stalled_hook == "phase":
            clock[0] = absolute

    if stalled_hook == "attempt":
        with pytest.raises(RuntimeError, match="shared owned work expired"):
            scenario.execute(record_attempt=record, observe_phase=phase, check_owned_work=check)
    else:
        result = scenario.execute(
            record_attempt=record, observe_phase=phase, check_owned_work=check
        )
        assert not result.passed and not result.guard_stopped
    assert scenario.calls == ["preview_order"]
    assert not scenario.stopped


def test_owned_snapshot_persistence_stall_prevents_collection_and_close() -> None:
    scenario = Scenario()
    clock = [0.0]
    paced_after_entry = [0]
    reader = scenario.read

    def check() -> None:
        if clock[0] >= 1280:
            raise RuntimeError("shared owned work expired")

    def persist(events: Any, entry: Entry, begun: int) -> None:
        clock[0] = 1280

    def read(payload: dict[str, Any]) -> object:
        if "place_order" in scenario.calls:
            paced_after_entry[0] += 1
        return reader(payload)

    scenario.read = read  # type: ignore[method-assign]
    result = scenario.execute(persist_ownership=persist, check_owned_work=check)
    assert not result.passed and not result.guard_stopped
    assert scenario.calls == ["preview_order", "place_order"]
    assert paced_after_entry[0] == 0


def test_warming_follows_complete_flat_scan_before_fresh_plan_and_keeps_single_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = Scenario()
    timeline: list[str] = []
    original = __import__("guard_harness.testnet_journey", fromlist=["flat_scan"]).flat_scan

    def scan(read: Any, account: str) -> Any:
        result = original(read, account)
        timeline.append("full-flat")
        return result

    def warming(client: str) -> tuple[object, Any]:
        assert client == scenario.opening[1].lower() and timeline == ["full-flat"]
        timeline.append("warm")
        return scenario.request("/guard/status"), lambda: None

    def plan() -> Entry:
        assert timeline == ["full-flat", "warm"]
        timeline.append("fresh-plan")
        return scenario.opening[2]  # type: ignore[no-any-return]

    monkeypatch.setattr("guard_harness.testnet_journey.flat_scan", scan)
    result = scenario.execute(entry=plan, warm_info=warming)
    assert result.passed and timeline[:3] == ["full-flat", "warm", "fresh-plan"]
    assert scenario.calls.count("place_order") == 1


@pytest.mark.parametrize("stall", ["plan", "preview", "attempt-fsync", "entry-phase-fsync"])
def test_stale_warm_performance_refuses_before_single_place_call(stall: str) -> None:
    scenario = Scenario()
    stale = [False]
    original = scenario.tool

    def check() -> None:
        if stale[0]:
            raise RuntimeError("owned Guard info warm prerequisite refused")

    def warming(client: str) -> tuple[object, Any]:
        return scenario.request("/guard/status"), check

    def plan() -> Entry:
        stale[0] = stall == "plan"
        return scenario.opening[2]  # type: ignore[no-any-return]

    def tool(name: Tool, arguments: dict[str, Any] | None = None) -> tuple[dict[str, Any], bool]:
        result = original(name, arguments)
        if name == "preview_order" and stall == "preview":
            stale[0] = True
        return result

    def record(entry: Entry, at: int) -> None:
        if stall == "attempt-fsync":
            stale[0] = True

    def phase(name: str) -> None:
        if name == "entry-attempt" and stall == "entry-phase-fsync":
            stale[0] = True

    scenario.tool = tool  # type: ignore[method-assign]
    if stall == "entry-phase-fsync":
        result = scenario.execute(
            entry=plan, warm_info=warming, record_attempt=record, observe_phase=phase
        )
        assert not result.passed and not result.guard_stopped
    else:
        with pytest.raises(RuntimeError, match="owned Guard info warm prerequisite refused"):
            scenario.execute(
                entry=plan, warm_info=warming, record_attempt=record, observe_phase=phase
            )
    assert "place_order" not in scenario.calls and "close_position" not in scenario.calls
    assert not scenario.stopped


@pytest.mark.parametrize(
    "field,value", [("mode", "mainnet"), ("last_error", "PRIVATE"), ("killed", "PRIVATE")]
)
def test_identical_status_safety_admission_rechecked_after_warm_before_planning(
    field: str, value: Any
) -> None:
    scenario = Scenario()
    status = scenario.request("/guard/status")
    assert isinstance(status, dict)
    status[field] = value
    with pytest.raises(RuntimeError):
        scenario.execute(
            warm_info=lambda client: (status, lambda: None),
            entry=lambda: pytest.fail("no plan after unsafe post-warm status"),
        )
    assert not scenario.calls and not scenario.stopped
