import copy
import json
from pathlib import Path
from typing import Any, cast

import pytest
from test_testnet_journey import Scenario

from guard_harness.mcp_client import MCP
from guard_harness.paper_bot import LocalGuard
from guard_harness.testnet_journey import execute
from guard_harness.testnet_snapshot import OwnershipStore, ownership_subset


@pytest.fixture
def scenario() -> Scenario:
    return Scenario()


def test_durable_subset_omits_started_accounts_free_text_and_preserves_run_wires(
    scenario: Scenario,
    tmp_path: Path,
) -> None:
    events, client, entry, _ = scenario.opening
    events = copy.deepcopy(events)
    events[0].update(text="PRIVATE-SENTINEL", signed_as="testnet")
    events.insert(0, {"kind": "started", "seq": 0, "account": "PRIVATE-ACCOUNT"})
    # Raw Started events are excluded by the caller's post-baseline read.
    store = OwnershipStore(
        tmp_path, account="0x" + "2" * 40, client=client, source="a" * 64, version="1.0.0-rc.14"
    )
    store.begin(entry, 1000)
    store.capture(events[1:], entry, 1000)
    value = json.loads((tmp_path / "ownership.json").read_bytes())
    encoded = json.dumps(value)
    assert "PRIVATE" not in encoded and "0x" + "2" * 40 not in encoded
    assert value["gate_eligible"] is False and value["started_ms"] == 1000
    assert value["entry_outcome"] == "unknown" and len(value["attempt_id"]) == 32
    assert value["events"][0]["request"] == scenario.opening[0][0]["request"]
    assert (tmp_path / "ownership.json").stat().st_mode & 0o777 == 0o600
    assert not (tmp_path / "ownership.pending").exists()
    with pytest.raises(RuntimeError):
        store.begin(entry, 1000)  # No second attempt record or transmission.


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate",
        "foreign",
        "missing-ack",
        "private-field",
        "wire-extra",
        "bad-stop",
        "bad-price",
        "wrong-network",
    ],
)
def test_missing_or_ambiguous_evidence_never_becomes_durable_ownership(
    scenario: Scenario,
    tmp_path: Path,
    mutation: str,
) -> None:
    events, client, entry, _ = copy.deepcopy(scenario.opening)
    if mutation == "duplicate":
        events.append(copy.deepcopy(events[0]))
    elif mutation == "foreign":
        events[0]["client"] = "0x" + "f" * 40
    elif mutation == "missing-ack":
        events.pop()
    elif mutation == "private-field":
        events[0]["private_key"] = "PRIVATE-SENTINEL"
    elif mutation == "wire-extra":
        events[0]["forward"]["orders"][0]["account"] = "PRIVATE-ACCOUNT"
    elif mutation == "bad-stop":
        events[0]["forward"]["orders"][1]["t"]["trigger"]["triggerPx"] = "59000"
    elif mutation == "bad-price":
        events[0]["request"]["orders"][0]["p"] = "60121"
    else:
        events[0]["signed_as"] = "mainnet"
    store = OwnershipStore(
        tmp_path, account="0x" + "2" * 40, client=client, source="a" * 64, version="1.0.0-rc.14"
    )
    store.begin(entry, 1000)
    with pytest.raises(RuntimeError):
        store.capture(events, entry, 1000)
    assert (tmp_path / "entry-attempt.json").exists()
    assert not (tmp_path / "ownership.json").exists()


def test_snapshot_can_accept_actual_pre_entry_isolated_setup_and_order_ack(
    scenario: Scenario,
) -> None:
    events, client, entry, _ = copy.deepcopy(scenario.opening)
    events[0]["pre"] = [
        {"type": "updateLeverage", "asset": entry.asset, "isCross": False, "leverage": 3}
    ]
    events[0]["forward"]["builder"] = {"b": "0x" + "2" * 40, "f": 20}
    selected = ownership_subset(events, client, entry)
    assert "builder" not in selected[0]["forward"]
    assert "pre" not in selected[0]  # No extra authority; venue proves isolated ownership.


@pytest.mark.parametrize("failure", ["", "entry-timeout"])
def test_persist_attempt_before_send_and_snapshot_before_first_paced_collection(
    tmp_path: Path,
    failure: str,
) -> None:
    scenario = Scenario(failure)
    _, client, entry, _ = scenario.opening
    store = OwnershipStore(
        tmp_path, account="0x" + "2" * 40, client=client, source="a" * 64, version="1.0.0-rc.14"
    )
    reader = scenario.read
    tool = scenario.tool
    entered = False

    def read(payload: dict[str, Any]) -> object:
        if entered:
            assert (tmp_path / "ownership.json").exists()
        return reader(payload)

    def mutate(name: Any, arguments: Any = None) -> Any:
        nonlocal entered
        if name == "place_order":
            assert (tmp_path / "entry-attempt.json").exists()
            entered = True
        return tool(name, arguments)

    scenario.tool = mutate  # type: ignore[method-assign]
    result = execute(
        cast(LocalGuard, scenario),
        cast(MCP, scenario),
        read,
        account="0x" + "12" * 20,
        client=client,
        entry=entry,
        version="1.0.0-rc.1",
        process_started_ms=1000,
        stop_guard=scenario.stop,
        now_ms=lambda: 1000,
        record_attempt=store.begin,
        persist_ownership=store.capture,
    )
    assert result.cleaned is not None and result.guard_stopped
    assert result.passed is (failure == "")
    assert scenario.calls.count("place_order") == 1
    assert len(json.loads((tmp_path / "ownership.json").read_bytes())["events"]) == 5


def test_missing_attempt_never_authorizes_capture(scenario: Scenario, tmp_path: Path) -> None:
    events, client, entry, _ = scenario.opening
    store = OwnershipStore(
        tmp_path, account="0x" + "2" * 40, client=client, source="a" * 64, version="1.0.0-rc.14"
    )
    with pytest.raises(RuntimeError):
        store.capture(events, entry, 1000)
    assert not (tmp_path / "ownership.json").exists()
