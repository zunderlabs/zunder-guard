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


@pytest.mark.parametrize("cause", ["unsupported", "guard-refusal", "venue-refusal", "unknown"])
def test_immediate_finite_entry_response_distinguishes_refusals_without_cleanup_authority(
    tmp_path: Path, cause: str
) -> None:
    scenario = Scenario()
    client, entry = scenario.opening[1:3]
    store = OwnershipStore(
        tmp_path, account="0x" + "2" * 40, client=client, source="a" * 64, version="1.0.0-rc.14"
    )
    original = scenario.tool
    replies: dict[str, dict[str, object]] = {
        "unsupported": {
            "ok": False,
            "sent": False,
            "error": {"code": "expected_mode_unsupported", "reason": "PRIVATE-SIGNATURE"},
        },
        "guard-refusal": {
            "ok": False,
            "sent": False,
            "outcome": "vetoed_by_guard",
            "error": {"code": "daily_loss_stop", "reason": "PRIVATE-SIGNATURE"},
        },
        "venue-refusal": {
            "ok": False,
            "sent": True,
            "outcome": "venue_refused",
            "error": {"code": "venue_refused", "reason": "PRIVATE-SIGNATURE"},
        },
        "unknown": {
            "ok": False,
            "sent": None,
            "outcome": "unknown",
            "error": {"code": "outcome_unknown", "reason": "PRIVATE-SIGNATURE"},
        },
    }

    def tool(name: Any, arguments: Any = None) -> Any:
        if name != "place_order":
            return original(name, arguments)
        scenario.calls.append(name)
        assert (tmp_path / "entry-attempt.json").exists()
        return {**replies[cause], "quoted_text": "PRIVATE-ACCOUNT-KEY-SIGNATURE"}, True

    scenario.tool = tool  # type: ignore[method-assign]
    result = scenario.execute(
        record_attempt=store.begin, persist_ownership=store.capture, persist_response=store.response
    )
    response = json.loads((tmp_path / "entry-response.json").read_text())
    assert (
        response["category"]
        == {
            "unsupported": "unsupported",
            "guard-refusal": "vetoed",
            "venue-refusal": "venue_refused",
            "unknown": "outcome_unknown",
        }[cause]
    )
    assert response["isError"] is True and response["ok"] is False
    assert response["sent"] is replies[cause]["sent"] and response["gate_eligible"] is False
    assert response["stage"] == "ownership-validation-refused"
    assert response["origin"] == "ownership-validation"
    assert (
        "PRIVATE" not in json.dumps(response)
        and "client" not in response
        and "account" not in response
    )
    assert not (tmp_path / "ownership.json").exists()
    assert scenario.fields["positions"] == scenario.fields["orders"] == []
    assert scenario.calls == ["preview_order", "place_order"]
    assert result.failure == "cleanup_incomplete_keep_guard_running" and not result.guard_stopped


def test_finite_entry_fields_never_copy_unknown_codes_booleans_or_body(tmp_path: Path) -> None:
    from guard_harness.testnet_snapshot import entry_response

    value = entry_response(
        {
            "ok": 1,
            "sent": "PRIVATE-ACCOUNT",
            "code": "PRIVATE-KEY",
            "outcome": "PRIVATE-SIGNATURE",
            "guard_decision": {"private": "PRIVATE-KEY"},
        },
        True,
    )
    assert value == {
        "response_available": True,
        "isError": True,
        "ok": None,
        "sent": None,
        "code": "unknown",
        "outcome": "unknown",
        "category": "unknown",
    }
    assert "PRIVATE" not in json.dumps(value)


@pytest.mark.parametrize(
    "nested,top,expected,category",
    [
        ("no_client_key", "expected_mode_unsupported", "no_client_key", "refused_before_send"),
        ("outcome_unknown", "preview_unsupported", "outcome_unknown", "outcome_unknown"),
        (
            "expected_mode_unsupported",
            "outcome_unknown",
            "expected_mode_unsupported",
            "unsupported",
        ),
        ("fee_not_approved", "preview_unsupported", "fee_not_approved", "refused_before_send"),
        ("PRIVATE-ACCOUNT-KEY", "preview_unsupported", "unknown", "refused_before_send"),
        ({"private": "PRIVATE-SIGNATURE"}, "preview_unsupported", "unknown", "refused_before_send"),
        (None, "preview_unsupported", "unknown", "refused_before_send"),
    ],
)
def test_shipped_nested_error_code_wins_without_copying_reason_or_top_level_conflicts(
    nested: object, top: str, expected: str, category: str
) -> None:
    from guard_harness.testnet_snapshot import entry_response

    observed = entry_response(
        {
            "ok": False,
            "sent": False,
            "code": top,
            "error": {"code": nested, "reason": "PRIVATE-ACCOUNT-KEY-SIGNATURE"},
            "guard_quoted": {"account": "PRIVATE-ACCOUNT-KEY-SIGNATURE"},
        },
        True,
    )
    assert observed["code"] == expected and observed["category"] == category
    assert observed["sent"] is False and observed["isError"] is True
    assert "PRIVATE" not in json.dumps(observed)


@pytest.mark.parametrize("detail", [None, [], "PRIVATE-KEY", 1])
def test_malformed_nested_error_never_uses_a_conflicting_top_level_code(detail: object) -> None:
    from guard_harness.testnet_snapshot import entry_response

    observed = entry_response(
        {"ok": False, "sent": False, "code": "preview_unsupported", "error": detail}, True
    )
    assert observed["code"] == "unknown"
    assert observed["category"] == "refused_before_send"
    assert "PRIVATE" not in json.dumps(observed)


def test_top_level_code_only_matches_the_actual_shipped_paper_reply_schema() -> None:
    from guard_harness.testnet_snapshot import entry_response

    body = {"ok": True, "sent": False, "outcome": "paper_mode_not_sent", "code": "allowed"}
    assert entry_response(body, False)["code"] == "allowed"
    assert entry_response(body, True)["code"] == "unknown"
    assert entry_response(dict(body, error={"code": "no_client_key"}), False)["code"] == "unknown"
    assert (
        entry_response({"ok": False, "sent": False, "code": "preview_unsupported"}, True)["code"]
        == "unknown"
    )


def test_dynamic_guard_preview_and_sanity_codes_are_pinned_to_public_shipped_sources() -> None:
    import re

    from guard_harness.testnet_snapshot import ENTRY_CODES, entry_response

    source = Path(__file__).resolve().parents[4] / "crates/zunder-guard-mcp/src"
    known = (source / "contract.rs").read_text().split("fn known_reason(code: &str)", 1)[1]
    known = known.split("/// The result of pulling", 1)[0]
    preview = (source / "preview.rs").read_text().split("pub fn sanity(", 1)[1]
    preview = preview.split("///", 1)[0]
    codes = set(re.findall(r'"([a-z_]+)"', known)) | set(re.findall(r'Err\("([a-z_]+)"\)', preview))
    assert {
        "fee_not_approved",
        "stop_required",
        "open_risk",
        "absurd_price",
        "absurd_size",
    } <= codes
    assert codes <= ENTRY_CODES
    for code in codes:
        observed = entry_response(
            {"ok": False, "sent": False, "error": {"code": code, "reason": "PRIVATE-KEY"}},
            True,
        )
        assert observed["code"] == code and observed["sent"] is False
        assert "PRIVATE" not in json.dumps(observed)


@pytest.mark.parametrize("failure", ["", "entry-timeout"])
def test_response_fsynced_before_postentry_predicate_or_first_paced_collection(
    tmp_path: Path, failure: str
) -> None:
    scenario = Scenario(failure)
    client, entry = scenario.opening[1:3]
    store = OwnershipStore(
        tmp_path, account="0x" + "2" * 40, client=client, source="a" * 64, version="1.0.0-rc.14"
    )
    reader = scenario.read
    attempted = False
    tool = scenario.tool

    def mutate(name: Any, arguments: Any = None) -> Any:
        nonlocal attempted
        if name == "place_order":
            attempted = True
        return tool(name, arguments)

    def read(payload: dict[str, Any]) -> object:
        if attempted:
            evidence = json.loads((tmp_path / "entry-response.json").read_text())
            assert evidence["stage"] == "venue-collection" and evidence["gate_eligible"] is False
            assert (tmp_path / "ownership.json").exists()
        return reader(payload)

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
        persist_response=store.response,
    )
    evidence = json.loads((tmp_path / "entry-response.json").read_text())
    assert evidence["response_available"] is (failure == "")
    assert scenario.calls.count("place_order") == 1 and result.guard_stopped
    assert result.passed is (failure == "")
    assert (tmp_path / "entry-response.json").stat().st_mode & 0o777 == 0o600


def test_capture_storage_failure_has_fixed_origin_without_raw_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario = Scenario()
    client, entry = scenario.opening[1:3]
    store = OwnershipStore(
        tmp_path, account="0x" + "2" * 40, client=client, source="a" * 64, version="1.0.0-rc.14"
    )

    def failed(*_: object) -> None:
        raise OSError("PRIVATE-KEY-ACCOUNT")

    result = scenario.execute(
        record_attempt=store.begin, persist_ownership=failed, persist_response=store.response
    )
    evidence = json.loads((tmp_path / "entry-response.json").read_text())
    assert (
        evidence["stage"] == "ownership-storage-failed"
        and evidence["origin"] == "ownership-storage"
    )
    assert "PRIVATE" not in json.dumps(evidence) and not result.guard_stopped
    assert not (tmp_path / "ownership.json").exists() and scenario.calls.count("place_order") == 1


def test_unknown_capture_stage_cannot_replace_finite_evidence(tmp_path: Path) -> None:
    scenario = Scenario()
    client, entry = scenario.opening[1:3]
    store = OwnershipStore(
        tmp_path, account="0x" + "2" * 40, client=client, source="a" * 64, version="1.0.0-rc.14"
    )
    store.begin(entry, 1000)
    store.response(
        {"sent": False, "ok": False, "outcome": "vetoed_by_guard"}, True, "entry-response"
    )
    before = (tmp_path / "entry-response.json").read_bytes()
    with pytest.raises(RuntimeError):
        store.response(None, None, "PRIVATE-KEY")
    assert (tmp_path / "entry-response.json").read_bytes() == before


def test_stalled_response_fsync_cannot_continue_paced_reads_or_mutations(tmp_path: Path) -> None:
    scenario = Scenario()
    client, entry = scenario.opening[1:3]
    store = OwnershipStore(
        tmp_path, account="0x" + "2" * 40, client=client, source="a" * 64, version="1.0.0-rc.14"
    )
    expired = False
    reads = scenario.read

    def read(payload: dict[str, Any]) -> object:
        assert not expired, "paced venue read after expired response persistence"
        return reads(payload)

    def response(value: object, error: bool | None, stage: str) -> None:
        nonlocal expired
        store.response(value, error, stage)
        if stage == "entry-response":
            expired = True

    def check() -> None:
        if expired:
            raise RuntimeError("fixed offline deadline refusal")

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
        persist_response=response,
        check_owned_work=check,
        begin_cleanup=check,
    )
    assert result.failure == "cleanup_incomplete_keep_guard_running" and not result.guard_stopped
    assert scenario.calls == ["preview_order", "place_order"]
    assert not (tmp_path / "ownership.json").exists()
    assert json.loads((tmp_path / "entry-response.json").read_text())["stage"] == "entry-response"


def test_response_directory_fsync_failure_is_not_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os
    import stat

    scenario = Scenario()
    client, entry = scenario.opening[1:3]
    store = OwnershipStore(
        tmp_path, account="0x" + "2" * 40, client=client, source="a" * 64, version="1.0.0-rc.14"
    )
    store.begin(entry, 1000)
    sync = os.fsync

    def failure(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError("PRIVATE-KEY")
        sync(descriptor)

    monkeypatch.setattr(os, "fsync", failure)
    with pytest.raises(OSError):
        store.response({"sent": True, "ok": True, "outcome": "sent"}, False, "entry-response")
    assert not (tmp_path / "ownership.json").exists()
    assert json.loads((tmp_path / "entry-response.json").read_text())["gate_eligible"] is False
