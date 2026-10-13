"""Independent P8 fee numbers: 0.01 BTC at 1000 USDC = 10; 2 bp = 0.002 USDC."""

import copy
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from guard_harness import builder_journey
from guard_harness.builder_journey import _descriptor, correlate_fee

ACCOUNT, BUILDER, CLIENT = "0x" + "1" * 40, "0x" + "2" * 40, "0x" + "1" * 40


def observations() -> dict[str, Any]:
    descriptor = {
        "account": ACCOUNT,
        "builder": BUILDER,
        "network": "testnet",
        "fee_tenths_bp": 20,
        "release_commit": "a" * 40,
        "manifest_sha256": "b" * 64,
        "binary_sha256": "c" * 64,
    }
    approval = {
        "journey": "P8",
        "account": ACCOUNT,
        "builder": BUILDER,
        "network": "testnet",
        "fee_tenths_bp": 20,
        "approval_accepted": True,
        "approval_readback": True,
        "nonce": 99,
    }
    journey = {
        "journey": "T1",
        "result": "passed",
        "commit": "a" * 40,
        "manifest_sha256": "b" * 64,
        "binary_sha256": "c" * 64,
        "account_sha256": hashlib.sha256(ACCOUNT.encode()).hexdigest(),
        "guard_stopped": True,
        "cleanup_complete": True,
        "protected_entry": {"entry_oid": 7, "filled": "0.01"},
    }
    wire = {"type": "order", "orders": [{"r": False}], "builder": {"b": BUILDER, "f": 20}}
    events = [
        {"kind": "decision", "seq": 1, "client": CLIENT, "verdict": "allow", "forward": wire},
        {
            "kind": "sent",
            "seq": 2,
            "decision": 1,
            "ok": True,
            "action": None,
            "reply": {
                "status": "ok",
                "response": {"type": "order", "data": {"statuses": [{"filled": {"oid": 7}}]}},
            },
        },
    ]
    fills = [
        {
            "oid": 7,
            "tid": 9,
            "time": 110,
            "coin": "BTC",
            "side": "B",
            "feeToken": "USDC",
            "sz": "0.01",
            "px": "1000",
            "builderFee": "0.002",
            "fee": "0.007",
        }
    ]
    return dict(
        descriptor=descriptor,
        approval=approval,
        journey=journey,
        events=events,
        fills=fills,
        client=CLIENT,
        started_ms=100,
        ended_ms=120,
    )


def test_exact_owned_guard_builder_wire_and_actual_venue_fee_complete_p8() -> None:
    inputs = observations()
    original = copy.deepcopy(inputs)
    proof = correlate_fee(**inputs)
    assert proof["completed"] is True and proof["result"] == "passed"
    assert proof["builder_fee_usdc"] == "0.002" and proof["notional_usdc"] == "10.00"
    assert proof["entry_oid"] == 7 and proof["trade_ids"] == [9]
    assert ACCOUNT not in str(proof) and BUILDER not in str(proof)
    assert inputs == original  # Inclusive total fee remains 0.007; no double subtraction.


@pytest.mark.parametrize(
    "mutation",
    [
        "account",
        "release",
        "cleanup",
        "approval",
        "builder",
        "rewrite",
        "oid",
        "window",
        "duplicate",
        "zero",
        "rate",
    ],
)
def test_unrelated_or_incomplete_fee_evidence_never_completes_p8(mutation: str) -> None:
    inputs = observations()
    if mutation == "account":
        inputs["journey"]["account_sha256"] = "f" * 64
    if mutation == "release":
        inputs["journey"]["binary_sha256"] = "d" * 64
    if mutation == "cleanup":
        inputs["journey"]["cleanup_complete"] = False
    if mutation == "approval":
        inputs["approval"]["approval_readback"] = False
    if mutation == "builder":
        inputs["events"][0]["forward"]["builder"]["b"] = ACCOUNT
    if mutation == "rewrite":
        inputs["events"][1]["action"] = {"type": "order", "orders": [{"r": False}]}
    if mutation == "oid":
        inputs["fills"][0]["oid"] = 8
    if mutation == "window":
        inputs["fills"][0]["time"] = 121
    if mutation == "duplicate":
        inputs["fills"].append(copy.deepcopy(inputs["fills"][0]))
    if mutation == "zero":
        inputs["fills"][0]["builderFee"] = "0"
    if mutation == "rate":
        inputs["fills"][0]["builderFee"] = "0.003"
    with pytest.raises(ValueError):
        correlate_fee(**inputs)


def test_descriptor_reads_fee_from_paper_testnet_account_subject() -> None:
    status = {
        "mode": "paper",
        "network": "testnet",
        "account": ACCOUNT,
        "version": "1.0.0-rc.4",
        "fee": {"mode": "builder", "address": BUILDER, "fee_tenths_bp": 20, "rate": "0.02%"},
    }
    descriptor = _descriptor(
        status,
        account=ACCOUNT,
        tag="v1.0.0-rc.4",
        commit="a" * 40,
        manifest="b" * 64,
        binary="c" * 64,
    )
    assert descriptor["builder"] == BUILDER and descriptor["fee_tenths_bp"] == 20
    status["network"] = "mainnet"
    with pytest.raises(ValueError):
        _descriptor(
            status,
            account=ACCOUNT,
            tag="v1.0.0-rc.4",
            commit="a" * 40,
            manifest="b" * 64,
            binary="c" * 64,
        )


@pytest.mark.parametrize("correct_fee", [True, False])
def test_producer_stops_keyless_paper_subject_before_persisting_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, correct_fee: bool
) -> None:
    work = tmp_path / "subject"
    stopped: list[bool] = []

    def signed(assets: Path, binary: Path, **kwargs: Any) -> tuple[str, str]:
        assert kwargs == {"tag": "v1.0.0-rc.4", "commit": "a" * 40}
        binary.write_bytes(b"authenticated fixture bytes")
        return "c" * 64, "b" * 64

    def init(argv: list[str], **kwargs: Any) -> None:
        assert "--no-key" in argv and "--account-network" in argv and "paper" in argv
        assert kwargs["sensitive_output"] is True and set(kwargs["env"]) == {"PATH", "HOME"}

    class Process:
        def __init__(self, argv: list[str], **kwargs: Any) -> None:
            assert argv[argv.index("--network") + 1] == "paper"
            assert kwargs["stdin"] == subprocess.DEVNULL
            assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
            assert set(kwargs["env"]) == {"PATH", "HOME"}

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            stopped.append(True)

        def wait(self, **kwargs: Any) -> int:
            return 0

    def status(self: Any, path: str) -> dict[str, Any]:
        assert path == "/guard/status"
        return {
            "mode": "paper",
            "network": "testnet",
            "account": ACCOUNT,
            "version": "1.0.0-rc.4",
            "last_sync_ms": 100,
            "fee": {
                "mode": "builder",
                "address": BUILDER,
                "fee_tenths_bp": 20 if correct_fee else 21,
                "rate": "0.02%",
            },
        }

    monkeypatch.setattr(builder_journey, "signed_binary", signed)
    monkeypatch.setattr(builder_journey, "run", init)
    monkeypatch.setattr("guard_harness.builder_journey.subprocess.Popen", Process)
    monkeypatch.setattr("guard_harness.builder_journey.LocalGuard.request", status)
    if correct_fee:
        path = builder_journey.produce_descriptor(
            tmp_path / "assets", work, account=ACCOUNT, tag="v1.0.0-rc.4", commit="a" * 40
        )
        assert json.loads(path.read_bytes())["builder"] == BUILDER
        assert path.stat().st_mode & 0o777 == 0o600
    else:
        with pytest.raises(ValueError):
            builder_journey.produce_descriptor(
                tmp_path / "assets", work, account=ACCOUNT, tag="v1.0.0-rc.4", commit="a" * 40
            )
        assert not (work / "builder-descriptor.json").exists()
    assert stopped == [True]


def protected_observations(stop_ack: object = "waitingForTrigger") -> dict[str, Any]:
    inputs = observations()
    opening = {
        "a": 3,
        "b": True,
        "r": False,
        "s": "0.01",
        "p": "1000",
        "c": "0x7a6d" + "1" * 28,
        "t": {"limit": {"tif": "Ioc"}},
    }
    stop = {
        "a": 3,
        "b": False,
        "r": True,
        "s": "0.01",
        "p": "882",
        "c": "0x7a67" + "2" * 28,
        "t": {"trigger": {"triggerPx": "980", "tpsl": "sl", "isMarket": True}},
    }
    inputs["journey"]["protected_entry"]["stop_oid"] = 8
    decision = inputs["events"][0]
    decision["request"] = {"type": "order", "grouping": "na", "orders": [copy.deepcopy(opening)]}
    decision["forward"] = {
        "type": "order",
        "grouping": "normalTpsl",
        "orders": [opening, stop],
        "builder": {"b": BUILDER, "f": 20},
    }
    inputs["events"][1]["reply"]["response"]["data"]["statuses"].append(stop_ack)
    return inputs


@pytest.mark.parametrize("first", ["filled", "resting"])
@pytest.mark.parametrize(
    "stop_ack", ["waitingForTrigger", {"resting": {"oid": 8, "cloid": "0x7a67" + "2" * 28}}]
)
def test_actual_protected_entry_stop_reply_correlates_same_owned_fee(
    first: str, stop_ack: object
) -> None:
    inputs = protected_observations(stop_ack)
    inputs["events"][1]["reply"]["response"]["data"]["statuses"][0] = {first: {"oid": 7}}
    before = copy.deepcopy(inputs)
    proof = correlate_fee(**inputs)
    assert proof["completed"] is True and proof["builder_fee_usdc"] == "0.002"
    assert proof["notional_usdc"] == "10.00" and proof["entry_oid"] == 7
    assert inputs == before


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-status",
        "extra-status",
        "entry-error",
        "stop-error",
        "mixed-entry",
        "waiting-fill",
        "stop-filled",
        "stop-wrong-oid",
        "stop-bool-oid",
        "stop-entry-oid",
        "stop-cloid",
        "entry-cloid",
        "stop-missing-observed-oid",
        "stop-foreign-asset",
        "stop-opening",
        "stop-buy",
        "stop-size",
        "stop-extra-field",
        "stop-type",
        "stop-trigger-extra",
        "stop-not-market",
        "stop-take-profit",
        "stop-zero-price",
        "wire-grouping",
        "extra-order",
        "request-cloid",
        "send-failed",
        "wire-rewrite",
    ],
)
def test_protected_fee_correlation_refuses_incomplete_or_unrelated_acknowledgement(
    mutation: str,
) -> None:
    inputs = protected_observations({"resting": {"oid": 8}})
    decision, sent = inputs["events"]
    statuses = sent["reply"]["response"]["data"]["statuses"]
    wire = decision["forward"]
    buy, stop = wire["orders"]
    trigger = stop["t"]["trigger"]
    if mutation == "missing-status":
        statuses.pop()
    elif mutation == "extra-status":
        statuses.append("waitingForTrigger")
    elif mutation == "entry-error":
        statuses[0] = {"error": "private venue rejection"}
    elif mutation == "stop-error":
        statuses[1] = {"error": "private venue rejection"}
    elif mutation == "mixed-entry":
        statuses[0]["resting"] = {"oid": 7}
    elif mutation == "waiting-fill":
        statuses[1] = "waitingForFill"
    elif mutation == "stop-filled":
        statuses[1] = {"filled": {"oid": 8}}
    elif mutation == "stop-wrong-oid":
        statuses[1]["resting"]["oid"] = 9
    elif mutation == "stop-bool-oid":
        statuses[1]["resting"]["oid"] = True
    elif mutation == "stop-entry-oid":
        inputs["journey"]["protected_entry"]["stop_oid"] = 7
    elif mutation == "stop-cloid":
        statuses[1]["resting"]["cloid"] = "0x7a67" + "3" * 28
    elif mutation == "entry-cloid":
        statuses[0]["filled"]["cloid"] = "0x7a6d" + "3" * 28
    elif mutation == "stop-missing-observed-oid":
        inputs["journey"]["protected_entry"].pop("stop_oid")
    elif mutation == "stop-foreign-asset":
        stop["a"] = 4
    elif mutation == "stop-opening":
        stop["r"] = False
    elif mutation == "stop-buy":
        stop["b"] = True
    elif mutation == "stop-size":
        stop["s"] = "0.02"
    elif mutation == "stop-extra-field":
        stop["unexpected"] = True
    elif mutation == "stop-type":
        stop["t"] = {"limit": {"tif": "Gtc"}}
    elif mutation == "stop-trigger-extra":
        trigger["unexpected"] = True
    elif mutation == "stop-not-market":
        trigger["isMarket"] = False
    elif mutation == "stop-take-profit":
        trigger["tpsl"] = "tp"
    elif mutation == "stop-zero-price":
        trigger["triggerPx"] = "0"
    elif mutation == "wire-grouping":
        wire["grouping"] = "na"
    elif mutation == "extra-order":
        wire["orders"].append(copy.deepcopy(stop))
    elif mutation == "request-cloid":
        decision["request"]["orders"][0]["c"] = "0x7a6d" + "3" * 28
    elif mutation == "send-failed":
        sent["ok"] = False
    elif mutation == "wire-rewrite":
        sent["action"] = copy.deepcopy(wire)
        sent["action"]["orders"][1]["s"] = "0.02"
    with pytest.raises((ValueError, RuntimeError)):
        correlate_fee(**inputs)


def test_two_statuses_cannot_be_attached_to_legacy_single_order_wire() -> None:
    inputs = observations()
    inputs["events"][1]["reply"]["response"]["data"]["statuses"].append("waitingForTrigger")
    with pytest.raises(ValueError):
        correlate_fee(**inputs)


@pytest.mark.parametrize(
    "mutation",
    [
        "asset",
        "side",
        "reduce-only",
        "type",
        "grouping",
        "tif",
        "both-forward-assets",
        "size-increase",
        "price-increase",
        "request-cap",
    ],
)
def test_original_protected_request_must_bind_to_actual_forward(mutation: str) -> None:
    inputs = protected_observations()
    decision = inputs["events"][0]
    request = decision["request"]
    original = request["orders"][0]
    if mutation == "asset":
        original["a"] = 99
    elif mutation == "side":
        original["b"] = False
    elif mutation == "reduce-only":
        original["r"] = True
    elif mutation == "type":
        request["type"] = "notAnOrder"
    elif mutation == "grouping":
        request["grouping"] = "normalTpsl"
    elif mutation == "tif":
        original["t"] = {"limit": {"tif": "Gtc"}}
    elif mutation == "both-forward-assets":
        for order in decision["forward"]["orders"]:
            order["a"] = 99
    elif mutation == "size-increase":
        original["s"] = "0.009"
    elif mutation == "price-increase":
        original["p"] = "999"
    elif mutation == "request-cap":
        original["s"] = "0.05"
    with pytest.raises(ValueError):
        correlate_fee(**inputs)


def test_guard_resize_within_original_request_and_budget_keeps_actual_fee() -> None:
    inputs = protected_observations()
    original = inputs["events"][0]["request"]["orders"][0]
    original["s"] = "0.02"  # Requested20USDC, actual forward/fill10USDC.
    proof = correlate_fee(**inputs)
    assert proof["builder_fee_usdc"] == "0.002" and proof["notional_usdc"] == "10.00"
