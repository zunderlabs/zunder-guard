import copy
from decimal import Decimal
from typing import Any

import pytest
import test_testnet_protection as reference

from guard_harness.testnet_protection import ProtectionError
from guard_harness.testnet_reconcile import open_stop, owned_quantity, protected_ack


@pytest.fixture
def evidence() -> Any:
    fixture: Any = reference.evidence
    return fixture.__wrapped__()


def acknowledgement(evidence: Any, first: str = "filled", stop: Any = "waitingForTrigger") -> Any:
    events = evidence[2]
    events.append({"kind": "intent", "seq": 2, "of": 1})
    events.append(
        {
            "kind": "sent",
            "seq": 3,
            "decision": 2,
            "ok": True,
            "reply": {
                "status": "ok",
                "response": {"type": "order", "data": {"statuses": [{first: {"oid": 41}}, stop]}},
            },
        }
    )
    return events


def test_exact_partial_fills_and_reduced_remaining_position(evidence: Any) -> None:
    # Two fills: .0001*60000 + .0001*60100 = 12.01 USDC, size .0002 BTC.
    fills = [
        {"oid": 41, "tid": tid, "coin": "BTC", "side": "B", "sz": "0.0001", "px": px}
        for tid, px in [(1, "60000"), (2, "60100")]
    ]
    assert owned_quantity([{"coin": "BTC", "szi": "0.0001"}], fills, 41, evidence[0]) == (
        Decimal("0.0002")
    )


@pytest.mark.parametrize(
    "case",
    [
        "duplicate",
        "sell",
        "coin",
        "unbounded",
        "price",
        "unrelated",
        "short",
        "large-position",
        "unknown-oid",
    ],
)
def test_unknown_or_unbounded_fill_exposure_refused(evidence: Any, case: str) -> None:
    fills = [{"oid": 41, "tid": 1, "coin": "BTC", "side": "B", "sz": "0.0002", "px": "60000"}]
    positions = [{"coin": "BTC", "szi": "0.0002"}]
    if case == "duplicate":
        fills = [dict(fills[0], sz="0.0001")] * 2
    elif case == "sell":
        fills[0]["side"] = "A"
    elif case == "coin":
        fills[0]["coin"] = "ETH"
    elif case == "unbounded":
        fills[0]["sz"] = "0.001"
    elif case == "price":
        fills[0]["px"] = "60121"
    elif case == "unrelated":
        positions.append({"coin": "ETH", "szi": "1"})
    elif case == "short":
        positions[0]["szi"] = "-0.0002"
    elif case == "large-position":
        positions[0]["szi"] = "0.0003"
    else:
        fills[0]["oid"] = 99
    with pytest.raises(RuntimeError):
        owned_quantity(positions, fills, 41, evidence[0])


@pytest.mark.parametrize("stop", ["waitingForTrigger", {"resting": {"oid": 42}}])
def test_exact_successful_protected_ack(evidence: Any, stop: Any) -> None:
    proof = reference.proof(evidence)
    protected_ack(acknowledgement(evidence, stop=stop), proof, 41, 42)


def test_resting_deferred_ack_only_admits_resting_cleanup(evidence: Any) -> None:
    proof = reference.proof(evidence)
    events = acknowledgement(evidence, "resting", "waitingForFill")
    with pytest.raises(ProtectionError):
        protected_ack(events, proof, 41, None)
    protected_ack(events, proof, 41, None, cleanup=True, resting_only=True)


@pytest.mark.parametrize(
    "case",
    [
        "duplicate",
        "failed",
        "unlinked",
        "entry-oid",
        "stop-oid",
        "partial",
        "unknown",
        "wrong-cloid",
        "bool-link",
    ],
)
def test_acknowledgement_must_be_complete_unique_successful_and_linked(
    evidence: Any, case: str
) -> None:
    proof = reference.proof(evidence)
    events = acknowledgement(evidence, stop={"resting": {"oid": 42}})
    sent = events[-1]
    statuses = sent["reply"]["response"]["data"]["statuses"]
    if case == "duplicate":
        events.append(dict(copy.deepcopy(sent), seq=4))
    elif case == "failed":
        sent["ok"] = False
    elif case == "unlinked":
        sent["decision"] = 99
    elif case == "entry-oid":
        statuses[0]["filled"]["oid"] = 40
    elif case == "stop-oid":
        statuses[1]["resting"]["oid"] = 43
    elif case == "partial":
        statuses.pop()
    elif case == "unknown":
        statuses[1] = "waitingForFill"
    elif case == "wrong-cloid":
        statuses[0]["filled"]["cloid"] = "unrelated"
    else:
        sent["decision"] = True
    with pytest.raises(ProtectionError):
        protected_ack(events, proof, 41, 42)


def test_duplicate_sequences_and_entry_stop_oid_alias_refused(evidence: Any) -> None:
    proof = reference.proof(evidence)
    events = acknowledgement(evidence)
    events[-1]["seq"] = 2
    for entry_oid, stop_oid in [(41, 42), (41, 41), (True, 42)]:
        with pytest.raises(ProtectionError):
            protected_ack(events, proof, entry_oid, stop_oid)


@pytest.mark.parametrize(
    "case", ["valid", "closed", "missing", "duplicate", "lookup-oid", "trigger"]
)
def test_frontend_and_cloid_lookup_must_match(evidence: Any, case: str) -> None:
    proof = reference.proof(evidence)
    orders = [evidence[3]]
    lookup: dict[str, Any] = {
        "status": "order",
        "order": {"status": "open", "order": copy.deepcopy(orders[0])},
    }
    if case == "closed":
        lookup["order"]["status"] = "filled"
    elif case == "missing":
        orders = []
    elif case == "duplicate":
        orders *= 2
    elif case == "lookup-oid":
        lookup["order"]["order"]["oid"] = 43
    elif case == "trigger":
        lookup["order"]["order"]["triggerPx"] = "1"
    if case == "valid":
        assert open_stop(orders, lookup, proof) == 42
    else:
        with pytest.raises(ProtectionError):
            open_stop(orders, lookup, proof)


@pytest.mark.parametrize("matching", [True, False])
def test_stop_ack_cannot_contradict_its_durable_cloid(evidence: Any, matching: bool) -> None:
    proof = reference.proof(evidence)
    cloid = proof.cloid if matching else "0x7a67" + "f" * 28
    events = acknowledgement(evidence, stop={"resting": {"oid": 42, "cloid": cloid}})
    if matching:
        protected_ack(events, proof, 41, 42)
    else:
        with pytest.raises(ProtectionError):
            protected_ack(events, proof, 41, 42)
