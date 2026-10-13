import copy
from decimal import Decimal
from typing import Any

import pytest
import test_testnet_protection as reference
from test_testnet_reconcile import acknowledgement

from guard_harness.testnet_ownership import reconcile_ownership


@pytest.fixture
def case() -> Any:
    fixture: Any = reference.evidence
    evidence = fixture.__wrapped__()
    entry, client, _, stop = evidence
    events = acknowledgement(evidence)
    opening = {
        "oid": 41,
        "cloid": events[0]["request"]["orders"][0]["c"],
        "coin": "BTC",
        "side": "B",
        "reduceOnly": False,
        "isTrigger": False,
        "orderType": "Limit",
        "timestamp": 1000,
        "origSz": "0.0002",
        "sz": "0",
        "limitPx": "60120",
    }
    fields = {
        "markets": [{"name": "BTC", "szDecimals": 5}],
        "entry_lookup": {"status": "order", "order": {"status": "filled", "order": opening}},
        "fills": [
            {
                "oid": 41,
                "tid": 1,
                "time": 1000,
                "coin": "BTC",
                "side": "B",
                "sz": "0.0002",
                "px": "60000",
            }
        ],
        "positions": [
            {
                "coin": "BTC",
                "szi": "0.0002",
                "positionValue": "12",
                "leverage": {"type": "isolated"},
            }
        ],
        "orders": [stop],
        "stop_lookup": {
            "status": "order",
            "order": {"status": "open", "order": copy.deepcopy(stop)},
        },
        "started_ms": 1000,
    }
    return events, client, entry, fields


def test_complete_owned_position_and_stop(case: Any) -> None:
    result = reconcile_ownership(*case[:3], **case[3])
    assert (result.entry_oid, result.stop_oid, result.filled, result.remaining) == (
        41,
        42,
        Decimal("0.0002"),
        Decimal("0.0002"),
    )
    assert not result.resting_entry


@pytest.mark.parametrize(
    "field,value",
    [
        ("cloid", "unrelated"),
        ("coin", "ETH"),
        ("side", "A"),
        ("reduceOnly", True),
        ("isTrigger", True),
        ("orderType", "Stop Market"),
        ("origSz", "0.001"),
        ("limitPx", "60121"),
        ("oid", True),
        ("timestamp", 999),
        ("timestamp", True),
    ],
)
def test_entry_lookup_cannot_lend_an_unrelated_oid(case: Any, field: str, value: object) -> None:
    case[3]["entry_lookup"]["order"]["order"][field] = value
    with pytest.raises(RuntimeError):
        reconcile_ownership(*case[:3], **case[3])


@pytest.mark.parametrize(
    "mutation",
    ["stale", "bool-time", "unrelated", "duplicate-stop", "missing-stop", "partial", "cross"],
)
def test_ambiguous_or_incomplete_journey_is_refused(case: Any, mutation: str) -> None:
    fields = case[3]
    if mutation in {"stale", "bool-time"}:
        fields["fills"][0]["time"] = 999 if mutation == "stale" else True
    elif mutation == "unrelated":
        fields["orders"].append(dict(fields["orders"][0], oid=99, cloid="unrelated"))
    elif mutation == "duplicate-stop":
        fields["orders"] *= 2
    elif mutation == "missing-stop":
        fields["stop_lookup"] = None
    elif mutation == "cross":
        fields["positions"][0]["leverage"]["type"] = "cross"
    else:
        fields["fills"][0]["sz"] = fields["positions"][0]["szi"] = "0.0001"
        fields["positions"][0]["positionValue"] = "6"
    with pytest.raises(RuntimeError):
        reconcile_ownership(*case[:3], **fields)
    if mutation == "partial":
        assert reconcile_ownership(*case[:3], **fields, cleanup=True).filled == Decimal("0.0001")


@pytest.mark.parametrize("remaining", ["0", "0.0001"])
def test_missing_exit_fills_cannot_explain_reduced_or_flat_exposure(
    case: Any, remaining: str
) -> None:
    fields = case[3]
    if remaining == "0":
        fields.update(positions=[], orders=[], stop_lookup=None)
    else:
        fields["positions"][0].update(szi=remaining, positionValue="6")
    for cleanup in (False, True):
        with pytest.raises(RuntimeError):
            reconcile_ownership(*case[:3], **fields, cleanup=cleanup)


def test_unfilled_cleanup_proves_only_the_exact_resting_entry(case: Any) -> None:
    fields = case[3]
    opening = fields["entry_lookup"]["order"]["order"]
    opening["sz"] = "0.0002"
    fields["entry_lookup"]["order"]["status"] = "open"
    fields.update(fills=[], positions=[], orders=[copy.deepcopy(opening)], stop_lookup=None)
    case[0][-1]["reply"]["response"]["data"]["statuses"] = [
        {"resting": {"oid": 41}},
        "waitingForFill",
    ]
    result = reconcile_ownership(*case[:3], **fields, cleanup=True)
    assert result.resting_entry and result.stop_oid is None and result.filled == 0
    fields["orders"][0]["sz"] = "0.0001"
    with pytest.raises(RuntimeError):
        reconcile_ownership(*case[:3], **fields, cleanup=True)


def test_foreign_roundtrip_cannot_replace_run_owned_exposure(case: Any) -> None:
    # Own .0002 BTC is sold by someone else, then replaced with a foreign .0001 buy.
    # Historical own buys still exceed current size, but cleanup must never close it.
    fields = case[3]
    fields["fills"].extend(
        [
            {
                "oid": 98,
                "tid": 2,
                "time": 1001,
                "coin": "BTC",
                "side": "A",
                "sz": "0.0002",
                "px": "60000",
            },
            {
                "oid": 99,
                "tid": 3,
                "time": 1002,
                "coin": "BTC",
                "side": "B",
                "sz": "0.0001",
                "px": "60000",
            },
        ]
    )
    fields["positions"][0].update(szi="0.0001", positionValue="6")
    for cleanup in (False, True):
        with pytest.raises(RuntimeError):
            reconcile_ownership(*case[:3], **fields, cleanup=cleanup)


@pytest.fixture
def closed_case(case: Any) -> Any:
    import test_testnet_exits as exits_reference

    fixture: Any = exits_reference.case
    exiting = fixture.__wrapped__()
    case[0].extend(exiting[3][1:])
    case[3]["stop_lookup"] = copy.deepcopy(exiting[4][exiting[2].cloid])
    case[3]["exit_lookups"] = {
        key: copy.deepcopy(value) for key, value in exiting[4].items() if key != exiting[2].cloid
    }
    case[3]["fills"] = copy.deepcopy(exiting[5])
    case[3]["positions"] = []
    case[3]["orders"] = []
    case[3]["stop_lookup"]["order"]["status"] = "canceled"
    return case


def test_authenticated_close_proves_exact_flatness_only_for_cleanup(closed_case: Any) -> None:
    result = reconcile_ownership(*closed_case[:3], **closed_case[3], cleanup=True)
    assert result.filled == Decimal("0.0002") and result.remaining == 0
    assert result.stop_oid is None and not result.resting_entry
    with pytest.raises(RuntimeError):
        reconcile_ownership(*closed_case[:3], **closed_case[3])


def test_partial_close_and_orphan_stop_remain_exact_owned_cleanup(closed_case: Any) -> None:
    fields = closed_case[3]
    fields["stop_lookup"]["order"]["status"] = "open"
    fields["orders"] = [copy.deepcopy(fields["stop_lookup"]["order"]["order"])]
    # .0002 bought minus .0001 authenticated sell leaves .0001, never a broad account close.
    fields["fills"][1]["sz"] = "0.0001"
    fields["positions"] = [
        {"coin": "BTC", "szi": "0.0001", "positionValue": "6", "leverage": {"type": "isolated"}}
    ]
    result = reconcile_ownership(*closed_case[:3], **fields, cleanup=True)
    assert result.remaining == Decimal("0.0001") and result.stop_oid == 42
    fields["fills"][1]["sz"] = "0.0002"
    fields["positions"] = []
    assert reconcile_ownership(*closed_case[:3], **fields, cleanup=True).stop_oid == 42


def test_authenticated_stop_execution_proves_flat_cleanup(case: Any) -> None:
    fields = case[3]
    fields["stop_lookup"]["order"]["order"].update(origSz="0.0002", timestamp=1000)
    fields["stop_lookup"]["order"]["status"] = "filled"
    fields["fills"].append(dict(fields["fills"][0], oid=42, tid=2, time=1001, side="A", px="58800"))
    fields.update(positions=[], orders=[], exit_lookups={})
    result = reconcile_ownership(*case[:3], **fields, cleanup=True)
    assert result.remaining == 0 and result.stop_oid is None


@pytest.mark.parametrize(
    "mutation", ["foreign", "missing-fill", "missing-lookup", "stop-identity", "unrelated-order"]
)
def test_exit_integration_refuses_ambiguous_cleanup(closed_case: Any, mutation: str) -> None:
    fields = closed_case[3]
    if mutation == "foreign":
        fields["fills"][1]["oid"] = 99
    elif mutation == "missing-fill":
        fields["fills"].pop()
    elif mutation == "missing-lookup":
        fields["exit_lookups"].clear()
    elif mutation == "stop-identity":
        fields["stop_lookup"]["order"]["order"]["cloid"] = "0x7a67" + "e" * 28
    else:
        fields["orders"] = [{"oid": 99, "cloid": "unrelated"}]
    with pytest.raises(RuntimeError):
        reconcile_ownership(*closed_case[:3], **fields, cleanup=True)


def test_canceled_unfilled_entry_proves_only_flat_cleanup(case: Any) -> None:
    fields = case[3]
    fields["entry_lookup"]["order"]["status"] = "canceled"
    fields["entry_lookup"]["order"]["order"]["sz"] = "0.0002"
    fields.update(fills=[], positions=[], orders=[], stop_lookup=None)
    case[0][-1]["reply"]["response"]["data"]["statuses"] = [
        {"resting": {"oid": 41}},
        "waitingForFill",
    ]
    result = reconcile_ownership(*case[:3], **fields, cleanup=True)
    assert result.filled == result.remaining == 0 and not result.resting_entry


def test_flat_frontend_cannot_hide_a_lookup_open_orphan_stop(closed_case: Any) -> None:
    closed_case[3]["stop_lookup"]["order"]["status"] = "open"
    with pytest.raises(RuntimeError):
        reconcile_ownership(*closed_case[:3], **closed_case[3], cleanup=True)


@pytest.mark.parametrize("remaining", ["0", "0.0001"])
def test_canceled_lookup_partial_fill_cannot_hide_missing_history(
    case: Any, remaining: str
) -> None:
    fields = case[3]
    fields["entry_lookup"]["order"]["status"] = "canceled"
    fields["entry_lookup"]["order"]["order"]["sz"] = remaining
    fields.update(fills=[], positions=[], orders=[], stop_lookup=None)
    case[0][-1]["reply"]["response"]["data"]["statuses"] = [
        {"resting": {"oid": 41}},
        "waitingForFill",
    ]
    with pytest.raises(RuntimeError):
        reconcile_ownership(*case[:3], **fields, cleanup=True)


def test_market_crossing_stop_keeps_owned_cleanup_but_refuses_journey_credit(case: Any) -> None:
    # .0002 BTC at 58000 => 11.6 USDC, below durable trigger 58800. Preserve identity/net
    # checks for emergency cleanup; a crossed stop can never count as protected T1 success.
    fields = case[3]
    fields["positions"][0]["positionValue"] = "11.6"
    fields["stop_lookup"]["order"]["order"].update(origSz="0.0002", timestamp=1000)
    fields["exit_lookups"] = {}
    result = reconcile_ownership(*case[:3], **fields, cleanup=True)
    assert result.remaining == Decimal("0.0002") and result.stop_oid == 42
    with pytest.raises(RuntimeError):
        reconcile_ownership(*case[:3], **fields)


def test_authenticated_original_reduce_only_canceled_stop_proves_closed_cleanup(
    closed_case: Any,
) -> None:
    closed_case[3]["stop_lookup"]["order"]["status"] = "reduceOnlyCanceled"
    result = reconcile_ownership(*closed_case[:3], **closed_case[3], cleanup=True)
    # .0002 BTC bought and .0002 sold through the authenticated close: exact net0,
    # no venue positions/orders; the original protective stop is terminal only.
    assert result.filled == Decimal("0.0002") and result.remaining == 0
    assert result.stop_oid is None and not result.resting_entry


@pytest.mark.parametrize(
    "mutation",
    [
        "remaining",
        "orphan-stop",
        "foreign-order",
        "missing-close-fill",
        "foreign-close-fill",
        "duplicate-fill",
        "stop-cloid",
        "stop-oid",
        "stop-side",
        "stop-reduce",
        "stop-trigger",
        "stop-size",
        "stop-time",
        "stop-coin",
        "entry-status",
        "close-status",
    ],
)
def test_terminal_reduce_only_cancel_requires_exact_original_stop_and_zero_owned_net(
    closed_case: Any, mutation: str
) -> None:
    fields = closed_case[3]
    stop = fields["stop_lookup"]["order"]
    stop["status"] = "reduceOnlyCanceled"
    if mutation == "remaining":
        fields["fills"][1]["sz"] = "0.0001"
        fields["positions"] = [
            {"coin": "BTC", "szi": "0.0001", "positionValue": "6", "leverage": {"type": "isolated"}}
        ]
    elif mutation == "orphan-stop":
        fields["orders"] = [copy.deepcopy(stop["order"])]
    elif mutation == "foreign-order":
        fields["orders"] = [dict(copy.deepcopy(stop["order"]), oid=99, cloid="foreign")]
    elif mutation == "missing-close-fill":
        fields["fills"].pop()
    elif mutation == "foreign-close-fill":
        fields["fills"][1]["oid"] = 99
    elif mutation == "duplicate-fill":
        fields["fills"].append(copy.deepcopy(fields["fills"][1]))
    elif mutation == "entry-status":
        fields["entry_lookup"]["order"]["status"] = "reduceOnlyCanceled"
    elif mutation == "close-status":
        for lookup in fields["exit_lookups"].values():
            lookup["order"]["status"] = "reduceOnlyCanceled"
    else:
        key, value = {
            "stop-cloid": ("cloid", "0x7a67" + "f" * 28),
            "stop-oid": ("oid", 99),
            "stop-side": ("side", "B"),
            "stop-reduce": ("reduceOnly", False),
            "stop-trigger": ("isTrigger", False),
            "stop-size": ("origSz", "0.0001"),
            "stop-time": ("timestamp", 999),
            "stop-coin": ("coin", "ETH"),
        }[mutation]
        if mutation == "stop-oid":
            # When the entry reply names a resting stop OID, that identity must still match.
            # The ordinary waitingForTrigger schema has no OID to cross-check.
            acknowledged = 0
            for event in closed_case[0]:
                statuses = (
                    event.get("reply", {}).get("response", {}).get("data", {}).get("statuses", [])
                )
                if len(statuses) == 2 and statuses[0].get("filled", {}).get("oid") == 41:
                    statuses[1] = {"resting": {"oid": 42, "cloid": stop["order"]["cloid"]}}
                    acknowledged += 1
            assert acknowledged == 1
        stop["order"][key] = value
    with pytest.raises(RuntimeError):
        reconcile_ownership(*closed_case[:3], **fields, cleanup=True)


def test_terminal_reduce_only_cancel_never_proves_normal_journey_success(closed_case: Any) -> None:
    closed_case[3]["stop_lookup"]["order"]["status"] = "reduceOnlyCanceled"
    with pytest.raises(RuntimeError):
        reconcile_ownership(*closed_case[:3], **closed_case[3], cleanup=False)


@pytest.mark.parametrize(
    "status",
    ["reduceonlycanceled", "reduceOnlyCanceled PRIVATE", "reduceOnlyCanceled\n", "unknown"],
)
def test_terminal_stop_does_not_admit_status_variants_or_private_suffix(
    closed_case: Any, status: str
) -> None:
    closed_case[3]["stop_lookup"]["order"]["status"] = status
    with pytest.raises(RuntimeError):
        reconcile_ownership(*closed_case[:3], **closed_case[3], cleanup=True)
