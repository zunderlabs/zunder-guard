import copy
import re
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import test_testnet_protection as reference

from guard_harness.testnet_exits import TESTNET_BUILDER, owned_balance, prove_exits


@pytest.fixture
def case() -> Any:
    fixture: Any = reference.evidence
    entry, client, events, stop = fixture.__wrapped__()
    proof = reference.proof((entry, client, events, stop))
    cloid = "0x7a6d" + "c" * 28
    action = {
        "type": "order",
        "grouping": "na",
        "orders": [
            {
                "a": 0,
                "b": False,
                "r": True,
                "t": {"limit": {"tif": "Ioc"}},
                "c": cloid,
                "s": "0.0002",
                "p": "59400",
            }
        ],
    }
    events.extend(
        [
            {
                "kind": "decision",
                "seq": 4,
                "client": client,
                "verdict": "allow",
                "action": "order",
                "request": copy.deepcopy(action),
                "forward": action,
            },
            {
                "kind": "sent",
                "seq": 5,
                "decision": 4,
                "ok": True,
                "reply": {
                    "status": "ok",
                    "response": {
                        "type": "order",
                        "data": {"statuses": [{"filled": {"oid": 43, "cloid": cloid}}]},
                    },
                },
            },
        ]
    )
    stop.update(origSz="0.0002", timestamp=1000)
    close = {
        "oid": 43,
        "cloid": cloid,
        "coin": "BTC",
        "side": "A",
        "reduceOnly": True,
        "isTrigger": False,
        "orderType": "Limit",
        "origSz": "0.0002",
        "limitPx": "59400",
        "timestamp": 1001,
    }
    lookups = {
        proof.cloid: {"status": "order", "order": {"status": "open", "order": stop}},
        cloid: {"status": "order", "order": {"status": "filled", "order": close}},
    }
    fills = [
        {
            "oid": 41,
            "tid": 1,
            "time": 1000,
            "coin": "BTC",
            "side": "B",
            "sz": "0.0002",
            "px": "60000",
        },
        {
            "oid": 43,
            "tid": 2,
            "time": 1001,
            "coin": "BTC",
            "side": "A",
            "sz": "0.0002",
            "px": "60000",
        },
    ]
    return entry, client, proof, events, lookups, fills


def exits(case: Any) -> Any:
    entry, client, proof, events, lookups, _ = case
    return prove_exits(events, client, proof, entry, lookups, started_ms=1000)


def test_owned_close_and_stop_identity_and_hand_computed_flat(case: Any) -> None:
    # .0002 BTC bought then .0002 sold, 12 USDC each at 60000: exactly flat.
    proofs = exits(case)
    assert set(proofs) == {42, 43}
    assert proofs[42].limit == Decimal("52920")
    assert proofs[43].limit == Decimal("59400")
    assert owned_balance([], case[5], 41, case[0], proofs, started_ms=1000) == (
        Decimal("0.0002"),
        Decimal(0),
    )


def test_partial_owned_close_reconciles_exact_isolated_remainder(case: Any) -> None:
    case[5][1]["sz"] = "0.0001"
    positions = [{"coin": "BTC", "szi": "0.0001", "leverage": {"type": "isolated"}}]
    assert owned_balance(positions, case[5], 41, case[0], exits(case), started_ms=1000)[
        1
    ] == Decimal("0.0001")


def test_default_fee_recipient_and_rate_match_public_shipped_source() -> None:
    source = Path(__file__).resolve().parents[4] / "crates/zunder-guard-core/src/licence.rs"
    text = source.read_text()
    recipient = re.search(
        r'pub const ORCASTRATE_TESTNET_BUILDER:\s*Option<&str>\s*=\s*Some\("([^"\n]+)"\);', text
    )
    assert recipient is not None and recipient[1].lower() == TESTNET_BUILDER
    assert "pub const BUILDER_FEE_TENTHS_BP: u64 = 20;" in text


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("uppercase", [False, True])
def test_compiled_fee_only_preserves_exact_full_or_partial_owned_close(
    case: Any, partial: bool, uppercase: bool
) -> None:
    # Reproduce the pinned raw-action comparison defect, not omitted historical
    # bytes: Guard clones a builder-free MCP close and adds its compiled fee.
    decision = case[3][-2]
    decision["forward"]["builder"] = {
        "b": TESTNET_BUILDER.upper() if uppercase else TESTNET_BUILDER,
        "f": 20,
    }
    assert decision["forward"] != decision["request"]
    positions: list[dict[str, Any]] = []
    if partial:
        case[5][1]["sz"] = "0.0001"
        positions = [{"coin": "BTC", "szi": "0.0001", "leverage": {"type": "isolated"}}]
    # Hand computed: .0002 buy minus .0002/.0001 sell is 0/.0001 BTC.
    assert owned_balance(positions, case[5], 41, case[0], exits(case), started_ms=1000) == (
        Decimal("0.0002"),
        Decimal("0.0001") if partial else Decimal(0),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "recipient",
        "rate",
        "rate-bool",
        "rate-string",
        "null",
        "keys",
        "address-null",
        "client-builder",
        "action-key",
        "price",
        "size",
        "cloid",
        "grouping",
        "wire-key",
    ],
)
def test_fee_transform_never_authorizes_other_close_changes(case: Any, mutation: str) -> None:
    decision = case[3][-2]
    forward = decision["forward"]
    forward["builder"] = {"b": TESTNET_BUILDER, "f": 20}
    if mutation == "recipient":
        forward["builder"]["b"] = "0x" + "1" * 40
    elif mutation in {"rate", "rate-bool", "rate-string"}:
        forward["builder"]["f"] = {"rate": 21, "rate-bool": True, "rate-string": "20"}[mutation]
    elif mutation == "null":
        forward["builder"] = None
    elif mutation == "keys":
        forward["builder"]["private"] = "PRIVATE-SENTINEL"
    elif mutation == "address-null":
        forward["builder"]["b"] = None
    elif mutation == "client-builder":
        decision["request"]["builder"] = copy.deepcopy(forward["builder"])
    elif mutation == "action-key":
        forward["private"] = "PRIVATE-SENTINEL"
    elif mutation == "grouping":
        forward["grouping"] = "normalTpsl"
    else:
        name = {"price": "p", "size": "s", "cloid": "c", "wire-key": "private"}[mutation]
        forward["orders"][0][name] = "PRIVATE-SENTINEL"
    with pytest.raises(RuntimeError):
        exits(case)


@pytest.mark.parametrize("side", ["request", "forward"])
@pytest.mark.parametrize(
    ("field", "value"),
    [("a", False), ("a", 0.0), ("b", 0), ("r", 1), ("p", 59400), ("s", 0.0002), ("c", 1)],
)
def test_fee_comparison_rejects_scalar_type_aliases(
    case: Any, side: str, field: str, value: object
) -> None:
    decision = case[3][-2]
    decision["forward"]["builder"] = {"b": TESTNET_BUILDER, "f": 20}
    decision[side]["orders"][0][field] = value
    with pytest.raises(RuntimeError):
        # An integer r=1 is not a reduce-only decision at all; its actual sell
        # consequently has no authenticated exit and accounting must refuse.
        proofs = exits(case)
        owned_balance([], case[5], 41, case[0], proofs, started_ms=1000)


@pytest.mark.parametrize(
    "mutation",
    [
        "foreign",
        "duplicate",
        "oversell",
        "price",
        "stale",
        "missing-close",
        "close-before-buy",
        "wrong-side",
        "wrong-coin",
    ],
)
def test_ambiguous_or_impossible_fills_never_earn_flat_credit(case: Any, mutation: str) -> None:
    fills = case[5]
    if mutation == "foreign":
        fills[1]["oid"] = 99
    elif mutation == "duplicate":
        fills.append(copy.deepcopy(fills[1]))
    elif mutation == "oversell":
        fills[1]["sz"] = "0.0003"
    elif mutation == "price":
        fills[1]["px"] = "59399"
    elif mutation == "stale":
        fills[1]["time"] = 999
    elif mutation == "missing-close":
        fills.pop()
    elif mutation == "close-before-buy":
        fills[0]["time"] = 1002
    elif mutation == "wrong-side":
        fills[1]["side"] = "B"
    else:
        fills[1]["coin"] = "ETH"
    with pytest.raises(RuntimeError):
        owned_balance([], fills, 41, case[0], exits(case), started_ms=1000)


@pytest.mark.parametrize(
    "mutation",
    [
        "forward",
        "buy",
        "reduce",
        "asset",
        "quantity",
        "gtc",
        "cloid",
        "lookup",
        "stale",
        "ack",
        "failed",
        "alias",
    ],
)
def test_exit_requires_durable_wire_lookup_and_successful_ack(case: Any, mutation: str) -> None:
    decision, sent = case[3][-2:]
    wire = decision["request"]["orders"][0]
    lookup = case[4][wire["c"]]["order"]["order"]
    if mutation == "forward":
        decision["forward"]["orders"][0]["p"] = "1"
    elif mutation in {"buy", "reduce", "asset", "quantity", "gtc", "cloid"}:
        key, value = {
            "buy": ("b", True),
            "reduce": ("r", False),
            "asset": ("a", True),
            "quantity": ("s", "0.001"),
            "gtc": ("t", {"limit": {"tif": "Gtc"}}),
            "cloid": ("c", case[2].entry_cloid),
        }[mutation]
        wire[key] = value
        decision["forward"] = copy.deepcopy(decision["request"])
    elif mutation == "lookup":
        lookup["coin"] = "ETH"
    elif mutation == "stale":
        lookup["timestamp"] = 999
    elif mutation == "ack":
        sent["reply"]["response"]["data"]["statuses"][0]["filled"]["oid"] = 99
    elif mutation == "failed":
        sent["ok"] = False
    else:
        lookup["oid"] = 42
        sent["reply"]["response"]["data"]["statuses"][0]["filled"]["oid"] = 42
    # An all-non-reduce decision isn't an exit; foreign fills still refuse net accounting.
    with pytest.raises(RuntimeError):
        proofs = exits(case)
        owned_balance([], case[5], 41, case[0], proofs, started_ms=1000)


def test_stop_fill_reconciles_with_exact_historical_stop_lookup(case: Any) -> None:
    case[5][1].update(oid=42, px="58800")
    case[4][case[2].cloid]["order"]["status"] = "filled"
    case[4][case[2].cloid]["order"]["order"]["sz"] = "0"
    assert owned_balance([], case[5], 41, case[0], exits(case), started_ms=1000)[1] == 0


def test_exit_fill_cannot_predate_its_proved_order(case: Any) -> None:
    case[5][1]["time"] = 1000
    with pytest.raises(RuntimeError):
        owned_balance([], case[5], 41, case[0], exits(case), started_ms=1000)


@pytest.mark.parametrize("trade", [0, True, -1])
def test_trade_ids_are_exact_nonnegative_integers(case: Any, trade: int) -> None:
    case[5][0]["tid"] = trade
    if type(trade) is int and trade == 0:
        assert owned_balance([], case[5], 41, case[0], exits(case), started_ms=1000)[1] == 0
    else:
        with pytest.raises(RuntimeError):
            owned_balance([], case[5], 41, case[0], exits(case), started_ms=1000)


def test_reduce_only_canceled_original_stop_is_opt_in_and_close_status_stays_strict(
    case: Any,
) -> None:
    entry, client, proof, events, lookups, fills = case
    lookups[proof.cloid]["order"]["status"] = "reduceOnlyCanceled"
    with pytest.raises(RuntimeError):
        prove_exits(events, client, proof, entry, lookups, started_ms=1000)
    proved = prove_exits(
        events, client, proof, entry, lookups, started_ms=1000, allow_closed_stop=True
    )
    assert owned_balance([], fills, 41, entry, proved, started_ms=1000)[1] == 0
    close = next(key for key in lookups if key != proof.cloid)
    lookups[close]["order"]["status"] = "reduceOnlyCanceled"
    with pytest.raises(RuntimeError):
        prove_exits(events, client, proof, entry, lookups, started_ms=1000, allow_closed_stop=True)


@pytest.mark.parametrize("state", ["full", "partial", "mismatch"])
@pytest.mark.parametrize("failure", ["none", "io", "interrupt"])
def test_existing_net_comparison_observer_preserves_hand_computed_proof(
    case: Any, state: str, failure: str
) -> None:
    from guard_harness.testnet_exits import AccountingViewMismatch

    # Buy .0002, sell .0002 =>0; sell .0001 =>.0001. Missing close with no position is refused.
    positions: list[dict[str, Any]] = []
    if state == "partial":
        case[5][1]["sz"] = "0.0001"
        positions = [{"coin": "BTC", "szi": "0.0001", "leverage": {"type": "isolated"}}]
    elif state == "mismatch":
        case[5].pop()
    observed: list[bool] = []

    def observer(matched: bool) -> None:
        assert type(matched) is bool
        observed.append(matched)
        if failure == "io":
            raise OSError("PRIVATE-KEY-BODY")
        if failure == "interrupt":
            raise KeyboardInterrupt("PRIVATE-KEY-BODY")

    if state == "mismatch":
        with pytest.raises(AccountingViewMismatch) as caught:
            owned_balance(
                positions, case[5], 41, case[0], exits(case), started_ms=1000, observe_net=observer
            )
        assert str(caught.value) == "owned accounting views disagree"
    else:
        actual = owned_balance(
            positions, case[5], 41, case[0], exits(case), started_ms=1000, observe_net=observer
        )
        assert actual == (
            Decimal("0.0002"),
            Decimal("0.0001") if state == "partial" else Decimal(0),
        )
    assert observed == [state != "mismatch"]
