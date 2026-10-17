"""Offline restore custody, exact money bounds, rerun idempotence and workflow admission.

Every number is hand computed from the approved baselines (Hyperliquid payer 20 USDC,
blocked payer 3 USDC, EVM payer 20 USDC per Sepolia chain) and the fixture balances
below; amounts are micro-USDC unless a string says USDC. No test contacts a network.
"""

import copy
import itertools
import json
import os
import shutil
import subprocess
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import rlp  # type: ignore[import-untyped]
from eth_account import Account

from guard_harness import purchase_evm as evm
from guard_harness import wallet_preflight
from guard_harness import wallet_restore as restore
from guard_harness.c6_owner import document
from guard_harness.purchase_payment import PaymentError

GUARD = Path(__file__).resolve().parents[2]
PRIVATE = GUARD / "github/workflows/verify.yml"
WORKFLOW = PRIVATE if PRIVATE.exists() else GUARD.parents[1] / ".github/workflows/verify.yml"
RUN = "123"


@pytest.fixture(autouse=True)
def no_live_http(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("offline wallet-restore tests must not contact a live endpoint")

    monkeypatch.setattr(restore, "request", refused)
    monkeypatch.setattr(evm, "request", refused)


def purchase(
    evidence: Path,
    row: str,
    *,
    run: str = RUN,
    attempt: str = "1",
    blocked: bool = False,
    layout: tuple[str, ...] = ("quote-evidence",),
    amount: int | None = None,
) -> Path:
    network = {
        "P1": "hyperliquid",
        "P2": "arbitrum",
        "P3": "base",
        "P5": "hyperliquid",
        "P6": "hyperliquid",
    }[row]
    leaf = ("blocked" if blocked else "under") if row == "P5" else "payment"
    path = evidence.joinpath(f"{row}-{run}-{attempt}", *layout, row, leaf)
    path.mkdir(parents=True)
    value: dict[str, Any] = {
        "order": "ZL-2026-123456",
        "network": network,
        # By default exactly what drained the payer to its fixture balance below:
        # 20 - 19.35, 3 - 2.28 and 20 - 19.64 USDC.
        "amount_micro": amount
        if amount is not None
        else 720000
        if blocked
        else 650000
        if network == "hyperliquid"
        else 360000,
        "nonce": 42,
    }
    if network == "hyperliquid":
        value.update(
            payer=restore.BLOCKED_PAYER if blocked else restore.HL_PAYER,
            scenario="blocked" if blocked else "exact",
        )
    else:
        value.update(
            transaction_hash="0x" + "1" * 64,
            gas=50000,
            gas_price=1000000000,
            max_total_fee_wei=50000000000000,
        )
    (path / "payment-attempt.json").write_text(json.dumps(value))
    (path / "payment-receipt.json").write_text(json.dumps({**value, "accepted": True}))
    return path


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    tmp_path = tmp_path.resolve()
    tmp_path.chmod(0o700)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for name in ("GUARD_ACCESS_CLIENT_ID", "GUARD_ACCESS_CLIENT_SECRET"):
        monkeypatch.setenv(name, "offline-access")
    monkeypatch.setenv("E2E_MERCHANT_TESTNET_KEY", "offline-merchant-key")
    monkeypatch.setattr(evm, "LOOKUP_SECONDS", 0)
    state: dict[str, Any] = {
        "root": tmp_path,
        "evidence": evidence,
        "balances": {
            restore.HL_PAYER: Decimal("19.35"),
            restore.BLOCKED_PAYER: Decimal("2.28"),
            restore.EVM_PAYER: Decimal("19.64"),
            restore.MERCHANT: Decimal("100"),
        },
        "reads": [],
        "sends": [],
        "signs": [],
        "custody": [],
        "chain_offset": 0,
        "pending": 2,
        "latest": 2,
        "head": 0x20,
        "gas": 50000,
        "price": 1000000000,
        "base_fee": 400000000,
        "eth": 10**16,
        "receipt_status": "0x1",
        "receipt_hash": True,
        "block": "0x10",
        "credit": True,
        "extra_credit": Decimal("0"),
        "send_failure": False,
        "known_after_failure": False,
        "positions": [],
        "withdrawable_offset": Decimal("0"),
        "decimals": "0x" + f"{6:064x}",
        "status": {
            "ok": True,
            "chain": "testnet",
            "profile": "staging",
            "priceDivisor": 1000,
            "payTo": dict.fromkeys(restore.TARGETS, restore.MERCHANT),
        },
    }
    # An offline signing key never leaves this process; the custody mock substitutes
    # the table-listed sender. Real custody must derive and match that sender.
    original_from_key = Account.from_key
    wallet = original_from_key(bytes([1]) * 32)

    def sign_tx(transaction: dict[str, Any]) -> Any:
        state["signs"].append(transaction)
        return wallet.sign_transaction(transaction)

    fake_wallet = SimpleNamespace(address=restore.MERCHANT, sign_transaction=sign_tx)

    def custody(key: Any) -> Any:
        if key == "offline-merchant-key":
            state["custody"].append(key)
            return fake_wallet
        return original_from_key(key)

    monkeypatch.setattr(Account, "from_key", custody)

    def sign_hl(wallet: Any, action: dict[str, Any], mainnet: bool) -> dict[str, Any]:
        assert wallet is fake_wallet and mainnet is False
        action.update(signatureChainId="0x66eee", hyperliquidChain="Testnet")
        state["signs"].append(copy.deepcopy(action))
        return {"r": "offline", "s": "offline", "v": 27}

    monkeypatch.setattr(restore, "sign_usd_transfer_action", sign_hl)

    def credit(address: str, amount: Decimal) -> None:
        if state["credit"]:
            state["balances"][address] += amount + state["extra_credit"]

    def http(url: str, *, headers: dict[str, str], data: bytes | None = None) -> dict[str, Any]:
        state["reads"].append(url)
        if url == restore.STAGING + "/api/licence/status":
            assert data is None
            assert headers == {
                "CF-Access-Client-Id": "offline-access",
                "CF-Access-Client-Secret": "offline-access",
            }
            return dict(state["status"])
        assert data is not None
        body = json.loads(data)
        if url == restore.HL_INFO:
            assert body["type"] == "clearinghouseState"
            balance = state["balances"][body["user"]]
            return {
                "marginSummary": {"accountValue": str(balance)},
                "withdrawable": str(balance + state["withdrawable_offset"]),
                "assetPositions": state["positions"],
            }
        if url == restore.HL_EXCHANGE:
            action = body["action"]
            assert action["hyperliquidChain"] == "Testnet" and action["type"] == "usdSend"
            dest = action["destination"]
            assert dest in dict(restore.TARGETS["hyperliquid"])
            assert (state["current"] / dest / "attempt.json").is_file()
            state["sends"].append(body)
            if state["send_failure"]:
                raise PaymentError("offline ambiguous send")
            credit(dest, Decimal(action["amount"]))
            return {"status": "ok", "response": {"type": "default"}}
        network = next(name for name, facts in evm.NETWORKS.items() if url == facts[0])
        method, params = body["method"], body["params"]
        state["reads"].append((network, method, params))
        value: Any
        if method == "eth_chainId":
            value = hex(evm.NETWORKS[network][1] + state["chain_offset"])
        elif method == "eth_blockNumber":
            value = hex(state["head"])
        elif method == "eth_call":
            assert params[0]["to"] == evm.NETWORKS[network][2]
            if params[0]["data"] == "0x313ce567":
                value = state["decimals"]
            else:
                assert params[0]["data"].startswith("0x70a08231")
                assert params[1] == hex(state["head"])  # Pinned to one fresh block.
                address = "0x" + params[0]["data"][-40:]
                value = "0x" + f"{int(state['balances'][address] * 1_000_000):064x}"
        elif method == "eth_getTransactionCount":
            assert params[0] == restore.MERCHANT
            value = hex(state["pending" if params[1] == "pending" else "latest"])
        elif method == "eth_estimateGas":
            value = hex(state["gas"])
        elif method == "eth_gasPrice":
            value = hex(state["price"])
        elif method == "eth_getBlockByNumber":
            value = {"baseFeePerGas": hex(state["base_fee"])}
        elif method == "eth_getBalance":
            assert params == [restore.MERCHANT, "latest"]
            value = hex(state["eth"])
        elif method == "eth_sendRawTransaction":
            assert (state["current"] / restore.EVM_PAYER / "attempt.json").is_file()
            state["sends"].append(params[0])
            decoded = rlp.decode(bytes.fromhex(params[0][2:]))
            # Actual offline signature encodes pinned chain, token, USDC-only calldata,
            # and zero native ETH value. Destination/amount come from the deficit.
            assert (int.from_bytes(decoded[6], "big") - 35) // 2 == evm.NETWORKS[network][1]
            assert decoded[3].hex() == evm.NETWORKS[network][2][2:]
            assert decoded[4] == b""
            assert decoded[5][:4].hex() == "a9059cbb"
            assert decoded[5][4:36].hex()[-40:] == restore.EVM_PAYER[2:]
            amount = Decimal(int.from_bytes(decoded[5][36:], "big")) / 1_000_000
            if state["send_failure"]:
                if state["known_after_failure"]:
                    credit(restore.EVM_PAYER, amount)
                raise PaymentError("offline ambiguous send")
            credit(restore.EVM_PAYER, amount)
            attempt = state["current"] / restore.EVM_PAYER / "attempt.json"
            value = json.loads(attempt.read_text())["transaction_hash"]
        elif method == "eth_getTransactionReceipt":
            if state["send_failure"] and not state["known_after_failure"]:
                value = None
            else:
                value = {
                    "transactionHash": params[0] if state["receipt_hash"] else "0xwrong",
                    "status": state["receipt_status"],
                    "blockNumber": state["block"],
                }
        elif method == "eth_getTransactionByHash":
            value = None
        else:
            pytest.fail("unexpected RPC method: " + method)
        return {"jsonrpc": "2.0", "id": 1, "result": value}

    monkeypatch.setattr(restore, "request", http)
    monkeypatch.setattr(evm, "request", http)
    return state


def work(state: dict[str, Any], attempt: str) -> Path:
    path: Path = state["root"] / f"work-{attempt}"
    if not path.exists():
        path.mkdir(mode=0o700)
    state["current"] = path
    return path


def plan(state: dict[str, Any], network: str = "hyperliquid", attempt: str = "1") -> Any:
    return restore.plan(network, state["evidence"], work(state, attempt), RUN, attempt)


def run(state: dict[str, Any], network: str = "hyperliquid", *, attempt: str = "1") -> None:
    # Each workflow attempt is a fresh job with the environment secret again.
    os.environ["E2E_MERCHANT_TESTNET_KEY"] = "offline-merchant-key"
    plan(state, network, attempt)
    restore.send(network, work(state, attempt), RUN, attempt)


def upload(state: dict[str, Any], network: str, attempt: str, *, final: bool = True) -> None:
    """What the workflow's two upload steps retain from one attempt's private workspace."""
    source = work(state, attempt)
    intent = state["evidence"] / f"wallet-restore-intent-{network}-{RUN}-{attempt}"
    intent.mkdir()
    for name in ("restore-started.json", "plan.json"):
        shutil.copy(source / name, intent / name)
    if final:
        shutil.copytree(source, state["evidence"] / f"wallet-restore-{network}-{RUN}-{attempt}")


@pytest.mark.parametrize(
    "balance,baseline,expected",
    [
        # Hand computed from the approved 20/3 USDC baselines; all values are micro-USDC.
        ("19.35", 20_000_000, 650000),
        ("2.28", 3_000_000, 720000),
        ("19.64", 20_000_000, 360000),
        ("20", 20_000_000, 0),
        ("25", 20_000_000, 0),
        ("0", 3_000_000, 3_000_000),
        ("19.9999991", 20_000_000, 0),
        ("19.9999989", 20_000_000, 1),
        ("19.999999999999999999", 20_000_000, 0),
        ("1000", 20_000_000, 0),
    ],
)
def test_exact_gap_never_overfills(balance: str, baseline: int, expected: int) -> None:
    assert restore.gap(Decimal(balance), baseline) == expected


@pytest.mark.parametrize(
    "value",
    ["NaN", "Infinity", "-1", "1e3", "1000000000001", 1, True, "1.0000000000000000001", "", None],
)
def test_malformed_balance_refused(value: Any) -> None:
    with pytest.raises(PaymentError):
        restore.decimal_balance(value)


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-1", "1000.000001", "1000000000001"])
def test_invalid_or_unexpected_payer_balance_refused(value: str) -> None:
    # Above 1,000 USDC a payer holds something nobody planned for: refuse, never guess.
    with pytest.raises(PaymentError):
        restore.gap(Decimal(value), 20_000_000)


def test_restore_parties_are_the_preflight_table_and_exclude_the_e2e_account() -> None:
    table = {(wallet.address, wallet.network) for wallet in wallet_preflight.WALLETS}
    for network, targets in restore.TARGETS.items():
        for address, _ in targets:
            assert (address, network) in table
            assert address not in (restore.MERCHANT, wallet_preflight.E2E_ACCOUNT)
    assert restore.MERCHANT != wallet_preflight.E2E_ACCOUNT
    assert set(restore.TARGETS) == {"hyperliquid", *evm.NETWORKS}


def test_hyperliquid_restores_two_exact_deficits(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A frozen clock: the second usdSend still needs a strictly higher nonce.
    monkeypatch.setattr("time.time", lambda: 1_700_000_000.0)
    purchase(fixture["evidence"], "P1")
    purchase(fixture["evidence"], "P5", blocked=True)
    run(fixture)
    # 20 - 19.35 = 0.65 and 3 - 2.28 = 0.72 USDC.
    assert [Decimal(send["action"]["amount"]) for send in fixture["sends"]] == [
        Decimal("0.65"),
        Decimal("0.72"),
    ]
    assert fixture["balances"][restore.HL_PAYER] == Decimal("20")
    assert fixture["balances"][restore.BLOCKED_PAYER] == Decimal("3")
    assert "E2E_MERCHANT_TESTNET_KEY" not in os.environ
    assert len(fixture["custody"]) == 1
    assert [send["nonce"] for send in fixture["sends"]] == [1_700_000_000_000, 1_700_000_000_001]
    summary = json.loads((work(fixture, "1") / "summary.json").read_text())
    assert summary == {"network": "hyperliquid", "status": "confirmed"}
    for path in work(fixture, "1").rglob("*.json"):
        assert path.stat().st_mode & 0o777 == 0o600
        assert all(
            secret not in path.read_text()
            for secret in (
                "offline-merchant-key",
                "offline-access",
                '"signature"',
                '"raw_transaction"',
            )
        )


@pytest.mark.parametrize("network,row", [("arbitrum", "P2"), ("base", "P3")])
def test_each_sepolia_restores_usdc_only(fixture: dict[str, Any], network: str, row: str) -> None:
    purchase(fixture["evidence"], row)
    run(fixture, network)
    assert len(fixture["sends"]) == 1
    tx = fixture["signs"][0]
    assert tx["chainId"] == evm.NETWORKS[network][1] and tx["value"] == 0
    assert int(tx["data"][-64:], 16) == 360000  # 20 - 19.64 USDC.
    assert fixture["balances"][restore.EVM_PAYER] == Decimal("20")
    receipt = json.loads(next(work(fixture, "1").rglob("receipt.json")).read_text())
    assert receipt["block_number"] == 0x10 and receipt["amount_micro"] == 360000


def test_plan_never_reads_the_merchant_key(fixture: dict[str, Any]) -> None:
    purchase(fixture["evidence"], "P1")
    result = plan(fixture)
    assert result["status"] == "planned"
    assert result["sends"] == [
        {"destination": restore.HL_PAYER, "baseline_micro": 20_000_000, "amount_micro": 650000}
    ]
    assert not fixture["custody"] and not fixture["sends"] and not fixture["signs"]


@pytest.mark.parametrize("balance", ["20", "20.1", "19.9999991"])
def test_baseline_or_submicro_gap_is_noop_without_custody(
    fixture: dict[str, Any], balance: str
) -> None:
    purchase(fixture["evidence"], "P1")
    fixture["balances"][restore.HL_PAYER] = Decimal(balance)
    run(fixture)
    assert not fixture["custody"] and not fixture["sends"]
    summary = json.loads((work(fixture, "1") / "summary.json").read_text())
    assert summary["status"] == "already-at-baseline"


def test_only_paid_payer_restored_including_renewal(fixture: dict[str, Any]) -> None:
    purchase(fixture["evidence"], "P6")
    run(fixture)
    assert len(fixture["sends"]) == 1
    assert fixture["sends"][0]["action"]["destination"] == restore.HL_PAYER


def test_no_payment_means_no_reads_and_no_custody(fixture: dict[str, Any]) -> None:
    run(fixture)
    assert not fixture["custody"] and not fixture["reads"] and not fixture["sends"]
    summary = json.loads((work(fixture, "1") / "summary.json").read_text())
    assert summary["status"] == "no-confirmed-payments"


@pytest.mark.parametrize("run_id,attempt", [("122", "1"), (RUN, "2")])
def test_other_run_or_later_attempt_receipts_never_authorize_restore(
    fixture: dict[str, Any], run_id: str, attempt: str
) -> None:
    purchase(fixture["evidence"], "P1", run=run_id, attempt=attempt)
    if run_id != RUN:
        # Another run's artifact inside this run's row namespace is refused outright.
        with pytest.raises(PaymentError):
            run(fixture)
    else:
        run(fixture)
    assert not fixture["custody"] and not fixture["sends"]


def test_rerun_uses_each_rows_latest_attempt_and_ignores_superseded_ones(
    fixture: dict[str, Any],
) -> None:
    # P1 attempt 1 is unresolved (no receipt) but superseded by its passing attempt 2.
    stale = purchase(fixture["evidence"], "P1", attempt="1")
    (stale / "payment-receipt.json").unlink()
    purchase(fixture["evidence"], "P1", attempt="2")
    run(fixture, attempt="2")
    assert len(fixture["sends"]) == 1
    # In attempt 3 the passing P5 of attempt 1 still counts: it was never rerun.
    purchase(fixture["evidence"], "P5", attempt="1", blocked=True)
    upload(fixture, "hyperliquid", "2")
    run(fixture, attempt="3")
    assert [Decimal(send["action"]["amount"]) for send in fixture["sends"]] == [
        Decimal("0.65"),
        Decimal("0.72"),
    ]


@pytest.mark.parametrize(
    "layout,accepted", [((), True), (("quote-evidence",), True), (("other",), False)]
)
def test_purchase_artifact_layouts(
    fixture: dict[str, Any], layout: tuple[str, ...], accepted: bool
) -> None:
    purchase(fixture["evidence"], "P1", layout=layout)
    if accepted:
        run(fixture)
        assert len(fixture["sends"]) == 1
    else:
        with pytest.raises(PaymentError):
            run(fixture)
        assert not fixture["custody"]


@pytest.mark.parametrize("network", ["mainnet", "ethereum", "base-mainnet", ""])
def test_nonallowlisted_network_refused_before_http(fixture: dict[str, Any], network: str) -> None:
    with pytest.raises(PaymentError):
        run(fixture, network)
    assert not fixture["reads"] and not fixture["custody"]


@pytest.mark.parametrize("attempt", ["0", "", "01", "1a", "-1"])
def test_exact_workflow_attempt_required(fixture: dict[str, Any], attempt: str) -> None:
    with pytest.raises(PaymentError):
        restore.plan("hyperliquid", fixture["evidence"], work(fixture, "1"), RUN, attempt)
    assert not fixture["reads"]


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-receipt",
        "missing-attempt",
        "failure-only",
        "accepted",
        "network",
        "amount",
        "order",
        "payer",
        "blocked-p1",
        "receipt-symlink",
        "parent-symlink",
    ],
)
def test_bad_or_unresolved_purchase_prevents_custody(
    fixture: dict[str, Any], mutation: str
) -> None:
    path = purchase(fixture["evidence"], "P1")
    receipt = path / "payment-receipt.json"
    value = json.loads(receipt.read_text())
    if mutation == "missing-receipt":
        receipt.unlink()
    elif mutation == "missing-attempt":
        (path / "payment-attempt.json").unlink()
    elif mutation == "failure-only":
        receipt.rename(path / "payment-failure.json")
    elif mutation == "receipt-symlink":
        saved = path / "saved.json"
        receipt.rename(saved)
        receipt.symlink_to(saved)
    elif mutation == "parent-symlink":
        saved = path.with_name("saved")
        path.rename(saved)
        path.symlink_to(saved, target_is_directory=True)
    else:
        if mutation == "blocked-p1":
            value.update(payer=restore.BLOCKED_PAYER, scenario="blocked")
        else:
            key, replacement = {
                "accepted": ("accepted", False),
                "network": ("network", "mainnet"),
                "amount": ("amount_micro", True),
                "order": ("order", "bad-order"),
                "payer": ("payer", restore.MERCHANT),
            }[mutation]
            value[key] = replacement
        receipt.write_text(json.dumps(value))
        (path / "payment-attempt.json").write_text(
            json.dumps({key: item for key, item in value.items() if key != "accepted"})
        )
    with pytest.raises(PaymentError):
        run(fixture)
    assert not fixture["custody"] and not fixture["sends"]


@pytest.mark.parametrize(
    "key,value",
    [
        ("chain", "mainnet"),
        ("profile", "production"),
        ("ok", False),
        ("priceDivisor", 1),
        ("priceDivisor", True),
        ("payTo", {"hyperliquid": restore.HL_PAYER}),
    ],
)
def test_staging_or_merchant_drift_refused_before_custody(
    fixture: dict[str, Any], key: str, value: Any
) -> None:
    purchase(fixture["evidence"], "P1")
    fixture["status"][key] = value
    with pytest.raises(PaymentError):
        run(fixture)
    assert not fixture["custody"] and not fixture["sends"]


@pytest.mark.parametrize(
    "field,value",
    [("positions", [{"position": {"coin": "BTC"}}]), ("withdrawable_offset", Decimal("-0.5"))],
)
def test_unexpected_hyperliquid_payer_state_refused_before_custody(
    fixture: dict[str, Any], field: str, value: Any
) -> None:
    purchase(fixture["evidence"], "P1")
    fixture[field] = value
    with pytest.raises(PaymentError, match="unexpected Hyperliquid payer state"):
        run(fixture)
    assert not fixture["custody"] and not fixture["sends"]


@pytest.mark.parametrize("network,row", [("hyperliquid", "P1"), ("base", "P3")])
def test_insufficient_merchant_usdc_never_partially_sends(
    fixture: dict[str, Any], network: str, row: str
) -> None:
    purchase(fixture["evidence"], row)
    fixture["balances"][restore.MERCHANT] = Decimal("0.01")
    with pytest.raises(PaymentError, match="USDC insufficient"):
        run(fixture, network)
    assert not fixture["sends"] and not fixture["custody"]


@pytest.mark.parametrize("network,row", [("hyperliquid", "P1"), ("base", "P3")])
def test_ambiguous_send_persists_attempt_and_never_retries(
    fixture: dict[str, Any], network: str, row: str
) -> None:
    purchase(fixture["evidence"], row)
    fixture["send_failure"] = True
    with pytest.raises(PaymentError):
        run(fixture, network)
    assert len(fixture["sends"]) == 1
    assert list(work(fixture, "1").rglob("attempt.json"))
    assert not list(work(fixture, "1").rglob("receipt.json"))
    # The same workspace refuses a second plan or send.
    with pytest.raises(PaymentError):
        run(fixture, network)
    # A rerun sees the uploaded unresolved attempt and refuses before custody.
    fixture["send_failure"] = False
    upload(fixture, network, "1")
    custody = len(fixture["custody"])
    with pytest.raises(PaymentError, match="unresolved"):
        run(fixture, network, attempt="2")
    assert len(fixture["sends"]) == 1 and len(fixture["custody"]) == custody


def test_errored_sepolia_broadcast_found_by_hash_is_confirmed_once(
    fixture: dict[str, Any],
) -> None:
    purchase(fixture["evidence"], "P2")
    fixture["send_failure"] = True
    fixture["known_after_failure"] = True
    run(fixture, "arbitrum")
    assert len(fixture["sends"]) == 1
    assert fixture["balances"][restore.EVM_PAYER] == Decimal("20")


@pytest.mark.parametrize("network,row", [("hyperliquid", "P1"), ("base", "P3")])
@pytest.mark.parametrize("credit,extra", [(False, "0"), (True, "0.000001"), (True, "-0.01")])
def test_credit_other_than_the_confirmed_send_fails_without_second_send(
    fixture: dict[str, Any], network: str, row: str, credit: bool, extra: str
) -> None:
    purchase(fixture["evidence"], row)
    fixture["credit"] = credit
    fixture["extra_credit"] = Decimal(extra)
    with pytest.raises(PaymentError, match="differs from the confirmed send"):
        run(fixture, network)
    assert len(fixture["sends"]) == 1
    assert list(work(fixture, "1").rglob("receipt.json"))
    assert not (work(fixture, "1") / "summary.json").exists()


@pytest.mark.parametrize(
    "field,value,before_custody",
    [
        ("chain_offset", 1, True),
        ("decimals", "0x12", True),
        ("pending", 3, True),
        ("gas", 1000001, False),
        ("price", 10**15, False),
        ("eth", 1, False),
    ],
)
def test_sepolia_chain_pending_or_gas_refusal_prevents_broadcast(
    fixture: dict[str, Any], field: str, value: Any, before_custody: bool
) -> None:
    purchase(fixture["evidence"], "P3")
    fixture[field] = value
    with pytest.raises(PaymentError):
        run(fixture, "base")
    assert not fixture["sends"] and not fixture["signs"]
    if before_custody:
        assert not fixture["custody"]


@pytest.mark.parametrize(
    "field,value", [("receipt_status", "0x0"), ("receipt_hash", False), ("block", "0x0")]
)
def test_bad_evm_receipt_keeps_only_attempt(
    fixture: dict[str, Any], field: str, value: Any
) -> None:
    purchase(fixture["evidence"], "P2")
    fixture[field] = value
    with pytest.raises(PaymentError):
        run(fixture, "arbitrum")
    assert len(fixture["sends"]) == 1
    assert not list(work(fixture, "1").rglob("receipt.json"))


@pytest.mark.parametrize("network,row", [("hyperliquid", "P1"), ("arbitrum", "P2")])
def test_rerun_after_confirmed_restore_is_a_noop(
    fixture: dict[str, Any], network: str, row: str
) -> None:
    purchase(fixture["evidence"], row)
    run(fixture, network)
    assert len(fixture["sends"]) == 1
    upload(fixture, network, "1")
    custody = len(fixture["custody"])
    run(fixture, network, attempt="2")
    assert len(fixture["sends"]) == 1 and len(fixture["custody"]) == custody
    result = json.loads((work(fixture, "2") / "plan.json").read_text())
    assert result["status"] == "payments-already-returned"
    # 0.65 USDC on Hyperliquid, 0.36 on Arbitrum Sepolia, paid and sent back once.
    payer = restore.HL_PAYER if network == "hyperliquid" else restore.EVM_PAYER
    amount = 650000 if network == "hyperliquid" else 360000
    assert result["paid_micro"] == {payer: amount}
    assert result["prior_sent_micro"] == {payer: amount}
    if network != "hyperliquid":
        assert result["floor_block"] == 0x10


@pytest.mark.parametrize("network,row", [("hyperliquid", "P1"), ("base", "P3")])
def test_lagging_read_rerun_sends_nothing_twice(
    fixture: dict[str, Any], network: str, row: str
) -> None:
    # Attempt 1's send is accepted, but its read-back lags: the exact-rise check fails.
    purchase(fixture["evidence"], row)
    fixture["credit"] = False
    with pytest.raises(PaymentError, match="differs from the confirmed send"):
        run(fixture, network)
    assert len(fixture["sends"]) == 1
    upload(fixture, network, "1")
    # The rerun still reads the stale balance (gap unchanged), yet owes nothing more:
    # paid 0.65 (0.36) less 0.65 (0.36) already returned.
    custody = len(fixture["custody"])
    run(fixture, network, attempt="2")
    assert len(fixture["sends"]) == 1 and len(fixture["custody"]) == custody
    result = json.loads((work(fixture, "2") / "plan.json").read_text())
    assert result["sends"] == [] and result["status"] == "payments-already-returned"


def test_outside_drain_is_not_refilled_beyond_this_runs_payment(
    fixture: dict[str, Any],
) -> None:
    # The payer sits at 19.35 (gap 0.65) but paid only 0.180001 in this run: the other
    # 0.469999 left it outside the run, and the merchant does not refill that.
    purchase(fixture["evidence"], "P1", amount=180001)
    run(fixture)
    assert [Decimal(send["action"]["amount"]) for send in fixture["sends"]] == [Decimal("0.180001")]
    assert fixture["balances"][restore.HL_PAYER] == Decimal("19.530001")
    summary = json.loads((work(fixture, "1") / "summary.json").read_text())
    assert summary["status"] == "confirmed"


def test_rerun_after_a_repaid_row_returns_nothing_beyond_the_latest_payment(
    fixture: dict[str, Any],
) -> None:
    # P1 attempt 1 paid 0.65 and was returned; P1 reran in attempt 2 and paid 0.180001.
    # The latest row (0.180001) less the 0.65 already returned owes nothing: a payer may
    # end below baseline, never above what this run took from it.
    purchase(fixture["evidence"], "P1")
    run(fixture)
    upload(fixture, "hyperliquid", "1")
    purchase(fixture["evidence"], "P1", attempt="2", amount=180001)
    fixture["balances"][restore.HL_PAYER] -= Decimal("0.180001")
    run(fixture, attempt="2")
    assert len(fixture["sends"]) == 1
    assert fixture["balances"][restore.HL_PAYER] == Decimal("19.819999")


def test_several_payments_from_one_payer_add_up(fixture: dict[str, Any]) -> None:
    # P1 0.4 + P6 0.25 = 0.65 USDC paid by the Hyperliquid payer: exactly its gap.
    purchase(fixture["evidence"], "P1", amount=400000)
    purchase(fixture["evidence"], "P6", amount=250000)
    run(fixture)
    assert [Decimal(send["action"]["amount"]) for send in fixture["sends"]] == [Decimal("0.65")]


def test_rerun_refuses_an_rpc_behind_the_confirmed_restore_block(
    fixture: dict[str, Any],
) -> None:
    # Attempt 1 returns P2's 0.1 USDC; P2 reruns in attempt 2 and pays 0.36, so 0.26 is
    # owed and the rerun must read balances, which a lagging node cannot serve.
    purchase(fixture["evidence"], "P2", amount=100000)
    run(fixture, "arbitrum")
    upload(fixture, "arbitrum", "1")
    purchase(fixture["evidence"], "P2", attempt="2")
    fixture["balances"][restore.EVM_PAYER] -= Decimal("0.36")
    fixture["head"] = 0x0F  # A lagging node, one block before the confirmed restore.
    with pytest.raises(PaymentError, match="behind a confirmed restore"):
        run(fixture, "arbitrum", attempt="2")
    assert len(fixture["sends"]) == 1


@pytest.mark.parametrize(
    "case",
    [
        "no-final",
        "no-receipt",
        "no-intent",
        "foreign-record",
        "receipt-amount",
        "receipt-nonce",
        "attempt-missing-binding",
    ],
)
def test_rerun_refuses_an_earlier_attempt_that_may_have_sent(
    fixture: dict[str, Any], case: str
) -> None:
    purchase(fixture["evidence"], "P1")
    run(fixture)
    if case == "no-final":
        upload(fixture, "hyperliquid", "1", final=False)
    else:
        upload(fixture, "hyperliquid", "1")
        final = fixture["evidence"] / f"wallet-restore-hyperliquid-{RUN}-1"
        if case == "no-receipt":
            next(final.rglob("receipt.json")).unlink()
        elif case == "no-intent":
            shutil.rmtree(fixture["evidence"] / f"wallet-restore-intent-hyperliquid-{RUN}-1")
        elif case in {"receipt-amount", "receipt-nonce"}:
            path = next(final.rglob("receipt.json"))
            receipt = json.loads(path.read_text())
            key = "amount_micro" if case == "receipt-amount" else "nonce"
            receipt[key] += 1  # A receipt for another send than the one announced.
            path.write_text(json.dumps(receipt))
        elif case == "attempt-missing-binding":
            path = next(final.rglob("attempt.json"))
            path.write_text(json.dumps({"amount_micro": 650000}))
        else:
            (final / restore.MERCHANT).mkdir()
            shutil.copy(next(final.rglob("attempt.json")), final / restore.MERCHANT)
    custody = len(fixture["custody"])
    with pytest.raises(PaymentError):
        run(fixture, attempt="2")
    assert len(fixture["sends"]) == 1 and len(fixture["custody"]) == custody


def test_rerun_admits_an_earlier_attempt_that_planned_nothing(fixture: dict[str, Any]) -> None:
    purchase(fixture["evidence"], "P1")
    fixture["balances"][restore.HL_PAYER] = Decimal("20")
    plan(fixture)
    upload(fixture, "hyperliquid", "1", final=False)  # Its runner was lost after planning.
    fixture["balances"][restore.HL_PAYER] = Decimal("19.35")
    run(fixture, attempt="2")
    assert len(fixture["sends"]) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("network", "base"),
        ("attempt", "2"),
        ("destination", restore.MERCHANT),
        ("destination", wallet_preflight.E2E_ACCOUNT),
        ("baseline_micro", 30_000_000),
        ("amount_micro", 20_000_001),
        ("amount_micro", True),
        ("amount_micro", 0),
    ],
)
def test_send_refuses_a_tampered_plan_before_custody(
    fixture: dict[str, Any], field: str, value: Any
) -> None:
    purchase(fixture["evidence"], "P1")
    plan(fixture)
    path = work(fixture, "1") / "plan.json"
    planned = json.loads(path.read_text())
    if field in planned:
        planned[field] = value
    else:
        planned["sends"][0][field] = value
    path.write_text(json.dumps(planned))
    with pytest.raises(PaymentError):
        restore.send("hyperliquid", work(fixture, "1"), RUN, "1")
    assert not fixture["custody"] and not fixture["sends"]


def test_merchant_key_must_derive_exact_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("E2E_MERCHANT_TESTNET_KEY", "offline-key")
    monkeypatch.setattr(Account, "from_key", lambda _: SimpleNamespace(address=restore.HL_PAYER))
    with pytest.raises(PaymentError, match="merchant key required"):
        restore.merchant_wallet()
    assert "E2E_MERCHANT_TESTNET_KEY" not in os.environ


@pytest.mark.parametrize(
    "sender,destination,amount",
    [
        (restore.MERCHANT, restore.MERCHANT, 1),
        (restore.MERCHANT, wallet_preflight.E2E_ACCOUNT, 1),
        (restore.MERCHANT, restore.HL_PAYER, 0),
        (restore.MERCHANT, restore.HL_PAYER, True),
        (restore.MERCHANT, restore.HL_PAYER, 20_000_001),
        (restore.MERCHANT, restore.BLOCKED_PAYER, 3_000_001),
        (restore.MERCHANT, restore.EVM_PAYER, 1),
        (wallet_preflight.E2E_ACCOUNT, restore.HL_PAYER, 1),
    ],
)
def test_send_boundary_refuses_unapproved_party_or_amount(
    sender: str, destination: str, amount: Any
) -> None:
    wallet: Any = SimpleNamespace(address=sender)
    with pytest.raises(PaymentError):
        restore.admit_send("hyperliquid", wallet, destination, amount)


@pytest.mark.parametrize("phase", ["plan", "send"])
def test_cleanup_cli_withholds_exception_text_and_consumes_secret(
    fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    phase: str,
) -> None:
    def failure(*args: Any) -> None:
        raise RuntimeError("sensitive-key-or-signed-payload")

    monkeypatch.setattr(restore, phase, failure)
    monkeypatch.setattr(
        "sys.argv",
        [
            "wallet-restore",
            "--phase",
            phase,
            "--network",
            "base",
            "--evidence",
            str(fixture["evidence"]),
            "--work",
            str(work(fixture, "1")),
        ],
    )
    assert restore.main() == 1
    assert "sensitive" not in capsys.readouterr().err
    assert "E2E_MERCHANT_TESTNET_KEY" not in os.environ


def jobs() -> dict[str, Any]:
    value: dict[str, Any] = document(WORKFLOW.read_text())["jobs"]
    return value


def cleanup_job() -> dict[str, Any]:
    job: dict[str, Any] = jobs()["wallet-restore"]
    return job


def test_cleanup_never_gates_release_admission_or_promotion() -> None:
    for name in ("gate", "completion", "promote", "install-matrix", "journeys"):
        assert "wallet-restore" not in str(jobs()[name].get("needs"))
        assert "wallet-restore" not in str(jobs()[name].get("if", ""))


@pytest.mark.parametrize(
    "cancelled,staging,journeys,installs",
    list(
        itertools.product(
            (False, True),
            ("success", "failure", "skipped", "cancelled"),
            ("success", "failure", "skipped", "cancelled"),
            ("success", "failure", "skipped", "cancelled"),
        )
    ),
)
def test_cleanup_admission_runs_after_every_trading_and_install_row_but_not_cancellation(
    cancelled: bool, staging: str, journeys: str, installs: str
) -> None:
    job = cleanup_job()
    assert job["needs"] == ["staging", "journeys", "install-matrix"]
    expression = job["if"].removeprefix("${{ ").removesuffix(" }}")
    expression = expression.replace("cancelled()", str(cancelled))
    expression = expression.replace("needs.staging.result", repr(staging))
    expression = expression.replace("needs.journeys.result", repr(journeys))
    expression = expression.replace("needs.install-matrix.result", repr(installs))
    expression = expression.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    result = eval(expression.strip(), {"__builtins__": {}}, {})
    assert result == (
        not cancelled
        and staging == "success"
        and journeys in {"success", "failure"}
        and installs in {"success", "failure", "skipped"}
    )


def test_cleanup_capabilities_locks_and_intent_before_custody() -> None:
    job = cleanup_job()
    assert job["environment"] == "e2e"
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    assert job["strategy"] == {
        "fail-fast": False,
        "matrix": {"network": ["hyperliquid", "arbitrum", "base"]},
    }
    # The same per-network lease as every paid purchase row and payment diagnostic.
    assert job["concurrency"] == {
        "group": "guard-e2e-purchase-${{ matrix.network }}",
        "cancel-in-progress": False,
        "queue": "max",
    }
    steps = job["steps"]

    def index(predicate: Any) -> int:
        found = [n for n, step in enumerate(steps) if predicate(step)]
        assert len(found) == 1
        return found[0]

    download = index(lambda step: "download-artifact@" in step.get("uses", ""))
    planning = index(lambda step: "--phase plan" in step.get("run", ""))
    intent = index(
        lambda step: (
            "upload-artifact@" in step.get("uses", "")
            and step["with"]["name"].startswith("wallet-restore-intent-")
        )
    )
    custody = index(lambda step: "E2E_MERCHANT_TESTNET_KEY" in str(step.get("env", {})))
    final = len(steps) - 1
    assert download < planning < intent < custody < final
    # Download every artifact: one directory per artifact keeps names and attempts.
    assert steps[download]["with"] == {"path": "${{ runner.temp }}/wallet-restore-evidence"}
    assert "E2E_MERCHANT" not in str(steps[planning])
    assert "--phase send" in steps[custody]["run"] and "set +x" in steps[custody]["run"]
    assert set(steps[custody]["env"]) == {
        "NETWORK",
        "GUARD_ACCESS_CLIENT_ID",
        "GUARD_ACCESS_CLIENT_SECRET",
        "E2E_MERCHANT_TESTNET_KEY",
    }
    assert steps[custody]["env"]["E2E_MERCHANT_TESTNET_KEY"] == (
        "${{ secrets.E2E_MERCHANT_TESTNET_KEY }}"
    )
    assert "if" not in steps[intent] and "if" not in steps[custody]
    run_suffix = "-${{ github.run_id }}-${{ github.run_attempt }}"
    assert (
        steps[intent]["with"]["name"] == "wallet-restore-intent-${{ matrix.network }}" + run_suffix
    )
    assert steps[final]["if"] == "${{ always() }}"
    assert steps[final]["with"]["name"] == "wallet-restore-${{ matrix.network }}" + run_suffix
    for upload_step in (steps[intent], steps[final]):
        # A passing attempt never leaves an older attempt's record to be selected.
        assert upload_step["with"]["if-no-files-found"] == "error"
        assert "wallet-restore-evidence" not in upload_step["with"]["path"]
        assert "**" not in upload_step["with"]["path"]
    # Never the E2E trading account, its key or its lock.
    assert "E2E_TESTNET" not in json.dumps(job)
    assert "guard-e2e-testnet" not in json.dumps(job)


def test_cleanup_artifact_names_stay_outside_every_gate_row_namespace() -> None:
    from guard_harness.release_state import GATE_JOURNEYS

    for network in restore.TARGETS:
        for name in (f"wallet-restore-{network}", f"wallet-restore-intent-{network}"):
            assert not any(name.startswith(row + "-") for row in GATE_JOURNEYS)
            assert not any(name.startswith(row) for row in ("state-chain", "complete-gate"))


@pytest.mark.parametrize("mutation", [None, "repository", "event", "source", "tag", "preview"])
@pytest.mark.parametrize("attempt", ["1", "2"])
def test_actual_cleanup_binding_script(mutation: str | None, attempt: str) -> None:
    env = {
        "GITHUB_REPOSITORY": "zunderlabs/zunder-guard",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "SOURCE": "a" * 40,
        "GITHUB_SHA": "a" * 40,
        "TAG": "v1.0.0-rc.16",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ATTEMPT": attempt,
    }
    if mutation:
        key, value = {
            "repository": ("GITHUB_REPOSITORY", "other/repo"),
            "event": ("GITHUB_EVENT_NAME", "push"),
            "source": ("SOURCE", "b" * 40),
            "tag": ("TAG", "not-a-release"),
            "preview": ("GITHUB_REF", "refs/heads/preview/w18"),
        }[mutation]
        env[key] = value
    result = subprocess.run(
        ["/bin/bash", "-c", cleanup_job()["steps"][0]["run"]],
        env=env,
        capture_output=True,
        timeout=5,
        check=False,
    )
    # Reruns are admitted: the restore itself is idempotent against prior attempts.
    assert (result.returncode == 0) == (mutation is None)
