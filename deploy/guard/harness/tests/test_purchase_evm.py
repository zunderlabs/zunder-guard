import json
import os
import time
from pathlib import Path
from typing import Any

import pytest
from eth_account import Account

from guard_harness import purchase_evm as evm
from guard_harness import purchase_payment as common


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    tmp_path.chmod(0o700)
    for name, value in {
        "GUARD_STAGING_URL": "https://staging.example.test",
        "GUARD_ACCESS_CLIENT_ID": "access-id",
        "GUARD_ACCESS_CLIENT_SECRET": "access-secret",
        "GUARD_ORDER_TOKEN": "order-secret",
        "GUARD_PAY_TO_BASE": "0x" + "2" * 40,
        "GUARD_PAY_TO_ARBITRUM": "0x" + "2" * 40,
        "E2E_PAYER_EVM_SEPOLIA_KEY": "offline-key",
    }.items():
        monkeypatch.setenv(name, value)
    state: dict[str, Any] = {
        "network": "base",
        "chain": "testnet",
        "chain_id": 84532,
        "pending": 2,
        "latest": 2,
        "gas": 50000,
        "price": 1000000000,
        "receipt_status": "0x1",
        "broadcast": "ok",
        "state": "quoted",
        "micro": 180001,
    }
    transactions: list[dict[str, Any]] = []
    broadcasts: list[str] = []
    key_reads: list[str] = []
    original_from_key = Account.from_key
    wallet = original_from_key(bytes([1]) * 32)

    def custody(key: Any) -> Any:
        if key == "offline-key":
            key_reads.append(key)
            return wallet
        return original_from_key(key)

    def signing(transaction: dict[str, Any]) -> Any:
        transactions.append(transaction)
        return Account.sign_transaction(transaction, bytes([1]) * 32)

    monkeypatch.setattr(wallet, "sign_transaction", signing)
    monkeypatch.setattr(Account, "from_key", custody)

    def staging(url: str, *, headers: dict[str, str], data: bytes | None = None) -> dict[str, Any]:
        assert url.startswith("https://staging.example.test/") and data is None
        if url.endswith("/status"):
            return {
                "ok": True,
                "open": True,
                "chain": state["chain"],
                "profile": "staging",
                "priceDivisor": 1000,
                "payTo": {state["network"]: "0x" + "2" * 40},
            }
        assert headers["Authorization"] == "Bearer order-secret"
        return {
            "state": state["state"],
            "network": state["network"],
            "amount_micro": state["micro"],
            "key_issued": False,
        }

    def rpc(network: str, method: str, params: list[object]) -> Any:
        assert network == state["network"]
        if method == "eth_chainId":
            assert "E2E_PAYER_EVM_SEPOLIA_KEY" in os.environ and not key_reads
            return hex(state["chain_id"])
        assert "E2E_PAYER_EVM_SEPOLIA_KEY" not in os.environ
        if method == "eth_getTransactionCount":
            return hex(state[str(params[1])])
        if method == "eth_estimateGas":
            return hex(state["gas"])
        if method == "eth_gasPrice":
            return hex(state["price"])
        if method == "eth_sendRawTransaction":
            assert (tmp_path / "payment-attempt.json").stat().st_mode & 0o777 == 0o600
            raw = str(params[0])
            assert Account.recover_transaction(raw) == wallet.address
            broadcasts.append(raw)
            if state["broadcast"] == "unknown":
                raise common.PaymentError("unknown broadcast")
            digest = json.loads((tmp_path / "payment-attempt.json").read_bytes())[
                "transaction_hash"
            ]
            return digest if state["broadcast"] == "ok" else "0x" + "0" * 64
        assert method == "eth_getTransactionReceipt"
        return {
            "transactionHash": params[0],
            "status": state["receipt_status"],
            "blockNumber": "0x1",
        }

    monkeypatch.setattr(common, "request", staging)
    monkeypatch.setattr(evm, "rpc", rpc)
    return state, transactions, broadcasts, key_reads, tmp_path


@pytest.mark.parametrize("network,chain_id", [("base", 84532), ("arbitrum", 421614)])
def test_exact_sepolia_transfer_signed_and_sent_once(
    setup: Any, network: str, chain_id: int
) -> None:
    state, transactions, broadcasts, keys, work = setup
    state.update(network=network, chain_id=chain_id)
    receipt = evm.pay(network, "ZL-2026-000001", "0.180001", work)
    assert receipt["accepted"] is True and receipt["amount_micro"] == 180001
    transaction = transactions[0]
    assert transaction["chainId"] == chain_id and transaction["value"] == 0
    assert transaction["to"].lower() == evm.NETWORKS[network][2]
    # 0.180001 USDC * 10^6 = 180001, encoded after the exact merchant's 32-byte address.
    assert transaction["data"] == "0xa9059cbb" + ("2" * 40).zfill(64) + f"{180001:064x}"
    assert len(keys) == len(broadcasts) == 1
    with pytest.raises(common.PaymentError, match="never retry"):
        evm.pay(network, "ZL-2026-000001", "0.180001", work)
    assert len(broadcasts) == 1
    for path in work.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
        assert "offline-key" not in path.read_text() and "access-secret" not in path.read_text()


@pytest.mark.parametrize(
    "field,value", [("chain", "mainnet"), ("chain_id", 8453), ("micro", 180000), ("state", "paid")]
)
def test_admission_refuses_before_key(setup: Any, field: str, value: object) -> None:
    state, transactions, broadcasts, keys, work = setup
    state[field] = value
    with pytest.raises(common.PaymentError):
        evm.pay("base", "ZL-2026-000001", "0.180001", work)
    assert not transactions and not broadcasts and not keys and not list(work.iterdir())


@pytest.mark.parametrize(
    "field,value", [("pending", 3), ("gas", 20000), ("price", 0), ("price", 5000000000)]
)
def test_pending_or_gas_budget_refuses_before_signing(setup: Any, field: str, value: int) -> None:
    state, transactions, broadcasts, _, work = setup
    state[field] = value
    with pytest.raises(common.PaymentError):
        evm.pay("base", "ZL-2026-000001", "0.180001", work)
    assert not transactions and not broadcasts and not list(work.iterdir())


@pytest.mark.parametrize(
    "field,value", [("broadcast", "unknown"), ("broadcast", "wrong"), ("receipt_status", "0x0")]
)
def test_failed_broadcast_or_receipt_cannot_retry(setup: Any, field: str, value: str) -> None:
    state, _, broadcasts, _, work = setup
    state[field] = value
    with pytest.raises(common.PaymentError):
        evm.pay("base", "ZL-2026-000001", "0.180001", work)
    assert (work / "payment-attempt.json").exists() and not (work / "payment-receipt.json").exists()
    with pytest.raises(common.PaymentError, match="never retry"):
        evm.pay("base", "ZL-2026-000001", "0.180001", work)
    assert len(broadcasts) == 1


@pytest.mark.parametrize("value", ["0x", "0x00", "0x01", "0x-1", "1", True, "0x" + "f" * 65])
def test_noncanonical_rpc_quantity_refused(value: object) -> None:
    with pytest.raises(common.PaymentError):
        evm.quantity(value)


@pytest.mark.parametrize("network", ["arbitrum", "base"])
def test_rpc_uses_only_pinned_sepolia_endpoint_without_access_credentials(
    monkeypatch: pytest.MonkeyPatch, network: str
) -> None:
    def request(url: str, *, headers: dict[str, str], data: bytes | None = None) -> dict[str, Any]:
        assert url == evm.NETWORKS[network][0]
        assert headers == {"Content-Type": "application/json"}
        assert data is not None
        assert json.loads(data) == {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_chainId",
            "params": [],
        }
        return {"jsonrpc": "2.0", "id": 1, "result": hex(evm.NETWORKS[network][1])}

    monkeypatch.setattr(evm, "request", request)
    assert evm.quantity(evm.rpc(network, "eth_chainId", [])) == evm.NETWORKS[network][1]


@pytest.mark.parametrize(
    "response",
    [
        {"jsonrpc": "2.0", "id": True, "result": "0x1"},
        {"jsonrpc": "2.0", "id": 2, "result": "0x1"},
        {"jsonrpc": "2.0", "id": 1, "error": {"message": "sensitive detail"}},
        {"jsonrpc": "2.0", "id": 1, "result": "0x1", "error": None},
    ],
)
def test_rpc_failure_or_wrong_request_id_is_not_admitted(
    monkeypatch: pytest.MonkeyPatch, response: dict[str, Any]
) -> None:
    monkeypatch.setattr(evm, "request", lambda *args, **kwargs: response)
    with pytest.raises(common.PaymentError, match="diagnostics withheld"):
        evm.rpc("base", "eth_chainId", [])


def test_unconfirmed_receipt_deadline_preserves_one_attempt(
    setup: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, broadcasts, _, work = setup
    rpc = evm.rpc
    monkeypatch.setattr(
        evm,
        "rpc",
        lambda network, method, params: (
            None if method == "eth_getTransactionReceipt" else rpc(network, method, params)
        ),
    )
    ticks = iter([0, 91])
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    with pytest.raises(common.PaymentError, match="never retry"):
        evm.pay("base", "ZL-2026-000001", "0.180001", work)
    assert len(broadcasts) == 1 and (work / "payment-attempt.json").exists()
    assert not (work / "payment-receipt.json").exists()
