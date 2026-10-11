import json
import os
from pathlib import Path
from typing import Any

import pytest
from eth_account import Account

from guard_harness import purchase_payment as payment


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    tmp_path.chmod(0o700)
    for name, value in {
        "GUARD_STAGING_URL": "https://staging.example.test",
        "GUARD_ACCESS_CLIENT_ID": "access-id",
        "GUARD_ACCESS_CLIENT_SECRET": "access-secret",
        "GUARD_ORDER_TOKEN": "order-secret",
        "E2E_PAYER_HYPERLIQUID_TESTNET_KEY": "dummy-secret",
    }.items():
        monkeypatch.setenv(name, value)
    status: dict[str, Any] = {
        "ok": True,
        "open": True,
        "chain": "testnet",
        "profile": "staging",
        "priceDivisor": 1000,
        "payTo": {"hyperliquid": "0x" + "1" * 40},
    }
    order: dict[str, Any] = {
        "state": "quoted",
        "network": "hyperliquid",
        "amount_micro": 180001,
        "key_issued": False,
    }
    sends: list[dict[str, Any]] = []
    behavior = {"fail": False}

    def request(url: str, *, headers: dict[str, str], data: bytes | None = None) -> dict[str, Any]:
        if url.endswith("/status"):
            return status
        if "/test/order/" in url:
            assert headers["Authorization"] == "Bearer order-secret"
            return order
        assert url == "https://api.hyperliquid-testnet.xyz/exchange"
        assert headers == {"Content-Type": "application/json"} and data is not None
        assert "secret" not in data.decode()
        assert (tmp_path / "payment-attempt.json").is_file()
        assert "E2E_PAYER_HYPERLIQUID_TESTNET_KEY" not in os.environ
        sends.append(json.loads(data))
        if behavior["fail"]:
            raise payment.PaymentError("ambiguous send")
        return {"status": "ok", "response": {"type": "default"}}

    def wallet(key: str) -> object:
        assert key == "dummy-secret"
        return object()

    def sign(wallet: object, action: dict[str, Any], mainnet: bool) -> dict[str, int]:
        assert mainnet is False and action["amount"] == "0.180001"
        action["hyperliquidChain"] = "Testnet"
        return {"r": 1, "s": 2, "v": 27}

    monkeypatch.setattr(payment, "request", request)
    monkeypatch.setattr(Account, "from_key", wallet)
    monkeypatch.setattr(payment, "sign_usd_transfer_action", sign)
    return status, order, sends, behavior, tmp_path


def test_exact_testnet_payment_and_replay_refusal(setup: Any) -> None:
    _, _, sends, _, work = setup
    receipt = payment.pay("ZL-2026-000001", "0.180001", work)
    assert receipt["accepted"] is True and receipt["amount_micro"] == 180001
    assert sends[0]["action"]["amount"] == "0.180001"
    assert sends[0]["action"]["hyperliquidChain"] == "Testnet"
    with pytest.raises(payment.PaymentError, match="never retry"):
        payment.pay("ZL-2026-000001", "0.180001", work)
    assert len(sends) == 1
    for path in work.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
        assert "secret" not in path.read_text()


@pytest.mark.parametrize(
    "field,value",
    [("chain", "mainnet"), ("profile", "production"), ("open", False), ("priceDivisor", True)],
)
def test_bad_staging_refuses_before_key_custody(setup: Any, field: str, value: Any) -> None:
    status, _, sends, _, work = setup
    status[field] = value
    with pytest.raises(payment.PaymentError, match="testnet staging"):
        payment.pay("ZL-2026-000001", "0.180001", work)
    assert "E2E_PAYER_HYPERLIQUID_TESTNET_KEY" in os.environ
    assert not sends and not list(work.iterdir())


@pytest.mark.parametrize(
    "field,value",
    [("state", "paid"), ("network", "base"), ("amount_micro", 180000), ("key_issued", True)],
)
def test_order_mismatch_refuses_without_send(setup: Any, field: str, value: Any) -> None:
    _, order, sends, _, work = setup
    order[field] = value
    with pytest.raises(payment.PaymentError, match="exact unpaid"):
        payment.pay("ZL-2026-000001", "0.180001", work)
    assert not sends and not list(work.iterdir())


def test_ambiguous_send_has_durable_marker_and_never_retries(setup: Any) -> None:
    _, _, sends, behavior, work = setup
    behavior["fail"] = True
    with pytest.raises(payment.PaymentError, match="ambiguous"):
        payment.pay("ZL-2026-000001", "0.180001", work)
    assert (work / "payment-attempt.json").exists()
    assert not (work / "payment-receipt.json").exists()
    with pytest.raises(payment.PaymentError, match="never retry"):
        payment.pay("ZL-2026-000001", "0.180001", work)
    assert len(sends) == 1


@pytest.mark.parametrize("amount", ["0", "1", "1.0", "0.0000001", "0.000000", "NaN", "1e-3", 0.18])
def test_amount_refuses_floats_or_outside_exact_subdollar_bound(amount: object) -> None:
    with pytest.raises(payment.PaymentError):
        payment.amount_micro(amount)
