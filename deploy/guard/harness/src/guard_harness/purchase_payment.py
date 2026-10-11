"""One bounded Hyperliquid testnet purchase payment; ambiguous sends never retry."""

import argparse
import json
import os
import re
import sys
import time
import urllib.request
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from eth_account import Account
from hyperliquid.utils.signing import sign_usd_transfer_action

from guard_harness.staged_subjects import _private

TESTNET = "https://api.hyperliquid-testnet.xyz/exchange"


class PaymentError(RuntimeError):
    pass


def request(url: str, *, headers: dict[str, str], data: bytes | None = None) -> dict[str, Any]:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: Any, **kwargs: Any) -> None:
            return None

    try:
        req = urllib.request.Request(
            url, data=data, headers={**headers, "User-Agent": "guard-release-journey/1"}
        )
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=20) as response:
            captured = response.read(65537)
            if response.status != 200 or len(captured) > 65536:
                raise PaymentError("payment endpoint response refused")
        value: Any = json.loads(captured)
        if not isinstance(value, dict):
            raise PaymentError("payment endpoint JSON object required")
        return value
    except Exception:
        raise PaymentError("payment endpoint failed; sensitive diagnostics withheld") from None


def amount_micro(value: object) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0\.[0-9]{1,6}", value):
        raise PaymentError("positive sub-dollar decimal-string testnet payment required")
    amount = Decimal(value) * 1_000_000
    if not 0 < amount < 1_000_000:
        raise PaymentError("testnet payment outside fixed sub-dollar bound")
    return int(amount)


def admit_order(order_number: str, amount: str, work: Path, network: str) -> tuple[str, int]:
    """Recheck C4 status and authenticated order before taking custody of the payer key.

    `work` is a fresh private directory. An exclusive attempt marker persists before any send;
    neither success nor failure permits retrying this order in that directory.
    """
    if network not in {"hyperliquid", "arbitrum", "base"}:
        raise PaymentError("unsupported testnet purchase network")
    _private(work, directory=True)
    if not re.fullmatch(r"ZL-[0-9]{4}-[0-9]{6}", order_number):
        raise PaymentError("C4 order identity required")
    micro = amount_micro(amount)
    if (work / "payment-attempt.json").exists():
        raise PaymentError("payment already attempted; reconcile order, never retry")
    base = os.environ.get("GUARD_STAGING_URL", "").rstrip("/")
    parsed = urlsplit(base)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise PaymentError("staging HTTPS origin without credentials required")
    headers = {
        "CF-Access-Client-Id": os.environ.get("GUARD_ACCESS_CLIENT_ID", ""),
        "CF-Access-Client-Secret": os.environ.get("GUARD_ACCESS_CLIENT_SECRET", ""),
    }
    token = os.environ.get("GUARD_ORDER_TOKEN", "")
    if not all(headers.values()) or not token:
        raise PaymentError("C4 Access and order credentials required")
    status = request(base + "/api/licence/status", headers=headers)
    targets = status.get("payTo")
    destination = targets.get(network) if isinstance(targets, dict) else None
    if (
        status.get("ok") is not True
        or status.get("open") is not True
        or status.get("chain") != "testnet"
        or status.get("profile") != "staging"
        or type(status.get("priceDivisor")) is not int
        or status["priceDivisor"] != 1000
        or not isinstance(destination, str)
        or not re.fullmatch(r"0x[0-9a-fA-F]{40}", destination)
    ):
        raise PaymentError("open testnet staging and payment target required")
    order = request(
        base + "/api/licence/test/order/" + order_number,
        headers={**headers, "Authorization": "Bearer " + token},
    )
    if (
        order.get("state") != "quoted"
        or order.get("network") != network
        or type(order.get("amount_micro")) is not int
        or order["amount_micro"] != micro
        or order.get("key_issued") is not False
    ):
        raise PaymentError("exact unpaid testnet order required")
    return destination, micro


def record(work: Path, name: str, value: dict[str, object]) -> None:
    try:
        with (work / name).open("x") as stream:
            (work / name).chmod(0o600)
            stream.write(json.dumps(value) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        raise PaymentError("payment already attempted; reconcile order, never retry") from None


def pay(order_number: str, amount: str, work: Path) -> dict[str, object]:
    destination, micro = admit_order(order_number, amount, work, "hyperliquid")
    # Consume once, never retain the key in a subprocess environment or receipt.
    key = os.environ.pop("E2E_PAYER_HYPERLIQUID_TESTNET_KEY", "")
    if not key:
        raise PaymentError("dedicated testnet payer key required")
    try:
        wallet = Account.from_key(key)
        nonce = int(time.time() * 1000)
        action = {"destination": destination, "amount": amount, "time": nonce, "type": "usdSend"}
        signature = sign_usd_transfer_action(wallet, action, False)
        body = json.dumps({"action": action, "nonce": nonce, "signature": signature}).encode()
    except Exception:
        raise PaymentError("testnet payment signing failed; diagnostics withheld") from None
    finally:
        del key
    attempt = {
        "order": order_number,
        "network": "hyperliquid",
        "amount_micro": micro,
        "nonce": nonce,
    }
    record(work, "payment-attempt.json", attempt)
    response = request(TESTNET, headers={"Content-Type": "application/json"}, data=body)
    accepted = response.get("response")
    if (
        response.get("status") != "ok"
        or not isinstance(accepted, dict)
        or accepted.get("type") != "default"
    ):
        raise PaymentError("testnet payment not confirmed; reconcile order, never retry")
    receipt = {**attempt, "accepted": True}
    record(work, "payment-receipt.json", receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--order", required=True)
    parser.add_argument("--amount", required=True)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    try:
        pay(args.order, args.amount, args.work)
        print("Hyperliquid testnet payment accepted; follow C4 order and inbox to completion")
        return 0
    except Exception:
        print(
            "Testnet payment failed; inspect private attempt receipt and reconcile; never retry",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
