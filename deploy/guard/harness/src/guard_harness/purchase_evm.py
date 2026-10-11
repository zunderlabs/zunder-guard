"""One exact Sepolia USDC payment; never retry a broadcast or ambiguous outcome."""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from eth_account import Account
from eth_utils.address import to_checksum_address

from guard_harness.purchase_payment import PaymentError, admit_order, record, request

# Public chain facts, verified against Circle, Arbitrum and Base documentation.
# https://developers.circle.com/stablecoins/usdc-contract-addresses
# https://docs.arbitrum.io/chain-info
# https://docs.base.org/get-started/connect-to-base
NETWORKS = {
    "arbitrum": (
        "https://sepolia-rollup.arbitrum.io/rpc",
        421614,
        "0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d",
    ),
    "base": (
        "https://sepolia.base.org",
        84532,
        "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
    ),
}
# Fixed testnet gas budget: at most 0.0002 test ETH, independently of RPC estimates.
MAX_FEE_WEI = 200_000_000_000_000


def rpc(network: str, method: str, params: list[object]) -> Any:
    response = request(
        NETWORKS[network][0],
        headers={"Content-Type": "application/json"},
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
    )
    if (
        response.get("jsonrpc") != "2.0"
        or type(response.get("id")) is not int
        or response["id"] != 1
        or "result" not in response
        or "error" in response
    ):
        raise PaymentError("Sepolia RPC admission failed; diagnostics withheld")
    return response["result"]


def quantity(value: Any) -> int:
    if not isinstance(value, str) or not re.fullmatch(
        r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})", value
    ):
        raise PaymentError("canonical bounded RPC quantity required")
    return int(value, 16)


def pay(network: str, order_number: str, amount: str, work: Path) -> dict[str, object]:
    if network not in NETWORKS:
        raise PaymentError("Arbitrum or Base Sepolia required")
    destination, micro = admit_order(order_number, amount, work, network)
    _, chain_id, token = NETWORKS[network]
    # Pinned chain identity is checked before custody; no RPC override or mainnet path.
    if quantity(rpc(network, "eth_chainId", [])) != chain_id:
        raise PaymentError("RPC is not the pinned Sepolia chain")
    key = os.environ.pop("E2E_PAYER_EVM_SEPOLIA_KEY", "")
    if not key:
        raise PaymentError("dedicated Sepolia payer key required")
    try:
        wallet = Account.from_key(key)
        nonce = quantity(rpc(network, "eth_getTransactionCount", [wallet.address, "pending"]))
        if nonce != quantity(rpc(network, "eth_getTransactionCount", [wallet.address, "latest"])):
            raise PaymentError("payer has a pending transaction; reconcile before payment")
        # ERC20 transfer(address,uint256), exact 6-decimal integer micro-USDC.
        data = "0xa9059cbb" + destination[2:].lower().zfill(64) + f"{micro:064x}"
        call = {"from": wallet.address, "to": token, "value": "0x0", "data": data}
        gas = quantity(rpc(network, "eth_estimateGas", [call]))
        price = quantity(rpc(network, "eth_gasPrice", []))
        if not 21_000 <= gas <= 1_000_000 or not 0 < gas * price <= MAX_FEE_WEI:
            raise PaymentError("Sepolia gas exceeds fixed test budget")
        transaction = {
            "chainId": chain_id,
            "nonce": nonce,
            "gas": gas,
            "gasPrice": price,
            "to": to_checksum_address(token),
            "value": 0,
            "data": data,
        }
        signed = wallet.sign_transaction(transaction)
        transaction_hash = "0x" + bytes(signed.hash).hex()
        raw = "0x" + bytes(signed.raw_transaction).hex()
    except PaymentError:
        raise
    except Exception:
        raise PaymentError("Sepolia signing failed; diagnostics withheld") from None
    finally:
        del key
    attempt: dict[str, object] = {
        "order": order_number,
        "network": network,
        "amount_micro": micro,
        "nonce": nonce,
        "transaction_hash": transaction_hash,
    }
    record(work, "payment-attempt.json", attempt)
    # Exactly one broadcast, preceded by a fsynced attempt. Read-only receipt polling
    # never re-sends, replaces or cancels the transaction, even after a timeout.
    if rpc(network, "eth_sendRawTransaction", [raw]) != transaction_hash:
        raise PaymentError("Sepolia broadcast unconfirmed; reconcile, never retry")
    deadline = time.monotonic() + 90
    while True:
        receipt = rpc(network, "eth_getTransactionReceipt", [transaction_hash])
        if receipt is not None:
            if (
                not isinstance(receipt, dict)
                or receipt.get("transactionHash") != transaction_hash
                or receipt.get("status") != "0x1"
                or quantity(receipt.get("blockNumber")) == 0
            ):
                raise PaymentError("Sepolia transaction not successful; reconcile, never retry")
            break
        if time.monotonic() >= deadline:
            raise PaymentError("Sepolia confirmation deadline; reconcile, never retry")
        time.sleep(5)
    result = {**attempt, "accepted": True}
    record(work, "payment-receipt.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=sorted(NETWORKS), required=True)
    parser.add_argument("--order", required=True)
    parser.add_argument("--amount", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    try:
        pay(args.network, args.order, args.amount, args.work)
        print("Sepolia test payment confirmed; follow C4 order and inbox to completion")
        return 0
    except Exception:
        print("Sepolia payment failed; reconcile private attempt, never retry", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
