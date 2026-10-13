"""One exact Sepolia USDC payment; never retry a broadcast or ambiguous outcome."""

import argparse
import json
import os
import re
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from eth_account import Account
from eth_utils.address import to_checksum_address

from guard_harness.purchase_payment import PaymentError, admit_order, record, request
from guard_harness.staged_subjects import _private

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

PAY_PHASES = frozenset(
    {
        "evm-order",
        "evm-chain",
        "evm-custody",
        "evm-nonce",
        "evm-gas-estimate",
        "evm-gas-price",
        "evm-base-fee",
        "evm-signing",
        "evm-attempt",
        "evm-broadcast",
        "evm-confirm",
        "evm-receipt",
    }
)
RPC_FAMILIES = frozenset(
    {
        "nonce-low",
        "nonce-conflict",
        "underpriced",
        "fee-cap-low",
        "gas-limit",
        "insufficient-funds",
        "rate-limit",
        "unknown",
    }
)
# Exact public messages only: suffixes, RPC data and arbitrary error text stay private.
RPC_MESSAGES = {
    "nonce too low": "nonce-low",
    "nonce too high": "nonce-conflict",
    "already known": "nonce-conflict",
    "nonce already used": "nonce-conflict",
    "replacement transaction underpriced": "underpriced",
    "transaction underpriced": "underpriced",
    "intrinsic gas too low": "gas-limit",
    "exceeds block gas limit": "gas-limit",
    "gas required exceeds allowance": "gas-limit",
    "insufficient funds": "insufficient-funds",
    "insufficient funds for gas * price + value": "insufficient-funds",
    "too many requests": "rate-limit",
    "rate limit exceeded": "rate-limit",
}


# Only fixed standard JSON-RPC codes and the reproduced Arbitrum server code are retained.
RPC_CODES = frozenset({-32700, -32600, -32601, -32602, -32603, -32000})
FEE_CAP_MESSAGE = re.compile(
    r"err: max fee per gas less than block base fee: address 0x[0-9a-fA-F]{40}, "
    r"maxFeePerGas: ([1-9][0-9]{0,77}), baseFee: ([1-9][0-9]{0,77}) "
    r"\(supplied gas ([1-9][0-9]{0,77})\)"
)


class RpcRejection(PaymentError):
    def __init__(self, family: str, code: object = None) -> None:
        self.code = code if type(code) is int and code in RPC_CODES else None
        self.family = family if type(family) is str and family in RPC_FAMILIES else "unknown"
        super().__init__("Sepolia RPC admission failed; diagnostics withheld")


def rpc_family(error: object) -> str:
    message = error.get("message") if type(error) is dict else None
    if type(message) is not str:
        return "unknown"
    exact = RPC_MESSAGES.get(message)
    if exact is not None:
        return exact
    matched = FEE_CAP_MESSAGE.fullmatch(message)
    if matched is not None:
        values = tuple(int(value) for value in matched.groups())
        if all(0 < value < 2**256 for value in values) and values[0] < values[1]:
            return "fee-cap-low"
    return "unknown"


def rpc(network: str, method: str, params: list[object]) -> Any:
    response = request(
        NETWORKS[network][0],
        headers={"Content-Type": "application/json"},
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
    )
    valid_identity = (
        response.get("jsonrpc") == "2.0" and type(response.get("id")) is int and response["id"] == 1
    )
    if valid_identity and "error" in response and "result" not in response:
        error = response["error"]
        code = error.get("code") if type(error) is dict else None
        raise RpcRejection(rpc_family(error), code)
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


def admitted_gas_price(gas: int, suggested: int, latest: object) -> int:
    """One fresh header, integer headroom, unchanged total cap before any signing.

    This only admits a new order's legacy gasPrice. It never replaces or retries
    a previously attempted transaction; the existing exclusive attempt remains binding.
    """
    if (
        type(gas) is not int
        or not 21_000 <= gas <= 1_000_000
        or type(suggested) is not int
        or not 0 < suggested < 2**256
        or not isinstance(latest, dict)
    ):
        raise PaymentError("Sepolia gas exceeds fixed test budget")
    base_fee = quantity(latest.get("baseFeePerGas"))
    if not 0 < base_fee < 2**255:
        raise PaymentError("canonical positive bounded Sepolia base fee required")
    # Hand-computed headroom: twice the latest base fee, or the higher RPC quote.
    price = max(suggested, 2 * base_fee)
    if not 0 < gas * price <= MAX_FEE_WEI:
        raise PaymentError("Sepolia gas exceeds fixed test budget")
    return price


# Read-only windows after the one broadcast. Both run from the send and end inside the journey's
# 180-second subprocess limit (subprocess.ts), admission included: 30 s to find the transaction
# by hash after the send errored, 90 s from the send to a receipt. Arbitrum Sepolia makes a block
# about every 0.25 s and Base Sepolia every 2 s, so a transaction the network has is mined well
# inside either window.
LOOKUP_SECONDS = 30
CONFIRM_SECONDS = 90
POLL_SECONDS = 3


class BroadcastUnseen(PaymentError):
    """The send errored and the signed hash was not found by lookup; the send's error stands."""

    def __init__(self, cause: PaymentError) -> None:
        self.cause = cause
        super().__init__("Sepolia broadcast not found by hash; reconcile, never retry")


# Marker: the network knows the transaction (by hash) but no receipt was read yet.
SEEN = object()


def lookup(network: str, transaction_hash: str, until: float) -> object:
    """After an errored send: the receipt, SEEN, or None once `until` passes unseen.

    Read-only and keyed by the signed hash; an RPC error here is retried until `until`,
    since it says nothing about the transaction.
    """
    while True:
        try:
            receipt = rpc(network, "eth_getTransactionReceipt", [transaction_hash])
            if receipt is not None:
                return receipt
            seen = rpc(network, "eth_getTransactionByHash", [transaction_hash])
            if isinstance(seen, dict) and seen.get("hash") == transaction_hash:
                return SEEN
        except PaymentError:
            pass
        if time.monotonic() >= until:
            return None
        time.sleep(POLL_SECONDS)


def await_receipt(network: str, transaction_hash: str, deadline: float) -> object:
    """The receipt of a transaction the network accepted; an RPC error is retried to `deadline`."""
    while True:
        try:
            receipt = rpc(network, "eth_getTransactionReceipt", [transaction_hash])
            if receipt is not None:
                return receipt
        except PaymentError:
            pass
        if time.monotonic() >= deadline:
            raise PaymentError("Sepolia confirmation deadline; reconcile, never retry")
        time.sleep(POLL_SECONDS)


def pay(
    network: str,
    order_number: str,
    amount: str,
    work: Path,
    *,
    observe: Callable[[str], None] | None = None,
) -> dict[str, object]:
    def phase(label: str) -> None:
        if observe is not None:
            observe(label)

    phase("evm-order")
    if network not in NETWORKS:
        raise PaymentError("Arbitrum or Base Sepolia required")
    destination, micro = admit_order(order_number, amount, work, network)
    _, chain_id, token = NETWORKS[network]
    # Pinned chain identity is checked before custody; no RPC override or mainnet path.
    phase("evm-chain")
    if quantity(rpc(network, "eth_chainId", [])) != chain_id:
        raise PaymentError("RPC is not the pinned Sepolia chain")
    phase("evm-custody")
    key = os.environ.pop("E2E_PAYER_EVM_SEPOLIA_KEY", "")
    if not key:
        raise PaymentError("dedicated Sepolia payer key required")
    try:
        wallet = Account.from_key(key)
        phase("evm-nonce")
        nonce = quantity(rpc(network, "eth_getTransactionCount", [wallet.address, "pending"]))
        if nonce != quantity(rpc(network, "eth_getTransactionCount", [wallet.address, "latest"])):
            raise PaymentError("payer has a pending transaction; reconcile before payment")
        # ERC20 transfer(address,uint256), exact 6-decimal integer micro-USDC.
        data = "0xa9059cbb" + destination[2:].lower().zfill(64) + f"{micro:064x}"
        call = {"from": wallet.address, "to": token, "value": "0x0", "data": data}
        phase("evm-gas-estimate")
        gas = quantity(rpc(network, "eth_estimateGas", [call]))
        phase("evm-gas-price")
        price = quantity(rpc(network, "eth_gasPrice", []))
        phase("evm-base-fee")
        latest = rpc(network, "eth_getBlockByNumber", ["latest", False])
        price = admitted_gas_price(gas, price, latest)
        transaction = {
            "chainId": chain_id,
            "nonce": nonce,
            "gas": gas,
            "gasPrice": price,
            "to": to_checksum_address(token),
            "value": 0,
            "data": data,
        }
        phase("evm-signing")
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
        "gas": gas,
        "gas_price": price,
        "max_total_fee_wei": gas * price,
    }
    phase("evm-attempt")
    record(work, "payment-attempt.json", attempt)
    # Exactly one broadcast, preceded by a fsynced attempt. Everything after it is read-only
    # and keyed by the signed hash: it never re-sends, replaces or cancels the transaction.
    phase("evm-broadcast")
    deadline = time.monotonic() + CONFIRM_SECONDS
    send_error: PaymentError | None = None
    try:
        if rpc(network, "eth_sendRawTransaction", [raw]) != transaction_hash:
            send_error = PaymentError("Sepolia broadcast unconfirmed; reconcile, never retry")
    except PaymentError as error:
        send_error = error
    receipt: object = None
    if send_error is not None:
        # The node's answer is not the outcome: a signed transaction can be in a pool or a
        # block although the send errored (lost response, a load-balanced RPC, "already
        # known"). Look for it by hash within a bounded window; unseen, the error stands.
        receipt = lookup(
            network, transaction_hash, min(deadline, time.monotonic() + LOOKUP_SECONDS)
        )
        if receipt is None:
            raise BroadcastUnseen(send_error)
    phase("evm-confirm")
    if receipt is None or receipt is SEEN:
        receipt = await_receipt(network, transaction_hash, deadline)
    if (
        not isinstance(receipt, dict)
        or receipt.get("transactionHash") != transaction_hash
        or receipt.get("status") != "0x1"
        or quantity(receipt.get("blockNumber")) == 0
    ):
        raise PaymentError("Sepolia transaction not successful; reconcile, never retry")
    result = {**attempt, "accepted": True}
    phase("evm-receipt")
    record(work, "payment-receipt.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", choices=sorted(NETWORKS), required=True)
    parser.add_argument("--order", required=True)
    parser.add_argument("--amount", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    current_phase = "unknown"
    attempt = False
    broadcast_started = False

    def observe(label: str) -> None:
        nonlocal current_phase, attempt, broadcast_started
        current_phase = label if type(label) is str and label in PAY_PHASES else "unknown"
        if current_phase == "evm-broadcast":
            attempt = True  # Only observed after the exclusive attempt was fsynced.
            broadcast_started = True  # Conservative: the one broadcast may have left custody.

    try:
        pay(args.network, args.order, args.amount, args.work, observe=observe)
        print("Sepolia test payment confirmed; follow C4 order and inbox to completion")
        return 0
    except Exception as error:
        # An unseen broadcast reports the send's own error, plus that the hash was not found.
        unseen = type(error) is BroadcastUnseen
        cause = error.cause if isinstance(error, BroadcastUnseen) else error
        family = cause.family if type(cause) is RpcRejection else None
        label = current_phase
        if type(family) is str and family in RPC_FAMILIES:
            label += "-" + family
        try:
            _private(args.work, directory=True)
            attempt = attempt or (args.work / "payment-attempt.json").exists()
            failure: dict[str, object] = {
                "phase": label,
                "attempt": attempt,
                "broadcast_started": broadcast_started,
            }
            if type(cause) is RpcRejection:
                failure["rpc_family"] = cause.family
                if cause.code is not None:
                    failure["rpc_code"] = cause.code
            if unseen:
                failure["seen_by_hash"] = False
            record(args.work, "payment-failure.json", failure)
        except Exception:
            pass  # Never overwrite evidence or let diagnostics obscure an ambiguous outcome.
        print(
            "Testnet payment failed at " + label + "; reconcile private receipts; never retry",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
