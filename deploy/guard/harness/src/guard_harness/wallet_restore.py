"""Restore paid staging payers to fixed testnet USDC baselines from the staging merchant.

Decision of 14 Oct 2026: after the purchase journeys have recorded their receipts, `verify`
sends testnet USDC from the staging merchant back to each payer that paid, up to a fixed
baseline (Hyperliquid payer 20, blocked payer 3, EVM payer 20 per Sepolia chain). Testnet
only, only to the pinned payer addresses, never more than the gap to baseline, never from
or to the E2E trading account, never the production merchant. Each payer also gets at most
what it paid in this run's confirmed receipts (each row's latest attempt) less what earlier
attempts of this job already returned to it, so a stale read cannot pay twice and a drain
from outside the run is left to a person.

The job runs in two phases under the network's purchase lock, after every trading and
install row of the run has finished:

* `plan` reads, never signs: it admits prior attempts of this job in the same run, the
  latest purchase receipts, staging's merchant and the chain, then fsyncs `plan.json`.
  The workflow uploads that plan as an intent artifact before any key is read.
* `send` takes the merchant key, re-reads each gap, sends at most min(planned, fresh gap)
  once per payer, confirms the outcome and checks the payer's balance rose by exactly
  that amount.

A rerun (the gate admits each row's latest attempt, so reruns of failed jobs are normal)
re-reads balances and subtracts earlier confirmed returns, so it sends nothing twice. A
prior attempt that uploaded an intent with sends is admitted only through its own uploaded
records with a confirmed receipt, bound to its fsynced attempt, for every attempted send;
anything else is refused for reconciliation.
No key, signed request, raw RPC reply or exception text enters the evidence.
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from decimal import ROUND_DOWN, Decimal, InvalidOperation, localcontext
from pathlib import Path
from typing import Any, cast

from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_typing import HexStr
from eth_utils.address import to_checksum_address
from hyperliquid.utils.signing import sign_usd_transfer_action

from guard_harness import purchase_evm as evm
from guard_harness.attestation import AttestationError
from guard_harness.purchase_payment import PaymentError, record, request
from guard_harness.run_attempts import attempts
from guard_harness.staged_subjects import _private
from guard_harness.wallet_preflight import E2E_ACCOUNT

# Pinned from the reviewed staging wallet table. Rotation requires code review.
MERCHANT = "0xb7a84cd527fc745c27de6090bb4badb909c5a0c9"
HL_PAYER = "0xc7834077426685f0aba6b369feb6f9d8bf3cf3e7"
BLOCKED_PAYER = "0x701efb44af39b74755abbc3ced664c622485b4a7"
EVM_PAYER = "0xdee26666d6240fe3309538a87dd7e0ff0d7e7bfc"
# Baselines in micro-USDC, per the 14 Oct 2026 decision.
TARGETS: dict[str, tuple[tuple[str, int], ...]] = {
    "hyperliquid": ((HL_PAYER, 20_000_000), (BLOCKED_PAYER, 3_000_000)),
    "arbitrum": ((EVM_PAYER, 20_000_000),),
    "base": ((EVM_PAYER, 20_000_000),),
}
# Purchase rows that pay on each network; their per-network lock is the one this job holds.
ROWS = {"hyperliquid": ("P1", "P5", "P6"), "arbitrum": ("P2",), "base": ("P3",)}
HL_INFO = "https://api.hyperliquid-testnet.xyz/info"
HL_EXCHANGE = "https://api.hyperliquid-testnet.xyz/exchange"
STAGING = "https://staging.zunderlabs.com"
# A payer above this holds something unexpected; refuse rather than guess (micro-USDC).
PAYER_CEILING = 1_000_000_000
RUN = re.compile(r"[1-9][0-9]{0,19}")

_PAYERS = {address for pairs in TARGETS.values() for address, _ in pairs}
if E2E_ACCOUNT in _PAYERS | {MERCHANT} or MERCHANT in _PAYERS:
    raise RuntimeError("restore parties must exclude the E2E account; the merchant pays only")


@dataclass(frozen=True)
class Prior:
    """What earlier attempts of this job in the same run did, from their own uploads."""

    sent: dict[str, int]
    floor_block: int


def gap(balance: Decimal, baseline: int) -> int:
    """Floor to micro-USDC: a fractional micro-dollar must never overfill baseline."""
    if not balance.is_finite() or balance < 0 or balance * 1_000_000 > PAYER_CEILING:
        raise PaymentError("wallet balance refused")
    with localcontext() as context:
        context.prec = 80
        deficit = Decimal(baseline) - balance * 1_000_000
        return max(0, int(deficit.to_integral_value(rounding=ROUND_DOWN)))


def decimal_balance(value: object) -> Decimal:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,13}(?:\.[0-9]{1,18})?", value):
        raise PaymentError("wallet balance refused")
    try:
        result = Decimal(value)
    except InvalidOperation:
        raise PaymentError("wallet balance refused") from None
    if not result.is_finite() or result > Decimal("1000000000000"):
        raise PaymentError("wallet balance refused")
    return result


def json_file(path: Path, what: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise PaymentError(what + " refused")
    try:
        value: Any = json.loads(path.read_bytes())
    except (ValueError, UnicodeDecodeError):
        raise PaymentError(what + " refused") from None
    if not isinstance(value, dict):
        raise PaymentError(what + " refused")
    return value


def _safe_tree(root: Path, what: str) -> None:
    if root.is_symlink() or not root.is_dir() or any(p.is_symlink() for p in root.rglob("*")):
        raise PaymentError(what + " refused")


def _attempts(evidence: Path, prefix: str, run_id: str, below: int) -> dict[int, Path]:
    """This run's attempts < `below` of one artifact; an ambiguous namespace refuses."""
    try:
        found = attempts(evidence, prefix, run_id)
    except AttestationError:
        raise PaymentError("restore evidence artifacts refused") from None
    return {k: path for k, path in found.items() if k < below}


def _latest(evidence: Path, prefix: str, run_id: str, attempt: str) -> Path | None:
    """This run's latest attempt <= ours of one artifact, or None when it never uploaded."""
    found = _attempts(evidence, prefix, run_id, int(attempt) + 1)
    return found[max(found)] if found else None


def paid_targets(evidence: Path, network: str, run_id: str, attempt: str) -> dict[str, int]:
    """Micro-USDC each payer paid in confirmed receipts of each row's latest attempt.

    The gate admits each row's latest attempt <= its own; superseded attempts are ignored
    here too. A payment attempt without its receipt is unresolved, also when a failure
    record sits beside it: the whole restore refuses until a person reconciles it.
    """
    paid: dict[str, int] = {}
    for row in ROWS[network]:
        root = _latest(evidence, row, run_id, attempt)
        if root is None:
            continue  # A row that never uploaded creates no restore authority.
        _safe_tree(root, "purchase receipt")
        attempted = list(root.rglob("payment-attempt.json"))
        receipts = list(root.rglob("payment-receipt.json"))
        if len(attempted) > 10 or len(receipts) > 10:
            raise PaymentError("purchase receipt refused")
        if {p.parent for p in attempted} != {p.parent for p in receipts}:
            raise PaymentError("purchase outcome unresolved; reconcile before restore")
        cases: tuple[str, ...] = ("payment",)
        if row == "P5":
            cases = ("under", "over", "late", "blocked")
        elif row == "P6":
            cases = ("payment", "renewal-payment")
        for path in receipts:
            parts = path.relative_to(root).parts
            # upload-artifact roots the files at their common ancestor: the evidence
            # directory itself, or its parent when the attestation bundle sits beside it.
            if parts[:-3] not in ((), ("quote-evidence",)) or parts[-3:] not in {
                (row, case, "payment-receipt.json") for case in cases
            }:
                raise PaymentError("purchase receipt refused")
            receipt = json_file(path, "purchase receipt")
            sent = json_file(path.with_name("payment-attempt.json"), "purchase receipt")
            if (
                receipt != {**sent, "accepted": True}
                or receipt.get("network") != network
                or not isinstance(receipt.get("order"), str)
                or not re.fullmatch(r"ZL-[0-9]{4}-[0-9]{6}", receipt["order"])
                or type(receipt.get("amount_micro")) is not int
                or not 0 < receipt["amount_micro"] < 1_000_000
            ):
                raise PaymentError("purchase receipt refused")
            payer = EVM_PAYER
            if network == "hyperliquid":
                payer = receipt.get("payer", "")
                expected = BLOCKED_PAYER if receipt.get("scenario") == "blocked" else HL_PAYER
                if payer != expected or (payer == BLOCKED_PAYER and row != "P5"):
                    raise PaymentError("purchase payer refused")
            paid[payer] = paid.get(payer, 0) + receipt["amount_micro"]
    return paid


def prior_attempts(evidence: Path, network: str, run_id: str, attempt: str) -> Prior:
    """Admit earlier attempts of this job only when every send they may have made is confirmed.

    The intent artifact is uploaded after planning and before the merchant key is read,
    so an attempt without one never sent. An attempt whose intent planned sends must have
    uploaded its records, and each fsynced `attempt.json` needs its `receipt.json`.
    """
    intents = _attempts(evidence, f"wallet-restore-intent-{network}", run_id, int(attempt))
    finals = _attempts(evidence, f"wallet-restore-{network}", run_id, int(attempt))
    sent: dict[str, int] = {}
    floor = 0
    for k in sorted(set(intents) | set(finals)):
        planned: list[Any] = []
        if k in intents:
            _safe_tree(intents[k], "prior restore intent")
            plan = json_file(intents[k] / "plan.json", "prior restore intent")
            if (
                plan.get("network") != network
                or plan.get("run_id") != run_id
                or plan.get("attempt") != str(k)
                or not isinstance(plan.get("sends"), list)
            ):
                raise PaymentError("prior restore intent refused")
            planned = plan["sends"]
        final = finals.get(k)
        if final is None:
            if planned:
                raise PaymentError("prior restore attempt unresolved; reconcile, never retry")
            continue
        _safe_tree(final, "prior restore record")
        broadcasts = list(final.rglob("attempt.json"))
        if broadcasts and not planned:
            raise PaymentError("prior restore record without intent; reconcile, never retry")
        for path in broadcasts:
            parts = path.relative_to(final).parts
            if len(parts) != 2 or parts[0] not in dict(TARGETS[network]):
                raise PaymentError("prior restore record refused")
            receipt_path = path.with_name("receipt.json")
            if not receipt_path.exists():
                raise PaymentError("prior restore send unresolved; reconcile, never retry")
            receipt = json_file(receipt_path, "prior restore record")
            started = json_file(path, "prior restore record")
            amount = receipt.get("amount_micro")
            # The receipt must confirm exactly the send its fsynced attempt announced.
            binding = ("amount_micro", "nonce" if network == "hyperliquid" else "transaction_hash")
            if (
                receipt.get("accepted") is not True
                or type(amount) is not int
                or amount <= 0
                or any(key not in started or receipt.get(key) != started[key] for key in binding)
            ):
                raise PaymentError("prior restore record refused")
            sent[parts[0]] = sent.get(parts[0], 0) + amount
            if network != "hyperliquid":
                block = receipt.get("block_number")
                if type(block) is not int or block <= 0:
                    raise PaymentError("prior restore record refused")
                floor = max(floor, block)
    return Prior(sent, floor)


def staging_admission(network: str) -> None:
    headers = {
        "CF-Access-Client-Id": os.environ.get("GUARD_ACCESS_CLIENT_ID", ""),
        "CF-Access-Client-Secret": os.environ.get("GUARD_ACCESS_CLIENT_SECRET", ""),
    }
    if not all(headers.values()):
        raise PaymentError("staging Access credentials required")
    status = request(STAGING + "/api/licence/status", headers=headers)
    targets = status.get("payTo")
    merchant = targets.get(network) if isinstance(targets, dict) else None
    if (
        status.get("ok") is not True
        or status.get("chain") != "testnet"
        or status.get("profile") != "staging"
        or type(status.get("priceDivisor")) is not int
        or status["priceDivisor"] != 1000
        or not isinstance(merchant, str)
        or merchant.lower() != MERCHANT
    ):
        raise PaymentError("pinned testnet staging merchant required")


def merchant_wallet() -> LocalAccount:
    key = os.environ.pop("E2E_MERCHANT_TESTNET_KEY", "")
    try:
        wallet = cast(LocalAccount, Account.from_key(key))
        if wallet.address.lower() != MERCHANT:
            raise PaymentError("pinned staging merchant key required")
        return wallet
    except Exception:
        raise PaymentError("pinned staging merchant key required") from None
    finally:
        del key


def hl_state(address: str) -> dict[str, Any]:
    return request(
        HL_INFO,
        headers={"Content-Type": "application/json"},
        data=json.dumps({"type": "clearinghouseState", "user": address}).encode(),
    )


def hl_balance(address: str) -> Decimal:
    """A payer holds plain USDC: no position, and all of its value withdrawable."""
    state = hl_state(address)
    summary = state.get("marginSummary")
    if not isinstance(summary, dict) or state.get("assetPositions") != []:
        raise PaymentError("unexpected Hyperliquid payer state; reconcile before restore")
    value = decimal_balance(summary.get("accountValue"))
    if decimal_balance(state.get("withdrawable")) != value:
        raise PaymentError("unexpected Hyperliquid payer state; reconcile before restore")
    return value


def evm_block(network: str, floor: int) -> int:
    """A fresh block at or after every confirmed restore this run has seen."""
    block = evm.quantity(evm.rpc(network, "eth_blockNumber", []))
    if block < max(floor, 1):
        raise PaymentError("Sepolia RPC behind a confirmed restore; retry later")
    return block


def token_balance(network: str, address: str, block: int) -> Decimal:
    call = {"to": evm.NETWORKS[network][2], "data": "0x70a08231" + address[2:].zfill(64)}
    value = evm.rpc(network, "eth_call", [call, hex(block)])
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        raise PaymentError("USDC balance response refused")
    return decimal_balance(str(Decimal(int(value, 16)) / 1_000_000))


def chain_admission(network: str) -> None:
    if network == "hyperliquid":
        return  # Fixed info/exchange URLs; usdSend signing always uses Testnet.
    _, chain_id, token = evm.NETWORKS[network]
    if evm.quantity(evm.rpc(network, "eth_chainId", [])) != chain_id:
        raise PaymentError("pinned Sepolia chain required")
    decimals = evm.rpc(network, "eth_call", [{"to": token, "data": "0x313ce567"}, "latest"])
    if decimals != "0x" + f"{6:064x}":
        raise PaymentError("pinned six-decimal USDC required")


def merchant_idle(network: str, block: int) -> None:
    """No merchant transaction in flight: a pending one could still credit a payer."""
    if network == "hyperliquid":
        return
    pending = evm.quantity(evm.rpc(network, "eth_getTransactionCount", [MERCHANT, "pending"]))
    if pending != evm.quantity(evm.rpc(network, "eth_getTransactionCount", [MERCHANT, hex(block)])):
        raise PaymentError("merchant has a pending transaction; reconcile before restore")


def payer_balance(network: str, address: str, floor: int) -> Decimal:
    if network == "hyperliquid":
        return hl_balance(address)
    return token_balance(network, address, evm_block(network, floor))


def admit_send(network: str, wallet: Any, destination: str, amount: int) -> None:
    limits = dict(TARGETS.get(network, ()))
    if (
        str(getattr(wallet, "address", "")).lower() != MERCHANT
        or destination not in limits
        or destination in (MERCHANT, E2E_ACCOUNT)
        or type(amount) is not int
        or not 0 < amount <= limits[destination]
    ):
        raise PaymentError("restore sender, destination or amount refused")


def send_hl(wallet: LocalAccount, destination: str, amount: int, work: Path, after: int) -> int:
    """One usdSend; returns its nonce, strictly above `after` (the previous send's)."""
    admit_send("hyperliquid", wallet, destination, amount)
    nonce = max(int(time.time() * 1000), after + 1)
    value = format(Decimal(amount) / 1_000_000, "f")
    action = {"destination": destination, "amount": value, "time": nonce, "type": "usdSend"}
    signature = sign_usd_transfer_action(wallet, action, False)  # False: Testnet only.
    if action.get("hyperliquidChain") != "Testnet":
        raise PaymentError("Hyperliquid testnet signature required")
    record(work, "attempt.json", {"nonce": nonce, "amount_micro": amount})
    response = request(
        HL_EXCHANGE,
        headers={"Content-Type": "application/json"},
        data=json.dumps({"action": action, "nonce": nonce, "signature": signature}).encode(),
    )
    accepted = response.get("response")
    if (
        response.get("status") != "ok"
        or not isinstance(accepted, dict)
        or accepted.get("type") != "default"
    ):
        raise PaymentError("restore outcome unresolved; reconcile, never retry")
    record(work, "receipt.json", {"accepted": True, "nonce": nonce, "amount_micro": amount})
    return nonce


def send_evm(network: str, wallet: LocalAccount, destination: str, amount: int, work: Path) -> int:
    """One USDC transfer; returns its block. Never re-sent, replaced or cancelled."""
    admit_send(network, wallet, destination, amount)
    _, chain_id, token = evm.NETWORKS[network]
    nonce = evm.quantity(evm.rpc(network, "eth_getTransactionCount", [MERCHANT, "pending"]))
    if nonce != evm.quantity(evm.rpc(network, "eth_getTransactionCount", [MERCHANT, "latest"])):
        raise PaymentError("merchant has a pending transaction; reconcile before restore")
    data = "0xa9059cbb" + destination[2:].zfill(64) + f"{amount:064x}"
    call = {"from": wallet.address, "to": token, "value": "0x0", "data": data}
    gas = evm.quantity(evm.rpc(network, "eth_estimateGas", [call]))
    price = evm.admitted_gas_price(
        gas,
        evm.quantity(evm.rpc(network, "eth_gasPrice", [])),
        evm.rpc(network, "eth_getBlockByNumber", ["latest", False]),
    )
    if evm.quantity(evm.rpc(network, "eth_getBalance", [wallet.address, "latest"])) < gas * price:
        raise PaymentError("merchant test ETH below restore gas; refill required")
    signed = wallet.sign_transaction(
        {
            "chainId": chain_id,
            "nonce": nonce,
            "gas": gas,
            "gasPrice": price,
            "to": to_checksum_address(token),
            "value": 0,
            "data": cast(HexStr, data),
        }
    )
    transaction_hash = "0x" + bytes(signed.hash).hex()
    record(
        work,
        "attempt.json",
        {
            "transaction_hash": transaction_hash,
            "nonce": nonce,
            "amount_micro": amount,
            "max_total_fee_wei": gas * price,
        },
    )
    deadline = time.monotonic() + evm.CONFIRM_SECONDS
    receipt: object = None
    try:
        raw = "0x" + bytes(signed.raw_transaction).hex()
        if evm.rpc(network, "eth_sendRawTransaction", [raw]) != transaction_hash:
            raise PaymentError("restore broadcast unconfirmed")
    except PaymentError:
        # The node's answer is not the outcome; look for the one signed hash, read-only.
        receipt = evm.lookup(
            network, transaction_hash, min(deadline, time.monotonic() + evm.LOOKUP_SECONDS)
        )
        if receipt is None:
            raise PaymentError("restore outcome unresolved; reconcile, never retry") from None
    if receipt is None or receipt is evm.SEEN:
        receipt = evm.await_receipt(network, transaction_hash, deadline)
    if (
        not isinstance(receipt, dict)
        or receipt.get("transactionHash") != transaction_hash
        or receipt.get("status") != "0x1"
        or evm.quantity(receipt.get("blockNumber")) == 0
    ):
        raise PaymentError("restore outcome unresolved; reconcile, never retry")
    block = evm.quantity(receipt["blockNumber"])
    record(
        work,
        "receipt.json",
        {
            "accepted": True,
            "transaction_hash": transaction_hash,
            "amount_micro": amount,
            "block_number": block,
        },
    )
    return block


def _identity(network: str, run_id: str, attempt: str) -> None:
    if network not in TARGETS or not RUN.fullmatch(run_id) or not RUN.fullmatch(attempt):
        raise PaymentError("pinned testnet and exact workflow attempt required")


def plan(network: str, evidence: Path, work: Path, run_id: str, attempt: str) -> dict[str, Any]:
    """Read-only: admit prior attempts and receipts, then fsync what `send` may do."""
    _identity(network, run_id, attempt)
    _private(work, directory=True)
    record(work, "restore-started.json", {"network": network, "run_id": run_id, "attempt": attempt})
    prior = prior_attempts(evidence, network, run_id, attempt)
    paid = paid_targets(evidence, network, run_id, attempt)
    result: dict[str, Any] = {
        "network": network,
        "run_id": run_id,
        "attempt": attempt,
        "floor_block": prior.floor_block,
        "paid_micro": paid,
        "prior_sent_micro": prior.sent,
        "sends": [],
    }
    if not paid:
        record(work, "plan.json", {**result, "status": "no-confirmed-payments"})
        return {**result, "status": "no-confirmed-payments"}
    staging_admission(network)
    chain_admission(network)
    sends: list[dict[str, Any]] = []
    owed_any = False
    for destination, baseline in TARGETS[network]:
        # Never more than this run's confirmed payments from the payer, less what earlier
        # attempts already sent back: a lagging read cannot make a rerun pay twice, and a
        # drain from outside this run is never refilled by the merchant.
        owed = paid.get(destination, 0) - prior.sent.get(destination, 0)
        if owed <= 0:
            continue
        owed_any = True
        amount = min(owed, gap(payer_balance(network, destination, prior.floor_block), baseline))
        if amount:
            sends.append(
                {"destination": destination, "baseline_micro": baseline, "amount_micro": amount}
            )
    required = sum(item["amount_micro"] for item in sends)
    if required:
        if network == "hyperliquid":
            available = decimal_balance(hl_state(MERCHANT).get("withdrawable"))
        else:
            block = evm_block(network, prior.floor_block)
            merchant_idle(network, block)
            available = token_balance(network, MERCHANT, block)
        if available * 1_000_000 < required:
            raise PaymentError("staging merchant USDC insufficient; refill required")
    status = (
        "planned" if sends else "already-at-baseline" if owed_any else "payments-already-returned"
    )
    result.update(sends=sends, status=status)
    record(work, "plan.json", result)
    return result


def send(network: str, work: Path, run_id: str, attempt: str) -> None:
    """Custody only after the intent upload: at most one send per planned payer."""
    _identity(network, run_id, attempt)
    _private(work, directory=True)
    planned = json_file(work / "plan.json", "restore plan")
    if (
        planned.get("network") != network
        or planned.get("run_id") != run_id
        or planned.get("attempt") != attempt
        or not isinstance(planned.get("sends"), list)
        or type(planned.get("floor_block")) is not int
    ):
        raise PaymentError("restore plan refused")
    items: list[tuple[str, int, int]] = []
    for item in planned["sends"]:
        if not isinstance(item, dict) or set(item) != {
            "destination",
            "baseline_micro",
            "amount_micro",
        }:
            raise PaymentError("restore plan refused")
        destination, baseline = item["destination"], item["baseline_micro"]
        planned_amount = item["amount_micro"]
        if (
            (destination, baseline) not in TARGETS[network]
            or type(planned_amount) is not int
            or not 0 < planned_amount <= baseline
            or destination in {seen for seen, _, _ in items}
        ):
            raise PaymentError("restore plan refused")
        items.append((destination, baseline, planned_amount))
    if not items:
        record(work, "summary.json", {"network": network, "status": planned.get("status")})
        return
    floor = planned["floor_block"]
    staging_admission(network)
    chain_admission(network)
    wallet = merchant_wallet()
    nonce = 0
    for destination, baseline, planned_amount in items:
        if network != "hyperliquid":
            merchant_idle(network, evm_block(network, floor))
        before = payer_balance(network, destination, floor)
        # Re-read under the purchase lock and never exceed either observed deficit.
        amount = min(planned_amount, gap(before, baseline))
        target = work / destination
        target.mkdir(mode=0o700)
        record(
            target,
            "plan.json",
            {
                "network": network,
                "destination": destination,
                "baseline_micro": baseline,
                "amount_micro": amount,
            },
        )
        if amount <= 0:
            continue
        if network == "hyperliquid":
            nonce = send_hl(wallet, destination, amount, target, nonce)
        else:
            floor = max(floor, send_evm(network, wallet, destination, amount, target))
        observed = payer_balance(network, destination, floor)
        record(target, "balance.json", {"balance_usdc": format(observed, "f")})
        # The payer must have risen by exactly the confirmed send: anything else means a
        # lagging read, a concurrent transfer or a lost credit, and a person reconciles it.
        # It may stay below baseline when it had lost more than this run's payments.
        if (observed - before) * 1_000_000 != amount:
            raise PaymentError("restore balance differs from the confirmed send; reconcile")
    record(work, "summary.json", {"network": network, "status": "confirmed"})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("plan", "send"), required=True)
    parser.add_argument("--network", choices=sorted(TARGETS), required=True)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    try:
        if args.phase == "plan":
            os.environ.pop("E2E_MERCHANT_TESTNET_KEY", None)  # Planning never holds the key.
            if args.evidence is None:
                raise PaymentError("purchase evidence required")
            result = plan(args.network, args.evidence, args.work, run_id, attempt)
            print(f"Staging wallet restore planned: {result['status']}")
        else:
            send(args.network, args.work, run_id, attempt)
            print("Staging wallet restore completed; see sanitized cleanup evidence")
        return 0
    except Exception:
        print(
            "Staging wallet restore refused; reconcile cleanup evidence, never retry a send",
            file=sys.stderr,
        )
        return 1
    finally:
        os.environ.pop("E2E_MERCHANT_TESTNET_KEY", None)


if __name__ == "__main__":
    raise SystemExit(main())
