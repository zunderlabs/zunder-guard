"""P8 released-byte paper descriptor and read-only correlation to an owned T fill.

No wallet key, signature or order path. Root authenticates C2 assets before `descriptor`,
and supplies successful T ownership/cleanup evidence plus that run's actual events/fills
to `correlate`. Public receipts hash account/builder identities; private runtime descriptors
are never publication artifacts.
"""

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import time
from collections.abc import Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

from guard_harness.paper_bot import LocalGuard, PaperError
from guard_harness.runner import run
from guard_harness.staged_subjects import _private
from guard_harness.testnet_reconcile import order_statuses
from guard_harness.testnet_run import ROOT, signed_binary
from guard_harness.testnet_scan import amount, digest


def need(value: bool) -> None:
    if not value:
        raise ValueError("P8 authenticated builder/owned fee correlation refused")


def _descriptor(
    status: dict[str, Any], *, account: str, tag: str, commit: str, manifest: str, binary: str
) -> dict[str, object]:
    need(status.get("mode") == "paper" and status.get("network") == "testnet")
    need(status.get("account", "").lower() == account)
    need(status.get("version") == tag.removeprefix("v"))
    fee = status.get("fee")
    need(isinstance(fee, dict))
    fee = cast(dict[str, Any], fee)
    builder = fee.get("address")
    need(isinstance(builder, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", builder) is not None)
    need(fee.get("mode") == "builder" and type(fee.get("fee_tenths_bp")) is int)
    need(fee["fee_tenths_bp"] == 20 and fee.get("rate") == "0.02%")
    return {
        "schema": 1,
        "network": "testnet",
        "account": account,
        "builder": str(builder).lower(),
        "fee_tenths_bp": 20,
        "release_commit": commit,
        "manifest_sha256": manifest,
        "binary_sha256": binary,
        "tag": tag,
    }


def produce_descriptor(assets: Path, work: Path, *, account: str, tag: str, commit: str) -> Path:
    need(re.fullmatch(r"0x[0-9a-fA-F]{40}", account) is not None)
    need(re.fullmatch(r"[0-9a-f]{40}", commit) is not None)
    need(re.fullmatch(r"v\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", tag) is not None)
    _private(work.parent, directory=True)
    need(work.is_absolute() and not work.exists())
    work.mkdir(mode=0o700)
    binary = work / "zunder-guard"
    binary_digest, manifest = signed_binary(assets, binary, tag=tag, commit=commit)
    binary.chmod(0o700)
    home = work / "home"
    home.mkdir(mode=0o700)
    env = {"PATH": os.defpath, "HOME": str(home)}
    rules = json.loads((ROOT / "rules/vectors.json").read_bytes())["valid"][0]["canonical"]
    run(
        [
            str(binary),
            "--home",
            str(home),
            "init",
            "--non-interactive",
            "--network",
            "paper",
            "--account-network",
            "testnet",
            "--account",
            account,
            "--no-key",
            "--rules",
            rules,
        ],
        env=env,
        log=work / "init.log",
        timeout=60,
        sensitive_output=True,
    )
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    process = subprocess.Popen(
        [
            str(binary),
            "--home",
            str(home),
            "run",
            "--network",
            "paper",
            "--listen",
            f"127.0.0.1:{port}",
        ],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 60
        guard = LocalGuard(f"http://127.0.0.1:{port}")
        while True:
            need(process.poll() is None and time.monotonic() < deadline)
            try:
                status = guard.request("/guard/status")
                if isinstance(status, dict) and status.get("last_sync_ms"):
                    break
            except PaperError:
                pass
            time.sleep(0.5)
        value = _descriptor(
            status,
            account=account.lower(),
            tag=tag,
            commit=commit,
            manifest=manifest,
            binary=binary_digest,
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    path = work / "builder-descriptor.json"
    with path.open("x") as stream:
        path.chmod(0o600)
        stream.write(json.dumps(value) + "\n")
    return path


def correlate_fee(
    descriptor: dict[str, Any],
    approval: dict[str, Any],
    journey: dict[str, Any],
    events: Sequence[dict[str, Any]],
    fills: Sequence[dict[str, Any]],
    *,
    client: str,
    started_ms: int,
    ended_ms: int,
) -> dict[str, object]:
    """Bind actual approval, release, Guard wire, successful entry OID and venue fills.

    Root must obtain fills from a bounded testnet `userFillsByTime` read for descriptor.account;
    journal events must come from its authenticated exclusive T Guard. No caller summaries
    substitute for these raw observations. Fee is inclusive in the venue's total fee: this
    helper never subtracts builderFee from cash or counts it as a second trading charge.
    """
    account, builder = descriptor.get("account"), descriptor.get("builder")
    need(
        all(
            isinstance(v, str) and re.fullmatch(r"0x[0-9a-f]{40}", v) is not None
            for v in (account, builder, client)
        )
    )
    account, builder = str(account), str(builder)
    need(descriptor.get("network") == "testnet" and descriptor.get("fee_tenths_bp") == 20)
    need(
        isinstance(descriptor.get("release_commit"), str)
        and re.fullmatch(r"[0-9a-f]{40}", descriptor["release_commit"]) is not None
    )
    for field in ("manifest_sha256", "binary_sha256"):
        need(
            isinstance(descriptor.get(field), str)
            and re.fullmatch(r"[0-9a-f]{64}", descriptor[field]) is not None
        )
        need(journey.get(field) == descriptor[field])
    need(journey.get("commit") == descriptor.get("release_commit"))
    need(journey.get("account_sha256") == hashlib.sha256(account.encode()).hexdigest())
    need(journey.get("journey") in {"T1", "T2"} and journey.get("result") == "passed")
    need(journey.get("guard_stopped") is True and journey.get("cleanup_complete") is True)
    need(approval.get("journey") == "P8" and approval.get("network") == "testnet")
    need(approval.get("account") == account and approval.get("builder") == builder)
    need(approval.get("approval_accepted") is True and approval.get("approval_readback") is True)
    need(type(approval.get("fee_tenths_bp")) is int and approval["fee_tenths_bp"] == 20)
    need(type(started_ms) is int and type(ended_ms) is int and 0 < started_ms <= ended_ms)
    need(type(approval.get("nonce")) is int and 0 < approval["nonce"] <= started_ms)
    observed = journey.get("protected_entry")
    need(isinstance(observed, dict) and type(observed.get("entry_oid")) is int)
    observed = cast(dict[str, Any], observed)
    oid = observed["entry_oid"]
    need(oid > 0 and amount(observed.get("filled")) > 0)
    need(0 < len(events) <= 1000)
    decisions = [
        event
        for event in events
        if event.get("kind") == "decision"
        and event.get("client") == client
        and isinstance(event.get("forward"), dict)
        and event["forward"].get("type") == "order"
        and any(order.get("r") is False for order in event["forward"].get("orders", []))
    ]
    need(len(decisions) == 1 and decisions[0].get("verdict") in {"allow", "resize"})
    decision = decisions[0]
    wire = decision["forward"]
    need(wire.get("builder") == {"b": builder, "f": 20})
    sequence = decision.get("seq")
    need(type(sequence) is int and sequence > 0)
    statuses = order_statuses(events, cast(int, sequence))
    need(len(statuses) == 1 and isinstance(statuses[0], dict))
    ack = statuses[0].get("filled", statuses[0].get("resting"))
    need(isinstance(ack, dict) and type(ack.get("oid")) is int and ack["oid"] == oid)
    for sent in events:
        if sent.get("kind") == "sent" and sent.get("decision") == decision.get("seq"):
            need(sent.get("action") is None or sent.get("action") == wire)
    need(0 < len(fills) < 500)
    trades: set[int] = set()
    quantity, notional, charged = Decimal(0), Decimal(0), Decimal(0)
    owned = [fill for fill in fills if type(fill.get("oid")) is int and fill["oid"] == oid]
    need(bool(owned))
    for fill in owned:
        need(type(fill.get("time")) is int and started_ms <= fill["time"] <= ended_ms)
        tid = fill.get("tid")
        need(type(tid) is int and tid >= 0 and tid not in trades)
        trades.add(cast(int, tid))
        need(
            fill.get("coin") == "BTC" and fill.get("side") == "B" and fill.get("feeToken") == "USDC"
        )
        size, price, fee = (
            amount(fill.get("sz")),
            amount(fill.get("px")),
            amount(fill.get("builderFee")),
        )
        need(size > 0 and price > 0 and fee > 0)
        expected = size * price * Decimal("0.0002")  # 20 tenths-bp = 2 bp = 0.02%.
        # At most one micro-USDC of representation rounding per actual fill.
        need(abs(fee - expected) <= Decimal("0.000001"))
        quantity += size
        notional += size * price
        charged += fee
    need(quantity == amount(observed["filled"]) and notional <= Decimal("40"))
    return {
        "schema": 1,
        "journey": "P8",
        "result": "passed",
        "completed": True,
        "commit": descriptor["release_commit"],
        "manifest_sha256": descriptor["manifest_sha256"],
        "binary_sha256": descriptor["binary_sha256"],
        "account_sha256": hashlib.sha256(account.encode()).hexdigest(),
        "builder_sha256": hashlib.sha256(builder.encode()).hexdigest(),
        "entry_oid": oid,
        "trade_ids": sorted(trades),
        "started_ms": started_ms,
        "ended_ms": ended_ms,
        "builder_fee_usdc": str(charged),
        "notional_usdc": str(notional),
        "guard_wire_sha256": digest(wire),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", nargs="?", choices=["descriptor", "correlate"], default="descriptor"
    )
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    for flag in ("tag", "commit", "account"):
        parser.add_argument("--" + flag, required=True)
    for flag in ("approval", "journey", "events", "fills"):
        parser.add_argument("--" + flag, type=Path)
    parser.add_argument("--client")
    parser.add_argument("--started-ms", type=int)
    parser.add_argument("--ended-ms", type=int)
    args = parser.parse_args()
    if args.action == "descriptor":
        produce_descriptor(
            args.assets, args.work, account=args.account, tag=args.tag, commit=args.commit
        )
        return
    # Re-derive the descriptor from released bytes instead of trusting an arbitrary caller file.
    _private(args.work.parent, directory=True)
    need(args.work.is_absolute() and not args.work.exists())
    args.work.mkdir(mode=0o700)
    descriptor_path = produce_descriptor(
        args.assets, args.work / "subject", account=args.account, tag=args.tag, commit=args.commit
    )
    values: dict[str, Any] = {}
    for name in ("approval", "journey", "events", "fills"):
        path = getattr(args, name)
        need(isinstance(path, Path))
        _private(path)
        need(0 < path.stat().st_size <= 4 * 1024 * 1024)
        values[name] = json.loads(path.read_bytes())
    proof = correlate_fee(
        json.loads(descriptor_path.read_bytes()),
        **values,
        client=args.client,
        started_ms=args.started_ms,
        ended_ms=args.ended_ms,
    )
    path = args.work / "P8.fee-proof.json"
    with path.open("x") as stream:
        path.chmod(0o600)
        stream.write(json.dumps(proof) + "\n")


if __name__ == "__main__":
    main()
