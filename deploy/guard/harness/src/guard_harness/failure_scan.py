"""Bounded independent keyless C6 postfailure observation; never repairs exposure."""

import argparse
import json
import os
from pathlib import Path
from typing import Any

from guard_harness.staged_subjects import _private
from guard_harness.testnet_scan import SCAN_TIMEOUT, ScanError, TestnetReads, flat_scan

_CATEGORIES = {
    "account is not flat; unrelated state is never repaired": "nonflat",
    "account has open orders; unrelated state is never repaired": "openorders",
    "unreadable holdings": "holdings",
    "unreadable position": "holdings",
    "venue accounting amount must be a decimal string": "holdings",
    "invalid venue accounting amount": "holdings",
    "nonfinite venue accounting amount": "holdings",
    "complete bounded DEX inventory required": "inventory",
    "invalid or duplicate DEX inventory": "inventory",
    "DEX inventory changed during scan": "inventory",
    "standard testnet account required": "mode",
    "refill the E2E testnet account": "equity",
    "positive finite equity floor required": "equity",
    "testnet HTTP/JSON read failed": "transport",
    "testnet read redirected": "transport",
    "oversized testnet response": "transport",
    "scan deadline exhausted; no incomplete flat credit": "deadline",
    "scan deadline exhausted after pacing; nothing sent": "deadline",
}


def _failure_kind(error: BaseException) -> str:
    # Match complete authored messages only, never copy exception text or arguments.
    if isinstance(error, ScanError) and len(error.args) == 1 and type(error.args[0]) is str:
        return _CATEGORIES.get(error.args[0], "unknown")
    return "unknown"


def observe(work: Path, account: str) -> None:
    if not work.is_absolute() or work.exists() or work.is_symlink():
        raise ScanError("fresh absolute postfailure observation required")
    work.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private(work.parent, directory=True)
    values: dict[str, Any] = {"flat": False, "network": "testnet", "repair_attempted": False}
    passed = False
    inventory_reads = 0
    values["last_read_phase"] = "not-started"
    try:
        upstream = TestnetReads(timeout=SCAN_TIMEOUT)

        def read(payload: dict[str, Any]) -> object:
            nonlocal inventory_reads
            kind = payload.get("type")
            phase = (
                {
                    "userAbstraction": "account-mode",
                    "clearinghouseState": "holdings",
                    "frontendOpenOrders": "open-orders",
                }.get(kind, "unknown")
                if isinstance(kind, str)
                else "unknown"
            )
            if kind == "perpDexs":
                inventory_reads += 1
                phase = "inventory-before" if inventory_reads == 1 else "inventory-after"
            values["last_read_phase"] = phase
            return upstream(payload)

        values["scan"] = flat_scan(read, account)
        values["flat"] = passed = True
    except (Exception, KeyboardInterrupt) as error:
        values["failure_kind"] = _failure_kind(error)
    finally:
        descriptor = os.open(work, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(values, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    if not passed:
        raise ScanError("failed journey exposure unknown; human review required")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    try:
        observe(args.work, os.environ["E2E_ACCOUNT"])
    except (Exception, KeyboardInterrupt):
        raise SystemExit("C6 postfailure flat scan incomplete; human review required") from None


if __name__ == "__main__":
    main()
