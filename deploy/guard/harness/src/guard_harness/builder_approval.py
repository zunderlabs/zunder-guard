"""Sign one exact testnet builder approval on private stdin; no HTTP or order path."""

import json
import os
import re
import sys
import time
from typing import Any

from eth_account import Account

CHAIN_ID = 421614


def validate(value: Any, *, expected_builder: str, now_ms: int) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("message"), dict):
        raise ValueError("bounded testnet approval required")
    if re.fullmatch(r"0x[0-9a-f]{40}", expected_builder) is None:
        raise ValueError("admitted testnet builder required")
    nonce = value["message"].get("nonce")
    if type(nonce) is not int or abs(nonce - now_ms) > 60_000:
        raise ValueError("fresh approval nonce required")
    expected = {
        "domain": {
            "name": "HyperliquidSignTransaction",
            "version": "1",
            "chainId": CHAIN_ID,
            "verifyingContract": "0x" + "0" * 40,
        },
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "HyperliquidTransaction:ApproveBuilderFee": [
                {"name": "hyperliquidChain", "type": "string"},
                {"name": "maxFeeRate", "type": "string"},
                {"name": "builder", "type": "address"},
                {"name": "nonce", "type": "uint64"},
            ],
        },
        "primaryType": "HyperliquidTransaction:ApproveBuilderFee",
        "message": {
            "hyperliquidChain": "Testnet",
            "maxFeeRate": "0.02%",
            "builder": expected_builder,
            "nonce": nonce,
        },
    }
    if value != expected or type(value["domain"].get("chainId")) is not int:
        raise ValueError("exact pinned testnet approval required")
    return expected


def sign(frame: Any, *, now_ms: int) -> str:
    if not isinstance(frame, dict) or set(frame) != {"key", "account", "expected_builder", "typed"}:
        raise ValueError("private approval frame required")
    key, account = frame["key"], frame["account"]
    if (
        not isinstance(key, str)
        or re.fullmatch(r"(?:0x)?[0-9a-fA-F]{64}", key) is None
        or not isinstance(account, str)
        or re.fullmatch(r"0x[0-9a-fA-F]{40}", account) is None
    ):
        raise ValueError("owner key and account required")
    typed = validate(frame["typed"], expected_builder=frame["expected_builder"], now_ms=now_ms)
    wallet = Account.from_key(key)
    if wallet.address.lower() != account.lower():
        raise ValueError("approval owner does not match account")
    result = Account.sign_typed_data(key, full_message=typed)
    signature = "0x" + str(result.signature.hex())
    if re.fullmatch(r"0x[0-9a-fA-F]{128}(?:1b|1c)", signature) is None:
        raise ValueError("approval signature shape refused")
    return signature


def main() -> int:
    # Neither the owner key nor other credentials enter a child process environment.
    os.environ.clear()
    try:
        captured = sys.stdin.buffer.read(8193)
        if len(captured) > 8192:
            raise ValueError("approval frame too large")
        signature = sign(json.loads(captured), now_ms=time.time_ns() // 1_000_000)
        # Protocol output is consumed privately by the injected wallet, never logged.
        print(signature)
        return 0
    except Exception:
        print("Testnet approval signer refused; sensitive diagnostics withheld", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
