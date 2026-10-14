"""Key-free, bounded refill checks for staging.md's funded testnet wallets.

Run directly with Python's stdlib, before installing the harness or publishing state.
This checks funding only; it does not replace C6's independent all-DEX flat scan.
"""

import json
import os
import re
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

INFO = "https://api.hyperliquid-testnet.xyz/info"
TIMEOUT = 10
LIMIT = 65_536
EVM_PAYER = "0xdee26666d6240fe3309538a87dd7e0ff0d7e7bfc"
E2E_ACCOUNT = "0x0d708cfc4316b58f4ab00ee641a54baacc89cb14"
# Pinned Sepolia identities and Circle contracts, shared facts with purchase_evm.py.
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


@dataclass(frozen=True)
class Wallet:
    name: str
    address: str
    network: str
    floors: tuple[tuple[str, Decimal], ...]


# Only numeric refill lines: the merchant is swept, and the API wallet holds nothing.
WALLETS = (
    Wallet(
        "Hyperliquid payer",
        "0xc7834077426685f0aba6b369feb6f9d8bf3cf3e7",
        "hyperliquid",
        (("USDC", Decimal("5")),),
    ),
    Wallet(
        "Blocked payer",
        "0x701efb44af39b74755abbc3ced664c622485b4a7",
        "hyperliquid",
        (("USDC", Decimal("1")),),
    ),
    *(
        Wallet(
            f"EVM payer ({network.title()} Sepolia)",
            EVM_PAYER,
            network,
            (("USDC", Decimal("5")), ("ETH", Decimal("0.003"))),
        )
        for network in NETWORKS
    ),
    Wallet(
        "E2E trading account",
        E2E_ACCOUNT,
        "hyperliquid",
        (("USDC equity", Decimal("200")),),
    ),
)


def amount(value: object) -> Decimal:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,30}(?:\.[0-9]{1,18})?", value):
        raise ValueError("invalid balance")
    try:
        result = Decimal(value)
    except InvalidOperation:
        raise ValueError("invalid balance") from None
    if not result.is_finite():
        raise ValueError("invalid balance")
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        raise ValueError("redirect refused")


def request(url: str, payload: dict[str, object]) -> dict[str, Any]:
    # No proxy/environment credentials or redirects; only the pinned testnet URLs.
    if url not in {INFO, *(network[0] for network in NETWORKS.values())}:
        raise ValueError("testnet endpoint required")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "guard-wallet-preflight/1"},
    )
    with opener.open(req, timeout=TIMEOUT) as response:
        raw = response.read(LIMIT + 1)
        if response.status != 200 or len(raw) > LIMIT:
            raise ValueError("response refused")
    value: object = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("response object required")
    return value


def rpc(network: str, method: str, params: list[object]) -> object:
    if method not in {"eth_chainId", "eth_getBalance", "eth_call"}:
        raise ValueError("read-only method required")
    value = request(
        NETWORKS[network][0],
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )
    if (
        value.get("jsonrpc") != "2.0"
        or type(value.get("id")) is not int
        or value["id"] != 1
        or "error" in value
        or "result" not in value
    ):
        raise ValueError("RPC response refused")
    return value["result"]


def quantity(value: object, *, abi: bool = False) -> int:
    pattern = r"0x[0-9a-fA-F]{64}" if abi else r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})"
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError("bounded RPC quantity required")
    return int(value, 16)


def balances(wallet: Wallet) -> dict[str, str]:
    if wallet.network == "hyperliquid":
        state = request(INFO, {"type": "clearinghouseState", "user": wallet.address})
        equity = amount(state["marginSummary"]["accountValue"])
        if wallet.address == E2E_ACCOUNT:
            return {"USDC equity": str(equity)}
        # A payer needs transferable cash, not equity tied up in margin.
        return {"USDC": str(min(equity, amount(state["withdrawable"])))}
    _, chain_id, token = NETWORKS[wallet.network]
    if quantity(rpc(wallet.network, "eth_chainId", [])) != chain_id:
        raise ValueError("wrong Sepolia chain")
    usdc = quantity(
        rpc(
            wallet.network,
            "eth_call",
            [{"to": token, "data": "0x70a08231" + wallet.address[2:].rjust(64, "0")}, "latest"],
        ),
        abi=True,
    )
    eth = quantity(rpc(wallet.network, "eth_getBalance", [wallet.address, "latest"]))
    # Integer unit conversion, with no float or Decimal context rounding.
    return {
        "USDC": f"{usdc // 10**6}.{usdc % 10**6:06d}",
        "ETH": f"{eth // 10**18}.{eth % 10**18:018d}",
    }


def observe(wallet: Wallet) -> dict[str, str]:
    # A process deadline bounds the entire response, including slow/dribbling bodies.
    # -I -S and this allowlist keep SDKs, keys, proxies and Python hooks out of the reader.
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(Path(__file__).resolve()), "--wallet", wallet.name],
        env={"PATH": os.defpath, "LANG": "C.UTF-8"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=TIMEOUT,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) > LIMIT:
        raise ValueError("read failed")
    value: object = json.loads(result.stdout)
    if not isinstance(value, dict) or set(value) != {asset for asset, _ in wallet.floors}:
        raise ValueError("incomplete balances")
    return {asset: str(amount(value[asset])) for asset, _ in wallet.floors}


def check(wallet: Wallet) -> tuple[bool, str]:
    try:
        values = observe(wallet)
        low = [
            f"{asset} {values[asset]} < {floor}"
            for asset, floor in wallet.floors
            if amount(values[asset]) < floor
        ]
    except Exception:
        return (
            False,
            f"FAIL {wallet.name} ({wallet.address}): testnet read failed within {TIMEOUT}s",
        )
    if low:
        return False, f"FAIL {wallet.name} ({wallet.address}): refill required; {', '.join(low)}"
    return True, f"PASS {wallet.name} ({wallet.address})"


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--wallet":
        try:
            wallet = next(wallet for wallet in WALLETS if wallet.name == sys.argv[2])
            print(json.dumps(balances(wallet)))
            return 0
        except Exception:
            return 1  # Never echo provider errors, environment values or a traceback.
    if len(sys.argv) != 1:
        print("FAIL wallet preflight: no arguments accepted", file=sys.stderr)
        return 1
    configured = os.environ.get("E2E_TESTNET_ACCOUNT", "")
    if configured and configured.lower() != E2E_ACCOUNT:
        print("FAIL E2E trading account: configured address differs from staging wallet table")
        return 1
    with ThreadPoolExecutor(max_workers=len(WALLETS)) as pool:
        results = list(pool.map(check, WALLETS))
    for _, message in results:
        print(message)
    return 0 if all(passed for passed, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
