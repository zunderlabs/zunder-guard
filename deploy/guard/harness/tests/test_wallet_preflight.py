"""Offline refill boundaries, key-free reads, process deadlines and workflow ordering."""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import yaml

from guard_harness import purchase_evm
from guard_harness import wallet_preflight as wp

GUARD = Path(__file__).resolve().parents[2]
SCRIPT = GUARD / "harness/src/guard_harness/wallet_preflight.py"


def funded(wallet: wp.Wallet) -> dict[str, str]:
    return {asset: str(floor) for asset, floor in wallet.floors}


def test_pins_match_the_refill_floors_and_existing_payment_networks() -> None:
    assert wp.NETWORKS == purchase_evm.NETWORKS
    assert [wallet.floors for wallet in wp.WALLETS] == [
        (("USDC", Decimal("5")),),
        (("USDC", Decimal("1")),),
        (("USDC", Decimal("5")), ("ETH", Decimal("0.003"))),
        (("USDC", Decimal("5")), ("ETH", Decimal("0.003"))),
        (("USDC equity", Decimal("200")),),
    ]


@pytest.mark.parametrize("wallet", wp.WALLETS, ids=lambda wallet: wallet.name)
def test_refill_line_itself_passes(wallet: wp.Wallet, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wp, "observe", lambda _: funded(wallet))
    passed, message = wp.check(wallet)
    assert passed and wallet.name in message and wallet.address in message


BELOW = [(wallet, asset, floor) for wallet in wp.WALLETS for asset, floor in wallet.floors]


@pytest.mark.parametrize("wallet,asset,floor", BELOW)
def test_one_base_unit_below_each_refill_line_fails_and_names_wallet(
    wallet: wp.Wallet, asset: str, floor: Decimal, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = funded(wallet)
    # USDC has 6 decimals and ETH 18: hand-computed smallest units below the table line.
    unit = Decimal("0.000000000000000001" if asset == "ETH" else "0.000001")
    values[asset] = str(floor - unit)
    monkeypatch.setattr(wp, "observe", lambda _: values)
    passed, message = wp.check(wallet)
    assert not passed
    assert wallet.name in message and wallet.address in message and asset in message
    assert "refill required" in message


@pytest.mark.parametrize(
    "value", [None, True, 5, 5.0, "NaN", "Infinity", "-1", "1e5", "", "9" * 31]
)
def test_invalid_balance_fails_closed(value: object) -> None:
    with pytest.raises(ValueError):
        wp.amount(value)


@pytest.mark.parametrize("wallet", [wp.WALLETS[0], wp.WALLETS[1], wp.WALLETS[4]])
def test_hyperliquid_only_reads_info_and_payers_need_transferable_cash(
    wallet: wp.Wallet, monkeypatch: pytest.MonkeyPatch
) -> None:
    def request(url: str, payload: dict[str, object]) -> dict[str, Any]:
        assert url == wp.INFO
        assert payload == {"type": "clearinghouseState", "user": wallet.address}
        return {"marginSummary": {"accountValue": "300"}, "withdrawable": "0.9"}

    monkeypatch.setattr(wp, "request", request)
    assert wp.balances(wallet) == (
        {"USDC equity": "300"} if wallet.address == wp.E2E_ACCOUNT else {"USDC": "0.9"}
    )


@pytest.mark.parametrize("wallet", [wp.WALLETS[2], wp.WALLETS[3]])
def test_sepolia_identity_and_read_only_balance_calls_use_exact_integer_units(
    wallet: wp.Wallet, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def request(url: str, payload: dict[str, object]) -> dict[str, Any]:
        endpoint, chain, token = wp.NETWORKS[wallet.network]
        assert url == endpoint
        assert payload["jsonrpc"] == "2.0" and payload["id"] == 1
        method = str(payload["method"])
        seen.append(method)
        if method == "eth_chainId":
            assert payload["params"] == []
            value = hex(chain)
        elif method == "eth_call":
            assert payload["params"] == [
                {"to": token, "data": "0x70a08231" + wallet.address[2:].rjust(64, "0")},
                "latest",
            ]
            value = "0x" + format(5_000_001, "064x")
        else:
            assert method == "eth_getBalance"
            assert payload["params"] == [wallet.address, "latest"]
            value = hex(3_000_000_000_000_001)
        return {"jsonrpc": "2.0", "id": 1, "result": value}

    monkeypatch.setattr(wp, "request", request)
    assert wp.balances(wallet) == {"USDC": "5.000001", "ETH": "0.003000000000000001"}
    assert seen == ["eth_chainId", "eth_call", "eth_getBalance"]


def test_wrong_chain_stops_before_balance_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def rpc(network: str, method: str, params: list[object]) -> str:
        assert method == "eth_chainId"
        return "0x1"

    monkeypatch.setattr(wp, "rpc", rpc)
    with pytest.raises(ValueError, match="wrong Sepolia"):
        wp.balances(wp.WALLETS[2])


@pytest.mark.parametrize(
    "response",
    [
        {"jsonrpc": "2.0", "id": 1, "error": {"message": "provider-private-data"}},
        {"jsonrpc": "2.0", "id": True, "result": "0x1"},
        {"jsonrpc": "2.0", "id": 2, "result": "0x1"},
        {"id": 1, "result": "0x1"},
        {"jsonrpc": "2.0", "id": 1},
        {"jsonrpc": "2.0", "id": 1, "error": {}, "result": "0x1"},
    ],
)
def test_rpc_errors_or_malformed_envelopes_fail_closed(
    response: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(wp, "request", lambda *_: response)
    with pytest.raises(ValueError, match="RPC response refused"):
        wp.rpc("base", "eth_chainId", [])


def test_no_write_rpc_or_unpinned_endpoint_or_redirect() -> None:
    with pytest.raises(ValueError, match="read-only"):
        wp.rpc("base", "eth_sendRawTransaction", [])
    with pytest.raises(ValueError, match="testnet endpoint"):
        wp.request("https://api.hyperliquid.xyz/info", {})
    with pytest.raises(ValueError, match="redirect refused"):
        wp.NoRedirect().redirect_request(None, None, 302, "", None, "https://other.invalid")


def test_http_read_has_no_proxy_credentials_and_a_bounded_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response:
        status = 200

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def read(self, limit: int) -> bytes:
            assert limit == wp.LIMIT + 1
            return b"{}"

    class Opener:
        def open(self, req: Any, *, timeout: float) -> Response:
            assert timeout == wp.TIMEOUT
            assert req.get_header("User-agent") == "guard-wallet-preflight/1"
            assert set(dict(req.header_items())) == {"Content-type", "User-agent"}
            return Response()

    def build(*handlers: Any) -> Opener:
        assert handlers[0].proxies == {} and isinstance(handlers[1], wp.NoRedirect)
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", build)
    assert wp.request(wp.INFO, {"type": "clearinghouseState", "user": wp.E2E_ACCOUNT}) == {}


@pytest.mark.parametrize("failure", ["timeout", "exit", "oversize", "json", "missing"])
def test_reader_is_isolated_bounded_and_never_echoes_sensitive_errors(
    failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        assert args == [sys.executable, "-I", "-S", str(SCRIPT), "--wallet", wp.WALLETS[1].name]
        assert kwargs["env"] == {"PATH": os.defpath, "LANG": "C.UTF-8"}
        assert kwargs["stdin"] == kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["timeout"] == wp.TIMEOUT
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, wp.TIMEOUT, output="provider-private-data")
        output = {
            "exit": b"provider-private-data",
            "oversize": b"a" * (wp.LIMIT + 1),
            "json": b"provider-private-data",
            "missing": b"{}",
        }[failure]
        return subprocess.CompletedProcess(args, 1 if failure == "exit" else 0, output)

    monkeypatch.setattr(subprocess, "run", run)
    passed, message = wp.check(wp.WALLETS[1])
    assert not passed and "Blocked payer" in message
    assert "provider-private-data" not in message


def test_real_hung_reader_is_killed_within_process_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "hung_reader.py"
    script.write_text("import time\ntime.sleep(30)\n")
    monkeypatch.setattr(wp, "__file__", str(script))
    monkeypatch.setattr(wp, "TIMEOUT", 0.2)
    started = time.monotonic()
    passed, _ = wp.check(wp.WALLETS[1])
    assert not passed and time.monotonic() - started < 3


def test_real_reader_success_has_no_inherited_credentials_or_python_hooks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "successful_reader.py"
    script.write_text(
        "import os, sys\n"
        "assert sys.flags.isolated and sys.flags.no_site\n"
        "assert set(os.environ) <= {'PATH', 'LANG', 'LC_CTYPE', '__CF_USER_TEXT_ENCODING'}\n"
        'print(\'{"USDC": "5.000000", "ETH": "0.003000000000000000"}\')\n'
    )
    monkeypatch.setenv("E2E_PAYER_EVM_SEPOLIA_KEY", "offline-credential-sentinel")
    monkeypatch.setattr(wp, "__file__", str(script))
    assert wp.observe(wp.WALLETS[2]) == {"USDC": "5.000000", "ETH": "0.003000000000000000"}


def test_main_checks_all_wallets_in_parallel_and_fails_on_empty_blocked_payer(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    barrier = threading.Barrier(len(wp.WALLETS), timeout=3)

    def observe(wallet: wp.Wallet) -> dict[str, str]:
        barrier.wait()
        return {"USDC": "0"} if wallet.name == "Blocked payer" else funded(wallet)

    monkeypatch.setattr(wp, "observe", observe)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT)])
    monkeypatch.delenv("E2E_TESTNET_ACCOUNT", raising=False)
    assert wp.main() == 1
    output = capsys.readouterr().out
    assert len(output.splitlines()) == len(wp.WALLETS)
    assert "FAIL Blocked payer" in output and output.count("PASS") == 4


def test_main_success_and_account_rotation_refusal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(wp, "observe", funded)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT)])
    monkeypatch.setenv("E2E_TESTNET_ACCOUNT", wp.E2E_ACCOUNT.upper())
    assert wp.main() == 0
    monkeypatch.setenv("E2E_TESTNET_ACCOUNT", "untrusted-config-value")
    assert wp.main() == 1
    assert "untrusted-config-value" not in capsys.readouterr().out


def test_child_failure_has_no_traceback_or_provider_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(wallet: wp.Wallet) -> dict[str, str]:
        raise ValueError("provider-private-data")

    monkeypatch.setattr(wp, "balances", fail)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--wallet", wp.WALLETS[0].name])
    assert wp.main() == 1
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "workflow,job",
    [
        ("verify.yml", "stable-template"),
        ("verify.yml", "staging"),
        ("journey.yml", "payment-diagnostic"),
    ],
)
def test_workflows_preflight_immediately_after_checkout_before_installs_and_mutations(
    workflow: str,
    job: str,
) -> None:
    private = GUARD / "github/workflows" / workflow
    path = private if private.exists() else GUARD.parents[1] / ".github/workflows" / workflow
    steps = yaml.safe_load(path.read_text())["jobs"][job]["steps"]
    checkout = next(
        i for i, step in enumerate(steps) if step.get("uses", "").startswith("actions/checkout@")
    )
    preflight = steps[checkout + 1]
    assert preflight["run"] == (
        "python3 -I -S deploy/guard/harness/src/guard_harness/wallet_preflight.py"
    )
    assert "if" not in preflight and "continue-on-error" not in preflight
    assert "secrets." not in json.dumps(preflight)
    assert not any("uses" in step for step in steps[:checkout])
