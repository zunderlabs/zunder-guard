"""Opt-in real paper-binary contract check; never uses a venue signing key."""

import hashlib
import json
import os
import socket
import subprocess
import time
from decimal import ROUND_DOWN, ROUND_UP, Decimal
from pathlib import Path

import pytest
from hyperliquid.utils.signing import order_wires_to_order_action

from guard_harness.cli import GuardCLI
from guard_harness.mcp_client import MCP, MCPError
from guard_harness.paper_bot import LocalGuard, PaperBot, PaperError, Verdict
from guard_harness.runner import run


def test_real_paper_decision_and_journal(tmp_path: Path) -> None:
    binary_value = os.environ.get("GUARD_TEST_BINARY")
    account = os.environ.get("GUARD_PAPER_READ_ACCOUNT")
    if not binary_value or not account:
        pytest.skip("requires a built Guard and a public read-only paper account")
    binary = Path(binary_value).resolve()
    home = tmp_path / "home"
    home.mkdir()
    logs = tmp_path / "logs"
    rules_file = Path(__file__).resolve().parents[2] / "rules/vectors.json"
    rules = json.loads(rules_file.read_bytes())["valid"][0]["canonical"]
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
        log=logs / "init.log",
        timeout=60,
    )
    cli = GuardCLI(binary, logs, home)
    pair = cli.pair()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    guard = LocalGuard(url)
    with (logs / "guard.log").open("wb") as output:
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
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=output,
        )
        try:
            deadline = time.monotonic() + 45
            while True:
                if process.poll() is not None:
                    pytest.fail("paper Guard exited; inspect retained service log")
                try:
                    status = guard.request("/guard/status")
                    if status.get("last_sync_ms"):
                        break
                except PaperError:
                    pass
                if time.monotonic() >= deadline:
                    pytest.fail("paper Guard did not sync; inspect retained service log")
                time.sleep(0.2)
            machine_status = cli.status(url=url)
            assert machine_status["mode"] == "paper"
            assert machine_status["licence"]["state"] in {"valid", "expired", "invalid", "none"}
            assert status["mode"] == "paper"
            assert status["capabilities"]["exchange_expected_mode"] is True
            client_key = tmp_path / "mcp-client.key"
            client_key.write_text(pair.key)
            client_key.chmod(0o600)
            home.chmod(0o700)
            with MCP(
                binary,
                sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                home=home,
                client_key=client_key,
                url=url,
                log=logs / "mcp.log",
            ) as mcp:
                for tool in ("account_overview", "limits"):
                    overview, is_error = mcp.tool(tool)
                    assert is_error is False and overview["ok"] is True
                if not mcp.writes_bound:
                    for write_tool in ("place_order", "close_position", "cancel_order"):
                        with pytest.raises(MCPError, match="write refused"):
                            mcp.tool(write_tool)
                    assert mcp.entry_attempted is False
            action = {
                "type": "order",
                "orders": [
                    {
                        "a": 10000,
                        "b": True,
                        "p": "100",
                        "s": "0.1",
                        "r": False,
                        "t": {"limit": {"tif": "Ioc"}},
                    }
                ],
                "grouping": "na",
            }
            decision = PaperBot(guard, pair).decide(
                action, "veto", expected_code="unsupported_market"
            )
            assert decision.verdict == "veto"

            # Read current public metadata; use Decimal throughout the order inputs.
            meta = guard.request("/info", {"type": "meta"})
            mids = guard.request("/info", {"type": "allMids"})
            asset, instrument = next(
                (i, item) for i, item in enumerate(meta["universe"]) if item["name"] == "BTC"
            )
            step = Decimal(1).scaleb(-instrument["szDecimals"])
            price_step = Decimal(1).scaleb(-(6 - instrument["szDecimals"]))
            price = Decimal(mids["BTC"]).quantize(price_step, rounding=ROUND_DOWN)
            stop = (price * Decimal("0.98")).quantize(price_step, rounding=ROUND_DOWN)
            # Give the supplied market stop its required 10% gap room, without a rewrite.
            stop_limit = (stop * Decimal("0.89")).quantize(price_step, rounding=ROUND_DOWN)
            small = (Decimal("20") / price / step).to_integral_value(rounding=ROUND_UP) * step
            bot = PaperBot(guard, pair)
            cases: list[tuple[Decimal, Verdict, str]] = [
                (small, "allow", "allowed"),
                (Decimal("10000"), "resize", "resized"),
            ]
            for quantity, verdict, code in cases:
                # Refill the unchanged request budget after the previous account read.
                # Paper plans are charged for their hypothetical forwarding too.
                time.sleep(15)
                size = format(quantity.normalize(), "f")
                entry = order_wires_to_order_action(
                    [
                        {
                            "a": asset,
                            "b": True,
                            "p": format(price.normalize(), "f"),
                            "s": size,
                            "r": False,
                            "t": {"limit": {"tif": "Ioc"}},
                        },
                        {
                            "a": asset,
                            "b": False,
                            "p": format(stop_limit.normalize(), "f"),
                            "s": size,
                            "r": True,
                            "t": {
                                "trigger": {
                                    "isMarket": True,
                                    "triggerPx": format(stop.normalize(), "f"),
                                    "tpsl": "sl",
                                }
                            },
                        },
                    ],
                    grouping="normalTpsl",
                )
                try:
                    result = bot.decide(entry, verdict, expected_code=code)
                except PaperError:
                    events = guard.request("/guard/events?since=0")
                    observed = next(
                        (e.get("code") for e in reversed(events) if e.get("nonce") == bot.nonce),
                        "missing-decision",
                    )
                    pytest.fail(f"paper {verdict} case failed; journal reason: {observed}")
                event = next(
                    e for e in guard.request("/guard/events?since=0") if e["seq"] == result.seq
                )
                orders = event["forward"]["orders"]
                forwarded = Decimal(orders[0]["s"])
                assert Decimal(orders[1]["s"]) == forwarded
                assert orders[1]["r"] is True
                if verdict == "resize":
                    assert Decimal("0") < forwarded < quantity
                else:
                    assert forwarded == quantity
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
