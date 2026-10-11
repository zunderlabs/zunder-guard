"""Opt-in real paper-binary contract check; never uses a venue signing key."""

import hashlib
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from guard_harness.cli import GuardCLI
from guard_harness.mcp_client import MCP, Tool
from guard_harness.paper_bot import LocalGuard, PaperError
from guard_harness.paper_roundtrip import round_trip
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
                assert mcp.writes_bound is True
                # The consumer pins testnet while this real Guard runs paper.
                # Valid tool arguments must reach the producer's mode check,
                # then refuse before signing or creating a decision event.
                before = guard.request("/guard/events?since=0")
                requests: tuple[tuple[Tool, dict[str, Any]], ...] = (
                    (
                        "place_order",
                        {"coin": "BTC", "side": "buy", "stop": "1", "size": "0.0001"},
                    ),
                    ("cancel_order", {"coin": "BTC", "order_id": 1}),
                )
                for write_tool, arguments in requests:
                    refused, is_error = mcp.tool(write_tool, arguments)
                    assert is_error is True
                    assert refused["ok"] is False
                    assert refused["error"]["code"] == "network_mismatch"
                    assert refused["sent"] is False
                assert guard.request("/guard/events?since=0") == before
            assert [decision.verdict for decision in round_trip(guard, pair)] == [
                "veto",
                "allow",
                "resize",
            ]
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
