import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from guard_harness.mcp_client import MCP, MCPError

SCRIPT = """import json,sys,time
for line in sys.stdin:
    value=json.loads(line)
    if value["method"]=="initialize":
        result={"protocolVersion":"2025-11-25",
            "capabilities":{"experimental":{"exchange_expected_mode":{"enabled":True},"close_expected_size":{"enabled":True},"limit_price_ioc":{"enabled":True}}}}
    else:
        result={"structuredContent":{"ok":True},"isError":False}
    reply={"jsonrpc":"2.0","id":value["id"],"result":result}
    CASE
    print(json.dumps(reply),flush=True)
"""


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    binary = tmp_path / "binary"
    binary.write_bytes(b"authenticated binary fixture")
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    key = tmp_path / "client.key"
    key.write_text("dummy-secret")
    key.chmod(0o600)
    original = subprocess.Popen
    children: list[Any] = []

    def start(case: str = "pass", timeout: float = 1) -> MCP:
        mutations = {
            "pass": "pass",
            "unbounded-close": (
                "if value['method']=='initialize': "
                "result['capabilities']['experimental'].pop('close_expected_size')"
            ),
            "legacy": "result.pop('capabilities',None)",
            "false-capability": (
                "if value['method']=='initialize': "
                "result['capabilities']['experimental']['exchange_expected_mode']=False"
            ),
            "boolean-capability": (
                "if value['method']=='initialize': "
                "result['capabilities']['experimental']['exchange_expected_mode']=True"
            ),
            "integer-capability": (
                "if value['method']=='initialize': "
                "result['capabilities']['experimental']['exchange_expected_mode']={'enabled':1}"
            ),
            "extended-capability": (
                "if value['method']=='initialize': "
                "result['capabilities']['experimental']['exchange_expected_mode']="
                "{'enabled':True,'extra':True}"
            ),
            "id": "reply['id']=True",
            "version": "result['protocolVersion']='older'",
            "error": "reply={'jsonrpc':'2.0','id':value['id'],'error':{'message':'dummy-secret'}}",
            "oversize": "reply['padding']='x'*1048577",
            "hang": "time.sleep(10)",
            "closed": "sys.exit(0)",
            "tool-error": (
                "result.update(isError='false') if value['method']!='initialize' else None"
            ),
        }

        for name, capability in {
            "boolean-close": "True",
            "false-close": "{'enabled':False}",
            "integer-close": "{'enabled':1}",
            "string-close": "{'enabled':'true'}",
            "extended-close": "{'enabled':True,'extra':True}",
        }.items():
            mutations[name] = (
                "if value['method']=='initialize': "
                "result['capabilities']['experimental']['close_expected_size']=" + capability
            )

        for name, capability in {
            "missing-ioc": "None",
            "false-ioc": "{'enabled':False}",
            "boolean-ioc": "True",
            "integer-ioc": "{'enabled':1}",
            "extended-ioc": "{'enabled':True,'extra':True}",
        }.items():
            mutations[name] = (
                "if value['method']=='initialize': "
                "result['capabilities']['experimental']['limit_price_ioc']=" + capability
            )

        def child(argv: Any, **kwargs: Any) -> Any:
            assert argv[argv.index("--network") + 1] == "testnet"
            assert argv[argv.index("--key-file") + 1] == str(key)
            assert "dummy-secret" not in " ".join(argv)
            assert "E2E_TESTNET_API_WALLET_KEY" not in kwargs["env"]
            process = original(
                [sys.executable, "-u", "-c", SCRIPT.replace("CASE", mutations[case])], **kwargs
            )
            children.append(process)
            return process

        monkeypatch.setattr(subprocess, "Popen", child)
        return MCP(
            binary,
            sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            home=home,
            client_key=key,
            url="http://127.0.0.1:18000",
            log=tmp_path / "mcp.log",
            timeout=timeout,
        )

    yield start, children
    for child in children:
        assert child.poll() is not None
        assert child.stdin.closed and child.stdout.closed
    if (tmp_path / "mcp.log").exists():
        assert "dummy-secret" not in (tmp_path / "mcp.log").read_text()


def test_tools_and_entry_is_never_retried(client: Any) -> None:
    start, _ = client
    with start() as mcp:
        assert mcp.tool("account_overview") == ({"ok": True}, False)
        assert mcp.tool("place_order", {"size": "0.0001"}) == ({"ok": True}, False)
        with pytest.raises(MCPError, match="already attempted"):
            mcp.tool("place_order")
        assert mcp.tool("close_position", {"coin": "BTC", "expected_size": "0.0001"}) == (
            {"ok": True},
            False,
        )


@pytest.mark.parametrize("case", ["id", "version", "error", "oversize", "hang", "closed"])
def test_bad_initialize_kills_child_with_fixed_diagnostics(client: Any, case: str) -> None:
    start, _ = client
    with pytest.raises(MCPError) as caught:
        start(case, timeout=0.1)
    assert "dummy-secret" not in str(caught.value)


def test_failed_entry_still_cannot_retry(client: Any) -> None:
    start, _ = client
    with start("tool-error") as mcp:
        with pytest.raises(MCPError, match="shape"):
            mcp.tool("place_order")
        with pytest.raises(MCPError, match="already attempted"):
            mcp.tool("place_order")


def test_oversized_request_and_unsupported_tool(client: Any) -> None:
    start, _ = client
    with start() as mcp:
        with pytest.raises(MCPError, match="size"):
            mcp.tool("preview_order", {"size": "x" * 4096})
        with pytest.raises(MCPError, match="tool refused"):
            mcp.tool(cast(Any, "kill_switch"))


def test_changed_binary_refused_before_spawn(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    key = tmp_path / "key"
    key.write_text("secret")
    key.chmod(0o600)
    binary = tmp_path / "binary"
    binary.write_bytes(b"changed")
    with pytest.raises(MCPError, match="differs"):
        MCP(
            binary,
            sha256="a" * 64,
            home=home,
            client_key=key,
            url="http://127.0.0.1:18000",
            log=tmp_path / "log",
        )


@pytest.mark.parametrize("case", ["legacy", "false-capability"])
def test_legacy_mcp_reads_allowed_but_all_writes_refused(client: Any, case: str) -> None:
    start, _ = client
    with start(case) as mcp:
        assert mcp.tool("account_overview") == ({"ok": True}, False)
        for tool in ("place_order", "close_position", "cancel_order"):
            with pytest.raises(MCPError, match="write refused"):
                mcp.tool(tool)
        assert mcp.entry_attempted is False


@pytest.mark.parametrize(
    "case",
    [
        "unbounded-close",
        "boolean-close",
        "false-close",
        "integer-close",
        "string-close",
        "extended-close",
    ],
)
def test_invalid_bounded_close_capability_refuses_without_sending(client: Any, case: str) -> None:
    start, _ = client
    with start(case) as mcp:
        before = mcp.sequence
        with pytest.raises(MCPError, match="close-size capability"):
            mcp.tool("close_position", {"coin": "BTC", "expected_size": "0.0001"})
        assert mcp.sequence == before


@pytest.mark.parametrize(
    "args",
    [
        None,
        {"coin": "BTC"},
        {"coin": "ETH", "expected_size": "1"},
        {"coin": "BTC", "expected_size": "0"},
        {"coin": "BTC", "expected_size": "1", "fraction": "1"},
    ],
)
def test_unbounded_close_arguments_refuse_before_send(client: Any, args: Any) -> None:
    start, _ = client
    with start() as mcp:
        before = mcp.sequence
        with pytest.raises(MCPError):
            mcp.tool("close_position", args)
        assert mcp.sequence == before


@pytest.mark.parametrize(
    "case", ["boolean-capability", "integer-capability", "extended-capability"]
)
def test_mode_capability_requires_exact_mcp_object(client: Any, case: str) -> None:
    start, _ = client
    with start(case) as mcp:
        assert not mcp.writes_bound
        assert mcp.tool("account_overview") == ({"ok": True}, False)
        for name in ("place_order", "close_position", "cancel_order"):
            with pytest.raises(MCPError):
                mcp.tool(cast(Any, name), {"coin": "BTC", "expected_size": "0.0001"})


@pytest.mark.parametrize(
    "case", ["missing-ioc", "false-ioc", "boolean-ioc", "integer-ioc", "extended-ioc"]
)
def test_explicit_limit_ioc_requires_exact_supported_capability(client: Any, case: str) -> None:
    start, _ = client
    with start(case) as mcp:
        assert not mcp.limit_price_ioc
        before = mcp.sequence
        for name in ("preview_order", "place_order"):
            with pytest.raises(MCPError):
                mcp.tool(
                    cast(Any, name), {"coin": "BTC", "limit_price": "60120", "time_in_force": "ioc"}
                )
        assert mcp.sequence == before and not mcp.entry_attempted
