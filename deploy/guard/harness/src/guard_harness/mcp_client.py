"""Bounded subprocess MCP client for the dedicated testnet journey; no entry retries."""

import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Literal

from guard_harness.paper_bot import LocalGuard
from guard_harness.staged_subjects import _private
from guard_harness.testnet_scan import amount

Tool = Literal[
    "account_overview", "limits", "preview_order", "place_order", "close_position", "cancel_order"
]
TOOLS = {
    "account_overview",
    "limits",
    "preview_order",
    "place_order",
    "close_position",
    "cancel_order",
}


class MCPError(RuntimeError):
    """Fixed diagnostics: response bodies and key material never enter exception text."""


class MCP:
    def __init__(
        self,
        binary: Path,
        *,
        sha256: str,
        home: Path,
        client_key: Path,
        url: str,
        log: Path,
        timeout: float = 45,
    ) -> None:
        LocalGuard(url)  # Literal loopback only; this object is never used to send an order.
        _private(home, directory=True)
        _private(client_key)
        if not 0 < timeout <= 45 or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise MCPError("bounded MCP configuration required")
        if not binary.is_absolute() or binary.is_symlink() or not binary.is_file():
            raise MCPError("regular staged MCP binary required")
        with binary.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != sha256:
                raise MCPError("MCP binary differs from authenticated release bytes")
        self.log, self.timeout = log, timeout
        self.sequence, self.buffer, self.entry_attempted = 0, b"", False
        log.parent.mkdir(parents=True, exist_ok=True)
        # Server stderr can contain credentials; retain fixed protocol-log markers instead.
        self.child = subprocess.Popen(
            [
                str(binary),
                "--home",
                str(home),
                "mcp",
                "--network",
                "testnet",
                "--guard-url",
                url,
                "--key-file",
                str(client_key),
            ],
            env={"PATH": os.defpath, "HOME": str(home.parent)},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            value = self._call(
                "initialize",
                {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "guard-release-journey", "version": "1"},
                },
            )
            capabilities = value.get("capabilities")
            experimental = (
                capabilities.get("experimental") if isinstance(capabilities, dict) else None
            )
            mode = (
                experimental.get("exchange_expected_mode")
                if isinstance(experimental, dict)
                else None
            )
            self.writes_bound = (
                isinstance(mode, dict) and set(mode) == {"enabled"} and mode["enabled"] is True
            )
            self.close_size_bound = (
                isinstance(experimental, dict) and experimental.get("close_expected_size") is True
            )
            if value.get("protocolVersion") != "2025-11-25":
                raise MCPError("MCP protocol version differs")
        except BaseException:
            self.stop()
            raise

    def _call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.sequence += 1
        request = (
            json.dumps(
                {"jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params},
                allow_nan=False,
            ).encode()
            + b"\n"
        )
        if len(request) > 4096 or self.child.stdin is None or self.child.stdout is None:
            raise MCPError("MCP request size or streams refused")
        try:
            deadline = time.monotonic() + self.timeout
            os.set_blocking(self.child.stdin.fileno(), False)
            offset = 0
            with selectors.DefaultSelector() as writer:
                writer.register(self.child.stdin, selectors.EVENT_WRITE)
                while offset < len(request):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise MCPError("MCP write deadline; never retry an entry")
                    if writer.select(min(0.1, remaining)):
                        offset += os.write(self.child.stdin.fileno(), request[offset:])
            with selectors.DefaultSelector() as selector:
                selector.register(self.child.stdout, selectors.EVENT_READ)
                while time.monotonic() < deadline:
                    if b"\n" in self.buffer:
                        raw, self.buffer = self.buffer.split(b"\n", 1)
                        value = json.loads(raw)
                        if (
                            not isinstance(value, dict)
                            or value.get("jsonrpc") != "2.0"
                            or type(value.get("id")) is not int
                            or value["id"] != self.sequence
                            or "error" in value
                            or not isinstance(value.get("result"), dict)
                        ):
                            raise MCPError("MCP protocol response refused")
                        with self.log.open("a") as log:
                            log.write(f"MCP request {self.sequence} received; stderr withheld\n")
                        return dict(value["result"])
                    if selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                        block = os.read(self.child.stdout.fileno(), 65536)
                        if not block:
                            raise MCPError("MCP stream closed")
                        self.buffer += block
                        if len(self.buffer) > 1_048_576:
                            raise MCPError("MCP response size refused")
            raise MCPError("MCP deadline; never retry an entry")
        except (OSError, ValueError):
            raise MCPError("MCP transport or JSON refused") from None
        finally:
            with self.log.open("a") as log:
                log.write(f"MCP request {self.sequence} finished\n")

    def tool(
        self, name: Tool, arguments: dict[str, Any] | None = None
    ) -> tuple[dict[str, Any], bool]:
        if name not in TOOLS:
            raise MCPError("MCP journey tool refused")
        if name in {"place_order", "close_position", "cancel_order"} and not self.writes_bound:
            raise MCPError("MCP atomic expected-mode capability absent; write refused")
        if name == "close_position":
            if not self.close_size_bound:
                raise MCPError("MCP exact close-size capability absent; close refused")
            if (
                not arguments
                or set(arguments) != {"coin", "expected_size"}
                or arguments["coin"] != "BTC"
                or amount(arguments["expected_size"]) <= 0
            ):
                raise MCPError("exact positive BTC close size required")
        if name == "place_order":
            if self.entry_attempted:
                raise MCPError("MCP entry already attempted; reconcile before cleanup")
            self.entry_attempted = True  # Before writing: timeout may mean the order arrived.
        value = self._call("tools/call", {"name": name, "arguments": arguments or {}})
        if (
            not isinstance(value.get("structuredContent"), dict)
            or type(value.get("isError")) is not bool
        ):
            raise MCPError("MCP tool result shape refused")
        return dict(value["structuredContent"]), value["isError"]

    def stop(self) -> None:
        if self.child.poll() is None:
            os.killpg(self.child.pid, signal.SIGTERM)
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.child.pid, signal.SIGKILL)
                self.child.wait(timeout=5)
        for stream in (self.child.stdin, self.child.stdout):
            if stream is not None:
                stream.close()

    def __enter__(self) -> "MCP":
        return self

    def __exit__(self, *args: object) -> None:
        self.stop()
