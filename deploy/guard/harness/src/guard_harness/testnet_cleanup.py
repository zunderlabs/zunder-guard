"""Bounded owned cleanup ordering; never cancels protection before exposure is flat."""

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from guard_harness.mcp_client import Tool
from guard_harness.testnet_ownership import Ownership


class CleanupError(RuntimeError):
    """Fixed diagnostics; caller keeps Guard running on incomplete cleanup."""


class Tools(Protocol):
    def tool(
        self, name: Tool, arguments: dict[str, Any] | None = None
    ) -> tuple[dict[str, Any], bool]: ...


@dataclass(frozen=True)
class Cleaned:
    actions: tuple[str, ...]
    flat_scan: dict[str, object]


def cleanup(
    observe: Callable[[], Ownership],
    mcp: Tools,
    scan: Callable[[], dict[str, object]],
    *,
    clock: Callable[[], float] = time.monotonic,
    timeout: float = 1280,
    check_work: Callable[[], None] = lambda: None,
) -> Cleaned:
    """Use fresh collect_ownership(cleanup=True) before/after each exact mutation.

    The orchestrator supplies exclusive all-DEX preflight, serialized C6 account access,
    bounded collectors/MCP requests, and an independent final flat_scan. Exceptions grant
    no cleanup evidence and must leave Guard running; this function never kills protection.
    No failed/uncertain mutation is retried. A partial successful close permits at most three
    total close attempts, each with freshly proved decreasing net exposure and exact size.
    Returned facts are observations, never release or journey attestations.
    """
    if not 0 < timeout <= 1280:
        raise CleanupError("bounded cleanup deadline required")
    deadline = clock() + timeout
    actions: list[str] = []

    def fresh() -> Ownership:
        check_work()
        if clock() >= deadline:
            raise CleanupError("cleanup deadline; keep Guard running")
        value = observe()
        if clock() >= deadline:
            raise CleanupError("cleanup deadline; keep Guard running")
        check_work()
        return value

    def mutate(name: Tool, arguments: dict[str, Any]) -> None:
        check_work()
        if clock() >= deadline:
            raise CleanupError("cleanup deadline; keep Guard running")
        result, error = mcp.tool(name, arguments)
        check_work()
        if error or result.get("sent") is not True:
            raise CleanupError("cleanup send unconfirmed; reconcile privately")
        actions.append(name)

    current = fresh()
    identity = current.entry_oid, current.filled

    def next_read() -> Ownership:
        value = fresh()
        if (value.entry_oid, value.filled) != identity:
            raise CleanupError("cleanup ownership changed; keep Guard running")
        return value

    if current.resting_entry:
        mutate("cancel_order", {"coin": "BTC", "order_id": current.entry_oid})
        current = next_read()
        if current.resting_entry or current.remaining:
            raise CleanupError("entry cancellation incomplete; keep Guard running")
    for _ in range(3):
        if not current.remaining:
            break
        before = current.remaining
        mutate("close_position", {"coin": "BTC", "expected_size": str(before)})
        current = next_read()
        if current.resting_entry or not 0 <= current.remaining < before:
            raise CleanupError("close made no proved progress; keep Guard running")
    if current.remaining:
        raise CleanupError("bounded close attempts exhausted; keep Guard running")
    if current.stop_oid is not None:
        # Exposure is already proved flat; preserve the protective stop until this point.
        mutate("cancel_order", {"coin": "BTC", "order_id": current.stop_oid})
        current = next_read()
        if current.stop_oid is not None or current.remaining or current.resting_entry:
            raise CleanupError("orphan cancellation incomplete; keep Guard running")
    if clock() >= deadline:
        raise CleanupError("cleanup deadline; keep Guard running")
    check_work()
    # A separate full-scan phase owns its 1800-second transport deadline. It must not
    # inherit or be enclosed by the shorter owned-mutation deadline.
    flat = scan()  # Must independently inspect every DEX; empty ownership is insufficient.
    return Cleaned(tuple(actions), flat)
