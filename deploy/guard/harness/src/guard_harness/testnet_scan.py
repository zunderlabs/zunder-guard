"""Read-only testnet cleanup scan; never accepts a key or repairs account state."""

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from guard_harness.bounded_http_read import ReadOpener

SCAN_TIMEOUT = 1800

INFO = "https://api.hyperliquid-testnet.xyz/info"
Read = Callable[[dict[str, Any]], object]


class ScanError(RuntimeError):
    """Incomplete or non-flat observations never earn passing cleanup evidence."""


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def amount(value: object) -> Decimal:
    if not isinstance(value, str):
        raise ScanError("venue accounting amount must be a decimal string")
    try:
        result = Decimal(value)
    except InvalidOperation:
        raise ScanError("invalid venue accounting amount") from None
    if not result.is_finite():
        raise ScanError("nonfinite venue accounting amount")
    return result


class InventoryChanged(ScanError):
    """The DEX inventory only grew during a scan; carries the end list for the restart check."""

    def __init__(self, message: str, dexes: list[str]) -> None:
        super().__init__(message)
        self.dexes = dexes


def inventory(value: object) -> list[str]:
    if not isinstance(value, list) or not value or value[0] is not None or len(value) > 512:
        raise ScanError("complete bounded DEX inventory required")
    names = [""]
    for item in value[1:]:
        name = item.get("name") if isinstance(item, dict) else None
        if (
            not isinstance(name, str)
            or not 0 < len(name) <= 128
            or not name.isprintable()
            or any(char.isspace() for char in name)
            or name in names
        ):
            raise ScanError("invalid or duplicate DEX inventory")
        names.append(name)
    return names


def flat_scan(
    read: Read, account: str, *, minimum_equity: Decimal = Decimal("200")
) -> dict[str, object]:
    """Scan every DEX twice-bound to its inventory; values are observations, not attestations."""
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", account):
        raise ScanError("explicit testnet account required")
    if not minimum_equity.is_finite() or minimum_equity <= 0:
        raise ScanError("positive finite equity floor required")
    started_at = datetime.now(UTC).isoformat()
    if read({"type": "userAbstraction", "user": account}) != "disabled":
        raise ScanError("standard testnet account required")

    def scan_once() -> tuple[object, object, list[str], list[dict[str, object]]]:
        before = read({"type": "perpDexs"})
        dexes = inventory(before)
        observations: list[dict[str, object]] = []
        for dex in dexes:
            fields = {"user": account, **({"dex": dex} if dex else {})}
            state = read({"type": "clearinghouseState", **fields})
            orders = read({"type": "frontendOpenOrders", **fields})
            if not isinstance(state, dict) or not isinstance(orders, list):
                raise ScanError("unreadable holdings")
            positions, summary = state.get("assetPositions"), state.get("marginSummary")
            if not isinstance(positions, list) or not isinstance(summary, dict):
                raise ScanError("unreadable holdings")
            for item in positions:
                position = item.get("position") if isinstance(item, dict) else None
                if (
                    not isinstance(position, dict)
                    or not isinstance(position.get("coin"), str)
                    or not position["coin"]
                ):
                    raise ScanError("unreadable position")
                if amount(position.get("szi")) != 0:
                    raise ScanError("account is not flat; unrelated state is never repaired")
            equity = amount(summary.get("accountValue"))
            if orders:
                raise ScanError("account has open orders; unrelated state is never repaired")
            if not dex and equity < minimum_equity:
                raise ScanError("refill the E2E testnet account")
            observations.append(
                {
                    "dex": dex,
                    "positions": 0,
                    "open_orders": 0,
                    "clearinghouse_sha256": digest(state),
                    "frontend_open_orders_sha256": digest(orders),
                }
            )
        after = read({"type": "perpDexs"})
        if inventory(after) != dexes:
            if not set(dexes) <= set(inventory(after)):
                raise ScanError("DEX inventory changed during scan")
            raise InventoryChanged("DEX inventory changed during scan", inventory(after))
        return before, after, dexes, observations

    # Testnet DEXes come and go (rc.16, 14 Oct: one appeared and one was removed during scans).
    # Only an added DEX restarts the whole scan, once, inside the same phase deadline: the second
    # pass must cover every DEX of the first, so a DEX that vanished from the list is never left
    # unchecked. Each completed scan covers one unchanged inventory; nothing partial is accepted.
    try:
        before, after, dexes, observations = scan_once()
    except InventoryChanged as changed:
        # Every DEX seen at any point of the first pass (its end list contains its start list)
        # must be scanned by the second pass; one added and removed again refuses.
        seen = changed.dexes
        before, after, dexes, observations = scan_once()
        if not set(seen) <= set(dexes):
            raise ScanError("DEX inventory changed during scan") from None
    return {
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat(),
        "network": "testnet",
        "account_sha256": hashlib.sha256(account.lower().encode()).hexdigest(),
        "user_abstraction": "disabled",
        "dexes": dexes,
        "observations": observations,
        "inventory_before_sha256": digest(before),
        "inventory_after_sha256": digest(after),
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        raise ScanError("testnet read redirected")


class TestnetReads:
    """Fixed public endpoint, no proxies, redirects or keys; at most 600 weight/minute.

    clearinghouseState, allMids and orderStatus reserve 2 weight; other ordinary reads
    reserve 20. A fill-history request reserves 120 (20 plus at most 2000/20 returned-item
    weight). Each request prepays its weight at 10/second, and rolling reservations keep
    every minute at 600, even on failures and across phases. Sequential only. See:
    https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/rate-limits-and-user-limits
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        timeout: float = SCAN_TIMEOUT,
    ) -> None:
        if not 10 < timeout <= SCAN_TIMEOUT:
            raise ScanError("bounded scan timeout required")
        self.clock, self.sleep = clock, sleep
        self.next_read = clock()
        self.reservations: list[tuple[float, int]] = []
        self.deadline = clock() + timeout
        self.opener = ReadOpener()

    def start_phase(self, *, timeout: float) -> None:
        """New bounded stage deadline without resetting the shared request pacing."""
        if not 10 < timeout <= SCAN_TIMEOUT:
            raise ScanError("bounded scan timeout required")
        self.deadline = self.clock() + timeout

    def __call__(self, payload: dict[str, Any]) -> object:
        kind = payload.get("type")
        fields = {"type"} if kind in ("perpDexs", "meta", "allMids") else {"type", "user"}
        if kind in ("clearinghouseState", "frontendOpenOrders") and "dex" in payload:
            fields.add("dex")
        if kind == "orderStatus":
            fields.add("oid")
            if not isinstance(payload.get("oid"), str) or not re.fullmatch(
                r"0x[0-9a-f]{32}", payload["oid"]
            ):
                raise ScanError("explicit cloid lookup required")
        if kind == "userFillsByTime":
            fields.add("startTime")
            if type(payload.get("startTime")) is not int or payload["startTime"] <= 0:
                raise ScanError("positive integer fill start required")
        if kind not in (
            "perpDexs",
            "meta",
            "allMids",
            "userAbstraction",
            "clearinghouseState",
            "frontendOpenOrders",
            "orderStatus",
            "userFillsByTime",
        ):
            raise ScanError("unsupported read-only info request")
        if set(payload) != fields:
            raise ScanError("unexpected info request fields")
        if "user" in fields and (
            not isinstance(payload.get("user"), str)
            or not re.fullmatch(r"0x[0-9a-fA-F]{40}", payload["user"])
        ):
            raise ScanError("explicit testnet account required")
        now = self.clock()
        weight = (
            120
            if kind == "userFillsByTime"
            else 2
            if kind in ("clearinghouseState", "allMids", "orderStatus")
            else 20
        )
        scheduled = max(now, self.next_read) + weight / 10
        active = [(at, cost) for at, cost in self.reservations if at > scheduled - 60]
        reserved = sum(cost for _, cost in active)
        for at, cost in active:
            if reserved + weight <= 600:
                break
            # Stay beyond the expiry boundary despite floating-clock rounding.
            scheduled = at + 60.001
            reserved -= cost
        wait = scheduled - now
        if now + wait + 10 > self.deadline:
            raise ScanError("scan deadline exhausted; no incomplete flat credit")
        self.sleep(wait)
        self.next_read = self.clock()
        if self.next_read + 10 > self.deadline:
            raise ScanError("scan deadline exhausted after pacing; nothing sent")
        self.reservations = [
            (at, cost) for at, cost in self.reservations if at > self.next_read - 60
        ]
        self.reservations.append((self.next_read, weight))
        request = urllib.request.Request(
            INFO,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=10) as response:
                raw = response.read(1_048_577)
            if len(raw) > 1_048_576:
                raise ScanError("oversized testnet response")
            if self.clock() >= self.deadline:
                raise ScanError("scan deadline exhausted after response; no flat credit")
            return json.loads(raw)
        except (OSError, UnicodeDecodeError, ValueError):
            raise ScanError("testnet HTTP/JSON read failed") from None
