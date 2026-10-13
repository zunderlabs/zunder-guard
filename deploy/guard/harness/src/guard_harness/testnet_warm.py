"""Cold owned Guard info-cache warming; performance only, never a trading permit."""

import math
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal

from guard_harness.testnet_protection import ProtectionError

LocalRead = Callable[[str, dict[str, object] | None, float], object]
TTL_MS = 60_000  # Guard.info stamps meta/userRole before upstream I/O (guard/read.rs).
MARGIN_MS = 1_000
MICRO = 1_000_000


def _need(value: bool) -> None:
    if not value:
        raise ProtectionError("owned Guard info warm prerequisite refused")


@dataclass
class Warm:
    meta_started: int
    role_started: int
    deadline: float
    clock: Callable[[], float]
    last_checked: float

    def check(self) -> None:
        now = self.clock()
        _need(math.isfinite(now) and self.last_checked <= now < self.deadline)
        self.last_checked = now
        millis = math.floor(now * 1000)
        _need(
            self.meta_started <= self.role_started <= millis
            and millis + MARGIN_MS < min(self.meta_started, self.role_started) + TTL_MS
        )


def warm(
    read: LocalRead,
    client: str,
    *,
    deadline: float,
    observe: Callable[[str], None] = lambda _: None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Warm:
    """Only for a fresh owned Guard with no prior passthrough meta/role requests.

    Its bucket starts full. Debit each read at response completion and never credit
    its unknown server-side I/O interval. TTL starts before request. Ceil waits and
    post-sleep checks refuse under-sleep/clock reversal; cache freshness is only a
    pre-call performance check. Guard still enforces all real budgets and risk.
    """
    _need(type(client) is str and re.fullmatch(r"0x[0-9a-f]{40}", client) is not None)
    _need(math.isfinite(deadline))
    last = clock()

    def stamp() -> int:
        nonlocal last
        now = clock()
        _need(math.isfinite(now) and now >= last and now < deadline)
        last = now
        return math.floor(now * 1000)

    def request(path: str, payload: dict[str, object] | None, expiry: int | None = None) -> object:
        began = stamp()
        limit = min(5.0, deadline - last)
        if expiry is not None:
            limit = min(limit, (expiry - MARGIN_MS - began) / 1000)
        _need(limit > 0)
        result = read(path, payload, limit)
        ended = stamp()
        _need(ended - began < limit * 1000)
        return result

    observe("warm-info-budget")
    status = request("/guard/status", None)
    _need(type(status) is dict)
    assert isinstance(status, dict)
    _need(status.get("ip_share") == "0.4" and type(status.get("ip_share")) is str)
    budgets = status.get("budgets")
    _need(type(budgets) is dict)
    assert isinstance(budgets, dict)
    info = budgets.get("info")
    _need(type(info) is dict)
    assert isinstance(info, dict)
    rate, burst = info.get("per_second"), info.get("burst")
    _need(
        type(rate) is str and re.fullmatch(r"(?:0|[1-9][0-9]?)(?:\.[0-9]{1,3})?", rate) is not None
    )
    assert isinstance(rate, str)
    milli_rate = int(Decimal(rate) * 1000)
    _need(0 < milli_rate <= 2000 and type(burst) is int and 60 <= burst <= 160)
    assert isinstance(burst, int)
    maximum = burst * MICRO

    observe("warm-info-meta")
    meta_started = stamp()
    meta = request("/info", {"type": "meta"}, meta_started + TTL_MS)
    _need(type(meta) is dict)
    assert isinstance(meta, dict)
    _need(isinstance(meta.get("universe"), list) and bool(meta["universe"]))
    balance, completed = maximum - 20 * MICRO, stamp()

    def refill(required: int, expiry: int) -> None:
        nonlocal balance, completed
        now = stamp()
        balance = min(maximum, balance + (now - completed) * milli_rate)
        completed = now
        deficit = max(0, required * MICRO - balance)
        wait_ms = (deficit + milli_rate - 1) // milli_rate
        _need(now + wait_ms + MARGIN_MS < expiry and last + wait_ms / 1000 < deadline)
        if wait_ms:
            sleep(wait_ms / 1000)
        after = stamp()
        _need(after - now >= wait_ms)
        balance = min(maximum, balance + (after - now) * milli_rate)
        completed = after
        _need(balance >= required * MICRO)

    observe("warm-info-role-budget")
    refill(60, meta_started + TTL_MS)
    observe("warm-info-role")
    role_started = stamp()
    role = request("/info", {"type": "userRole", "user": client}, meta_started + TTL_MS)
    _need(type(role) is dict)
    assert isinstance(role, dict)
    _need(role.get("role") == "missing")
    # Pessimistic: no credit for the role request's elapsed I/O interval.
    balance -= 60 * MICRO
    completed = stamp()
    observe("warm-info-light-budget")
    refill(8, min(meta_started, role_started) + TTL_MS)
    value = Warm(meta_started, role_started, deadline, clock, last)
    observe("warm-info-ttl")
    value.check()
    return value
