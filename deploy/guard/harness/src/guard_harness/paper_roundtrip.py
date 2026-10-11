"""Shared installed-Guard paper lifecycle: allow, resize and veto, no venue key."""

import time
from collections.abc import Callable
from decimal import ROUND_DOWN, ROUND_UP, Decimal

from hyperliquid.utils.signing import order_wires_to_order_action

from guard_harness.cli import Pair
from guard_harness.paper_bot import Decision, LocalGuard, PaperBot, PaperError, Verdict


def round_trip(
    guard: LocalGuard, pair: Pair, *, pause: Callable[[float], None] = time.sleep
) -> list[Decision]:
    bot = PaperBot(guard, pair)
    unsupported = {
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
    decisions = [bot.decide(unsupported, "veto", expected_code="unsupported_market")]
    meta = guard.request("/info", {"type": "meta"})
    mids = guard.request("/info", {"type": "allMids"})
    asset, instrument = next(
        (i, item) for i, item in enumerate(meta["universe"]) if item["name"] == "BTC"
    )
    decimals = instrument["szDecimals"]
    if type(decimals) is not int or not 0 <= decimals <= 5:
        raise PaperError("BTC instrument precision refused")
    step = Decimal(1).scaleb(-decimals)
    price_step = Decimal(1).scaleb(-(6 - decimals))
    price = Decimal(mids["BTC"]).quantize(price_step, rounding=ROUND_DOWN)
    if not price.is_finite() or price <= 0:
        raise PaperError("BTC paper price refused")
    stop = (price * Decimal("0.98")).quantize(price_step, rounding=ROUND_DOWN)
    stop_limit = (stop * Decimal("0.89")).quantize(price_step, rounding=ROUND_DOWN)
    small = (Decimal("20") / price / step).to_integral_value(rounding=ROUND_UP) * step
    cases: list[tuple[Decimal, Verdict, str]] = [
        (small, "allow", "allowed"),
        (Decimal("10000"), "resize", "resized"),
    ]
    for quantity, verdict, code in cases:
        # Refill the unchanged request budget; hypothetical paper forwards consume it too.
        pause(15)
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
        result = bot.decide(entry, verdict, expected_code=code)
        events = guard.request("/guard/events?since=0")
        event = next(e for e in events if e["seq"] == result.seq)
        orders = event["forward"]["orders"]
        forwarded = Decimal(orders[0]["s"])
        if Decimal(orders[1]["s"]) != forwarded or orders[1]["r"] is not True:
            raise PaperError("paper entry and reduce-only stop sizes differ")
        if (verdict == "resize" and not Decimal("0") < forwarded < quantity) or (
            verdict == "allow" and forwarded != quantity
        ):
            raise PaperError("paper forwarded quantity differs from expected decision")
        decisions.append(result)
    return decisions
