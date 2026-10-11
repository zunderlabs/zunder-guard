from decimal import Decimal
from typing import Any

import pytest

from guard_harness.testnet_protection import ProtectionError, entry_plan


def test_btc_order_uses_hand_computed_decimal_floor() -> None:
    # 100000 * 1.002 = 100200; 15 / 100200 = .0001497..., floor at 5 places = .00014.
    # Notional = .00014 * 100200 = 14.028, within the 10..40 USDC bounds.
    entry = entry_plan([{"name": "ETH"}, {"name": "BTC", "szDecimals": 5}], {"BTC": "100000"})
    assert entry.asset == 1 and entry.precision == 5
    assert entry.size == Decimal("0.00014") and entry.limit == Decimal("100200")
    assert entry.size * entry.limit == Decimal("14.028")


@pytest.mark.parametrize(
    "markets,mids",
    [
        ([], {"BTC": "100000"}),
        ([{"name": "BTC", "szDecimals": 5}] * 2, {"BTC": "100000"}),
        ([{"name": "BTC", "szDecimals": 5, "isDelisted": True}], {"BTC": "100000"}),
        ([{"name": "BTC", "szDecimals": True}], {"BTC": "100000"}),
        ([{"name": "BTC", "szDecimals": 7}], {"BTC": "100000"}),
        ([{"name": "BTC", "szDecimals": 5}], {"BTC": "2000000"}),
        ([{"name": "BTC", "szDecimals": 5}], {"BTC": "NaN"}),
        ([{"name": "BTC", "szDecimals": 5}], {"BTC": 100000.0}),
        ([{"name": "BTC", "szDecimals": 5}], {}),
    ],
)
def test_inactive_ambiguous_or_unexecutable_market_is_refused(markets: Any, mids: Any) -> None:
    with pytest.raises((ProtectionError, RuntimeError)):
        entry_plan(markets, mids)
