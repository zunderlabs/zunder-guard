// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Lot sizes and price grids.
//!
//! Executors refuse quantities and prices that are off the venue's grid
//! instead of rounding them, because the safe direction depends on what an
//! order is for. The session rounds, with these rules:
//!
//! - Opening quantity: down. Never more than the risk engine sized.
//! - Closing quantity (stops, exits, flattening): up. Reduce-only orders
//!   cannot grow a position, and rounding down would leave a residue
//!   unprotected.
//! - Entry price bound: towards the passive side (a buy rounds down), so
//!   the fill is never worse than the price the risk engine sized from.
//! - Stop trigger: towards the position (a long's stop rounds up), so the
//!   stop is never looser than the one the risk engine sized for.
//! - Worst price of a stop, an exit or a flatten order: towards the
//!   aggressive side (a sell rounds down), so that getting out is never
//!   blocked by a rounding step.

use rust_decimal::{Decimal, RoundingStrategy};
use serde::Serialize;
use zunder_core::{Position, Symbol};

/// Which way to round a quantity or price that is off the grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Round {
    /// Towards zero.
    Down,
    /// Away from zero.
    Up,
}

impl Round {
    const fn strategy(self) -> RoundingStrategy {
        match self {
            Round::Down => RoundingStrategy::ToNegativeInfinity,
            Round::Up => RoundingStrategy::ToPositiveInfinity,
        }
    }
}

/// Hyperliquid perps allow `6 - szDecimals` price decimals...
const HYPERLIQUID_PERP_MAX_DECIMALS: u32 = 6;
/// ...and spot pairs `8 - szDecimals` of the base token ("Tick and lot
/// size" in the API documentation).
const HYPERLIQUID_SPOT_MAX_DECIMALS: u32 = 8;
/// Hyperliquid prices have at most five significant figures.
const HYPERLIQUID_SIG_FIGS: u32 = 5;
/// "Order must have minimum value of $10."
const HYPERLIQUID_MIN_NOTIONAL: Decimal = Decimal::TEN;

/// Largest number of decimals accepted for quantities and prices. Far above
/// any venue's, and far below `Decimal`'s limit of 28.
const MAX_DECIMALS: u32 = 18;

/// What kind of instrument the rules are for. A trading session treats the
/// two differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstrumentKind {
    /// A perpetual future: long or short, with reduce-only orders.
    Perp,
    /// A spot pair: the account holds the base token. Long only: a sell can
    /// never open a short, because the venue refuses to sell more than the
    /// account holds, and there is nothing to borrow.
    Spot,
}

/// How a venue constrains quantities and prices for one instrument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstrumentRules {
    symbol: Symbol,
    kind: InstrumentKind,
    qty_decimals: u32,
    max_price_decimals: u32,
    max_price_sig_figs: u32,
    min_notional: Decimal,
    /// The venue's highest leverage for a perpetual (`maxLeverage` in
    /// Hyperliquid's `meta`), when it says. The maintenance margin is half
    /// the initial margin at this leverage ("Margining"), which decides
    /// where an isolated position is liquidated.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_leverage: Option<u32>,
}

impl InstrumentRules {
    /// Rules for a perpetual with explicit numbers. `None` when a number is
    /// out of range: more than 18 decimals, no significant figures, or a
    /// negative minimum.
    pub fn new(
        symbol: Symbol,
        qty_decimals: u32,
        max_price_decimals: u32,
        max_price_sig_figs: u32,
        min_notional: Decimal,
    ) -> Option<Self> {
        Self::with_kind(
            symbol,
            InstrumentKind::Perp,
            qty_decimals,
            max_price_decimals,
            max_price_sig_figs,
            min_notional,
        )
    }

    /// Rules of either kind with explicit numbers, bounded as in
    /// [`InstrumentRules::new`].
    pub fn with_kind(
        symbol: Symbol,
        kind: InstrumentKind,
        qty_decimals: u32,
        max_price_decimals: u32,
        max_price_sig_figs: u32,
        min_notional: Decimal,
    ) -> Option<Self> {
        let in_range = qty_decimals <= MAX_DECIMALS
            && max_price_decimals <= MAX_DECIMALS
            && (1..=MAX_DECIMALS).contains(&max_price_sig_figs)
            && min_notional >= Decimal::ZERO;
        in_range.then_some(Self {
            symbol,
            kind,
            qty_decimals,
            max_price_decimals,
            max_price_sig_figs,
            min_notional,
            max_leverage: None,
        })
    }

    /// The same rules with the venue's highest leverage for the instrument.
    /// A leverage of zero says nothing and is ignored.
    #[must_use]
    pub fn with_max_leverage(mut self, max_leverage: u32) -> Self {
        self.max_leverage = (max_leverage > 0).then_some(max_leverage);
        self
    }

    /// The venue's highest leverage for the instrument, when known.
    pub fn max_leverage(&self) -> Option<u32> {
        self.max_leverage
    }

    /// The rules for a Hyperliquid perpetual with `sz_decimals` from the
    /// `meta` endpoint. See "Tick and lot size" in the API documentation.
    /// `None` when `sz_decimals` is above 6, which would leave no price
    /// decimals at all and means the metadata is not what we expect.
    pub fn hyperliquid_perp(symbol: Symbol, sz_decimals: u32) -> Option<Self> {
        let max_price_decimals = HYPERLIQUID_PERP_MAX_DECIMALS.checked_sub(sz_decimals)?;
        Self::new(
            symbol,
            sz_decimals,
            max_price_decimals,
            HYPERLIQUID_SIG_FIGS,
            HYPERLIQUID_MIN_NOTIONAL,
        )
    }

    /// The rules for a Hyperliquid spot pair whose base token has
    /// `sz_decimals` in `spotMeta`: quantities in steps of
    /// `10^-szDecimals`, prices with at most five significant figures and
    /// `8 - szDecimals` decimals, orders worth at least 10 USDC. `None` when
    /// `sz_decimals` is above 8, which would leave no price decimals at all.
    pub fn hyperliquid_spot(symbol: Symbol, sz_decimals: u32) -> Option<Self> {
        let max_price_decimals = HYPERLIQUID_SPOT_MAX_DECIMALS.checked_sub(sz_decimals)?;
        Self::with_kind(
            symbol,
            InstrumentKind::Spot,
            sz_decimals,
            max_price_decimals,
            HYPERLIQUID_SIG_FIGS,
            HYPERLIQUID_MIN_NOTIONAL,
        )
    }

    pub fn symbol(&self) -> &Symbol {
        &self.symbol
    }

    pub fn kind(&self) -> InstrumentKind {
        self.kind
    }

    pub fn is_spot(&self) -> bool {
        self.kind == InstrumentKind::Spot
    }

    /// Quantities are whole multiples of `10^-qty_decimals`.
    pub fn qty_decimals(&self) -> u32 {
        self.qty_decimals
    }

    /// Prices have at most this many decimal places...
    pub fn max_price_decimals(&self) -> u32 {
        self.max_price_decimals
    }

    /// ...and at most this many significant figures, unless they are whole
    /// numbers, which are always allowed.
    pub fn max_price_sig_figs(&self) -> u32 {
        self.max_price_sig_figs
    }

    /// Smallest value of an order that opens or grows a position, in quote
    /// currency. Also the minimum for the risk engine's `SizeRequest`.
    pub fn min_notional(&self) -> Decimal {
        self.min_notional
    }

    /// Smallest quantity increment, for the risk engine's `SizeRequest`.
    pub fn qty_step(&self) -> Decimal {
        // In range by construction: at most 18 decimals.
        Decimal::new(1, self.qty_decimals)
    }

    pub fn is_valid_qty(&self, qty: Decimal) -> bool {
        qty > Decimal::ZERO && qty.normalize().scale() <= self.qty_decimals
    }

    pub fn round_qty(&self, qty: Decimal, direction: Round) -> Decimal {
        qty.round_dp_with_strategy(self.qty_decimals, direction.strategy())
            .normalize()
    }

    /// A spot balance of the base token as a position: the part on the
    /// quantity grid, rounded down, since nothing more can be sold.
    ///
    /// `None` when that part is zero, or worth less than the venue minimum
    /// at `price`: such a balance cannot be sold, so it is dust, not a
    /// position. Dust arises because a spot buy pays its fee in the base
    /// token (a buy of 0.001 at 7 bps leaves 0.0009993, of which 0.00099 can
    /// be sold with steps of 0.00001). The entry price is what the balance
    /// cost per token, `entry_notional / balance`, or `price` when the venue
    /// gives no cost.
    pub fn spot_position(
        &self,
        balance: Decimal,
        entry_notional: Option<Decimal>,
        price: Decimal,
    ) -> Option<Position> {
        let qty = self.round_qty(balance, Round::Down);
        if qty <= Decimal::ZERO || price <= Decimal::ZERO {
            return None;
        }
        if qty.checked_mul(price)? < self.min_notional {
            return None;
        }
        let entry = entry_notional
            .filter(|cost| *cost > Decimal::ZERO)
            .and_then(|cost| cost.checked_div(balance))
            .unwrap_or(price);
        Some(Position { qty, entry })
    }

    pub fn is_valid_price(&self, price: Decimal) -> bool {
        if price <= Decimal::ZERO {
            return false;
        }
        if price.fract().is_zero() {
            return true;
        }
        let normalized = price.normalize();
        normalized.scale() <= self.max_price_decimals
            && significant_figures(normalized) <= self.max_price_sig_figs
    }

    /// The nearest valid price in `direction`, or `None` when there is none
    /// above zero.
    pub fn round_price(&self, price: Decimal, direction: Round) -> Option<Decimal> {
        if price <= Decimal::ZERO {
            return None;
        }
        let rounded = price
            .round_dp_with_strategy(self.allowed_decimals(price), direction.strategy())
            .normalize();
        // A carry into the next power of ten only removes digits, so one pass
        // is enough; the check guards that reasoning.
        (rounded > Decimal::ZERO && self.is_valid_price(rounded)).then_some(rounded)
    }

    /// Decimal places allowed at the magnitude of `price`.
    fn allowed_decimals(&self, price: Decimal) -> u32 {
        let by_sig_figs = i64::from(self.max_price_sig_figs) - 1 - floor_log10(price);
        let clamped = by_sig_figs.clamp(0, i64::from(self.max_price_decimals));
        u32::try_from(clamped).unwrap_or(0)
    }
}

/// `floor(log10(value))` for a positive value, computed exactly from the
/// mantissa and the scale: `value = m * 10^-scale`.
fn floor_log10(value: Decimal) -> i64 {
    let mantissa = value.mantissa().unsigned_abs();
    let digits = mantissa.checked_ilog10().map_or(0, i64::from);
    digits - i64::from(value.scale())
}

/// Significant figures of a normalised, non-zero value.
fn significant_figures(normalized: Decimal) -> u32 {
    normalized
        .mantissa()
        .unsigned_abs()
        .checked_ilog10()
        .map_or(0, |log| log + 1)
}

#[cfg(test)]
mod tests {
    use rust_decimal::dec;

    use super::*;

    fn perp(sz_decimals: u32) -> InstrumentRules {
        InstrumentRules::hyperliquid_perp(Symbol::new("TEST"), sz_decimals).unwrap()
    }

    #[test]
    fn documented_perp_price_examples() {
        // All from "Tick and lot size" in the Hyperliquid API documentation.
        // BTC has szDecimals 5, so at most 1 decimal; the examples there do
        // not name an asset, so they are checked with szDecimals 0 (6 decimals).
        let rules = perp(0);
        assert!(rules.is_valid_price(dec!(1234.5)));
        assert!(
            !rules.is_valid_price(dec!(1234.56)),
            "six significant figures"
        );
        assert!(rules.is_valid_price(dec!(0.001234)));
        assert!(!rules.is_valid_price(dec!(0.0012345)), "seven decimals");
        // "If szDecimals = 1, 0.01234 is valid but 0.012345 is not".
        assert!(perp(1).is_valid_price(dec!(0.01234)));
        assert!(!perp(1).is_valid_price(dec!(0.012345)));
        // "123456 is a valid price even though 12345.6 is not".
        assert!(rules.is_valid_price(dec!(123456)));
        assert!(!rules.is_valid_price(dec!(12345.6)));
    }

    #[test]
    fn documented_size_example() {
        // "if szDecimals = 3 then 1.001 is a valid size but 1.0001 is not".
        let rules = perp(3);
        assert!(rules.is_valid_qty(dec!(1.001)));
        assert!(!rules.is_valid_qty(dec!(1.0001)));
        // Trailing zeros do not count as decimals.
        assert!(rules.is_valid_qty(dec!(1.00100)));
        assert!(!rules.is_valid_qty(dec!(0)));
        assert_eq!(rules.qty_step(), dec!(0.001));
    }

    #[test]
    fn quantities_round_in_the_requested_direction() {
        let rules = perp(3);
        assert_eq!(rules.round_qty(dec!(1.0009), Round::Down), dec!(1));
        assert_eq!(rules.round_qty(dec!(1.0001), Round::Up), dec!(1.001));
        // Already on the grid: unchanged either way.
        assert_eq!(rules.round_qty(dec!(2.5), Round::Down), dec!(2.5));
        assert_eq!(rules.round_qty(dec!(2.5), Round::Up), dec!(2.5));
    }

    #[test]
    fn prices_round_to_five_significant_figures_or_the_decimal_cap() {
        // szDecimals 5 (BTC on Hyperliquid): at most 1 decimal.
        let btc = perp(5);
        // 62345.67 has 5 integer digits: whole dollars only.
        assert_eq!(
            btc.round_price(dec!(62345.67), Round::Down),
            Some(dec!(62345))
        );
        assert_eq!(
            btc.round_price(dec!(62345.67), Round::Up),
            Some(dec!(62346))
        );
        // 1234.56: four integer digits leave one decimal for five figures.
        assert_eq!(
            btc.round_price(dec!(1234.56), Round::Down),
            Some(dec!(1234.5))
        );
        // 0.123456: five figures would allow 5 decimals, the cap is 1.
        assert_eq!(btc.round_price(dec!(0.123456), Round::Up), Some(dec!(0.2)));
        assert_eq!(
            btc.round_price(dec!(0.123456), Round::Down),
            Some(dec!(0.1))
        );

        // szDecimals 0: up to 6 decimals.
        let small = perp(0);
        // 0.00123456 -> five figures are 0.0012345(6), but six decimals cap it.
        assert_eq!(
            small.round_price(dec!(0.00123456), Round::Down),
            Some(dec!(0.001234))
        );
        assert_eq!(
            small.round_price(dec!(0.00123456), Round::Up),
            Some(dec!(0.001235))
        );
        // Whole numbers above five figures stay whole numbers.
        assert_eq!(
            small.round_price(dec!(123456.7), Round::Down),
            Some(dec!(123456))
        );
    }

    #[test]
    fn rounding_up_across_a_power_of_ten_stays_valid() {
        let rules = perp(0);
        // 9.99996 -> 4 decimals allowed -> 10.0000, which is just 10.
        assert_eq!(rules.round_price(dec!(9.99996), Round::Up), Some(dec!(10)));
        // 99999.5 -> whole dollars -> 100000.
        assert_eq!(
            rules.round_price(dec!(99999.5), Round::Up),
            Some(dec!(100000))
        );
    }

    #[test]
    fn prices_that_round_to_nothing_are_refused() {
        // szDecimals 5 allows one decimal: 0.04 rounds down to zero.
        assert_eq!(perp(5).round_price(dec!(0.04), Round::Down), None);
        assert_eq!(perp(5).round_price(dec!(0.04), Round::Up), Some(dec!(0.1)));
        assert_eq!(perp(5).round_price(dec!(0), Round::Up), None);
        assert_eq!(perp(5).round_price(dec!(-3), Round::Up), None);
    }

    #[test]
    fn valid_prices_round_to_themselves() {
        let rules = perp(2);
        for price in [dec!(1234), dec!(12.345), dec!(0.0123), dec!(98765)] {
            assert!(rules.is_valid_price(price), "{price}");
            assert_eq!(rules.round_price(price, Round::Up), Some(price));
            assert_eq!(rules.round_price(price, Round::Down), Some(price));
        }
    }

    #[test]
    fn metadata_beyond_six_size_decimals_is_refused() {
        assert!(InstrumentRules::hyperliquid_perp(Symbol::new("X"), 6).is_some());
        assert!(InstrumentRules::hyperliquid_perp(Symbol::new("X"), 7).is_none());
    }

    #[test]
    fn spot_prices_allow_eight_minus_size_decimals() {
        // "MAX_DECIMALS is 6 for perps and 8 for spot" ("Tick and lot size").
        // UBTC has szDecimals 5 in spotMeta: 3 price decimals, steps of 0.00001.
        let ubtc = InstrumentRules::hyperliquid_spot(Symbol::new("UBTC/USDC"), 5).unwrap();
        assert!(ubtc.is_spot());
        assert_eq!(ubtc.kind(), InstrumentKind::Spot);
        assert_eq!(ubtc.qty_step(), dec!(0.00001));
        assert_eq!(ubtc.max_price_decimals(), 3);
        assert_eq!(ubtc.min_notional(), dec!(10));
        // Five significant figures still bind at BTC prices: whole dollars.
        assert!(ubtc.is_valid_price(dec!(86491)));
        assert!(!ubtc.is_valid_price(dec!(86491.5)));
        assert_eq!(
            ubtc.round_price(dec!(86491.5), Round::Down),
            Some(dec!(86491))
        );
        // PURR has szDecimals 0: 8 decimals for a coin priced in cents,
        // where a perp with szDecimals 0 would stop at 6.
        let purr = InstrumentRules::hyperliquid_spot(Symbol::new("PURR/USDC"), 0).unwrap();
        assert!(purr.is_valid_price(dec!(0.00012345)));
        assert!(!perp(0).is_valid_price(dec!(0.00012345)));
        assert!(!purr.is_valid_price(dec!(0.000123456)), "nine decimals");
        // Perps are perps.
        assert!(!perp(5).is_spot());
        assert!(InstrumentRules::hyperliquid_spot(Symbol::new("X"), 8).is_some());
        assert!(InstrumentRules::hyperliquid_spot(Symbol::new("X"), 9).is_none());
    }

    #[test]
    fn spot_balances_become_positions_on_the_grid_and_dust_is_dropped() {
        let ubtc = InstrumentRules::hyperliquid_spot(Symbol::new("UBTC/USDC"), 5).unwrap();
        // A buy of 0.002 at 80,000 paying 7 bps in UBTC leaves 0.0019986
        // UBTC: 0.00199 can be sold. It cost 160 USDC, 80,056.04 per token
        // held (160 / 0.0019986, to Decimal's precision).
        let position = ubtc
            .spot_position(dec!(0.0019986), Some(dec!(160)), dec!(80000))
            .unwrap();
        assert_eq!(position.qty, dec!(0.00199));
        assert_eq!(position.entry.round_dp(2), dec!(80056.04));
        // Without a cost the entry is the price.
        assert_eq!(
            ubtc.spot_position(dec!(0.002), None, dec!(80000))
                .unwrap()
                .entry,
            dec!(80000)
        );
        // The 0.0000086 left after selling 0.00199 is below one step.
        assert_eq!(ubtc.spot_position(dec!(0.0000086), None, dec!(80000)), None);
        // 0.00012 is on the grid but worth 9.60 at 80,000: below the 10 minimum.
        assert_eq!(ubtc.spot_position(dec!(0.00012), None, dec!(80000)), None);
        // 0.000125 at 80,000 rounds down to 0.00012 as well.
        assert_eq!(ubtc.spot_position(dec!(0.000125), None, dec!(80000)), None);
        // 0.00013 is worth 10.40.
        assert_eq!(
            ubtc.spot_position(dec!(0.00013), None, dec!(80000))
                .unwrap()
                .qty,
            dec!(0.00013)
        );
    }

    #[test]
    fn explicit_rules_are_bounded() {
        let symbol = Symbol::new("X");
        assert!(InstrumentRules::new(symbol.clone(), 18, 18, 18, dec!(0)).is_some());
        assert!(InstrumentRules::new(symbol.clone(), 19, 2, 5, dec!(10)).is_none());
        assert!(InstrumentRules::new(symbol.clone(), 2, 19, 5, dec!(10)).is_none());
        assert!(InstrumentRules::new(symbol.clone(), 2, 2, 0, dec!(10)).is_none());
        assert!(InstrumentRules::new(symbol, 2, 2, 5, dec!(-1)).is_none());
    }
}
