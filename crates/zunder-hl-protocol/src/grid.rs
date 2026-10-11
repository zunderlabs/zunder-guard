// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Hyperliquid's price and size grid ("Tick and lot size" in the API
//! documentation).
//!
//! - Sizes are whole multiples of `10^-szDecimals`.
//! - Prices have at most five significant figures and at most
//!   `6 - szDecimals` decimals on a perp, `8 - szDecimals` on a spot pair
//!   (of the base token); whole numbers are always allowed. Trailing zeros
//!   do not count.
//!
//! Which way to round depends on what an order is for; the caller says,
//! with a [`Round`].

use rust_decimal::{Decimal, RoundingStrategy};

/// Hyperliquid perps allow `6 - szDecimals` price decimals...
pub const PERP_MAX_DECIMALS: u32 = 6;
/// ...and spot pairs `8 - szDecimals` of the base token.
pub const SPOT_MAX_DECIMALS: u32 = 8;
/// Hyperliquid prices have at most five significant figures.
pub const PRICE_SIG_FIGS: u32 = 5;
/// "Order must have minimum value of $10." (error responses in the API
/// documentation). A reduce-only order that closes a position exactly is
/// exempt.
pub const MIN_ORDER_VALUE: Decimal = Decimal::TEN;

/// Which way to round a quantity or price that is off the grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Round {
    /// Down: towards zero for the positive prices and sizes on the grid
    /// (towards negative infinity in general).
    Down,
    /// Up: away from zero for positive values (towards positive infinity).
    Up,
}

impl Round {
    pub const fn strategy(self) -> RoundingStrategy {
        match self {
            Round::Down => RoundingStrategy::ToNegativeInfinity,
            Round::Up => RoundingStrategy::ToPositiveInfinity,
        }
    }
}

/// `value` rounded to `decimals` places in `direction`, without trailing
/// zeros: a size onto the grid of an asset with `szDecimals` `decimals`.
pub fn round_to_decimals(value: Decimal, decimals: u32, direction: Round) -> Decimal {
    value
        .round_dp_with_strategy(decimals, direction.strategy())
        .normalize()
}

/// The price grid of one instrument: at most `max_decimals` decimals and at
/// most `sig_figs` significant figures, unless a price is a whole number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceGrid {
    max_decimals: u32,
    sig_figs: u32,
}

impl PriceGrid {
    /// A grid with explicit numbers. Callers bound them (more than 28
    /// decimals is beyond `Decimal`).
    pub const fn new(max_decimals: u32, sig_figs: u32) -> Self {
        Self {
            max_decimals,
            sig_figs,
        }
    }

    /// A Hyperliquid perp with `sz_decimals` in `meta`. `None` above 6,
    /// which would leave no price decimals and means the metadata is not
    /// what this code expects.
    pub const fn hyperliquid_perp(sz_decimals: u32) -> Option<Self> {
        match PERP_MAX_DECIMALS.checked_sub(sz_decimals) {
            Some(max_decimals) => Some(Self::new(max_decimals, PRICE_SIG_FIGS)),
            None => None,
        }
    }

    /// A Hyperliquid spot pair whose base token has `sz_decimals` in
    /// `spotMeta`. `None` above 8.
    pub const fn hyperliquid_spot(sz_decimals: u32) -> Option<Self> {
        match SPOT_MAX_DECIMALS.checked_sub(sz_decimals) {
            Some(max_decimals) => Some(Self::new(max_decimals, PRICE_SIG_FIGS)),
            None => None,
        }
    }

    pub const fn max_decimals(&self) -> u32 {
        self.max_decimals
    }

    pub const fn sig_figs(&self) -> u32 {
        self.sig_figs
    }

    /// Whether `price` is on the grid: positive, and a whole number or
    /// within both the decimal and the significant-figure limits.
    pub fn is_valid(&self, price: Decimal) -> bool {
        if price <= Decimal::ZERO {
            return false;
        }
        if price.fract().is_zero() {
            return true;
        }
        let normalized = price.normalize();
        normalized.scale() <= self.max_decimals && significant_figures(normalized) <= self.sig_figs
    }

    /// The nearest price on the grid in `direction`, or `None` when there
    /// is none above zero.
    pub fn round(&self, price: Decimal, direction: Round) -> Option<Decimal> {
        if price <= Decimal::ZERO {
            return None;
        }
        let rounded = round_to_decimals(price, self.allowed_decimals(price), direction);
        // A carry into the next power of ten only removes digits, so one pass
        // is enough; the check guards that reasoning.
        (rounded > Decimal::ZERO && self.is_valid(rounded)).then_some(rounded)
    }

    /// Decimal places allowed at the magnitude of `price`.
    fn allowed_decimals(&self, price: Decimal) -> u32 {
        let by_sig_figs = i64::from(self.sig_figs) - 1 - floor_log10(price);
        let clamped = by_sig_figs.clamp(0, i64::from(self.max_decimals));
        u32::try_from(clamped).unwrap_or(0)
    }
}

/// `floor(log10(value))` for a positive value, computed exactly from the
/// mantissa and the scale: `value = m * 10^-scale`.
pub fn floor_log10(value: Decimal) -> i64 {
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

    fn perp(sz_decimals: u32) -> PriceGrid {
        PriceGrid::hyperliquid_perp(sz_decimals).unwrap()
    }

    #[test]
    fn documented_perp_price_examples() {
        // All from "Tick and lot size" in the Hyperliquid API documentation.
        let grid = perp(0);
        assert!(grid.is_valid(dec!(1234.5)));
        assert!(!grid.is_valid(dec!(1234.56)), "six significant figures");
        assert!(grid.is_valid(dec!(0.001234)));
        assert!(!grid.is_valid(dec!(0.0012345)), "seven decimals");
        // "If szDecimals = 1, 0.01234 is valid but 0.012345 is not".
        assert!(perp(1).is_valid(dec!(0.01234)));
        assert!(!perp(1).is_valid(dec!(0.012345)));
        // "123456 is a valid price even though 12345.6 is not".
        assert!(grid.is_valid(dec!(123456)));
        assert!(!grid.is_valid(dec!(12345.6)));
        // Trailing zeros do not count; nothing at or below zero is a price.
        assert!(perp(5).is_valid(dec!(85259.0)));
        assert!(!perp(5).is_valid(dec!(8525.95)));
        assert!(!perp(5).is_valid(dec!(0)));
        assert!(!perp(5).is_valid(dec!(-1)));
    }

    #[test]
    fn prices_round_to_five_significant_figures_or_the_decimal_cap() {
        // szDecimals 5 (BTC): at most 1 decimal.
        let btc = perp(5);
        assert_eq!(btc.round(dec!(62345.67), Round::Down), Some(dec!(62345)));
        assert_eq!(btc.round(dec!(62345.67), Round::Up), Some(dec!(62346)));
        assert_eq!(btc.round(dec!(1234.56), Round::Down), Some(dec!(1234.5)));
        assert_eq!(btc.round(dec!(0.123456), Round::Up), Some(dec!(0.2)));
        assert_eq!(btc.round(dec!(0.123456), Round::Down), Some(dec!(0.1)));
        // szDecimals 0: up to 6 decimals.
        let small = perp(0);
        assert_eq!(
            small.round(dec!(0.00123456), Round::Down),
            Some(dec!(0.001234))
        );
        assert_eq!(
            small.round(dec!(0.00123456), Round::Up),
            Some(dec!(0.001235))
        );
        assert_eq!(small.round(dec!(123456.7), Round::Down), Some(dec!(123456)));
        // Across a power of ten: 9.99996 -> 10, 99999.5 -> 100000.
        assert_eq!(small.round(dec!(9.99996), Round::Up), Some(dec!(10)));
        assert_eq!(small.round(dec!(99999.5), Round::Up), Some(dec!(100000)));
        // Nothing above zero below 0.04 at one decimal.
        assert_eq!(btc.round(dec!(0.04), Round::Down), None);
        assert_eq!(btc.round(dec!(0.04), Round::Up), Some(dec!(0.1)));
        assert_eq!(btc.round(dec!(0), Round::Up), None);
        assert_eq!(btc.round(dec!(-3), Round::Up), None);
    }

    #[test]
    fn grids_by_size_decimals() {
        assert_eq!(perp(5).max_decimals(), 1);
        assert_eq!(perp(6).max_decimals(), 0);
        assert_eq!(PriceGrid::hyperliquid_perp(7), None);
        // "MAX_DECIMALS is 6 for perps and 8 for spot".
        let purr = PriceGrid::hyperliquid_spot(0).unwrap();
        assert!(purr.is_valid(dec!(0.00012345)));
        assert!(!perp(0).is_valid(dec!(0.00012345)));
        assert_eq!(PriceGrid::hyperliquid_spot(5).unwrap().max_decimals(), 3);
        assert_eq!(PriceGrid::hyperliquid_spot(9), None);
        assert_eq!(perp(0).sig_figs(), 5);
    }

    #[test]
    fn sizes_round_in_the_requested_direction() {
        // "if szDecimals = 3 then 1.001 is a valid size but 1.0001 is not".
        assert_eq!(round_to_decimals(dec!(1.0009), 3, Round::Down), dec!(1));
        assert_eq!(round_to_decimals(dec!(1.0001), 3, Round::Up), dec!(1.001));
        assert_eq!(round_to_decimals(dec!(2.500), 3, Round::Up), dec!(2.5));
    }

    #[test]
    fn floor_log10_is_exact() {
        assert_eq!(floor_log10(dec!(1)), 0);
        assert_eq!(floor_log10(dec!(9.999)), 0);
        assert_eq!(floor_log10(dec!(10)), 1);
        assert_eq!(floor_log10(dec!(10.00)), 1);
        assert_eq!(floor_log10(dec!(0.01)), -2);
        assert_eq!(floor_log10(dec!(0.0999)), -2);
        assert_eq!(floor_log10(dec!(123456)), 5);
    }
}
