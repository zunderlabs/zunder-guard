// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Zunder Guard's product defaults, in one place for Guard and the
//! website's judge.
//!
//! A preset of its own, never read from [`crate::RiskLimits::default`] (the
//! limits of Zunder's own bot): equal in value today, but changing one
//! never changes the other, and changing either is a recorded decision.
//! Guard's policy (`Policy::guard_defaults()`) and the website's playground
//! defaults are built from these constants. They are not the mainnet
//! ceiling, which Guard pins separately.

use rust_decimal::{Decimal, dec};
use serde::{Deserialize, Serialize};

/// What Guard does with an entry that carries no stop loss.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopPolicy {
    /// Size the entry from a stop at the default stop distance and attach a
    /// reduce-only stop there. A stop the bot sends later replaces it only
    /// when it is tighter: stops only tighten.
    #[default]
    Attach,
    /// Refuse the entry.
    Refuse,
}

/// Max leverage: open positions worth at most 5x equity.
pub const MAX_LEVERAGE: Decimal = dec!(5);
/// Max loss at the stop: 2% of equity per trade.
pub const MAX_LOSS_AT_STOP: Decimal = dec!(0.02);
/// An entry without a stop gets one attached.
pub const STOP: StopPolicy = StopPolicy::Attach;
/// An attached stop 2% from the entry.
pub const DEFAULT_STOP_DISTANCE: Decimal = dec!(0.02);
/// At least 10% from the price to the liquidation price.
pub const MIN_LIQUIDATION_DISTANCE: Decimal = dec!(0.10);
/// A position worth at most 200% of account value.
pub const MAX_POSITION_OF_ACCOUNT: Decimal = dec!(2);
/// Max open risk: all stops together lose at most 6% of equity.
pub const MAX_OPEN_RISK: Decimal = dec!(0.06);
/// Daily loss stop: 6% of the day's starting equity.
pub const DAILY_LOSS_STOP: Decimal = dec!(0.06);
/// Drawdown halt: 25% below the peak.
pub const DRAWDOWN_HALT: Decimal = dec!(0.25);
/// An entry's price at most 0.5% beyond the mid.
pub const ENTRY_PRICE_BOUND: Decimal = dec!(0.005);
/// Expected fee per side, in basis points.
pub const FEE_BPS: Decimal = dec!(4.5);
/// Expected slippage per side, in basis points.
pub const SLIPPAGE_BPS: Decimal = dec!(1);
/// How far beyond its trigger Guard's own market stops may fill: 10%.
pub const STOP_SLIPPAGE: Decimal = dec!(0.10);
/// How far from the mid Guard's own closing orders may fill: 5%.
pub const EXIT_SLIPPAGE: Decimal = dec!(0.05);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_preset_is_guards_recorded_defaults() {
        // 5x, 2% at the stop, attach a stop 2% away, liquidation at least
        // 10% away, 200% per position, 6% open risk, 6% daily, 25%
        // drawdown; entries within 0.5% of the mid; 4.5 bp fee and 1 bp
        // slippage per side; stops filling up to 10% and closes up to 5%
        // beyond the price.
        assert_eq!(MAX_LEVERAGE, dec!(5));
        assert_eq!(MAX_LOSS_AT_STOP, dec!(0.02));
        assert_eq!(STOP, StopPolicy::Attach);
        assert_eq!(StopPolicy::default(), StopPolicy::Attach);
        assert_eq!(DEFAULT_STOP_DISTANCE, dec!(0.02));
        assert_eq!(MIN_LIQUIDATION_DISTANCE, dec!(0.10));
        assert_eq!(MAX_POSITION_OF_ACCOUNT, dec!(2));
        assert_eq!(MAX_OPEN_RISK, dec!(0.06));
        assert_eq!(DAILY_LOSS_STOP, dec!(0.06));
        assert_eq!(DRAWDOWN_HALT, dec!(0.25));
        assert_eq!(ENTRY_PRICE_BOUND, dec!(0.005));
        assert_eq!(FEE_BPS, dec!(4.5));
        assert_eq!(SLIPPAGE_BPS, dec!(1));
        assert_eq!(STOP_SLIPPAGE, dec!(0.10));
        assert_eq!(EXIT_SLIPPAGE, dec!(0.05));
    }

    #[test]
    fn the_preset_is_not_read_from_the_bots_frame() {
        // Equal in value today, so only the source can tell: no line of
        // code here leads back to `RiskLimits` (the bot's frame) or to the
        // mainnet ceiling.
        let source = include_str!("guard_defaults.rs");
        let code = &source[..source.find("#[cfg(test)]").expect("tests")];
        for line in code.lines() {
            let line = line.trim_start();
            if line.starts_with("//") {
                continue;
            }
            for word in [
                "RiskLimits",
                "mainnet",
                "default()",
                "aggressive",
                "..",
                "frame",
            ] {
                assert!(!line.contains(word), "`{word}` in: {line}");
            }
        }
    }

    #[test]
    fn stop_policy_reads_and_writes_snake_case() {
        let attach: StopPolicy = serde_json::from_str("\"attach\"").expect("reads");
        assert_eq!(attach, StopPolicy::Attach);
        assert_eq!(
            serde_json::to_string(&StopPolicy::Refuse).expect("writes"),
            "\"refuse\""
        );
    }
}
