// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The numbers the risk engine enforces.

use rust_decimal::{Decimal, dec};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Highest [`RiskLimits::max_trading_equity_usd`] that `validate` accepts:
/// USD 2,500. Raising it is a recorded decision first, and then a change
/// here.
pub const MAX_TRADING_EQUITY_USD: Decimal = dec!(2500);

/// Risk limits as fractions of equity. The defaults are the risk frame
/// recorded on 4 Oct 2026, the limits of Zunder's own bot. Zunder Guard's
/// defaults are its own preset (`zunder_guard_core::policy::guard_defaults`),
/// equal in value today but never read from here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RiskLimits {
    /// Equity put at risk per trade: quantity times the distance to the stop
    /// plus the expected round-trip costs.
    pub risk_per_trade: Decimal,
    /// Cap on risk-to-stop summed over all open positions.
    pub max_open_risk: Decimal,
    /// Cap on total position value divided by equity.
    pub max_leverage: Decimal,
    /// Loss since the start of the UTC day that halts trading until the next day.
    pub daily_loss_stop: Decimal,
    /// Fall from the equity peak that stops the bot until a manual review.
    pub drawdown_stop: Decimal,
    /// The equity cap: the most equity, in the quote currency
    /// (USDC), that the engine sizes from and measures its stops against.
    /// `None`, the default, means no cap (backtests, paper books, testnet).
    ///
    /// It only ever tightens: entries are sized from the smaller of the
    /// venue's equity and the cap, so a deposit above the cap does not
    /// raise the size; and a loss counts as a fraction of the smaller of
    /// its base (the peak, or the day's start) and the cap, so the stops
    /// fire no later than without the cap, and no later than on an account
    /// holding exactly the cap. Positive and at most
    /// [`MAX_TRADING_EQUITY_USD`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_trading_equity_usd: Option<Decimal>,
}

impl Default for RiskLimits {
    fn default() -> Self {
        Self {
            risk_per_trade: dec!(0.02),
            max_open_risk: dec!(0.06),
            max_leverage: dec!(5),
            daily_loss_stop: dec!(0.06),
            drawdown_stop: dec!(0.25),
            max_trading_equity_usd: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RiskConfigError {
    #[error("{field} must be greater than 0 and at most 1, got {value}")]
    FractionOutOfRange { field: &'static str, value: Decimal },
    #[error("max_leverage must be greater than 0 and at most 100, got {0}")]
    LeverageOutOfRange(Decimal),
    #[error("max_open_risk ({max_open_risk}) must not be below risk_per_trade ({risk_per_trade})")]
    OpenRiskBelowTradeRisk {
        max_open_risk: Decimal,
        risk_per_trade: Decimal,
    },
    #[error("starting equity must be positive, got {0}")]
    EquityNotPositive(Decimal),
    #[error(
        "max_trading_equity_usd must be greater than 0 and at most {MAX_TRADING_EQUITY_USD}, got {0}"
    )]
    EquityCapOutOfRange(Decimal),
}

impl RiskLimits {
    /// The aggressive frame (recorded 5 Oct 2026, for research and paper):
    /// at most 5% risk per
    /// trade, 20% open risk, 10x leverage, a 15% daily loss stop and a 50%
    /// drawdown stop. For research and paper only; it is never the default.
    /// A study or a book that opts into it names its own, smaller risk per
    /// trade where the Kelly analysis of its trades calls for one.
    pub fn aggressive() -> Self {
        Self {
            risk_per_trade: dec!(0.05),
            max_open_risk: dec!(0.20),
            max_leverage: dec!(10),
            daily_loss_stop: dec!(0.15),
            drawdown_stop: dec!(0.50),
            max_trading_equity_usd: None,
        }
    }

    /// Reject limits that make no sense before any money depends on them.
    pub fn validate(&self) -> Result<(), RiskConfigError> {
        let fractions = [
            ("risk_per_trade", self.risk_per_trade),
            ("max_open_risk", self.max_open_risk),
            ("daily_loss_stop", self.daily_loss_stop),
            ("drawdown_stop", self.drawdown_stop),
        ];
        for (field, value) in fractions {
            if value <= Decimal::ZERO || value > Decimal::ONE {
                return Err(RiskConfigError::FractionOutOfRange { field, value });
            }
        }
        if self.max_leverage <= Decimal::ZERO || self.max_leverage > Decimal::ONE_HUNDRED {
            return Err(RiskConfigError::LeverageOutOfRange(self.max_leverage));
        }
        if self.max_open_risk < self.risk_per_trade {
            return Err(RiskConfigError::OpenRiskBelowTradeRisk {
                max_open_risk: self.max_open_risk,
                risk_per_trade: self.risk_per_trade,
            });
        }
        if let Some(cap) = self.max_trading_equity_usd
            && (cap <= Decimal::ZERO || cap > MAX_TRADING_EQUITY_USD)
        {
            return Err(RiskConfigError::EquityCapOutOfRange(cap));
        }
        Ok(())
    }

    /// `equity`, or the cap where that is smaller.
    pub fn capped(&self, equity: Decimal) -> Decimal {
        self.max_trading_equity_usd
            .map_or(equity, |cap| equity.min(cap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_recorded_risk_frame() {
        let limits = RiskLimits::default();
        assert_eq!(limits.risk_per_trade, dec!(0.02));
        assert_eq!(limits.max_open_risk, dec!(0.06));
        assert_eq!(limits.max_leverage, dec!(5));
        assert_eq!(limits.daily_loss_stop, dec!(0.06));
        assert_eq!(limits.drawdown_stop, dec!(0.25));
        assert_eq!(limits.validate(), Ok(()));
    }

    #[test]
    fn the_aggressive_preset_is_the_recorded_aggressive_frame() {
        // The recorded aggressive frame, 5 Oct 2026: 5% per trade, 20% open, 10x, 15% daily, 50% drawdown.
        let aggressive = RiskLimits::aggressive();
        assert_eq!(aggressive.risk_per_trade, dec!(0.05));
        assert_eq!(aggressive.max_open_risk, dec!(0.20));
        assert_eq!(aggressive.max_leverage, dec!(10));
        assert_eq!(aggressive.daily_loss_stop, dec!(0.15));
        assert_eq!(aggressive.drawdown_stop, dec!(0.50));
        assert_eq!(aggressive.validate(), Ok(()));
        // The preset exists next to the default, it does not replace it.
        assert_ne!(aggressive, RiskLimits::default());
        assert_eq!(RiskLimits::default().drawdown_stop, dec!(0.25));
    }

    #[test]
    fn fractions_outside_zero_to_one_are_rejected() {
        let zero = RiskLimits {
            risk_per_trade: dec!(0),
            ..RiskLimits::default()
        };
        assert!(matches!(
            zero.validate(),
            Err(RiskConfigError::FractionOutOfRange {
                field: "risk_per_trade",
                ..
            })
        ));

        // 25 instead of 0.25: the classic percent-versus-fraction slip.
        let percent = RiskLimits {
            drawdown_stop: dec!(25),
            ..RiskLimits::default()
        };
        assert!(matches!(
            percent.validate(),
            Err(RiskConfigError::FractionOutOfRange {
                field: "drawdown_stop",
                ..
            })
        ));
    }

    #[test]
    fn open_risk_cap_cannot_be_below_one_trade() {
        let limits = RiskLimits {
            risk_per_trade: dec!(0.05),
            max_open_risk: dec!(0.02),
            ..RiskLimits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(RiskConfigError::OpenRiskBelowTradeRisk { .. })
        ));
    }

    #[test]
    fn the_equity_cap_is_off_by_default_and_bounded_by_the_sleeve() {
        assert_eq!(RiskLimits::default().max_trading_equity_usd, None);
        assert_eq!(RiskLimits::aggressive().max_trading_equity_usd, None);
        // The ceiling: USD 2,500.
        assert_eq!(MAX_TRADING_EQUITY_USD, dec!(2500));
        for good in [dec!(0.01), dec!(2000), dec!(2500)] {
            let limits = RiskLimits {
                max_trading_equity_usd: Some(good),
                ..RiskLimits::default()
            };
            assert_eq!(limits.validate(), Ok(()), "{good}");
        }
        for bad in [dec!(0), dec!(-1), dec!(2500.01), dec!(1000000)] {
            let limits = RiskLimits {
                max_trading_equity_usd: Some(bad),
                ..RiskLimits::default()
            };
            assert_eq!(
                limits.validate(),
                Err(RiskConfigError::EquityCapOutOfRange(bad)),
                "{bad}"
            );
        }
    }

    #[test]
    fn capped_takes_the_smaller_of_equity_and_the_cap() {
        let capped = RiskLimits {
            max_trading_equity_usd: Some(dec!(2000)),
            ..RiskLimits::default()
        };
        assert_eq!(capped.capped(dec!(5000)), dec!(2000));
        assert_eq!(capped.capped(dec!(1500)), dec!(1500));
        assert_eq!(RiskLimits::default().capped(dec!(5000)), dec!(5000));
    }

    #[test]
    fn limits_without_a_cap_serialise_as_before() {
        // Paper logs and risk journals written before the cap existed hold
        // the limits without the key: the same bytes must come out, and
        // they must read back as no cap.
        let json = serde_json::to_string(&RiskLimits::default()).unwrap();
        assert_eq!(
            json,
            r#"{"risk_per_trade":"0.02","max_open_risk":"0.06","max_leverage":"5","daily_loss_stop":"0.06","drawdown_stop":"0.25"}"#
        );
        let back: RiskLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(back, RiskLimits::default());
        let capped = RiskLimits {
            max_trading_equity_usd: Some(dec!(2300)),
            ..RiskLimits::default()
        };
        let json = serde_json::to_string(&capped).unwrap();
        assert!(
            json.ends_with(r#""max_trading_equity_usd":"2300"}"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<RiskLimits>(&json).unwrap(), capped);
    }

    #[test]
    fn leverage_must_be_positive_and_sane() {
        for leverage in [dec!(0), dec!(-1), dec!(101)] {
            let limits = RiskLimits {
                max_leverage: leverage,
                ..RiskLimits::default()
            };
            assert_eq!(
                limits.validate(),
                Err(RiskConfigError::LeverageOutOfRange(leverage))
            );
        }
    }
}
