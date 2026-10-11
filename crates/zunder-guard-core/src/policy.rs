// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Guard's policy: the nine rules, their defaults and their bounds.
//!
//! This file is the one source of truth for the defaults and bounds; the
//! website's rules (and the `zr1_` rules code it hands out, the rules crate
//! `zunder-guard-rules` in `deploy/guard/rules`) map onto it.
//!
//! Guard's defaults are Guard's own named preset ([`Policy::guard_defaults`],
//! the constants in [`guard_defaults`]). They are a product choice and are
//! not read from `RiskLimits::default()`, the limits of Zunder's own bot:
//! changing Guard's defaults can never change the bot's limits, and the
//! other way round. Today the five shared rules happen to have the same
//! values as the bot's frame. On mainnet a policy may not be looser than
//! [`Policy::mainnet_ceiling`], which takes the engine's five from
//! `RiskLimits::default()` and
//! pins Guard's own rules separately, so that loosening Guard's product
//! defaults never loosens what mainnet accepts.
//!
//! The defaults:
//!
//! | Rule | Default |
//! |---|---|
//! | Max leverage | 5x |
//! | Max loss at the stop (per trade) | 2% of equity |
//! | Protective stop | required; Guard attaches one at 2% when an entry has none |
//! | Min distance to liquidation | 10% of the price |
//! | Max position | 200% of equity |
//! | Max open risk | 6% of equity |
//! | Daily loss stop | 6% |
//! | Drawdown halt | 25% |
//! | Markets | all |
//!
//! Five of them are the risk engine's own limits ([`Policy::risk_limits`]):
//! sizing from the stop, open risk, leverage, the daily loss stop and the
//! drawdown stop are enforced by `zunder-risk`, not re-implemented here.
//! Every value is checked by [`Policy::validate`] against lower and upper
//! bounds; out-of-bounds values are refused, never clamped.

use std::collections::BTreeSet;

use rust_decimal::{Decimal, dec};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zunder_risk::{RiskConfigError, RiskLimits};

/// What Guard does with an entry that carries no stop loss.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopPolicy {
    /// Size the entry from a stop at [`Policy::default_stop_distance`] and
    /// attach a reduce-only stop there. A stop the bot sends later replaces
    /// it only when it is tighter: stops only tighten.
    #[default]
    Attach,
    /// Refuse the entry.
    Refuse,
}

/// The markets Guard lets a bot open positions in. Closing, stops and
/// cancels are never limited by it, on the dexes Guard reads.
///
/// Hyperliquid's main dex is always read and protected. A HIP-3 dex (a
/// builder-deployed perp dex, its coins named `dex:COIN`) is read, judged
/// and protected only when a market names it: `dex:*` for every market of
/// the dex, `dex:COIN` for one. `*` is every market of the main dex, never
/// a HIP-3 one: the default stays main-dex only. At most
/// [`MAX_HIP3_DEXES`] HIP-3 dexes, for the venue's request budget.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Markets {
    /// Every perp of Hyperliquid's main dex (`["*"]` in a rules code).
    #[default]
    All,
    /// Only these entries: coins by the venue's name (`BTC`, `xyz:GOLD`),
    /// `dex:*` for every market of a HIP-3 dex, and `*` for every market
    /// of the main dex.
    Only(BTreeSet<String>),
}

/// The entry that stands for every market of the main dex.
pub const ALL_MAIN_MARKETS: &str = "*";
/// Most HIP-3 dexes Guard reads: each one adds a full read of its account
/// to every request and every sync (`docs/guard.md`, "HIP-3 markets").
pub const MAX_HIP3_DEXES: usize = 2;

/// The HIP-3 dex of a coin name (`xyz` of `xyz:GOLD`); `None` for a
/// main-dex coin.
pub fn dex_of(coin: &str) -> Option<&str> {
    coin.split_once(':').map(|(dex, _)| dex)
}

impl Markets {
    /// Whether an entry may open a position in `coin`.
    pub fn allows(&self, coin: &str) -> bool {
        match (self, dex_of(coin)) {
            (Markets::All, None) => true,
            (Markets::All, Some(_)) => false,
            (Markets::Only(entries), None) => {
                entries.contains(ALL_MAIN_MARKETS) || entries.contains(coin)
            }
            (Markets::Only(entries), Some(dex)) => {
                entries.contains(coin) || entries.contains(&format!("{dex}:*"))
            }
        }
    }

    /// The HIP-3 dexes the markets name (by `dex:*` or `dex:COIN`): the
    /// dexes Guard reads, judges and protects besides the main dex.
    pub fn hip3_dexes(&self) -> BTreeSet<String> {
        match self {
            Markets::All => BTreeSet::new(),
            Markets::Only(entries) => entries
                .iter()
                .filter_map(|entry| dex_of(entry))
                // A dex's name is letters and digits; another prefix names
                // no dex and matches nothing.
                .filter(|dex| !dex.is_empty() && dex.bytes().all(|b| b.is_ascii_alphanumeric()))
                .map(str::to_owned)
                .collect(),
        }
    }

    /// A list as written: `["*"]` alone is [`Markets::All`].
    pub fn from_list(entries: impl IntoIterator<Item = String>) -> Self {
        let entries: BTreeSet<String> = entries.into_iter().collect();
        if entries.len() == 1 && entries.contains(ALL_MAIN_MARKETS) {
            Markets::All
        } else {
            Markets::Only(entries)
        }
    }
}

/// In TOML: `markets = "all"` or a list of coins.
impl Serialize for Markets {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Markets::All => serializer.serialize_str("all"),
            Markets::Only(coins) => coins.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Markets {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Word(String),
            List(Vec<String>),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Word(word) if word == "all" => Ok(Markets::All),
            Raw::Word(word) => Err(serde::de::Error::custom(format!(
                "markets must be \"all\" or a list of coins, got \"{word}\""
            ))),
            Raw::List(coins) => Ok(Markets::from_list(coins)),
        }
    }
}

/// Most coins a market list may hold.
pub const MAX_MARKETS: usize = 32;

/// The bounds of one of the nine rules: above `min` (or at it when
/// `min_inclusive`) and at most `max`. As fractions (2% is 0.02), the
/// leverage as a multiple. These are the rules schema v1's bounds: the
/// rules crate (`deploy/guard/rules`, `zr1.ts`, `schema-v1.json`) reads them
/// from here. The upper bounds of the risk engine's five never exceed
/// `RiskLimits::aggressive()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleBound {
    pub min: Decimal,
    pub min_inclusive: bool,
    pub max: Decimal,
    pub text: &'static str,
}

const fn open_to(max: Decimal, text: &'static str) -> RuleBound {
    RuleBound {
        min: Decimal::ZERO,
        min_inclusive: false,
        max,
        text,
    }
}

pub const MAX_LEVERAGE_BOUNDS: RuleBound = open_to(dec!(10), "above 0 and at most 10");
pub const MAX_LOSS_AT_STOP_BOUNDS: RuleBound = open_to(dec!(0.05), "above 0 and at most 0.05");
pub const DEFAULT_STOP_DISTANCE_BOUNDS: RuleBound = open_to(dec!(0.5), "above 0 and at most 0.5");
pub const MIN_LIQUIDATION_DISTANCE_BOUNDS: RuleBound = RuleBound {
    min: dec!(0.01),
    min_inclusive: true,
    max: dec!(0.5),
    text: "between 0.01 and 0.5",
};
pub const MAX_POSITION_OF_ACCOUNT_BOUNDS: RuleBound = open_to(dec!(10), "above 0 and at most 10");
pub const MAX_OPEN_RISK_BOUNDS: RuleBound = open_to(dec!(0.2), "above 0 and at most 0.2");
pub const DAILY_LOSS_STOP_BOUNDS: RuleBound = open_to(dec!(0.15), "above 0 and at most 0.15");
pub const DRAWDOWN_HALT_BOUNDS: RuleBound = open_to(dec!(0.5), "above 0 and at most 0.5");

/// The policy. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Total position value over equity, and (its whole part, at least 1x)
    /// the highest isolated leverage Guard sets or lets a bot set. Above 0,
    /// at most 10, four decimals.
    pub max_leverage: Decimal,
    /// Loss at the stop per trade, fees and slippage included, as a
    /// fraction of equity: the risk engine's `risk_per_trade`. Up to 0.05.
    pub max_loss_at_stop: Decimal,
    pub stop: StopPolicy,
    /// The default stop distance: where Guard puts the stop of an entry
    /// that has none, as a fraction of the price away from it. Above 0, at
    /// most 0.5, below `min_liquidation_distance`. `defaultStopDistancePct`
    /// in a rules code.
    pub default_stop_distance: Decimal,
    /// Least distance between the entry and the liquidation price, as a
    /// fraction of the price. 0.01 to 0.5; also at least beyond the stop.
    pub min_liquidation_distance: Decimal,
    /// Most value of one position as a fraction of equity (2 is 200%).
    /// Above 0, at most 10 and `max_leverage`.
    pub max_position_of_account: Decimal,
    /// Risk to the stops of all positions and resting entries together,
    /// as a fraction of equity. Up to 0.2, at least `max_loss_at_stop`.
    pub max_open_risk: Decimal,
    /// Loss since the start of the UTC day that halts and flattens until
    /// the next day. Up to 0.15.
    pub daily_loss_stop: Decimal,
    /// Fall from the equity peak that halts and flattens until a person's
    /// review. Up to 0.5.
    pub drawdown_halt: Decimal,
    pub markets: Markets,
    /// The most an entry's limit price may lie beyond the mid price, as a
    /// fraction: a marketable order's worst fill. A limit further out is
    /// pulled in to this bound. 0.0005 to 0.05.
    pub entry_price_bound: Decimal,
    /// Taker fee per side in basis points, counted into each entry's risk.
    /// 0 to 50.
    pub fee_bps: Decimal,
    /// Expected slippage per side in basis points, counted likewise. 0 to
    /// 100.
    pub slippage_bps: Decimal,
    /// How far beyond its trigger a stop may fill, as a fraction: the limit
    /// of Guard's own market stops (Hyperliquid's stop-market tolerance,
    /// 10%, as in Zunder's own executor), and the liquidation price must lie beyond
    /// that worst fill. 0.05 to 0.2.
    pub stop_slippage: Decimal,
    /// How far from the mid Guard's own closing orders may fill when it
    /// flattens, as a fraction (5%, as in Zunder's own executor). 0.01 to 0.1.
    pub exit_slippage: Decimal,
    /// The equity Guard sizes from and measures its stops against is never
    /// more than this (USDC). Off by default; at most
    /// `zunder_risk::MAX_TRADING_EQUITY_USD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_trading_equity_usd: Option<Decimal>,
}

/// Guard's product defaults. Kept separate from `RiskLimits::default()`
/// so changes to this preset cannot change the shared engine defaults.
/// The rules schema and website derive their defaults from these constants.
pub mod guard_defaults {
    use rust_decimal::{Decimal, dec};

    use super::StopPolicy;

    pub const MAX_LEVERAGE: Decimal = dec!(5);
    pub const MAX_LOSS_AT_STOP: Decimal = dec!(0.02);
    pub const STOP: StopPolicy = StopPolicy::Attach;
    pub const DEFAULT_STOP_DISTANCE: Decimal = dec!(0.02);
    pub const MIN_LIQUIDATION_DISTANCE: Decimal = dec!(0.10);
    pub const MAX_POSITION_OF_ACCOUNT: Decimal = dec!(2);
    pub const MAX_OPEN_RISK: Decimal = dec!(0.06);
    pub const DAILY_LOSS_STOP: Decimal = dec!(0.06);
    pub const DRAWDOWN_HALT: Decimal = dec!(0.25);
    pub const ENTRY_PRICE_BOUND: Decimal = dec!(0.005);
    pub const FEE_BPS: Decimal = dec!(4.5);
    pub const SLIPPAGE_BPS: Decimal = dec!(1);
    pub const STOP_SLIPPAGE: Decimal = dec!(0.10);
    pub const EXIT_SLIPPAGE: Decimal = dec!(0.05);
}

/// The loosest Guard's own rules (those that are not the risk engine's) may
/// be on mainnet, pinned here so that a change of Guard's product defaults
/// cannot loosen mainnet. The engine's five come from `RiskLimits::default()`
/// instead ([`Policy::mainnet_ceiling`]). Changing one is a decision first.
mod mainnet_ceiling {
    use rust_decimal::{Decimal, dec};

    pub const DEFAULT_STOP_DISTANCE: Decimal = dec!(0.02);
    pub const MIN_LIQUIDATION_DISTANCE: Decimal = dec!(0.10);
    pub const MAX_POSITION_OF_ACCOUNT: Decimal = dec!(2);
    pub const ENTRY_PRICE_BOUND: Decimal = dec!(0.005);
    pub const FEE_BPS: Decimal = dec!(4.5);
    pub const SLIPPAGE_BPS: Decimal = dec!(1);
    pub const STOP_SLIPPAGE: Decimal = dec!(0.10);
    pub const EXIT_SLIPPAGE: Decimal = dec!(0.05);
}

impl Default for Policy {
    /// [`Policy::guard_defaults`].
    fn default() -> Self {
        Self::guard_defaults()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    #[error("{field} must be {bounds}, got {value}")]
    OutOfBounds {
        field: &'static str,
        bounds: &'static str,
        value: Decimal,
    },
    #[error("markets lists no coin; use \"all\" for every market")]
    NoMarkets,
    #[error("markets lists more than {MAX_MARKETS} coins")]
    TooManyMarkets,
    #[error("market `{0}` is not a coin name, `dex:*` or `*`")]
    BadMarket(String),
    #[error(
        "markets name more than {MAX_HIP3_DEXES} HIP-3 dexes; Guard reads at most {MAX_HIP3_DEXES}"
    )]
    TooManyDexes,
    #[error("market `{0}` is listed besides an entry that covers it (`*` or `dex:*`)")]
    CoveredMarket(String),
    #[error(transparent)]
    Risk(#[from] RiskConfigError),
}

/// `(field, value, low, low_inclusive, high, bounds text)`.
type Bound = (&'static str, Decimal, Decimal, bool, Decimal, &'static str);

impl Policy {
    /// Refuse a policy outside its bounds. Nothing is clamped.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let rule = |field: &'static str, value: Decimal, bound: RuleBound| {
            (
                field,
                value,
                bound.min,
                bound.min_inclusive,
                bound.max,
                bound.text,
            )
        };
        let bounds: [Bound; 13] = [
            rule("max_leverage", self.max_leverage, MAX_LEVERAGE_BOUNDS),
            rule(
                "max_loss_at_stop",
                self.max_loss_at_stop,
                MAX_LOSS_AT_STOP_BOUNDS,
            ),
            rule(
                "default_stop_distance",
                self.default_stop_distance,
                DEFAULT_STOP_DISTANCE_BOUNDS,
            ),
            rule(
                "min_liquidation_distance",
                self.min_liquidation_distance,
                MIN_LIQUIDATION_DISTANCE_BOUNDS,
            ),
            rule(
                "max_position_of_account",
                self.max_position_of_account,
                MAX_POSITION_OF_ACCOUNT_BOUNDS,
            ),
            rule("max_open_risk", self.max_open_risk, MAX_OPEN_RISK_BOUNDS),
            rule(
                "daily_loss_stop",
                self.daily_loss_stop,
                DAILY_LOSS_STOP_BOUNDS,
            ),
            rule("drawdown_halt", self.drawdown_halt, DRAWDOWN_HALT_BOUNDS),
            (
                "entry_price_bound",
                self.entry_price_bound,
                dec!(0.0005),
                true,
                dec!(0.05),
                "between 0.0005 and 0.05",
            ),
            (
                "fee_bps",
                self.fee_bps,
                dec!(0),
                true,
                dec!(50),
                "between 0 and 50",
            ),
            (
                "slippage_bps",
                self.slippage_bps,
                dec!(0),
                true,
                dec!(100),
                "between 0 and 100",
            ),
            (
                "stop_slippage",
                self.stop_slippage,
                dec!(0.05),
                true,
                dec!(0.2),
                "between 0.05 and 0.2",
            ),
            (
                "exit_slippage",
                self.exit_slippage,
                dec!(0.01),
                true,
                dec!(0.1),
                "between 0.01 and 0.1",
            ),
        ];
        for (field, value, low, inclusive, high, text) in bounds {
            let above_low = if inclusive { value >= low } else { value > low };
            if !above_low || value > high {
                return Err(PolicyError::OutOfBounds {
                    field,
                    bounds: text,
                    value,
                });
            }
        }
        // At most four decimal places in the rules code's percent (six as a
        // fraction), four in the leverage: what the website can express.
        for (field, value, places) in [
            ("max_leverage", self.max_leverage, 4),
            ("max_loss_at_stop", self.max_loss_at_stop, 6),
            ("default_stop_distance", self.default_stop_distance, 6),
            ("min_liquidation_distance", self.min_liquidation_distance, 6),
            ("max_position_of_account", self.max_position_of_account, 6),
            ("max_open_risk", self.max_open_risk, 6),
            ("daily_loss_stop", self.daily_loss_stop, 6),
            ("drawdown_halt", self.drawdown_halt, 6),
        ] {
            if value.normalize().scale() > places {
                return Err(PolicyError::OutOfBounds {
                    field,
                    bounds: "at most four decimal places in percent",
                    value,
                });
            }
        }
        // The liquidation lies beyond the attached stop: a stop further
        // away than the minimum liquidation distance could never fire first.
        if self.min_liquidation_distance <= self.default_stop_distance {
            return Err(PolicyError::OutOfBounds {
                field: "min_liquidation_distance",
                bounds: "above default_stop_distance",
                value: self.min_liquidation_distance,
            });
        }
        if self.max_position_of_account > self.max_leverage {
            return Err(PolicyError::OutOfBounds {
                field: "max_position_of_account",
                bounds: "at most max_leverage",
                value: self.max_position_of_account,
            });
        }
        if let Markets::Only(coins) = &self.markets {
            if coins.is_empty() {
                return Err(PolicyError::NoMarkets);
            }
            if coins.len() > MAX_MARKETS {
                return Err(PolicyError::TooManyMarkets);
            }
            if let Some(bad) = coins.iter().find(|coin| {
                !(coin.as_str() == ALL_MAIN_MARKETS || is_dex_wildcard(coin) || is_coin_name(coin))
            }) {
                return Err(PolicyError::BadMarket(bad.clone()));
            }
            if let Some(covered) = coins.iter().find(|coin| match dex_of(coin) {
                None => coin.as_str() != ALL_MAIN_MARKETS && coins.contains(ALL_MAIN_MARKETS),
                Some(dex) => !is_dex_wildcard(coin) && coins.contains(&format!("{dex}:*")),
            }) {
                return Err(PolicyError::CoveredMarket(covered.clone()));
            }
            if self.markets.hip3_dexes().len() > MAX_HIP3_DEXES {
                return Err(PolicyError::TooManyDexes);
            }
        }
        // The engine's own checks: open risk at least one trade's, the
        // equity cap within the sleeve.
        self.risk_limits().validate()?;
        Ok(())
    }

    /// Guard's default preset (the constants in [`guard_defaults`]).
    pub fn guard_defaults() -> Self {
        use guard_defaults as d;
        Self {
            max_leverage: d::MAX_LEVERAGE,
            max_loss_at_stop: d::MAX_LOSS_AT_STOP,
            stop: d::STOP,
            default_stop_distance: d::DEFAULT_STOP_DISTANCE,
            min_liquidation_distance: d::MIN_LIQUIDATION_DISTANCE,
            max_position_of_account: d::MAX_POSITION_OF_ACCOUNT,
            max_open_risk: d::MAX_OPEN_RISK,
            daily_loss_stop: d::DAILY_LOSS_STOP,
            drawdown_halt: d::DRAWDOWN_HALT,
            markets: Markets::All,
            entry_price_bound: d::ENTRY_PRICE_BOUND,
            fee_bps: d::FEE_BPS,
            slippage_bps: d::SLIPPAGE_BPS,
            stop_slippage: d::STOP_SLIPPAGE,
            exit_slippage: d::EXIT_SLIPPAGE,
            max_trading_equity_usd: None,
        }
    }

    /// The loosest policy mainnet accepts: the engine's five rules are
    /// Zunder's default risk frame, `RiskLimits::default()` ("Mainnet code
    /// path": the limits may not exceed the default frame), and Guard's own
    /// rules and cost assumptions are pinned in this file. Independent of
    /// [`Policy::guard_defaults`].
    pub fn mainnet_ceiling() -> Self {
        use mainnet_ceiling as c;
        let frame = RiskLimits::default();
        Self {
            max_leverage: frame.max_leverage,
            max_loss_at_stop: frame.risk_per_trade,
            stop: StopPolicy::Attach,
            default_stop_distance: c::DEFAULT_STOP_DISTANCE,
            min_liquidation_distance: c::MIN_LIQUIDATION_DISTANCE,
            max_position_of_account: c::MAX_POSITION_OF_ACCOUNT,
            max_open_risk: frame.max_open_risk,
            daily_loss_stop: frame.daily_loss_stop,
            drawdown_halt: frame.drawdown_stop,
            markets: Markets::All,
            entry_price_bound: c::ENTRY_PRICE_BOUND,
            fee_bps: c::FEE_BPS,
            slippage_bps: c::SLIPPAGE_BPS,
            stop_slippage: c::STOP_SLIPPAGE,
            exit_slippage: c::EXIT_SLIPPAGE,
            max_trading_equity_usd: None,
        }
    }

    /// Refuse, on mainnet, a policy looser than [`Policy::mainnet_ceiling`]
    /// in any rule that bounds a loss: Zunder's default risk frame for the
    /// engine's five ("Mainnet code path": the limits may not exceed the
    /// default frame), and Guard's own rules and cost assumptions no looser
    /// than pinned. Names the first field that is. Not tied to Guard's
    /// default preset, so loosening that never loosens mainnet.
    pub fn within_mainnet_ceiling(&self) -> Result<(), &'static str> {
        let defaults = Policy::mainnet_ceiling();
        // (field, at most the default, at least the default)
        let checks: [(&'static str, bool); 14] = [
            ("max_leverage", self.max_leverage <= defaults.max_leverage),
            (
                "max_loss_at_stop",
                self.max_loss_at_stop <= defaults.max_loss_at_stop,
            ),
            (
                "max_open_risk",
                self.max_open_risk <= defaults.max_open_risk,
            ),
            (
                "daily_loss_stop",
                self.daily_loss_stop <= defaults.daily_loss_stop,
            ),
            (
                "drawdown_halt",
                self.drawdown_halt <= defaults.drawdown_halt,
            ),
            (
                "max_position_of_account",
                self.max_position_of_account <= defaults.max_position_of_account,
            ),
            (
                "min_liquidation_distance",
                self.min_liquidation_distance >= defaults.min_liquidation_distance,
            ),
            (
                "entry_price_bound",
                self.entry_price_bound <= defaults.entry_price_bound,
            ),
            ("fee_bps", self.fee_bps >= defaults.fee_bps),
            ("slippage_bps", self.slippage_bps >= defaults.slippage_bps),
            (
                "stop_slippage",
                self.stop_slippage >= defaults.stop_slippage,
            ),
            (
                "exit_slippage",
                self.exit_slippage >= defaults.exit_slippage,
            ),
            // The distance of the stops Guard attaches and places for an
            // unprotected position: a wider one risks more than sized.
            (
                "default_stop_distance",
                self.default_stop_distance <= defaults.default_stop_distance,
            ),
            // HIP-3 markets are paper and testnet only until it is decided
            // otherwise ("Guard phase 2a: HIP-3 markets").
            (
                "markets",
                match &self.markets {
                    Markets::All => true,
                    Markets::Only(entries) => entries.iter().all(|entry| dex_of(entry).is_none()),
                },
            ),
        ];
        match checks.iter().find(|(_, ok)| !ok) {
            Some((field, _)) => Err(field),
            None => Ok(()),
        }
    }

    /// The five rules the risk engine enforces, as its limits.
    pub fn risk_limits(&self) -> RiskLimits {
        RiskLimits {
            risk_per_trade: self.max_loss_at_stop,
            max_open_risk: self.max_open_risk,
            max_leverage: self.max_leverage,
            daily_loss_stop: self.daily_loss_stop,
            drawdown_stop: self.drawdown_halt,
            max_trading_equity_usd: self.max_trading_equity_usd,
        }
    }

    /// Expected cost of getting in and out, per unit at `price`: fee and
    /// slippage on both sides.
    pub fn round_trip_cost(&self, price: Decimal) -> Option<Decimal> {
        self.round_trip_cost_scaled(price, Decimal::ONE)
    }

    /// [`Policy::round_trip_cost`] with the fee `fee_scale` times
    /// `fee_bps`: a HIP-3 market's taker fee (`AssetInfo::fee_scale`).
    pub fn round_trip_cost_scaled(&self, price: Decimal, fee_scale: Decimal) -> Option<Decimal> {
        let per_side = self
            .fee_bps
            .checked_mul(fee_scale)?
            .checked_add(self.slippage_bps)?;
        price
            .checked_mul(per_side)?
            .checked_mul(Decimal::TWO)?
            .checked_div(dec!(10000))
    }
}

/// A market name as the rules schema allows it: 1 to 32 characters,
/// letters, digits and `: / @ . _ -`, starting with a letter, a digit or
/// `@` (`BTC`, `kPEPE`, `xyz:XYZ100`, `PURR/USDC`, `@107`). Guard trades
/// perps (the main dex's, and those of the HIP-3 dexes named); other names
/// are allowed and simply never match.
fn is_coin_name(coin: &str) -> bool {
    let bytes = coin.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'@')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b":/@._-".contains(b))
}

/// `dex:*`, every market of a HIP-3 dex: the dex's name 1 to 30 letters
/// and digits, 32 characters at most in all.
pub fn is_dex_wildcard(entry: &str) -> bool {
    entry.strip_suffix(":*").is_some_and(|dex| {
        (1..=30).contains(&dex.len()) && dex.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_guards_recorded_preset() {
        // Guard's preset: 5x, 2% at the stop, attach a stop 2% away, liquidation at
        // least 10% away, 200% per position, 6% open risk, 6% daily, 25%
        // drawdown, every market; 4.5 bp fee and 1 bp slippage per side.
        let policy = Policy::default();
        assert_eq!(policy, Policy::guard_defaults());
        assert_eq!(policy.entry_price_bound, dec!(0.005));
        assert_eq!(policy.fee_bps, dec!(4.5));
        assert_eq!(policy.slippage_bps, dec!(1));
        assert_eq!(policy.stop_slippage, dec!(0.10));
        assert_eq!(policy.exit_slippage, dec!(0.05));
        // Today the preset sits exactly at the mainnet ceiling.
        assert_eq!(policy.within_mainnet_ceiling(), Ok(()));
        assert_eq!(policy.max_leverage, dec!(5));
        assert_eq!(policy.max_loss_at_stop, dec!(0.02));
        assert_eq!(policy.stop, StopPolicy::Attach);
        assert_eq!(policy.default_stop_distance, dec!(0.02));
        assert_eq!(policy.min_liquidation_distance, dec!(0.10));
        assert_eq!(policy.max_position_of_account, dec!(2));
        assert_eq!(policy.max_open_risk, dec!(0.06));
        assert_eq!(policy.daily_loss_stop, dec!(0.06));
        assert_eq!(policy.drawdown_halt, dec!(0.25));
        assert_eq!(policy.markets, Markets::All);
        assert_eq!(policy.max_trading_equity_usd, None);
        assert_eq!(policy.validate(), Ok(()));
    }

    #[test]
    fn the_bots_frame_is_pinned_and_guard_does_not_read_it() {
        // Shared engine defaults: 2% per trade, 6% open, 5x, 6%
        // daily, 25% drawdown. Guard's preset must not be built from it, so
        // that a change of Guard's defaults never moves the bot's limits.
        let frame = RiskLimits::default();
        assert_eq!(frame.risk_per_trade, dec!(0.02));
        assert_eq!(frame.max_open_risk, dec!(0.06));
        assert_eq!(frame.max_leverage, dec!(5));
        assert_eq!(frame.daily_loss_stop, dec!(0.06));
        assert_eq!(frame.drawdown_stop, dec!(0.25));
        assert_eq!(frame.max_trading_equity_usd, None);
        // The mainnet ceiling's engine part is the bot's frame, exactly.
        assert_eq!(Policy::mainnet_ceiling().risk_limits(), frame);
        // Guard's preset is its own constants: neither `guard_defaults()`
        // nor the `guard_defaults` module names `RiskLimits`.
        let source = include_str!("policy.rs");
        let body_of = |head: &str, tail: &str| -> String {
            let start = source.find(head).expect("defined");
            let rest = &source[start..];
            rest[..rest.find(tail).expect("ends")].to_owned()
        };
        // No indirection that could lead back to the bot's frame or the
        // mainnet ceiling (which reads it).
        let forbidden = [
            "RiskLimits",
            "mainnet_ceiling",
            "Default::default",
            "..",
            "frame",
        ];
        let module = body_of("pub mod guard_defaults {", "\n}\n");
        let preset = body_of("pub fn guard_defaults() -> Self {", "\n    }\n");
        let default = body_of("impl Default for Policy {", "\n}\n");
        for body in [&module, &preset, &default] {
            for word in forbidden {
                assert!(!body.contains(word), "`{word}` in:\n{body}");
            }
        }
        // `Policy::default()` is the preset, and every field of the preset
        // is one of the module's constants (or all markets, no equity cap).
        assert!(default.contains("Self::guard_defaults()"), "{default}");
        let fields: Vec<&str> = preset
            .lines()
            .filter(|l| l.trim_end().ends_with(','))
            .collect();
        assert_eq!(fields.len(), 16, "{preset}");
        for field in fields {
            assert!(
                field.contains(": d::")
                    || field.contains("markets: Markets::All")
                    || field.contains("max_trading_equity_usd: None"),
                "{field}"
            );
        }
    }

    #[test]
    fn the_mainnet_ceiling_is_pinned_value_by_value() {
        // Changing the ceiling is its own decision ("Mainnet code path"):
        // every value is pinned here by hand, not by comparison with Guard's
        // preset. Engine part: the bot's frame (above). Guard's own rules:
        // stop 2% away, liquidation at least 10% away, at most 200% per
        // position, entries at most 0.5% beyond the mid, 4.5 bp fee and 1 bp
        // slippage per side, stops filling up to 10% and closes up to 5%
        // beyond the price.
        let c = Policy::mainnet_ceiling();
        assert_eq!(c.risk_limits(), RiskLimits::default());
        assert_eq!(c.default_stop_distance, dec!(0.02));
        assert_eq!(c.min_liquidation_distance, dec!(0.10));
        assert_eq!(c.max_position_of_account, dec!(2));
        assert_eq!(c.entry_price_bound, dec!(0.005));
        assert_eq!(c.fee_bps, dec!(4.5));
        assert_eq!(c.slippage_bps, dec!(1));
        assert_eq!(c.stop_slippage, dec!(0.10));
        assert_eq!(c.exit_slippage, dec!(0.05));
        assert_eq!(c.max_trading_equity_usd, None);
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn a_looser_guard_preset_does_not_loosen_mainnet() {
        // A Guard preset looser than the bot's frame is a valid policy
        // (inside the schema's bounds) but refused on mainnet: the ceiling
        // does not follow Guard's defaults.
        let looser = Policy {
            max_leverage: dec!(10),
            max_loss_at_stop: dec!(0.03),
            default_stop_distance: dec!(0.03),
            max_position_of_account: dec!(3),
            max_open_risk: dec!(0.10),
            daily_loss_stop: dec!(0.10),
            drawdown_halt: dec!(0.35),
            ..Policy::guard_defaults()
        };
        assert_eq!(looser.validate(), Ok(()));
        assert_eq!(looser.within_mainnet_ceiling(), Err("max_leverage"));
        let ceiling = Policy::mainnet_ceiling();
        assert_eq!(ceiling.within_mainnet_ceiling(), Ok(()));
        assert_eq!(ceiling.default_stop_distance, dec!(0.02));
        assert_eq!(ceiling.min_liquidation_distance, dec!(0.10));
        assert_eq!(ceiling.max_position_of_account, dec!(2));
    }

    #[test]
    fn every_bound_refuses_just_beyond_it() {
        type Set = fn(&mut Policy, Decimal);
        let cases: Vec<(Set, Decimal, Decimal)> = vec![
            // The rules schema v1's bounds (10x and the aggressive frame).
            (|p, v| p.max_leverage = v, dec!(0), dec!(10.0001)),
            (|p, v| p.max_loss_at_stop = v, dec!(0), dec!(0.050001)),
            (|p, v| p.default_stop_distance = v, dec!(0), dec!(0.500001)),
            (
                |p, v| p.min_liquidation_distance = v,
                dec!(0.009999),
                dec!(0.500001),
            ),
            (|p, v| p.max_position_of_account = v, dec!(0), dec!(5.01)),
            (|p, v| p.max_open_risk = v, dec!(0), dec!(0.200001)),
            (|p, v| p.daily_loss_stop = v, dec!(0), dec!(0.150001)),
            (|p, v| p.drawdown_halt = v, dec!(0), dec!(0.500001)),
            // More than four decimal places in percent.
            (
                |p, v| p.max_loss_at_stop = v,
                dec!(0.0100001),
                dec!(0.0200001),
            ),
            (|p, v| p.max_leverage = v, dec!(2.00001), dec!(3.00001)),
            (|p, v| p.entry_price_bound = v, dec!(0.0004), dec!(0.0501)),
            (|p, v| p.fee_bps = v, dec!(-0.1), dec!(50.1)),
            (|p, v| p.slippage_bps = v, dec!(-0.1), dec!(100.1)),
            (|p, v| p.stop_slippage = v, dec!(0.0499), dec!(0.2001)),
            (|p, v| p.exit_slippage = v, dec!(0.0099), dec!(0.1001)),
        ];
        for (set, low, high) in cases {
            for value in [low, high] {
                let mut policy = Policy::default();
                set(&mut policy, value);
                assert!(policy.validate().is_err(), "{value} passed: {policy:?}");
            }
        }
        // Fractional leverage is allowed (the venue's isolated leverage is
        // its whole part, at least 1x); a position cap above the leverage
        // cap, open risk below one trade are not.
        let mut policy = Policy {
            max_leverage: dec!(2.5),
            ..Policy::default()
        };
        assert_eq!(policy.validate(), Ok(()));
        policy.max_position_of_account = dec!(2.5);
        assert_eq!(policy.validate(), Ok(()));
        policy.max_position_of_account = dec!(2.6);
        assert!(policy.validate().is_err());
        let policy = Policy {
            max_open_risk: dec!(0.01),
            ..Policy::default()
        };
        assert!(matches!(policy.validate(), Err(PolicyError::Risk(_))));
        let policy = Policy {
            max_trading_equity_usd: Some(dec!(2500.01)),
            ..Policy::default()
        };
        assert!(matches!(policy.validate(), Err(PolicyError::Risk(_))));
    }

    #[test]
    fn the_liquidation_lies_beyond_the_default_stop() {
        let policy = Policy {
            default_stop_distance: dec!(0.10),
            ..Policy::default()
        };
        assert!(matches!(
            policy.validate(),
            Err(PolicyError::OutOfBounds {
                field: "min_liquidation_distance",
                ..
            })
        ));
        let policy = Policy {
            default_stop_distance: dec!(0.0999),
            ..Policy::default()
        };
        assert_eq!(policy.validate(), Ok(()));
    }

    #[test]
    fn within_mainnet_ceiling_refuses_anything_looser() {
        assert_eq!(Policy::default().within_mainnet_ceiling(), Ok(()));
        let tighter = Policy {
            max_leverage: dec!(3),
            max_loss_at_stop: dec!(0.01),
            min_liquidation_distance: dec!(0.2),
            stop_slippage: dec!(0.15),
            ..Policy::default()
        };
        assert_eq!(tighter.within_mainnet_ceiling(), Ok(()));
        let cases: Vec<(Policy, &str)> = vec![
            (
                Policy {
                    max_leverage: dec!(6),
                    ..Policy::default()
                },
                "max_leverage",
            ),
            (
                Policy {
                    max_loss_at_stop: dec!(0.021),
                    ..Policy::default()
                },
                "max_loss_at_stop",
            ),
            (
                Policy {
                    max_open_risk: dec!(0.07),
                    ..Policy::default()
                },
                "max_open_risk",
            ),
            (
                Policy {
                    daily_loss_stop: dec!(0.07),
                    ..Policy::default()
                },
                "daily_loss_stop",
            ),
            (
                Policy {
                    drawdown_halt: dec!(0.3),
                    ..Policy::default()
                },
                "drawdown_halt",
            ),
            (
                Policy {
                    max_position_of_account: dec!(2.5),
                    ..Policy::default()
                },
                "max_position_of_account",
            ),
            (
                Policy {
                    min_liquidation_distance: dec!(0.05),
                    ..Policy::default()
                },
                "min_liquidation_distance",
            ),
            (
                Policy {
                    entry_price_bound: dec!(0.01),
                    ..Policy::default()
                },
                "entry_price_bound",
            ),
            (
                Policy {
                    fee_bps: dec!(1),
                    ..Policy::default()
                },
                "fee_bps",
            ),
            (
                Policy {
                    slippage_bps: dec!(0),
                    ..Policy::default()
                },
                "slippage_bps",
            ),
            (
                Policy {
                    stop_slippage: dec!(0.05),
                    ..Policy::default()
                },
                "stop_slippage",
            ),
            (
                Policy {
                    default_stop_distance: dec!(0.03),
                    ..Policy::default()
                },
                "default_stop_distance",
            ),
            // A narrower exit band may leave a flatten unfilled in a crash.
            (
                Policy {
                    exit_slippage: dec!(0.01),
                    ..Policy::default()
                },
                "exit_slippage",
            ),
        ];
        for (policy, field) in cases {
            assert_eq!(policy.within_mainnet_ceiling(), Err(field));
        }
    }

    #[test]
    fn markets_read_as_all_or_a_list() {
        let all: Policy = toml_like(r#"{"markets": "all"}"#);
        assert_eq!(all.markets, Markets::All);
        let some: Policy = toml_like(r#"{"markets": ["BTC", "ETH"]}"#);
        assert!(some.markets.allows("BTC"));
        assert!(!some.markets.allows("SOL"));
        assert!(serde_json::from_str::<Policy>(r#"{"markets": "some"}"#).is_err());
        assert!(serde_json::from_str::<Policy>(r#"{"unknown": 1}"#).is_err());
        let empty = Policy {
            markets: Markets::Only(BTreeSet::new()),
            ..Policy::default()
        };
        assert_eq!(empty.validate(), Err(PolicyError::NoMarkets));
        let bad = Policy {
            markets: Markets::Only(["BTC USDC".to_owned()].into()),
            ..Policy::default()
        };
        assert!(matches!(bad.validate(), Err(PolicyError::BadMarket(_))));
    }

    #[test]
    fn hip3_dexes_are_opt_in_by_name() {
        // The default: the main dex only, HIP-3 never.
        assert!(Markets::All.allows("BTC"));
        assert!(!Markets::All.allows("xyz:GOLD"));
        assert!(Markets::All.hip3_dexes().is_empty());
        // Every market of the main dex and of xyz.
        let both: Policy = toml_like(r#"{"markets": ["*", "xyz:*"]}"#);
        assert!(both.markets.allows("BTC"));
        assert!(both.markets.allows("xyz:GOLD"));
        assert!(!both.markets.allows("flx:GOLD"));
        assert_eq!(both.markets.hip3_dexes(), ["xyz".to_owned()].into());
        assert_eq!(both.validate(), Ok(()));
        // One coin of a dex: that dex is read, its other coins not traded,
        // nor the main dex's.
        let gold: Policy = toml_like(r#"{"markets": ["xyz:GOLD"]}"#);
        assert!(gold.markets.allows("xyz:GOLD"));
        assert!(!gold.markets.allows("xyz:TSLA"));
        assert!(!gold.markets.allows("BTC"));
        assert_eq!(gold.markets.hip3_dexes(), ["xyz".to_owned()].into());
        // `["*"]` written as a list is "all".
        let star: Policy = toml_like(r#"{"markets": ["*"]}"#);
        assert_eq!(star.markets, Markets::All);
        // Refused: a market beside the entry that covers it, more than two
        // HIP-3 dexes, a wildcard that is not a dex's.
        for (list, error) in [
            (r#"["*", "BTC"]"#, "covered"),
            (r#"["xyz:*", "xyz:GOLD"]"#, "covered"),
            (r#"["xyz:A", "flx:B", "km:C"]"#, "dexes"),
            (r#"["BTC*"]"#, "bad"),
            (r#"["*:*"]"#, "bad"),
            (r#"[":*"]"#, "bad"),
            (r#"["x/y:*"]"#, "bad"),
        ] {
            let policy: Policy = toml_like(&format!(r#"{{"markets": {list}}}"#));
            let result = policy.validate();
            let matched = match error {
                "covered" => matches!(result, Err(PolicyError::CoveredMarket(_))),
                "dexes" => result == Err(PolicyError::TooManyDexes),
                _ => matches!(result, Err(PolicyError::BadMarket(_))),
            };
            assert!(matched, "{list}: {result:?}");
        }
        // Two dexes are the most.
        let two: Policy = toml_like(r#"{"markets": ["xyz:*", "flx:GOLD", "ETH"]}"#);
        assert_eq!(two.validate(), Ok(()));
        // HIP-3 stays off mainnet ("Guard phase 2a: HIP-3 markets").
        assert_eq!(both.within_mainnet_ceiling(), Err("markets"));
        assert_eq!(gold.within_mainnet_ceiling(), Err("markets"));
        let main_only: Policy = toml_like(r#"{"markets": ["BTC", "ETH"]}"#);
        assert_eq!(main_only.within_mainnet_ceiling(), Ok(()));
    }

    fn toml_like(json: &str) -> Policy {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn the_round_trip_cost_counts_fee_and_slippage_twice() {
        // (4.5 + 1) bp per side, both sides, at 3000: 3000 * 11 / 10000 = 3.3.
        assert_eq!(
            Policy::default().round_trip_cost(dec!(3000)),
            Some(dec!(3.3))
        );
    }
}
