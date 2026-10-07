// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Guard rules schema v1: the `zr1_…` string that the website, the docs and the CLI share.
//!
//! A rules string is `zr1_` followed by the base64url encoding (no padding) of a JSON object:
//!
//! ```json
//! {"v":1,"maxLeverage":5,"maxLossAtStopPct":2,"stopPolicy":"attach","defaultStopDistancePct":2,
//!  "minLiqDistancePct":10,"maxPositionPct":200,"maxOpenRiskPct":6,"dailyLossStopPct":6,
//!  "drawdownHaltPct":25,"markets":["*"]}
//! ```
//!
//! Values named `…Pct` are percent (2 means 2%), unlike the fractions elsewhere in Zunder;
//! [`Rules::risk_limits`] converts them. Missing fields take the defaults, unknown fields are
//! refused, and every value is bounds-checked. `markets: ["*"]` means every market of
//! Hyperliquid's main dex; a HIP-3 dex's markets are allowed only by name: `dex:*` for all of
//! them, `dex:COIN` for one, and `*` may stand beside such entries (`["*", "xyz:*"]`). These
//! two forms were refused by earlier v1 decoders, so a code written before decodes exactly as
//! it did, and a code that uses them is refused by an older decoder rather than misread.
//!
//! Defaults are the reconciled schema v1 (6 Oct 2026), equal to the Guard core's
//! `Policy::default()`. The bounds are the Guard core's (`zunder_guard_core::policy`, the
//! `…_BOUNDS` constants), read from there; the upper bounds of the `zunder-risk` fields never
//! exceed `RiskLimits::aggressive()`, so a rules string can never loosen what `zunder-risk`
//! allows. [`Rules::to_policy`] and [`Rules::from_policy`] map rules onto Guard's policy.
//!
//! The TypeScript twin is `../zr1.ts`; both pass the same `../vectors.json`, and
//! `../schema-v1.json` documents the same defaults and bounds (a test keeps them equal).
//! The full specification, including the order in which errors are reported, is in
//! `deploy/guard/README.md`, "Rules schema v1".

use std::fmt::Write as _;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rust_decimal::Decimal;
use serde_json::{Map, Value};
use thiserror::Error;
use zunder_risk::RiskLimits;

/// Every v1 rules string starts with this.
pub const PREFIX: &str = "zr1_";
/// Longest rules string accepted, prefix included.
pub const MAX_ENCODED_LEN: usize = 4096;
/// Numbers may have at most this many decimal places.
pub const MAX_DECIMALS: u32 = 4;
/// At most this many markets in the allowlist.
pub const MAX_MARKETS: usize = 32;
/// Longest market name (`xyz:XYZ100`, `PURR/USDC`, `@107` are all valid names).
pub const MAX_MARKET_LEN: usize = 32;
/// The market entry that allows every market of Hyperliquid's main dex (never a HIP-3 one).
pub const ALL_MARKETS: &str = "*";

/// What Guard does with an entry that arrives without a stop. Either way no entry is ever
/// without a stop: the risk engine sizes every entry from its stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopPolicy {
    /// Guard attaches a stop `defaultStopDistancePct` away and sizes the entry from it. The
    /// default.
    Attach,
    /// Guard refuses the entry with a readable reason.
    Refuse,
}

impl StopPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            StopPolicy::Attach => "attach",
            StopPolicy::Refuse => "refuse",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "attach" => Some(StopPolicy::Attach),
            "refuse" => Some(StopPolicy::Refuse),
            _ => None,
        }
    }
}

/// The fields of schema v1 in their canonical order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    MaxLeverage,
    MaxLossAtStopPct,
    StopPolicy,
    DefaultStopDistancePct,
    MinLiqDistancePct,
    MaxPositionPct,
    MaxOpenRiskPct,
    DailyLossStopPct,
    DrawdownHaltPct,
    Markets,
}

impl Field {
    pub const ALL: [Field; 10] = [
        Field::MaxLeverage,
        Field::MaxLossAtStopPct,
        Field::StopPolicy,
        Field::DefaultStopDistancePct,
        Field::MinLiqDistancePct,
        Field::MaxPositionPct,
        Field::MaxOpenRiskPct,
        Field::DailyLossStopPct,
        Field::DrawdownHaltPct,
        Field::Markets,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Field::MaxLeverage => "maxLeverage",
            Field::MaxLossAtStopPct => "maxLossAtStopPct",
            Field::StopPolicy => "stopPolicy",
            Field::DefaultStopDistancePct => "defaultStopDistancePct",
            Field::MinLiqDistancePct => "minLiqDistancePct",
            Field::MaxPositionPct => "maxPositionPct",
            Field::MaxOpenRiskPct => "maxOpenRiskPct",
            Field::DailyLossStopPct => "dailyLossStopPct",
            Field::DrawdownHaltPct => "drawdownHaltPct",
            Field::Markets => "markets",
        }
    }

    pub fn from_key(key: &str) -> Option<Field> {
        Field::ALL.into_iter().find(|f| f.key() == key)
    }
}

/// Default and bounds of one numeric field. A value must be above `min` (or equal to it when
/// `min_inclusive`) and at most `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberBounds {
    pub field: Field,
    pub default: Decimal,
    pub min: Decimal,
    pub min_inclusive: bool,
    pub max: Decimal,
}

fn pct(fraction: Decimal) -> Decimal {
    (fraction * Decimal::ONE_HUNDRED).normalize()
}

/// The numeric fields in canonical order: the Guard core's defaults (`Policy::default()`) and
/// bounds (`zunder_guard_core::policy::…_BOUNDS`), in percent where the field is.
pub fn number_bounds() -> [NumberBounds; 8] {
    use zunder_guard_core::policy as core;
    let d = core::Policy::default();
    let percent = |field, default: Decimal, bound: core::RuleBound| NumberBounds {
        field,
        default: pct(default),
        min: pct(bound.min),
        min_inclusive: bound.min_inclusive,
        max: pct(bound.max),
    };
    let b = core::MAX_LEVERAGE_BOUNDS;
    [
        NumberBounds {
            field: Field::MaxLeverage,
            default: d.max_leverage.normalize(),
            min: b.min,
            min_inclusive: b.min_inclusive,
            max: b.max,
        },
        percent(
            Field::MaxLossAtStopPct,
            d.max_loss_at_stop,
            core::MAX_LOSS_AT_STOP_BOUNDS,
        ),
        percent(
            Field::DefaultStopDistancePct,
            d.default_stop_distance,
            core::DEFAULT_STOP_DISTANCE_BOUNDS,
        ),
        percent(
            Field::MinLiqDistancePct,
            d.min_liquidation_distance,
            core::MIN_LIQUIDATION_DISTANCE_BOUNDS,
        ),
        // One position can never be larger than the leverage cap allows for all of them.
        percent(
            Field::MaxPositionPct,
            d.max_position_of_account,
            core::MAX_POSITION_OF_ACCOUNT_BOUNDS,
        ),
        percent(
            Field::MaxOpenRiskPct,
            d.max_open_risk,
            core::MAX_OPEN_RISK_BOUNDS,
        ),
        percent(
            Field::DailyLossStopPct,
            d.daily_loss_stop,
            core::DAILY_LOSS_STOP_BOUNDS,
        ),
        percent(
            Field::DrawdownHaltPct,
            d.drawdown_halt,
            core::DRAWDOWN_HALT_BOUNDS,
        ),
    ]
}

/// The bounds of one numeric field, `None` for the others.
pub fn bounds_of(field: Field) -> Option<NumberBounds> {
    number_bounds().into_iter().find(|b| b.field == field)
}

/// Why a rules string or a set of rules was refused. [`RulesError::code`] is the stable code
/// shared with the TypeScript twin.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RulesError {
    #[error("the rules string is longer than {MAX_ENCODED_LEN} characters")]
    TooLong,
    #[error("a rules string starts with {PREFIX}")]
    Prefix,
    #[error("the rules string is not valid base64url (no padding)")]
    Base64,
    #[error("the rules are not valid JSON")]
    Json,
    #[error("the rules must be a JSON object")]
    NotObject,
    #[error("unknown field {0}")]
    UnknownField(String),
    #[error("v must be 1 (this build reads rules schema v1 only)")]
    Version,
    #[error("{0} has the wrong type")]
    Type(&'static str),
    #[error("{field} must be {} {min} and at most {max}, got {value}", if *.min_inclusive { "at least" } else { "above" })]
    OutOfRange {
        field: &'static str,
        value: String,
        min: Decimal,
        min_inclusive: bool,
        max: Decimal,
    },
    #[error("{0} may have at most {MAX_DECIMALS} decimal places")]
    Precision(&'static str),
    #[error("stopPolicy must be \"attach\" or \"refuse\"")]
    StopPolicy,
    #[error("markets: {0}")]
    Markets(&'static str),
    #[error("maxOpenRiskPct must not be below maxLossAtStopPct")]
    OpenRiskBelowTradeRisk,
    #[error("maxPositionPct must not exceed maxLeverage × 100")]
    PositionAboveLeverage,
    #[error(
        "minLiqDistancePct must be above defaultStopDistancePct (the liquidation lies beyond the stop)"
    )]
    LiquidationNotBeyondStop,
}

impl RulesError {
    /// The stable error code, the same in `zr1.ts` and `vectors.json`.
    pub fn code(&self) -> &'static str {
        match self {
            RulesError::TooLong => "too_long",
            RulesError::Prefix => "prefix",
            RulesError::Base64 => "base64",
            RulesError::Json => "json",
            RulesError::NotObject => "not_object",
            RulesError::UnknownField(_) => "unknown_field",
            RulesError::Version => "version",
            RulesError::Type(_) => "type",
            RulesError::OutOfRange { .. } => "out_of_range",
            RulesError::Precision(_) => "precision",
            RulesError::StopPolicy => "stop_policy",
            RulesError::Markets(_) => "markets",
            RulesError::OpenRiskBelowTradeRisk => "open_risk_below_trade_risk",
            RulesError::PositionAboveLeverage => "position_above_leverage",
            RulesError::LiquidationNotBeyondStop => "liq_not_beyond_stop",
        }
    }

    /// The field the error is about, where there is exactly one.
    pub fn field(&self) -> Option<&'static str> {
        match self {
            RulesError::Type(f) | RulesError::Precision(f) => Some(f),
            RulesError::OutOfRange { field, .. } => Some(field),
            RulesError::StopPolicy => Some("stopPolicy"),
            RulesError::Markets(_) => Some("markets"),
            _ => None,
        }
    }
}

/// A user's Guard rules, schema v1. Percent values are percent (2 means 2%).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    pub max_leverage: Decimal,
    pub max_loss_at_stop_pct: Decimal,
    pub stop_policy: StopPolicy,
    pub default_stop_distance_pct: Decimal,
    pub min_liq_distance_pct: Decimal,
    pub max_position_pct: Decimal,
    pub max_open_risk_pct: Decimal,
    pub daily_loss_stop_pct: Decimal,
    pub drawdown_halt_pct: Decimal,
    /// Market names, or `["*"]` for every market.
    pub markets: Vec<String>,
}

impl Default for Rules {
    fn default() -> Self {
        let mut rules = Rules {
            max_leverage: Decimal::ZERO,
            max_loss_at_stop_pct: Decimal::ZERO,
            stop_policy: StopPolicy::Attach,
            default_stop_distance_pct: Decimal::ZERO,
            min_liq_distance_pct: Decimal::ZERO,
            max_position_pct: Decimal::ZERO,
            max_open_risk_pct: Decimal::ZERO,
            daily_loss_stop_pct: Decimal::ZERO,
            drawdown_halt_pct: Decimal::ZERO,
            markets: vec![ALL_MARKETS.to_string()],
        };
        for b in number_bounds() {
            rules.set_number(b.field, b.default);
        }
        rules
    }
}

impl Rules {
    /// The numeric value of `field`, `None` for the non-numeric fields.
    pub fn number(&self, field: Field) -> Option<Decimal> {
        Some(match field {
            Field::MaxLeverage => self.max_leverage,
            Field::MaxLossAtStopPct => self.max_loss_at_stop_pct,
            Field::DefaultStopDistancePct => self.default_stop_distance_pct,
            Field::MinLiqDistancePct => self.min_liq_distance_pct,
            Field::MaxPositionPct => self.max_position_pct,
            Field::MaxOpenRiskPct => self.max_open_risk_pct,
            Field::DailyLossStopPct => self.daily_loss_stop_pct,
            Field::DrawdownHaltPct => self.drawdown_halt_pct,
            Field::StopPolicy | Field::Markets => return None,
        })
    }

    /// Sets a numeric field (normalised: `2.50` becomes `2.5`); does nothing for the others.
    /// Call [`Rules::validate`] afterwards.
    pub fn set_number(&mut self, field: Field, value: Decimal) {
        let value = value.normalize();
        match field {
            Field::MaxLeverage => self.max_leverage = value,
            Field::MaxLossAtStopPct => self.max_loss_at_stop_pct = value,
            Field::DefaultStopDistancePct => self.default_stop_distance_pct = value,
            Field::MinLiqDistancePct => self.min_liq_distance_pct = value,
            Field::MaxPositionPct => self.max_position_pct = value,
            Field::MaxOpenRiskPct => self.max_open_risk_pct = value,
            Field::DailyLossStopPct => self.daily_loss_stop_pct = value,
            Field::DrawdownHaltPct => self.drawdown_halt_pct = value,
            Field::StopPolicy | Field::Markets => {}
        }
    }

    /// Whether `market` may be traded under these rules: `*` is every market of Hyperliquid's
    /// main dex, `dex:*` every market of that HIP-3 dex, any other entry that market alone. A
    /// HIP-3 market (`dex:COIN`) is never covered by `*`.
    pub fn allows_market(&self, market: &str) -> bool {
        self.markets.iter().any(|m| {
            m == market
                || (m == ALL_MARKETS && !market.contains(':'))
                || m.strip_suffix('*')
                    .is_some_and(|prefix| prefix.ends_with(':') && market.starts_with(prefix))
        })
    }

    /// Refuses out-of-bounds values. Order: the numeric fields in canonical order, then
    /// `markets`, then the two checks across fields.
    pub fn validate(&self) -> Result<(), RulesError> {
        for b in number_bounds() {
            let value = self.number(b.field).unwrap_or(Decimal::ZERO);
            let below = if b.min_inclusive {
                value < b.min
            } else {
                value <= b.min
            };
            if below || value > b.max {
                return Err(out_of_range(&b, value.normalize().to_string()));
            }
            if value.normalize().scale() > MAX_DECIMALS {
                return Err(RulesError::Precision(b.field.key()));
            }
        }
        check_markets(&self.markets)?;
        if self.max_open_risk_pct < self.max_loss_at_stop_pct {
            return Err(RulesError::OpenRiskBelowTradeRisk);
        }
        if self.max_position_pct > self.max_leverage * Decimal::ONE_HUNDRED {
            return Err(RulesError::PositionAboveLeverage);
        }
        if self.min_liq_distance_pct <= self.default_stop_distance_pct {
            return Err(RulesError::LiquidationNotBeyondStop);
        }
        Ok(())
    }

    /// The limits `zunder-risk` enforces, as fractions. No equity cap: that is set per
    /// deployment, not by a rules string.
    pub fn risk_limits(&self) -> RiskLimits {
        let frac = |p: Decimal| (p / Decimal::ONE_HUNDRED).normalize();
        RiskLimits {
            risk_per_trade: frac(self.max_loss_at_stop_pct),
            max_open_risk: frac(self.max_open_risk_pct),
            max_leverage: self.max_leverage.normalize(),
            daily_loss_stop: frac(self.daily_loss_stop_pct),
            drawdown_stop: frac(self.drawdown_halt_pct),
            max_trading_equity_usd: None,
        }
    }

    /// The canonical JSON: every field (the optional `defaultStopDistancePct` included), in
    /// schema order, numbers without trailing zeros.
    pub fn to_json(&self) -> String {
        let num = |d: Decimal| d.normalize().to_string();
        let mut s = String::from("{\"v\":1");
        // Writing to a String cannot fail.
        let _ = write!(
            s,
            ",\"maxLeverage\":{},\"maxLossAtStopPct\":{},\"stopPolicy\":\"{}\",\
             \"defaultStopDistancePct\":{},\"minLiqDistancePct\":{},\"maxPositionPct\":{},\
             \"maxOpenRiskPct\":{},\"dailyLossStopPct\":{},\"drawdownHaltPct\":{},\"markets\":[",
            num(self.max_leverage),
            num(self.max_loss_at_stop_pct),
            self.stop_policy.as_str(),
            num(self.default_stop_distance_pct),
            num(self.min_liq_distance_pct),
            num(self.max_position_pct),
            num(self.max_open_risk_pct),
            num(self.daily_loss_stop_pct),
            num(self.drawdown_halt_pct),
        );
        for (i, market) in self.markets.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&Value::String(market.clone()).to_string());
        }
        s.push_str("]}");
        s
    }

    /// Guard's policy with these rules, the other fields (costs, slippage, the equity cap)
    /// taken from `base`, validated by the policy itself.
    pub fn to_policy(
        &self,
        base: &zunder_guard_core::policy::Policy,
    ) -> Result<zunder_guard_core::policy::Policy, zunder_guard_core::policy::PolicyError> {
        use zunder_guard_core::policy::{Markets, Policy, StopPolicy as CoreStop};
        let frac = |p: Decimal| (p / Decimal::ONE_HUNDRED).normalize();
        let policy = Policy {
            max_leverage: self.max_leverage.normalize(),
            max_loss_at_stop: frac(self.max_loss_at_stop_pct),
            stop: match self.stop_policy {
                StopPolicy::Attach => CoreStop::Attach,
                StopPolicy::Refuse => CoreStop::Refuse,
            },
            default_stop_distance: frac(self.default_stop_distance_pct),
            min_liquidation_distance: frac(self.min_liq_distance_pct),
            max_position_of_account: frac(self.max_position_pct),
            max_open_risk: frac(self.max_open_risk_pct),
            daily_loss_stop: frac(self.daily_loss_stop_pct),
            drawdown_halt: frac(self.drawdown_halt_pct),
            // `["*"]` alone is every market of the main dex; with HIP-3 entries beside it, a
            // list Guard reads the same way.
            markets: Markets::from_list(self.markets.iter().cloned()),
            ..base.clone()
        };
        policy.validate()?;
        Ok(policy)
    }

    /// The rules of Guard's policy (its nine rules; the rest of the policy is not in a rules
    /// string).
    pub fn from_policy(policy: &zunder_guard_core::policy::Policy) -> Rules {
        use zunder_guard_core::policy::{Markets, StopPolicy as CoreStop};
        Rules {
            max_leverage: policy.max_leverage.normalize(),
            max_loss_at_stop_pct: pct(policy.max_loss_at_stop),
            stop_policy: match policy.stop {
                CoreStop::Attach => StopPolicy::Attach,
                CoreStop::Refuse => StopPolicy::Refuse,
            },
            default_stop_distance_pct: pct(policy.default_stop_distance),
            min_liq_distance_pct: pct(policy.min_liquidation_distance),
            max_position_pct: pct(policy.max_position_of_account),
            max_open_risk_pct: pct(policy.max_open_risk),
            daily_loss_stop_pct: pct(policy.daily_loss_stop),
            drawdown_halt_pct: pct(policy.drawdown_halt),
            markets: match &policy.markets {
                Markets::All => vec![ALL_MARKETS.to_owned()],
                Markets::Only(coins) => coins.iter().cloned().collect(),
            },
        }
    }

    /// The `zr1_…` string of a policy that validated. Every valid policy is valid rules (the
    /// bounds are the same); should one not be, the error says why.
    pub fn encode_policy(policy: &zunder_guard_core::policy::Policy) -> Result<String, RulesError> {
        Rules::from_policy(policy).encode()
    }

    /// The `zr1_…` string. Refuses rules that do not validate.
    pub fn encode(&self) -> Result<String, RulesError> {
        self.validate()?;
        Ok(format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(self.to_json().as_bytes())
        ))
    }

    /// Reads and validates a `zr1_…` string.
    pub fn decode(text: &str) -> Result<Rules, RulesError> {
        if text.len() > MAX_ENCODED_LEN {
            return Err(RulesError::TooLong);
        }
        let body = text.strip_prefix(PREFIX).ok_or(RulesError::Prefix)?;
        if !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(RulesError::Base64);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| RulesError::Base64)?;
        // Only the canonical encoding: no stray bits in the last character.
        if URL_SAFE_NO_PAD.encode(&bytes) != body {
            return Err(RulesError::Base64);
        }
        let json = std::str::from_utf8(&bytes).map_err(|_| RulesError::Json)?;
        let value: Value = serde_json::from_str(json).map_err(|_| RulesError::Json)?;
        let Value::Object(map) = value else {
            return Err(RulesError::NotObject);
        };
        Rules::from_object(&map)
    }

    fn from_object(map: &Map<String, Value>) -> Result<Rules, RulesError> {
        if let Some(key) = map
            .keys()
            .find(|k| k.as_str() != "v" && Field::from_key(k).is_none())
        {
            return Err(RulesError::UnknownField(key.clone()));
        }
        match map.get("v").and_then(Value::as_f64) {
            Some(1.0) => {}
            _ => return Err(RulesError::Version),
        }
        let mut rules = Rules::default();
        for field in Field::ALL {
            let Some(value) = map.get(field.key()) else {
                continue;
            };
            let wrong_type = RulesError::Type(field.key());
            match field {
                Field::StopPolicy => {
                    let text = value.as_str().ok_or(wrong_type)?;
                    rules.stop_policy = StopPolicy::parse(text).ok_or(RulesError::StopPolicy)?;
                }
                Field::Markets => {
                    let items = value.as_array().ok_or(wrong_type.clone())?;
                    rules.markets = items
                        .iter()
                        .map(|m| m.as_str().map(str::to_string).ok_or(wrong_type.clone()))
                        .collect::<Result<_, _>>()?;
                }
                _ => {
                    let x = match value {
                        Value::Number(n) => n.as_f64().ok_or(wrong_type)?,
                        _ => return Err(wrong_type),
                    };
                    let bounds = bounds_of(field).ok_or(RulesError::Type(field.key()))?;
                    rules.set_number(field, json_number(&bounds, x)?);
                }
            }
        }
        rules.validate()?;
        Ok(rules)
    }
}

fn out_of_range(b: &NumberBounds, value: String) -> RulesError {
    RulesError::OutOfRange {
        field: b.field.key(),
        value,
        min: b.min,
        min_inclusive: b.min_inclusive,
        max: b.max,
    }
}

/// A JSON number (an IEEE double, as in every browser) checked against its bounds, then for
/// at most four decimal places, then turned into a `Decimal`. Comparing as doubles keeps this
/// identical to the TypeScript twin; after both checks the value is an exact short decimal.
fn json_number(b: &NumberBounds, x: f64) -> Result<Decimal, RulesError> {
    let as_f64 = |d: Decimal| f64::from_str(&d.to_string()).unwrap_or(f64::NAN);
    let (min, max) = (as_f64(b.min), as_f64(b.max));
    let below = if b.min_inclusive { x < min } else { x <= min };
    if !x.is_finite() || below || x > max {
        return Err(out_of_range(b, format!("{x}")));
    }
    let scaled = (x * 10_000.0).round() / 10_000.0;
    #[allow(clippy::float_cmp)] // exact comparison is the point: the round trip must be exact
    if scaled != x {
        return Err(RulesError::Precision(b.field.key()));
    }
    Decimal::from_str(&format!("{x}")).map_err(|_| RulesError::Precision(b.field.key()))
}

fn check_markets(markets: &[String]) -> Result<(), RulesError> {
    if markets.is_empty() {
        return Err(RulesError::Markets(
            "at least one market is required (\"*\" for all)",
        ));
    }
    if markets.len() > MAX_MARKETS {
        return Err(RulesError::Markets("at most 32 markets"));
    }
    // `*` is every market of the main dex: beside it only HIP-3 entries (`dex:…`) may stand.
    if markets.iter().any(|m| m == ALL_MARKETS)
        && markets.iter().any(|m| m != ALL_MARKETS && !m.contains(':'))
    {
        return Err(RulesError::Markets(
            "\"*\" (every main-dex market) stands alone among the main dex's markets",
        ));
    }
    for (i, market) in markets.iter().enumerate() {
        if market == ALL_MARKETS {
            if markets[..i].contains(market) {
                return Err(RulesError::Markets("a market is listed twice"));
            }
            continue;
        }
        if let Some(dex) = market.strip_suffix(":*") {
            // `dex:*`: every market of a HIP-3 dex.
            if dex.is_empty()
                || dex.len() > MAX_MARKET_LEN - 2
                || !dex.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                return Err(RulesError::Markets(
                    "dex:* names a HIP-3 dex by its letters and digits",
                ));
            }
            if markets[..i].contains(market) {
                return Err(RulesError::Markets("a market is listed twice"));
            }
            continue;
        }
        if let Some((dex, _)) = market.split_once(':')
            && markets.iter().any(|m| *m == format!("{dex}:*"))
        {
            return Err(RulesError::Markets(
                "a market of a dex listed as dex:* is listed again",
            ));
        }
        let bytes = market.as_bytes();
        let first_ok = bytes
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'@');
        let rest_ok = bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b":/@._-".contains(b));
        if !first_ok || !rest_ok || bytes.len() > MAX_MARKET_LEN {
            return Err(RulesError::Markets(
                "a market name is 1 to 32 characters: letters, digits and : / @ . _ -",
            ));
        }
        if markets[..i].contains(market) {
            return Err(RulesError::Markets("a market is listed twice"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rust_decimal::dec;

    use super::*;

    const VECTORS: &str = include_str!("../vectors.json");
    const SCHEMA: &str = include_str!("../schema-v1.json");

    fn b64(json: &str) -> String {
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    #[test]
    fn defaults_are_the_reconciled_schema_v1() {
        // Schema v1 as reconciled on 6 Oct 2026: 5x, 2% at the stop, attach a stop 2% away,
        // liquidation at least 10% away, positions up to 200%, 6% open risk, 6% daily loss,
        // 25% drawdown, every market. The risk-engine part is Guard core's preset
        // (`Policy::guard_defaults`), not read from the bot's `RiskLimits::default()`.
        let rules = Rules::default();
        assert_eq!(rules.max_leverage, dec!(5));
        assert_eq!(rules.max_loss_at_stop_pct, dec!(2));
        assert_eq!(rules.stop_policy, StopPolicy::Attach);
        assert_eq!(rules.default_stop_distance_pct, dec!(2));
        assert_eq!(rules.min_liq_distance_pct, dec!(10));
        assert_eq!(rules.max_position_pct, dec!(200));
        assert_eq!(rules.max_open_risk_pct, dec!(6));
        assert_eq!(rules.daily_loss_stop_pct, dec!(6));
        assert_eq!(rules.drawdown_halt_pct, dec!(25));
        assert_eq!(rules.markets, ["*"]);
        // Every market of the main dex; HIP-3 dexes only when named.
        assert!(rules.allows_market("BTC"));
        assert!(!rules.allows_market("xyz:XYZ100"));
        assert_eq!(rules.validate(), Ok(()));
        assert_eq!(
            rules.risk_limits(),
            zunder_guard_core::policy::Policy::guard_defaults().risk_limits()
        );
    }

    #[test]
    fn upper_bounds_never_exceed_the_aggressive_frame() {
        // RiskLimits::aggressive(): 5% per trade, 20% open, 10x, 15% daily, 50% drawdown
        // (recorded 5 Oct 2026). A position may use at most the 10x cap: 1000%.
        let max = |f| bounds_of(f).map(|b| b.max);
        assert_eq!(max(Field::MaxLeverage), Some(dec!(10)));
        assert_eq!(max(Field::MaxLossAtStopPct), Some(dec!(5)));
        assert_eq!(max(Field::MaxOpenRiskPct), Some(dec!(20)));
        assert_eq!(max(Field::DailyLossStopPct), Some(dec!(15)));
        assert_eq!(max(Field::DrawdownHaltPct), Some(dec!(50)));
        assert_eq!(max(Field::MaxPositionPct), Some(dec!(1000)));
        assert_eq!(max(Field::MinLiqDistancePct), Some(dec!(50)));
        assert_eq!(max(Field::DefaultStopDistancePct), Some(dec!(50)));
        let mut top = Rules::default();
        for b in number_bounds() {
            top.set_number(b.field, b.max);
        }
        // The stop distance stays below the liquidation distance.
        assert_eq!(top.validate(), Err(RulesError::LiquidationNotBeyondStop));
        top.set_number(Field::DefaultStopDistancePct, dec!(49.9999));
        assert_eq!(top.validate(), Ok(()));
        let limits = top.risk_limits();
        assert_eq!(limits.risk_per_trade, dec!(0.05));
        assert_eq!(limits.max_open_risk, dec!(0.2));
        assert_eq!(limits.max_leverage, dec!(10));
        assert_eq!(limits.daily_loss_stop, dec!(0.15));
        assert_eq!(limits.drawdown_stop, dec!(0.5));
        assert_eq!(limits.validate(), Ok(()));
    }

    #[test]
    fn every_field_one_step_beyond_its_bounds_is_refused() {
        for b in number_bounds() {
            let mut over = Rules::default();
            over.set_number(b.field, b.max + dec!(0.0001));
            assert_eq!(over.validate().map_err(|e| e.code()), Err("out_of_range"));
            let mut under = Rules::default();
            let low = if b.min_inclusive {
                b.min - dec!(0.0001)
            } else {
                b.min
            };
            under.set_number(b.field, low);
            assert_eq!(under.validate().map_err(|e| e.code()), Err("out_of_range"));
            let mut fine = Rules::default();
            fine.set_number(b.field, b.default + dec!(0.00001));
            assert_eq!(fine.validate().map_err(|e| e.code()), Err("precision"));
        }
    }

    #[test]
    fn percent_converts_to_fractions_exactly() {
        // 0.85% per trade (the paper books' risk) is 0.0085; 12.5% daily is 0.125.
        let mut rules = Rules::default();
        rules.set_number(Field::MaxLossAtStopPct, dec!(0.85));
        rules.set_number(Field::DailyLossStopPct, dec!(12.5));
        let limits = rules.risk_limits();
        assert_eq!(limits.risk_per_trade, dec!(0.0085));
        assert_eq!(limits.daily_loss_stop, dec!(0.125));
    }

    #[test]
    fn a_market_list_allows_only_its_markets() {
        let mut rules = Rules {
            markets: vec!["BTC".into(), "ETH".into()],
            ..Rules::default()
        };
        assert_eq!(rules.validate(), Ok(()));
        assert!(rules.allows_market("BTC"));
        assert!(!rules.allows_market("SOL"));
        rules.markets = vec!["*".into(), "BTC".into()];
        assert_eq!(rules.validate().map_err(|e| e.code()), Err("markets"));
    }

    #[test]
    fn hip3_dexes_are_named_to_be_allowed() {
        // Every main-dex market and every market of HIP-3 dex xyz.
        let rules = Rules {
            markets: vec!["*".into(), "xyz:*".into()],
            ..Rules::default()
        };
        assert_eq!(rules.validate(), Ok(()));
        assert!(rules.allows_market("BTC"));
        assert!(rules.allows_market("xyz:GOLD"));
        assert!(!rules.allows_market("flx:GOLD"));
        // One market of a dex.
        let gold = Rules {
            markets: vec!["xyz:GOLD".into(), "ETH".into()],
            ..Rules::default()
        };
        assert!(gold.allows_market("xyz:GOLD") && gold.allows_market("ETH"));
        assert!(!gold.allows_market("xyz:TSLA") && !gold.allows_market("BTC"));
        // Guard reads them as its policy does.
        let policy = rules
            .to_policy(&zunder_guard_core::policy::Policy::default())
            .unwrap();
        assert!(policy.markets.allows("xyz:GOLD") && policy.markets.allows("SOL"));
        assert_eq!(Rules::from_policy(&policy).markets, ["*", "xyz:*"]);
        // Refused: a main-dex market beside "*", a dex's market beside its
        // dex:*, a wildcard that is not a dex's.
        for markets in [
            vec!["*", "xyz:*", "BTC"],
            vec!["xyz:*", "xyz:GOLD"],
            vec!["*:*"],
            vec![":*"],
            vec!["xyz:**"],
            vec!["x.y:*"],
            vec!["*", "*"],
        ] {
            let rules = Rules {
                markets: markets.iter().map(|m| (*m).to_owned()).collect(),
                ..Rules::default()
            };
            assert_eq!(
                rules.validate().map_err(|e| e.code()),
                Err("markets"),
                "{markets:?}"
            );
        }
        // A v1 code that was valid before HIP-3 support decodes as before:
        // the same rules, the same canonical string.
        let older = b64("{\"v\":1,\"markets\":[\"BTC\",\"xyz:XYZ100\"]}");
        let rules = Rules::decode(&older).unwrap();
        assert_eq!(rules.markets, ["BTC", "xyz:XYZ100"]);
        assert_eq!(Rules::decode(&rules.encode().unwrap()), Ok(rules));
    }

    #[test]
    fn long_strings_and_wrong_prefixes_are_refused_first() {
        let long = format!("{PREFIX}{}", "A".repeat(MAX_ENCODED_LEN));
        assert_eq!(Rules::decode(&long), Err(RulesError::TooLong));
        assert_eq!(Rules::decode("zr2_eyJ2IjoxfQ"), Err(RulesError::Prefix));
    }

    #[test]
    fn vectors_shared_with_typescript() {
        let vectors: Value = serde_json::from_str(VECTORS).expect("vectors.json is JSON");
        let valid = vectors["valid"].as_array().expect("valid list");
        assert!(valid.len() >= 5);
        for case in valid {
            let name = case["name"].as_str().expect("name");
            let input = b64(case["json"].as_str().expect("json"));
            let rules = Rules::decode(&input).unwrap_or_else(|e| panic!("{name}: {e}"));
            let canonical = case["canonical"].as_str().expect("canonical");
            assert_eq!(rules.encode().as_deref(), Ok(canonical), "{name}");
            assert_eq!(Rules::decode(canonical).as_ref(), Ok(&rules), "{name}");
            assert_eq!(rules.risk_limits().validate(), Ok(()), "{name}");
        }
        let invalid = vectors["invalid"].as_array().expect("invalid list");
        assert!(invalid.len() >= 20);
        for case in invalid {
            let name = case["name"].as_str().expect("name");
            let input = match case.get("input") {
                Some(text) => text.as_str().expect("input").to_string(),
                None => b64(case["json"].as_str().expect("json")),
            };
            let err = Rules::decode(&input).expect_err(name);
            assert_eq!(err.code(), case["code"].as_str().expect("code"), "{name}");
            if let Some(field) = case.get("field") {
                assert_eq!(err.field(), field.as_str(), "{name}");
            }
        }
    }

    #[test]
    fn schema_file_matches_the_code() {
        let schema: Value = serde_json::from_str(SCHEMA).expect("schema-v1.json is JSON");
        let props = &schema["properties"];
        let dec_of = |v: &Value| Decimal::from_str(&v.to_string()).expect("a number");
        for b in number_bounds() {
            let p = &props[b.field.key()];
            assert_eq!(dec_of(&p["default"]), b.default, "{:?}", b.field);
            assert_eq!(dec_of(&p["maximum"]), b.max, "{:?}", b.field);
            let min_key = if b.min_inclusive {
                "minimum"
            } else {
                "exclusiveMinimum"
            };
            assert_eq!(dec_of(&p[min_key]), b.min, "{:?}", b.field);
            assert_eq!(p["multipleOf"], serde_json::json!(0.0001), "{:?}", b.field);
        }
        let d = Rules::default();
        assert_eq!(props["stopPolicy"]["default"], d.stop_policy.as_str());
        assert_eq!(props["markets"]["default"], serde_json::json!(d.markets));
        assert_eq!(props["markets"]["maxItems"], MAX_MARKETS);
        let keys: Vec<&str> = props
            .as_object()
            .expect("properties")
            .keys()
            .map(String::as_str)
            .collect();
        for field in Field::ALL {
            assert!(keys.contains(&field.key()), "{:?}", field);
        }
        assert_eq!(keys.len(), Field::ALL.len() + 1, "v plus the ten fields");
        assert!(
            !keys.contains(&"requireStop"),
            "removed in the reconciled v1"
        );
    }

    #[test]
    fn default_rules_string_is_stable() {
        // The string the website shows for "defaults"; changing it breaks shared links.
        let expected = b64(
            "{\"v\":1,\"maxLeverage\":5,\"maxLossAtStopPct\":2,\"stopPolicy\":\"attach\",\
             \"defaultStopDistancePct\":2,\"minLiqDistancePct\":10,\"maxPositionPct\":200,\
             \"maxOpenRiskPct\":6,\"dailyLossStopPct\":6,\"drawdownHaltPct\":25,\
             \"markets\":[\"*\"]}",
        );
        assert_eq!(Rules::default().encode(), Ok(expected));
    }
}
