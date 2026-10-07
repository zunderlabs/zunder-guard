// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The account as Guard judges against it: equity, positions with their
//! leverage and stops, resting orders, mid prices and the venue's asset
//! list, parsed from the `info` endpoint's answers.
//!
//! Requests and answers are the documented ones ("Info endpoint",
//! "Perpetuals"): `meta`, `clearinghouseState`, `frontendOpenOrders`,
//! `allMids` and `userAbstraction`. Prices and sizes arrive as strings and
//! are parsed as exact decimals; a number where a string is expected is an
//! error. Fields Guard does not use are ignored.
//!
//! Guard covers perps of Hyperliquid's main dex and of the HIP-3 dexes
//! (builder-deployed perp dexes) its markets name, in standard account
//! mode (`userAbstraction` = `"disabled"`). In that mode each perp dex has
//! a margin account of its own, read with the `dex` parameter of `meta`,
//! `clearinghouseState`, `frontendOpenOrders` and `allMids` (a HIP-3 dex's
//! coins are named `dex:COIN`); [`AccountView::parse_dexes`] merges them
//! into one view. Equity is the sum of the perp accounts' values over the
//! dexes read whose collateral is USDC: the account-wide figure the risk
//! engine's daily loss stop, drawdown halt, open risk and leverage cap
//! use. Spot balances, and dexes Guard does not read, are left out, which
//! can only make sizes smaller; a transfer to them counts as a loss, so
//! moving money out trips the daily loss stop sooner, never later. Other
//! account modes leave the equity unknown, and nothing is opened.

use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
};

use rust_decimal::{Decimal, RoundingStrategy};
use serde_json::{Value, json};
use thiserror::Error;
use zunder_core::{Side, Symbol};
use zunder_risk::{Exposure, VenuePosition, VenueView};

use crate::{action::Tpsl, sign::Address};

/// Hyperliquid perps allow `6 - szDecimals` price decimals and five
/// significant figures; integer prices are always allowed ("Tick and lot
/// size").
const PERP_MAX_DECIMALS: u32 = 6;
const SIG_FIGS: i64 = 5;
/// "Order must have minimum value of $10."
pub const MIN_NOTIONAL: Decimal = Decimal::TEN;
/// Spot asset ids start here (`10000 + pair index`); HIP-3 dexes' perps
/// are `100000 + 10000 × dex + index` ([`FIRST_HIP3_ASSET`]), HIP-4
/// outcome sides `100000000 + 10 × outcome + side`
/// ([`FIRST_OUTCOME_ASSET`]) (Hyperliquid's "Asset IDs").
pub const FIRST_SPOT_ASSET: u32 = 10_000;
/// The first HIP-3 asset id: `100000 + 10000 × dex + index`, the dex's
/// position in `perpDexs` (the main dex is 0 and has no such ids) and the
/// coin's in that dex's `meta`.
pub const FIRST_HIP3_ASSET: u32 = 100_000;
/// HIP-3 assets of one dex: indices below this.
pub const HIP3_ASSETS_PER_DEX: u32 = 10_000;
/// The first HIP-4 outcome asset id. HIP-3 ids would reach it at dex 9,990;
/// a dex index that high is refused rather than read as an outcome.
pub const FIRST_OUTCOME_ASSET: u32 = 100_000_000;
/// The highest HIP-3 dex index whose every asset id lies below
/// [`FIRST_OUTCOME_ASSET`].
pub const MAX_HIP3_DEX_INDEX: u32 =
    (FIRST_OUTCOME_ASSET - FIRST_HIP3_ASSET) / HIP3_ASSETS_PER_DEX - 1;
/// The collateral token of a dex whose accounts are in USDC (`spotMeta`
/// token 0). Equity is summed in USDC; other collateral is not summed.
pub const USDC_TOKEN: u32 = 0;

/// What an asset id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetKind {
    /// A perp of the main dex: its index in `meta`.
    MainPerp,
    Spot,
    /// A perp of the HIP-3 dex at this index of `perpDexs`.
    Hip3 {
        dex: u32,
    },
    Outcome,
    /// An id in the HIP-3 range that names no dex (dex 0, which is the main
    /// dex's and has no HIP-3 ids).
    Invalid,
}

/// Classify an asset id by Hyperliquid's arithmetic.
pub fn asset_kind(id: u32) -> AssetKind {
    if id < FIRST_SPOT_ASSET {
        AssetKind::MainPerp
    } else if id < FIRST_HIP3_ASSET {
        AssetKind::Spot
    } else if id < FIRST_OUTCOME_ASSET {
        match (id - FIRST_HIP3_ASSET) / HIP3_ASSETS_PER_DEX {
            0 => AssetKind::Invalid,
            dex => AssetKind::Hip3 { dex },
        }
    } else {
        AssetKind::Outcome
    }
}

/// The asset id of the coin at `index` of HIP-3 dex `dex`'s `meta`; `None`
/// outside the HIP-3 range.
pub fn hip3_asset_id(dex: u32, index: u32) -> Option<u32> {
    if dex == 0 || dex > MAX_HIP3_DEX_INDEX || index >= HIP3_ASSETS_PER_DEX {
        return None;
    }
    FIRST_HIP3_ASSET
        .checked_add(dex.checked_mul(HIP3_ASSETS_PER_DEX)?)?
        .checked_add(index)
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unexpected answer to {request}: {message}")]
pub struct InfoError {
    pub request: &'static str,
    pub message: String,
}

fn bad(request: &'static str, message: impl Into<String>) -> InfoError {
    InfoError {
        request,
        message: message.into(),
    }
}

/// The `info` requests Guard reads, as JSON bodies.
pub mod requests {
    use super::*;

    pub fn meta() -> Value {
        json!({"type": "meta"})
    }
    pub fn all_mids() -> Value {
        json!({"type": "allMids"})
    }
    pub fn clearinghouse_state(user: Address) -> Value {
        json!({"type": "clearinghouseState", "user": user.to_hex()})
    }
    pub fn frontend_open_orders(user: Address) -> Value {
        json!({"type": "frontendOpenOrders", "user": user.to_hex()})
    }
    pub fn user_abstraction(user: Address) -> Value {
        json!({"type": "userAbstraction", "user": user.to_hex()})
    }
    pub fn user_role(user: Address) -> Value {
        json!({"type": "userRole", "user": user.to_hex()})
    }
    /// The account's deposits, withdrawals and transfers since `start_ms`,
    /// oldest first (weight 20, and 1 more per 20 entries).
    pub fn ledger_updates(user: Address, start_ms: i64) -> Value {
        json!({"type": "userNonFundingLedgerUpdates", "user": user.to_hex(), "startTime": start_ms})
    }
    /// The account's settings for one perp, its leverage among them (a
    /// HIP-3 coin by its full name, `dex:COIN`).
    pub fn active_asset_data(user: Address, coin: &str) -> Value {
        json!({"type": "activeAssetData", "user": user.to_hex(), "coin": coin})
    }
    /// Every perp dex: `null` for the main dex, then one object per HIP-3
    /// dex with its `name`, in the order that gives each its index.
    pub fn perp_dexs() -> Value {
        json!({"type": "perpDexs"})
    }
    /// The `meta` of HIP-3 dex `dex`.
    pub fn meta_of(dex: &str) -> Value {
        json!({"type": "meta", "dex": dex})
    }
    pub fn clearinghouse_state_of(user: Address, dex: &str) -> Value {
        json!({"type": "clearinghouseState", "user": user.to_hex(), "dex": dex})
    }
    pub fn frontend_open_orders_of(user: Address, dex: &str) -> Value {
        json!({"type": "frontendOpenOrders", "user": user.to_hex(), "dex": dex})
    }
    pub fn all_mids_of(dex: &str) -> Value {
        json!({"type": "allMids", "dex": dex})
    }
    /// The coins of HIP-3 dex `dex` at their open-interest cap.
    pub fn perps_at_open_interest_cap(dex: &str) -> Value {
        json!({"type": "perpsAtOpenInterestCap", "dex": dex})
    }
    /// The order book of one coin, its prices aggregated to `sig_figs`
    /// significant figures (up to 20 levels a side; [`book_sig_figs`]).
    pub fn l2_book(coin: &str, sig_figs: u32) -> Value {
        json!({"type": "l2Book", "coin": coin, "nSigFigs": sig_figs})
    }
}

/// The significant figures to read a book at around `mid`, so that 20
/// levels a side reach a stop's worst fill (about 12% away at the
/// defaults) with levels no wider than 2.5% of the price: 2 when the
/// price's leading digits are 4 or more (levels 1% to 2.5% wide, 20 of them
/// 20% to 50%), 3 below (levels 0.25% to 1%, 20 of them 5% to 20%; what lies
/// beyond the twentieth counts as no depth).
pub fn book_sig_figs(mid: Decimal) -> u32 {
    let unit = pow10(floor_log10(mid));
    match unit.and_then(|unit| mid.checked_div(unit)) {
        Some(leading) if leading >= Decimal::from(4) => 2,
        _ => 3,
    }
}

/// `10^exponent`, exactly; `None` beyond what a `Decimal` holds.
fn pow10(exponent: i64) -> Option<Decimal> {
    if exponent >= 0 {
        10u64
            .checked_pow(u32::try_from(exponent).ok()?)
            .map(Decimal::from)
    } else {
        let scale = u32::try_from(-exponent).ok().filter(|scale| *scale <= 28)?;
        Some(Decimal::new(1, scale))
    }
}

/// The HIP-3 dexes `perpDexs` lists, by name: `(index, name)`. The main
/// dex (index 0, `null`) is left out.
pub fn parse_perp_dexs(value: &Value) -> Result<Vec<(u32, String)>, InfoError> {
    const R: &str = "perpDexs";
    let list = value.as_array().ok_or_else(|| bad(R, "not an array"))?;
    let mut dexes = Vec::new();
    for (index, dex) in list.iter().enumerate() {
        if index == 0 || dex.is_null() {
            continue;
        }
        let name = dex
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| bad(R, "a dex without a name"))?;
        let index = u32::try_from(index).map_err(|_| bad(R, "too many dexes"))?;
        dexes.push((index, name.to_owned()));
    }
    Ok(dexes)
}

/// A book of one coin: `(price, size)` levels, best first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Book {
    pub bids: Vec<(Decimal, Decimal)>,
    pub asks: Vec<(Decimal, Decimal)>,
    /// The significant figures the venue aggregated the prices to: a bid
    /// level at `px` holds the bids from `px` up to the next step, an ask
    /// level the asks above the step below up to `px`. `None`: exact prices.
    pub sig_figs: Option<u32>,
}

impl Book {
    /// Parse an `l2Book` answer for `coin`, read with `nSigFigs` `sig_figs`.
    pub fn parse_aggregated(value: &Value, coin: &str, sig_figs: u32) -> Result<Self, InfoError> {
        Ok(Self {
            sig_figs: Some(sig_figs),
            ..Self::parse(value, coin)?
        })
    }

    /// Parse an `l2Book` answer for `coin`, at exact prices.
    pub fn parse(value: &Value, coin: &str) -> Result<Self, InfoError> {
        const R: &str = "l2Book";
        if value.get("coin").and_then(Value::as_str) != Some(coin) {
            return Err(bad(R, format!("not the book of {coin}")));
        }
        let levels = value
            .get("levels")
            .and_then(Value::as_array)
            .filter(|levels| levels.len() == 2)
            .ok_or_else(|| bad(R, "levels is not two lists"))?;
        let side = |levels: &Value| -> Result<Vec<(Decimal, Decimal)>, InfoError> {
            levels
                .as_array()
                .ok_or_else(|| bad(R, "a side is not a list"))?
                .iter()
                .map(|level| {
                    Ok((
                        decimal_str(level.get("px"), R, "px")?,
                        decimal_str(level.get("sz"), R, "sz")?,
                    ))
                })
                .collect()
        };
        Ok(Self {
            bids: side(&levels[0])?,
            asks: side(&levels[1])?,
            sig_figs: None,
        })
    }

    /// The size a stop of a position on `side` can fill into: on the side
    /// it trades against (the bids for a long, the asks for a short), only
    /// levels lying wholly between its trigger and its worst fill. What
    /// rests between the price and the trigger is not counted: by the time
    /// the stop fires it has traded or gone.
    pub fn exit_depth(&self, side: Side, trigger: Decimal, worst: Decimal) -> Option<Decimal> {
        let levels = match side {
            Side::Buy => &self.bids,
            Side::Sell => &self.asks,
        };
        let width_at = |price: Decimal| -> Option<Decimal> {
            match self.sig_figs {
                None => Some(Decimal::ZERO),
                Some(figs) => pow10(
                    floor_log10(price)
                        .checked_sub(i64::from(figs))?
                        .checked_add(1)?,
                ),
            }
        };
        // The venue aggregates the whole book at the mid's step, on both
        // sides of a power of ten (HBAR at 0.1004, 3 figures: bids 0.1,
        // 0.099, 0.098; HYPE at 93, 2 figures: asks 99, 100, 101). The best
        // ask lies at or above the mid, so its step is at least the mid's
        // (ten times it only when the mid sits within a step below a power
        // of ten: fewer levels counted, never more). An aggregated book
        // without asks gives no depth: its step is unknown.
        let book_width = match (self.sig_figs, self.asks.first()) {
            (None, _) => Decimal::ZERO,
            (Some(_), Some((best_ask, _))) if *best_ask > Decimal::ZERO => width_at(*best_ask)?,
            (Some(_), _) => return Some(Decimal::ZERO),
        };
        let mut depth = Decimal::ZERO;
        for (price, size) in levels {
            let width = book_width;
            let inside = match side {
                // A bid level covers [price, price + width).
                Side::Buy => *price >= worst && price.checked_add(width)? <= trigger,
                // An ask level covers (price - width, price].
                Side::Sell => *price <= worst && price.checked_sub(width)? >= trigger,
            };
            if inside {
                depth = depth.checked_add(*size)?;
            }
        }
        Some(depth)
    }
}

/// Whether an `activeAssetData` answer shows isolated margin at `leverage`:
/// how Guard confirms its `updateLeverage` before sending an entry.
pub fn confirms_isolated(answer: &Value, leverage: u32) -> bool {
    answer.pointer("/leverage/type").and_then(Value::as_str) == Some("isolated")
        && answer.pointer("/leverage/value").and_then(Value::as_u64) == Some(u64::from(leverage))
}

/// How the venue lets an asset be margined (`marginMode` in `meta`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MarginMode {
    /// Cross or isolated.
    #[default]
    Any,
    /// Isolated only (`noCross`, or the older `onlyIsolated`).
    NoCross,
    /// Isolated only, and margin cannot be removed from an open position
    /// (`strictIsolated`).
    StrictIsolated,
}

/// One perp, of the main dex or of a HIP-3 dex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetInfo {
    /// The asset id in orders: the index in the main dex's
    /// `meta.universe`, or `100000 + 10000 × dex + index` for a HIP-3
    /// dex's perp ([`hip3_asset_id`]).
    pub index: u32,
    /// The venue's name: `BTC`, or `dex:COIN` on a HIP-3 dex.
    pub name: String,
    pub sz_decimals: u32,
    /// The venue's highest leverage; 1 when it does not say.
    pub max_leverage: u32,
    /// Delisted; on a HIP-3 dex also what the deployer's `haltTrading`
    /// leaves (the market halted and its positions settled).
    pub delisted: bool,
    /// The dex's index in `perpDexs`: 0 for the main dex.
    pub dex: u32,
    /// Informational: Guard keeps every position isolated and never removes
    /// margin, which every mode allows.
    pub margin_mode: MarginMode,
    /// The taker fee as a multiple of the main dex's: 1 there; on a HIP-3
    /// dex, with the deployer's fee scale `s`, `1 + s` below 1 and `2s` from
    /// 1 up (Hyperliquid's documentation, "Fees", HIP-3;
    /// growth mode's discount is not counted, validators may end it), and
    /// [`MAX_HIP3_FEE_SCALE`] when `meta` does not say.
    pub fee_scale: Decimal,
}

/// The highest HIP-3 taker fee as a multiple of the main dex's: a deployer
/// fee share of at most 300% (`deployerFeeScale` 3) is `2 × 3`.
pub const MAX_HIP3_FEE_SCALE: Decimal = Decimal::from_parts(6, 0, 0, false, 0);

/// The taker-fee multiple of a HIP-3 asset with `deployerFeeScale` `s`.
pub fn hip3_fee_scale(s: Option<Decimal>) -> Decimal {
    match s {
        Some(s) if s >= Decimal::ZERO && s < Decimal::ONE => Decimal::ONE + s,
        Some(s) if s >= Decimal::ONE && s <= Decimal::from(3) => s * Decimal::TWO,
        _ => MAX_HIP3_FEE_SCALE,
    }
}

impl AssetInfo {
    /// Smallest quantity step: `10^-szDecimals`.
    pub fn qty_step(&self) -> Decimal {
        Decimal::new(1, self.sz_decimals.min(18))
    }

    /// `qty` rounded down to the quantity step.
    pub fn round_qty_down(&self, qty: Decimal) -> Decimal {
        qty.round_dp_with_strategy(self.sz_decimals.min(18), RoundingStrategy::ToZero)
            .normalize()
    }

    /// `price` on the venue's grid, rounded up or down; `None` for a price
    /// of zero or less.
    pub fn round_price(&self, price: Decimal, up: bool) -> Option<Decimal> {
        if price <= Decimal::ZERO {
            return None;
        }
        let max_decimals = i64::from(PERP_MAX_DECIMALS.saturating_sub(self.sz_decimals));
        let by_sig_figs = SIG_FIGS - 1 - floor_log10(price);
        let decimals = u32::try_from(by_sig_figs.clamp(0, max_decimals)).unwrap_or(0);
        let strategy = if up {
            RoundingStrategy::ToPositiveInfinity
        } else {
            RoundingStrategy::ToNegativeInfinity
        };
        let rounded = price.round_dp_with_strategy(decimals, strategy).normalize();
        (rounded > Decimal::ZERO).then_some(rounded)
    }
}

/// `floor(log10(value))` for a positive value, exactly.
fn floor_log10(value: Decimal) -> i64 {
    let mantissa = value.mantissa().unsigned_abs();
    let digits = mantissa.checked_ilog10().map_or(0, i64::from);
    digits - i64::from(value.scale())
}

/// One perp dex Guard read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexInfo {
    /// Its index in `perpDexs`: 0 for the main dex.
    pub index: u32,
    /// Its name: empty for the main dex.
    pub name: String,
    /// The `spotMeta` token its accounts are margined in ([`USDC_TOKEN`]
    /// for USDC).
    pub collateral_token: u32,
}

/// The venue's perps, from `meta`: the main dex's, and those of the HIP-3
/// dexes Guard reads, merged ([`Meta::merge`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Meta {
    pub assets: Vec<AssetInfo>,
    /// The dexes these assets come from.
    pub dexes: Vec<DexInfo>,
}

impl Meta {
    /// The main dex's `meta`.
    pub fn parse(value: &Value) -> Result<Self, InfoError> {
        Self::parse_universe(value, 0, "")
    }

    /// The `meta` of HIP-3 dex `name` at `index` in `perpDexs`: every
    /// asset must carry the dex's prefix (`name:`), and its id is
    /// `100000 + 10000 × index + its position`.
    pub fn parse_dex(value: &Value, index: u32, name: &str) -> Result<Self, InfoError> {
        if index == 0 || index > MAX_HIP3_DEX_INDEX || name.is_empty() {
            return Err(bad("meta", format!("dex {name} at index {index}")));
        }
        Self::parse_universe(value, index, name)
    }

    fn parse_universe(value: &Value, dex: u32, dex_name: &str) -> Result<Self, InfoError> {
        const R: &str = "meta";
        let universe = value
            .get("universe")
            .and_then(Value::as_array)
            .ok_or_else(|| bad(R, "no universe"))?;
        let collateral_token = match value.get("collateralToken") {
            // The main dex's `meta` may leave it out: USDC.
            None | Some(Value::Null) if dex == 0 => USDC_TOKEN,
            Some(token) => token
                .as_u64()
                .and_then(|token| u32::try_from(token).ok())
                .ok_or_else(|| bad(R, "collateralToken is not a token index"))?,
            None => return Err(bad(R, "a HIP-3 dex's meta without collateralToken")),
        };
        let prefix = format!("{dex_name}:");
        let mut assets = Vec::with_capacity(universe.len());
        for (index, asset) in universe.iter().enumerate() {
            let name = asset
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| bad(R, "an asset without a name"))?;
            // A HIP-3 dex's coins carry its name. An asset under another
            // prefix would be judged under the wrong id.
            let named_right = dex == 0
                || name
                    .strip_prefix(&prefix)
                    .is_some_and(|coin| !coin.is_empty() && !coin.contains(':'));
            if !named_right {
                return Err(bad(R, format!("{name} is not a coin of dex `{dex_name}`")));
            }
            let index = u32::try_from(index).map_err(|_| bad(R, "too many assets"))?;
            let id = if dex == 0 {
                if index >= FIRST_SPOT_ASSET {
                    return Err(bad(R, "too many assets"));
                }
                index
            } else {
                hip3_asset_id(dex, index).ok_or_else(|| bad(R, "too many assets"))?
            };
            let margin_mode = match asset.get("marginMode").and_then(Value::as_str) {
                Some("strictIsolated") => MarginMode::StrictIsolated,
                Some("noCross") => MarginMode::NoCross,
                _ if asset.get("onlyIsolated").and_then(Value::as_bool) == Some(true) => {
                    MarginMode::NoCross
                }
                _ => MarginMode::Any,
            };
            let sz_decimals = asset
                .get("szDecimals")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| *value <= PERP_MAX_DECIMALS)
                .ok_or_else(|| bad(R, format!("{name} has no valid szDecimals")))?;
            let max_leverage = match asset.get("maxLeverage") {
                None | Some(Value::Null) => 1,
                Some(value) => value
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .filter(|value| *value >= 1)
                    .ok_or_else(|| bad(R, format!("{name} has an invalid maxLeverage")))?,
            };
            assets.push(AssetInfo {
                index: id,
                name: name.to_owned(),
                sz_decimals,
                max_leverage,
                delisted: asset
                    .get("isDelisted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                dex,
                margin_mode,
                fee_scale: if dex == 0 {
                    Decimal::ONE
                } else {
                    hip3_fee_scale(
                        asset
                            .get("deployerFeeScale")
                            .and_then(Value::as_str)
                            .and_then(|text| Decimal::from_str(text).ok()),
                    )
                },
            });
        }
        Ok(Self {
            assets,
            dexes: vec![DexInfo {
                index: dex,
                name: dex_name.to_owned(),
                collateral_token,
            }],
        })
    }

    /// Add another dex's perps. A dex already present is not added twice.
    pub fn merge(&mut self, other: Meta) {
        for dex in other.dexes {
            if self.dex(dex.index).is_none() {
                self.dexes.push(dex);
            }
        }
        for asset in other.assets {
            if self.by_index(asset.index).is_none() {
                self.assets.push(asset);
            }
        }
    }

    /// The asset with this id.
    pub fn by_index(&self, index: u32) -> Option<&AssetInfo> {
        // The main dex's assets come first, at their own index.
        if let Some(asset) = usize::try_from(index)
            .ok()
            .and_then(|at| self.assets.get(at))
            .filter(|asset| asset.index == index)
        {
            return Some(asset);
        }
        self.assets.iter().find(|asset| asset.index == index)
    }

    pub fn by_name(&self, name: &str) -> Option<&AssetInfo> {
        self.assets.iter().find(|asset| asset.name == name)
    }

    /// A dex that was read, by its index in `perpDexs`.
    pub fn dex(&self, index: u32) -> Option<&DexInfo> {
        self.dexes.iter().find(|dex| dex.index == index)
    }
}

/// An isolated or cross leverage setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Leverage {
    pub isolated: bool,
    pub value: u32,
}

/// A position as `clearinghouseState` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionView {
    pub coin: String,
    pub side: Side,
    /// Always positive.
    pub qty: Decimal,
    pub entry: Decimal,
    pub leverage: Leverage,
    pub liquidation_px: Option<Decimal>,
}

/// A resting order as `frontendOpenOrders` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenOrderView {
    pub oid: u64,
    /// Lowercase.
    pub cloid: Option<String>,
    pub coin: String,
    pub side: Side,
    /// The size still open; zero for a position TP/SL, which covers the
    /// whole position.
    pub qty: Decimal,
    pub limit_px: Decimal,
    pub reduce_only: bool,
    /// The trigger price and kind of a trigger order. An order type Guard
    /// does not know is read as a take profit: never protection.
    pub trigger: Option<(Decimal, Tpsl)>,
    /// A trigger that becomes a market order ("Stop Market"), rather than a
    /// limit order at `limit_px` ("Stop Limit").
    pub is_market: bool,
    pub is_position_tpsl: bool,
    /// The TP/SL waiting for this order to fill (`normalTpsl`).
    pub children: Vec<OpenOrderView>,
}

impl OpenOrderView {
    /// A market stop loss that only reduces: protection. A stop-limit is
    /// none: once triggered its limit may rest on the wrong side of the
    /// market and never fill.
    pub fn is_protective_stop(&self) -> bool {
        self.protective_level().is_some()
    }

    /// The trigger at which this market stop bounds the loss; `None` for
    /// anything that is not a reduce-only market stop loss whose limit
    /// leaves room to fill (`action::limit_leaves_room`).
    pub fn protective_level(&self) -> Option<Decimal> {
        match self.trigger {
            Some((trigger, Tpsl::Sl))
                if self.is_market
                    && (self.reduce_only || self.is_position_tpsl)
                    && crate::action::limit_leaves_room(
                        self.side == Side::Buy,
                        trigger,
                        self.limit_px,
                    ) =>
            {
                Some(trigger)
            }
            _ => None,
        }
    }

    /// An order that could open or grow a position.
    pub fn is_opening(&self) -> bool {
        !self.reduce_only && !self.is_position_tpsl
    }

    /// The trigger of the stop loss waiting for this order, the tightest
    /// if there are several.
    pub fn child_stop(&self) -> Option<Decimal> {
        let triggers = self
            .children
            .iter()
            .filter(|child| child.side == self.side.opposite())
            .filter_map(OpenOrderView::protective_level)
            // Only a stop on the losing side of the entry's price protects
            // it; one on the other side would close the position at once.
            .filter(|level| match self.side {
                Side::Buy => *level < self.limit_px,
                Side::Sell => *level > self.limit_px,
            });
        match self.side {
            Side::Buy => triggers.max(),
            Side::Sell => triggers.min(),
        }
    }
}

/// One dex's margin account, as `clearinghouseState` with its `dex` shows
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexAccount {
    /// The dex's index in `perpDexs`: 0 for the main dex.
    pub index: u32,
    /// Empty for the main dex.
    pub name: String,
    /// `marginSummary.accountValue`, in the dex's collateral.
    pub value: Decimal,
    /// `withdrawable`: what is free to margin a new position; `None` when
    /// the answer leaves it out.
    pub withdrawable: Option<Decimal>,
    /// The venue's time of the answer (`clearinghouseState`'s `time`),
    /// epoch ms, when it carries one.
    pub time: Option<i64>,
    /// Whether the dex margins in USDC: only those are summed into equity.
    pub usdc: bool,
}

/// One dex's answers, for [`AccountView::parse_dexes`].
#[derive(Debug, Clone, Copy)]
pub struct DexAnswers<'a> {
    /// That dex's `meta`, parsed ([`Meta::parse`] or [`Meta::parse_dex`]).
    pub meta: &'a Meta,
    pub clearinghouse: &'a Value,
    pub open_orders: &'a Value,
    pub mids: &'a Value,
    /// `perpsAtOpenInterestCap` for a HIP-3 dex, when read.
    pub at_open_interest_cap: Option<&'a Value>,
}

/// Everything Guard judges a request against: the main dex and the HIP-3
/// dexes Guard reads, merged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountView {
    /// When it was read, epoch milliseconds.
    pub at_ms: i64,
    /// The sum of the USDC perp accounts' values over the dexes read;
    /// `None` when the account mode is not standard, or the value could
    /// not be read.
    pub equity: Option<Decimal>,
    /// The `userAbstraction` answer.
    pub mode: String,
    /// Every position on the dexes read; a HIP-3 dex's coins carry its
    /// prefix, so a coin name is unique across dexes.
    pub positions: Vec<PositionView>,
    pub open_orders: Vec<OpenOrderView>,
    pub mids: HashMap<String, Decimal>,
    pub meta: Meta,
    /// Each dex's margin account, the main dex first. Empty in views built
    /// by hand.
    pub dexes: Vec<DexAccount>,
    /// HIP-3 coins at their open-interest cap.
    pub at_open_interest_cap: BTreeSet<String>,
    /// Order books read for this request (a HIP-3 entry's coin).
    pub books: HashMap<String, Book>,
    /// The account's leverage setting of a coin as the venue showed it
    /// moments ago (`activeAssetData`, from the account stream), for an
    /// entry's coin: an isolated setting at most the leverage the entry
    /// allows needs no `updateLeverage`. Empty when not known.
    pub leverage_settings: HashMap<String, Leverage>,
}

impl AccountView {
    /// Parse the four answers of the main dex. `mode` is the
    /// `userAbstraction` answer, a bare JSON string.
    pub fn parse(
        at_ms: i64,
        meta: Meta,
        mode: &Value,
        clearinghouse: &Value,
        open_orders: &Value,
        mids: &Value,
    ) -> Result<Self, InfoError> {
        let mut view = Self::parse_dexes(
            at_ms,
            mode,
            &[DexAnswers {
                meta: &meta,
                clearinghouse,
                open_orders,
                mids,
                at_open_interest_cap: None,
            }],
        )?;
        view.meta = meta;
        Ok(view)
    }

    /// Parse and merge the answers of several dexes: the main dex first,
    /// then HIP-3 dexes. A HIP-3 dex's positions, orders and mids must all
    /// carry its prefix (`dex:`), so nothing is booked to the wrong dex.
    /// Equity sums the USDC dexes' account values.
    pub fn parse_dexes(
        at_ms: i64,
        mode: &Value,
        dexes: &[DexAnswers<'_>],
    ) -> Result<Self, InfoError> {
        let mode = mode
            .as_str()
            .ok_or_else(|| bad("userAbstraction", "not a string"))?
            .to_owned();
        let mut view = Self {
            at_ms,
            mode,
            ..Self::default()
        };
        let mut equity = Some(Decimal::ZERO);
        for (at, answers) in dexes.iter().enumerate() {
            let dex = answers.meta.dexes.first().cloned().unwrap_or(DexInfo {
                index: 0,
                name: String::new(),
                collateral_token: USDC_TOKEN,
            });
            if (at == 0) != (dex.index == 0) {
                return Err(bad("meta", "the main dex comes first, and only first"));
            }
            if view
                .dexes
                .iter()
                .any(|seen| seen.index == dex.index || seen.name == dex.name)
            {
                return Err(bad("meta", format!("dex {} read twice", dex.name)));
            }
            let (value, withdrawable, positions) = parse_clearinghouse(answers.clearinghouse)?;
            let orders = parse_open_orders(answers.open_orders)?;
            let mids = parse_mids(answers.mids)?;
            let capped = match answers.at_open_interest_cap {
                None => Vec::new(),
                Some(list) => list
                    .as_array()
                    .ok_or_else(|| bad("perpsAtOpenInterestCap", "not a list"))?
                    .iter()
                    .map(|coin| {
                        coin.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| bad("perpsAtOpenInterestCap", "not a coin"))
                    })
                    .collect::<Result<_, _>>()?,
            };
            if dex.index == 0 {
                // The main dex's positions and orders are its own: a HIP-3
                // coin there would be counted twice.
                if let Some(coin) = positions
                    .iter()
                    .map(|position| position.coin.as_str())
                    .chain(
                        orders
                            .iter()
                            .flat_map(|order| std::iter::once(order).chain(&order.children))
                            .map(|order| order.coin.as_str()),
                    )
                    .find(|coin| coin.contains(':'))
                {
                    return Err(bad(
                        "clearinghouseState",
                        format!("{coin} in the main dex's answers"),
                    ));
                }
            } else {
                let prefix = format!("{}:", dex.name);
                let foreign = positions
                    .iter()
                    .map(|position| position.coin.as_str())
                    .chain(
                        orders
                            .iter()
                            .flat_map(|order| std::iter::once(order).chain(&order.children))
                            .map(|order| order.coin.as_str()),
                    )
                    .chain(mids.keys().map(String::as_str))
                    .chain(capped.iter().map(String::as_str))
                    .find(|coin| !coin.starts_with(&prefix));
                if let Some(coin) = foreign {
                    return Err(bad(
                        "clearinghouseState",
                        format!("{coin} in the answers for dex `{}`", dex.name),
                    ));
                }
            }
            let usdc = dex.collateral_token == USDC_TOKEN;
            if usdc {
                equity = equity.and_then(|sum| sum.checked_add(value));
            }
            view.dexes.push(DexAccount {
                index: dex.index,
                name: dex.name.clone(),
                value,
                withdrawable,
                time: answers.clearinghouse.get("time").and_then(Value::as_i64),
                usdc,
            });
            view.positions.extend(positions);
            view.open_orders.extend(orders);
            view.mids.extend(mids);
            view.at_open_interest_cap.extend(capped);
            view.meta.merge(answers.meta.clone());
        }
        view.equity = equity.filter(|_| view.mode == "disabled");
        Ok(view)
    }

    /// The margin account of the dex at `index`.
    pub fn dex_account(&self, index: u32) -> Option<&DexAccount> {
        self.dexes.iter().find(|dex| dex.index == index)
    }

    pub fn position(&self, coin: &str) -> Option<&PositionView> {
        self.positions.iter().find(|position| position.coin == coin)
    }

    pub fn mid(&self, coin: &str) -> Option<Decimal> {
        self.mids
            .get(coin)
            .copied()
            .filter(|mid| *mid > Decimal::ZERO)
    }

    /// The order with venue id `oid`, or with client id `cloid`, at the
    /// top level or waiting as a child.
    pub fn order_by_oid(&self, oid: u64) -> Option<&OpenOrderView> {
        self.all_orders().find(|order| order.oid == oid)
    }

    pub fn order_by_cloid(&self, cloid: &str) -> Option<&OpenOrderView> {
        let cloid = cloid.to_ascii_lowercase();
        self.all_orders()
            .find(|order| order.cloid.as_deref() == Some(cloid.as_str()))
    }

    /// The parent order a waiting child belongs to.
    pub fn parent_of(&self, oid: u64) -> Option<&OpenOrderView> {
        self.open_orders
            .iter()
            .find(|order| order.children.iter().any(|child| child.oid == oid))
    }

    pub fn all_orders(&self) -> impl Iterator<Item = &OpenOrderView> {
        self.open_orders
            .iter()
            .flat_map(|order| std::iter::once(order).chain(order.children.iter()))
    }

    /// The stop that bounds the loss of the position in `coin`, ignoring
    /// the orders in `except`, as one trigger for the risk engine.
    ///
    /// Stops placed with separate entries are each sized to their entry,
    /// so several may protect one position together. As the price moves
    /// against it the tightest fires first and closes its size, then the
    /// next: the loss is the sum over the stops, tightest first, of the
    /// size each one closes times its distance. The trigger returned is the
    /// size-weighted average of those triggers, so that the position's
    /// size times its distance to the price is exactly that loss. A
    /// position TP/SL covers all that remains alone. `None` when the stops
    /// do not cover the whole position.
    pub fn covering_stop(&self, coin: &str, except: &[u64]) -> Option<Decimal> {
        self.covering_stop_with(coin, except, None)
    }

    /// [`AccountView::covering_stop`] with one more stop loss, `(trigger,
    /// size)`: a modified stop in place of the one it replaces.
    pub fn covering_stop_with(
        &self,
        coin: &str,
        except: &[u64],
        extra: Option<(Decimal, Decimal)>,
    ) -> Option<Decimal> {
        let position = self.position(coin)?;
        let mut stops: Vec<(Decimal, Decimal, bool)> = self
            .open_orders
            .iter()
            .filter(|order| {
                order.coin == coin
                    && !except.contains(&order.oid)
                    && order.is_protective_stop()
                    && order.side == position.side.opposite()
            })
            .filter_map(|order| {
                order
                    .protective_level()
                    .map(|px| (px, order.qty, order.is_position_tpsl))
            })
            .collect();
        stops.extend(extra.map(|(trigger, qty)| (trigger, qty, false)));
        // Tightest first: the highest trigger under a long, the lowest
        // above a short.
        match position.side {
            Side::Buy => stops.sort_by_key(|stop| std::cmp::Reverse(stop.0)),
            Side::Sell => stops.sort_by_key(|stop| stop.0),
        }
        let mut remaining = position.qty;
        let mut weighted = Decimal::ZERO;
        for (trigger, qty, whole) in stops {
            let closes = if whole { remaining } else { qty.min(remaining) };
            weighted = weighted.checked_add(closes.checked_mul(trigger)?)?;
            remaining = remaining.checked_sub(closes)?;
            if remaining <= Decimal::ZERO {
                // Rounded towards the looser side: the risk measured from
                // it is never below the real one.
                let strategy = match position.side {
                    Side::Buy => RoundingStrategy::ToNegativeInfinity,
                    Side::Sell => RoundingStrategy::ToPositiveInfinity,
                };
                return weighted
                    .checked_div(position.qty)
                    .map(|average| average.round_dp_with_strategy(12, strategy));
            }
        }
        None
    }

    /// The venue's side for the risk engine: every position with the stop
    /// that covers it, and the mid of every coin.
    pub fn venue_view(&self) -> VenueView {
        let mut view = VenueView::default();
        for position in &self.positions {
            view.positions.push(VenuePosition {
                symbol: Symbol::new(&position.coin),
                side: position.side,
                qty: position.qty,
                entry: position.entry,
                stop: self.covering_stop(&position.coin, &[]),
            });
        }
        for (coin, mid) in &self.mids {
            if *mid > Decimal::ZERO {
                view.marks.insert(Symbol::new(coin), *mid);
            }
        }
        view
    }

    /// Risk and value of the orders that rest and could open positions:
    /// their size times the distance from their limit price to the stop
    /// waiting for them. `Err` with the order's id when one has no stop:
    /// its risk has no bound.
    pub fn resting_entry_exposure(&self) -> Result<Exposure, u64> {
        self.resting_entry_exposure_except(&[])
    }

    /// [`AccountView::resting_entry_exposure`] without the entries in
    /// `except` (about to be cancelled).
    pub fn resting_entry_exposure_except(&self, except: &[u64]) -> Result<Exposure, u64> {
        let mut total = Exposure::default();
        for order in self
            .open_orders
            .iter()
            .filter(|order| order.is_opening() && !except.contains(&order.oid))
        {
            // A trigger that opens a position fills at a price nobody
            // knows in advance: unbounded too.
            let stop = order
                .child_stop()
                .filter(|_| order.trigger.is_none())
                .ok_or(order.oid)?;
            let distance = match order.side {
                Side::Buy => order.limit_px.checked_sub(stop),
                Side::Sell => stop.checked_sub(order.limit_px),
            }
            .ok_or(order.oid)?;
            if distance <= Decimal::ZERO {
                return Err(order.oid);
            }
            let risk = order.qty.checked_mul(distance).ok_or(order.oid)?;
            let notional = order.qty.checked_mul(order.limit_px).ok_or(order.oid)?;
            total = Exposure {
                risk: total.risk.checked_add(risk).ok_or(order.oid)?,
                notional: total.notional.checked_add(notional).ok_or(order.oid)?,
            };
        }
        Ok(total)
    }
}

/// Check the venue's `userRole` answer for `key`: it must be an API wallet
/// (`"agent"`) of `account`. An API wallet can trade but cannot withdraw;
/// the account's own key ("user") can, and is refused, as is a key of
/// another account.
pub fn check_api_wallet_role(answer: &Value, key: Address, account: Address) -> Result<(), String> {
    let role = answer
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let approved_by = answer
        .pointer("/data/user")
        .and_then(Value::as_str)
        .and_then(Address::from_hex);
    if role == "agent" && approved_by == Some(account) {
        return Ok(());
    }
    Err(match (role, approved_by) {
        ("agent", Some(other)) => {
            format!("{key} is an API wallet of {other}, not of the account {account}")
        }
        ("user", _) => format!(
            "{key} is an account's own key, which can withdraw; give Guard an API wallet's key (Hyperliquid app: More > API), never the main wallet's"
        ),
        (role, _) => format!("{key} is not an API wallet of {account} (the venue says: {role})"),
    })
}

/// One dex's `clearinghouseState` answer revalued at newer mark prices,
/// for a snapshot that is a few seconds old (the account stream's).
///
/// The venue values a position at its mark price: `positionValue` is
/// `|szi| × mark` and the unrealized PnL moves by `szi × Δmark` (checked
/// against testnet answers, 6 Oct 2026: `positionValue / |szi|` equals the
/// `markPx` of `metaAndAssetCtxs` exactly). So at a new mark `m` each
/// position moves by `Δ = szi × m − sign(szi) × positionValue`, exactly;
/// the account value moves by the sum of the `Δ`, as the venue's own would.
/// `withdrawable` (the free margin a HIP-3 entry is capped by) moves by
/// the `Δ` and by the margin a cross position ties up at its new value; it
/// is lowered by `2 × Σ |Δ|`, at least that move for any leverage from 1
/// up, and never raised. Each position's `positionValue` and
/// `unrealizedPnl` are updated too.
///
/// `mark` gives the new mark of a coin. An error when a position has no
/// mark or its numbers do not parse: the snapshot cannot be revalued.
pub fn revalue_clearinghouse(
    state: &Value,
    mark: impl Fn(&str) -> Option<Decimal>,
) -> Result<Value, String> {
    const R: &str = "clearinghouseState";
    let text = |value: Decimal| Value::String(value.normalize().to_string());
    let overflow = || "revaluing the account overflows".to_owned();
    let mut out = state.clone();
    let mut moved = Decimal::ZERO;
    let mut moved_abs = Decimal::ZERO;
    let positions = out
        .get_mut("assetPositions")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| bad(R, "no assetPositions").to_string())?;
    for entry in positions {
        let Some(position) = entry.get_mut("position") else {
            return Err(bad(R, "no position").to_string());
        };
        let szi = decimal_str(position.get("szi"), R, "szi").map_err(|e| e.to_string())?;
        if szi == Decimal::ZERO {
            continue;
        }
        let coin = position
            .get("coin")
            .and_then(Value::as_str)
            .ok_or_else(|| bad(R, "a position without a coin").to_string())?
            .to_owned();
        let value = decimal_str(position.get("positionValue"), R, "positionValue")
            .map_err(|e| e.to_string())?;
        let pnl = decimal_str(position.get("unrealizedPnl"), R, "unrealizedPnl")
            .map_err(|e| e.to_string())?;
        let now = mark(&coin).ok_or_else(|| format!("no fresh mark for {coin}"))?;
        let signed_value = if szi > Decimal::ZERO { value } else { -value };
        let delta = szi
            .checked_mul(now)
            .and_then(|at_now| at_now.checked_sub(signed_value))
            .ok_or_else(overflow)?;
        let new_value = szi.abs().checked_mul(now).ok_or_else(overflow)?;
        let new_pnl = pnl.checked_add(delta).ok_or_else(overflow)?;
        position["positionValue"] = text(new_value);
        position["unrealizedPnl"] = text(new_pnl);
        moved = moved.checked_add(delta).ok_or_else(overflow)?;
        moved_abs = moved_abs.checked_add(delta.abs()).ok_or_else(overflow)?;
    }
    let value = decimal_str(
        out.get("marginSummary")
            .and_then(|summary| summary.get("accountValue")),
        R,
        "marginSummary.accountValue",
    )
    .map_err(|e| e.to_string())?;
    out["marginSummary"]["accountValue"] = text(value.checked_add(moved).ok_or_else(overflow)?);
    if let Some(free) = out.get("withdrawable").filter(|free| !free.is_null()) {
        let free = decimal_str(Some(free), R, "withdrawable").map_err(|e| e.to_string())?;
        let lowered = moved_abs
            .checked_mul(Decimal::TWO)
            .and_then(|down| free.checked_sub(down))
            .ok_or_else(overflow)?;
        out["withdrawable"] = text(lowered);
    }
    Ok(out)
}

fn decimal_str(
    value: Option<&Value>,
    request: &'static str,
    what: &str,
) -> Result<Decimal, InfoError> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| bad(request, format!("{what} is not a string")))?;
    Decimal::from_str(text).map_err(|_| bad(request, format!("{what} is not a decimal")))
}

/// The account value, what is withdrawable (when the answer says), and
/// the positions.
type Clearinghouse = (Decimal, Option<Decimal>, Vec<PositionView>);

fn parse_clearinghouse(value: &Value) -> Result<Clearinghouse, InfoError> {
    const R: &str = "clearinghouseState";
    let equity = decimal_str(
        value
            .get("marginSummary")
            .and_then(|summary| summary.get("accountValue")),
        R,
        "marginSummary.accountValue",
    )?;
    let withdrawable = match value.get("withdrawable") {
        None | Some(Value::Null) => None,
        some => Some(decimal_str(some, R, "withdrawable")?),
    };
    let mut positions = Vec::new();
    for entry in value
        .get("assetPositions")
        .and_then(Value::as_array)
        .ok_or_else(|| bad(R, "no assetPositions"))?
    {
        let position = entry.get("position").ok_or_else(|| bad(R, "no position"))?;
        let coin = position
            .get("coin")
            .and_then(Value::as_str)
            .ok_or_else(|| bad(R, "a position without a coin"))?;
        let szi = decimal_str(position.get("szi"), R, "szi")?;
        if szi == Decimal::ZERO {
            continue;
        }
        let leverage = position
            .get("leverage")
            .ok_or_else(|| bad(R, "a position without leverage"))?;
        let isolated = match leverage.get("type").and_then(Value::as_str) {
            Some("isolated") => true,
            // Anything else is not known to be isolated.
            _ => false,
        };
        let value = leverage
            .get("value")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| bad(R, "leverage.value is not a whole number"))?;
        let liquidation_px = match position.get("liquidationPx") {
            None | Some(Value::Null) => None,
            some => Some(decimal_str(some, R, "liquidationPx")?),
        };
        positions.push(PositionView {
            coin: coin.to_owned(),
            side: if szi > Decimal::ZERO {
                Side::Buy
            } else {
                Side::Sell
            },
            qty: szi.abs(),
            entry: decimal_str(position.get("entryPx"), R, "entryPx")?,
            leverage: Leverage { isolated, value },
            liquidation_px,
        });
    }
    Ok((equity, withdrawable, positions))
}

fn parse_order(value: &Value, depth: u32) -> Result<OpenOrderView, InfoError> {
    const R: &str = "frontendOpenOrders";
    let coin = value
        .get("coin")
        .and_then(Value::as_str)
        .ok_or_else(|| bad(R, "an order without a coin"))?;
    let side = match value.get("side").and_then(Value::as_str) {
        Some("B") => Side::Buy,
        Some("A") => Side::Sell,
        _ => return Err(bad(R, "side is not A or B")),
    };
    let is_trigger = value
        .get("isTrigger")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let kind = value.get("orderType").and_then(Value::as_str).unwrap_or("");
    let trigger = if is_trigger {
        let px = decimal_str(value.get("triggerPx"), R, "triggerPx")?;
        // "Stop Market" and "Stop Limit" are stop losses; anything else
        // ("Take Profit …", or a type Guard does not know) is never
        // counted as protection.
        let tpsl = if kind.starts_with("Stop") {
            Tpsl::Sl
        } else {
            Tpsl::Tp
        };
        Some((px, tpsl))
    } else {
        None
    };
    let is_market = kind.ends_with("Market");
    let children = match value.get("children") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(children)) if depth == 0 => children
            .iter()
            .map(|child| parse_order(child, depth + 1))
            .collect::<Result<_, _>>()?,
        // Children of children do not exist; ignore rather than refuse.
        Some(_) if depth > 0 => Vec::new(),
        Some(_) => return Err(bad(R, "children is not an array")),
    };
    Ok(OpenOrderView {
        oid: value
            .get("oid")
            .and_then(Value::as_u64)
            .ok_or_else(|| bad(R, "an order without an oid"))?,
        cloid: value
            .get("cloid")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase),
        coin: coin.to_owned(),
        side,
        qty: decimal_str(value.get("sz"), R, "sz")?,
        limit_px: decimal_str(value.get("limitPx"), R, "limitPx")?,
        reduce_only: value
            .get("reduceOnly")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        trigger,
        is_market,
        is_position_tpsl: value
            .get("isPositionTpsl")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        children,
    })
}

fn parse_open_orders(value: &Value) -> Result<Vec<OpenOrderView>, InfoError> {
    value
        .as_array()
        .ok_or_else(|| bad("frontendOpenOrders", "not an array"))?
        .iter()
        .map(|order| parse_order(order, 0))
        .collect()
}

fn parse_mids(value: &Value) -> Result<HashMap<String, Decimal>, InfoError> {
    let mids = value
        .as_object()
        .ok_or_else(|| bad("allMids", "not an object"))?;
    let mut out = HashMap::with_capacity(mids.len());
    for (coin, mid) in mids {
        out.insert(coin.clone(), decimal_str(Some(mid), "allMids", coin)?);
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use rust_decimal::dec;

    use super::*;

    /// Shapes as the venue answers (Hyperliquid API docs, "Perpetuals" and
    /// "Info endpoint"), trimmed to what Guard reads plus a few fields it
    /// must ignore.
    pub(crate) fn meta_json() -> Value {
        json!({"universe": [
            {"name": "BTC", "szDecimals": 5, "maxLeverage": 40, "marginTableId": 56},
            {"name": "ETH", "szDecimals": 4, "maxLeverage": 25},
            {"name": "SOL", "szDecimals": 2, "maxLeverage": 20},
            {"name": "OLD", "szDecimals": 0, "maxLeverage": 3, "isDelisted": true},
        ]})
    }

    #[test]
    fn an_account_parses_from_the_documented_answers() {
        let clearinghouse = json!({
            "marginSummary": {"accountValue": "2000.5", "totalNtlPos": "3100.0"},
            "assetPositions": [{"type": "oneWay", "position": {
                "coin": "ETH", "szi": "-1.5", "entryPx": "3100.0", "positionValue": "4650",
                "leverage": {"type": "isolated", "value": 3, "rawUsd": "6200"},
                "liquidationPx": "4000.5", "unrealizedPnl": "0"}}],
            "withdrawable": "100", "time": 1
        });
        let orders = json!([
            {"coin": "ETH", "side": "B", "limitPx": "3500", "sz": "1.5", "oid": 7,
             "isTrigger": true, "triggerPx": "3300", "orderType": "Stop Market",
             "reduceOnly": true, "isPositionTpsl": false, "cloid": "0xABC00000000000000000000000000001",
             "children": []},
            {"coin": "BTC", "side": "B", "limitPx": "60000", "sz": "0.01", "oid": 8,
             "isTrigger": false, "triggerPx": "0.0", "orderType": "Limit", "reduceOnly": false,
             "children": [{"coin": "BTC", "side": "A", "limitPx": "53000", "sz": "0.01", "oid": 9,
                           "isTrigger": true, "triggerPx": "58800", "orderType": "Stop Market",
                           "reduceOnly": true, "children": []}]}
        ]);
        let mids = json!({"ETH": "3150.5", "BTC": "61000"});
        let view = AccountView::parse(
            5,
            Meta::parse(&meta_json()).unwrap(),
            &json!("disabled"),
            &clearinghouse,
            &orders,
            &mids,
        )
        .unwrap();
        assert_eq!(view.equity, Some(dec!(2000.5)));
        let eth = view.position("ETH").unwrap();
        assert_eq!(
            (eth.side, eth.qty, eth.entry),
            (Side::Sell, dec!(1.5), dec!(3100))
        );
        assert_eq!(
            eth.leverage,
            Leverage {
                isolated: true,
                value: 3
            }
        );
        assert_eq!(eth.liquidation_px, Some(dec!(4000.5)));
        // The short is covered by the stop at 3300 (a buy of 1.5).
        assert_eq!(view.covering_stop("ETH", &[]), Some(dec!(3300)));
        assert_eq!(view.covering_stop("ETH", &[7]), None);
        assert_eq!(
            view.order_by_cloid("0xabc00000000000000000000000000001")
                .unwrap()
                .oid,
            7
        );
        assert_eq!(view.order_by_oid(9).unwrap().coin, "BTC");
        assert_eq!(view.parent_of(9).unwrap().oid, 8);
        // The resting BTC buy: 0.01 * (60000 - 58800) = 12 at risk, 600 in value.
        assert_eq!(
            view.resting_entry_exposure(),
            Ok(Exposure {
                risk: dec!(12),
                notional: dec!(600)
            })
        );
        let venue = view.venue_view();
        assert_eq!(venue.positions[0].stop, Some(dec!(3300)));
        assert_eq!(venue.marks[&Symbol::new("ETH")], dec!(3150.5));
        // Another account mode leaves the equity unknown.
        let unified = AccountView::parse(
            5,
            Meta::default(),
            &json!("unifiedAccount"),
            &clearinghouse,
            &orders,
            &mids,
        )
        .unwrap();
        assert_eq!(unified.equity, None);
    }

    #[test]
    fn several_stops_cover_a_position_together() {
        // A long of 3: a stop of 1 at 95, one of 2 at 90, one of 5 at 80.
        // Tightest first: 1 closes at 95, 2 at 90; the third is not needed.
        // Loss to the price 100: 1 * 5 + 2 * 10 = 25 = 3 * (100 - 91.666..).
        let stop = |oid, trigger, sz| OpenOrderView {
            oid,
            cloid: None,
            coin: "ETH".into(),
            side: Side::Sell,
            qty: sz,
            limit_px: trigger * dec!(0.9),
            reduce_only: true,
            trigger: Some((trigger, Tpsl::Sl)),
            is_market: true,
            is_position_tpsl: false,
            children: Vec::new(),
        };
        let view = AccountView {
            at_ms: 0,
            equity: Some(dec!(1000)),
            mode: "disabled".into(),
            positions: vec![PositionView {
                coin: "ETH".into(),
                side: Side::Buy,
                qty: dec!(3),
                entry: dec!(100),
                leverage: Leverage {
                    isolated: true,
                    value: 1,
                },
                liquidation_px: None,
            }],
            open_orders: vec![
                stop(1, dec!(90), dec!(2)),
                stop(2, dec!(80), dec!(5)),
                stop(3, dec!(95), dec!(1)),
            ],
            mids: HashMap::new(),
            meta: Meta::default(),
            ..AccountView::default()
        };
        let risk = |average: Decimal| (dec!(100) - average) * dec!(3);
        let average = view.covering_stop("ETH", &[]).unwrap();
        // 275 / 3, rounded down at 12 decimals: never less than 25.
        assert_eq!(average, dec!(91.666666666666));
        assert!(risk(average) >= dec!(25) && risk(average) < dec!(25.000000001));
        // Without the stop at 90: 1 at 95, 2 at 80: 5 + 40 = 45.
        let average = view.covering_stop("ETH", &[1]).unwrap();
        assert!(risk(average) >= dec!(45) && risk(average) < dec!(45.000000001));
        // Without the big one: 1 + 2 cover the 3 exactly.
        assert!(view.covering_stop("ETH", &[2]).is_some());
        // The two small ones alone: 1 + 2 = 3; without 3, only 2 + 0.
        assert!(view.covering_stop("ETH", &[2, 3]).is_none());
        // One more of 1 at 98 in place of the 95.
        let average = view
            .covering_stop_with("ETH", &[3], Some((dec!(98), dec!(1))))
            .unwrap();
        assert!(risk(average) >= dec!(22) && risk(average) < dec!(22.000000001));
    }

    #[test]
    fn a_resting_entry_without_a_stop_is_unbounded() {
        let orders = json!([{"coin": "BTC", "side": "B", "limitPx": "60000", "sz": "0.01", "oid": 8,
            "isTrigger": false, "orderType": "Limit", "reduceOnly": false}]);
        let view = AccountView::parse(
            0,
            Meta::default(),
            &json!("disabled"),
            &json!({"marginSummary": {"accountValue": "100"}, "assetPositions": []}),
            &orders,
            &json!({}),
        )
        .unwrap();
        assert_eq!(view.resting_entry_exposure(), Err(8));
    }

    #[test]
    fn only_an_api_wallet_of_the_account_is_accepted() {
        let key = Address::from_hex("0x14791697260e4c9a71f18484c9f997b308e59325").unwrap();
        let account = Address::from_hex("0x5e9ee1089755c3435139848e47e6635505d5a13a").unwrap();
        let agent = json!({"role": "agent", "data": {"user": account.to_hex()}});
        assert!(check_api_wallet_role(&agent, key, account).is_ok());
        let other = json!({"role": "agent", "data": {"user": key.to_hex()}});
        assert!(check_api_wallet_role(&other, key, account).is_err());
        let user = json!({"role": "user"});
        assert!(
            check_api_wallet_role(&user, key, account)
                .unwrap_err()
                .contains("withdraw")
        );
        assert!(check_api_wallet_role(&json!({"role": "missing"}), key, account).is_err());
    }

    #[test]
    fn numbers_where_strings_belong_are_refused() {
        assert!(
            parse_clearinghouse(
                &json!({"marginSummary": {"accountValue": 2000.5}, "assetPositions": []})
            )
            .is_err()
        );
        assert!(parse_mids(&json!({"BTC": 1.5})).is_err());
        assert!(Meta::parse(&json!({"universe": [{"name": "X", "szDecimals": 7}]})).is_err());
    }

    #[test]
    fn asset_ids_follow_hyperliquids_arithmetic() {
        // "Asset IDs": perps by their index, spot 10000 + index, HIP-3
        // 100000 + 10000 × dex + index (the docs' example: test:ABC, dex 1,
        // index 0, is 110000), outcomes 100000000 + 10 × outcome + side.
        assert_eq!(asset_kind(0), AssetKind::MainPerp);
        assert_eq!(asset_kind(9_999), AssetKind::MainPerp);
        assert_eq!(asset_kind(10_000), AssetKind::Spot);
        assert_eq!(asset_kind(99_999), AssetKind::Spot);
        assert_eq!(asset_kind(100_000), AssetKind::Invalid);
        assert_eq!(asset_kind(109_999), AssetKind::Invalid);
        assert_eq!(asset_kind(110_000), AssetKind::Hip3 { dex: 1 });
        assert_eq!(asset_kind(119_999), AssetKind::Hip3 { dex: 1 });
        assert_eq!(asset_kind(750_003), AssetKind::Hip3 { dex: 65 });
        assert_eq!(asset_kind(99_999_999), AssetKind::Hip3 { dex: 9_989 });
        assert_eq!(asset_kind(100_000_010), AssetKind::Outcome);
        assert_eq!(hip3_asset_id(1, 0), Some(110_000));
        assert_eq!(hip3_asset_id(65, 3), Some(750_003));
        assert_eq!(hip3_asset_id(0, 0), None);
        assert_eq!(hip3_asset_id(1, 10_000), None);
        assert_eq!(hip3_asset_id(9_990, 0), None);
        assert_eq!(MAX_HIP3_DEX_INDEX, 9_989);
    }

    #[test]
    fn a_hip3_meta_carries_its_dex_and_nothing_else() {
        // Shapes as the venue answers `{"type":"meta","dex":"xyz"}`
        // (mainnet, 6 Oct 2026), trimmed.
        let xyz = json!({"universe": [
            {"szDecimals": 4, "name": "xyz:XYZ100", "maxLeverage": 30, "marginTableId": 30,
             "growthMode": "enabled", "deployerFeeScale": "1.0"},
            {"szDecimals": 3, "name": "xyz:HOOD", "maxLeverage": 10, "onlyIsolated": true,
             "marginMode": "noCross"},
            {"szDecimals": 3, "name": "xyz:URANIUM", "maxLeverage": 10, "onlyIsolated": true,
             "isDelisted": true, "marginMode": "strictIsolated"},
        ], "marginTables": [[50, {"description": "", "marginTiers": [
            {"lowerBound": "0.0", "maxLeverage": 50}]}]], "collateralToken": 0});
        let meta = Meta::parse_dex(&xyz, 1, "xyz").unwrap();
        let ids: Vec<u32> = meta.assets.iter().map(|asset| asset.index).collect();
        assert_eq!(ids, vec![110_000, 110_001, 110_002]);
        assert_eq!(meta.assets[0].margin_mode, MarginMode::Any);
        assert_eq!(meta.assets[1].margin_mode, MarginMode::NoCross);
        assert_eq!(meta.assets[2].margin_mode, MarginMode::StrictIsolated);
        assert!(meta.assets[2].delisted);
        assert_eq!(meta.dex(1).unwrap().collateral_token, USDC_TOKEN);
        // Read as another dex's meta, or as the main dex's index: refused.
        assert!(Meta::parse_dex(&xyz, 2, "flx").is_err());
        assert!(Meta::parse_dex(&xyz, 0, "xyz").is_err());
        assert!(Meta::parse_dex(&xyz, 9_990, "xyz").is_err());
        let mut no_collateral = xyz.clone();
        no_collateral
            .as_object_mut()
            .unwrap()
            .remove("collateralToken");
        assert!(Meta::parse_dex(&no_collateral, 1, "xyz").is_err());
        // USDH-margined (token 360, as flx, vntl and km on mainnet).
        let mut usdh = xyz.clone();
        usdh["collateralToken"] = json!(360);
        assert_eq!(
            Meta::parse_dex(&usdh, 1, "xyz")
                .unwrap()
                .dex(1)
                .unwrap()
                .collateral_token,
            360
        );
        // Merged with the main dex: both lists, each id once.
        let mut merged = Meta::parse(&meta_json()).unwrap();
        merged.merge(meta.clone());
        merged.merge(meta);
        assert_eq!(merged.assets.len(), 7);
        assert_eq!(merged.by_index(1).unwrap().name, "ETH");
        assert_eq!(merged.by_index(110_001).unwrap().name, "xyz:HOOD");
        assert_eq!(merged.by_name("xyz:HOOD").unwrap().dex, 1);
        assert_eq!(merged.dexes.len(), 2);
    }

    #[test]
    fn perp_dexs_lists_each_dex_at_its_index() {
        // `{"type":"perpDexs"}`: null for the main dex, then the HIP-3 dexes.
        let answer = json!([null,
            {"name": "xyz", "fullName": "XYZ", "deployer": "0x88806a71d74ad0a510b350545c9ae490912f0888"},
            {"name": "flx", "fullName": "Felix Exchange"}]);
        assert_eq!(
            parse_perp_dexs(&answer).unwrap(),
            vec![(1, "xyz".to_owned()), (2, "flx".to_owned())]
        );
        assert!(parse_perp_dexs(&json!([null, {"fullName": "x"}])).is_err());
    }

    #[test]
    fn several_dexes_merge_into_one_view() {
        let main_meta = Meta::parse(&meta_json()).unwrap();
        let xyz_meta = Meta::parse_dex(
            &json!({"universe": [{"name": "xyz:GOLD", "szDecimals": 4, "maxLeverage": 20}],
                    "collateralToken": 0}),
            1,
            "xyz",
        )
        .unwrap();
        let usdh_meta = Meta::parse_dex(
            &json!({"universe": [{"name": "km:US500", "szDecimals": 2, "maxLeverage": 20}],
                    "collateralToken": 360}),
            5,
            "km",
        )
        .unwrap();
        let state = |value: &str, positions: Value| {
            json!({"marginSummary": {"accountValue": value}, "withdrawable": value,
                   "assetPositions": positions})
        };
        let gold_long = json!([{"type": "oneWay", "position": {"coin": "xyz:GOLD", "szi": "0.5",
            "entryPx": "4000", "leverage": {"type": "isolated", "value": 4}, "liquidationPx": "3100"}}]);
        let main = state("9000", json!([]));
        let xyz = state("1000", gold_long.clone());
        let km = state("500", json!([]));
        let answers = |xyz_mids: &Value, xyz_orders: &Value| {
            vec![
                (
                    main_meta.clone(),
                    main.clone(),
                    json!([]),
                    json!({"BTC": "60000"}),
                ),
                (
                    xyz_meta.clone(),
                    xyz.clone(),
                    xyz_orders.clone(),
                    xyz_mids.clone(),
                ),
                (
                    usdh_meta.clone(),
                    km.clone(),
                    json!([]),
                    json!({"km:US500": "7000"}),
                ),
            ]
        };
        let parse = |parts: &[(Meta, Value, Value, Value)]| {
            let answers: Vec<DexAnswers<'_>> = parts
                .iter()
                .map(|(meta, state, orders, mids)| DexAnswers {
                    meta,
                    clearinghouse: state,
                    open_orders: orders,
                    mids,
                    at_open_interest_cap: None,
                })
                .collect();
            AccountView::parse_dexes(1, &json!("disabled"), &answers)
        };
        let good_mids = json!({"xyz:GOLD": "4000"});
        let view = parse(&answers(&good_mids, &json!([]))).unwrap();
        // 9,000 + 1,000 USDC; the USDH dex's 500 is not summed.
        assert_eq!(view.equity, Some(dec!(10000)));
        assert_eq!(view.dexes.len(), 3);
        assert!(!view.dex_account(5).unwrap().usdc);
        assert_eq!(view.position("xyz:GOLD").unwrap().qty, dec!(0.5));
        assert_eq!(view.mid("xyz:GOLD"), Some(dec!(4000)));
        assert_eq!(view.meta.by_index(150_000).unwrap().name, "km:US500");
        // A coin of another dex in xyz's answers: refused, never booked to
        // the wrong dex.
        assert!(parse(&answers(&json!({"BTC": "1"}), &json!([]))).is_err());
        let stray_order =
            json!([{"coin": "ETH", "side": "B", "limitPx": "1", "sz": "1", "oid": 1}]);
        assert!(parse(&answers(&good_mids, &stray_order)).is_err());
        // The main dex first, each dex once.
        let mut parts = answers(&good_mids, &json!([]));
        parts.swap(0, 1);
        assert!(parse(&parts).is_err());
        let mut parts = answers(&good_mids, &json!([]));
        parts.push(parts[1].clone());
        assert!(parse(&parts).is_err());
    }

    #[test]
    fn a_book_gives_the_depth_a_stop_can_fill_into() {
        // `{"type":"l2Book","coin":"xyz:GOLD"}` on testnet, 6 Oct 2026.
        let answer = json!({"coin": "xyz:GOLD", "time": 1, "levels": [
            [{"px": "4128.5", "sz": "0.05", "n": 1}, {"px": "4124.3", "sz": "0.05", "n": 1},
             {"px": "4123.1", "sz": "0.0097", "n": 1}],
            [{"px": "4136.7", "sz": "0.05", "n": 1}, {"px": "4140.9", "sz": "0.05", "n": 1}]]});
        let book = Book::parse(&answer, "xyz:GOLD").unwrap();
        // A long's stop at 4,125 sells into the bids down to its worst fill:
        // only levels between the two count. To 4,120: 0.05 at 4,124.3 and
        // 0.0097 at 4,123.1; the 0.05 at 4,128.5 trades before it fires.
        assert_eq!(
            book.exit_depth(Side::Buy, dec!(4125), dec!(4120)),
            Some(dec!(0.0597))
        );
        // A short's at 4,137 buys from the asks up to 4,141: 0.05 at 4,140.9.
        assert_eq!(
            book.exit_depth(Side::Sell, dec!(4137), dec!(4141)),
            Some(dec!(0.05))
        );
        assert!(Book::parse(&answer, "xyz:TSLA").is_err());
        assert!(Book::parse(&json!({"coin": "xyz:GOLD", "levels": [[]]}), "xyz:GOLD").is_err());

        // The same coin on mainnet at 2 significant figures (6 Oct 2026,
        // trimmed): bids are rounded down, asks up, to levels 100 wide. A
        // long's stop at 4,057 (2% below 4,139) with its worst fill 3,651:
        // the level at 3,900 holds bids from 3,900 to 3,999 and the one at
        // 3,800 from 3,800 to 3,899, both inside; 4,000 reaches 4,099, above
        // the trigger, and 3,600 starts below the worst fill.
        let aggregated = json!({"coin": "xyz:GOLD", "time": 1, "levels": [
            [{"px": "4100.0", "sz": "3613.7209", "n": 9}, {"px": "4000.0", "sz": "2685.9066", "n": 7},
             {"px": "3900.0", "sz": "337.5271", "n": 3}, {"px": "3800.0", "sz": "315.4942", "n": 2},
             {"px": "3600.0", "sz": "100", "n": 1}],
            [{"px": "4200.0", "sz": "3646.0058", "n": 9}, {"px": "4300.0", "sz": "1005.7605", "n": 4},
             {"px": "4400.0", "sz": "317.1245", "n": 2}, {"px": "4600.0", "sz": "160", "n": 1}]]});
        let book = Book::parse_aggregated(&aggregated, "xyz:GOLD", 2).unwrap();
        assert_eq!(
            book.exit_depth(Side::Buy, dec!(4057), dec!(3651)),
            Some(dec!(653.0213))
        );
        // A short's stop at 4,222 (worst 4,644): the ask level at 4,300
        // holds asks above 4,200, below the trigger; 4,400 (above 4,300) and
        // 4,600 (above 4,500) count: 477.1245.
        assert_eq!(
            book.exit_depth(Side::Sell, dec!(4222), dec!(4644)),
            Some(dec!(477.1245))
        );
        // Just above a power of ten (the review's case, as HBAR at 0.1004
        // shows the venue doing it): a mid of 100.5 read at 3 figures, every
        // level 1.0 wide, also below 100. A long's stop at 99.5, worst fill
        // 89.55: the level at 99 holds bids up to 99.99, above the trigger,
        // so only the 0.4 at 95 counts (6.4 if levels below 100 were taken
        // as 0.1 wide).
        let near_ten = json!({"coin": "X", "time": 1, "levels": [
            [{"px": "100", "sz": "5", "n": 1}, {"px": "99", "sz": "6", "n": 1},
             {"px": "95", "sz": "0.4", "n": 1}],
            [{"px": "101", "sz": "5", "n": 1}]]});
        let book = Book::parse_aggregated(&near_ten, "X", 3).unwrap();
        assert_eq!(
            book.exit_depth(Side::Buy, dec!(99.5), dec!(89.55)),
            Some(dec!(0.4))
        );
        // Just below one (the second review's case, xyz:CL at 88.5, 2
        // figures): the asks run on past 100 at the mid's step of 1, so the
        // step is the best ask's, not the highest's (which would be 10 and
        // count nothing). A long's stop at 86.73, worst fill 78.06: only the
        // 7 at 80 lies wholly between them.
        let below_ten = json!({"coin": "X", "time": 1, "levels": [
            [{"px": "88", "sz": "10", "n": 1}, {"px": "86", "sz": "5", "n": 1},
             {"px": "80", "sz": "7", "n": 1}, {"px": "77", "sz": "100", "n": 1}],
            [{"px": "89", "sz": "1", "n": 1}, {"px": "99", "sz": "1", "n": 1},
             {"px": "100", "sz": "1", "n": 1}, {"px": "108", "sz": "1", "n": 1}]]});
        let book = Book::parse_aggregated(&below_ten, "X", 2).unwrap();
        assert_eq!(
            book.exit_depth(Side::Buy, dec!(86.73), dec!(78.06)),
            Some(dec!(7))
        );
        // An aggregated book without asks: its step is unknown, no depth.
        let one_sided = json!({"coin": "X", "time": 1, "levels": [
            [{"px": "80", "sz": "7", "n": 1}], []]});
        let book = Book::parse_aggregated(&one_sided, "X", 2).unwrap();
        assert_eq!(
            book.exit_depth(Side::Buy, dec!(86.73), dec!(78.06)),
            Some(dec!(0))
        );
        // Read at 2 figures where the price's leading digits are 4 or more,
        // else at 3.
        assert_eq!(book_sig_figs(dec!(4139)), 2);
        assert_eq!(book_sig_figs(dec!(9999)), 2);
        assert_eq!(book_sig_figs(dec!(31000)), 3);
        assert_eq!(book_sig_figs(dec!(1500)), 3);
        assert_eq!(book_sig_figs(dec!(0.0512)), 2);
        assert_eq!(book_sig_figs(dec!(0.0312)), 3);
    }

    #[test]
    fn a_snapshot_is_revalued_at_newer_marks() {
        // A long of 0.16 BTC valued at a mark of 60,000 (9,600) and a short
        // of 0.5 ETH at 3,000 (1,500); account value 1,900, 500 free.
        let state = json!({
            "marginSummary": {"accountValue": "1900"}, "withdrawable": "500",
            "assetPositions": [
                {"position": {"coin": "BTC", "szi": "0.16", "positionValue": "9600",
                    "unrealizedPnl": "16", "entryPx": "59900"}},
                {"position": {"coin": "ETH", "szi": "-0.5", "positionValue": "1500",
                    "unrealizedPnl": "-5", "entryPx": "2990"}},
            ], "time": 1});
        let marks = |coin: &str| match coin {
            "BTC" => Some(dec!(59400)),
            "ETH" => Some(dec!(3030)),
            _ => None,
        };
        let revalued = revalue_clearinghouse(&state, marks).unwrap();
        // BTC 1% lower: 0.16 × 59,400 − 9,600 = 9,504 − 9,600 = −96.
        // ETH 1% higher against the short: −0.5 × 3,030 + 1,500 = −15.
        // Account value 1,900 − 96 − 15 = 1,789; withdrawable 500 −
        // 2 × (96 + 15) = 278.
        assert_eq!(revalued["marginSummary"]["accountValue"], "1789");
        assert_eq!(revalued["withdrawable"], "278");
        let btc = &revalued["assetPositions"][0]["position"];
        assert_eq!(btc["positionValue"], "9504");
        assert_eq!(btc["unrealizedPnl"], "-80");
        let eth = &revalued["assetPositions"][1]["position"];
        assert_eq!(eth["positionValue"], "1515");
        assert_eq!(eth["unrealizedPnl"], "-20");
        // A gain raises the account value but never what is free: BTC at
        // 60,600 is +96, ETH at 2,970 is +15; 1,900 + 111 = 2,011, and
        // withdrawable 500 − 2 × 111 = 278 all the same.
        let up = revalue_clearinghouse(&state, |coin: &str| match coin {
            "BTC" => Some(dec!(60600)),
            "ETH" => Some(dec!(2970)),
            _ => None,
        })
        .unwrap();
        assert_eq!(up["marginSummary"]["accountValue"], "2011");
        assert_eq!(up["withdrawable"], "278");
        // Unchanged marks: unchanged numbers.
        let same = revalue_clearinghouse(&state, |coin: &str| match coin {
            "BTC" => Some(dec!(60000)),
            "ETH" => Some(dec!(3000)),
            _ => None,
        })
        .unwrap();
        assert_eq!(same["marginSummary"]["accountValue"], "1900");
        assert_eq!(same["withdrawable"], "500");
        // A position without a mark, or without its value: no revaluation.
        assert!(revalue_clearinghouse(&state, |_: &str| None).is_err());
        let mut no_value = state.clone();
        no_value["assetPositions"][0]["position"]
            .as_object_mut()
            .unwrap()
            .remove("positionValue");
        assert!(revalue_clearinghouse(&no_value, marks).is_err());
        // No positions: the snapshot as it was.
        let flat = json!({"marginSummary": {"accountValue": "100"}, "withdrawable": "100",
            "assetPositions": []});
        assert_eq!(revalue_clearinghouse(&flat, |_: &str| None).unwrap(), flat);
    }

    #[test]
    fn hip3_fees_follow_the_deployers_fee_scale() {
        // (1 + s) below 1, 2s from 1 up, the most (6) when unknown or out of
        // range (Hyperliquid's documentation, "Fees", HIP-3).
        assert_eq!(hip3_fee_scale(Some(dec!(0))), dec!(1));
        assert_eq!(hip3_fee_scale(Some(dec!(0.5))), dec!(1.5));
        assert_eq!(hip3_fee_scale(Some(dec!(1))), dec!(2));
        assert_eq!(hip3_fee_scale(Some(dec!(3))), dec!(6));
        assert_eq!(hip3_fee_scale(Some(dec!(3.5))), dec!(6));
        assert_eq!(hip3_fee_scale(Some(dec!(-1))), dec!(6));
        assert_eq!(hip3_fee_scale(None), dec!(6));
        assert_eq!(MAX_HIP3_FEE_SCALE, dec!(6));
        // The main dex: 1.
        let main = Meta::parse(&meta_json()).unwrap();
        assert!(
            main.assets
                .iter()
                .all(|asset| asset.fee_scale == Decimal::ONE)
        );
    }

    #[test]
    fn prices_round_to_five_significant_figures_and_the_decimal_limit() {
        let meta = Meta::parse(&meta_json()).unwrap();
        let btc = meta.by_name("BTC").unwrap(); // szDecimals 5: 1 price decimal
        assert_eq!(btc.round_price(dec!(61234.56), false), Some(dec!(61234)));
        assert_eq!(btc.round_price(dec!(61234.56), true), Some(dec!(61235)));
        assert_eq!(btc.round_price(dec!(123456.7), false), Some(dec!(123456)));
        let sol = meta.by_name("SOL").unwrap(); // szDecimals 2: 4 decimals
        assert_eq!(sol.round_price(dec!(150.123456), false), Some(dec!(150.12)));
        assert_eq!(sol.round_price(dec!(1.2345678), true), Some(dec!(1.2346)));
        assert_eq!(sol.round_price(dec!(0), true), None);
        assert_eq!(sol.round_qty_down(dec!(1.239)), dec!(1.23));
        assert_eq!(sol.qty_step(), dec!(0.01));
        assert_eq!(meta.by_index(3).unwrap().max_leverage, 3);
        assert!(meta.by_index(3).unwrap().delisted);
    }
}
