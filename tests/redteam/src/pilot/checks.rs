// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The pilot client's pure checks: what Guard's status must say before a
//! step may send, the hard caps every planned entry is held to, the hand
//! calculation of an entry's size, and Hyperliquid's price and size
//! rounding. No I/O here, so every rule has a unit test with numbers worked
//! out by hand.

use std::str::FromStr;

use rust_decimal::{Decimal, RoundingStrategy, dec};
use serde_json::{Value, json};

/// The largest equity cap a Guard may report for the pilot to run
/// (300 USD). The pilot's own cap is 200 USD.
pub const MAX_EQUITY_CAP_USD: Decimal = dec!(300);

/// The highest isolated leverage the pilot rules allow (`max_leverage = "3"`).
pub const MAX_LEVERAGE: Decimal = dec!(3);

/// Guard's market stops fill at most this far beyond their trigger
/// (`stop_slippage`, the default 10%). A Guard reporting a wider one is
/// refused: the gap figures below assume 10%.
pub const MAX_STOP_SLIPPAGE: Decimal = dec!(0.10);

/// The oldest the status's last sync may be before a step sends (C7: two
/// sync intervals of 5 s).
pub const MAX_SYNC_AGE_MS: u64 = 10_000;

/// The size every BTC entry asks for: 0.01 BTC, about ten times what the
/// rules allow, so that every entry demonstrates Guard resizing.
pub const REQUEST_SIZE_BTC: Decimal = dec!(0.01);

/// The ETH entry request, about the same value as 0.01 BTC:
/// (0.25 ETH at 3,000 to 5,000 is 750 to
/// 1,250 USDC), so Guard resizes it too.
pub const REQUEST_SIZE_ETH: Decimal = dec!(0.25);

/// The most an entry may ask for, at its limit price. Guard cuts it to the
/// rules; this only bounds what the client ever puts in a request.
pub const MAX_REQUEST_NOTIONAL_USD: Decimal = dec!(2000);

/// The most the HIP-3 probe (H0, expected to be refused) may be worth: it
/// asks for one size step, below the venue's 10 USDC minimum, so even a
/// Guard that let it through could not open anything there.
pub const MAX_HIP3_PROBE_NOTIONAL_USD: Decimal = dec!(10);

/// The coins the client trades. Every asset id comes from `meta` by name.
pub const ALLOWED_COINS: [&str; 2] = ["BTC", "ETH"];

/// Client order ids of the client's own orders start with this ("zp").
pub const CLOID_PREFIX: &str = "0x7a70";

/// Client order ids of Guard's own stops start with this ("zg").
pub const GUARD_STOP_PREFIX: &str = "0x7a67";

/// The pilot's address of Guard: the only one on mainnet.
pub const PILOT_URL: &str = "http://127.0.0.1:8547";

/// Loss and notional caps checked before an entry is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub name: &'static str,
    /// The rules' loss at the stop, as a fraction of the capped equity.
    pub max_loss_at_stop: Decimal,
    /// The most an entry Guard forwards may be worth at its worst price.
    /// With a 200 USDC equity cap, the loss budget and the 2% stop bound it
    /// by construction: 2 / 0.02 = 100 (pilot), 1 / 0.02 = 50 (drill).
    pub max_entry_notional_usd: Decimal,
    /// The most an entry may lose at its stop with fees and slippage both
    /// ways: the loss budget on 200 USDC, plus 1% for rounding.
    pub max_planned_loss_usd: Decimal,
    /// The most an entry may lose if its stop fills at its 10% limit
    /// is at most the notional cap times (2% + 10%).
    pub max_gap_loss_usd: Decimal,
}

/// The pilot rules: 1% at the stop on at most 200 USDC.
pub const PILOT: Frame = Frame {
    name: "pilot",
    max_loss_at_stop: dec!(0.01),
    max_entry_notional_usd: dec!(100),
    max_planned_loss_usd: dec!(2.02),
    max_gap_loss_usd: dec!(12),
};

/// The drill rules: 0.5% at the stop.
pub const DRILL: Frame = Frame {
    name: "drill",
    max_loss_at_stop: dec!(0.005),
    max_entry_notional_usd: dec!(50),
    max_planned_loss_usd: dec!(1.01),
    max_gap_loss_usd: dec!(6),
};

/// The pilot's fixed rules encoded as a rules code.
pub fn pilot_rules() -> Value {
    json!({"v": 1, "maxLeverage": 3, "maxLossAtStopPct": 1, "stopPolicy": "attach",
        "defaultStopDistancePct": 2, "minLiqDistancePct": 15, "maxPositionPct": 100,
        "maxOpenRiskPct": 2, "dailyLossStopPct": 3, "drawdownHaltPct": 10,
        "markets": ["BTC", "ETH"]})
}

/// The drill's rules: the pilot's with `max_loss_at_stop = "0.005"`,
/// `daily_loss_stop = "0.0001"` and `markets = ["BTC"]`.
pub fn drill_rules() -> Value {
    json!({"v": 1, "maxLeverage": 3, "maxLossAtStopPct": 0.5, "stopPolicy": "attach",
        "defaultStopDistancePct": 2, "minLiqDistancePct": 15, "maxPositionPct": 100,
        "maxOpenRiskPct": 2, "dailyLossStopPct": 0.01, "drawdownHaltPct": 10,
        "markets": ["BTC"]})
}

/// Which rules a step requires Guard to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesSet {
    Pilot,
    Drill,
    /// The end check runs against either Guard home.
    PilotOrDrill,
    /// `watch` sends nothing and runs beside both.
    Any,
}

/// The JSON inside a `zr1_` rules code.
pub fn decode_rules(code: &str) -> Option<Value> {
    use base64::Engine as _;
    let body = code.trim().strip_prefix("zr1_")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Whether two rules values are the same: the same keys, numbers equal as
/// decimals (`3` and `3.0` alike), everything else exactly.
pub fn rules_equal(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Number(_), Value::Number(_)) => match (decimal_of(actual), decimal_of(expected)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, value)| b.get(key).is_some_and(|other| rules_equal(value, other)))
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| rules_equal(a, b))
        }
        _ => actual == expected,
    }
}

/// Whether a status's rules code is the one `set` requires; the frame the
/// step's entries are held to.
pub fn rules_frame(code: &str, set: RulesSet) -> Result<Frame, String> {
    let Some(rules) = decode_rules(code) else {
        return Err(format!("Guard's rules code cannot be read: {code}"));
    };
    let pilot = rules_equal(&rules, &pilot_rules());
    let drill = rules_equal(&rules, &drill_rules());
    match set {
        RulesSet::Pilot if pilot => Ok(PILOT),
        RulesSet::Drill if drill => Ok(DRILL),
        RulesSet::PilotOrDrill | RulesSet::Any if pilot => Ok(PILOT),
        RulesSet::PilotOrDrill | RulesSet::Any if drill => Ok(DRILL),
        // `watch` sends nothing: any rules, held to the tighter frame.
        RulesSet::Any => Ok(DRILL),
        RulesSet::Pilot => Err(format!(
            "Guard does not run the pilot's rules: it runs {rules}"
        )),
        RulesSet::Drill => Err(format!(
            "Guard does not run the drill's rules: it runs {rules}"
        )),
        RulesSet::PilotOrDrill => Err(format!(
            "Guard runs neither the pilot's nor the drill's rules: {rules}"
        )),
    }
}

/// A decimal from a JSON string or number.
pub fn decimal_of(value: &Value) -> Option<Decimal> {
    match value {
        Value::String(text) => Decimal::from_str(text.trim()).ok(),
        Value::Number(number) => {
            let text = number.to_string();
            Decimal::from_str(&text)
                .or_else(|_| Decimal::from_scientific(&text))
                .ok()
        }
        _ => None,
    }
}

/// The three modes a Guard runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardMode {
    Paper,
    Testnet,
    Mainnet,
}

impl GuardMode {
    pub fn name(self) -> &'static str {
        match self {
            GuardMode::Paper => "paper",
            GuardMode::Testnet => "testnet",
            GuardMode::Mainnet => "mainnet",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "paper" => Some(GuardMode::Paper),
            "testnet" => Some(GuardMode::Testnet),
            "mainnet" => Some(GuardMode::Mainnet),
            _ => None,
        }
    }

    /// Whether a Guard in this mode sends to a venue.
    pub fn sends(self) -> bool {
        self != GuardMode::Paper
    }
}

/// What a step needs from Guard's status before it may do anything.
#[derive(Debug, Clone)]
pub struct Expect {
    pub mode: GuardMode,
    /// The account named on the command line (`--confirm-account`).
    pub account: String,
    /// The client key's address: Guard must accept it.
    pub client: String,
    pub rules: RulesSet,
}

/// The fee as the status reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fee {
    /// `builder`, `fee_free` or `off`.
    pub mode: String,
    pub builder: Option<String>,
    pub fee_tenths_bp: Option<u64>,
    /// `unchecked`, `approved`, `not_approved`, `refused_by_venue`, ...
    pub approval: Option<String>,
    pub entries_blocked: bool,
    /// Whether order actions holding a trigger carry the builder field
    /// (`BUILDER_ON_TRIGGERS`; off until the testnet experiment).
    pub on_triggers: bool,
}

/// The facts of a status a step works from.
#[derive(Debug, Clone)]
pub struct Facts {
    pub mode: GuardMode,
    pub account: String,
    pub started_at_ms: u64,
    pub killed: Option<String>,
    /// `active`, `halted_for_day` or `stopped`.
    pub risk_state: String,
    pub equity: Option<Decimal>,
    pub equity_cap: Option<Decimal>,
    pub sizing_fee_bps: Decimal,
    pub slippage_bps: Decimal,
    pub stop_slippage: Decimal,
    pub exit_slippage: Decimal,
    /// The HIP-3 dexes Guard manages (name), the main dex left out.
    pub hip3_dexes: Vec<String>,
    pub unmanaged_dexes: usize,
    pub positions: u64,
    pub open_orders: u64,
    pub last_sync_ms: Option<u64>,
    pub last_error: Option<String>,
    pub alerts: Vec<String>,
    pub rules: String,
    pub fee: Fee,
    pub clients: Vec<String>,
    pub last_event: u64,
    pub journal_broken: bool,
}

fn field<'a>(status: &'a Value, pointer: &str) -> Result<&'a Value, String> {
    status
        .pointer(pointer)
        .ok_or_else(|| format!("the status has no {pointer}"))
}

fn decimal_field(status: &Value, pointer: &str) -> Result<Decimal, String> {
    decimal_of(field(status, pointer)?)
        .ok_or_else(|| format!("the status's {pointer} is not a number"))
}

fn optional_decimal(status: &Value, pointer: &str) -> Result<Option<Decimal>, String> {
    match status.pointer(pointer) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => decimal_of(value)
            .map(Some)
            .ok_or_else(|| format!("the status's {pointer} is not a number")),
    }
}

/// Read the facts out of a `/guard/status` answer (schema 1). Fails closed:
/// a field missing or of the wrong shape refuses the step.
pub fn parse_facts(status: &Value) -> Result<Facts, String> {
    if status.get("schema").and_then(Value::as_u64) != Some(1) {
        return Err(format!(
            "the status is not schema 1: {}",
            status.get("schema").unwrap_or(&Value::Null)
        ));
    }
    let text = |pointer: &str| -> Result<String, String> {
        field(status, pointer)?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("the status's {pointer} is not a string"))
    };
    let mode = text("/mode")?;
    let mode = GuardMode::parse(&mode).ok_or_else(|| format!("unknown mode {mode}"))?;
    let strings = |pointer: &str| -> Vec<String> {
        status
            .pointer(pointer)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let fee = field(status, "/fee")?;
    let fee = Fee {
        mode: fee
            .get("mode")
            .and_then(Value::as_str)
            .ok_or("the status's fee has no mode")?
            .to_owned(),
        builder: fee
            .get("address")
            .and_then(Value::as_str)
            .map(str::to_owned),
        fee_tenths_bp: fee.get("fee_tenths_bp").and_then(Value::as_u64),
        approval: fee
            .pointer("/approval/state")
            .and_then(Value::as_str)
            .map(str::to_owned),
        entries_blocked: fee
            .get("entries_blocked")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        on_triggers: fee
            .get("on_triggers")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    };
    Ok(Facts {
        mode,
        account: text("/account")?,
        started_at_ms: field(status, "/started_at_ms")?
            .as_u64()
            .ok_or("the status's started_at_ms is not a number")?,
        killed: status
            .get("killed")
            .and_then(Value::as_str)
            .map(str::to_owned),
        risk_state: text("/risk/state")?,
        equity: optional_decimal(status, "/equity")?,
        equity_cap: optional_decimal(status, "/equity_cap")?,
        sizing_fee_bps: decimal_field(status, "/assumptions/sizing_fee_bps")?,
        slippage_bps: decimal_field(status, "/assumptions/slippage_bps")?,
        stop_slippage: decimal_field(status, "/assumptions/stop_slippage")?,
        exit_slippage: decimal_field(status, "/assumptions/exit_slippage")?,
        hip3_dexes: status
            .get("dexes")
            .and_then(Value::as_array)
            .map(|dexes| {
                dexes
                    .iter()
                    .filter(|dex| dex.get("index").and_then(Value::as_u64).unwrap_or(0) > 0)
                    .filter_map(|dex| dex.get("name").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        unmanaged_dexes: status
            .get("unmanaged_dexes")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        positions: field(status, "/positions")?
            .as_u64()
            .ok_or("the status's positions is not a count")?,
        open_orders: field(status, "/open_orders")?
            .as_u64()
            .ok_or("the status's open_orders is not a count")?,
        last_sync_ms: status.get("last_sync_ms").and_then(Value::as_u64),
        last_error: status
            .get("last_error")
            .and_then(Value::as_str)
            .map(str::to_owned),
        alerts: strings("/alerts"),
        rules: text("/rules")?,
        fee,
        clients: strings("/clients"),
        last_event: status
            .get("last_event")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        journal_broken: status
            .get("journal_broken")
            .and_then(Value::as_bool)
            .ok_or("the status's journal_broken is not a flag")?,
    })
}

/// Every step first checks these prerequisites: the mode, the
/// account, the equity cap, the rules, the client, an intact journal. The
/// frame the step's entries are held to.
pub fn check_status(facts: &Facts, expect: &Expect) -> Result<Frame, String> {
    if facts.mode != expect.mode {
        return Err(format!(
            "Guard runs in {} mode, not {} (--expect-mode)",
            facts.mode.name(),
            expect.mode.name()
        ));
    }
    if !facts.account.eq_ignore_ascii_case(&expect.account) {
        return Err(format!(
            "Guard trades account {}, not {} (--confirm-account)",
            facts.account, expect.account
        ));
    }
    match facts.equity_cap {
        None => {
            return Err("Guard runs without an equity cap; the pilot's is 200".to_owned());
        }
        Some(cap) if cap > MAX_EQUITY_CAP_USD || cap <= Decimal::ZERO => {
            return Err(format!(
                "Guard's equity cap is {cap}; the pilot runs only with a cap of at most {MAX_EQUITY_CAP_USD}"
            ));
        }
        Some(_) => {}
    }
    let frame = rules_frame(&facts.rules, expect.rules)?;
    if !facts
        .clients
        .iter()
        .any(|client| client.eq_ignore_ascii_case(&expect.client))
    {
        return Err(format!(
            "Guard does not accept this client key ({}); its clients are {:?}",
            expect.client, facts.clients
        ));
    }
    if facts.journal_broken {
        return Err("Guard's decision journal is broken (abort rule)".to_owned());
    }
    if facts.stop_slippage > MAX_STOP_SLIPPAGE {
        return Err(format!(
            "Guard's stop slippage is {}; the pilot's figures assume at most {MAX_STOP_SLIPPAGE}",
            facts.stop_slippage
        ));
    }
    Ok(frame)
}

/// `price` rounded as Hyperliquid accepts a perp price: at most five
/// significant figures and at most `6 - sz_decimals` decimals (an integer
/// price is always accepted). Up or down, as the caller needs it.
pub fn round_price(price: Decimal, sz_decimals: u32, up: bool) -> Decimal {
    let strategy = if up {
        RoundingStrategy::AwayFromZero
    } else {
        RoundingStrategy::ToZero
    };
    let max_decimals = 6u32.saturating_sub(sz_decimals);
    let integer_digits = {
        let whole = price.trunc().abs();
        if whole.is_zero() {
            0
        } else {
            whole.to_string().len() as u32
        }
    };
    let decimals = if integer_digits >= 5 {
        0
    } else if integer_digits > 0 {
        (5 - integer_digits).min(max_decimals)
    } else {
        // Below 1: five significant figures after the leading zeros.
        let mut leading = 0u32;
        let mut scaled = price.abs();
        while !scaled.is_zero() && scaled < Decimal::ONE && leading < 28 {
            scaled *= Decimal::TEN;
            leading += 1;
        }
        (leading + 4).min(max_decimals)
    };
    price.round_dp_with_strategy(decimals, strategy).normalize()
}

/// `size` rounded down to the coin's size step.
pub fn round_size_down(size: Decimal, sz_decimals: u32) -> Decimal {
    size.round_dp_with_strategy(sz_decimals, RoundingStrategy::ToZero)
        .normalize()
}

/// One size step of a coin: `10^-sz_decimals`.
pub fn size_step(sz_decimals: u32) -> Decimal {
    Decimal::new(1, sz_decimals)
}

/// The hand calculation of an entry's size (`RiskEngine::size_entry` is the
/// reference): the
/// budget is the loss at the stop on the smaller of the equity and the cap;
/// the risk per unit is the distance to the stop plus fees and slippage on
/// both sides at the worst price; rounded down to the size step.
pub fn hand_size(
    equity: Decimal,
    cap: Decimal,
    max_loss_at_stop: Decimal,
    worst: Decimal,
    stop: Decimal,
    cost_bps_per_side: Decimal,
    sz_decimals: u32,
) -> Option<Decimal> {
    let budget = equity.min(cap).checked_mul(max_loss_at_stop)?;
    let costs = Decimal::TWO
        .checked_mul(cost_bps_per_side)?
        .checked_div(dec!(10000))?
        .checked_mul(worst)?;
    let per_unit = worst.checked_sub(stop)?.checked_add(costs)?;
    if per_unit <= Decimal::ZERO {
        return None;
    }
    Some(round_size_down(budget.checked_div(per_unit)?, sz_decimals))
}

/// What a previewed entry risks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRisk {
    pub coin: String,
    pub size: Decimal,
    pub worst: Decimal,
    pub stop: Decimal,
    pub notional: Decimal,
    /// The loss at the stop, with fees and slippage both ways.
    pub planned_loss: Decimal,
    /// The loss if the stop fills at its limit (`stop_slippage` beyond).
    pub gap_loss: Decimal,
}

/// Hold a long entry Guard would forward (the preview's `entry`) to the
/// frame's caps. Every refusal says which cap.
pub fn assess_long_entry(entry: &Value, facts: &Facts, frame: &Frame) -> Result<EntryRisk, String> {
    let coin = entry
        .get("coin")
        .and_then(Value::as_str)
        .ok_or("the preview's entry names no coin")?;
    if !ALLOWED_COINS.contains(&coin) {
        return Err(format!(
            "the entry is on {coin}; the pilot trades BTC and ETH only"
        ));
    }
    if entry.get("side").and_then(Value::as_str) != Some("buy") {
        return Err(format!(
            "the entry is not a buy: {}",
            entry.get("side").unwrap_or(&Value::Null)
        ));
    }
    let number = |key: &str| {
        entry
            .get(key)
            .and_then(decimal_of)
            .ok_or_else(|| format!("the preview's entry has no {key}"))
    };
    let size = number("size")?;
    let requested = number("requested_size")?;
    let worst = number("worst_price")?;
    let stop = number("stop")?;
    if size <= Decimal::ZERO || size > requested {
        return Err(format!(
            "the entry's size {size} is not between 0 and the size asked, {requested}"
        ));
    }
    if stop <= Decimal::ZERO || stop >= worst {
        return Err(format!(
            "the entry's stop {stop} is not below its worst price {worst}"
        ));
    }
    match entry.get("leverage") {
        Some(number @ Value::Number(_)) => {
            let leverage = decimal_of(number).ok_or("the entry's leverage is not a number")?;
            if leverage < Decimal::ONE || leverage > MAX_LEVERAGE {
                return Err(format!(
                    "the entry would run at {leverage}x; the pilot allows 1x to {MAX_LEVERAGE}x"
                ));
            }
        }
        // An entry on a new position always gets Guard's isolated leverage.
        other => {
            return Err(format!(
                "the entry carries no isolated leverage: {}",
                other.unwrap_or(&Value::Null)
            ));
        }
    }
    let notional = size * worst;
    let costs = Decimal::TWO * (facts.sizing_fee_bps + facts.slippage_bps) / dec!(10000) * worst;
    let planned_loss = size * (worst - stop + costs);
    let gap_loss = size * (worst - stop * (Decimal::ONE - facts.stop_slippage));
    if notional > frame.max_entry_notional_usd {
        return Err(format!(
            "the entry would be worth {} USDC; the {} cap is {}",
            notional.round_dp(2),
            frame.name,
            frame.max_entry_notional_usd
        ));
    }
    if planned_loss > frame.max_planned_loss_usd {
        return Err(format!(
            "the entry would lose {} USDC at its stop; the {} cap is {}",
            planned_loss.round_dp(4),
            frame.name,
            frame.max_planned_loss_usd
        ));
    }
    if gap_loss > frame.max_gap_loss_usd {
        return Err(format!(
            "the entry would lose {} USDC with its stop filled at its limit; the {} cap is {}",
            gap_loss.round_dp(4),
            frame.name,
            frame.max_gap_loss_usd
        ));
    }
    Ok(EntryRisk {
        coin: coin.to_owned(),
        size,
        worst,
        stop,
        notional,
        planned_loss,
        gap_loss,
    })
}

/// Hold an order the client is about to put in a request to the client's
/// own caps: BTC or ETH (the HIP-3 probe aside), at most the step's asked
/// size, at most [`MAX_REQUEST_NOTIONAL_USD`] at its price.
pub fn check_request(coin: &str, size: Decimal, price: Decimal) -> Result<(), String> {
    let most = match coin {
        "BTC" => REQUEST_SIZE_BTC,
        "ETH" => REQUEST_SIZE_ETH,
        other => return Err(format!("{other} is not a pilot market (BTC and ETH only)")),
    };
    if size <= Decimal::ZERO || size > most {
        return Err(format!("{size} {coin} is outside (0, {most}]"));
    }
    if size * price > MAX_REQUEST_NOTIONAL_USD {
        return Err(format!(
            "{size} {coin} at {price} is worth more than {MAX_REQUEST_NOTIONAL_USD} USDC"
        ));
    }
    Ok(())
}

/// Whether the URL is the plain-HTTP loopback address Guard listens on.
pub fn loopback_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    // A user part (`127.0.0.1:1@elsewhere`) would send the request to the
    // host after the `@`.
    if host.contains('@') || host.contains('\\') {
        return false;
    }
    let name = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next().map(|inner| format!("[{inner}]"))
    } else {
        host.split(':').next().map(str::to_owned)
    };
    matches!(
        name.as_deref(),
        Some("127.0.0.1") | Some("localhost") | Some("[::1]")
    )
}

/// Whether `text` is an address: `0x` and 40 hex digits.
pub fn is_address(text: &str) -> bool {
    text.strip_prefix("0x")
        .is_some_and(|digits| digits.len() == 40 && digits.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
    const CLIENT: &str = "0x14791697260e4c9a71f18484c9f997b308e59325";

    fn code_of(rules: &Value) -> String {
        use base64::Engine as _;
        format!(
            "zr1_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rules.to_string())
        )
    }

    fn status() -> Value {
        json!({
            "schema": 1, "mode": "mainnet", "account": ACCOUNT, "started_at_ms": 1_000,
            "killed": null, "risk": {"state": "active"}, "equity_cap": "200", "equity": "201.5",
            "assumptions": {"fee_bps": "4.5", "sizing_fee_bps": "6.5", "slippage_bps": "1",
                "stop_slippage": "0.10", "exit_slippage": "0.05"},
            "dexes": [{"index": 0, "name": ""}], "unmanaged_dexes": [],
            "positions": 0, "open_orders": 0, "last_sync_ms": 2_000, "last_error": null,
            "alert": null, "alerts": [], "rules": code_of(&pilot_rules()),
            "fee": {"mode": "builder", "address": "0xbb", "fee_tenths_bp": 20,
                "approval": {"state": "not_approved"}, "entries_blocked": true},
            "clients": [CLIENT], "last_event": 7, "journal_broken": false,
        })
    }

    fn expect(mode: GuardMode) -> Expect {
        Expect {
            mode,
            account: ACCOUNT.to_owned(),
            client: CLIENT.to_owned(),
            rules: RulesSet::Pilot,
        }
    }

    #[test]
    fn a_pilot_status_passes_and_reads_its_facts() {
        let facts = parse_facts(&status()).unwrap();
        assert_eq!(facts.mode, GuardMode::Mainnet);
        assert_eq!(facts.equity, Some(dec!(201.5)));
        assert_eq!(facts.fee.approval.as_deref(), Some("not_approved"));
        assert!(facts.fee.entries_blocked);
        assert_eq!(check_status(&facts, &expect(GuardMode::Mainnet)), Ok(PILOT));
        // The account is compared without regard to case.
        let mut upper = expect(GuardMode::Mainnet);
        upper.account = ACCOUNT.to_uppercase().replace("0X", "0x");
        assert!(check_status(&facts, &upper).is_ok());
    }

    #[test]
    fn the_status_refuses_a_wrong_mode_account_cap_rules_client_or_journal() {
        let facts = parse_facts(&status()).unwrap();
        assert!(
            check_status(&facts, &expect(GuardMode::Testnet))
                .unwrap_err()
                .contains("not testnet")
        );
        let mut other = expect(GuardMode::Mainnet);
        other.account = "0x0000000000000000000000000000000000000001".to_owned();
        assert!(
            check_status(&facts, &other)
                .unwrap_err()
                .contains("--confirm-account")
        );
        let mut stranger = expect(GuardMode::Mainnet);
        stranger.client = "0x0000000000000000000000000000000000000002".to_owned();
        assert!(
            check_status(&facts, &stranger)
                .unwrap_err()
                .contains("client")
        );

        for (pointer, value, says) in [
            ("/equity_cap", json!("300.01"), "equity cap"),
            ("/equity_cap", json!(null), "without an equity cap"),
            ("/journal_broken", json!(true), "broken"),
            ("/assumptions/stop_slippage", json!("0.15"), "stop slippage"),
            ("/rules", json!(code_of(&drill_rules())), "pilot's rules"),
        ] {
            let mut changed = status();
            *changed.pointer_mut(pointer).unwrap() = value;
            let facts = parse_facts(&changed).unwrap();
            let refusal = check_status(&facts, &expect(GuardMode::Mainnet)).unwrap_err();
            assert!(refusal.contains(says), "{pointer}: {refusal}");
        }
        // A cap of exactly 300 is the most allowed.
        let mut at_most = status();
        at_most["equity_cap"] = json!("300");
        assert!(check_status(&parse_facts(&at_most).unwrap(), &expect(GuardMode::Mainnet)).is_ok());
        // A status of another schema, or without a field, is refused.
        let mut old = status();
        old["schema"] = json!(2);
        assert!(parse_facts(&old).is_err());
        let mut missing = status();
        missing.as_object_mut().unwrap().remove("journal_broken");
        assert!(parse_facts(&missing).is_err());
    }

    #[test]
    fn the_rules_sets_pick_the_pilot_or_the_drill() {
        let pilot = code_of(&pilot_rules());
        let drill = code_of(&drill_rules());
        assert_eq!(rules_frame(&pilot, RulesSet::Pilot), Ok(PILOT));
        assert_eq!(rules_frame(&drill, RulesSet::Drill), Ok(DRILL));
        assert!(rules_frame(&pilot, RulesSet::Drill).is_err());
        assert!(rules_frame(&drill, RulesSet::Pilot).is_err());
        assert_eq!(rules_frame(&drill, RulesSet::PilotOrDrill), Ok(DRILL));
        // Numbers compare as decimals: 3.0 is 3, 0.50 is 0.5.
        let mut written = drill_rules();
        written["maxLeverage"] = json!(3.0);
        written["maxLossAtStopPct"] = json!(0.50);
        assert_eq!(rules_frame(&code_of(&written), RulesSet::Drill), Ok(DRILL));
        // One rule off, one market more, or a field more: not the pilot's.
        for (key, value) in [
            ("maxLossAtStopPct", json!(1.5)),
            ("markets", json!(["BTC", "ETH", "SOL"])),
            ("extra", json!(1)),
        ] {
            let mut rules = pilot_rules();
            rules[key] = value;
            assert!(
                rules_frame(&code_of(&rules), RulesSet::Pilot).is_err(),
                "{key}"
            );
        }
        assert!(rules_frame("zr1_!!", RulesSet::Pilot).is_err());
        assert!(rules_frame("zr2_e30", RulesSet::Any).is_err());
        // watch: anything readable, held to the tighter frame.
        assert_eq!(
            rules_frame(&code_of(&json!({"v": 1})), RulesSet::Any),
            Ok(DRILL)
        );
    }

    #[test]
    fn prices_round_to_five_significant_figures_and_the_decimals_allowed() {
        // BTC (5 size decimals): integers above 10,000.
        assert_eq!(round_price(dec!(63000.4), 5, true), dec!(63001));
        assert_eq!(round_price(dec!(63000.4), 5, false), dec!(63000));
        assert_eq!(round_price(dec!(105123.7), 5, false), dec!(105123));
        // ETH (4 size decimals): at most 2 decimals, 5 figures: 2566.62 -> 2566.6.
        assert_eq!(round_price(dec!(2566.62), 4, false), dec!(2566.6));
        assert_eq!(round_price(dec!(2851.8), 4, false), dec!(2851.8));
        assert_eq!(round_price(dec!(2851.81), 4, true), dec!(2851.9));
        // A coin of 2 size decimals at 4.12345: 4 decimals, 5 figures -> 4.1234.
        assert_eq!(round_price(dec!(4.12345), 2, false), dec!(4.1234));
        // Below 1 with 0 size decimals: 0.0123456 -> 0.012345 (6 decimals).
        assert_eq!(round_price(dec!(0.0123456), 0, false), dec!(0.012345));
        assert_eq!(round_size_down(dec!(0.0012769), 5), dec!(0.00127));
        assert_eq!(size_step(5), dec!(0.00001));
    }

    #[test]
    fn the_hand_calculation_matches_the_runbook() {
        // Hand calculation: 200 USDC, 1%, mid 100,000: worst 100,500,
        // stop 98,000, 7.5 bp a side: 2 / (2,500 + 150.75) = 0.0007545 -> 0.00075.
        assert_eq!(
            hand_size(
                dec!(200),
                dec!(200),
                dec!(0.01),
                dec!(100500),
                dec!(98000),
                dec!(7.5),
                5
            ),
            Some(dec!(0.00075))
        );
        // A larger account is held to the cap: the same size.
        assert_eq!(
            hand_size(
                dec!(9000),
                dec!(200),
                dec!(0.01),
                dec!(100500),
                dec!(98000),
                dec!(7.5),
                5
            ),
            Some(dec!(0.00075))
        );
        // The in-memory venue: mid 60,000, worst 60,300, stop 58,800, fee off
        // (4.5 + 1 bp): 2 / (1,500 + 66.33) = 0.0012769 -> 0.00127.
        assert_eq!(
            hand_size(
                dec!(200),
                dec!(200),
                dec!(0.01),
                dec!(60300),
                dec!(58800),
                dec!(5.5),
                5
            ),
            Some(dec!(0.00127))
        );
        // A stop above the price sizes nothing.
        assert_eq!(
            hand_size(
                dec!(200),
                dec!(200),
                dec!(0.01),
                dec!(100),
                dec!(101),
                dec!(5.5),
                5
            ),
            None
        );
    }

    fn entry(size: &str, worst: &str, stop: &str, leverage: Value) -> Value {
        json!({"coin": "BTC", "side": "buy", "requested_size": "0.01", "size": size,
            "worst_price": worst, "stop": stop, "leverage": leverage})
    }

    #[test]
    fn an_entry_within_the_caps_is_assessed_by_hand() {
        let facts = parse_facts(&status()).unwrap();
        // 0.00127 BTC at 60,300 with its stop at 58,800, 6.5 + 1 bp a side:
        // notional 76.581; loss at the stop 0.00127 x (1,500 + 90.45)
        // = 2.0198715; at the stop's 10% limit 0.00127 x (60,300 - 52,920)
        // = 9.3726.
        let risk = assess_long_entry(
            &entry("0.00127", "60300", "58800", json!(3)),
            &facts,
            &PILOT,
        )
        .unwrap();
        assert_eq!(risk.notional, dec!(76.581));
        assert_eq!(risk.planned_loss, dec!(2.0198715));
        assert_eq!(risk.gap_loss, dec!(9.3726));
    }

    #[test]
    fn an_entry_beyond_any_cap_is_refused() {
        let facts = parse_facts(&status()).unwrap();
        // The gap cap alone: the pilot's notional and loss caps, the drill's
        // gap cap of 6.
        let gap_only = Frame {
            max_gap_loss_usd: dec!(6),
            ..PILOT
        };
        for (value, frame, says) in [
            // 0.002 BTC at 60,300 is 120.6 USDC.
            (
                entry("0.002", "60300", "58800", json!(3)),
                PILOT,
                "worth 120.6",
            ),
            (entry("0.00127", "60300", "58800", json!(5)), PILOT, "5x"),
            (
                entry("0.00127", "60300", "58800", Value::Null),
                PILOT,
                "no isolated leverage",
            ),
            (
                entry("0.00127", "60300", "61000", json!(3)),
                PILOT,
                "not below",
            ),
            (
                entry("0.02", "60300", "58800", json!(3)),
                PILOT,
                "between 0",
            ),
            // A tight stop: 0.0016 BTC at 60,300 (96.48 USDC) with its stop
            // at 59,700: loss at the stop 0.0016 x (600 + 90.45) = 1.10472;
            // at the stop's 10% limit 0.0016 x (60,300 - 53,730) = 10.512 > 6.
            (
                entry("0.0016", "60300", "59700", json!(3)),
                gap_only,
                "filled at its limit",
            ),
        ] {
            let refusal = assess_long_entry(&value, &facts, &frame).unwrap_err();
            assert!(refusal.contains(says), "{says}: {refusal}");
        }
        // The drill: 0.00063 BTC (37.99 USDC; loss at the stop 0.00063 x
        // 1,590.45 = 1.002; gap 0.00063 x 7,380 = 4.65) passes, 0.00127 does not.
        assert!(
            assess_long_entry(
                &entry("0.00063", "60300", "58800", json!(3)),
                &facts,
                &DRILL
            )
            .is_ok()
        );
        assert!(
            assess_long_entry(
                &entry("0.00127", "60300", "58800", json!(3)),
                &facts,
                &DRILL
            )
            .unwrap_err()
            .contains("drill cap is 50")
        );
        let mut sol = entry("0.00127", "60300", "58800", json!(3));
        sol["coin"] = json!("SOL");
        assert!(
            assess_long_entry(&sol, &facts, &PILOT)
                .unwrap_err()
                .contains("BTC and ETH")
        );
        let mut short = entry("0.00127", "60300", "58800", json!(3));
        short["side"] = json!("sell");
        assert!(
            assess_long_entry(&short, &facts, &PILOT)
                .unwrap_err()
                .contains("not a buy")
        );
    }

    #[test]
    fn requests_are_held_to_the_client_caps() {
        assert!(check_request("BTC", dec!(0.01), dec!(105000)).is_ok());
        assert!(check_request("BTC", dec!(0.011), dec!(60000)).is_err());
        // 0.01 BTC at 210,000 is 2,100 USDC.
        assert!(check_request("BTC", dec!(0.01), dec!(210000)).is_err());
        assert!(check_request("ETH", dec!(0.25), dec!(4000)).is_ok());
        assert!(check_request("ETH", dec!(0.3), dec!(4000)).is_err());
        assert!(check_request("SOL", dec!(1), dec!(150)).is_err());
        assert!(check_request("BTC", dec!(0), dec!(60000)).is_err());
    }

    #[test]
    fn only_plain_http_on_loopback_is_guard() {
        assert!(loopback_url("http://127.0.0.1:8547"));
        assert!(loopback_url("http://localhost:9000/"));
        assert!(loopback_url("http://[::1]:8547"));
        assert!(!loopback_url("https://127.0.0.1:8547"));
        assert!(!loopback_url("http://10.0.0.5:8547"));
        assert!(!loopback_url("http://127.0.0.1.evil.example:8547"));
        // A user part sends the request to the host after the `@`.
        assert!(!loopback_url("http://127.0.0.1:1@evil.example:8547"));
        assert!(!loopback_url("http://localhost@evil.example"));
        assert!(loopback_url("http://127.0.0.1:8547/?x=1"));
        assert!(!loopback_url("http://api.hyperliquid.xyz"));
        assert!(is_address(ACCOUNT));
        assert!(!is_address("0x5e9e"));
    }
}
