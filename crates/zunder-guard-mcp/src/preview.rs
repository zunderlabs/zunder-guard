// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `preview_order`: what Guard would allow for one entry, **estimated**
//! here because Guard has no preview endpoint yet (`contract.rs`).
//!
//! The estimate uses the real risk engine (`zunder-risk`'s
//! `RiskEngine::size_entry` and `combined_exposure`, never a copy of their
//! arithmetic), Guard's rules from its status (the `zr1_` code), Guard's
//! own state (kill switch, halts) and the account as the venue reports it
//! through Guard. It follows Guard's documented order (`docs/guard.md`, "An
//! entry"). What it cannot see is listed in every result as `not_judged`,
//! and Guard judges every real order again: its verdict wins.
//!
//! When Guard gets a preview endpoint, this module is replaced by a call to
//! it; nothing else in the server depends on how the estimate is made.

use std::collections::HashMap;

use rust_decimal::{Decimal, dec};
use serde::Serialize;
use serde_json::{Value, json};
use zunder_core::{Side, Symbol, Timestamp};
use zunder_risk::{RiskEngine, RiskLimits, SizeRequest, VenuePosition, VenueView, Veto};

use crate::{
    contract::{
        ENTRY_PRICE_BOUND, MIN_NOTIONAL, ROUND_TRIP_COST, RiskStateView, Rules, Status, StopPolicy,
        reason_for,
    },
    schema::{SizeSpec, StopSpec},
    venue::{Account, Market, OpenOrder, effective_stop},
};

/// An entry is refused as absurd when its value exceeds this many times
/// the account's equity: twice the largest leverage any rules code allows.
pub const ABSURD_NOTIONAL_MULTIPLE: Decimal = dec!(200);
/// A limit or stop price this many times away from the mid (either way) is
/// refused as absurd.
pub const ABSURD_PRICE_FACTOR: Decimal = Decimal::TEN;

/// The risk engine's budget vetoes: the estimate may see less room than
/// Guard (it counts open risk more conservatively), so with an explicit
/// size these go to Guard, whose verdict counts. Every other veto is final
/// in `place_order`.
pub const BUDGET_VETOES: [&str; 4] = [
    "open_risk",
    "leverage",
    "below_minimum",
    "unprotected_position",
];

/// The entry being asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRequest {
    pub side: Side,
    pub stop: StopSpec,
    pub size: SizeSpec,
    pub limit_price: Option<Decimal>,
}

/// Everything the estimate reads, fetched through Guard just before.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot<'a> {
    pub status: &'a Status,
    pub rules: &'a Rules,
    pub account: &'a Account,
    pub orders: &'a [OpenOrder],
    pub market: &'a Market,
    pub mids: &'a HashMap<String, Decimal>,
    pub now_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Resize,
    Veto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecidedBy {
    /// Guard's own state (kill switch, halts, journal).
    GuardState,
    /// Guard's policy rules, applied here as Guard documents them.
    GuardPolicy,
    /// `zunder-risk`, run here.
    RiskEngine,
    /// This server's own sanity checks.
    ThisServer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Resized,
    Vetoed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub rule: &'static str,
    pub decided_by: DecidedBy,
    pub status: CheckStatus,
}

/// How the stop was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopSource {
    Explicit,
    /// Guard attaches it; the price is where Guard documents it would go.
    GuardPolicy,
}

/// The estimate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Estimate {
    pub verdict: Verdict,
    pub code: &'static str,
    pub decided_by: DecidedBy,
    /// The rule that bound a resize.
    pub bound_by: Option<&'static str>,
    pub requested_size: Option<Decimal>,
    /// What would be sent and filled at most; `None` on a veto.
    pub allowed_size: Option<Decimal>,
    /// The most the rules allow for this entry and stop.
    pub max_size: Option<Decimal>,
    /// The price the entry is sent at: the limit, or for a market order an
    /// IOC limit at Guard's 0.5% bound from the mid. It is also the worst
    /// fill the size is computed from.
    pub order_price: Option<Decimal>,
    pub mid: Option<Decimal>,
    pub stop_price: Option<Decimal>,
    pub stop_source: StopSource,
    pub notional: Option<Decimal>,
    pub risk_at_stop: Option<Decimal>,
    pub equity: Decimal,
    pub checks: Vec<Check>,
}

/// What every estimate says it did not judge.
pub const NOT_JUDGED: [&str; 4] = [
    "min_liquidation_distance: Guard chooses the isolated leverage when it sends, and may still refuse (liquidation_too_close, no_safe_leverage)",
    "resting entry orders: Guard counts their risk and value; this estimate does not",
    "equity cap: Guard may size from less equity (max_trading_equity_usd), which its status does not show",
    "costs: Guard's fees and slippage are assumed at its defaults, 4.5 + 1 bps per side",
];

struct Builder {
    estimate: Estimate,
}

impl Builder {
    fn pass(&mut self, rule: &'static str, by: DecidedBy) {
        self.estimate.checks.push(Check {
            rule,
            decided_by: by,
            status: CheckStatus::Passed,
        });
    }

    fn veto(mut self, rule: &'static str, by: DecidedBy, code: &'static str) -> Estimate {
        self.estimate.checks.push(Check {
            rule,
            decided_by: by,
            status: CheckStatus::Vetoed,
        });
        self.estimate.verdict = Verdict::Veto;
        self.estimate.code = code;
        self.estimate.decided_by = by;
        self.estimate.allowed_size = None;
        self.estimate.notional = None;
        self.estimate.risk_at_stop = None;
        self.estimate
    }
}

fn engine_code(veto: Veto) -> &'static str {
    match veto {
        Veto::HaltedForDay => "daily_loss_stop",
        Veto::Stopped => "drawdown_halt",
        Veto::StopOnWrongSide => "stop_wrong_side",
        Veto::OpenRiskExhausted => "open_risk",
        Veto::LeverageExhausted => "leverage",
        Veto::BelowMinimum => "below_minimum",
        Veto::InvalidRequest => "invalid",
        Veto::Overflow => "overflow",
        Veto::UnprotectedPosition => "unprotected_position",
    }
}

/// Estimate Guard's verdict on `request`.
pub fn estimate(snapshot: Snapshot<'_>, request: &EntryRequest) -> Estimate {
    let Snapshot {
        status,
        rules,
        account,
        orders: _,
        market,
        mids,
        now_ms,
    } = snapshot;
    let side = request.side;
    let mid = mids.get(&market.name).copied();
    let mut b = Builder {
        estimate: Estimate {
            verdict: Verdict::Allow,
            code: "allowed",
            decided_by: DecidedBy::RiskEngine,
            bound_by: None,
            requested_size: match request.size {
                SizeSpec::Exactly(size) => Some(size),
                SizeSpec::Max => None,
            },
            allowed_size: None,
            max_size: None,
            order_price: None,
            mid,
            stop_price: None,
            stop_source: match request.stop {
                StopSpec::Price(_) => StopSource::Explicit,
                StopSpec::GuardPolicy => StopSource::GuardPolicy,
            },
            notional: None,
            risk_at_stop: None,
            equity: account.equity,
            checks: Vec::new(),
        },
    };

    // 1. Guard's state.
    if status.killed {
        return b.veto("kill_switch", DecidedBy::GuardState, "kill_switch");
    }
    if status.journal_broken {
        return b.veto("decision_journal", DecidedBy::GuardState, "journal");
    }
    match status.risk_state {
        RiskStateView::Active => b.pass("risk_state", DecidedBy::GuardState),
        RiskStateView::HaltedForDay => {
            return b.veto("daily_loss_stop", DecidedBy::GuardState, "daily_loss_stop");
        }
        RiskStateView::Stopped => {
            return b.veto("drawdown_halt", DecidedBy::GuardState, "drawdown_halt");
        }
        RiskStateView::Unknown => {
            return b.veto("risk_state", DecidedBy::GuardState, "not_ready");
        }
    }

    // 2. A listed market, and an account and a price.
    if market.delisted {
        return b.veto("market", DecidedBy::GuardPolicy, "unknown_market");
    }
    if account.equity <= Decimal::ZERO {
        return b.veto("account", DecidedBy::GuardPolicy, "equity_not_positive");
    }
    let Some(mid) = mid else {
        return b.veto("price", DecidedBy::GuardPolicy, "no_price");
    };

    // 3. This server's sanity checks, before anything else is weighed: an
    // absurd price or size is refused, never resized.
    let absurd = |price: Decimal| {
        price < mid / ABSURD_PRICE_FACTOR
            || mid
                .checked_mul(ABSURD_PRICE_FACTOR)
                .is_none_or(|high| price > high)
    };
    let stop_price = match request.stop {
        StopSpec::Price(price) => Some(price),
        StopSpec::GuardPolicy => None,
    };
    if request.limit_price.is_some_and(absurd) || stop_price.is_some_and(absurd) {
        return b.veto("sanity", DecidedBy::ThisServer, "absurd_price");
    }
    if let SizeSpec::Exactly(size) = request.size {
        let price = request.limit_price.unwrap_or(mid).max(mid);
        let value = size.checked_mul(price);
        let limit = account.equity.checked_mul(ABSURD_NOTIONAL_MULTIPLE);
        match (value, limit) {
            (Some(value), Some(limit)) if value <= limit => {}
            _ => return b.veto("sanity", DecidedBy::ThisServer, "absurd_size"),
        }
    }
    b.pass("sanity", DecidedBy::ThisServer);

    // 4. The market allowlist and the position already held.
    if !rules.markets.allows(&market.name) {
        return b.veto(
            "market_allowlist",
            DecidedBy::GuardPolicy,
            "market_not_allowed",
        );
    }
    b.pass("market_allowlist", DecidedBy::GuardPolicy);
    let existing = account
        .positions
        .iter()
        .find(|position| position.coin == market.name);
    if let Some(position) = existing {
        if position.side != side {
            return b.veto("one_direction", DecidedBy::GuardPolicy, "flip");
        }
        if position.leverage_type.as_deref() != Some("isolated") {
            return b.veto("isolated_margin", DecidedBy::GuardPolicy, "cross_margin");
        }
    }

    // 5. The worst fill: the limit, pulled in to 0.5% beyond the mid.
    let Some(entry) = entry_price(market, mid, side, request.limit_price) else {
        return b.veto("price", DecidedBy::ThisServer, "no_price");
    };
    b.estimate.order_price = Some(entry);

    // The stop.
    let stop = match request.stop {
        StopSpec::Price(price) => round_stop(market, side, price),
        StopSpec::GuardPolicy => {
            if rules.stop_policy == StopPolicy::Refuse {
                return b.veto("protective_stop", DecidedBy::GuardPolicy, "stop_required");
            }
            let distance = rules.attach_distance();
            match side {
                Side::Buy => entry
                    .min(mid)
                    .checked_mul(Decimal::ONE - distance)
                    .and_then(|price| market.round_price(price, true)),
                Side::Sell => entry
                    .max(mid)
                    .checked_mul(Decimal::ONE + distance)
                    .and_then(|price| market.round_price(price, false)),
            }
        }
    };
    let Some(stop) = stop else {
        return b.veto("protective_stop", DecidedBy::ThisServer, "invalid");
    };
    b.estimate.stop_price = Some(stop);
    let wrong_side = match side {
        Side::Buy => stop >= mid || stop >= entry,
        Side::Sell => stop <= mid || stop <= entry,
    };
    if wrong_side {
        return b.veto("protective_stop", DecidedBy::GuardPolicy, "stop_wrong_side");
    }
    b.pass("protective_stop", DecidedBy::GuardPolicy);

    // A requested size on the venue's grid.
    let requested = match request.size {
        SizeSpec::Exactly(size) => Some(market.round_qty_down(size)),
        SizeSpec::Max => None,
    };

    // 6. The risk engine: per-trade loss, open risk, leverage.
    let limits = rules.risk_limits();
    let engine_qty = match size_with(&limits, snapshot, side, entry, stop, now_ms) {
        Ok(qty) => qty,
        Err(veto) => {
            let rule = match veto {
                Veto::OpenRiskExhausted | Veto::UnprotectedPosition => "max_open_risk",
                Veto::LeverageExhausted => "max_leverage",
                _ => "max_loss_per_trade",
            };
            return b.veto(rule, DecidedBy::RiskEngine, engine_code(veto));
        }
    };
    b.pass("risk_engine", DecidedBy::RiskEngine);

    // 7. The position cap: the coin's position plus this entry, valued at
    // the higher of the entry and the mid.
    // Checked throughout: the equity and the position come from outside.
    let cap = account
        .equity
        .checked_mul(rules.max_position_pct)
        .and_then(|value| value.checked_div(Decimal::ONE_HUNDRED))
        .and_then(|cap_value| {
            let held = existing.map_or(Some(Decimal::ZERO), |position| {
                position.qty.checked_mul(mid)
            })?;
            cap_value.checked_sub(held)
        })
        .map(|room| {
            if room > Decimal::ZERO {
                room.checked_div(entry.max(mid))
                    .map(|qty| market.round_qty_down(qty))
                    .unwrap_or(Decimal::ZERO)
            } else {
                Decimal::ZERO
            }
        });
    let Some(cap_qty) = cap else {
        return b.veto("sanity", DecidedBy::ThisServer, "overflow");
    };
    if cap_qty <= Decimal::ZERO
        || cap_qty
            .checked_mul(entry)
            .is_none_or(|value| value < MIN_NOTIONAL)
    {
        return b.veto("max_position_size", DecidedBy::GuardPolicy, "position_cap");
    }
    b.pass("max_position_size", DecidedBy::GuardPolicy);

    let (max, bound_by, decided_by) = if cap_qty < engine_qty {
        (cap_qty, "max_position_size", DecidedBy::GuardPolicy)
    } else {
        (
            engine_qty,
            engine_bound(&limits, snapshot, side, entry, stop, engine_qty),
            DecidedBy::RiskEngine,
        )
    };
    b.estimate.max_size = Some(max);

    let allowed = match requested {
        None => max,
        Some(asked) => {
            if asked <= Decimal::ZERO
                || asked
                    .checked_mul(entry)
                    .is_none_or(|value| value < MIN_NOTIONAL)
            {
                return b.veto("venue_minimum", DecidedBy::ThisServer, "below_minimum");
            }
            if asked <= max {
                asked
            } else {
                b.estimate.verdict = Verdict::Resize;
                b.estimate.code = "resized";
                b.estimate.bound_by = Some(bound_by);
                b.estimate.decided_by = decided_by;
                let resized_rule = if decided_by == DecidedBy::GuardPolicy {
                    "max_position_size"
                } else {
                    "risk_engine"
                };
                if let Some(check) = b
                    .estimate
                    .checks
                    .iter_mut()
                    .find(|check| check.rule == resized_rule)
                {
                    check.status = CheckStatus::Resized;
                }
                max
            }
        }
    };
    b.estimate.allowed_size = Some(allowed);
    b.estimate.notional = allowed.checked_mul(entry);
    b.estimate.risk_at_stop = entry
        .checked_sub(stop)
        .zip(entry.checked_mul(ROUND_TRIP_COST))
        .and_then(|(distance, cost)| distance.abs().checked_add(cost))
        .and_then(|per_unit| allowed.checked_mul(per_unit));
    b.estimate
}

/// The price an entry is sent at, which is also its worst fill: a limit
/// pulled in to Guard's bound of 0.5% beyond the mid, or for a market order
/// an IOC limit at that bound; on the venue's grid, rounded towards the mid.
pub fn entry_price(
    market: &Market,
    mid: Decimal,
    side: Side,
    limit: Option<Decimal>,
) -> Option<Decimal> {
    let bound = match side {
        Side::Buy => mid
            .checked_mul(Decimal::ONE + ENTRY_PRICE_BOUND)
            .and_then(|price| market.round_price(price, false))?,
        Side::Sell => mid
            .checked_mul(Decimal::ONE - ENTRY_PRICE_BOUND)
            .and_then(|price| market.round_price(price, true))?,
    };
    match (side, limit) {
        (_, None) => Some(bound),
        (Side::Buy, Some(limit)) => market.round_price(limit.min(bound), false),
        (Side::Sell, Some(limit)) => market.round_price(limit.max(bound), true),
    }
}

/// A stop for a `side` entry on the venue's grid, rounded towards the price:
/// tighter than asked, never looser.
pub fn round_stop(market: &Market, side: Side, stop: Decimal) -> Option<Decimal> {
    market.round_price(stop, side == Side::Buy)
}

/// `RiskEngine::size_entry` on the account as the venue shows it, through
/// `combined_exposure` exactly as Zunder's own trading session does.
fn size_with(
    limits: &RiskLimits,
    snapshot: Snapshot<'_>,
    side: Side,
    entry: Decimal,
    stop: Decimal,
    now_ms: u64,
) -> Result<Decimal, Veto> {
    let account = snapshot.account;
    let now = Timestamp::from_millis(i64::try_from(now_ms).map_err(|_| Veto::Overflow)?);
    let engine =
        RiskEngine::new(limits.clone(), now, account.equity).map_err(|_| Veto::InvalidRequest)?;
    let mut marks = HashMap::new();
    let mut positions = Vec::new();
    for position in &account.positions {
        let Some(mark) = snapshot
            .mids
            .get(&position.coin)
            .copied()
            .or_else(|| position.mark())
        else {
            // A position without a price cannot be bounded.
            return Err(Veto::UnprotectedPosition);
        };
        let symbol = Symbol::new(&position.coin);
        marks.insert(symbol.clone(), mark);
        positions.push(VenuePosition {
            symbol,
            side: position.side,
            qty: position.qty,
            entry: position.entry_price.unwrap_or(mark),
            stop: effective_stop(position, snapshot.orders),
        });
    }
    let view = VenueView { positions, marks };
    let open = engine.combined_exposure(&view)?.exposure;
    engine.size_entry(&SizeRequest {
        equity: account.equity,
        side,
        entry,
        stop,
        round_trip_cost: entry.checked_mul(ROUND_TRIP_COST).ok_or(Veto::Overflow)?,
        open_risk: open.risk,
        open_notional: open.notional,
        qty_step: snapshot.market.qty_step(),
        min_notional: MIN_NOTIONAL,
    })
}

/// Which of the engine's three limits bound `qty`: the engine asked again
/// with one limit opened up, as the website's judge does; never our own
/// arithmetic.
fn engine_bound(
    limits: &RiskLimits,
    snapshot: Snapshot<'_>,
    side: Side,
    entry: Decimal,
    stop: Decimal,
    qty: Decimal,
) -> &'static str {
    let wider = |limits: RiskLimits| {
        size_with(&limits, snapshot, side, entry, stop, snapshot.now_ms)
            .is_ok_and(|wider| wider > qty)
    };
    if wider(RiskLimits {
        max_leverage: Decimal::ONE_HUNDRED,
        ..limits.clone()
    }) {
        "max_leverage"
    } else if wider(RiskLimits {
        max_open_risk: Decimal::ONE,
        ..limits.clone()
    }) {
        "max_open_risk"
    } else {
        "max_loss_per_trade"
    }
}

fn text(value: Option<Decimal>) -> Value {
    value.map_or(Value::Null, |value| {
        Value::String(value.normalize().to_string())
    })
}

impl Estimate {
    pub fn to_json(&self) -> Value {
        let risk_pct = self
            .risk_at_stop
            .filter(|_| self.equity > Decimal::ZERO)
            .and_then(|risk| risk.checked_mul(Decimal::ONE_HUNDRED))
            .and_then(|risk| risk.checked_div(self.equity))
            .map(|pct| pct.round_dp(4));
        json!({
            "estimate": true,
            "verdict": self.verdict,
            "code": self.code,
            "reason": reason_for(self.code),
            "decided_by": self.decided_by,
            "bound_by": self.bound_by,
            "requested_size": text(self.requested_size),
            "allowed_size": text(self.allowed_size),
            "max_size": text(self.max_size),
            "order_price": text(self.order_price),
            "mid_price": text(self.mid),
            "stop_price": text(self.stop_price),
            "stop_source": self.stop_source,
            "notional_usd": text(self.notional),
            "risk_at_stop_usd": text(self.risk_at_stop),
            "risk_at_stop_pct_of_equity": text(risk_pct),
            "equity_usd": text(Some(self.equity)),
            "checks": self.checks,
            "not_judged": NOT_JUDGED,
            "note": "An estimate made by this server with the risk engine and Guard's published rules. Guard judges every real order again, and its verdict wins.",
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{
        contract::{Markets, Mode},
        venue::{parse_account, parse_meta, parse_open_orders},
    };

    fn status() -> Status {
        Status {
            mode: Mode::Testnet,
            account: "0x14791697260e4c9a71f18484c9f997b308e59325".into(),
            killed: false,
            risk_state: RiskStateView::Active,
            journal_ready: true,
            journal_broken: false,
            rules_code: String::new(),
            clients: Vec::new(),
            last_event: 0,
            equity: None,
            version: "test".into(),
        }
    }

    fn rules() -> Rules {
        Rules {
            max_leverage: dec!(5),
            max_loss_at_stop_pct: dec!(2),
            require_stop: true,
            stop_policy: StopPolicy::Attach,
            min_liq_distance_pct: dec!(10),
            max_position_pct: dec!(200),
            max_open_risk_pct: dec!(6),
            daily_loss_stop_pct: dec!(6),
            drawdown_halt_pct: dec!(25),
            markets: Markets::All,
            default_stop_distance_pct: Some(dec!(2)),
        }
    }

    fn btc() -> Market {
        parse_meta(&json!({"universe": [{"name": "BTC", "szDecimals": 5}, {"name": "ETH", "szDecimals": 4}]}))
            .unwrap()
            .remove(0)
    }

    fn mids() -> HashMap<String, Decimal> {
        HashMap::from([("BTC".into(), dec!(60000)), ("ETH".into(), dec!(3000))])
    }

    fn flat() -> Account {
        parse_account(&json!({"marginSummary": {"accountValue": "2000"}, "assetPositions": []}))
            .unwrap()
    }

    fn run(
        status: &Status,
        rules: &Rules,
        account: &Account,
        orders: &[OpenOrder],
        request: EntryRequest,
    ) -> Estimate {
        let market = btc();
        let mids = mids();
        estimate(
            Snapshot {
                status,
                rules,
                account,
                orders,
                market: &market,
                mids: &mids,
                now_ms: 1_791_000_000_000,
            },
            &request,
        )
    }

    fn buy(stop: StopSpec, size: SizeSpec) -> EntryRequest {
        EntryRequest {
            side: Side::Buy,
            stop,
            size,
            limit_price: None,
        }
    }

    /// Equity 2,000, BTC mid 60,000, a market buy with its stop at 58,800.
    /// Worst fill: 60,000 × 1.005 = 60,300. Risk per BTC: 60,300 − 58,800 =
    /// 1,500, plus costs 60,300 × 0.0011 = 66.33: 1,566.33. Budget 2% of
    /// 2,000 = 40. 40 / 1,566.33 = 0.0255372…, down to the 0.00001 step:
    /// 0.02553. Leverage room 10,000 / 60,300 = 0.1658; position cap 4,000 /
    /// 60,300 = 0.0663: neither binds. Risk at the stop: 0.02553 × 1,566.33
    /// = 39.9884049.
    #[test]
    fn a_market_buy_is_sized_from_its_stop() {
        let estimate = run(
            &status(),
            &rules(),
            &flat(),
            &[],
            buy(StopSpec::Price(dec!(58800)), SizeSpec::Exactly(dec!(0.5))),
        );
        assert_eq!(estimate.verdict, Verdict::Resize);
        assert_eq!(estimate.order_price, Some(dec!(60300)));
        assert_eq!(estimate.allowed_size, Some(dec!(0.02553)));
        assert_eq!(estimate.max_size, Some(dec!(0.02553)));
        assert_eq!(estimate.bound_by, Some("max_loss_per_trade"));
        assert_eq!(estimate.risk_at_stop, Some(dec!(39.9884049)));
        assert_eq!(estimate.notional, Some(dec!(1539.459)));
        // A size within the budget is allowed as asked.
        let small = run(
            &status(),
            &rules(),
            &flat(),
            &[],
            buy(StopSpec::Price(dec!(58800)), SizeSpec::Exactly(dec!(0.01))),
        );
        assert_eq!(small.verdict, Verdict::Allow);
        assert_eq!(small.allowed_size, Some(dec!(0.01)));
    }

    /// A market sell with its stop at 61,200: sent at 60,000 × 0.995 =
    /// 59,700; risk per BTC 61,200 − 59,700 = 1,500 plus 59,700 × 0.0011 =
    /// 65.67: 1,565.67. 40 / 1,565.67 = 0.0255481…, down to 0.02554
    /// (0.02555 would risk 40.0029).
    #[test]
    fn a_market_sell_is_sized_from_its_stop() {
        let estimate = run(
            &status(),
            &rules(),
            &flat(),
            &[],
            EntryRequest {
                side: Side::Sell,
                stop: StopSpec::Price(dec!(61200)),
                size: SizeSpec::Max,
                limit_price: None,
            },
        );
        assert_eq!(estimate.verdict, Verdict::Allow);
        assert_eq!(estimate.order_price, Some(dec!(59700)));
        assert_eq!(estimate.allowed_size, Some(dec!(0.02554)));
        // Under attach, a sell's stop goes 2% above the higher of fill and
        // mid: 60,000 × 1.02 = 61,200.
        let attached = run(
            &status(),
            &rules(),
            &flat(),
            &[],
            EntryRequest {
                side: Side::Sell,
                stop: StopSpec::GuardPolicy,
                size: SizeSpec::Max,
                limit_price: None,
            },
        );
        assert_eq!(attached.stop_price, Some(dec!(61200)));
        assert_eq!(attached.allowed_size, Some(dec!(0.02554)));
    }

    /// An account value from outside near `Decimal::MAX` must not panic.
    #[test]
    fn huge_numbers_from_outside_never_panic() {
        let huge = parse_account(&json!({
            "marginSummary": {"accountValue": "79228162514264337593543950335"},
            "assetPositions": []
        }))
        .unwrap();
        let one_x = Rules {
            max_leverage: dec!(1),
            ..rules()
        };
        let estimate = run(
            &status(),
            &one_x,
            &huge,
            &[],
            buy(StopSpec::Price(dec!(58800)), SizeSpec::Max),
        );
        assert_eq!(estimate.verdict, Verdict::Veto);
        let _ = estimate.to_json();
    }

    /// Under `attach`, Guard's stop goes 2% below the lower of the fill
    /// (60,300) and the mid (60,000): 58,800, the same numbers as above.
    #[test]
    fn guard_policy_attaches_or_refuses() {
        let attached = run(
            &status(),
            &rules(),
            &flat(),
            &[],
            buy(StopSpec::GuardPolicy, SizeSpec::Max),
        );
        assert_eq!(attached.verdict, Verdict::Allow);
        assert_eq!(attached.stop_price, Some(dec!(58800)));
        assert_eq!(attached.allowed_size, Some(dec!(0.02553)));
        let refuse = Rules {
            stop_policy: StopPolicy::Refuse,
            ..rules()
        };
        let refused = run(
            &status(),
            &refuse,
            &flat(),
            &[],
            buy(StopSpec::GuardPolicy, SizeSpec::Max),
        );
        assert_eq!(refused.verdict, Verdict::Veto);
        assert_eq!(refused.code, "stop_required");
    }

    /// Position cap 10% of 2,000 = 200; 200 / 60,300 = 0.0033167, down to
    /// 0.00331, worth 199.593 at 60,300.
    #[test]
    fn the_position_cap_binds_before_the_engine() {
        let capped = Rules {
            max_position_pct: dec!(10),
            ..rules()
        };
        let estimate = run(
            &status(),
            &capped,
            &flat(),
            &[],
            buy(StopSpec::Price(dec!(58800)), SizeSpec::Exactly(dec!(0.5))),
        );
        assert_eq!(estimate.verdict, Verdict::Resize);
        assert_eq!(estimate.allowed_size, Some(dec!(0.00331)));
        assert_eq!(estimate.bound_by, Some("max_position_size"));
    }

    #[test]
    fn guard_state_and_policy_veto_first() {
        let killed = Status {
            killed: true,
            ..status()
        };
        let request = || buy(StopSpec::Price(dec!(58800)), SizeSpec::Max);
        assert_eq!(
            run(&killed, &rules(), &flat(), &[], request()).code,
            "kill_switch"
        );
        let halted = Status {
            risk_state: RiskStateView::HaltedForDay,
            ..status()
        };
        assert_eq!(
            run(&halted, &rules(), &flat(), &[], request()).code,
            "daily_loss_stop"
        );
        let stopped = Status {
            risk_state: RiskStateView::Stopped,
            ..status()
        };
        assert_eq!(
            run(&stopped, &rules(), &flat(), &[], request()).code,
            "drawdown_halt"
        );
        let eth_only = Rules {
            markets: Markets::Only(vec!["ETH".into()]),
            ..rules()
        };
        assert_eq!(
            run(&status(), &eth_only, &flat(), &[], request()).code,
            "market_not_allowed"
        );
        // A stop above the price for a buy.
        let wrong = run(
            &status(),
            &rules(),
            &flat(),
            &[],
            buy(StopSpec::Price(dec!(61000)), SizeSpec::Max),
        );
        assert_eq!(wrong.code, "stop_wrong_side");
    }

    #[test]
    fn an_unprotected_position_blocks_every_entry() {
        let account = parse_account(&json!({"marginSummary": {"accountValue": "2000"}, "assetPositions": [
            {"position": {"coin": "ETH", "szi": "0.1", "entryPx": "3000", "positionValue": "300",
              "leverage": {"type": "isolated", "value": 3}}}
        ]}))
        .unwrap();
        let estimate = run(
            &status(),
            &rules(),
            &account,
            &[],
            buy(StopSpec::Price(dec!(58800)), SizeSpec::Max),
        );
        assert_eq!(estimate.code, "unprotected_position");
        assert_eq!(estimate.decided_by, DecidedBy::RiskEngine);
        // With a stop at 2,940 it counts 0.1 × 60 = 6 of open risk: the
        // per-trade budget (40) still binds, at the same size.
        let orders = parse_open_orders(&json!([
            {"coin": "ETH", "side": "A", "limitPx": "2646", "sz": "0.1", "oid": 9, "isTrigger": true,
             "triggerPx": "2940", "orderType": "Stop Market", "reduceOnly": true}
        ]))
        .unwrap();
        let protected = run(
            &status(),
            &rules(),
            &account,
            &orders,
            buy(StopSpec::Price(dec!(58800)), SizeSpec::Max),
        );
        assert_eq!(protected.verdict, Verdict::Allow);
        assert_eq!(protected.allowed_size, Some(dec!(0.02553)));
    }

    #[test]
    fn opposite_and_cross_positions_are_refused() {
        let short = parse_account(
            &json!({"marginSummary": {"accountValue": "2000"}, "assetPositions": [
                {"position": {"coin": "BTC", "szi": "-0.01", "positionValue": "600",
                  "leverage": {"type": "isolated", "value": 3}}}
            ]}),
        )
        .unwrap();
        let request = || buy(StopSpec::Price(dec!(58800)), SizeSpec::Max);
        assert_eq!(
            run(&status(), &rules(), &short, &[], request()).code,
            "flip"
        );
        let cross = parse_account(
            &json!({"marginSummary": {"accountValue": "2000"}, "assetPositions": [
                {"position": {"coin": "BTC", "szi": "0.01", "positionValue": "600",
                  "leverage": {"type": "cross", "value": 3}}}
            ]}),
        )
        .unwrap();
        assert_eq!(
            run(&status(), &rules(), &cross, &[], request()).code,
            "cross_margin"
        );
    }

    #[test]
    fn absurd_sizes_and_prices_are_refused_not_resized() {
        // 1,000,000 BTC at 60,300 is far above 200 × 2,000.
        let huge = run(
            &status(),
            &rules(),
            &flat(),
            &[],
            buy(
                StopSpec::Price(dec!(58800)),
                SizeSpec::Exactly(dec!(1000000)),
            ),
        );
        assert_eq!(huge.code, "absurd_size");
        assert_eq!(huge.decided_by, DecidedBy::ThisServer);
        let far_stop = run(
            &status(),
            &rules(),
            &flat(),
            &[],
            buy(StopSpec::Price(dec!(1)), SizeSpec::Max),
        );
        assert_eq!(far_stop.code, "absurd_price");
        let tiny = run(
            &status(),
            &rules(),
            &flat(),
            &[],
            buy(
                StopSpec::Price(dec!(58800)),
                SizeSpec::Exactly(dec!(0.000001)),
            ),
        );
        assert_eq!(tiny.code, "below_minimum");
    }

    #[test]
    fn a_limit_beyond_the_bound_is_pulled_in() {
        let estimate = run(
            &status(),
            &rules(),
            &flat(),
            &[],
            EntryRequest {
                side: Side::Buy,
                stop: StopSpec::Price(dec!(58800)),
                size: SizeSpec::Max,
                limit_price: Some(dec!(65000)),
            },
        );
        assert_eq!(estimate.order_price, Some(dec!(60300)));
        let resting = run(
            &status(),
            &rules(),
            &flat(),
            &[],
            EntryRequest {
                side: Side::Buy,
                stop: StopSpec::Price(dec!(58800)),
                size: SizeSpec::Max,
                limit_price: Some(dec!(59500.5)),
            },
        );
        // 59,500.5 has six significant figures: down to 59,500.
        assert_eq!(resting.order_price, Some(dec!(59500)));
    }
}
