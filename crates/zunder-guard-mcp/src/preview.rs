// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `preview_order`: what Guard would decide about one entry, asked of Guard
//! itself (`POST /guard/preview`), never estimated here.
//!
//! Guard's preview runs the same judgement as its `/exchange` on the exact
//! action this server would send, from the background sync's last view of
//! the account (at most 60 s old), and journals, sends and consumes
//! nothing. This module builds what is asked and shows what Guard
//! answered; the arithmetic of the rules lives in Guard alone. `place_order`
//! asks the same question first and sends nothing that Guard's preview
//! vetoes.
//!
//! What stays here: the price an entry is sent at (Guard's bound from the
//! mid), stops on the venue's grid rounded towards the price, the size
//! asked for `max`, and this server's sanity bound on absurd prices and
//! sizes, which are refused before Guard is asked.

use rust_decimal::{Decimal, dec};
use serde::Serialize;
use serde_json::{Value, json};
use zunder_core::Side;
use zunder_venue_types::{passive, toward_position};

use crate::{
    contract::{ENTRY_PRICE_BOUND, GuardPreview, ROUND_TRIP_COST, reason_for},
    schema::{SizeSpec, StopSpec},
    sign::Tif,
    venue::Market,
};

/// An entry is refused as absurd when its value exceeds this many times
/// the account's equity: twice the largest leverage any rules code allows.
pub const ABSURD_NOTIONAL_MULTIPLE: Decimal = dec!(200);
/// A limit or stop price this many times away from the mid (either way) is
/// refused as absurd.
pub const ABSURD_PRICE_FACTOR: Decimal = Decimal::TEN;

/// The entry being asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRequest {
    pub side: Side,
    pub stop: StopSpec,
    pub size: SizeSpec,
    pub limit_price: Option<Decimal>,
    /// Only `Some(Ioc)` is accepted from callers, with an explicit limit.
    pub time_in_force: Option<Tif>,
}

impl EntryRequest {
    /// Preserve the existing defaults unless the caller explicitly opts in.
    pub fn tif(&self) -> Tif {
        self.time_in_force.unwrap_or(if self.limit_price.is_some() {
            Tif::Gtc
        } else {
            Tif::Ioc
        })
    }

    pub fn tif_name(&self) -> &'static str {
        match self.tif() {
            Tif::Gtc => "gtc",
            Tif::Ioc => "ioc",
        }
    }
}

/// How the stop was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopSource {
    Explicit,
    /// Guard attaches it, at the price its preview names.
    GuardPolicy,
}

/// What every preview says about itself.
pub const CAVEATS: [&str; 4] = [
    "Guard judged this from its last view of the account, view_age_ms old (at most 60 s; null on a veto Guard made before looking at the view); the real order is judged again from a fresh read, and that verdict is the one that counts",
    "the entry is priced from the mid when it is sent; Guard pulls a limit further than 0.5% beyond the mid in to that bound",
    "only sending can show venue_refused_leverage (the venue did not confirm the isolated leverage Guard sets first) or venue_unreachable",
    "risk_at_stop_usd adds Guard's default costs (4.5 + 1 bps per side) to the distance from the worst fill to the stop; a stop can fill worse in a gap",
];

/// This server's sanity bound, before Guard is asked: a limit or stop more
/// than [`ABSURD_PRICE_FACTOR`] times away from the mid, or an explicit
/// size worth more than [`ABSURD_NOTIONAL_MULTIPLE`] times `equity`
/// (valued at the higher of the limit and the mid), is refused, never
/// resized. `equity` must be positive. The refusal's code.
pub fn sanity(request: &EntryRequest, mid: Decimal, equity: Decimal) -> Result<(), &'static str> {
    let absurd = |price: Decimal| {
        price < mid / ABSURD_PRICE_FACTOR
            || mid
                .checked_mul(ABSURD_PRICE_FACTOR)
                .is_none_or(|high| price > high)
    };
    let stop = match request.stop {
        StopSpec::Price(price) => Some(price),
        StopSpec::GuardPolicy => None,
    };
    if request.limit_price.is_some_and(absurd) || stop.is_some_and(absurd) {
        return Err("absurd_price");
    }
    if let SizeSpec::Exactly(size) = request.size {
        let price = request.limit_price.unwrap_or(mid).max(mid);
        let value = size.checked_mul(price);
        let limit = equity.checked_mul(ABSURD_NOTIONAL_MULTIPLE);
        match (value, limit) {
            (Some(value), Some(limit)) if value <= limit => {}
            _ => return Err("absurd_size"),
        }
    }
    Ok(())
}

/// The size asked of Guard for `max`: the sanity bound itself, worth
/// [`ABSURD_NOTIONAL_MULTIPLE`] times `equity` at `price`, on the venue's
/// grid. No rules code lets Guard allow that much (leverage at most 100x,
/// a position at most 100 times equity), so Guard cuts it to the most its
/// rules allow, and its preview names that size.
pub fn max_probe(market: &Market, equity: Decimal, price: Decimal) -> Option<Decimal> {
    let size = equity
        .checked_mul(ABSURD_NOTIONAL_MULTIPLE)?
        .checked_div(price)?;
    Some(market.round_qty_down(size)).filter(|size| *size > Decimal::ZERO)
}

/// The price an entry is sent at, which is also its worst fill: a limit
/// pulled in to Guard's default bound of 0.5% beyond the mid (`docs/guard.md`,
/// "The rules", `entry_price_bound`), or for a market order
/// an IOC limit at that bound; on the venue's grid, rounded towards the mid.
pub fn entry_price(
    market: &Market,
    mid: Decimal,
    side: Side,
    limit: Option<Decimal>,
) -> Option<Decimal> {
    let factor = match side {
        Side::Buy => Decimal::ONE + ENTRY_PRICE_BOUND,
        Side::Sell => Decimal::ONE - ENTRY_PRICE_BOUND,
    };
    let bound = mid
        .checked_mul(factor)
        .and_then(|price| market.round_price(price, passive(side)))?;
    let price = match (side, limit) {
        (_, None) => bound,
        (Side::Buy, Some(limit)) => limit.min(bound),
        (Side::Sell, Some(limit)) => limit.max(bound),
    };
    market.round_price(price, passive(side))
}

/// A stop for a `side` entry on the venue's grid, rounded towards the price:
/// tighter than asked, never looser.
pub fn round_stop(market: &Market, side: Side, stop: Decimal) -> Option<Decimal> {
    market.round_price(stop, toward_position(side))
}

fn text(value: Option<Decimal>) -> Value {
    value.map_or(Value::Null, |value| {
        Value::String(value.normalize().to_string())
    })
}

/// What `preview_order` shows: Guard's answer, with the order this server
/// built (`asked`: the size asked of Guard, on the venue's grid) and a few
/// numbers computed from Guard's size, worst fill and stop.
pub fn to_json(
    preview: &GuardPreview,
    request: &EntryRequest,
    asked: Decimal,
    order_price: Decimal,
    equity: Decimal,
) -> Value {
    let entry = preview.entry.as_ref();
    let allowed = entry.map(|entry| entry.size);
    let notional = entry.and_then(|entry| entry.size.checked_mul(entry.worst_price));
    let risk = entry.and_then(|entry| {
        let distance = entry.worst_price.checked_sub(entry.stop)?.abs();
        let cost = entry.worst_price.checked_mul(ROUND_TRIP_COST)?;
        entry.size.checked_mul(distance.checked_add(cost)?)
    });
    let risk_pct = risk
        .filter(|_| equity > Decimal::ZERO)
        .and_then(|risk| risk.checked_mul(Decimal::ONE_HUNDRED))
        .and_then(|risk| risk.checked_div(equity))
        .map(|pct| pct.round_dp(4));
    // `resized` also covers changes that are not a size (an attached stop,
    // a limit pulled in): say which.
    let reason = if preview.code == "resized"
        && entry.is_some_and(|entry| entry.size == entry.requested_size)
    {
        "Guard would forward it with changes other than its size (see changes_quoted): an attached stop, a limit pulled in, or a stop's limit widened.".to_owned()
    } else {
        reason_for(&preview.code)
    };
    json!({
        "source": "guard",
        "verdict": preview.verdict,
        "code": preview.code,
        "reason": reason,
        "guard_quoted": preview.quoted,
        "changes_quoted": preview.changes_quoted,
        "requested_size": match request.size {
            SizeSpec::Exactly(_) => text(Some(asked)),
            SizeSpec::Max => json!("max"),
        },
        "allowed_size": text(allowed),
        "size_cut": entry.is_some_and(|entry| entry.size < entry.requested_size)
            && request.size != SizeSpec::Max,
        "order_price": text(Some(order_price)),
        "time_in_force": request.tif_name(),
        "worst_price": text(entry.map(|entry| entry.worst_price)),
        "stop_price": text(entry.map(|entry| entry.stop)),
        "stop_source": match request.stop {
            StopSpec::Price(_) => StopSource::Explicit,
            StopSpec::GuardPolicy => StopSource::GuardPolicy,
        },
        "isolated_leverage": entry.and_then(|entry| entry.leverage),
        "notional_usd": text(notional),
        "risk_at_stop_usd": text(risk),
        "risk_at_stop_pct_of_equity": text(risk_pct),
        "equity_usd": text(Some(equity)),
        "view_age_ms": preview.view_age_ms,
        "caveats": CAVEATS,
        "note": "Guard's own judgement (its preview), made without sending anything. Guard judges every real order again, and its verdict wins.",
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{
        contract::{Mode, PreviewEntry, PreviewVerdict},
        venue::parse_meta,
    };

    fn btc() -> Market {
        parse_meta(&json!({"universe": [{"name": "BTC", "szDecimals": 5}]}))
            .unwrap()
            .remove(0)
    }

    fn buy(stop: StopSpec, size: SizeSpec, limit_price: Option<Decimal>) -> EntryRequest {
        EntryRequest {
            side: Side::Buy,
            stop,
            size,
            limit_price,
            time_in_force: None,
        }
    }

    #[test]
    fn absurd_sizes_and_prices_are_refused_not_resized() {
        let mid = dec!(60000);
        let equity = dec!(2000);
        // 1,000,000 BTC at 60,000 is far above 200 × 2,000 = 400,000.
        assert_eq!(
            sanity(
                &buy(
                    StopSpec::Price(dec!(58800)),
                    SizeSpec::Exactly(dec!(1000000)),
                    None
                ),
                mid,
                equity
            ),
            Err("absurd_size")
        );
        // 6.66 BTC × 60,000 = 399,600: within; 6.67 × 60,000 = 400,200: not.
        assert_eq!(
            sanity(
                &buy(
                    StopSpec::Price(dec!(58800)),
                    SizeSpec::Exactly(dec!(6.66)),
                    None
                ),
                mid,
                equity
            ),
            Ok(())
        );
        assert_eq!(
            sanity(
                &buy(
                    StopSpec::Price(dec!(58800)),
                    SizeSpec::Exactly(dec!(6.67)),
                    None
                ),
                mid,
                equity
            ),
            Err("absurd_size")
        );
        // A stop at 1 is more than 10 times below 60,000; a limit at
        // 600,001 more than 10 times above.
        assert_eq!(
            sanity(
                &buy(StopSpec::Price(dec!(1)), SizeSpec::Max, None),
                mid,
                equity
            ),
            Err("absurd_price")
        );
        assert_eq!(
            sanity(
                &buy(StopSpec::GuardPolicy, SizeSpec::Max, Some(dec!(600001))),
                mid,
                equity
            ),
            Err("absurd_price")
        );
        // An equity near the largest `Decimal` must not panic.
        let huge = Decimal::MAX;
        let _ = sanity(
            &buy(
                StopSpec::Price(dec!(58800)),
                SizeSpec::Exactly(dec!(1)),
                None,
            ),
            mid,
            huge,
        );
        assert_eq!(max_probe(&btc(), huge, dec!(60300)), None);
    }

    /// 200 × 2,000 = 400,000; / 60,300 = 6.633499…, down to the 0.00001
    /// step: 6.63349.
    #[test]
    fn max_asks_guard_for_the_sanity_bound() {
        assert_eq!(
            max_probe(&btc(), dec!(2000), dec!(60300)),
            Some(dec!(6.63349))
        );
        assert_eq!(max_probe(&btc(), dec!(0.000001), dec!(60300)), None);
    }

    #[test]
    fn a_limit_beyond_the_bound_is_pulled_in() {
        // 60,000 × 1.005 = 60,300.
        assert_eq!(
            entry_price(&btc(), dec!(60000), Side::Buy, Some(dec!(65000))),
            Some(dec!(60300))
        );
        // 59,500.5 has six significant figures: down to 59,500.
        assert_eq!(
            entry_price(&btc(), dec!(60000), Side::Buy, Some(dec!(59500.5))),
            Some(dec!(59500))
        );
        // A market sell: 60,000 × 0.995 = 59,700.
        assert_eq!(
            entry_price(&btc(), dec!(60000), Side::Sell, None),
            Some(dec!(59700))
        );
        // Towards the passive side off the grid: from a mid of 60,000.5 a
        // market buy's bound 60,300.5025 goes down to 60,300, a market
        // sell's 59,700.4975 up to 59,701.
        assert_eq!(
            entry_price(&btc(), dec!(60000.5), Side::Buy, None),
            Some(dec!(60300))
        );
        assert_eq!(
            entry_price(&btc(), dec!(60000.5), Side::Sell, None),
            Some(dec!(59701))
        );
        // Stops round towards the price: up for a buy, down for a sell.
        assert_eq!(
            round_stop(&btc(), Side::Buy, dec!(58800.5)),
            Some(dec!(58801))
        );
        assert_eq!(
            round_stop(&btc(), Side::Sell, dec!(61200.5)),
            Some(dec!(61200))
        );
    }

    /// Guard's answer for a 0.5 BTC buy at 60,300 with its stop at 58,800,
    /// cut to 0.02553: notional 0.02553 × 60,300 = 1,539.459; risk per BTC
    /// 1,500 + 60,300 × 0.0011 = 1,566.33, × 0.02553 = 39.9884049, which is
    /// 1.9994% of 2,000.
    #[test]
    fn the_numbers_shown_come_from_guards_answer() {
        let preview = GuardPreview {
            verdict: PreviewVerdict::Resize,
            code: "resized".into(),
            quoted: "size cut".into(),
            changes_quoted: vec!["size 0.5 to 0.02553".into()],
            entry: Some(PreviewEntry {
                coin: "BTC".into(),
                side: Side::Buy,
                requested_size: dec!(0.5),
                size: dec!(0.02553),
                worst_price: dec!(60300),
                stop: dec!(58800),
                leverage: Some(4),
            }),
            mode: Mode::Testnet,
            view_age_ms: Some(1200),
        };
        let shown = to_json(
            &preview,
            &buy(
                StopSpec::Price(dec!(58800)),
                SizeSpec::Exactly(dec!(0.5)),
                None,
            ),
            dec!(0.5),
            dec!(60300),
            dec!(2000),
        );
        assert_eq!(shown["source"], "guard");
        assert_eq!(shown["verdict"], "resize");
        assert_eq!(shown["allowed_size"], "0.02553");
        assert_eq!(shown["size_cut"], true);
        assert_eq!(shown["notional_usd"], "1539.459");
        assert_eq!(shown["risk_at_stop_usd"], "39.9884049");
        assert_eq!(shown["risk_at_stop_pct_of_equity"], "1.9994");
        assert_eq!(shown["isolated_leverage"], 4);
        assert_eq!(shown["view_age_ms"], 1200);
        assert_eq!(
            shown["reason"],
            "Guard cut the size to what its rules allow."
        );
        // A veto has no size and no numbers.
        let vetoed = GuardPreview {
            verdict: PreviewVerdict::Veto,
            code: "stop_wrong_side".into(),
            entry: None,
            changes_quoted: Vec::new(),
            ..preview
        };
        let shown = to_json(
            &vetoed,
            &buy(StopSpec::Price(dec!(61000)), SizeSpec::Max, None),
            dec!(6.63349),
            dec!(60300),
            dec!(2000),
        );
        assert_eq!(shown["allowed_size"], Value::Null);
        assert_eq!(shown["risk_at_stop_usd"], Value::Null);
        assert_eq!(shown["requested_size"], "max");
        assert_eq!(shown["size_cut"], false);
    }

    /// The caveats name only codes Guard has.
    #[test]
    fn the_caveats_name_real_codes() {
        let joined = CAVEATS.join(" ");
        for code in ["venue_refused_leverage", "venue_unreachable"] {
            assert!(joined.contains(code));
            assert_ne!(crate::contract::known_code(code), "other");
        }
        assert!(!joined.contains("no_safe_leverage"));
    }
}
