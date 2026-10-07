// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Pilot order sequence, one function per step, with explicit acceptance checks.

use std::time::{Duration, Instant};

use rust_decimal::{Decimal, dec};
use serde_json::{Value, json};

use super::checks::{self, Frame, round_price};
use super::session::{Answer, Coin, Holdings, Plan, Session, Stop};
use super::{Step, session};
use crate::actions::{OrderSpec, cancel, order};
use crate::hlsign::Wire;
use crate::now_ms;

pub(super) fn run(s: &mut Session) -> Result<(), Stop> {
    match s.opts.step {
        Step::Look => look(s),
        Step::FeeGate => fee_gate(s),
        Step::Entry | Step::RestartBefore | Step::FeeWithdrawnOpen | Step::DrillEntry => {
            entry_step(s)
        }
        Step::StopChecks => stop_checks(s),
        Step::Close => close_step(s),
        Step::TightenAndFire => tighten_and_fire(s),
        Step::Kill => kill(s),
        Step::RestartAfter => restart_after(s),
        Step::FeeWithdrawnClose => fee_withdrawn_close(s),
        Step::DrillAfter => drill_after(s),
        Step::Hip3Off => hip3_off(s),
        Step::Flat => flat(s),
        Step::Watch => watch(s),
    }
}

// ---- building orders --------------------------------------------------------

fn text(value: Decimal) -> String {
    value.normalize().to_string()
}

/// An entry as ccxt sends a market buy: an IOC limit 5% above the mid
/// (Guard pulls it in to its 0.5% bound).
struct Draft {
    label: String,
    coin: Coin,
    mid: Decimal,
    action: Wire,
}

/// With `size` `None`, a probe expected to be refused: at most 90% of the
/// frame's entry cap at its limit price, so that even a Guard that wrongly
/// let it through could forward nothing beyond the caps.
fn market_buy(
    s: &mut Session,
    label: &str,
    name: &str,
    size: Option<Decimal>,
) -> Result<Draft, Stop> {
    let coin = s.coin(name)?;
    let mid = s.mid(name, None)?;
    let price = round_price(mid * dec!(1.05), coin.sz_decimals, true);
    let size = match size {
        Some(size) => size,
        None => checks::round_size_down(
            s.frame.max_entry_notional_usd * dec!(0.9) / price,
            coin.sz_decimals,
        ),
    };
    checks::check_request(name, size, price).map_err(Stop::Refused)?;
    let cloid = s.cloid();
    let action = order(
        &[OrderSpec {
            asset: coin.asset,
            is_buy: true,
            price: text(price),
            size: text(size),
            reduce_only: false,
            trigger: None,
            cloid: Some(cloid),
            tif: "Ioc",
        }],
        "na",
    );
    Ok(Draft {
        label: label.to_owned(),
        coin,
        mid,
        action,
    })
}

/// A reduce-only market stop (sell) for a long: trigger and limit.
fn stop_sell(
    asset: u64,
    trigger: Decimal,
    limit: Decimal,
    size: Decimal,
    cloid: String,
) -> OrderSpec {
    OrderSpec {
        asset,
        is_buy: false,
        price: text(limit),
        size: text(size),
        reduce_only: true,
        trigger: Some((true, text(trigger), "sl")),
        cloid: Some(cloid),
        tif: "Gtc",
    }
}

fn reduce_only_sell(asset: u64, price: Decimal, size: Decimal, cloid: String) -> Wire {
    order(
        &[OrderSpec {
            asset,
            is_buy: false,
            price: text(price),
            size: text(size),
            reduce_only: true,
            trigger: None,
            cloid: Some(cloid),
            tif: "Ioc",
        }],
        "na",
    )
}

fn oid_of(order: &Value) -> Option<u64> {
    order.get("oid").and_then(Value::as_u64)
}

fn dec_at(value: &Value, key: &str) -> Option<Decimal> {
    value.get(key).and_then(checks::decimal_of)
}

// ---- preconditions ----------------------------------------------------------

/// Flat with no open orders on every dex Guard reads, by the venue and by
/// Guard's own view.
fn require_flat(s: &mut Session) -> Result<(), Stop> {
    if s.facts.positions > 0 || s.facts.open_orders > 0 {
        return Err(Stop::Refused(format!(
            "Guard's view shows {} positions and {} open orders; the step needs the account flat",
            s.facts.positions, s.facts.open_orders
        )));
    }
    if s.sending() {
        let holdings = s.holdings()?;
        if !holdings.flat() {
            return Err(Stop::Refused(format!(
                "the account is not flat ({} positions, {} open orders); the step needs it flat",
                holdings.positions.len(),
                holdings.orders.len()
            )));
        }
    }
    Ok(())
}

fn require_unkilled_active(s: &mut Session) -> Result<(), Stop> {
    if let Some(killed) = &s.facts.killed {
        return Err(Stop::Refused(format!(
            "Guard's kill switch is pulled: {killed}"
        )));
    }
    if s.facts.risk_state != "active" {
        return Err(Stop::Refused(format!(
            "Guard's risk state is {}, not active",
            s.facts.risk_state
        )));
    }
    Ok(())
}

/// Exactly one position, a BTC long, and nothing else open but stops.
fn require_btc_long(s: &mut Session) -> Result<(Holdings, Decimal), Stop> {
    let holdings = s.holdings()?;
    let size = match holdings.positions.as_slice() {
        [(coin, size)] if coin == "BTC" && *size > Decimal::ZERO => *size,
        other => {
            return Err(Stop::Refused(format!(
                "the step needs exactly one BTC long; the account holds {other:?}"
            )));
        }
    };
    Ok((holdings, size))
}

/// The builder fee must be on and approved for an entry (fee steps aside).
fn require_fee_allows_entries(s: &mut Session) -> Result<(), Stop> {
    if s.facts.fee.entries_blocked {
        return Err(Stop::Refused(format!(
            "Guard blocks entries for the builder fee (approval {}): approve it first (S1)",
            s.facts.fee.approval.as_deref().unwrap_or("?")
        )));
    }
    Ok(())
}

// ---- the entry, sent and checked (C1) --------------------------------------------

/// What an entry did on the venue.
struct Filled {
    size: Decimal,
    price: Decimal,
}

/// Plan the S2 entry: 0.01 BTC as a market buy, held to the caps.
fn plan_btc_entry(s: &mut Session, label: &str) -> Result<(Draft, Plan), Stop> {
    let draft = market_buy(s, label, "BTC", Some(checks::REQUEST_SIZE_BTC))?;
    let plan = s.plan_entry(label, &draft.action, "resized")?;
    if let Plan::Entry(risk) = &plan
        && risk.size >= checks::REQUEST_SIZE_BTC
    {
        return Err(Stop::Refused(format!(
            "Guard would not cut {label} ({} of {}): not sent",
            risk.size,
            checks::REQUEST_SIZE_BTC
        )));
    }
    Ok((draft, plan))
}

/// Send a planned entry and make C1's checks: resized, filled within the
/// size and the worst price; with `full`, also the isolated leverage, the
/// position, Guard's stop and the hand calculation.
fn send_entry(
    s: &mut Session,
    draft: &Draft,
    plan: &Plan,
    full: bool,
) -> Result<(Answer, Option<Filled>), Stop> {
    let label = draft.label.clone();
    let answer = s.send(&label, &draft.action, plan)?;
    let cut = matches!((answer.requested, answer.size), (Some(asked), Some(size)) if size < asked);
    s.check(
        "C1",
        &format!("{label}: resized"),
        answer.forwarded() && answer.code_is("resized") && cut,
        format!(
            "code {:?}, asked {:?}, forwarded {:?}",
            answer.code, answer.requested, answer.size
        ),
    );
    // The plan it went out under: a new one if it was previewed again
    // after `rate_limited`.
    let plan = answer.plan.clone().unwrap_or_else(|| plan.clone());
    let Plan::Entry(risk) = &plan else {
        return Ok((answer, None));
    };
    if !s.sending() {
        s.skip(
            "C1",
            &format!("{label}: the fill"),
            "paper mode: nothing was sent",
        );
        return Ok((answer, None));
    }
    let size = answer.size.unwrap_or(Decimal::ZERO);
    // The worst price Guard forwarded (its decision), else the preview's.
    let worst = answer
        .forwarded_entry
        .as_ref()
        .map_or(risk.worst, |sent| sent.worst);
    let status = answer.first_status().cloned().unwrap_or(Value::Null);
    let filled = status.get("filled").cloned();
    let fill = filled.as_ref().and_then(|filled| {
        Some(Filled {
            size: dec_at(filled, "totalSz")?,
            price: dec_at(filled, "avgPx")?,
        })
    });
    match &fill {
        Some(fill) => s.check(
            "C1",
            &format!("{label}: filled within the size and the worst price"),
            fill.size > Decimal::ZERO && fill.size <= size && fill.price <= worst,
            format!(
                "filled {} at {}; Guard's size {size}, worst price {worst}",
                fill.size, fill.price
            ),
        ),
        None => s.check(
            "C1",
            &format!("{label}: filled"),
            false,
            format!("the venue's status: {status}"),
        ),
    }
    if !full {
        return Ok((answer, fill));
    }
    let Some(filled) = fill else {
        return Ok((answer, None));
    };
    entry_venue_checks(s, draft, &answer, &filled)?;
    Ok((answer, Some(filled)))
}

/// C1 and C6 on the venue and in Guard's decision.
fn entry_venue_checks(
    s: &mut Session,
    draft: &Draft,
    answer: &Answer,
    filled: &Filled,
) -> Result<(), Stop> {
    let label = draft.label.clone();
    let decision = match &answer.decision {
        Some(decision) => decision.clone(),
        None => s.decision(answer.nonce)?,
    };
    let event = decision.get("decision").cloned().unwrap_or(Value::Null);
    // The leverage update before the entry: isolated, at most 3x.
    let leverage = event
        .get("pre")
        .and_then(Value::as_array)
        .and_then(|pre| {
            pre.iter()
                .find(|action| action.get("type").and_then(Value::as_str) == Some("updateLeverage"))
        })
        .cloned();
    let isolated = leverage.as_ref().is_some_and(|update| {
        update.get("isCross").and_then(Value::as_bool) == Some(false)
            && update
                .get("leverage")
                .and_then(checks::decimal_of)
                .is_some_and(|value| value >= Decimal::ONE && value <= checks::MAX_LEVERAGE)
    });
    s.check(
        "C1",
        &format!("{label}: isolated leverage set first"),
        isolated,
        format!("pre: {}", event.get("pre").unwrap_or(&Value::Null)),
    );
    let sent = decision
        .get("sent")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    s.check(
        "C1",
        &format!("{label}: everything Guard sent was accepted"),
        !sent.is_empty()
            && sent
                .iter()
                .all(|event| event.get("ok").and_then(Value::as_bool) == Some(true)),
        format!("{} sent events", sent.len()),
    );
    // C6: an action holding a trigger carries the builder field only when
    // the fee is on triggers.
    let forward = event.get("forward").cloned().unwrap_or(Value::Null);
    if s.facts.fee.mode == "builder" {
        let carries = forward
            .get("builder")
            .is_some_and(|builder| !builder.is_null());
        let on_triggers = s.facts.fee.on_triggers;
        s.check(
            "C6",
            &format!("{label}: the builder field on the entry with its stop"),
            carries == on_triggers,
            format!("carries the field: {carries}; on triggers: {on_triggers}"),
        );
    } else {
        s.skip(
            "C6",
            &format!("{label}: the builder field"),
            "the fee is off",
        );
    }
    // The leverage the venue reports.
    let account = s.facts.account.clone();
    let active = s.info(json!({"type": "activeAssetData", "user": account, "coin": "BTC"}))?;
    let kind = active.pointer("/leverage/type").and_then(Value::as_str);
    let value = active
        .pointer("/leverage/value")
        .and_then(checks::decimal_of);
    s.check(
        "C1",
        &format!("{label}: the venue reports isolated at most 3x"),
        kind == Some("isolated") && value.is_some_and(|value| value <= checks::MAX_LEVERAGE),
        format!("{}", active.get("leverage").unwrap_or(&Value::Null)),
    );
    // The position and Guard's stop (within 5 s of the fill).
    let mut holdings = s.holdings()?;
    if holdings
        .orders_with("BTC", checks::GUARD_STOP_PREFIX)
        .is_empty()
    {
        std::thread::sleep(Duration::from_millis(s.opts.timing.stop_recheck_ms));
        holdings = s.holdings()?;
    }
    let position = holdings.position("BTC");
    s.check(
        "C1",
        &format!("{label}: the position is the fill"),
        position == Some(filled.size),
        format!("position {position:?}, filled {}", filled.size),
    );
    let stops = holdings.orders_with("BTC", checks::GUARD_STOP_PREFIX);
    let stop = stops.first().map(|stop| (*stop).clone());
    let Some(stop) = stop else {
        s.check(
            "C1",
            &format!("{label}: Guard's stop rests"),
            false,
            "no order with client id 0x7a67 on BTC within 5 s of the fill",
        );
        return Ok(());
    };
    let trigger = dec_at(&stop, "triggerPx").unwrap_or(Decimal::ZERO);
    let limit = dec_at(&stop, "limitPx").unwrap_or(Decimal::MAX);
    let reference = filled.price.min(draft.mid);
    let expected = reference * dec!(0.98);
    let off = if expected.is_zero() {
        Decimal::ONE
    } else {
        ((trigger - expected) / expected).abs()
    };
    let ok = stops.len() == 1
        && stop.get("reduceOnly").and_then(Value::as_bool) == Some(true)
        && stop.get("isTrigger").and_then(Value::as_bool) == Some(true)
        && stop
            .get("orderType")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind.contains("Market"))
        && dec_at(&stop, "sz") == position
        && off <= dec!(0.001)
        && limit <= trigger * dec!(0.9);
    s.check(
        "C1",
        &format!("{label}: Guard's stop rests as specified"),
        ok,
        format!(
            "{} stop(s); trigger {trigger} (2% below {reference} is {expected}), limit {limit}, size {:?}, type {:?}",
            stops.len(),
            stop.get("sz"),
            stop.get("orderType")
        ),
    );
    // The hand calculation, from what Guard forwarded: the entry's price is
    // its worst price, the stop child's trigger its stop.
    let worst = forward.pointer("/orders/0/p").and_then(checks::decimal_of);
    let stop_px = forward
        .get("orders")
        .and_then(Value::as_array)
        .and_then(|orders| {
            orders.iter().find_map(|order| {
                order
                    .pointer("/t/trigger/triggerPx")
                    .and_then(checks::decimal_of)
            })
        });
    hand_check(
        s,
        &label,
        worst,
        stop_px,
        answer.size,
        draft.coin.sz_decimals,
    );
    Ok(())
}

/// C1: the size matches the hand calculation to within one size step.
fn hand_check(
    s: &mut Session,
    label: &str,
    worst: Option<Decimal>,
    stop: Option<Decimal>,
    size: Option<Decimal>,
    sz_decimals: u32,
) {
    let frame: Frame = s.frame;
    let (Some(worst), Some(stop), Some(size), Some(equity), Some(cap)) =
        (worst, stop, size, s.facts.equity, s.facts.equity_cap)
    else {
        s.check(
            "C1",
            &format!("{label}: the hand calculation"),
            false,
            format!("missing figures: worst {worst:?}, stop {stop:?}, size {size:?}"),
        );
        return;
    };
    let cost = s.facts.sizing_fee_bps + s.facts.slippage_bps;
    let hand = checks::hand_size(
        equity,
        cap,
        frame.max_loss_at_stop,
        worst,
        stop,
        cost,
        sz_decimals,
    );
    let step = checks::size_step(sz_decimals);
    s.check(
        "C1",
        &format!("{label}: the size matches the hand calculation"),
        hand.is_some_and(|hand| (hand - size).abs() <= step),
        format!(
            "Guard {size}, by hand {hand:?}: {} x min({equity}, {cap}) / ({worst} - {stop} + 2 x {cost} bp x {worst})",
            frame.max_loss_at_stop
        ),
    );
}

// ---- closing (S4) -------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum CloseFee {
    /// The fee is approved: the close carries the builder field (C6).
    Approved,
    /// The approval was withdrawn: the close still fills, sent again
    /// without the field if the venue refused it (C5).
    Withdrawn,
    /// No fee in this setting.
    Off,
}

fn close_fee(s: &Session) -> CloseFee {
    match (s.facts.fee.mode.as_str(), s.facts.fee.approval.as_deref()) {
        ("builder", Some("approved")) => CloseFee::Approved,
        ("builder", _) => CloseFee::Withdrawn,
        _ => CloseFee::Off,
    }
}

/// The `close` orders: a reduce-only IOC sell of the whole BTC long at the
/// mid - 5%, then, once flat, the cancel of every stop left on BTC.
fn close_btc(s: &mut Session, fee: CloseFee) -> Result<(), Stop> {
    let holdings = s.holdings()?;
    let others: Vec<_> = holdings
        .positions
        .iter()
        .filter(|(coin, _)| coin != "BTC")
        .collect();
    if !others.is_empty() {
        return Err(Stop::Refused(format!(
            "positions other than BTC are open: {others:?}"
        )));
    }
    unexplained(s, &holdings);
    s.gate()?;
    if let Some(size) = holdings.position("BTC") {
        if size <= Decimal::ZERO {
            return Err(Stop::Refused(format!(
                "a BTC short of {size}: the client never opens one; close it by hand"
            )));
        }
        let coin = s.coin("BTC")?;
        let mid = s.mid("BTC", None)?;
        let price = round_price(mid * dec!(0.95), coin.sz_decimals, false);
        let cloid = s.cloid();
        let action = reduce_only_sell(coin.asset, price, size, cloid);
        let plan = s.plan_exit("close", &action, &["allowed"])?;
        let answer = s.send("close", &action, &plan)?;
        s.check(
            "S4",
            "close: forwarded as sent",
            answer.forwarded() && answer.code_is("allowed"),
            format!("code {:?}", answer.code),
        );
        let filled = answer
            .first_status()
            .and_then(|status| status.get("filled"))
            .and_then(|filled| dec_at(filled, "totalSz"));
        s.check(
            "S4",
            "close: filled",
            filled == Some(size),
            format!("filled {filled:?} of {size}"),
        );
        let decision = s.decision(answer.nonce)?;
        close_fee_checks(s, &decision, fee);
        let after = s.wait_holdings(s.opts.timing.flat_wait_ms, false, |holdings| {
            holdings.position("BTC").is_none()
        })?;
        s.check(
            "S4",
            "close: no BTC position within 15 s",
            after.position("BTC").is_none(),
            format!("positions {:?}", after.positions),
        );
        s.gate()?;
    } else {
        s.note("no BTC position: only the stops left on BTC are cancelled");
    }
    cancel_leftover_stops(s)
}

/// C6 (approved) or C5 (withdrawn) on a close's decision.
fn close_fee_checks(s: &mut Session, decision: &Value, fee: CloseFee) {
    let forward = decision
        .pointer("/decision/forward")
        .cloned()
        .unwrap_or(Value::Null);
    let sent = decision
        .get("sent")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    match fee {
        CloseFee::Approved => {
            let expected = json!({"b": s.facts.fee.builder, "f": s.facts.fee.fee_tenths_bp});
            let builder = forward.get("builder").cloned().unwrap_or(Value::Null);
            let same = builder.get("f") == expected.get("f")
                && builder
                    .get("b")
                    .and_then(Value::as_str)
                    .zip(s.facts.fee.builder.as_deref())
                    .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b));
            s.check(
                "C6",
                "close: carries Guard's builder field",
                same,
                format!("forward's builder {builder}, expected {expected}"),
            );
        }
        CloseFee::Withdrawn => {
            let first_ok = sent
                .first()
                .and_then(|event| event.get("ok"))
                .and_then(Value::as_bool)
                == Some(true);
            let resent = sent.iter().any(|event| {
                event.get("action").is_some_and(|action| !action.is_null())
                    && event.get("ok").and_then(Value::as_bool) == Some(true)
            });
            if first_ok {
                s.note("the venue took the close as first sent (no refusal for the builder field)");
            }
            s.check(
                "C5",
                "close: never held back for the fee",
                first_ok || resent,
                format!(
                    "{} sent events; sent again without the field: {resent}",
                    sent.len()
                ),
            );
        }
        CloseFee::Off => s.skip("C6", "close: the builder field", "the fee is off"),
    }
}

/// Orders the step does not explain: anything without the client's or
/// Guard's client id, and positions other than BTC and ETH (abort rule
/// "unexplained activity"). Never touched; a FAIL.
fn unexplained(s: &mut Session, holdings: &Holdings) {
    for (coin, size) in &holdings.positions {
        if !checks::ALLOWED_COINS.contains(&coin.as_str()) {
            s.check(
                "abort",
                "no unexplained position",
                false,
                format!("{size} {coin}"),
            );
        }
    }
    for order in &holdings.orders {
        let ours = order
            .get("cloid")
            .and_then(Value::as_str)
            .is_some_and(|cloid| {
                cloid.starts_with(checks::CLOID_PREFIX)
                    || cloid.starts_with(checks::GUARD_STOP_PREFIX)
            });
        if !ours {
            s.check("abort", "no unexplained order", false, order.to_string());
        }
    }
}

/// Cancel the reduce-only stops (the client's and Guard's) left on coins
/// with no position, one cancel at a time. A stop that still protects a
/// position is never touched.
fn cancel_leftover_stops(s: &mut Session) -> Result<(), Stop> {
    // Guard judges a cancel on its view of the account: wait for a sync
    // that shows the position gone (else Guard's stop still protects it).
    let facts = s.wait_sync_after(now_ms())?;
    let holdings = s.holdings()?;
    if facts.positions as usize != holdings.positions.len() {
        return Err(Stop::Failed(format!(
            "Guard's view ({} positions) and the venue ({:?}) disagree; look before cancelling anything",
            facts.positions, holdings.positions
        )));
    }
    unexplained(s, &holdings);
    s.gate()?;
    let leftover: Vec<Value> = holdings
        .orders
        .iter()
        .filter(|order| {
            let coin = order.get("coin").and_then(Value::as_str).unwrap_or("");
            holdings.position(coin).is_none()
                && order.get("reduceOnly").and_then(Value::as_bool) == Some(true)
                && checks::ALLOWED_COINS.contains(&coin)
        })
        .cloned()
        .collect();
    for stop in leftover {
        let coin_name = stop.get("coin").and_then(Value::as_str).unwrap_or("");
        let coin = s.coin(coin_name)?;
        let Some(oid) = oid_of(&stop) else {
            s.check("S4", "a stop left has an order id", false, stop.to_string());
            continue;
        };
        let action = cancel(coin.asset, oid);
        let label = format!("cancel of stop {oid} on {coin_name}");
        let plan = s.plan_exit(&label, &action, &["allowed"])?;
        let answer = s.send(&label, &action, &plan)?;
        let success = answer
            .first_status()
            .is_some_and(|status| status.as_str() == Some("success"));
        s.check(
            "S4",
            &format!("{label}: allowed"),
            answer.forwarded() && answer.code_is("allowed") && (success || !s.sending()),
            format!("code {:?}, venue {:?}", answer.code, answer.first_status()),
        );
        s.gate()?;
    }
    let after = s.holdings()?;
    let flat_coins = after.orders.iter().all(|order| {
        let coin = order.get("coin").and_then(Value::as_str).unwrap_or("");
        after.position(coin).is_some()
    });
    s.check(
        "S4",
        "no order left on a coin without a position",
        flat_coins,
        format!(
            "{} open orders, positions {:?}",
            after.orders.len(),
            after.positions
        ),
    );
    Ok(())
}

// ---- the steps ---------------------------------------------------------------------

/// Pre-flight: the status, `/healthz`, and the preview of the S2 entry.
fn look(s: &mut Session) -> Result<(), Stop> {
    let facts = s.facts.clone();
    s.check(
        "pre-flight",
        "kill switch off",
        facts.killed.is_none(),
        format!("{:?}", facts.killed),
    );
    s.check(
        "pre-flight",
        "risk active",
        facts.risk_state == "active",
        facts.risk_state.clone(),
    );
    s.check(
        "pre-flight",
        "equity read",
        facts.equity.is_some_and(|equity| equity > Decimal::ZERO),
        format!("equity {:?}, cap {:?}", facts.equity, facts.equity_cap),
    );
    let age = facts.last_sync_ms.map(|at| now_ms().saturating_sub(at));
    s.check(
        "C7",
        "last sync under 10 s old",
        age.is_some_and(|age| age <= checks::MAX_SYNC_AGE_MS),
        format!("{age:?} ms"),
    );
    // While the fee is not approved, Guard lists that as an alert of its own.
    let allowed_alerts = usize::from(facts.fee.entries_blocked);
    s.check(
        "pre-flight",
        "no alerts (beside the fee approval's)",
        facts.alerts.len() <= allowed_alerts,
        format!("{:?}", facts.alerts),
    );
    s.note(format!(
        "fee: mode {}, approval {:?}, entries blocked {}",
        facts.fee.mode, facts.fee.approval, facts.fee.entries_blocked
    ));
    let health = s.healthz()?;
    s.check(
        "pre-flight",
        "/healthz ok",
        health.get("status").and_then(Value::as_str) == Some("ok"),
        health.to_string(),
    );
    let draft = market_buy(
        s,
        "S2 entry (preview only)",
        "BTC",
        Some(checks::REQUEST_SIZE_BTC),
    )?;
    let preview = s.preview(&draft.label, &draft.action)?;
    let code = preview.get("code").and_then(Value::as_str);
    match (preview.get("verdict").and_then(Value::as_str), code) {
        (Some("resize"), Some("resized")) => {
            let entry = preview.get("entry").cloned().unwrap_or(Value::Null);
            let caps = checks::assess_long_entry(&entry, &s.facts, &s.frame);
            s.check(
                "caps",
                "the S2 entry is within the caps",
                caps.is_ok(),
                format!("{caps:?}"),
            );
            hand_check(
                s,
                "S2 preview",
                dec_at(&entry, "worst_price"),
                dec_at(&entry, "stop"),
                dec_at(&entry, "size"),
                draft.coin.sz_decimals,
            );
        }
        (Some("veto"), Some("fee_not_approved")) if facts.fee.entries_blocked => {
            // Runbook gap: the preview refuses the entry until the fee is
            // approved, so its size can only be checked at S2.
            s.skip(
                "C1",
                "S2 preview: the size matches the hand calculation",
                "the preview is refused fee_not_approved until the operator approves the fee (S1); the size is checked at S2",
            );
        }
        other => s.check(
            "C1",
            "S2 preview: resized",
            false,
            format!("the preview answers {other:?}"),
        ),
    }
    Ok(())
}

/// S1: an entry while the fee is not approved: refused, nothing sent.
fn fee_gate(s: &mut Session) -> Result<(), Stop> {
    require_flat(s)?;
    require_unkilled_active(s)?;
    if s.facts.fee.mode != "builder" {
        return Err(Stop::Refused(format!(
            "Guard's fee is {}, not builder: the fee gate cannot be tested",
            s.facts.fee.mode
        )));
    }
    if s.facts.fee.approval.as_deref() == Some("approved") || !s.facts.fee.entries_blocked {
        return Err(Stop::Refused(
            "the fee is already approved: S1 runs before the approval".to_owned(),
        ));
    }
    let draft = market_buy(s, "S1 entry", "BTC", None)?;
    let plan = s.plan_veto(&draft.label, &draft.action, Some("fee_not_approved"))?;
    s.assert_worst_case()?;
    let answer = s.send(&draft.label, &draft.action, &plan)?;
    s.check(
        "C5",
        "S1 entry: vetoed fee_not_approved",
        answer.vetoed() && answer.code_is("fee_not_approved"),
        format!("code {:?}", answer.code),
    );
    nothing_sent(s, &answer, "C5", "S1 entry")?;
    s.note("now the operator approves the builder fee at 0.02% on https://zunderlabs.com/approve; wait for the status to show approval \"approved\" (at most about 1 minute)");
    Ok(())
}

/// The decision of a refused request has no `sent` event.
fn nothing_sent(
    s: &mut Session,
    answer: &Answer,
    criterion: &str,
    label: &str,
) -> Result<(), Stop> {
    let decision = s.decision(answer.nonce)?;
    let sent = decision
        .get("sent")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    s.check(
        criterion,
        &format!("{label}: nothing sent"),
        !decision.is_null() && sent == 0,
        format!("{sent} sent events"),
    );
    Ok(())
}

/// S2 (`entry`), S7 (`restart-before`), S8's first half and D1: one entry.
fn entry_step(s: &mut Session) -> Result<(), Stop> {
    require_flat(s)?;
    require_unkilled_active(s)?;
    let step = s.opts.step;
    if step == Step::FeeWithdrawnOpen
        && (s.facts.fee.mode != "builder" || s.facts.fee.approval.as_deref() != Some("approved"))
    {
        return Err(Stop::Refused(format!(
            "S8 needs the builder fee approved; Guard's fee is {} with approval {:?}",
            s.facts.fee.mode, s.facts.fee.approval
        )));
    }
    require_fee_allows_entries(s)?;
    let label = match step {
        Step::Entry => "S2 entry",
        Step::RestartBefore => "S7 entry",
        Step::FeeWithdrawnOpen => "S8 entry",
        _ => "D1 drill entry",
    };
    let (draft, plan) = plan_btc_entry(s, label)?;
    s.assert_worst_case()?;
    // D1: the halt may flatten the position within seconds, so only the
    // reply is checked here; drill-after checks the halt.
    let full = step != Step::DrillEntry;
    send_entry(s, &draft, &plan, full)?;
    s.note(match step {
        Step::Entry => "next: --step stop-checks on this position",
        Step::RestartBefore => {
            "next: journal-show --mode mainnet > before.jsonl, systemctl restart zunder-guard, journal-show again, then --step restart-after"
        }
        Step::FeeWithdrawnOpen => {
            "next: the operator withdraws the approval (approveBuilderFee at 0%) while the position is open, then --step fee-withdrawn-close"
        }
        _ => {
            "next: the halt and its flatten should follow at the first settled sync (5 to 10 s); after 15 s run --step drill-after (no halt within 2 minutes: --step close, see D1)"
        }
    });
    Ok(())
}

/// S3: Guard's stop can be neither cancelled nor loosened.
fn stop_checks(s: &mut Session) -> Result<(), Stop> {
    let (holdings, size) = require_btc_long(s)?;
    unexplained(s, &holdings);
    let stops = holdings.orders_with("BTC", checks::GUARD_STOP_PREFIX);
    let [stop] = stops.as_slice() else {
        return Err(Stop::Refused(format!(
            "S3 needs exactly one Guard stop on BTC; {} rest",
            stops.len()
        )));
    };
    let stop = (*stop).clone();
    let oid = oid_of(&stop).ok_or_else(|| Stop::Refused("Guard's stop has no oid".to_owned()))?;
    let trigger = dec_at(&stop, "triggerPx").unwrap_or(Decimal::ZERO);
    let limit = dec_at(&stop, "limitPx").unwrap_or(Decimal::MAX);
    s.check(
        "C2",
        "Guard's stop counts as protection (limit at least 5% beyond its trigger)",
        trigger > Decimal::ZERO
            && limit <= trigger * dec!(0.95)
            && dec_at(&stop, "sz") == Some(size),
        format!(
            "trigger {trigger}, limit {limit}, size {:?} of {size}",
            stop.get("sz")
        ),
    );
    let facts = s.facts.clone();
    s.check(
        "C2",
        "the status shows the position covered, no alert",
        facts.positions == 1 && facts.alerts.is_empty(),
        format!("positions {}, alerts {:?}", facts.positions, facts.alerts),
    );
    s.gate()?;
    let coin = s.coin("BTC")?;
    // The cancel of Guard's stop.
    let action = cancel(coin.asset, oid);
    let plan = s.plan_veto("S3 cancel of Guard's stop", &action, Some("guard_stop"))?;
    let answer = s.send("S3 cancel of Guard's stop", &action, &plan)?;
    s.check(
        "C2",
        "S3 cancel of Guard's stop: vetoed guard_stop",
        answer.vetoed() && answer.code_is("guard_stop"),
        format!("code {:?}", answer.code),
    );
    nothing_sent(s, &answer, "C2", "S3 cancel")?;
    s.gate()?;
    // A modify to 4% below the mid: looser.
    let mid = s.mid("BTC", None)?;
    let looser = round_price(mid * dec!(0.96), coin.sz_decimals, false);
    let looser_limit = round_price(looser * dec!(0.9), coin.sz_decimals, false);
    let spec = OrderSpec {
        asset: coin.asset,
        is_buy: false,
        price: text(looser_limit),
        size: text(size),
        reduce_only: true,
        trigger: Some((true, text(looser), "sl")),
        cloid: None,
        tif: "Gtc",
    };
    let modify = Wire::map(vec![
        ("type", Wire::str("modify")),
        ("oid", Wire::UInt(oid)),
        ("order", spec.to_wire()),
    ]);
    let plan = s.plan_veto(
        "S3 modify of Guard's stop to 4% below the mid",
        &modify,
        None,
    )?;
    let answer = s.send("S3 modify of Guard's stop", &modify, &plan)?;
    s.check(
        "C2",
        "S3 modify of Guard's stop: vetoed",
        answer.vetoed(),
        format!("code {:?} (expected stop_loosened)", answer.code),
    );
    if !answer.code_is("stop_loosened") {
        s.note(format!(
            "the modify was refused with {:?}, not stop_loosened: record the code",
            answer.code
        ));
    }
    nothing_sent(s, &answer, "C2", "S3 modify")?;
    let after = s.holdings()?;
    let same = after.orders.iter().any(|order| {
        oid_of(order) == Some(oid)
            && dec_at(order, "triggerPx") == Some(trigger)
            && dec_at(order, "sz") == Some(size)
    });
    s.check(
        "C2",
        "Guard's stop still rests unchanged",
        same,
        format!("open orders {:?}", after.orders),
    );
    Ok(())
}

/// S4 (and the fallback of S5 and D1): close the BTC long, cancel what is
/// left. On a flat account it only cancels the stops left behind.
fn close_step(s: &mut Session) -> Result<(), Stop> {
    let fee = close_fee(s);
    close_btc(s, fee)
}

/// S5: an entry, then the client's tighter stand-alone market stop, which
/// replaces Guard's.
fn tighten_and_fire(s: &mut Session) -> Result<(), Stop> {
    require_flat(s)?;
    require_unkilled_active(s)?;
    require_fee_allows_entries(s)?;
    let (draft, plan) = plan_btc_entry(s, "S5 entry")?;
    s.assert_worst_case()?;
    send_entry(s, &draft, &plan, true)?;
    s.gate()?;
    // Guard's view must hold the position before the stop is previewed: a
    // sync that began after the entry's answer.
    let facts = s.wait_sync_after(now_ms())?;
    if facts.positions == 0 {
        return Err(Stop::Failed(
            "Guard's view shows no position after the entry".to_owned(),
        ));
    }
    let size = s
        .positions()?
        .position("BTC")
        .filter(|size| *size > Decimal::ZERO)
        .ok_or_else(|| Stop::Failed("no BTC long after the entry".to_owned()))?;
    let coin = s.coin("BTC")?;
    let mid = s.mid("BTC", None)?;
    let trigger = round_price(mid * dec!(0.9985), coin.sz_decimals, false);
    let limit = round_price(trigger * dec!(0.9), coin.sz_decimals, false);
    if trigger >= mid || limit > trigger * dec!(0.9) {
        return Err(Stop::Failed(format!(
            "the stop's trigger {trigger} or limit {limit} is wrong for mid {mid}"
        )));
    }
    let cloid = s.cloid();
    let action = order(&[stop_sell(coin.asset, trigger, limit, size, cloid)], "na");
    let plan = s.plan_exit("S5 client stop", &action, &["allowed", "resized"])?;
    let answer = s.send("S5 client stop", &action, &plan)?;
    s.check(
        "C2",
        "S5 client stop: forwarded as sent",
        answer.forwarded() && (answer.code_is("allowed") || answer.code_is("resized")),
        format!(
            "code {:?} (allowed or resized is expected when Guard only cancels its own stop and the previewed order is unchanged)",
            answer.code
        ),
    );
    let decision = s.decision(answer.nonce)?;
    let cancels_guard = decision
        .pointer("/decision/post")
        .and_then(Value::as_array)
        .is_some_and(|post| {
            post.iter()
                .any(|action| action.get("type").and_then(Value::as_str) == Some("cancel"))
        });
    s.check(
        "C2",
        "S5: Guard cancels its own stop once the client's rests",
        cancels_guard,
        format!(
            "post: {}",
            decision.pointer("/decision/post").unwrap_or(&Value::Null)
        ),
    );
    let mut holdings = s.holdings()?;
    if !holdings
        .orders_with("BTC", checks::GUARD_STOP_PREFIX)
        .is_empty()
    {
        std::thread::sleep(Duration::from_millis(s.opts.timing.stop_recheck_ms));
        holdings = s.holdings()?;
    }
    let ours = holdings.orders_with("BTC", checks::CLOID_PREFIX).len();
    let guards = holdings.orders_with("BTC", checks::GUARD_STOP_PREFIX).len();
    // The client's stop may already have fired (it sits 0.15% below the mid).
    let fired = holdings.position("BTC").is_none();
    s.check(
        "C2",
        "S5: the client's stop rests (or fired) and Guard's is gone",
        guards == 0 && (ours == 1 || fired),
        format!(
            "client stops {ours}, Guard stops {guards}, position {:?}",
            holdings.position("BTC")
        ),
    );
    s.note(format!(
        "now wait for the client's stop to trigger (trigger {trigger}, polling the mark); after 60 minutes without a trigger run --step close and record that it did not fire; then --step flat"
    ));
    Ok(())
}

/// S6: a BTC entry, a resting ETH entry, the kill switch, an entry after it.
fn kill(s: &mut Session) -> Result<(), Stop> {
    require_flat(s)?;
    require_unkilled_active(s)?;
    require_fee_allows_entries(s)?;
    let since = s.facts.last_event;
    // Both entries planned, and the step's worst case asserted, before the first.
    let (btc, btc_plan) = plan_btc_entry(s, "S6 BTC entry")?;
    let eth = s.coin("ETH")?;
    let eth_mid = s.mid("ETH", None)?;
    let price = round_price(eth_mid * dec!(0.97), eth.sz_decimals, false);
    let stop = round_price(price * dec!(0.98), eth.sz_decimals, false);
    let stop_limit = round_price(stop * dec!(0.9), eth.sz_decimals, false);
    let size = checks::REQUEST_SIZE_ETH;
    checks::check_request("ETH", size, price).map_err(Stop::Refused)?;
    let entry_cloid = s.cloid();
    let stop_cloid = s.cloid();
    let eth_action = order(
        &[
            OrderSpec {
                asset: eth.asset,
                is_buy: true,
                price: text(price),
                size: text(size),
                reduce_only: false,
                trigger: None,
                cloid: Some(entry_cloid),
                tif: "Gtc",
            },
            stop_sell(eth.asset, stop, stop_limit, size, stop_cloid),
        ],
        "normalTpsl",
    );
    let eth_plan = s.plan_entry("S6 ETH entry", &eth_action, "resized")?;
    s.assert_worst_case()?;
    send_entry(s, &btc, &btc_plan, false)?;
    s.gate()?;
    let answer = s.send("S6 ETH entry", &eth_action, &eth_plan)?;
    s.check(
        "C3",
        "S6 ETH entry: resized",
        answer.forwarded() && answer.code_is("resized"),
        format!(
            "code {:?}, asked {:?}, forwarded {:?}",
            answer.code, answer.requested, answer.size
        ),
    );
    if s.sending() {
        let resting = answer
            .first_status()
            .is_some_and(|status| status.get("resting").is_some());
        s.check(
            "C3",
            "S6 ETH entry: resting",
            resting,
            format!("{:?}", answer.first_status()),
        );
    }
    s.gate()?;
    // The kill switch.
    let killed = s.kill("pilot S6")?;
    let expected_positions = u64::from(s.sending());
    s.check(
        "C3",
        "kill: killed, durable, one position at the kill",
        killed.get("status").and_then(Value::as_str) == Some("ok")
            && killed.get("killed").is_some_and(|reason| !reason.is_null())
            && killed.get("durable").and_then(Value::as_bool) == Some(true)
            && killed.get("positions_at_kill").and_then(Value::as_u64) == Some(expected_positions),
        killed.to_string(),
    );
    // An entry after it: refused.
    let after = market_buy(s, "S6 ETH entry after the kill", "ETH", None)?;
    let plan = s.plan_veto(&after.label, &after.action, Some("kill_switch"))?;
    let answer = s.send(&after.label, &after.action, &plan)?;
    s.check(
        "C3",
        "S6 entry after the kill: vetoed kill_switch",
        answer.vetoed() && answer.code_is("kill_switch"),
        format!("code {:?}", answer.code),
    );
    nothing_sent(s, &answer, "C3", "S6 entry after the kill")?;
    if !s.sending() {
        // Guard flattens only what is exposed, and a paper Guard holds
        // nothing the client opened.
        s.skip(
            "C3",
            "a flatten event follows the kill",
            "paper mode: nothing to flatten",
        );
        s.skip("C3", "flat within 15 s", "paper mode: nothing was sent");
        return Ok(());
    }
    let events = s.events_since(since)?;
    let flattened = events
        .iter()
        .any(|event| event.get("kind").and_then(Value::as_str) == Some("flatten"));
    s.check(
        "C3",
        "a flatten event follows the kill",
        flattened,
        format!("{} events", events.len()),
    );
    let holdings = s.wait_holdings(s.opts.timing.flat_wait_ms, true, |holdings| {
        holdings.positions.is_empty()
            && holdings
                .orders
                .iter()
                .all(|order| order.get("reduceOnly").and_then(Value::as_bool) == Some(true))
    })?;
    let entries_left = holdings
        .orders
        .iter()
        .filter(|order| order.get("reduceOnly").and_then(Value::as_bool) != Some(true))
        .count();
    s.check(
        "C3",
        "flat within 15 s: the BTC position closed, the ETH entry cancelled",
        holdings.positions.is_empty() && entries_left == 0,
        format!(
            "positions {:?}, entries left {entries_left}",
            holdings.positions
        ),
    );
    s.gate()?;
    // Reduce-only stops the venue left resting: cancelled and recorded.
    let left = holdings.orders.len();
    if left > 0 {
        s.note(format!(
            "{left} reduce-only stop(s) left resting after the flatten: cancelled now"
        ));
    }
    cancel_leftover_stops(s)?;
    s.note("next: systemctl restart zunder-guard (still killed), then remove the kill file and restart (released)");
    Ok(())
}

/// S7 after the restart: a request with a nonce from before it, then the close.
fn restart_after(s: &mut Session) -> Result<(), Stop> {
    let (holdings, _) = require_btc_long(s)?;
    let guards = holdings.orders_with("BTC", checks::GUARD_STOP_PREFIX).len();
    s.check(
        "C9",
        "exactly one Guard stop rests after the restart",
        guards == 1,
        format!("{guards} Guard stops"),
    );
    s.gate()?;
    let coin = s.coin("BTC")?;
    // A cancel (harmless whatever happens) signed with a nonce from before
    // Guard's start: refused before it is judged.
    let action = cancel(coin.asset, 0);
    let answer = s.send_stale(
        "S7 request signed before the restart",
        &action,
        s.facts.started_at_ms,
    )?;
    s.check(
        "C9",
        "S7 request from before the restart: auth_nonce_before_start",
        answer.vetoed() && answer.code_is("auth_nonce_before_start"),
        format!("code {:?}", answer.code),
    );
    s.gate()?;
    let fee = close_fee(s);
    close_btc(s, fee)
}

/// S8 after the operator withdrew the approval: the close still fills, the next
/// entry is refused.
fn fee_withdrawn_close(s: &mut Session) -> Result<(), Stop> {
    if s.facts.fee.mode != "builder" {
        return Err(Stop::Refused(format!(
            "Guard's fee is {}, not builder: S8 cannot run",
            s.facts.fee.mode
        )));
    }
    require_btc_long(s)?;
    let builder = s
        .facts
        .fee
        .builder
        .clone()
        .ok_or_else(|| Stop::Refused("the status names no builder".to_owned()))?;
    let account = s.facts.account.clone();
    let approved = s.info(json!({"type": "maxBuilderFee", "user": account, "builder": builder}))?;
    if checks::decimal_of(&approved).is_none_or(|max| max > Decimal::ZERO) {
        return Err(Stop::Refused(format!(
            "the venue still reports an approval of {approved} for the builder: withdraw it first (approveBuilderFee at 0%)"
        )));
    }
    close_btc(s, CloseFee::Withdrawn)?;
    s.gate()?;
    let draft = market_buy(s, "S8 entry after the withdrawal", "BTC", None)?;
    let plan = s.plan_veto(&draft.label, &draft.action, Some("fee_not_approved"))?;
    let answer = s.send(&draft.label, &draft.action, &plan)?;
    s.check(
        "C5",
        "S8 entry: vetoed fee_not_approved",
        answer.vetoed() && answer.code_is("fee_not_approved"),
        format!("code {:?}", answer.code),
    );
    nothing_sent(s, &answer, "C5", "S8 entry")?;
    let (_, facts) = s.status()?;
    s.check(
        "C5",
        "the withdrawal shows as an alert",
        !facts.alerts.is_empty() && facts.fee.entries_blocked,
        format!("alerts {:?}", facts.alerts),
    );
    s.note("next: the operator approves the builder fee again at 0.02%");
    Ok(())
}

/// D2 and D3: halted, flat; an entry refused, a reduce-only order not.
fn drill_after(s: &mut Session) -> Result<(), Stop> {
    let facts = s.facts.clone();
    s.check(
        "C4",
        "the drill Guard is halted for the day",
        facts.risk_state == "halted_for_day",
        facts.risk_state.clone(),
    );
    if s.sending() {
        let holdings = s.positions()?;
        s.check(
            "C4",
            "no position after the halt's flatten",
            holdings.positions.is_empty(),
            format!("positions {:?}", holdings.positions),
        );
    }
    s.gate()?;
    let draft = market_buy(s, "D2 entry while halted", "BTC", None)?;
    let plan = s.plan_veto(&draft.label, &draft.action, Some("daily_loss_stop"))?;
    s.assert_worst_case()?;
    let answer = s.send(&draft.label, &draft.action, &plan)?;
    s.check(
        "C4",
        "D2 entry: vetoed daily_loss_stop",
        answer.vetoed() && answer.code_is("daily_loss_stop"),
        format!("code {:?}", answer.code),
    );
    nothing_sent(s, &answer, "C4", "D2 entry")?;
    s.gate()?;
    let coin = s.coin("BTC")?;
    let mid = s.mid("BTC", None)?;
    let price = round_price(mid * dec!(0.95), coin.sz_decimals, false);
    let cloid = s.cloid();
    let action = reduce_only_sell(coin.asset, price, dec!(0.00001), cloid);
    let plan = s.plan_exit("D2 reduce-only sell of 0.00001 BTC", &action, &[])?;
    let answer = s.send("D2 reduce-only sell of 0.00001 BTC", &action, &plan)?;
    let halted_code = ["daily_loss_stop", "drawdown_halt", "kill_switch"]
        .iter()
        .any(|code| answer.code_is(code));
    s.check(
        "C4",
        "D2 reduce-only order: not refused for the halt",
        !halted_code,
        format!(
            "code {:?}, forwarded {} (the venue may refuse it for size)",
            answer.code,
            answer.forwarded()
        ),
    );
    Ok(())
}

/// H0: an entry on a HIP-3 market, refused `dex_not_allowed`, nothing sent.
fn hip3_off(s: &mut Session) -> Result<(), Stop> {
    require_unkilled_active(s)?;
    let dexes = s.info(json!({"type": "perpDexs"}))?;
    let index = dexes
        .as_array()
        .and_then(|dexes| {
            dexes
                .iter()
                .position(|dex| dex.get("name").and_then(Value::as_str) == Some("xyz"))
        })
        .ok_or_else(|| Stop::Refused("perpDexs lists no dex xyz".to_owned()))?;
    let meta = s.info(json!({"type": "meta", "dex": "xyz"}))?;
    let first = meta
        .pointer("/universe/0")
        .cloned()
        .ok_or_else(|| Stop::Refused("xyz's meta lists no market".to_owned()))?;
    let name = first
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| Stop::Refused("xyz's first market has no name".to_owned()))?
        .to_owned();
    let sz_decimals = first
        .get("szDecimals")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| Stop::Refused(format!("{name} has no size decimals")))?;
    let mid = s.mid(&name, Some("xyz"))?;
    let asset = 100_000 + 10_000 * index as u64;
    let size = checks::size_step(sz_decimals);
    let price = round_price(mid * dec!(1.05), sz_decimals, true);
    if size * price > checks::MAX_HIP3_PROBE_NOTIONAL_USD {
        return Err(Stop::Refused(format!(
            "one size step of {name} is worth {} USDC, more than {}",
            size * price,
            checks::MAX_HIP3_PROBE_NOTIONAL_USD
        )));
    }
    let cloid = s.cloid();
    let action = order(
        &[OrderSpec {
            asset,
            is_buy: true,
            price: text(price),
            size: text(size),
            reduce_only: false,
            trigger: None,
            cloid: Some(cloid),
            tif: "Ioc",
        }],
        "na",
    );
    let label = format!("H0 entry on {name} (asset {asset})");
    let plan = s.plan_veto(&label, &action, Some("dex_not_allowed"))?;
    let answer = s.send(&label, &action, &plan)?;
    s.check(
        "C8",
        "H0: vetoed dex_not_allowed",
        answer.vetoed() && answer.code_is("dex_not_allowed"),
        format!("code {:?}", answer.code),
    );
    nothing_sent(s, &answer, "C8", "H0 entry")
}

/// The end: nothing open on any dex Guard reads.
fn flat(s: &mut Session) -> Result<(), Stop> {
    let facts = s.facts.clone();
    s.check(
        "end",
        "Guard's view: 0 positions, 0 open orders",
        facts.positions == 0 && facts.open_orders == 0,
        format!(
            "{} positions, {} open orders",
            facts.positions, facts.open_orders
        ),
    );
    s.check(
        "end",
        "no unmanaged HIP-3 dex holds anything",
        facts.unmanaged_dexes == 0,
        format!("{} unmanaged dexes", facts.unmanaged_dexes),
    );
    let holdings = s.holdings()?;
    s.check(
        "end",
        "the venue: 0 positions, 0 open orders on every dex Guard reads",
        holdings.flat(),
        format!(
            "positions {:?}, open orders {:?}",
            holdings.positions, holdings.orders
        ),
    );
    Ok(())
}

/// C7: the status once a second for the run, into `watch.jsonl`. Sends nothing.
fn watch(s: &mut Session) -> Result<(), Stop> {
    let mut log = session::open_log(s.opts, "watch.jsonl").map_err(Stop::Refused)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| Stop::Refused(format!("no HTTP client: {error}")))?;
    let url = format!("{}/guard/status", s.opts.url.trim_end_matches('/'));
    let interval = Duration::from_millis(s.opts.timing.poll_ms.max(1));
    let until = Instant::now() + Duration::from_millis(s.opts.timing.watch_ms);
    let (mut polls, mut breaches, mut unreachable) = (0u64, 0u64, 0u64);
    s.note(format!(
        "watching the status every {} ms for {} s; writing watch.jsonl",
        interval.as_millis(),
        s.opts.timing.watch_ms / 1000
    ));
    while Instant::now() < until {
        let at = now_ms();
        let status = client
            .get(&url)
            .send()
            .and_then(|response| response.text())
            .map_err(|error| error.to_string())
            .and_then(|text| {
                serde_json::from_str::<Value>(&text).map_err(|error| error.to_string())
            });
        let line = match status {
            Ok(status) => {
                polls += 1;
                let last = status.get("last_sync_ms").and_then(Value::as_u64);
                let age = last.map(|last| at.saturating_sub(last));
                let breach = age.is_none_or(|age| age > checks::MAX_SYNC_AGE_MS);
                if breach {
                    breaches += 1;
                }
                let line = json!({"at_ms": at, "age_ms": age, "breach": breach,
                    "last_sync_ms": last, "positions": status.get("positions"),
                    "open_orders": status.get("open_orders"), "killed": status.get("killed"),
                    "risk": status.pointer("/risk/state"), "alert": status.get("alert"),
                    "last_error": status.get("last_error")});
                if breach {
                    s.line(json!({"kind": "breach", "age_ms": age, "last_sync_ms": last}));
                }
                line
            }
            Err(error) => {
                unreachable += 1;
                json!({"at_ms": at, "unreachable": error})
            }
        };
        use std::io::Write as _;
        if writeln!(log, "{line}").and_then(|()| log.flush()).is_err() {
            return Err(Stop::Failed(
                "watch.jsonl can no longer be written".to_owned(),
            ));
        }
        std::thread::sleep(interval);
    }
    s.check(
        "C7",
        "the view stayed within 10 s at every poll",
        breaches == 0 && unreachable == 0,
        format!("{polls} polls, {breaches} breaches, {unreachable} unreachable"),
    );
    Ok(())
}
