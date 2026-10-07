// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Guard's deposits and withdrawals against the reference model of
//! `docs/guard.md#deposits-and-withdrawals`.
//!
//! A generator builds random timelines of an account: trading gains and
//! losses, deposits, withdrawals, transfers between two dexes, views of the
//! account read at different venue times, views that go back in time,
//! restarts, and ledger reports that arrive at once, late, out of order,
//! across midnight, or never. The implementation (`PersistentRisk` with
//! flows, on a journal on disk) is fed the timeline as Guard would feed it,
//! and after every step compared with the reference model fed the same
//! views and, from the start, every flow reported so far:
//!
//! - I1/I2: the figures (peak, day, day's start, last equity) are equal,
//!   and the state is equal or stricter, stricter only after a view that
//!   showed a flow not yet reported was taken; a restart is the run in
//!   which the views the journal did not hold were never fed; every record
//!   written is one the reader accepts.
//! - I3: once everything is reported, the order and latency of the reports
//!   do not matter.
//! - I8: the reference model against a model that knows the true equity at
//!   every flow.
//!
//! The reference model is written apart from the implementation, from the
//! flow-accounting rules; it uses an independent solution of the base/share equation and
//! `RiskEngine`, which defines every stop. Only a cash-only singleton with
//! explicit provenance is trusted; candle ranges and old journal singletons
//! are unknown stretches and cannot establish a human stop.
//!
//! Amounts are whole multiples of a unit larger than the share of a fall the
//! journal may leave unwritten (`docs/guard.md#deposits-and-withdrawals`), so that a
//! view not on the journal has the equity of the last one written; then a
//! restart is exactly a run that never saw the views it forgot.

#![allow(clippy::unwrap_used)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use proptest::prelude::*;
use rust_decimal::{Decimal, dec};
use zunder_core::Timestamp;
use zunder_risk::{RiskEngine, RiskLimits, RiskSnapshot, RiskState, VenueView};
use zunder_venue::{
    FLOW_TIME_MARGIN_MS as MARGIN, Flow, FlowOutcome, JournalError, JournalEvent, JournalRecord,
    PersistentRisk, SeenView, ValueRange, rebase,
};

const DAY: i64 = Timestamp::MS_PER_DAY;
/// The second managed dex.
const SECOND: &str = "xyz";
/// Every amount is a multiple of this (USDC).
const UNIT: Decimal = dec!(100);
/// The share of the day's start (or the cap) a fall may stay unwritten by
/// (`docs/guard.md#deposits-and-withdrawals`).
const DELTA: Decimal = dec!(0.001);
/// The most a timeline lets the account hold, so that the share of a fall
/// the journal may leave unwritten (0.1% of the day's start) stays below
/// one unit: the day's start is at most a third above the equity before a
/// drawdown stop.
const MOST: i64 = 700;

fn ts(ms: i64) -> Timestamp {
    Timestamp::from_millis(ms)
}

// ---------------------------------------------------------------------
// The independent reference model
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Before,
    Either,
    Shows,
}

/// Flow chronology: where a view read at `times` stands to `flow`.
fn side(flow: &Flow, times: &BTreeMap<String, i64>) -> Side {
    let Some(earliest) = times.values().min().copied() else {
        return Side::Either;
    };
    let read: Vec<i64> = if flow.between {
        times.values().copied().collect()
    } else {
        vec![times.get(&flow.dex).copied().unwrap_or(earliest)]
    };
    if read.iter().all(|time| *time < flow.time_ms - MARGIN) {
        Side::Before
    } else if read.iter().all(|time| *time >= flow.time_ms + MARGIN) {
        Side::Shows
    } else {
        Side::Either
    }
}

fn rank(state: RiskState) -> u8 {
    match state {
        RiskState::Active => 0,
        RiskState::HaltedForDay { .. } => 1,
        RiskState::Stopped { .. } => 2,
    }
}

/// Solve S6 directly from the loss fraction equation. This test oracle never
/// calls the production `rebase` used by the fold.
fn reference_rebase(
    base: Decimal,
    before: Decimal,
    after: Decimal,
    cap: Option<Decimal>,
) -> Option<Decimal> {
    let denominator = cap.map_or(base, |ceiling| ceiling.min(base));
    let loss = base.checked_sub(before)?.checked_div(denominator)?;
    if let Some(ceiling) = cap {
        let dollar_base = after.checked_add(loss.checked_mul(ceiling)?)?;
        if dollar_base >= ceiling {
            return Some(dollar_base);
        }
    }
    let remaining = Decimal::ONE.checked_sub(loss)?;
    if remaining <= Decimal::ZERO {
        return None;
    }
    let result = after.checked_div(remaining)?;
    (result > Decimal::ZERO).then_some(result)
}

/// Spec S6: the move of one flow of `amount` at pre-flow equity `before`,
/// the engine having observed `before`.
fn moved(
    limits: &RiskLimits,
    engine: &RiskEngine,
    time: i64,
    before: Decimal,
    amount: Decimal,
) -> Option<RiskEngine> {
    if amount.is_zero() {
        return Some(engine.clone());
    }
    let cap = limits.max_trading_equity_usd;
    let now = engine.snapshot();
    let after = before + amount;
    let peak = reference_rebase(now.peak, before, after, cap)?
        .max(after)
        .normalize();
    // A known trading zero can be the last value before UTC rollover in
    // an already stopped account. Its nonpositive daily base defines no
    // fraction; the first positive cash movement starts a numeric daily
    // base while the human Stop and ordinary peak conservation survive.
    let mut day_start =
        if rank(now.state) == 2 && now.day_start <= Decimal::ZERO && after > Decimal::ZERO {
            after
        } else {
            reference_rebase(now.day_start, before, after, cap)?
        };
    if amount > Decimal::ZERO {
        day_start = day_start.max(now.day_start + amount);
    }
    let mut engine = RiskEngine::restore(
        limits.clone(),
        RiskSnapshot {
            peak,
            day_start: day_start.normalize(),
            last: peak,
            ..now
        },
    )
    .ok()?;
    engine.observe(ts(time), after);
    Some(engine)
}

/// The reference model: every flow known from the start, the equity seen
/// only through the views. With an oracle (the true equity just before
/// each flow, by id), the truth model of I8 instead.
#[derive(Debug, Clone)]
struct Model {
    limits: RiskLimits,
    engine: RiskEngine,
    /// Original monetary checkpoint of an unplaced group. Displayed UTC
    /// rolls and decision latches never change this replay origin.
    pending_origin: Option<RiskEngine>,
    latest: BTreeMap<String, i64>,
    flows: Vec<Flow>,
    applied: Vec<bool>,
    oracle: Option<BTreeMap<String, Decimal>>,
    /// For each group applied: the views (their index in the views fed)
    /// around it: the last one taken before it, and the one that showed it.
    groups: Vec<(Option<usize>, usize)>,
    views: usize,
    last_taken: Option<usize>,
    /// Coverage: views left out, ignored, groups of two flows or more,
    /// losses split across stretches.
    left: usize,
    ignored: usize,
    multi: usize,
    splits: std::cell::Cell<usize>,
    /// Coverage: groups whose stops were waived for a day's halt,
    /// histories with an account a withdrawal emptied and money refilled,
    /// histories that cannot have happened.
    downgraded: std::cell::Cell<usize>,
    emptied: std::cell::Cell<usize>,
    impossible: std::cell::Cell<usize>,
}

enum Applied {
    Placed(RiskEngine),
    /// Money stays pending, but exact observations can already establish
    /// a decision; unreadable zero anchors impose a current-day halt.
    Deferred(RiskEngine),
}

impl Model {
    fn new(limits: &RiskLimits, start: Timestamp, equity: Decimal, flows: Vec<Flow>) -> Self {
        let applied = vec![false; flows.len()];
        Self {
            limits: limits.clone(),
            engine: RiskEngine::new(limits.clone(), start, equity).unwrap(),
            pending_origin: None,
            latest: BTreeMap::new(),
            flows,
            applied,
            oracle: None,
            groups: Vec::new(),
            views: 0,
            last_taken: None,
            left: 0,
            ignored: 0,
            multi: 0,
            splits: std::cell::Cell::new(0),
            downgraded: std::cell::Cell::new(0),
            emptied: std::cell::Cell::new(0),
            impossible: std::cell::Cell::new(0),
        }
    }

    /// A view only its venue times are left of (a restart forgot it, but a
    /// later record holds its times): it counts for which views go back.
    fn ghost(&mut self, view: &SeenView) {
        for (dex, time) in &view.times {
            let latest = self.latest.entry(dex.clone()).or_insert(*time);
            *latest = (*latest).max(*time);
        }
    }

    /// Feed a view: `None` when it goes back in venue time (S1), else
    /// whether it was taken.
    fn view(&mut self, view: &SeenView) -> Option<bool> {
        if view
            .times
            .iter()
            .any(|(dex, time)| self.latest.get(dex).is_some_and(|latest| time < latest))
        {
            self.ignored += 1;
            return None;
        }
        for (dex, time) in &view.times {
            let latest = self.latest.entry(dex.clone()).or_insert(*time);
            *latest = (*latest).max(*time);
        }
        let index = self.views;
        self.views += 1;
        let mut left = false;
        let mut shown = Vec::new();
        for (i, flow) in self.flows.iter().enumerate() {
            match (self.applied[i], side(flow, &view.times)) {
                (true, Side::Shows) | (false, Side::Before) => {}
                (true, _) | (false, Side::Either) => left = true,
                (false, Side::Shows) => shown.push(i),
            }
        }
        if !left && !shown.is_empty() {
            shown.sort_by_key(|i| (self.flows[*i].time_ms, self.flows[*i].id.clone()));
            match self.apply(&shown, view.equity, view.at) {
                Some(Applied::Placed(engine)) => {
                    self.engine = engine;
                    self.pending_origin = None;
                    for i in &shown {
                        self.applied[*i] = true;
                    }
                    self.groups.push((self.last_taken, index));
                    if shown.len() > 1 {
                        self.multi += 1;
                    }
                }
                Some(Applied::Deferred(engine)) => {
                    if self.pending_origin.is_none() {
                        self.pending_origin = Some(self.engine.clone());
                    }
                    self.engine = engine;
                    left = true;
                }
                None => left = true,
            }
        }
        if left {
            self.left += 1;
            let last = self.engine.snapshot().last;
            self.engine.observe(view.at, last);
            return Some(false);
        }
        self.engine.observe(view.at, view.equity);
        self.last_taken = Some(index);
        Some(true)
    }

    /// The scalar oracle knows exact cash-only flow values. It treats an
    /// unknown stretch as money movements, then normalizes at the next
    /// trusted anchor without inventing a trading loss across that stretch.
    fn apply(&self, group: &[usize], shown: Decimal, at: Timestamp) -> Option<Applied> {
        if let Some(oracle) = &self.oracle {
            return self.fully_informed(group, oracle).map(Applied::Placed);
        }
        let flows: Vec<&Flow> = group.iter().map(|i| &self.flows[*i]).collect();
        let known = |flow: &Flow| -> Option<Decimal> {
            let value = flow.value?;
            (value.cash_exact
                && value.lo == value.hi
                && value.lo >= Decimal::ZERO
                && value.lo.checked_add(flow.amount)? >= Decimal::ZERO)
                .then_some(value.lo)
        };
        let mut engine = self.checkpoint();
        let mut cursor = 0;
        let mut unknown = false;
        // The start of an exact withdrawal that emptied the account. The
        // flow is not applied until a refill makes a positive balance.
        let mut empty: Option<(usize, RiskEngine, Decimal)> = None;
        while cursor < flows.len() {
            let flow = flows[cursor];
            if let Some(equity) = known(flow) {
                let after = equity.checked_add(flow.amount)?;
                if let Some((start, saved, from)) = empty.take() {
                    if after > Decimal::ZERO {
                        engine = saved;
                        engine.observe(ts(flow.time_ms), from);
                        engine = moved(&self.limits, &engine, flow.time_ms, from, after - from)?;
                        self.emptied.set(self.emptied.get() + 1);
                    } else {
                        empty = Some((start, saved, from));
                    }
                } else {
                    engine.observe(ts(flow.time_ms), equity);
                    if equity > Decimal::ZERO && after.is_zero() {
                        empty = Some((cursor, engine.clone(), equity));
                    } else if equity > Decimal::ZERO {
                        engine = moved(&self.limits, &engine, flow.time_ms, equity, flow.amount)?;
                    }
                    // Observed trading zero has already stopped the engine;
                    // no division by zero or inference from incoming cash.
                }
                cursor += 1;
                continue;
            }
            if flow.amount.is_zero() {
                cursor += 1;
                continue;
            }
            unknown = true;
            let start = if let Some((start, saved, _)) = empty.take() {
                engine = saved;
                start
            } else {
                cursor
            };
            let end = ((cursor + 1)..flows.len())
                .find(|i| known(flows[*i]).is_some_and(|equity| equity > Decimal::ZERO))
                .unwrap_or(flows.len());
            let (anchor, anchor_time) = if end == flows.len() {
                (shown, at)
            } else {
                (known(flows[end])?, ts(flows[end].time_ms))
            };
            if anchor <= Decimal::ZERO {
                return self
                    .defer(engine.state(), unknown, at)
                    .map(Applied::Deferred);
            }
            let original = engine.clone();
            engine = self
                .money_only(engine, &flows[start..end])
                .filter(|neutral| rank(neutral.state()) < 2 || rank(original.state()) == 2)
                .unwrap_or_else(|| {
                    self.impossible.set(self.impossible.get() + 1);
                    original
                });
            engine = self.normalize(engine, anchor, anchor_time)?;
            cursor = end;
        }
        if empty.is_some() {
            return self
                .defer(engine.state(), unknown, at)
                .map(Applied::Deferred);
        }
        if unknown {
            self.downgraded.set(self.downgraded.get() + 1);
            // The gap was closed at an exact flow or at the showing view.
            // Subsequent exact losses have already counted normally.
            engine.observe(at, shown);
            let mut snapshot = engine.snapshot();
            if rank(snapshot.state) < 2 {
                snapshot.state = RiskState::HaltedForDay { day: snapshot.day };
            }
            engine = RiskEngine::restore(self.limits.clone(), snapshot).ok()?;
        }
        Some(Applied::Placed(engine))
    }

    /// Empty showing equity supplies no positive denominator for normalizing
    /// unreadable history. Leave all money pending on the original bases,
    /// carrying only independently proved decisions and UTC chronology.
    fn defer(&self, decision: RiskState, unknown: bool, at: Timestamp) -> Option<RiskEngine> {
        let mut original = self.checkpoint();
        original.observe(at, original.snapshot().last);
        let mut snapshot = original.snapshot();
        if rank(decision) == 2 {
            snapshot.state = decision;
        } else if rank(snapshot.state) < 2
            && (unknown
                || matches!(decision, RiskState::HaltedForDay { day } if day == snapshot.day))
        {
            snapshot.state = RiskState::HaltedForDay { day: snapshot.day };
        }
        RiskEngine::restore(self.limits.clone(), snapshot).ok()
    }

    fn checkpoint(&self) -> RiskEngine {
        let original = self.pending_origin.as_ref().unwrap_or(&self.engine);
        let mut snapshot = original.snapshot();
        // A human Stop is durable knowledge, independent of where the
        // unresolved money is eventually placed. Daily halts have dates.
        if matches!(self.engine.state(), RiskState::Stopped { .. }) {
            snapshot.state = self.engine.state();
        }
        RiskEngine::restore(self.limits.clone(), snapshot)
            .expect("the immutable origin remains a valid monetary checkpoint")
    }

    /// The separate fully informed truth loop has no trust classifier,
    /// unknown stretches, anchors, fallback, or normalization. Its caller
    /// excludes withdrawals that empty the account, so each event is simply
    /// an observation followed by its known external cash movement.
    fn fully_informed(
        &self,
        group: &[usize],
        oracle: &BTreeMap<String, Decimal>,
    ) -> Option<RiskEngine> {
        let mut engine = self.engine.clone();
        for index in group {
            let flow = &self.flows[*index];
            let equity = oracle[&flow.id];
            engine.observe(ts(flow.time_ms), equity);
            if equity > Decimal::ZERO {
                engine = moved(&self.limits, &engine, flow.time_ms, equity, flow.amount)?;
            }
        }
        Some(engine)
    }

    /// A neutral stretch applies cash and UTC rolls only. A zero reached by
    /// withdrawal is held at its last positive equity until refill. An
    /// impossible negative cash history yields no inferred trading zero.
    fn money_only(&self, mut engine: RiskEngine, flows: &[&Flow]) -> Option<RiskEngine> {
        let mut empty: Option<Decimal> = None;
        let mut cash = engine.snapshot().last;
        for flow in flows {
            let after = cash.checked_add(flow.amount)?;
            if after < Decimal::ZERO {
                return None;
            }
            if let Some(from) = empty {
                if after > Decimal::ZERO {
                    engine.observe(ts(flow.time_ms), from);
                    engine = moved(&self.limits, &engine, flow.time_ms, from, after - from)?;
                    empty = None;
                    self.emptied.set(self.emptied.get() + 1);
                }
            } else {
                engine.observe(ts(flow.time_ms), cash);
                if cash <= Decimal::ZERO {
                    return None;
                }
                if after.is_zero() {
                    empty = Some(cash);
                } else if cash > Decimal::ZERO {
                    engine = moved(&self.limits, &engine, flow.time_ms, cash, flow.amount)?;
                }
            }
            cash = after;
        }
        if empty.is_some() {
            return None;
        }
        Some(engine)
    }

    fn normalize(
        &self,
        mut engine: RiskEngine,
        equity: Decimal,
        at: Timestamp,
    ) -> Option<RiskEngine> {
        let before = engine.snapshot().last;
        // Roll from the last known value before normalizing its bases.
        engine.observe(at, before);
        let stopped = rank(engine.state()) == 2;
        let mut snapshot = engine.snapshot();
        snapshot.peak = reference_rebase(
            snapshot.peak,
            before,
            equity,
            self.limits.max_trading_equity_usd,
        )
        .or_else(|| stopped.then_some(snapshot.peak.max(equity)))?
        .max(equity);
        snapshot.day_start = reference_rebase(
            snapshot.day_start,
            before,
            equity,
            self.limits.max_trading_equity_usd,
        )
        .or_else(|| stopped.then_some(equity.max(Decimal::ONE)))?;
        snapshot.last = equity;
        // The numerical contract never turns a previously sublimit loss
        // into a stop when an unknown span is merely rescaled.
        let denominator = self
            .limits
            .max_trading_equity_usd
            .map_or(snapshot.peak, |cap| snapshot.peak.min(cap));
        if !stopped && (snapshot.peak - equity) / denominator >= self.limits.drawdown_stop {
            snapshot.peak = (snapshot.peak
                - snapshot.peak.abs().max(Decimal::ONE) * dec!(0.000000000000000000000001))
            .max(equity);
        }
        if !stopped {
            snapshot.state = RiskState::HaltedForDay { day: snapshot.day };
        }

        RiskEngine::restore(self.limits.clone(), snapshot).ok()
    }
}

// ---------------------------------------------------------------------
// The generator
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Latency {
    /// Reported before the next view.
    Now,
    /// Reported after this many ms.
    After(u32),
    /// Never reported.
    Never,
}

#[derive(Debug, Clone)]
enum Op {
    Wait(u32),
    Pnl {
        second: bool,
        units: i32,
    },
    Deposit {
        second: bool,
        units: u32,
        latency: Latency,
    },
    Withdraw {
        second: bool,
        share: u8,
        latency: Latency,
    },
    Transfer {
        to_second: bool,
        share: u8,
        fee: bool,
        latency: Latency,
    },
    View {
        lag: u16,
        second_after: u16,
        second_lag: u16,
        guard: u16,
    },
    Stale {
        back: u8,
    },
    Restart,
}

fn latency(never: bool) -> impl Strategy<Value = Latency> {
    let never_weight = u32::from(never);
    prop_oneof![
        6 => Just(Latency::Now),
        3 => (0u32..3_000).prop_map(Latency::After),
        2 => (3_000u32..60_000).prop_map(Latency::After),
        1 => (60_000u32..600_000).prop_map(Latency::After),
        never_weight => Just(Latency::Never),
    ]
}

fn op(never: bool, restarts: bool) -> impl Strategy<Value = Op> {
    let restart_weight = u32::from(restarts);
    prop_oneof![
        6 => (200u32..8_000).prop_map(Op::Wait),
        6 => (any::<bool>(), -3i32..4).prop_map(|(second, units)| Op::Pnl { second, units }),
        1 => (any::<bool>(), -10i32..-3).prop_map(|(second, units)| Op::Pnl { second, units }),
        2 => (any::<bool>(), 1u32..200, latency(never))
            .prop_map(|(second, units, latency)| Op::Deposit { second, units, latency }),
        2 => (any::<bool>(), 1u8..=100, latency(never))
            .prop_map(|(second, share, latency)| Op::Withdraw { second, share, latency }),
        1 => (any::<bool>(), 1u8..=100, any::<bool>(), latency(never)).prop_map(
            |(to_second, share, fee, latency)| Op::Transfer { to_second, share, fee, latency }
        ),
        8 => (0u16..2_000, 0u16..700, 0u16..2_000, 0u16..400).prop_map(
            |(lag, second_after, second_lag, guard)| Op::View { lag, second_after, second_lag, guard }
        ),
        1 => (1u8..6).prop_map(|back| Op::Stale { back }),
        restart_weight => Just(Op::Restart),
    ]
}

#[derive(Debug, Clone)]
struct Setup {
    /// Start, in ms after midnight of day 20,000 (some cross midnight).
    start: i64,
    /// Starting equity, in units, on the main dex and the second.
    main: i64,
    second: i64,
    cap: Option<i64>,
    /// What the flows' values are (S5): 0 none read, 1 all exact (no
    /// position open), 2 mixed: none, exact, or a range a unit either side.
    values: u8,
}

fn setup(two_dexes: bool) -> impl Strategy<Value = Setup> {
    let start = prop_oneof![0i64..DAY, (DAY - 300_000)..DAY];
    let second = if two_dexes {
        (0i64..80).boxed()
    } else {
        Just(0i64).boxed()
    };
    (
        start,
        60i64..250,
        second,
        prop_oneof![Just(None), Just(Some(20)), Just(Some(25))],
        0u8..3,
    )
        .prop_map(|(start, main, second, cap, values)| Setup {
            start,
            main,
            second,
            cap,
            values,
        })
}

#[derive(Debug, Clone)]
enum Event {
    View(usize),
    Report(usize),
    Restart,
}

/// A built timeline: what really happened, and what Guard is fed.
#[derive(Debug, Clone)]
struct Timeline {
    limits: RiskLimits,
    start: Timestamp,
    equity: Decimal,
    views: Vec<SeenView>,
    /// For each view, the venue times of the state it holds.
    states: Vec<BTreeMap<String, i64>>,
    flows: Vec<Flow>,
    /// The true equity just before each flow, by id.
    before: BTreeMap<String, Decimal>,
    /// Trading gains and losses: venue time and amount.
    pnl: Vec<(i64, Decimal)>,
    /// In the order Guard meets them (its clock).
    events: Vec<(i64, Event)>,
}

fn build(setup: &Setup, ops: &[Op], two_dexes: bool) -> Timeline {
    let limits = RiskLimits {
        max_trading_equity_usd: setup.cap.map(|cap| UNIT * Decimal::from(cap)),
        ..RiskLimits::default()
    };
    let origin = 20_000 * DAY + setup.start;
    // The first flow comes clearly after the journal was started (its
    // equity holds every flow up to the margin after it).
    let mut now = origin + MARGIN + 1_000;
    let dexes: Vec<String> = if two_dexes {
        vec![String::new(), SECOND.into()]
    } else {
        vec![String::new()]
    };
    // Each dex's balance changes: venue time and amount in units.
    let mut changes: BTreeMap<String, Vec<(i64, i64)>> = BTreeMap::new();
    let mut balance: BTreeMap<String, i64> = BTreeMap::new();
    balance.insert(String::new(), setup.main);
    if two_dexes {
        balance.insert(SECOND.into(), setup.second);
    }
    let initial = balance.clone();
    let balance_at = |changes: &BTreeMap<String, Vec<(i64, i64)>>, dex: &str, time: i64| -> i64 {
        initial[dex]
            + changes.get(dex).map_or(0, |list| {
                list.iter()
                    .filter(|(at, _)| *at <= time)
                    .map(|(_, units)| units)
                    .sum()
            })
    };
    let mut timeline = Timeline {
        limits,
        start: ts(origin),
        equity: UNIT * Decimal::from(setup.main + if two_dexes { setup.second } else { 0 }),
        views: Vec::new(),
        states: Vec::new(),
        flows: Vec::new(),
        before: BTreeMap::new(),
        pnl: Vec::new(),
        events: Vec::new(),
    };
    let mut last_at = origin;
    let values = setup.values;
    let report = |timeline: &mut Timeline, mut flow: Flow, latency: Latency, total: i64| {
        let truth = UNIT * Decimal::from(total);
        let kind = if values == 2 {
            timeline.flows.len() % 4
        } else {
            usize::from(values)
        };
        flow.value = match kind {
            1 => Some(ValueRange::cash_exact(truth)),
            2 => Some(ValueRange {
                lo: truth - UNIT,
                hi: truth + UNIT,
                cash_exact: false,
            }),
            3 => Some(ValueRange {
                lo: truth,
                hi: truth,
                cash_exact: false,
            }),
            _ => None,
        };
        let at = match latency {
            Latency::Now => Some(flow.time_ms),
            Latency::After(ms) => Some(flow.time_ms + i64::from(ms)),
            Latency::Never => None,
        };
        timeline
            .before
            .insert(flow.id.clone(), UNIT * Decimal::from(total));
        timeline.flows.push(flow);
        if let Some(at) = at {
            timeline
                .events
                .push((at, Event::Report(timeline.flows.len() - 1)));
        }
    };
    for op in ops {
        let total: i64 = balance.values().sum();
        let pick = |second: bool| -> String {
            if second && two_dexes {
                SECOND.into()
            } else {
                String::new()
            }
        };
        match op {
            Op::Wait(ms) => now += i64::from(*ms),
            Op::Pnl { second, units } => {
                let dex = pick(*second);
                let units = (*units).max(-(balance[&dex] as i32)) as i64;
                if units != 0 {
                    now += 1;
                    *balance.get_mut(&dex).unwrap() += units;
                    changes.entry(dex).or_default().push((now, units));
                    timeline.pnl.push((now, UNIT * Decimal::from(units)));
                }
            }
            Op::Deposit {
                second,
                units,
                latency,
            } => {
                let dex = pick(*second);
                let units = i64::from(*units).min(MOST - total);
                if units > 0 {
                    now += 1;
                    *balance.get_mut(&dex).unwrap() += units;
                    changes.entry(dex.clone()).or_default().push((now, units));
                    let id = format!("d{}", timeline.flows.len());
                    report(
                        &mut timeline,
                        Flow {
                            time_ms: now,
                            amount: UNIT * Decimal::from(units),
                            id,
                            dex,
                            between: false,
                            value: None,
                        },
                        *latency,
                        total,
                    );
                }
            }
            Op::Withdraw {
                second,
                share,
                latency,
            } => {
                let dex = pick(*second);
                let units = (balance[&dex] * i64::from(*share) + 99) / 100;
                if units > 0 {
                    now += 1;
                    *balance.get_mut(&dex).unwrap() -= units;
                    changes.entry(dex.clone()).or_default().push((now, -units));
                    let id = format!("w{}", timeline.flows.len());
                    report(
                        &mut timeline,
                        Flow {
                            time_ms: now,
                            amount: -UNIT * Decimal::from(units),
                            id,
                            dex,
                            between: false,
                            value: None,
                        },
                        *latency,
                        total,
                    );
                }
            }
            Op::Transfer {
                to_second,
                share,
                fee,
                latency,
            } => {
                if !two_dexes {
                    continue;
                }
                let (from, to) = if *to_second {
                    (String::new(), SECOND.to_owned())
                } else {
                    (SECOND.to_owned(), String::new())
                };
                let fee = i64::from(*fee);
                let units = (balance[&from] * i64::from(*share) / 100).min(balance[&from] - fee);
                if units > 0 {
                    now += 1;
                    *balance.get_mut(&from).unwrap() -= units + fee;
                    *balance.get_mut(&to).unwrap() += units;
                    changes
                        .entry(from.clone())
                        .or_default()
                        .push((now, -units - fee));
                    changes.entry(to).or_default().push((now, units));
                    let id = format!("t{}", timeline.flows.len());
                    report(
                        &mut timeline,
                        Flow {
                            time_ms: now,
                            amount: -UNIT * Decimal::from(fee),
                            id,
                            dex: from,
                            between: true,
                            value: None,
                        },
                        *latency,
                        total,
                    );
                }
            }
            Op::View {
                lag,
                second_after,
                second_lag,
                guard,
            } => {
                now += 1;
                // The main dex answers at `now`, holding the state `lag` ms
                // before; the second dex is read after it.
                let mut times = BTreeMap::new();
                let mut state = BTreeMap::new();
                let mut equity = 0i64;
                for (index, dex) in dexes.iter().enumerate() {
                    let (answer, behind) = if index == 0 {
                        (now, i64::from(*lag))
                    } else {
                        (now + i64::from(*second_after), i64::from(*second_lag))
                    };
                    let held = answer - behind;
                    times.insert(dex.clone(), answer);
                    state.insert(dex.clone(), held);
                    equity += balance_at(&changes, dex, held);
                }
                let read = times.values().copied().max().unwrap_or(now);
                let at = (read + i64::from(*guard)).max(last_at);
                last_at = at;
                timeline.views.push(SeenView {
                    at: ts(at),
                    times,
                    equity: UNIT * Decimal::from(equity),
                });
                timeline.states.push(state);
                timeline
                    .events
                    .push((at, Event::View(timeline.views.len() - 1)));
            }
            Op::Stale { back } => {
                let count = timeline.views.len();
                let back = usize::from(*back);
                if count > back {
                    let mut old = timeline.views[count - 1 - back].clone();
                    old.at = ts(last_at);
                    let state = timeline.states[count - 1 - back].clone();
                    timeline.views.push(old);
                    timeline.states.push(state);
                    timeline.events.push((last_at, Event::View(count)));
                }
            }
            Op::Restart => timeline.events.push((last_at, Event::Restart)),
        }
    }
    // Guard's clock order; at the same time, reports before restarts
    // before views (a report "now" is known before the next view).
    timeline.events.sort_by_key(|(at, event)| {
        (
            *at,
            match event {
                Event::Report(_) => 0,
                Event::Restart => 1,
                Event::View(_) => 2,
            },
        )
    });
    timeline
}

// ---------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "zunder-flows-model-{}-{unique}",
            std::process::id()
        ));
        fs::remove_dir_all(&path).ok();
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn journal(&self) -> PathBuf {
        self.0.join("risk.jsonl")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

/// Every view the journal holds: in records of their own and in `flowed`
/// records' lists.
fn journaled(records: &[JournalRecord]) -> BTreeSet<String> {
    let key = |view: &SeenView| serde_json::to_string(view).unwrap();
    let mut out = BTreeSet::new();
    for record in records {
        if let Some(view) = &record.view {
            out.insert(key(view));
        }
        if let JournalEvent::Flowed { views, .. } = &record.event {
            out.extend(views.iter().map(key));
        }
    }
    out
}

/// What a run of the implementation saw, to build its reference with.
struct Run<'a> {
    timeline: &'a Timeline,
    dir: Dir,
    /// `None` only while it is reopened.
    risk: Option<PersistentRisk>,
    /// The views fed and not ignored, by index into the timeline's, with
    /// the journal's record count right after each; those a restart forgot
    /// entirely (after the last record), and those it forgot but a later
    /// record holds the times of.
    fed: Vec<(usize, usize)>,
    forgotten: BTreeSet<usize>,
    ghosts: BTreeSet<usize>,
    /// Decisions already checked against the oracle are durable human
    /// knowledge. A later ledger report may omit their original view
    /// during replay, but cannot revoke the decision without human review.
    decisions: BTreeMap<usize, RiskState>,
    /// The flows reported so far, in order, and those the implementation
    /// skipped.
    reported: Vec<usize>,
    skipped: BTreeSet<usize>,
    /// Whether a view that showed a flow not yet reported was taken.
    tainted: bool,
    /// Steps compared.
    steps: usize,
    /// Coverage: restarts, and flows applied when reported (late).
    restarts: usize,
    late: usize,
    ignored: usize,
}

impl<'a> Run<'a> {
    fn new(timeline: &'a Timeline) -> Self {
        let dir = Dir::new();
        let risk = PersistentRisk::initialise(
            &dir.journal(),
            timeline.limits.clone(),
            timeline.start,
            timeline.equity,
            "flows model",
        )
        .unwrap()
        .with_flows();
        Self {
            timeline,
            dir,
            risk: Some(risk),
            fed: Vec::new(),
            forgotten: BTreeSet::new(),
            ghosts: BTreeSet::new(),
            decisions: BTreeMap::new(),
            reported: Vec::new(),
            skipped: BTreeSet::new(),
            tainted: false,
            steps: 0,
            restarts: 0,
            late: 0,
            ignored: 0,
        }
    }

    fn risk(&mut self) -> &mut PersistentRisk {
        self.risk.as_mut().expect("open")
    }

    fn snapshot(&self) -> RiskSnapshot {
        self.risk.as_ref().expect("open").engine().snapshot()
    }

    fn records(&self) -> Vec<JournalRecord> {
        PersistentRisk::read(&self.dir.journal()).expect("the reader accepts the journal")
    }

    fn step(&mut self, at: i64, event: &Event) -> Result<(), TestCaseError> {
        if std::env::var("ZUNDER_FLOWS_TRACE").is_ok() {
            let what = match event {
                Event::Report(index) => format!("report {:?}", self.timeline.flows[*index]),
                Event::View(index) => format!("view {:?}", self.timeline.views[*index]),
                Event::Restart => "restart".to_owned(),
            };
            println!("at {at}: {what}");
        }
        match event {
            Event::Report(index) => {
                let flow = &self.timeline.flows[*index];
                let before = rank(self.snapshot().state);
                let outcome = self
                    .risk()
                    .apply_flow(ts(at), flow)
                    .map_err(|error| TestCaseError::fail(format!("apply_flow: {error}")))?;
                // A replay can take views left out before (a group no
                // history fitted until this flow was known): stricter for
                // a flow still unreported that one of them shows is D1's.
                if rank(self.snapshot().state) > before {
                    let shown_unreported = self.fed.iter().any(|(view, _)| {
                        let times = &self.timeline.views[*view].times;
                        self.timeline.flows.iter().enumerate().any(|(i, other)| {
                            i != *index
                                && !self.reported.contains(&i)
                                && side(other, times) != Side::Before
                        })
                    });
                    if shown_unreported {
                        self.tainted = true;
                    }
                }
                if let FlowOutcome::Skipped(why) = &outcome {
                    if flow.amount.is_zero() && !flow.between {
                        self.skipped.insert(*index);
                    } else {
                        return Err(TestCaseError::fail(format!("{} skipped: {why}", flow.id)));
                    }
                }
                prop_assert_ne!(&outcome, &FlowOutcome::Duplicate);
                if outcome == FlowOutcome::Applied {
                    self.late += 1;
                }
                self.reported.push(*index);
            }
            Event::View(index) => {
                let view = &self.timeline.views[*index];
                let unreported: Vec<&Flow> = self
                    .timeline
                    .flows
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !self.reported.contains(i))
                    .map(|(_, flow)| flow)
                    .collect();
                let sync = self.risk().observe_view_at(
                    view.at,
                    view.times.clone(),
                    view.equity,
                    &VenueView::default(),
                    true,
                );
                prop_assert_eq!(&sync.journal_error, &None);
                if sync.ignored {
                    self.ignored += 1;
                    return self.check();
                }
                if sync.taken
                    && unreported
                        .iter()
                        .any(|flow| side(flow, &view.times) != Side::Before)
                {
                    self.tainted = true;
                }
                let count = self.records().len();
                self.fed.push((*index, count));
            }
            Event::Restart => {
                let records = self.records();
                let on_journal = journaled(&records);
                for (index, count) in &self.fed {
                    let key = serde_json::to_string(&self.timeline.views[*index]).unwrap();
                    if on_journal.contains(&key) || self.forgotten.contains(index) {
                        continue;
                    }
                    if *count == records.len() {
                        self.forgotten.insert(*index);
                    } else {
                        self.ghosts.insert(*index);
                    }
                }
                // Independently of the reference: a restart forgets at most a
                // fall of the last equity within δ of the day's start (or
                // the cap), nothing else.
                let memory = self.snapshot();
                let written = &records.last().unwrap().state;
                let base = self
                    .timeline
                    .limits
                    .max_trading_equity_usd
                    .map_or(written.day_start, |cap| written.day_start.min(cap));
                prop_assert_eq!(
                    (memory.state, memory.peak, memory.day, memory.day_start),
                    (written.state, written.peak, written.day, written.day_start)
                );
                prop_assert!(
                    memory.last <= written.last && written.last - memory.last <= base * DELTA,
                    "a restart forgets {} - {}, more than δ of {}",
                    written.last,
                    memory.last,
                    base
                );
                // The journal is locked while open: close it first.
                self.restarts += 1;
                self.risk = None;
                let fresh = PersistentRisk::open(&self.dir.journal(), &self.timeline.limits)
                    .map_err(|error| TestCaseError::fail(format!("reopening: {error}")))?
                    .with_flows();
                self.risk = Some(fresh);
                // What the last record holds, exactly.
                let last = records.last().unwrap();
                prop_assert_eq!(&self.snapshot(), &last.state);
                // Guard reads the ledger again from the journal's horizon.
                let from = self.risk().flows_from_ms();
                for index in self.reported.clone() {
                    let flow = &self.timeline.flows[index];
                    if flow.time_ms >= from && !self.skipped.contains(&index) {
                        let outcome = self.risk().apply_flow(ts(at), flow).map_err(|error| {
                            TestCaseError::fail(format!("apply_flow after a restart: {error}"))
                        })?;
                        prop_assert!(
                            matches!(outcome, FlowOutcome::Duplicate | FlowOutcome::Pending),
                            "{} again after a restart: {:?}",
                            flow.id,
                            outcome
                        );
                    }
                }
            }
        }
        self.check()
    }

    /// The reference fed what the implementation knows.
    fn reference(&self) -> Model {
        let flows: Vec<Flow> = self
            .reported
            .iter()
            .filter(|index| !self.skipped.contains(index))
            .map(|index| self.timeline.flows[*index].clone())
            .collect();
        let mut model = Model::new(
            &self.timeline.limits,
            self.timeline.start,
            self.timeline.equity,
            flows,
        );
        for (index, _) in &self.fed {
            if self.ghosts.contains(index) {
                model.ghost(&self.timeline.views[*index]);
            } else if !self.forgotten.contains(index) {
                model.view(&self.timeline.views[*index]);
            }
            if let Some(decision) = self.decisions.get(index) {
                let mut snapshot = model.engine.snapshot();
                let applicable = match decision {
                    RiskState::Stopped { .. } => true,
                    RiskState::HaltedForDay { day } => *day == snapshot.day,
                    RiskState::Active => false,
                };
                if applicable && rank(*decision) > rank(snapshot.state) {
                    snapshot.state = *decision;
                    model.engine = RiskEngine::restore(self.timeline.limits.clone(), snapshot)
                        .expect("a validated decision preserves the oracle's valid figures");
                }
            }
        }
        model
    }

    fn check(&mut self) -> Result<(), TestCaseError> {
        self.steps += 1;
        let model = self.reference();
        let (got, want) = (self.snapshot(), model.engine.snapshot());
        let figures = |s: &RiskSnapshot| (s.day, s.peak, s.day_start, s.last);
        if std::env::var("ZUNDER_FLOWS_TRACE").is_ok() {
            println!(
                "step {}: implementation {:?} {:?}; reference {:?} {:?}",
                self.steps,
                got.state,
                figures(&got),
                want.state,
                figures(&want)
            );
        }
        prop_assert_eq!(
            figures(&got),
            figures(&want),
            "figures, step {}",
            self.steps
        );
        prop_assert!(
            rank(got.state) >= rank(want.state),
            "looser than the reference: {:?} against {:?}",
            got.state,
            want.state
        );
        if let (RiskState::HaltedForDay { day: a }, RiskState::HaltedForDay { day: b }) =
            (got.state, want.state)
        {
            prop_assert_eq!(a, b);
        }
        if !self.tainted {
            prop_assert_eq!(rank(got.state), rank(want.state), "stricter without cause");
        }
        if model.applied.iter().any(|applied| !applied) {
            // An unresolved known cash event blocks entries independently
            // of UTC risk state, including immediately after a restart.
            prop_assert!(matches!(
                self.risk().check_ready(),
                Err(JournalError::PendingFlows | JournalError::NotObserved)
            ));
        }
        // Record only after this step passed. Injecting the current result
        // before comparison would conceal newly manufactured stops.
        if let Some((index, _)) = self.fed.last()
            && rank(got.state) > 0
        {
            self.decisions.insert(*index, got.state);
        }
        Ok(())
    }
}

/// What one run went through, summed over runs by the coverage test.
#[derive(Debug, Default, Clone)]
struct Coverage {
    runs: usize,
    steps: usize,
    flows: usize,
    flowed: usize,
    replayed_over_records: usize,
    late: usize,
    restarts: usize,
    tainted: usize,
    halted: usize,
    stopped: usize,
    left: usize,
    ignored: usize,
    multi: usize,
    splits: usize,
    downgraded: usize,
    emptied: usize,
    impossible: usize,
    transfers: usize,
    capped: usize,
    midnight: usize,
}

impl Coverage {
    fn add(&mut self, other: &Self) {
        self.runs += other.runs;
        self.steps += other.steps;
        self.flows += other.flows;
        self.flowed += other.flowed;
        self.replayed_over_records += other.replayed_over_records;
        self.late += other.late;
        self.restarts += other.restarts;
        self.tainted += other.tainted;
        self.halted += other.halted;
        self.stopped += other.stopped;
        self.left += other.left;
        self.ignored += other.ignored;
        self.multi += other.multi;
        self.splits += other.splits;
        self.downgraded += other.downgraded;
        self.emptied += other.emptied;
        self.impossible += other.impossible;
        self.transfers += other.transfers;
        self.capped += other.capped;
        self.midnight += other.midnight;
    }
}

fn run(timeline: &Timeline) -> Result<(usize, RiskSnapshot), TestCaseError> {
    run_covered(timeline).map(|(steps, snapshot, _)| (steps, snapshot))
}

fn run_covered(timeline: &Timeline) -> Result<(usize, RiskSnapshot, Coverage), TestCaseError> {
    let mut run = Run::new(timeline);
    for (at, event) in &timeline.events {
        run.step(*at, event)?;
    }
    // The reader accepts the whole journal, and opening it gives its last
    // record.
    let records = run.records();
    prop_assert!(!records.is_empty());
    let last = records.last().unwrap();
    let now = run.snapshot();
    prop_assert_eq!(
        (
            last.state.state,
            last.state.peak,
            last.state.day,
            last.state.day_start
        ),
        (now.state, now.peak, now.day, now.day_start)
    );
    let model = run.reference();
    let coverage = Coverage {
        runs: 1,
        steps: run.steps,
        flows: timeline.flows.len(),
        flowed: records
            .iter()
            .filter(|record| matches!(record.event, JournalEvent::Flowed { .. }))
            .count(),
        replayed_over_records: records
            .iter()
            .filter(|record| matches!(record.event, JournalEvent::Flowed { base, .. } if base + 1 < record.seq))
            .count(),
        late: run.late,
        restarts: run.restarts,
        tainted: usize::from(run.tainted),
        halted: usize::from(records.iter().any(|record| matches!(record.state.state, RiskState::HaltedForDay { .. }))),
        stopped: usize::from(records.iter().any(|record| matches!(record.state.state, RiskState::Stopped { .. }))),
        left: model.left,
        ignored: run.ignored,
        multi: model.multi,
        splits: model.splits.get(),
        downgraded: model.downgraded.get(),
        emptied: model.emptied.get(),
        impossible: model.impossible.get(),
        transfers: timeline.flows.iter().filter(|flow| flow.between).count(),
        capped: usize::from(timeline.limits.max_trading_equity_usd.is_some()),
        midnight: usize::from(now.day > timeline.start.utc_day()),
    };
    Ok((run.steps, now, coverage))
}

/// The generator reaches every path the invariants are about: a run of
/// generated cases, with what they went through counted and printed
/// (`cargo test -p zunder-venue --test flows_model -- --nocapture`).
#[test]
fn the_generator_reaches_every_path() {
    use proptest::{strategy::ValueTree, test_runner::TestRunner};
    // At least 400 cases, from a fixed seed: the rarest path (a loss after
    // an emptied account was filled again) comes about once in 30.
    let cases = std::env::var("ZUNDER_FLOWS_CASES")
        .ok()
        .and_then(|cases| cases.parse().ok())
        .unwrap_or(4_000usize)
        .max(400);
    let mut runner = TestRunner::deterministic();
    let strategy = (
        any::<bool>(),
        setup(true),
        prop::collection::vec(op(true, true), 1..160),
    );
    let mut total = Coverage::default();
    for case in 0..cases {
        let (two, setup, ops) = strategy.new_tree(&mut runner).unwrap().current();
        let setup = Setup {
            second: if two { setup.second } else { 0 },
            ..setup
        };
        let timeline = build(&setup, &ops, two);
        let (_, _, coverage) = run_covered(&timeline).unwrap_or_else(|error| {
            panic!("case {case}: {error}\nTWO {two} SETUP {setup:?}\nOPS {ops:?}")
        });
        total.add(&coverage);
    }
    println!("flows model coverage over {cases} generated cases: {total:#?}");
    let every = [
        ("flowed records", total.flowed),
        ("replays over written records", total.replayed_over_records),
        ("flows applied late", total.late),
        ("restarts", total.restarts),
        ("runs with a view showing an unreported flow", total.tainted),
        ("runs halted", total.halted),
        ("runs stopped", total.stopped),
        ("views left out", total.left),
        ("views ignored", total.ignored),
        ("groups of two flows or more", total.multi),
        (
            "ambiguous groups that would stop, counted as a halt",
            total.downgraded,
        ),
        (
            "histories with an account emptied and refilled",
            total.emptied,
        ),
        ("histories that cannot have happened", total.impossible),
        ("transfers between dexes", total.transfers),
        ("capped runs", total.capped),
        ("runs across midnight", total.midnight),
    ];
    for (what, count) in every {
        assert!(count > 0, "the generator never reached: {what}");
    }
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: std::env::var("ZUNDER_FLOWS_CASES")
            .ok()
            .and_then(|cases| cases.parse().ok())
            .unwrap_or(4_000),
        max_shrink_iters: 2_000,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// I1, I2: the implementation against the reference, with late,
    /// out-of-order and missing reports and restarts, one dex or two.
    #[test]
    fn the_implementation_is_the_reference(
        two in any::<bool>(),
        setup in setup(true),
        ops in prop::collection::vec(op(true, true), 1..160),
    ) {
        let setup = Setup { second: if two { setup.second } else { 0 }, ..setup };
        let timeline = build(&setup, &ops, two);
        run(&timeline)?;
    }

    /// I1's special case: every flow reported as it happens, so the
    /// implementation is the reference exactly, the state included, with
    /// restarts.
    #[test]
    fn the_implementation_is_the_reference_when_told_in_time(
        two in any::<bool>(),
        setup in setup(true),
        ops in prop::collection::vec(op(false, true), 1..160),
    ) {
        let setup = Setup { second: if two { setup.second } else { 0 }, ..setup };
        let mut timeline = build(&setup, &ops, two);
        // In time: before any view could show it, its margin included
        // (a test's privilege; Guard learns of a flow after it).
        for (at, event) in &mut timeline.events {
            if let Event::Report(index) = event {
                *at = timeline.flows[*index].time_ms - MARGIN - 1;
            }
        }
        timeline.events.sort_by_key(|(at, event)| {
            (*at, match event { Event::Report(_) => 0, Event::Restart => 1, Event::View(_) => 2 })
        });
        let (_, _, coverage) = run_covered(&timeline)?;
        prop_assert_eq!(coverage.tainted, 0);
    }

    /// I3: once everything is reported, how and when does not matter.
    #[test]
    fn the_order_of_the_reports_does_not_matter(
        setup in setup(true),
        ops in prop::collection::vec(op(false, false), 1..120),
    ) {
        let timeline = build(&setup, &ops, true);
        let (_, late) = run(&timeline)?;
        // The same flows, each reported as it happens.
        let mut prompt = timeline.clone();
        for (at, event) in &mut prompt.events {
            if let Event::Report(index) = event {
                *at = prompt.flows[*index].time_ms;
            }
        }
        prompt.events.sort_by_key(|(at, event)| (*at, !matches!(event, Event::Report(_))));
        let (_, now) = run(&prompt)?;
        // Every report lands, at the latest after the last view: both know
        // everything at the end.
        let figures = |s: &RiskSnapshot| (s.day, s.peak, s.day_start, s.last);
        prop_assert_eq!(figures(&late), figures(&now));
    }

    /// I8: with every flow's value read exactly (S5: no position open),
    /// the reference is the truth (the true equity just before every
    /// flow), figures and state, at every view.
    #[test]
    fn measured_the_reference_is_the_truth(
        setup in setup(false),
        ops in prop::collection::vec(op_truth(), 1..140),
    ) {
        let setup = Setup { values: 1, ..setup };
        let timeline = build(&setup, &ops, false);
        // The truth model has no reading for an account a flow empties, nor
        // S5 for a view of an empty account.
        prop_assume!(timeline.flows.iter().all(|flow| timeline.before[&flow.id] + flow.amount > Decimal::ZERO));
        prop_assume!(timeline.views.iter().all(|view| view.equity > Decimal::ZERO));
        let mut reference = Model::new(&timeline.limits, timeline.start, timeline.equity, timeline.flows.clone());
        let mut truth = reference.clone();
        truth.oracle = Some(timeline.before.clone());
        for (_, event) in &timeline.events {
            let Event::View(index) = event else { continue };
            let view = &timeline.views[*index];
            reference.view(view);
            truth.view(view);
            let (got, want) = (reference.engine.snapshot(), truth.engine.snapshot());
            prop_assert_eq!((got.day, got.peak, got.day_start, got.last), (want.day, want.peak, want.day_start, want.last));
            prop_assert_eq!(rank(got.state), rank(want.state));
        }
    }

    /// I5: a move keeps the share of a loss as the engine measures it,
    /// with and without the cap, across it.
    #[test]
    fn rebase_keeps_the_share(
        base in 1i64..100_000,
        before in 1i64..100_000,
        after in 1i64..100_000,
        cap in prop_oneof![Just(None), (1i64..50_000).prop_map(Some)],
    ) {
        let (base, before, after) = (Decimal::from(base), Decimal::from(before), Decimal::from(after));
        let cap = cap.map(Decimal::from);
        let share = |base: Decimal, equity: Decimal| (base - equity) / cap.map_or(base, |cap| base.min(cap));
        if let Some(moved) = rebase(base, before, after, cap) {
            prop_assert!(moved > Decimal::ZERO);
            prop_assert!((share(moved, after) - share(base, before)).abs() < dec!(0.00000000000000000001));
            // Back again: where it was.
            if let Some(back) = rebase(moved, after, before, cap) {
                prop_assert!((back - base).abs() / base < dec!(0.00000000000000000001));
            }
        } else {
            // Only a loss of the whole base, or more, has none.
            prop_assert!(share(base, before) >= Decimal::ONE);
        }
    }
}

/// Scenario invariants independent of the reference implementation.
/// A loss below the daily stop (as a share of the account, or of
/// the cap), then any withdrawal up to everything that is left, and perhaps
/// a deposit after it, all between two views (the loss perhaps seen by a
/// view the journal does not hold, then forgotten by a restart). Where the
/// loss came is ambiguous, so it never stops the engine; it can halt the
/// day, read after the withdrawal, unless it was seen before the flows or
/// is within what the journal may not hold (δ): then the engine stays
/// active. The state the run ends in.
fn a_withdrawal_after_a_small_loss(
    equity: i64,
    loss_bps: i64,
    out_percent: i64,
    back: Option<i64>,
    cap: Option<i64>,
    seen: bool,
    restart: bool,
) -> Result<(), TestCaseError> {
    let limits = RiskLimits {
        max_trading_equity_usd: cap.map(Decimal::from),
        ..RiskLimits::default()
    };
    let t0 = 20_000 * DAY + 3_600_000;
    let equity = Decimal::from(equity);
    let measure = limits
        .max_trading_equity_usd
        .map_or(equity, |cap| equity.min(cap));
    let loss = (measure * Decimal::new(loss_bps, 4)).round_dp(2);
    let out = ((equity - loss) * Decimal::new(out_percent, 2))
        .round_dp(2)
        .min(equity - loss);
    let dir = Dir::new();
    let mut risk =
        PersistentRisk::initialise(&dir.journal(), limits.clone(), ts(t0), equity, "small loss")
            .unwrap()
            .with_flows();
    let view = |risk: &mut PersistentRisk, at: i64, equity: Decimal| {
        risk.observe_view_at(
            ts(at),
            [(String::new(), at)].into(),
            equity,
            &VenueView::default(),
            true,
        )
    };
    view(&mut risk, t0 + 5_000, equity);
    if seen {
        view(&mut risk, t0 + 7_000, equity - loss);
    }
    if restart {
        drop(risk);
        risk = PersistentRisk::open(&dir.journal(), &limits)
            .unwrap()
            .with_flows();
    }
    let mut flows = vec![Flow {
        time_ms: t0 + 10_000,
        amount: -out,
        id: "out".into(),
        dex: String::new(),
        between: false,
        value: None,
    }];
    if let Some(back) = back {
        flows.push(Flow {
            time_ms: t0 + 12_000,
            amount: Decimal::from(back),
            id: "back".into(),
            dex: String::new(),
            between: false,
            value: None,
        });
    }
    for flow in &flows {
        let outcome = risk.apply_flow(ts(t0 + 15_000), flow).unwrap();
        prop_assert_eq!(outcome, FlowOutcome::Pending);
    }
    let shown = equity - loss - out + Decimal::from(back.unwrap_or(0));
    let sync = view(&mut risk, t0 + 20_000, shown);
    prop_assert_eq!(&sync.journal_error, &None);
    let state = risk.state();
    let why = format!("loss {loss} then {out} out, back {back:?}: {state:?}");
    prop_assert!(rank(state) < 2, "{}", why);
    if shown > Decimal::ZERO {
        prop_assert_eq!(
            state,
            RiskState::HaltedForDay {
                day: ts(t0 + 20_000).utc_day()
            },
            "{}",
            why
        );
    }
    drop(risk);
    let reopened = PersistentRisk::open(&dir.journal(), &limits).unwrap();
    prop_assert_eq!(reopened.state(), state);
    Ok(())
}

/// A withdrawal seen by a view, then a loss: no question where the loss
/// came, so it counts in full against what is left (peak and day's start
/// moved to what is left, no loss before): halted from 6% of it (or of the
/// cap), stopped from 25%.
fn a_loss_after_a_withdrawal_seen(
    equity: i64,
    out_percent: i64,
    loss_bps: i64,
    cap: Option<i64>,
) -> Result<(), TestCaseError> {
    let limits = RiskLimits {
        max_trading_equity_usd: cap.map(Decimal::from),
        ..RiskLimits::default()
    };
    let t0 = 20_000 * DAY + 3_600_000;
    let equity = Decimal::from(equity);
    let out = (equity * Decimal::new(out_percent, 2)).round_dp(2);
    let left = equity - out;
    let measure = limits
        .max_trading_equity_usd
        .map_or(left, |cap| left.min(cap));
    let loss = (measure * Decimal::new(loss_bps, 4))
        .round_dp(2)
        .min(left - dec!(0.01));
    let dir = Dir::new();
    let mut risk =
        PersistentRisk::initialise(&dir.journal(), limits.clone(), ts(t0), equity, "seen")
            .unwrap()
            .with_flows();
    let view = |risk: &mut PersistentRisk, at: i64, equity: Decimal| {
        let sync = risk.observe_view_at(
            ts(at),
            [(String::new(), at)].into(),
            equity,
            &VenueView::default(),
            true,
        );
        assert_eq!(sync.journal_error, None);
    };
    view(&mut risk, t0 + 5_000, equity);
    let flow = Flow {
        time_ms: t0 + 10_000,
        amount: -out,
        id: "out".into(),
        dex: String::new(),
        between: false,
        value: Some(ValueRange::cash_exact(equity)),
    };
    prop_assert_eq!(
        risk.apply_flow(ts(t0 + 8_000), &flow).unwrap(),
        FlowOutcome::Pending
    );
    view(&mut risk, t0 + 20_000, left);
    let s = risk.engine().snapshot();
    prop_assert_eq!((s.peak, s.day_start), (left, left));
    view(&mut risk, t0 + 30_000, left - loss);
    let share = loss / measure;
    let want = if share >= dec!(0.25) {
        2
    } else if share >= dec!(0.06) {
        1
    } else {
        0
    };
    prop_assert_eq!(
        rank(risk.state()),
        want,
        "{} of {}: {:?}",
        loss,
        measure,
        risk.state()
    );
    Ok(())
}

/// A withdrawal and a loss between the same two views: the loss may have
/// come before it or after. Never a drawdown stop unless the reading before
/// it (the loss against the whole account) stops too; a halt when that
/// reading halts; active within δ.
fn a_loss_next_to_a_withdrawal(
    equity: i64,
    out_percent: i64,
    loss_bps: i64,
    cap: Option<i64>,
    midnight: bool,
) -> Result<(), TestCaseError> {
    let limits = RiskLimits {
        max_trading_equity_usd: cap.map(Decimal::from),
        ..RiskLimits::default()
    };
    // Across midnight: the first view and the withdrawal on day 20,000,
    // the view after them on day 20,001.
    let t0 = if midnight {
        20_001 * DAY - 15_000
    } else {
        20_000 * DAY + 3_600_000
    };
    let equity = Decimal::from(equity);
    let out = (equity * Decimal::new(out_percent, 2)).round_dp(2);
    let measure = limits
        .max_trading_equity_usd
        .map_or(equity, |cap| equity.min(cap));
    let loss = (measure * Decimal::new(loss_bps, 4))
        .round_dp(2)
        .min(equity - out - dec!(0.01));
    let dir = Dir::new();
    let mut risk =
        PersistentRisk::initialise(&dir.journal(), limits.clone(), ts(t0), equity, "next to")
            .unwrap()
            .with_flows();
    let view = |risk: &mut PersistentRisk, at: i64, equity: Decimal| {
        let sync = risk.observe_view_at(
            ts(at),
            [(String::new(), at)].into(),
            equity,
            &VenueView::default(),
            true,
        );
        assert_eq!(sync.journal_error, None);
    };
    view(&mut risk, t0 + 5_000, equity);
    let flow = Flow {
        time_ms: t0 + 10_000,
        amount: -out,
        id: "out".into(),
        dex: String::new(),
        between: false,
        value: None,
    };
    prop_assert_eq!(
        risk.apply_flow(ts(t0 + 8_000), &flow).unwrap(),
        FlowOutcome::Pending
    );
    let shown = equity - out - loss;
    view(&mut risk, t0 + 20_000, shown);
    prop_assert_eq!(
        risk.state(),
        RiskState::HaltedForDay {
            day: ts(t0 + 20_000).utc_day()
        }
    );
    Ok(())
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn a_withdrawal_never_turns_a_small_loss_into_a_stop(
        equity in 1_000i64..100_000,
        loss_bps in 1i64..590,
        out_percent in 1i64..=100,
        back in prop_oneof![Just(None), (1i64..100_000).prop_map(Some)],
        cap in prop_oneof![Just(None), (500i64..2_500).prop_map(Some)],
        seen in any::<bool>(),
        restart in any::<bool>(),
    ) {
        a_withdrawal_after_a_small_loss(equity, loss_bps, out_percent, back, cap, seen, restart)?;
    }

    #[test]
    fn an_unambiguous_loss_after_a_withdrawal_counts_in_full(
        equity in 1_000i64..100_000,
        out_percent in 1i64..=95,
        loss_bps in 1i64..5_000,
        cap in prop_oneof![Just(None), (500i64..2_500).prop_map(Some)],
    ) {
        a_loss_after_a_withdrawal_seen(equity, out_percent, loss_bps, cap)?;
    }

    #[test]
    fn an_ambiguous_loss_next_to_a_withdrawal_never_stops_the_engine(
        equity in 1_000i64..100_000,
        out_percent in 1i64..=95,
        loss_bps in 1i64..10_000,
        cap in prop_oneof![Just(None), (500i64..2_500).prop_map(Some)],
        midnight in any::<bool>(),
    ) {
        a_loss_next_to_a_withdrawal(equity, out_percent, loss_bps, cap, midnight)?;
    }
}

/// Regression scenarios: a fee, then everything
/// withdrawn; a fall the journal did not hold, a restart, then all but 25
/// withdrawn.
#[test]
fn a_fee_then_everything_withdrawn_stops_nothing() {
    a_withdrawal_after_a_small_loss(10_000, 5, 100, None, None, false, false).unwrap();
    a_withdrawal_after_a_small_loss(10_000, 5, 100, None, None, true, true).unwrap();
    a_withdrawal_after_a_small_loss(10_000, 9, 100, Some(25), None, true, true).unwrap();
    a_withdrawal_after_a_small_loss(10_000, 45, 100, Some(25), Some(2_000), true, true).unwrap();
}

fn op_truth() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => (200u32..8_000).prop_map(Op::Wait),
        6 => (-12i32..8).prop_map(|units| Op::Pnl { second: false, units }),
        2 => (1u32..200).prop_map(|units| Op::Deposit { second: false, units, latency: Latency::Now }),
        2 => (1u8..=90).prop_map(|share| Op::Withdraw { second: false, share, latency: Latency::Now }),
        8 => (0u16..2_000, 0u16..400).prop_map(|(lag, guard)| Op::View { lag, second_after: 0, second_lag: 0, guard }),
    ]
}

/// Found by a run of 4,000 cases (two dexes, transfers, a late
/// withdrawal, a restart).
#[test]
fn case_late_withdrawal_after_transfers() {
    let setup = Setup {
        start: 0,
        main: 185,
        second: 41,
        cap: None,
        values: 0,
    };
    let now = Latency::Now;
    let view = |second_after, second_lag, guard| Op::View {
        lag: 0,
        second_after,
        second_lag,
        guard,
    };
    let ops = vec![
        Op::Deposit {
            second: false,
            units: 64,
            latency: now,
        },
        Op::Transfer {
            to_second: true,
            share: 33,
            fee: false,
            latency: now,
        },
        Op::Wait(200),
        Op::Transfer {
            to_second: false,
            share: 33,
            fee: false,
            latency: now,
        },
        Op::Withdraw {
            second: true,
            share: 21,
            latency: now,
        },
        Op::Wait(200),
        Op::Deposit {
            second: false,
            units: 10,
            latency: now,
        },
        Op::Deposit {
            second: false,
            units: 30,
            latency: now,
        },
        Op::Transfer {
            to_second: false,
            share: 88,
            fee: false,
            latency: now,
        },
        Op::Deposit {
            second: false,
            units: 46,
            latency: now,
        },
        Op::Withdraw {
            second: false,
            share: 98,
            latency: now,
        },
        Op::Pnl {
            second: false,
            units: -3,
        },
        Op::Pnl {
            second: false,
            units: 2,
        },
        Op::Pnl {
            second: false,
            units: -3,
        },
        Op::Wait(1996),
        view(0, 0, 0),
        Op::Withdraw {
            second: false,
            share: 67,
            latency: Latency::After(7632),
        },
        Op::Pnl {
            second: false,
            units: 3,
        },
        Op::Wait(1996),
        Op::Wait(200),
        Op::Pnl {
            second: true,
            units: 2,
        },
        view(0, 2, 0),
        view(310, 0, 0),
        view(217, 0, 93),
        Op::Wait(200),
        Op::Restart,
    ];
    let timeline = build(&setup, &ops, true);
    run(&timeline).unwrap();
}

proptest! {
    #![proptest_config(config())]

    /// The immutable original cash checkpoint survives multiple UTC days,
    /// ordinary retention limits, reverse reports and restart. Settlement
    /// applies each prefix/withdrawal/refill exactly once before readiness.
    #[test]
    fn deferred_origin_survives_days_and_settles_money_once(
        base in 5000i64..50000,
        deposit in 1i64..5000,
        cap in prop_oneof![Just(None), (500i64..2500).prop_map(Some)],
        stop in any::<bool>(),
        reverse in any::<bool>(),
        restart in any::<bool>(),
        days in 2i64..5,
    ) {
        let base = Decimal::from(base);
        let deposit = Decimal::from(deposit);
        let limits = RiskLimits { max_trading_equity_usd: cap.map(Decimal::from), ..RiskLimits::default() };
        let denominator = limits.max_trading_equity_usd.map_or(base, |cap| base.min(cap));
        let before = base - denominator * if stop { dec!(0.30) } else { dec!(0.07) };
        let origin = 20000 * DAY + DAY - 20000;
        let zero_at = origin + 30000;
        let refill_at = origin + days * DAY + 40000;
        let flows = vec![
            Flow { time_ms: origin+5000, amount: deposit, id: "prefix".into(), dex: String::new(), between: false, value: Some(ValueRange::cash_exact(before)) },
            Flow { time_ms: origin+10000, amount: -(before+deposit), id: "empty".into(), dex: String::new(), between: false, value: None },
            Flow { time_ms: refill_at-5000, amount: base, id: "refill".into(), dex: String::new(), between: false, value: None },
        ];
        let dir = Dir::new();
        let mut risk = PersistentRisk::initialise(&dir.journal(), limits.clone(), ts(origin), base, "deferred origin").unwrap().with_flows();
        for index in if reverse { [1,0] } else { [0,1] } { risk.apply_flow(ts(origin), &flows[index]).unwrap(); }
        let mut model = Model::new(&limits, ts(origin), base, flows[..2].to_vec());
        for at in [zero_at, refill_at-10000] {
            let view = SeenView { at: ts(at), times: [(String::new(), at)].into(), equity: Decimal::ZERO };
            let sync = risk.observe_view_at(view.at, view.times.clone(), view.equity, &VenueView::default(), true);
            prop_assert_eq!(sync.journal_error, None);
            model.view(&view);
            prop_assert_eq!(risk.engine().snapshot(), model.engine.snapshot());
            prop_assert_eq!(risk.check_ready(), Err(JournalError::PendingFlows));
            if restart {
                drop(risk);
                risk = PersistentRisk::open(&dir.journal(), &limits).unwrap().with_flows();
                prop_assert_eq!(risk.engine().snapshot(), model.engine.snapshot());
            }
        }
        risk.apply_flow(ts(refill_at-5000), &flows[2]).unwrap();
        model.flows.push(flows[2].clone());
        model.applied.push(false);
        let view = SeenView { at: ts(refill_at), times: [(String::new(), refill_at)].into(), equity: base };
        let sync = risk.observe_view_at(view.at, view.times.clone(), view.equity, &VenueView::default(), true);
        prop_assert_eq!(sync.journal_error, None);
        model.view(&view);
        let got = risk.engine().snapshot();
        let want = model.engine.snapshot();
        // Independent algebra can differ in the final Decimal place after
        // repeated division; this family compares twelve decimal places.
        prop_assert_eq!((got.peak.round_dp(12),got.day_start.round_dp(12),got.last,got.day,rank(got.state)), (want.peak.round_dp(12),want.day_start.round_dp(12),want.last,want.day,rank(want.state)));
        prop_assert!(risk.check_ready().is_ok());
        let settled = risk.engine().snapshot();
        drop(risk);
        risk = PersistentRisk::open(&dir.journal(), &limits).unwrap().with_flows();
        for flow in &flows { prop_assert_eq!(risk.apply_flow(ts(refill_at+1000), flow).unwrap(), FlowOutcome::Duplicate); }
        prop_assert_eq!(&risk.engine().snapshot(), &settled);
        prop_assert_eq!(rank(settled.state), if stop { 2 } else { 1 });
    }

    /// A known exact-prefix stop survives every unreadable suffix, late
    /// delivery order, UTC rollover and restart in this generated family.
    #[test]
    fn exact_prefix_stop_survives_unknown_suffix(
        base in 1000i64..100000,
        incoming in 1i64..10000,
        cap in prop_oneof![Just(None), (500i64..2500).prop_map(Some)],
        reverse in any::<bool>(),
        late in any::<bool>(),
        restart in any::<bool>(),
        midnight in any::<bool>(),
    ) {
        let base = Decimal::from(base);
        let limits = RiskLimits { max_trading_equity_usd: cap.map(Decimal::from), ..RiskLimits::default() };
        let denominator = limits.max_trading_equity_usd.map_or(base, |cap| base.min(cap));
        let before = base - denominator * dec!(0.30);
        let origin = 20000 * DAY + if midnight { DAY - 15000 } else { 3600000 };
        let flows = [
            Flow { time_ms: origin + 5000, amount: Decimal::ONE, id: "known".into(), dex: String::new(), between: false, value: Some(ValueRange::cash_exact(before)) },
            Flow { time_ms: origin + 10000, amount: Decimal::from(incoming), id: "unknown".into(), dex: String::new(), between: false, value: None },
        ];
        let shown = before + Decimal::ONE + Decimal::from(incoming);
        let at = origin + 20000;
        let dir = Dir::new();
        let mut risk = PersistentRisk::initialise(&dir.journal(), limits.clone(), ts(origin), base, "known prefix").unwrap().with_flows();
        if late { risk.observe_view_at(ts(at), [(String::new(), at)].into(), shown, &VenueView::default(), true); }
        for index in if reverse { [1,0] } else { [0,1] } { risk.apply_flow(ts(at + 1000), &flows[index]).unwrap(); }
        if restart {
            drop(risk);
            risk = PersistentRisk::open(&dir.journal(), &limits).unwrap().with_flows();
            for flow in &flows { risk.apply_flow(ts(at + 2000), flow).unwrap(); }
        }
        risk.observe_view_at(ts(at + 5000), [(String::new(), at + 5000)].into(), shown, &VenueView::default(), true);
        prop_assert!(matches!(risk.state(), RiskState::Stopped { .. }), "expected a stop, got {:?}", risk.state());
    }

    /// Once a trusted positive anchor closes an unknown span, a subsequent
    /// exact thirty-percent loss counts in full, including with a cap.
    #[test]
    fn unknown_span_then_exact_anchor_cannot_hide_later_loss(
        base in 1000i64..100000,
        deposit in 1i64..10000,
        cap in prop_oneof![Just(None), (500i64..2500).prop_map(Some)],
        reverse in any::<bool>(),
        midnight in any::<bool>(),
        legacy in any::<bool>(),
    ) {
        let base = Decimal::from(base);
        let deposit = Decimal::from(deposit);
        let limits = RiskLimits { max_trading_equity_usd: cap.map(Decimal::from), ..RiskLimits::default() };
        let origin = 20000 * DAY + if midnight { DAY - 10000 } else { 3600000 };
        let unknown = if legacy { Some(ValueRange { lo: base * dec!(0.50), hi: base * dec!(0.50), cash_exact: false }) } else { None };
        let flows = [
            Flow { time_ms: origin + 5000, amount: deposit, id: "unknown".into(), dex: String::new(), between: false, value: unknown },
            Flow { time_ms: origin + 15000, amount: Decimal::ONE, id: "known".into(), dex: String::new(), between: false, value: Some(ValueRange::cash_exact(base)) },
        ];
        let after = base + Decimal::ONE;
        let denominator = limits.max_trading_equity_usd.map_or(after, |cap| after.min(cap));
        let shown = after - denominator * dec!(0.30);
        let at = origin + 20000;
        let dir = Dir::new();
        let mut risk = PersistentRisk::initialise(&dir.journal(), limits, ts(origin), base, "exact anchor").unwrap().with_flows();
        for index in if reverse { [1,0] } else { [0,1] } { risk.apply_flow(ts(origin + 1000), &flows[index]).unwrap(); }
        risk.observe_view_at(ts(at), [(String::new(), at)].into(), shown, &VenueView::default(), true);
        prop_assert!(matches!(risk.state(), RiskState::Stopped { .. }), "expected a stop, got {:?}", risk.state());
    }
}

#[test]
fn case_unknown_deposit_next_to_unreported_emptying_withdrawal() {
    // Deterministic TestRunner coverage seed, 4,000-case run 2026-10-07.
    // The old oracle forgot a validated Stop when a late flow omitted its
    // causal view; the later zero anchor must retain that durable decision.
    let setup = Setup {
        start: 36627988,
        main: 161,
        second: 0,
        cap: None,
        values: 2,
    };
    let view = |lag, guard| Op::View {
        lag,
        second_after: 0,
        second_lag: 0,
        guard,
    };
    let ops = [
        view(586, 214),
        view(254, 269),
        Op::Restart,
        Op::Wait(5925),
        Op::Pnl {
            second: false,
            units: 1,
        },
        view(721, 370),
        Op::Wait(4309),
        Op::Pnl {
            second: false,
            units: -1,
        },
        Op::Pnl {
            second: false,
            units: -8,
        },
        view(489, 210),
        view(1988, 302),
        Op::Wait(658),
        view(1883, 281),
        Op::Wait(1466),
        Op::Deposit {
            second: false,
            units: 160,
            latency: Latency::After(1834),
        },
        Op::Wait(1100),
        Op::Withdraw {
            second: false,
            share: 100,
            latency: Latency::After(41608),
        },
        view(809, 386),
        view(1046, 111),
        view(1921, 176),
        Op::Wait(4355),
        Op::Wait(763),
        view(1013, 161),
    ];
    run(&build(&setup, &ops, false)).unwrap();
}

#[test]
fn case_unknown_span_zero_anchor_defers_without_journal_error() {
    // Failed proptest seed, 2,949 successful cases before this minimized input:
    // cc 4a5dc6090ca8967dc84a5905cf0d6ec09448f87795d650723712fc933f75457f
    // Whole-unit withdrawal rounding: 6000-1700-3300-900 = 100;
    // then 100+100-200 = 0. The late 3300 withdrawal is still unreported.
    let setup = Setup {
        start: 0,
        main: 60,
        second: 0,
        cap: None,
        values: 0,
    };
    let view = Op::View {
        lag: 0,
        second_after: 0,
        second_lag: 0,
        guard: 0,
    };
    let ops = [
        Op::Wait(200),
        Op::Withdraw {
            second: false,
            share: 27,
            latency: Latency::Now,
        },
        Op::Wait(1997),
        Op::Withdraw {
            second: false,
            share: 75,
            latency: Latency::After(11639),
        },
        Op::Pnl {
            second: false,
            units: -9,
        },
        view.clone(),
        Op::Wait(2000),
        Op::Deposit {
            second: false,
            units: 1,
            latency: Latency::Now,
        },
        Op::Pnl {
            second: false,
            units: -2,
        },
        Op::Wait(1998),
        view,
    ];
    run(&build(&setup, &ops, false)).unwrap();
}

#[test]
fn case_stopped_zero_then_two_exact_deposits_across_midnight() {
    // Failed proptest case cc 6f45765feb812ed702df9f9682226a4ef9e7b31b427941b54d0a9a6f9b9b271a.
    // Remove the original 8500-w100-w100-w6700 prefix to start at 1600.
    // Exact trading to zero precedes a 500 deposit before midnight and 100 after.
    let setup = Setup {
        start: DAY - 10000,
        main: 16,
        second: 0,
        cap: None,
        values: 1,
    };
    let view = Op::View {
        lag: 0,
        second_after: 0,
        second_lag: 0,
        guard: 0,
    };
    let ops = [
        Op::Pnl {
            second: false,
            units: -9,
        },
        view.clone(),
        Op::Pnl {
            second: false,
            units: -7,
        },
        Op::Wait(2000),
        Op::Deposit {
            second: false,
            units: 5,
            latency: Latency::Now,
        },
        Op::Wait(6000),
        Op::Deposit {
            second: false,
            units: 1,
            latency: Latency::Now,
        },
        Op::Wait(2000),
        view,
    ];
    run(&build(&setup, &ops, false)).unwrap();
}
