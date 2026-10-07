// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Deposits, withdrawals and transfers kept out of the account stops, as
//! specified in `docs/guard.md#deposits-and-withdrawals`: one deterministic fold over the
//! views of the account and the flows known, shared by the risk journal's
//! writer ([`crate::PersistentRisk::with_flows`]) and its reader, so that the
//! two cannot disagree.
//!
//! The fold never decides a stop itself: every halt and stop is
//! [`RiskEngine::observe`]'s. A flow only moves the figures the engine
//! measures from (the peak and the day's start), so that a loss stays the
//! share of them the engine measures it as ([`rebase`]).

use std::collections::BTreeMap;

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use zunder_core::Timestamp;
use zunder_risk::{RiskEngine, RiskLimits, RiskSnapshot, RiskState};

/// How far a view's venue time may be from a flow's and still not tell
/// whether it shows the flow, on either side: the venue's `time` of an
/// account may be when it answered rather than the state it answered with
/// (spec, "margin").
pub const FLOW_TIME_MARGIN_MS: i64 = 2_000;

/// How far below the last equity written a view's equity may fall before an
/// engine that takes flows writes it, as a share of the day's start (or of
/// the equity cap, when smaller): what a restart can forget
/// (`docs/guard.md#deposits-and-withdrawals`). A loss up to this much in a gap is read
/// before the flows (S5).
pub(crate) const FLOW_FALL_WRITTEN: Decimal = Decimal::from_parts(1, 0, 0, false, 3);

/// For each dex (`""` for the main dex), the latest venue time of any view
/// so far.
pub type Horizon = BTreeMap<String, i64>;

/// A deposit, a withdrawal or a transfer of the accounts the equity sums.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    /// When the venue booked it, epoch milliseconds.
    pub time_ms: i64,
    /// Positive for money in, negative for money out.
    pub amount: Decimal,
    /// The venue's id of it (Hyperliquid: the ledger entry's hash and
    /// type), so that one flow is applied once.
    pub id: String,
    /// The dex whose account it moved (`""` for the main dex).
    pub dex: String,
    /// A transfer between two of the accounts the equity sums (its fee the
    /// only money out): a view that read one of them before it and the
    /// other after shows the money twice or not at all.
    pub between: bool,
    /// What the accounts the equity sums were worth just before it, as
    /// reconstructed from the venue's public records (spec S5); `None` when
    /// they could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<ValueRange>,
}

/// Journal-compatible measured value. Only explicitly cash-exact singleton
/// values are trusted. Legacy ranges, including singleton trade candles,
/// deserialize without provenance and are treated as unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueRange {
    pub lo: Decimal,
    pub hi: Decimal,
    #[serde(default)]
    pub cash_exact: bool,
}

impl ValueRange {
    /// Complete reconstruction proves every individual target position flat.
    pub fn cash_exact(equity: Decimal) -> Self {
        Self {
            lo: equity,
            hi: equity,
            cash_exact: true,
        }
    }

    fn trusted(self, amount: Decimal) -> Option<Decimal> {
        (self.cash_exact
            && self.lo == self.hi
            && self.lo >= Decimal::ZERO
            && self.lo.checked_add(amount)? >= Decimal::ZERO)
            .then_some(self.lo)
    }
}

/// One view of the account, as the engine observed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeenView {
    /// When the engine observed it (the caller's clock).
    pub at: Timestamp,
    /// The venue's time of each dex's account in it.
    pub times: BTreeMap<String, i64>,
    /// The equity: the sum of those accounts.
    pub equity: Decimal,
}

/// An unknown flow span halted the current UTC day (spec S5). The name
/// and legacy figures remain for callers; scalar reconstruction never
/// estimates a drawdown from range endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaivedStop {
    /// When the view that applied the flows was observed.
    pub at: Timestamp,
    /// Legacy estimated drawdown, zero under exact-or-unknown accounting.
    pub waived: Decimal,
    /// Legacy retained estimate, zero under exact-or-unknown accounting.
    pub kept: Decimal,
    /// Legacy range-estimate marker; false for unknown scalar spans.
    pub measured: bool,
    /// Why otherwise exact arithmetic could not be represented.
    pub reason: Option<String>,
}

/// Where a view stands to a flow (spec, "where a view stands to a flow").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    /// Read before it: the flow is not in it.
    Before,
    /// May or may not show it.
    Either,
    /// Shows it.
    Shows,
}

/// Where a view whose dexes the venue showed at `times` stands to `flow`.
pub(crate) fn side(flow: &Flow, times: &BTreeMap<String, i64>) -> Side {
    let (Some(first), Some(last)) = (times.values().min(), times.values().max()) else {
        return Side::Either;
    };
    let (early, late) = if flow.between {
        (*first, *last)
    } else {
        let time = *times.get(&flow.dex).unwrap_or(first);
        (time, time)
    };
    if late < flow.time_ms.saturating_sub(FLOW_TIME_MARGIN_MS) {
        Side::Before
    } else if early >= flow.time_ms.saturating_add(FLOW_TIME_MARGIN_MS) {
        Side::Shows
    } else {
        Side::Either
    }
}

/// Whether a view whose dexes the venue showed at `times` goes back in
/// venue time from `horizon` (S1): such a view is ignored.
pub(crate) fn goes_back(times: &BTreeMap<String, i64>, horizon: &Horizon) -> bool {
    times
        .iter()
        .any(|(dex, time)| horizon.get(dex).is_some_and(|latest| *time < *latest))
}

/// Whether every view folded up to `horizon` was read before `flow` (so a
/// state with that horizon knows nothing of it).
pub(crate) fn before_horizon(flow: &Flow, horizon: &Horizon) -> bool {
    let before = flow.time_ms.saturating_sub(FLOW_TIME_MARGIN_MS);
    horizon.values().all(|time| *time < before)
}

/// The base (a peak or a day's start) that keeps the share of it a loss is,
/// as the risk engine measures it (`(base - equity)` over the smaller of the
/// base and the `cap`, [`RiskLimits::max_trading_equity_usd`]), when money
/// coming in or going out moves the equity from `before` to `after`. Without
/// a cap, or below it, the base moves in proportion to the equity; at or
/// above it, by the amount (a dollar loss stays the same dollar loss);
/// across it, to the one base that keeps the share. `None` when no positive
/// base does, or on overflow.
pub fn rebase(
    base: Decimal,
    before: Decimal,
    after: Decimal,
    cap: Option<Decimal>,
) -> Option<Decimal> {
    let against = cap.map_or(base, |cap| base.min(cap));
    let fraction = base.checked_sub(before)?.checked_div(against)?;
    if let Some(cap) = cap {
        let shifted = after.checked_add(fraction.checked_mul(cap)?)?;
        if shifted >= cap {
            return Some(shifted);
        }
    }
    let keep = Decimal::ONE.checked_sub(fraction)?;
    if keep <= Decimal::ZERO {
        return None;
    }
    let moved = after.checked_div(keep)?;
    (moved > Decimal::ZERO).then_some(moved)
}

/// How strict a state is: a drawdown stop over a day's halt over active;
/// between two stops, the larger drawdown (then the later one).
/// The fold of spec §2: views in order, each left out (S1-S3) or taken
/// (S4), with the flows it shows applied just before it as one group (S5,
/// S6).
#[derive(Debug, Clone)]
pub(crate) struct Fold {
    limits: RiskLimits,
    pub(crate) engine: RiskEngine,
    pub(crate) horizon: Horizon,
    pub(crate) flows: Vec<Flow>,
    /// For each flow, the index (in views folded by this fold) of the view
    /// it was applied at.
    pub(crate) placed: Vec<Option<usize>>,
    views: usize,
    /// Immutable monetary origin while an empty showing view defers a group.
    deferred_origin: Option<RiskEngine>,
    /// The stops waived so far (S5 (b)).
    pub(crate) waived: Vec<WaivedStop>,
}

/// What [`Fold::view`] did with a view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    /// Left out (ambiguous to a flow, or showing flows that cannot be
    /// applied yet): the day rolled at most.
    Left,
    /// Observed, after applying these flows (indices into the fold's flows).
    Taken { applied: Vec<usize> },
}

enum MeasurementFailure {
    Arithmetic(String),
    Invariant(String),
}
impl From<String> for MeasurementFailure {
    fn from(why: String) -> Self {
        Self::Arithmetic(why)
    }
}

enum Measured {
    Applied(RiskSnapshot, Option<WaivedStop>),
    Deferred(RiskSnapshot, Option<WaivedStop>),
    Failed(RiskSnapshot, Option<WaivedStop>, String),
}

impl Fold {
    pub(crate) fn new(limits: RiskLimits, engine: RiskEngine, horizon: Horizon) -> Self {
        Self {
            limits,
            engine,
            horizon,
            flows: Vec::new(),
            placed: Vec::new(),
            views: 0,
            deferred_origin: None,
            waived: Vec::new(),
        }
    }

    /// Learn a flow that is not applied yet.
    pub(crate) fn add_flow(&mut self, flow: Flow) {
        self.flows.push(flow);
        self.placed.push(None);
    }

    /// Fold one view.
    pub(crate) fn view(&mut self, view: &SeenView) -> Result<Step, String> {
        let at = view.at;
        // The callers feed views that go forward in venue time (S1,
        // `ignored`); the horizon is the latest of them, per dex.
        for (dex, time) in &view.times {
            let latest = self.horizon.entry(dex.clone()).or_insert(*time);
            *latest = (*latest).max(*time);
        }
        let index = self.views;
        self.views += 1;
        // S2: a view must show every flow applied, and stand clearly to
        // every flow not applied yet.
        let mut left = false;
        let mut shows = Vec::new();
        for (i, flow) in self.flows.iter().enumerate() {
            let seen = side(flow, &view.times);
            if self.placed[i].is_some() {
                if seen != Side::Shows {
                    left = true;
                    break;
                }
                continue;
            }
            match seen {
                Side::Either => {
                    left = true;
                    break;
                }
                Side::Shows => shows.push(i),
                Side::Before => {}
            }
        }
        if !left && !shows.is_empty() {
            shows.sort_by(|a, b| {
                let (a, b) = (&self.flows[*a], &self.flows[*b]);
                (a.time_ms, &a.id).cmp(&(b.time_ms, &b.id))
            });
            // S4: a group that cannot be applied leaves the view out.
            if self.group(&shows, view.equity, at)? {
                for i in &shows {
                    self.placed[*i] = Some(index);
                }
            } else {
                left = true;
            }
        }
        if left {
            // S3: the day still rolls at the view's time.
            let last = self.engine.snapshot().last;
            self.engine.observe(at, last);
            return Ok(Step::Left);
        }
        self.engine.observe(at, view.equity);
        Ok(Step::Taken { applied: shows })
    }

    /// S5: apply the flows `group` (indices, in time order) between the
    /// engine's last equity and a view that shows them all at `shown`,
    /// observed at `at`. `false` when the view is left out: the account is
    /// empty at it after a withdrawal, or no value of the account at the
    /// flows fits them.
    fn group(&mut self, group: &[usize], shown: Decimal, at: Timestamp) -> Result<bool, String> {
        let flows: Vec<Flow> = group.iter().map(|i| self.flows[*i].clone()).collect();
        let mut trial = self.clone();
        if let Some(origin) = &self.deferred_origin {
            trial.engine = origin.clone();
        }
        let measured = trial.measure(&flows, shown, at)?;
        let (merged, undecided, applied, failure) = match measured {
            Measured::Applied(snapshot, report) => (snapshot, report, true, None),
            Measured::Deferred(snapshot, report) => (snapshot, report, false, None),
            Measured::Failed(snapshot, report, why) => (snapshot, report, false, Some(why)),
        };
        // Monetary replay may repair history; an already established human
        // stop, or a halt of this same day, never disappears with it.
        let merged = settle(&self.limits, &self.engine.snapshot(), &merged)?;
        if applied {
            self.deferred_origin = None;
        } else if self.deferred_origin.is_none() {
            self.deferred_origin = Some(self.engine.clone());
        }
        self.engine = RiskEngine::restore(self.limits.clone(), merged)
            .map_err(|error| format!("the flows: {error}"))?;
        self.waived.extend(undecided);
        if let Some(why) = failure {
            return Err(why);
        }
        Ok(applied)
    }

    /// Judge exact chronological checkpoints. Unknown spans carry only
    /// known money movements; their right anchor normalizes existing loss
    /// rather than inferring new trading losses across missing history.
    fn measure(&self, flows: &[Flow], shown: Decimal, at: Timestamp) -> Result<Measured, String> {
        let mut proof = self.engine.clone();
        match self.measure_inner(flows, shown, at, &mut proof) {
            Ok(measured) => Ok(measured),
            Err(failure) => {
                let (invariant, why) = match failure {
                    MeasurementFailure::Arithmetic(why) => (false, why),
                    MeasurementFailure::Invariant(why) => (true, why),
                };
                let Measured::Deferred(snapshot, mut report) = self.defer(&proof, true, at)? else {
                    return Err("invalid deferred measurement result".to_owned());
                };
                if let Some(report) = &mut report {
                    report.reason = Some(why.clone());
                }
                // Restore/invariant errors remain broken. Valid checked
                // arithmetic inability keeps money pending for review.
                if invariant {
                    Ok(Measured::Failed(snapshot, report, why))
                } else {
                    Ok(Measured::Deferred(snapshot, report))
                }
            }
        }
    }

    fn measure_inner(
        &self,
        flows: &[Flow],
        shown: Decimal,
        at: Timestamp,
        engine: &mut RiskEngine,
    ) -> Result<Measured, MeasurementFailure> {
        if flows.iter().all(|flow| {
            flow.amount.is_zero()
                && flow
                    .value
                    .and_then(|value| value.trusted(flow.amount))
                    .is_none()
        }) {
            return Ok(Measured::Applied(self.engine.snapshot(), None));
        }
        let mut unknown = false;
        // Keep the pre-empty checkpoint and its external withdrawal until
        // refill. An emptying transfer is not a trading loss to zero.
        let mut emptied: Option<(Decimal, Flow)> = None;
        let mut index = 0;
        while index < flows.len() {
            let flow = &flows[index];
            let value = flow.value.and_then(|value| value.trusted(flow.amount));
            if flow.amount.is_zero() && value.is_none() {
                index += 1;
                continue;
            }
            if let Some(value) = value {
                let time = Timestamp::from_millis(flow.time_ms);
                let after = value
                    .checked_add(flow.amount)
                    .ok_or_else(|| "flow amount overflow".to_owned())?;
                if let Some((from, _)) = &emptied {
                    if after > Decimal::ZERO {
                        engine.observe(time, *from);
                        move_flow(
                            engine,
                            &self.limits,
                            flow.time_ms,
                            *from,
                            after
                                .checked_sub(*from)
                                .ok_or_else(|| "refill overflow".to_owned())?,
                        )
                        .ok_or_else(|| "exact refill cannot be rebased".to_owned())?;
                        emptied = None;
                    }
                } else {
                    engine.observe(time, value);
                    if value.is_zero() {
                        // Trading reached zero before the deposit. The
                        // already established stop survives its money.
                    } else if after.is_zero() {
                        emptied = Some((value, flow.clone()));
                    } else {
                        move_flow(engine, &self.limits, flow.time_ms, value, flow.amount)
                            .ok_or_else(|| "exact flow cannot be rebased".to_owned())?;
                    }
                }
                index += 1;
                continue;
            }
            unknown = true;
            let begin = index;
            // A zero cash checkpoint cannot safely normalize a nonzero
            // loss base. Keep its money in the span until a positive anchor.
            index += 1;
            while index < flows.len()
                && flows[index]
                    .value
                    .and_then(|value| value.trusted(flows[index].amount))
                    .is_none_or(|value| value <= Decimal::ZERO)
            {
                index += 1;
            }
            let (right, time) = if index < flows.len() {
                (
                    flows[index]
                        .value
                        .and_then(|value| value.trusted(flows[index].amount))
                        .expect("the uncertainty span ended at a trusted positive anchor"),
                    Timestamp::from_millis(flows[index].time_ms),
                )
            } else {
                (shown, at)
            };
            let mut gap = Vec::new();
            if let Some((_, withdrawal)) = emptied.take() {
                gap.push(withdrawal);
            }
            gap.extend_from_slice(&flows[begin..index]);
            if right <= Decimal::ZERO {
                return self
                    .defer(engine, unknown, at)
                    .map_err(MeasurementFailure::Invariant);
            }
            *engine = self.unknown_span(engine, &gap, right, time)?;
        }
        if emptied.is_some() {
            return self
                .defer(engine, unknown, at)
                .map_err(MeasurementFailure::Invariant);
        }
        engine.observe(at, shown);
        let mut snapshot = engine.snapshot();
        if unknown && !matches!(snapshot.state, RiskState::Stopped { .. }) {
            snapshot.state = RiskState::HaltedForDay { day: snapshot.day };
        }
        let report = unknown.then_some(WaivedStop {
            at,
            waived: Decimal::ZERO,
            kept: Decimal::ZERO,
            measured: false,
            reason: None,
        });
        Ok(Measured::Applied(snapshot, report))
    }

    /// An empty showing view cannot normalize a positive loss base. Keep
    /// the group's monetary origin unmodified, but retain independently
    /// proved exact-prefix decisions. Daily halts keep their UTC identity.
    fn defer(&self, proved: &RiskEngine, unknown: bool, at: Timestamp) -> Result<Measured, String> {
        let mut display = self.engine.clone();
        let last = display.snapshot().last;
        display.observe(at, last);
        let mut out = display.snapshot();
        match proved.state() {
            state @ RiskState::Stopped { .. } => out.state = state,
            state @ RiskState::HaltedForDay { day } if day == out.day => out.state = state,
            _ => {}
        }
        if unknown && !matches!(out.state, RiskState::Stopped { .. }) {
            out.state = RiskState::HaltedForDay { day: out.day };
        }
        RiskEngine::restore(self.limits.clone(), out.clone())
            .map_err(|error| format!("deferred flows: {error}"))?;
        Ok(Measured::Deferred(
            out,
            unknown.then_some(WaivedStop {
                at,
                waived: Decimal::ZERO,
                kept: Decimal::ZERO,
                measured: false,
                reason: None,
            }),
        ))
    }

    /// Normalize at the right anchor BEFORE observing it. There is no
    /// comparison between an old peak and equity after an unknown gap.
    fn unknown_span(
        &self,
        checkpoint: &RiskEngine,
        flows: &[Flow],
        shown: Decimal,
        at: Timestamp,
    ) -> Result<RiskEngine, MeasurementFailure> {
        let mut neutral = self
            .neutral_history(checkpoint, flows)
            .unwrap_or_else(|| checkpoint.clone());
        if !matches!(checkpoint.state(), RiskState::Stopped { .. })
            && matches!(neutral.state(), RiskState::Stopped { .. })
        {
            // A money-only rebase may round at a boundary. It cannot
            // establish a trading stop within an unknown span.
            neutral = checkpoint.clone();
        }
        let last = neutral.snapshot().last;
        neutral.observe(at, last); // UTC rollover with unchanged equity only.
        let before = neutral.snapshot();
        let mut out = before.clone();
        let already_stopped = matches!(before.state, RiskState::Stopped { .. });
        out.peak = rebase(
            before.peak,
            before.last,
            shown,
            self.limits.max_trading_equity_usd,
        )
        .or_else(|| already_stopped.then_some(before.peak.max(shown)))
        .ok_or_else(|| "unknown span peak cannot be normalized".to_owned())?
        .max(shown);
        out.day_start = rebase(
            before.day_start,
            before.last,
            shown,
            self.limits.max_trading_equity_usd,
        )
        .or_else(|| already_stopped.then_some(shown.max(Decimal::ONE)))
        .ok_or_else(|| "unknown span day cannot be normalized".to_owned())?;
        out.last = shown;
        // Decimal rounding must not turn a previously sub-limit loss into
        // a permanent stop. Widen toward less loss by a tiny relative ulp.
        if !matches!(before.state, RiskState::Stopped { .. })
            && share(&self.limits, out.peak, shown) >= self.limits.drawdown_stop
        {
            let epsilon = out
                .peak
                .abs()
                .max(Decimal::ONE)
                .checked_mul(Decimal::from_parts(1, 0, 0, false, 24))
                .ok_or_else(|| "normalization precision overflow".to_owned())?;
            out.peak = out
                .peak
                .checked_sub(epsilon)
                .ok_or_else(|| "normalization precision overflow".to_owned())?
                .max(shown);
        }
        out.state = if matches!(before.state, RiskState::Stopped { .. }) {
            before.state
        } else {
            RiskState::HaltedForDay { day: out.day }
        };
        RiskEngine::restore(self.limits.clone(), out)
            .map_err(|error| MeasurementFailure::Invariant(format!("unknown span: {error}")))
    }

    /// Money-only chronology. An impossible neutral ledger falls back to
    /// the pre-span checkpoint; it never guesses a hidden trading result.
    fn neutral_history(&self, checkpoint: &RiskEngine, flows: &[Flow]) -> Option<RiskEngine> {
        let mut engine = checkpoint.clone();
        let mut balance = engine.snapshot().last;
        let mut emptied = None;
        for flow in flows {
            let time = Timestamp::from_millis(flow.time_ms);
            let after = balance.checked_add(flow.amount)?;
            if after < Decimal::ZERO {
                return None;
            }
            if let Some(from) = emptied {
                if after > Decimal::ZERO {
                    engine.observe(time, from);
                    move_flow(
                        &mut engine,
                        &self.limits,
                        flow.time_ms,
                        from,
                        after.checked_sub(from)?,
                    )?;
                    emptied = None;
                }
            } else {
                engine.observe(time, balance);
                if balance <= Decimal::ZERO {
                    return None;
                }
                if after.is_zero() {
                    emptied = Some(balance);
                } else {
                    move_flow(
                        &mut engine,
                        &self.limits,
                        flow.time_ms,
                        balance,
                        flow.amount,
                    )?;
                }
            }
            balance = after;
        }
        if emptied.is_some() {
            return None;
        }
        Some(engine)
    }
}

/// The drawdown of `equity` from `peak`, as the engine measures it.
fn share(limits: &RiskLimits, peak: Decimal, equity: Decimal) -> Decimal {
    let against = limits
        .max_trading_equity_usd
        .map_or(peak, |cap| peak.min(cap));
    peak.checked_sub(equity)
        .and_then(|fall| fall.checked_div(against))
        .unwrap_or(Decimal::ONE)
}

/// S6: move the engine's peak and day's start for a flow of `amount` at the
/// equity `before` just before it, the engine having observed `before` at
/// the flow's time. `None` when they cannot be moved.
fn move_flow(
    engine: &mut RiskEngine,
    limits: &RiskLimits,
    time_ms: i64,
    before: Decimal,
    amount: Decimal,
) -> Option<()> {
    if amount.is_zero() {
        return Some(());
    }
    let cap = limits.max_trading_equity_usd;
    let snapshot = engine.snapshot();
    let after = before.checked_add(amount)?;
    let peak = rebase(snapshot.peak, before, after, cap)?.max(after);
    let mut day_start = rebase(snapshot.day_start, before, after, cap).or_else(|| {
        // A permanent stop can roll midnight with last equity zero. Its
        // daily loss fraction is then undefined; a verified positive cash
        // checkpoint starts only that daily base. Keep the ordinary peak
        // rebase and exact original Stop; no nonstopped fallback exists.
        (matches!(snapshot.state, RiskState::Stopped { .. })
            && snapshot.day_start <= Decimal::ZERO
            && after > Decimal::ZERO)
            .then_some(after)
    })?;
    if amount > Decimal::ZERO {
        // A gain made earlier that day stays a gain in dollars.
        day_start = day_start.max(snapshot.day_start.checked_add(amount)?);
    }
    let moved = RiskSnapshot {
        state: snapshot.state,
        peak: peak.normalize(),
        day: snapshot.day,
        day_start: day_start.normalize(),
        // Set below by an observation at the flow's time, which also takes
        // a share that rounding put at a stop.
        last: peak.normalize(),
        positions: snapshot.positions,
    };
    *engine = RiskEngine::restore(limits.clone(), moved).ok()?;
    engine.observe(Timestamp::from_millis(time_ms), after);
    Some(())
}

/// What [`replay`] made of a base and the views and flows after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Replayed {
    pub(crate) snapshot: RiskSnapshot,
    pub(crate) horizon: Horizon,
    /// For each flow, the index of the view it was applied at.
    pub(crate) placed: Vec<Option<usize>>,
    /// The stops waived on the way (S5 (b)).
    pub(crate) waived: Vec<WaivedStop>,
}

/// Fold `views` with `flows` from the engine state `base` and its horizon.
/// The writer and the reader of the journal both compute a `flowed`
/// record's state with this and [`settle`].
pub(crate) fn replay(
    limits: &RiskLimits,
    base: &RiskSnapshot,
    horizon: &Horizon,
    views: &[SeenView],
    flows: &[Flow],
) -> Result<Replayed, String> {
    let engine = RiskEngine::restore(limits.clone(), base.clone())
        .map_err(|error| format!("the base: {error}"))?;
    let mut fold = Fold::new(limits.clone(), engine, horizon.clone());
    for flow in flows {
        fold.add_flow(flow.clone());
    }
    for view in views {
        fold.view(view)?;
    }
    Ok(Replayed {
        snapshot: fold.engine.snapshot(),
        horizon: fold.horizon,
        placed: fold.placed,
        waived: fold.waived,
    })
}

/// The engine state after a replay, given the state `before` it (the
/// journal's last record): the replay's figures, with a halt of the same
/// day or a stop that was already set kept (a flow never clears one), and
/// the positions as they were (flows do not touch them).
pub(crate) fn settle(
    limits: &RiskLimits,
    before: &RiskSnapshot,
    replayed: &RiskSnapshot,
) -> Result<RiskSnapshot, String> {
    let mut engine = RiskEngine::restore(limits.clone(), replayed.clone())
        .map_err(|error| format!("the replay: {error}"))?;
    if engine.snapshot().day < before.day {
        // The day never goes back: roll as the engine would.
        let last = engine.snapshot().last;
        let midnight = Timestamp::from_millis(
            before
                .day
                .checked_mul(Timestamp::MS_PER_DAY)
                .ok_or("the day overflows")?,
        );
        engine.observe(midnight, last);
    }
    let figures = engine.snapshot();
    let state = match (before.state, figures.state) {
        (RiskState::Stopped { .. }, _) => before.state,
        (_, RiskState::Stopped { .. }) => figures.state,
        (RiskState::HaltedForDay { day }, _) if day == figures.day => before.state,
        _ => figures.state,
    };
    let settled = RiskSnapshot {
        state,
        positions: before.positions.clone(),
        ..figures
    };
    RiskEngine::restore(limits.clone(), settled.clone())
        .map_err(|error| format!("the settled state: {error}"))?;
    Ok(settled)
}

#[cfg(test)]
mod tests;
