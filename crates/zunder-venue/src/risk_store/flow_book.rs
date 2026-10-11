// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Deposits, withdrawals and transfers kept out of the account stops: what
//! an engine that takes flows remembers ([`FlowBook`]), and
//! [`PersistentRisk`]'s calls for them. The fold itself is
//! [`crate::flows`], shared with the reader.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use rust_decimal::Decimal;
use serde::Serialize;
use zunder_core::Timestamp;
use zunder_risk::{RiskEngine, RiskLimits, RiskSnapshot, RiskState, VenueView};

use super::{
    JournalError,
    check::reach,
    file::mark_broken,
    persistent::{PersistentRisk, ViewSync},
    record::{FlowFields, JournalEvent, JournalRecord},
};
use crate::flows::{self, Flow, Fold, Horizon, SeenView, Step, WaivedStop};

/// How long views not on the journal are remembered for a flow reported
/// late, at least (`docs/guard.md#deposits-and-withdrawals`).
const FLOW_UNWRITTEN_KEEP_MS: i64 = 30 * 60_000;

/// How long views on the journal, and the records a replay may start from,
/// are remembered (D4).
const FLOW_KEEP_MS: i64 = 24 * Timestamp::MS_PER_HOUR;

/// At most one record a replay may start from per this long, besides the
/// newest.
const FLOW_BASE_EVERY_MS: i64 = 10_000;

/// At most this many views remembered (fewer in the crate's own tests, so
/// that they reach it).
pub(super) const FLOW_VIEWS_MAX: usize = if cfg!(test) { 300 } else { 200_000 };

/// How far before the journal's horizon a restart reads the account's
/// ledger again ([`PersistentRisk::flows_from_ms`]): flows reported late.
pub const FLOW_READ_BACK_MS: i64 = 30 * 60_000;

/// What became of a flow ([`PersistentRisk::apply_flow`],
/// [`PersistentRisk::take_flow_outcomes`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "why")]
pub enum FlowOutcome {
    /// Applied: the peak and the day's start moved with it, on the journal.
    Applied,
    /// Known, and applied at the first view that shows it.
    Pending,
    /// Known before (the same id).
    Duplicate,
    /// Not applied, and why: it counts as the engine counts any change of
    /// equity.
    Skipped(String),
}

/// A flow known to an engine that takes flows.
#[derive(Debug, Clone)]
pub(super) struct Known {
    pub(super) flow: Flow,
    /// The number of the view it was applied at.
    pub(super) place: Option<u64>,
}

/// A view an engine that takes flows remembers.
#[derive(Debug, Clone)]
pub(super) struct Remembered {
    pub(super) number: u64,
    pub(super) view: SeenView,
    /// On the journal (in a record of its own or a `flowed` record's list).
    pub(super) written: bool,
}

/// A record a replay may start from: no flow learned since it was written
/// falls at or before its horizon.
#[derive(Debug, Clone)]
pub(super) struct Base {
    pub(super) seq: u64,
    pub(super) at: Timestamp,
    pub(super) state: RiskSnapshot,
    /// Its horizon as recorded (what a replay from it starts with, as the
    /// reader's does).
    pub(super) horizon: Horizon,
    /// How far its views reached, for whether a flow contradicts it: its
    /// horizon, or for a record written without one the time it was
    /// written at.
    pub(super) reach: Horizon,
    /// The number of the first view after it.
    pub(super) next_view: u64,
}

/// What an engine that takes flows keeps besides the engine
/// (`docs/guard.md#deposits-and-withdrawals`).
#[derive(Debug, Default)]
pub(super) struct FlowBook {
    /// For each dex, the latest venue time of any view so far.
    pub(super) horizon: Horizon,
    /// The flows a replay may need: those not applied yet, and those
    /// applied after the oldest base.
    pub(super) known: Vec<Known>,
    /// The id of every flow known, against applying one twice.
    pub(super) ids: BTreeSet<String>,
    /// The views a replay may need, in order.
    pub(super) views: VecDeque<Remembered>,
    /// The number the next view gets.
    pub(super) next_view: u64,
    /// The records a replay may start from, oldest first.
    pub(super) bases: VecDeque<Base>,
    /// What became of flows since the caller last asked.
    pub(super) outcomes: Vec<(Flow, FlowOutcome)>,
    /// Stops waived (S5 (b)) since the caller last asked, and the views
    /// they were waived at lately (a replay meets them again).
    pub(super) waived: Vec<WaivedStop>,
    pub(super) waived_at: VecDeque<Timestamp>,
}

impl FlowBook {
    pub(super) fn pending(&self) -> bool {
        self.known.iter().any(|known| known.place.is_none())
    }

    /// Note stops waived, each once.
    fn note_waived(&mut self, waived: Vec<WaivedStop>) {
        for stop in waived {
            if self.waived_at.contains(&stop.at) {
                continue;
            }
            self.waived_at.push_back(stop.at);
            if self.waived_at.len() > 256 {
                self.waived_at.pop_front();
            }
            self.waived.push(stop);
        }
    }

    /// Remember `record`, just written or read, as a base.
    pub(super) fn add_base(&mut self, record: &JournalRecord) {
        // A pending group owns its immutable pre-group replay origin.
        // Displayed UTC rollovers and exact-prefix state latches cannot
        // replace that origin with partly processed money.
        if !self.pending() {
            self.push_base(record, reach(record));
        }
    }

    /// Remember `record` as a base whose views reached `reach`.
    fn push_base(&mut self, record: &JournalRecord, reach: Horizon) {
        let at = record.at;
        let len = self.bases.len();
        if len >= 2
            && at
                .as_millis()
                .saturating_sub(self.bases[len - 2].at.as_millis())
                < FLOW_BASE_EVERY_MS
        {
            self.bases.pop_back();
        }
        self.bases.push_back(Base {
            seq: record.seq,
            at,
            state: record.state.clone(),
            horizon: record.horizon.clone().unwrap_or_default(),
            reach,
            next_view: self.next_view,
        });
    }

    /// Forget what no replay can need any more at `now`.
    fn prune(&mut self, now: Timestamp) {
        if self.pending() {
            return; // Pin origin, exact provenance and chronology until settled.
        }
        let now = now.as_millis();
        // A day old, or too many views: the oldest bases go first, with the
        // views only they need (a replay from a base needs every view on
        // the journal since it).
        let mut oldest = self
            .bases
            .front()
            .map_or(self.next_view, |base| base.next_view);
        loop {
            while self.views.front().is_some_and(|view| view.number < oldest) {
                self.views.pop_front();
            }
            let old = self
                .bases
                .front()
                .is_some_and(|base| now.saturating_sub(base.at.as_millis()) > FLOW_KEEP_MS);
            if self.bases.len() < 2 || !(old || self.views.len() > FLOW_VIEWS_MAX) {
                break;
            }
            self.bases.pop_front();
            oldest = self
                .bases
                .front()
                .map_or(self.next_view, |base| base.next_view);
        }
        if self.next_view.is_multiple_of(64) || self.views.len() > FLOW_VIEWS_MAX {
            // Views not on the journal: after 30 minutes, or the oldest
            // while there are too many.
            let mut excess = self.views.len().saturating_sub(FLOW_VIEWS_MAX);
            self.views.retain(|view| {
                let keep = view.written
                    || (excess == 0
                        && now.saturating_sub(view.view.at.as_millis()) <= FLOW_UNWRITTEN_KEEP_MS);
                if !keep {
                    excess = excess.saturating_sub(1);
                }
                keep
            });
        }
        self.known
            .retain(|known| known.place.is_none_or(|place| place >= oldest));
    }

    /// Forget every view and base: what came before cannot be replayed.
    pub(super) fn reset(&mut self) {
        self.views.clear();
        self.bases.clear();
        self.known.retain(|known| known.place.is_none());
    }

    /// The fold as the engine stands now, with every flow known.
    fn live_fold(&self, limits: &RiskLimits, engine: &RiskEngine) -> Result<Fold, String> {
        let base = self.pending().then(|| self.bases.back()).flatten();
        let (start, horizon) = match base {
            Some(base) => (
                RiskEngine::restore(limits.clone(), base.state.clone())
                    .map_err(|error| format!("pending origin: {error}"))?,
                base.horizon.clone(),
            ),
            None => (engine.clone(), self.horizon.clone()),
        };
        let mut fold = Fold::new(limits.clone(), start, horizon);
        for known in &self.known {
            fold.add_flow(known.flow.clone());
            let in_origin = known
                .place
                .is_some_and(|place| base.is_none_or(|base| place < base.next_view));
            if in_origin && let Some(placed) = fold.placed.last_mut() {
                *placed = Some(0);
            }
        }
        if let Some(base) = base {
            for remembered in self
                .views
                .iter()
                .filter(|view| view.number >= base.next_view)
            {
                fold.view(&remembered.view)?;
            }
        }
        Ok(fold)
    }

    /// Rebuild from a journal's checked records (`limits` its limits).
    fn rebuild(&mut self, limits: &RiskLimits, records: &[JournalRecord]) -> Result<(), String> {
        // The number of the first view after each record.
        let mut after: BTreeMap<u64, u64> = BTreeMap::new();
        for record in records {
            match (&record.event, &record.horizon) {
                // Nothing before them is replayed (as the reader's trail).
                (JournalEvent::Initialised { .. } | JournalEvent::ResumedAfterReview { .. }, _) => {
                    self.reset()
                }
                (
                    JournalEvent::Flowed {
                        base,
                        views,
                        flows: listed,
                    },
                    Some(_),
                ) => {
                    let first = after
                        .get(base)
                        .copied()
                        .ok_or("a flowed record from a record that cannot be replayed")?;
                    let base_record = usize::try_from(*base)
                        .ok()
                        .and_then(|base| base.checked_sub(1))
                        .and_then(|index| records.get(index))
                        .ok_or("a flowed record from a missing record")?;
                    let empty = Horizon::new();
                    let replayed = flows::replay(
                        limits,
                        &base_record.state,
                        base_record.horizon.as_ref().unwrap_or(&empty),
                        views,
                        listed,
                    )?;
                    // The stops this record waived were reported when it was
                    // written: not again.
                    for stop in &replayed.waived {
                        if !self.waived_at.contains(&stop.at) {
                            self.waived_at.push_back(stop.at);
                        }
                    }
                    while self.waived_at.len() > 256 {
                        self.waived_at.pop_front();
                    }
                    self.views.retain(|view| view.number < first);
                    self.next_view = first;
                    for view in views {
                        self.views.push_back(Remembered {
                            number: self.next_view,
                            view: view.clone(),
                            written: true,
                        });
                        self.next_view += 1;
                    }
                    // Each listed flow where this record applied it; a flow
                    // it does not list stays where an earlier one did (in
                    // the base's state).
                    for (flow, placed) in listed.iter().zip(&replayed.placed) {
                        let place = placed.map(|index| first + index as u64);
                        match self.known.iter_mut().find(|known| known.flow.id == flow.id) {
                            Some(known) => known.place = place,
                            None => self.known.push(Known {
                                flow: flow.clone(),
                                place,
                            }),
                        }
                    }
                    self.ids.extend(listed.iter().map(|flow| flow.id.clone()));
                    self.bases.retain(|candidate| candidate.seq <= *base);
                }
                (_, Some(_)) => {
                    if let Some(view) = &record.view {
                        self.views.push_back(Remembered {
                            number: self.next_view,
                            view: view.clone(),
                            written: true,
                        });
                        self.next_view += 1;
                    }
                }
                // Written without flows (by a person's command, or an
                // older build): what came before it cannot be replayed.
                (_, None) => self.reset(),
            }
            after.insert(record.seq, self.next_view);
            if record.horizon.is_some() || matches!(record.event, JournalEvent::Initialised { .. })
            {
                self.add_base(record);
            }
        }
        let last = records.last().ok_or("the journal is empty")?;
        self.horizon = match &last.horizon {
            Some(horizon) => horizon.clone(),
            None if matches!(last.event, JournalEvent::Initialised { .. }) => Horizon::new(),
            None => {
                // Its views' times are not known; none was after it.
                let horizon: Horizon = [(String::new(), last.at.as_millis())].into();
                self.push_base(last, horizon.clone());
                horizon
            }
        };
        self.prune(last.at);
        Ok(())
    }
}

/// Whether `after` is a stricter state than `before`.
fn stricter(before: RiskState, after: RiskState) -> bool {
    match (before, after) {
        (RiskState::Active, after) => after != RiskState::Active,
        (RiskState::HaltedForDay { .. }, RiskState::Stopped { .. }) => true,
        // Halted again on a later day (the first view of it).
        (RiskState::HaltedForDay { day: before }, RiskState::HaltedForDay { day: after }) => {
            after > before
        }
        _ => false,
    }
}

impl PersistentRisk {
    /// Keep deposits, withdrawals and transfers out of the account stops,
    /// as `docs/guard.md#deposits-and-withdrawals` specifies: the caller reports each
    /// flow with [`PersistentRisk::apply_flow`] and shows the engine the
    /// account with [`PersistentRisk::observe_view_at`]. Off unless asked
    /// for; the runner leaves it off (`docs/guard.md`). What the
    /// journal holds of earlier flows and views is read back, so that a
    /// restart applies no flow twice and can still place a late one.
    #[must_use]
    pub fn with_flows(mut self) -> Self {
        let mut book = FlowBook::default();
        let rebuilt = self
            .journal
            .records()
            .map_err(|error| error.to_string())
            .and_then(|records| book.rebuild(&self.journal.limits, &records));
        if let Err(error) = rebuilt {
            // The journal opened, so this should not happen; if it does,
            // no new positions until a person looks.
            self.broken = Some(format!("reading the journal's flows: {error}"));
        }
        if let Some(oldest) = book.bases.front() {
            self.journal.checks.trail.prune(oldest.seq);
        }
        self.flows = Some(book);
        self
    }

    /// Forget what no replay can need any more at `now`, here and in the
    /// journal's checks.
    fn prune_flows(&mut self, now: Timestamp) {
        if let Some(book) = &mut self.flows {
            book.prune(now);
            if let Some(oldest) = book.bases.front() {
                self.journal.checks.trail.prune(oldest.seq);
            }
        }
    }

    /// Whether deposits and withdrawals are kept out of the account stops.
    pub fn takes_flows(&self) -> bool {
        self.flows.is_some()
    }

    /// Whether this flow id has already been recorded (including pending flows).
    pub fn knows_flow(&self, id: &str) -> bool {
        self.flows
            .as_ref()
            .is_some_and(|book| book.ids.contains(id))
    }

    /// From when to read the account's ledger at a start: the journal's
    /// horizon, less [`FLOW_READ_BACK_MS`] (epoch ms); for a journal that
    /// has seen no view since it was started, its last record's time (the
    /// equity it started from holds every flow before). Flows already known
    /// come again and are recognised by their id.
    pub fn flows_from_ms(&self) -> i64 {
        match self
            .flows
            .as_ref()
            .and_then(|book| book.horizon.values().max().copied())
        {
            Some(newest) => newest.saturating_sub(FLOW_READ_BACK_MS),
            None => self.journal.last.at.as_millis(),
        }
    }

    /// The drawdown stops waived since the last call: a loss next to a
    /// withdrawal that would have stopped the engine in one reading and not
    /// in another halted the day instead (`docs/guard.md#deposits-and-withdrawals`). For the caller to tell a person.
    pub fn take_waived_stops(&mut self) -> Vec<WaivedStop> {
        self.flows
            .as_mut()
            .map(|book| std::mem::take(&mut book.waived))
            .unwrap_or_default()
    }

    /// What became of flows since the last call, in order: applied (when
    /// reported, or at the first view that showed them), or skipped.
    pub fn take_flow_outcomes(&mut self) -> Vec<(Flow, FlowOutcome)> {
        self.flows
            .as_mut()
            .map(|book| std::mem::take(&mut book.outcomes))
            .unwrap_or_default()
    }

    /// [`PersistentRisk::observe_view`] for an engine that may take flows:
    /// `times` are the venue's times of each dex's account in the view
    /// (`""` for the main dex). The view is left out when it is older than
    /// one before it or may or may not show a flow (the day still rolls),
    /// and the flows it shows are applied before it is observed
    /// (`docs/guard.md#deposits-and-withdrawals`). `taken` in the result says which.
    pub fn observe_view_at(
        &mut self,
        now: Timestamp,
        times: BTreeMap<String, i64>,
        equity: Decimal,
        view: &VenueView,
        settled: bool,
    ) -> ViewSync {
        let Some(book) = &self.flows else {
            return self.observe_view(now, equity, view, settled);
        };
        if flows::goes_back(&times, &book.horizon) {
            // Older than a view before it: not a view at all (S1).
            return ViewSync {
                state: self.engine.state(),
                discrepancies: Vec::new(),
                journal_error: None,
                taken: false,
                ignored: true,
            };
        }
        let seen = SeenView {
            at: now,
            times,
            equity,
        };
        let (taken, flowed, mut journal_error) = match self.fold_view(now, &seen) {
            Ok((taken, flowed)) => (taken, flowed, None),
            Err(error) => (false, false, Some(error.to_string())),
        };
        let discrepancies = self.engine.reconcile_positions(view, settled);
        let committed = self
            .commit_view(now, JournalEvent::Updated, (!flowed).then_some(&seen))
            .err()
            .map(|error| error.to_string());
        journal_error = journal_error.or(committed);
        self.observed = true;
        ViewSync {
            state: self.engine.state(),
            discrepancies,
            journal_error,
            taken,
            ignored: false,
        }
    }

    /// Fold `seen` into the engine: whether it was taken, and whether it
    /// applied flows (written as a `flowed` record, which then holds it).
    pub(super) fn fold_view(
        &mut self,
        now: Timestamp,
        seen: &SeenView,
    ) -> Result<(bool, bool), JournalError> {
        let limits = self.journal.limits.clone();
        let Some(book) = &mut self.flows else {
            return Ok((true, false));
        };
        if book.pending() && book.views.len() >= FLOW_VIEWS_MAX {
            let reason =
                "pending account-flow history reached its safety bound; review required".to_owned();
            // Preserve the pinned origin and do not observe unresolved
            // equity against old bases. The durable marker blocks entries
            // after restart without inventing a human loss stop.
            mark_broken(&self.journal.path, &reason);
            self.broken = Some(reason.clone());
            return Err(JournalError::Broken(reason));
        }
        let before = self.engine.snapshot();
        let mut fold = book
            .live_fold(&limits, &self.engine)
            .map_err(JournalError::Invalid)?;
        let step = match fold.view(seen) {
            Ok(step) => step,
            Err(error) => {
                // An invalid invariant must fail closed without observing
                // unresolved raw money against old bases. Prefix Stop
                // proof retained by the fold survives; entries stay blocked.
                let mut retained = fold.engine.snapshot();
                let last = retained.last;
                fold.engine.observe(seen.at, last);
                retained = fold.engine.snapshot();
                if !matches!(retained.state, RiskState::Stopped { .. }) {
                    retained.state = RiskState::HaltedForDay { day: retained.day };
                }
                self.engine = RiskEngine::restore(limits.clone(), retained)
                    .map_err(|error| JournalError::Invalid(error.to_string()))?;
                let reason = format!("the flows could not be applied to a view: {error}");
                mark_broken(&self.journal.path, &reason);
                self.broken = Some(reason.clone());
                return Err(JournalError::Invalid(reason));
            }
        };
        let number = book.next_view;
        book.next_view += 1;
        book.views.push_back(Remembered {
            number,
            view: seen.clone(),
            written: false,
        });
        book.horizon = fold.horizon;
        let settled = flows::settle(&limits, &before, &fold.engine.snapshot())
            .map_err(JournalError::Invalid)?;
        self.engine = RiskEngine::restore(limits.clone(), settled)
            .map_err(|error| JournalError::Invalid(error.to_string()))?;
        book.note_waived(fold.waived);
        let applied = match step {
            Step::Taken { applied } if !applied.is_empty() => applied,
            step => {
                if book.pending() {
                    // Deferred views and their proved-prefix decisions
                    // must be durable before any future readiness clears.
                    self.write_flowed(now)?;
                    self.prune_flows(now);
                    return Ok((step != Step::Left, true));
                }
                self.prune_flows(now);
                return Ok((step != Step::Left, false));
            }
        };
        for index in applied {
            if let Some(known) = book.known.get_mut(index) {
                known.place = Some(number);
                book.outcomes
                    .push((known.flow.clone(), FlowOutcome::Applied));
            }
        }
        self.write_flowed(now)?;
        self.prune_flows(now);
        Ok((true, true))
    }

    /// Replay from the newest base with every view since it and every flow
    /// not in it, and the state that gives: the `flowed` record, its state
    /// and horizon, where each listed flow (an index into the book's known
    /// flows) was applied, and the base.
    #[allow(clippy::type_complexity)]
    fn replay_from_base(
        &self,
    ) -> Result<
        (
            JournalEvent,
            RiskSnapshot,
            Horizon,
            Vec<(usize, Option<u64>)>,
            Base,
            Vec<WaivedStop>,
        ),
        JournalError,
    > {
        let limits = &self.journal.limits;
        let book = self
            .flows
            .as_ref()
            .ok_or_else(|| JournalError::Invalid("this engine does not take flows".into()))?;
        let base =
            book.bases.back().cloned().ok_or_else(|| {
                JournalError::Invalid("no record to replay the flows from".into())
            })?;
        let remembered: Vec<&Remembered> = book
            .views
            .iter()
            .filter(|view| view.number >= base.next_view)
            .collect();
        let views: Vec<SeenView> = remembered.iter().map(|view| view.view.clone()).collect();
        let listed: Vec<usize> = book
            .known
            .iter()
            .enumerate()
            .filter(|(_, known)| known.place.is_none_or(|place| place >= base.next_view))
            .map(|(index, _)| index)
            .collect();
        let flow_list: Vec<Flow> = listed
            .iter()
            .map(|index| book.known[*index].flow.clone())
            .collect();
        let replayed = flows::replay(limits, &base.state, &base.horizon, &views, &flow_list)
            .map_err(JournalError::Invalid)?;
        let settled = flows::settle(limits, &self.journal.last.state, &replayed.snapshot)
            .map_err(JournalError::Invalid)?;
        let mut horizon = replayed.horizon;
        for (dex, time) in self.journal.last.horizon.iter().flatten() {
            let latest = horizon.entry(dex.clone()).or_insert(*time);
            *latest = (*latest).max(*time);
        }
        let places = listed
            .iter()
            .zip(&replayed.placed)
            .map(|(index, placed)| {
                (
                    *index,
                    placed.and_then(|view| remembered.get(view).map(|view| view.number)),
                )
            })
            .collect();
        let event = JournalEvent::Flowed {
            base: base.seq,
            views,
            flows: flow_list,
        };
        Ok((event, settled, horizon, places, base, replayed.waived))
    }

    /// Write the `flowed` record of [`PersistentRisk::replay_from_base`]
    /// and take its state. The engine takes it also when the write fails
    /// (the journal is then broken and no new positions are allowed): the
    /// recomputed state is the right one either way.
    fn write_flowed(&mut self, now: Timestamp) -> Result<(), JournalError> {
        self.check_intact()?;
        let (event, settled, horizon, places, base, waived) = self.replay_from_base()?;
        if let Some(book) = &mut self.flows {
            book.note_waived(waived);
        }
        self.engine = RiskEngine::restore(self.journal.limits.clone(), settled.clone())
            .map_err(|error| JournalError::Invalid(error.to_string()))?;
        if let Some(book) = &mut self.flows {
            book.horizon = horizon.clone();
            for (index, place) in places {
                if let Some(known) = book.known.get_mut(index) {
                    known.place = place;
                }
            }
        }
        self.journal
            .append(
                now,
                event,
                settled,
                FlowFields {
                    horizon: Some(horizon),
                    view: None,
                },
                Some((&base.state, &base.horizon, &base.reach)),
            )
            .inspect_err(|error| {
                let reason = error.to_string();
                mark_broken(&self.journal.path, &reason);
                self.broken = Some(reason);
            })?;
        if let Some(book) = &mut self.flows {
            for view in &mut book.views {
                if view.number >= base.next_view {
                    view.written = true;
                }
            }
            book.add_base(&self.journal.last);
        }
        Ok(())
    }

    /// Whether observing this view now would make the engine stricter
    /// (halt it, or stop it), with every flow known: for a caller that
    /// first makes sure no flow it has not heard of explains the loss.
    /// Changes nothing.
    pub fn would_halt(
        &self,
        now: Timestamp,
        times: &BTreeMap<String, i64>,
        equity: Decimal,
    ) -> bool {
        let before = self.engine.state();
        let after = match &self.flows {
            Some(book) if flows::goes_back(times, &book.horizon) => return false,
            Some(book) => {
                let Ok(mut fold) = book.live_fold(&self.journal.limits, &self.engine) else {
                    return true;
                };
                let seen = SeenView {
                    at: now,
                    times: times.clone(),
                    equity,
                };
                if fold.view(&seen).is_err() {
                    return true;
                }
                match flows::settle(
                    &self.journal.limits,
                    &self.engine.snapshot(),
                    &fold.engine.snapshot(),
                ) {
                    Ok(snapshot) => snapshot.state,
                    Err(_) => return true,
                }
            }
            None => {
                let mut trial = self.engine.clone();
                trial.observe(now, equity)
            }
        };
        stricter(before, after)
    }

    /// Keep a deposit, a withdrawal or a transfer out of the account stops
    /// (`docs/guard.md#deposits-and-withdrawals`). A flow no view shows yet is applied at
    /// the first that does ([`FlowOutcome::Pending`]); one that views
    /// already show is placed at its own time among them, and the engine is
    /// recomputed from the last record before it with every view since. On
    /// the journal as a `flowed` record (every flow is, once known); a halt
    /// or stop set meanwhile stays. A flow seen before (by id) is a
    /// duplicate; one of nothing, or older than every record a replay may
    /// start from, is skipped and counts as any change of equity.
    pub fn apply_flow(&mut self, now: Timestamp, flow: &Flow) -> Result<FlowOutcome, JournalError> {
        self.check_intact()?;
        let Some(book) = &mut self.flows else {
            return Ok(FlowOutcome::Skipped(
                "this engine does not take flows".into(),
            ));
        };
        if flow.amount.is_zero() && !flow.between {
            return Ok(FlowOutcome::Skipped("a flow of nothing".into()));
        }
        if book.ids.contains(&flow.id) {
            let pending = book
                .known
                .iter()
                .any(|known| known.flow.id == flow.id && known.place.is_none());
            return Ok(if pending {
                FlowOutcome::Pending
            } else {
                FlowOutcome::Duplicate
            });
        }
        book.ids.insert(flow.id.clone());
        // A record whose views reach the flow did not know it: the newest
        // that did not is where the replay starts.
        let Some(keep) = book
            .bases
            .iter()
            .rposition(|base| flows::before_horizon(flow, &base.reach))
        else {
            let outcome = FlowOutcome::Skipped(
                "older than every state kept to replay from (a day, a review or the journal's start since): it counts as a gain or loss"
                    .into(),
            );
            book.outcomes.push((flow.clone(), outcome.clone()));
            return Ok(outcome);
        };
        book.bases.truncate(keep + 1);
        book.known.push(Known {
            flow: flow.clone(),
            place: None,
        });
        let index = book.known.len() - 1;
        // Every flow is on the journal once known (the reader checks the
        // records after it against it), applied or not.
        self.write_flowed(now)?;
        let Some(book) = &mut self.flows else {
            return Ok(FlowOutcome::Pending);
        };
        let applied = book
            .known
            .get(index)
            .is_some_and(|known| known.place.is_some());
        let outcome = if applied {
            book.outcomes.push((flow.clone(), FlowOutcome::Applied));
            FlowOutcome::Applied
        } else {
            FlowOutcome::Pending
        };
        self.prune_flows(now);
        Ok(outcome)
    }
}
