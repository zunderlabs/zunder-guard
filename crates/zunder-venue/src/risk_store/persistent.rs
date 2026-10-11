// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! [`PersistentRisk`]: the risk engine and its journal, opened, written
//! and reviewed.

use std::{fs::File, path::Path};

use rust_decimal::Decimal;
use serde::Serialize;
use zunder_core::{Side, Symbol, Timestamp};
use zunder_risk::{
    PositionDiscrepancy, RiskEngine, RiskLimits, RiskSnapshot, RiskState, TrackedPosition,
    VenueView,
};

use super::{
    JournalError,
    check::Checks,
    file::{self, RiskJournal},
    flow_book::FlowBook,
    parse::parse,
    record::{FlowFields, JournalEvent, JournalRecord, JournalScope},
};
use crate::flows::{FLOW_FALL_WRITTEN, SeenView};

/// [`must_write`] for an engine that takes flows: also a last equity that
/// fell more than [`FLOW_FALL_WRITTEN`] below the last one written.
fn must_write_flows(written: &RiskSnapshot, now: &RiskSnapshot, limits: &RiskLimits) -> bool {
    if must_write(written, now) {
        return true;
    }
    let base = limits
        .max_trading_equity_usd
        .map_or(written.day_start, |cap| written.day_start.min(cap));
    let Some(allowed) = base.checked_mul(FLOW_FALL_WRITTEN) else {
        return true;
    };
    written
        .last
        .checked_sub(now.last)
        .is_none_or(|fall| fall > allowed)
}

/// Whether `now` differs from the `written` state in a way that has to
/// reach the disk. See the module documentation.
pub(super) fn must_write(written: &RiskSnapshot, now: &RiskSnapshot) -> bool {
    // The last price of a recorded position is only a fallback.
    let without_marks = |positions: &[TrackedPosition]| -> Vec<TrackedPosition> {
        positions
            .iter()
            .map(|position| TrackedPosition {
                mark: Decimal::ZERO,
                ..position.clone()
            })
            .collect()
    };
    now.state != written.state
        || now.peak != written.peak
        || now.day != written.day
        || now.day_start != written.day_start
        || without_marks(&now.positions) != without_marks(&written.positions)
        || now.last > written.last
}

/// The result of [`PersistentRisk::observe_view`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ViewSync {
    pub state: RiskState,
    /// Where the engine's record of positions and the view disagreed.
    pub discrepancies: Vec<PositionDiscrepancy>,
    /// Set when the journal could not be written.
    pub journal_error: Option<String>,
    /// Whether the view was observed: an engine that takes flows leaves out
    /// a view that may or may not show a flow, and ignores one older than a
    /// view before it ([`PersistentRisk::observe_view_at`]).
    pub taken: bool,
    /// Whether it was ignored as older than a view before it.
    pub ignored: bool,
}

/// A risk engine whose state survives restarts, kept in a journal on disk.
/// See the module documentation.
#[derive(Debug)]
pub struct PersistentRisk {
    pub(super) engine: RiskEngine,
    pub(super) journal: RiskJournal,
    /// Whether [`PersistentRisk::sync`] has observed the venue since the
    /// journal was opened.
    pub(super) observed: bool,
    /// Why the journal can no longer be written, after a failed write.
    pub(super) broken: Option<String>,
    /// Deposits and withdrawals are kept out of the account stops
    /// ([`PersistentRisk::with_flows`]); `None`: they count as gains and
    /// losses, as the engine sees any change of equity.
    pub(super) flows: Option<FlowBook>,
}

impl PersistentRisk {
    /// Start a new journal at `path` for an engine with `limits`, starting
    /// at `equity`. **A person's decision**: it is the only way to trade
    /// without a journal's history, so a running engine must never call
    /// it. Refuses if anything exists at `path`, or a marker of a failed
    /// write; a damaged journal is moved aside by hand, never replaced by
    /// code.
    pub fn initialise(
        path: &Path,
        limits: RiskLimits,
        at: Timestamp,
        equity: Decimal,
        note: &str,
    ) -> Result<Self, JournalError> {
        Self::initialise_in(path, limits, None, at, equity, note)
    }

    /// [`PersistentRisk::initialise`] for one network and account, which
    /// the journal records: it then opens only with
    /// [`PersistentRisk::open_for`] and the same scope.
    pub fn initialise_for(
        path: &Path,
        limits: RiskLimits,
        scope: &JournalScope,
        at: Timestamp,
        equity: Decimal,
        note: &str,
    ) -> Result<Self, JournalError> {
        Self::initialise_in(path, limits, Some(scope), at, equity, note)
    }

    fn initialise_in(
        path: &Path,
        limits: RiskLimits,
        scope: Option<&JournalScope>,
        at: Timestamp,
        equity: Decimal,
        note: &str,
    ) -> Result<Self, JournalError> {
        let engine = RiskEngine::new(limits.clone(), at, equity)
            .map_err(|error| JournalError::Invalid(error.to_string()))?;
        file::refuse_existing(path)?;
        let (_, line) = JournalRecord::new(
            1,
            at,
            JournalEvent::Initialised {
                limits: limits.clone(),
                scope: scope.cloned(),
                note: note.to_owned(),
            },
            engine.snapshot(),
            String::new(),
            FlowFields::default(),
        )
        .map_err(|message| JournalError::Io {
            path: path.to_owned(),
            message,
        })?;
        file::create(path, &line)?;
        Self::open_in(path, &limits, scope)
    }

    /// Open the journal at `path` and restore the engine from its last
    /// record. Refuses a journal that is missing, unreadable, torn,
    /// inconsistent, marked broken by a failed write, or written under
    /// limits other than `limits`. Nothing can be entered until
    /// [`PersistentRisk::sync`] has observed the venue.
    pub fn open(path: &Path, limits: &RiskLimits) -> Result<Self, JournalError> {
        Self::open_in(path, limits, None)
    }

    /// [`PersistentRisk::open`] for one network and account: refuses also a
    /// journal started for another scope, or without one.
    pub fn open_for(
        path: &Path,
        limits: &RiskLimits,
        scope: &JournalScope,
    ) -> Result<Self, JournalError> {
        Self::open_in(path, limits, Some(scope))
    }

    fn open_in(
        path: &Path,
        limits: &RiskLimits,
        scope: Option<&JournalScope>,
    ) -> Result<Self, JournalError> {
        file::refuse_marked(path)?;
        let (file, bytes) = file::open_complete(path)?;
        let (header, records, checks) = parse(path, &bytes)?;
        header.check(limits, scope)?;
        Self::from_records(path, file, limits, records, checks)
    }

    /// The engine and the journal handle from checked records.
    fn from_records(
        path: &Path,
        file: File,
        limits: &RiskLimits,
        records: Vec<JournalRecord>,
        checks: Checks,
    ) -> Result<Self, JournalError> {
        let line = records.len();
        let last = records
            .into_iter()
            .last()
            .ok_or_else(|| JournalError::Invalid("the journal is empty".into()))?;
        let engine = RiskEngine::restore(limits.clone(), last.state.clone()).map_err(|error| {
            JournalError::Inconsistent {
                path: path.to_owned(),
                line,
                message: error.to_string(),
            }
        })?;
        Ok(Self {
            engine,
            journal: RiskJournal {
                path: path.to_owned(),
                file,
                limits: limits.clone(),
                last,
                checks,
            },
            observed: false,
            broken: None,
            flows: None,
        })
    }

    /// Read every record of the journal at `path`, checked as
    /// [`PersistentRisk::open`] checks them, without locking or changing
    /// it. For inspection; a marker of a failed write does not stop it.
    pub fn read(path: &Path) -> Result<Vec<JournalRecord>, JournalError> {
        let bytes = file::read_complete(path)?;
        Ok(parse(path, &bytes)?.1)
    }

    /// Cut off a last record whose write was interrupted, and record that
    /// in the journal. **A person's decision**, after looking at the file
    /// and the account's history: the cut record may have held a new peak
    /// or a halt that the next observation cannot find again. Returns the
    /// number of bytes cut off; zero if the journal was intact. Refuses if
    /// what remains is not a valid journal under `limits`. Does not remove
    /// a marker of a failed write: the person does that, after looking.
    pub fn repair_torn_tail(
        path: &Path,
        limits: &RiskLimits,
        at: Timestamp,
        note: &str,
    ) -> Result<u64, JournalError> {
        Self::repair_torn_tail_in(path, limits, None, at, note)
    }

    /// [`PersistentRisk::repair_torn_tail`] of a journal started for
    /// `scope`; refuses one started for another scope, or without one.
    pub fn repair_torn_tail_for(
        path: &Path,
        limits: &RiskLimits,
        scope: &JournalScope,
        at: Timestamp,
        note: &str,
    ) -> Result<u64, JournalError> {
        Self::repair_torn_tail_in(path, limits, Some(scope), at, note)
    }

    fn repair_torn_tail_in(
        path: &Path,
        limits: &RiskLimits,
        scope: Option<&JournalScope>,
        at: Timestamp,
        note: &str,
    ) -> Result<u64, JournalError> {
        let mut file = file::open_locked_mode(path, true)?;
        let (bytes, complete) = file::read_all(path, &mut file)?;
        if complete == bytes.len() {
            // Nothing to cut; still refuse a journal of other limits or
            // another network or account, as a repair of it would be.
            parse(path, &bytes)?.0.check(limits, scope)?;
            return Ok(0);
        }
        if complete == 0 {
            return Err(JournalError::Invalid(format!(
                "{}: no complete record is left; move the file aside and initialise a new journal",
                path.display()
            )));
        }
        let (header, records, checks) = parse(path, &bytes[..complete])?;
        header.check(limits, scope)?;
        file::truncate(path, &mut file, complete as u64)?;
        let cut = (bytes.len() - complete) as u64;
        // Still under the same lock.
        let mut risk = Self::from_records(path, file, limits, records, checks)?;
        let state = risk.engine.snapshot();
        risk.journal.append(
            at,
            JournalEvent::Repaired {
                cut_bytes: cut,
                note: note.to_owned(),
            },
            state,
            FlowFields::default(),
            None,
        )?;
        Ok(cut)
    }

    /// Record that the journal at `path`, started without a network and
    /// account, belongs to `scope`. **A person's decision**, for a journal
    /// written before journals named them (the testnet runner's), after
    /// checking that it really was written for that network and account:
    /// its peak, day start and halts carry over. Refuses a journal that
    /// already names a scope, one written under other limits, and
    /// everything [`PersistentRisk::open`] refuses. The journal is locked
    /// meanwhile, so the runner has to be stopped.
    pub fn adopt_scope(
        path: &Path,
        limits: &RiskLimits,
        scope: &JournalScope,
        at: Timestamp,
        note: &str,
    ) -> Result<(), JournalError> {
        let mut risk = Self::open_in(path, limits, None)?;
        let state = risk.engine.snapshot();
        risk.journal.append(
            at,
            JournalEvent::Scoped {
                scope: scope.clone(),
                note: note.to_owned(),
            },
            state,
            FlowFields::default(),
            None,
        )
    }

    /// The engine, for sizing entries (the session's sized entry) and reading its
    /// state.
    pub fn engine(&self) -> &RiskEngine {
        &self.engine
    }

    pub fn state(&self) -> RiskState {
        self.engine.state()
    }

    pub fn path(&self) -> &Path {
        &self.journal.path
    }

    /// Whether new positions may be opened as far as the journal is
    /// concerned: every write so far succeeded, and the venue has been
    /// observed since the journal was opened. The engine's own state is
    /// checked by the session.
    pub fn check_ready(&self) -> Result<(), JournalError> {
        self.check_intact()?;
        if !self.observed {
            return Err(JournalError::NotObserved);
        }
        if self.flows.as_ref().is_some_and(FlowBook::pending) {
            return Err(JournalError::PendingFlows);
        }
        Ok(())
    }

    pub(super) fn check_intact(&self) -> Result<(), JournalError> {
        match &self.broken {
            Some(why) => Err(JournalError::Broken(why.clone())),
            None => Ok(()),
        }
    }

    /// Write the engine's state if it changed in a way that matters. After
    /// a failed write nothing is written again: a write cut short may have
    /// left a torn record, and appending behind it would bury it. The
    /// failure is also marked on disk, for the next process.
    pub(super) fn commit(
        &mut self,
        at: Timestamp,
        event: JournalEvent,
    ) -> Result<(), JournalError> {
        self.commit_view(at, event, None)
    }

    /// [`PersistentRisk::commit`] for an engine that may take flows: its
    /// records carry the horizon, and `view` when written for one, and a
    /// fall of the last equity is written too ([`must_write_flows`]).
    pub(super) fn commit_view(
        &mut self,
        at: Timestamp,
        event: JournalEvent,
        view: Option<&SeenView>,
    ) -> Result<(), JournalError> {
        self.check_intact()?;
        let state = self.engine.snapshot();
        let written = &self.journal.last.state;
        let must = if self.flows.is_some() {
            must_write_flows(written, &state, &self.journal.limits)
        } else {
            must_write(written, &state)
        };
        if event == JournalEvent::Updated && !must {
            return Ok(());
        }
        let fields = match &self.flows {
            Some(book) => FlowFields {
                horizon: Some(book.horizon.clone()),
                view: view.cloned(),
            },
            None => FlowFields::default(),
        };
        let resumed = matches!(event, JournalEvent::ResumedAfterReview { .. });
        self.journal
            .append(at, event, state, fields, None)
            .inspect_err(|error| {
                let reason = error.to_string();
                file::mark_broken(&self.journal.path, &reason);
                self.broken = Some(reason);
            })?;
        if let Some(book) = &mut self.flows {
            if resumed {
                // A review starts afresh: nothing before it is replayed.
                book.reset();
            }
            if view.is_some()
                && let Some(last) = book.views.back_mut()
            {
                last.written = true;
            }
            book.add_base(&self.journal.last);
        }
        Ok(())
    }

    /// Show the engine an account its caller read itself, for a caller that
    /// holds no session: Zunder Guard, which forwards a bot's orders and
    /// reads the venue through its own requests (`zunder-guard`). Observes
    /// `equity`, reconciles the record of positions with `view` (`settled`
    /// as in [`RiskEngine::reconcile_positions`]: the caller vouches that
    /// nothing of its own is in flight), and writes the result to the
    /// journal before returning, so a halt is on disk before the caller
    /// acts on it. Nothing is flattened here: when the state is not active
    /// the caller has to flatten, as after [`PersistentRisk::sync`].
    ///
    /// When the journal cannot be written the state lives on in memory and
    /// `journal_error` says why; [`PersistentRisk::check_ready`] then
    /// refuses, so no new positions are allowed.
    pub fn observe_view(
        &mut self,
        now: Timestamp,
        equity: Decimal,
        view: &VenueView,
        settled: bool,
    ) -> ViewSync {
        self.engine.observe(now, equity);
        let discrepancies = self.engine.reconcile_positions(view, settled);
        let journal_error = self
            .commit(now, JournalEvent::Updated)
            .err()
            .map(|error| error.to_string());
        self.observed = true;
        ViewSync {
            state: self.engine.state(),
            discrepancies,
            journal_error,
            taken: true,
            ignored: false,
        }
    }

    /// Record a position its caller opened on the venue without a
    /// session (Zunder Guard forwarding a bot's entry, once the venue
    /// reported the fill): `qty` filled at `price`, protected by `stop`,
    /// written to the journal. The engine then counts it at once, also
    /// before the venue's next view shows it. Refused while the journal is
    /// broken.
    pub fn record_entry(
        &mut self,
        now: Timestamp,
        symbol: Symbol,
        side: Side,
        qty: Decimal,
        price: Decimal,
        stop: Decimal,
    ) -> Result<(), JournalError> {
        self.check_intact()?;
        self.engine
            .record_entry(symbol, side, qty, price, stop)
            .map_err(|veto| JournalError::Invalid(format!("recording an entry: {veto}")))?;
        self.commit(now, JournalEvent::Updated)
    }

    /// Check review prerequisites before fetching equity or changing state.
    /// Durable pending flows also block callers opened without `with_flows`.
    pub fn check_review_ready(&self) -> Result<(), JournalError> {
        self.check_intact()?;
        if self.journal.checks.listings.pending()
            || self.flows.as_ref().is_some_and(FlowBook::pending)
        {
            return Err(JournalError::PendingFlows);
        }
        Ok(())
    }

    /// Clear a drawdown stop after a person has reviewed it, restarting the
    /// peak from `equity`, the account's equity now, and write that to the
    /// journal. **A person's decision**: never call this from anything
    /// automatic. Does nothing unless the engine is stopped.
    pub fn resume_after_review(
        &mut self,
        at: Timestamp,
        equity: Decimal,
        note: &str,
    ) -> Result<RiskState, JournalError> {
        self.check_review_ready()?;
        if !matches!(self.engine.state(), RiskState::Stopped { .. }) {
            return Ok(self.engine.state());
        }
        if at.utc_day() < self.engine.snapshot().day {
            return Err(JournalError::Invalid(format!(
                "a review at {at} is dated before the engine's current day"
            )));
        }
        let before = self.engine.clone();
        self.engine.resume_after_review(at, equity);
        if self.engine.state() == RiskState::Active
            && let Err(error) = self.commit(
                at,
                JournalEvent::ResumedAfterReview {
                    note: note.to_owned(),
                },
            )
        {
            // Not on disk: not resumed.
            self.engine = before;
            return Err(error);
        }
        Ok(self.engine.state())
    }
}
