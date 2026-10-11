// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! A trading session driven by [`PersistentRisk`]: what the session may do
//! with the engine it is lent ([`SessionRisk`], [`EngineHandle`]), what it
//! has to provide ([`RiskSession`]), and [`PersistentRisk::sync`] and
//! [`PersistentRisk::enter`], which drive it.

use std::{fmt, future::Future};

use rust_decimal::Decimal;
use serde::Serialize;
use zunder_core::{Side, Symbol, Timestamp};
use zunder_risk::{
    CombinedExposure, PositionDiscrepancy, RiskEngine, RiskLimits, RiskState, SizeRequest,
    TrackedPosition, VenueView, Veto,
};

use super::{JournalError, JournalEvent, PersistentRisk};

/// What a trading session may do with the risk engine: read its limits,
/// state, record of positions and exposure, size an entry, and show it the venue and
/// what the session did. Nothing else: no replacing the engine, no change of
/// limits, no review. [`RiskEngine`] has it, for a session that holds its own
/// engine; [`EngineHandle`] has it, for the engine [`PersistentRisk`] lends.
/// Sealed: nothing else can implement it, so a session's entries are always
/// sized by a real engine.
pub trait SessionRisk: sealed::Sealed {
    fn limits(&self) -> &RiskLimits;
    fn state(&self) -> RiskState;
    fn positions(&self) -> &[TrackedPosition];
    fn combined_exposure(&self, view: &VenueView) -> Result<CombinedExposure, Veto>;
    fn size_entry(&self, request: &SizeRequest) -> Result<Decimal, Veto>;
    fn observe(&mut self, now: Timestamp, equity: Decimal) -> RiskState;
    fn reconcile_positions(&mut self, view: &VenueView, settled: bool) -> Vec<PositionDiscrepancy>;
    fn record_entry(
        &mut self,
        symbol: Symbol,
        side: Side,
        qty: Decimal,
        price: Decimal,
        stop: Decimal,
    ) -> Result<(), Veto>;
    fn record_closed(&mut self, symbol: &Symbol);
    fn record_stop(&mut self, symbol: &Symbol, stop: Decimal);
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for zunder_risk::RiskEngine {}
    impl Sealed for super::EngineHandle<'_> {}
}

impl SessionRisk for RiskEngine {
    fn limits(&self) -> &RiskLimits {
        RiskEngine::limits(self)
    }
    fn state(&self) -> RiskState {
        RiskEngine::state(self)
    }
    fn positions(&self) -> &[TrackedPosition] {
        RiskEngine::positions(self)
    }
    fn combined_exposure(&self, view: &VenueView) -> Result<CombinedExposure, Veto> {
        RiskEngine::combined_exposure(self, view)
    }
    fn size_entry(&self, request: &SizeRequest) -> Result<Decimal, Veto> {
        RiskEngine::size_entry(self, request)
    }
    fn observe(&mut self, now: Timestamp, equity: Decimal) -> RiskState {
        RiskEngine::observe(self, now, equity)
    }
    fn reconcile_positions(&mut self, view: &VenueView, settled: bool) -> Vec<PositionDiscrepancy> {
        RiskEngine::reconcile_positions(self, view, settled)
    }
    fn record_entry(
        &mut self,
        symbol: Symbol,
        side: Side,
        qty: Decimal,
        price: Decimal,
        stop: Decimal,
    ) -> Result<(), Veto> {
        RiskEngine::record_entry(self, symbol, side, qty, price, stop)
    }
    fn record_closed(&mut self, symbol: &Symbol) {
        RiskEngine::record_closed(self, symbol);
    }
    fn record_stop(&mut self, symbol: &Symbol, stop: Decimal) {
        RiskEngine::record_stop(self, symbol, stop);
    }
}

/// The engine of a [`PersistentRisk`], lent to a [`RiskSession`] for one
/// call. Only this crate makes one, and it gives access to [`SessionRisk`]
/// and nothing else: a session cannot replace the engine, change its limits,
/// restore a snapshot or call the review through it. What it can still do is
/// what a session always did with the engine: show it equity at the time it
/// names, and reconcile and record positions.
pub struct EngineHandle<'a> {
    engine: &'a mut RiskEngine,
}

impl<'a> EngineHandle<'a> {
    fn new(engine: &'a mut RiskEngine) -> Self {
        Self { engine }
    }
}

impl SessionRisk for EngineHandle<'_> {
    fn limits(&self) -> &RiskLimits {
        self.engine.limits()
    }
    fn state(&self) -> RiskState {
        self.engine.state()
    }
    fn positions(&self) -> &[TrackedPosition] {
        self.engine.positions()
    }
    fn combined_exposure(&self, view: &VenueView) -> Result<CombinedExposure, Veto> {
        self.engine.combined_exposure(view)
    }
    fn size_entry(&self, request: &SizeRequest) -> Result<Decimal, Veto> {
        self.engine.size_entry(request)
    }
    fn observe(&mut self, now: Timestamp, equity: Decimal) -> RiskState {
        self.engine.observe(now, equity)
    }
    fn reconcile_positions(&mut self, view: &VenueView, settled: bool) -> Vec<PositionDiscrepancy> {
        self.engine.reconcile_positions(view, settled)
    }
    fn record_entry(
        &mut self,
        symbol: Symbol,
        side: Side,
        qty: Decimal,
        price: Decimal,
        stop: Decimal,
    ) -> Result<(), Veto> {
        self.engine.record_entry(symbol, side, qty, price, stop)
    }
    fn record_closed(&mut self, symbol: &Symbol) {
        self.engine.record_closed(symbol);
    }
    fn record_stop(&mut self, symbol: &Symbol, stop: Decimal) {
        self.engine.record_stop(symbol, stop);
    }
}

/// What [`PersistentRisk::sync`] and [`PersistentRisk::enter`] drive: a
/// trading session on a venue. Implemented outside this crate, by the
/// executor's session. The engine is lent to it for one call at a time,
/// as an [`EngineHandle`].
pub trait RiskSession {
    /// The session's error.
    type Error: fmt::Display;
    /// An entry the risk engine sized.
    type Entry;
    /// What an entry did.
    type EntryReport;
    /// What a reconciliation found.
    type ReconcileReport;
    /// What flattening did.
    type FlattenReport: FlattenOutcome;

    /// Show the engine the venue: observe the equity and reconcile the
    /// engine's record of positions with the venue's.
    fn observe_risk(
        &mut self,
        engine: &mut EngineHandle<'_>,
        now: Timestamp,
    ) -> impl Future<Output = Result<RiskObservation, Self::Error>>;

    /// Reconcile the session with the venue.
    fn reconcile(
        &mut self,
        now: Timestamp,
    ) -> impl Future<Output = Result<Self::ReconcileReport, Self::Error>>;

    /// Cancel every order that could open a position and close every
    /// position.
    fn flatten_all(&mut self, now: Timestamp) -> impl Future<Output = Self::FlattenReport>;

    /// Open a position sized by `engine`, with its protective stop.
    fn enter(
        &mut self,
        engine: &mut EngineHandle<'_>,
        entry: Self::Entry,
        now: Timestamp,
    ) -> impl Future<Output = Result<Self::EntryReport, Self::Error>>;

    /// The session's error for an entry refused because the engine is in
    /// `state`, not active.
    fn risk_not_active(state: RiskState) -> Self::Error;
}

/// Whether a flatten left the account flat.
pub trait FlattenOutcome {
    fn is_flat(&self) -> bool;
}

/// What a session's [`RiskSession::observe_risk`] showed the risk engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskObservation {
    /// The engine's state after the observation.
    pub state: RiskState,
    /// The account's equity, as observed.
    pub equity: Decimal,
    /// Where the engine's record of positions and the venue disagreed.
    pub discrepancies: Vec<PositionDiscrepancy>,
    /// Why the record of positions could not be compared with the venue
    /// this time (an order list or a price that could not be read). The
    /// equity was observed anyway.
    pub book_error: Option<String>,
    /// Whether the venue showed any position.
    pub positions_open: bool,
    /// Whether any order that could open or grow a position rests; true
    /// when the orders could not be read.
    pub opening_orders: bool,
    /// Whether a position the session tracks is gone from the venue (its
    /// stop most likely executed). The session then needs a
    /// reconciliation before it trades again, and the risk engine's record
    /// keeps the position until then.
    pub tracked_gone: bool,
}

/// Errors of [`PersistentRisk`]'s trading calls, for a session whose error
/// is `E`, whose entries report `R` and whose flattening reports `F`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskStoreError<E, R, F> {
    Journal(JournalError),
    Session(E),
    /// The entry went through, and its stop rests on the venue, but the
    /// journal could not record it. No new positions after this.
    EntryNotJournaled {
        report: Box<R>,
        error: JournalError,
    },
    /// Equity could not be read, so nothing was observed, but the engine
    /// already held a halt and the session flattened for it: `flatten`
    /// says whether that left the account flat.
    EquityUnreadable {
        error: E,
        flatten: Box<F>,
    },
}

impl<E, R, F> From<JournalError> for RiskStoreError<E, R, F> {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl<E: fmt::Display, R: fmt::Debug, F: FlattenOutcome> fmt::Display for RiskStoreError<E, R, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => fmt::Display::fmt(error, f),
            Self::Session(error) => fmt::Display::fmt(error, f),
            Self::EntryNotJournaled { report, error } => write!(
                f,
                "the entry went through ({report:?}), but the journal could not record it: {error}"
            ),
            Self::EquityUnreadable { error, flatten } => write!(
                f,
                "equity could not be read ({error}); the held halt flattened: flat {}",
                flatten.is_flat()
            ),
        }
    }
}

impl<E, R, F> std::error::Error for RiskStoreError<E, R, F>
where
    E: std::error::Error + 'static,
    R: fmt::Debug,
    F: FlattenOutcome + fmt::Debug,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // As `#[error(transparent)]` would: the wrapped error's source.
        match self {
            Self::Journal(error) => std::error::Error::source(error),
            Self::Session(error) => std::error::Error::source(error),
            Self::EntryNotJournaled { .. } | Self::EquityUnreadable { .. } => None,
        }
    }
}

/// [`RiskStoreError`] for the session `S`.
pub type StoreErrorOf<S> = RiskStoreError<
    <S as RiskSession>::Error,
    <S as RiskSession>::EntryReport,
    <S as RiskSession>::FlattenReport,
>;

/// The result of [`PersistentRisk::sync`], for a session whose
/// reconciliation reports `C` and whose flattening reports `F`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskSync<C, F> {
    pub state: RiskState,
    pub equity: Decimal,
    /// Where the engine's record of positions and the venue disagreed.
    pub discrepancies: Vec<PositionDiscrepancy>,
    /// Why the record of positions could not be compared with the venue
    /// this time, if it could not. The equity was observed anyway.
    pub book_error: Option<String>,
    /// The reconciliation run because a position the session tracked had
    /// gone from the venue, and its result.
    pub reconcile: Option<Result<C, String>>,
    /// The flattening a halt or stop asked for, if anything was open.
    pub flatten: Option<F>,
    /// Set when the journal could not be written. The engine's state then
    /// lives in memory only, and no new positions are allowed.
    pub journal_error: Option<String>,
}

/// [`RiskSync`] for the session `S`.
pub type SyncOf<S> =
    RiskSync<<S as RiskSession>::ReconcileReport, <S as RiskSession>::FlattenReport>;

impl PersistentRisk {
    /// Show the engine the venue and act on what it says: observe the
    /// equity, reconcile the record of positions, write the result to the
    /// journal, and then, if the engine is halted or stopped, flatten
    /// everything. The journal is written before anything is flattened.
    /// The equity is observed even when the positions cannot be compared
    /// (`book_error`); only an unreadable account stops the observation.
    /// When a position the session tracks has gone from the venue (its stop
    /// executed, most likely), the session is reconciled and the venue
    /// observed again (`reconcile`), so the record lets go of it.
    ///
    /// Call it at start-up and regularly while trading;
    /// [`PersistentRisk::enter`] calls it first. When the journal cannot be
    /// written the state lives on in memory, a halt is still acted on, and
    /// `journal_error` says why; no new positions are allowed after that.
    pub async fn sync<S: RiskSession>(
        &mut self,
        session: &mut S,
        now: Timestamp,
    ) -> Result<SyncOf<S>, StoreErrorOf<S>> {
        let mut observation = self.observe(session, now).await?;
        let mut reconcile = None;
        let mut early_journal_error = None;
        if observation.tracked_gone {
            // The first observation may have fired a halt: it reaches the
            // journal before anything else happens, also if the second
            // observation below fails (and then flattens for it).
            early_journal_error = self.commit(now, JournalEvent::Updated).err();
            // A tracked position is gone, most likely by its stop: let the
            // session explain it, then look again, so that the record lets
            // go of it and entries are not refused for a position that no
            // longer exists.
            reconcile = Some(
                session
                    .reconcile(now)
                    .await
                    .map_err(|error| error.to_string()),
            );
            observation = self.observe(session, now).await?;
        }
        let mut journal_error =
            early_journal_error.or(self.commit(now, JournalEvent::Updated).err());
        self.observed = true;

        let mut flatten = None;
        let must_flatten = observation.positions_open || observation.opening_orders;
        if observation.state != RiskState::Active && must_flatten {
            let report = session.flatten_all(now).await;
            if report.is_flat() {
                // Confirmed flat on the venue: the record is empty too.
                self.engine.reconcile_positions(&VenueView::default(), true);
                if journal_error.is_none() {
                    journal_error = self.commit(now, JournalEvent::Updated).err();
                }
            }
            flatten = Some(report);
        }
        Ok(RiskSync {
            state: observation.state,
            equity: observation.equity,
            discrepancies: observation.discrepancies,
            book_error: observation.book_error,
            reconcile,
            flatten,
            journal_error: journal_error.map(|error| error.to_string()),
        })
    }

    /// [`RiskSession::observe_risk`], for [`PersistentRisk::sync`]. When equity
    /// cannot be read (an account mode the executor refuses, a price that
    /// cannot be read), nothing is observed, but a halt the engine already
    /// holds is still acted on: closing needs no equity. The error then
    /// carries the flatten's report.
    async fn observe<S: RiskSession>(
        &mut self,
        session: &mut S,
        now: Timestamp,
    ) -> Result<RiskObservation, StoreErrorOf<S>> {
        let observed = session
            .observe_risk(&mut EngineHandle::new(&mut self.engine), now)
            .await;
        match observed {
            Ok(observation) => Ok(observation),
            Err(error) if self.engine.state() != RiskState::Active => {
                let flatten = session.flatten_all(now).await;
                Err(RiskStoreError::EquityUnreadable {
                    error,
                    flatten: Box::new(flatten),
                })
            }
            Err(error) => Err(RiskStoreError::Session(error)),
        }
    }

    /// Open a position through `session` ([`RiskSession::enter`]) and write the
    /// engine's record of it to the journal. Syncs first, so the entry is
    /// judged on a fresh observation: refused when that sync fails, when
    /// the engine is not active afterwards, or when a write has failed.
    ///
    /// When the journal cannot be written afterwards, the error carries
    /// the entry's report; whatever opened is protected by its stop on the
    /// venue.
    pub async fn enter<S: RiskSession>(
        &mut self,
        session: &mut S,
        entry: S::Entry,
        now: Timestamp,
    ) -> Result<S::EntryReport, StoreErrorOf<S>> {
        self.check_intact()?;
        let synced = self.sync(session, now).await?;
        if let Some(error) = synced.journal_error {
            return Err(JournalError::Broken(error).into());
        }
        if synced.state != RiskState::Active {
            return Err(RiskStoreError::Session(S::risk_not_active(synced.state)));
        }
        let result = session
            .enter(&mut EngineHandle::new(&mut self.engine), entry, now)
            .await;
        match (self.commit(now, JournalEvent::Updated), result) {
            (Ok(()), result) => result.map_err(RiskStoreError::Session),
            (Err(error), Ok(report)) => Err(RiskStoreError::EntryNotJournaled {
                report: Box::new(report),
                error,
            }),
            (Err(_), Err(error)) => Err(RiskStoreError::Session(error)),
        }
    }
}
