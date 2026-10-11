// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The risk engine's memory across restarts: an append-only journal on
//! disk, and [`PersistentRisk`], which keeps it.
//!
//! # The journal
//!
//! One JSON record per line, appended and never rewritten. Every record
//! carries the engine's complete state after a change ([`RiskSnapshot`]):
//! the halt or stop, the equity peak, the daily loss window, the last
//! equity and the engine's record of open positions. Loading takes the last
//! record, after checking all of them.
//!
//! - **Versioned.** Each line names the format (`zunder-risk-journal`) and
//!   its version ([`JOURNAL_VERSION`]). A newer version is refused, never
//!   guessed at.
//! - **Crash-safe.** A record is written with one append and synced to disk
//!   before anything acts on it: a halt is on disk before the session
//!   flattens. A write cut short leaves a last line without its newline;
//!   loading refuses such a journal, and only a person can cut the torn
//!   record off ([`PersistentRisk::repair_torn_tail`]). A failed write also
//!   leaves a marker file next to the journal (`<journal>.broken`), so that
//!   a write that failed without leaving a trace, such as on a full disk,
//!   is not forgotten by a restart: loading refuses while the marker is
//!   there, and a person removes it after looking. A new journal is written
//!   to a temporary file, synced, and linked into place in one step that
//!   fails if anything exists there already, so a journal is never
//!   overwritten.
//! - **Checked.** Each line starts with a SHA3-256 checksum of the exact
//!   bytes of the rest of the line, which include the previous record's
//!   checksum and a sequence number. Loading refuses a journal with a
//!   damaged or reordered record, a record from which no observation could
//!   have led, or a step between two records the engine cannot take: a
//!   lower peak, a cleared drawdown stop, or a halt cleared on the day it
//!   fired. Only a record of a person's review
//!   ([`PersistentRisk::resume_after_review`]) may clear a drawdown stop and
//!   restart the peak. The writer runs the same checks before it appends,
//!   and refuses to write a record its reader would refuse.
//! - **One writer.** The journal is locked while open; a second process
//!   cannot open it.
//!
//! # When a record is written
//!
//! Whenever the state, the peak, the day, the day's starting equity or the
//! recorded positions (apart from their last price) change, and whenever
//! the last equity rises above the last one written. A falling last equity
//! is not written on its own: the last equity matters only as the next
//! day's starting point, and a starting point that is too high measures
//! that day's loss as larger. A restored engine is therefore never less
//! strict than the one that wrote the journal, as long as every write
//! succeeded; and a failed write stops trading until a person has looked.
//!
//! # Refusing to trade
//!
//! [`PersistentRisk::open`] fails when the journal is missing, unreadable,
//! torn, inconsistent, marked broken, written under other limits, or for
//! another network or account ([`JournalScope`], recorded when the journal
//! is started with [`PersistentRisk::initialise_for`] and checked by
//! [`PersistentRisk::open_for`]).
//! Starting a journal is a person's decision:
//! [`PersistentRisk::initialise`], which refuses to replace anything.
//! Changing the limits means a new journal, and with it a new peak and no
//! halt: a person's decision as well. [`PersistentRisk::enter`] observes
//! the venue first ([`PersistentRisk::sync`]) and refuses unless the engine
//! is active and every write so far succeeded.
//!
//! A replay does not need this: paper books that replay their own event
//! logs rebuild the risk engine from the start every time.
//!
//! # Deposits and withdrawals
//!
//! An engine that takes flows ([`PersistentRisk::with_flows`], Zunder Guard;
//! never the runner) keeps them out of its stops as
//! `docs/guard.md#deposits-and-withdrawals` specifies, through the fold in [`crate::flows`].
//! Its records are version 3: each carries the horizon (the latest venue
//! time of any view, per dex), a record written for a view also the view,
//! and a falling last equity is written too once the last record is a
//! minute old. A flow that changes the engine is a `flowed` record: an
//! earlier record to start from (its base), every view since it and every
//! flow not in it; its state is [`crate::flows::replay`] of those, then
//! [`crate::flows::settle`], and the reader computes the same and refuses
//! the record unless the result is identical. Every other record is checked
//! as before.
//!
//! # The session
//!
//! [`PersistentRisk::sync`] and [`PersistentRisk::enter`] drive a trading
//! session through [`RiskSession`]: it shows the engine the venue,
//! reconciles, flattens and enters. The engine is lent to the session for
//! one call at a time and never handed out. A caller without a session,
//! such as Zunder Guard, observes with [`PersistentRisk::observe_view`] and
//! records its entries with [`PersistentRisk::record_entry`].

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(not(windows))]
use std::fs::TryLockError;

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use zunder_core::{Side, Symbol, Timestamp};
use zunder_risk::{
    CombinedExposure, PositionDiscrepancy, RiskEngine, RiskLimits, RiskSnapshot, RiskState,
    SizeRequest, TrackedPosition, VenueView, Veto,
};

use crate::flows::{self, FLOW_FALL_WRITTEN, Flow, Fold, Horizon, SeenView, Step, WaivedStop};

/// The `format` of every journal line.
pub const JOURNAL_FORMAT: &str = "zunder-risk-journal";

/// The journal version this build writes and the newest it reads. Version
/// 2 (6 Oct 2026) adds the journal's network and account ([`JournalScope`]);
/// version 3 (7 Oct 2026) the records of an engine that takes deposits and
/// withdrawals ([`PersistentRisk::with_flows`]: the horizon, the view, and
/// [`JournalEvent::Flowed`]), the only records written as version 3: an
/// engine without flows (the runner) writes version 2 as before, so an
/// older build still reads its journal. Older journals are still read, and
/// an older build refuses a newer record as too new rather than misreading
/// it.
pub const JOURNAL_VERSION: u32 = 3;

/// The version every record of an engine without flows is written as.
const RECORD_VERSION: u32 = 2;

/// How every line starts: the checksum of the rest comes first.
const CHECK_PREFIX: &str = "{\"check\":\"";

/// Hex digits in a SHA3-256 checksum.
const CHECK_LEN: usize = 64;

/// Where a journal's engine trades: the network and the account. Recorded
/// in the first record and checked whenever the journal is opened, so that
/// a journal never moves to another network or account (a testnet journal
/// copied into a mainnet state directory, say): its peak, day start and
/// halts belong to the account it was written for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalScope {
    /// `"testnet"` or `"mainnet"`.
    pub network: String,
    /// The account's address, as `0x` and 40 lowercase hex digits.
    pub account: String,
}

/// Why a journal record was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum JournalEvent {
    /// A person started the journal, under these limits, for this network
    /// and account when it says. Always the first record, and only the
    /// first.
    Initialised {
        limits: RiskLimits,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<JournalScope>,
        note: String,
    },
    /// The engine's state changed: an observation, a fill, a
    /// reconciliation.
    Updated,
    /// A person reviewed a drawdown stop and resumed trading.
    ResumedAfterReview { note: String },
    /// A person cut off a record whose write had been interrupted.
    Repaired { cut_bytes: u64, note: String },
    /// A person recorded the network and account of a journal started
    /// without them ([`PersistentRisk::adopt_scope`]). Only in a journal
    /// whose first record names none, at most once, and it changes no
    /// state.
    Scoped { scope: JournalScope, note: String },
    /// Deposits, withdrawals or transfers changed the engine
    /// (`docs/guard.md#deposits-and-withdrawals`): its state is
    /// [`crate::flows::replay`] from the state of record `base` (and its
    /// horizon) through `views`, every view since that record, with
    /// `flows`, every flow not in that state, then
    /// [`crate::flows::settle`] against the record before this one. Only an
    /// engine that takes flows ([`PersistentRisk::with_flows`]) writes it.
    Flowed {
        base: u64,
        views: Vec<SeenView>,
        flows: Vec<Flow>,
    },
}

/// What a record's checksum covers: everything but the checksum.
#[derive(Serialize)]
struct Body<'a> {
    format: &'a str,
    version: u32,
    seq: u64,
    at: Timestamp,
    event: &'a JournalEvent,
    state: &'a RiskSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    horizon: Option<&'a Horizon>,
    #[serde(skip_serializing_if = "Option::is_none")]
    view: Option<&'a SeenView>,
    prev: &'a str,
}

/// One line of the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    /// SHA3-256, in hex, of the exact bytes of the rest of the line.
    pub check: String,
    pub format: String,
    pub version: u32,
    /// 1, 2, 3, ... without gaps.
    pub seq: u64,
    /// When the change happened, by the caller's clock.
    pub at: Timestamp,
    pub event: JournalEvent,
    /// The engine's state after the change.
    pub state: RiskSnapshot,
    /// For an engine that takes flows: for each dex, the latest venue time
    /// of any view so far (version 3 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub horizon: Option<Horizon>,
    /// For an engine that takes flows, a record written for a view: that
    /// view (version 3 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<SeenView>,
    /// The previous record's checksum; empty for the first.
    pub prev: String,
}

/// What an engine that takes flows adds to a record.
#[derive(Debug, Clone, Default)]
struct FlowFields {
    horizon: Option<Horizon>,
    view: Option<SeenView>,
}

impl JournalRecord {
    /// A record and the line that holds it, newline included.
    fn new(
        seq: u64,
        at: Timestamp,
        event: JournalEvent,
        state: RiskSnapshot,
        prev: String,
        fields: FlowFields,
    ) -> Result<(Self, String), String> {
        let FlowFields { horizon, view } = fields;
        let version = if horizon.is_some() {
            JOURNAL_VERSION
        } else {
            RECORD_VERSION
        };
        let body = serde_json::to_string(&Body {
            format: JOURNAL_FORMAT,
            version,
            seq,
            at,
            event: &event,
            state: &state,
            horizon: horizon.as_ref(),
            view: view.as_ref(),
            prev: &prev,
        })
        .map_err(|error| error.to_string())?;
        let rest = body
            .strip_prefix('{')
            .ok_or_else(|| "a record must be a JSON object".to_owned())?;
        let check = hex(&Sha3_256::digest(body.as_bytes()));
        let line = format!("{CHECK_PREFIX}{check}\",{rest}\n");
        let record = Self {
            check,
            format: JOURNAL_FORMAT.to_owned(),
            version,
            seq,
            at,
            event,
            state,
            horizon,
            view,
            prev,
        };
        Ok((record, line))
    }
}

/// Check a line's checksum against the exact bytes after it.
fn verify_line(line: &str) -> Result<(), String> {
    let wrong = || "the checksum does not match: the record was changed or damaged".to_owned();
    let after = line.strip_prefix(CHECK_PREFIX).ok_or_else(wrong)?;
    let (check, rest) = after.split_at_checked(CHECK_LEN).ok_or_else(wrong)?;
    let rest = rest.strip_prefix("\",").ok_or_else(wrong)?;
    let body = format!("{{{rest}");
    if hex(&Sha3_256::digest(body.as_bytes())) == check {
        Ok(())
    } else {
        Err(wrong())
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// The marker a failed write leaves next to the journal at `path`.
pub fn broken_marker(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(ToOwned::to_owned).unwrap_or_default();
    name.push(".broken");
    path.with_file_name(name)
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum JournalError {
    #[error(
        "no risk journal at {0}: starting one is a decision for a person (PersistentRisk::initialise)"
    )]
    Missing(PathBuf),
    #[error("{0} already exists; a risk journal is never overwritten")]
    Exists(PathBuf),
    #[error("the risk journal {0} is open in another process")]
    Locked(PathBuf),
    #[error(
        "{0} exists: a write to the risk journal failed earlier, and what it held may be lost; a person has to compare the journal with the account's history, then remove the marker"
    )]
    MarkedBroken(PathBuf),
    #[error("{path}: {message}")]
    Io { path: PathBuf, message: String },
    #[error("{path}, line {line}: {message}")]
    Malformed {
        path: PathBuf,
        line: usize,
        message: String,
    },
    #[error(
        "{path}: the last {bytes} bytes are a record whose write was interrupted; a person has to repair the journal (PersistentRisk::repair_torn_tail)"
    )]
    TornTail { path: PathBuf, bytes: u64 },
    #[error(
        "{path}, line {line}: journal version {version}, newer than this build reads ({JOURNAL_VERSION})"
    )]
    UnsupportedVersion {
        path: PathBuf,
        line: usize,
        version: u64,
    },
    #[error("{path}, line {line}: {message}")]
    Inconsistent {
        path: PathBuf,
        line: usize,
        message: String,
    },
    #[error(
        "the journal was written under the limits {journal:?}, not the configured {configured:?}"
    )]
    LimitsDiffer {
        journal: Box<RiskLimits>,
        configured: Box<RiskLimits>,
    },
    #[error(
        "the journal was started for {journal:?}, not {configured:?} (network and account): a journal never moves to another network or account; start a new one"
    )]
    ScopeDiffers {
        journal: Option<JournalScope>,
        configured: Option<JournalScope>,
    },
    #[error("{0}")]
    Invalid(String),
    #[error(
        "writing the risk journal failed ({0}); no new positions until a person has looked at it"
    )]
    Broken(String),
    #[error("the risk engine has not observed the venue since the journal was opened: sync first")]
    NotObserved,
    #[error("known account flows are still pending a fresh, fully settled positive view")]
    PendingFlows,
}

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

/// The journal file, open, locked, and positioned for appending.
#[derive(Debug)]
struct RiskJournal {
    path: PathBuf,
    file: File,
    limits: RiskLimits,
    /// The last record in the file.
    last: JournalRecord,
    /// What the reader keeps to check `flowed` records.
    checks: Checks,
}

impl RiskJournal {
    /// Read through the writer's existing handle, keeping its cursor and lock.
    /// A pathname lookup could refer to a different file after a namespace change.
    fn records(&mut self) -> Result<Vec<JournalRecord>, JournalError> {
        let io = |error: io::Error| JournalError::Io {
            path: self.path.clone(),
            message: error.to_string(),
        };
        let position = self.file.stream_position().map_err(io)?;
        let read = (|| {
            self.file.seek(SeekFrom::Start(0)).map_err(io)?;
            let (bytes, complete) = read_all(&self.path, &mut self.file)?;
            if complete < bytes.len() {
                return Err(JournalError::TornTail {
                    path: self.path.clone(),
                    bytes: (bytes.len() - complete) as u64,
                });
            }
            let records = parse(&self.path, &bytes)?.1;
            if records.last() != Some(&self.last) {
                return Err(JournalError::Inconsistent {
                    path: self.path.clone(),
                    line: records.len(),
                    message: "the journal changed while its writer was open".into(),
                });
            }
            Ok(records)
        })();
        // Attempt restoration even if reading or parsing failed. Either failure
        // is returned to the caller, which latches the existing broken state.
        let restored = self.file.seek(SeekFrom::Start(position)).map_err(io);
        let records = read?;
        restored?;
        Ok(records)
    }

    /// Append one record, after checking that the reader would accept it.
    /// A `flowed` record is checked against `base`, the state, horizon and
    /// reach ([`reach`]) of the record it names, as the reader finds them.
    fn append(
        &mut self,
        at: Timestamp,
        event: JournalEvent,
        state: RiskSnapshot,
        fields: FlowFields,
        base: Option<(&RiskSnapshot, &Horizon, &Horizon)>,
    ) -> Result<(), JournalError> {
        let seq = self.last.seq + 1;
        let refuse = |message: String| JournalError::Inconsistent {
            path: self.path.clone(),
            line: usize::try_from(seq).unwrap_or(usize::MAX),
            message: format!("refusing to write: {message}"),
        };
        let (record, line) =
            JournalRecord::new(seq, at, event, state, self.last.check.clone(), fields)
                .map_err(refuse)?;
        RiskEngine::restore(self.limits.clone(), record.state.clone())
            .map_err(|error| refuse(error.to_string()))?;
        check_step(&self.last, &record).map_err(refuse)?;
        self.checks
            .listings
            .check_review(&record.event)
            .map_err(refuse)?;
        let mut placed = None;
        if let JournalEvent::Flowed {
            base: base_seq,
            views,
            flows: listed,
        } = &record.event
        {
            let (state, horizon, reached) =
                base.ok_or_else(|| refuse("a flowed record without its base".into()))?;
            self.checks
                .trail
                .check(*base_seq, record.seq, views)
                .map_err(refuse)?;
            self.checks
                .listings
                .check(*base_seq, reached, listed)
                .map_err(refuse)?;
            let replayed =
                check_flowed(&self.limits, state, horizon, &self.last, &record).map_err(refuse)?;
            placed = Some(replayed.placed);
        }
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_data())
            .map_err(|error| JournalError::Io {
                path: self.path.clone(),
                message: error.to_string(),
            })?;
        if let (Some(placed), JournalEvent::Flowed { flows: listed, .. }) = (placed, &record.event)
        {
            self.checks.listings.record(record.seq, listed, &placed);
        }
        self.checks.trail.record(&record);
        self.last = record;
        Ok(())
    }
}

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
fn must_write(written: &RiskSnapshot, now: &RiskSnapshot) -> bool {
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

/// Sync the directory holding `path`, so that a new name in it is durable.
/// Not every platform can; the data is synced either way.
fn sync_dir(path: &Path) {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    if let Ok(dir) = File::open(dir) {
        dir.sync_all().ok();
    }
}

/// Leave the marker for a failed write. Best effort: if even an empty file
/// cannot be created, the failure lives on in the running process only,
/// which refuses new positions.
fn mark_broken(path: &Path, reason: &str) {
    if let Ok(mut marker) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(broken_marker(path))
    {
        marker.write_all(reason.as_bytes()).ok();
        marker.sync_all().ok();
    }
    sync_dir(path);
}

/// Open `path` for reading and appending, and lock it.
fn open_locked(path: &Path) -> Result<File, JournalError> {
    open_locked_mode(path, false)
}

/// Only manual repair needs truncation rights; its handle never leaves repair.
fn open_locked_mode(path: &Path, repair: bool) -> Result<File, JournalError> {
    let mut options = OpenOptions::new();
    options.read(true).write(repair).append(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Atomically exclude other writers and delete/rename handles while
        // allowing read-only inspection. Windows byte locks also block the
        // locking process's separate inspection handles.
        options.share_mode(0x0000_0001); // FILE_SHARE_READ
        if repair {
            // Windows append mode omits FILE_WRITE_DATA, which set_len needs.
            // Repair explicitly seeks to EOF before appending its audit record.
            options.access_mode(0xc000_0000); // GENERIC_READ | GENERIC_WRITE
        }
    }
    let file = options.open(path).map_err(|error| {
        #[cfg(windows)]
        if error.raw_os_error() == Some(32) {
            // ERROR_SHARING_VIOLATION: another incompatible handle is open.
            return JournalError::Locked(path.to_owned());
        }
        match error.kind() {
            io::ErrorKind::NotFound => JournalError::Missing(path.to_owned()),
            _ => JournalError::Io {
                path: path.to_owned(),
                message: error.to_string(),
            },
        }
    })?;
    #[cfg(windows)]
    {
        Ok(file)
    }
    #[cfg(not(windows))]
    {
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(TryLockError::WouldBlock) => Err(JournalError::Locked(path.to_owned())),
            Err(TryLockError::Error(error)) => Err(JournalError::Io {
                path: path.to_owned(),
                message: format!("locking: {error}"),
            }),
        }
    }
}

/// Read every byte of `file`, and the length of its complete lines.
fn read_all(path: &Path, file: &mut File) -> Result<(Vec<u8>, usize), JournalError> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| JournalError::Io {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    let complete = complete_len(&bytes);
    Ok((bytes, complete))
}

/// Length of the complete lines at the start of `bytes`.
fn complete_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |newline| newline + 1)
}

/// Parse and check complete journal lines. See the module documentation
/// for what is checked.
#[allow(clippy::type_complexity)]
fn parse(path: &Path, bytes: &[u8]) -> Result<(Header, Vec<JournalRecord>, Checks), JournalError> {
    let malformed = |line: usize, message: String| JournalError::Malformed {
        path: path.to_owned(),
        line,
        message,
    };
    let inconsistent = |line: usize, message: String| JournalError::Inconsistent {
        path: path.to_owned(),
        line,
        message,
    };
    let text = std::str::from_utf8(bytes).map_err(|error| malformed(0, error.to_string()))?;
    let mut records: Vec<JournalRecord> = Vec::new();
    let mut limits: Option<RiskLimits> = None;
    let mut scope: Option<JournalScope> = None;
    let mut checks = Checks::default();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        // The format and version first: a newer version may not parse.
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|error| malformed(number, error.to_string()))?;
        if value.get("format").and_then(serde_json::Value::as_str) != Some(JOURNAL_FORMAT) {
            return Err(malformed(number, format!("not a {JOURNAL_FORMAT} record")));
        }
        let version = value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| malformed(number, "no version".into()))?;
        if version > u64::from(JOURNAL_VERSION) {
            return Err(JournalError::UnsupportedVersion {
                path: path.to_owned(),
                line: number,
                version,
            });
        }
        if version == 0 {
            return Err(malformed(number, "version 0 does not exist".into()));
        }
        verify_line(line).map_err(|message| inconsistent(number, message))?;
        let record: JournalRecord =
            serde_json::from_value(value).map_err(|error| malformed(number, error.to_string()))?;

        let expected = records.len() as u64 + 1;
        if record.seq != expected {
            return Err(inconsistent(
                number,
                format!(
                    "sequence number {} where {expected} was expected",
                    record.seq
                ),
            ));
        }
        let prev = records.last().map_or("", |last| last.check.as_str());
        if record.prev != prev {
            return Err(inconsistent(
                number,
                "the record does not follow the one before it".into(),
            ));
        }
        let limits = match (&record.event, &limits) {
            (
                JournalEvent::Initialised {
                    limits: first,
                    scope: first_scope,
                    ..
                },
                None,
            ) => {
                scope.clone_from(first_scope);
                limits.insert(first.clone()).clone()
            }
            (_, None) => {
                return Err(inconsistent(
                    number,
                    "the first record must be `initialised`".into(),
                ));
            }
            (JournalEvent::Initialised { .. }, Some(_)) => {
                return Err(inconsistent(
                    number,
                    "only the first record may be `initialised`".into(),
                ));
            }
            (JournalEvent::Scoped { scope: adopted, .. }, Some(limits)) => {
                if scope.is_some() {
                    return Err(inconsistent(
                        number,
                        "the journal's network and account are already recorded".into(),
                    ));
                }
                scope = Some(adopted.clone());
                limits.clone()
            }
            (_, Some(limits)) => limits.clone(),
        };
        RiskEngine::restore(limits.clone(), record.state.clone())
            .map_err(|error| inconsistent(number, error.to_string()))?;
        if let Some(previous) = records.last() {
            check_step(previous, &record).map_err(|message| inconsistent(number, message))?;
        }
        checks
            .listings
            .check_review(&record.event)
            .map_err(|message| inconsistent(number, message))?;
        if let JournalEvent::Flowed {
            base,
            views,
            flows: listed,
        } = &record.event
        {
            let previous = records
                .last()
                .ok_or_else(|| inconsistent(number, "a flowed record first".into()))?;
            let base_record = usize::try_from(*base)
                .ok()
                .and_then(|base| base.checked_sub(1))
                .and_then(|index| records.get(index))
                .filter(|base_record| base_record.seq < record.seq)
                .ok_or_else(|| {
                    inconsistent(
                        number,
                        format!("a flowed record from record {base}, which is not before it"),
                    )
                })?;
            let empty = Horizon::new();
            let horizon = base_record.horizon.as_ref().unwrap_or(&empty);
            checks
                .trail
                .check(*base, record.seq, views)
                .map_err(|message| inconsistent(number, message))?;
            checks
                .listings
                .check(*base, &reach(base_record), listed)
                .map_err(|message| inconsistent(number, message))?;
            let replayed = check_flowed(&limits, &base_record.state, horizon, previous, &record)
                .map_err(|message| inconsistent(number, message))?;
            checks.listings.record(record.seq, listed, &replayed.placed);
        }
        checks.trail.record(&record);
        records.push(record);
    }
    match limits {
        Some(limits) => Ok((Header { limits, scope }, records, checks)),
        None => Err(malformed(0, "the journal is empty".into())),
    }
}

/// What a journal's first record fixes.
#[derive(Debug)]
struct Header {
    limits: RiskLimits,
    scope: Option<JournalScope>,
}

impl Header {
    /// Refuse other limits, or another network or account.
    fn check(&self, limits: &RiskLimits, scope: Option<&JournalScope>) -> Result<(), JournalError> {
        if self.limits != *limits {
            return Err(JournalError::LimitsDiffer {
                journal: Box::new(self.limits.clone()),
                configured: Box::new(limits.clone()),
            });
        }
        if self.scope.as_ref() != scope {
            return Err(JournalError::ScopeDiffers {
                journal: self.scope.clone(),
                configured: scope.cloned(),
            });
        }
        Ok(())
    }
}

/// Whether the engine can get from `before` to `after` in one record. A
/// `flowed` record is checked further by [`check_flowed`].
fn check_step(before: &JournalRecord, after: &JournalRecord) -> Result<(), String> {
    let (old, new) = (&before.state, &after.state);
    if new.day < old.day {
        return Err(format!("the day went back from {} to {}", old.day, new.day));
    }
    // The fields of an engine that takes flows, only in version 3.
    let flowed = matches!(after.event, JournalEvent::Flowed { .. });
    if (after.version >= JOURNAL_VERSION) != after.horizon.is_some() {
        return Err("a horizon in a record of version 3, and only there".into());
    }
    if (flowed || after.view.is_some()) && after.horizon.is_none() {
        return Err("a flowed record or a view without a horizon".into());
    }
    if flowed && after.view.is_some() {
        return Err("a flowed record lists its views in the event".into());
    }
    if let Some(horizon) = &after.horizon {
        if let Some(previous) = &before.horizon
            && previous
                .iter()
                .any(|(dex, time)| horizon.get(dex).is_none_or(|now| now < time))
        {
            return Err("the horizon went back".into());
        }
        if let Some(view) = &after.view {
            if view.at != after.at {
                return Err("a view observed at another time than its record".into());
            }
            if let Some(previous) = &before.horizon
                && flows::goes_back(&view.times, previous)
            {
                return Err("a view that goes back in venue time".into());
            }
            if view
                .times
                .iter()
                .any(|(dex, time)| horizon.get(dex).is_none_or(|latest| latest < time))
            {
                return Err("a view beyond the horizon".into());
            }
        }
    }
    match &after.event {
        JournalEvent::Flowed { .. } => Ok(()),
        JournalEvent::Initialised { .. } => Err("a second `initialised` record".into()),
        JournalEvent::Repaired { .. } => {
            if new == old {
                Ok(())
            } else {
                Err("a repair changed the state".into())
            }
        }
        JournalEvent::Scoped { .. } => {
            if new == old {
                Ok(())
            } else {
                Err("recording the scope changed the state".into())
            }
        }
        JournalEvent::ResumedAfterReview { .. } => {
            // The record of positions may have caught up with the session
            // since the last record; the rest is the review itself.
            let resumed = matches!(old.state, RiskState::Stopped { .. })
                && new.state == RiskState::Active
                && new.peak == new.last
                && new.day_start == new.last
                && new.day == after.at.utc_day();
            if resumed {
                Ok(())
            } else {
                Err("a review record that is not a resumption from a drawdown stop".into())
            }
        }
        JournalEvent::Updated => {
            if new.peak < old.peak {
                return Err(format!("the peak fell from {} to {}", old.peak, new.peak));
            }
            match (old.state, new.state) {
                (RiskState::Stopped { .. }, _) if new.state != old.state => {
                    Err("a drawdown stop was cleared or changed without a review".into())
                }
                (
                    RiskState::HaltedForDay { day },
                    RiskState::Active | RiskState::HaltedForDay { .. },
                ) if new.day == day && new.state != old.state => {
                    Err(format!("the halt for day {day} was cleared on that day"))
                }
                _ => Ok(()),
            }
        }
    }
}

/// The views on the journal and where `flowed` records may start from: what
/// the reader needs to check that a `flowed` record's base can be replayed
/// from and that it lists every view the journal holds since that base. The
/// writer keeps the same, from the same records, back to its oldest base.
#[derive(Debug, Clone, Default)]
struct Trail {
    /// The views on the journal, in order, from the `first`-th on.
    views: Vec<SeenView>,
    first: usize,
    /// For each record kept: how many views the journal held after it.
    after: BTreeMap<u64, usize>,
    /// The newest record nothing before which can be replayed: the first,
    /// a review, or one written without flows.
    reset: u64,
    /// For each `flowed` record kept: its base.
    flowed: BTreeMap<u64, u64>,
}

impl Trail {
    /// Whether a `flowed` record `seq` may start from record `base` and
    /// list `views`.
    fn check(&self, base: u64, seq: u64, views: &[SeenView]) -> Result<(), String> {
        if base < self.reset {
            return Err(format!(
                "a flowed record from record {base}, before record {} (a review, or written without flows)",
                self.reset
            ));
        }
        if let Some((later, from)) = self
            .flowed
            .range(base.saturating_add(1)..seq)
            .find(|(_, from)| **from < base)
        {
            return Err(format!(
                "a flowed record from record {base}, which record {later} replaced (from record {from})"
            ));
        }
        let start = self
            .after
            .get(&base)
            .and_then(|count| count.checked_sub(self.first))
            .ok_or_else(|| format!("a flowed record from record {base}, which is not kept"))?;
        let mut listed = views.iter();
        for journaled in self.views.iter().skip(start) {
            if !listed.any(|view| view == journaled) {
                return Err(format!(
                    "a flowed record from record {base} leaves out a view on the journal since"
                ));
            }
        }
        Ok(())
    }

    /// Note a record checked and kept.
    fn record(&mut self, record: &JournalRecord) {
        match &record.event {
            JournalEvent::Flowed { base, views, .. } => {
                if let Some(count) = self.after.get(base) {
                    self.views.truncate(count.saturating_sub(self.first));
                }
                self.views.extend(views.iter().cloned());
                self.flowed.insert(record.seq, *base);
            }
            _ => {
                if let Some(view) = &record.view {
                    self.views.push(view.clone());
                }
            }
        }
        let count = self.first + self.views.len();
        if record.horizon.is_none()
            || matches!(record.event, JournalEvent::ResumedAfterReview { .. })
        {
            // Nothing before it is replayed again: forget it.
            self.reset = record.seq;
            self.first = count;
            self.views.clear();
            self.after.clear();
            self.flowed.clear();
        }
        self.after.insert(record.seq, count);
    }

    /// Forget what lies before record `oldest`: no record before it is a
    /// base any more (the writer's).
    fn prune(&mut self, oldest: u64) {
        let Some(count) = self.after.get(&oldest).copied() else {
            return;
        };
        let drop = count.saturating_sub(self.first).min(self.views.len());
        self.views.drain(..drop);
        self.first += drop;
        self.after = self.after.split_off(&oldest);
        self.flowed = self.flowed.split_off(&oldest);
    }
}

/// Which `flowed` records listed each flow, and whether each applied it:
/// what the reader needs to check that a record's base and its list of
/// flows agree with the records before it (`docs/guard.md#deposits-and-withdrawals`).
/// The writer keeps the same, from the same records.
#[derive(Debug, Clone, Default)]
struct Listings {
    /// For each flow id: the flow as first listed, and each listing's
    /// record and whether it applied the flow, in order.
    flows: BTreeMap<String, (Flow, Vec<(u64, bool)>)>,
}

impl Listings {
    /// Latest durable placement, independent of whether the caller enables
    /// reconstruction in memory. A review must not discard this money origin.
    fn pending(&self) -> bool {
        self.flows
            .values()
            .any(|(_, listings)| listings.last().is_some_and(|(_, applied)| !applied))
    }

    fn check_review(&self, event: &JournalEvent) -> Result<(), String> {
        if matches!(event, JournalEvent::ResumedAfterReview { .. }) && self.pending() {
            return Err("a review cannot discard pending account flows".into());
        }
        Ok(())
    }

    /// Whether a `flowed` record `seq` from record `base` (with that
    /// horizon) may list `listed`: no flow it lists first is one the base's
    /// views reached, none is listed again after the latest listing at or
    /// before the base applied it, none known and not applied at the base,
    /// or listed since, is left out, and none changed.
    fn check(&self, base: u64, base_horizon: &Horizon, listed: &[Flow]) -> Result<(), String> {
        let mut ids = BTreeSet::new();
        for flow in listed {
            if !ids.insert(flow.id.as_str()) {
                return Err(format!("the flow {} listed twice", flow.id));
            }
            let latest = match self.flows.get(&flow.id) {
                Some((first, listings)) => {
                    if first != flow {
                        return Err(format!("the flow {} changed since it was listed", flow.id));
                    }
                    listings.iter().rev().find(|(seq, _)| *seq <= base)
                }
                None => None,
            };
            match latest {
                Some((_, true)) => {
                    return Err(format!(
                        "the flow {} listed again, although applied at or before record {base}",
                        flow.id
                    ));
                }
                Some((_, false)) => {}
                None => {
                    if !flows::before_horizon(flow, base_horizon) {
                        return Err(format!(
                            "record {base} had seen past the flow {} it did not know",
                            flow.id
                        ));
                    }
                }
            }
        }
        for (id, (_, listings)) in &self.flows {
            if ids.contains(id.as_str()) {
                continue;
            }
            let pending_at_base = listings
                .iter()
                .rev()
                .find(|(seq, _)| *seq <= base)
                .is_some_and(|(_, applied)| !applied);
            if pending_at_base || listings.iter().any(|(seq, _)| *seq > base) {
                return Err(format!("the flow {id}, not in record {base}, is left out"));
            }
        }
        Ok(())
    }

    /// Note record `seq` listing `listed`, applied where `placed` says.
    fn record(&mut self, seq: u64, listed: &[Flow], placed: &[Option<usize>]) {
        for (flow, place) in listed.iter().zip(placed) {
            self.flows
                .entry(flow.id.clone())
                .or_insert_with(|| (flow.clone(), Vec::new()))
                .1
                .push((seq, place.is_some()));
        }
    }
}

/// What the reader keeps across records to check `flowed` records, and the
/// writer with it.
#[derive(Debug, Clone, Default)]
struct Checks {
    trail: Trail,
    listings: Listings,
}

/// How far the views a record knew of reached, for whether a flow learned
/// later contradicts it: its horizon; for the first record, a review, or a
/// record written without flows, also the time it was written at (the
/// equity it holds was read then, every flow before it in it).
fn reach(record: &JournalRecord) -> Horizon {
    let mut reach = record.horizon.clone().unwrap_or_default();
    if record.horizon.is_none()
        || matches!(
            record.event,
            JournalEvent::Initialised { .. } | JournalEvent::ResumedAfterReview { .. }
        )
    {
        let at = record.at.as_millis();
        let main = reach.entry(String::new()).or_insert(at);
        *main = (*main).max(at);
    }
    reach
}

/// Whether a `flowed` record holds exactly what its inputs give: the replay
/// from its base's state and horizon through its views with its flows
/// ([`flows::replay`]), settled against the record before it
/// ([`flows::settle`]), with the later of the two horizons. The writer runs
/// this before it appends, the reader when it loads: they compute the same.
/// The replay, for where it applied each flow.
fn check_flowed(
    limits: &RiskLimits,
    base: &RiskSnapshot,
    base_horizon: &Horizon,
    before: &JournalRecord,
    after: &JournalRecord,
) -> Result<flows::Replayed, String> {
    let JournalEvent::Flowed {
        base: seq,
        views,
        flows: flow_list,
    } = &after.event
    else {
        return Err("not a flowed record".into());
    };
    if *seq >= after.seq {
        return Err(format!(
            "a flowed record from record {seq}, which is not before it"
        ));
    }
    if views.windows(2).any(|pair| pair[1].at < pair[0].at) {
        return Err("views out of order".into());
    }
    let mut latest = base_horizon.clone();
    for view in views {
        if flows::goes_back(&view.times, &latest) {
            return Err("a view that goes back in venue time".into());
        }
        for (dex, time) in &view.times {
            let entry = latest.entry(dex.clone()).or_insert(*time);
            *entry = (*entry).max(*time);
        }
    }
    let replayed = flows::replay(limits, base, base_horizon, views, flow_list)?;
    let settled = flows::settle(limits, &before.state, &replayed.snapshot)?;
    if settled != after.state {
        return Err(format!(
            "the flows give {settled:?}, the record holds {:?}",
            after.state
        ));
    }
    let mut horizon = replayed.horizon.clone();
    for (dex, time) in before.horizon.iter().flatten() {
        let latest = horizon.entry(dex.clone()).or_insert(*time);
        *latest = (*latest).max(*time);
    }
    if after.horizon.as_ref() != Some(&horizon) {
        return Err("the horizon is not the one the flows give".into());
    }
    Ok(replayed)
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

/// A risk engine whose state survives restarts, kept in a journal on disk.
/// See the module documentation.
#[derive(Debug)]
pub struct PersistentRisk {
    engine: RiskEngine,
    journal: RiskJournal,
    /// Whether [`PersistentRisk::sync`] has observed the venue since the
    /// journal was opened.
    observed: bool,
    /// Why the journal can no longer be written, after a failed write.
    broken: Option<String>,
    /// Deposits and withdrawals are kept out of the account stops
    /// ([`PersistentRisk::with_flows`]); `None`: they count as gains and
    /// losses, as the engine sees any change of equity.
    flows: Option<FlowBook>,
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
        if fs::symlink_metadata(path).is_ok() {
            return Err(JournalError::Exists(path.to_owned()));
        }
        let marker = broken_marker(path);
        if fs::symlink_metadata(&marker).is_ok() {
            return Err(JournalError::MarkedBroken(marker));
        }
        let io = |message: String| JournalError::Io {
            path: path.to_owned(),
            message,
        };
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
        .map_err(io)?;

        let mut name = path.file_name().map(ToOwned::to_owned).unwrap_or_default();
        name.push(format!(".init-{}", std::process::id()));
        let temporary = path.with_file_name(name);
        let written = File::create_new(&temporary).and_then(|mut file| {
            file.write_all(line.as_bytes())?;
            file.sync_all()
        });
        // Linking fails if the journal appeared meanwhile: never overwrite.
        let linked = written.and_then(|()| fs::hard_link(&temporary, path));
        fs::remove_file(&temporary).ok();
        match linked {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(JournalError::Exists(path.to_owned()));
            }
            Err(error) => return Err(io(error.to_string())),
        }
        sync_dir(path);
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
        let marker = broken_marker(path);
        if fs::symlink_metadata(&marker).is_ok() {
            return Err(JournalError::MarkedBroken(marker));
        }
        let mut file = open_locked(path)?;
        let (bytes, complete) = read_all(path, &mut file)?;
        if complete < bytes.len() {
            return Err(JournalError::TornTail {
                path: path.to_owned(),
                bytes: (bytes.len() - complete) as u64,
            });
        }
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
        let bytes = fs::read(path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => JournalError::Missing(path.to_owned()),
            _ => JournalError::Io {
                path: path.to_owned(),
                message: error.to_string(),
            },
        })?;
        let complete = complete_len(&bytes);
        if complete < bytes.len() {
            return Err(JournalError::TornTail {
                path: path.to_owned(),
                bytes: (bytes.len() - complete) as u64,
            });
        }
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
        let mut file = open_locked_mode(path, true)?;
        let (bytes, complete) = read_all(path, &mut file)?;
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
        let io = |error: io::Error| JournalError::Io {
            path: path.to_owned(),
            message: error.to_string(),
        };
        file.set_len(complete as u64).map_err(io)?;
        file.sync_all().map_err(io)?;
        file.seek(SeekFrom::End(0)).map_err(io)?;
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

    fn check_intact(&self) -> Result<(), JournalError> {
        match &self.broken {
            Some(why) => Err(JournalError::Broken(why.clone())),
            None => Ok(()),
        }
    }

    /// Write the engine's state if it changed in a way that matters. After
    /// a failed write nothing is written again: a write cut short may have
    /// left a torn record, and appending behind it would bury it. The
    /// failure is also marked on disk, for the next process.
    fn commit(&mut self, at: Timestamp, event: JournalEvent) -> Result<(), JournalError> {
        self.commit_view(at, event, None)
    }

    /// [`PersistentRisk::commit`] for an engine that may take flows: its
    /// records carry the horizon, and `view` when written for one, and a
    /// fall of the last equity is written too ([`must_write_flows`]).
    fn commit_view(
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
                mark_broken(&self.journal.path, &reason);
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
const FLOW_VIEWS_MAX: usize = if cfg!(test) { 300 } else { 200_000 };

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
struct Known {
    flow: Flow,
    /// The number of the view it was applied at.
    place: Option<u64>,
}

/// A view an engine that takes flows remembers.
#[derive(Debug, Clone)]
struct Remembered {
    number: u64,
    view: SeenView,
    /// On the journal (in a record of its own or a `flowed` record's list).
    written: bool,
}

/// A record a replay may start from: no flow learned since it was written
/// falls at or before its horizon.
#[derive(Debug, Clone)]
struct Base {
    seq: u64,
    at: Timestamp,
    state: RiskSnapshot,
    /// Its horizon as recorded (what a replay from it starts with, as the
    /// reader's does).
    horizon: Horizon,
    /// How far its views reached, for whether a flow contradicts it: its
    /// horizon, or for a record written without one the time it was
    /// written at.
    reach: Horizon,
    /// The number of the first view after it.
    next_view: u64,
}

/// What an engine that takes flows keeps besides the engine
/// (`docs/guard.md#deposits-and-withdrawals`).
#[derive(Debug, Default)]
struct FlowBook {
    /// For each dex, the latest venue time of any view so far.
    horizon: Horizon,
    /// The flows a replay may need: those not applied yet, and those
    /// applied after the oldest base.
    known: Vec<Known>,
    /// The id of every flow known, against applying one twice.
    ids: BTreeSet<String>,
    /// The views a replay may need, in order.
    views: VecDeque<Remembered>,
    /// The number the next view gets.
    next_view: u64,
    /// The records a replay may start from, oldest first.
    bases: VecDeque<Base>,
    /// What became of flows since the caller last asked.
    outcomes: Vec<(Flow, FlowOutcome)>,
    /// Stops waived (S5 (b)) since the caller last asked, and the views
    /// they were waived at lately (a replay meets them again).
    waived: Vec<WaivedStop>,
    waived_at: VecDeque<Timestamp>,
}

impl FlowBook {
    fn pending(&self) -> bool {
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
    fn add_base(&mut self, record: &JournalRecord) {
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
    fn reset(&mut self) {
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
    fn fold_view(&mut self, now: Timestamp, seen: &SeenView) -> Result<(bool, bool), JournalError> {
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rust_decimal::dec;
    use zunder_core::{Side, Symbol};
    use zunder_risk::TrackedPosition;

    use super::*;

    const HOUR: i64 = Timestamp::MS_PER_HOUR;
    const DAY: i64 = Timestamp::MS_PER_DAY;

    fn at(ms: i64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    /// A scratch directory, removed when dropped.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "zunder-risk-store-{name}-{}-{unique}",
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

    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).ok();
        }
    }

    fn limits() -> RiskLimits {
        RiskLimits::default()
    }

    /// A journal started at 2,000 whose engine then observed `equities`,
    /// one an hour, each written as the store writes it.
    fn journal_with(dir: &TestDir, equities: &[Decimal]) -> PersistentRisk {
        let mut risk =
            PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test")
                .unwrap();
        for (hour, equity) in (1..).zip(equities) {
            risk.engine.observe(at(hour * HOUR), *equity);
            risk.commit(at(hour * HOUR), JournalEvent::Updated).unwrap();
        }
        risk
    }

    fn lines(dir: &TestDir) -> Vec<String> {
        fs::read_to_string(dir.journal())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn write_lines(dir: &TestDir, lines: &[String]) {
        let mut text = lines.join("\n");
        text.push('\n');
        fs::write(dir.journal(), text).unwrap();
    }

    /// Write a journal of chained records with the given events and states,
    /// checksums and all, bypassing the store's own checks.
    fn forge(dir: &TestDir, steps: &[(i64, JournalEvent, RiskSnapshot)]) {
        let mut prev = String::new();
        let mut text = String::new();
        for (seq, (ms, event, state)) in (1..).zip(steps) {
            let (record, line) = JournalRecord::new(
                seq,
                at(*ms),
                event.clone(),
                state.clone(),
                prev,
                FlowFields::default(),
            )
            .unwrap();
            prev = record.check;
            text.push_str(&line);
        }
        fs::write(dir.journal(), text).unwrap();
    }

    fn initialised() -> JournalEvent {
        JournalEvent::Initialised {
            limits: limits(),
            scope: None,
            note: String::new(),
        }
    }

    fn fresh() -> RiskSnapshot {
        RiskEngine::new(limits(), at(0), dec!(2000))
            .unwrap()
            .snapshot()
    }

    fn inconsistent(result: Result<PersistentRisk, JournalError>) -> String {
        match result {
            Err(JournalError::Inconsistent { message, .. }) => message,
            other => panic!("expected an inconsistent journal, got {other:?}"),
        }
    }

    #[test]
    fn pending_origin_survives_retention_restart_and_blocks_entries() {
        // An unknown full2,000 withdrawal waits through day2 and restart.
        // Refill1,000 on day3 applies the cash once; neither old monetary
        // figures nor midnight may reopen entries while it is pending.
        let dir = TestDir::new("pending-origin");
        let mut risk =
            PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test")
                .unwrap()
                .with_flows();
        let withdrawal = Flow {
            time_ms: HOUR,
            amount: dec!(-2000),
            id: "withdraw".into(),
            dex: String::new(),
            between: false,
            value: None,
        };
        risk.apply_flow(at(HOUR), &withdrawal).unwrap();
        let empty = VenueView::default();
        for ms in [2 * HOUR, DAY + 2 * HOUR, 2 * DAY] {
            let out =
                risk.observe_view_at(at(ms), [(String::new(), ms)].into(), dec!(0), &empty, true);
            assert!(out.journal_error.is_none(), "{out:?}");
            assert_eq!(risk.check_ready(), Err(JournalError::PendingFlows));
        }
        assert_eq!(risk.flows.as_ref().unwrap().bases.back().unwrap().seq, 1);
        drop(risk);
        let mut risk = PersistentRisk::open(&dir.journal(), &limits())
            .unwrap()
            .with_flows();
        let out = risk.observe_view_at(
            at(2 * DAY + HOUR),
            [(String::new(), 2 * DAY + HOUR)].into(),
            dec!(0),
            &empty,
            true,
        );
        assert!(out.journal_error.is_none(), "{out:?}");
        assert_eq!(risk.check_ready(), Err(JournalError::PendingFlows));
        let refill = Flow {
            time_ms: 2 * DAY + 2 * HOUR,
            amount: dec!(1000),
            id: "refill".into(),
            dex: String::new(),
            between: false,
            value: Some(flows::ValueRange::cash_exact(dec!(0))),
        };
        risk.apply_flow(at(2 * DAY + 2 * HOUR), &refill).unwrap();
        let ms = 2 * DAY + 3 * HOUR;
        let out = risk.observe_view_at(
            at(ms),
            [(String::new(), ms)].into(),
            dec!(1000),
            &empty,
            true,
        );
        assert!(out.journal_error.is_none(), "{out:?}");
        assert!(risk.check_ready().is_ok());
        assert_eq!(risk.engine.snapshot().peak, dec!(1000));
        drop(risk);
        PersistentRisk::read(&dir.journal()).unwrap();
    }

    #[test]
    fn a_review_refuses_pending_money_without_mutation() {
        for stopped in [false, true] {
            let dir = TestDir::new("review-pending");
            let mut risk =
                PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(10000), "test")
                    .unwrap()
                    .with_flows();
            let mut flows = Vec::new();
            if stopped {
                // The exact7,000 checkpoint proves30% before500 is added.
                flows.push(Flow {
                    time_ms: HOUR,
                    amount: dec!(500),
                    id: "prefix".into(),
                    dex: String::new(),
                    between: false,
                    value: Some(flows::ValueRange::cash_exact(dec!(7000))),
                });
            }
            flows.push(Flow {
                time_ms: 2 * HOUR,
                amount: if stopped { dec!(-7500) } else { dec!(-10000) },
                id: "empty".into(),
                dex: String::new(),
                between: false,
                value: None,
            });
            for flow in flows {
                risk.apply_flow(at(2 * HOUR), &flow).unwrap();
            }
            let out = risk.observe_view_at(
                at(3 * HOUR),
                [(String::new(), 3 * HOUR)].into(),
                dec!(0),
                &VenueView::default(),
                true,
            );
            assert!(out.journal_error.is_none());
            assert_eq!(matches!(risk.state(), RiskState::Stopped { .. }), stopped);
            let snapshot = risk.engine.snapshot();
            let bytes = fs::read(dir.journal()).unwrap();
            assert_eq!(
                risk.resume_after_review(at(4 * HOUR), dec!(10000), "review"),
                Err(JournalError::PendingFlows)
            );
            assert_eq!(risk.engine.snapshot(), snapshot);
            assert_eq!(fs::read(dir.journal()).unwrap(), bytes);
            drop(risk);
            // CLI and other callers may open without enabling reconstruction.
            // The durable listings must still prohibit destroying the origin.
            let mut without_flows = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
            assert!(without_flows.flows.is_none());
            assert_eq!(
                without_flows.check_review_ready(),
                Err(JournalError::PendingFlows)
            );
            assert_eq!(
                without_flows.resume_after_review(at(4 * HOUR), dec!(10000), "review"),
                Err(JournalError::PendingFlows)
            );
            assert_eq!(without_flows.engine.snapshot(), snapshot);
            assert_eq!(fs::read(dir.journal()).unwrap(), bytes);
            let forged = if stopped {
                let mut cleared = without_flows.engine.clone();
                cleared.resume_after_review(at(4 * HOUR), dec!(10000));
                let event = JournalEvent::ResumedAfterReview {
                    note: "bypass".into(),
                };
                assert!(
                    without_flows
                        .journal
                        .append(
                            at(4 * HOUR),
                            event.clone(),
                            cleared.snapshot(),
                            FlowFields::default(),
                            None,
                        )
                        .is_err()
                );
                assert_eq!(fs::read(dir.journal()).unwrap(), bytes);
                // A checksummed forged record is refused by the reader too.
                let (_, line) = JournalRecord::new(
                    without_flows.journal.last.seq + 1,
                    at(4 * HOUR),
                    event,
                    cleared.snapshot(),
                    without_flows.journal.last.check.clone(),
                    FlowFields::default(),
                )
                .unwrap();
                let mut forged = bytes.clone();
                forged.extend_from_slice(line.as_bytes());
                Some(forged)
            } else {
                None
            };
            drop(without_flows);
            // Offline corruption: close the writer after every live refusal
            // assertion, then prove the reader rejects a forged resume.
            if let Some(forged) = forged {
                fs::write(dir.journal(), forged).unwrap();
                assert!(PersistentRisk::read(&dir.journal()).is_err());
                fs::write(dir.journal(), &bytes).unwrap();
            }
            let mut restored = PersistentRisk::open(&dir.journal(), &limits())
                .unwrap()
                .with_flows();
            assert_eq!(restored.engine.snapshot(), snapshot);
            assert!(restored.flows.as_ref().unwrap().pending());
            let out = restored.observe_view_at(
                at(5 * HOUR),
                [(String::new(), 5 * HOUR)].into(),
                dec!(0),
                &VenueView::default(),
                true,
            );
            assert!(out.journal_error.is_none());
            assert_eq!(restored.check_ready(), Err(JournalError::PendingFlows));
        }
    }

    #[test]
    fn exact_arithmetic_underflow_stays_pending_after_restart() {
        let dir = TestDir::new("exact-underflow");
        let mut risk =
            PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(0.000001), "test")
                .unwrap()
                .with_flows();
        risk.observe_view_at(
            at(HOUR),
            [(String::new(), HOUR)].into(),
            dec!(100000000000000000000),
            &VenueView::default(),
            true,
        );
        let flow = Flow {
            time_ms: 2 * HOUR,
            amount: dec!(-99999999999999999999.999999),
            id: "underflow".into(),
            dex: String::new(),
            between: false,
            value: Some(flows::ValueRange::cash_exact(dec!(100000000000000000000))),
        };
        risk.apply_flow(at(2 * HOUR), &flow).unwrap();
        let out = risk.observe_view_at(
            at(3 * HOUR),
            [(String::new(), 3 * HOUR)].into(),
            dec!(0.000001),
            &VenueView::default(),
            true,
        );
        assert!(out.journal_error.is_none());
        assert_eq!(risk.check_ready(), Err(JournalError::PendingFlows));
        assert!(!matches!(risk.engine.state(), RiskState::Stopped { .. }));
        drop(risk);
        let mut risk = PersistentRisk::open(&dir.journal(), &limits())
            .unwrap()
            .with_flows();
        let ms = DAY + HOUR;
        let out = risk.observe_view_at(
            at(ms),
            [(String::new(), ms)].into(),
            dec!(0.000001),
            &VenueView::default(),
            true,
        );
        assert!(out.journal_error.is_none());
        assert_eq!(risk.check_ready(), Err(JournalError::PendingFlows));
        assert_eq!(risk.engine.state(), RiskState::HaltedForDay { day: 1 });
    }

    #[test]
    fn pending_history_bound_refuses_entries_without_a_loss_stop() {
        let dir = TestDir::new("pending-bound");
        let mut risk =
            PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test")
                .unwrap()
                .with_flows();
        let withdrawal = Flow {
            time_ms: HOUR,
            amount: dec!(-2000),
            id: "withdraw".into(),
            dex: String::new(),
            between: false,
            value: None,
        };
        risk.apply_flow(at(HOUR), &withdrawal).unwrap();
        let seen = SeenView {
            at: at(2 * HOUR),
            times: [(String::new(), 2 * HOUR)].into(),
            equity: dec!(0),
        };
        let book = risk.flows.as_mut().unwrap();
        for number in 0..FLOW_VIEWS_MAX {
            book.views.push_back(Remembered {
                number: number as u64,
                view: seen.clone(),
                written: false,
            });
        }
        assert!(matches!(
            risk.fold_view(at(2 * HOUR), &seen),
            Err(JournalError::Broken(_))
        ));
        assert!(!matches!(risk.engine.state(), RiskState::Stopped { .. }));
        assert!(matches!(risk.check_ready(), Err(JournalError::Broken(_))));
        assert_eq!(risk.flows.as_ref().unwrap().views.len(), FLOW_VIEWS_MAX);
        drop(risk);
        assert!(matches!(
            PersistentRisk::open(&dir.journal(), &limits()),
            Err(JournalError::MarkedBroken(_))
        ));
    }

    #[test]
    fn too_many_views_forget_the_oldest_bases_first_and_never_break_the_journal() {
        // The cap is 300 views in these tests. From 1:00, a view a second,
        // every fifth a new high (on the journal, a base each; bases kept
        // one per 10 s), the rest unchanged: 400 views. The oldest bases go
        // with the views only they need; the journal stays whole. A deposit
        // just after the 350th view is replayed from a base kept; one from
        // the 10th, older than every base kept, is skipped.
        let dir = TestDir::new("views-cap");
        let mut risk =
            PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(10000), "test")
                .unwrap()
                .with_flows();
        let mut equity = dec!(10000);
        for n in 0..400i64 {
            let ms = HOUR + n * 1_000;
            if n % 5 == 0 {
                equity += dec!(1);
            }
            let seen = risk.observe_view_at(
                at(ms),
                [(String::new(), ms)].into(),
                equity,
                &VenueView::default(),
                true,
            );
            assert_eq!(seen.journal_error, None);
            assert!(risk.flows.as_ref().unwrap().views.len() <= FLOW_VIEWS_MAX);
        }
        let late = Flow {
            time_ms: HOUR + 350 * 1_000 + 500,
            amount: dec!(100),
            id: "late".into(),
            dex: String::new(),
            between: false,
            value: None,
        };
        assert_eq!(
            risk.apply_flow(at(HOUR + 400_000), &late).unwrap(),
            FlowOutcome::Applied
        );
        let old = Flow {
            time_ms: HOUR + 10 * 1_000 + 500,
            id: "old".into(),
            ..late
        };
        assert!(matches!(
            risk.apply_flow(at(HOUR + 400_000), &old).unwrap(),
            FlowOutcome::Skipped(_)
        ));
        risk.check_ready().unwrap();
        drop(risk);
        PersistentRisk::open(&dir.journal(), &limits()).unwrap();
    }

    #[test]
    fn the_trail_forgets_what_lies_before_the_oldest_base_and_checks_what_follows() {
        // Records: the start, then three falls (each 1%, written with its
        // view). Forgetting what lies before record 3 keeps the last view
        // only; a flowed record from record 3 must list it.
        let dir = TestDir::new("trail-prune");
        let mut risk =
            PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(10000), "test")
                .unwrap()
                .with_flows();
        for (hour, equity) in [(1, dec!(9900)), (2, dec!(9800)), (3, dec!(9700))] {
            let ms = hour * HOUR;
            risk.observe_view_at(
                at(ms),
                [(String::new(), ms)].into(),
                equity,
                &VenueView::default(),
                true,
            );
        }
        drop(risk);
        let records = PersistentRisk::read(&dir.journal()).unwrap();
        assert_eq!(records.len(), 4);
        let mut trail = Trail::default();
        for record in &records {
            trail.record(record);
        }
        trail.prune(3);
        assert_eq!(trail.views.len(), 1);
        let last = records[3].view.clone().unwrap();
        assert!(trail.check(3, 5, &[]).is_err());
        assert!(trail.check(3, 5, &[last]).is_ok());
    }

    #[test]
    fn a_view_observed_without_a_session_reaches_the_journal() {
        // Zunder Guard's path: start at 2,000, see 1,870 an hour later the
        // same day: a loss of 130 / 2,000 = 6.5%, beyond the 6% daily stop.
        let dir = TestDir::new("observe-view");
        let mut risk =
            PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test")
                .unwrap();
        assert!(matches!(risk.check_ready(), Err(JournalError::NotObserved)));
        let seen = risk.observe_view(at(HOUR), dec!(1870), &VenueView::default(), true);
        assert_eq!(seen.state, RiskState::HaltedForDay { day: 0 });
        assert_eq!(seen.journal_error, None);
        assert!(risk.check_ready().is_ok());
        drop(risk);
        // The halt is on disk.
        let reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
        assert_eq!(reopened.state(), RiskState::HaltedForDay { day: 0 });
    }

    #[test]
    fn an_entry_recorded_without_a_session_counts_until_the_venue_settles() {
        // 1 ETH bought at 2,000 with its stop at 1,960: 40 at risk, 2,000 in
        // value, recorded and journaled.
        let dir = TestDir::new("record-entry");
        let mut risk =
            PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test")
                .unwrap();
        risk.observe_view(at(1), dec!(2000), &VenueView::default(), true);
        risk.record_entry(
            at(2),
            Symbol::new("ETH"),
            Side::Buy,
            dec!(1),
            dec!(2000),
            dec!(1960),
        )
        .unwrap();
        let exposure = risk.engine().book_exposure().unwrap();
        assert_eq!((exposure.risk, exposure.notional), (dec!(40), dec!(2000)));
        drop(risk);
        let mut reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
        assert_eq!(reopened.engine().positions().len(), 1);
        // A view that is not settled keeps it; a settled empty one drops it.
        reopened.observe_view(at(3), dec!(2000), &VenueView::default(), false);
        assert_eq!(reopened.engine().positions().len(), 1);
        reopened.observe_view(at(4), dec!(2000), &VenueView::default(), true);
        assert!(reopened.engine().positions().is_empty());
        // Nonsense is refused, and nothing is written for it.
        assert!(
            reopened
                .record_entry(
                    at(5),
                    Symbol::new("ETH"),
                    Side::Buy,
                    dec!(0),
                    dec!(2000),
                    dec!(1960)
                )
                .is_err()
        );
    }

    #[test]
    fn a_journal_restores_the_engine_it_was_written_from() {
        let dir = TestDir::new("restore");
        let risk = journal_with(&dir, &[dec!(2100), dec!(2050), dec!(1960)]);
        assert_eq!(risk.engine().snapshot().last, dec!(1960));
        drop(risk);
        let reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
        // Peak 2,100. The last equity on disk is 2,100 too: a falling
        // equity alone (2,050, then 1,960) is not written.
        assert_eq!(reopened.engine().peak(), dec!(2100));
        assert_eq!(reopened.engine().snapshot().last, dec!(2100));
        assert_eq!(lines(&dir).len(), 2);
        assert_eq!(reopened.check_ready(), Err(JournalError::NotObserved));
    }

    #[test]
    fn what_is_written_and_what_is_not() {
        let base = fresh();
        assert!(!must_write(&base, &base));
        let lower = RiskSnapshot {
            last: dec!(1990),
            ..base.clone()
        };
        // A lower last equity alone: not written. A higher one: written.
        assert!(!must_write(&base, &lower));
        assert!(must_write(
            &lower,
            &RiskSnapshot {
                last: dec!(1995),
                ..base.clone()
            }
        ));
        // A new peak, a new day, a halt, a position: written.
        assert!(must_write(
            &base,
            &RiskSnapshot {
                peak: dec!(2001),
                last: dec!(2001),
                ..base.clone()
            }
        ));
        assert!(must_write(
            &base,
            &RiskSnapshot {
                day: base.day + 1,
                ..base.clone()
            }
        ));
        assert!(must_write(
            &base,
            &RiskSnapshot {
                state: RiskState::HaltedForDay { day: base.day },
                ..base.clone()
            }
        ));
        let position = TrackedPosition {
            symbol: Symbol::new("BTC"),
            side: Side::Buy,
            qty: dec!(1),
            entry: dec!(100),
            stop: Some(dec!(98)),
            mark: dec!(100),
        };
        let holding = RiskSnapshot {
            positions: vec![position.clone()],
            ..base.clone()
        };
        assert!(must_write(&base, &holding));
        // A new price for it alone: not written. A tighter stop: written.
        let repriced = RiskSnapshot {
            positions: vec![TrackedPosition {
                mark: dec!(101),
                ..position.clone()
            }],
            ..base.clone()
        };
        assert!(!must_write(&holding, &repriced));
        let tightened = RiskSnapshot {
            positions: vec![TrackedPosition {
                stop: Some(dec!(99)),
                ..position
            }],
            ..base
        };
        assert!(must_write(&holding, &tightened));
    }

    #[test]
    fn a_halt_and_a_stop_survive_a_restart() {
        let dir = TestDir::new("halt");
        // 2,000 -> 1,880 in the first hour: 6%, halted for day 0.
        let risk = journal_with(&dir, &[dec!(1880)]);
        assert_eq!(risk.state(), RiskState::HaltedForDay { day: 0 });
        drop(risk);
        let mut reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
        assert_eq!(reopened.state(), RiskState::HaltedForDay { day: 0 });

        // 1,880 -> 1,500 a day later: 25% below the peak of 2,000.
        reopened.engine.observe(at(DAY), dec!(1500));
        reopened.commit(at(DAY), JournalEvent::Updated).unwrap();
        drop(reopened);
        let mut reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
        assert!(matches!(reopened.state(), RiskState::Stopped { .. }));
        // A new day and a recovery do not clear it; only a review does.
        reopened.engine.observe(at(3 * DAY), dec!(2500));
        reopened.commit(at(3 * DAY), JournalEvent::Updated).unwrap();
        drop(reopened);
        let mut reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
        assert!(matches!(reopened.state(), RiskState::Stopped { .. }));
        assert_eq!(reopened.engine().peak(), dec!(2500));

        assert_eq!(
            reopened
                .resume_after_review(at(3 * DAY + HOUR), dec!(1600), "reviewed")
                .unwrap(),
            RiskState::Active
        );
        drop(reopened);
        let reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
        assert_eq!(reopened.state(), RiskState::Active);
        assert_eq!(reopened.engine().peak(), dec!(1600));
        let records = PersistentRisk::read(&dir.journal()).unwrap();
        assert!(matches!(
            records.last().unwrap().event,
            JournalEvent::ResumedAfterReview { .. }
        ));
    }

    #[test]
    fn a_review_changes_nothing_unless_stopped_and_cannot_be_back_dated() {
        let dir = TestDir::new("review");
        let mut risk = journal_with(&dir, &[dec!(1880)]);
        // Halted for the day, not stopped: a review changes nothing.
        assert_eq!(
            risk.resume_after_review(at(2 * HOUR), dec!(1880), "no")
                .unwrap(),
            RiskState::HaltedForDay { day: 0 }
        );
        risk.engine.observe(at(2 * DAY), dec!(1400));
        risk.commit(at(2 * DAY), JournalEvent::Updated).unwrap();
        assert!(matches!(
            risk.resume_after_review(at(DAY), dec!(1400), "back-dated"),
            Err(JournalError::Invalid(_))
        ));
        assert!(matches!(risk.state(), RiskState::Stopped { .. }));
    }

    #[test]
    fn a_failed_write_stops_trading_and_is_not_forgotten_by_a_restart() {
        let dir = TestDir::new("failed-write");
        let mut risk = journal_with(&dir, &[]);
        // Writes fail from now on, before a byte reaches the file, as on a
        // full disk: the handle is read-only.
        risk.journal.file = File::open(dir.journal()).unwrap();
        let before = fs::read(dir.journal()).unwrap();
        // A new peak of 2,400 that cannot be written.
        risk.engine.observe(at(HOUR), dec!(2400));
        assert!(matches!(
            risk.commit(at(HOUR), JournalEvent::Updated),
            Err(JournalError::Io { .. })
        ));
        assert_eq!(fs::read(dir.journal()).unwrap(), before);
        assert!(matches!(risk.check_ready(), Err(JournalError::Broken(_))));
        // Nothing is written after a failure, a review included.
        risk.engine.observe(at(2 * HOUR), dec!(1700));
        assert!(matches!(risk.state(), RiskState::Stopped { .. }));
        assert!(matches!(
            risk.commit(at(2 * HOUR), JournalEvent::Updated),
            Err(JournalError::Broken(_))
        ));
        assert!(matches!(
            risk.resume_after_review(at(3 * HOUR), dec!(1700), "no"),
            Err(JournalError::Broken(_))
        ));
        drop(risk);

        // The file alone says peak 2,000 and active; the marker says that
        // is not the whole story.
        let marker = broken_marker(&dir.journal());
        assert!(
            fs::read_to_string(&marker)
                .unwrap()
                .contains(dir.journal().to_str().unwrap())
        );
        assert_eq!(
            PersistentRisk::open(&dir.journal(), &limits()).unwrap_err(),
            JournalError::MarkedBroken(marker.clone())
        );
        // A person looks, decides, and removes the marker.
        fs::remove_file(&marker).unwrap();
        assert_eq!(
            PersistentRisk::open(&dir.journal(), &limits())
                .unwrap()
                .engine()
                .peak(),
            dec!(2000)
        );
    }

    #[test]
    fn a_review_that_cannot_be_written_does_not_resume() {
        let dir = TestDir::new("review-unwritten");
        let mut risk = journal_with(&dir, &[dec!(1400)]);
        assert!(matches!(risk.state(), RiskState::Stopped { .. }));
        risk.journal.file = File::open(dir.journal()).unwrap();
        assert!(matches!(
            risk.resume_after_review(at(2 * HOUR), dec!(1400), "reviewed"),
            Err(JournalError::Io { .. })
        ));
        // Not on disk, so not resumed in memory either.
        assert!(matches!(risk.state(), RiskState::Stopped { .. }));
        assert_eq!(risk.engine().peak(), dec!(2000));
    }

    #[test]
    fn the_writer_refuses_a_record_its_reader_would_refuse() {
        let dir = TestDir::new("refuse-write");
        let mut risk = journal_with(&dir, &[dec!(2200)]);
        let before = fs::read(dir.journal()).unwrap();
        // Make the engine's next state a step the reader refuses: a peak
        // below the one on disk.
        risk.engine = RiskEngine::new(limits(), at(2 * HOUR), dec!(2100)).unwrap();
        let refused = risk
            .commit(at(2 * HOUR), JournalEvent::Updated)
            .unwrap_err();
        assert!(
            matches!(&refused, JournalError::Inconsistent { message, .. } if message.contains("peak")),
            "{refused:?}"
        );
        // Nothing was appended; the journal still opens, after the marker.
        assert_eq!(fs::read(dir.journal()).unwrap(), before);
        assert!(matches!(risk.check_ready(), Err(JournalError::Broken(_))));
        drop(risk);
        fs::remove_file(broken_marker(&dir.journal())).unwrap();
        assert_eq!(
            PersistentRisk::open(&dir.journal(), &limits())
                .unwrap()
                .engine()
                .peak(),
            dec!(2200)
        );
    }

    #[test]
    fn a_review_may_carry_a_record_of_positions_that_caught_up() {
        let dir = TestDir::new("review-positions");
        let mut risk = journal_with(&dir, &[]);
        risk.engine
            .record_entry(Symbol::new("BTC"), Side::Buy, dec!(1), dec!(100), dec!(98))
            .unwrap();
        risk.commit(at(HOUR), JournalEvent::Updated).unwrap();
        risk.engine.observe(at(2 * HOUR), dec!(1400));
        risk.commit(at(2 * HOUR), JournalEvent::Updated).unwrap();
        // The session closed it and told the engine, but the sync that
        // would have written that failed to read the venue.
        risk.engine.record_closed(&Symbol::new("BTC"));
        assert_eq!(
            risk.resume_after_review(at(3 * HOUR), dec!(1400), "reviewed")
                .unwrap(),
            RiskState::Active
        );
        drop(risk);
        let reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
        assert_eq!(reopened.state(), RiskState::Active);
        assert!(reopened.engine().positions().is_empty());
    }

    #[test]
    fn a_missing_journal_is_refused_and_an_existing_one_never_replaced() {
        let dir = TestDir::new("missing");
        assert_eq!(
            PersistentRisk::open(&dir.journal(), &limits()).unwrap_err(),
            JournalError::Missing(dir.journal())
        );
        drop(journal_with(&dir, &[dec!(1880)]));
        let before = fs::read(dir.journal()).unwrap();
        assert_eq!(
            PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "again")
                .unwrap_err(),
            JournalError::Exists(dir.journal())
        );
        assert_eq!(fs::read(dir.journal()).unwrap(), before);
        // An empty file is not a journal either.
        let empty = dir.0.join("empty.jsonl");
        fs::write(&empty, "").unwrap();
        assert!(matches!(
            PersistentRisk::open(&empty, &limits()),
            Err(JournalError::Malformed { .. })
        ));
    }

    #[test]
    fn a_journal_is_open_in_one_process_at_a_time() {
        let dir = TestDir::new("lock");
        let risk = journal_with(&dir, &[]);
        assert_eq!(
            PersistentRisk::open(&dir.journal(), &limits()).unwrap_err(),
            JournalError::Locked(dir.journal())
        );
        drop(risk);
        assert!(PersistentRisk::open(&dir.journal(), &limits()).is_ok());
    }

    #[test]
    fn the_locked_writer_allows_read_inspection_and_preserves_its_cursor() {
        let dir = TestDir::new("read-locked");
        let mut risk = journal_with(&dir, &[dec!(2200)]);
        let position = risk.journal.file.stream_position().unwrap();
        let inspected = PersistentRisk::read(&dir.journal()).unwrap();
        assert_eq!(risk.journal.records().unwrap(), inspected);
        assert_eq!(risk.journal.file.stream_position().unwrap(), position);
        assert_eq!(inspected.last(), Some(&risk.journal.last));
        // Even after a read/seek, an ordinary writer must append at EOF.
        risk.journal.file.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(
            PersistentRisk::open(&dir.journal(), &limits()).unwrap_err(),
            JournalError::Locked(dir.journal())
        );
        risk.engine.observe(at(2 * HOUR), dec!(2400));
        risk.commit(at(2 * HOUR), JournalEvent::Updated).unwrap();
        drop(risk);
        assert_eq!(
            PersistentRisk::open(&dir.journal(), &limits())
                .unwrap()
                .engine()
                .peak(),
            dec!(2400)
        );
    }

    #[test]
    fn rebuilding_flows_keeps_the_writer_and_appends_after_the_existing_records() {
        let dir = TestDir::new("rebuild-handle");
        let mut risk = journal_with(&dir, &[]).with_flows();
        let empty = VenueView::default();
        let first =
            risk.observe_view_at(at(0), [(String::new(), 0)].into(), dec!(2000), &empty, true);
        assert!(first.journal_error.is_none());
        let flow = Flow {
            time_ms: HOUR,
            amount: dec!(100),
            id: "deposit-on-held-handle".into(),
            dex: String::new(),
            between: false,
            value: Some(flows::ValueRange::cash_exact(dec!(2000))),
        };
        risk.apply_flow(at(HOUR), &flow).unwrap();
        // Hand calculation: 2,000 cash + 100 deposit = 2,100; no trade PnL.
        let out = risk.observe_view_at(
            at(2 * HOUR),
            [(String::new(), 2 * HOUR)].into(),
            dec!(2100),
            &empty,
            true,
        );
        assert!(out.journal_error.is_none());
        let before = risk.engine.snapshot();
        let position = risk.journal.file.stream_position().unwrap();
        let mut rebuilt = risk.with_flows();
        assert!(rebuilt.broken.is_none());
        assert!(rebuilt.knows_flow(&flow.id));
        assert_eq!(rebuilt.engine.snapshot(), before);
        assert_eq!(rebuilt.journal.file.stream_position().unwrap(), position);
        assert!(matches!(
            PersistentRisk::open(&dir.journal(), &limits()),
            Err(JournalError::Locked(_))
        ));
        let out = rebuilt.observe_view_at(
            at(3 * HOUR),
            [(String::new(), 3 * HOUR)].into(),
            dec!(2100),
            &empty,
            true,
        );
        assert!(out.journal_error.is_none());
        drop(rebuilt);
        let restarted = PersistentRisk::open(&dir.journal(), &limits())
            .unwrap()
            .with_flows();
        assert!(restarted.broken.is_none());
        assert!(restarted.knows_flow(&flow.id));
        assert_eq!(restarted.engine.peak(), dec!(2100));
    }

    #[test]
    fn rebuilding_a_damaged_journal_restores_the_cursor_and_blocks_entries() {
        for damage in [b"{".as_slice(), b"not-json\n".as_slice()] {
            let dir = TestDir::new("rebuild-damaged");
            let mut risk = journal_with(&dir, &[]);
            risk.journal.file.write_all(damage).unwrap();
            risk.journal.file.sync_data().unwrap();
            let position = risk.journal.file.stream_position().unwrap();
            assert!(risk.journal.records().is_err());
            assert_eq!(risk.journal.file.stream_position().unwrap(), position);
            let mut rebuilt = risk.with_flows();
            assert!(matches!(
                rebuilt.check_ready(),
                Err(JournalError::Broken(_))
            ));
            assert_eq!(rebuilt.journal.file.stream_position().unwrap(), position);
        }
    }

    #[test]
    fn reconstruction_refuses_a_valid_record_not_written_by_its_writer() {
        let dir = TestDir::new("rebuild-other-writer");
        let mut risk = journal_with(&dir, &[]);
        let (_, line) = JournalRecord::new(
            risk.journal.last.seq + 1,
            at(HOUR),
            JournalEvent::Updated,
            risk.engine.snapshot(),
            risk.journal.last.check.clone(),
            FlowFields::default(),
        )
        .unwrap();
        risk.journal.file.write_all(line.as_bytes()).unwrap();
        risk.journal.file.sync_data().unwrap();
        let position = risk.journal.file.stream_position().unwrap();
        assert!(matches!(
            risk.journal.records(),
            Err(JournalError::Inconsistent { .. })
        ));
        assert_eq!(risk.journal.file.stream_position().unwrap(), position);
        assert!(matches!(
            risk.with_flows().check_ready(),
            Err(JournalError::Broken(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn flow_reconstruction_uses_the_open_journal_after_path_substitution() {
        let dir = TestDir::new("rebuild-namespace");
        let risk = journal_with(&dir, &[]);
        let state = risk.engine.snapshot();
        let original = dir.0.join("original.jsonl");
        fs::rename(dir.journal(), &original).unwrap();
        fs::write(dir.journal(), "not the opened journal\n").unwrap();
        let rebuilt = risk.with_flows();
        assert!(rebuilt.broken.is_none());
        assert_eq!(rebuilt.engine.snapshot(), state);
        assert!(PersistentRisk::read(&dir.journal()).is_err());
        assert!(PersistentRisk::read(&original).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_writer_excludes_legacy_write_and_delete_handles_in_both_orders() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = TestDir::new("windows-writer-sharing");
        drop(journal_with(&dir, &[]));
        // The previous implementation opened read+append with default sharing
        // and then took std's exclusive byte lock. Both versions exclude one another.
        let legacy = OpenOptions::new()
            .read(true)
            .append(true)
            .open(dir.journal())
            .unwrap();
        legacy.try_lock().unwrap();
        assert_eq!(
            open_locked(&dir.journal()).unwrap_err(),
            JournalError::Locked(dir.journal())
        );
        drop(legacy);
        let writer = open_locked(&dir.journal()).unwrap();
        assert!(
            OpenOptions::new()
                .read(true)
                .append(true)
                .open(dir.journal())
                .is_err()
        );
        assert!(fs::rename(dir.journal(), dir.0.join("renamed")).is_err());
        assert!(fs::remove_file(dir.journal()).is_err());
        assert!(PersistentRisk::read(&dir.journal()).is_ok());
        drop(writer);
        for access in [0x4000_0000, 0x0001_0000] {
            // GENERIC_WRITE, DELETE
            let incompatible = OpenOptions::new()
                .access_mode(access)
                .share_mode(7)
                .open(dir.journal())
                .unwrap();
            assert_eq!(
                open_locked(&dir.journal()).unwrap_err(),
                JournalError::Locked(dir.journal())
            );
            drop(incompatible);
            assert!(open_locked(&dir.journal()).is_ok());
        }
    }

    #[test]
    fn other_limits_are_refused() {
        let dir = TestDir::new("limits");
        drop(journal_with(&dir, &[]));
        let tighter = RiskLimits {
            daily_loss_stop: dec!(0.05),
            ..limits()
        };
        assert!(matches!(
            PersistentRisk::open(&dir.journal(), &tighter),
            Err(JournalError::LimitsDiffer { .. })
        ));
    }

    #[test]
    fn a_torn_record_is_refused_until_a_person_repairs_it() {
        let dir = TestDir::new("torn");
        drop(journal_with(&dir, &[dec!(1880)]));
        let complete = fs::read(dir.journal()).unwrap();
        let mut torn = complete.clone();
        // 51 bytes of a third record whose write was cut short.
        torn.extend_from_slice(br#"{"format":"zunder-risk-journal","version":1,"seq":3"#);
        fs::write(dir.journal(), &torn).unwrap();

        assert!(matches!(
            PersistentRisk::open(&dir.journal(), &limits()),
            Err(JournalError::TornTail { bytes: 51, .. })
        ));
        assert!(matches!(
            PersistentRisk::read(&dir.journal()),
            Err(JournalError::TornTail { .. })
        ));
        let cut = PersistentRisk::repair_torn_tail(&dir.journal(), &limits(), at(HOUR), "repaired")
            .unwrap();
        assert_eq!(cut, 51);
        let repaired = fs::read(dir.journal()).unwrap();
        assert!(repaired.starts_with(&complete));
        let added = &repaired[complete.len()..];
        assert!(!added.contains(&0));
        assert_eq!(added.iter().filter(|byte| **byte == b'\n').count(), 1);
        let reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
        // The halt in the last complete record is still there.
        assert_eq!(reopened.state(), RiskState::HaltedForDay { day: 0 });
        drop(reopened);
        let records = PersistentRisk::read(&dir.journal()).unwrap();
        assert_eq!(records.len(), 3);
        assert!(matches!(
            records[2].event,
            JournalEvent::Repaired { cut_bytes: 51, .. }
        ));
        // Nothing to repair now.
        assert_eq!(
            PersistentRisk::repair_torn_tail(&dir.journal(), &limits(), at(HOUR), "again").unwrap(),
            0
        );
    }

    #[test]
    fn repair_refuses_a_live_writer_without_mutation() {
        let dir = TestDir::new("repair-live-writer");
        let risk = journal_with(&dir, &[dec!(1880)]);
        let before = fs::read(dir.journal()).unwrap();
        assert_eq!(
            PersistentRisk::repair_torn_tail(&dir.journal(), &limits(), at(HOUR), "repair")
                .unwrap_err(),
            JournalError::Locked(dir.journal())
        );
        assert_eq!(fs::read(dir.journal()).unwrap(), before);
        // 2,000 - 120 = 1,880; the daily-loss halt must survive refused repair.
        assert_eq!(risk.state(), RiskState::HaltedForDay { day: 0 });
    }

    #[test]
    fn a_changed_record_is_refused() {
        let dir = TestDir::new("tamper");
        drop(journal_with(&dir, &[dec!(1880)]));
        let mut edited = lines(&dir);
        // Someone lifts the halt by hand.
        edited[1] = edited[1].replace(r#"{"halted_for_day":{"day":0}}"#, r#""active""#);
        assert_ne!(edited, lines(&dir));
        write_lines(&dir, &edited);
        let message = inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
        assert!(message.contains("checksum"), "{message}");
    }

    #[test]
    fn a_removed_or_reordered_record_is_refused() {
        let dir = TestDir::new("order");
        drop(journal_with(&dir, &[dec!(2100), dec!(2200), dec!(1880)]));
        let original = lines(&dir);
        assert_eq!(original.len(), 4);

        let mut gap = original.clone();
        gap.remove(1);
        write_lines(&dir, &gap);
        let message = inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
        assert!(message.contains("sequence"), "{message}");

        let mut swapped = original;
        swapped.swap(1, 2);
        write_lines(&dir, &swapped);
        inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
    }

    #[test]
    fn a_newer_version_or_a_foreign_file_is_refused() {
        let dir = TestDir::new("version");
        drop(journal_with(&dir, &[]));
        let mut newer = lines(&dir);
        // An engine without flows writes version 2; anything above the
        // newest version this build reads is refused.
        newer[0] = newer[0].replace(
            &format!(r#""version":{RECORD_VERSION}"#),
            &format!(r#""version":{}"#, JOURNAL_VERSION + 1),
        );
        write_lines(&dir, &newer);
        assert!(matches!(
            PersistentRisk::open(&dir.journal(), &limits()),
            Err(JournalError::UnsupportedVersion { version, .. }) if version == u64::from(JOURNAL_VERSION) + 1
        ));
        write_lines(&dir, &[r#"{"seq":1}"#.to_owned()]);
        assert!(matches!(
            PersistentRisk::open(&dir.journal(), &limits()),
            Err(JournalError::Malformed { .. })
        ));
    }

    #[test]
    fn steps_the_engine_cannot_take_are_refused_even_with_valid_checksums() {
        let dir = TestDir::new("steps");
        let start = fresh();
        let higher = RiskSnapshot {
            peak: dec!(2200),
            last: dec!(2200),
            ..start.clone()
        };

        // The peak falls.
        forge(
            &dir,
            &[
                (0, initialised(), start.clone()),
                (HOUR, JournalEvent::Updated, higher),
                (2 * HOUR, JournalEvent::Updated, start.clone()),
            ],
        );
        let message = inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
        assert!(message.contains("peak"), "{message}");

        // A drawdown stop cleared without a review.
        let stopped = RiskSnapshot {
            state: RiskState::Stopped {
                at: at(HOUR),
                drawdown: dec!(0.3),
            },
            last: dec!(1400),
            ..start.clone()
        };
        let active_again = RiskSnapshot {
            day: 1,
            day_start: dec!(1400),
            last: dec!(1400),
            peak: dec!(1400),
            ..start.clone()
        };
        forge(
            &dir,
            &[
                (0, initialised(), start.clone()),
                (HOUR, JournalEvent::Updated, stopped.clone()),
                (DAY, JournalEvent::Updated, active_again.clone()),
            ],
        );
        inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
        // Cleared without a review and without touching the peak: a new
        // day at the old peak of 2,000.
        let cleared_at_peak = RiskSnapshot {
            day: 1,
            ..start.clone()
        };
        forge(
            &dir,
            &[
                (0, initialised(), start.clone()),
                (HOUR, JournalEvent::Updated, stopped.clone()),
                (DAY, JournalEvent::Updated, cleared_at_peak),
            ],
        );
        let message = inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
        assert!(message.contains("without a review"), "{message}");
        // The same step as a review is fine.
        forge(
            &dir,
            &[
                (0, initialised(), start.clone()),
                (HOUR, JournalEvent::Updated, stopped.clone()),
                (
                    DAY,
                    JournalEvent::ResumedAfterReview {
                        note: "reviewed".into(),
                    },
                    active_again,
                ),
            ],
        );
        assert_eq!(
            PersistentRisk::open(&dir.journal(), &limits())
                .unwrap()
                .state(),
            RiskState::Active
        );

        // A halt cleared on the day it fired.
        let halted = RiskSnapshot {
            state: RiskState::HaltedForDay { day: 0 },
            last: dec!(1880),
            ..start.clone()
        };
        let cleared = RiskSnapshot {
            last: dec!(1990),
            ..start.clone()
        };
        forge(
            &dir,
            &[
                (0, initialised(), start.clone()),
                (HOUR, JournalEvent::Updated, halted),
                (2 * HOUR, JournalEvent::Updated, cleared),
            ],
        );
        let message = inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
        assert!(message.contains("halt"), "{message}");

        // A second `initialised` record, which could reset everything.
        forge(
            &dir,
            &[
                (0, initialised(), stopped),
                (HOUR, initialised(), start.clone()),
            ],
        );
        inconsistent(PersistentRisk::open(&dir.journal(), &limits()));

        // A state no observation leads to: active 30% below the peak.
        forge(
            &dir,
            &[(
                0,
                initialised(),
                RiskSnapshot {
                    last: dec!(1400),
                    ..start
                },
            )],
        );
        inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
    }

    /// A small deterministic generator for the property test below.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
    }

    fn strictness(state: RiskState) -> u8 {
        match state {
            RiskState::Active => 0,
            RiskState::HaltedForDay { .. } => 1,
            RiskState::Stopped { .. } => 2,
        }
    }

    #[test]
    fn a_restored_engine_is_never_less_strict_than_one_that_kept_running() {
        // Random equity paths, a few hours between observations, with a
        // restart at a random step from what the write policy put on disk.
        // From then on both engines see the same observations; the
        // restored one must be at least as strict at every step, with the
        // same peak. Without the equity cap, and with a cap of 1,500 that
        // binds from the start (decision of 6 Oct 2026).
        let capped = RiskLimits {
            max_trading_equity_usd: Some(dec!(1500)),
            ..limits()
        };
        for (limits, seed) in [limits(), capped]
            .into_iter()
            .flat_map(|limits| (1..400u64).map(move |seed| (limits.clone(), seed)))
        {
            let mut rng = Lcg(seed);
            let mut running = RiskEngine::new(limits.clone(), at(0), dec!(2000)).unwrap();
            let mut written = running.snapshot();
            let crash_at = rng.next() % 120;
            let mut restored: Option<RiskEngine> = None;
            let mut equity = dec!(2000);
            let mut ms = 0;
            for step in 0..160u64 {
                ms += i64::try_from(1 + rng.next() % 9).unwrap() * HOUR;
                // Moves of -3% to +3% in steps of 0.1%, and now and then a
                // fall of 8% on top.
                let percent =
                    Decimal::from(i64::try_from(rng.next() % 61).unwrap() - 30) / dec!(1000);
                let shock = if rng.next().is_multiple_of(25) {
                    dec!(-0.08)
                } else {
                    Decimal::ZERO
                };
                equity = (equity * (Decimal::ONE + percent + shock)).round_dp(2);
                if step == crash_at {
                    restored = Some(RiskEngine::restore(limits.clone(), written.clone()).unwrap());
                }
                let state = running.observe(at(ms), equity);
                let snapshot = running.snapshot();
                if must_write(&written, &snapshot) {
                    written = snapshot;
                }
                // Every state the policy writes can be restored.
                RiskEngine::restore(limits.clone(), written.clone()).unwrap();
                if let Some(restored) = restored.as_mut() {
                    let restored_state = restored.observe(at(ms), equity);
                    assert!(
                        strictness(restored_state) >= strictness(state),
                        "seed {seed}, step {step}: restored {restored_state:?}, running {state:?}"
                    );
                    assert_eq!(restored.peak(), running.peak(), "seed {seed}, step {step}");
                }
            }
        }
    }

    fn scope(network: &str, account: &str) -> JournalScope {
        JournalScope {
            network: network.into(),
            account: account.into(),
        }
    }

    const A: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
    const B: &str = "0x0000000000000000000000000000000000000001";

    #[test]
    fn a_journal_opens_only_for_its_own_network_and_account() {
        let dir = TestDir::new("scope");
        let testnet_a = scope("testnet", A);
        let risk = PersistentRisk::initialise_for(
            &dir.journal(),
            limits(),
            &testnet_a,
            at(0),
            dec!(2000),
            "test",
        )
        .unwrap();
        drop(risk);
        // The scope is in the first record.
        let records = PersistentRisk::read(&dir.journal()).unwrap();
        assert!(matches!(
            &records[0].event,
            JournalEvent::Initialised { scope: Some(recorded), .. } if *recorded == testnet_a
        ));
        // Another network, another account, or no scope at all: refused.
        for other in [scope("mainnet", A), scope("testnet", B)] {
            assert!(matches!(
                PersistentRisk::open_for(&dir.journal(), &limits(), &other),
                Err(JournalError::ScopeDiffers { .. })
            ));
        }
        assert!(matches!(
            PersistentRisk::open(&dir.journal(), &limits()),
            Err(JournalError::ScopeDiffers { .. })
        ));
        // The same scope opens.
        assert!(PersistentRisk::open_for(&dir.journal(), &limits(), &testnet_a).is_ok());
    }

    #[test]
    fn a_journal_without_a_scope_does_not_open_for_one() {
        // Journals started before scopes existed belong to no network: a
        // runner, which always names one, needs a new journal.
        let dir = TestDir::new("unscoped");
        drop(
            PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test")
                .unwrap(),
        );
        assert!(matches!(
            PersistentRisk::open_for(&dir.journal(), &limits(), &scope("mainnet", A)),
            Err(JournalError::ScopeDiffers { journal: None, .. })
        ));
        assert!(PersistentRisk::open(&dir.journal(), &limits()).is_ok());
        // Its first record carries no scope key, as before scopes existed.
        let text = fs::read_to_string(dir.journal()).unwrap();
        assert!(!text.contains("scope"), "{text}");
    }

    #[test]
    fn a_torn_journal_is_repaired_only_for_its_own_scope() {
        let dir = TestDir::new("scope-repair");
        let mainnet_a = scope("mainnet", A);
        drop(
            PersistentRisk::initialise_for(
                &dir.journal(),
                limits(),
                &mainnet_a,
                at(0),
                dec!(2000),
                "test",
            )
            .unwrap(),
        );
        let mut file = OpenOptions::new().append(true).open(dir.journal()).unwrap();
        file.write_all(b"{\"check\":\"torn").unwrap();
        drop(file);
        assert!(matches!(
            PersistentRisk::repair_torn_tail_for(
                &dir.journal(),
                &limits(),
                &scope("testnet", A),
                at(1),
                "test"
            ),
            Err(JournalError::ScopeDiffers { .. })
        ));
        assert!(
            PersistentRisk::repair_torn_tail_for(
                &dir.journal(),
                &limits(),
                &mainnet_a,
                at(1),
                "test"
            )
            .unwrap()
                > 0
        );
        assert!(PersistentRisk::open_for(&dir.journal(), &limits(), &mainnet_a).is_ok());
    }

    #[test]
    fn a_version_1_journal_is_still_read() {
        // A journal written before version 2: its first record re-encoded
        // as version 1, with its checksum computed again.
        let dir = TestDir::new("v1");
        drop(journal_with(&dir, &[]));
        let line = lines(&dir).remove(0);
        let body = format!(
            "{{{}",
            line.split_once("\",")
                .unwrap()
                .1
                .replace(&format!(r#""version":{RECORD_VERSION}"#), r#""version":1"#)
        );
        let check = hex(&Sha3_256::digest(body.as_bytes()));
        let old = format!("{CHECK_PREFIX}{check}\",{}", &body[1..]);
        write_lines(&dir, &[old]);
        let records = PersistentRisk::read(&dir.journal()).unwrap();
        assert_eq!(records[0].version, 1);
        assert!(PersistentRisk::open(&dir.journal(), &limits()).is_ok());
    }

    #[test]
    fn a_person_can_record_the_scope_of_an_unscoped_journal_once() {
        let dir = TestDir::new("adopt");
        drop(journal_with(&dir, &[dec!(2100)]));
        let peak = PersistentRisk::open(&dir.journal(), &limits())
            .unwrap()
            .engine()
            .peak();
        let testnet_a = scope("testnet", A);
        PersistentRisk::adopt_scope(&dir.journal(), &limits(), &testnet_a, at(HOUR), "test")
            .unwrap();
        // Now it opens for that scope only, with its history.
        let risk = PersistentRisk::open_for(&dir.journal(), &limits(), &testnet_a).unwrap();
        assert_eq!(risk.engine().peak(), peak);
        drop(risk);
        for other in [scope("mainnet", A), scope("testnet", B)] {
            assert!(matches!(
                PersistentRisk::open_for(&dir.journal(), &limits(), &other),
                Err(JournalError::ScopeDiffers { .. })
            ));
        }
        assert!(matches!(
            PersistentRisk::open(&dir.journal(), &limits()),
            Err(JournalError::ScopeDiffers { .. })
        ));
        // Once only: a second adoption, to any scope, is refused.
        assert!(matches!(
            PersistentRisk::adopt_scope(
                &dir.journal(),
                &limits(),
                &scope("mainnet", A),
                at(2 * HOUR),
                "test"
            ),
            Err(JournalError::ScopeDiffers { .. })
        ));
        // And a journal started with a scope cannot be adopted either.
        let scoped = TestDir::new("adopt-scoped");
        drop(
            PersistentRisk::initialise_for(
                &scoped.journal(),
                limits(),
                &testnet_a,
                at(0),
                dec!(2000),
                "test",
            )
            .unwrap(),
        );
        assert!(matches!(
            PersistentRisk::adopt_scope(&scoped.journal(), &limits(), &testnet_a, at(1), "test"),
            Err(JournalError::ScopeDiffers { .. })
        ));
    }

    #[test]
    fn a_second_scope_record_or_one_that_changes_the_state_is_refused() {
        let dir = TestDir::new("scope-records");
        let scoped = || JournalEvent::Scoped {
            scope: scope("testnet", A),
            note: String::new(),
        };
        forge(
            &dir,
            &[
                (0, initialised(), fresh()),
                (1, scoped(), fresh()),
                (2, scoped(), fresh()),
            ],
        );
        assert!(inconsistent(PersistentRisk::open(&dir.journal(), &limits())).contains("already"));
        let mut changed = fresh();
        changed.peak = dec!(2500);
        changed.last = dec!(2500);
        forge(&dir, &[(0, initialised(), fresh()), (1, scoped(), changed)]);
        assert!(inconsistent(PersistentRisk::open(&dir.journal(), &limits())).contains("scope"));
    }
}
