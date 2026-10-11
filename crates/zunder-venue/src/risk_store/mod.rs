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
//!
//! # Where the parts are
//!
//! - `record`: the format of a line, its checksum and the chain.
//! - `parse` and `check`: reading a journal's bytes, and the checks every
//!   record passes (the step from the record before, and what a `flowed`
//!   record lists and holds),
//!   which the writer runs too before it appends. No file access.
//! - `file`: the journal on disk: creating, locking, reading, appending,
//!   and the marker a failed write leaves.
//! - `persistent`: [`PersistentRisk`] itself; `flow_book` its deposits and
//!   withdrawals; `session` the trading session it drives.

mod check;
mod error;
mod file;
mod flow_book;
mod parse;
mod persistent;
mod record;
mod session;
#[cfg(test)]
mod tests;

#[cfg(doc)]
use zunder_risk::RiskSnapshot;

pub use self::{
    error::JournalError,
    file::broken_marker,
    flow_book::{FLOW_READ_BACK_MS, FlowOutcome},
    persistent::{PersistentRisk, ViewSync},
    record::{JOURNAL_FORMAT, JOURNAL_VERSION, JournalEvent, JournalRecord, JournalScope},
    session::{
        EngineHandle, FlattenOutcome, RiskObservation, RiskSession, RiskStoreError, RiskSync,
        SessionRisk, StoreErrorOf, SyncOf,
    },
};
