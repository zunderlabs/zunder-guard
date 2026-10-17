// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! What a program needs to talk to a venue safely, without an executor:
//! the parts that touch the network or the disk. The types they share with
//! everything else (instrument rules, the network choice and mainnet
//! consent, the errors) are `zunder-venue-types`', without I/O.
//!
//! - [`hyperliquid`]: the sealed transport that sends requests to the
//!   chosen network's API and nowhere else.
//! - [`PersistentRisk`]: the risk engine's memory across restarts, an
//!   append-only, checksummed journal on disk ([`risk_store`]), which for
//!   Zunder Guard also keeps deposits and withdrawals out of the account
//!   stops ([`flows`], `docs/guard.md#deposits-and-withdrawals`).
//! - [`owner_only`]: key files only their owner can read (Unix modes, Windows ACLs).
//!
//! Nothing here signs or places an order. [`PersistentRisk::sync`] and
//! [`PersistentRisk::enter`] drive a trading session through the
//! [`RiskSession`] trait, which the executor's session implements outside
//! this crate.

pub mod flows;
pub mod hyperliquid;
pub mod owner_only;
pub mod risk_store;

pub use flows::{
    FLOW_TIME_MARGIN_MS, Flow, Horizon, RebaseBudget, SeenView, UNKNOWN_TYPE_GAP_MAX_MS,
    UNKNOWN_TYPE_ID_PREFIX, Unaccounted, UnaccountedEntry, UnaccountedRule, ValueRange, WaivedStop,
    rebase,
};
pub use risk_store::{
    EngineHandle, FLOW_READ_BACK_MS, FlattenOutcome, FlowOutcome, JOURNAL_FORMAT, JOURNAL_VERSION,
    JournalError, JournalEvent, JournalRecord, JournalScope, PersistentRisk, RiskObservation,
    RiskSession, RiskStoreError, RiskSync, SessionRisk, StoreErrorOf, SyncOf, ViewSync,
};
