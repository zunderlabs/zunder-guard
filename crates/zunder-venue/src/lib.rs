// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! What a program needs to talk to a venue safely, without an executor.
//!
//! - [`hyperliquid`]: account addresses, the network ([`hyperliquid::Network`]
//!   and [`hyperliquid::VenueNetwork`]), the proof a person allowed mainnet
//!   ([`hyperliquid::MainnetConsent`]), and the sealed transport that sends
//!   requests to the chosen network's API and nowhere else.
//! - [`InstrumentRules`]: lot sizes and price grids, and which way to round
//!   ([`Round`]).
//! - [`PersistentRisk`]: the risk engine's memory across restarts, an
//!   append-only, checksummed journal on disk ([`risk_store`]), which for
//!   Zunder Guard also keeps deposits and withdrawals out of the account
//!   stops ([`flows`], `docs/guard.md#deposits-and-withdrawals`).
//! - [`ExecError`]: what can go wrong between a caller and a venue.
//! - [`owner_only`]: key files only their owner can read (Unix modes, Windows ACLs).
//!
//! Nothing here signs or places an order. [`PersistentRisk::sync`] and
//! [`PersistentRisk::enter`] drive a trading session through the
//! [`RiskSession`] trait, which the executor's session implements outside
//! this crate.

mod error;
pub mod flows;
pub mod hyperliquid;
pub mod owner_only;
pub mod risk_store;
mod rules;

pub use error::ExecError;
pub use flows::{FLOW_TIME_MARGIN_MS, Flow, Horizon, SeenView, ValueRange, WaivedStop, rebase};
pub use risk_store::{
    EngineHandle, FLOW_READ_BACK_MS, FlattenOutcome, FlowOutcome, JOURNAL_FORMAT, JOURNAL_VERSION,
    JournalError, JournalEvent, JournalRecord, JournalScope, PersistentRisk, RiskObservation,
    RiskSession, RiskStoreError, RiskSync, SessionRisk, StoreErrorOf, SyncOf, ViewSync,
};
pub use rules::{InstrumentKind, InstrumentRules, Round};
