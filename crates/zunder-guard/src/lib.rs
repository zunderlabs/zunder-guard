// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Zunder Guard, the local binary: a risk firewall between a trading bot
//! and Hyperliquid that speaks Hyperliquid's own HTTP and WebSocket API on
//! a loopback address. See `docs/guard.md`.
//!
//! The decisions are `zunder-guard-core`'s (shared with the browser
//! Guard); this crate adds what needs I/O: the config, the venue
//! ([`upstream`]), the risk journal (`zunder-venue`'s `PersistentRisk`),
//! the decision journal ([`journal`]), the server ([`server`]) and the
//! setup ([`init`]).
//!
//! Guard forwards a bot's orders and holds no trading session of its own.
//! The network choice and mainnet consent, the HTTPS transport and the
//! persistent risk engine come from `zunder-venue`.

pub mod budget;
pub mod config;
pub mod guard;
pub mod init;
pub mod journal;
pub mod keyread;
pub mod licence_life;
pub mod recover;
pub mod rules;
pub mod server;
pub mod service;
pub mod statusview;
pub mod stream;
#[doc(hidden)]
pub mod testdir;
pub mod upstream;
