// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The venue's types, without I/O: what an executor, Zunder Guard and its
//! tools agree on before anything is sent.
//!
//! - [`InstrumentRules`]: lot sizes and price grids, and which way to round
//!   ([`Round`]).
//! - [`VenueNetwork`] and [`MainnetConsent`]: the Hyperliquid network as a
//!   typed choice, mainnet only with a person's confirmation naming the
//!   account ([`CONFIRM_VAR`]).
//! - [`ExecError`] and [`KeyError`]: what can go wrong between a caller and
//!   a venue, and why a key or an address could not be loaded.
//!
//! No files, no network and no clock. The only outside input is the
//! process environment, read at a start for an account address
//! ([`address_from_env`]) and for the mainnet confirmation
//! ([`MainnetConsent::from_env`], which has to live with the consent it
//! makes, so that nothing else can make one). Addresses, networks and the
//! price grid are `zunder-hl-protocol`'s. Compiles to
//! `wasm32-unknown-unknown`.

mod error;
mod key;
mod network;
mod rules;

pub use error::ExecError;
pub use key::{KeyError, address_from_env};
pub use network::{CONFIRM_VAR, MainnetConsent, VenueNetwork};
pub use rules::{InstrumentKind, InstrumentRules, Round, aggressive, passive, toward_position};
