// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Hyperliquid: which network, which account, and how requests get there.
//!
//! - [`Network`] and [`Address`]: mainnet or testnet, and an account or
//!   wallet address (`zunder-hl-protocol`'s, re-exported here);
//!   [`address_from_env`] reads one from the environment.
//! - [`VenueNetwork`] and [`MainnetConsent`]: the network as a typed choice,
//!   mainnet only with a person's confirmation naming the account
//!   (`network` module).
//! - [`Transport`]: sealed; [`HttpTransport`] goes to the chosen network's
//!   REST URL only, [`ScriptedTransport`] never leaves this machine.

mod address;
mod network;
mod transport;

// The protocol's types, at the paths the programs built on this crate use.
pub use zunder_hl_protocol::{Address, Network};

pub use self::{
    address::{KeyError, address_from_env},
    network::{CONFIRM_VAR, MainnetConsent, VenueNetwork},
    transport::{Endpoint, HttpTransport, ScriptedTransport, Transport, TransportError},
};
