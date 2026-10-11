// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Hyperliquid: how requests get to the network.
//!
//! [`Transport`] is sealed; [`HttpTransport`] goes to the REST URL of the
//! [`VenueNetwork`](zunder_venue_types::VenueNetwork) it was built for
//! only, [`ScriptedTransport`] never leaves this machine. [`Network`] and
//! [`Address`] are `zunder-hl-protocol`'s, re-exported here.

mod transport;

// The protocol's types, at the paths the programs built on this crate use.
pub use zunder_hl_protocol::{Address, Network};

pub use self::transport::{Endpoint, HttpTransport, ScriptedTransport, Transport, TransportError};
