// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Hyperliquid: how requests get to the network.
//!
//! [`Transport`] is sealed; [`HttpTransport`] goes to the REST URL of the
//! [`VenueNetwork`](zunder_venue_types::VenueNetwork) it was built for
//! only; `ScriptedTransport`, which never leaves this machine, exists only
//! in test builds (feature `test-hooks`). [`Network`] and [`Address`] are
//! `zunder-hl-protocol`'s, re-exported here.

mod transport;

// The protocol's types, at the paths the programs built on this crate use.
pub use zunder_hl_protocol::{Address, Network};

#[cfg(any(test, feature = "test-hooks"))]
pub use self::transport::ScriptedTransport;
pub use self::transport::{Endpoint, HttpTransport, Transport, TransportError};
