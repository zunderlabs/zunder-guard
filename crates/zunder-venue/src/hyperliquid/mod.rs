// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Hyperliquid: which network, which account, and how requests get there.
//!
//! - [`Network`]: mainnet or testnet, and their URLs.
//! - [`Address`]: an account or wallet address.
//! - [`VenueNetwork`] and [`MainnetConsent`]: the network as a typed choice,
//!   mainnet only with a person's confirmation naming the account
//!   (`network` module).
//! - [`Transport`]: sealed; [`HttpTransport`] goes to the chosen network's
//!   REST URL only, [`ScriptedTransport`] never leaves this machine.

mod address;
mod network;
mod transport;

pub use self::{
    address::{Address, KeyError},
    network::{CONFIRM_VAR, MainnetConsent, VenueNetwork},
    transport::{Endpoint, HttpTransport, ScriptedTransport, Transport, TransportError},
};

/// Which Hyperliquid network to talk to. There is deliberately no default:
/// every caller has to say which one it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    /// Base URL of the REST API. Requests go to `/info` and `/exchange`.
    pub const fn rest_url(self) -> &'static str {
        match self {
            Network::Mainnet => "https://api.hyperliquid.xyz",
            Network::Testnet => "https://api.hyperliquid-testnet.xyz",
        }
    }

    pub const fn ws_url(self) -> &'static str {
        match self {
            Network::Mainnet => "wss://api.hyperliquid.xyz/ws",
            Network::Testnet => "wss://api.hyperliquid-testnet.xyz/ws",
        }
    }

    /// Whether real money is at stake.
    pub const fn is_live(self) -> bool {
        matches!(self, Network::Mainnet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_never_points_at_mainnet() {
        assert!(Network::Testnet.rest_url().contains("testnet"));
        assert!(Network::Testnet.ws_url().contains("testnet"));
        assert!(!Network::Mainnet.rest_url().contains("testnet"));
        assert!(!Network::Testnet.is_live());
        assert!(Network::Mainnet.is_live());
    }
}
