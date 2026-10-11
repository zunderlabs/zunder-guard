// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Mainnet and testnet, and what differs between them.
//!
//! Checked against the Hyperliquid API documentation ("Exchange endpoint",
//! "Signing") and the official Python SDK (`hyperliquid/utils/signing.py`,
//! `tests/signing_test.py`) on 6 Oct 2026:
//!
//! - **The URLs** ([`Network::rest_url`], [`Network::ws_url`]).
//! - **L1 actions** (orders, cancels, leverage): the EIP-712 domain is the
//!   same on both; only the phantom agent's `source` differs, `"a"` on
//!   mainnet and `"b"` on testnet ([`Network::phantom_agent_source`]). A
//!   signature for one network recovers another signer on the other.
//! - **User-signed actions** (`usdSend`, `withdraw3`, `approveAgent`): the
//!   `hyperliquidChain` field is `"Mainnet"` or `"Testnet"`
//!   ([`Network::hyperliquid_chain`]). Nothing here signs one.

use serde::{Deserialize, Serialize};

/// Which Hyperliquid network. There is deliberately no default: every
/// caller has to say which one it means. Choosing [`Network::Mainnet`] is
/// not consent to trade it: executors need a person's confirmation as well
/// (`zunder-venue-types`' `MainnetConsent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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

    /// The phantom agent's `source` in an L1 action signature
    /// (`construct_phantom_agent` in the Python SDK's `signing.py`).
    pub const fn phantom_agent_source(self) -> &'static str {
        match self {
            Network::Mainnet => "a",
            Network::Testnet => "b",
        }
    }

    /// The `hyperliquidChain` field of a user-signed action
    /// (`sign_user_signed_action` in the same file).
    pub const fn hyperliquid_chain(self) -> &'static str {
        match self {
            Network::Mainnet => "Mainnet",
            Network::Testnet => "Testnet",
        }
    }

    /// `"mainnet"` or `"testnet"`, as serialised.
    pub const fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_never_points_at_mainnet() {
        assert_eq!(
            Network::Testnet.rest_url(),
            "https://api.hyperliquid-testnet.xyz"
        );
        assert_eq!(Network::Mainnet.rest_url(), "https://api.hyperliquid.xyz");
        assert!(Network::Testnet.ws_url().contains("testnet"));
        assert!(!Network::Mainnet.ws_url().contains("testnet"));
        assert!(!Network::Testnet.is_live());
        assert!(Network::Mainnet.is_live());
    }

    #[test]
    fn each_network_has_its_own_source_chain_and_name() {
        assert_eq!(Network::Mainnet.phantom_agent_source(), "a");
        assert_eq!(Network::Testnet.phantom_agent_source(), "b");
        assert_eq!(Network::Mainnet.hyperliquid_chain(), "Mainnet");
        assert_eq!(Network::Testnet.hyperliquid_chain(), "Testnet");
        for network in [Network::Mainnet, Network::Testnet] {
            let json = serde_json::to_string(&network).unwrap();
            assert_eq!(json, format!("\"{}\"", network.name()));
            assert_eq!(serde_json::from_str::<Network>(&json).unwrap(), network);
        }
        assert!(serde_json::from_str::<Network>("\"Mainnet\"").is_err());
    }
}
