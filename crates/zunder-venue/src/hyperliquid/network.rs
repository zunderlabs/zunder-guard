// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Which Hyperliquid network the executor trades on, and the proof that
//! choosing it was allowed.
//!
//! An executor and its transport can only be built from a [`VenueNetwork`].
//! Testnet needs nothing: [`VenueNetwork::testnet`]. Mainnet needs a
//! [`MainnetConsent`], which only [`MainnetConsent::from_env`] makes outside
//! this crate: it requires [`CONFIRM_VAR`] in the process's environment to
//! name the very account that is traded. Programs ask for more before
//! they get that far (`allow_mainnet`, the risk frame and the equity cap
//! in their config, and the expected addresses).
//! An executor built with a consent trades only the account the consent
//! names, and refuses a key read from the environment.
//!
//! What the confirmation is: an explicit act by a person, setting a
//! variable to the account's address (on a server, a file only the
//! account's owner writes and removes). It is not a secret, and it is read at every start,
//! so it stands until it is removed. It keeps a config, a binary or a
//! session's mistake from reaching mainnet by itself; it cannot stop a
//! caller deliberately setting the account confirmation without authorization.
//!
//! # What differs between the networks
//!
//! Checked against the Hyperliquid API documentation ("Exchange endpoint",
//! "Signing") and the official Python SDK (`hyperliquid/utils/signing.py`,
//! [SDK signing tests](https://github.com/hyperliquid-dex/hyperliquid-python-sdk/blob/master/tests/signing_test.py),
//! `hyperliquid/exchange.py`) on 6 Oct 2026:
//!
//! - **The REST URL:** `https://api.hyperliquid.xyz` against
//!   `https://api.hyperliquid-testnet.xyz` ([`Network::rest_url`]).
//! - **L1 actions** (orders, cancels, `updateLeverage`: everything this
//!   crate signs): the EIP-712 domain is the same on both (`Exchange`,
//!   version `1`, chain id 1337, verifying contract zero); only the phantom
//!   agent's `source` differs, `"a"` on mainnet and `"b"` on testnet
//!   (`construct_phantom_agent`). The SDK's own vectors for both halves are
//!   pinned in Guard's signing tests, so a testnet signature can never be sent to
//!   mainnet or the other way round: the venue would recover another signer.
//! - **User-signed actions** (`usdSend`, `withdraw3`, `approveAgent` and
//!   the like): the `hyperliquidChain` field is `"Mainnet"` or `"Testnet"`
//!   ([`VenueNetwork::hyperliquid_chain`]). Their EIP-712 domain
//!   (`HyperliquidSignTransaction`) takes its chain id from the action's
//!   `signatureChainId`, which names the chain of the signing wallet, not
//!   the Hyperliquid network: the docs give `0xa4b1` (Arbitrum) as an
//!   example, and the Python SDK sends `0x66eee` on both networks
//!   (`sign_user_signed_action`). **This crate signs no user-signed action
//!   and has no code for one**: they move funds or approve keys, which is
//!   the account owner's business, and an API wallet cannot sign them.
//!   The chain name is kept here so that the difference is written down in
//!   one place, with a test.

use std::fmt;

use super::{Network, address::Address};
use crate::error::ExecError;

/// The environment variable a person sets, to the address of the account,
/// to allow mainnet for one start of the process.
pub const CONFIRM_VAR: &str = "ZUNDER_MAINNET_CONFIRM";

/// The network an executor trades on. Testnet is free to choose; mainnet
/// needs a [`MainnetConsent`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VenueNetwork {
    network: Network,
    /// For mainnet: the only account the executor may trade for.
    account: Option<Address>,
}

impl fmt::Debug for VenueNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VenueNetwork({:?})", self.network)
    }
}

impl VenueNetwork {
    /// Hyperliquid testnet.
    pub const fn testnet() -> Self {
        Self {
            network: Network::Testnet,
            account: None,
        }
    }

    /// Hyperliquid mainnet, for the account `consent` names only.
    pub const fn mainnet(consent: MainnetConsent) -> Self {
        Self {
            network: Network::Mainnet,
            account: Some(consent.account),
        }
    }

    /// The choice for `network`: testnet always, mainnet only with
    /// `consent`. Mainnet without one is [`ExecError::MainnetRefused`].
    pub fn new(network: Network, consent: Option<MainnetConsent>) -> Result<Self, ExecError> {
        match (network, consent) {
            (Network::Testnet, None) => Ok(Self::testnet()),
            (Network::Mainnet, Some(consent)) => Ok(Self::mainnet(consent)),
            (Network::Mainnet, None) => Err(ExecError::MainnetRefused),
            // A consent is never given for testnet: refusing keeps a mixed
            // up caller from carrying one around.
            (Network::Testnet, Some(_)) => Err(ExecError::Config(
                "a mainnet consent was given for testnet".into(),
            )),
        }
    }

    pub const fn network(self) -> Network {
        self.network
    }

    pub const fn is_mainnet(self) -> bool {
        matches!(self.network, Network::Mainnet)
    }

    /// Base URL of the REST API of this network.
    pub const fn rest_url(self) -> &'static str {
        self.network.rest_url()
    }

    /// The phantom agent's `source` in an L1 action signature.
    pub const fn phantom_agent_source(self) -> &'static str {
        match self.network {
            Network::Mainnet => "a",
            Network::Testnet => "b",
        }
    }

    /// The `hyperliquidChain` field of a user-signed action on this
    /// network. Not used: see the module documentation.
    pub const fn hyperliquid_chain(self) -> &'static str {
        match self.network {
            Network::Mainnet => "Mainnet",
            Network::Testnet => "Testnet",
        }
    }

    /// Refuse to trade for `account` on mainnet unless the consent named
    /// it.
    pub fn check_account(self, account: Address) -> Result<(), ExecError> {
        match self.account {
            Some(allowed) if allowed != account => Err(ExecError::Config(format!(
                "the mainnet consent is for account {allowed}, not {account}"
            ))),
            _ => Ok(()),
        }
    }
}

/// A person's go-ahead to trade one account on Hyperliquid mainnet (hard
/// rule 1), as read at this start of the process. Outside this crate only
/// [`MainnetConsent::from_env`] makes one; it cannot be cloned,
/// deserialised or built any other way.
#[derive(PartialEq, Eq)]
pub struct MainnetConsent {
    account: Address,
}

impl fmt::Debug for MainnetConsent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MainnetConsent({})", self.account)
    }
}

impl MainnetConsent {
    /// The consent to trade `account` on mainnet, when `confirmation` (the
    /// value of [`CONFIRM_VAR`]) is that account's address. Missing, empty,
    /// malformed or naming another address: refused.
    pub(crate) fn confirm(account: Address, confirmation: Option<&str>) -> Result<Self, ExecError> {
        let Some(confirmation) = confirmation.map(str::trim).filter(|text| !text.is_empty()) else {
            return Err(ExecError::Config(format!(
                "mainnet needs {CONFIRM_VAR} set to the account's address ({account}) at start: a person's confirmation for this start (https://zunderlabs.com/docs/deploy/ssh/, \"Mainnet\")"
            )));
        };
        match Address::from_hex(confirmation) {
            Some(confirmed) if confirmed == account => Ok(Self { account }),
            Some(confirmed) => Err(ExecError::Config(format!(
                "{CONFIRM_VAR} names {confirmed}, but the account to trade is {account}"
            ))),
            None => Err(ExecError::Config(format!(
                "{CONFIRM_VAR} must be the account's address, 0x and 40 hex digits"
            ))),
        }
    }

    /// `MainnetConsent::confirm` for tests outside this crate, which
    /// cannot set [`CONFIRM_VAR`] (`set_var` is unsafe, and unsafe code is
    /// forbidden). Only with the `test-hooks` feature, which only
    /// dev-dependencies enable; never in a release build.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn confirm_for_tests(
        account: Address,
        confirmation: Option<&str>,
    ) -> Result<Self, ExecError> {
        Self::confirm(account, confirmation)
    }

    /// The consent from the environment: [`CONFIRM_VAR`] read now.
    pub fn from_env(account: Address) -> Result<Self, ExecError> {
        let value = std::env::var(CONFIRM_VAR).ok();
        Self::confirm(account, value.as_deref())
    }

    /// The account this consent is for.
    pub fn account(&self) -> Address {
        self.account
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
    const OTHER: &str = "0x0000000000000000000000000000000000000001";

    fn account() -> Address {
        Address::from_hex(ACCOUNT).unwrap()
    }

    #[test]
    fn mainnet_is_refused_without_a_consent() {
        assert_eq!(
            VenueNetwork::new(Network::Mainnet, None),
            Err(ExecError::MainnetRefused)
        );
        assert_eq!(
            VenueNetwork::new(Network::Testnet, None),
            Ok(VenueNetwork::testnet())
        );
    }

    #[test]
    fn a_consent_needs_the_confirmation_to_name_the_account() {
        for refused in [
            None,
            Some(""),
            Some("  "),
            Some("yes"),
            Some("0x1234"),
            Some(OTHER),
        ] {
            assert!(
                MainnetConsent::confirm(account(), refused).is_err(),
                "{refused:?}"
            );
        }
        let consent = MainnetConsent::confirm(account(), Some(ACCOUNT)).unwrap();
        assert_eq!(consent.account(), account());
        // Case and surrounding whitespace do not matter; the address does.
        let upper = format!(" 0x{} \n", ACCOUNT[2..].to_uppercase());
        assert!(MainnetConsent::confirm(account(), Some(&upper)).is_ok());
    }

    #[test]
    fn a_consent_is_not_accepted_for_testnet() {
        let consent = MainnetConsent::confirm(account(), Some(ACCOUNT)).unwrap();
        assert!(matches!(
            VenueNetwork::new(Network::Testnet, Some(consent)),
            Err(ExecError::Config(_))
        ));
    }

    #[test]
    fn a_mainnet_choice_trades_only_the_confirmed_account() {
        let consent = MainnetConsent::confirm(account(), Some(ACCOUNT)).unwrap();
        let mainnet = VenueNetwork::new(Network::Mainnet, Some(consent)).unwrap();
        assert!(mainnet.check_account(account()).is_ok());
        assert!(
            mainnet
                .check_account(Address::from_hex(OTHER).unwrap())
                .is_err()
        );
        // Testnet names no account.
        assert!(
            VenueNetwork::testnet()
                .check_account(Address::from_hex(OTHER).unwrap())
                .is_ok()
        );
    }

    #[test]
    fn each_network_has_its_own_url_source_and_chain_name() {
        let consent = MainnetConsent::confirm(account(), Some(ACCOUNT)).unwrap();
        let mainnet = VenueNetwork::mainnet(consent);
        let testnet = VenueNetwork::testnet();
        // Pinned here so that a change to `Network` cannot move the
        // executor without this test noticing.
        assert_eq!(testnet.rest_url(), "https://api.hyperliquid-testnet.xyz");
        assert_eq!(mainnet.rest_url(), "https://api.hyperliquid.xyz");
        // construct_phantom_agent in the Python SDK's signing.py.
        assert_eq!(testnet.phantom_agent_source(), "b");
        assert_eq!(mainnet.phantom_agent_source(), "a");
        // sign_user_signed_action in the same file, and the exchange
        // endpoint's docs ("Mainnet", on testnet "Testnet").
        assert_eq!(testnet.hyperliquid_chain(), "Testnet");
        assert_eq!(mainnet.hyperliquid_chain(), "Mainnet");
        assert!(mainnet.is_mainnet());
        assert!(!testnet.is_mainnet());
    }
}
