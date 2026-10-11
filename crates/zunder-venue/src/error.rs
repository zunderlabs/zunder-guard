// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! What can go wrong between the session and a venue.

use thiserror::Error;
use zunder_core::Symbol;

use crate::hyperliquid::KeyError;

/// Errors from an executor, and from the venue types it is built from.
///
/// The variants that matter most for safety are the network ones:
/// [`ExecError::Transport`] means the request never reached the venue, so
/// nothing happened; [`ExecError::OutcomeUnknown`] means it may have, and the
/// caller has to look at the venue before doing anything else. No message
/// ever contains key material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExecError {
    #[error(
        "refusing Hyperliquid mainnet: it needs a person's consent for this start (allow_mainnet in the config and ZUNDER_MAINNET_CONFIRM naming the account; https://zunderlabs.com/docs/deploy/ssh/, \"Mainnet\"), and keys from the environment are for testnet only"
    )]
    MainnetRefused,
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error("configuration: {0}")]
    Config(String),
    #[error(
        "the trading key {agent} is not an API wallet approved by account {account}: the venue gives its role as `{role}`"
    )]
    NotAnApiWallet {
        agent: String,
        account: String,
        role: String,
    },
    #[error("unknown instrument {0}")]
    UnknownSymbol(Symbol),
    #[error("invalid order: {0}")]
    InvalidOrder(String),
    #[error("the request did not reach the venue: {0}")]
    Transport(String),
    #[error("the venue may or may not have executed the request: {0}")]
    OutcomeUnknown(String),
    #[error("the venue refused the request: {0}")]
    Venue(String),
    #[error("unexpected response from the venue: {0}")]
    Malformed(String),
}
