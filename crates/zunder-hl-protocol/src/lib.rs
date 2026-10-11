// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Hyperliquid's protocol rules, each implemented once, for every crate
//! that talks to the venue: Zunder's executor, Zunder Guard's core and its
//! MCP server, the venue foundations and the market-data client.
//!
//! - [`wire`]: an action as one [`Wire`] value, encoded as MessagePack for
//!   the signature and as JSON for the request, so that what is signed is
//!   what is sent.
//! - [`sign`]: the L1 action hash (`connectionId`), the phantom agent's
//!   EIP-712 digest, signing with a secp256k1 key the caller holds, and
//!   recovering a signer.
//! - [`Address`] and [`Network`]: accounts and wallets, mainnet and testnet.
//! - [`grid`]: the price grid (five significant figures, a decimal cap that
//!   depends on `szDecimals`) and the size grid, rounded in a [`Round`]
//!   direction.
//!
//! No I/O, no clock and no key storage: signing borrows a key the caller
//! keeps. Pinned against the official Python SDK's signing vectors
//! (`tests/sdk_vectors.rs`). Compiles to `wasm32-unknown-unknown` for the
//! browser Guard.

mod address;
pub mod grid;
mod network;
pub mod sign;
pub mod wire;

pub use address::Address;
pub use grid::{PriceGrid, Round};
pub use network::Network;
pub use sign::{SignError, Signature};
pub use wire::{TooLarge, Wire};
