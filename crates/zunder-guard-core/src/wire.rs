// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Values in the exact shape Hyperliquid hashes and accepts:
//! `zunder-hl-protocol`'s [`Wire`], the one MessagePack and JSON encoding
//! that Zunder's executor, Guard and its MCP server share, and its
//! `/exchange` request body. Hyperliquid hashes an action's MessagePack in
//! its own typed field order; the action model ([`crate::action`],
//! `zunder-hl-protocol`'s) encodes every action in that order whatever
//! order a bot's JSON used.
//!
//! Re-exported at this path for `zunder-guard`.

pub use zunder_hl_protocol::{TooLarge, Wire, action::exchange_request, wire::minimal_hex};
