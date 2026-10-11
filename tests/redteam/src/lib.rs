// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Zunder Guard red-team suite (library).
//!
//! A black-box adversary for Zunder Guard. It talks to Guard only through
//! Guard's public interface — Hyperliquid's `/exchange` and `/info` over
//! HTTP, `post` over the WebSocket, and the read-only `/guard/*` endpoints —
//! and tries, in [`catalogue`], to make Guard break one of its own limits.
//! Every attack must be refused.
//!
//! The suite shares no code with `zunder-guard` or `zunder-guard-core`. Its
//! Hyperliquid signing ([`hlsign`]) is an independent second implementation,
//! pinned against the official Python SDK's signing vectors, so a bug in
//! Guard's signer cannot be hidden by a matching bug here.

pub mod actions;
pub mod catalogue;
pub mod hlsign;
pub mod mock;
pub mod pilot;
pub mod report;
pub mod runner;
pub mod target;

use std::time::{SystemTime, UNIX_EPOCH};

/// The throwaway client key the suite plays by default (the official
/// Python SDK's test key). A real run passes `--client-key` with the key
/// `zunder-guard init` issued.
pub const DEFAULT_CLIENT_KEY: &str =
    "0x0123456789012345678901234567890123456789012345678901234567890123";

/// A second key, never a Guard client, used to forge signatures.
pub const DEFAULT_ATTACKER_KEY: &str =
    "0x1111111111111111111111111111111111111111111111111111111111111111";

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
