// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! MCP server for guarded trading tools on Hyperliquid through a local
//! Zunder Guard. Supports local MCP clients, including Cursor, LangGraph
//! and the OpenAI Agents SDK.
//! See `docs/guard-mcp.md`.
//!
//! The server holds no API wallet key and never talks to Hyperliquid
//! itself. It talks only to a Guard on this machine ([`guard`]), through
//! Guard's public contract: Hyperliquid's own `/info` and `/exchange`
//! formats, with requests signed by a Guard-issued client key as the
//! official SDK signs ([`sign`]), and Guard's read-only status and events.
//! Every assumption about that contract lives in [`contract`].
//!
//! Where each guarantee is enforced:
//!
//! - **The limits**: by Guard, on every request, whatever this server
//!   sends. This server cannot change them; it has no code path that could.
//! - **Which actions exist**: by type ([`sign::Action`]: order, cancel,
//!   modify) and by the tool list ([`tools`]): nine tools, none that moves
//!   funds, changes limits or leverage, resumes, or sends a raw action.
//! - **Arguments**: strict schemas, checked again on the server
//!   ([`schema`]); absurd prices and sizes refused ([`preview`]).
//! - **Stops only tighten**: here before sending (`move_stop`) and by
//!   Guard.
//! - **Which Guard and which network**: a loopback URL only, a status that
//!   is Guard's, Guard's mode equal to the configured network, and this
//!   server's client key among Guard's clients, before anything is sent.
//! - **What the agent reads**: reasons in this server's own words;
//!   anything from Guard or the venue only as short quoted data
//!   ([`sanitize`]).
//! - **How fast**: token buckets on tool calls ([`ratelimit`]).

pub mod cli;
pub mod contract;
pub mod guard;
pub mod key;
pub mod preview;
pub mod protocol;
pub mod ratelimit;
pub mod sanitize;
pub mod schema;
pub mod sign;
pub mod tools;
pub mod venue;
