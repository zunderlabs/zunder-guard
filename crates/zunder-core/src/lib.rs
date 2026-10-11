// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Domain types and the strategy interface shared by every Zunder crate.
//!
//! This crate does no I/O and knows nothing about any venue. Everything that
//! touches money uses [`Decimal`]; `f64` is for statistics only.

pub mod account;
pub mod market;
pub mod order;
pub mod strategy;
pub mod time;

pub use account::{Account, Position};
pub use market::{
    Candle, FundingRate, NOT_TRADING_AFTER_MS, QuietRuns, Symbol, traded_until, trading_stretches,
};
pub use order::{Fill, Intent, Liquidity, Side};
pub use rust_decimal::Decimal;
pub use strategy::{
    BasketContext, BasketIntent, BasketStrategy, Member, Strategy, StrategyContext,
};
pub use time::Timestamp;
