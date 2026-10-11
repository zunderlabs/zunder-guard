// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The one interface every strategy implements.
//!
//! The same strategy code must run unchanged in backtest, paper, testnet and
//! live. So a strategy is a pure state machine: market data in, intents out.
//! It does no I/O, reads no clock and never sizes or places orders itself.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::{
    account::Position,
    market::{Candle, Symbol},
    order::Intent,
    time::Timestamp,
};

/// What the engine tells a strategy about its own state on each call.
#[derive(Debug, Clone, Copy)]
pub struct StrategyContext<'a> {
    pub symbol: &'a Symbol,
    /// The open position in `symbol`, or `None` when flat.
    pub position: Option<&'a Position>,
    /// The protective stop currently working for that position.
    pub stop: Option<Decimal>,
    /// Account equity marked at the close of the candle being delivered.
    pub equity: Decimal,
}

pub trait Strategy {
    /// Short stable name used in reports and logs.
    fn name(&self) -> &str;

    /// Called once per closed candle, oldest first.
    ///
    /// The strategy may use this candle and anything it stored from earlier
    /// calls. Returned intents are acted on at the next opportunity, which in
    /// a candle backtest is the next bar's open, never this bar's close.
    fn on_candle(&mut self, ctx: &StrategyContext<'_>, candle: &Candle) -> Vec<Intent>;
}

/// A boxed strategy is a strategy, so that runners can hold any strategy
/// chosen at run time.
impl<S: Strategy + ?Sized> Strategy for Box<S> {
    fn name(&self) -> &str {
        (**self).name()
    }

    fn on_candle(&mut self, ctx: &StrategyContext<'_>, candle: &Candle) -> Vec<Intent> {
        (**self).on_candle(ctx, candle)
    }
}

/// A borrowed strategy is a strategy, so that an engine can drive one its
/// caller keeps.
impl<S: Strategy + ?Sized> Strategy for &mut S {
    fn name(&self) -> &str {
        (**self).name()
    }

    fn on_candle(&mut self, ctx: &StrategyContext<'_>, candle: &Candle) -> Vec<Intent> {
        (**self).on_candle(ctx, candle)
    }
}

/// One instrument of a basket at a step: the candle of it that has just
/// closed, and the account's own state in it.
#[derive(Debug, Clone, Copy)]
pub struct Member<'a> {
    pub symbol: &'a Symbol,
    pub candle: &'a Candle,
    /// The open position in `symbol`, or `None` when flat.
    pub position: Option<&'a Position>,
    /// The protective stop currently working for that position.
    pub stop: Option<Decimal>,
}

/// What the engine shows a basket strategy at a step.
#[derive(Debug, Clone, Copy)]
pub struct BasketContext<'a> {
    /// Opening time of the bars that have just closed.
    pub ts: Timestamp,
    /// Account equity marked at this close.
    pub equity: Decimal,
    /// Every instrument whose bar opened at `ts` and has now closed, in
    /// byte order of symbol. Instruments without a bar at `ts` (not started
    /// yet, in a hole in their data, or finished) are not shown.
    pub members: &'a [Member<'a>],
}

/// An intent for one instrument of a basket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasketIntent {
    pub symbol: Symbol,
    pub intent: Intent,
}

impl BasketIntent {
    pub fn new(symbol: &Symbol, intent: Intent) -> Self {
        Self {
            symbol: symbol.clone(),
            intent,
        }
    }
}

/// A strategy that trades several instruments as one book: it sees the
/// closed candles of every instrument at a step together and may compare
/// them, for example to rank instruments against each other.
///
/// The rules of [`Strategy`] hold unchanged. It sees a candle only after it
/// closed, its intents are acted on at each instrument's next open, and it
/// names a side and a stop, never a quantity: the risk engine sizes every
/// entry against the shared equity and the other open positions.
pub trait BasketStrategy {
    /// Short stable name used in reports and logs.
    fn name(&self) -> &str;

    /// Called once per step, oldest first, with the instruments whose bars
    /// closed at that step.
    ///
    /// Intents may name only the instruments in `ctx.members`; an engine
    /// refuses any other. Each instrument's intents are acted on in the
    /// order returned, at that instrument's next open.
    fn on_bars(&mut self, ctx: &BasketContext<'_>) -> Vec<BasketIntent>;
}

impl<B: BasketStrategy + ?Sized> BasketStrategy for Box<B> {
    fn name(&self) -> &str {
        (**self).name()
    }

    fn on_bars(&mut self, ctx: &BasketContext<'_>) -> Vec<BasketIntent> {
        (**self).on_bars(ctx)
    }
}
