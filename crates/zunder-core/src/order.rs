// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! What strategies ask for and what venues report back.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::{market::Symbol, time::Timestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    /// `+1` for buy, `-1` for sell.
    pub const fn sign(self) -> Decimal {
        match self {
            Side::Buy => Decimal::ONE,
            Side::Sell => Decimal::NEGATIVE_ONE,
        }
    }

    pub const fn opposite(self) -> Self {
        match self {
            Side::Buy => Side::Sell,
            Side::Sell => Side::Buy,
        }
    }

    /// Whether a stop at `new` is tighter than one at `current` for a
    /// position on this side: higher for a long, lower for a short. Equal is
    /// not tighter. Stops only tighten, so this is the one comparison every
    /// stop move goes through.
    pub fn tightens(self, new: Decimal, current: Decimal) -> bool {
        match self {
            Side::Buy => new > current,
            Side::Sell => new < current,
        }
    }
}

/// Whether a fill added liquidity to the book or took it. Decides the fee rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Liquidity {
    Maker,
    Taker,
}

/// An execution reported by a venue, real or simulated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fill {
    pub ts: Timestamp,
    pub symbol: Symbol,
    pub side: Side,
    /// Always positive; direction is in `side`.
    pub qty: Decimal,
    pub price: Decimal,
    /// Fee paid in quote currency. Never negative yet (no maker rebates).
    pub fee: Decimal,
    pub liquidity: Liquidity,
}

/// What a strategy asks for.
///
/// Strategies never choose a quantity. The risk engine sizes every entry from
/// the distance between entry price and `stop`, and it can refuse the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Intent {
    /// Open a position at the next opportunity, protected by `stop`.
    Enter { side: Side, stop: Decimal },
    /// Close the whole position at the next opportunity.
    Exit,
    /// Tighten the protective stop. A request that would loosen it is ignored.
    MoveStop { stop: Decimal },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_opposite_agree() {
        assert_eq!(Side::Buy.sign(), Decimal::ONE);
        assert_eq!(Side::Sell.sign(), Decimal::NEGATIVE_ONE);
        assert_eq!(Side::Buy.opposite(), Side::Sell);
        assert_eq!(Side::Sell.opposite().sign(), Decimal::ONE);
    }

    #[test]
    fn a_stop_tightens_towards_the_price_and_never_when_equal() {
        let (low, high) = (Decimal::from(95), Decimal::from(96));
        // A long's stop tightens upwards, a short's downwards.
        assert!(Side::Buy.tightens(high, low));
        assert!(!Side::Buy.tightens(low, high));
        assert!(Side::Sell.tightens(low, high));
        assert!(!Side::Sell.tightens(high, low));
        assert!(!Side::Buy.tightens(low, low));
        assert!(!Side::Sell.tightens(low, low));
    }
}
