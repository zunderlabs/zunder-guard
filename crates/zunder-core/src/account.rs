// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Position and cash bookkeeping for one margin account.

use std::collections::HashMap;

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::{
    market::Symbol,
    order::{Fill, Side},
};

/// A net position in one instrument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    /// Signed quantity: positive is long, negative is short. Never zero.
    pub qty: Decimal,
    /// Average entry price of the open quantity.
    pub entry: Decimal,
}

impl Position {
    /// The side that opened this position: `Buy` for a long, `Sell` for a short.
    pub fn side(&self) -> Side {
        if self.qty.is_sign_negative() {
            Side::Sell
        } else {
            Side::Buy
        }
    }

    /// Position value at `mark`, always positive.
    pub fn notional(&self, mark: Decimal) -> Decimal {
        self.qty.abs() * mark
    }

    /// Profit or loss that closing at `mark` would realise, before fees.
    pub fn unrealized(&self, mark: Decimal) -> Decimal {
        self.qty * (mark - self.entry)
    }
}

/// Cash and positions of one margin account, in quote currency (USDC on Hyperliquid).
///
/// The account only records what happened. It does not check margin and it
/// does not refuse anything: limits are the risk engine's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    cash: Decimal,
    positions: HashMap<Symbol, Position>,
    realized: Decimal,
    fees: Decimal,
    funding: Decimal,
}

impl Account {
    pub fn new(cash: Decimal) -> Self {
        Self {
            cash,
            positions: HashMap::new(),
            realized: Decimal::ZERO,
            fees: Decimal::ZERO,
            funding: Decimal::ZERO,
        }
    }

    /// Deposits plus realised PnL, minus fees and funding. Excludes unrealised PnL.
    pub fn cash(&self) -> Decimal {
        self.cash
    }

    /// The open position in `symbol`, or `None` when flat.
    pub fn position(&self, symbol: &Symbol) -> Option<&Position> {
        self.positions.get(symbol)
    }

    pub fn positions(&self) -> impl Iterator<Item = (&Symbol, &Position)> {
        self.positions.iter()
    }

    /// Gross realised PnL so far, before fees and funding.
    pub fn realized(&self) -> Decimal {
        self.realized
    }

    pub fn fees_paid(&self) -> Decimal {
        self.fees
    }

    /// Net funding paid so far. Negative when more was received than paid.
    pub fn funding_paid(&self) -> Decimal {
        self.funding
    }

    /// Cash plus unrealised PnL, with each position valued at `mark(symbol)`.
    pub fn equity(&self, mark: impl Fn(&Symbol) -> Decimal) -> Decimal {
        self.positions
            .iter()
            .fold(self.cash, |equity, (symbol, position)| {
                equity + position.unrealized(mark(symbol))
            })
    }

    /// Book a fill. Returns the gross PnL it realised (zero when it opened or added).
    ///
    /// A fill larger than the open position closes it and opens the remainder
    /// in the other direction at the fill price.
    pub fn apply_fill(&mut self, fill: &Fill) -> Decimal {
        if fill.qty <= Decimal::ZERO {
            // Not a real execution. Leave the position alone, but book the
            // fee so that nothing a venue charged goes missing.
            self.fees += fill.fee;
            self.cash -= fill.fee;
            return Decimal::ZERO;
        }

        let delta = fill.qty * fill.side.sign();
        let (next, realized) = match self.positions.get(&fill.symbol).copied() {
            None => (
                Some(Position {
                    qty: delta,
                    entry: fill.price,
                }),
                Decimal::ZERO,
            ),
            Some(open) if open.side() == fill.side => {
                let qty = open.qty + delta;
                let entry = (open.entry * open.qty.abs() + fill.price * fill.qty) / qty.abs();
                (Some(Position { qty, entry }), Decimal::ZERO)
            }
            Some(open) => {
                let closed = fill.qty.min(open.qty.abs());
                let realized = closed * (fill.price - open.entry) * open.side().sign();
                let qty = open.qty + delta;
                let next = if qty.is_zero() {
                    None
                } else if qty.is_sign_negative() == open.qty.is_sign_negative() {
                    Some(Position {
                        qty,
                        entry: open.entry,
                    })
                } else {
                    Some(Position {
                        qty,
                        entry: fill.price,
                    })
                };
                (next, realized)
            }
        };

        match next {
            Some(position) => {
                self.positions.insert(fill.symbol.clone(), position);
            }
            None => {
                self.positions.remove(&fill.symbol);
            }
        }
        self.realized += realized;
        self.fees += fill.fee;
        self.cash += realized - fill.fee;
        realized
    }

    /// Book a funding payment. Positive `amount` is paid, negative is received.
    pub fn pay_funding(&mut self, amount: Decimal) {
        self.funding += amount;
        self.cash -= amount;
    }
}

#[cfg(test)]
mod tests {
    use rust_decimal::dec;

    use super::*;
    use crate::{order::Liquidity, time::Timestamp};

    fn fill(side: Side, qty: Decimal, price: Decimal, fee: Decimal) -> Fill {
        Fill {
            ts: Timestamp::from_millis(0),
            symbol: Symbol::new("BTC"),
            side,
            qty,
            price,
            fee,
            liquidity: Liquidity::Taker,
        }
    }

    fn btc() -> Symbol {
        Symbol::new("BTC")
    }

    #[test]
    fn opening_a_long_costs_only_the_fee() {
        let mut account = Account::new(dec!(2000));
        let realized = account.apply_fill(&fill(Side::Buy, dec!(2), dec!(100), dec!(0.09)));

        assert_eq!(realized, dec!(0));
        assert_eq!(account.cash(), dec!(1999.91));
        assert_eq!(
            account.position(&btc()),
            Some(&Position {
                qty: dec!(2),
                entry: dec!(100)
            })
        );
        // Marked at the entry price, equity is down by exactly the fee.
        assert_eq!(account.equity(|_| dec!(100)), dec!(1999.91));
        assert_eq!(account.equity(|_| dec!(110)), dec!(2019.91));
    }

    #[test]
    fn adding_averages_the_entry_price() {
        let mut account = Account::new(dec!(2000));
        account.apply_fill(&fill(Side::Buy, dec!(1), dec!(100), dec!(0)));
        account.apply_fill(&fill(Side::Buy, dec!(3), dec!(108), dec!(0)));

        assert_eq!(
            account.position(&btc()),
            Some(&Position {
                qty: dec!(4),
                entry: dec!(106)
            })
        );
    }

    #[test]
    fn partial_close_realises_pnl_and_keeps_the_entry() {
        let mut account = Account::new(dec!(2000));
        account.apply_fill(&fill(Side::Buy, dec!(4), dec!(100), dec!(0)));
        let realized = account.apply_fill(&fill(Side::Sell, dec!(1), dec!(110), dec!(0.5)));

        assert_eq!(realized, dec!(10));
        assert_eq!(account.cash(), dec!(2009.5));
        assert_eq!(
            account.position(&btc()),
            Some(&Position {
                qty: dec!(3),
                entry: dec!(100)
            })
        );
        assert_eq!(account.realized(), dec!(10));
        assert_eq!(account.fees_paid(), dec!(0.5));
    }

    #[test]
    fn full_close_removes_the_position() {
        let mut account = Account::new(dec!(2000));
        account.apply_fill(&fill(Side::Buy, dec!(2), dec!(100), dec!(0)));
        let realized = account.apply_fill(&fill(Side::Sell, dec!(2), dec!(95), dec!(0)));

        assert_eq!(realized, dec!(-10));
        assert_eq!(account.position(&btc()), None);
        assert_eq!(account.cash(), dec!(1990));
        // Flat: equity no longer depends on the mark.
        assert_eq!(account.equity(|_| dec!(1)), dec!(1990));
    }

    #[test]
    fn short_profits_when_the_price_falls() {
        let mut account = Account::new(dec!(2000));
        account.apply_fill(&fill(Side::Sell, dec!(2), dec!(100), dec!(0)));
        assert_eq!(
            account.position(&btc()).map(Position::side),
            Some(Side::Sell)
        );
        assert_eq!(account.equity(|_| dec!(90)), dec!(2020));

        let realized = account.apply_fill(&fill(Side::Buy, dec!(2), dec!(90), dec!(0)));
        assert_eq!(realized, dec!(20));
        assert_eq!(account.cash(), dec!(2020));
    }

    #[test]
    fn oversized_fill_flips_the_position_at_the_fill_price() {
        let mut account = Account::new(dec!(2000));
        account.apply_fill(&fill(Side::Buy, dec!(2), dec!(100), dec!(0)));
        let realized = account.apply_fill(&fill(Side::Sell, dec!(5), dec!(104), dec!(0)));

        // Only the two units that were open are realised.
        assert_eq!(realized, dec!(8));
        assert_eq!(
            account.position(&btc()),
            Some(&Position {
                qty: dec!(-3),
                entry: dec!(104)
            })
        );
    }

    #[test]
    fn a_fill_without_quantity_changes_nothing_but_the_fee() {
        let mut account = Account::new(dec!(2000));
        let realized = account.apply_fill(&fill(Side::Buy, dec!(0), dec!(100), dec!(0.25)));

        assert_eq!(realized, dec!(0));
        assert_eq!(account.position(&btc()), None);
        assert_eq!(account.cash(), dec!(1999.75));
        assert_eq!(account.fees_paid(), dec!(0.25));
    }

    #[test]
    fn funding_moves_cash_in_both_directions() {
        let mut account = Account::new(dec!(2000));
        account.pay_funding(dec!(1.25));
        assert_eq!(account.cash(), dec!(1998.75));
        account.pay_funding(dec!(-0.25));
        assert_eq!(account.cash(), dec!(1999));
        assert_eq!(account.funding_paid(), dec!(1));
    }
}
