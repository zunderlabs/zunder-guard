// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The engine's own record of open positions, and how it is compared with
//! the venue's.
//!
//! The engine records every position the session opens through it, with
//! its stop. When it sizes an entry it measures open risk and position
//! value from that record and from the venue's, symbol by symbol, and the
//! larger of the two counts. Wherever the two records disagree, the
//! disagreement is reported. Backtests never record positions here, so for
//! them nothing changes: their callers pass open risk and value as before.
//!
//! Open risk of one position is its quantity times the distance from the
//! current reference price to its stop; its value is the quantity times the
//! reference price. A position without a stop, or with the price at or
//! through its stop, has no bounded risk: nothing can be sized next to it.

use std::collections::HashMap;

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use zunder_core::{Side, Symbol};

use crate::engine::Veto;

/// A position as the engine recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackedPosition {
    pub symbol: Symbol,
    /// `Buy` for a long, `Sell` for a short.
    pub side: Side,
    /// Always positive.
    pub qty: Decimal,
    /// Average entry price.
    pub entry: Decimal,
    /// The protective stop. `None` when no stop is known to protect it.
    pub stop: Option<Decimal>,
    /// The last reference price the engine was shown for the instrument.
    /// Used only when no fresher price is at hand.
    pub mark: Decimal,
}

/// A position as the venue shows it, with the protective stop that rests
/// there for it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VenuePosition {
    pub symbol: Symbol,
    pub side: Side,
    /// Always positive.
    pub qty: Decimal,
    pub entry: Decimal,
    /// Trigger of a protective stop that rests on the venue and covers the
    /// whole position; `None` when there is none.
    pub stop: Option<Decimal>,
}

/// The venue's side of the comparison: its positions, and current
/// reference prices for its positions and for the ones the engine records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VenueView {
    pub positions: Vec<VenuePosition>,
    pub marks: HashMap<Symbol, Decimal>,
}

/// Where the engine's record and the venue disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "discrepancy")]
pub enum PositionDiscrepancy {
    /// The venue holds a position the engine has no record of.
    NotInBook {
        symbol: Symbol,
        side: Side,
        qty: Decimal,
    },
    /// The engine records a position the venue does not show.
    NotOnVenue {
        symbol: Symbol,
        side: Side,
        qty: Decimal,
    },
    SideDiffers {
        symbol: Symbol,
        book: Side,
        venue: Side,
    },
    QtyDiffers {
        symbol: Symbol,
        book: Decimal,
        venue: Decimal,
    },
    StopDiffers {
        symbol: Symbol,
        book: Option<Decimal>,
        venue: Option<Decimal>,
    },
}

/// Open risk and position value, in quote currency.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Exposure {
    /// What equity loses if every position is stopped out at its stop now.
    pub risk: Decimal,
    /// Value of all positions at the reference price.
    pub notional: Decimal,
}

/// Exposure measured from both records, the larger counting per symbol.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CombinedExposure {
    pub exposure: Exposure,
    pub discrepancies: Vec<PositionDiscrepancy>,
}

/// Open risk and value of one position at `mark`.
pub(crate) fn position_exposure(
    side: Side,
    qty: Decimal,
    stop: Option<Decimal>,
    mark: Decimal,
) -> Result<Exposure, Veto> {
    if qty <= Decimal::ZERO || mark <= Decimal::ZERO {
        return Err(Veto::InvalidRequest);
    }
    let Some(stop) = stop else {
        return Err(Veto::UnprotectedPosition);
    };
    let distance = match side {
        Side::Buy => mark.checked_sub(stop),
        Side::Sell => stop.checked_sub(mark),
    }
    .ok_or(Veto::Overflow)?;
    if distance <= Decimal::ZERO {
        // The stop should have executed: its risk is not bounded by it.
        return Err(Veto::UnprotectedPosition);
    }
    Ok(Exposure {
        risk: qty.checked_mul(distance).ok_or(Veto::Overflow)?,
        notional: qty.checked_mul(mark).ok_or(Veto::Overflow)?,
    })
}

impl Exposure {
    pub(crate) fn add(self, other: Exposure) -> Result<Exposure, Veto> {
        Ok(Exposure {
            risk: self.risk.checked_add(other.risk).ok_or(Veto::Overflow)?,
            notional: self
                .notional
                .checked_add(other.notional)
                .ok_or(Veto::Overflow)?,
        })
    }

    fn max(self, other: Exposure) -> Exposure {
        Exposure {
            risk: self.risk.max(other.risk),
            notional: self.notional.max(other.notional),
        }
    }
}

/// The stop with the larger risk: the one further from the price. `None`
/// (no stop) is the loosest of all.
pub(crate) fn looser_stop(side: Side, a: Option<Decimal>, b: Option<Decimal>) -> Option<Decimal> {
    match (a, b) {
        (Some(a), Some(b)) => Some(match side {
            Side::Buy => a.min(b),
            Side::Sell => a.max(b),
        }),
        _ => None,
    }
}

/// Every symbol either record holds, sorted by name so that reports come
/// out in a stable order.
pub(crate) fn symbols(book: &[TrackedPosition], view: &VenueView) -> Vec<Symbol> {
    let mut all: Vec<Symbol> = book
        .iter()
        .map(|position| position.symbol.clone())
        .chain(
            view.positions
                .iter()
                .map(|position| position.symbol.clone()),
        )
        .collect();
    all.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    all.dedup();
    all
}

/// The discrepancies between one recorded position and the venue's.
pub(crate) fn compare(
    symbol: &Symbol,
    book: Option<&TrackedPosition>,
    venue: Option<&VenuePosition>,
) -> Vec<PositionDiscrepancy> {
    match (book, venue) {
        (None, None) => Vec::new(),
        (None, Some(venue)) => vec![PositionDiscrepancy::NotInBook {
            symbol: symbol.clone(),
            side: venue.side,
            qty: venue.qty,
        }],
        (Some(book), None) => vec![PositionDiscrepancy::NotOnVenue {
            symbol: symbol.clone(),
            side: book.side,
            qty: book.qty,
        }],
        (Some(book), Some(venue)) if book.side != venue.side => {
            vec![PositionDiscrepancy::SideDiffers {
                symbol: symbol.clone(),
                book: book.side,
                venue: venue.side,
            }]
        }
        (Some(book), Some(venue)) => {
            let mut found = Vec::new();
            if book.qty != venue.qty {
                found.push(PositionDiscrepancy::QtyDiffers {
                    symbol: symbol.clone(),
                    book: book.qty,
                    venue: venue.qty,
                });
            }
            if book.stop != venue.stop {
                found.push(PositionDiscrepancy::StopDiffers {
                    symbol: symbol.clone(),
                    book: book.stop,
                    venue: venue.stop,
                });
            }
            found
        }
    }
}

/// Exposure of both records combined: per symbol, the larger risk and the
/// larger value of the two, each measured at the same, freshest price.
pub(crate) fn combined(
    book: &[TrackedPosition],
    view: &VenueView,
) -> Result<CombinedExposure, Veto> {
    let mut total = CombinedExposure::default();
    for symbol in symbols(book, view) {
        let recorded = book.iter().find(|position| position.symbol == symbol);
        let shown = view
            .positions
            .iter()
            .find(|position| position.symbol == symbol);
        let mark = match (view.marks.get(&symbol), recorded) {
            (Some(mark), _) => *mark,
            // Only the engine's record holds it: its last known price.
            (None, Some(recorded)) if shown.is_none() => recorded.mark,
            // A position on the venue needs a current price.
            _ => return Err(Veto::InvalidRequest),
        };
        let from_book = recorded
            .map(|position| position_exposure(position.side, position.qty, position.stop, mark))
            .transpose()?;
        let from_venue = shown
            .map(|position| position_exposure(position.side, position.qty, position.stop, mark))
            .transpose()?;
        let larger = match (from_book, from_venue) {
            (Some(book), Some(venue)) => book.max(venue),
            (Some(one), None) | (None, Some(one)) => one,
            (None, None) => Exposure::default(),
        };
        total.exposure = total.exposure.add(larger)?;
        total
            .discrepancies
            .extend(compare(&symbol, recorded, shown));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use rust_decimal::dec;

    use super::*;

    #[test]
    fn exposure_of_one_position_is_the_distance_to_the_stop() {
        // Long 2 at a mark of 105 with the stop at 98: 2 x 7 = 14 at risk,
        // 2 x 105 = 210 of value.
        assert_eq!(
            position_exposure(Side::Buy, dec!(2), Some(dec!(98)), dec!(105)),
            Ok(Exposure {
                risk: dec!(14),
                notional: dec!(210)
            })
        );
        // Short 3 at 50 with the stop at 52: 3 x 2 = 6, value 150.
        assert_eq!(
            position_exposure(Side::Sell, dec!(3), Some(dec!(52)), dec!(50)),
            Ok(Exposure {
                risk: dec!(6),
                notional: dec!(150)
            })
        );
    }

    #[test]
    fn a_position_without_a_stop_or_through_it_is_unprotected() {
        assert_eq!(
            position_exposure(Side::Buy, dec!(1), None, dec!(100)),
            Err(Veto::UnprotectedPosition)
        );
        assert_eq!(
            position_exposure(Side::Buy, dec!(1), Some(dec!(100)), dec!(100)),
            Err(Veto::UnprotectedPosition)
        );
        assert_eq!(
            position_exposure(Side::Sell, dec!(1), Some(dec!(99)), dec!(100)),
            Err(Veto::UnprotectedPosition)
        );
    }

    #[test]
    fn the_looser_stop_is_further_from_the_price() {
        assert_eq!(
            looser_stop(Side::Buy, Some(dec!(98)), Some(dec!(97))),
            Some(dec!(97))
        );
        assert_eq!(
            looser_stop(Side::Sell, Some(dec!(102)), Some(dec!(103))),
            Some(dec!(103))
        );
        assert_eq!(looser_stop(Side::Buy, Some(dec!(98)), None), None);
    }
}
