// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The stop that covers a position, as one trigger for the engine.
//!
//! Stops placed with separate entries are each sized to their entry, so
//! several may protect one position together. As the price moves against
//! the position the tightest fires first and closes its size, then the
//! next: the loss is the sum over the stops, tightest first, of the size
//! each one closes times its distance. The covering stop is the
//! size-weighted average of those triggers, so that the position's size
//! times its distance to the price is exactly that loss. It is rounded to
//! 12 places towards the looser side, so that the risk measured from it is
//! never below the real one. A stop attached to the whole position (a
//! position TP/SL) covers whatever is left on its own. Stops that together
//! do not cover the whole position cover none of it: the rest would be
//! unbounded.
//!
//! Which orders count as protective stops is the caller's to decide; this
//! module only does the arithmetic, so that Guard and the website's judge
//! measure a position against its stops in exactly the same way.

use rust_decimal::{Decimal, RoundingStrategy};
use zunder_core::Side;

/// One protective stop, as the coverage counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverStop {
    pub trigger: Decimal,
    /// What it closes; `None` for a stop attached to the whole position,
    /// which closes whatever is left.
    pub size: Option<Decimal>,
    /// It covers only the first part ([`covering_parts`]): a stop placed
    /// for the position held before an entry never covers the entry.
    pub first_part_only: bool,
}

impl CoverStop {
    /// A stop that closes `size`.
    pub fn sized(trigger: Decimal, size: Decimal) -> Self {
        Self {
            trigger,
            size: Some(size),
            first_part_only: false,
        }
    }

    /// A stop attached to the whole position.
    pub fn whole(trigger: Decimal) -> Self {
        Self {
            trigger,
            size: None,
            first_part_only: false,
        }
    }
}

/// The stop covering a position of `qty` on `side` (`Buy` for a long):
/// `None` when `qty` is not positive or the stops do not cover it all, or
/// on overflow.
pub fn covering_stop(
    side: Side,
    qty: Decimal,
    stops: impl IntoIterator<Item = CoverStop>,
) -> Option<Decimal> {
    if qty <= Decimal::ZERO {
        return None;
    }
    covering_parts(side, &[qty], stops)?.first().copied()
}

/// The stops covering consecutive parts of one position on `side`
/// (`parts`, in order): each part's covering stop, or `None` when the
/// stops do not cover every part, or on overflow. A part that is not
/// positive gets a stop of zero and takes none.
///
/// The stops are taken first-part-only first, then the others, each group
/// tightest first (the highest trigger under a long, the lowest above a
/// short; equal triggers in the order given). Each part takes them in that
/// order until it is covered; a sized stop used up is gone, one partly used
/// covers the next part with what is left, and a stop attached to the
/// whole position stays for the next part too. A first-part-only stop is
/// skipped by every later part.
pub fn covering_parts(
    side: Side,
    parts: &[Decimal],
    stops: impl IntoIterator<Item = CoverStop>,
) -> Option<Vec<Decimal>> {
    let mut queue: Vec<CoverStop> = stops.into_iter().collect();
    queue.sort_by(|a, b| {
        let tighter = match side {
            Side::Buy => b.trigger.cmp(&a.trigger),
            Side::Sell => a.trigger.cmp(&b.trigger),
        };
        b.first_part_only.cmp(&a.first_part_only).then(tighter)
    });
    let strategy = match side {
        Side::Buy => RoundingStrategy::ToNegativeInfinity,
        Side::Sell => RoundingStrategy::ToPositiveInfinity,
    };
    let mut covers = Vec::with_capacity(parts.len());
    let mut next = 0;
    for (index, part) in parts.iter().copied().enumerate() {
        if part <= Decimal::ZERO {
            covers.push(Decimal::ZERO);
            continue;
        }
        let mut remaining = part;
        let mut weighted = Decimal::ZERO;
        while remaining > Decimal::ZERO {
            let stop = queue.get_mut(next)?;
            if stop.first_part_only && index > 0 {
                next += 1;
                continue;
            }
            let closes = stop.size.map_or(remaining, |left| left.min(remaining));
            weighted = weighted.checked_add(closes.checked_mul(stop.trigger)?)?;
            remaining = remaining.checked_sub(closes)?;
            // A sized stop used up is gone; one attached to the whole
            // position stays for the next part.
            if let Some(left) = stop.size.as_mut() {
                *left = left.checked_sub(closes)?;
                if left.is_zero() {
                    next += 1;
                }
            }
        }
        covers.push(
            weighted
                .checked_div(part)?
                .round_dp_with_strategy(12, strategy),
        );
    }
    Some(covers)
}

#[cfg(test)]
mod tests {
    use rust_decimal::dec;

    use super::*;

    #[test]
    fn several_sized_stops_cover_at_their_weighted_trigger() {
        // Long 1: 0.4 at 58,000 and 0.6 at 57,000, given loosest first, are
        // taken tightest first: (0.4 × 58,000 + 0.6 × 57,000) / 1 = 57,400.
        let stops = [
            CoverStop::sized(dec!(57000), dec!(0.6)),
            CoverStop::sized(dec!(58000), dec!(0.4)),
        ];
        assert_eq!(covering_stop(Side::Buy, dec!(1), stops), Some(dec!(57400)));
        // Short 2 under a stop for 1 at 110 and the whole position at 120:
        // (1 × 110 + 1 × 120) / 2 = 115.
        let stops = [
            CoverStop::whole(dec!(120)),
            CoverStop::sized(dec!(110), dec!(1)),
        ];
        assert_eq!(covering_stop(Side::Sell, dec!(2), stops), Some(dec!(115)));
    }

    #[test]
    fn stops_that_leave_part_uncovered_cover_nothing() {
        // 0.4 + 0.5 of a long of 1: 0.1 is unbounded.
        let stops = [
            CoverStop::sized(dec!(58000), dec!(0.4)),
            CoverStop::sized(dec!(57000), dec!(0.5)),
        ];
        assert_eq!(covering_stop(Side::Buy, dec!(1), stops), None);
        assert_eq!(covering_stop(Side::Buy, dec!(1), []), None);
        // No position, no stop.
        assert_eq!(
            covering_stop(Side::Buy, Decimal::ZERO, [CoverStop::whole(dec!(1))]),
            None
        );
    }

    #[test]
    fn the_average_rounds_towards_the_looser_side() {
        // Long 3: 1 at 100 and 2 at 99: 298 / 3 = 99.3333..., down to
        // 99.333333333333 for a long; the same as a short's stops, up.
        let stops = [
            CoverStop::sized(dec!(100), dec!(1)),
            CoverStop::sized(dec!(99), dec!(2)),
        ];
        assert_eq!(
            covering_stop(Side::Buy, dec!(3), stops),
            Some(dec!(99.333333333333))
        );
        let stops = [
            CoverStop::sized(dec!(99), dec!(1)),
            CoverStop::sized(dec!(100), dec!(2)),
        ];
        assert_eq!(
            covering_stop(Side::Sell, dec!(3), stops),
            Some(dec!(99.666666666667))
        );
    }

    #[test]
    fn parts_take_the_stops_in_turn_and_first_part_stops_stay_with_the_first() {
        // Long, 1 held before and 1 entered. The held part's own stop for 1
        // at 99 is first-part-only; the account's stop for 1.5 at 98 covers
        // nothing of the first part, which is covered, and 1 of the entry;
        // the entry is measured at 98, never at a blend with 99.
        let held_stop = CoverStop {
            first_part_only: true,
            ..CoverStop::sized(dec!(99), dec!(1))
        };
        let stops = [CoverStop::sized(dec!(98), dec!(1.5)), held_stop];
        assert_eq!(
            covering_parts(Side::Buy, &[dec!(1), dec!(1)], stops),
            Some(vec![dec!(99), dec!(98)])
        );
        // A first-part-only stop left over is skipped by the entry, which
        // is then not covered: 2 at 99 for the held part only.
        let held_stop = CoverStop {
            first_part_only: true,
            ..CoverStop::sized(dec!(99), dec!(2))
        };
        assert_eq!(
            covering_parts(Side::Buy, &[dec!(1), dec!(1)], [held_stop]),
            None
        );
        // A part of zero takes nothing; a whole-position stop covers every
        // part.
        assert_eq!(
            covering_parts(
                Side::Sell,
                &[Decimal::ZERO, dec!(2)],
                [CoverStop::whole(dec!(105))]
            ),
            Some(vec![Decimal::ZERO, dec!(105)])
        );
        // A sized stop partly used covers the next part with what is left:
        // 3 at 97 covers 1 of the first part and 1 of the second.
        assert_eq!(
            covering_parts(
                Side::Buy,
                &[dec!(1), dec!(1)],
                [CoverStop::sized(dec!(97), dec!(3))]
            ),
            Some(vec![dec!(97), dec!(97)])
        );
    }

    /// A small deterministic generator (xorshift64), so that the
    /// comparison below needs no dependency.
    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    /// One position's coverage the way it was written before it was shared:
    /// the stops `(trigger, size, whole)` sorted tightest first, then taken
    /// until the position is covered (Guard's own loop).
    fn reference_single(
        side: Side,
        qty: Decimal,
        stops: &[(Decimal, Decimal, bool)],
    ) -> Option<Decimal> {
        let mut stops = stops.to_vec();
        match side {
            Side::Buy => stops.sort_by_key(|stop| std::cmp::Reverse(stop.0)),
            Side::Sell => stops.sort_by_key(|stop| stop.0),
        }
        let mut remaining = qty;
        let mut weighted = Decimal::ZERO;
        for (trigger, size, whole) in stops {
            let closes = if whole {
                remaining
            } else {
                size.min(remaining)
            };
            weighted = weighted.checked_add(closes.checked_mul(trigger)?)?;
            remaining = remaining.checked_sub(closes)?;
            if remaining <= Decimal::ZERO {
                let strategy = match side {
                    Side::Buy => RoundingStrategy::ToNegativeInfinity,
                    Side::Sell => RoundingStrategy::ToPositiveInfinity,
                };
                return weighted
                    .checked_div(qty)
                    .map(|average| average.round_dp_with_strategy(12, strategy));
            }
        }
        None
    }

    /// The parts of a position the way they were written before: stops
    /// `(trigger, size or None, first part only)`, those for the first part
    /// only first, each group sorted tightest first, then a queue taken
    /// part by part (the website judge's loop).
    fn reference_parts(
        side: Side,
        parts: &[Decimal],
        stops: &[(Decimal, Option<Decimal>, bool)],
    ) -> Option<Vec<Decimal>> {
        let tightest_first = |stops: &mut Vec<(Decimal, Option<Decimal>, bool)>| match side {
            Side::Buy => stops.sort_by_key(|stop| std::cmp::Reverse(stop.0)),
            Side::Sell => stops.sort_by_key(|stop| stop.0),
        };
        let (mut firsts, mut others): (Vec<_>, Vec<_>) =
            stops.iter().copied().partition(|stop| stop.2);
        tightest_first(&mut firsts);
        tightest_first(&mut others);
        let mut queue = firsts;
        queue.extend(others);
        let strategy = match side {
            Side::Buy => RoundingStrategy::ToNegativeInfinity,
            Side::Sell => RoundingStrategy::ToPositiveInfinity,
        };
        let mut covers = Vec::new();
        let mut next = 0;
        for (index, part) in parts.iter().copied().enumerate() {
            if part <= Decimal::ZERO {
                covers.push(Decimal::ZERO);
                continue;
            }
            let mut remaining = part;
            let mut weighted = Decimal::ZERO;
            while remaining > Decimal::ZERO {
                let (trigger, left, first_only) = queue.get_mut(next)?;
                if *first_only && index > 0 {
                    next += 1;
                    continue;
                }
                let closes = left.map_or(remaining, |left| left.min(remaining));
                weighted = weighted.checked_add(closes.checked_mul(*trigger)?)?;
                remaining = remaining.checked_sub(closes)?;
                if let Some(left) = left {
                    *left = left.checked_sub(closes)?;
                    if left.is_zero() {
                        next += 1;
                    }
                }
            }
            covers.push(
                weighted
                    .checked_div(part)?
                    .round_dp_with_strategy(12, strategy),
            );
        }
        Some(covers)
    }

    #[test]
    fn property_the_shared_coverage_is_both_loops_it_replaced() {
        // Random positions and stops (ties, zero sizes, whole-position
        // stops, too few stops): the shared functions give exactly what the
        // two loops they replaced gave.
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let (mut covered, mut uncovered) = (0, 0);
        for case in 0..20_000 {
            let side = if rng.below(2) == 0 {
                Side::Buy
            } else {
                Side::Sell
            };
            let amount = |rng: &mut Rng| Decimal::new(rng.below(40) as i64, rng.below(3) as u32);
            let stops: Vec<(Decimal, Decimal, bool, bool)> = (0..rng.below(6))
                .map(|_| {
                    (
                        // Few distinct triggers, so that ties are common.
                        Decimal::new(9_000 + rng.below(12) as i64 * 50, 2),
                        amount(&mut rng),
                        rng.below(4) == 0,
                        rng.below(3) == 0,
                    )
                })
                .collect();
            let qty = amount(&mut rng);
            let single: Vec<(Decimal, Decimal, bool)> = stops
                .iter()
                .map(|&(t, s, whole, _)| (t, s, whole))
                .collect();
            let shared = covering_stop(
                side,
                qty,
                stops.iter().map(|&(trigger, size, whole, _)| CoverStop {
                    trigger,
                    size: (!whole).then_some(size),
                    first_part_only: false,
                }),
            );
            if qty > Decimal::ZERO {
                assert_eq!(shared, reference_single(side, qty, &single), "case {case}");
            } else {
                assert_eq!(shared, None, "case {case}");
            }
            if shared.is_some() {
                covered += 1;
            } else {
                uncovered += 1;
            }
            let parts: Vec<Decimal> = (0..1 + rng.below(3)).map(|_| amount(&mut rng)).collect();
            let queued: Vec<(Decimal, Option<Decimal>, bool)> = stops
                .iter()
                .map(|&(t, s, whole, first)| (t, (!whole).then_some(s), first))
                .collect();
            let shared = covering_parts(
                side,
                &parts,
                queued
                    .iter()
                    .map(|&(trigger, size, first_part_only)| CoverStop {
                        trigger,
                        size,
                        first_part_only,
                    }),
            );
            assert_eq!(
                shared,
                reference_parts(side, &parts, &queued),
                "case {case}"
            );
        }
        assert!(
            covered > 2_000 && uncovered > 2_000,
            "{covered} {uncovered}"
        );
    }
}
