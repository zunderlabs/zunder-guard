// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Sizing, vetoes and the two circuit breakers.

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zunder_core::{Side, Symbol, Timestamp};

use crate::{
    book::{self, CombinedExposure, Exposure, PositionDiscrepancy, TrackedPosition, VenueView},
    limits::{RiskConfigError, RiskLimits},
};

/// Whether new entries are allowed right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskState {
    /// New entries are allowed.
    Active,
    /// Daily loss stop hit on UTC day `day`: flat, no entries until the next day.
    HaltedForDay { day: i64 },
    /// Drawdown stop hit: flat, no entries until [`RiskEngine::resume_after_review`].
    Stopped { at: Timestamp, drawdown: Decimal },
}

/// Why an entry was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Veto {
    #[error("trading is halted for the day")]
    HaltedForDay,
    #[error("trading is stopped until a manual review")]
    Stopped,
    #[error("the stop is not on the losing side of the entry price")]
    StopOnWrongSide,
    #[error("the open-risk budget is used up")]
    OpenRiskExhausted,
    #[error("the leverage cap is reached")]
    LeverageExhausted,
    #[error("the sized quantity is below the venue minimum")]
    BelowMinimum,
    #[error("the sizing request contains a negative or non-positive amount")]
    InvalidRequest,
    #[error("the numbers are too large or too small to size safely")]
    Overflow,
    #[error("an open position has no protective stop, or its price is at or through it")]
    UnprotectedPosition,
}

/// Everything the engine needs to size one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeRequest {
    /// Current account equity.
    pub equity: Decimal,
    pub side: Side,
    /// Expected fill price, including expected slippage.
    pub entry: Decimal,
    /// Protective stop price. Must be below `entry` for a buy, above for a sell.
    pub stop: Decimal,
    /// Expected cost of getting in and out again, per unit of quantity: fees
    /// and slippage on both sides. It counts towards the per-trade risk, so
    /// a stop-out costs the budgeted amount including costs.
    pub round_trip_cost: Decimal,
    /// Risk-to-stop of the positions that are already open, in quote
    /// currency, as the caller measures it. The engine uses the larger of
    /// this and what its own record of positions gives
    /// ([`RiskEngine::book_exposure`]).
    pub open_risk: Decimal,
    /// Value of the positions that are already open, in quote currency, as
    /// the caller measures it. The larger of this and the engine's own
    /// record counts.
    pub open_notional: Decimal,
    /// Smallest quantity increment the venue accepts. Zero means no rounding.
    pub qty_step: Decimal,
    /// Smallest order value the venue accepts.
    pub min_notional: Decimal,
}

/// Tracks equity against the limits and sizes entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskEngine {
    limits: RiskLimits,
    state: RiskState,
    peak: Decimal,
    day: i64,
    day_start: Decimal,
    last: Decimal,
    /// The engine's own record of open positions, sorted by symbol. Empty
    /// in backtests, which pass open risk in the request instead.
    positions: Vec<TrackedPosition>,
}

/// Everything a [`RiskEngine`] remembers apart from its limits: what has to
/// survive a restart. [`RiskEngine::snapshot`] takes one,
/// [`RiskEngine::restore`] checks one and rebuilds the engine from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskSnapshot {
    pub state: RiskState,
    /// Highest equity seen since the start or the last review.
    pub peak: Decimal,
    /// UTC day (whole days since the epoch) of the daily loss window.
    pub day: i64,
    /// Equity at the start of that day.
    pub day_start: Decimal,
    /// The last equity observed.
    pub last: Decimal,
    /// The engine's record of open positions.
    pub positions: Vec<TrackedPosition>,
}

/// Why a snapshot cannot be restored.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RestoreError {
    #[error(transparent)]
    Limits(#[from] RiskConfigError),
    #[error("inconsistent risk state: {0}")]
    Inconsistent(String),
}

impl RiskEngine {
    pub fn new(
        limits: RiskLimits,
        ts: Timestamp,
        equity: Decimal,
    ) -> Result<Self, RiskConfigError> {
        limits.validate()?;
        if equity <= Decimal::ZERO {
            return Err(RiskConfigError::EquityNotPositive(equity));
        }
        Ok(Self {
            limits,
            state: RiskState::Active,
            peak: equity,
            day: ts.utc_day(),
            day_start: equity,
            last: equity,
            positions: Vec::new(),
        })
    }

    /// The state to persist. See [`RiskSnapshot`].
    pub fn snapshot(&self) -> RiskSnapshot {
        RiskSnapshot {
            state: self.state,
            peak: self.peak,
            day: self.day,
            day_start: self.day_start,
            last: self.last,
            positions: self.positions.clone(),
        }
    }

    /// Rebuild an engine from a snapshot taken by [`RiskEngine::snapshot`].
    ///
    /// Refuses a snapshot that no sequence of observations could have
    /// produced under `limits`: a last equity above the peak, an engine
    /// that is active or halted for the day although its last equity is at
    /// or beyond the drawdown stop, one that is active although the day's
    /// loss is at or beyond the daily loss stop, a halt for a day other
    /// than the current one, a drawdown stop recorded below the limit, or a
    /// recorded position that makes no sense. A stored state that fails
    /// these checks was damaged or edited, and guessing what it meant could
    /// clear a halt.
    pub fn restore(limits: RiskLimits, snapshot: RiskSnapshot) -> Result<Self, RestoreError> {
        limits.validate()?;
        let RiskSnapshot {
            state,
            peak,
            day,
            day_start,
            last,
            mut positions,
        } = snapshot;
        let bad = |what: String| Err(RestoreError::Inconsistent(what));
        if peak <= Decimal::ZERO {
            return bad(format!("the peak must be positive, got {peak}"));
        }
        if last > peak {
            return bad(format!("the last equity {last} is above the peak {peak}"));
        }
        let cap = limits.max_trading_equity_usd;
        let drawdown = loss_fraction(peak, last, cap);
        match state {
            RiskState::Stopped {
                drawdown: at_stop, ..
            } => {
                if at_stop < limits.drawdown_stop {
                    return bad(format!(
                        "stopped at a drawdown of {at_stop}, below the limit {}",
                        limits.drawdown_stop
                    ));
                }
            }
            RiskState::HaltedForDay { day: halted } => {
                if halted != day {
                    return bad(format!(
                        "halted for day {halted} while the current day is {day}"
                    ));
                }
                if drawdown >= limits.drawdown_stop {
                    return bad(format!(
                        "halted for the day with a drawdown of {drawdown}, at or beyond the drawdown stop {}",
                        limits.drawdown_stop
                    ));
                }
                if day_start <= Decimal::ZERO {
                    return bad(format!("the day started at {day_start}"));
                }
            }
            RiskState::Active => {
                if drawdown >= limits.drawdown_stop {
                    return bad(format!(
                        "active with a drawdown of {drawdown}, at or beyond the drawdown stop {}",
                        limits.drawdown_stop
                    ));
                }
                if day_start <= Decimal::ZERO {
                    return bad(format!("the day started at {day_start}"));
                }
                let day_loss = loss_fraction(day_start, last, cap);
                if day_loss >= limits.daily_loss_stop {
                    return bad(format!(
                        "active with a daily loss of {day_loss}, at or beyond the daily loss stop {}",
                        limits.daily_loss_stop
                    ));
                }
            }
        }
        positions.sort_by(|a, b| a.symbol.as_str().cmp(b.symbol.as_str()));
        for (index, position) in positions.iter().enumerate() {
            // A price of zero can come from the venue and is harmless: such
            // a position cannot be measured, and vetoes every entry.
            let sane = position.qty > Decimal::ZERO
                && position.entry >= Decimal::ZERO
                && position.mark >= Decimal::ZERO
                && position.stop.is_none_or(|stop| stop > Decimal::ZERO);
            if !sane {
                return bad(format!("the recorded position {position:?} makes no sense"));
            }
            if index > 0 && positions[index - 1].symbol == position.symbol {
                return bad(format!("two positions recorded in {}", position.symbol));
            }
        }
        Ok(Self {
            limits,
            state,
            peak,
            day,
            day_start,
            last,
            positions,
        })
    }

    /// The engine's record of open positions, sorted by symbol.
    pub fn positions(&self) -> &[TrackedPosition] {
        &self.positions
    }

    /// Open risk and value of the positions the engine records, at the last
    /// prices it was shown. An error when one of them has no stop, or its
    /// price is at or through it.
    pub fn book_exposure(&self) -> Result<Exposure, Veto> {
        self.positions
            .iter()
            .try_fold(Exposure::default(), |total, position| {
                total.add(book::position_exposure(
                    position.side,
                    position.qty,
                    position.stop,
                    position.mark,
                )?)
            })
    }

    /// Open risk and value from the engine's record and the venue's view
    /// together: per symbol, the larger risk and the larger value of the
    /// two, at the view's prices; and every place where the two disagree.
    ///
    /// An error when either record holds a position without a stop, with
    /// the price at or through its stop, or a venue position without a
    /// price in the view: such risk has no bound and nothing can be sized.
    pub fn combined_exposure(&self, view: &VenueView) -> Result<CombinedExposure, Veto> {
        book::combined(&self.positions, view)
    }

    /// Record a position the session has just opened: `qty` filled at
    /// `price`, protected by a stop at `stop`. A position already recorded
    /// on the same side grows, at the looser of the two stops; one on the
    /// other side is replaced, and the next reconciliation reports what the
    /// venue holds.
    pub fn record_entry(
        &mut self,
        symbol: Symbol,
        side: Side,
        qty: Decimal,
        price: Decimal,
        stop: Decimal,
    ) -> Result<(), Veto> {
        if qty <= Decimal::ZERO || price <= Decimal::ZERO || stop <= Decimal::ZERO {
            return Err(Veto::InvalidRequest);
        }
        let new = TrackedPosition {
            symbol,
            side,
            qty,
            entry: price,
            stop: Some(stop),
            mark: price,
        };
        match self
            .positions
            .iter_mut()
            .find(|position| position.symbol == new.symbol)
        {
            Some(held) if held.side == side => {
                let total = held.qty.checked_add(qty).ok_or(Veto::Overflow)?;
                let cost = held
                    .qty
                    .checked_mul(held.entry)
                    .and_then(|old| qty.checked_mul(price)?.checked_add(old))
                    .ok_or(Veto::Overflow)?;
                held.entry = cost.checked_div(total).ok_or(Veto::Overflow)?;
                held.qty = total;
                held.stop = book::looser_stop(side, held.stop, Some(stop));
                held.mark = price;
            }
            Some(held) => *held = new,
            None => {
                self.positions.push(new);
                self.sort_positions();
            }
        }
        Ok(())
    }

    /// Record that the position in `symbol` was closed: the session saw the
    /// venue flat there after an exit, a flatten or a stop.
    pub fn record_closed(&mut self, symbol: &Symbol) {
        self.positions.retain(|position| &position.symbol != symbol);
    }

    /// Record a tighter stop for the position in `symbol`. Like the session,
    /// the record only tightens: a looser stop is ignored. A position
    /// recorded without a stop takes it.
    pub fn record_stop(&mut self, symbol: &Symbol, stop: Decimal) {
        if stop <= Decimal::ZERO {
            return;
        }
        if let Some(held) = self
            .positions
            .iter_mut()
            .find(|position| &position.symbol == symbol)
        {
            let tighter = match (held.stop, held.side) {
                (None, _) => true,
                (Some(current), Side::Buy) => stop > current,
                (Some(current), Side::Sell) => stop < current,
            };
            if tighter {
                held.stop = Some(stop);
            }
        }
    }

    /// Bring the engine's record in line with the venue's view and report
    /// every disagreement.
    ///
    /// A position only the venue holds is real and is recorded. Prices are
    /// taken from the view. Otherwise the record keeps the larger risk:
    /// the larger quantity, the looser stop (no stop being the loosest),
    /// and a position the venue no longer shows stays recorded.
    ///
    /// With `settled`, the caller vouches that the view is the venue's
    /// settled state: the session has just reconciled with the venue and
    /// nothing of ours is in flight. The record then takes the venue's
    /// quantity and stop also where they carry less risk (a stop that was
    /// tightened, a position a stop or an exit has closed), and drops
    /// positions the venue no longer holds. A position on the other side
    /// from the record is the venue's in either case.
    pub fn reconcile_positions(
        &mut self,
        view: &VenueView,
        settled: bool,
    ) -> Vec<PositionDiscrepancy> {
        let mut discrepancies = Vec::new();
        let mut reconciled = Vec::new();
        for symbol in book::symbols(&self.positions, view) {
            let recorded = self
                .positions
                .iter()
                .find(|position| position.symbol == symbol);
            let shown = view
                .positions
                .iter()
                .find(|position| position.symbol == symbol);
            discrepancies.extend(book::compare(&symbol, recorded, shown));
            // Nonsense from the venue is not recorded as such: a price of
            // zero or less is no price, a stop of zero or less no stop.
            let mark = view
                .marks
                .get(&symbol)
                .copied()
                .filter(|mark| *mark > Decimal::ZERO);
            // A position of zero or less is no position, but not proof that
            // a recorded one is gone either: the record keeps it.
            let nonsense = shown.is_some_and(|shown| shown.qty <= Decimal::ZERO);
            let shown = shown.filter(|shown| shown.qty > Decimal::ZERO);
            let kept = match (recorded, shown) {
                (None, None) => None,
                (Some(recorded), None) => (!settled || nonsense).then(|| TrackedPosition {
                    mark: mark.unwrap_or(recorded.mark),
                    ..recorded.clone()
                }),
                (recorded, Some(shown)) => {
                    let entry = shown.entry.max(Decimal::ZERO);
                    let venue_stop = shown.stop.filter(|stop| *stop > Decimal::ZERO);
                    let from_venue = TrackedPosition {
                        symbol: symbol.clone(),
                        side: shown.side,
                        qty: shown.qty,
                        entry,
                        stop: venue_stop,
                        mark: mark
                            .or(recorded.map(|recorded| recorded.mark))
                            .unwrap_or(entry),
                    };
                    Some(match recorded {
                        Some(recorded) if recorded.side == shown.side && !settled => {
                            TrackedPosition {
                                qty: recorded.qty.max(shown.qty),
                                entry: recorded.entry,
                                stop: book::looser_stop(shown.side, recorded.stop, venue_stop),
                                ..from_venue
                            }
                        }
                        _ => from_venue,
                    })
                }
            };
            reconciled.extend(kept);
        }
        self.positions = reconciled;
        discrepancies
    }

    fn sort_positions(&mut self) {
        self.positions
            .sort_by(|a, b| a.symbol.as_str().cmp(b.symbol.as_str()));
    }

    pub fn limits(&self) -> &RiskLimits {
        &self.limits
    }

    pub fn state(&self) -> RiskState {
        self.state
    }

    /// Highest equity seen since the start or the last review.
    pub fn peak(&self) -> Decimal {
        self.peak
    }

    /// Feed an equity observation and get the resulting state.
    ///
    /// Call this at least once per bar, and before sizing anything on that
    /// bar. Observations must arrive in time order. When the returned state
    /// is not [`RiskState::Active`] the caller has to flatten.
    pub fn observe(&mut self, ts: Timestamp, equity: Decimal) -> RiskState {
        let day = ts.utc_day();
        // Only ever roll forwards: a late or replayed observation from an
        // earlier day must not clear today's halt.
        if day > self.day {
            // The new day starts from where the old one ended, so a gap at
            // the first bar of the day counts as that day's loss.
            self.day = day;
            self.day_start = self.last;
            if matches!(self.state, RiskState::HaltedForDay { .. }) {
                self.state = RiskState::Active;
            }
        }
        self.last = equity;
        if equity > self.peak {
            self.peak = equity;
        }

        if matches!(self.state, RiskState::Stopped { .. }) {
            return self.state;
        }

        let cap = self.limits.max_trading_equity_usd;
        let drawdown = loss_fraction(self.peak, equity, cap);
        if drawdown >= self.limits.drawdown_stop {
            self.state = RiskState::Stopped { at: ts, drawdown };
            return self.state;
        }

        // `day_start` is positive: an equity of zero or less is a 100% drawdown
        // and stops the engine before it can become the start of a day.
        let day_loss = loss_fraction(self.day_start, equity, cap);
        if day_loss >= self.limits.daily_loss_stop {
            self.state = RiskState::HaltedForDay { day: self.day };
        }
        self.state
    }

    /// Quantity for a new entry, or the reason it is refused.
    ///
    /// The quantity is the largest one that keeps the trade inside the
    /// per-trade risk, the open-risk budget and the leverage cap at once,
    /// rounded down to the venue's quantity step. Risk per unit is the
    /// distance to the stop plus `round_trip_cost`.
    ///
    /// The engine never sizes from more equity than it has itself observed,
    /// nor from more than the sleeve: it uses the smallest of
    /// `request.equity`, the last observation and
    /// [`RiskLimits::max_trading_equity_usd`].
    /// Nor from less open risk or position value than its own record of
    /// positions holds: it uses the larger of the request's figures and
    /// [`RiskEngine::book_exposure`], and refuses while a recorded position
    /// has no stop.
    pub fn size_entry(&self, request: &SizeRequest) -> Result<Decimal, Veto> {
        match self.state {
            RiskState::Active => {}
            RiskState::HaltedForDay { .. } => return Err(Veto::HaltedForDay),
            RiskState::Stopped { .. } => return Err(Veto::Stopped),
        }

        let equity = self.limits.capped(request.equity.min(self.last));
        let amounts = [
            request.open_risk,
            request.open_notional,
            request.round_trip_cost,
            request.qty_step,
            request.min_notional,
        ];
        if equity <= Decimal::ZERO
            || request.entry <= Decimal::ZERO
            || amounts.iter().any(|amount| *amount < Decimal::ZERO)
        {
            return Err(Veto::InvalidRequest);
        }

        // Checked: a strategy may hand over any stop, even an absurd one.
        let distance = match request.side {
            Side::Buy => request.entry.checked_sub(request.stop),
            Side::Sell => request.stop.checked_sub(request.entry),
        };
        let Some(distance) = distance else {
            return Err(Veto::Overflow);
        };
        if distance <= Decimal::ZERO {
            return Err(Veto::StopOnWrongSide);
        }

        // The caller's figures, or the engine's own record where it holds
        // more.
        let book = self.book_exposure()?;
        let request = SizeRequest {
            open_risk: request.open_risk.max(book.risk),
            open_notional: request.open_notional.max(book.notional),
            ..*request
        };

        // Checked arithmetic: absurd inputs become a veto, never a panic.
        self.quantity(equity, distance, &request)
            .unwrap_or(Err(Veto::Overflow))
    }

    /// The sizing arithmetic. `None` means a step overflowed.
    fn quantity(
        &self,
        equity: Decimal,
        distance: Decimal,
        request: &SizeRequest,
    ) -> Option<Result<Decimal, Veto>> {
        let trade_budget = equity.checked_mul(self.limits.risk_per_trade)?;
        let open_budget = equity
            .checked_mul(self.limits.max_open_risk)?
            .checked_sub(request.open_risk)?;
        let risk_budget = trade_budget.min(open_budget);
        if risk_budget <= Decimal::ZERO {
            return Some(Err(Veto::OpenRiskExhausted));
        }

        let notional_room = equity
            .checked_mul(self.limits.max_leverage)?
            .checked_sub(request.open_notional)?;
        if notional_room <= Decimal::ZERO {
            return Some(Err(Veto::LeverageExhausted));
        }

        let risk_per_unit = distance.checked_add(request.round_trip_cost)?;
        let unrounded = risk_budget
            .checked_div(risk_per_unit)?
            .min(notional_room.checked_div(request.entry)?);
        let qty = if request.qty_step > Decimal::ZERO {
            unrounded
                .checked_div(request.qty_step)?
                .floor()
                .checked_mul(request.qty_step)?
        } else {
            unrounded
        };
        if qty <= Decimal::ZERO || qty.checked_mul(request.entry)? < request.min_notional {
            return Some(Err(Veto::BelowMinimum));
        }
        Some(Ok(qty))
    }

    /// Clear a drawdown stop after a human has reviewed it.
    ///
    /// The peak restarts from the current equity, so the next stop is measured
    /// from here. Does nothing unless the engine is stopped. Never call this
    /// automatically: the whole point of the stop is that a person looks first.
    pub fn resume_after_review(&mut self, ts: Timestamp, equity: Decimal) {
        if !matches!(self.state, RiskState::Stopped { .. }) || equity <= Decimal::ZERO {
            return;
        }
        self.state = RiskState::Active;
        self.peak = equity;
        self.day = ts.utc_day();
        self.day_start = equity;
        self.last = equity;
    }
}

/// How far `equity` has fallen below `base`, as a fraction of `base`, or
/// of `cap` where that is smaller ([`RiskLimits::max_trading_equity_usd`]).
/// The fall is the real one, in the quote currency; only what it is
/// measured against shrinks, so a cap makes every loss count for at least
/// as much as without one. `base` and `cap` are positive. Saturates
/// instead of overflowing: a base close to zero turns any loss into a total
/// one and any gain into no loss.
fn loss_fraction(base: Decimal, equity: Decimal, cap: Option<Decimal>) -> Decimal {
    let measured_against = cap.map_or(base, |cap| base.min(cap));
    base.checked_sub(equity)
        .and_then(|fall| fall.checked_div(measured_against))
        .unwrap_or(if equity < base {
            Decimal::MAX
        } else {
            Decimal::MIN
        })
}

#[cfg(test)]
mod tests {
    use rust_decimal::dec;

    use super::*;

    const HOUR: i64 = Timestamp::MS_PER_HOUR;
    const DAY: i64 = Timestamp::MS_PER_DAY;

    fn at(ms: i64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    fn engine() -> RiskEngine {
        RiskEngine::new(RiskLimits::default(), at(0), dec!(2000)).unwrap()
    }

    fn long(entry: Decimal, stop: Decimal) -> SizeRequest {
        SizeRequest {
            equity: dec!(2000),
            side: Side::Buy,
            entry,
            stop,
            round_trip_cost: dec!(0),
            open_risk: dec!(0),
            open_notional: dec!(0),
            qty_step: dec!(0.001),
            min_notional: dec!(10),
        }
    }

    #[test]
    fn sizes_so_that_the_stop_loses_two_percent() {
        // 2% of 2,000 is 40; a 2-wide stop gives 20 units.
        assert_eq!(
            engine().size_entry(&long(dec!(100), dec!(98))),
            Ok(dec!(20))
        );
    }

    #[test]
    fn sizes_shorts_from_a_stop_above_the_entry() {
        let request = SizeRequest {
            side: Side::Sell,
            ..long(dec!(100), dec!(104))
        };
        assert_eq!(engine().size_entry(&request), Ok(dec!(10)));
    }

    #[test]
    fn leverage_cap_binds_when_the_stop_is_tight() {
        // Risk alone would allow 400 units (40 / 0.1); 5x of 2,000 allows 100.
        assert_eq!(
            engine().size_entry(&long(dec!(100), dec!(99.9))),
            Ok(dec!(100))
        );
    }

    #[test]
    fn existing_exposure_shrinks_the_leverage_room() {
        let request = SizeRequest {
            open_notional: dec!(9000),
            ..long(dec!(100), dec!(99.9))
        };
        assert_eq!(engine().size_entry(&request), Ok(dec!(10)));

        let full = SizeRequest {
            open_notional: dec!(10000),
            ..long(dec!(100), dec!(99.9))
        };
        assert_eq!(engine().size_entry(&full), Err(Veto::LeverageExhausted));
    }

    #[test]
    fn open_risk_budget_caps_the_next_trade() {
        // 6% of 2,000 is 120. With 100 already at risk only 20 is left.
        let request = SizeRequest {
            open_risk: dec!(100),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(engine().size_entry(&request), Ok(dec!(10)));

        let exhausted = SizeRequest {
            open_risk: dec!(120),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(
            engine().size_entry(&exhausted),
            Err(Veto::OpenRiskExhausted)
        );
    }

    #[test]
    fn quantity_rounds_down_to_the_step() {
        // 40 / 3 = 13.333...; never round up into more risk.
        assert_eq!(
            engine().size_entry(&long(dec!(100), dec!(97))),
            Ok(dec!(13.333))
        );
    }

    #[test]
    fn orders_below_the_venue_minimum_are_refused() {
        let request = SizeRequest {
            min_notional: dec!(5000),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(engine().size_entry(&request), Err(Veto::BelowMinimum));
    }

    #[test]
    fn stop_on_the_wrong_side_is_refused() {
        assert_eq!(
            engine().size_entry(&long(dec!(100), dec!(100))),
            Err(Veto::StopOnWrongSide)
        );
        assert_eq!(
            engine().size_entry(&long(dec!(100), dec!(101))),
            Err(Veto::StopOnWrongSide)
        );
    }

    #[test]
    fn daily_loss_stop_halts_until_the_next_day() {
        let mut engine = engine();
        assert_eq!(engine.observe(at(HOUR), dec!(1881)), RiskState::Active);
        // 6% of 2,000 is 120.
        assert_eq!(
            engine.observe(at(2 * HOUR), dec!(1880)),
            RiskState::HaltedForDay { day: 0 }
        );
        assert_eq!(
            engine.size_entry(&long(dec!(100), dec!(98))),
            Err(Veto::HaltedForDay)
        );
        // Recovering during the same day does not lift the halt.
        assert_eq!(
            engine.observe(at(3 * HOUR), dec!(1990)),
            RiskState::HaltedForDay { day: 0 }
        );
        // The next UTC day does.
        assert_eq!(engine.observe(at(DAY), dec!(1990)), RiskState::Active);
    }

    #[test]
    fn new_day_measures_loss_from_the_previous_close() {
        let mut engine = engine();
        engine.observe(at(23 * HOUR), dec!(1900));
        // Day two opens with a gap down: 1,900 -> 1,780 is a 6.3% loss for
        // day two, even though it is the first observation of that day.
        assert_eq!(
            engine.observe(at(DAY), dec!(1780)),
            RiskState::HaltedForDay { day: 1 }
        );
    }

    #[test]
    fn drawdown_stop_needs_a_manual_review() {
        let mut engine = engine();
        engine.observe(at(HOUR), dec!(2400));
        assert_eq!(engine.peak(), dec!(2400));

        // 25% below the 2,400 peak is 1,800. Spread over days so that the
        // daily stop does not fire first.
        engine.observe(at(DAY), dec!(2300));
        engine.observe(at(2 * DAY), dec!(2200));
        engine.observe(at(3 * DAY), dec!(2100));
        engine.observe(at(4 * DAY), dec!(2000));
        engine.observe(at(5 * DAY), dec!(1900));
        let state = engine.observe(at(6 * DAY), dec!(1800));
        assert_eq!(
            state,
            RiskState::Stopped {
                at: at(6 * DAY),
                drawdown: dec!(0.25)
            }
        );
        assert_eq!(
            engine.size_entry(&long(dec!(100), dec!(98))),
            Err(Veto::Stopped)
        );

        // Neither a new day nor a recovery clears it.
        assert!(matches!(
            engine.observe(at(7 * DAY), dec!(2500)),
            RiskState::Stopped { .. }
        ));

        engine.resume_after_review(at(7 * DAY), dec!(1800));
        assert_eq!(engine.state(), RiskState::Active);
        assert_eq!(engine.peak(), dec!(1800));
    }

    #[test]
    fn drawdown_stop_wins_over_the_daily_stop() {
        let mut engine = engine();
        assert!(matches!(
            engine.observe(at(HOUR), dec!(1400)),
            RiskState::Stopped { .. }
        ));
    }

    #[test]
    fn wiped_out_account_stops_instead_of_dividing_by_zero() {
        let mut engine = engine();
        assert!(matches!(
            engine.observe(at(HOUR), dec!(0)),
            RiskState::Stopped { .. }
        ));
        assert!(matches!(
            engine.observe(at(DAY), dec!(-5)),
            RiskState::Stopped { .. }
        ));
    }

    #[test]
    fn costs_count_towards_the_trade_risk() {
        // 2-wide stop plus 0.5 of expected costs per unit: 40 / 2.5 = 16.
        let request = SizeRequest {
            round_trip_cost: dec!(0.5),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(engine().size_entry(&request), Ok(dec!(16)));
    }

    // The equity cap (`max_trading_equity_usd`). Every number below is
    // worked out by hand from the default
    // frame (2% per trade, 6% open risk, 5x, 6% daily, 25% drawdown) and a
    // cap of 2,000.

    fn capped_engine(start: Decimal) -> RiskEngine {
        let limits = RiskLimits {
            max_trading_equity_usd: Some(dec!(2000)),
            ..RiskLimits::default()
        };
        RiskEngine::new(limits, at(0), start).unwrap()
    }

    #[test]
    fn the_cap_sizes_from_the_sleeve_when_the_venue_holds_more() {
        // Venue 3,000, cap 2,000: 2% of 2,000 = 40 over a 2-wide stop = 20
        // units, not the 30 that 2% of 3,000 = 60 would give.
        let engine = capped_engine(dec!(3000));
        let request = SizeRequest {
            equity: dec!(3000),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(engine.size_entry(&request), Ok(dec!(20)));
        // Without the cap the same request is 30 units.
        let uncapped = RiskEngine::new(RiskLimits::default(), at(0), dec!(3000)).unwrap();
        assert_eq!(uncapped.size_entry(&request), Ok(dec!(30)));
    }

    #[test]
    fn a_deposit_above_the_cap_does_not_raise_the_size() {
        // Started at the sleeve, then 3,000 more arrive (a wrong transfer).
        let mut engine = capped_engine(dec!(2000));
        engine.observe(at(HOUR), dec!(5000));
        let request = SizeRequest {
            equity: dec!(5000),
            ..long(dec!(100), dec!(98))
        };
        // Still 2% of 2,000 = 40 over 2 = 20 units.
        assert_eq!(engine.size_entry(&request), Ok(dec!(20)));
        // The leverage room too: 5x of 2,000 = 10,000 at 100 = 100 units
        // with a stop 0.1 away (risk alone would allow 40 / 0.1 = 400).
        let tight = SizeRequest {
            equity: dec!(5000),
            ..long(dec!(100), dec!(99.9))
        };
        assert_eq!(engine.size_entry(&tight), Ok(dec!(100)));
        // And the open-risk budget: 6% of 2,000 = 120, of which 110 is
        // used, leaves 10 over a 2-wide stop = 5 units.
        let crowded = SizeRequest {
            equity: dec!(5000),
            open_risk: dec!(110),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(engine.size_entry(&crowded), Ok(dec!(5)));
    }

    #[test]
    fn below_the_cap_the_venue_equity_counts() {
        // Venue 1,500 under a cap of 2,000: 2% of 1,500 = 30 over 2 = 15.
        let engine = capped_engine(dec!(1500));
        let request = SizeRequest {
            equity: dec!(1500),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(engine.size_entry(&request), Ok(dec!(15)));
    }

    #[test]
    fn with_the_cap_a_daily_loss_counts_against_the_sleeve() {
        // The day starts at 3,000 on the venue. The stop is 6% of the
        // smaller of 3,000 and the cap 2,000 = 120 (uncapped it would be
        // 6% of 3,000 = 180).
        let mut engine = capped_engine(dec!(3000));
        // A loss of 119: 119 / 2,000 = 5.95%, still active.
        assert_eq!(engine.observe(at(HOUR), dec!(2881)), RiskState::Active);
        // A loss of 120: 120 / 2,000 = 6%, halted.
        assert_eq!(
            engine.observe(at(2 * HOUR), dec!(2880)),
            RiskState::HaltedForDay { day: 0 }
        );
        // Uncapped, 120 / 3,000 = 4% does not halt: the cap tightens.
        let mut uncapped = RiskEngine::new(RiskLimits::default(), at(0), dec!(3000)).unwrap();
        assert_eq!(uncapped.observe(at(HOUR), dec!(2880)), RiskState::Active);
    }

    #[test]
    fn with_the_cap_the_drawdown_counts_against_the_sleeve() {
        // Peak 3,000 on the venue; 25% of the smaller of 3,000 and the cap
        // 2,000 = 500. Spread over days, so the daily stop stays out of it
        // (each day loses 100: 100 / 2,000 = 5% < 6%).
        let mut engine = capped_engine(dec!(3000));
        let mut equity = dec!(3000);
        for day in 1..=4 {
            equity -= dec!(100);
            assert_eq!(engine.observe(at(day * DAY), equity), RiskState::Active);
        }
        // 2,600: a fall of 400 = 20% of 2,000. Day 5 loses 99 more: 499 =
        // 24.95%, still active.
        assert_eq!(engine.observe(at(5 * DAY), dec!(2501)), RiskState::Active);
        // Day 6: 2,500, a fall of 500 = 25% of 2,000: stopped. Uncapped it
        // would be 500 / 3,000 = 16.7%.
        assert!(matches!(
            engine.observe(at(6 * DAY), dec!(2500)),
            RiskState::Stopped { drawdown, .. } if drawdown == dec!(0.25)
        ));
    }

    #[test]
    fn a_restored_engine_measures_with_the_cap_too() {
        // Peak 3,000, last 2,500, active: a fall of 500 = 25% of the cap
        // 2,000, which no capped engine leaves active. Without the cap it
        // is 16.7% and fine.
        let limits = RiskLimits {
            max_trading_equity_usd: Some(dec!(2000)),
            ..RiskLimits::default()
        };
        let snapshot = RiskSnapshot {
            state: RiskState::Active,
            peak: dec!(3000),
            day: 0,
            day_start: dec!(2500),
            last: dec!(2500),
            positions: Vec::new(),
        };
        assert!(matches!(
            RiskEngine::restore(limits.clone(), snapshot.clone()),
            Err(RestoreError::Inconsistent(_))
        ));
        assert!(RiskEngine::restore(RiskLimits::default(), snapshot).is_ok());

        // The daily loss too: the day started at 3,000 and stands at 2,880,
        // active. 120 / 2,000 = 6% halts a capped engine, so no capped
        // engine is active there; uncapped it is 4%.
        let daily = RiskSnapshot {
            state: RiskState::Active,
            peak: dec!(3000),
            day: 0,
            day_start: dec!(3000),
            last: dec!(2880),
            positions: Vec::new(),
        };
        assert!(matches!(
            RiskEngine::restore(limits.clone(), daily.clone()),
            Err(RestoreError::Inconsistent(_))
        ));
        assert!(RiskEngine::restore(RiskLimits::default(), daily.clone()).is_ok());
        // Halted for that day it restores under the cap.
        let halted = RiskSnapshot {
            state: RiskState::HaltedForDay { day: 0 },
            ..daily
        };
        assert!(RiskEngine::restore(limits, halted).is_ok());
    }

    #[test]
    fn the_capped_fraction_is_never_below_the_uncapped_one() {
        // For every base, equity and cap in a grid: the capped loss
        // fraction is at least the uncapped one, so no stop fires later.
        let values = [
            dec!(1),
            dec!(500),
            dec!(1999),
            dec!(2000),
            dec!(2001),
            dec!(3000),
            dec!(10000),
        ];
        for base in values {
            for equity in values.iter().copied().chain([dec!(0), dec!(-50)]) {
                for cap in [dec!(1), dec!(2000), dec!(2500)] {
                    let capped = loss_fraction(base, equity, Some(cap));
                    let uncapped = loss_fraction(base, equity, None);
                    if equity < base {
                        assert!(capped >= uncapped, "{base} {equity} {cap}");
                    }
                }
            }
        }
    }

    #[test]
    fn never_sizes_from_more_equity_than_it_has_observed() {
        let mut engine = engine();
        engine.observe(at(HOUR), dec!(1900));
        // The caller claims ten times the equity the engine has seen.
        let request = SizeRequest {
            equity: dec!(20000),
            ..long(dec!(100), dec!(98))
        };
        // 2% of the observed 1,900 over a 2-wide stop.
        assert_eq!(engine.size_entry(&request), Ok(dec!(19)));
    }

    #[test]
    fn negative_amounts_are_refused_instead_of_widening_the_limits() {
        // A caller that sums signed short notionals must not buy extra room.
        let request = SizeRequest {
            open_notional: dec!(-100000),
            ..long(dec!(100), dec!(99.9))
        };
        assert_eq!(engine().size_entry(&request), Err(Veto::InvalidRequest));

        let request = SizeRequest {
            open_risk: dec!(-1),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(engine().size_entry(&request), Err(Veto::InvalidRequest));

        let request = SizeRequest {
            entry: dec!(0),
            stop: dec!(-1),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(engine().size_entry(&request), Err(Veto::InvalidRequest));
    }

    #[test]
    fn absurd_numbers_are_vetoed_not_panics() {
        // A quantity step this small overflows the rounding step.
        let request = SizeRequest {
            qty_step: dec!(0.0000000000000000000000000001),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(engine().size_entry(&request), Err(Veto::Overflow));

        // A stop distance of 1e-24 on a large account overflows the division.
        let big = RiskEngine::new(RiskLimits::default(), at(0), dec!(1000000000)).unwrap();
        let request = SizeRequest {
            equity: dec!(1000000000),
            entry: dec!(100),
            stop: dec!(99.999999999999999999999999),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(big.size_entry(&request), Err(Veto::Overflow));
    }

    #[test]
    fn absurd_stops_are_vetoed_not_panics() {
        // 100 - (-7.9e28) does not fit in a Decimal.
        let request = long(dec!(100), Decimal::MIN);
        assert_eq!(engine().size_entry(&request), Err(Veto::Overflow));
        // A short stopped at the largest Decimal fits, and is sized to dust.
        let short = SizeRequest {
            side: Side::Sell,
            ..long(dec!(100), Decimal::MAX)
        };
        assert_eq!(engine().size_entry(&short), Err(Veto::BelowMinimum));
        let short_below = SizeRequest {
            side: Side::Sell,
            ..long(dec!(100), Decimal::MIN)
        };
        assert_eq!(engine().size_entry(&short_below), Err(Veto::Overflow));
    }

    #[test]
    fn an_observation_from_an_earlier_day_does_not_clear_the_halt() {
        let mut engine = engine();
        engine.observe(at(DAY), dec!(2000));
        assert_eq!(
            engine.observe(at(DAY + HOUR), dec!(1870)),
            RiskState::HaltedForDay { day: 1 }
        );
        // A replayed observation stamped with the previous day.
        assert_eq!(
            engine.observe(at(HOUR), dec!(1870)),
            RiskState::HaltedForDay { day: 1 }
        );
        assert_eq!(
            engine.size_entry(&long(dec!(100), dec!(98))),
            Err(Veto::HaltedForDay)
        );
    }

    #[test]
    fn a_later_daily_loss_does_not_downgrade_a_drawdown_stop() {
        let mut engine = engine();
        assert!(matches!(
            engine.observe(at(HOUR), dec!(1400)),
            RiskState::Stopped { .. }
        ));
        // Another bad day, then a new day: still stopped, never "halted".
        assert!(matches!(
            engine.observe(at(DAY), dec!(1200)),
            RiskState::Stopped { .. }
        ));
        assert!(matches!(
            engine.observe(at(2 * DAY), dec!(1200)),
            RiskState::Stopped { .. }
        ));
    }

    #[test]
    fn a_tiny_day_start_cannot_overflow_the_daily_loss() {
        // From the review of the M2 changes: equity of 1e-20 at the end of a
        // day, then 1e8 the next morning, divided the loss by 1e-20.
        let limits = RiskLimits {
            drawdown_stop: dec!(1),
            daily_loss_stop: dec!(1),
            ..RiskLimits::default()
        };
        let mut engine = RiskEngine::new(limits, at(0), dec!(0.00000000000000000001)).unwrap();
        // (1e-20 - 1e9) / 1e-20 = -1e29: beyond Decimal, so this panicked.
        assert_eq!(engine.observe(at(DAY), dec!(1000000000)), RiskState::Active);
        assert_eq!(
            loss_fraction(dec!(0.0000000000000000000000000001), dec!(-10), None),
            Decimal::MAX
        );
        assert_eq!(
            loss_fraction(dec!(0.0000000000000000000000000001), dec!(10), None),
            Decimal::MIN
        );
        assert_eq!(loss_fraction(dec!(2000), dec!(1500), None), dec!(0.25));
    }

    #[test]
    fn resume_with_a_wiped_out_account_is_ignored() {
        let mut engine = engine();
        engine.observe(at(HOUR), dec!(0));
        engine.resume_after_review(at(2 * HOUR), dec!(0));
        assert!(matches!(engine.state(), RiskState::Stopped { .. }));
    }

    #[test]
    fn resume_is_ignored_unless_stopped() {
        let mut engine = engine();
        engine.observe(at(HOUR), dec!(2100));
        engine.resume_after_review(at(2 * HOUR), dec!(1500));
        assert_eq!(engine.peak(), dec!(2100));
        assert_eq!(engine.state(), RiskState::Active);
    }

    #[test]
    fn invalid_setup_is_rejected() {
        assert_eq!(
            RiskEngine::new(RiskLimits::default(), at(0), dec!(0)),
            Err(RiskConfigError::EquityNotPositive(dec!(0)))
        );
        let limits = RiskLimits {
            max_leverage: dec!(-1),
            ..RiskLimits::default()
        };
        assert!(RiskEngine::new(limits, at(0), dec!(2000)).is_err());
    }

    // The engine's own record of positions.

    fn btc() -> Symbol {
        Symbol::new("BTC")
    }

    fn venue_long(symbol: &str, qty: Decimal, stop: Option<Decimal>) -> book::VenuePosition {
        book::VenuePosition {
            symbol: Symbol::new(symbol),
            side: Side::Buy,
            qty,
            entry: dec!(100),
            stop,
        }
    }

    fn view(positions: Vec<book::VenuePosition>, marks: &[(&str, Decimal)]) -> VenueView {
        VenueView {
            positions,
            marks: marks
                .iter()
                .map(|(symbol, mark)| (Symbol::new(symbol), *mark))
                .collect(),
        }
    }

    #[test]
    fn the_book_counts_when_the_caller_forgets_a_position() {
        let mut engine = engine();
        // Long 50 at 100 with the stop at 98: 50 x 2 = 100 at risk.
        engine
            .record_entry(btc(), Side::Buy, dec!(50), dec!(100), dec!(98))
            .unwrap();
        assert_eq!(
            engine.book_exposure(),
            Ok(Exposure {
                risk: dec!(100),
                notional: dec!(5000)
            })
        );
        // The caller says nothing is open. 6% of 2,000 is 120; the book
        // holds 100 of it, so 20 is left: 10 units over a 2-wide stop
        // instead of the 20 a flat account would get.
        assert_eq!(engine.size_entry(&long(dec!(100), dec!(98))), Ok(dec!(10)));
    }

    #[test]
    fn the_larger_of_the_callers_figures_and_the_book_counts() {
        let mut engine = engine();
        engine
            .record_entry(btc(), Side::Buy, dec!(50), dec!(100), dec!(98))
            .unwrap();
        // The caller measures 110 at risk, more than the book's 100:
        // 120 - 110 = 10 left, 5 units over a 2-wide stop.
        let request = SizeRequest {
            open_risk: dec!(110),
            ..long(dec!(100), dec!(98))
        };
        assert_eq!(engine.size_entry(&request), Ok(dec!(5)));
    }

    #[test]
    fn the_book_counts_against_the_leverage_cap_too() {
        let mut engine = engine();
        // Long 90 at 100, stop 99.9: 9 at risk, 9,000 of value. 5x of
        // 2,000 leaves 1,000 of room: 10 units at 100.
        engine
            .record_entry(btc(), Side::Buy, dec!(90), dec!(100), dec!(99.9))
            .unwrap();
        assert_eq!(
            engine.size_entry(&long(dec!(100), dec!(99.9))),
            Ok(dec!(10))
        );
    }

    #[test]
    fn a_recorded_position_without_a_stop_vetoes_every_entry() {
        let mut engine = engine();
        engine.reconcile_positions(
            &view(
                vec![venue_long("BTC", dec!(1), None)],
                &[("BTC", dec!(100))],
            ),
            false,
        );
        assert_eq!(
            engine.size_entry(&long(dec!(100), dec!(98))),
            Err(Veto::UnprotectedPosition)
        );
    }

    /// The book holds BTC long 20 at 100 (stop 98) and SOL long 10 at 20
    /// (stop 19). The venue shows BTC long 25 with its stop at 97, and ETH
    /// short 2 at 50 with its stop at 52, which the book does not know.
    fn disagreeing() -> (RiskEngine, VenueView) {
        let mut engine = engine();
        engine
            .record_entry(btc(), Side::Buy, dec!(20), dec!(100), dec!(98))
            .unwrap();
        engine
            .record_entry(Symbol::new("SOL"), Side::Buy, dec!(10), dec!(20), dec!(19))
            .unwrap();
        let eth = book::VenuePosition {
            symbol: Symbol::new("ETH"),
            side: Side::Sell,
            qty: dec!(2),
            entry: dec!(50),
            stop: Some(dec!(52)),
        };
        let view = view(
            vec![venue_long("BTC", dec!(25), Some(dec!(97))), eth],
            &[("BTC", dec!(101)), ("ETH", dec!(50))],
        );
        (engine, view)
    }

    #[test]
    fn combined_exposure_takes_the_larger_risk_per_symbol_and_reports_the_rest() {
        let (engine, view) = disagreeing();
        let combined = engine.combined_exposure(&view).unwrap();
        // BTC at 101: the book's 20 x (101 - 98) = 60 and 2,020; the
        // venue's 25 x (101 - 97) = 100 and 2,525. The venue's counts.
        // ETH, venue only: 2 x (52 - 50) = 4 and 100.
        // SOL, book only, at its last price 20: 10 x 1 = 10 and 200.
        assert_eq!(
            combined.exposure,
            Exposure {
                risk: dec!(114),
                notional: dec!(2825)
            }
        );
        assert_eq!(
            combined.discrepancies,
            vec![
                PositionDiscrepancy::QtyDiffers {
                    symbol: btc(),
                    book: dec!(20),
                    venue: dec!(25)
                },
                PositionDiscrepancy::StopDiffers {
                    symbol: btc(),
                    book: Some(dec!(98)),
                    venue: Some(dec!(97))
                },
                PositionDiscrepancy::NotInBook {
                    symbol: Symbol::new("ETH"),
                    side: Side::Sell,
                    qty: dec!(2)
                },
                PositionDiscrepancy::NotOnVenue {
                    symbol: Symbol::new("SOL"),
                    side: Side::Buy,
                    qty: dec!(10)
                },
            ]
        );
    }

    #[test]
    fn the_book_wins_where_it_holds_more() {
        let mut engine = engine();
        engine
            .record_entry(btc(), Side::Buy, dec!(30), dec!(100), dec!(96))
            .unwrap();
        // The venue shows 10 with a stop at 99, at a price of 100: 10 at
        // risk. The book's 30 x 4 = 120 counts, and 3,000 of value.
        let view = view(
            vec![venue_long("BTC", dec!(10), Some(dec!(99)))],
            &[("BTC", dec!(100))],
        );
        assert_eq!(
            engine.combined_exposure(&view).unwrap().exposure,
            Exposure {
                risk: dec!(120),
                notional: dec!(3000)
            }
        );
    }

    #[test]
    fn a_venue_position_without_a_price_cannot_be_measured() {
        let (engine, mut view) = disagreeing();
        view.marks.remove(&btc());
        assert_eq!(engine.combined_exposure(&view), Err(Veto::InvalidRequest));
    }

    #[test]
    fn reconciling_keeps_the_larger_risk_until_the_venue_is_settled() {
        let (mut engine, first) = disagreeing();
        let found = engine.reconcile_positions(&first, false);
        assert_eq!(found.len(), 4);
        let recorded: Vec<(&str, Decimal, Option<Decimal>, Decimal)> = engine
            .positions()
            .iter()
            .map(|p| (p.symbol.as_str(), p.qty, p.stop, p.mark))
            .collect();
        // BTC: the larger quantity, the looser stop, the new price. ETH is
        // adopted. SOL stays, at its last price.
        assert_eq!(
            recorded,
            vec![
                ("BTC", dec!(25), Some(dec!(97)), dec!(101)),
                ("ETH", dec!(2), Some(dec!(52)), dec!(50)),
                ("SOL", dec!(10), Some(dec!(19)), dec!(20)),
            ]
        );

        // Settled: the venue's tighter stop and smaller quantity are taken,
        // and SOL, which the venue no longer holds, is dropped.
        let settled = view(
            vec![venue_long("BTC", dec!(15), Some(dec!(99)))],
            &[("BTC", dec!(102))],
        );
        let found = engine.reconcile_positions(&settled, true);
        assert_eq!(found.len(), 4, "{found:?}");
        assert_eq!(engine.positions().len(), 1);
        let btc_now = &engine.positions()[0];
        assert_eq!(
            (btc_now.qty, btc_now.stop, btc_now.mark),
            (dec!(15), Some(dec!(99)), dec!(102))
        );
        // In agreement now: nothing to report.
        assert!(engine.reconcile_positions(&settled, true).is_empty());
        assert!(engine.reconcile_positions(&settled, false).is_empty());
    }

    #[test]
    fn a_position_on_the_other_side_is_the_venues() {
        let mut engine = engine();
        engine
            .record_entry(btc(), Side::Buy, dec!(20), dec!(100), dec!(98))
            .unwrap();
        let short = book::VenuePosition {
            side: Side::Sell,
            stop: Some(dec!(103)),
            ..venue_long("BTC", dec!(5), None)
        };
        let found = engine.reconcile_positions(&view(vec![short], &[("BTC", dec!(100))]), false);
        assert_eq!(
            found,
            vec![PositionDiscrepancy::SideDiffers {
                symbol: btc(),
                book: Side::Buy,
                venue: Side::Sell
            }]
        );
        assert_eq!(engine.positions()[0].side, Side::Sell);
        assert_eq!(engine.positions()[0].qty, dec!(5));
    }

    #[test]
    fn nonsense_from_the_venue_is_recorded_safely_and_can_be_restored() {
        let mut engine = engine();
        let zero = book::VenuePosition {
            entry: dec!(0),
            ..venue_long("BTC", dec!(1), Some(dec!(0)))
        };
        engine.reconcile_positions(&view(vec![zero], &[("BTC", dec!(0))]), true);
        let held = &engine.positions()[0];
        // A stop of zero is no stop, a price of zero no price; a position
        // without a price cannot be measured, and nothing is sized.
        assert_eq!((held.entry, held.stop, held.mark), (dec!(0), None, dec!(0)));
        assert_eq!(
            engine.size_entry(&long(dec!(100), dec!(98))),
            Err(Veto::InvalidRequest)
        );
        // And the state can be stored and restored: a journal must never
        // hold a record its reader refuses.
        let restored = RiskEngine::restore(RiskLimits::default(), engine.snapshot()).unwrap();
        assert_eq!(restored, engine);
    }

    #[test]
    fn a_stop_of_zero_from_the_venue_is_no_stop_while_unsettled_too() {
        // From the second review: the looser of 98 and 0 for a long was 0,
        // a stop the journal's reader refuses.
        let mut engine = engine();
        engine
            .record_entry(btc(), Side::Buy, dec!(20), dec!(100), dec!(98))
            .unwrap();
        let zero_stop = venue_long("BTC", dec!(20), Some(dec!(0)));
        engine.reconcile_positions(&view(vec![zero_stop], &[("BTC", dec!(100))]), false);
        assert_eq!(engine.positions()[0].stop, None);
        RiskEngine::restore(RiskLimits::default(), engine.snapshot()).unwrap();
    }

    #[test]
    fn a_venue_position_of_zero_does_not_remove_the_record() {
        let mut engine = engine();
        engine
            .record_entry(btc(), Side::Buy, dec!(20), dec!(100), dec!(98))
            .unwrap();
        let zero = venue_long("BTC", dec!(0), Some(dec!(98)));
        engine.reconcile_positions(&view(vec![zero], &[("BTC", dec!(100))]), true);
        assert_eq!(engine.positions()[0].qty, dec!(20));
    }

    #[test]
    fn recording_more_of_a_position_averages_and_keeps_the_looser_stop() {
        let mut engine = engine();
        engine
            .record_entry(btc(), Side::Buy, dec!(10), dec!(100), dec!(98))
            .unwrap();
        // 10 at 100 and 30 at 104: 40 at (1,000 + 3,120) / 40 = 103.
        engine
            .record_entry(btc(), Side::Buy, dec!(30), dec!(104), dec!(101))
            .unwrap();
        let held = &engine.positions()[0];
        assert_eq!(
            (held.qty, held.entry, held.stop),
            (dec!(40), dec!(103), Some(dec!(98)))
        );
        assert_eq!(
            engine.record_entry(btc(), Side::Buy, dec!(0), dec!(100), dec!(98)),
            Err(Veto::InvalidRequest)
        );
    }

    #[test]
    fn recorded_stops_only_tighten_and_closes_remove() {
        let mut engine = engine();
        engine
            .record_entry(btc(), Side::Buy, dec!(20), dec!(100), dec!(98))
            .unwrap();
        engine.record_stop(&btc(), dec!(97));
        assert_eq!(engine.positions()[0].stop, Some(dec!(98)));
        engine.record_stop(&btc(), dec!(99));
        assert_eq!(engine.positions()[0].stop, Some(dec!(99)));
        // 20 x (100 - 99) = 20 at risk now.
        assert_eq!(engine.book_exposure().unwrap().risk, dec!(20));
        engine.record_closed(&btc());
        assert!(engine.positions().is_empty());
        assert_eq!(engine.book_exposure(), Ok(Exposure::default()));
    }

    // Snapshots.

    #[test]
    fn a_snapshot_restores_the_same_engine() {
        let mut engine = engine();
        engine.observe(at(HOUR), dec!(2400));
        engine.observe(at(DAY), dec!(2300));
        engine
            .record_entry(btc(), Side::Buy, dec!(1), dec!(100), dec!(98))
            .unwrap();
        let restored = RiskEngine::restore(RiskLimits::default(), engine.snapshot()).unwrap();
        assert_eq!(restored, engine);
    }

    #[test]
    fn a_restored_halt_still_refuses_until_the_next_day() {
        let mut engine = engine();
        engine.observe(at(2 * HOUR), dec!(1880));
        assert_eq!(engine.state(), RiskState::HaltedForDay { day: 0 });
        let mut restored = RiskEngine::restore(RiskLimits::default(), engine.snapshot()).unwrap();
        assert_eq!(
            restored.size_entry(&long(dec!(100), dec!(98))),
            Err(Veto::HaltedForDay)
        );
        // A recovery on the same day does not lift it, the next day does.
        assert_eq!(
            restored.observe(at(3 * HOUR), dec!(2000)),
            RiskState::HaltedForDay { day: 0 }
        );
        assert_eq!(restored.observe(at(DAY), dec!(2000)), RiskState::Active);
    }

    #[test]
    fn a_restored_drawdown_stop_stays_until_a_review() {
        let mut engine = engine();
        engine.observe(at(HOUR), dec!(1400));
        let mut restored = RiskEngine::restore(RiskLimits::default(), engine.snapshot()).unwrap();
        assert!(matches!(
            restored.observe(at(5 * DAY), dec!(2500)),
            RiskState::Stopped { .. }
        ));
        assert_eq!(
            restored.size_entry(&long(dec!(100), dec!(98))),
            Err(Veto::Stopped)
        );
    }

    #[test]
    fn snapshots_no_observation_could_produce_are_refused() {
        let base = engine().snapshot();
        let refused = |snapshot: RiskSnapshot| {
            assert!(
                matches!(
                    RiskEngine::restore(RiskLimits::default(), snapshot.clone()),
                    Err(RestoreError::Inconsistent(_))
                ),
                "{snapshot:?}"
            );
        };
        // Active although 6% down on the day (2,000 -> 1,880).
        refused(RiskSnapshot {
            last: dec!(1880),
            ..base.clone()
        });
        // Active although 25% below the peak, spread over days.
        refused(RiskSnapshot {
            peak: dec!(2400),
            day_start: dec!(1800),
            last: dec!(1800),
            ..base.clone()
        });
        // Halted for another day than the current one.
        refused(RiskSnapshot {
            state: RiskState::HaltedForDay { day: 3 },
            day: 4,
            last: dec!(1880),
            ..base.clone()
        });
        // Halted for the day although the drawdown stop has fired.
        refused(RiskSnapshot {
            state: RiskState::HaltedForDay { day: 0 },
            last: dec!(1400),
            ..base.clone()
        });
        // Stopped at a drawdown below the limit.
        refused(RiskSnapshot {
            state: RiskState::Stopped {
                at: at(0),
                drawdown: dec!(0.1),
            },
            ..base.clone()
        });
        // Last equity above the peak, a peak of zero.
        refused(RiskSnapshot {
            last: dec!(2001),
            ..base.clone()
        });
        refused(RiskSnapshot {
            peak: dec!(0),
            last: dec!(0),
            ..base.clone()
        });
        // A position of zero, and two positions in one instrument.
        let position = TrackedPosition {
            symbol: btc(),
            side: Side::Buy,
            qty: dec!(1),
            entry: dec!(100),
            stop: Some(dec!(98)),
            mark: dec!(100),
        };
        refused(RiskSnapshot {
            positions: vec![TrackedPosition {
                qty: dec!(0),
                ..position.clone()
            }],
            ..base.clone()
        });
        refused(RiskSnapshot {
            positions: vec![position.clone(), position.clone()],
            ..base.clone()
        });
        // Limits that do not validate.
        assert!(matches!(
            RiskEngine::restore(
                RiskLimits {
                    daily_loss_stop: dec!(6),
                    ..RiskLimits::default()
                },
                base
            ),
            Err(RestoreError::Limits(_))
        ));
    }

    #[test]
    fn a_halted_snapshot_that_could_have_happened_is_accepted() {
        // 2,000 -> 1,880 on day 0 halts; the state survives a round trip.
        let snapshot = RiskSnapshot {
            state: RiskState::HaltedForDay { day: 0 },
            last: dec!(1880),
            ..engine().snapshot()
        };
        assert!(RiskEngine::restore(RiskLimits::default(), snapshot).is_ok());
    }
}
