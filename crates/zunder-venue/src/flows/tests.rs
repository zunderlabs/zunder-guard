// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The fold of `docs/guard.md#deposits-and-withdrawals` on hand-computed
//! numbers, each worked out in the comment next to it. Default limits: 6%
//! daily stop, 25% drawdown stop.

use rust_decimal::dec;

use super::*;

const HOUR: i64 = Timestamp::MS_PER_HOUR;
const DAY: i64 = Timestamp::MS_PER_DAY;

fn at(ms: i64) -> Timestamp {
    Timestamp::from_millis(ms)
}

fn capped(cap: Decimal) -> RiskLimits {
    RiskLimits {
        max_trading_equity_usd: Some(cap),
        ..RiskLimits::default()
    }
}

/// A fold over an engine started at `equity` at time 0, seen once at 1 h.
fn fold_at(limits: RiskLimits, equity: Decimal) -> Fold {
    let engine = RiskEngine::new(limits.clone(), at(0), equity).unwrap();
    let mut fold = Fold::new(limits, engine, Horizon::new(), None);
    view(&mut fold, HOUR, equity);
    fold
}

/// A view of the main dex at `ms` (venue time and engine time alike).
fn view(fold: &mut Fold, ms: i64, equity: Decimal) -> Step {
    fold.view(&SeenView {
        at: at(ms),
        times: [(String::new(), ms)].into(),
        equity,
    })
    .unwrap()
}

fn flow(time_ms: i64, amount: Decimal, id: &str) -> Flow {
    Flow {
        time_ms,
        amount,
        id: id.into(),
        dex: String::new(),
        between: false,
        value: None,
        unaccounted: None,
    }
}

fn figures(fold: &Fold) -> (RiskState, Decimal, Decimal, Decimal) {
    let s = fold.engine.snapshot();
    (
        s.state,
        s.peak.normalize(),
        s.day_start.normalize(),
        s.last.normalize(),
    )
}

#[test]
fn rebase_keeps_the_share_of_a_loss_as_the_engine_measures_it() {
    // No cap: in proportion. 10,000 at 9,500 (5%), 4,750 withdrawn: 5,000.
    assert_eq!(
        rebase(dec!(10000), dec!(9500), dec!(4750), None),
        Some(dec!(5000))
    );
    // At or above a 2,000 cap: by the amount. 110 lost (5.5% of the cap),
    // 7,890 withdrawn: 2,000 + 0.055 x 2,000 = 2,110.
    let cap = Some(dec!(2000));
    assert_eq!(
        rebase(dec!(10000), dec!(9890), dec!(2000), cap),
        Some(dec!(2110))
    );
    // Across it: 2,500 at 2,400 is 100 / 2,000 = 5%; at 1,000 after the
    // flow, 1,000 + 100 = 1,100 is below the cap, so the base is below it
    // too: 1,000 / 0.95 = 1,052.63..., and (1,052.63 - 1,000) / 1,052.63 = 5%.
    let across = rebase(dec!(2500), dec!(2400), dec!(1000), cap).unwrap();
    assert_eq!(across.round_dp(2), dec!(1052.63));
    // Nothing keeps a share of an account emptied: none.
    assert_eq!(rebase(dec!(10000), dec!(9500), dec!(0), None), None);
    // A gain stays a gain: 10,000 at 11,000 (10% up), doubled: 20,000.
    assert_eq!(
        rebase(dec!(10000), dec!(11000), dec!(22000), None),
        Some(dec!(20000))
    );
    // A loss of the whole base has no positive base to keep it.
    assert_eq!(rebase(dec!(10000), dec!(0), dec!(5000), None), None);
}

#[test]
fn a_view_stands_before_a_flow_shows_it_or_may_either_way() {
    let f = flow(10 * HOUR, dec!(-100), "w");
    let side_at = |ms: i64| side(&f, &[(String::new(), ms)].into());
    // Before: more than the 2 s margin before it; shows it: 2 s or more after.
    assert_eq!(side_at(10 * HOUR - 2_001), Side::Before);
    assert_eq!(side_at(10 * HOUR - 2_000), Side::Either);
    assert_eq!(side_at(10 * HOUR + 1_999), Side::Either);
    assert_eq!(side_at(10 * HOUR + 2_000), Side::Shows);
    // A transfer between two dexes: every dex on the same side, or either.
    let t = Flow {
        between: true,
        dex: "xyz".into(),
        ..flow(10 * HOUR, dec!(-1), "t")
    };
    let two = |main: i64, xyz: i64| side(&t, &[(String::new(), main), ("xyz".into(), xyz)].into());
    assert_eq!(two(10 * HOUR - 5_000, 10 * HOUR - 3_000), Side::Before);
    assert_eq!(two(10 * HOUR - 5_000, 10 * HOUR + 5_000), Side::Either);
    assert_eq!(two(10 * HOUR + 3_000, 10 * HOUR + 5_000), Side::Shows);
    // No times at all: either.
    assert_eq!(side(&f, &BTreeMap::new()), Side::Either);
}

#[test]
fn a_withdrawal_is_no_loss_and_a_loss_after_it_counts() {
    // Example 1: 10,000, 9,500 seen, 4,750 withdrawn, 4,750 seen: 5,000 and
    // 5,000, still 5% down; 4,650 is 7%: halted.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    view(&mut fold, 2 * HOUR, dec!(9500));
    fold.add_flow(exact_flow(3 * HOUR, dec!(-4750), "w", dec!(9500)));
    assert_eq!(
        view(&mut fold, 3 * HOUR + 5_000, dec!(4750)),
        Step::Taken { applied: vec![0] }
    );
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(5000), dec!(5000), dec!(4750))
    );
    view(&mut fold, 4 * HOUR, dec!(4650));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn a_deposit_hides_no_loss() {
    // Example 2: 9,500 seen, 9,500 deposited: day start and peak 20,000;
    // 18,780 is 6.1%: halted.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    view(&mut fold, 2 * HOUR, dec!(9500));
    fold.add_flow(exact_flow(3 * HOUR, dec!(9500), "d", dec!(9500)));
    view(&mut fold, 3 * HOUR + 5_000, dec!(19000));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(20000), dec!(20000), dec!(19000))
    );
    view(&mut fold, 4 * HOUR, dec!(18780));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn a_deposit_on_a_day_that_is_up_keeps_the_gain_in_dollars() {
    // Example 3: day start 10,000, 11,000 seen, 11,000 deposited: 21,000
    // (not 20,000); the peak follows the equity to 22,000. 19,740 is 6% of
    // 21,000: halted; 19,741 is not.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    view(&mut fold, 2 * HOUR, dec!(11000));
    fold.add_flow(exact_flow(3 * HOUR, dec!(11000), "d", dec!(11000)));
    view(&mut fold, 3 * HOUR + 5_000, dec!(22000));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(22000), dec!(21000), dec!(22000))
    );
    let mut close = fold.clone();
    view(&mut close, 4 * HOUR, dec!(19741));
    assert_eq!(close.engine.state(), RiskState::Active);
    view(&mut fold, 4 * HOUR, dec!(19740));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn with_the_cap_a_loss_counts_in_dollars() {
    // Example 4: cap 2,000; 110 lost (9,890), 7,890 withdrawn: day start
    // 2,110; 97 more lost (1,903) is 207 / 2,000 = 10.35%: halted.
    let mut fold = fold_at(capped(dec!(2000)), dec!(10000));
    view(&mut fold, 2 * HOUR, dec!(9890));
    fold.add_flow(exact_flow(3 * HOUR, dec!(-7890), "w", dec!(9890)));
    view(&mut fold, 3 * HOUR + 5_000, dec!(2000));
    assert_eq!(figures(&fold).2, dec!(2110));
    view(&mut fold, 4 * HOUR, dec!(1903));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn a_flow_after_midnight_rolls_the_day_first() {
    // Example 5: day 0 ends at 11,000; 5,000 deposited at 00:00:00.5 of day
    // 1, seen at 00:00:05 as 16,000. The flow's own observation rolls the
    // day (day start 11,000), then 16,000; a loss of 1,000 (6.25%) halts.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    view(&mut fold, DAY - 2_000, dec!(11000));
    fold.add_flow(exact_flow(DAY + 500, dec!(5000), "d", dec!(11000)));
    view(&mut fold, DAY + 5_000, dec!(16000));
    let snapshot = fold.engine.snapshot();
    assert_eq!((snapshot.day, snapshot.day_start), (1, dec!(16000)));
    view(&mut fold, DAY + HOUR, dec!(15000));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 1 });
}

#[test]
fn a_measured_loss_after_a_withdrawal_counts_against_the_remainder() {
    // Exact pre-flow10,000, withdraw9000, view900:100/1000=10%, daily halt.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(exact_flow(2 * HOUR, dec!(-9000), "w", dec!(10000)));
    view(&mut fold, 2 * HOUR + 5000, dec!(900));
    assert_eq!(fold.engine.snapshot().peak, dec!(1000));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn an_ambiguous_loss_halts_the_day_but_never_stops() {
    // A legacy range has no exact provenance. Neutral withdrawal leaves
    //1000; normalize to showing500 without attributing a trading loss.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(measured_flow(
        2 * HOUR,
        dec!(-9000),
        dec!(9500),
        dec!(10000),
    ));
    view(&mut fold, 2 * HOUR + 5000, dec!(500));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
    assert_eq!(fold.engine.snapshot().peak, dec!(500));
    view(&mut fold, 2 * HOUR + 10000, dec!(400));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
    // Exact10,000 before withdrawal proves subsequent500/1000=50% loss.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(exact_flow(2 * HOUR, dec!(-9000), "w", dec!(10000)));
    view(&mut fold, 2 * HOUR + 5000, dec!(1000));
    view(&mut fold, 2 * HOUR + 10000, dec!(500));
    assert!(matches!(fold.engine.state(), RiskState::Stopped { .. }));
}

#[test]
fn a_loss_that_would_leave_nothing_after_a_withdrawal_is_no_reading() {
    // 10,000 seen, 9,500 withdrawn, 0 seen: 500 lost. Before the
    // withdrawal, it would leave 9,500 to be withdrawn, emptying the
    // account; after it, it would take the 500 left to zero, which is not
    // a reading either. No reading: the view is left out,
    // current day halted for uncertainty, until money comes back.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(flow(2 * HOUR, dec!(-9500), "w"));
    assert_eq!(view(&mut fold, 2 * HOUR + 5_000, dec!(0)), Step::Left);
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn a_measured_gain_before_a_withdrawal_keeps_the_day_gain() {
    // Exact10,100 before9000 withdrawal: D=10000*1100/10100=1089.11.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(exact_flow(2 * HOUR, dec!(-9000), "w", dec!(10100)));
    view(&mut fold, 2 * HOUR + 5000, dec!(1100));
    assert_eq!(fold.engine.state(), RiskState::Active);
    assert_eq!(fold.engine.snapshot().day_start.round_dp(2), dec!(1089.11));
}

#[test]
fn a_transfer_of_nothing_is_no_withdrawal() {
    // A zero internal transfer does not resize; exact9300 before day1
    // deposit10000 preserves 7% known daily loss: D=10000*19300/9300.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    let mut nothing = exact_flow(DAY - 1000, dec!(0), "t", dec!(10000));
    nothing.between = true;
    fold.add_flow(nothing);
    fold.add_flow(exact_flow(DAY + 1000, dec!(10000), "d", dec!(9300)));
    view(&mut fold, DAY + 5000, dec!(19300));
    assert_eq!(fold.engine.snapshot().day_start.round_dp(2), dec!(20752.69));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 1 });
}

#[test]
fn everything_withdrawn_after_a_measured_fee_is_no_loss() {
    // Exact9995 after five fees: emptying withdrawal merges with1000 refill.
    // Peak=10000*1000/9995=1000.50: only the measured five-dollar loss.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(exact_flow(2 * HOUR, dec!(-9995), "w", dec!(9995)));
    assert_eq!(view(&mut fold, 2 * HOUR + 5000, dec!(0)), Step::Left);
    fold.add_flow(exact_flow(3 * HOUR, dec!(1000), "d", dec!(0)));
    view(&mut fold, 3 * HOUR + 5000, dec!(1000));
    assert_eq!(fold.engine.state(), RiskState::Active);
    assert_eq!(fold.engine.snapshot().peak.round_dp(2), dec!(1000.50));
}

#[test]
fn a_record_knows_a_flow_only_clearly_after_its_horizon() {
    // Before the horizon means at least the margin (2 s) after every time
    // in it.
    let horizon: Horizon = [(String::new(), 8_000)].into();
    assert!(!before_horizon(&flow(10_000, dec!(1), "f"), &horizon));
    assert!(before_horizon(&flow(10_001, dec!(1), "f"), &horizon));
    let two: Horizon = [(String::new(), 7_000), ("xyz".to_owned(), 8_000)].into();
    assert!(!before_horizon(&flow(10_000, dec!(1), "f"), &two));
    assert!(before_horizon(&flow(10_001, dec!(1), "f"), &two));
}

#[test]
fn settle_rolls_a_day_the_replay_did_not_reach_and_keeps_the_positions() {
    use zunder_core::{Side, Symbol};
    use zunder_risk::TrackedPosition;
    let limits = RiskLimits::default();
    let position = TrackedPosition {
        symbol: Symbol::new("BTC"),
        side: Side::Buy,
        qty: dec!(0.1),
        entry: dec!(60000),
        stop: Some(dec!(59000)),
        mark: dec!(60000),
    };
    let before = RiskSnapshot {
        state: RiskState::Active,
        peak: dec!(10000),
        day: 1,
        day_start: dec!(9800),
        last: dec!(9800),
        positions: vec![position],
    };
    // The replay ended on day 0 at 9,500 (a view the record before had
    // rolled past): rolled to day 1, which starts from 9,500.
    let replayed = RiskSnapshot {
        state: RiskState::Active,
        peak: dec!(10000),
        day: 0,
        day_start: dec!(10000),
        last: dec!(9500),
        positions: Vec::new(),
    };
    let settled = settle(&limits, &before, &replayed).unwrap();
    assert_eq!(
        (settled.day, settled.day_start, settled.last),
        (1, dec!(9500), dec!(9500))
    );
    assert_eq!(settled.positions, before.positions);
    // A replay on the same day or a later one is not rolled.
    let same = settle(
        &limits,
        &before,
        &RiskSnapshot {
            day: 1,
            ..replayed.clone()
        },
    )
    .unwrap();
    assert_eq!((same.day, same.day_start), (1, dec!(10000)));
    let later = settle(&limits, &before, &RiskSnapshot { day: 2, ..replayed }).unwrap();
    assert_eq!((later.day, later.day_start), (2, dec!(10000)));
}

#[test]
fn an_emptied_account_is_left_out_until_money_comes_back() {
    // Example 8: 10,000, then 9,600 seen (4% down); everything withdrawn:
    // the view of 0 is left out and the flow waits; 4,800 deposited and
    // seen: one flow of -4,800 from 9,600, peak and day start
    // 10,000 x 4,800 / 9,600 = 5,000, still 4% down and active.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    view(&mut fold, 2 * HOUR, dec!(9600));
    fold.add_flow(exact_flow(3 * HOUR, dec!(-9600), "w", dec!(9600)));
    assert_eq!(view(&mut fold, 3 * HOUR + 5_000, dec!(0)), Step::Left);
    assert_eq!(fold.placed, vec![None]);
    fold.add_flow(exact_flow(4 * HOUR, dec!(4800), "d", dec!(0)));
    assert_eq!(
        view(&mut fold, 4 * HOUR + 5_000, dec!(4800)),
        Step::Taken {
            applied: vec![0, 1]
        }
    );
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(5000), dec!(5000), dec!(4800))
    );
}

#[test]
fn trading_that_took_everything_before_a_deposit_stops_the_engine() {
    // 10,000 seen; a deposit of 100,000 and, before or after it, a loss of
    // 10,000. Before it the account was at 0: the engine observes 0 and
    // stops. (Read after the deposit it would be a 9% fall.) Next to a
    // deposit alone the stricter reading stands: a deposit must not mask a
    // loss (no waiver, which is for withdrawals).
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(exact_flow(2 * HOUR, dec!(100000), "d", dec!(0)));
    view(&mut fold, 2 * HOUR + 5_000, dec!(100000));
    assert!(matches!(fold.engine.state(), RiskState::Stopped { .. }));
}

#[test]
fn a_view_that_may_or_may_not_show_a_flow_is_left_out_but_rolls_the_day() {
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    view(&mut fold, DAY - 10_000, dec!(9800));
    fold.add_flow(exact_flow(DAY - 500, dec!(-5000), "w", dec!(9800)));
    // 00:00:00.5 by the venue: within 2 s of the flow: left out, the day
    // rolls from 9,800.
    assert_eq!(view(&mut fold, DAY + 500, dec!(4800)), Step::Left);
    let snapshot = fold.engine.snapshot();
    assert_eq!(
        (snapshot.day, snapshot.day_start, snapshot.last),
        (1, dec!(9800), dec!(9800))
    );
    // Then shown: the withdrawal moves the new day's start.
    view(&mut fold, DAY + 3_000, dec!(4800));
    assert_eq!(figures(&fold).2, dec!(4800));
    assert_eq!(fold.engine.state(), RiskState::Active);
}

#[test]
fn a_view_that_goes_back_in_venue_time_is_recognised() {
    let horizon: Horizon = [(String::new(), 2 * HOUR), ("xyz".into(), 2 * HOUR + 300)].into();
    let times = |main: i64, xyz: i64| -> BTreeMap<String, i64> {
        [(String::new(), main), ("xyz".into(), xyz)].into()
    };
    assert!(!goes_back(&times(2 * HOUR, 2 * HOUR + 300), &horizon));
    assert!(!goes_back(&times(2 * HOUR + 1, 2 * HOUR + 400), &horizon));
    assert!(goes_back(&times(2 * HOUR - 1, 2 * HOUR + 400), &horizon));
    assert!(goes_back(&times(2 * HOUR + 1, 2 * HOUR + 299), &horizon));
    // A dex not seen before has no time to go back from.
    assert!(!goes_back(&[("abc".into(), 0)].into(), &horizon));
}

#[test]
fn a_flow_of_nothing_moves_nothing_exactly() {
    // A transfer between two dexes without a fee, at odd figures that
    // rebase could not divide exactly.
    let mut fold = fold_at(RiskLimits::default(), dec!(3));
    view(&mut fold, 2 * HOUR, dec!(2.9));
    let before = fold.engine.snapshot();
    fold.add_flow(Flow {
        between: true,
        ..flow(3 * HOUR, Decimal::ZERO, "t")
    });
    view(&mut fold, 3 * HOUR + 5_000, dec!(2.9));
    assert_eq!(fold.engine.snapshot(), before);
}

#[test]
fn a_round_trip_leaves_the_figures_as_they_were() {
    // 10,000, 9,500 (5% down); 9,000 out and back with nothing between.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    view(&mut fold, 2 * HOUR, dec!(9500));
    fold.add_flow(exact_flow(3 * HOUR, dec!(-9000), "w", dec!(9500)));
    view(&mut fold, 3 * HOUR + 5_000, dec!(500));
    fold.add_flow(flow(4 * HOUR, dec!(9000), "d"));
    view(&mut fold, 4 * HOUR + 5_000, dec!(9500));
    let snapshot = fold.engine.snapshot();
    assert!((snapshot.peak - dec!(10000)).abs() < dec!(0.0000000000000000001));
    assert!((snapshot.day_start - dec!(10000)).abs() < dec!(0.0000000000000000001));
}

#[test]
fn settle_keeps_a_halt_of_the_same_day_and_a_stop() {
    let limits = RiskLimits::default();
    let halted = RiskSnapshot {
        state: RiskState::HaltedForDay { day: 0 },
        peak: dec!(10000),
        day: 0,
        day_start: dec!(10000),
        last: dec!(9300),
        positions: Vec::new(),
    };
    let replayed = RiskSnapshot {
        state: RiskState::Active,
        last: dec!(9900),
        ..halted.clone()
    };
    // The replay found no halt (the loss was a withdrawal): the halt stays.
    let settled = settle(&limits, &halted, &replayed).unwrap();
    assert_eq!(settled.state, RiskState::HaltedForDay { day: 0 });
    assert_eq!(settled.last, dec!(9900));
    // On a later day it does not.
    let next_day = RiskSnapshot {
        day: 1,
        ..replayed.clone()
    };
    assert_eq!(
        settle(&limits, &halted, &next_day).unwrap().state,
        RiskState::Active
    );
    // A stop stays whatever the replay says.
    let stopped = RiskSnapshot {
        state: RiskState::Stopped {
            at: at(HOUR),
            drawdown: dec!(0.3),
        },
        last: dec!(7000),
        ..halted
    };
    assert_eq!(
        settle(&limits, &stopped, &replayed).unwrap().state,
        stopped.state
    );
}

fn measured_flow(time: i64, amount: Decimal, lo: Decimal, hi: Decimal) -> Flow {
    Flow {
        value: Some(ValueRange {
            lo,
            hi,
            cash_exact: lo == hi,
        }),
        ..flow(time, amount, "measured")
    }
}

#[test]
fn endpoints_stopping_on_opposite_sides_do_not_prove_an_interior_stop() {
    // 7400: known 26% pre-withdrawal loss. 10000: peak rebases to5000,
    // then3500 is30% down. Interior9000: peak4444.44,3500 is21.25% down.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(measured_flow(
        2 * HOUR,
        dec!(-5000),
        dec!(7400),
        dec!(10000),
    ));
    view(&mut fold, 3 * HOUR, dec!(3500));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
    assert_eq!(fold.waived.len(), 1);
    view(&mut fold, 4 * HOUR, dec!(3500));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn measured_deposit_preserves_a_known_thirty_percent_loss() {
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(measured_flow(2 * HOUR, dec!(90000), dec!(7000), dec!(7000)));
    view(&mut fold, 3 * HOUR, dec!(97000));
    assert!(matches!(fold.engine.state(), RiskState::Stopped { .. }));
}

#[test]
fn unreadable_deposit_halts_even_when_account_value_rose() {
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(flow(2 * HOUR, dec!(90000), "deposit"));
    view(&mut fold, 3 * HOUR, dec!(97000));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
    assert_eq!(fold.waived.len(), 1);
    view(&mut fold, 4 * HOUR, dec!(97000));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn more_than_eight_exact_flows_do_not_require_endpoint_enumeration() {
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    for i in 0..9 {
        let mut entry = measured_flow(
            2 * HOUR + i * 3000,
            dec!(100),
            dec!(10000) + Decimal::from(i) * dec!(100),
            dec!(10000) + Decimal::from(i) * dec!(100),
        );
        entry.id = i.to_string();
        fold.add_flow(entry);
    }
    view(&mut fold, 3 * HOUR, dec!(10900));
    assert_eq!(fold.engine.state(), RiskState::Active);
    assert!(fold.waived.is_empty());
}

fn exact_flow(time: i64, amount: Decimal, id: &str, value: Decimal) -> Flow {
    Flow {
        value: Some(ValueRange::cash_exact(value)),
        ..flow(time, amount, id)
    }
}

#[test]
fn exact_zero_fee_transfer_keeps_the_trusted_gain_checkpoint() {
    // Observe6500 after100 gain on6400, then exact deposit100 at6400.
    // Peak6500 scales by6500/6400, producing6601.5625, not6500.
    let mut fold = fold_at(RiskLimits::default(), dec!(6400));
    fold.add_flow(exact_flow(HOUR, Decimal::ZERO, "zero", dec!(6500)));
    fold.add_flow(exact_flow(2 * HOUR, dec!(100), "deposit", dec!(6400)));
    view(&mut fold, 3 * HOUR, dec!(6500));
    assert!((fold.engine.snapshot().peak - dec!(6601.5625)).abs() < dec!(0.00000000000000000001));
    assert!(fold.waived.is_empty());
}

#[test]
fn exact_loss_before_unknown_flow_stays_stopped() {
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(exact_flow(HOUR, dec!(100), "exact", dec!(7000)));
    fold.add_flow(flow(2 * HOUR, dec!(1000), "unknown"));
    view(&mut fold, 3 * HOUR, dec!(8100));
    assert!(matches!(fold.engine.state(), RiskState::Stopped { .. }));
}

#[test]
fn unknown_gap_does_not_suppress_a_later_exact_loss() {
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(flow(HOUR, dec!(1000), "unknown"));
    fold.add_flow(exact_flow(2 * HOUR, dec!(1000), "exact", dec!(10000)));
    view(&mut fold, 3 * HOUR, dec!(7700));
    assert!(matches!(fold.engine.state(), RiskState::Stopped { .. }));
}

#[test]
fn legacy_singleton_trade_price_is_not_exact_provenance() {
    let range: ValueRange = serde_json::from_str(r#"{"lo":"7000","hi":"7000"}"#).unwrap();
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(Flow {
        value: Some(range),
        ..flow(HOUR, dec!(90000), "legacy")
    });
    view(&mut fold, 2 * HOUR, dec!(97000));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn a_range_cannot_become_exact_even_with_a_cash_origin_bit() {
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(Flow {
        value: Some(ValueRange {
            lo: dec!(7400),
            hi: dec!(10000),
            cash_exact: true,
        }),
        ..flow(HOUR, dec!(500), "invalid-range")
    });
    view(&mut fold, 2 * HOUR, dec!(10500));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn deferred_zero_keeps_an_unrolled_origin_across_three_days() {
    // Exact day1 loss is 1,000/10,000 =10%. Day2 sees zero after an
    // unknown withdrawal; day3 refill of4,500 retains peak5,000 (10%) but
    // starts a new daily base4,500. No day1 daily loss leaks into day3.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    let mut checkpoint = exact_flow(2 * HOUR, dec!(0), "checkpoint", dec!(9000));
    checkpoint.between = true;
    fold.add_flow(checkpoint);
    fold.add_flow(flow(3 * HOUR, dec!(-9000), "unknown-withdrawal"));
    assert_eq!(view(&mut fold, DAY + HOUR, dec!(0)), Step::Left);
    assert_eq!(fold.placed, vec![None, None]);
    assert_eq!(fold.engine.snapshot().last, dec!(10000));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 1 });
    assert_eq!(view(&mut fold, 2 * DAY, dec!(0)), Step::Left);
    fold.add_flow(exact_flow(2 * DAY + HOUR, dec!(4500), "refill", dec!(0)));
    assert!(matches!(
        view(&mut fold, 2 * DAY + 2 * HOUR, dec!(4500)),
        Step::Taken { .. }
    ));
    assert_eq!(
        figures(&fold),
        (
            RiskState::HaltedForDay { day: 2 },
            dec!(5000),
            dec!(4500),
            dec!(4500)
        )
    );
}

#[test]
fn deferred_zero_latches_a_known_exact_prefix_stop_without_partial_money() {
    // 7,000 before an exact500 deposit proves30% loss from10,000.
    // A later unknown7,500 withdrawal empties the account. Retain that
    // Stop immediately, while original monetary bases remain10,000.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(exact_flow(2 * HOUR, dec!(500), "exact", dec!(7000)));
    fold.add_flow(flow(3 * HOUR, dec!(-7500), "unknown"));
    assert_eq!(view(&mut fold, 4 * HOUR, dec!(0)), Step::Left);
    assert!(matches!(fold.engine.state(), RiskState::Stopped { .. }));
    assert_eq!(fold.engine.snapshot().peak, dec!(10000));
    assert_eq!(fold.engine.snapshot().last, dec!(10000));
    assert_eq!(fold.placed, vec![None, None]);
    fold.add_flow(exact_flow(DAY + HOUR, dec!(3750), "refill", dec!(0)));
    view(&mut fold, DAY + 2 * HOUR, dec!(3750));
    assert!(matches!(fold.engine.state(), RiskState::Stopped { .. }));
    assert!(fold.placed.iter().all(Option::is_some));
}

#[test]
fn unknown_span_ending_before_midnight_still_halts_the_showing_day() {
    // Unknown500 deposit then exact500 deposit on day1 leave11,000.
    // The trustworthy right anchor is still day1; a day2 showing view
    // must retain uncertainty on day2, rather than silently roll active.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(flow(2 * HOUR, dec!(500), "unknown"));
    fold.add_flow(exact_flow(3 * HOUR, dec!(500), "exact", dec!(10500)));
    view(&mut fold, DAY + HOUR, dec!(11000));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 1 });
}

#[test]
fn unknown_normalization_preserves_capped_dollar_loss() {
    // Observed100 loss is5% of2,000 cap. Neutral1,000 deposit takes
    // P10,000/e9,900 toP11,000/e10,900. Showing5,000 remains missing
    // history; normalize P to5,100, preserving100 dollars/2,000 cap.
    let mut fold = fold_at(capped(dec!(2000)), dec!(10000));
    view(&mut fold, 2 * HOUR, dec!(9900));
    fold.add_flow(flow(3 * HOUR, dec!(1000), "unknown"));
    view(&mut fold, 4 * HOUR, dec!(5000));
    assert_eq!(
        figures(&fold),
        (
            RiskState::HaltedForDay { day: 0 },
            dec!(5100),
            dec!(5100),
            dec!(5000)
        )
    );
}

#[test]
fn an_already_stopped_zero_day_base_accepts_later_exact_positive_cash() {
    // Stop at700 from1,600; exact500 deposit at pre0 before midnight,
    // then100 at pre500 after it. A stopped midnight rollover makes D0.
    // No cap: P=1600/500*600=1920. Cap1,000: P=600+1100=1700.
    // Only undefined daily base becomes600; the original Stop is exact.
    for (limits, peak) in [
        (RiskLimits::default(), dec!(1920)),
        (capped(dec!(1000)), dec!(1700)),
    ] {
        let mut fold = fold_at(limits, dec!(1600));
        view(&mut fold, DAY - 10000, dec!(700));
        let stopped = fold.engine.state();
        assert!(matches!(stopped, RiskState::Stopped { .. }));
        fold.add_flow(exact_flow(DAY - 5000, dec!(500), "first", dec!(0)));
        fold.add_flow(exact_flow(DAY + 1000, dec!(100), "second", dec!(500)));
        view(&mut fold, DAY + 4000, dec!(600));
        assert_eq!(figures(&fold), (stopped, peak, dec!(600), dec!(600)));
    }
}

#[test]
fn a_stop_proved_inside_a_group_keeps_its_original_reason_through_later_exact_flows() {
    // Exact7,000 from10,000 proves30% Stop at2h. Deposits500 then500
    // preserve that share and must not replace its timestamp with3h.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(exact_flow(2 * HOUR, dec!(500), "first", dec!(7000)));
    fold.add_flow(exact_flow(3 * HOUR, dec!(500), "second", dec!(7500)));
    view(&mut fold, 4 * HOUR, dec!(8000));
    assert_eq!(
        fold.engine.state(),
        RiskState::Stopped {
            at: at(2 * HOUR),
            drawdown: dec!(0.3)
        }
    );
}

#[test]
fn valid_exact_decimal_underflow_defers_without_a_raw_equity_stop() {
    // A huge same-day gain leaves D=0.000001 but P=1e20. Withdraw all
    // except0.000001: exact D rebase underflows Decimal to0. Keep the
    // monetary origin pending; raw observation would invent100% loss.
    let mut fold = fold_at(RiskLimits::default(), dec!(0.000001));
    view(&mut fold, 2 * HOUR, dec!(100000000000000000000));
    fold.add_flow(exact_flow(
        3 * HOUR,
        dec!(-99999999999999999999.999999),
        "withdraw",
        dec!(100000000000000000000),
    ));
    assert_eq!(view(&mut fold, 4 * HOUR, dec!(0.000001)), Step::Left);
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
    assert_eq!(fold.engine.snapshot().last, dec!(100000000000000000000));
    assert_eq!(fold.placed, vec![None]);
    assert!(fold.waived.last().unwrap().reason.is_some());
}

#[test]
fn arithmetic_deferral_keeps_a_stop_proved_in_the_exact_prefix() {
    let mut fold = fold_at(RiskLimits::default(), dec!(0.000001));
    view(&mut fold, 2 * HOUR, dec!(100000000000000000000));
    // A trusted zero-fee checkpoint proves the stop without adding cash
    // to the tiny daily base before the later unrepresentable withdrawal.
    fold.add_flow(exact_flow(
        3 * HOUR,
        dec!(0),
        "prefix",
        dec!(70000000000000000000),
    ));
    fold.add_flow(exact_flow(
        4 * HOUR,
        dec!(-99999999999999999999.999999),
        "underflow",
        dec!(100000000000000000000),
    ));
    assert_eq!(view(&mut fold, 5 * HOUR, dec!(0.000001)), Step::Left);
    assert_eq!(
        fold.engine.state(),
        RiskState::Stopped {
            at: at(3 * HOUR),
            drawdown: dec!(0.3)
        }
    );
    assert_eq!(fold.placed, vec![None, None]);
    assert_eq!(fold.engine.snapshot().last, dec!(100000000000000000000));
}

// Ledger entries the caller cannot account for (`UNKNOWN_TYPE_ID_PREFIX`).
// Default limits: 6% daily stop, 25% drawdown stop. The watched gap is
// Guard's at its default 5 s sync: 3 x 5 s + 4 s + 10 s + 2 s = 31 s
// (`zunder-guard`, `observe::watched_gap_ms`).

const S: i64 = 1_000;
const GAP: i64 = 31 * S;

/// An entry the caller cannot account for at `time_ms` under `rule`,
/// watched through gaps of up to `gap` ms, reading `credit`: booked 0, no
/// value, against every dex's time.
fn unknown_as(time_ms: i64, gap: i64, rule: UnaccountedRule, credit: Decimal) -> Flow {
    Flow {
        between: true,
        unaccounted: Some(UnaccountedEntry {
            watched_gap_ms: gap,
            rule,
            credit,
        }),
        ..flow(
            time_ms,
            Decimal::ZERO,
            &format!("{UNKNOWN_TYPE_ID_PREFIX}0xabc:{time_ms}:hip3LiquidatorDeposit"),
        )
    }
}

/// A classified liquidator transfer (re-basable) reading no credit.
fn unknown_within(time_ms: i64, gap: i64) -> Flow {
    unknown_as(time_ms, gap, UnaccountedRule::Rebasable, Decimal::ZERO)
}

fn unknown_entry(time_ms: i64) -> Flow {
    unknown_within(time_ms, GAP)
}

fn reported(fold: &Fold) -> Vec<Option<Unaccounted>> {
    fold.waived.iter().map(|stop| stop.unaccounted).collect()
}

/// A re-basable entry, watched (the first view showing it 10 s after the
/// last view taken), whose change fits the room and the day's budget: its
/// money. A rise by a deposit's rules; a fall moves the day's start only,
/// never the drawdown peak.
#[test]
fn a_watched_change_within_the_room_is_the_entrys_money() {
    // 10,000 to 10,500: a loss of 500 would be 5% (< 6%); the day's budget
    // is the room then, 600 (6% of 10,000; the drawdown stop's 2,500 is
    // more): 0.06 of the day's start, 0.05 used. As a deposit: P = D = 10,500, active, nothing reported. A
    // trading loss of 629 (5.99% of 10,500) leaves it active; 630 (6%, to
    // 9,870) halts the day.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    view(&mut fold, HOUR + 10 * S, dec!(10500));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(10500), dec!(10500), dec!(10500))
    );
    assert_eq!(fold.placed, vec![Some(1)]);
    assert!(fold.waived.is_empty());
    assert_eq!(
        fold.budget,
        Some(RebaseBudget {
            day: 0,
            room: dec!(0.06),
            used: dec!(0.05)
        })
    );
    view(&mut fold, HOUR + 20 * S, dec!(9871));
    assert_eq!(fold.engine.state(), RiskState::Active);
    view(&mut fold, HOUR + 30 * S, dec!(9870));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
    // 10,000 to 9,500 (5%): the day's start 9,500 (a withdrawal's rules);
    // the peak stays 10,000, so the drawdown is 5%. 570 more (6% of 9,500,
    // to 8,930) halts.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    view(&mut fold, HOUR + 10 * S, dec!(9500));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(10000), dec!(9500), dec!(9500))
    );
    view(&mut fold, HOUR + 20 * S, dec!(8930));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
    // The edge: 599 down (5.99%, under the budget of 600): D = 9,401.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    view(&mut fold, HOUR + 10 * S, dec!(9401));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(10000), dec!(9401), dec!(9401))
    );
}

/// The review's finding: a re-base could absorb a liquidation-sized loss
/// and skip the review a wipe-out needs. A fall bigger than the room
/// counts as the loss it shows, watched or not.
#[test]
fn a_fall_beyond_the_room_counts_as_the_loss_it_shows() {
    // 600 down (6% of 10,000): the daily stop. Counted: halted, P = D =
    // 10,000, last 9,400; reported.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    view(&mut fold, HOUR + 10 * S, dec!(9400));
    assert_eq!(
        figures(&fold),
        (
            RiskState::HaltedForDay { day: 0 },
            dec!(10000),
            dec!(10000),
            dec!(9400)
        )
    );
    assert_eq!(fold.placed, vec![Some(1)]);
    assert_eq!(reported(&fold), vec![Some(Unaccounted::CountedAsLoss)]);
    // 10,000 to 7,000 within 10 s: 30%, a drawdown stop (needs a review).
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    view(&mut fold, HOUR + 10 * S, dec!(7000));
    assert_eq!(
        fold.engine.state(),
        RiskState::Stopped {
            at: at(HOUR + 10 * S),
            drawdown: dec!(0.3)
        }
    );
    // To nothing: a 100% drawdown stop, never deferred.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    view(&mut fold, HOUR + 10 * S, Decimal::ZERO);
    assert_eq!(
        fold.engine.state(),
        RiskState::Stopped {
            at: at(HOUR + 10 * S),
            drawdown: Decimal::ONE
        }
    );
    assert_eq!(fold.placed, vec![Some(1)]);
    // Not watched (2 h between views): the same.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(2 * HOUR));
    view(&mut fold, 3 * HOUR, dec!(7000));
    assert!(matches!(fold.engine.state(), RiskState::Stopped { .. }));
    assert_eq!(reported(&fold), vec![Some(Unaccounted::CountedAsLoss)]);
    // The room is what the day has left: 400 lost trading (4%), then an
    // entry's 300 (to 9,300) would make 7%: counted, halted.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    view(&mut fold, 2 * HOUR, dec!(9600));
    fold.add_flow(unknown_entry(2 * HOUR + 5 * S));
    view(&mut fold, 2 * HOUR + 10 * S, dec!(9300));
    assert_eq!(
        figures(&fold),
        (
            RiskState::HaltedForDay { day: 0 },
            dec!(10000),
            dec!(10000),
            dec!(9300)
        )
    );
}

/// The reviewer's probe: five watched entries, each beside a fall of 5.9%
/// (each under the 6% daily stop on its own), take 10,000 to 7,378.16
/// (26.2%). In one UTC day: the first fits (590 of a budget of 600: the
/// day's start 9,410, the peak kept); the second (555.19) is over the
/// budget and counts (5.9% of 9,410, active, drawdown 11.45%); the third
/// (522.43) would make the day 11.45% down: counted, halted; the fifth
/// takes the drawdown from the 10,000 peak to 26.2%: a drawdown stop.
#[test]
fn repeated_entries_in_one_day_cannot_hide_a_drawdown() {
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    let mut equity = dec!(10000);
    let mut states = Vec::new();
    for k in 1..=5 {
        equity *= dec!(0.941);
        fold.add_flow(Flow {
            id: format!("{UNKNOWN_TYPE_ID_PREFIX}0x{k}:liquidator"),
            ..unknown_entry(HOUR + k * 20 * S - 5 * S)
        });
        view(&mut fold, HOUR + k * 20 * S, equity);
        states.push(fold.engine.state());
        if k == 1 {
            assert_eq!(
                figures(&fold),
                (RiskState::Active, dec!(10000), dec!(9410), dec!(9410))
            );
        }
        if k == 2 {
            assert_eq!(
                figures(&fold),
                (RiskState::Active, dec!(10000), dec!(9410), dec!(8854.81))
            );
        }
    }
    assert_eq!(equity.normalize(), dec!(7378.16081880701));
    assert_eq!(states[2], RiskState::HaltedForDay { day: 0 });
    assert_eq!(states[3], RiskState::HaltedForDay { day: 0 });
    assert!(matches!(states[4], RiskState::Stopped { .. }));
    assert_eq!(fold.engine.snapshot().peak, dec!(10000));
    assert_eq!(
        fold.budget,
        Some(RebaseBudget {
            day: 0,
            room: dec!(0.06),
            used: dec!(0.059)
        })
    );
}

/// The same five, one a day: each fits its day's budget (590 of 600,
/// 555.19 of 564.6, 522.43 of 531.29, 491.61 of 499.94), so each day starts
/// where the last ended and is not down; but the peak is never lowered, so
/// the drawdown adds up (5.9%, 11.45%, 16.68%, 21.59%), and the fifth fall,
/// to 26.22% of 10,000, is a drawdown stop.
#[test]
fn repeated_entries_one_a_day_cannot_hide_a_drawdown() {
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    let mut equity = dec!(10000);
    for k in 1..=5_i64 {
        let start = k * DAY + HOUR;
        view(&mut fold, start, equity);
        equity *= dec!(0.941);
        fold.add_flow(Flow {
            id: format!("{UNKNOWN_TYPE_ID_PREFIX}0x{k}:liquidator"),
            ..unknown_entry(start + 5 * S)
        });
        view(&mut fold, start + 10 * S, equity);
        let snapshot = fold.engine.snapshot();
        assert_eq!(snapshot.peak, dec!(10000), "day {k}");
        if k < 5 {
            assert_eq!(snapshot.state, RiskState::Active, "day {k}");
            assert_eq!(snapshot.day_start, equity, "day {k}");
            assert_eq!(fold.budget.as_ref().map(|budget| budget.day), Some(k));
        } else {
            assert!(
                matches!(snapshot.state, RiskState::Stopped { .. }),
                "{snapshot:?}"
            );
        }
    }
}

/// A rise bigger than the room or the day's budget may hide a trading loss
/// up to its size; a rise the caller did not watch may hide trading it
/// could not see: the day halts, as for any flow whose value is unknown
/// (the bases normalised on the view, never a stop). A fall not watched
/// counts as the loss it shows.
#[test]
fn a_rise_beyond_the_room_or_not_watched_halts_the_day() {
    // 10,000 to 13,000 within 10 s: a loss of 3,000 would be 30%. Halted;
    // P = D = 13,000 (the span normalised).
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    view(&mut fold, HOUR + 10 * S, dec!(13000));
    assert_eq!(
        figures(&fold),
        (
            RiskState::HaltedForDay { day: 0 },
            dec!(13000),
            dec!(13000),
            dec!(13000)
        )
    );
    assert_eq!(reported(&fold), vec![Some(Unaccounted::RiseBeyondRoom)]);
    // A restart, or reads that failed: the last view at 1 h, the entry at
    // 2 h, the first view after it at 3 h, 200 up: halted, P = D = 10,200.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(2 * HOUR));
    view(&mut fold, 3 * HOUR, dec!(10200));
    assert_eq!(
        figures(&fold),
        (
            RiskState::HaltedForDay { day: 0 },
            dec!(10200),
            dec!(10200),
            dec!(10200)
        )
    );
    assert_eq!(reported(&fold), vec![Some(Unaccounted::NotWatched)]);
    // 200 down, not watched: counted (2%, active), P = D = 10,000.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(2 * HOUR));
    view(&mut fold, 3 * HOUR, dec!(9800));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(10000), dec!(10000), dec!(9800))
    );
    assert_eq!(reported(&fold), vec![Some(Unaccounted::CountedAsLoss)]);
    // Unchanged, watched or not: nothing moves, active.
    for (entry, shown) in [(HOUR + 5 * S, HOUR + 10 * S), (2 * HOUR, 3 * HOUR)] {
        let mut fold = fold_at(RiskLimits::default(), dec!(10000));
        fold.add_flow(unknown_entry(entry));
        view(&mut fold, shown, dec!(10000));
        assert_eq!(
            figures(&fold),
            (RiskState::Active, dec!(10000), dec!(10000), dec!(10000))
        );
        assert!(fold.waived.is_empty());
    }
}

/// A credit the caller reads (a liquidator withdrawal's USDC amount) is
/// taken as money in first; only the rest of the change is judged, and a
/// debit is never added back.
#[test]
fn a_readable_credit_never_hides_a_loss() {
    let credit = |shown: Decimal| {
        let mut fold = fold_at(RiskLimits::default(), dec!(10000));
        fold.add_flow(unknown_as(
            HOUR + 5 * S,
            GAP,
            UnaccountedRule::Rebasable,
            dec!(3000),
        ));
        view(&mut fold, HOUR + 10 * S, shown);
        fold
    };
    // 3,000 in and 2,700 lost trading: 10,300 shown. The credit as a
    // deposit (P = D = 13,000); the rest, -2,700, is 20.77% of 13,000:
    // over the room, counted, halted. Not re-based as +300.
    let fold = credit(dec!(10300));
    assert_eq!(
        figures(&fold),
        (
            RiskState::HaltedForDay { day: 0 },
            dec!(13000),
            dec!(13000),
            dec!(10300)
        )
    );
    assert_eq!(reported(&fold), vec![Some(Unaccounted::CountedAsLoss)]);
    // The 3,000 came, nothing else: P = D = 13,000, active.
    let fold = credit(dec!(13000));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(13000), dec!(13000), dec!(13000))
    );
    // Read but never came: -3,000 of 13,000 (23.08%) counted, halted.
    let fold = credit(dec!(10000));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
    // A credit is read only for a re-basable entry.
    assert!(
        unknown_as(HOUR, GAP, UnaccountedRule::Strict, dec!(1))
            .check()
            .is_err()
    );
}

/// The types that may never be taken as money: a fall counts, a rise
/// halts; a type read as a dollar credit halts the day whatever the change
/// (a fall counted as well); in one span the strictest rule holds.
#[test]
fn only_the_listed_types_are_ever_taken_as_money() {
    let judged = |rule: UnaccountedRule, shown: Decimal| {
        let mut fold = fold_at(RiskLimits::default(), dec!(10000));
        fold.add_flow(unknown_as(HOUR + 5 * S, GAP, rule, Decimal::ZERO));
        view(&mut fold, HOUR + 10 * S, shown);
        (figures(&fold), reported(&fold))
    };
    let halted = RiskState::HaltedForDay { day: 0 };
    // Strict: 100 down (1%, which a liquidator transfer would re-base)
    // counts, active; 100 up halts.
    assert_eq!(
        judged(UnaccountedRule::Strict, dec!(9900)),
        (
            (RiskState::Active, dec!(10000), dec!(10000), dec!(9900)),
            vec![Some(Unaccounted::CountedAsLoss)]
        )
    );
    assert_eq!(
        judged(UnaccountedRule::Strict, dec!(10100)),
        (
            (halted, dec!(10100), dec!(10100), dec!(10100)),
            vec![Some(Unaccounted::RiseNotRebased)]
        )
    );
    // Halts: 100 down counts and halts; unchanged or up halts.
    assert_eq!(
        judged(UnaccountedRule::Halts, dec!(9900)),
        (
            (halted, dec!(10000), dec!(10000), dec!(9900)),
            vec![Some(Unaccounted::Halted)]
        )
    );
    assert_eq!(judged(UnaccountedRule::Halts, dec!(10000)).0.0, halted);
    assert_eq!(judged(UnaccountedRule::Halts, dec!(10100)).0.0, halted);
    // A liquidator transfer beside a strict entry: 100 down counts.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    fold.add_flow(Flow {
        id: format!("{UNKNOWN_TYPE_ID_PREFIX}0xdef:welcomeBonus"),
        ..unknown_as(HOUR + 6 * S, GAP, UnaccountedRule::Strict, Decimal::ZERO)
    });
    view(&mut fold, HOUR + 10 * S, dec!(9900));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(10000), dec!(10000), dec!(9900))
    );
}

/// The watched gap is the flow's own (the caller's sync interval when it
/// learned the entry), measured on every dex from the last view taken.
#[test]
fn the_watched_gap_is_the_flows_own() {
    // 100 up: taken as money when watched (P = D = 10,100), else halted.
    let up = |gap: i64, after: i64| {
        let mut fold = fold_at(RiskLimits::default(), dec!(10000));
        fold.add_flow(unknown_within(HOUR + 15 * S, gap));
        view(&mut fold, HOUR + after, dec!(10100));
        fold.engine.state()
    };
    // Guard at 5 s: 31 s; 31 s after the last view is watched, 31.001 s
    // is not.
    assert_eq!(up(GAP, 31 * S), RiskState::Active);
    assert_eq!(up(GAP, 31 * S + 1), RiskState::HaltedForDay { day: 0 });
    // Guard with two HIP-3 dexes (sync every 20,770 ms): 3 x 20,770 + 16,000
    // = 78,310 ms. The old fixed 30 s halted here.
    assert_eq!(up(78_310, 78_310), RiskState::Active);
    assert_eq!(up(78_310, 78_311), RiskState::HaltedForDay { day: 0 });
    // Two entries in one group: the smaller gap holds.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_within(HOUR + 15 * S, 78_310));
    fold.add_flow(Flow {
        id: format!("{UNKNOWN_TYPE_ID_PREFIX}0xdef:{}:x", HOUR + 16 * S),
        ..unknown_within(HOUR + 16 * S, GAP)
    });
    view(&mut fold, HOUR + 40 * S, dec!(10100));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
    // A dex the last view taken did not have is not watched.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    fold.view(&SeenView {
        at: at(HOUR + 10 * S),
        times: [
            (String::new(), HOUR + 10 * S),
            ("xyz".to_owned(), HOUR + 10 * S),
        ]
        .into(),
        equity: dec!(10100),
    })
    .unwrap();
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

/// A view left out (it may or may not show the entry) is no view taken:
/// the gap runs from the last view the engine took.
#[test]
fn a_view_left_out_does_not_count_as_watching() {
    // The entry at 1 h + 20 s. A view at 1 h + 19 s may show it: left out.
    // The next, at 1 h + 33 s, is 33 s after the last taken (1 h): not
    // watched, 100 up halts.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 20 * S));
    assert_eq!(view(&mut fold, HOUR + 19 * S, dec!(10100)), Step::Left);
    view(&mut fold, HOUR + 33 * S, dec!(10100));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
    // A view at 1 h + 17 s stands before it (17 < 20 - 2): taken. The
    // next is then 16 s on: watched, P = D = 10,100.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 20 * S));
    assert_eq!(
        view(&mut fold, HOUR + 17 * S, dec!(10000)),
        Step::Taken { applied: vec![] }
    );
    view(&mut fold, HOUR + 33 * S, dec!(10100));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(10100), dec!(10100), dec!(10100))
    );
}

/// A replay from a record starts watching from that record's horizon and
/// spends from its budget (the writer's and the reader's replay alike); a
/// journal that has seen no view (right after `zunder-guard init`) has
/// watched nothing: a rise beside an entry before its first view halts.
#[test]
fn a_replay_starts_from_its_bases_horizon_and_budget() {
    let limits = RiskLimits::default();
    let base = RiskEngine::new(limits.clone(), at(0), dec!(10000))
        .unwrap()
        .snapshot();
    let entry = unknown_entry(HOUR + 10 * S);
    let showing = |equity: Decimal| SeenView {
        at: at(HOUR + 20 * S),
        times: [(String::new(), HOUR + 20 * S)].into(),
        equity,
    };
    let from = |horizon: Horizon, budget: Option<&RebaseBudget>, equity: Decimal| {
        replay(
            &limits,
            &base,
            &horizon,
            budget,
            std::slice::from_ref(&showing(equity)),
            std::slice::from_ref(&entry),
        )
        .unwrap()
    };
    let hour: Horizon = [(String::new(), HOUR)].into();
    // From a record whose horizon is 1 h: 20 s on, watched.
    let replayed = from(hour.clone(), None, dec!(10100));
    assert_eq!(replayed.snapshot.state, RiskState::Active);
    assert_eq!(
        (replayed.snapshot.peak, replayed.snapshot.day_start),
        (dec!(10100), dec!(10100))
    );
    assert_eq!(replayed.placed, vec![Some(0)]);
    // From the journal's start (no horizon): not watched.
    let replayed = from(Horizon::new(), None, dec!(10100));
    assert_eq!(replayed.snapshot.state, RiskState::HaltedForDay { day: 0 });
    // From a base whose day had used 0.055 of a 0.06 budget (550 of 600 on
    // 10,000): 100 more (0.01) does not fit, and the fall counts (active,
    // 1%).
    let spent = RebaseBudget {
        day: 0,
        room: dec!(0.06),
        used: dec!(0.055),
    };
    let replayed = from(hour.clone(), Some(&spent), dec!(9900));
    assert_eq!(
        (replayed.snapshot.state, replayed.snapshot.day_start),
        (RiskState::Active, dec!(10000))
    );
    assert_eq!(replayed.budget, Some(spent.clone()));
    // A budget of an earlier day is no budget: a fresh 0.06, 0.01 used.
    let yesterday = RebaseBudget { day: -1, ..spent };
    let replayed = from(hour, Some(&yesterday), dec!(9900));
    assert_eq!(replayed.snapshot.day_start, dec!(9900));
    assert_eq!(
        replayed.budget,
        Some(RebaseBudget {
            day: 0,
            room: dec!(0.06),
            used: dec!(0.01)
        })
    );
}

/// An exact flow and an entry the caller cannot account for in one group.
#[test]
fn an_exact_flow_beside_an_unknown_entry_keeps_its_exact_value() {
    // 10,000 at 1 h. The entry at +5 s; a deposit of 500 at +6 s whose
    // value just before was exactly 9,900; the view at +10 s shows 10,450.
    // The entry's span ends at the deposit's anchor: 10,000 to 9,900, 100
    // (1%), the day's start 9,900, the peak kept at 10,000. The deposit:
    // 9,900 to 10,400, the peak 10,000 x 10,400 / 9,900 = 10,505.05, the
    // day's start 10,400. Then 50 of trading: last 10,450.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    fold.add_flow(exact_flow(HOUR + 6 * S, dec!(500), "deposit", dec!(9900)));
    view(&mut fold, HOUR + 10 * S, dec!(10450));
    let snapshot = fold.engine.snapshot();
    assert_eq!(snapshot.state, RiskState::Active);
    assert_eq!(snapshot.peak.round_dp(2), dec!(10505.05));
    assert_eq!(snapshot.day_start.normalize(), dec!(10400));
    assert_eq!(snapshot.last.normalize(), dec!(10450));
    assert_eq!(fold.placed, vec![Some(1), Some(1)]);
    assert!(fold.waived.is_empty());
}

/// UTC midnight between the last view and the entry: the day rolls at the
/// entry first, and the room and the budget are the new day's.
#[test]
fn a_day_rolling_before_the_entry_rolls_first() {
    // Day 0: 10,000, then 9,500 at 23:59:50 (5% down, active). The entry
    // at 00:00:05 of day 1, the view at 00:00:15 shows 9,000 (25 s on:
    // watched). Rolled, the day starts at 9,500: a loss of 500 is 5.26%
    // (the budget is 6% of 9,500, 570), and 10% from the 10,000 peak:
    // within. The day's start 9,000; the peak kept at 10,000. Unrolled,
    // 1,000 of 10,000 (10%) would have halted it.
    let limits = RiskLimits::default();
    let engine = RiskEngine::new(limits.clone(), at(0), dec!(10000)).unwrap();
    let mut fold = Fold::new(limits, engine, Horizon::new(), None);
    view(&mut fold, DAY - 10 * S, dec!(9500));
    fold.add_flow(unknown_entry(DAY + 5 * S));
    view(&mut fold, DAY + 15 * S, dec!(9000));
    let snapshot = fold.engine.snapshot();
    assert_eq!(snapshot.state, RiskState::Active);
    assert_eq!(snapshot.day, 1);
    assert_eq!(snapshot.day_start.normalize(), dec!(9000));
    assert_eq!(snapshot.peak, dec!(10000));
    // 570 of 9,500 is 0.06; 500 of 9,500 is 0.0526...
    let budget = fold.budget.unwrap();
    assert_eq!((budget.day, budget.room), (1, dec!(0.06)));
    assert_eq!(budget.used.round_dp(6), dec!(0.052632));
}

/// The budget is a share of the day's start, so a known withdrawal scales
/// what is left of it as it scales the day's start (the reviewer's
/// numbers): 500 of 10,000 re-based (0.05 of a 0.06 budget), then 9,000
/// withdrawn exactly at 9,500, the day's start 500 and the peak 10,000 x 500
/// / 9,500 = 526.32. A second entry beside 25 down (5% of 500, within the
/// room) would be 0.05 more: over the budget, it counts (active, the day's
/// start still 500). In dollars, 525 of 600 would have re-based it.
#[test]
fn a_known_withdrawal_scales_the_days_budget() {
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    view(&mut fold, HOUR + 10 * S, dec!(9500));
    fold.add_flow(exact_flow(
        HOUR + 15 * S,
        dec!(-9000),
        "withdrawal",
        dec!(9500),
    ));
    view(&mut fold, HOUR + 20 * S, dec!(500));
    let snapshot = fold.engine.snapshot();
    assert_eq!(
        (snapshot.day_start.normalize(), snapshot.peak.round_dp(2)),
        (dec!(500), dec!(526.32))
    );
    fold.add_flow(Flow {
        id: format!("{UNKNOWN_TYPE_ID_PREFIX}0x2:liquidator"),
        ..unknown_entry(HOUR + 25 * S)
    });
    view(&mut fold, HOUR + 30 * S, dec!(475));
    let snapshot = fold.engine.snapshot();
    assert_eq!(snapshot.state, RiskState::Active);
    assert_eq!(snapshot.day_start.normalize(), dec!(500));
    assert_eq!(snapshot.last.normalize(), dec!(475));
    assert_eq!(reported(&fold), vec![Some(Unaccounted::CountedAsLoss)]);
    assert_eq!(
        fold.budget,
        Some(RebaseBudget {
            day: 0,
            room: dec!(0.06),
            used: dec!(0.05)
        })
    );
}

/// With an equity cap the room is in dollars of the cap.
#[test]
fn with_the_cap_the_room_is_in_dollars() {
    // Cap 2,000, account 10,000: the daily stop is 120 (6% of 2,000). 100
    // down (5%): within, the day's start moved by the amount at the cap,
    // 9,900; the peak kept at 10,000 (5% of the cap down).
    let mut fold = fold_at(capped(dec!(2000)), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    view(&mut fold, HOUR + 10 * S, dec!(9900));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(10000), dec!(9900), dec!(9900))
    );
    // 120 down: counted, halted, P = D = 10,000.
    let mut fold = fold_at(capped(dec!(2000)), dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    view(&mut fold, HOUR + 10 * S, dec!(9880));
    assert_eq!(
        figures(&fold),
        (
            RiskState::HaltedForDay { day: 0 },
            dec!(10000),
            dec!(10000),
            dec!(9880)
        )
    );
}

#[test]
fn a_transfer_of_nothing_after_an_unknown_entry_never_halts() {
    // Two dexes (main 9,000, xyz 1,000). An unknown entry at +5 s, then a
    // send of 500 from main to xyz without a fee whose value could not be
    // reconstructed (between, 0, no value) at +6 s; the view at +10 s shows
    // 10,500 in all. Alone the send moves nothing; with the entry the 500
    // (5%, within the room and the budget of 600) is the entry's: P = D =
    // 10,500, active.
    let engine = RiskEngine::new(RiskLimits::default(), at(0), dec!(10000)).unwrap();
    let mut fold = Fold::new(RiskLimits::default(), engine, Horizon::new(), None);
    let both = |fold: &mut Fold, ms: i64, equity: Decimal| {
        fold.view(&SeenView {
            at: at(ms),
            times: [(String::new(), ms), ("xyz".to_owned(), ms)].into(),
            equity,
        })
        .unwrap()
    };
    both(&mut fold, HOUR, dec!(10000));
    fold.add_flow(unknown_entry(HOUR + 5 * S));
    fold.add_flow(Flow {
        between: true,
        ..flow(HOUR + 6 * S, Decimal::ZERO, "send")
    });
    both(&mut fold, HOUR + 10 * S, dec!(10500));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(10500), dec!(10500), dec!(10500))
    );
}

#[test]
fn an_unknown_entry_waits_for_a_view_every_dex_of_which_shows_it() {
    // The entry at T = 1 h + 10 s, on a dex nobody knows. A view whose
    // main dex was read at T - 2.5 s and xyz at T + 0.5 s may or may not
    // show it: left out (by main alone it would be before it, and xyz's
    // change counted as trading). The next, both at T + 3 s (13 s after
    // the last taken), shows it: 300 down (3%), D = 9,700, P kept.
    let engine = RiskEngine::new(RiskLimits::default(), at(0), dec!(10000)).unwrap();
    let mut fold = Fold::new(RiskLimits::default(), engine, Horizon::new(), None);
    let t = HOUR + 10 * S;
    let seen = |main: i64, xyz: i64, equity: Decimal| SeenView {
        at: at(main.max(xyz)),
        times: [(String::new(), main), ("xyz".to_owned(), xyz)].into(),
        equity,
    };
    fold.view(&seen(HOUR, HOUR, dec!(10000))).unwrap();
    fold.add_flow(unknown_entry(t));
    let step = fold.view(&seen(t - 2_500, t + 500, dec!(9700))).unwrap();
    assert_eq!(step, Step::Left);
    assert_eq!(fold.engine.state(), RiskState::Active);
    fold.view(&seen(t + 3 * S, t + 3 * S, dec!(9700))).unwrap();
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(10000), dec!(9700), dec!(9700))
    );
}

#[test]
fn an_unknown_credit_on_an_up_day_keeps_the_gain_in_dollars() {
    // Day's start 10,000; trading to 12,000 (+20%, peak 12,000). The room:
    // a loss of c from 12,000 keeps (c - 2,000) / 10,000 under 6% and c /
    // 12,000 under 25%, so c < 2,600 (the budget). An unknown credit shows
    // 14,400 (2,400) within 10 s. As a deposit's: the peak 12,000 x 14,400
    // / 12,000 = 14,400; the day's start the larger of 10,000 x 14,400 /
    // 12,000 = 12,000 and 10,000 + 2,400 = 12,400 (the 2,000 gain stays
    // 2,000). The 6% stop is then at 11,656 (744 of 12,400), not 11,280.
    let mut fold = fold_at(RiskLimits::default(), dec!(10000));
    view(&mut fold, 2 * HOUR, dec!(12000));
    fold.add_flow(unknown_entry(2 * HOUR + 5 * S));
    view(&mut fold, 2 * HOUR + 10 * S, dec!(14400));
    assert_eq!(
        figures(&fold),
        (RiskState::Active, dec!(14400), dec!(12400), dec!(14400))
    );
    view(&mut fold, 2 * HOUR + 20 * S, dec!(11657));
    assert_eq!(fold.engine.state(), RiskState::Active);
    view(&mut fold, 2 * HOUR + 30 * S, dec!(11656));
    assert_eq!(fold.engine.state(), RiskState::HaltedForDay { day: 0 });
}

/// A flow for an entry the caller cannot account for is well formed only
/// as a transfer of nothing between the accounts, without a value, with a
/// watched gap of 1 ms to 2 minutes and a credit of 0 or more (more only
/// when re-basable); no other flow carries one. A replay (the writer's and
/// the reader's) refuses any other.
#[test]
fn a_malformed_unknown_entry_is_refused() {
    let good = unknown_entry(HOUR);
    assert_eq!(good.check(), Ok(()));
    assert_eq!(
        unknown_within(HOUR, UNKNOWN_TYPE_GAP_MAX_MS).check(),
        Ok(())
    );
    assert_eq!(UNKNOWN_TYPE_GAP_MAX_MS, 120_000);
    assert_eq!(unknown_within(HOUR, 1).check(), Ok(()));
    assert_eq!(
        unknown_as(HOUR, GAP, UnaccountedRule::Rebasable, dec!(5)).check(),
        Ok(())
    );
    let bad = [
        Flow {
            unaccounted: None,
            ..good.clone()
        },
        unknown_within(HOUR, 0),
        unknown_within(HOUR, UNKNOWN_TYPE_GAP_MAX_MS + 1),
        unknown_as(HOUR, GAP, UnaccountedRule::Rebasable, dec!(-1)),
        unknown_as(HOUR, GAP, UnaccountedRule::Halts, dec!(1)),
        Flow {
            amount: dec!(5),
            ..good.clone()
        },
        Flow {
            between: false,
            ..good.clone()
        },
        Flow {
            value: Some(ValueRange::cash_exact(dec!(10000))),
            ..good.clone()
        },
        Flow {
            unaccounted: good.unaccounted.clone(),
            ..flow(HOUR, dec!(5), "deposit")
        },
    ];
    let limits = RiskLimits::default();
    let base = RiskEngine::new(limits.clone(), at(0), dec!(10000))
        .unwrap()
        .snapshot();
    for flow in bad {
        assert!(flow.check().is_err(), "{flow:?}");
        assert!(replay(&limits, &base, &Horizon::new(), None, &[], &[flow]).is_err());
    }
}
