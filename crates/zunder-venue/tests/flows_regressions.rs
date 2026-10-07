// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Regression scenarios for persistent account-flow accounting, with
//! hand-computed expected values. See `docs/guard.md#deposits-and-withdrawals`.
//! Default limits: 6% daily loss and 25% drawdown. Test identifiers are
//! stable so failures can be compared across runs.

#![allow(clippy::unwrap_used)]

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use rust_decimal::{Decimal, dec};
use zunder_core::{Side, Symbol, Timestamp};
use zunder_risk::{RiskLimits, RiskSnapshot, RiskState, VenueView};
use zunder_venue::{
    Flow, FlowOutcome, JournalError, JournalEvent, JournalRecord, PersistentRisk, SeenView,
    ValueRange,
};

const HOUR: i64 = Timestamp::MS_PER_HOUR;
const DAY: i64 = Timestamp::MS_PER_DAY;

fn at(ms: i64) -> Timestamp {
    Timestamp::from_millis(ms)
}

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "zunder-flows-regression-{name}-{}-{unique}",
            std::process::id()
        ));
        fs::remove_dir_all(&path).ok();
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn journal(&self) -> PathBuf {
        self.0.join("risk.jsonl")
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

fn capped() -> RiskLimits {
    RiskLimits {
        max_trading_equity_usd: Some(dec!(2000)),
        ..RiskLimits::default()
    }
}

/// A journal started at `equity` at time 0, seen once at 1 h.
fn start(dir: &Dir, limits: RiskLimits, equity: Decimal) -> PersistentRisk {
    let mut risk = PersistentRisk::initialise(&dir.journal(), limits, at(0), equity, "test")
        .unwrap()
        .with_flows();
    seen(&mut risk, HOUR, equity);
    risk
}

fn reopen(dir: &Dir, limits: &RiskLimits, risk: PersistentRisk) -> PersistentRisk {
    drop(risk);
    PersistentRisk::open(&dir.journal(), limits)
        .unwrap()
        .with_flows()
}

/// A view of the main dex read at `ms` and observed then.
fn seen(risk: &mut PersistentRisk, ms: i64, equity: Decimal) -> RiskState {
    let sync = risk.observe_view_at(
        at(ms),
        [(String::new(), ms)].into(),
        equity,
        &VenueView::default(),
        true,
    );
    assert_eq!(sync.journal_error, None);
    sync.state
}

fn flow(time_ms: i64, amount: Decimal, id: &str) -> Flow {
    Flow {
        time_ms,
        amount,
        id: id.into(),
        dex: String::new(),
        between: false,
        value: None,
    }
}

fn reading(time_ms: i64, amount: Decimal, id: &str, before: Decimal) -> Flow {
    Flow {
        value: Some(ValueRange::cash_exact(before)),
        ..flow(time_ms, amount, id)
    }
}

#[test]
fn unknown_zero_anchor_keeps_cash_pending_and_halts_without_journal_error() {
    let dir = Dir::new("unknown-zero-anchor");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(100));
    report(
        &mut risk,
        HOUR + 1000,
        flow(HOUR + 1000, dec!(100), "unread-deposit"),
    );
    // Missing history cannot establish a trading loss from 200 to zero.
    // Preserve 100/100/100 and keep the cash event pending until refill.
    assert!(matches!(
        seen(&mut risk, HOUR + 3000, Decimal::ZERO),
        RiskState::HaltedForDay { .. }
    ));
    assert_eq!(
        (
            snapshot(&risk).peak,
            snapshot(&risk).day_start,
            snapshot(&risk).last
        ),
        (dec!(100), dec!(100), dec!(100))
    );
    risk = reopen(&dir, &limits, risk);
    assert!(matches!(risk.state(), RiskState::HaltedForDay { .. }));
    assert!(matches!(
        seen(&mut risk, HOUR + 5000, dec!(200)),
        RiskState::HaltedForDay { .. }
    ));
    assert_eq!(
        (
            snapshot(&risk).peak,
            snapshot(&risk).day_start,
            snapshot(&risk).last
        ),
        (dec!(200), dec!(200), dec!(200))
    );
}

#[test]
fn exact_prefix_stop_survives_deferred_unknown_zero_anchor() {
    let dir = Dir::new("prefix-stop-unknown-zero");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    // 3000/10000 = 30% observed loss proves the human stop before the
    // unread deposit; a zero final anchor defers all cash placement.
    report(
        &mut risk,
        HOUR + 1000,
        reading(HOUR + 1000, dec!(1), "exact", dec!(7000)),
    );
    report(
        &mut risk,
        HOUR + 2000,
        flow(HOUR + 2000, dec!(100), "unknown"),
    );
    assert!(matches!(
        seen(&mut risk, HOUR + 4000, Decimal::ZERO),
        RiskState::Stopped { .. }
    ));
    assert_eq!(
        (
            snapshot(&risk).peak,
            snapshot(&risk).day_start,
            snapshot(&risk).last
        ),
        (dec!(10000), dec!(10000), dec!(10000))
    );
}

#[test]
fn deferred_origin_survives_midnight_retention_restart_and_refill_once() {
    for cap in [None, Some(dec!(2000))] {
        let dir = Dir::new("deferred-origin-retention");
        let limits = RiskLimits {
            max_trading_equity_usd: cap,
            ..RiskLimits::default()
        };
        let mut risk = start(&dir, limits.clone(), dec!(10000));
        let loss = if cap.is_some() { dec!(140) } else { dec!(700) };
        let before = dec!(10000) - loss;
        let after = before + dec!(1000);
        let prefix = reading(DAY - 10000, dec!(1000), "prefix", before);
        let withdrawal = flow(DAY - 5000, -after, "unknown-withdrawal");
        report(&mut risk, DAY - 20000, prefix.clone());
        report(&mut risk, DAY - 20000, withdrawal.clone());
        assert_eq!(risk.check_ready(), Err(JournalError::PendingFlows));
        assert_eq!(
            seen(&mut risk, DAY + 5000, Decimal::ZERO),
            RiskState::HaltedForDay { day: 1 }
        );
        assert_eq!(
            (
                snapshot(&risk).peak,
                snapshot(&risk).day_start,
                snapshot(&risk).last
            ),
            (dec!(10000), dec!(10000), dec!(10000))
        );
        assert_eq!(risk.take_waived_stops().len(), 1);
        // Refeeding the identical deferred view cannot alert twice.
        seen(&mut risk, DAY + 5000, Decimal::ZERO);
        assert!(risk.take_waived_stops().is_empty());
        risk = reopen(&dir, &limits, risk);
        // More than 24h since origin and 30min since the first deferred
        // view: neither ordinary history retention window may drop it.
        assert_eq!(
            seen(&mut risk, 2 * DAY + HOUR, Decimal::ZERO),
            RiskState::HaltedForDay { day: 2 }
        );
        assert_eq!(risk.check_ready(), Err(JournalError::PendingFlows));
        assert_eq!(snapshot(&risk).day_start, dec!(10000));
        risk = reopen(&dir, &limits, risk);
        let refill = flow(2 * DAY + HOUR + 1000, dec!(20000), "refill");
        report(&mut risk, 2 * DAY + HOUR + 1000, refill.clone());
        assert_eq!(
            seen(&mut risk, 2 * DAY + HOUR + 4000, dec!(20000)),
            RiskState::HaltedForDay { day: 2 }
        );
        // S6 conserves the known 7% drawdown exactly once. With cap:
        // peak=20000+140. Without cap: peak=20000/(1-.07).
        let peak = if cap.is_some() {
            dec!(20140)
        } else {
            dec!(20000) / dec!(0.93)
        };
        assert_eq!(snapshot(&risk).peak.round_dp(12), peak.round_dp(12));
        assert_eq!(
            (snapshot(&risk).day_start, snapshot(&risk).last),
            (dec!(20000), dec!(20000))
        );
        assert!(risk.check_ready().is_ok());
        let settled = snapshot(&risk);
        risk = reopen(&dir, &limits, risk);
        for event in [prefix, withdrawal, refill] {
            assert_eq!(
                report(&mut risk, 2 * DAY + HOUR + 5000, event),
                FlowOutcome::Duplicate
            );
        }
        seen(&mut risk, 2 * DAY + HOUR + 6000, dec!(20000));
        assert_eq!(snapshot(&risk), settled);
        assert_eq!(
            seen(&mut risk, 3 * DAY + HOUR, dec!(20000)),
            RiskState::Active
        );
        assert!(risk.check_ready().is_ok());
        journal_sound(&dir, &limits, risk);
    }
}

fn report(risk: &mut PersistentRisk, now: i64, flow: Flow) -> FlowOutcome {
    risk.apply_flow(at(now), &flow).unwrap()
}

fn snapshot(risk: &PersistentRisk) -> RiskSnapshot {
    risk.engine().snapshot()
}

/// The journal reads back, and holds what the engine holds (all but a
/// falling last equity); closed and opened again, it gives the state
/// written last.
fn journal_sound(dir: &Dir, limits: &RiskLimits, risk: PersistentRisk) {
    let records = PersistentRisk::read(&dir.journal()).unwrap();
    let last = records.last().unwrap().state.clone();
    let now = snapshot(&risk);
    assert_eq!(
        (last.state, last.peak, last.day, last.day_start),
        (now.state, now.peak, now.day, now.day_start)
    );
    drop(risk);
    let reopened = PersistentRisk::open(&dir.journal(), limits).unwrap();
    assert_eq!(reopened.engine().snapshot(), last);
}

#[test]
fn r3_h1_p1_a_withdrawal_while_down_on_a_later_day() {
    // Journal on day 0 at 10,000; while Guard is down, 3,000 is withdrawn
    // on day 1. The flow's own observation rolls the day (start 10,000),
    // then the move: 7,000 and 7,000. The 7,000 view is no loss.
    let dir = Dir::new("p1");
    let limits = RiskLimits::default();
    let risk = start(&dir, limits.clone(), dec!(10000));
    let mut risk = reopen(&dir, &limits, risk);
    report(
        &mut risk,
        DAY + 2 * HOUR,
        reading(DAY + HOUR, dec!(-3000), "w", dec!(10000)),
    );
    assert_eq!(
        seen(&mut risk, DAY + 2 * HOUR, dec!(7000)),
        RiskState::Active
    );
    let s = snapshot(&risk);
    assert_eq!((s.day, s.peak, s.day_start), (1, dec!(7000), dec!(7000)));
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r3_h1_p1b_a_deposit_while_down_on_a_later_day() {
    // As above with 5,000 in: the day starts at 15,000, and a loss of
    // 1,000 (6.67%) halts it.
    let dir = Dir::new("p1b");
    let limits = RiskLimits::default();
    let risk = start(&dir, limits.clone(), dec!(10000));
    let mut risk = reopen(&dir, &limits, risk);
    report(
        &mut risk,
        DAY + 2 * HOUR,
        reading(DAY + HOUR, dec!(5000), "d", dec!(10000)),
    );
    seen(&mut risk, DAY + 2 * HOUR, dec!(15000));
    assert_eq!(snapshot(&risk).day_start, dec!(15000));
    assert_eq!(
        seen(&mut risk, DAY + 3 * HOUR, dec!(14000)),
        RiskState::HaltedForDay { day: 1 }
    );
}

#[test]
fn r3_h1_p1c_a_deposit_at_midnight_while_running() {
    // 5,000 in at 00:00:00.5, reported at 00:00:00.9. The view at
    // 00:00:01.5 may or may not show it: left out, it rolls the day from
    // 10,000. The view at 00:00:05.5 shows it: the day's start 15,000; a
    // loss of 1,000 halts.
    let dir = Dir::new("p1c");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    seen(&mut risk, DAY - 2_000, dec!(10000));
    assert_eq!(
        report(
            &mut risk,
            DAY + 900,
            reading(DAY + 500, dec!(5000), "d", dec!(10000))
        ),
        FlowOutcome::Pending
    );
    seen(&mut risk, DAY + 1_500, dec!(15000));
    assert_eq!(snapshot(&risk).day_start, dec!(10000));
    seen(&mut risk, DAY + 5_500, dec!(15000));
    assert_eq!(snapshot(&risk).day_start, dec!(15000));
    assert_eq!(
        seen(&mut risk, DAY + HOUR, dec!(14000)),
        RiskState::HaltedForDay { day: 1 }
    );
}

#[test]
fn r3_h1_p2_and_s_q2_a_deposit_reported_late_across_midnight() {
    // Day 0 ends at 11,000. 5,000 in at 00:00:00.5, seen first as a gain
    // (16,000 at 00:00:05), reported at 00:00:06. Recomputed: the day
    // starts at 11,000 (the flow's roll), then 16,000. A loss of 960 (6% of
    // 16,000) halts, 959 does not; with a 2,000 cap 120 (6% of the cap)
    // does, 119 does not.
    for (limits, loss) in [(RiskLimits::default(), dec!(960)), (capped(), dec!(120))] {
        let dir = Dir::new("p2");
        let mut risk = start(&dir, limits.clone(), dec!(10000));
        seen(&mut risk, DAY - 2_000, dec!(11000));
        seen(&mut risk, DAY + 5_000, dec!(16000));
        assert_eq!(snapshot(&risk).day_start, dec!(11000));
        assert_eq!(
            report(
                &mut risk,
                DAY + 6_000,
                reading(DAY + 500, dec!(5000), "d", dec!(11000))
            ),
            FlowOutcome::Applied
        );
        let s = snapshot(&risk);
        assert_eq!((s.day, s.day_start, s.peak), (1, dec!(16000), dec!(16000)));
        let times = [(String::new(), DAY + HOUR)].into();
        assert!(!risk.would_halt(at(DAY + HOUR), &times, dec!(16000) - loss + dec!(1)));
        assert!(risk.would_halt(at(DAY + HOUR), &times, dec!(16000) - loss));
        journal_sound(&dir, &limits, risk);
    }
}

#[test]
fn r3_h1_p2b_a_withdrawal_reported_late_across_midnight() {
    // Day 0 ends at 11,000; 100 out at 00:00:00.5; seen as 10,900 (a loss)
    // at 00:00:05; reported at 00:00:06: the day starts at 11,000, moved to
    // 10,900. No loss, and the journal stays readable.
    let dir = Dir::new("p2b");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, DAY - 2_000, dec!(11000));
    seen(&mut risk, DAY + 5_000, dec!(10900));
    report(
        &mut risk,
        DAY + 6_000,
        reading(DAY + 500, dec!(-100), "w", dec!(11000)),
    );
    let s = snapshot(&risk);
    assert_eq!(
        (s.state, s.day, s.day_start),
        (RiskState::Active, 1, dec!(10900))
    );
    assert!(risk.check_ready().is_ok());
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r3_m1_p3_a_view_inside_the_window_set_a_peak_before_the_deposit_was_known() {
    // 5,000 in at 2 h. A view 0.5 s later shows 15,100 (taken: unknown,
    // a new peak); one at 2 h 5 s shows 15,000; reported at 2 h 5.5 s. The
    // first view may or may not show the deposit: left out on the
    // recomputation (its 100 of gain is not seen, D6). Peak and day start
    // 15,000; the journal is readable and reopens.
    let dir = Dir::new("p3");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, 2 * HOUR + 500, dec!(15100));
    seen(&mut risk, 2 * HOUR + 5_000, dec!(15000));
    report(
        &mut risk,
        2 * HOUR + 5_500,
        reading(2 * HOUR, dec!(5000), "d", dec!(10000)),
    );
    let s = snapshot(&risk);
    assert_eq!(
        (s.peak, s.day_start, s.state),
        (dec!(15000), dec!(15000), RiskState::Active)
    );
    assert!(risk.check_ready().is_ok());
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r3_m1_q3_a_withdrawal_known_after_a_view_inside_its_window() {
    // 500 out at 2 h. A view 0.5 s later shows 10,010 (taken while unknown,
    // a new peak); the withdrawal is reported at 2 h 1 s: that view is left
    // out on the recomputation. The view at 2 h 5 s shows 9,400: of the 100
    // lost since 10,000, δ (0.1% of the 9,500 the withdrawal leaves: 9.5) is
    // read before the withdrawal, the rest the stricter way, after it:
    // 9,990.50, then 10,000 x 9,490.50 / 9,990.50 = 9,499.52 for both, so
    // 9,400 is a 1.05% loss: active, no journal error.
    let dir = Dir::new("q3");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, 2 * HOUR + 500, dec!(10010));
    report(
        &mut risk,
        2 * HOUR + 1_000,
        reading(2 * HOUR, dec!(-500), "w", dec!(9990.50)),
    );
    assert_eq!(snapshot(&risk).peak, dec!(10000));
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(9400)),
        RiskState::Active
    );
    let s = snapshot(&risk);
    assert_eq!(s.peak.round_dp(2), dec!(9499.52));
    assert_eq!(s.day_start, s.peak);
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r3_m1_p6b_a_transfer_of_nothing_between_dexes_changes_nothing() {
    // 3 then 2.9: figures that rebasing could not divide exactly. A
    // transfer between two dexes without a fee moves nothing, exactly, and
    // the journal accepts it.
    let dir = Dir::new("p6b");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(3));
    seen(&mut risk, 2 * HOUR, dec!(2.9));
    let before = snapshot(&risk);
    let transfer = Flow {
        between: true,
        ..flow(3 * HOUR, Decimal::ZERO, "t")
    };
    report(&mut risk, 3 * HOUR, transfer);
    seen(&mut risk, 3 * HOUR + 5_000, dec!(2.9));
    let after = snapshot(&risk);
    assert_eq!(
        (after.peak, after.day_start, after.state),
        (before.peak, before.day_start, before.state)
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r3_m2_p4_and_p11_two_opposite_flows_between_two_views() {
    // 5,000 in at 2 h and out at 2 h 1 s; seen at 10,000 (running), or
    // after a restart: nothing traded, so every reading is exact. Active,
    // peak and day start 10,000 (the earlier version stopped at 50%).
    let dir = Dir::new("p4");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR,
        reading(2 * HOUR, dec!(5000), "d", dec!(10000)),
    );
    report(
        &mut risk,
        2 * HOUR + 1_000,
        reading(2 * HOUR + 1_000, dec!(-5000), "w", dec!(15000)),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(10000)),
        RiskState::Active
    );
    let s = snapshot(&risk);
    assert_eq!((s.peak, s.day_start), (dec!(10000), dec!(10000)));

    let dir = Dir::new("p11");
    let risk = start(&dir, limits.clone(), dec!(10000));
    let mut risk = reopen(&dir, &limits, risk);
    report(
        &mut risk,
        5 * HOUR,
        reading(2 * HOUR, dec!(5000), "d", dec!(10000)),
    );
    report(
        &mut risk,
        5 * HOUR,
        reading(3 * HOUR, dec!(-5000), "w", dec!(15000)),
    );
    assert_eq!(seen(&mut risk, 5 * HOUR, dec!(10000)), RiskState::Active);
    assert_eq!(snapshot(&risk).peak, dec!(10000));
}

#[test]
fn r3_m2_p5_a_fall_seen_before_a_restart_is_on_the_journal() {
    // 10,000, then 9,700 seen (a 3% fall: more than 0.1%, written), a
    // restart, 9,000 withdrawn, 700 seen: nothing traded since 9,700, so
    // the reading is exact: 3% down, active (the earlier version stopped
    // at 30%).
    let dir = Dir::new("p5");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, 2 * HOUR, dec!(9700));
    let mut risk = reopen(&dir, &limits, risk);
    assert_eq!(snapshot(&risk).last, dec!(9700));
    report(
        &mut risk,
        4 * HOUR,
        reading(3 * HOUR, dec!(-9000), "w", dec!(9700)),
    );
    assert_eq!(seen(&mut risk, 4 * HOUR, dec!(700)), RiskState::Active);
}

#[test]
fn r3_m2_p5r_an_unknown_split_of_a_loss_is_read_the_stricter_way() {
    // Spec example 7: 10,000 seen, 9,000 withdrawn, 900 seen; the 100 lost
    // happened before (1%) or after (10%, 9.2% with δ read before): the
    // stricter reading halts the day (the operator, 7 Oct: strict, a halt at most
    // where it is ambiguous). Next to a deposit the same.
    let dir = Dir::new("p5r");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(&mut risk, 2 * HOUR, flow(2 * HOUR, dec!(-9000), "w"));
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(900)),
        RiskState::HaltedForDay { day: 0 }
    );
    // 10,000 seen, 9,000 deposited, 18,000 seen: 1,000 lost before the
    // deposit (10%) or after it (5.3%): halted.
    let dir = Dir::new("p5r-deposit");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(&mut risk, 2 * HOUR, flow(2 * HOUR, dec!(9000), "d"));
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(18000)),
        RiskState::HaltedForDay { day: 0 }
    );
}

#[test]
fn r3_m2_q6_a_withdrawal_not_yet_known_explains_a_loss() {
    // 10,000 in at 2 h 1 s (known), 1,000 out at 2 h (not known yet); the
    // view at 2 h 6 s shows 19,000. With the deposit alone, the 1,000 may
    // have been lost before it (10% of 10,000): it would halt, so Guard
    // reads the ledger first. Once the withdrawal is known, the view is
    // exact: active.
    let dir = Dir::new("q6");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR + 1_500,
        reading(2 * HOUR + 1_000, dec!(10000), "d", dec!(9000)),
    );
    let times = [(String::new(), 2 * HOUR + 6_000)].into();
    assert!(risk.would_halt(at(2 * HOUR + 6_000), &times, dec!(19000)));
    report(
        &mut risk,
        2 * HOUR + 6_000,
        reading(2 * HOUR, dec!(-1000), "w", dec!(10000)),
    );
    assert!(!risk.would_halt(at(2 * HOUR + 6_000), &times, dec!(19000)));
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 6_000, dec!(19000)),
        RiskState::Active
    );
    // Taken before the withdrawal was known, the halt stays (D1).
    let dir = Dir::new("q6b");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR + 1_500,
        reading(2 * HOUR + 1_000, dec!(10000), "d", dec!(9000)),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 6_000, dec!(19000)),
        RiskState::HaltedForDay { day: 0 }
    );
    report(
        &mut risk,
        2 * HOUR + 7_000,
        reading(2 * HOUR, dec!(-1000), "w", dec!(10000)),
    );
    assert_eq!(risk.state(), RiskState::HaltedForDay { day: 0 });
    let s = snapshot(&risk);
    assert_eq!((s.peak, s.day_start), (dec!(19000), dec!(19000)));
}

#[test]
fn r3_m3_p7_a_deposit_on_a_day_that_is_up() {
    // Gain followed by a complete withdrawal: 11,000 seen (10% up), 11,000
    // deposited: the day's start is 21,000, not 20,000; at 19,000 the day
    // is down 2,000 on 21,000 (9.5%): halted (the earlier version kept it
    // active at 5%).
    let dir = Dir::new("p7");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    seen(&mut risk, 2 * HOUR, dec!(11000));
    report(
        &mut risk,
        3 * HOUR,
        reading(3 * HOUR, dec!(11000), "d", dec!(11000)),
    );
    seen(&mut risk, 3 * HOUR + 5_000, dec!(22000));
    assert_eq!(snapshot(&risk).day_start, dec!(21000));
    assert_eq!(
        seen(&mut risk, 4 * HOUR, dec!(19000)),
        RiskState::HaltedForDay { day: 0 }
    );
}

#[test]
fn r3_m4_p9_a_deposit_reported_after_thousands_of_views() {
    // 5,000 in at 2 h, then 4,100 views of 15,000 every 50 ms (the earlier
    // version kept 4,000 and skipped it as a gain), then reported: applied
    // at its own time, the day's start 15,000.
    let dir = Dir::new("p9");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    for i in 0..4_100 {
        seen(&mut risk, 2 * HOUR + 3_000 + i * 50, dec!(15000));
    }
    assert_eq!(
        report(
            &mut risk,
            3 * HOUR,
            reading(2 * HOUR, dec!(5000), "d", dec!(10000))
        ),
        FlowOutcome::Applied
    );
    let s = snapshot(&risk);
    assert_eq!((s.day_start, s.peak), (dec!(15000), dec!(15000)));
}

#[test]
fn r3_q1_a_capped_deposit_at_midnight() {
    // Cap 2,000. 10,000 at the end of day 0; 5,000 in at 00:00:00.5: the
    // day rolls at 10,000, then moves by the amount (at or above the cap):
    // 15,000. A loss of 120 (6% of the cap) halts; 119 does not.
    let dir = Dir::new("q1");
    let mut risk = start(&dir, capped(), dec!(10000));
    seen(&mut risk, DAY - 2_000, dec!(10000));
    report(
        &mut risk,
        DAY + 900,
        reading(DAY + 500, dec!(5000), "d", dec!(10000)),
    );
    seen(&mut risk, DAY + 5_500, dec!(15000));
    assert_eq!(snapshot(&risk).day_start, dec!(15000));
    let times = [(String::new(), DAY + HOUR)].into();
    assert!(!risk.would_halt(at(DAY + HOUR), &times, dec!(14881)));
    assert!(risk.would_halt(at(DAY + HOUR), &times, dec!(14880)));
}

#[test]
fn r2_1_with_the_cap_a_withdrawal_keeps_the_dollar_loss() {
    // Cap 2,000: 110 lost from 10,000 (5.5% of the cap), 7,890 out: day
    // start 2,110; 97 more lost is 207 = 10.35%: halted.
    let dir = Dir::new("r2-1");
    let mut risk = start(&dir, capped(), dec!(10000));
    seen(&mut risk, 2 * HOUR, dec!(9890));
    report(
        &mut risk,
        3 * HOUR,
        reading(3 * HOUR, dec!(-7890), "w", dec!(9890)),
    );
    seen(&mut risk, 3 * HOUR + 5_000, dec!(2000));
    assert_eq!(snapshot(&risk).day_start, dec!(2110));
    assert_eq!(
        seen(&mut risk, 4 * HOUR, dec!(1903)),
        RiskState::HaltedForDay { day: 0 }
    );
}

#[test]
fn r2_1_with_the_cap_a_deposit_keeps_the_days_loss() {
    // Cap 2,000; 2,000 at 1,900 (5% of the cap); 2,000 deposited: the day's
    // start moves to keep 100 / 2,000: 4,000. A loss of 20 more (6%)
    // halts.
    let dir = Dir::new("r2-1b");
    let mut risk = start(&dir, capped(), dec!(2000));
    seen(&mut risk, 2 * HOUR, dec!(1900));
    report(
        &mut risk,
        3 * HOUR,
        reading(3 * HOUR, dec!(2000), "d", dec!(1900)),
    );
    seen(&mut risk, 3 * HOUR + 5_000, dec!(3900));
    assert_eq!(snapshot(&risk).day_start, dec!(4000));
    assert_eq!(
        seen(&mut risk, 4 * HOUR, dec!(3880)),
        RiskState::HaltedForDay { day: 0 }
    );
}

#[test]
fn r2_2_a_deposit_after_a_loss_a_restart_lost() {
    // Day start 10,000; 9,450 seen (5.5% down: written); a restart; 9,450
    // deposited while down; 18,850 seen. 50 more was lost somewhere: read
    // before the deposit it is 6% of the day: halted (the earlier version
    // read it as 3.1%).
    let dir = Dir::new("r2-2");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, 2 * HOUR, dec!(9450));
    let mut risk = reopen(&dir, &limits, risk);
    report(
        &mut risk,
        4 * HOUR,
        reading(3 * HOUR, dec!(9450), "d", dec!(9400)),
    );
    assert_eq!(
        seen(&mut risk, 4 * HOUR, dec!(18850)),
        RiskState::HaltedForDay { day: 0 }
    );
}

#[test]
fn r2_3_a_view_just_after_a_deposit_may_not_show_it() {
    // 10,000 in at 2 h; a view at 2 h 0.1 s shows 10,000 (without it); the
    // deposit is known: that view may or may not show it, left out. Then
    // 20,000 at 2 h 5 s: the deposit, no loss (the earlier version stopped).
    let dir = Dir::new("r2-3");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR,
        reading(2 * HOUR, dec!(10000), "d", dec!(10000)),
    );
    seen(&mut risk, 2 * HOUR + 100, dec!(10000));
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(20000)),
        RiskState::Active
    );
}

#[test]
fn r1_h1_a_restart_never_applies_a_flow_twice() {
    // 2,000 out of 10,000: 8,000 and 8,000. After a restart the same flow
    // comes again (the ledger is read from before it): a duplicate.
    let dir = Dir::new("r1-h1");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR,
        reading(2 * HOUR, dec!(-2000), "w", dec!(10000)),
    );
    seen(&mut risk, 2 * HOUR + 5_000, dec!(8000));
    let mut risk = reopen(&dir, &limits, risk);
    assert!(risk.flows_from_ms() <= 2 * HOUR);
    assert_eq!(
        report(
            &mut risk,
            3 * HOUR,
            reading(2 * HOUR, dec!(-2000), "w", dec!(10000))
        ),
        FlowOutcome::Duplicate
    );
    let s = snapshot(&risk);
    assert_eq!((s.peak, s.day_start), (dec!(8000), dec!(8000)));
}

#[test]
fn r1_h2_a_round_trip_erases_no_loss() {
    // Day start 10,000, 9,500; 9,000 out and back: the day's start is
    // 10,000 again (to Decimal's rounding), and 8,980 (10.2%) halts.
    let dir = Dir::new("r1-h2");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    seen(&mut risk, 2 * HOUR, dec!(9500));
    report(
        &mut risk,
        3 * HOUR,
        reading(3 * HOUR, dec!(-9000), "w", dec!(9500)),
    );
    seen(&mut risk, 3 * HOUR + 5_000, dec!(500));
    report(
        &mut risk,
        4 * HOUR,
        reading(4 * HOUR, dec!(9000), "d", dec!(500)),
    );
    seen(&mut risk, 4 * HOUR + 5_000, dec!(9500));
    assert!((snapshot(&risk).day_start - dec!(10000)).abs() < dec!(0.000001));
    assert_eq!(
        seen(&mut risk, 5 * HOUR, dec!(8980)),
        RiskState::HaltedForDay { day: 0 }
    );
}

#[test]
fn r1_h3_a_flow_with_a_position_open_keeps_the_journal_whole() {
    // A position recorded, its mark moving (never written), then 1,000
    // out: the journal stays readable and the position stays recorded.
    let dir = Dir::new("r1-h3");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    risk.record_entry(
        at(2 * HOUR),
        Symbol::new("BTC"),
        Side::Buy,
        dec!(0.01),
        dec!(100000),
        dec!(99000),
    )
    .unwrap();
    // Not settled: the record keeps the position the view does not show.
    let unsettled = |risk: &mut PersistentRisk, ms: i64, equity: Decimal| {
        let sync = risk.observe_view_at(
            at(ms),
            [(String::new(), ms)].into(),
            equity,
            &VenueView::default(),
            false,
        );
        assert_eq!(sync.journal_error, None);
    };
    unsettled(&mut risk, 2 * HOUR + 1_000, dec!(9990));
    report(
        &mut risk,
        3 * HOUR,
        reading(3 * HOUR, dec!(-1000), "w", dec!(9990)),
    );
    unsettled(&mut risk, 3 * HOUR + 5_000, dec!(8990));
    assert!(risk.check_ready().is_ok());
    assert_eq!(snapshot(&risk).positions.len(), 1);
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r1_m1_a_flow_while_halted_moves_the_figures_and_keeps_the_halt() {
    // 9,300 (7%): halted. 2,000 out: 10,000 x 7,300 / 9,300 = 7,849.46...;
    // 7,300 is still 7% down: halted, not stopped.
    let dir = Dir::new("r1-m1");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    assert_eq!(
        seen(&mut risk, 2 * HOUR, dec!(9300)),
        RiskState::HaltedForDay { day: 0 }
    );
    report(
        &mut risk,
        3 * HOUR,
        reading(3 * HOUR, dec!(-2000), "w", dec!(9300)),
    );
    assert_eq!(
        seen(&mut risk, 3 * HOUR + 5_000, dec!(7300)),
        RiskState::HaltedForDay { day: 0 }
    );
    assert_eq!(snapshot(&risk).peak.round_dp(2), dec!(7849.46));
}

#[test]
fn r1_m5_flows_reported_out_of_order() {
    // 1,000 out at 3 h and 500 in at 2 h, reported in that order after
    // views that show both: applied in the order they happened, no broken
    // journal. 10,000 then 9,500 (both seen at 3 h 5 s): exact, 9,500.
    let dir = Dir::new("r1-m5");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, 3 * HOUR + 5_000, dec!(9500));
    report(
        &mut risk,
        3 * HOUR + 6_000,
        reading(3 * HOUR, dec!(-1000), "w", dec!(10500)),
    );
    report(
        &mut risk,
        3 * HOUR + 7_000,
        reading(2 * HOUR, dec!(500), "d", dec!(10000)),
    );
    let s = snapshot(&risk);
    assert_eq!(
        (s.state, s.peak, s.day_start),
        (RiskState::Active, dec!(9500), dec!(9500))
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn s1_l1_everything_withdrawn_and_some_back() {
    // Spec example 8 through the journal: 9,600 (4% down), all out (the
    // view of 0 is left out), 4,800 back: one flow of -4,800 from 9,600:
    // 5,000 and 5,000, 4% down, active.
    let dir = Dir::new("empty");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, 2 * HOUR, dec!(9600));
    report(
        &mut risk,
        3 * HOUR,
        reading(3 * HOUR, dec!(-9600), "w", dec!(9600)),
    );
    assert_eq!(
        seen(&mut risk, 3 * HOUR + 5_000, dec!(0)),
        RiskState::Active
    );
    report(
        &mut risk,
        4 * HOUR,
        reading(4 * HOUR, dec!(4800), "d", dec!(0)),
    );
    assert_eq!(
        seen(&mut risk, 4 * HOUR + 5_000, dec!(4800)),
        RiskState::Active
    );
    let s = snapshot(&risk);
    assert_eq!((s.peak, s.day_start), (dec!(5000), dec!(5000)));
    journal_sound(&dir, &limits, risk);
}

#[test]
fn s2_me_a_refill_between_flows_is_read_as_it_must_have_happened() {
    // Restart with offsetting flows: Guard down; all 10,000 out, 1,000 in,
    // 300 lost, 10,000 in; seen at 10,700. Nothing can be traded while the
    // account is empty, so the first two are one flow of -9,000, and the
    // 300 cannot have been lost before it (the 10,000 out took all there
    // was): it was lost between the two (300 of 1,000: 30%, a stop) or
    // after (2.7%). The reading that stops is not waived: the other has the
    // loss after a deposit, not before a withdrawal (a deposit must not
    // mask a loss): stopped.
    let dir = Dir::new("refill");
    let limits = RiskLimits::default();
    let risk = start(&dir, limits.clone(), dec!(10000));
    let mut risk = reopen(&dir, &limits, risk);
    report(
        &mut risk,
        5 * HOUR,
        reading(2 * HOUR, dec!(-10000), "w", dec!(10000)),
    );
    report(
        &mut risk,
        5 * HOUR,
        reading(3 * HOUR, dec!(1000), "d1", dec!(0)),
    );
    report(
        &mut risk,
        5 * HOUR,
        reading(4 * HOUR, dec!(10000), "d2", dec!(700)),
    );
    assert!(matches!(
        seen(&mut risk, 5 * HOUR, dec!(10700)),
        RiskState::Stopped { .. }
    ));
}

#[test]
fn s2_ma_settle_takes_a_stop_over_a_halt() {
    // A deposit after a daily halt: 9,300 (7%): halted. A deposit of 3,000
    // nobody reported yet (12,300: a new peak), then 2,500 lost (9,800).
    // Reported: 10,000 x 12,300 / 9,300 = 13,225.8; 9,800 is 25.9% below
    // it: stopped, not the halt kept.
    let dir = Dir::new("ma");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, 2 * HOUR, dec!(9300));
    seen(&mut risk, 3 * HOUR + 5_000, dec!(12300));
    assert_eq!(
        seen(&mut risk, 4 * HOUR, dec!(9800)),
        RiskState::HaltedForDay { day: 0 }
    );
    report(
        &mut risk,
        5 * HOUR,
        reading(3 * HOUR, dec!(3000), "d", dec!(9300)),
    );
    assert!(matches!(risk.state(), RiskState::Stopped { .. }));
    journal_sound(&dir, &limits, risk);
}

#[test]
fn a_view_that_goes_back_in_venue_time_is_ignored() {
    // An older view fed after a newer one (a stream snapshot behind an HTTP
    // read): ignored, so its loss does not count.
    let dir = Dir::new("back");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    seen(&mut risk, 2 * HOUR, dec!(10000));
    let sync = risk.observe_view_at(
        at(2 * HOUR + 1_000),
        [(String::new(), 2 * HOUR - 1)].into(),
        dec!(5000),
        &VenueView::default(),
        true,
    );
    assert!(!sync.taken);
    assert_eq!(sync.state, RiskState::Active);
    assert_eq!(snapshot(&risk).last, dec!(10000));
}

#[test]
fn a_review_starts_afresh_and_a_flow_from_before_it_counts_as_it_did() {
    // 7,000 (30%): stopped; a person resumes at 7,000. A withdrawal from
    // before the review, reported after it, is not replayed across the
    // review (skipped: it counts as the loss it already was).
    let dir = Dir::new("review");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    assert!(matches!(
        seen(&mut risk, 2 * HOUR, dec!(7000)),
        RiskState::Stopped { .. }
    ));
    risk.resume_after_review(at(3 * HOUR), dec!(7000), "checked")
        .unwrap();
    seen(&mut risk, 3 * HOUR + 1_000, dec!(7000));
    let outcome = report(
        &mut risk,
        3 * HOUR + 2_000,
        flow(HOUR + 30 * 60_000, dec!(-3000), "w"),
    );
    assert!(matches!(outcome, FlowOutcome::Skipped(_)), "{outcome:?}");
    let s = snapshot(&risk);
    assert_eq!((s.state, s.peak), (RiskState::Active, dec!(7000)));
    journal_sound(&dir, &limits, risk);
}

// ---------------------------------------------------------------------
// The reader refuses `flowed` records that do not replay, or whose base or
// list of flows the journal contradicts.
// ---------------------------------------------------------------------

/// A journal with a withdrawal applied, as lines.
fn journal_with_a_withdrawal(dir: &Dir) -> Vec<String> {
    let mut risk = start(dir, RiskLimits::default(), dec!(10000));
    seen(&mut risk, 2 * HOUR, dec!(9500));
    report(&mut risk, 3 * HOUR, flow(3 * HOUR, dec!(-4750), "w"));
    seen(&mut risk, 3 * HOUR + 5_000, dec!(4750));
    drop(risk);
    fs::read_to_string(dir.journal())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// What a record's checksum covers, in the journal's field order.
#[derive(serde::Serialize)]
struct Body<'a> {
    format: &'a str,
    version: u32,
    seq: u64,
    at: Timestamp,
    event: &'a JournalEvent,
    state: &'a RiskSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    horizon: Option<&'a zunder_venue::Horizon>,
    #[serde(skip_serializing_if = "Option::is_none")]
    view: Option<&'a SeenView>,
    prev: &'a str,
}

/// The journal's records with record `seq` changed by `change`, written
/// with every checksum and link computed again, so that only the reader's
/// checks of content can refuse it.
fn forge(dir: &Dir, seq: u64, change: impl Fn(&mut JournalRecord)) -> Vec<String> {
    use sha3::{Digest, Sha3_256};
    let records = PersistentRisk::read(&dir.journal()).unwrap();
    let mut out = Vec::new();
    let mut prev = String::new();
    for mut record in records {
        if record.seq == seq {
            change(&mut record);
        }
        let text = serde_json::to_string(&Body {
            format: &record.format,
            version: record.version,
            seq: record.seq,
            at: record.at,
            event: &record.event,
            state: &record.state,
            horizon: record.horizon.as_ref(),
            view: record.view.as_ref(),
            prev: &prev,
        })
        .unwrap();
        let check: String = Sha3_256::digest(text.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        out.push(format!("{{\"check\":\"{check}\",{}", &text[1..]));
        prev = check;
    }
    out
}

/// The `flowed` record written last.
fn last_flowed(dir: &Dir) -> JournalRecord {
    PersistentRisk::read(&dir.journal())
        .unwrap()
        .into_iter()
        .rev()
        .find(|record| matches!(record.event, JournalEvent::Flowed { .. }))
        .unwrap()
}

fn refused(dir: &Dir, lines: &[String]) -> String {
    fs::write(dir.journal(), lines.join("\n") + "\n").unwrap();
    match PersistentRisk::read(&dir.journal()) {
        Ok(_) => panic!("a forged journal was accepted"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn the_reader_accepts_the_journal_as_written_and_reforged_unchanged() {
    let dir = Dir::new("forge-same");
    let lines = journal_with_a_withdrawal(&dir);
    assert_eq!(forge(&dir, 0, |_| {}), lines);
}

#[test]
fn the_reader_refuses_a_flowed_record_that_does_not_replay() {
    // r1 L1, r2 #7, r3 L1: a record whose state is not what its inputs
    // give, here a day's start lowered to the equity (the withdrawal's
    // 5% loss erased) where the move keeps it at 5,000.
    let dir = Dir::new("forge-state");
    journal_with_a_withdrawal(&dir);
    let seq = last_flowed(&dir).seq;
    let forged = forge(&dir, seq, |record| record.state.day_start = dec!(4750));
    let message = refused(&dir, &forged);
    assert!(message.contains("the flows give"), "{message}");
}

#[test]
fn the_reader_refuses_a_flowed_record_that_leaves_out_a_view_or_a_flow_or_starts_elsewhere() {
    let dir = Dir::new("forge-list");
    journal_with_a_withdrawal(&dir);
    let record = last_flowed(&dir);
    let JournalEvent::Flowed { base, flows, .. } = &record.event else {
        unreachable!()
    };
    // The last flowed record applied the withdrawal at the 4,750 view.
    assert_eq!(flows.len(), 1);
    let base = *base;
    let twice = forge(&dir, record.seq, |record| {
        if let JournalEvent::Flowed { flows, .. } = &mut record.event {
            flows.push(flows[0].clone());
        }
    });
    assert!(refused(&dir, &twice).contains("twice"));
    journal_with_a_withdrawal(&Dir::new("forge-list-2"));
    let dir = Dir::new("forge-list-3");
    journal_with_a_withdrawal(&dir);
    let without = forge(&dir, record.seq, |record| {
        if let JournalEvent::Flowed { flows, .. } = &mut record.event {
            flows.clear();
        }
    });
    assert!(refused(&dir, &without).contains("left out"));
    let dir = Dir::new("forge-list-4");
    journal_with_a_withdrawal(&dir);
    let no_views = forge(&dir, record.seq, |record| {
        if let JournalEvent::Flowed { views, .. } = &mut record.event {
            views.clear();
        }
    });
    refused(&dir, &no_views);
    let dir = Dir::new("forge-list-5");
    journal_with_a_withdrawal(&dir);
    let elsewhere = forge(&dir, record.seq, |record| {
        if let JournalEvent::Flowed { base: from, .. } = &mut record.event {
            *from = base + 100;
        }
    });
    refused(&dir, &elsewhere);
}

#[test]
fn every_record_of_an_engine_with_flows_is_version_3_and_the_runner_writes_version_2() {
    let dir = Dir::new("versions");
    journal_with_a_withdrawal(&dir);
    let records = PersistentRisk::read(&dir.journal()).unwrap();
    assert_eq!(records[0].version, 2);
    for record in &records[1..] {
        assert_eq!(record.version, 3);
        assert!(record.horizon.is_some());
    }
    assert!(
        records
            .iter()
            .any(|record| matches!(record.event, JournalEvent::Flowed { .. }))
    );
    // An engine without flows writes version 2, as before.
    let plain = Dir::new("plain");
    let mut risk = PersistentRisk::initialise(
        &plain.journal(),
        RiskLimits::default(),
        at(0),
        dec!(1000),
        "runner",
    )
    .unwrap();
    risk.observe_view(at(HOUR), dec!(1100), &VenueView::default(), true);
    drop(risk);
    for record in PersistentRisk::read(&plain.journal()).unwrap() {
        assert_eq!(record.version, 2);
        assert!(record.horizon.is_none() && record.view.is_none());
    }
}

#[test]
fn a_flow_right_after_a_review_written_without_flows() {
    // `zunder-guard journal-resume` opens the journal without flows: its
    // review record has no horizon. Guard then learns of a deposit before
    // any view: the record it writes starts from the review, and the reader
    // computes the same from it.
    let dir = Dir::new("review-cli");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    assert!(matches!(
        seen(&mut risk, 2 * HOUR, dec!(7000)),
        RiskState::Stopped { .. }
    ));
    drop(risk);
    let mut person = PersistentRisk::open(&dir.journal(), &limits).unwrap();
    person
        .resume_after_review(at(3 * HOUR), dec!(7000), "checked")
        .unwrap();
    drop(person);
    let mut risk = PersistentRisk::open(&dir.journal(), &limits)
        .unwrap()
        .with_flows();
    assert_eq!(
        report(
            &mut risk,
            3 * HOUR + 1_000,
            reading(4 * HOUR, dec!(1000), "d", dec!(7000))
        ),
        FlowOutcome::Pending
    );
    seen(&mut risk, 4 * HOUR + 5_000, dec!(8000));
    let s = snapshot(&risk);
    assert_eq!(
        (s.state, s.peak, s.day_start),
        (RiskState::Active, dec!(8000), dec!(8000))
    );
    journal_sound(&dir, &limits, risk);
}

// ---------------------------------------------------------------------
// Journal consistency, crash recovery and mutation regression cases.
// ---------------------------------------------------------------------

fn times(ms: i64) -> std::collections::BTreeMap<String, i64> {
    [(String::new(), ms)].into()
}

#[test]
fn r4_h1_p7_a_deposit_before_the_journal_was_started_is_in_its_equity() {
    // 1,000 on the account, 1,000 deposited at 9:50, `init` at 10:00 with
    // 2,000. The deposit is in the 2,000: the ledger is read from the start
    // on, and a deposit from before it, if reported, is skipped.
    let dir = Dir::new("r4-p7");
    let limits = RiskLimits::default();
    let t0 = 10 * HOUR;
    let risk =
        PersistentRisk::initialise(&dir.journal(), limits.clone(), at(t0), dec!(2000), "test")
            .unwrap()
            .with_flows();
    let mut risk = reopen(&dir, &limits, risk);
    assert_eq!(risk.flows_from_ms(), t0);
    let outcome = report(
        &mut risk,
        t0 + 60_000,
        flow(t0 - 10 * 60_000, dec!(1000), "d"),
    );
    assert!(matches!(outcome, FlowOutcome::Skipped(_)), "{outcome:?}");
    // Within the margin after the start, as ambiguous: skipped too.
    let outcome = report(&mut risk, t0 + 60_000, flow(t0 + 2_000, dec!(500), "d2"));
    assert!(matches!(outcome, FlowOutcome::Skipped(_)), "{outcome:?}");
    assert_eq!(seen(&mut risk, t0 + 120_000, dec!(2000)), RiskState::Active);
    let s = snapshot(&risk);
    assert_eq!((s.peak, s.day_start), (dec!(2000), dec!(2000)));
    // Once a view is seen: from 30 minutes before it.
    assert_eq!(risk.flows_from_ms(), t0 + 120_000 - 30 * 60_000);
    // A deposit after the start is applied.
    assert_eq!(
        report(
            &mut risk,
            t0 + 130_000,
            reading(t0 + 125_000, dec!(1000), "d3", dec!(2000))
        ),
        FlowOutcome::Pending
    );
    assert_eq!(seen(&mut risk, t0 + 135_000, dec!(3000)), RiskState::Active);
    assert_eq!(snapshot(&risk).day_start, dec!(3000));
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r4_h1_p7b_a_withdrawal_before_the_journal_was_started_does_not_loosen_the_day() {
    // 1,000 withdrawn at 9:50, `init` at 10:00 with 2,000: the day starts
    // at 2,000. 1,900 is 5% down (active); 1,870 is 6.5%: halted.
    let dir = Dir::new("r4-p7b");
    let limits = RiskLimits::default();
    let t0 = 10 * HOUR;
    let mut risk =
        PersistentRisk::initialise(&dir.journal(), limits.clone(), at(t0), dec!(2000), "test")
            .unwrap()
            .with_flows();
    let outcome = report(
        &mut risk,
        t0 + 60_000,
        flow(t0 - 10 * 60_000, dec!(-1000), "w"),
    );
    assert!(matches!(outcome, FlowOutcome::Skipped(_)), "{outcome:?}");
    assert_eq!(seen(&mut risk, t0 + 120_000, dec!(1900)), RiskState::Active);
    assert_eq!(snapshot(&risk).day_start, dec!(2000));
    assert_eq!(
        seen(&mut risk, t0 + 125_000, dec!(1870)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r4_h2_p6_a_flow_too_old_to_place_does_not_make_later_ones_skipped() {
    // Stopped at 7,000 (30% below 10,000). Guard stopped; 1,000 withdrawn
    // at 2:40; a person resumes at 3:00 with 6,000 (the CLI, without
    // flows); 5,000 deposited at 3:30; Guard starts at 4:00 and reads the
    // ledger from 2:30. The withdrawal is from before the review (in the
    // 6,000 it resumed from): skipped. The deposit is not: 11,000 is no
    // gain, the day starts at 11,000, and 10,000 (9.1% below) halts.
    let dir = Dir::new("r4-p6");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    assert!(matches!(
        seen(&mut risk, 2 * HOUR, dec!(7000)),
        RiskState::Stopped { .. }
    ));
    drop(risk);
    let mut person = PersistentRisk::open(&dir.journal(), &limits).unwrap();
    person
        .resume_after_review(at(3 * HOUR), dec!(6000), "checked")
        .unwrap();
    drop(person);
    let mut risk = PersistentRisk::open(&dir.journal(), &limits)
        .unwrap()
        .with_flows();
    assert_eq!(risk.flows_from_ms(), 3 * HOUR - 30 * 60_000);
    let outcome = report(
        &mut risk,
        4 * HOUR,
        flow(2 * HOUR + 40 * 60_000, dec!(-1000), "w"),
    );
    assert!(matches!(outcome, FlowOutcome::Skipped(_)), "{outcome:?}");
    assert_eq!(
        report(
            &mut risk,
            4 * HOUR,
            reading(3 * HOUR + 30 * 60_000, dec!(5000), "d", dec!(6000))
        ),
        FlowOutcome::Pending
    );
    assert_eq!(
        seen(&mut risk, 4 * HOUR + 5_000, dec!(11000)),
        RiskState::Active
    );
    assert_eq!(snapshot(&risk).day_start, dec!(11000));
    assert_eq!(
        seen(&mut risk, 4 * HOUR + 10_000, dec!(10000)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r4_l1_p4_a_halt_on_the_next_day_is_one_to_check_the_ledger_for() {
    // Halted on day 0 at 9,300 (7% below 10,000). Day 1 starts from 9,300:
    // 8,000 is 14% below it, a new halt; 9,300 is none.
    let dir = Dir::new("r4-p4");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    assert_eq!(
        seen(&mut risk, 2 * HOUR, dec!(9300)),
        RiskState::HaltedForDay { day: 0 }
    );
    let next = DAY + 1_000;
    assert!(risk.would_halt(at(next), &times(next), dec!(8000)));
    assert!(!risk.would_halt(at(next), &times(next), dec!(9300)));
    // The same day: already halted, unless it stops (7,000 is 30% below
    // the peak).
    assert!(!risk.would_halt(at(3 * HOUR), &times(3 * HOUR), dec!(9000)));
    assert!(risk.would_halt(at(3 * HOUR), &times(3 * HOUR), dec!(7000)));
    // A view older than one seen is ignored, whatever it shows.
    assert!(!risk.would_halt(at(3 * HOUR), &times(HOUR + 1_000), dec!(7000)));
}

#[test]
fn r4_l2_p5_a_review_in_guard_then_a_restart_then_a_flow_from_before_it() {
    // Stopped at 7,000; Guard records a person's review at 3:00 with 7,000
    // and restarts. A withdrawal at 2:30 is in what the review saw:
    // skipped, the journal whole. A deposit at 3:30 is applied: 8,000 is
    // no gain.
    let dir = Dir::new("r4-p5");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    assert!(matches!(
        seen(&mut risk, 2 * HOUR, dec!(7000)),
        RiskState::Stopped { .. }
    ));
    risk.resume_after_review(at(3 * HOUR), dec!(7000), "checked")
        .unwrap();
    let mut risk = reopen(&dir, &limits, risk);
    let outcome = report(
        &mut risk,
        4 * HOUR,
        flow(2 * HOUR + 30 * 60_000, dec!(-1000), "w"),
    );
    assert!(matches!(outcome, FlowOutcome::Skipped(_)), "{outcome:?}");
    assert_eq!(
        report(
            &mut risk,
            4 * HOUR,
            reading(3 * HOUR + 30 * 60_000, dec!(1000), "d", dec!(7000))
        ),
        FlowOutcome::Pending
    );
    assert_eq!(
        seen(&mut risk, 4 * HOUR + 5_000, dec!(8000)),
        RiskState::Active
    );
    let s = snapshot(&risk);
    assert_eq!((s.peak, s.day_start), (dec!(8000), dec!(8000)));
    risk.check_ready().unwrap();
    journal_sound(&dir, &limits, risk);
}

#[test]
fn m_a_fall_of_more_than_a_tenth_of_a_percent_is_written() {
    // δ = 0.1% of the day's start (10,000): 10. A fall of 10 from the last
    // equity written stays in memory; one of 10.01 is written. With a cap
    // of 2,000 the share is of the cap: 2.
    for (limits, within, beyond) in [
        (RiskLimits::default(), dec!(9990), dec!(9989.99)),
        (capped(), dec!(9998), dec!(9997.99)),
    ] {
        let dir = Dir::new("delta");
        let mut risk = start(&dir, limits, dec!(10000));
        let count = || PersistentRisk::read(&dir.journal()).unwrap().len();
        let before = count();
        seen(&mut risk, 2 * HOUR, within);
        assert_eq!(count(), before);
        seen(&mut risk, 3 * HOUR, beyond);
        assert_eq!(count(), before + 1);
        // A view without flows writes an ordinary record.
        let last = PersistentRisk::read(&dir.journal()).unwrap().pop().unwrap();
        assert_eq!(last.event, JournalEvent::Updated);
        assert_eq!(last.view.map(|view| view.equity), Some(beyond));
    }
}

#[test]
fn m_what_an_engine_with_flows_says_about_them() {
    let dir = Dir::new("api");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    assert!(risk.takes_flows());
    let w = flow(2 * HOUR, dec!(-1000), "w");
    assert_eq!(
        report(&mut risk, 2 * HOUR - 10_000, w.clone()),
        FlowOutcome::Pending
    );
    // Reported again while waiting for a view that shows it, and after.
    assert_eq!(
        report(&mut risk, 2 * HOUR - 5_000, w.clone()),
        FlowOutcome::Pending
    );
    assert!(risk.take_flow_outcomes().is_empty());
    seen(&mut risk, 2 * HOUR + 5_000, dec!(9000));
    assert_eq!(
        risk.take_flow_outcomes(),
        vec![(w.clone(), FlowOutcome::Applied)]
    );
    assert!(risk.take_flow_outcomes().is_empty());
    assert_eq!(
        report(&mut risk, 2 * HOUR + 6_000, w),
        FlowOutcome::Duplicate
    );
    let old = flow(-DAY, dec!(5), "old");
    let outcome = report(&mut risk, 2 * HOUR + 7_000, old.clone());
    assert_eq!(risk.take_flow_outcomes(), vec![(old, outcome)]);
    drop(risk);
    let plain = PersistentRisk::open(&dir.journal(), &limits).unwrap();
    assert!(!plain.takes_flows());
}

#[test]
fn m_a_flow_a_day_after_the_last_record_still_has_it_to_replay_from() {
    // Started at 0 with 10,000; nothing seen until 25:00, which shows
    // 11,000: a deposit of 1,000 at 24:30 not yet reported. Reported then,
    // it is applied from the start, the only record before it although a
    // day old: the day (day 1, from 10,000 at the flow's own time) starts
    // at 11,000, and 11,000 is no gain.
    let dir = Dir::new("day-old-base");
    let limits = RiskLimits::default();
    let mut risk =
        PersistentRisk::initialise(&dir.journal(), limits.clone(), at(0), dec!(10000), "test")
            .unwrap()
            .with_flows();
    seen(&mut risk, 25 * HOUR, dec!(11000));
    assert_eq!(
        report(
            &mut risk,
            25 * HOUR + 1_000,
            flow(24 * HOUR + 30 * 60_000, dec!(1000), "d")
        ),
        FlowOutcome::Applied
    );
    let s = snapshot(&risk);
    assert_eq!((s.day, s.day_start, s.peak), (1, dec!(11000), dec!(11000)));
    journal_sound(&dir, &limits, risk);
}

#[test]
fn m_a_flow_older_than_every_record_kept_is_skipped() {
    // Records at 0 (start), 1:00 (10,500, a new peak) and 26:00 (the day
    // rolled). At 26:00 the records of more than a day ago go but the
    // newest of them: a deposit at 0:30 is before every record left.
    let dir = Dir::new("too-old");
    let limits = RiskLimits::default();
    let mut risk =
        PersistentRisk::initialise(&dir.journal(), limits.clone(), at(0), dec!(10000), "test")
            .unwrap()
            .with_flows();
    seen(&mut risk, HOUR, dec!(10500));
    seen(&mut risk, 26 * HOUR, dec!(10500));
    seen(&mut risk, 26 * HOUR + 1_000, dec!(10500));
    let outcome = report(
        &mut risk,
        26 * HOUR + 2_000,
        flow(30 * 60_000, dec!(1000), "d"),
    );
    assert!(matches!(outcome, FlowOutcome::Skipped(_)), "{outcome:?}");
    journal_sound(&dir, &limits, risk);
}

#[test]
fn m_views_on_the_journal_are_kept_for_a_late_flow_after_half_an_hour() {
    // A deposit of 1,000 at 1:00:30, reported at 2:15 after 70 views a
    // minute apart, each a new peak (so each on the journal), the first
    // showing it. It is replayed from the record at 1:00 with all of them;
    // read before or after the deposit, the day starts at 11,000 (10,000
    // + 1,000; 10,000 x 11,010 / 10,010 = 10,999.00 is lower).
    let dir = Dir::new("written-kept");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, HOUR + 1_000, dec!(10000.01));
    for minute in 1..=70i64 {
        seen(
            &mut risk,
            HOUR + minute * 60_000,
            dec!(11000) + Decimal::from(10 * minute),
        );
    }
    assert_eq!(
        report(
            &mut risk,
            2 * HOUR + 15 * 60_000,
            reading(HOUR + 30_000, dec!(1000), "d", dec!(10000.01))
        ),
        FlowOutcome::Applied
    );
    let s = snapshot(&risk);
    assert_eq!((s.day_start, s.peak), (dec!(11000), dec!(11700)));
    journal_sound(&dir, &limits, risk);
}

#[test]
fn m_views_a_flowed_record_listed_are_kept_for_a_flow_after_half_an_hour() {
    // Views at 1:00:10, :20 and :30 (10,000, not on the journal on their
    // own) are listed by the record of a deposit reported at 1:00:40 for
    // 1:01:00, applied at 1:01:10 (11,000). Seventy minutes of unchanged
    // views later, a withdrawal of 500 at 1:00:15 is reported: it is
    // replayed from the start, with the three listed views, which are on
    // the journal and so still remembered.
    let dir = Dir::new("listed-kept");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    for second in [10, 20, 30] {
        seen(&mut risk, HOUR + second * 1_000, dec!(10000));
    }
    assert_eq!(
        report(
            &mut risk,
            HOUR + 40_000,
            reading(HOUR + 60_000, dec!(1000), "d", dec!(10000))
        ),
        FlowOutcome::Pending
    );
    seen(&mut risk, HOUR + 70_000, dec!(11000));
    for minute in 2..=72i64 {
        seen(&mut risk, HOUR + minute * 60_000, dec!(11000));
    }
    let outcome = report(
        &mut risk,
        2 * HOUR + 15 * 60_000,
        reading(HOUR + 15_000, dec!(-500), "w", dec!(10000)),
    );
    assert_eq!(outcome, FlowOutcome::Applied);
    risk.check_ready().unwrap();
    journal_sound(&dir, &limits, risk);
}

#[test]
fn m_a_view_without_flows_is_an_ordinary_record() {
    let dir = Dir::new("ordinary");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    seen(&mut risk, 2 * HOUR, dec!(9500));
    let records = PersistentRisk::read(&dir.journal()).unwrap();
    assert!(
        records
            .iter()
            .all(|record| !matches!(record.event, JournalEvent::Flowed { .. }))
    );
}

/// A journal with views on it of their own: 10,000 at 1:00 (not written),
/// 9,500 at 2:00 and 9,400 at 3:00 (falls, written).
fn journal_with_views(dir: &Dir) {
    let mut risk = start(dir, RiskLimits::default(), dec!(10000));
    seen(&mut risk, 2 * HOUR, dec!(9500));
    seen(&mut risk, 3 * HOUR, dec!(9400));
}

#[test]
fn m_the_reader_refuses_a_view_without_a_horizon_or_beyond_it() {
    let dir = Dir::new("forge-view");
    journal_with_views(&dir);
    let last = PersistentRisk::read(&dir.journal()).unwrap().pop().unwrap();
    assert!(last.view.is_some());
    // As version 2 (no horizon) with the view kept.
    let forged = forge(&dir, last.seq, |record| {
        record.version = 2;
        record.horizon = None;
    });
    let message = refused(&dir, &forged);
    assert!(message.contains("without a horizon"), "{message}");
    // A view read later than the record's horizon.
    let dir = Dir::new("forge-view-2");
    journal_with_views(&dir);
    let forged = forge(&dir, last.seq, |record| {
        if let Some(view) = &mut record.view {
            *view.times.get_mut("").unwrap() += 1;
        }
    });
    let message = refused(&dir, &forged);
    assert!(message.contains("beyond the horizon"), "{message}");
}

#[test]
fn m_the_reader_refuses_a_review_that_is_not_one() {
    // A review record (written without flows by the CLI) whose state is not
    // a resumption at its own equity: each condition broken alone.
    let make = |name: &str| {
        let dir = Dir::new(name);
        let limits = RiskLimits::default();
        let mut risk = start(&dir, limits.clone(), dec!(10000));
        seen(&mut risk, 2 * HOUR, dec!(7000));
        drop(risk);
        let mut person = PersistentRisk::open(&dir.journal(), &limits).unwrap();
        person
            .resume_after_review(at(3 * HOUR), dec!(7000), "checked")
            .unwrap();
        drop(person);
        let seq = PersistentRisk::read(&dir.journal())
            .unwrap()
            .pop()
            .unwrap()
            .seq;
        (dir, seq)
    };
    type Change = fn(&mut JournalRecord);
    let changes: [(&str, Change); 4] = [
        ("review-stays-stopped", |record| {
            record.state.state = RiskState::Stopped {
                at: at(2 * HOUR),
                drawdown: dec!(0.3),
            };
        }),
        ("review-peak", |record| record.state.peak = dec!(7100)),
        ("review-day-start", |record| {
            record.state.day_start = dec!(7100);
            record.state.peak = dec!(7100);
        }),
        ("review-day", |record| record.state.day = 1),
    ];
    for (name, change) in changes {
        let (dir, seq) = make(name);
        let forged = forge(&dir, seq, change);
        let message = refused(&dir, &forged);
        assert!(
            message.contains("not a resumption") || message.contains("day"),
            "{name}: {message}"
        );
    }
}

#[test]
fn m_a_flowed_record_may_not_leave_out_a_view_an_earlier_one_listed() {
    // 9,995 at 1:30 (5 withdrawn at 1:20, not yet reported: a fall within
    // δ, on no record of its own) is listed by the record of a withdrawal
    // of 1,000 reported at 1:40 for 2:00, applied at 2:00:05 (8,995). The 5
    // reported at 2:10 is replayed from the start, with the 1:30 view. A
    // record leaving that view out replays to the same state (both flows
    // with no trading between), and is refused all the same.
    let dir = Dir::new("forge-listed");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    seen(&mut risk, HOUR + 30 * 60_000, dec!(9995));
    assert_eq!(
        report(
            &mut risk,
            HOUR + 40 * 60_000,
            flow(2 * HOUR, dec!(-1000), "w")
        ),
        FlowOutcome::Pending
    );
    seen(&mut risk, 2 * HOUR + 5_000, dec!(8995));
    assert_eq!(
        report(
            &mut risk,
            2 * HOUR + 10 * 60_000,
            flow(HOUR + 20 * 60_000, dec!(-5), "w5")
        ),
        FlowOutcome::Applied
    );
    drop(risk);
    let record = last_flowed(&dir);
    let JournalEvent::Flowed { base, views, .. } = &record.event else {
        unreachable!()
    };
    assert_eq!((*base, views.len()), (1, 3));
    let forged = forge(&dir, record.seq, |record| {
        if let JournalEvent::Flowed { views, .. } = &mut record.event {
            views.retain(|view| view.equity != dec!(9995));
        }
    });
    let message = refused(&dir, &forged);
    assert!(message.contains("leaves out a view"), "{message}");
}

#[test]
fn m_the_reader_refuses_a_flowed_record_from_before_a_review_guard_wrote() {
    // A review Guard recorded (version 3, with a horizon) starts afresh as
    // one the CLI recorded does: a flowed record from before it is refused.
    let dir = Dir::new("forge-review-base");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    assert!(matches!(
        seen(&mut risk, 2 * HOUR, dec!(7000)),
        RiskState::Stopped { .. }
    ));
    risk.resume_after_review(at(3 * HOUR), dec!(7000), "checked")
        .unwrap();
    assert_eq!(
        report(&mut risk, 3 * HOUR + 1_000, flow(4 * HOUR, dec!(1000), "d")),
        FlowOutcome::Pending
    );
    seen(&mut risk, 4 * HOUR + 5_000, dec!(8000));
    drop(risk);
    let record = last_flowed(&dir);
    let forged = forge(&dir, record.seq, |record| {
        if let JournalEvent::Flowed { base, .. } = &mut record.event {
            *base = 1;
        }
    });
    let message = refused(&dir, &forged);
    assert!(message.contains("a review"), "{message}");
}

// ---------------------------------------------------------------------
// Regression cases for loss attribution: a loss next
// to a withdrawal is read the stricter way, but not where it would take
// what the withdrawal left to zero or below, and not the part the journal
// may not hold (δ, a fall seen before a restart); where the reading is
// ambiguous, a reading that stops counts as a halt for the day only.
// ---------------------------------------------------------------------

#[test]
fn r5_v1_a_loss_after_a_withdrawal_while_running_halts_the_day() {
    // 10,000 seen; 9,000 withdrawn; the 1,000 left loses 500 before the next
    // view (500). Before the withdrawal it would be 5% (peak 10,000 x 500
    // / 9,500 = 526.32); after it, 49.5% (a stop). Ambiguous: halted for
    // the day, not stopped; 400 (24% below 526.32) does not stop it either.
    let dir = Dir::new("r5-v1");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1_000,
        flow(2 * HOUR, dec!(-9000), "w"),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(500)),
        RiskState::HaltedForDay { day: 0 }
    );
    assert_eq!(snapshot(&risk).peak.round_dp(2), dec!(500));
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 10_000, dec!(400)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r5_v1b_the_same_loss_after_a_view_showed_the_withdrawal_stops() {
    // Unambiguous: the view after the withdrawal shows 1,000; 500 lost then
    // is 50% of it: stopped.
    let dir = Dir::new("r5-v1b");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1_000,
        reading(2 * HOUR, dec!(-9000), "w", dec!(10000)),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(1000)),
        RiskState::Active
    );
    assert!(matches!(
        seen(&mut risk, 2 * HOUR + 10_000, dec!(500)),
        RiskState::Stopped { .. }
    ));
}

#[test]
fn r5_v2_a_loss_after_a_withdrawal_while_guard_was_down_halts_the_day() {
    // Guard down; 9,000 withdrawn; the positions left lose 400 over two
    // hours. Before the withdrawal: 4% (peak 10,000 x 600 / 9,600 = 625);
    // after: 39.5% (a stop). Ambiguous: halted for the day, peak 625.
    let dir = Dir::new("r5-v2");
    let limits = RiskLimits::default();
    let risk = start(&dir, limits.clone(), dec!(10000));
    let mut risk = reopen(&dir, &limits, risk);
    report(&mut risk, 4 * HOUR, flow(2 * HOUR, dec!(-9000), "w"));
    assert_eq!(
        seen(&mut risk, 4 * HOUR + 5_000, dec!(600)),
        RiskState::HaltedForDay { day: 0 }
    );
    assert_eq!(snapshot(&risk).peak, dec!(600));
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r5_round_trip_while_down_halts_the_day() {
    // Spec example 7's round trip: Guard down; 9,000 out, 9,000 back, 300
    // lost meanwhile, seen at 9,700. Before both: 3%; between them: 290 of
    // 990 (29%, a stop); after both: 2.9%. Ambiguous: halted for the day.
    let dir = Dir::new("r5-round");
    let limits = RiskLimits::default();
    let risk = start(&dir, limits.clone(), dec!(10000));
    let mut risk = reopen(&dir, &limits, risk);
    report(&mut risk, 4 * HOUR, flow(2 * HOUR, dec!(-9000), "w"));
    report(&mut risk, 4 * HOUR, flow(3 * HOUR, dec!(9000), "d"));
    assert_eq!(
        seen(&mut risk, 4 * HOUR + 5_000, dec!(9700)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r5_p1_p2_a_fee_then_everything_withdrawn_is_no_loss() {
    // p1: 10,000 seen; a position closed for 5 in fees, 9,995 withdrawn, 0
    // seen: after the withdrawal the loss would leave nothing (no reading),
    // before it the withdrawal empties the account. Unknown zero history
    // stays pending and halts today's entries without inventing a loss Stop.
    let dir = Dir::new("r5-p1");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1_000,
        flow(2 * HOUR, dec!(-9995), "w"),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(0)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
    // p2: the same with the 5 seen by a view the journal does not hold
    // (within δ), then a restart.
    let dir = Dir::new("r5-p2");
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, HOUR + 30 * 60_000, dec!(9995));
    let mut risk = reopen(&dir, &limits, risk);
    report(
        &mut risk,
        2 * HOUR - 1_000,
        flow(2 * HOUR, dec!(-9995), "w"),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(0)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r5_p3_a_fall_seen_before_a_restart_halts_the_day_at_most() {
    // 9 lost (seen at 9,991, within δ = 10: not on the journal), a restart,
    // then 9,966 withdrawn: 25 seen. Read after the withdrawal the 9 would
    // be 26% of the 34 left; the restart forgot the view, and only δ of the
    // 34 left (0.034) is read before the flow (a small remainder cannot
    // hide a large share of itself). Read before the
    // withdrawal, 0.09%: ambiguous, so halted for the day, not stopped.
    let dir = Dir::new("r5-p3");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, HOUR + 30 * 60_000, dec!(9991));
    let mut risk = reopen(&dir, &limits, risk);
    report(
        &mut risk,
        2 * HOUR - 1_000,
        flow(2 * HOUR, dec!(-9966), "w"),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(25)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r5_p3b_with_the_cap_a_fall_beyond_what_the_journal_may_miss_halts_the_day() {
    // Cap 2,000: δ is 2. A fall of 1.50 seen before a restart, then all but
    // 25 withdrawn: read before the flow, active. A loss of 9 not seen by
    // any view, then all but 25 withdrawn: 2 read before; after the
    // withdrawal, 7 of the 32 left (rebased peak 32 / 0.999 = 32.03): 22%,
    // a halt and no stop; before it, 0.45% of the cap. Halted for the day.
    let dir = Dir::new("r5-p3b");
    let limits = capped();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, HOUR + 30 * 60_000, dec!(9998.50));
    let mut risk = reopen(&dir, &limits, risk);
    report(
        &mut risk,
        2 * HOUR - 1_000,
        flow(2 * HOUR, dec!(-9973.50), "w"),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(25)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
    let dir = Dir::new("r5-p3b-unseen");
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1_000,
        flow(2 * HOUR, dec!(-9966), "w"),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(25)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
}

// ---------------------------------------------------------------------
// A waived stop halts the view's day. Waivers apply only next to a
// withdrawal, are reported, and δ is bounded by what the flows leave.
// ---------------------------------------------------------------------

#[test]
fn r6_m1_a_waived_stop_across_midnight_halts_the_views_day() {
    // r5_v1 across midnight: 10,000 seen at 23:59:50 (day 0), 9,000
    // withdrawn at 23:59:59, 500 seen at 00:00:05 (day 1). Before the
    // withdrawal 5%, after it 49.9%: the stop is waived, and the day the
    // view is judged on (day 1) halts, rather than day 0, which the view
    // would roll past.
    let dir = Dir::new("r6-m1");
    let limits = RiskLimits::default();
    let mut risk =
        PersistentRisk::initialise(&dir.journal(), limits.clone(), at(0), dec!(10000), "test")
            .unwrap()
            .with_flows();
    seen(&mut risk, DAY - 10_000, dec!(10000));
    report(&mut risk, DAY - 5_000, flow(DAY - 1_000, dec!(-9000), "w"));
    assert_eq!(
        seen(&mut risk, DAY + 5_000, dec!(500)),
        RiskState::HaltedForDay { day: 1 }
    );
    let waived = risk.take_waived_stops();
    assert_eq!(waived.len(), 1);
    assert_eq!(waived[0].at, at(DAY + 5_000));
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r6_m2_a_stop_next_to_a_deposit_alone_stands() {
    // Guard down; positions lose 3,000 of 10,000 (30%); 90,000 deposited;
    // 97,000 seen. Before the deposit a drawdown stop; after it a 3.1%
    // fall. No withdrawal: the strict reading stands (a deposit must not
    // mask a loss): stopped.
    let dir = Dir::new("r6-m2");
    let limits = RiskLimits::default();
    let risk = start(&dir, limits.clone(), dec!(10000));
    let mut risk = reopen(&dir, &limits, risk);
    report(
        &mut risk,
        4 * HOUR,
        reading(3 * HOUR, dec!(90000), "d", dec!(7000)),
    );
    assert!(matches!(
        seen(&mut risk, 4 * HOUR + 5_000, dec!(97000)),
        RiskState::Stopped { .. }
    ));
    assert!(risk.take_waived_stops().is_empty());
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r6_l1_uncertainty_is_reported_once_without_invented_drawdowns() {
    // r5_v1: 10,000 seen, 9,000 withdrawn, 500 seen. Waived: after the
    // withdrawal, with 1 (δ of the 1,000 left) read before it, the peak is
    // 10,000 x 999 / 9,999 = 999.10 and 500 is 49.95% below; kept: before
    // it, 526.32 and 5% below.
    let dir = Dir::new("r6-l1");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1_000,
        measured(2 * HOUR, dec!(-9000), "w", dec!(9500), dec!(10000)),
    );
    seen(&mut risk, 2 * HOUR + 5_000, dec!(500));
    let waived = risk.take_waived_stops();
    assert_eq!(waived.len(), 1, "{waived:?}");
    assert_eq!(waived[0].waived, Decimal::ZERO);
    assert_eq!(waived[0].kept, Decimal::ZERO);
    assert!(!waived[0].measured);
    // Once.
    seen(&mut risk, 2 * HOUR + 10_000, dec!(500));
    assert!(risk.take_waived_stops().is_empty());
}

#[test]
fn r6_l3_a_small_remainder_cannot_hide_a_large_share_of_itself() {
    // 10,000 seen, 9,950 withdrawn, the 50 left loses 10 (20%), 40 seen. δ
    // of 10,000 would be 10, all of it: read before the withdrawal, 0.1%.
    // δ is also bounded by what the withdrawal leaves (0.1% of 50: 0.05):
    // the rest, 9.95, read after it, is 19.9% of 50: halted for the day
    // (no reading stops).
    let dir = Dir::new("r6-l3");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1_000,
        flow(2 * HOUR, dec!(-9950), "w"),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(40)),
        RiskState::HaltedForDay { day: 0 }
    );
}

// ---------------------------------------------------------------------
// Loss attribution considers only possible histories and uses the
// strictest feasible split of a loss.
// ---------------------------------------------------------------------

#[test]
fn r7_a_a_withdrawal_larger_than_a_loss_before_it_allows_waives_nothing() {
    // 10,000 seen; 9,980 withdrawn (20 left); 100 deposited; 70 seen: 50
    // lost. At most 20 can have been lost before the withdrawal (it took
    // all but 20), so at least 30 of the 100 deposited was lost after it.
    // δ (0.1% of the 120 the flows leave) 0.12 before every flow; then:
    // 19.88 before the withdrawal, which empties the account, and 30 after
    // the deposit: from 100, 30.1% below the peak 10,000 x 100 / 9,980 =
    // 100.20; or 19.88 after the withdrawal (taking what it left to zero:
    // not read, (a)); or all 49.88 after the deposit: 41.6%. Every history
    // stops: stopped, nothing waived.
    let dir = Dir::new("r7-a");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1_000,
        reading(2 * HOUR, dec!(-9980), "w", dec!(9980)),
    );
    report(
        &mut risk,
        2 * HOUR - 1_000,
        reading(2 * HOUR + 1_000, dec!(100), "d", dec!(0)),
    );
    assert!(matches!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(70)),
        RiskState::Stopped { .. }
    ));
    assert!(risk.take_waived_stops().is_empty());
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r7_a2_the_same_in_dollars_after_a_restart() {
    // 100,000 seen; Guard down; 99,000 withdrawn (1,000 left); 10,000
    // deposited; 7,000 seen: 4,000 lost, of which at most 1,000 before the
    // withdrawal: at least 3,000 of the 10,000 after the deposit (30%).
    // Stopped.
    let dir = Dir::new("r7-a2");
    let limits = RiskLimits::default();
    let risk = start(&dir, limits.clone(), dec!(100000));
    let mut risk = reopen(&dir, &limits, risk);
    report(
        &mut risk,
        4 * HOUR,
        reading(2 * HOUR, dec!(-99000), "w", dec!(100000)),
    );
    report(
        &mut risk,
        4 * HOUR,
        reading(3 * HOUR, dec!(10000), "d", dec!(0)),
    );
    assert!(matches!(
        seen(&mut risk, 4 * HOUR + 5_000, dec!(7000)),
        RiskState::Stopped { .. }
    ));
    assert!(risk.take_waived_stops().is_empty());
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r7_i8_a_loss_split_around_a_withdrawal_and_a_deposit() {
    // Found by the 4,000-case run. 6,000 seen; 3,400 withdrawn; 1,700
    // lost (65% of the 2,600 left); 7,900 deposited; 900 lost; 7,900 seen:
    // 2,600 lost in all. δ 6 before every flow, then: all 2,594 before the
    // withdrawal (it then empties the account: 2,600 of 6,000, 43%, a
    // stop); after it (taking the 2,600 left to zero: not read, (a)); or
    // after the deposit (24.7%: a halt). The reading that stops has no
    // alternative with more of the loss before the withdrawal: it stands.
    // Stopped, as the truth (65%).
    let dir = Dir::new("r7-i8");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(6000));
    report(
        &mut risk,
        2 * HOUR - 1_000,
        reading(2 * HOUR, dec!(-3400), "w", dec!(6000)),
    );
    report(
        &mut risk,
        2 * HOUR - 1_000,
        reading(2 * HOUR + 1_000, dec!(7900), "d", dec!(900)),
    );
    assert!(matches!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(7900)),
        RiskState::Stopped { .. }
    ));
    assert!(risk.take_waived_stops().is_empty());
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r7_a_fee_everything_withdrawn_then_money_back_trips_nothing() {
    // 10,000 seen; a fee of 5; 9,995 withdrawn; 1,000 deposited; 1,000
    // seen. The 5 (less δ) before the withdrawal, which empties the account
    // (0.05%); after it, taking the 4 left to zero: not read (a); or after
    // the deposit (0.4%). Active.
    let dir = Dir::new("r7-fee");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1_000,
        reading(2 * HOUR, dec!(-9995), "w", dec!(9995)),
    );
    report(
        &mut risk,
        2 * HOUR - 1_000,
        reading(2 * HOUR + 1_000, dec!(1000), "d", dec!(0)),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(1000)),
        RiskState::Active
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r7_l1_a_restart_does_not_report_a_waived_stop_again() {
    // r5_v1's waiver at 2:00:05, taken; a restart; a deposit of 1 at
    // 2:00:00.5 reported late replays that view: not reported again.
    let dir = Dir::new("r7-l1");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1_000,
        flow(2 * HOUR, dec!(-9000), "w"),
    );
    seen(&mut risk, 2 * HOUR + 5_000, dec!(500));
    assert_eq!(risk.take_waived_stops().len(), 1);
    let mut risk = reopen(&dir, &limits, risk);
    report(
        &mut risk,
        2 * HOUR + 10_000,
        flow(2 * HOUR + 500, dec!(1), "d"),
    );
    assert!(risk.take_waived_stops().is_empty());
    journal_sound(&dir, &limits, risk);
}

#[test]
fn r7_l2_uncertainty_reports_once_without_clearing_existing_stop() {
    // Stopped at 7,000 (30%); 6,300 withdrawn and 350 seen: whatever the
    // reading, the engine stays stopped and unreadable data is reported once.
    let dir = Dir::new("r7-l2");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    assert!(matches!(
        seen(&mut risk, 2 * HOUR, dec!(7000)),
        RiskState::Stopped { .. }
    ));
    report(
        &mut risk,
        2 * HOUR + 1_000,
        flow(3 * HOUR, dec!(-6300), "w"),
    );
    assert!(matches!(
        seen(&mut risk, 3 * HOUR + 5_000, dec!(350)),
        RiskState::Stopped { .. }
    ));
    assert_eq!(risk.take_waived_stops().len(), 1);
    assert!(risk.take_waived_stops().is_empty());
}

#[test]
fn r7_l3_a_transfer_fee_between_dexes_is_no_withdrawal() {
    // 10,000 seen; a transfer between two dexes the equity sums, its fee 1
    // (the only money out); 7,499.20 seen. Before the fee 24.998%, after it
    // 25.0005%: a stop either way within rounding of the fee, and the fee is
    // no withdrawal: nothing is waived, the strict reading stands.
    let dir = Dir::new("r7-l3");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    let mut fee = reading(2 * HOUR, dec!(-1), "t", dec!(10000));
    fee.between = true;
    report(&mut risk, 2 * HOUR - 1_000, fee);
    assert!(matches!(
        seen(&mut risk, 2 * HOUR + 5_000, dec!(7499.20)),
        RiskState::Stopped { .. }
    ));
    assert!(risk.take_waived_stops().is_empty());
}

// S5/S6 worked numbers from the measured-value specification of 7 Oct.
fn measured(time_ms: i64, amount: Decimal, id: &str, lo: Decimal, hi: Decimal) -> Flow {
    Flow {
        value: Some(ValueRange {
            lo,
            hi,
            cash_exact: false,
        }),
        ..flow(time_ms, amount, id)
    }
}

#[test]
fn measured_withdrawal_preserves_five_percent_loss() {
    // 10,000 * (9,500 - 4,750) / 9,500 = 5,000; 4,750 is still 5% down.
    let dir = Dir::new("measured-withdrawal");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1000,
        reading(2 * HOUR, dec!(-4750), "w", dec!(9500)),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5000, dec!(4750)),
        RiskState::Active
    );
    assert_eq!(
        (snapshot(&risk).peak, snapshot(&risk).day_start),
        (dec!(5000), dec!(5000))
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 10000, dec!(4650)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn measured_deposit_preserves_five_percent_loss() {
    // 10,000 * (9,500 + 9,500) / 9,500 = 20,000; 18,780 is 6.1% down.
    let dir = Dir::new("measured-deposit");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1000,
        reading(2 * HOUR, dec!(9500), "d", dec!(9500)),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5000, dec!(19000)),
        RiskState::Active
    );
    assert_eq!(snapshot(&risk).day_start, dec!(20000));
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 10000, dec!(18780)),
        RiskState::HaltedForDay { day: 0 }
    );
}

#[test]
fn measured_exact_withdrawal_distinguishes_loss_before_and_after() {
    for (pre, stop) in [(dec!(10000), true), (dec!(9500), false)] {
        // Out 9,000: at 10,000 preflow the 1,000 left loses 50%; at
        // 9,500 preflow the rebased peak is 10,000*500/9,500 = 526.315... .
        let dir = Dir::new("exact-location");
        let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
        report(
            &mut risk,
            2 * HOUR - 1000,
            reading(2 * HOUR, dec!(-9000), "w", pre),
        );
        assert_eq!(
            matches!(
                seen(&mut risk, 2 * HOUR + 5000, dec!(500)),
                RiskState::Stopped { .. }
            ),
            stop
        );
    }
}

#[test]
fn measured_endpoint_stops_on_different_boundaries_have_no_common_witness() {
    // At 7,400 preflow: 26% loss before withdrawal. At 10,000 preflow:
    // 5,000 left ->3,500 is 30% loss afterwards. But preflow 9,000 gives
    // peak 10,000*4,000/9,000 = 4,444.44... ->3,500 is only 21.25%.
    // Therefore both endpoints stopping proves no human stop for the range.
    let dir = Dir::new("common-boundary");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1000,
        measured(2 * HOUR, dec!(-5000), "w", dec!(7400), dec!(10000)),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5000, dec!(3500)),
        RiskState::HaltedForDay { day: 0 }
    );
    assert_eq!(risk.take_waived_stops().len(), 1);
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 10000, dec!(3500)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn candle_range_with_common_endpoint_loss_only_halts_the_day() {
    // Trade-candle prices do not prove historical marks, even when every
    // endpoint would imply at least 30% loss. This remains day halt only.
    let dir = Dir::new("common-loss");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1000,
        measured(2 * HOUR, dec!(90000), "d", dec!(6900), dec!(7000)),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5000, dec!(97000)),
        RiskState::HaltedForDay { day: 0 }
    );
    assert_eq!(risk.take_waived_stops().len(), 1);
}

#[test]
fn unreadable_deposit_halts_even_with_gain_and_survives_restart() {
    let dir = Dir::new("unreadable-gain");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    report(&mut risk, 2 * HOUR - 1000, flow(2 * HOUR, dec!(90000), "d"));
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5000, dec!(97000)),
        RiskState::HaltedForDay { day: 0 }
    );
    assert_eq!(risk.take_waived_stops().len(), 1);
    let mut risk = reopen(&dir, &limits, risk);
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 10000, dec!(97000)),
        RiskState::HaltedForDay { day: 0 }
    );
    assert!(risk.take_waived_stops().is_empty());
    // A further unambiguous 30% fall still needs a human review.
    assert!(matches!(
        seen(&mut risk, 2 * HOUR + 15000, dec!(67000)),
        RiskState::Stopped { .. }
    ));
}

#[test]
fn invalid_or_untrusted_ranges_cannot_manufacture_a_stop() {
    for variant in 0..3 {
        let dir = Dir::new("invalid-range");
        let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
        let count = if variant == 2 { 9 } else { 1 };
        for i in 0..count {
            let (lo, hi) = match variant {
                0 => (dec!(10000), dec!(9000)),
                1 => (dec!(-1), dec!(10000)),
                _ => (dec!(10000), dec!(10000)),
            };
            let mut invalid = measured(2 * HOUR + i, dec!(1), &format!("d{i}"), lo, hi);
            if variant < 2 {
                invalid.value.as_mut().unwrap().cash_exact = true;
            }
            report(&mut risk, 2 * HOUR - 1000, invalid);
        }
        assert_eq!(
            seen(&mut risk, 2 * HOUR + 5000, dec!(7000)),
            RiskState::HaltedForDay { day: 0 }
        );
        assert_eq!(
            seen(&mut risk, 2 * HOUR + 10000, dec!(7000)),
            RiskState::HaltedForDay { day: 0 }
        );
    }
}

#[test]
fn measured_zero_trading_equity_before_deposit_is_still_a_stop() {
    // Positions lost all 10,000 before the deposit; the incoming 90,000
    // cannot erase the known 100% drawdown at the earlier boundary.
    let dir = Dir::new("zero-before-deposit");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1000,
        reading(2 * HOUR, dec!(90000), "d", dec!(0)),
    );
    assert!(matches!(
        seen(&mut risk, 2 * HOUR + 5000, dec!(90000)),
        RiskState::Stopped { .. }
    ));
}

#[test]
fn exact_anchor_after_unknown_span_makes_subsequent_loss_count() {
    // The candle range is unknown. A later cash-only 10,000 checkpoint
    // closes it; the following deposit 1 makes 10,001. Shown 7,000 proves
    // a subsequent 30% loss and needs a human review.
    let dir = Dir::new("prior-ambiguity");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1000,
        measured(2 * HOUR, dec!(1), "d1", dec!(9000), dec!(10000)),
    );
    report(
        &mut risk,
        2 * HOUR - 1000,
        reading(2 * HOUR + 1000, dec!(1), "d2", dec!(10000)),
    );
    assert!(matches!(
        seen(&mut risk, 2 * HOUR + 5000, dec!(7000)),
        RiskState::Stopped { .. }
    ));
    assert!(matches!(
        seen(&mut risk, 2 * HOUR + 10000, dec!(7000)),
        RiskState::Stopped { .. }
    ));
}

#[test]
fn legacy_equal_range_without_cash_provenance_cannot_stop() {
    // A journal written before provenance existed cannot turn a trade
    // candle singleton 7,000 into proof of a 30% account-mark loss.
    let dir = Dir::new("legacy-singleton");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    let legacy: ValueRange = serde_json::from_str(r#"{"lo":"7000","hi":"7000"}"#).unwrap();
    assert!(!legacy.cash_exact);
    report(
        &mut risk,
        2 * HOUR - 1000,
        Flow {
            value: Some(legacy),
            ..flow(2 * HOUR, dec!(90000), "d")
        },
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5000, dec!(97000)),
        RiskState::HaltedForDay { day: 0 }
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn exact_prefix_stop_survives_later_unknown_flow() {
    // A known 30% loss occurs before a deposit of 1; an unreadable 90,000
    // deposit later cannot clear the already established human stop.
    let dir = Dir::new("prefix-stop");
    let mut risk = start(&dir, RiskLimits::default(), dec!(10000));
    report(
        &mut risk,
        2 * HOUR - 1000,
        reading(2 * HOUR, dec!(1), "d1", dec!(7000)),
    );
    report(
        &mut risk,
        2 * HOUR - 1000,
        flow(2 * HOUR + 1000, dec!(90000), "d2"),
    );
    assert!(matches!(
        seen(&mut risk, 2 * HOUR + 5000, dec!(97001)),
        RiskState::Stopped { .. }
    ));
}

#[test]
fn exact_anchor_after_unknown_flow_keeps_later_cap_loss_across_midnight() {
    // Cap 2,000: unreadable deposit 1 before midnight, then trusted cash
    // equity 10,000 just after midnight closes the unknown gap. Its deposit 1
    // makes 10,001. A subsequent 501 loss is 25.05% of the cap and stops.
    let dir = Dir::new("anchor-cap-midnight");
    let limits = capped();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, DAY - 10000, dec!(10000));
    report(&mut risk, DAY - 9000, flow(DAY - 5000, dec!(1), "d1"));
    report(
        &mut risk,
        DAY - 9000,
        reading(DAY + 1000, dec!(1), "d2", dec!(10000)),
    );
    assert!(matches!(
        seen(&mut risk, DAY + 5000, dec!(9500)),
        RiskState::Stopped { .. }
    ));
    journal_sound(&dir, &limits, risk);
}

#[test]
fn unknown_span_keeps_prior_loss_and_rolls_current_utc_day() {
    // A known 5% loss: 10,000->9,500. Unknown deposit 9,500 doubles bases
    // to 20,000 and cash to 19,000 before midnight. Normalize the new-day
    // showing balance 19,000 without inferring loss; halt only day 1. A
    // later 4,000 loss exceeds 25% of the 2,000 cap only in a separate case.
    let dir = Dir::new("unknown-midnight");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(10000));
    seen(&mut risk, DAY - 10000, dec!(9500));
    report(&mut risk, DAY - 9000, flow(DAY - 5000, dec!(9500), "d"));
    assert_eq!(
        seen(&mut risk, DAY + 5000, dec!(19000)),
        RiskState::HaltedForDay { day: 1 }
    );
    assert_eq!(
        (snapshot(&risk).peak, snapshot(&risk).day_start),
        (dec!(20000), dec!(19000))
    );
    journal_sound(&dir, &limits, risk);
}

#[test]
fn trusted_zero_fee_transfer_observes_real_peak_without_rebase() {
    // Start 6,400; an exact transfer-time cash reading 6,500 records a
    // real 100 gain. Then 100 is lost, followed by 100 deposited: peak
    // 6,500*6,500/6,400 = 6,601.5625; day start becomes 6,500.
    let dir = Dir::new("zero-fee-known-peak");
    let mut risk = start(&dir, RiskLimits::default(), dec!(6400));
    let mut transfer = reading(2 * HOUR, Decimal::ZERO, "t", dec!(6500));
    transfer.between = true;
    report(&mut risk, 2 * HOUR - 1000, transfer);
    report(
        &mut risk,
        2 * HOUR - 1000,
        reading(2 * HOUR + 1000, dec!(100), "d", dec!(6400)),
    );
    assert_eq!(
        seen(&mut risk, 2 * HOUR + 5000, dec!(6500)),
        RiskState::Active
    );
    assert_eq!(snapshot(&risk).peak.round_dp(8), dec!(6601.5625));
    assert_eq!(snapshot(&risk).day_start, dec!(6500));
}

#[test]
fn proved_stop_trading_zero_then_two_exact_deposits_across_midnight() {
    // Failed 4k proptest case cc 6f45765feb812ed702df9f9682226a4ef9e7b31b427941b54d0a9a6f9b9b271a.
    // Reduce 8500-w100-w100-w6700 to the equivalent 1600 checkpoint.
    // Trade to700 proves56.25% Stop, then trade to0 before depositing500.
    // The next exact100 deposit is across UTC midnight: its known500 cash
    // must not leave a zero day-start denominator or clear the human Stop.
    let dir = Dir::new("stopped-zero-two-deposits");
    let limits = RiskLimits::default();
    let mut risk = start(&dir, limits.clone(), dec!(1600));
    seen(&mut risk, DAY - 10000, dec!(700));
    let prior = risk.state();
    assert!(matches!(prior, RiskState::Stopped { .. }));
    report(
        &mut risk,
        DAY - 9000,
        reading(DAY - 5000, dec!(500), "refill", Decimal::ZERO),
    );
    report(
        &mut risk,
        DAY - 9000,
        reading(DAY + 1000, dec!(100), "second", dec!(500)),
    );
    assert_eq!(seen(&mut risk, DAY + 4000, dec!(600)), prior);
    assert!(risk.check_ready().is_ok());
    assert_eq!(
        (
            snapshot(&risk).peak,
            snapshot(&risk).day_start,
            snapshot(&risk).last
        ),
        (dec!(1920), dec!(600), dec!(600))
    );
    let settled = snapshot(&risk);
    risk = reopen(&dir, &limits, risk);
    seen(&mut risk, DAY + 5000, dec!(600));
    assert_eq!(snapshot(&risk), settled);
    journal_sound(&dir, &limits, risk);
}
