// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use rust_decimal::{Decimal, dec};
use sha3::{Digest, Sha3_256};
use zunder_core::{Side, Symbol, Timestamp};
use zunder_risk::{RiskEngine, RiskLimits, RiskSnapshot, RiskState, TrackedPosition, VenueView};

use super::{
    FlowOutcome, JOURNAL_VERSION, JournalError, JournalEvent, JournalRecord, JournalScope,
    PersistentRisk, broken_marker,
    check::Trail,
    flow_book::{FLOW_VIEWS_MAX, Remembered},
    persistent::must_write,
    record::{CHECK_PREFIX, FlowFields, RECORD_VERSION, hex},
};
use crate::flows::{self, Flow, RebaseBudget, SeenView, UnaccountedEntry, UnaccountedRule};

const HOUR: i64 = Timestamp::MS_PER_HOUR;
const DAY: i64 = Timestamp::MS_PER_DAY;

fn at(ms: i64) -> Timestamp {
    Timestamp::from_millis(ms)
}

/// A scratch directory, removed when dropped.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "zunder-risk-store-{name}-{}-{unique}",
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

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).ok();
    }
}

fn limits() -> RiskLimits {
    RiskLimits::default()
}

/// A journal started at 2,000 whose engine then observed `equities`,
/// one an hour, each written as the store writes it.
fn journal_with(dir: &TestDir, equities: &[Decimal]) -> PersistentRisk {
    let mut risk =
        PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test").unwrap();
    for (hour, equity) in (1..).zip(equities) {
        risk.engine.observe(at(hour * HOUR), *equity);
        risk.commit(at(hour * HOUR), JournalEvent::Updated).unwrap();
    }
    risk
}

fn lines(dir: &TestDir) -> Vec<String> {
    fs::read_to_string(dir.journal())
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(dir: &TestDir, lines: &[String]) {
    let mut text = lines.join("\n");
    text.push('\n');
    fs::write(dir.journal(), text).unwrap();
}

/// Write a journal of chained records with the given events and states,
/// checksums and all, bypassing the store's own checks.
fn forge(dir: &TestDir, steps: &[(i64, JournalEvent, RiskSnapshot)]) {
    let steps: Vec<_> = steps
        .iter()
        .map(|(ms, event, state)| (*ms, event.clone(), state.clone(), FlowFields::default()))
        .collect();
    forge_with(dir, &steps);
}

/// [`forge`], each record with its flow fields (a horizon makes it a
/// version 3 record).
fn forge_with(dir: &TestDir, steps: &[(i64, JournalEvent, RiskSnapshot, FlowFields)]) {
    let mut prev = String::new();
    let mut text = String::new();
    for (seq, (ms, event, state, fields)) in (1..).zip(steps) {
        let (record, line) = JournalRecord::new(
            seq,
            at(*ms),
            event.clone(),
            state.clone(),
            prev,
            fields.clone(),
        )
        .unwrap();
        prev = record.check;
        text.push_str(&line);
    }
    fs::write(dir.journal(), text).unwrap();
}

fn initialised() -> JournalEvent {
    JournalEvent::Initialised {
        limits: limits(),
        scope: None,
        note: String::new(),
    }
}

fn fresh() -> RiskSnapshot {
    RiskEngine::new(limits(), at(0), dec!(2000))
        .unwrap()
        .snapshot()
}

fn inconsistent(result: Result<PersistentRisk, JournalError>) -> String {
    match result {
        Err(JournalError::Inconsistent { message, .. }) => message,
        other => panic!("expected an inconsistent journal, got {other:?}"),
    }
}

#[test]
fn pending_origin_survives_retention_restart_and_blocks_entries() {
    // An unknown full2,000 withdrawal waits through day2 and restart.
    // Refill1,000 on day3 applies the cash once; neither old monetary
    // figures nor midnight may reopen entries while it is pending.
    let dir = TestDir::new("pending-origin");
    let mut risk = PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test")
        .unwrap()
        .with_flows();
    let withdrawal = Flow {
        time_ms: HOUR,
        amount: dec!(-2000),
        id: "withdraw".into(),
        dex: String::new(),
        between: false,
        value: None,
        unaccounted: None,
    };
    risk.apply_flow(at(HOUR), &withdrawal).unwrap();
    let empty = VenueView::default();
    for ms in [2 * HOUR, DAY + 2 * HOUR, 2 * DAY] {
        let out = risk.observe_view_at(at(ms), [(String::new(), ms)].into(), dec!(0), &empty, true);
        assert!(out.journal_error.is_none(), "{out:?}");
        assert_eq!(risk.check_ready(), Err(JournalError::PendingFlows));
    }
    assert_eq!(risk.flows.as_ref().unwrap().bases.back().unwrap().seq, 1);
    drop(risk);
    let mut risk = PersistentRisk::open(&dir.journal(), &limits())
        .unwrap()
        .with_flows();
    let out = risk.observe_view_at(
        at(2 * DAY + HOUR),
        [(String::new(), 2 * DAY + HOUR)].into(),
        dec!(0),
        &empty,
        true,
    );
    assert!(out.journal_error.is_none(), "{out:?}");
    assert_eq!(risk.check_ready(), Err(JournalError::PendingFlows));
    let refill = Flow {
        time_ms: 2 * DAY + 2 * HOUR,
        amount: dec!(1000),
        id: "refill".into(),
        dex: String::new(),
        between: false,
        value: Some(flows::ValueRange::cash_exact(dec!(0))),
        unaccounted: None,
    };
    risk.apply_flow(at(2 * DAY + 2 * HOUR), &refill).unwrap();
    let ms = 2 * DAY + 3 * HOUR;
    let out = risk.observe_view_at(
        at(ms),
        [(String::new(), ms)].into(),
        dec!(1000),
        &empty,
        true,
    );
    assert!(out.journal_error.is_none(), "{out:?}");
    assert!(risk.check_ready().is_ok());
    assert_eq!(risk.engine.snapshot().peak, dec!(1000));
    drop(risk);
    PersistentRisk::read(&dir.journal()).unwrap();
}

#[test]
fn a_review_refuses_pending_money_without_mutation() {
    for stopped in [false, true] {
        let dir = TestDir::new("review-pending");
        let mut risk =
            PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(10000), "test")
                .unwrap()
                .with_flows();
        let mut flows = Vec::new();
        if stopped {
            // The exact7,000 checkpoint proves30% before500 is added.
            flows.push(Flow {
                time_ms: HOUR,
                amount: dec!(500),
                id: "prefix".into(),
                dex: String::new(),
                between: false,
                value: Some(flows::ValueRange::cash_exact(dec!(7000))),
                unaccounted: None,
            });
        }
        flows.push(Flow {
            time_ms: 2 * HOUR,
            amount: if stopped { dec!(-7500) } else { dec!(-10000) },
            id: "empty".into(),
            dex: String::new(),
            between: false,
            value: None,
            unaccounted: None,
        });
        for flow in flows {
            risk.apply_flow(at(2 * HOUR), &flow).unwrap();
        }
        let out = risk.observe_view_at(
            at(3 * HOUR),
            [(String::new(), 3 * HOUR)].into(),
            dec!(0),
            &VenueView::default(),
            true,
        );
        assert!(out.journal_error.is_none());
        assert_eq!(matches!(risk.state(), RiskState::Stopped { .. }), stopped);
        let snapshot = risk.engine.snapshot();
        let bytes = fs::read(dir.journal()).unwrap();
        assert_eq!(
            risk.resume_after_review(at(4 * HOUR), dec!(10000), "review"),
            Err(JournalError::PendingFlows)
        );
        assert_eq!(risk.engine.snapshot(), snapshot);
        assert_eq!(fs::read(dir.journal()).unwrap(), bytes);
        drop(risk);
        // CLI and other callers may open without enabling reconstruction.
        // The durable listings must still prohibit destroying the origin.
        let mut without_flows = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
        assert!(without_flows.flows.is_none());
        assert_eq!(
            without_flows.check_review_ready(),
            Err(JournalError::PendingFlows)
        );
        assert_eq!(
            without_flows.resume_after_review(at(4 * HOUR), dec!(10000), "review"),
            Err(JournalError::PendingFlows)
        );
        assert_eq!(without_flows.engine.snapshot(), snapshot);
        assert_eq!(fs::read(dir.journal()).unwrap(), bytes);
        let forged = if stopped {
            let mut cleared = without_flows.engine.clone();
            cleared.resume_after_review(at(4 * HOUR), dec!(10000));
            let event = JournalEvent::ResumedAfterReview {
                note: "bypass".into(),
            };
            // Refused for the pending flow alone: the step itself is a
            // resumption from a drawdown stop.
            let refused = without_flows
                .journal
                .append(
                    at(4 * HOUR),
                    event.clone(),
                    cleared.snapshot(),
                    FlowFields::default(),
                    None,
                )
                .unwrap_err();
            assert!(
                matches!(&refused, JournalError::Inconsistent { message, .. }
                    if message == "refusing to write: a review cannot discard pending account flows"),
                "{refused:?}"
            );
            assert_eq!(fs::read(dir.journal()).unwrap(), bytes);
            // A checksummed forged record is refused by the reader too.
            let (_, line) = JournalRecord::new(
                without_flows.journal.last.seq + 1,
                at(4 * HOUR),
                event,
                cleared.snapshot(),
                without_flows.journal.last.check.clone(),
                FlowFields::default(),
            )
            .unwrap();
            let mut forged = bytes.clone();
            forged.extend_from_slice(line.as_bytes());
            Some(forged)
        } else {
            None
        };
        drop(without_flows);
        // Offline corruption: close the writer after every live refusal
        // assertion, then prove the reader rejects a forged resume.
        if let Some(forged) = forged {
            fs::write(dir.journal(), forged).unwrap();
            let refused = PersistentRisk::read(&dir.journal()).unwrap_err();
            assert!(
                matches!(&refused, JournalError::Inconsistent { message, .. }
                    if message == "a review cannot discard pending account flows"),
                "{refused:?}"
            );
            fs::write(dir.journal(), &bytes).unwrap();
        }
        let mut restored = PersistentRisk::open(&dir.journal(), &limits())
            .unwrap()
            .with_flows();
        assert_eq!(restored.engine.snapshot(), snapshot);
        assert!(restored.flows.as_ref().unwrap().pending());
        let out = restored.observe_view_at(
            at(5 * HOUR),
            [(String::new(), 5 * HOUR)].into(),
            dec!(0),
            &VenueView::default(),
            true,
        );
        assert!(out.journal_error.is_none());
        assert_eq!(restored.check_ready(), Err(JournalError::PendingFlows));
    }
}

#[test]
fn exact_arithmetic_underflow_stays_pending_after_restart() {
    let dir = TestDir::new("exact-underflow");
    let mut risk =
        PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(0.000001), "test")
            .unwrap()
            .with_flows();
    risk.observe_view_at(
        at(HOUR),
        [(String::new(), HOUR)].into(),
        dec!(100000000000000000000),
        &VenueView::default(),
        true,
    );
    let flow = Flow {
        time_ms: 2 * HOUR,
        amount: dec!(-99999999999999999999.999999),
        id: "underflow".into(),
        dex: String::new(),
        between: false,
        value: Some(flows::ValueRange::cash_exact(dec!(100000000000000000000))),
        unaccounted: None,
    };
    risk.apply_flow(at(2 * HOUR), &flow).unwrap();
    let out = risk.observe_view_at(
        at(3 * HOUR),
        [(String::new(), 3 * HOUR)].into(),
        dec!(0.000001),
        &VenueView::default(),
        true,
    );
    assert!(out.journal_error.is_none());
    assert_eq!(risk.check_ready(), Err(JournalError::PendingFlows));
    assert!(!matches!(risk.engine.state(), RiskState::Stopped { .. }));
    drop(risk);
    let mut risk = PersistentRisk::open(&dir.journal(), &limits())
        .unwrap()
        .with_flows();
    let ms = DAY + HOUR;
    let out = risk.observe_view_at(
        at(ms),
        [(String::new(), ms)].into(),
        dec!(0.000001),
        &VenueView::default(),
        true,
    );
    assert!(out.journal_error.is_none());
    assert_eq!(risk.check_ready(), Err(JournalError::PendingFlows));
    assert_eq!(risk.engine.state(), RiskState::HaltedForDay { day: 1 });
}

#[test]
fn pending_history_bound_refuses_entries_without_a_loss_stop() {
    let dir = TestDir::new("pending-bound");
    let mut risk = PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test")
        .unwrap()
        .with_flows();
    let withdrawal = Flow {
        time_ms: HOUR,
        amount: dec!(-2000),
        id: "withdraw".into(),
        dex: String::new(),
        between: false,
        value: None,
        unaccounted: None,
    };
    risk.apply_flow(at(HOUR), &withdrawal).unwrap();
    let seen = SeenView {
        at: at(2 * HOUR),
        times: [(String::new(), 2 * HOUR)].into(),
        equity: dec!(0),
    };
    let book = risk.flows.as_mut().unwrap();
    for number in 0..FLOW_VIEWS_MAX {
        book.views.push_back(Remembered {
            number: number as u64,
            view: seen.clone(),
            written: false,
        });
    }
    assert!(matches!(
        risk.fold_view(at(2 * HOUR), &seen),
        Err(JournalError::Broken(_))
    ));
    assert!(!matches!(risk.engine.state(), RiskState::Stopped { .. }));
    assert!(matches!(risk.check_ready(), Err(JournalError::Broken(_))));
    assert_eq!(risk.flows.as_ref().unwrap().views.len(), FLOW_VIEWS_MAX);
    drop(risk);
    assert!(matches!(
        PersistentRisk::open(&dir.journal(), &limits()),
        Err(JournalError::MarkedBroken(_))
    ));
}

#[test]
fn too_many_views_forget_the_oldest_bases_first_and_never_break_the_journal() {
    // The cap is 300 views in these tests. From 1:00, a view a second,
    // every fifth a new high (on the journal, a base each; bases kept
    // one per 10 s), the rest unchanged: 400 views. The oldest bases go
    // with the views only they need; the journal stays whole. A deposit
    // just after the 350th view is replayed from a base kept; one from
    // the 10th, older than every base kept, is skipped.
    let dir = TestDir::new("views-cap");
    let mut risk = PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(10000), "test")
        .unwrap()
        .with_flows();
    let mut equity = dec!(10000);
    for n in 0..400i64 {
        let ms = HOUR + n * 1_000;
        if n % 5 == 0 {
            equity += dec!(1);
        }
        let seen = risk.observe_view_at(
            at(ms),
            [(String::new(), ms)].into(),
            equity,
            &VenueView::default(),
            true,
        );
        assert_eq!(seen.journal_error, None);
        assert!(risk.flows.as_ref().unwrap().views.len() <= FLOW_VIEWS_MAX);
    }
    let late = Flow {
        time_ms: HOUR + 350 * 1_000 + 500,
        amount: dec!(100),
        id: "late".into(),
        dex: String::new(),
        between: false,
        value: None,
        unaccounted: None,
    };
    assert_eq!(
        risk.apply_flow(at(HOUR + 400_000), &late).unwrap(),
        FlowOutcome::Applied
    );
    let old = Flow {
        time_ms: HOUR + 10 * 1_000 + 500,
        id: "old".into(),
        ..late
    };
    assert!(matches!(
        risk.apply_flow(at(HOUR + 400_000), &old).unwrap(),
        FlowOutcome::Skipped(_)
    ));
    risk.check_ready().unwrap();
    drop(risk);
    PersistentRisk::open(&dir.journal(), &limits()).unwrap();
}

#[test]
fn the_trail_forgets_what_lies_before_the_oldest_base_and_checks_what_follows() {
    // Records: the start, then three falls (each 1%, written with its
    // view). Forgetting what lies before record 3 keeps the last view
    // only; a flowed record from record 3 must list it.
    let dir = TestDir::new("trail-prune");
    let mut risk = PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(10000), "test")
        .unwrap()
        .with_flows();
    for (hour, equity) in [(1, dec!(9900)), (2, dec!(9800)), (3, dec!(9700))] {
        let ms = hour * HOUR;
        risk.observe_view_at(
            at(ms),
            [(String::new(), ms)].into(),
            equity,
            &VenueView::default(),
            true,
        );
    }
    drop(risk);
    let records = PersistentRisk::read(&dir.journal()).unwrap();
    assert_eq!(records.len(), 4);
    let mut trail = Trail::default();
    for record in &records {
        trail.record(record);
    }
    trail.prune(3);
    assert_eq!(trail.views.len(), 1);
    let last = records[3].view.clone().unwrap();
    assert!(trail.check(3, 5, &[]).is_err());
    assert!(trail.check(3, 5, &[last]).is_ok());
}

#[test]
fn a_view_observed_without_a_session_reaches_the_journal() {
    // Zunder Guard's path: start at 2,000, see 1,870 an hour later the
    // same day: a loss of 130 / 2,000 = 6.5%, beyond the 6% daily stop.
    let dir = TestDir::new("observe-view");
    let mut risk =
        PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test").unwrap();
    assert!(matches!(risk.check_ready(), Err(JournalError::NotObserved)));
    let seen = risk.observe_view(at(HOUR), dec!(1870), &VenueView::default(), true);
    assert_eq!(seen.state, RiskState::HaltedForDay { day: 0 });
    assert_eq!(seen.journal_error, None);
    assert!(risk.check_ready().is_ok());
    drop(risk);
    // The halt is on disk.
    let reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
    assert_eq!(reopened.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn an_entry_recorded_without_a_session_counts_until_the_venue_settles() {
    // 1 ETH bought at 2,000 with its stop at 1,960: 40 at risk, 2,000 in
    // value, recorded and journaled.
    let dir = TestDir::new("record-entry");
    let mut risk =
        PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test").unwrap();
    risk.observe_view(at(1), dec!(2000), &VenueView::default(), true);
    risk.record_entry(
        at(2),
        Symbol::new("ETH"),
        Side::Buy,
        dec!(1),
        dec!(2000),
        dec!(1960),
    )
    .unwrap();
    let exposure = risk.engine().book_exposure().unwrap();
    assert_eq!((exposure.risk, exposure.notional), (dec!(40), dec!(2000)));
    drop(risk);
    let mut reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
    assert_eq!(reopened.engine().positions().len(), 1);
    // A view that is not settled keeps it; a settled empty one drops it.
    reopened.observe_view(at(3), dec!(2000), &VenueView::default(), false);
    assert_eq!(reopened.engine().positions().len(), 1);
    reopened.observe_view(at(4), dec!(2000), &VenueView::default(), true);
    assert!(reopened.engine().positions().is_empty());
    // Nonsense is refused, and nothing is written for it.
    assert!(
        reopened
            .record_entry(
                at(5),
                Symbol::new("ETH"),
                Side::Buy,
                dec!(0),
                dec!(2000),
                dec!(1960)
            )
            .is_err()
    );
}

#[test]
fn a_journal_restores_the_engine_it_was_written_from() {
    let dir = TestDir::new("restore");
    let risk = journal_with(&dir, &[dec!(2100), dec!(2050), dec!(1960)]);
    assert_eq!(risk.engine().snapshot().last, dec!(1960));
    drop(risk);
    let reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
    // Peak 2,100. The last equity on disk is 2,100 too: a falling
    // equity alone (2,050, then 1,960) is not written.
    assert_eq!(reopened.engine().peak(), dec!(2100));
    assert_eq!(reopened.engine().snapshot().last, dec!(2100));
    assert_eq!(lines(&dir).len(), 2);
    assert_eq!(reopened.check_ready(), Err(JournalError::NotObserved));
}

#[test]
fn what_is_written_and_what_is_not() {
    let base = fresh();
    assert!(!must_write(&base, &base));
    let lower = RiskSnapshot {
        last: dec!(1990),
        ..base.clone()
    };
    // A lower last equity alone: not written. A higher one: written.
    assert!(!must_write(&base, &lower));
    assert!(must_write(
        &lower,
        &RiskSnapshot {
            last: dec!(1995),
            ..base.clone()
        }
    ));
    // A new peak, a new day, a halt, a position: written.
    assert!(must_write(
        &base,
        &RiskSnapshot {
            peak: dec!(2001),
            last: dec!(2001),
            ..base.clone()
        }
    ));
    assert!(must_write(
        &base,
        &RiskSnapshot {
            day: base.day + 1,
            ..base.clone()
        }
    ));
    assert!(must_write(
        &base,
        &RiskSnapshot {
            state: RiskState::HaltedForDay { day: base.day },
            ..base.clone()
        }
    ));
    let position = TrackedPosition {
        symbol: Symbol::new("BTC"),
        side: Side::Buy,
        qty: dec!(1),
        entry: dec!(100),
        stop: Some(dec!(98)),
        mark: dec!(100),
    };
    let holding = RiskSnapshot {
        positions: vec![position.clone()],
        ..base.clone()
    };
    assert!(must_write(&base, &holding));
    // A new price for it alone: not written. A tighter stop: written.
    let repriced = RiskSnapshot {
        positions: vec![TrackedPosition {
            mark: dec!(101),
            ..position.clone()
        }],
        ..base.clone()
    };
    assert!(!must_write(&holding, &repriced));
    let tightened = RiskSnapshot {
        positions: vec![TrackedPosition {
            stop: Some(dec!(99)),
            ..position
        }],
        ..base
    };
    assert!(must_write(&holding, &tightened));
}

#[test]
fn a_halt_and_a_stop_survive_a_restart() {
    let dir = TestDir::new("halt");
    // 2,000 -> 1,880 in the first hour: 6%, halted for day 0.
    let risk = journal_with(&dir, &[dec!(1880)]);
    assert_eq!(risk.state(), RiskState::HaltedForDay { day: 0 });
    drop(risk);
    let mut reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
    assert_eq!(reopened.state(), RiskState::HaltedForDay { day: 0 });

    // 1,880 -> 1,500 a day later: 25% below the peak of 2,000.
    reopened.engine.observe(at(DAY), dec!(1500));
    reopened.commit(at(DAY), JournalEvent::Updated).unwrap();
    drop(reopened);
    let mut reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
    assert!(matches!(reopened.state(), RiskState::Stopped { .. }));
    // A new day and a recovery do not clear it; only a review does.
    reopened.engine.observe(at(3 * DAY), dec!(2500));
    reopened.commit(at(3 * DAY), JournalEvent::Updated).unwrap();
    drop(reopened);
    let mut reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
    assert!(matches!(reopened.state(), RiskState::Stopped { .. }));
    assert_eq!(reopened.engine().peak(), dec!(2500));

    assert_eq!(
        reopened
            .resume_after_review(at(3 * DAY + HOUR), dec!(1600), "reviewed")
            .unwrap(),
        RiskState::Active
    );
    drop(reopened);
    let reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
    assert_eq!(reopened.state(), RiskState::Active);
    assert_eq!(reopened.engine().peak(), dec!(1600));
    let records = PersistentRisk::read(&dir.journal()).unwrap();
    assert!(matches!(
        records.last().unwrap().event,
        JournalEvent::ResumedAfterReview { .. }
    ));
}

#[test]
fn a_review_changes_nothing_unless_stopped_and_cannot_be_back_dated() {
    let dir = TestDir::new("review");
    let mut risk = journal_with(&dir, &[dec!(1880)]);
    // Halted for the day, not stopped: a review changes nothing.
    assert_eq!(
        risk.resume_after_review(at(2 * HOUR), dec!(1880), "no")
            .unwrap(),
        RiskState::HaltedForDay { day: 0 }
    );
    risk.engine.observe(at(2 * DAY), dec!(1400));
    risk.commit(at(2 * DAY), JournalEvent::Updated).unwrap();
    assert!(matches!(
        risk.resume_after_review(at(DAY), dec!(1400), "back-dated"),
        Err(JournalError::Invalid(_))
    ));
    assert!(matches!(risk.state(), RiskState::Stopped { .. }));
}

#[test]
fn a_failed_write_stops_trading_and_is_not_forgotten_by_a_restart() {
    let dir = TestDir::new("failed-write");
    let mut risk = journal_with(&dir, &[]);
    // Writes fail from now on, before a byte reaches the file, as on a
    // full disk: the handle is read-only.
    risk.journal.file = File::open(dir.journal()).unwrap();
    let before = fs::read(dir.journal()).unwrap();
    // A new peak of 2,400 that cannot be written.
    risk.engine.observe(at(HOUR), dec!(2400));
    assert!(matches!(
        risk.commit(at(HOUR), JournalEvent::Updated),
        Err(JournalError::Io { .. })
    ));
    assert_eq!(fs::read(dir.journal()).unwrap(), before);
    assert!(matches!(risk.check_ready(), Err(JournalError::Broken(_))));
    // Nothing is written after a failure, a review included.
    risk.engine.observe(at(2 * HOUR), dec!(1700));
    assert!(matches!(risk.state(), RiskState::Stopped { .. }));
    assert!(matches!(
        risk.commit(at(2 * HOUR), JournalEvent::Updated),
        Err(JournalError::Broken(_))
    ));
    assert!(matches!(
        risk.resume_after_review(at(3 * HOUR), dec!(1700), "no"),
        Err(JournalError::Broken(_))
    ));
    drop(risk);

    // The file alone says peak 2,000 and active; the marker says that
    // is not the whole story.
    let marker = broken_marker(&dir.journal());
    assert!(
        fs::read_to_string(&marker)
            .unwrap()
            .contains(dir.journal().to_str().unwrap())
    );
    assert_eq!(
        PersistentRisk::open(&dir.journal(), &limits()).unwrap_err(),
        JournalError::MarkedBroken(marker.clone())
    );
    // A person looks, decides, and removes the marker.
    fs::remove_file(&marker).unwrap();
    assert_eq!(
        PersistentRisk::open(&dir.journal(), &limits())
            .unwrap()
            .engine()
            .peak(),
        dec!(2000)
    );
}

#[test]
fn a_review_that_cannot_be_written_does_not_resume() {
    let dir = TestDir::new("review-unwritten");
    let mut risk = journal_with(&dir, &[dec!(1400)]);
    assert!(matches!(risk.state(), RiskState::Stopped { .. }));
    risk.journal.file = File::open(dir.journal()).unwrap();
    assert!(matches!(
        risk.resume_after_review(at(2 * HOUR), dec!(1400), "reviewed"),
        Err(JournalError::Io { .. })
    ));
    // Not on disk, so not resumed in memory either.
    assert!(matches!(risk.state(), RiskState::Stopped { .. }));
    assert_eq!(risk.engine().peak(), dec!(2000));
}

#[test]
fn the_writer_refuses_a_record_its_reader_would_refuse() {
    let dir = TestDir::new("refuse-write");
    let mut risk = journal_with(&dir, &[dec!(2200)]);
    let before = fs::read(dir.journal()).unwrap();
    // Make the engine's next state a step the reader refuses: a peak
    // below the one on disk.
    risk.engine = RiskEngine::new(limits(), at(2 * HOUR), dec!(2100)).unwrap();
    let refused = risk
        .commit(at(2 * HOUR), JournalEvent::Updated)
        .unwrap_err();
    assert!(
        matches!(&refused, JournalError::Inconsistent { message, .. } if message.contains("peak")),
        "{refused:?}"
    );
    // Nothing was appended; the journal still opens, after the marker.
    assert_eq!(fs::read(dir.journal()).unwrap(), before);
    assert!(matches!(risk.check_ready(), Err(JournalError::Broken(_))));
    drop(risk);
    fs::remove_file(broken_marker(&dir.journal())).unwrap();
    assert_eq!(
        PersistentRisk::open(&dir.journal(), &limits())
            .unwrap()
            .engine()
            .peak(),
        dec!(2200)
    );
}

#[test]
fn a_review_may_carry_a_record_of_positions_that_caught_up() {
    let dir = TestDir::new("review-positions");
    let mut risk = journal_with(&dir, &[]);
    risk.engine
        .record_entry(Symbol::new("BTC"), Side::Buy, dec!(1), dec!(100), dec!(98))
        .unwrap();
    risk.commit(at(HOUR), JournalEvent::Updated).unwrap();
    risk.engine.observe(at(2 * HOUR), dec!(1400));
    risk.commit(at(2 * HOUR), JournalEvent::Updated).unwrap();
    // The session closed it and told the engine, but the sync that
    // would have written that failed to read the venue.
    risk.engine.record_closed(&Symbol::new("BTC"));
    assert_eq!(
        risk.resume_after_review(at(3 * HOUR), dec!(1400), "reviewed")
            .unwrap(),
        RiskState::Active
    );
    drop(risk);
    let reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
    assert_eq!(reopened.state(), RiskState::Active);
    assert!(reopened.engine().positions().is_empty());
}

#[test]
fn a_missing_journal_is_refused_and_an_existing_one_never_replaced() {
    let dir = TestDir::new("missing");
    assert_eq!(
        PersistentRisk::open(&dir.journal(), &limits()).unwrap_err(),
        JournalError::Missing(dir.journal())
    );
    drop(journal_with(&dir, &[dec!(1880)]));
    let before = fs::read(dir.journal()).unwrap();
    assert_eq!(
        PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "again")
            .unwrap_err(),
        JournalError::Exists(dir.journal())
    );
    assert_eq!(fs::read(dir.journal()).unwrap(), before);
    // An empty file is not a journal either.
    let empty = dir.0.join("empty.jsonl");
    fs::write(&empty, "").unwrap();
    assert!(matches!(
        PersistentRisk::open(&empty, &limits()),
        Err(JournalError::Malformed { .. })
    ));
}

#[test]
fn a_journal_is_open_in_one_process_at_a_time() {
    let dir = TestDir::new("lock");
    let risk = journal_with(&dir, &[]);
    assert_eq!(
        PersistentRisk::open(&dir.journal(), &limits()).unwrap_err(),
        JournalError::Locked(dir.journal())
    );
    drop(risk);
    assert!(PersistentRisk::open(&dir.journal(), &limits()).is_ok());
}

#[test]
fn the_locked_writer_allows_read_inspection_and_preserves_its_cursor() {
    let dir = TestDir::new("read-locked");
    let mut risk = journal_with(&dir, &[dec!(2200)]);
    let position = risk.journal.file.stream_position().unwrap();
    let inspected = PersistentRisk::read(&dir.journal()).unwrap();
    assert_eq!(risk.journal.records().unwrap(), inspected);
    assert_eq!(risk.journal.file.stream_position().unwrap(), position);
    assert_eq!(inspected.last(), Some(&risk.journal.last));
    // Even after a read/seek, an ordinary writer must append at EOF.
    risk.journal.file.seek(SeekFrom::Start(0)).unwrap();
    assert_eq!(
        PersistentRisk::open(&dir.journal(), &limits()).unwrap_err(),
        JournalError::Locked(dir.journal())
    );
    risk.engine.observe(at(2 * HOUR), dec!(2400));
    risk.commit(at(2 * HOUR), JournalEvent::Updated).unwrap();
    drop(risk);
    assert_eq!(
        PersistentRisk::open(&dir.journal(), &limits())
            .unwrap()
            .engine()
            .peak(),
        dec!(2400)
    );
}

#[test]
fn rebuilding_flows_keeps_the_writer_and_appends_after_the_existing_records() {
    let dir = TestDir::new("rebuild-handle");
    let mut risk = journal_with(&dir, &[]).with_flows();
    let empty = VenueView::default();
    let first = risk.observe_view_at(at(0), [(String::new(), 0)].into(), dec!(2000), &empty, true);
    assert!(first.journal_error.is_none());
    let flow = Flow {
        time_ms: HOUR,
        amount: dec!(100),
        id: "deposit-on-held-handle".into(),
        dex: String::new(),
        between: false,
        value: Some(flows::ValueRange::cash_exact(dec!(2000))),
        unaccounted: None,
    };
    risk.apply_flow(at(HOUR), &flow).unwrap();
    // Hand calculation: 2,000 cash + 100 deposit = 2,100; no trade PnL.
    let out = risk.observe_view_at(
        at(2 * HOUR),
        [(String::new(), 2 * HOUR)].into(),
        dec!(2100),
        &empty,
        true,
    );
    assert!(out.journal_error.is_none());
    let before = risk.engine.snapshot();
    let position = risk.journal.file.stream_position().unwrap();
    let mut rebuilt = risk.with_flows();
    assert!(rebuilt.broken.is_none());
    assert!(rebuilt.knows_flow(&flow.id));
    assert_eq!(rebuilt.engine.snapshot(), before);
    assert_eq!(rebuilt.journal.file.stream_position().unwrap(), position);
    assert!(matches!(
        PersistentRisk::open(&dir.journal(), &limits()),
        Err(JournalError::Locked(_))
    ));
    let out = rebuilt.observe_view_at(
        at(3 * HOUR),
        [(String::new(), 3 * HOUR)].into(),
        dec!(2100),
        &empty,
        true,
    );
    assert!(out.journal_error.is_none());
    drop(rebuilt);
    let restarted = PersistentRisk::open(&dir.journal(), &limits())
        .unwrap()
        .with_flows();
    assert!(restarted.broken.is_none());
    assert!(restarted.knows_flow(&flow.id));
    assert_eq!(restarted.engine.peak(), dec!(2100));
}

#[test]
fn rebuilding_a_damaged_journal_restores_the_cursor_and_blocks_entries() {
    for damage in [b"{".as_slice(), b"not-json\n".as_slice()] {
        let dir = TestDir::new("rebuild-damaged");
        let mut risk = journal_with(&dir, &[]);
        risk.journal.file.write_all(damage).unwrap();
        risk.journal.file.sync_data().unwrap();
        let position = risk.journal.file.stream_position().unwrap();
        assert!(risk.journal.records().is_err());
        assert_eq!(risk.journal.file.stream_position().unwrap(), position);
        let mut rebuilt = risk.with_flows();
        assert!(matches!(
            rebuilt.check_ready(),
            Err(JournalError::Broken(_))
        ));
        assert_eq!(rebuilt.journal.file.stream_position().unwrap(), position);
    }
}

#[test]
fn reconstruction_refuses_a_valid_record_not_written_by_its_writer() {
    let dir = TestDir::new("rebuild-other-writer");
    let mut risk = journal_with(&dir, &[]);
    let (_, line) = JournalRecord::new(
        risk.journal.last.seq + 1,
        at(HOUR),
        JournalEvent::Updated,
        risk.engine.snapshot(),
        risk.journal.last.check.clone(),
        FlowFields::default(),
    )
    .unwrap();
    risk.journal.file.write_all(line.as_bytes()).unwrap();
    risk.journal.file.sync_data().unwrap();
    let position = risk.journal.file.stream_position().unwrap();
    assert!(matches!(
        risk.journal.records(),
        Err(JournalError::Inconsistent { .. })
    ));
    assert_eq!(risk.journal.file.stream_position().unwrap(), position);
    assert!(matches!(
        risk.with_flows().check_ready(),
        Err(JournalError::Broken(_))
    ));
}

#[cfg(unix)]
#[test]
fn flow_reconstruction_uses_the_open_journal_after_path_substitution() {
    let dir = TestDir::new("rebuild-namespace");
    let risk = journal_with(&dir, &[]);
    let state = risk.engine.snapshot();
    let original = dir.0.join("original.jsonl");
    fs::rename(dir.journal(), &original).unwrap();
    fs::write(dir.journal(), "not the opened journal\n").unwrap();
    let rebuilt = risk.with_flows();
    assert!(rebuilt.broken.is_none());
    assert_eq!(rebuilt.engine.snapshot(), state);
    assert!(PersistentRisk::read(&dir.journal()).is_err());
    assert!(PersistentRisk::read(&original).is_ok());
}

#[cfg(windows)]
#[test]
fn windows_writer_excludes_legacy_write_and_delete_handles_in_both_orders() {
    use std::os::windows::fs::OpenOptionsExt;

    use super::file::open_locked;
    let dir = TestDir::new("windows-writer-sharing");
    drop(journal_with(&dir, &[]));
    // The previous implementation opened read+append with default sharing
    // and then took std's exclusive byte lock. Both versions exclude one another.
    let legacy = OpenOptions::new()
        .read(true)
        .append(true)
        .open(dir.journal())
        .unwrap();
    legacy.try_lock().unwrap();
    assert_eq!(
        open_locked(&dir.journal()).unwrap_err(),
        JournalError::Locked(dir.journal())
    );
    drop(legacy);
    let writer = open_locked(&dir.journal()).unwrap();
    assert!(
        OpenOptions::new()
            .read(true)
            .append(true)
            .open(dir.journal())
            .is_err()
    );
    assert!(fs::rename(dir.journal(), dir.0.join("renamed")).is_err());
    assert!(fs::remove_file(dir.journal()).is_err());
    assert!(PersistentRisk::read(&dir.journal()).is_ok());
    drop(writer);
    for access in [0x4000_0000, 0x0001_0000] {
        // GENERIC_WRITE, DELETE
        let incompatible = OpenOptions::new()
            .access_mode(access)
            .share_mode(7)
            .open(dir.journal())
            .unwrap();
        assert_eq!(
            open_locked(&dir.journal()).unwrap_err(),
            JournalError::Locked(dir.journal())
        );
        drop(incompatible);
        assert!(open_locked(&dir.journal()).is_ok());
    }
}

#[test]
fn other_limits_are_refused() {
    let dir = TestDir::new("limits");
    drop(journal_with(&dir, &[]));
    let tighter = RiskLimits {
        daily_loss_stop: dec!(0.05),
        ..limits()
    };
    assert!(matches!(
        PersistentRisk::open(&dir.journal(), &tighter),
        Err(JournalError::LimitsDiffer { .. })
    ));
}

#[test]
fn a_torn_record_is_refused_until_a_person_repairs_it() {
    let dir = TestDir::new("torn");
    drop(journal_with(&dir, &[dec!(1880)]));
    let complete = fs::read(dir.journal()).unwrap();
    let mut torn = complete.clone();
    // 51 bytes of a third record whose write was cut short.
    torn.extend_from_slice(br#"{"format":"zunder-risk-journal","version":1,"seq":3"#);
    fs::write(dir.journal(), &torn).unwrap();

    assert!(matches!(
        PersistentRisk::open(&dir.journal(), &limits()),
        Err(JournalError::TornTail { bytes: 51, .. })
    ));
    assert!(matches!(
        PersistentRisk::read(&dir.journal()),
        Err(JournalError::TornTail { .. })
    ));
    let cut =
        PersistentRisk::repair_torn_tail(&dir.journal(), &limits(), at(HOUR), "repaired").unwrap();
    assert_eq!(cut, 51);
    let repaired = fs::read(dir.journal()).unwrap();
    assert!(repaired.starts_with(&complete));
    let added = &repaired[complete.len()..];
    assert!(!added.contains(&0));
    assert_eq!(added.iter().filter(|byte| **byte == b'\n').count(), 1);
    let reopened = PersistentRisk::open(&dir.journal(), &limits()).unwrap();
    // The halt in the last complete record is still there.
    assert_eq!(reopened.state(), RiskState::HaltedForDay { day: 0 });
    drop(reopened);
    let records = PersistentRisk::read(&dir.journal()).unwrap();
    assert_eq!(records.len(), 3);
    assert!(matches!(
        records[2].event,
        JournalEvent::Repaired { cut_bytes: 51, .. }
    ));
    // Nothing to repair now.
    assert_eq!(
        PersistentRisk::repair_torn_tail(&dir.journal(), &limits(), at(HOUR), "again").unwrap(),
        0
    );
}

#[test]
fn repair_refuses_a_live_writer_without_mutation() {
    let dir = TestDir::new("repair-live-writer");
    let risk = journal_with(&dir, &[dec!(1880)]);
    let before = fs::read(dir.journal()).unwrap();
    assert_eq!(
        PersistentRisk::repair_torn_tail(&dir.journal(), &limits(), at(HOUR), "repair")
            .unwrap_err(),
        JournalError::Locked(dir.journal())
    );
    assert_eq!(fs::read(dir.journal()).unwrap(), before);
    // 2,000 - 120 = 1,880; the daily-loss halt must survive refused repair.
    assert_eq!(risk.state(), RiskState::HaltedForDay { day: 0 });
}

#[test]
fn a_changed_record_is_refused() {
    let dir = TestDir::new("tamper");
    drop(journal_with(&dir, &[dec!(1880)]));
    let mut edited = lines(&dir);
    // Someone lifts the halt by hand.
    edited[1] = edited[1].replace(r#"{"halted_for_day":{"day":0}}"#, r#""active""#);
    assert_ne!(edited, lines(&dir));
    write_lines(&dir, &edited);
    let message = inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
    assert!(message.contains("checksum"), "{message}");
}

#[test]
fn a_removed_or_reordered_record_is_refused() {
    let dir = TestDir::new("order");
    drop(journal_with(&dir, &[dec!(2100), dec!(2200), dec!(1880)]));
    let original = lines(&dir);
    assert_eq!(original.len(), 4);

    let mut gap = original.clone();
    gap.remove(1);
    write_lines(&dir, &gap);
    let message = inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
    assert!(message.contains("sequence"), "{message}");

    let mut swapped = original;
    swapped.swap(1, 2);
    write_lines(&dir, &swapped);
    inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
}

#[test]
fn a_newer_version_or_a_foreign_file_is_refused() {
    let dir = TestDir::new("version");
    drop(journal_with(&dir, &[]));
    let mut newer = lines(&dir);
    // An engine without flows writes version 2; anything above the
    // newest version this build reads is refused.
    newer[0] = newer[0].replace(
        &format!(r#""version":{RECORD_VERSION}"#),
        &format!(r#""version":{}"#, JOURNAL_VERSION + 1),
    );
    write_lines(&dir, &newer);
    assert!(matches!(
        PersistentRisk::open(&dir.journal(), &limits()),
        Err(JournalError::UnsupportedVersion { version, .. }) if version == u64::from(JOURNAL_VERSION) + 1
    ));
    write_lines(&dir, &[r#"{"seq":1}"#.to_owned()]);
    assert!(matches!(
        PersistentRisk::open(&dir.journal(), &limits()),
        Err(JournalError::Malformed { .. })
    ));
}

#[test]
fn steps_the_engine_cannot_take_are_refused_even_with_valid_checksums() {
    let dir = TestDir::new("steps");
    let start = fresh();
    let higher = RiskSnapshot {
        peak: dec!(2200),
        last: dec!(2200),
        ..start.clone()
    };

    // The peak falls.
    forge(
        &dir,
        &[
            (0, initialised(), start.clone()),
            (HOUR, JournalEvent::Updated, higher),
            (2 * HOUR, JournalEvent::Updated, start.clone()),
        ],
    );
    let message = inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
    assert!(message.contains("peak"), "{message}");

    // A drawdown stop cleared without a review.
    let stopped = RiskSnapshot {
        state: RiskState::Stopped {
            at: at(HOUR),
            drawdown: dec!(0.3),
        },
        last: dec!(1400),
        ..start.clone()
    };
    let active_again = RiskSnapshot {
        day: 1,
        day_start: dec!(1400),
        last: dec!(1400),
        peak: dec!(1400),
        ..start.clone()
    };
    forge(
        &dir,
        &[
            (0, initialised(), start.clone()),
            (HOUR, JournalEvent::Updated, stopped.clone()),
            (DAY, JournalEvent::Updated, active_again.clone()),
        ],
    );
    inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
    // Cleared without a review and without touching the peak: a new
    // day at the old peak of 2,000.
    let cleared_at_peak = RiskSnapshot {
        day: 1,
        ..start.clone()
    };
    forge(
        &dir,
        &[
            (0, initialised(), start.clone()),
            (HOUR, JournalEvent::Updated, stopped.clone()),
            (DAY, JournalEvent::Updated, cleared_at_peak),
        ],
    );
    let message = inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
    assert!(message.contains("without a review"), "{message}");
    // The same step as a review is fine.
    forge(
        &dir,
        &[
            (0, initialised(), start.clone()),
            (HOUR, JournalEvent::Updated, stopped.clone()),
            (
                DAY,
                JournalEvent::ResumedAfterReview {
                    note: "reviewed".into(),
                },
                active_again,
            ),
        ],
    );
    assert_eq!(
        PersistentRisk::open(&dir.journal(), &limits())
            .unwrap()
            .state(),
        RiskState::Active
    );

    // A halt cleared on the day it fired.
    let halted = RiskSnapshot {
        state: RiskState::HaltedForDay { day: 0 },
        last: dec!(1880),
        ..start.clone()
    };
    let cleared = RiskSnapshot {
        last: dec!(1990),
        ..start.clone()
    };
    forge(
        &dir,
        &[
            (0, initialised(), start.clone()),
            (HOUR, JournalEvent::Updated, halted),
            (2 * HOUR, JournalEvent::Updated, cleared),
        ],
    );
    let message = inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
    assert!(message.contains("halt"), "{message}");

    // A second `initialised` record, which could reset everything.
    forge(
        &dir,
        &[
            (0, initialised(), stopped),
            (HOUR, initialised(), start.clone()),
        ],
    );
    inconsistent(PersistentRisk::open(&dir.journal(), &limits()));

    // A state no observation leads to: active 30% below the peak.
    forge(
        &dir,
        &[(
            0,
            initialised(),
            RiskSnapshot {
                last: dec!(1400),
                ..start
            },
        )],
    );
    inconsistent(PersistentRisk::open(&dir.journal(), &limits()));
}

/// A small deterministic generator for the property test below.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
}

fn strictness(state: RiskState) -> u8 {
    match state {
        RiskState::Active => 0,
        RiskState::HaltedForDay { .. } => 1,
        RiskState::Stopped { .. } => 2,
    }
}

#[test]
fn a_restored_engine_is_never_less_strict_than_one_that_kept_running() {
    // Random equity paths, a few hours between observations, with a
    // restart at a random step from what the write policy put on disk.
    // From then on both engines see the same observations; the
    // restored one must be at least as strict at every step, with the
    // same peak. Without the equity cap, and with a cap of 1,500 that
    // binds from the start (decision of 6 Oct 2026).
    let capped = RiskLimits {
        max_trading_equity_usd: Some(dec!(1500)),
        ..limits()
    };
    for (limits, seed) in [limits(), capped]
        .into_iter()
        .flat_map(|limits| (1..400u64).map(move |seed| (limits.clone(), seed)))
    {
        let mut rng = Lcg(seed);
        let mut running = RiskEngine::new(limits.clone(), at(0), dec!(2000)).unwrap();
        let mut written = running.snapshot();
        let crash_at = rng.next() % 120;
        let mut restored: Option<RiskEngine> = None;
        let mut equity = dec!(2000);
        let mut ms = 0;
        for step in 0..160u64 {
            ms += i64::try_from(1 + rng.next() % 9).unwrap() * HOUR;
            // Moves of -3% to +3% in steps of 0.1%, and now and then a
            // fall of 8% on top.
            let percent = Decimal::from(i64::try_from(rng.next() % 61).unwrap() - 30) / dec!(1000);
            let shock = if rng.next().is_multiple_of(25) {
                dec!(-0.08)
            } else {
                Decimal::ZERO
            };
            equity = (equity * (Decimal::ONE + percent + shock)).round_dp(2);
            if step == crash_at {
                restored = Some(RiskEngine::restore(limits.clone(), written.clone()).unwrap());
            }
            let state = running.observe(at(ms), equity);
            let snapshot = running.snapshot();
            if must_write(&written, &snapshot) {
                written = snapshot;
            }
            // Every state the policy writes can be restored.
            RiskEngine::restore(limits.clone(), written.clone()).unwrap();
            if let Some(restored) = restored.as_mut() {
                let restored_state = restored.observe(at(ms), equity);
                assert!(
                    strictness(restored_state) >= strictness(state),
                    "seed {seed}, step {step}: restored {restored_state:?}, running {state:?}"
                );
                assert_eq!(restored.peak(), running.peak(), "seed {seed}, step {step}");
            }
        }
    }
}

fn scope(network: &str, account: &str) -> JournalScope {
    JournalScope {
        network: network.into(),
        account: account.into(),
    }
}

const A: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
const B: &str = "0x0000000000000000000000000000000000000001";

#[test]
fn a_journal_opens_only_for_its_own_network_and_account() {
    let dir = TestDir::new("scope");
    let testnet_a = scope("testnet", A);
    let risk = PersistentRisk::initialise_for(
        &dir.journal(),
        limits(),
        &testnet_a,
        at(0),
        dec!(2000),
        "test",
    )
    .unwrap();
    drop(risk);
    // The scope is in the first record.
    let records = PersistentRisk::read(&dir.journal()).unwrap();
    assert!(matches!(
        &records[0].event,
        JournalEvent::Initialised { scope: Some(recorded), .. } if *recorded == testnet_a
    ));
    // Another network, another account, or no scope at all: refused.
    for other in [scope("mainnet", A), scope("testnet", B)] {
        assert!(matches!(
            PersistentRisk::open_for(&dir.journal(), &limits(), &other),
            Err(JournalError::ScopeDiffers { .. })
        ));
    }
    assert!(matches!(
        PersistentRisk::open(&dir.journal(), &limits()),
        Err(JournalError::ScopeDiffers { .. })
    ));
    // The same scope opens.
    assert!(PersistentRisk::open_for(&dir.journal(), &limits(), &testnet_a).is_ok());
}

#[test]
fn a_journal_without_a_scope_does_not_open_for_one() {
    // Journals started before scopes existed belong to no network: a
    // runner, which always names one, needs a new journal.
    let dir = TestDir::new("unscoped");
    drop(PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test").unwrap());
    assert!(matches!(
        PersistentRisk::open_for(&dir.journal(), &limits(), &scope("mainnet", A)),
        Err(JournalError::ScopeDiffers { journal: None, .. })
    ));
    assert!(PersistentRisk::open(&dir.journal(), &limits()).is_ok());
    // Its first record carries no scope key, as before scopes existed.
    let text = fs::read_to_string(dir.journal()).unwrap();
    assert!(!text.contains("scope"), "{text}");
}

#[test]
fn a_torn_journal_is_repaired_only_for_its_own_scope() {
    let dir = TestDir::new("scope-repair");
    let mainnet_a = scope("mainnet", A);
    drop(
        PersistentRisk::initialise_for(
            &dir.journal(),
            limits(),
            &mainnet_a,
            at(0),
            dec!(2000),
            "test",
        )
        .unwrap(),
    );
    let mut file = OpenOptions::new().append(true).open(dir.journal()).unwrap();
    file.write_all(b"{\"check\":\"torn").unwrap();
    drop(file);
    assert!(matches!(
        PersistentRisk::repair_torn_tail_for(
            &dir.journal(),
            &limits(),
            &scope("testnet", A),
            at(1),
            "test"
        ),
        Err(JournalError::ScopeDiffers { .. })
    ));
    assert!(
        PersistentRisk::repair_torn_tail_for(&dir.journal(), &limits(), &mainnet_a, at(1), "test")
            .unwrap()
            > 0
    );
    assert!(PersistentRisk::open_for(&dir.journal(), &limits(), &mainnet_a).is_ok());
}

#[test]
fn a_version_1_journal_is_still_read() {
    // A journal written before version 2: its first record re-encoded
    // as version 1, with its checksum computed again.
    let dir = TestDir::new("v1");
    drop(journal_with(&dir, &[]));
    let line = lines(&dir).remove(0);
    let body = format!(
        "{{{}",
        line.split_once("\",")
            .unwrap()
            .1
            .replace(&format!(r#""version":{RECORD_VERSION}"#), r#""version":1"#)
    );
    let check = hex(&Sha3_256::digest(body.as_bytes()));
    let old = format!("{CHECK_PREFIX}{check}\",{}", &body[1..]);
    write_lines(&dir, &[old]);
    let records = PersistentRisk::read(&dir.journal()).unwrap();
    assert_eq!(records[0].version, 1);
    assert!(PersistentRisk::open(&dir.journal(), &limits()).is_ok());
}

#[test]
fn a_person_can_record_the_scope_of_an_unscoped_journal_once() {
    let dir = TestDir::new("adopt");
    drop(journal_with(&dir, &[dec!(2100)]));
    let peak = PersistentRisk::open(&dir.journal(), &limits())
        .unwrap()
        .engine()
        .peak();
    let testnet_a = scope("testnet", A);
    PersistentRisk::adopt_scope(&dir.journal(), &limits(), &testnet_a, at(HOUR), "test").unwrap();
    // Now it opens for that scope only, with its history.
    let risk = PersistentRisk::open_for(&dir.journal(), &limits(), &testnet_a).unwrap();
    assert_eq!(risk.engine().peak(), peak);
    drop(risk);
    for other in [scope("mainnet", A), scope("testnet", B)] {
        assert!(matches!(
            PersistentRisk::open_for(&dir.journal(), &limits(), &other),
            Err(JournalError::ScopeDiffers { .. })
        ));
    }
    assert!(matches!(
        PersistentRisk::open(&dir.journal(), &limits()),
        Err(JournalError::ScopeDiffers { .. })
    ));
    // Once only: a second adoption, to any scope, is refused.
    assert!(matches!(
        PersistentRisk::adopt_scope(
            &dir.journal(),
            &limits(),
            &scope("mainnet", A),
            at(2 * HOUR),
            "test"
        ),
        Err(JournalError::ScopeDiffers { .. })
    ));
    // And a journal started with a scope cannot be adopted either.
    let scoped = TestDir::new("adopt-scoped");
    drop(
        PersistentRisk::initialise_for(
            &scoped.journal(),
            limits(),
            &testnet_a,
            at(0),
            dec!(2000),
            "test",
        )
        .unwrap(),
    );
    assert!(matches!(
        PersistentRisk::adopt_scope(&scoped.journal(), &limits(), &testnet_a, at(1), "test"),
        Err(JournalError::ScopeDiffers { .. })
    ));
}

#[test]
fn a_second_scope_record_or_one_that_changes_the_state_is_refused() {
    let dir = TestDir::new("scope-records");
    let scoped = || JournalEvent::Scoped {
        scope: scope("testnet", A),
        note: String::new(),
    };
    forge(
        &dir,
        &[
            (0, initialised(), fresh()),
            (1, scoped(), fresh()),
            (2, scoped(), fresh()),
        ],
    );
    assert!(inconsistent(PersistentRisk::open(&dir.journal(), &limits())).contains("already"));
    let mut changed = fresh();
    changed.peak = dec!(2500);
    changed.last = dec!(2500);
    forge(&dir, &[(0, initialised(), fresh()), (1, scoped(), changed)]);
    assert!(inconsistent(PersistentRisk::open(&dir.journal(), &limits())).contains("scope"));
}

/// A record's flow fields: the main dex's horizon at `venue_ms`, no view.
fn seen(venue_ms: i64) -> FlowFields {
    FlowFields {
        horizon: Some([(String::new(), venue_ms)].into()),
        view: None,
        budget: None,
    }
}

/// A view of 2,000 observed at `at_ms`, the main dex's account read at
/// `venue_ms` venue time.
fn view(at_ms: i64, venue_ms: i64) -> SeenView {
    SeenView {
        at: at(at_ms),
        times: [(String::new(), venue_ms)].into(),
        equity: dec!(2000),
    }
}

/// The message the reader refuses the forged journal with.
fn refused_by_reader(dir: &TestDir) -> String {
    inconsistent(PersistentRisk::open(&dir.journal(), &limits()))
}

#[test]
fn a_horizon_belongs_in_a_version_3_record_and_only_there() {
    let dir = TestDir::new("tamper-version");
    // `line` re-encoded from version `from` to `to`, checksum and all.
    let reencoded = |line: &str, from: u32, to: u32| {
        let body = format!(
            "{{{}",
            line.split_once("\",").unwrap().1.replace(
                &format!(r#""version":{from}"#),
                &format!(r#""version":{to}"#)
            )
        );
        let check = hex(&Sha3_256::digest(body.as_bytes()));
        format!("{CHECK_PREFIX}{check}\",{}", &body[1..])
    };
    // A record without a horizon claiming version 3.
    forge(
        &dir,
        &[
            (0, initialised(), fresh()),
            (HOUR, JournalEvent::Updated, fresh()),
        ],
    );
    let mut forged = lines(&dir);
    forged[1] = reencoded(&forged[1], RECORD_VERSION, JOURNAL_VERSION);
    write_lines(&dir, &forged);
    assert_eq!(
        refused_by_reader(&dir),
        "a horizon in a record of version 3 or later, and only there"
    );
    // A record with a horizon claiming version 2.
    forge_with(
        &dir,
        &[
            (0, initialised(), fresh(), FlowFields::default()),
            (HOUR, JournalEvent::Updated, fresh(), seen(HOUR)),
        ],
    );
    let mut forged = lines(&dir);
    forged[1] = reencoded(&forged[1], JOURNAL_VERSION, RECORD_VERSION);
    write_lines(&dir, &forged);
    assert_eq!(
        refused_by_reader(&dir),
        "a horizon in a record of version 3 or later, and only there"
    );
    // A view without a horizon (a version 2 record).
    forge_with(
        &dir,
        &[
            (0, initialised(), fresh(), FlowFields::default()),
            (
                HOUR,
                JournalEvent::Updated,
                fresh(),
                FlowFields {
                    horizon: None,
                    view: Some(view(HOUR, HOUR)),
                    budget: None,
                },
            ),
        ],
    );
    assert_eq!(
        refused_by_reader(&dir),
        "a flowed record or a view without a horizon"
    );
}

#[test]
fn a_flowed_record_lists_its_views_in_its_event_only() {
    let dir = TestDir::new("tamper-flowed-view");
    forge_with(
        &dir,
        &[
            (0, initialised(), fresh(), FlowFields::default()),
            (
                HOUR,
                JournalEvent::Flowed {
                    base: 1,
                    views: Vec::new(),
                    flows: Vec::new(),
                },
                fresh(),
                FlowFields {
                    view: Some(view(HOUR, HOUR)),
                    ..seen(HOUR)
                },
            ),
        ],
    );
    assert_eq!(
        refused_by_reader(&dir),
        "a flowed record lists its views in the event"
    );
}

#[test]
fn the_horizon_never_goes_back() {
    let dir = TestDir::new("tamper-horizon");
    // Earlier on the main dex.
    forge_with(
        &dir,
        &[
            (0, initialised(), fresh(), FlowFields::default()),
            (HOUR, JournalEvent::Updated, fresh(), seen(HOUR)),
            (2 * HOUR, JournalEvent::Updated, fresh(), seen(HOUR - 1)),
        ],
    );
    assert_eq!(refused_by_reader(&dir), "the horizon went back");
    // A dex left out.
    forge_with(
        &dir,
        &[
            (0, initialised(), fresh(), FlowFields::default()),
            (
                HOUR,
                JournalEvent::Updated,
                fresh(),
                FlowFields {
                    horizon: Some([(String::new(), HOUR), ("xyz".to_owned(), HOUR)].into()),
                    view: None,
                    budget: None,
                },
            ),
            (2 * HOUR, JournalEvent::Updated, fresh(), seen(2 * HOUR)),
        ],
    );
    assert_eq!(refused_by_reader(&dir), "the horizon went back");
    // The same horizon again is fine.
    forge_with(
        &dir,
        &[
            (0, initialised(), fresh(), FlowFields::default()),
            (HOUR, JournalEvent::Updated, fresh(), seen(HOUR)),
            (2 * HOUR, JournalEvent::Updated, fresh(), seen(HOUR)),
        ],
    );
    PersistentRisk::open(&dir.journal(), &limits()).unwrap();
}

#[test]
fn a_view_is_observed_with_its_record_and_within_its_horizon() {
    let dir = TestDir::new("tamper-view");
    // Observed a millisecond after the record's time.
    forge_with(
        &dir,
        &[
            (0, initialised(), fresh(), FlowFields::default()),
            (
                HOUR,
                JournalEvent::Updated,
                fresh(),
                FlowFields {
                    view: Some(view(HOUR + 1, HOUR)),
                    ..seen(HOUR)
                },
            ),
        ],
    );
    assert_eq!(
        refused_by_reader(&dir),
        "a view observed at another time than its record"
    );
    // Read before the venue time the record before had reached.
    forge_with(
        &dir,
        &[
            (0, initialised(), fresh(), FlowFields::default()),
            (HOUR, JournalEvent::Updated, fresh(), seen(HOUR)),
            (
                2 * HOUR,
                JournalEvent::Updated,
                fresh(),
                FlowFields {
                    view: Some(view(2 * HOUR, HOUR - 1)),
                    ..seen(2 * HOUR)
                },
            ),
        ],
    );
    assert_eq!(
        refused_by_reader(&dir),
        "a view that goes back in venue time"
    );
    // Read beyond the record's own horizon.
    forge_with(
        &dir,
        &[
            (0, initialised(), fresh(), FlowFields::default()),
            (
                HOUR,
                JournalEvent::Updated,
                fresh(),
                FlowFields {
                    view: Some(view(HOUR, HOUR + 1)),
                    ..seen(HOUR)
                },
            ),
        ],
    );
    assert_eq!(refused_by_reader(&dir), "a view beyond the horizon");
}

#[test]
fn a_flowed_records_views_are_in_order_and_never_go_back() {
    let dir = TestDir::new("tamper-flowed-views");
    // Record 2 reached 1:00 venue time; record 3 replays from it.
    let flowed = |views: Vec<SeenView>| {
        [
            (0, initialised(), fresh(), FlowFields::default()),
            (HOUR, JournalEvent::Updated, fresh(), seen(HOUR)),
            (
                3 * HOUR,
                JournalEvent::Flowed {
                    base: 2,
                    views,
                    flows: Vec::new(),
                },
                fresh(),
                seen(2 * HOUR),
            ),
        ]
    };
    // Observed at 2:00, then a millisecond before.
    forge_with(
        &dir,
        &flowed(vec![view(2 * HOUR, 2 * HOUR), view(2 * HOUR - 1, 2 * HOUR)]),
    );
    assert_eq!(refused_by_reader(&dir), "views out of order");
    // Read before the venue time its base had reached.
    forge_with(&dir, &flowed(vec![view(2 * HOUR, HOUR - 1)]));
    assert_eq!(
        refused_by_reader(&dir),
        "a view that goes back in venue time"
    );
}

#[test]
fn a_second_initialised_record_is_refused_by_writer_and_reader() {
    let dir = TestDir::new("tamper-initialised");
    let mut risk = journal_with(&dir, &[]);
    let before = fs::read(dir.journal()).unwrap();
    let refused = risk.commit(at(HOUR), initialised()).unwrap_err();
    assert!(
        matches!(&refused, JournalError::Inconsistent { message, .. }
            if message == "refusing to write: a second `initialised` record"),
        "{refused:?}"
    );
    assert_eq!(fs::read(dir.journal()).unwrap(), before);
    drop(risk);
    fs::remove_file(broken_marker(&dir.journal())).ok();
    // The reader refuses it before the step is checked.
    forge(
        &dir,
        &[(0, initialised(), fresh()), (HOUR, initialised(), fresh())],
    );
    assert_eq!(
        refused_by_reader(&dir),
        "only the first record may be `initialised`"
    );
}

#[test]
fn a_repair_record_never_changes_the_state() {
    let dir = TestDir::new("tamper-repair");
    let repaired = || JournalEvent::Repaired {
        cut_bytes: 51,
        note: String::new(),
    };
    let higher = RiskSnapshot {
        peak: dec!(2200),
        last: dec!(2200),
        ..fresh()
    };
    forge(
        &dir,
        &[(0, initialised(), fresh()), (HOUR, repaired(), higher)],
    );
    assert_eq!(refused_by_reader(&dir), "a repair changed the state");
    forge(
        &dir,
        &[(0, initialised(), fresh()), (HOUR, repaired(), fresh())],
    );
    PersistentRisk::open(&dir.journal(), &limits()).unwrap();
}

#[test]
fn a_flow_listed_again_must_be_the_flow_first_listed() {
    // An unknown withdrawal of the whole 2,000 at 1:00, pending; a view
    // of 0 at 2:00. Then a forged flowed record from the last record
    // lists the same flow id at 1,000 instead.
    let dir = TestDir::new("tamper-flow-changed");
    let mut risk = PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(2000), "test")
        .unwrap()
        .with_flows();
    let withdrawal = Flow {
        time_ms: HOUR,
        amount: dec!(-2000),
        id: "withdraw".into(),
        dex: String::new(),
        between: false,
        value: None,
        unaccounted: None,
    };
    risk.apply_flow(at(HOUR), &withdrawal).unwrap();
    let out = risk.observe_view_at(
        at(2 * HOUR),
        [(String::new(), 2 * HOUR)].into(),
        dec!(0),
        &VenueView::default(),
        true,
    );
    assert!(out.journal_error.is_none(), "{out:?}");
    drop(risk);
    let records = PersistentRisk::read(&dir.journal()).unwrap();
    assert!(
        records.iter().any(|record| matches!(&record.event,
            JournalEvent::Flowed { flows, .. } if flows.contains(&withdrawal))),
        "{records:?}"
    );
    let last = records.last().unwrap();
    let changed = Flow {
        amount: dec!(-1000),
        ..withdrawal
    };
    let (_, line) = JournalRecord::new(
        last.seq + 1,
        at(3 * HOUR),
        JournalEvent::Flowed {
            base: last.seq,
            views: Vec::new(),
            flows: vec![changed],
        },
        last.state.clone(),
        last.check.clone(),
        FlowFields {
            horizon: last.horizon.clone(),
            view: None,
            budget: None,
        },
    )
    .unwrap();
    let mut forged = fs::read(dir.journal()).unwrap();
    forged.extend_from_slice(line.as_bytes());
    fs::write(dir.journal(), forged).unwrap();
    let refused = PersistentRisk::read(&dir.journal()).unwrap_err();
    assert!(
        matches!(&refused, JournalError::Inconsistent { message, .. }
            if message == "the flow withdraw changed since it was listed"),
        "{refused:?}"
    );
}

/// `line` changed by `change` (on its JSON, the checksum left out) and
/// checksummed again: the last line of a journal, tampered with.
fn rechecked(line: &str, change: impl FnOnce(&mut serde_json::Value)) -> String {
    let mut record: serde_json::Value = serde_json::from_str(line).unwrap();
    record.as_object_mut().unwrap().remove("check");
    change(&mut record);
    let body = record.to_string();
    let check = hex(&Sha3_256::digest(body.as_bytes()));
    format!("{CHECK_PREFIX}{check}\",{}", &body[1..])
}

/// A base is never taken while a flow is pending: a replay starts watching
/// from a base's horizon, which then is the last view the engine took (a
/// view is left out only beside a flow not applied yet).
#[test]
fn no_base_is_taken_while_a_flow_is_pending() {
    let dir = TestDir::new("no-base-pending");
    let mut risk = PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(10000), "test")
        .unwrap()
        .with_flows();
    risk.observe_view_at(
        at(HOUR),
        [(String::new(), HOUR)].into(),
        dec!(10000),
        &VenueView::default(),
        true,
    );
    let entry = Flow {
        time_ms: HOUR + 20_000,
        amount: Decimal::ZERO,
        id: format!("{}0xabc:liquidator", flows::UNKNOWN_TYPE_ID_PREFIX),
        dex: String::new(),
        between: true,
        value: None,
        unaccounted: Some(UnaccountedEntry {
            watched_gap_ms: 31_000,
            rule: UnaccountedRule::Rebasable,
            credit: Decimal::ZERO,
        }),
    };
    assert_eq!(
        risk.apply_flow(at(HOUR + 19_000), &entry).unwrap(),
        FlowOutcome::Pending
    );
    let bases = |risk: &PersistentRisk| {
        risk.flows
            .as_ref()
            .unwrap()
            .bases
            .iter()
            .map(|base| base.seq)
            .collect::<Vec<_>>()
    };
    let before = bases(&risk);
    // A view at 1 h + 19 s may or may not show it: left out, written, and
    // no base.
    let out = risk.observe_view_at(
        at(HOUR + 19_000),
        [(String::new(), HOUR + 19_000)].into(),
        dec!(10100),
        &VenueView::default(),
        true,
    );
    assert!(!out.taken);
    assert_eq!(bases(&risk), before);
    // The view that shows it, 30 s after the last view taken (1 h; the
    // left-out view does not count): watched, the 100 is the entry's (1%,
    // within the room): P = D = 10,100, active.
    let out = risk.observe_view_at(
        at(HOUR + 30_000),
        [(String::new(), HOUR + 30_000)].into(),
        dec!(10100),
        &VenueView::default(),
        true,
    );
    assert!(out.taken);
    let snapshot = risk.engine.snapshot();
    assert_eq!(
        (snapshot.state, snapshot.peak, snapshot.day_start),
        (RiskState::Active, dec!(10100), dec!(10100))
    );
}

/// Every line of a journal re-encoded from version `from` to `to`, the
/// checksums and the chain redone: a journal as an older build wrote it.
fn as_version(lines: &[String], from: u32, to: u32) -> Vec<String> {
    let mut out = Vec::new();
    let (mut old_prev, mut new_prev) = (String::new(), String::new());
    for line in lines {
        let old_check = line
            .strip_prefix(CHECK_PREFIX)
            .and_then(|rest| rest.split_once('"'))
            .map(|(check, _)| check.to_owned())
            .unwrap();
        let mut body = format!("{{{}", line.split_once("\",").unwrap().1).replace(
            &format!(r#""version":{from}"#),
            &format!(r#""version":{to}"#),
        );
        if !old_prev.is_empty() {
            body = body.replace(
                &format!(r#""prev":"{old_prev}""#),
                &format!(r#""prev":"{new_prev}""#),
            );
        }
        let check = hex(&Sha3_256::digest(body.as_bytes()));
        out.push(format!("{CHECK_PREFIX}{check}\",{}", &body[1..]));
        old_prev = old_check;
        new_prev = check;
    }
    out
}

/// An engine that takes flows, 10,000 at 1 h; an entry the caller cannot
/// account for at 1 h + 5 s, watched through 31 s, shown by the view at
/// 1 h + 10 s at 10,500: the 500 (a loss of it would be 5%, under the 6%
/// daily stop) is its money (P = D = 10,500, active). The journal holds it
/// as version 4 and reopens intact, with the same figures; the same records
/// claiming version 3 are refused (an older build would replay the entry as
/// another flow); a malformed entry is never journaled; one written as
/// version 3 (an older build's, before any such entry) opens in this build.
#[test]
fn a_journal_with_an_unknown_entry_reopens_and_version_3_still_opens() {
    let dir = TestDir::new("unknown-entry");
    let mut risk = PersistentRisk::initialise(&dir.journal(), limits(), at(0), dec!(10000), "test")
        .unwrap()
        .with_flows();
    risk.observe_view_at(
        at(HOUR),
        [(String::new(), HOUR)].into(),
        dec!(10000),
        &VenueView::default(),
        true,
    );
    // A version 3 copy of the journal so far (no unknown entry in it).
    let older = as_version(&lines(&dir), JOURNAL_VERSION, 3);
    let entry = Flow {
        time_ms: HOUR + 5_000,
        amount: Decimal::ZERO,
        id: format!(
            "{}0xabc:{}:welcomeBonus",
            flows::UNKNOWN_TYPE_ID_PREFIX,
            HOUR + 5_000
        ),
        dex: String::new(),
        between: true,
        value: None,
        unaccounted: Some(UnaccountedEntry {
            watched_gap_ms: 31_000,
            rule: UnaccountedRule::Rebasable,
            credit: Decimal::ZERO,
        }),
    };
    assert_eq!(
        risk.apply_flow(at(HOUR + 5_000), &entry).unwrap(),
        FlowOutcome::Pending
    );
    let out = risk.observe_view_at(
        at(HOUR + 10_000),
        [(String::new(), HOUR + 10_000)].into(),
        dec!(10500),
        &VenueView::default(),
        true,
    );
    assert!(out.journal_error.is_none());
    let state = risk.engine.snapshot();
    assert_eq!(
        (state.state, state.peak, state.day_start),
        (RiskState::Active, dec!(10500), dec!(10500))
    );
    assert!(risk.check_ready().is_ok());
    assert!(
        lines(&dir)
            .iter()
            .any(|line| line.contains(&format!(r#""version":{JOURNAL_VERSION}"#)))
    );
    // The day's re-base budget: the room at the entry, 600 (6% of 10,000),
    // 500 used, as shares of the day's start; on the journal's last record.
    let budget = Some(RebaseBudget {
        day: 0,
        room: dec!(0.06),
        used: dec!(0.05),
    });
    assert_eq!(risk.journal.last.budget, budget);
    assert_eq!(
        risk.unaccounted_entries()
            .iter()
            .map(|(flow, at)| (flow.id.clone(), *at))
            .collect::<Vec<_>>(),
        vec![(entry.id.clone(), at(HOUR + 5_000))]
    );
    drop(risk);
    let mut reopened = PersistentRisk::open(&dir.journal(), &limits())
        .unwrap()
        .with_flows();
    // Intact (not broken); ready once a view is observed, nothing pending.
    assert_eq!(reopened.check_ready(), Err(JournalError::NotObserved));
    reopened.observe_view_at(
        at(HOUR + 20_000),
        [(String::new(), HOUR + 20_000)].into(),
        dec!(10500),
        &VenueView::default(),
        true,
    );
    assert!(reopened.check_ready().is_ok());
    let again = reopened.engine.snapshot();
    assert_eq!(
        (again.state, again.peak, again.day_start),
        (RiskState::Active, dec!(10500), dec!(10500))
    );
    // The budget and the entry, read back (a restarted Guard refuses
    // entries for the day from them).
    assert_eq!(reopened.journal.last.budget, budget);
    assert_eq!(reopened.flows.as_ref().unwrap().budget, budget);
    assert_eq!(reopened.unaccounted_entries().len(), 1);
    // An entry without its watched gap: skipped, nothing written.
    let before = lines(&dir).len();
    let malformed = Flow {
        id: format!(
            "{}0xdef:{}:welcomeBonus",
            flows::UNKNOWN_TYPE_ID_PREFIX,
            HOUR + 25_000
        ),
        time_ms: HOUR + 25_000,
        unaccounted: None,
        ..entry
    };
    let outcome = reopened.apply_flow(at(HOUR + 25_000), &malformed).unwrap();
    assert!(
        matches!(&outcome, FlowOutcome::Skipped(why) if why.contains("no watched gap")),
        "{outcome:?}"
    );
    assert_eq!(lines(&dir).len(), before);
    assert!(!reopened.knows_flow(&malformed.id));
    drop(reopened);
    // A budget changed on the last record: refused.
    let current = lines(&dir);
    let mut tampered = current.clone();
    let last = tampered.pop().unwrap();
    tampered.push(rechecked(&last, |record| {
        record["budget"]["used"] = serde_json::json!("1");
    }));
    write_lines(&dir, &tampered);
    let refused = refused_by_reader(&dir);
    assert!(refused.contains("budget"), "{refused}");
    // The same records claiming version 3: refused.
    write_lines(&dir, &as_version(&current, JOURNAL_VERSION, 3));
    let refused = refused_by_reader(&dir);
    assert!(
        refused.contains("lists a flow for a ledger entry the caller cannot account for"),
        "{refused}"
    );
    write_lines(&dir, &older);
    let opened = PersistentRisk::open(&dir.journal(), &limits())
        .unwrap()
        .with_flows();
    assert_eq!(opened.check_ready(), Err(JournalError::NotObserved));
    assert_eq!(opened.engine.snapshot().last, dec!(10000));
}
