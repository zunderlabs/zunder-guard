// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The decision journal's write-ahead rule and recovery, end to end
//! (`docs/guard.md#journals`): an intent naming each action is on disk
//! before the venue receives it (J1), and after a crash Guard asks the
//! venue what became of the actions nothing answered (J3).

#![allow(clippy::unwrap_used)]

mod support;

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use rust_decimal::dec;
use serde_json::{Value, json};
use support::{MORE_COINS, MemoryVenue};
use zunder_core::Timestamp;
use zunder_guard::{
    config::{GuardConfig, GuardMode, GuardNetwork},
    guard::{Clock, Guard, INTENT_COVERS_MS, Limits, Mode, Setup, SystemClock},
    journal::{DecisionJournal, Gate},
    recover::intent_actions,
    testdir::TestDir,
};
use zunder_guard_core::{
    auth::AuthConfig,
    event::EventBody,
    licence::FeeMode,
    sign::{Address, GuardKey, SigningNetwork},
    wire::{Wire, minimal_hex},
};
use zunder_venue::PersistentRisk;

const CLIENT_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
/// A second bot.
const OTHER_KEY: &str = "0x0223456789012345678901234567890123456789012345678901234567890123";
const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

fn api_key() -> GuardKey {
    GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap()
}

fn config(dir: &Path) -> GuardConfig {
    GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: GuardMode::Testnet,
        account: Some(ACCOUNT.to_owned()),
        api_wallet: Some(api_key().address().to_hex()),
        state_dir: dir.to_owned(),
        auth: AuthConfig {
            clients: [CLIENT_KEY, OTHER_KEY]
                .iter()
                .map(|key| GuardKey::from_hex(key).unwrap().address().to_hex())
                .collect(),
            ..AuthConfig::default()
        },
        ..GuardConfig::default()
    }
}

/// Guard's clock, moved by hand.
#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl TestClock {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(SystemClock.now_ms())))
    }

    fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

/// A sending Guard over `venue` in `dir`; `first` starts its risk
/// journal, otherwise it opens the one there (a restart). Waits past the
/// nonce floor.
async fn start(dir: &Path, venue: MemoryVenue, first: bool) -> Arc<Guard<MemoryVenue>> {
    let guard = start_with(dir, venue, first, SystemClock).await;
    tokio::time::sleep(Duration::from_millis(5_100)).await;
    guard
}

/// [`start`] on `clock`, synced once, without waiting.
async fn start_with<C: Clock + Clone>(
    dir: &Path,
    venue: MemoryVenue,
    first: bool,
    clock: C,
) -> Arc<Guard<MemoryVenue, C>> {
    let config = config(dir);
    let limits = config.policy.risk_limits();
    let scope = config.journal_scope(false).unwrap();
    let risk = if first {
        PersistentRisk::initialise_for(
            &config.risk_journal(false),
            limits,
            &scope,
            Timestamp::from_millis(clock.now_ms() as i64),
            dec!(10000),
            "journal test",
        )
        .unwrap()
    } else {
        PersistentRisk::open_for(&config.risk_journal(false), &limits, &scope).unwrap()
    };
    let journal = DecisionJournal::open(&config.decision_journal(false)).unwrap();
    let guard = Guard::new(
        Setup {
            config,
            mode: Mode::Send {
                key: api_key(),
                network: SigningNetwork::Testnet,
            },
            risk,
            journal,
            fee: FeeMode::Off("test".into()),
            fee_warning: None,
            limits: Limits {
                request_weight_per_second: 1_000_000,
                request_weight_burst: 1_000_000,
            },
        },
        venue,
        clock,
    )
    .unwrap();
    guard.sync().await;
    guard
}

fn venue() -> MemoryVenue {
    MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "10000",
    )
}

fn signed(action: Wire) -> Value {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = SystemClock
        .now_ms()
        .max(LAST.fetch_add(1, Ordering::SeqCst) + 1);
    LAST.store(nonce, Ordering::SeqCst);
    signed_by(CLIENT_KEY, action, nonce)
}

fn signed_by(key: &str, action: Wire, nonce: u64) -> Value {
    let signature = GuardKey::from_hex(key)
        .unwrap()
        .sign_l1_action(SigningNetwork::Testnet, &action, nonce, None)
        .unwrap();
    json!({
        "action": action.to_value(),
        "nonce": nonce,
        "signature": {"r": minimal_hex(&signature.r), "s": minimal_hex(&signature.s), "v": signature.v},
    })
}

/// An IOC buy of ETH (asset 1) without a client id.
fn buy(price: &str, size: &str) -> Value {
    signed(buy_wire(1, price, size))
}

fn buy_wire(asset: u64, price: &str, size: &str) -> Wire {
    order_wire(asset, price, size, "Ioc")
}

fn order_wire(asset: u64, price: &str, size: &str, tif: &str) -> Wire {
    Wire::Map(vec![
        ("type", Wire::str("order")),
        (
            "orders",
            Wire::Array(vec![Wire::Map(vec![
                ("a", Wire::UInt(asset)),
                ("b", Wire::Bool(true)),
                ("p", Wire::str(price)),
                ("s", Wire::str(size)),
                ("r", Wire::Bool(false)),
                (
                    "t",
                    Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str(tif))]))]),
                ),
            ])]),
        ),
        ("grouping", Wire::str("na")),
    ])
}

/// Every record's event in the journal file's first `synced` bytes (what
/// a sync made durable), up to the first line that is no record.
fn on_disk(path: &Path, synced: u64) -> Vec<Value> {
    let mut bytes = std::fs::read(path).unwrap_or_default();
    bytes.truncate(usize::try_from(synced).unwrap());
    bytes
        .split(|byte| *byte == b'\n')
        .map_while(|line| serde_json::from_slice::<Value>(line).ok())
        .filter_map(|record| record.get("event").cloned())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_intent_naming_each_action_is_on_disk_before_the_venue_gets_it() {
    let dir = TestDir::new("journal-j1");
    let path = config(dir.path()).decision_journal(false);
    let venue = venue();
    let checked = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(std::sync::Mutex::new(Vec::new()));
    let synced: Arc<std::sync::Mutex<Option<Arc<std::sync::atomic::AtomicU64>>>> =
        Arc::new(std::sync::Mutex::new(None));
    {
        let (path, checked, failures, synced) = (
            path.clone(),
            checked.clone(),
            failures.clone(),
            synced.clone(),
        );
        venue.before_send(move |action| {
            let durable = synced
                .lock()
                .unwrap()
                .as_ref()
                .map_or(u64::MAX, |synced| synced.load(Ordering::SeqCst));
            let named = on_disk(&path, durable)
                .iter()
                .filter_map(intent_actions)
                .any(|actions| actions.contains(action));
            checked.fetch_add(1, Ordering::SeqCst);
            if !named {
                failures.lock().unwrap().push(action.clone());
            }
        });
    }
    let guard = start(dir.path(), venue, true).await;
    *synced.lock().unwrap() = Some(guard.journal_synced_for_test().await);
    // An entry (isolated leverage set first, the order with Guard's stop).
    let reply = guard.exchange(buy("3000", "0.1"), "http").await;
    assert_eq!(reply["status"], "ok", "{reply}");
    // Its client id, given by Guard, is not in the bot's reply.
    assert!(
        reply.to_string().contains("filled") && !reply.to_string().contains("cloid"),
        "{reply}"
    );
    // An entry whose stop the venue refuses: Guard closes it (an action no
    // earlier intent named: its own intent first).
    guard.upstream().refuse_stops();
    let before = checked.load(Ordering::SeqCst);
    let reply = guard.exchange(buy("3000", "0.05"), "http").await;
    assert_eq!(reply["status"], "ok", "{reply}");
    // The entry and Guard's close of it.
    assert!(checked.load(Ordering::SeqCst) >= before + 2);
    // The kill switch: Guard flattens (a close, cancels).
    std::fs::write(config(dir.path()).kill_file(), "test").unwrap();
    guard.sync().await;
    assert!(
        !guard
            .upstream()
            .positions()
            .iter()
            .any(|p| p["position"]["coin"] == "ETH")
    );
    assert!(
        checked.load(Ordering::SeqCst) >= 3,
        "{}",
        checked.load(Ordering::SeqCst)
    );
    assert!(
        failures.lock().unwrap().is_empty(),
        "{:?}",
        failures.lock().unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn after_a_crash_guard_asks_the_venue_what_became_of_unanswered_actions() {
    let dir = TestDir::new("journal-j3");
    let path = config(dir.path()).decision_journal(false);
    let guard = start(dir.path(), venue(), true).await;
    // The venue takes the entry but its answer is lost: in doubt.
    guard.upstream().swallow_answers(true);
    let reply = guard.exchange(buy("3000", "0.1"), "http").await;
    assert_ne!(reply["status"], "ok", "{reply}");
    let venue = guard.upstream().fork();
    venue.swallow_answers(false);
    drop(guard);
    // And an intent that was on disk when the process died, its order
    // never sent (a client id the venue never saw).
    let mut journal = DecisionJournal::open(&path).unwrap();
    let never = json!({"type": "order", "orders": [{"a": 1, "b": true, "p": "3000", "s": "0.1",
        "r": false, "t": {"limit": {"tif": "Ioc"}}, "c": "0x7a680000000000000000000000000001"}],
        "grouping": "na"});
    journal
        .append(
            SystemClock.now_ms() as i64,
            EventBody::Started {
                schema: 1,
                version: "test".into(),
                mode: "testnet".into(),
                account: ACCOUNT.into(),
                rules: String::new(),
                clients: Vec::new(),
            },
        )
        .unwrap();
    journal
        .append(
            SystemClock.now_ms() as i64,
            EventBody::Intent {
                of: 0,
                action: never.clone(),
            },
        )
        .unwrap();
    drop(journal);
    let guard = start(dir.path(), venue, false).await;
    let pending = guard.pending_for_recovery().await;
    assert_eq!(guard.recover_after(pending, 0, 90_000).await, 2);
    let recovered: Vec<Value> = guard
        .events(0)
        .await
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "recovered")
        .cloned()
        .collect();
    let outcome_of = |pred: &dyn Fn(&Value) -> bool| {
        recovered
            .iter()
            .find(|event| pred(&event["action"]))
            .map(|event| event["outcome"].as_str().unwrap().to_owned())
    };
    assert_eq!(
        outcome_of(&|action| *action == never).as_deref(),
        Some("did_not_happen"),
        "{recovered:?}"
    );
    assert_eq!(
        outcome_of(&|action| action["orders"][0]["c"]
            .as_str()
            .is_some_and(|cloid| cloid.starts_with("0x7a68"))
            && *action != never)
        .as_deref(),
        Some("happened"),
        "{recovered:?}"
    );
    // Concluded once: a second recovery finds nothing.
    let pending = guard.pending_for_recovery().await;
    assert_eq!(guard.recover_after(pending, 0, 90_000).await, 0);
    let _: PathBuf = path;
}

/// E1: while the decision journal cannot be written,
/// no new position is opened, but Guard still flattens and protects, each
/// action recorded in the emergency log first, with an alert.
#[tokio::test(flavor = "multi_thread")]
async fn with_the_journal_broken_guard_refuses_entries_and_still_flattens() {
    let dir = TestDir::new("journal-e1");
    let config = config(dir.path());
    let guard = start(dir.path(), venue(), true).await;
    let reply = guard.exchange(buy("3000", "0.1"), "http").await;
    assert_eq!(reply["status"], "ok", "{reply}");
    guard.break_journal_for_test().await;
    let reply = guard.exchange(buy("3000", "0.1"), "http").await;
    assert!(reply.to_string().contains("journal"), "{reply}");
    std::fs::write(config.kill_file(), "test").unwrap();
    guard.sync().await;
    assert!(
        !guard
            .upstream()
            .positions()
            .iter()
            .any(|position| position["position"]["coin"] == "ETH"),
        "flattened"
    );
    // The intents written before the sends; the outcomes after, not
    // waited for.
    let mut log = String::new();
    for _ in 0..200 {
        log = std::fs::read_to_string(config.emergency_log(false)).unwrap();
        if log.contains("\"kind\":\"sent\"") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        log.contains("\"kind\":\"intent\"") && log.contains("\"kind\":\"sent\""),
        "{log}"
    );
    let status = guard.status().await;
    assert!(status.to_string().contains("emergency log"), "{status}");
}

/// Recovery waits until an action has expired before asking the venue (an
/// action not yet expired may still arrive), and refuses bots' requests
/// meanwhile.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_waits_for_expiry() {
    let dir = TestDir::new("journal-j3-wait");
    let clock = TestClock::new();
    let guard = start_with(dir.path(), venue(), true, clock.clone()).await;
    clock.advance(5_100);
    guard.upstream().swallow_answers(true);
    let request = signed_by(CLIENT_KEY, buy_wire(1, "3000", "0.1"), clock.now_ms());
    let reply = guard.exchange(request, "http").await;
    assert_ne!(reply["status"], "ok", "{reply}");
    let venue = guard.upstream().fork();
    venue.swallow_answers(false);
    drop(guard);
    let guard = start_with(dir.path(), venue, false, clock.clone()).await;
    let pending = guard.pending_for_recovery().await;
    assert_eq!(pending.len(), 1);
    // Poll at the exact boundary on Guard's clock; venue/setup delays
    // cannot consume the wait being tested.
    let expires = u64::try_from(pending[0].at_ms + 8_000).unwrap();
    clock.0.store(expires - 1, Ordering::SeqCst);
    let reads_before = guard.upstream().info_log().len();
    let mut recovering = std::pin::pin!(guard.recover_after(pending, 8_000, 90_000));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(recovering.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert!(guard.recovering());
    let request = signed_by(CLIENT_KEY, buy_wire(1, "3000", "0.01"), clock.now_ms());
    let reply = guard.exchange(request, "http").await;
    assert!(reply.to_string().contains("restart"), "{reply}");
    assert_eq!(guard.upstream().info_log().len(), reads_before);
    clock.advance(1);
    let concluded = tokio::time::timeout(Duration::from_secs(10), recovering.as_mut())
        .await
        .expect("recovery concludes after the controlled expiry");
    assert_eq!(concluded, 1);
    assert!(!guard.recovering());
    let reads = guard.upstream().info_log();
    assert_eq!(reads[reads_before..].len(), 1);
    assert_eq!(reads[reads_before]["type"], "orderStatus");
    let recovered: Vec<Value> = guard
        .events(0)
        .await
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "recovered")
        .cloned()
        .collect();
    assert_eq!(recovered[0]["outcome"], "happened", "{recovered:?}");
}

/// E1 for protection: with the journal broken, a position without a stop
/// gets Guard's stop all the same, recorded in the emergency log first.
#[tokio::test(flavor = "multi_thread")]
async fn with_the_journal_broken_guard_still_places_protective_stops() {
    let dir = TestDir::new("journal-e1-protect");
    let config = config(dir.path());
    let guard = start(dir.path(), venue(), true).await;
    guard.break_journal_for_test().await;
    // A position opened elsewhere, without a stop.
    guard.upstream().add_position("ETH", "0.5");
    let before = guard.upstream().received().len();
    guard.sync().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    guard.sync().await;
    let sent: Vec<Value> = guard.upstream().received()[before..]
        .iter()
        .map(|received| received.json.clone())
        .collect();
    assert!(
        sent.iter()
            .any(|action| action.to_string().contains("\"trigger\"")),
        "{sent:?}"
    );
    let log = std::fs::read_to_string(config.emergency_log(false)).unwrap();
    assert!(
        log.contains("\"kind\":\"intent\"") && log.contains("trigger"),
        "{log}"
    );
}

/// An order the venue's info does not know yet on the first read is read
/// once more before recovery concludes it never happened.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_reads_an_unknown_order_twice() {
    let dir = TestDir::new("journal-j3-twice");
    let guard = start(dir.path(), venue(), true).await;
    guard.upstream().swallow_answers(true);
    guard.exchange(buy("3000", "0.1"), "http").await;
    let venue = guard.upstream().fork();
    venue.swallow_answers(false);
    venue.lag_order_status(1);
    drop(guard);
    let guard = start(dir.path(), venue, false).await;
    let pending = guard.pending_for_recovery().await;
    assert_eq!(guard.recover_after(pending, 0, 90_000).await, 1);
    let recovered: Vec<Value> = guard
        .events(0)
        .await
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "recovered")
        .cloned()
        .collect();
    assert_eq!(recovered[0]["outcome"], "happened", "{recovered:?}");
}

/// Regression case: with too little
/// of the bound left for the second read, one read of `unknownOid` (the
/// venue's info trailing) is no proof: `unknown`, never `did_not_happen`
/// for an order that filled.
#[tokio::test(flavor = "multi_thread")]
async fn without_time_for_the_second_read_an_unknown_order_stays_unknown() {
    let dir = TestDir::new("journal-j3-short");
    let guard = start(dir.path(), venue(), true).await;
    guard.upstream().swallow_answers(true);
    guard.exchange(buy("3000", "0.1"), "http").await;
    let venue = guard.upstream().fork();
    venue.swallow_answers(false);
    venue.lag_order_status(1);
    drop(guard);
    let guard = start(dir.path(), venue, false).await;
    let pending = guard.pending_for_recovery().await;
    assert_eq!(guard.recover_after(pending, 0, 1_500).await, 1);
    let recovered = recovered(&guard).await;
    assert_eq!(recovered[0]["outcome"], "unknown", "{recovered:?}");
    assert_eq!(
        recovered[0]["evidence"]["first_read"]["order_status"][0]["status"], "unknownOid",
        "{recovered:?}"
    );
}

async fn recovered<C: Clock>(guard: &Guard<MemoryVenue, C>) -> Vec<Value> {
    guard
        .events(0)
        .await
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "recovered")
        .cloned()
        .collect()
}

/// Intents on disk naming an order each (client ids the venue never saw),
/// as a crash leaves them; their `at_ms` now.
fn crashed_with(path: &Path, orders: u64) {
    let mut journal = DecisionJournal::open(path).unwrap();
    for i in 0..orders {
        let action = json!({"type": "order", "orders": [{"a": 1, "b": true, "p": "3000",
            "s": "0.1", "r": false, "t": {"limit": {"tif": "Ioc"}},
            "c": format!("0x7a68{:028x}", 1_000 + i)}], "grouping": "na"});
        journal
            .append(
                SystemClock.now_ms() as i64,
                EventBody::Intent { of: 0, action },
            )
            .unwrap();
    }
}

/// Regression case: the bound holds against a slow venue
/// (each `orderStatus` taking 2 s) and against actions that expire after
/// it: recovery ends within it, what it could not read `unknown`.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_ends_within_its_bound_on_a_slow_venue() {
    let dir = TestDir::new("journal-j3-slow");
    let path = config(dir.path()).decision_journal(false);
    let guard = start(dir.path(), venue(), true).await;
    let venue = guard.upstream().fork();
    drop(guard);
    crashed_with(&path, 5);
    venue.slow_order_status(2_000);
    let guard = start(dir.path(), venue, false).await;
    let pending = guard.pending_for_recovery().await;
    assert_eq!(pending.len(), 5);
    // Expiry 60 s away: the bound (2.5 s) comes first.
    let started = std::time::Instant::now();
    assert_eq!(guard.recover_after(pending, 60_000, 2_500).await, 5);
    let took = started.elapsed();
    assert!(took < Duration::from_millis(3_500), "{took:?}");
    let outcomes = recovered(&guard).await;
    assert_eq!(outcomes.len(), 5);
    assert!(
        outcomes.iter().all(|event| event["outcome"] == "unknown"),
        "{outcomes:?}"
    );
    // Expired at once, but each read 2 s: the first answered in time but
    // too late to read again, the second cut at the bound, the rest not
    // read.
    let dir = TestDir::new("journal-j3-slow2");
    let path = config(dir.path()).decision_journal(false);
    let guard = start(dir.path(), venue_with_slow_status(2_000), true).await;
    let venue = guard.upstream().fork();
    drop(guard);
    crashed_with(&path, 5);
    let guard = start(dir.path(), venue, false).await;
    let pending = guard.pending_for_recovery().await;
    let started = std::time::Instant::now();
    assert_eq!(guard.recover_after(pending, 0, 2_500).await, 5);
    let took = started.elapsed();
    assert!(took < Duration::from_millis(3_500), "{took:?}");
    assert!(
        recovered(&guard)
            .await
            .iter()
            .all(|event| event["outcome"] == "unknown")
    );
}

fn venue_with_slow_status(ms: u64) -> MemoryVenue {
    let venue = venue();
    venue.slow_order_status(ms);
    venue
}

/// Ten positions without a stop, one a coin.
fn unprotected(venue: &MemoryVenue) {
    venue.add_position_at("BTC", "0.01", "60000");
    venue.add_position_at("ETH", "0.1", "3000");
    venue.add_position_at("SOL", "1", "150");
    for coin in MORE_COINS {
        venue.add_position_at(coin, "5", "100");
    }
}

/// A Guard over ten unprotected positions whose venue takes 4 s of Guard's
/// clock for each send; the arrival time of each send on that clock.
async fn slow_round(
    dir: &Path,
) -> (
    Arc<Guard<MemoryVenue, TestClock>>,
    TestClock,
    Arc<Mutex<Vec<u64>>>,
) {
    let clock = TestClock::new();
    let venue = venue();
    venue.add_coins();
    let guard = start_with(dir, venue, true, clock.clone()).await;
    let arrivals = Arc::new(Mutex::new(Vec::new()));
    {
        let (clock, arrivals) = (clock.clone(), arrivals.clone());
        guard.upstream().before_send(move |_| {
            arrivals.lock().unwrap().push(clock.now_ms());
            clock.advance(4_000);
        });
    }
    (guard, clock, arrivals)
}

/// Sync until a stop is on every one of the ten positions (each round
/// 31 s after the last, so protection is due), within 20 s.
async fn protect_all(guard: &Guard<MemoryVenue, TestClock>, clock: &TestClock, from: usize) {
    tokio::time::timeout(Duration::from_secs(20), async {
        for _ in 0..3 {
            clock.advance(31_000);
            guard.sync().await;
            let stops = guard.upstream().received()[from..]
                .iter()
                .filter(|received| received.json.to_string().contains("\"trigger\""))
                .count();
            if stops >= 10 {
                return;
            }
        }
        panic!("not every position got its stop");
    })
    .await
    .expect("protection is never held up for long");
}

/// Regression case: the journal broken and the emergency
/// log's disk hung. Protection waits for the emergency log once (2 s),
/// then marks it stalled and goes on without waiting; every stop is sent
/// with an expiry of its own, never already expired (the venue taking 4 s
/// of Guard's clock for each); one write was begun, so no blocking thread
/// piles up.
#[tokio::test(flavor = "multi_thread")]
async fn on_a_hung_emergency_disk_every_stop_goes_out_unexpired() {
    let dir = TestDir::new("journal-e1-hung");
    let (guard, clock, arrivals) = slow_round(dir.path()).await;
    guard.break_journal_for_test().await;
    let gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
    let attempts = guard.hold_emergency_log_for_test(gate.clone()).await;
    let _open = OpenOnDrop(gate.clone());
    unprotected(guard.upstream());
    let from = guard.upstream().received().len();
    let first = arrivals.lock().unwrap().len();
    let started = std::time::Instant::now();
    protect_all(&guard, &clock, from).await;
    let took = started.elapsed();
    assert!(took < Duration::from_secs(6), "{took:?}");
    let received = guard.upstream().received()[from..].to_vec();
    let arrivals = arrivals.lock().unwrap()[first..].to_vec();
    assert_eq!(received.len(), arrivals.len());
    for (sent, at) in received.iter().zip(&arrivals) {
        let expires = sent.expires_after.unwrap();
        assert!(
            expires > *at,
            "expired on arrival: {expires} <= {at}: {}",
            sent.json
        );
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let status = guard.status().await;
    assert_eq!(status["emergency_log_stalled"], true, "{status}");
    assert!(status.to_string().contains("emergency log"), "{status}");
    // The disk back: the write finishes, and the log is no longer stalled.
    open_gate(&gate);
    tokio::time::timeout(Duration::from_secs(5), async {
        while guard.status().await["emergency_log_stalled"] == true {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

/// J1 with the round's sends late (the venue taking 4 s of Guard's clock
/// for each): an action goes out named by an intent written no more than
/// [`INTENT_COVERS_MS`] before it expires, the late ones by intents of
/// their own, so that recovery, which waits that long after an intent,
/// never asks the venue about an action that may still arrive.
#[tokio::test(flavor = "multi_thread")]
async fn a_slow_round_gives_its_late_sends_intents_of_their_own() {
    let dir = TestDir::new("journal-j1-slow");
    let (guard, clock, _arrivals) = slow_round(dir.path()).await;
    unprotected(guard.upstream());
    let from = guard.upstream().received().len();
    protect_all(&guard, &clock, from).await;
    let events = guard.events(0).await.as_array().unwrap().clone();
    let received = guard.upstream().received()[from..].to_vec();
    assert!(received.len() >= 10);
    for sent in &received {
        let expires = sent.expires_after.unwrap();
        let covered = events.iter().any(|event| {
            intent_actions(event).is_some_and(|actions| actions.contains(&sent.json))
                && event["at_ms"].as_u64().unwrap() + INTENT_COVERS_MS >= expires
        });
        assert!(
            covered,
            "no intent covers {} (expires {expires})",
            sent.json
        );
    }
    assert!(
        events.iter().any(|event| event["kind"] == "intent"),
        "the late sends have intents of their own"
    );
}

fn open_gate(gate: &Gate) {
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
}

/// Opens the gate when dropped: the hung write ends, and the test's
/// runtime with it.
struct OpenOnDrop(Gate);

impl Drop for OpenOnDrop {
    fn drop(&mut self) {
        open_gate(&self.0);
    }
}

/// Vetoes are journaled 600 a minute for each client: a bot looping on
/// refused orders does not leave another's vetoes unjournaled, and the
/// count of those left out is journaled the next minute. A decision is
/// found from memory before the journal's writer has written it.
#[tokio::test(flavor = "multi_thread")]
async fn vetoes_are_journaled_600_a_minute_for_each_client() {
    let dir = TestDir::new("journal-vetoes");
    let path = config(dir.path()).decision_journal(false);
    let clock = TestClock::new();
    let guard = start_with(dir.path(), venue(), true, clock.clone()).await;
    // Past the nonce floor; well inside a minute.
    let minute = clock.now_ms() / 60_000;
    clock
        .0
        .store((minute + 1) * 60_000 + 6_000, Ordering::SeqCst);
    // An order on a HIP-3 dex the rules do not name: vetoed. Nonces from
    // Guard's clock, each above the last.
    let mut nonce = 0;
    let now = clock.clone();
    let mut veto = |key: &str| {
        nonce = (nonce + 1).max(now.now_ms());
        (nonce, signed_by(key, buy_wire(120_000, "10", "1"), nonce))
    };
    let client = |key: &str| GuardKey::from_hex(key).unwrap().address().to_hex();
    // Held: nothing is written, and the decision is still found.
    let held = guard.hold_journal_writer_for_test().await;
    let (first, request) = veto(CLIENT_KEY);
    let reply = guard.exchange(request, "http").await;
    assert_eq!(reply["code"], "dex_not_allowed", "{reply}");
    let found = guard.decision(first, Some(&client(CLIENT_KEY))).await;
    assert_eq!(
        found
            .as_ref()
            .map(|found| found["decision"]["code"].clone()),
        Some(json!("dex_not_allowed")),
        "{found:?}"
    );
    assert!(
        !std::fs::read_to_string(&path)
            .unwrap()
            .contains(&format!("\"nonce\":{first}"))
    );
    drop(held);
    for _ in 1..VETOES {
        let (_, request) = veto(CLIENT_KEY);
        guard.exchange(request, "http").await;
    }
    // One more: refused, not journaled.
    let (over, request) = veto(CLIENT_KEY);
    let reply = guard.exchange(request, "http").await;
    assert_eq!(reply["code"], "dex_not_allowed", "{reply}");
    // The other bot's: journaled.
    let (other, request) = veto(OTHER_KEY);
    guard.exchange(request, "http").await;
    let journaled = |events: &Value, key: &str| {
        events
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| {
                event["kind"] == "decision"
                    && event["client"].as_str() == Some(client(key).as_str())
            })
            .count()
    };
    let events = guard.events(0).await;
    assert_eq!(journaled(&events, CLIENT_KEY), VETOES as usize);
    assert_eq!(journaled(&events, OTHER_KEY), 1);
    assert!(
        guard
            .decision(over, Some(&client(CLIENT_KEY)))
            .await
            .is_none()
    );
    assert!(
        guard
            .decision(other, Some(&client(OTHER_KEY)))
            .await
            .is_some()
    );
    // The next minute: the one left out is counted.
    clock.advance(60_000);
    let (_, request) = veto(CLIENT_KEY);
    guard.exchange(request, "http").await;
    let events = guard.events(0).await;
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["kind"] == "error"
                && event["text"]
                    .as_str()
                    .is_some_and(|text| text.starts_with("1 more vetoes"))),
        "{events}"
    );
    assert_eq!(journaled(&events, CLIENT_KEY), VETOES as usize + 1);
}

const VETOES: u32 = zunder_guard::guard::VETOES_JOURNALED_PER_MINUTE;

/// Regression case: a cancel on disk that
/// never went out (a crash), and after the restart, before recovery reads,
/// the same order cancelled by another action (here a bot; the kill
/// switch's flattening alike). The venue shows it cancelled within the old
/// cancel's validity, but recovery asks the journal as it is then, not as
/// it was when the pending actions were taken: `moot`, never `happened`.
#[tokio::test(flavor = "multi_thread")]
async fn a_send_after_the_restart_makes_the_old_action_shared() {
    let dir = TestDir::new("journal-j3-later");
    let path = config(dir.path()).decision_journal(false);
    let guard = start(dir.path(), venue(), true).await;
    // A bot's limit buy below the market: it rests.
    let reply = guard
        .exchange(signed(order_wire(1, "2900", "0.1", "Gtc")), "http")
        .await;
    let oid = reply["response"]["data"]["statuses"][0]["resting"]["oid"]
        .as_u64()
        .unwrap_or_else(|| panic!("{reply}"));
    let venue = guard.upstream().fork();
    drop(guard);
    let cancel = |oid: u64| {
        Wire::Map(vec![
            ("type", Wire::str("cancel")),
            (
                "cancels",
                Wire::Array(vec![Wire::Map(vec![
                    ("a", Wire::UInt(1)),
                    ("o", Wire::UInt(oid)),
                ])]),
            ),
        ])
    };
    let mut journal = DecisionJournal::open(&path).unwrap();
    journal
        .append(
            SystemClock.now_ms() as i64,
            EventBody::Intent {
                of: 0,
                action: cancel(oid).to_value(),
            },
        )
        .unwrap();
    drop(journal);
    let guard = start(dir.path(), venue, false).await;
    let pending = guard.pending_for_recovery().await;
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert!(!pending[0].shared);
    let reply = guard.exchange(signed(cancel(oid)), "http").await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(guard.recover_after(pending, 0, 90_000).await, 1);
    let recovered = recovered(&guard).await;
    assert_eq!(recovered[0]["outcome"], "moot", "{recovered:?}");
}

/// The same for an order: an order on disk that never went out, and
/// after the restart the bot sends the same order with the same client
/// id, which fills, its answer lost (so no answered order id tells). The
/// venue's order matches the old intent in every field, but another
/// action names it: `moot`, never `happened`.
#[tokio::test(flavor = "multi_thread")]
async fn a_retry_after_the_restart_makes_the_old_order_moot() {
    let dir = TestDir::new("journal-j3-retry");
    let path = config(dir.path()).decision_journal(false);
    let venue = venue();
    venue.add_position_at("ETH", "0.5", "3000");
    let guard = start(dir.path(), venue, true).await;
    let venue = guard.upstream().fork();
    drop(guard);
    // A reduce-only IOC sell of 0.1 ETH with the bot's client id: Guard
    // forwards it as it is.
    let close = Wire::Map(vec![
        ("type", Wire::str("order")),
        (
            "orders",
            Wire::Array(vec![Wire::Map(vec![
                ("a", Wire::UInt(1)),
                ("b", Wire::Bool(false)),
                ("p", Wire::str("2900")),
                ("s", Wire::str("0.1")),
                ("r", Wire::Bool(true)),
                (
                    "t",
                    Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Ioc"))]))]),
                ),
                ("c", Wire::str("0x000000000000000000000000000c105e")),
            ])]),
        ),
        ("grouping", Wire::str("na")),
    ]);
    let mut journal = DecisionJournal::open(&path).unwrap();
    journal
        .append(
            SystemClock.now_ms() as i64,
            EventBody::Intent {
                of: 0,
                action: close.to_value(),
            },
        )
        .unwrap();
    drop(journal);
    let guard = start(dir.path(), venue, false).await;
    let pending = guard.pending_for_recovery().await;
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert!(!pending[0].shared);
    let before = guard.upstream().received().len();
    guard.upstream().swallow_answers(true);
    guard.exchange(signed(close.clone()), "http").await;
    guard.upstream().swallow_answers(false);
    // Sent as the old intent named it: the venue's order matches it.
    assert!(
        guard.upstream().received()[before..]
            .iter()
            .any(|received| received.json == close.to_value()),
        "{:?}",
        guard.upstream().received()
    );
    assert_eq!(guard.recover_after(pending, 0, 90_000).await, 1);
    let recovered = recovered(&guard).await;
    assert_eq!(recovered[0]["outcome"], "moot", "{recovered:?}");
}

/// Regression case: the bot's cancel by
/// client id on disk, never sent (a crash); after the restart the kill
/// switch's flattening cancels the same order by its order id. The names
/// differ, but the venue's answer gives both: `moot`, never `happened`.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_by_order_id_after_the_restart_makes_one_by_client_id_moot() {
    let dir = TestDir::new("journal-j3-alias");
    let config = config(dir.path());
    let path = config.decision_journal(false);
    let cloid = "0x000000000000000000000000000ab1de";
    // A position, and an order resting with the bot's client id that no
    // action in the journal names (placed elsewhere).
    let venue = venue();
    venue.add_position_at("ETH", "0.5", "3000");
    venue.add_resting_order(
        json!({"coin": "ETH", "side": "B", "limitPx": "2900", "sz": "0.1",
        "oid": 5_555, "isTrigger": false, "triggerPx": "0.0", "orderType": "Limit",
        "reduceOnly": false, "isPositionTpsl": false, "cloid": cloid, "children": [],
        "origSz": "0.1", "timestamp": SystemClock.now_ms()}),
    );
    let guard = start(dir.path(), venue, true).await;
    let venue = guard.upstream().fork();
    drop(guard);
    let by_cloid = json!({"type": "cancelByCloid", "cancels": [{"asset": 1, "cloid": cloid}]});
    let mut journal = DecisionJournal::open(&path).unwrap();
    journal
        .append(
            SystemClock.now_ms() as i64,
            EventBody::Intent {
                of: 0,
                action: by_cloid,
            },
        )
        .unwrap();
    drop(journal);
    let guard = start(dir.path(), venue, false).await;
    let pending = guard.pending_for_recovery().await;
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert!(!pending[0].shared);
    // The kill switch: the sync flattens, cancelling the order by its id.
    std::fs::write(config.kill_file(), "test").unwrap();
    guard.sync().await;
    assert!(
        guard
            .upstream()
            .received()
            .iter()
            .any(|received| received.json["type"] == "cancel"),
        "{:?}",
        guard.upstream().received()
    );
    assert_eq!(guard.recover_after(pending, 0, 90_000).await, 1);
    let recovered = recovered(&guard).await;
    assert_eq!(recovered[0]["outcome"], "moot", "{recovered:?}");
}

/// The same for an order: the bot's order with its client id on disk,
/// never sent (a crash); an order with that client id and those terms
/// rests at the venue (placed elsewhere), and after the restart the kill
/// switch's flattening cancels it by its order id. The venue's order
/// matches the old intent, but another action names it by its order id:
/// `moot`, never `happened`.
#[tokio::test(flavor = "multi_thread")]
async fn an_order_another_action_names_by_its_order_id_is_moot() {
    let dir = TestDir::new("journal-j3-alias-order");
    let config = config(dir.path());
    let path = config.decision_journal(false);
    let cloid = "0x000000000000000000000000000ab1df";
    let venue = venue();
    venue.add_position_at("ETH", "0.5", "3000");
    venue.add_resting_order(
        json!({"coin": "ETH", "side": "B", "limitPx": "2900", "sz": "0.1",
        "oid": 5_556, "isTrigger": false, "triggerPx": "0.0", "orderType": "Limit",
        "reduceOnly": false, "isPositionTpsl": false, "cloid": cloid, "children": [],
        "origSz": "0.1", "timestamp": SystemClock.now_ms()}),
    );
    let guard = start(dir.path(), venue, true).await;
    let venue = guard.upstream().fork();
    drop(guard);
    let order = json!({"type": "order", "orders": [{"a": 1, "b": true, "p": "2900", "s": "0.1",
        "r": false, "t": {"limit": {"tif": "Gtc"}}, "c": cloid}], "grouping": "na"});
    let mut journal = DecisionJournal::open(&path).unwrap();
    journal
        .append(
            SystemClock.now_ms() as i64,
            EventBody::Intent {
                of: 0,
                action: order,
            },
        )
        .unwrap();
    drop(journal);
    let guard = start(dir.path(), venue, false).await;
    let pending = guard.pending_for_recovery().await;
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert!(!pending[0].shared);
    std::fs::write(config.kill_file(), "test").unwrap();
    guard.sync().await;
    assert_eq!(guard.recover_after(pending, 0, 90_000).await, 1);
    let recovered = recovered(&guard).await;
    assert_eq!(recovered[0]["outcome"], "moot", "{recovered:?}");
}

/// Recovery's conclusions with the journal's writer stuck behind: written
/// within one deadline for all, then an alert says which were not (those
/// actions stay open for the next restart); Guard's lock is not held
/// beyond it.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_conclusions_the_writer_cannot_take_raise_an_alert() {
    let dir = TestDir::new("journal-j3-unwritten");
    let path = config(dir.path()).decision_journal(false);
    let guard = start(dir.path(), venue(), true).await;
    let venue = guard.upstream().fork();
    drop(guard);
    crashed_with(&path, 2);
    let guard = start(dir.path(), venue, false).await;
    let pending = guard.pending_for_recovery().await;
    assert_eq!(pending.len(), 2);
    let held = guard.hold_journal_writer_for_test().await;
    guard.fill_journal_queue_for_test().await;
    let started = std::time::Instant::now();
    assert_eq!(guard.recover_after(pending, 0, 90_000).await, 2);
    // Two reads 2 s apart, then one 2 s deadline for both records.
    let took = started.elapsed();
    assert!(took < Duration::from_millis(5_500), "{took:?}");
    let status = guard.status().await;
    assert!(
        status["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|alert| alert
                .as_str()
                .is_some_and(|text| text.contains("2 recovery conclusion(s) were not written"))),
        "{status}"
    );
    assert!(!guard.recovering());
    drop(held);
    // Still open: a second recovery finds them again.
    assert_eq!(guard.pending_for_recovery().await.len(), 2);
}
