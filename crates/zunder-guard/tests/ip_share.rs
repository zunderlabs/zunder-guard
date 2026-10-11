// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `ip_share`: a Guard with a third of its IP address's request weight
//! (three Guards on one machine) still protects and flattens first when a
//! bot has spent its request budget and the `/info` passthrough is spent
//! too. Protection's sends and the sync's reads come from no bucket.
//!
//! In memory, on a hand-moved clock: account 10,000 USDC, ETH at 3,000;
//! default policy (the main dex alone).

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use rust_decimal::dec;
use serde_json::{Value, json};
use support::MemoryVenue;
use zunder_core::Timestamp;
use zunder_guard::{
    config::{GuardConfig, GuardMode, GuardNetwork},
    guard::{Clock, Guard, Mode, Setup, SystemClock},
    journal::DecisionJournal,
    testdir::TestDir,
};
use zunder_guard_core::{
    action::Action,
    auth::AuthConfig,
    event::EventBody,
    licence::FeeMode,
    sign::{Address, GuardKey, SigningNetwork},
    wire::{Wire, minimal_hex},
};
use zunder_venue::PersistentRisk;

const CLIENT_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

fn api_key() -> GuardKey {
    GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap()
}

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn cancel(nonce: u64) -> Value {
    let action = Wire::Map(vec![
        ("type", Wire::str("cancel")),
        (
            "cancels",
            Wire::Array(vec![Wire::Map(vec![
                ("a", Wire::UInt(1)),
                ("o", Wire::UInt(999_999)),
            ])]),
        ),
    ]);
    let signature = GuardKey::from_hex(CLIENT_KEY)
        .unwrap()
        .sign_l1_action(SigningNetwork::Testnet, &action, nonce, None)
        .unwrap();
    json!({
        "action": action.to_value(),
        "nonce": nonce,
        "signature": {"r": minimal_hex(&signature.r), "s": minimal_hex(&signature.s), "v": signature.v},
    })
}

fn rate_limited(reply: &Value) -> bool {
    reply.to_string().contains("rate_limited")
}

#[tokio::test]
async fn protection_goes_first_on_a_spent_budget_at_a_third_of_the_ip() {
    let dir = TestDir::new("ip-share-third");
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: GuardMode::Testnet,
        account: Some(ACCOUNT.to_owned()),
        api_wallet: Some(api_key().address().to_hex()),
        state_dir: dir.path().to_owned(),
        ip_share: dec!(0.3333),
        auth: AuthConfig {
            clients: vec![GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex()],
            ..AuthConfig::default()
        },
        ..GuardConfig::default()
    };
    config.validate().unwrap();
    let start = SystemClock.now_ms();
    let clock = TestClock(Arc::new(AtomicU64::new(start)));
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(false),
        config.policy.risk_limits(),
        &config.journal_scope(false).unwrap(),
        Timestamp::from_millis(start as i64),
        dec!(10000),
        "ip_share test",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(false)).unwrap();
    let venue = MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "10000",
    );
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
            // The production budgets, fitted to the share.
            limits: Default::default(),
        },
        venue,
        clock.clone(),
    )
    .unwrap();

    // The status reports the share and every budget fitted to it: 399 of
    // 1,200 a minute; scale (399.96 − 90) / 1,110 = 0.27924; bots'
    // requests a burst of 46 (one read and an entry with its leverage) and
    // (300 × 0.27924 − 46) / 60 = 0.629 a second; the sync every 60,000 ×
    // 24 / 80 = 18 s (its reads 288 × 0.27924 = 80.4 a minute).
    let status = guard.status().await;
    assert_eq!(status["ip_share"], "0.3333", "{status}");
    let budgets = &status["budgets"];
    assert_eq!(budgets["weight_per_minute"], 399, "{budgets}");
    assert_eq!(budgets["requests"]["burst"], 46, "{budgets}");
    assert_eq!(budgets["requests"]["per_second"], "0.629", "{budgets}");
    assert_eq!(budgets["sync_interval_ms"], 18_000, "{budgets}");
    assert!(budgets["reserve_per_minute"].as_u64().unwrap() >= 23);

    // A bot spends the request budget (each cancel needs a read of the
    // account, 24, and sends 1; no stream here): refused within a few.
    let mut nonce = start + 10_000;
    clock.0.store(nonce, Ordering::SeqCst);
    let mut spent = false;
    for _ in 0..10 {
        nonce += 1;
        if rate_limited(&guard.exchange(cancel(nonce), "http").await) {
            spent = true;
            break;
        }
    }
    assert!(spent, "the request budget was never spent");
    // And the passthrough (a burst of 60 at this share: three requests of
    // weight 20).
    let mut info_spent = false;
    for _ in 0..10 {
        if let Err(error) = guard.info(&json!({"type": "candleSnapshot"})).await
            && error
                .to_string()
                .contains("Guard passes info requests within")
        {
            info_spent = true;
            break;
        }
    }
    assert!(info_spent, "the passthrough budget was never spent");

    // A position without a stop appears: the sync protects it at once,
    // whatever the budgets.
    guard.upstream().add_position("ETH", "0.5");
    let before = guard.upstream().received().len();
    guard.sync().await;
    let received = guard.upstream().received();
    assert_eq!(received.len(), before + 1, "{received:?}");
    let Action::Order(stop) = &received[before].action else {
        panic!("{:?}", received[before])
    };
    // 2% below the 3,000 mid, for the whole 0.5, reduce-only.
    assert_eq!(stop.orders[0].protective_level(), Some(dec!(2940)));
    assert!(stop.orders[0].reduce_only);
    // The bot is still held to its budget.
    nonce += 1;
    assert!(rate_limited(&guard.exchange(cancel(nonce), "http").await));

    // The kill switch: the bot's request cannot even read to flatten (no
    // budget), the sync flattens all the same.
    std::fs::write(dir.path().join("kill"), "ip_share drill\n").unwrap();
    nonce += 1;
    guard.exchange(cancel(nonce), "http").await;
    guard.sync().await;
    assert!(
        guard.upstream().positions().is_empty(),
        "{:?}",
        guard.upstream().positions()
    );
    let last = guard.upstream().received().pop().unwrap();
    let Action::Order(close) = &last.action else {
        panic!("{last:?}")
    };
    assert!(close.orders.iter().all(|order| order.reduce_only));
}

/// A share too small for the markets is refused at start, not run with
/// budgets that would crowd out protection.
#[test]
fn guard_refuses_to_start_on_too_small_a_share() {
    let dir = TestDir::new("ip-share-small");
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: GuardMode::Paper,
        account: Some(ACCOUNT.to_owned()),
        state_dir: dir.path().to_owned(),
        ip_share: dec!(0.2),
        auth: AuthConfig {
            clients: vec![GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex()],
            ..AuthConfig::default()
        },
        ..GuardConfig::default()
    };
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(true),
        config.policy.risk_limits(),
        &config.journal_scope(true).unwrap(),
        Timestamp::from_millis(SystemClock.now_ms() as i64),
        dec!(10000),
        "ip_share test",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(true)).unwrap();
    let venue = MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "10000",
    )
    .read_only();
    let refused = Guard::new(
        Setup {
            config,
            mode: Mode::Paper,
            risk,
            journal,
            fee: FeeMode::Off("test".into()),
            fee_warning: None,
            limits: Default::default(),
        },
        venue,
        SystemClock,
    );
    let Err(error) = refused else {
        panic!("started on ip_share 0.2")
    };
    assert!(error.contains("ip_share 0.2"), "{error}");
}

/// A Guard sending on testnet (in memory) at `share`, the main dex alone,
/// with a request budget no test here reaches.
fn sending_guard(
    name: &str,
    share: rust_decimal::Decimal,
) -> (Arc<Guard<MemoryVenue, TestClock>>, TestClock, TestDir) {
    let dir = TestDir::new(name);
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: GuardMode::Testnet,
        account: Some(ACCOUNT.to_owned()),
        api_wallet: Some(api_key().address().to_hex()),
        state_dir: dir.path().to_owned(),
        ip_share: share,
        auth: AuthConfig {
            clients: vec![GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex()],
            ..AuthConfig::default()
        },
        ..GuardConfig::default()
    };
    let start = SystemClock.now_ms();
    let clock = TestClock(Arc::new(AtomicU64::new(start)));
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(false),
        config.policy.risk_limits(),
        &config.journal_scope(false).unwrap(),
        Timestamp::from_millis(start as i64),
        dec!(10000),
        "ip_share test",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(false)).unwrap();
    let venue = MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "10000",
    );
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
            limits: zunder_guard::guard::Limits {
                request_weight_per_second: 1_000_000,
                request_weight_burst: 1_000_000,
            },
        },
        venue,
        clock.clone(),
    )
    .unwrap();
    (guard, clock, dir)
}

/// A bot's send overtakes the sync's read (held 1 s by the venue). Alone on
/// the address the sync reads without the lock, so it reads again and
/// skips its next round, as before. At a third (the sync every 18 s; a
/// skipped round would leave 36 s) it reads holding the lock: the request
/// waits for it, the round reads once and skips nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_stretched_sync_never_skips_a_round() {
    for (share, locked) in [(dec!(1), false), (dec!(0.3333), true)] {
        let (guard, clock, _dir) = sending_guard(&format!("ip-share-locked-{locked}"), share);
        assert_eq!(guard.status().await["budgets"]["sync_reads_locked"], locked);
        let nonce = clock.now_ms() + 10_000;
        clock.0.store(nonce, Ordering::SeqCst);
        guard.upstream().slow_reads(1_000);
        let syncing = guard.clone();
        let sync = tokio::spawn(async move { syncing.sync().await });
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        guard.exchange(cancel(nonce + 1), "http").await;
        sync.await.unwrap();
        guard.upstream().slow_reads(0);
        let status = guard.status().await;
        let (reads, delayed) = if locked { (1, false) } else { (2, true) };
        assert_eq!(status["last_sync_reads"], reads, "{share}: {status}");
        assert_eq!(status["next_sync_delayed"], delayed, "{share}: {status}");
    }
}

/// A venue slower than the locked read's 5 s: the locked round fails, the
/// next reads without the lock (no overall limit) and gets the account, so
/// a slow venue never stops a stretched sync.
#[tokio::test(flavor = "multi_thread")]
async fn a_stretched_sync_reads_unlocked_after_a_locked_timeout() {
    let (guard, _clock, _dir) = sending_guard("ip-share-slow", dec!(0.3333));
    guard.upstream().slow_reads(6_000);
    guard.sync().await;
    let status = guard.status().await;
    assert!(status["last_sync_ms"].is_null(), "{status}");
    assert!(!status["last_error"].is_null(), "{status}");
    guard.sync().await;
    let status = guard.status().await;
    assert!(!status["last_sync_ms"].is_null(), "{status}");
}

/// A Guard at `share` on `clock`, with the production budgets, restarted
/// after a crash that left `pending` intents naming an order each that the
/// venue never saw (`unknownOid`: each read twice).
fn recovering_guard(
    dir: &TestDir,
    share: rust_decimal::Decimal,
    clock: &TestClock,
    pending: u64,
) -> Arc<Guard<MemoryVenue, TestClock>> {
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: GuardMode::Testnet,
        account: Some(ACCOUNT.to_owned()),
        api_wallet: Some(api_key().address().to_hex()),
        state_dir: dir.path().to_owned(),
        ip_share: share,
        auth: AuthConfig {
            clients: vec![GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex()],
            ..AuthConfig::default()
        },
        ..GuardConfig::default()
    };
    let now = clock.now_ms();
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(false),
        config.policy.risk_limits(),
        &config.journal_scope(false).unwrap(),
        Timestamp::from_millis(now as i64),
        dec!(10000),
        "ip_share recovery test",
    )
    .unwrap();
    let mut journal = DecisionJournal::open(&config.decision_journal(false)).unwrap();
    for i in 0..pending {
        let action = json!({"type": "order", "orders": [{"a": 1, "b": true, "p": "3000",
            "s": "0.1", "r": false, "t": {"limit": {"tif": "Ioc"}},
            "c": format!("0x7a68{:028x}", 1_000 + i)}], "grouping": "na"});
        journal
            .append(now as i64, EventBody::Intent { of: 0, action })
            .unwrap();
    }
    let venue = MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "10000",
    );
    Guard::new(
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
            limits: Default::default(),
        },
        venue,
        clock.clone(),
    )
    .unwrap()
}

/// Regression case: three Guards at
/// a third of one IP address each (`ip_share` 0.33) come back after a
/// crash with 200 actions in doubt each, every one of which recovery reads
/// twice (2 of weight a read). Recovery waits on the request budget
/// rather than reading back to back, so the address's weight (the sync's
/// reads every 18 s and recovery's, as the venue counts them) stays
/// within its 1,200 in every minute; what recovery could not read within
/// its 90 s is `unknown`.
#[tokio::test(flavor = "multi_thread")]
async fn three_guards_recovering_on_one_address_stay_within_its_limit() {
    let clock = TestClock(Arc::new(AtomicU64::new(SystemClock.now_ms())));
    let dirs: Vec<TestDir> = (0..3)
        .map(|i| TestDir::new(&format!("ip-share-recovery-{i}")))
        .collect();
    let guards: Vec<_> = dirs
        .iter()
        .map(|dir| recovering_guard(dir, dec!(0.33), &clock, 200))
        .collect();
    let interval = guards[0].status().await["budgets"]["sync_interval_ms"]
        .as_u64()
        .unwrap();
    // Started (their first reads are not recovery's), and the account
    // read once: the weight counted from here.
    for guard in &guards {
        guard.sync().await;
    }
    let mut counted: Vec<usize> = guards
        .iter()
        .map(|guard| guard.upstream().info_log().len())
        .collect();
    let started = clock.now_ms();
    let mut recoveries = Vec::new();
    for guard in &guards {
        let pending = guard.pending_for_recovery().await;
        assert_eq!(pending.len(), 200);
        let guard = guard.clone();
        recoveries.push(tokio::spawn(async move {
            guard.recover_after(pending, 0, 90_000).await
        }));
    }
    // Guard's clock runs 20 times as fast as the test's; the sync every
    // 18 s of it. Each read is counted at the time it was made.
    let mut weights: Vec<(u64, u64)> = Vec::new();
    let mut next_sync = started + interval;
    while recoveries.iter().any(|recovery| !recovery.is_finished()) {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        clock.0.fetch_add(20, Ordering::SeqCst);
        let now = clock.now_ms();
        assert!(now < started + 200_000, "recovery outran its bound");
        if now >= next_sync {
            next_sync += interval;
            for guard in &guards {
                guard.sync().await;
            }
        }
        for (guard, counted) in guards.iter().zip(counted.iter_mut()) {
            let log = guard.upstream().info_log();
            for body in &log[*counted..] {
                weights.push((now, zunder_guard::guard::info_weight(body["type"].as_str())));
            }
            *counted = log.len();
        }
    }
    for recovery in recoveries {
        assert_eq!(recovery.await.unwrap(), 200);
    }
    // Every minute's weight, the worst first.
    let worst = weights
        .iter()
        .map(|(at, _)| {
            weights
                .iter()
                .filter(|(other, _)| *other >= *at && *other < at + 60_000)
                .map(|(_, weight)| weight)
                .sum::<u64>()
        })
        .max()
        .unwrap();
    assert!(worst <= 1_200, "the address spent {worst} in a minute");
    // Recovery read what it could: some concluded (read twice), the rest
    // unknown with an alert.
    for guard in &guards {
        let events = guard.events(0).await;
        let outcomes: Vec<&str> = events
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["kind"] == "recovered")
            .map(|event| event["outcome"].as_str().unwrap())
            .collect();
        assert_eq!(outcomes.len(), 200);
        assert!(outcomes.contains(&"did_not_happen"), "{outcomes:?}");
        assert!(outcomes.contains(&"unknown"), "{outcomes:?}");
    }
}
