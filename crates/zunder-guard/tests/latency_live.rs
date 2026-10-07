// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The latency Guard adds to a request, end to end, in paper mode against
//! Hyperliquid TESTNET's public data (no key, nothing sent): a client signs
//! an order, posts it to Guard over HTTP on loopback, and times Guard's
//! answer (its would-send). Ignored; run on the Linux build host:
//!
//! ```sh
//! env CARGO_INCREMENTAL=0 ZUNDER_GUARD_LATENCY=1 \
//!   cargo test --release -p zunder-guard --test latency_live -- --ignored --nocapture
//! ```
//!
//! Two runs: 72 small BTC buys (IOC, judged and journaled in full, as paper
//! does), one every 5 s (an entry costs up to 22 of Guard's request budget
//! of 4 a second, 24 more after a read; `ZUNDER_GUARD_LATENCY_COUNT` and
//! `_GAP_MS` change them),
//! with the account stream on (each counted as judged from the stream or
//! after a read); then 30 with the stream off, one every 10 s (a read per
//! request, within Guard's request budget). The background sync runs
//! throughout, as in production. The account is
//! `ZUNDER_GUARD_LATENCY_ACCOUNT`, a public testnet account (its own trading
//! sends the stream back to reading). The second run reads 24 of request
//! weight a request, about 720 in all; it is left out with
//! `ZUNDER_GUARD_LATENCY_READS=0`. Why requests fell back to a read is
//! counted by reason.

#![allow(clippy::unwrap_used)]

use std::{sync::Arc, time::Instant};

use rust_decimal::dec;
use serde_json::{Value, json};
use zunder_core::Timestamp;
use zunder_guard::{
    config::{GuardConfig, GuardMode, GuardNetwork},
    guard::{Clock, Guard, Mode, Setup, SystemClock},
    journal::DecisionJournal,
    server,
    testdir::TestDir,
    upstream::{Hyperliquid, Upstream},
};
use zunder_guard_core::{
    auth::AuthConfig,
    licence::FeeMode,
    sign::{GuardKey, SigningNetwork},
    wire::{Wire, minimal_hex},
};
use zunder_venue::PersistentRisk;
use zunder_venue::hyperliquid::Network;

const CLIENT_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";

async fn start(name: &str, account: &str) -> (String, Arc<Guard<Hyperliquid>>, TestDir) {
    let dir = TestDir::new(name);
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: GuardMode::Paper,
        account: Some(account.to_owned()),
        state_dir: dir.path().to_owned(),
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
        dec!(1000),
        "latency measurement",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(true)).unwrap();
    let guard = Guard::new(
        Setup {
            config,
            mode: Mode::Paper,
            risk,
            journal,
            fee: FeeMode::Off("latency".into()),
            fee_warning: None,
            limits: Default::default(),
        },
        Hyperliquid::paper(Network::Testnet).unwrap(),
        SystemClock,
    )
    .unwrap();
    let (addr, _) = server::bind(guard.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    (format!("http://{addr}"), guard, dir)
}

fn signed_buy(asset: u64, nonce: u64) -> Value {
    let action = Wire::Map(vec![
        ("type", Wire::str("order")),
        (
            "orders",
            Wire::Array(vec![Wire::Map(vec![
                ("a", Wire::UInt(asset)),
                ("b", Wire::Bool(true)),
                ("p", Wire::str("200000")),
                ("s", Wire::str("0.001")),
                ("r", Wire::Bool(false)),
                (
                    "t",
                    Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Ioc"))]))]),
                ),
            ])]),
        ),
        ("grouping", Wire::str("na")),
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

/// BTC's index in testnet's `meta`.
async fn btc_index(guard: &Guard<Hyperliquid>) -> u64 {
    let meta = guard
        .upstream()
        .info(&json!({"type": "meta"}))
        .await
        .unwrap();
    meta["universe"]
        .as_array()
        .unwrap()
        .iter()
        .position(|asset| asset["name"] == "BTC")
        .unwrap() as u64
}

/// Send `count` requests, one every `gap_ms`; each latency in µs, with
/// whether Guard judged it from the stream.
async fn measure(
    url: &str,
    guard: &Guard<Hyperliquid>,
    asset: u64,
    count: usize,
    gap_ms: u64,
) -> Vec<(u128, bool, bool, Option<String>)> {
    let client = reqwest::Client::new();
    let mut out = Vec::with_capacity(count);
    let judged = |status: Value| status["stream"]["judged_from_stream"].as_u64().unwrap_or(0);
    for _ in 0..count {
        let before = judged(guard.status().await);
        let body = signed_buy(asset, SystemClock.now_ms()).to_string();
        let started = Instant::now();
        let reply = client
            .post(format!("{url}/exchange"))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let elapsed = started.elapsed().as_micros();
        assert!(reply.contains("Zunder Guard"), "{reply}");
        let status = guard.status().await;
        let after = judged(status.clone());
        // Why the stream was not used, with numbers left out.
        let why = (after == before).then(|| {
            status["stream"]["last_fallback"]
                .as_str()
                .unwrap_or("")
                .chars()
                .map(|c| if c.is_ascii_digit() { '#' } else { c })
                .collect::<String>()
                .replace("##", "#")
                .replace("##", "#")
                .replace("##", "#")
        });
        // Refused for the budget first: such a request was judged from
        // nothing, whatever the stream's counter says.
        let limited = reply.contains("rate_limited");
        out.push((elapsed, after > before && !limited, limited, why));
        tokio::time::sleep(std::time::Duration::from_millis(gap_ms)).await;
    }
    out
}

fn report(label: &str, mut micros: Vec<u128>) {
    if micros.is_empty() {
        println!("{label}: none");
        return;
    }
    micros.sort_unstable();
    let at = |q: f64| micros[((micros.len() as f64 - 1.0) * q).round() as usize] as f64 / 1000.0;
    println!(
        "{label}: n {}, p50 {:.2} ms, p90 {:.2} ms, p99 {:.2} ms, max {:.2} ms",
        micros.len(),
        at(0.5),
        at(0.9),
        at(0.99),
        at(1.0)
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live testnet reads: run on the build box with ZUNDER_GUARD_LATENCY=1"]
async fn the_latency_guard_adds_with_and_without_the_stream() {
    if std::env::var("ZUNDER_GUARD_LATENCY").as_deref() != Ok("1") {
        return;
    }
    let account = std::env::var("ZUNDER_GUARD_LATENCY_ACCOUNT")
        .unwrap_or_else(|_| "0x5972698398d8c5bbe67c0db74906236691020417".to_owned());
    // With the stream.
    let (url, guard, _dir) = start("latency-stream", &account).await;
    let stream = guard.start_stream().await.unwrap();
    guard.sync().await;
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    let asset = btc_index(&guard).await;
    // The first request follows BTC; give its bbo a moment.
    measure(&url, &guard, asset, 1, 1_000).await;
    let count = std::env::var("ZUNDER_GUARD_LATENCY_COUNT")
        .ok()
        .and_then(|count| count.parse().ok())
        .unwrap_or(72);
    let gap = std::env::var("ZUNDER_GUARD_LATENCY_GAP_MS")
        .ok()
        .and_then(|gap| gap.parse().ok())
        .unwrap_or(5_000);
    let sync = tokio::spawn(guard.clone().sync_forever());
    let runs = measure(&url, &guard, asset, count, gap).await;
    sync.abort();
    stream.abort();
    println!(
        "account {account}; stream: {}",
        guard.status().await["stream"]
    );
    report(
        "stream on, judged from the stream",
        runs.iter().filter(|r| r.1).map(|r| r.0).collect(),
    );
    report(
        "stream on, judged after a read",
        runs.iter().filter(|r| !r.1 && !r.2).map(|r| r.0).collect(),
    );
    report(
        "stream on, refused rate_limited (the read budget spent)",
        runs.iter().filter(|r| r.2).map(|r| r.0).collect(),
    );
    report("stream on, all", runs.iter().map(|r| r.0).collect());
    let mut reasons = std::collections::BTreeMap::new();
    for why in runs.iter().filter_map(|r| r.3.clone()) {
        *reasons.entry(why).or_insert(0) += 1;
    }
    for (why, count) in reasons {
        println!("  fell back {count}x: {why}");
    }
    if std::env::var("ZUNDER_GUARD_LATENCY_READS").as_deref() == Ok("0") {
        return;
    }
    // A request refused before judging (a signature that recovers no key):
    // HTTP on loopback and the decision journal's synced write, no judgement.
    let client = reqwest::Client::new();
    let mut refused = Vec::new();
    for _ in 0..50 {
        let mut body = signed_buy(asset, SystemClock.now_ms());
        body["signature"] = json!({"r": "0x0", "s": "0x0", "v": 27});
        let started = Instant::now();
        client
            .post(format!("{url}/exchange"))
            .body(body.to_string())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        refused.push(started.elapsed().as_micros());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    report("refused before judging (HTTP and the journal)", refused);
    // Without the stream: every request reads (24 of weight, and 22 for
    // what it would send, within Guard's request budget of 4 a second: one
    // every 10 s).
    let (url, guard, _dir) = start("latency-read", &account).await;
    guard.sync().await;
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    let sync = tokio::spawn(guard.clone().sync_forever());
    let runs = measure(&url, &guard, asset, 30, 10_000).await;
    sync.abort();
    report(
        "stream off (a read per request)",
        runs.iter().map(|r| r.0).collect(),
    );
}
