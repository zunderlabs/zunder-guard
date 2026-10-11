// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The account stream end to end: Guard follows the in-memory venue's
//! WebSocket (`support::serve_ws`, snapshots and prices every 100 ms) and
//! judges a request from it when it is clean, without reading the account
//! over HTTP; after an order (an `orderUpdates` event, or Guard's own
//! send), on a dropped or stalled socket, it reads the account again, and
//! exits still go. A price move after the last snapshot is judged at the
//! fresh price (equity, daily stop, open risk), a halt flattens from a
//! fresh read, and the background sync always finishes its round however
//! often Guard sends.
//!
//! Account: 9,000 USDC on the main dex and 1,000 on HIP-3 dex xyz; markets
//! `["*", "xyz:*"]`.

#![allow(clippy::unwrap_used)]

mod support;

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use rust_decimal::dec;
use serde_json::{Value, json};
use support::{GOLD, MemoryVenue, serve_ws};
use zunder_core::Timestamp;
use zunder_guard::{
    config::{GuardConfig, GuardMode, GuardNetwork},
    guard::{Clock, Guard, Limits, Mode, Setup, SystemClock},
    journal::DecisionJournal,
    server,
    testdir::TestDir,
};
use zunder_guard_core::{
    auth::AuthConfig,
    licence::FeeMode,
    policy::{Markets, Policy},
    sign::{Address, GuardKey, SigningNetwork},
    wire::{Wire, minimal_hex},
};
use zunder_venue::PersistentRisk;

const CLIENT_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

fn api_key() -> GuardKey {
    GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap()
}

struct Running<C = SystemClock> {
    url: String,
    guard: Arc<Guard<MemoryVenue, C>>,
    ws: tokio::task::JoinHandle<()>,
    _dir: TestDir,
}

/// A Guard whose request budget no test reaches (the in-memory venue has
/// no limit), except where a test is about the budget.
async fn start(name: &str, paper: bool) -> Running {
    start_with(
        name,
        paper,
        Limits {
            request_weight_per_second: 1_000_000,
            request_weight_burst: 1_000_000,
        },
    )
    .await
}

async fn start_with(name: &str, paper: bool, limits: Limits) -> Running {
    start_markets(name, paper, limits, &["*", "xyz:*"]).await
}

async fn start_markets(name: &str, paper: bool, limits: Limits, markets: &[&str]) -> Running {
    start_syncing(name, paper, limits, markets, None).await
}

/// [`start_markets`] with the background sync every `sync_seconds`.
async fn start_syncing(
    name: &str,
    paper: bool,
    limits: Limits,
    markets: &[&str],
    sync_seconds: Option<u64>,
) -> Running {
    start_syncing_with_clock(name, paper, limits, markets, sync_seconds, SystemClock).await
}

async fn start_syncing_with_clock<C: Clock>(
    name: &str,
    paper: bool,
    limits: Limits,
    markets: &[&str],
    sync_seconds: Option<u64>,
    clock: C,
) -> Running<C> {
    let dir = TestDir::new(name);
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: if paper {
            GuardMode::Paper
        } else {
            GuardMode::Testnet
        },
        account: Some(ACCOUNT.to_owned()),
        api_wallet: Some(api_key().address().to_hex()),
        state_dir: dir.path().to_owned(),
        auth: AuthConfig {
            clients: vec![GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex()],
            ..AuthConfig::default()
        },
        policy: Policy {
            markets: Markets::from_list(markets.iter().map(|market| (*market).to_owned())),
            ..Policy::default()
        },
        sync_seconds: sync_seconds.unwrap_or(GuardConfig::default().sync_seconds),
        ..GuardConfig::default()
    };
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(paper),
        config.policy.risk_limits(),
        &config.journal_scope(paper).unwrap(),
        Timestamp::from_millis(clock.now_ms() as i64),
        dec!(10000),
        "stream test",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(paper)).unwrap();
    let venue = MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "9000",
    );
    venue.set_dex_equity("xyz", "1000");
    let venue = if paper { venue.read_only() } else { venue };
    let guard = Guard::new(
        Setup {
            config,
            mode: if paper {
                Mode::Paper
            } else {
                Mode::Send {
                    key: api_key(),
                    network: SigningNetwork::Testnet,
                }
            },
            risk,
            journal,
            fee: FeeMode::Off("test".into()),
            fee_warning: None,
            limits,
        },
        venue,
        clock,
    )
    .unwrap();
    let ws = serve_ws(guard.clone(), 100).await;
    guard.start_stream().await.unwrap();
    // The reference data the stream view needs (meta, mode, perpDexs, xyz's
    // meta and caps) from one ordinary read, and nonces after start + 5 s.
    guard.sync().await;
    tokio::time::sleep(Duration::from_millis(5_100)).await;
    let (addr, _) = server::bind(guard.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    Running {
        url: format!("http://{addr}"),
        guard,
        ws,
        _dir: dir,
    }
}

fn order(asset: u64, is_buy: bool, price: &str, size: &str, reduce_only: bool) -> Value {
    order_tif(asset, is_buy, price, size, reduce_only, "Ioc")
}

fn order_tif(
    asset: u64,
    is_buy: bool,
    price: &str,
    size: &str,
    reduce_only: bool,
    tif: &str,
) -> Value {
    let action = Wire::Map(vec![
        ("type", Wire::str("order")),
        (
            "orders",
            Wire::Array(vec![Wire::Map(vec![
                ("a", Wire::UInt(asset)),
                ("b", Wire::Bool(is_buy)),
                ("p", Wire::str(price)),
                ("s", Wire::str(size)),
                ("r", Wire::Bool(reduce_only)),
                (
                    "t",
                    Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str(tif))]))]),
                ),
            ])]),
        ),
        ("grouping", Wire::str("na")),
    ]);
    signed(action)
}

/// `n` reduce-only IOC sells of 0.001 ETH at 2,900 in one action (41 or
/// more weigh 2 with the venue).
fn reduce_only_batch(n: usize) -> Value {
    let one = Wire::Map(vec![
        ("a", Wire::UInt(1)),
        ("b", Wire::Bool(false)),
        ("p", Wire::str("2900")),
        ("s", Wire::str("0.001")),
        ("r", Wire::Bool(true)),
        (
            "t",
            Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Ioc"))]))]),
        ),
    ]);
    signed(Wire::Map(vec![
        ("type", Wire::str("order")),
        ("orders", Wire::Array(vec![one; n])),
        ("grouping", Wire::str("na")),
    ]))
}

/// A cancel of an order the venue does not know: judged, and sent.
fn cancel(oid: u64) -> Value {
    signed(Wire::Map(vec![
        ("type", Wire::str("cancel")),
        (
            "cancels",
            Wire::Array(vec![Wire::Map(vec![
                ("a", Wire::UInt(1)),
                ("o", Wire::UInt(oid)),
            ])]),
        ),
    ]))
}

fn signed(action: Wire) -> Value {
    signed_at(action, next_nonce())
}

fn signed_at(action: Wire, nonce: u64) -> Value {
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

/// Nonces that never repeat, even for requests in the same millisecond.
fn next_nonce() -> u64 {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let now = SystemClock.now_ms();
    let mut last = LAST.load(std::sync::atomic::Ordering::SeqCst);
    loop {
        let next = now.max(last + 1);
        match LAST.compare_exchange(
            last,
            next,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        ) {
            Ok(_) => return next,
            Err(seen) => last = seen,
        }
    }
}

async fn post(url: &str, body: &Value) -> Value {
    tokio::time::sleep(Duration::from_millis(2)).await;
    let text = reqwest::Client::new()
        .post(format!("{url}/exchange"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

async fn stream_status(guard: &Guard<MemoryVenue>) -> Value {
    guard.status().await["stream"].clone()
}

/// How many times Guard read an account (`clearinghouseState`) over HTTP.
fn account_reads(venue: &MemoryVenue) -> usize {
    venue
        .info_log()
        .iter()
        .filter(|body| body["type"] == "clearinghouseState")
        .count()
}

#[tokio::test]
async fn a_clean_stream_judges_without_reading_the_account() {
    let running = start("stream-clean", true).await;
    let venue = running.guard.upstream();
    assert_eq!(
        stream_status(&running.guard).await["state"]["connected"],
        true
    );
    // The first ETH entry: ETH is not followed yet, so Guard reads.
    let reply = post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    assert!(
        reply["response"].as_str().unwrap().contains("paper mode"),
        "{reply}"
    );
    let status = stream_status(&running.guard).await;
    assert_eq!(status["judged_after_read"], 1, "{status}");
    assert!(
        status["last_fallback"].as_str().unwrap().contains("ETH"),
        "{status}"
    );
    // A few snapshots and ETH's bbo later: judged from the stream, no read.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let reads = account_reads(venue);
    let reply = post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    assert!(
        reply["response"].as_str().unwrap().contains("would resize"),
        "{reply}"
    );
    let status = stream_status(&running.guard).await;
    assert_eq!(status["judged_from_stream"], 1, "{status}");
    assert_eq!(account_reads(venue), reads, "no account read for it");
    // The same on HIP-3 dex xyz: GOLD's prices are followed after the
    // first entry; the second is judged from the stream with GOLD's book
    // read over HTTP for it (20 levels), sized to xyz's 1,000 of margin as
    // after a read: 1 GOLD at 4x.
    post(
        &running.url,
        &order(u64::from(GOLD), true, "4000", "10", false),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let reads = account_reads(venue);
    let reply = post(
        &running.url,
        &order(u64::from(GOLD), true, "4000", "10", false),
    )
    .await;
    assert_eq!(reply["size"], "1", "{reply}");
    assert_eq!(account_reads(venue), reads, "no account read for it");
    assert_eq!(stream_status(&running.guard).await["judged_from_stream"], 2);
    let books = venue
        .info_log()
        .iter()
        .filter(|body| body["type"] == "l2Book" && body["coin"] == "xyz:GOLD")
        .count();
    assert_eq!(books, 2, "a book read for each GOLD entry");
}

/// After Guard's own send the stream waits for snapshots that came after
/// the send's events. The venue's snapshots are held back from just
/// before the send until the check (otherwise, with snapshots every tick,
/// a request that comes a tick later is rightly judged from the stream
/// again: the send was reported and a snapshot followed it).
#[tokio::test]
async fn after_an_order_guard_reads_until_the_snapshots_have_caught_up() {
    let running = start("stream-event", false).await;
    let venue = running.guard.upstream();
    // Follow ETH (that entry is sent: its event dirties the stream for 1 s
    // and a snapshot), then an entry from the stream, sent to the venue.
    post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    venue.pause_ws_snapshots(true);
    let reply = post(&running.url, &order(1, true, "3000", "0.01", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(stream_status(&running.guard).await["judged_from_stream"], 1);
    // Its events may come; no snapshot after them: a read.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let reads = account_reads(venue);
    post(&running.url, &order(1, false, "2900", "0.01", true)).await;
    let status = stream_status(&running.guard).await;
    assert!(
        account_reads(venue) > reads,
        "read after the send: {status}"
    );
    assert_eq!(status["judged_from_stream"], 1, "{status}");
    let why = status["last_fallback"].as_str().unwrap();
    assert!(
        why.contains("changed") || why.contains("Guard just sent"),
        "{status}"
    );
    // Snapshots again, more than 1 s after the last event: the stream again.
    venue.pause_ws_snapshots(false);
    tokio::time::sleep(Duration::from_millis(1_400)).await;
    let before = stream_status(&running.guard).await["judged_from_stream"]
        .as_u64()
        .unwrap();
    post(&running.url, &order(1, true, "3000", "0.01", false)).await;
    assert_eq!(
        stream_status(&running.guard).await["judged_from_stream"],
        before + 1
    );
}

#[tokio::test]
async fn a_stalled_or_dropped_stream_falls_back_and_exits_still_go() {
    let running = start("stream-drop", false).await;
    let venue = running.guard.upstream();
    post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    // Stalled: nothing for 6 s.
    venue.pause_ws(true);
    tokio::time::sleep(Duration::from_millis(6_300)).await;
    let reads = account_reads(venue);
    post(&running.url, &order(1, true, "3000", "0.01", false)).await;
    assert!(account_reads(venue) > reads);
    let status = stream_status(&running.guard).await;
    assert!(
        status["last_fallback"].as_str().unwrap().contains("ms old"),
        "{status}"
    );
    // Dropped: the venue's socket goes away.
    venue.pause_ws(false);
    running.ws.abort();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        stream_status(&running.guard).await["state"]["connected"],
        false
    );
    // A close (reduce-only) still goes, judged after a read.
    let reply = post(&running.url, &order(1, false, "2900", "0.01", true)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let status = stream_status(&running.guard).await;
    assert!(
        status["last_fallback"]
            .as_str()
            .unwrap()
            .contains("not connected"),
        "{status}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_does_not_wait_for_the_syncs_read() {
    let running = start("stream-sync", true).await;
    let venue = running.guard.upstream();
    post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    // Every account read over HTTP now takes 1.5 s; the sync starts one.
    venue.slow_reads(1_500);
    let guard = running.guard.clone();
    let sync = tokio::spawn(async move { guard.sync().await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // A request meanwhile is judged from the stream, at once.
    let started = std::time::Instant::now();
    let reply = post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    let took = started.elapsed();
    assert!(
        reply["response"].as_str().unwrap().contains("paper mode"),
        "{reply}"
    );
    assert!(took < Duration::from_millis(500), "{took:?}");
    assert!(!sync.is_finished(), "the sync was still reading");
    sync.await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sync_read_that_a_send_overtook_is_read_again_under_the_lock() {
    let running = start("stream-overtaken", false).await;
    let venue = running.guard.upstream();
    // Follow ETH; its entry is sent, so let the snapshots catch up (and
    // 2 s pass, after which the sync reads without the lock).
    post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    venue.slow_reads(1_500);
    let reads = account_reads(venue);
    let guard = running.guard.clone();
    let sync = tokio::spawn(async move { guard.sync().await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // An entry sent while the sync reads: the sync's read predates it.
    let reply = post(&running.url, &order(1, true, "3000", "0.01", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = SystemClock.now_ms();
    sync.await.unwrap();
    // The sync read the account again after the send, holding the lock,
    // and finished its round from that read: the risk engine saw it. Two
    // reads of both dexes.
    assert_eq!(account_reads(venue), reads + 4, "read again");
    let status = running.guard.status().await;
    assert_eq!(status["last_sync_reads"], 2);
    assert_eq!(status["next_sync_delayed"], true, "the next round waits");
    let synced = running.guard.status().await["last_sync_ms"]
        .as_u64()
        .unwrap();
    assert!(synced >= sent, "{synced} {sent}");
    // The preview's view is that read's, about 1.5 s old (its read began
    // after the send), not the first one's (over 3 s).
    let preview = running
        .guard
        .preview(json!({"action": {"type": "scheduleCancel"}}))
        .await;
    assert!(
        preview["view_age_ms"].as_u64().unwrap() < 2_500,
        "{preview}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bot_that_sends_during_every_sync_cannot_hold_off_protection() {
    let running = start("stream-busy", false).await;
    let venue = running.guard.upstream();
    // A GTC buy at 2,950 rests below the 3,000 mid; its stop is refused,
    // so Guard cancels it and protects whatever filled at the next sync,
    // settled or not.
    venue.refuse_stops();
    let reply = post(
        &running.url,
        &order_tif(1, true, "2950", "0.1", false, "Gtc"),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert!(venue.orders().is_empty(), "{:?}", venue.orders());
    // 0.05 of it had filled before the cancel.
    venue.add_position("ETH", "0.05");
    venue.accept_stops();
    // A bot that sends during every sync: each sync's read (1.5 s, without
    // the lock) is overtaken by a cancel sent from the stream meanwhile.
    venue.slow_reads(1_500);
    for round in 0..3 {
        // The snapshots catch up with the last send, and 2 s pass.
        tokio::time::sleep(Duration::from_millis(2_100)).await;
        let guard = running.guard.clone();
        let sync = tokio::spawn(async move { guard.sync().await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let before = venue.received().len();
        let reply = post(&running.url, &cancel(999_999)).await;
        assert_eq!(reply["status"], "ok", "{reply}");
        assert_eq!(venue.received().len(), before + 1, "sent during the read");
        let sent = SystemClock.now_ms();
        sync.await.unwrap();
        // The round finished from a read made after the send.
        let synced = running.guard.status().await["last_sync_ms"]
            .as_u64()
            .unwrap();
        assert!(synced >= sent, "round {round}: {synced} {sent}");
        // The first round protected the 0.05; none added another stop.
        let stops: Vec<Value> = venue
            .orders()
            .into_iter()
            .filter(|order| order["coin"] == "ETH" && order["isTrigger"] == true)
            .collect();
        assert_eq!(stops.len(), 1, "round {round}: {stops:?}");
        assert_eq!(stops[0]["sz"], "0.05");
        assert_eq!(stops[0]["reduceOnly"], true);
    }
}

/// Within 2 s of a send the sync reads holding the lock at once: one read
/// a round, however soon the bot sends again.
#[tokio::test(flavor = "multi_thread")]
async fn soon_after_a_send_the_sync_reads_once_under_the_lock() {
    let running = start("stream-locked", false).await;
    let venue = running.guard.upstream();
    post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    venue.slow_reads(1_000);
    let reads = account_reads(venue);
    let after_read = stream_status(&running.guard).await["judged_after_read"]
        .as_u64()
        .unwrap();
    let guard = running.guard.clone();
    let sync = tokio::spawn(async move { guard.sync().await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // A cancel meanwhile waits for the sync's read (it holds the lock),
    // then is sent.
    let started = std::time::Instant::now();
    let reply = post(&running.url, &cancel(999_999)).await;
    assert!(started.elapsed() >= Duration::from_millis(800), "it waited");
    assert_eq!(reply["status"], "ok", "{reply}");
    sync.await.unwrap();
    // One read of both dexes by the sync, and one by the cancel if the
    // stream was not clean yet; the sync read nothing again.
    let cancel_read = stream_status(&running.guard).await["judged_after_read"]
        .as_u64()
        .unwrap()
        - after_read;
    assert_eq!(
        account_reads(venue) as u64,
        reads as u64 + 2 + 2 * cancel_read
    );
    assert_eq!(running.guard.status().await["last_sync_reads"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_overlapping_syncs_keep_the_risk_engines_time_order() {
    let running = start("stream-overlap", true).await;
    let venue = running.guard.upstream();
    // Sync A reads slowly; sync B starts later and reads fast, so B's
    // newer view arrives first.
    venue.slow_reads(1_500);
    let guard = running.guard.clone();
    let a = tokio::spawn(async move { guard.sync().await });
    tokio::time::sleep(Duration::from_millis(700)).await;
    venue.slow_reads(0);
    let b_started = SystemClock.now_ms();
    running.guard.sync().await;
    let after_b = running.guard.status().await["last_sync_ms"]
        .as_u64()
        .unwrap();
    assert!(after_b >= b_started);
    a.await.unwrap();
    // A's older view was not shown to the risk engine after B's: the view
    // on record is B's, read 0.8 s ago (A's was read 1.5 s ago).
    let after_a = running.guard.status().await["last_sync_ms"]
        .as_u64()
        .unwrap();
    assert_eq!(after_a, after_b);
    let preview = running
        .guard
        .preview(json!({"action": {"type": "scheduleCancel"}}))
        .await;
    assert!(
        preview["view_age_ms"].as_u64().unwrap() < 1_200,
        "{preview}"
    );
}

/// Equity 10,000 at the start of the day; a long BTC position whose loss
/// took the account to 9,500 (5%, under the 6% daily stop) in the last
/// snapshot. BTC then falls 1% with no snapshot since.
#[tokio::test]
async fn a_fall_after_the_snapshot_trips_the_daily_stop_and_flattens_from_a_fresh_read() {
    let running = start("stream-fall", true).await;
    let venue = running.guard.upstream();
    // 0.8 BTC at 60,000 (48,000, 4.8x of 10,000); the main dex's value
    // 8,500 with xyz's 1,000: 9,500.
    venue.add_position_at("BTC", "0.8", "60000");
    venue.add_order(
        json!({"coin": "BTC", "side": "A", "limitPx": "50000", "sz": "0.8",
        "oid": 555, "isTrigger": true, "triggerPx": "57000", "orderType": "Stop Market",
        "reduceOnly": true, "isPositionTpsl": false, "cloid": null, "children": []}),
    );
    venue.set_equity("8500");
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "{status}");
    // Let the stream follow BTC (its position) and ETH (an entry).
    post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let from_stream = stream_status(&running.guard).await["judged_from_stream"]
        .as_u64()
        .unwrap();
    // No snapshot from now on; BTC falls 1% to 59,400.
    venue.pause_ws_snapshots(true);
    tokio::time::sleep(Duration::from_millis(150)).await;
    venue.set_mid("BTC", "59400");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let reads = account_reads(venue);
    let reply = post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    // Judged from the stream: the snapshot said 9,500, but at the fresh
    // mark the account is 9,500 + 0.8 × (59,400 − 60,000) = 9,020, 9.8%
    // down on the day: the daily stop, once a ledger read at least 2 s on
    // shows no withdrawal (refused meanwhile).
    let status = stream_status(&running.guard).await;
    assert_eq!(status["judged_from_stream"], from_stream + 1, "{status}");
    assert_ne!(reply["status"], "ok", "{reply}");
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    // Revaluing the SAME paused account snapshot cannot end a hold (H2).
    // Fresh REST snapshots now include the480 main-dex mark loss. A new
    // ledger-confirmed run has a fresh venue clock and still flattens.
    venue.set_equity("8020");
    running.guard.sync().await;
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    running.guard.sync().await;
    let reply = post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    assert_ne!(reply["status"], "ok", "{reply}");
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "halted_for_day", "{status}");
    // The flatten (paper: journaled) came from a fresh read, not the stream.
    assert!(account_reads(venue) > reads, "a fresh read to flatten");
    let events = serde_json::to_string(&running.guard.events(0).await).unwrap();
    assert!(events.to_lowercase().contains("flatten"), "{events}");
}

/// Equity 10,000, so 600 of open risk (6%). A long of 2.5 ETH with its
/// stop at 2,880: 300 at risk from the 3,000 of the last snapshot. ETH
/// then rises 4.7% to 3,140 with no snapshot since: 650 at risk, over the
/// budget, so no new entry may add any.
#[tokio::test]
async fn open_risk_is_measured_from_fresh_mids() {
    let running = start("stream-open-risk", true).await;
    let venue = running.guard.upstream();
    venue.add_position_at("ETH", "2.5", "3000");
    venue.add_order(
        json!({"coin": "ETH", "side": "A", "limitPx": "2600", "sz": "2.5",
        "oid": 556, "isTrigger": true, "triggerPx": "2880", "orderType": "Stop Market",
        "reduceOnly": true, "isPositionTpsl": false, "cloid": null, "children": []}),
    );
    running.guard.sync().await;
    // Follow BTC with a first entry; the second is judged from the stream
    // and passes: 300 + its 200 is within 600.
    post(&running.url, &order(0, true, "60000", "0.01", false)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let reply = post(&running.url, &order(0, true, "60000", "0.01", false)).await;
    assert!(
        reply["response"]
            .as_str()
            .unwrap_or("")
            .contains("paper mode"),
        "{reply}"
    );
    let from_stream = stream_status(&running.guard).await["judged_from_stream"]
        .as_u64()
        .unwrap();
    // No snapshot from now on; ETH rises to 3,140.
    venue.pause_ws_snapshots(true);
    tokio::time::sleep(Duration::from_millis(150)).await;
    venue.set_mid("ETH", "3140");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let reply = post(&running.url, &order(0, true, "60000", "0.01", false)).await;
    let status = stream_status(&running.guard).await;
    assert_eq!(status["judged_from_stream"], from_stream + 1, "{status}");
    // 2.5 × (3,140 − 2,880) = 650 at risk already: refused.
    assert_eq!(reply["code"], "open_risk", "{reply}");
}

#[tokio::test]
async fn a_price_feed_that_stops_falls_back_to_a_read() {
    let running = start("stream-prices", true).await;
    let venue = running.guard.upstream();
    post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let reads = account_reads(venue);
    post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    assert_eq!(account_reads(venue), reads, "from the stream");
    // Snapshots go on, prices stop: after 1.5 s the mark is stale.
    venue.pause_ws_prices(true);
    tokio::time::sleep(Duration::from_millis(1_700)).await;
    post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    assert!(account_reads(venue) > reads, "read");
    let status = stream_status(&running.guard).await;
    assert!(
        status["last_fallback"].as_str().unwrap().contains("ms old"),
        "{status}"
    );
}

/// While killed, a bot that keeps sending must not spend the venue's
/// request limit on reads to flatten (the reads flattening itself needs):
/// over 4 s of requests, a flat account is not read at all, an exposed one
/// once (Guard's request budget as in production).
#[tokio::test]
async fn requests_while_killed_stay_within_the_read_budget() {
    for exposed in [false, true] {
        let running =
            start_with(&format!("stream-killed-{exposed}"), true, Limits::default()).await;
        let venue = running.guard.upstream();
        if exposed {
            venue.add_position("BTC", "0.01");
            running.guard.sync().await;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
        std::fs::write(running._dir.path().join("kill"), "test\n").unwrap();
        let reads = account_reads(venue);
        let before = stream_status(&running.guard).await["judged_from_stream"]
            .as_u64()
            .unwrap();
        // 40 cancels (1 of weight each), 100 ms apart: over 4 s, beyond the
        // 3 s between two reads to flatten.
        let started = std::time::Instant::now();
        for _ in 0..40 {
            post(&running.url, &cancel(999_999)).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(started.elapsed() > Duration::from_millis(4_000));
        let judged = stream_status(&running.guard).await["judged_from_stream"]
            .as_u64()
            .unwrap();
        assert!(judged >= before + 30, "{judged} {before}");
        // Each read is of both dexes: two `clearinghouseState`.
        let made = account_reads(venue) - reads;
        if exposed {
            assert_eq!(made, 2, "one read to flatten");
            let events = serde_json::to_string(&running.guard.events(0).await).unwrap();
            assert!(events.to_lowercase().contains("flatten"), "{events}");
        } else {
            assert_eq!(made, 0, "nothing to flatten, nothing read");
        }
    }
}

/// A halted request reads to flatten only within the request budget: with
/// the budget spent by a bot's cancels, the read is left to the sync.
#[tokio::test]
async fn a_halted_request_does_not_read_beyond_the_budget() {
    let running = start_with("stream-halt-budget", true, Limits::default()).await;
    let venue = running.guard.upstream();
    venue.add_position("BTC", "0.01");
    running.guard.sync().await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    // Cancels until the budget is spent (1 of weight each, 60 at most).
    let mut spent = false;
    for _ in 0..400 {
        let reply = post(&running.url, &cancel(999_999)).await;
        if reply.to_string().contains("rate_limited") {
            spent = true;
            break;
        }
    }
    assert!(spent, "the budget was never spent");
    // 0.3 s on: room for one more cancel (4 a second), not for a read (48).
    tokio::time::sleep(Duration::from_millis(300)).await;
    std::fs::write(running._dir.path().join("kill"), "test\n").unwrap();
    let reads = account_reads(venue);
    let reply = post(&running.url, &cancel(999_999)).await;
    assert!(!reply.to_string().contains("rate_limited"), "{reply}");
    assert_eq!(account_reads(venue), reads, "no read beyond the budget");
}

/// The stream's view may be flat while the last read showed a position (a
/// position the snapshots do not show yet): then a halted request reads.
#[tokio::test]
async fn a_halted_request_reads_when_the_last_read_showed_a_position() {
    let running = start("stream-halt-exposed", true).await;
    let venue = running.guard.upstream();
    tokio::time::sleep(Duration::from_millis(400)).await;
    // No snapshot from now on; a position appears, the sync reads it.
    venue.pause_ws_snapshots(true);
    venue.add_position("BTC", "0.01");
    running.guard.sync().await;
    std::fs::write(running._dir.path().join("kill"), "test\n").unwrap();
    let reads = account_reads(venue);
    let before = stream_status(&running.guard).await["judged_from_stream"]
        .as_u64()
        .unwrap();
    post(&running.url, &cancel(999_999)).await;
    let status = stream_status(&running.guard).await;
    assert_eq!(status["judged_from_stream"], before + 1, "{status}");
    assert_eq!(account_reads(venue), reads + 2, "read to flatten");
    let events = serde_json::to_string(&running.guard.events(0).await).unwrap();
    assert!(events.to_lowercase().contains("flatten"), "{events}");
}

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The reference data a sync read without the lock never replaces what a
/// request read later: `meta` read by a request at +62 s outlives the
/// sync's own of +61 s.
#[tokio::test(flavor = "multi_thread")]
async fn a_syncs_older_reference_data_never_replaces_a_requests_newer() {
    let dir = TestDir::new("stream-caches");
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: GuardMode::Paper,
        account: Some(ACCOUNT.to_owned()),
        api_wallet: Some(api_key().address().to_hex()),
        state_dir: dir.path().to_owned(),
        auth: AuthConfig {
            clients: vec![GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex()],
            ..AuthConfig::default()
        },
        ..GuardConfig::default()
    };
    let start = SystemClock.now_ms();
    let clock = TestClock(Arc::new(AtomicU64::new(start)));
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(true),
        config.policy.risk_limits(),
        &config.journal_scope(true).unwrap(),
        Timestamp::from_millis(start as i64),
        dec!(10000),
        "stream test",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(true)).unwrap();
    let venue = MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "10000",
    )
    .read_only();
    let guard = Guard::new(
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
        clock.clone(),
    )
    .unwrap();
    let metas = |guard: &Guard<MemoryVenue, TestClock>| {
        guard
            .upstream()
            .info_log()
            .iter()
            .filter(|body| body["type"] == "meta" && body.get("dex").is_none())
            .count()
    };
    guard.sync().await;
    // +61 s: the sync reads (meta again, then the account for 1.5 s).
    clock.0.store(start + 61_000, Ordering::SeqCst);
    guard.upstream().slow_reads(1_500);
    let syncing = guard.clone();
    let sync = tokio::spawn(async move { syncing.sync().await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    // +62 s: a request reads meta as well, with the lock.
    clock.0.store(start + 62_000, Ordering::SeqCst);
    let action = Wire::Map(vec![("type", Wire::str("scheduleCancel"))]);
    guard
        .exchange(signed_at(action, start + 62_000), "http")
        .await;
    sync.await.unwrap();
    guard.upstream().slow_reads(0);
    // +121.5 s: the request's meta (+62) is 59.5 s old, still good; the
    // sync's (+61) would be 60.5 s old, and read again.
    clock.0.store(start + 121_500, Ordering::SeqCst);
    let before = metas(&guard);
    let action = Wire::Map(vec![("type", Wire::str("scheduleCancel"))]);
    guard
        .exchange(signed_at(action, start + 121_500), "http")
        .await;
    assert_eq!(metas(&guard), before, "meta was still fresh");
}

fn reduce_only(asset: u64, is_buy: bool, price: &str, size: &str) -> Value {
    order(asset, is_buy, price, size, true)
}

/// On a spent request budget, reduce-only orders that go are charged into
/// debt: 5 at once and 1 a second on the allowance, then those that reduce
/// a position the last view shows (5 more, 1 a second); others are refused
/// (and cost nothing), and the debt holds off the bot's other requests.
#[tokio::test]
async fn exits_on_a_spent_budget_go_within_their_allowance() {
    let running = start_with("stream-exits", true, Limits::default()).await;
    let venue = running.guard.upstream();
    venue.add_position("ETH", "0.5");
    running.guard.sync().await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mut spent = false;
    for _ in 0..400 {
        if post(&running.url, &cancel(999_999))
            .await
            .to_string()
            .contains("rate_limited")
        {
            spent = true;
            break;
        }
    }
    assert!(spent);
    let through = |reply: &Value| !reply.to_string().contains("rate_limited");
    // The allowance's 5: any reduce-only order.
    let mut passed = 0;
    for _ in 0..6 {
        let reply = post(&running.url, &reduce_only(1, false, "2900", "0.1")).await;
        if through(&reply) {
            passed += 1;
        }
    }
    assert!((5..=6).contains(&passed), "{passed} of 6");
    // Beyond it, with room for 5 more that reduce a known position: a
    // reduce-only BTC buy (no BTC position) and a reduce-only ETH buy (the
    // same side as the long) reduce nothing, and are refused ...
    let reply = post(&running.url, &reduce_only(0, true, "61000", "0.01")).await;
    assert!(!through(&reply), "{reply}");
    let reply = post(&running.url, &reduce_only(1, true, "3100", "0.1")).await;
    assert!(!through(&reply), "{reply}");
    // ... while ETH sells, which reduce the long, still go.
    let mut passed = 0;
    for _ in 0..5 {
        let reply = post(&running.url, &reduce_only(1, false, "2900", "0.1")).await;
        if through(&reply) {
            passed += 1;
        }
    }
    assert!(passed >= 4, "{passed} of 5");
    // The exits that went were charged: the bot's cancels wait for the
    // debt.
    let reply = post(&running.url, &cancel(999_999)).await;
    assert!(!through(&reply), "{reply}");
    // Refused exits cost nothing: 30 more BTC buys, refused but for the
    // odd one the allowance's 1 a second lets through on a slow machine,
    // and the debt of the dozen or so that went is paid back within 4 s
    // (4 a second).
    let mut refused = 0;
    for _ in 0..30 {
        let reply = post(&running.url, &reduce_only(0, true, "61000", "0.01")).await;
        if !through(&reply) {
            refused += 1;
        }
    }
    assert!(refused >= 25, "{refused} of 30 refused");
    tokio::time::sleep(Duration::from_millis(4_000)).await;
    let reply = post(&running.url, &cancel(999_999)).await;
    assert!(through(&reply), "{reply}");
}

/// The exit allowances count the venue's weight: a batch of 41 reduce-only
/// orders weighs 2, so 2 of them fit the allowance's 5 and 2 more the
/// known position's 5, not 10.
#[tokio::test]
async fn the_exit_allowances_count_weight() {
    let running = start_with("stream-exits-weight", true, Limits::default()).await;
    let venue = running.guard.upstream();
    venue.add_position("ETH", "5");
    running.guard.sync().await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mut spent = false;
    for _ in 0..400 {
        if post(&running.url, &cancel(999_999))
            .await
            .to_string()
            .contains("rate_limited")
        {
            spent = true;
            break;
        }
    }
    assert!(spent);
    let mut passed = 0;
    for _ in 0..8 {
        let reply = post(&running.url, &reduce_only_batch(41)).await;
        if !reply.to_string().contains("rate_limited") {
            passed += 1;
        }
    }
    assert!((4..=5).contains(&passed), "{passed} of 8");
}

/// The same when the stream is not clean and the read itself is over
/// budget (Guard sending): reduce-only orders go unjudged within the
/// allowance, then only those that reduce a position the last view shows.
#[tokio::test]
async fn exits_after_a_refused_read_go_within_their_allowance() {
    // Hold the budget clock fixed: signing, journal fsync and HTTP latency
    // must not refill the allowance while this test spends its initial burst.
    // Real HTTP and WebSocket transport still run normally.
    let start = SystemClock.now_ms();
    let clock = TestClock(Arc::new(AtomicU64::new(start)));
    let running = start_syncing_with_clock(
        "stream-exits-read",
        false,
        Limits::default(),
        &["*", "xyz:*"],
        None,
        clock.clone(),
    )
    .await;
    // Keep the original restart nonce floor (+5 s) and nonce windows.
    let now = start + 5_100;
    clock.0.store(now, Ordering::SeqCst);
    let mut nonce = now;
    let mut sign = |body: Value| {
        nonce += 1;
        let action = zunder_guard_core::action::decode_action_value(&body["action"]).unwrap();
        signed_at(action.to_wire(), nonce)
    };
    let venue = running.guard.upstream();
    venue.add_position("ETH", "5");
    running.guard.sync().await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    // Cancels (sent) until the budget is spent; each send leaves the
    // stream unclean, so the next request needs a read.
    let mut spent = false;
    for _ in 0..100 {
        if post(&running.url, &sign(cancel(999_999)))
            .await
            .to_string()
            .contains("rate_limited")
        {
            spent = true;
            break;
        }
    }
    assert!(spent);
    // More than one real refill interval passes, without budget time advancing.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    // A read needs 48, so up to 47 may be left: reduce-only BTC buys (no
    // BTC position) go on that, then on the allowance, then are refused.
    let mut refused = false;
    for _ in 0..80 {
        let reply = post(&running.url, &sign(reduce_only(0, true, "61000", "0.01"))).await;
        if reply.to_string().contains("rate_limited") {
            refused = true;
            break;
        }
    }
    assert!(
        refused,
        "a reduce-only order that reduces nothing is refused"
    );
    // An ETH sell, which reduces the long Guard saw, still goes.
    let reply = post(&running.url, &sign(reduce_only(1, false, "2900", "0.1"))).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        clock.now_ms(),
        now,
        "request latency cannot refill the budget"
    );
}

/// A stop refused by HTTP status (the venue's 429) was not placed: Guard
/// does not spend weight looking for it, and closes the position.
#[tokio::test]
async fn a_stop_refused_by_status_is_not_looked_for() {
    let running = start("stream-429", false).await;
    let venue = running.guard.upstream();
    venue.add_position("ETH", "0.5");
    venue.stop_status(429);
    let lookups = venue_reads(venue, "frontendOpenOrders");
    running.guard.sync().await;
    // The sync's own read of both dexes, and no lookup after the 429.
    assert_eq!(venue_reads(venue, "frontendOpenOrders"), lookups + 2);
    assert!(venue.positions().is_empty(), "{:?}", venue.positions());
}

/// A second entry on a coin the stream shows set to isolated at the
/// leverage the entry allows sends no `updateLeverage` first.
#[tokio::test]
async fn a_kept_leverage_setting_saves_the_update() {
    let running = start("stream-leverage", false).await;
    let venue = running.guard.upstream();
    let leverage_updates = |venue: &MemoryVenue| {
        venue
            .received()
            .iter()
            .filter(|received| {
                matches!(
                    received.action,
                    zunder_guard_core::action::Action::UpdateLeverage { .. }
                )
            })
            .count()
    };
    // An ETH entry (IOC, fills): isolated 5x set first. Then closed.
    let reply = post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(leverage_updates(venue), 1);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let reply = post(&running.url, &reduce_only(1, false, "2900", "100")).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert!(venue.positions().is_empty(), "{:?}", venue.positions());
    // Once the stream is clean again, a new entry: judged from the
    // stream, which shows ETH at isolated 5x; nothing sent first.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let before = stream_status(&running.guard).await["judged_from_stream"]
        .as_u64()
        .unwrap();
    let reply = post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        stream_status(&running.guard).await["judged_from_stream"],
        before + 1
    );
    assert_eq!(leverage_updates(venue), 1, "no second update");
}

/// The settle window counts from when the view was read: a stream view of
/// snapshots 4.7 s old, judged 6.5 s after Guard's send, is not settled,
/// so the risk engine keeps the position it recorded although the view no
/// longer shows it.
#[tokio::test]
async fn the_settle_window_counts_from_the_views_own_time() {
    let running = start("stream-settle", false).await;
    let venue = running.guard.upstream();
    let reply = post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = std::time::Instant::now();
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["tracked"], 1, "{status}");
    // The position goes (a stop fired) with no event; the snapshots show
    // it gone, then stop.
    tokio::time::sleep(Duration::from_millis(1_400)).await;
    venue.clear_positions();
    tokio::time::sleep(Duration::from_millis(400)).await;
    venue.pause_ws_snapshots(true);
    // 6.5 s after the send: judged from the stream, whose snapshots were
    // taken about 1.8 s after it.
    tokio::time::sleep(Duration::from_millis(6_500).saturating_sub(sent.elapsed())).await;
    let before = stream_status(&running.guard).await["judged_from_stream"]
        .as_u64()
        .unwrap();
    post(&running.url, &cancel(999_999)).await;
    let status = stream_status(&running.guard).await;
    assert_eq!(status["judged_from_stream"], before + 1, "{status}");
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["tracked"], 1, "not settled: {status}");
}

/// How many entries a minute a bot gets through Guard, with the venue's
/// cadence (snapshots every 5 s, prices every 0.5 s), Guard's request
/// budget as in production, and the in-memory venue filling every entry: a
/// bot that sends a small BTC entry every 250 ms for 60 s. Quiet: the bot
/// alone on its account; busy: another app's order on the account every
/// 2 s. Ignored (2 minutes): run with
/// `cargo test -p zunder-guard --test stream sustained -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "two minutes; a measurement"]
async fn sustained_entries_a_minute() {
    for (busy, after_entry) in [
        (false, Some(1_000)),
        (true, Some(1_000)),
        (false, None),
        (true, None),
    ] {
        let running = start_with(
            &format!("stream-throughput-{busy}-{after_entry:?}"),
            false,
            Limits::default(),
        )
        .await;
        let venue = running.guard.upstream();
        drop(running.ws);
        let ws = serve_ws(running.guard.clone(), 500).await;
        venue.ws_snapshot_every(10);
        venue.ws_snapshot_after_entry(after_entry);
        tokio::time::sleep(Duration::from_millis(6_000)).await;
        let outside = busy.then(|| {
            let guard = running.guard.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(2_000)).await;
                    guard.upstream().outside_event();
                }
            })
        });
        let (mut sent, mut limited, mut other) = (0, 0, 0);
        let mut latencies = Vec::new();
        let until = std::time::Instant::now() + Duration::from_secs(60);
        while std::time::Instant::now() < until {
            let started = std::time::Instant::now();
            let reply = post(&running.url, &order(0, true, "60000", "0.001", false)).await;
            latencies.push(started.elapsed().as_micros());
            if reply["status"] == "ok" {
                sent += 1;
            } else if reply.to_string().contains("rate_limited") {
                limited += 1;
            } else {
                other += 1;
                println!("other: {reply}");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        if let Some(outside) = outside {
            outside.abort();
        }
        ws.abort();
        latencies.sort_unstable();
        let status = stream_status(&running.guard).await;
        println!(
            "{} (snapshots after an entry: {after_entry:?} ms): {sent} entries sent in 60 s, {limited} rate_limited, {other} other; latency p50 {:.1} ms; stream {status}",
            if busy { "busy" } else { "quiet" },
            latencies[latencies.len() / 2] as f64 / 1000.0,
        );
    }
}

async fn info(url: &str, body: &Value) -> Value {
    let text = reqwest::Client::new()
        .post(format!("{url}/info"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// How many times the venue was asked `kind` over HTTP.
fn venue_reads(venue: &MemoryVenue, kind: &str) -> usize {
    venue
        .info_log()
        .iter()
        .filter(|body| body["type"] == kind)
        .count()
}

/// The bot's own account reads are answered from the stream while it is
/// clean, as the venue's socket sent them (not revalued); anything else,
/// and everything after an event Guard did not cause, from the venue.
#[tokio::test]
async fn the_bots_own_account_reads_come_from_a_clean_stream() {
    let running = start("stream-info", true).await;
    let venue = running.guard.upstream();
    // A long of 0.5 ETH from 3,000; the mark (the mid) at 3,000.
    venue.add_position_at("ETH", "0.5", "3000");
    running.guard.sync().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let ask = json!({"type": "clearinghouseState", "user": ACCOUNT});
    let reads = venue_reads(venue, "clearinghouseState");
    let orders_read = venue_reads(venue, "frontendOpenOrders");
    let state = info(&running.url, &ask).await;
    assert_eq!(
        venue_reads(venue, "clearinghouseState"),
        reads,
        "from the stream"
    );
    assert_eq!(state["marginSummary"]["accountValue"], "9000");
    // ETH's mark moves to 3,100 while its mid stays at 3,000: the bot gets
    // the snapshot as the venue sent it (9,000 until the venue's next
    // snapshot), not a revalued one (9,050), and its time.
    venue.pause_ws_snapshots(true);
    tokio::time::sleep(Duration::from_millis(150)).await;
    venue.set_mark("ETH", "3100");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let state = info(&running.url, &ask).await;
    assert_eq!(state["marginSummary"]["accountValue"], "9000", "{state}");
    assert!(state["time"].is_u64(), "{state}");
    assert_eq!(venue_reads(venue, "clearinghouseState"), reads);
    // Its open orders too, and xyz's account by its dex.
    let orders = info(
        &running.url,
        &json!({"type": "frontendOpenOrders", "user": ACCOUNT}),
    )
    .await;
    assert!(orders.is_array(), "{orders}");
    let xyz = info(
        &running.url,
        &json!({"type": "clearinghouseState", "user": ACCOUNT, "dex": "xyz"}),
    )
    .await;
    assert_eq!(xyz["marginSummary"]["accountValue"], "1000");
    assert_eq!(venue_reads(venue, "clearinghouseState"), reads);
    assert_eq!(venue_reads(venue, "frontendOpenOrders"), orders_read);
    assert_eq!(stream_status(&running.guard).await["info_from_stream"], 4);
    // Another account, or another request: from the venue.
    info(
        &running.url,
        &json!({"type": "clearinghouseState", "user": "0x0000000000000000000000000000000000000001"}),
    )
    .await;
    assert_eq!(venue_reads(venue, "clearinghouseState"), reads + 1);
    let opens = venue_reads(venue, "openOrders");
    info(
        &running.url,
        &json!({"type": "openOrders", "user": ACCOUNT}),
    )
    .await;
    assert_eq!(venue_reads(venue, "openOrders"), opens + 1);
    // An event Guard did not cause (another app's order): the snapshots
    // predate it, so the venue answers.
    venue.outside_event();
    tokio::time::sleep(Duration::from_millis(300)).await;
    info(&running.url, &ask).await;
    assert_eq!(venue_reads(venue, "clearinghouseState"), reads + 2);
}

/// Deposits and withdrawals are kept out of the account stops (default
/// rules: a 6% daily stop). Account 9,000 on the main dex and 1,000 on xyz:
/// 10,000 at the day's start.
#[tokio::test]
async fn a_withdrawal_never_halts_and_a_loss_still_does() {
    let running = start("stream-withdrawal", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    // 1,000 withdrawn (10%), which the socket does not report: the sync's
    // read would halt the engine, so the ledger is read first. The read,
    // as of less than 2 s after the withdrawal, may or may not show it: not
    // taken. One 2 s on shows it: the withdrawal is applied first, no loss.
    tokio::time::sleep(Duration::from_millis(20)).await;
    venue.flow("-1000", true);
    // Exact reconstruction needs anchor ordering strictly after the flow;
    // a same-millisecond ledger/state boundary is deliberately unknown.
    tokio::time::sleep(Duration::from_millis(2)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "{status}");
    assert_eq!(status["risk"]["flows_applied"], 0, "{status}");
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "{status}");
    assert_eq!(status["risk"]["flows_applied"], 1, "{status}");
    assert_eq!(status["risk"]["peak"], "9000", "{status}");
    // A trading loss of 10% of what is left (900 of 9,000) halts it, once
    // the ledger, read again at least 2 s after the first view of it (the
    // ledger may be served a little behind the account), shows no flow.
    venue.set_equity("7100");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "held: {status}");
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "halted_for_day", "{status}");
}

/// A one-second wick, held, counts when it goes (it was trading: a
/// withdrawal does not come back), and a later withdrawal that would stop
/// Guard, shown before a lagging ledger has it, is held and applied: a
/// fresh run, checked only by a read 2 s into it (the fifth review's M1),
/// also within 10-12 s of the wick (the seventh review's M2). The ledger is
/// served a second behind; 3,000 withdrawn (30%), not on the socket.
async fn a_wick_then_a_withdrawal(name: &str, after_ms: u64) {
    let running = start(name, true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.lag_ledger(1_000);
    venue.set_equity("8000");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "held: {status}");
    venue.set_equity("9000");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(
        status["risk"]["state"], "halted_for_day",
        "the wick counts: {status}"
    );
    tokio::time::sleep(Duration::from_millis(after_ms)).await;
    venue.flow("-3000", true);
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "halted_for_day", "held: {status}");
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "halted_for_day", "{status}");
    assert_eq!(status["risk"]["flows_applied"], 1, "{status}");
}

#[tokio::test]
async fn a_withdrawal_ten_seconds_after_a_wick_is_held_for_the_ledger() {
    a_wick_then_a_withdrawal("stream-wick-10", 8_300).await;
}

#[tokio::test]
async fn a_withdrawal_twenty_seconds_after_a_wick_is_held_for_the_ledger() {
    a_wick_then_a_withdrawal("stream-wick-20", 18_000).await;
}

/// With the background sync every 13 s or 30 s (HIP-3, a small share), a
/// loss is looked at again every second while held: a loss that goes at
/// once is counted at the next look, one that stays within 2 s with the
/// ledger working and 10 s with it down. The state after `wait_ms`.
async fn slow_sync(
    name: &str,
    seconds: u64,
    ledger_down: bool,
    goes: bool,
    wait_ms: u64,
) -> String {
    let limits = Limits {
        request_weight_per_second: 1_000_000,
        request_weight_burst: 1_000_000,
    };
    let running = start_syncing(name, true, limits, &["*", "xyz:*"], Some(seconds)).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.fail_ledger(ledger_down);
    // 10% down (main dex 8,000) for the first tick.
    venue.set_equity("8000");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let sync = tokio::spawn(running.guard.clone().sync_forever());
    if goes {
        tokio::time::sleep(Duration::from_millis(400)).await;
        venue.set_equity("9000");
    }
    tokio::time::sleep(Duration::from_millis(wait_ms)).await;
    let status = running.guard.status().await;
    sync.abort();
    status["risk"]["state"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn with_a_slow_sync_a_loss_that_goes_at_once_is_counted_at_the_next_look() {
    for seconds in [13, 30] {
        for down in [false, true] {
            let state = slow_sync(
                &format!("stream-slow-go-{seconds}-{down}"),
                seconds,
                down,
                true,
                2_000,
            )
            .await;
            assert_eq!(state, "halted_for_day", "{seconds} s, ledger down {down}");
        }
    }
}

#[tokio::test]
async fn with_a_slow_sync_a_loss_that_stays_is_counted_within_the_hold() {
    for seconds in [13, 30] {
        let state = slow_sync(
            &format!("stream-slow-up-{seconds}"),
            seconds,
            false,
            false,
            3_500,
        )
        .await;
        assert_eq!(state, "halted_for_day", "{seconds} s, ledger up");
        let state = slow_sync(
            &format!("stream-slow-down-{seconds}"),
            seconds,
            true,
            false,
            11_500,
        )
        .await;
        assert_eq!(state, "halted_for_day", "{seconds} s, ledger down");
    }
}

/// A loss that crosses the line back and forth, a view every 1.1 s: the
/// 10 s a loss is held for the ledger keep counting across the flat views
/// in between (D5: a loss hovering at the line cannot stretch it), with the
/// ledger working or down. The round at which Guard was no longer active.
async fn alternate(name: &str, pattern: &[&str], ledger_down: bool) -> Option<usize> {
    let running = start(name, true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.fail_ledger(ledger_down);
    for round in 0..16 {
        venue.set_equity(pattern[round % pattern.len()]);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        running.guard.sync().await;
        let status = running.guard.status().await;
        if status["risk"]["state"] != "active" {
            return Some(round);
        }
    }
    None
}

/// The fifth review's follow-up (H1): 10% down (main dex 8,000) and flat
/// (9,000) in turn; two down, one flat. Counted within the 10 s of the hold
/// plus a view (round 10 at the latest: 12.1 s).
#[tokio::test]
async fn a_loss_crossing_the_line_back_and_forth_is_counted_within_the_hold() {
    for (name, pattern) in [
        ("alt-1", &["8000", "9000"][..]),
        ("alt-2", &["8000", "8000", "9000"][..]),
    ] {
        for down in [false, true] {
            let round = alternate(&format!("stream-{name}-{down}"), pattern, down).await;
            assert!(
                round.is_some_and(|round| round <= 10),
                "{name}, ledger down {down}: {round:?}"
            );
        }
    }
}

/// 30% down (main dex 6,000) and flat in turn: stopped within the hold.
#[tokio::test]
async fn a_drawdown_crossing_the_line_back_and_forth_stops_within_the_hold() {
    let running = start("stream-alt-stop", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    let mut stopped = None;
    for round in 0..16 {
        venue.set_equity(["6000", "9000"][round % 2]);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        running.guard.sync().await;
        let status = running.guard.status().await;
        if status["risk"]["state"] == "stopped" {
            stopped = Some(round);
            break;
        }
        assert_eq!(status["risk"]["state"], "active", "{status}");
    }
    assert!(stopped.is_some_and(|round| round <= 10), "{stopped:?}");
}

/// A loss next to a withdrawal that stops on one reading and not on the
/// other halts the day, and Guard says so: an event and an alert with both
/// drawdowns. 8,000 withdrawn from the main dex (on the socket), and 600
/// lost before the next view: 6% of 10,000 before it, 30% of 2,000 after.
#[tokio::test]
async fn a_waived_drawdown_stop_halts_the_day_and_is_told() {
    let running = start("stream-waived", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    venue.fail_flow_records(true);
    venue.flow("-8000", false);
    venue.set_equity("400");
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    running.guard.sync().await;
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "halted_for_day", "{status}");
    let alerts = status["alerts"].to_string();
    assert!(
        alerts.contains("account value at a flow is uncertain"),
        "{status}"
    );
    let events = serde_json::to_string(&running.guard.events(0).await).unwrap();
    assert!(
        events.contains("account value at a flow is uncertain"),
        "{events}"
    );
}

/// While a loss is held for the ledger, Guard looks again every second: the
/// halt comes about 2 s after the first view of it, not a sync interval
/// (here 11.6 s, with a HIP-3 dex) later.
#[tokio::test]
async fn a_held_loss_is_looked_at_again_every_second() {
    let running = start("stream-hold-resync", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    // 10% down (main dex 9,000 to 8,000), no flow.
    venue.set_equity("8000");
    let sync = tokio::spawn(running.guard.clone().sync_forever());
    tokio::time::sleep(Duration::from_millis(3_500)).await;
    let status = running.guard.status().await;
    sync.abort();
    assert_eq!(status["risk"]["state"], "halted_for_day", "{status}");
}

/// The ledger may be served a little behind the account: a read begun less
/// than 2 s after the first view that would halt the engine does not clear
/// that view's loss, so a withdrawal the read missed is still recognised.
#[tokio::test]
async fn a_ledger_read_right_after_a_loss_does_not_clear_it() {
    let running = start("stream-ledger-lag", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.lag_ledger(1_000);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    // 1,000 withdrawn (10%), not on the socket; the view shows it at once,
    // the ledger a second later.
    venue.flow("-1000", true);
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "held: {status}");
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "{status}");
    assert_eq!(status["risk"]["flows_applied"], 1, "{status}");
}

/// While the ledger cannot be read, a loss that would halt the engine is
/// held back (it might be a withdrawal) for at most 10 s, then counted.
#[tokio::test]
async fn a_loss_waits_for_the_ledger_ten_seconds_at_most() {
    let running = start("stream-ledger-down", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.fail_ledger(true);
    // 10% lost (main dex 9,000 to 8,000), no flow.
    venue.set_equity("8000");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "held: {status}");
    // Meanwhile no new position: an entry is refused, a cancel judged.
    let reply = post(&running.url, &order(1, true, "3000", "0.01", false)).await;
    assert!(reply.to_string().contains("account_unreadable"), "{reply}");
    let reply = post(&running.url, &cancel(999_999)).await;
    assert!(!reply.to_string().contains("account_unreadable"), "{reply}");
    tokio::time::sleep(Duration::from_millis(10_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "halted_for_day", "{status}");
}

/// The deepest view of a held run counts when the run ends: with the
/// ledger down, 10% down (held), then 30% down (held), then flat: the 30%
/// view goes to the engine, a drawdown stop.
#[tokio::test]
async fn the_deepest_view_of_a_held_loss_counts_when_it_goes() {
    let running = start("stream-hold-deepest", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.fail_ledger(true);
    for equity in ["8000", "6000"] {
        venue.set_equity(equity);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        running.guard.sync().await;
        let status = running.guard.status().await;
        assert_eq!(status["risk"]["state"], "active", "held: {status}");
    }
    venue.set_equity("9000");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "stopped", "{status}");
}

/// With the ledger down, a loss that would halt the engine and then goes
/// (a loss hovering at the line) is counted when it goes: it was trading,
/// a withdrawal does not come back. It cannot stretch the hold.
#[tokio::test]
async fn a_loss_hovering_at_the_line_is_counted_when_it_goes() {
    let running = start("stream-ledger-hover", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.fail_ledger(true);
    // 10% down (main dex 9,000 to 8,000): held.
    venue.set_equity("8000");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "held: {status}");
    // Back at 10,000: the held view goes to the engine first.
    venue.set_equity("9000");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "halted_for_day", "{status}");
}

/// A complete ledger read that explains a held loss ends the hold: a later
/// loss, with the ledger down again, waits its own 10 s (not counted at once
/// from the first hold).
#[tokio::test]
async fn a_read_that_explains_a_held_loss_ends_the_hold() {
    let running = start("stream-hold-reset", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.fail_ledger(true);
    tokio::time::sleep(Duration::from_millis(20)).await;
    // 1,000 withdrawn (10%), only on the HTTP ledger, which fails: held.
    venue.flow("-1000", true);
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "held: {status}");
    // The ledger answers: the withdrawal explains it, the hold ends.
    venue.fail_ledger(false);
    tokio::time::sleep(Duration::from_millis(3_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["flows_applied"], 1, "{status}");
    assert_eq!(status["risk"]["state"], "active", "{status}");
    // 10 s on, the ledger down again and 10% lost (8,000 to 7,100 on the
    // main dex, 9,000 to 8,100 in all): held again, not counted at once.
    tokio::time::sleep(Duration::from_millis(8_000)).await;
    venue.fail_ledger(true);
    venue.set_equity("7100");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "held again: {status}");
}

/// Guard asks whether a view would halt the engine with its dexes' venue
/// times, so a flow it knows of but no view shows yet does not hide a loss
/// from the ledger check: with the ledger down, a 10% trading loss is held.
#[tokio::test]
async fn a_known_flow_not_yet_shown_does_not_skip_the_ledger_check() {
    let running = start("stream-pending-check", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    // A deposit booked 5 s ahead, reported on the socket: known, and in no
    // view yet (each view is more than 2 s before it).
    let ahead = SystemClock.now_ms() as i64 + 5_000;
    venue.flow_at("0.01", ahead, false);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    venue.fail_ledger(true);
    // 10% lost on the main dex (9,000.01 to 8,000.01).
    venue.set_equity("8000.01");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "active", "held: {status}");
}

/// Views older than one already seen (the venue's time of the account gone
/// back) are ignored; for 10 s of them the engine sees nothing new, and new
/// positions are refused.
#[tokio::test]
async fn views_older_than_one_seen_for_ten_seconds_refuse_new_positions() {
    let running = start("stream-time-back", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.hold_account_time(Some(SystemClock.now_ms() as i64 - 60_000));
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    let entry = || order(1, true, "3000", "0.01", false);
    let reply = post(&running.url, &entry()).await;
    assert!(!reply.to_string().contains("account_unreadable"), "{reply}");
    tokio::time::sleep(Duration::from_millis(10_100)).await;
    running.guard.sync().await;
    let reply = post(&running.url, &entry()).await;
    assert!(reply.to_string().contains("account_unreadable"), "{reply}");
}

/// While every view for 10 s may or may not show a withdrawal Guard knows
/// of (the venue's time of the account stuck within 2 s of it), the risk
/// engine sees nothing new: no new positions; once a view shows it, they
/// go again.
#[tokio::test]
async fn views_that_cannot_tell_a_flow_for_ten_seconds_refuse_new_positions() {
    let running = start("stream-stuck-time", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let before = SystemClock.now_ms() as i64;
    venue.flow("-100", false);
    venue.hold_account_time(Some(before + 600));
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    running.guard.sync().await;
    let entry = || order(1, true, "3000", "0.01", false);
    let reply = post(&running.url, &entry()).await;
    assert!(!reply.to_string().contains("account_unreadable"), "{reply}");
    tokio::time::sleep(Duration::from_millis(10_100)).await;
    running.guard.sync().await;
    let reply = post(&running.url, &entry()).await;
    assert!(reply.to_string().contains("account_unreadable"), "{reply}");
    // The account's time moves on: the view shows the withdrawal.
    venue.hold_account_time(None);
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["flows_applied"], 1, "{status}");
    let reply = post(&running.url, &entry()).await;
    assert!(!reply.to_string().contains("account_unreadable"), "{reply}");
}

/// A flow applied before a restart is not applied again after it: the
/// journal knows it (its `flowed` records), and the ledger read again from
/// before it brings it as a duplicate.
#[tokio::test]
async fn a_flow_is_not_applied_again_after_a_restart() {
    let running = start("stream-flow-restart", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    venue.flow("-2000", true);
    tokio::time::sleep(Duration::from_millis(2)).await;
    running.guard.sync().await;
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["flows_applied"], 1, "{status}");
    // 10,000 × 8,000 / 10,000.
    assert_eq!(status["risk"]["peak"], "8000", "{status}");
    // The journal, copied (the running Guard holds its lock), reopened with
    // flows as a restarted Guard opens it.
    let path = running._dir.path().join("risk-paper.jsonl");
    let records = zunder_venue::PersistentRisk::read(&path).unwrap();
    let copy = running._dir.path().join("risk-copy.jsonl");
    std::fs::copy(&path, &copy).unwrap();
    let scope = zunder_venue::JournalScope {
        network: "paper-testnet".into(),
        account: ACCOUNT.into(),
    };
    let mut reopened =
        zunder_venue::PersistentRisk::open_for(&copy, &Policy::default().risk_limits(), &scope)
            .unwrap()
            .with_flows();
    assert!(
        records
            .iter()
            .any(|record| matches!(record.event, zunder_venue::JournalEvent::Flowed { .. }))
    );
    assert!(reopened.flows_from_ms() <= venue_ledger_flow(&records).time_ms);
    let ledger = venue_ledger_flow(&records);
    assert_eq!(
        reopened
            .apply_flow(Timestamp::from_millis(SystemClock.now_ms() as i64), &ledger)
            .unwrap(),
        zunder_venue::FlowOutcome::Duplicate
    );
    assert_eq!(reopened.engine().peak(), dec!(8000));
}

/// The flow a journal's `flowed` record lists, as the ledger would bring it
/// again.
fn venue_ledger_flow(records: &[zunder_venue::JournalRecord]) -> zunder_venue::Flow {
    records
        .iter()
        .find_map(|record| match &record.event {
            zunder_venue::JournalEvent::Flowed { flows, .. } => flows.first().cloned(),
            _ => None,
        })
        .unwrap()
}

/// A deposit, reported on the socket, raises the day's start: a loss of 7%
/// with 500 deposited after it is still a loss of 7%.
#[tokio::test]
async fn a_deposit_does_not_hide_a_days_loss() {
    let running = start("stream-deposit", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    // A loss of 700 (main dex 9,000 to 8,300), then 500 deposited: 8,800
    // and xyz's 1,000, 9,800 in all, the next view. Where the 700 went is
    // not known: before the deposit it is 700 of 10,000 (7%), after it 700
    // of 10,500 (6.67%); both over the 6% daily stop.
    tokio::time::sleep(Duration::from_millis(20)).await;
    venue.set_equity("8300");
    venue.flow("500", false);
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["flows_applied"], 1, "{status}");
    assert_eq!(status["risk"]["state"], "halted_for_day", "{status}");
}

/// Right after Guard's own fill the bot's read of its account goes to the
/// venue, not to a stream whose snapshot predates the fill; and a read with
/// a field Guard does not know goes to the venue too.
#[tokio::test]
async fn the_bots_reads_after_a_send_or_with_other_fields_go_to_the_venue() {
    let running = start("stream-info-send", false).await;
    let venue = running.guard.upstream();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let ask = json!({"type": "clearinghouseState", "user": ACCOUNT});
    let reads = venue_reads(venue, "clearinghouseState");
    info(&running.url, &ask).await;
    assert_eq!(
        venue_reads(venue, "clearinghouseState"),
        reads,
        "from the stream"
    );
    // No snapshot from now on: the stream's predates the entry below.
    venue.pause_ws_snapshots(true);
    let reply = post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let reads = venue_reads(venue, "clearinghouseState");
    let state = info(&running.url, &ask).await;
    assert_eq!(
        venue_reads(venue, "clearinghouseState"),
        reads + 1,
        "from the venue"
    );
    // The venue's answer shows the position the stream does not.
    assert_eq!(
        state["assetPositions"].as_array().unwrap().len(),
        1,
        "{state}"
    );
    // A field Guard does not know: the venue answers.
    venue.pause_ws_snapshots(false);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let reads = venue_reads(venue, "clearinghouseState");
    info(
        &running.url,
        &json!({"type": "clearinghouseState", "user": ACCOUNT, "extra": 1}),
    )
    .await;
    assert_eq!(venue_reads(venue, "clearinghouseState"), reads + 1);
}

/// After Guard's own send the stream is clean again as soon as the socket
/// reported what the send did and the account's snapshots followed,
/// without the 1 s wait: with the venue's periodic snapshots every 5 s and
/// those after an entry 0.3 s later (0.6 to 1.4 s recorded on testnet), a
/// request 0.7 s after a filled entry is judged from the stream, where the
/// old rule needed a snapshot at least 1 s after the send. Its mark differs
/// from its mid, as on the venue. An event Guard did not cause, or a send
/// whose outcome is unknown (an HTTP error), sends the next request to the
/// venue again.
#[tokio::test]
async fn after_its_own_reported_send_guard_judges_from_the_stream_at_once() {
    let running = start("stream-own-send", false).await;
    let venue = running.guard.upstream();
    venue.ws_snapshot_every(50);
    venue.ws_snapshot_after_entry(Some(300));
    venue.set_mark("ETH", "3001");
    post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let reply = post(&running.url, &order(1, true, "3000", "0.01", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    tokio::time::sleep(Duration::from_millis(700)).await;
    let before = stream_status(&running.guard).await["judged_from_stream"]
        .as_u64()
        .unwrap();
    let reads = account_reads(venue);
    let reply = post(&running.url, &order(1, true, "3000", "0.01", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let status = stream_status(&running.guard).await;
    assert_eq!(status["judged_from_stream"], before + 1, "{status}");
    assert_eq!(account_reads(venue), reads, "no read");
    // Another app's order: the next request reads.
    tokio::time::sleep(Duration::from_millis(300)).await;
    venue.outside_event();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let reads = account_reads(venue);
    post(&running.url, &cancel(999_999)).await;
    assert!(account_reads(venue) > reads, "read after an outside event");
    // A send that got an HTTP error (its outcome unknown): the next
    // request reads too.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    venue.stop_status(429);
    post(&running.url, &order(1, true, "3000", "0.01", false)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let reads = account_reads(venue);
    post(&running.url, &cancel(999_999)).await;
    assert!(
        account_reads(venue) > reads,
        "read after an unknown outcome"
    );
}

/// The production budget fits the HIP-3 dexes Guard reads
/// (`Limits::for_hip3_dexes`, applied when the default is given): with two
/// HIP-3 dexes and the stream not clean, a HIP-3 entry on a full budget
/// reads every dex (72), the book (2), sets isolated leverage (22) and
/// goes, within the burst of 100, where the main dex's burst of 60 would
/// refuse every such request for ever.
#[tokio::test]
async fn the_default_budget_fits_two_hip3_dexes() {
    let running = start_markets(
        "stream-hip3-budget",
        false,
        Limits::default(),
        &["*", "xyz:*", "abc:*"],
    )
    .await;
    let venue = running.guard.upstream();
    venue.set_dex_equity("abc", "1000");
    venue.pause_ws_prices(true);
    tokio::time::sleep(Duration::from_millis(1_600)).await;
    let reads = account_reads(venue);
    let reply = post(
        &running.url,
        &order(u64::from(GOLD), true, "4000", "10", false),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert!(account_reads(venue) >= reads + 3, "read every dex");
}

/// The bot's reads answered from the stream are at most 20 a second (in
/// each second the requests touched); the rest go to the venue.
#[tokio::test]
async fn the_bots_reads_from_the_stream_are_twenty_a_second_at_most() {
    let running = start("stream-info-limit", true).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let before = stream_status(&running.guard).await["info_from_stream"]
        .as_u64()
        .unwrap();
    let started = std::time::Instant::now();
    let tasks: Vec<_> = (0..100)
        .map(|_| {
            let url = running.url.clone();
            tokio::spawn(async move {
                info(
                    &url,
                    &json!({"type": "clearinghouseState", "user": ACCOUNT}),
                )
                .await
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
    // A span of e seconds touches at most floor(e) + 2 one-second windows.
    let windows = started.elapsed().as_secs() + 2;
    let from_stream = stream_status(&running.guard).await["info_from_stream"]
        .as_u64()
        .unwrap()
        - before;
    assert!(from_stream > 0, "some from the stream");
    assert!(
        from_stream <= 20 * windows,
        "{from_stream} from the stream in {windows} windows"
    );
}

/// A close that empties the position: the venue cancels Guard's stop on it
/// (`reduceOnlyCanceled`) with the fill, as recorded on testnet; that is
/// Guard's own send too, and the next request is judged from the stream.
#[tokio::test]
async fn a_close_and_the_stop_it_cancels_keep_the_stream_clean() {
    let running = start("stream-own-close", false).await;
    let venue = running.guard.upstream();
    venue.ws_snapshot_every(10);
    let reply = post(&running.url, &order(1, true, "3000", "0.1", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(!venue.orders().is_empty(), "Guard's stop rests");
    let reply = post(&running.url, &order(1, false, "2900", "1", true)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(venue.orders().is_empty(), "the venue cancelled the stop");
    let before = stream_status(&running.guard).await["judged_from_stream"]
        .as_u64()
        .unwrap();
    let reads = account_reads(venue);
    let reply = post(&running.url, &order(1, true, "3000", "0.01", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let status = stream_status(&running.guard).await;
    assert_eq!(status["judged_from_stream"], before + 1, "{status}");
    assert_eq!(account_reads(venue), reads, "no read");
}

/// Guard's own `updateLeverage` before an entry raises no event: until the
/// account's snapshots and leverage setting come a second after it, the
/// next entry is judged after a read, also when
/// the entry itself was reported at once. (A setting shown before the
/// update must not be taken as the one after it.)
#[tokio::test]
async fn a_leverage_update_of_guards_keeps_the_stream_unclean_for_a_second() {
    let running = start("stream-own-leverage", false).await;
    let venue = running.guard.upstream();
    venue.ws_snapshot_every(50);
    venue.ws_snapshot_after_entry(Some(300));
    let leverage_updates = |venue: &MemoryVenue| {
        venue
            .received()
            .iter()
            .filter(|received| {
                matches!(
                    received.action,
                    zunder_guard_core::action::Action::UpdateLeverage { .. }
                )
            })
            .count()
    };
    let before = leverage_updates(venue);
    let reply = post(&running.url, &order(1, true, "3000", "0.01", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(leverage_updates(venue), before + 1, "leverage set first");
    tokio::time::sleep(Duration::from_millis(600)).await;
    let reads = account_reads(venue);
    let reply = post(&running.url, &order(1, true, "3000", "0.01", false)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert!(
        account_reads(venue) > reads,
        "read after Guard's leverage update"
    );
}

/// Latency of a request in paper mode and in send mode, judged from the
/// stream, over HTTP with reused clients, against the in-memory venue
/// (`--ignored --nocapture`; TMPDIR decides the disk): one client at a
/// time, and four at once. Send mode: a resting entry (its stop attached)
/// and its cancel, in turns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, not a check"]
async fn request_latency_paper_and_send() {
    use std::time::Instant;
    fn line(what: &str, mut samples: Vec<u128>) {
        samples.sort_unstable();
        let at = |q: f64| {
            samples[((samples.len() as f64 * q) as usize).min(samples.len() - 1)] as f64 / 1000.0
        };
        println!(
            "{what}: n {}, p50 {:.3} ms, p90 {:.3} ms, p99 {:.3} ms",
            samples.len(),
            at(0.5),
            at(0.9),
            at(0.99)
        );
    }
    async fn timed(client: &reqwest::Client, url: &str, body: Value) -> (u128, Value) {
        let started = Instant::now();
        let text = client
            .post(format!("{url}/exchange"))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        (
            started.elapsed().as_micros(),
            serde_json::from_str::<Value>(&text).unwrap(),
        )
    }
    let client = reqwest::Client::new();
    // Paper: entries, one at a time, then four clients at once.
    let paper = start("latency-paper", true).await;
    timed(&client, &paper.url, order(1, true, "3000", "0.01", false)).await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let mut samples = Vec::new();
    for _ in 0..300 {
        let (elapsed, _) = timed(&client, &paper.url, order(1, true, "3000", "0.01", false)).await;
        samples.push(elapsed);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    line("paper, one client", samples);
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let (client, url) = (client.clone(), paper.url.clone());
        tasks.push(tokio::spawn(async move {
            let mut samples = Vec::new();
            for _ in 0..100 {
                let (elapsed, _) =
                    timed(&client, &url, order(1, true, "3000", "0.01", false)).await;
                samples.push(elapsed);
            }
            samples
        }));
    }
    let mut samples = Vec::new();
    for task in tasks {
        samples.extend(task.await.unwrap());
    }
    line("paper, four clients at once", samples);
    // Send: a resting entry and its cancel, in turns.
    let send = start("latency-send", false).await;
    timed(&client, &send.url, order(1, true, "3000", "0.01", false)).await;
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    let (mut entries, mut cancels) = (Vec::new(), Vec::new());
    for _ in 0..100 {
        let (elapsed, reply) = timed(
            &client,
            &send.url,
            order_tif(1, true, "2000", "0.01", false, "Gtc"),
        )
        .await;
        assert_eq!(reply["status"], "ok", "{reply}");
        entries.push(elapsed);
        let oid = send
            .guard
            .upstream()
            .orders()
            .iter()
            .find(|order| order["isTrigger"] == false)
            .and_then(|order| order["oid"].as_u64())
            .unwrap();
        // The stream clean again (the send reported, a snapshot after).
        tokio::time::sleep(Duration::from_millis(250)).await;
        let (elapsed, reply) = timed(&client, &send.url, cancel(oid)).await;
        assert_eq!(reply["status"], "ok", "{reply}");
        cancels.push(elapsed);
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    line("send, a resting entry with its stop", entries);
    line("send, its cancel", cancels);
    // Send, four clients at once: cancels of orders that are not there
    // (each judged, sent, answered).
    let mut tasks = Vec::new();
    for task in 0..4u64 {
        let (client, url) = (client.clone(), send.url.clone());
        tasks.push(tokio::spawn(async move {
            let mut samples = Vec::new();
            for round in 0..50u64 {
                let (elapsed, _) =
                    timed(&client, &url, cancel(900_000 + task * 1_000 + round)).await;
                samples.push(elapsed);
            }
            samples
        }));
    }
    let mut samples = Vec::new();
    for task in tasks {
        samples.extend(task.await.unwrap());
    }
    line("send, four clients at once (cancels)", samples);
}

/// A stale request snapshot cannot end a fresh loss hold. The venue clock
/// stays at the pre-loss snapshot while a recovered equity is reused.
#[tokio::test]
async fn a_stale_recovered_snapshot_cannot_clear_a_loss_hold() {
    let running = start("stream-hold-stale-recovery", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.fail_ledger(true);
    venue.set_equity("6000");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    running.guard.sync().await;
    let held_at = SystemClock.now_ms() as i64;
    venue.hold_account_time(Some(held_at - 60000));
    venue.set_equity("9000");
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(
        status["risk"]["state"], "active",
        "stale recovery ended hold: {status}"
    );
    // Wall time, independently of freshness, expires the held 30% loss.
    tokio::time::sleep(Duration::from_millis(10100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(
        status["risk"]["state"], "stopped",
        "expired hold lost deepest view: {status}"
    );
}

/// A request begins a hold between slow sync ticks. Its notification wakes
/// the one-second loop; waiting for the next normal30s round would miss it.
#[tokio::test]
async fn a_request_started_hold_wakes_the_one_second_sync_loop() {
    let running = start_syncing(
        "stream-request-hold-wake",
        true,
        Limits {
            request_weight_per_second: 1_000_000,
            request_weight_burst: 1_000_000,
        },
        &["*", "xyz:*"],
        Some(30),
    )
    .await;
    running.guard.sync().await;
    let sync = tokio::spawn(running.guard.clone().sync_forever());
    tokio::time::sleep(Duration::from_millis(300)).await;
    running.guard.upstream().set_equity("8000");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let action = Wire::Map(vec![("type", Wire::str("scheduleCancel"))]);
    running.guard.exchange(signed(action), "http").await;
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let status = running.guard.status().await;
    sync.abort();
    assert_eq!(
        status["risk"]["state"], "halted_for_day",
        "request hold was not revisited: {status}"
    );
}

/// Hold expiry precedes the account read, so losing both socket and HTTP
/// cannot leave the deepest independently known30% loss waiting forever.
#[tokio::test]
async fn a_hold_expires_before_a_failed_account_read() {
    let running = start("stream-hold-failed-read", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.fail_ledger(true);
    venue.set_equity("6000"); // Total7,000 versus10,000 is30% drawdown.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    running.guard.sync().await;
    assert_eq!(running.guard.status().await["risk"]["state"], "active");
    venue.pause_ws(true);
    venue.fail_reads("");
    tokio::time::sleep(Duration::from_millis(10100)).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["risk"]["state"], "stopped", "{status}");
}

#[tokio::test]
async fn an_inflight_slow_read_cannot_extend_an_existing_hold_deadline() {
    let running = start("stream-hold-inflight-deadline", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.fail_ledger(true);
    venue.set_equity("6000");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let begun = SystemClock.now_ms();
    running.guard.sync().await;
    assert_eq!(running.guard.status().await["risk"]["state"], "active");
    venue.slow_reads(15000);
    let guard = running.guard.clone();
    let sync = tokio::spawn(async move { guard.sync().await });
    tokio::time::sleep(Duration::from_millis(10500)).await;
    let records = PersistentRisk::read(&running._dir.path().join("risk-paper.jsonl")).unwrap();
    let zunder_risk::RiskState::Stopped { at, drawdown } = records.last().unwrap().state.state
    else {
        panic!("hold did not expire during in-flight read");
    };
    assert_eq!(drawdown, dec!(0.3));
    assert!(at.as_millis() >= begun as i64 && at.as_millis() <= begun as i64 + 1000);
    assert!(SystemClock.now_ms().saturating_sub(begun) < 12500);
    // Only the delayed read-only position fallback remains in flight.
    sync.abort();
    let _ = sync.await;
    assert_eq!(running.guard.status().await["risk"]["state"], "stopped");
}

#[tokio::test]
async fn a_request_hold_bounds_a_sync_read_already_inflight() {
    let running = start("stream-request-hold-inflight", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.fail_ledger(true);
    venue.set_equity("6000");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    venue.slow_reads(15000);
    let guard = running.guard.clone();
    let sync = tokio::spawn(async move { guard.sync().await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let begun = SystemClock.now_ms();
    let action = Wire::Map(vec![("type", Wire::str("scheduleCancel"))]);
    running.guard.exchange(signed(action), "http").await;
    assert_eq!(running.guard.status().await["risk"]["state"], "active");
    tokio::time::sleep(Duration::from_millis(10500)).await;
    let records = PersistentRisk::read(&running._dir.path().join("risk-paper.jsonl")).unwrap();
    let zunder_risk::RiskState::Stopped { at, drawdown } = records.last().unwrap().state.state
    else {
        panic!("hold did not expire during in-flight read");
    };
    assert_eq!(drawdown, dec!(0.3));
    assert!(at.as_millis() >= begun as i64 && at.as_millis() <= begun as i64 + 1000);
    assert!(SystemClock.now_ms().saturating_sub(begun) < 12500);
    // Only the delayed read-only position fallback remains in flight.
    sync.abort();
    let _ = sync.await;
    assert_eq!(running.guard.status().await["risk"]["state"], "stopped");
}

async fn late_flow_read_respects_deadline(reconstruction: bool) {
    let running = start("stream-hold-late-flow-read", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    venue.fail_ledger(true);
    venue.set_equity("6000"); //7,000 summed equity proves30% from10,000.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let begun = SystemClock.now_ms();
    running.guard.sync().await;
    venue.fail_ledger(false);
    if reconstruction {
        venue.flow("-100", true);
        venue.slow_flow_reads(0, 15000);
    } else {
        venue.slow_flow_reads(15000, 0);
    }
    tokio::time::sleep(Duration::from_millis(8900)).await;
    let guard = running.guard.clone();
    let sync = tokio::spawn(async move { guard.sync().await });
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let records = PersistentRisk::read(&running._dir.path().join("risk-paper.jsonl")).unwrap();
    let zunder_risk::RiskState::Stopped { at, drawdown } = records.last().unwrap().state.state
    else {
        panic!("late flow read extended the hold deadline");
    };
    assert_eq!(drawdown, dec!(0.3));
    assert!(at.as_millis() >= begun as i64 && at.as_millis() <= begun as i64 + 1000);
    assert!(SystemClock.now_ms().saturating_sub(begun) < 12500);
    sync.abort();
    let _ = sync.await;
}

#[tokio::test]
async fn an_inflight_ledger_read_respects_the_hold_deadline() {
    late_flow_read_respects_deadline(false).await;
}

#[tokio::test]
async fn an_inflight_reconstruction_respects_the_hold_deadline() {
    late_flow_read_respects_deadline(true).await;
}

#[tokio::test]
async fn spent_passthrough_budget_refuses_optional_flow_reads_before_sending() {
    let running = start("stream-flow-shared-info-budget", true).await;
    let venue = running.guard.upstream();
    running.guard.sync().await;
    //Each userRole costs60 of the same160 burst. Two leave40, below a
    //45-weight reconstruction history read, even after2s refill.
    for user in 1..=2 {
        running
            .guard
            .info(&json!({"type":"userRole","user":format!("0x{user:040x}")}))
            .await
            .unwrap();
    }
    let before = venue
        .info_log()
        .iter()
        .filter(|body| body["type"] == "userFillsByTime")
        .count();
    venue.flow("100", false);
    tokio::time::sleep(Duration::from_millis(3100)).await;
    running.guard.sync().await;
    let after = venue
        .info_log()
        .iter()
        .filter(|body| body["type"] == "userFillsByTime")
        .count();
    assert_eq!(after, before, "unadmitted optional history was sent");
    assert_eq!(
        running.guard.status().await["risk"]["state"],
        "halted_for_day"
    );
}

async fn late_request_read_respects_deadline(book: bool) {
    let running = start("stream-hold-request-read-deadline", true).await;
    let venue = running.guard.upstream();
    if book {
        running
            .guard
            .exchange(order(u64::from(GOLD), true, "4000", "10", false), "http")
            .await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    running.guard.sync().await;
    venue.fail_ledger(true);
    venue.set_equity("6000");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let begun = SystemClock.now_ms();
    running.guard.sync().await;
    if book {
        venue.slow_books(15000);
    } else {
        venue.pause_ws(true);
        venue.slow_reads(15000);
    }
    tokio::time::sleep(Duration::from_millis(8900)).await;
    let guard = running.guard.clone();
    let request = tokio::spawn(async move {
        let body = if book {
            order(u64::from(GOLD), true, "4000", "10", false)
        } else {
            signed(Wire::Map(vec![("type", Wire::str("scheduleCancel"))]))
        };
        guard.exchange(body, "http").await
    });
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let records = PersistentRisk::read(&running._dir.path().join("risk-paper.jsonl")).unwrap();
    let zunder_risk::RiskState::Stopped { at, drawdown } = records.last().unwrap().state.state
    else {
        panic!("request read extended the hold deadline");
    };
    assert_eq!(drawdown, dec!(0.3));
    assert!(at.as_millis() >= begun as i64 && at.as_millis() <= begun as i64 + 1000);
    assert!(SystemClock.now_ms().saturating_sub(begun) < 12500);
    request.abort();
    let _ = request.await;
}

#[tokio::test]
async fn an_inflight_request_account_read_respects_the_hold_deadline() {
    late_request_read_respects_deadline(false).await;
}

#[tokio::test]
async fn an_inflight_request_hip3_book_respects_the_hold_deadline() {
    late_request_read_respects_deadline(true).await;
}

async fn failed_optional_flow_read_still_spends_budget(timeout: bool) {
    let running = start("stream-flow-failed-info-budget", true).await;
    let venue = running.guard.upstream();
    if timeout {
        venue.slow_flow_reads(0, 15000);
    } else {
        venue.fail_flow_records(true);
    }
    venue.flow("100", false);
    tokio::time::sleep(Duration::from_millis(3100)).await;
    running.guard.sync().await;
    //160 minus two anchors(4) minus failed history(45), at most6 refill
    //during its3s timeout: <=117. Two60-weight reads must not both fit.
    let body = json!({"type":"userRole","user":ACCOUNT});
    assert!(running.guard.info(&body).await.is_ok());
    let other = json!({"type":"userRole","user":"0x0000000000000000000000000000000000000001"});
    assert!(
        running.guard.info(&other).await.is_err(),
        "failed optional read was refunded"
    );
}

#[tokio::test]
async fn a_failed_optional_flow_read_keeps_its_budget_reservation() {
    failed_optional_flow_read_still_spends_budget(false).await;
}

#[tokio::test]
async fn a_timed_out_optional_flow_read_keeps_its_budget_reservation() {
    failed_optional_flow_read_still_spends_budget(true).await;
}
