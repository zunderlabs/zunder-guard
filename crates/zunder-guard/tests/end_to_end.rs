// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! End to end through the real server: a ccxt-style client signs with its
//! Guard client key and posts to Guard over HTTP and WebSocket; Guard
//! judges, re-signs with the API wallet key and sends to an in-memory
//! venue that checks the signature as Hyperliquid does.
//!
//! Account: 10,000 USDC, mids BTC 60,000, ETH 3,000, SOL 150; default
//! policy.

#![allow(clippy::unwrap_used)]

mod support;

use std::{path::Path, sync::Arc};

use futures_util::{SinkExt, StreamExt};
use rust_decimal::{Decimal, dec};
use serde_json::{Value, json};
use support::MemoryVenue;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use zunder_core::Timestamp;
use zunder_guard::{
    config::{GuardConfig, GuardMode, GuardNetwork},
    guard::{Clock, Guard, Limits, Mode, Setup, SystemClock},
    journal::DecisionJournal,
    server,
    testdir::TestDir,
};
use zunder_guard_core::{
    action::{Action, Grouping, OrderKind, Tpsl},
    auth::AuthConfig,
    licence::FeeMode,
    sign::{Address, GuardKey, SigningNetwork},
    wire::{Wire, minimal_hex},
};
use zunder_venue::PersistentRisk;

/// The bot's client key: the SDK tests' throwaway key.
const CLIENT_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
/// Guard's API wallet key in these tests: another throwaway.
fn api_key() -> GuardKey {
    GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap()
}
const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

struct Running {
    url: String,
    venue_handle: Arc<Guard<MemoryVenue>>,
    dir: TestDir,
}

impl Running {
    fn venue(&self) -> &MemoryVenue {
        self.venue_handle.upstream()
    }
}

fn config(dir: &Path, paper: bool) -> GuardConfig {
    GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: if paper {
            GuardMode::Paper
        } else {
            GuardMode::Testnet
        },
        account: Some(ACCOUNT.to_owned()),
        api_wallet: Some(api_key().address().to_hex()),
        state_dir: dir.to_owned(),
        auth: AuthConfig {
            clients: vec![GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex()],
            ..AuthConfig::default()
        },
        ..GuardConfig::default()
    }
}

async fn start(paper: bool) -> Running {
    let dir = TestDir::new(if paper { "e2e-paper" } else { "e2e" });
    let config = config(dir.path(), paper);
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(paper),
        config.policy.risk_limits(),
        &config.journal_scope(paper).unwrap(),
        Timestamp::from_millis(SystemClock.now_ms() as i64),
        dec!(10000),
        "end-to-end test",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(paper)).unwrap();
    let mode = if paper {
        Mode::Paper
    } else {
        Mode::Send {
            key: api_key(),
            network: SigningNetwork::Testnet,
        }
    };
    let venue = MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "10000",
    );
    let venue = if paper { venue.read_only() } else { venue };
    let guard = Guard::new(
        Setup {
            config,
            mode,
            risk,
            journal,
            fee: FeeMode::Off("test".into()),
            fee_warning: None,
            // No venue request limit in memory.
            limits: Limits {
                request_weight_per_second: 1_000_000,
                request_weight_burst: 1_000_000,
            },
        },
        venue,
        SystemClock,
    )
    .unwrap();
    // Guard refuses nonces from before its start plus 5 s: let the clock
    // pass that, as a bot started after Guard would.
    tokio::time::sleep(std::time::Duration::from_millis(5_100)).await;
    let (addr, _) = server::bind(guard.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    Running {
        url: format!("http://{addr}"),
        venue_handle: guard,
        dir,
    }
}

/// What ccxt's hyperliquid `createOrder` sends for a market buy of `size`
/// ETH: an IOC limit 5% above the mid, grouping "na", no vaultAddress, no
/// expiresAfter, signed as testnet (sandbox mode) with the client key.
fn ccxt_market_buy(size: &str, nonce: u64) -> Value {
    ccxt_buy("3150", size, "Ioc", nonce)
}

/// A ccxt limit buy of `size` ETH at `price`, time in force `tif`.
fn ccxt_buy(price: &str, size: &str, tif: &str, nonce: u64) -> Value {
    let action = Wire::Map(vec![
        ("type", Wire::str("order")),
        (
            "orders",
            Wire::Array(vec![Wire::Map(vec![
                ("a", Wire::UInt(1)),
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
    ]);
    signed_body(&GuardKey::from_hex(CLIENT_KEY).unwrap(), action, nonce)
}

fn signed_body(key: &GuardKey, action: Wire, nonce: u64) -> Value {
    let signature = key
        .sign_l1_action(SigningNetwork::Testnet, &action, nonce, None)
        .unwrap();
    json!({
        "action": action.to_value(),
        "nonce": nonce,
        "signature": {"r": minimal_hex(&signature.r), "s": minimal_hex(&signature.s), "v": signature.v},
    })
}

async fn post(url: &str, path: &str, body: &Value) -> Value {
    reqwest::Client::new()
        .post(format!("{url}{path}"))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap()
        .json_text()
        .await
}

trait JsonText {
    async fn json_text(self) -> Value;
}

impl JsonText for reqwest::Response {
    async fn json_text(self) -> Value {
        serde_json::from_str(&self.text().await.unwrap()).unwrap()
    }
}

fn now() -> u64 {
    SystemClock.now_ms()
}

#[tokio::test]
async fn a_ccxt_market_buy_reaches_the_venue_sized_with_its_stop_and_signed_by_the_api_wallet() {
    let guard = start(false).await;
    let reply = post(&guard.url, "/exchange", &ccxt_market_buy("10", now())).await;
    // The bot sees one status for its one order: filled.
    let statuses = reply["response"]["data"]["statuses"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(statuses.len(), 1, "{reply}");
    assert!(statuses[0].get("filled").is_some(), "{reply}");

    let received = guard.venue().received();
    assert_eq!(received.len(), 2, "{received:?}");
    // First the isolated leverage, read back from the venue before the
    // order went: the fill bound 3,015 and the stop 2,940 with 10% stop
    // slippage (worst fill 2,646) put the stop's worst 12.24% below; with
    // 10% room and 5% for funding the liquidation must lie 18.46% away; at
    // 5x it lies 18.37% away (ETH's maintenance margin 2%), at 4x 23.47%:
    // 4x.
    assert_eq!(
        received[0].action,
        Action::UpdateLeverage {
            asset: 1,
            is_cross: false,
            leverage: 4
        }
    );
    // Then the entry and its stop as one normalTpsl group. The limit 3,150
    // is pulled in to 3,000 * 1.005 = 3,015; the stop goes 2% below the
    // mid: 2,940. Risk per unit 75 + 3,015 * 11 bp (3.3165) = 78.3165; 2% of
    // 10,000 is 200: 200 / 78.3165 = 2.55374 ETH, down to 2.5537.
    let Action::Order(order) = &received[1].action else {
        panic!("{:?}", received[1])
    };
    assert_eq!(order.grouping, Grouping::NormalTpsl);
    assert_eq!(order.orders.len(), 2);
    let (entry, stop) = (&order.orders[0], &order.orders[1]);
    assert_eq!((entry.price.raw(), entry.size.raw()), ("3015", "2.5537"));
    assert!(entry.is_buy && !entry.reduce_only);
    assert!(matches!(
        &stop.kind,
        OrderKind::Trigger { tpsl: Tpsl::Sl, trigger_px, is_market: true } if trigger_px.value() == dec!(2940)
    ));
    assert!(stop.reduce_only && !stop.is_buy);
    assert_eq!(stop.size.raw(), "2.5537");
    // Every request the venue took is signed by the API wallet, never by
    // the client, with Guard's own increasing nonces.
    let api_wallet = api_key().address();
    assert!(received.iter().all(|r| r.signer == api_wallet));
    assert!(received[0].nonce < received[1].nonce);
    // Loss at the stop: 2.5537 * 78.3165 = 199.99 <= 200.
    assert!(dec!(2.5537) * dec!(78.3165) <= Decimal::from(200));

    // The decision is in the journal, before the sends.
    let events: Value = reqwest::get(format!("{}/guard/events?since=0", guard.url))
        .await
        .unwrap()
        .json_text()
        .await;
    let kinds: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["kind"].as_str().unwrap())
        .collect();
    let decision = kinds.iter().position(|kind| *kind == "decision").unwrap();
    let sent = kinds.iter().position(|kind| *kind == "sent").unwrap();
    assert!(decision < sent, "{kinds:?}");
    assert_eq!(events[decision]["verdict"], "resize");
}

#[tokio::test]
async fn replays_forgeries_and_withdrawals_never_reach_the_venue() {
    let guard = start(false).await;
    let body = ccxt_market_buy("0.1", now());
    let first = post(&guard.url, "/exchange", &body).await;
    assert_eq!(first["status"], "ok", "{first}");
    let sent = guard.venue().received().len();
    // The same request again: a replay.
    let replay = post(&guard.url, "/exchange", &body).await;
    assert_eq!(replay["status"], "err");
    assert!(
        replay["response"].as_str().unwrap().contains("auth_replay"),
        "{replay}"
    );
    // Signed by a key Guard never issued.
    let stranger = GuardKey::from_hex(&format!("0x{}", "11".repeat(32))).unwrap();
    let forged = signed_body(
        &stranger,
        Wire::Map(vec![("type", Wire::str("scheduleCancel"))]),
        now(),
    );
    let forged = post(&guard.url, "/exchange", &forged).await;
    assert!(
        forged["response"]
            .as_str()
            .unwrap()
            .contains("auth_unknown_signer"),
        "{forged}"
    );
    // A withdrawal, even signed by the client: refused by name.
    let withdraw = json!({
        "action": {"type": "withdraw3", "hyperliquidChain": "Testnet", "signatureChainId": "0x66eee",
                   "amount": "100", "time": now(), "destination": ACCOUNT},
        "nonce": now(), "signature": {"r": "0x1", "s": "0x1", "v": 27},
    });
    let refused = post(&guard.url, "/exchange", &withdraw).await;
    assert!(
        refused["response"]
            .as_str()
            .unwrap()
            .contains("funds_or_permissions"),
        "{refused}"
    );
    // The venue saw nothing of these.
    assert_eq!(guard.venue().received().len(), sent);
}

#[tokio::test]
async fn websocket_posts_go_through_guard() {
    let guard = start(false).await;
    let ws_url = guard.url.replace("http://", "ws://") + "/ws";
    let (mut socket, _) = connect_async(ws_url.as_str()).await.unwrap();
    // The Python SDK and ccxt.pro post actions over the socket like this.
    let post = json!({"method": "post", "id": 7, "request": {"type": "action", "payload": ccxt_market_buy("0.1", now())}});
    socket.send(Message::text(post.to_string())).await.unwrap();
    let answer = loop {
        let Some(Ok(Message::Text(text))) = socket.next().await else {
            panic!("the socket closed")
        };
        let value: Value = serde_json::from_str(text.as_str()).unwrap();
        if value["channel"] == "post" {
            break value;
        }
    };
    assert_eq!(answer["data"]["id"], 7);
    assert_eq!(answer["data"]["response"]["type"], "action");
    assert_eq!(
        answer["data"]["response"]["payload"]["status"], "ok",
        "{answer}"
    );
    assert_eq!(guard.venue().received().len(), 2);
}

#[tokio::test]
async fn paper_mode_judges_and_sends_nothing() {
    let guard = start(true).await;
    let reply = post(&guard.url, "/exchange", &ccxt_market_buy("10", now())).await;
    assert_eq!(reply["status"], "err");
    let text = reply["response"].as_str().unwrap();
    assert!(text.contains("paper mode: would resize"), "{text}");
    assert!(guard.venue().received().is_empty());
    let status: Value = reqwest::get(format!("{}/guard/status", guard.url))
        .await
        .unwrap()
        .json_text()
        .await;
    assert_eq!(status["mode"], "paper");
    assert!(status["rules"].as_str().unwrap().starts_with("zr1_"));
}

#[tokio::test]
async fn info_passes_through_and_foreign_hosts_are_refused() {
    let guard = start(true).await;
    let mids = post(&guard.url, "/info", &json!({"type": "allMids"})).await;
    assert_eq!(mids["ETH"], "3000");
    let response = reqwest::Client::new()
        .get(format!("{}/guard/status", guard.url))
        .header("host", "attacker.example:8547")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn an_entry_whose_stop_is_refused_is_closed_at_once() {
    let guard = start(false).await;
    guard.venue().refuse_stops();
    let reply = post(&guard.url, "/exchange", &ccxt_market_buy("0.1", now())).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let received = guard.venue().received();
    // The leverage, the entry with its (refused) stop, then Guard's close.
    assert_eq!(received.len(), 3, "{received:?}");
    let Action::Order(close) = &received[2].action else {
        panic!("{:?}", received[2])
    };
    assert!(close.orders[0].reduce_only && !close.orders[0].is_buy);
    assert_eq!(close.orders[0].size.raw(), "0.1");
    assert!(guard.venue().positions().is_empty());
    let status: Value = reqwest::get(format!("{}/guard/status", guard.url))
        .await
        .unwrap()
        .json_text()
        .await;
    assert!(
        status["alert"].as_str().unwrap().contains("closed at once"),
        "{status}"
    );
}

#[tokio::test]
async fn a_resting_entry_whose_stop_is_refused_is_cancelled() {
    let guard = start(false).await;
    guard.venue().refuse_stops();
    // A GTC buy at 2,950, below the 3,000 mid: it rests, its stop is
    // refused, Guard cancels it.
    let reply = post(
        &guard.url,
        "/exchange",
        &ccxt_buy("2950", "0.1", "Gtc", now()),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let received = guard.venue().received();
    assert_eq!(received.len(), 3, "{received:?}");
    assert!(matches!(&received[2].action, Action::Cancel(cancels) if cancels.len() == 1));
    assert!(
        guard.venue().orders().is_empty(),
        "{:?}",
        guard.venue().orders()
    );
}

#[tokio::test]
async fn the_sync_gives_an_unprotected_position_guards_stop() {
    let guard = start(false).await;
    // A position opened outside Guard, without a stop: long 0.5 ETH.
    guard.venue().add_position("ETH", "0.5");
    guard.venue_handle.sync().await;
    let received = guard.venue().received();
    assert_eq!(received.len(), 1, "{received:?}");
    let Action::Order(order) = &received[0].action else {
        panic!("{:?}", received[0])
    };
    // 2% below the 3,000 mid: 2,940, for the whole 0.5, reduce-only.
    assert_eq!(order.orders[0].protective_level(), Some(dec!(2940)));
    assert_eq!(order.orders[0].size.raw(), "0.5");
    assert_eq!(guard.venue().orders().len(), 1);
    // Covered now: a sync after the settle window sends nothing more.
    tokio::time::sleep(std::time::Duration::from_millis(5_100)).await;
    guard.venue_handle.sync().await;
    assert_eq!(guard.venue().received().len(), 1);
    let status: Value = reqwest::get(format!("{}/guard/status", guard.url))
        .await
        .unwrap()
        .json_text()
        .await;
    assert!(status["alert"].is_null(), "{status}");
}

#[tokio::test]
async fn an_unprotected_position_whose_stop_is_refused_is_closed() {
    let guard = start(false).await;
    guard.venue().refuse_stops();
    guard.venue().add_position("ETH", "-0.5");
    guard.venue_handle.sync().await;
    let received = guard.venue().received();
    // Guard's stop (refused), then the close.
    assert_eq!(received.len(), 2, "{received:?}");
    let Action::Order(close) = &received[1].action else {
        panic!("{:?}", received[1])
    };
    assert!(close.orders[0].reduce_only && close.orders[0].is_buy);
    assert!(guard.venue().positions().is_empty());
    let status: Value = reqwest::get(format!("{}/guard/status", guard.url))
        .await
        .unwrap()
        .json_text()
        .await;
    assert!(
        status["alert"].as_str().unwrap().contains("closed at once"),
        "{status}"
    );
}

#[tokio::test]
async fn a_paper_guard_reports_an_unprotected_position_once() {
    let guard = start(true).await;
    guard.venue().add_position("ETH", "0.5");
    guard.venue_handle.sync().await;
    guard.venue_handle.sync().await;
    let events: Value = reqwest::get(format!("{}/guard/events?since=0", guard.url))
        .await
        .unwrap()
        .json_text()
        .await;
    let protects = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "protect")
        .count();
    assert_eq!(protects, 1, "{events}");
    assert!(guard.venue().received().is_empty());
}

#[tokio::test]
async fn the_kill_file_refuses_entries_and_flattens() {
    let guard = start(false).await;
    // A position with its stop, then the kill file.
    let reply = post(&guard.url, "/exchange", &ccxt_market_buy("0.1", now())).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(guard.venue().positions().len(), 1);
    std::fs::write(guard.dir.path().join("kill"), "test drill\n").unwrap();
    // The next request sees it before anything else.
    let refused = post(&guard.url, "/exchange", &ccxt_market_buy("0.1", now())).await;
    assert!(
        refused["response"]
            .as_str()
            .unwrap()
            .contains("kill_switch"),
        "{refused}"
    );
    // And Guard has closed the position (on that request, or the sync).
    guard.venue_handle.sync().await;
    assert!(
        guard.venue().positions().is_empty(),
        "{:?}",
        guard.venue().positions()
    );
    let last = guard.venue().received().pop().unwrap();
    let Action::Order(close) = &last.action else {
        panic!("{last:?}")
    };
    assert!(close.orders.iter().all(|order| order.reduce_only));
}

#[tokio::test]
async fn pages_from_other_sites_are_refused() {
    let guard = start(true).await;
    let client = reqwest::Client::new();
    let from = |origin: &str| {
        client
            .post(format!("{}/info", guard.url))
            .header("origin", origin)
            .header("content-type", "application/json")
            .body(json!({"type": "allMids"}).to_string())
            .send()
    };
    assert_eq!(
        from("https://attacker.example").await.unwrap().status(),
        403
    );
    assert_eq!(from("null").await.unwrap().status(), 403);
    let local = guard.url.clone();
    assert_eq!(from(&local).await.unwrap().status(), 200);
}

#[tokio::test]
async fn a_preview_judges_without_sending_or_consuming_anything() {
    let guard = start(false).await;
    // A preview answers from the background sync's view of the account.
    let early = post(
        &guard.url,
        "/guard/preview",
        &json!({"action": ccxt_market_buy("10", now())["action"]}),
    )
    .await;
    assert!(
        early["error"].as_str().unwrap().contains("no recent view"),
        "{early}"
    );
    guard.venue_handle.sync().await;
    // One preview a second.
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let body = ccxt_market_buy("10", now());
    let preview = post(
        &guard.url,
        "/guard/preview",
        &json!({"action": body["action"]}),
    )
    .await;
    assert_eq!(preview["verdict"], "resize", "{preview}");
    assert_eq!(preview["forward"]["orders"][0]["s"], "2.5537");
    // The size asked for and the size Guard would send.
    assert_eq!(preview["entry"]["requested_size"], "10", "{preview}");
    assert_eq!(preview["entry"]["size"], "2.5537", "{preview}");
    assert!(guard.venue().received().is_empty());
    // The signed request itself still goes through afterwards.
    let reply = post(&guard.url, "/exchange", &body).await;
    assert_eq!(reply["status"], "ok", "{reply}");
}

/// A Guard on `dir` in paper or testnet mode, over a venue that sends or
/// only reads, as [`Guard::new`] answers.
fn new_guard(
    dir: &Path,
    paper: bool,
    venue_sends: bool,
) -> Result<Arc<Guard<MemoryVenue>>, String> {
    let config = config(dir, paper);
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(paper),
        config.policy.risk_limits(),
        &config.journal_scope(paper).unwrap(),
        Timestamp::from_millis(SystemClock.now_ms() as i64),
        dec!(10000),
        "end-to-end test",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(paper)).unwrap();
    let mode = if paper {
        Mode::Paper
    } else {
        Mode::Send {
            key: api_key(),
            network: SigningNetwork::Testnet,
        }
    };
    let venue = MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "10000",
    );
    let venue = if venue_sends {
        venue
    } else {
        venue.read_only()
    };
    Guard::new(
        Setup {
            config,
            mode,
            risk,
            journal,
            fee: FeeMode::Off("test".into()),
            fee_warning: None,
            // No venue request limit in memory.
            limits: Limits {
                request_weight_per_second: 1_000_000,
                request_weight_burst: 1_000_000,
            },
        },
        venue,
        SystemClock,
    )
}

#[tokio::test]
async fn guard_refuses_a_mode_and_a_venue_that_disagree() {
    // Paper over a sending venue, testnet over a read-only one: refused.
    let dir = TestDir::new("e2e-mismatch-paper");
    assert!(new_guard(dir.path(), true, true).is_err());
    let dir = TestDir::new("e2e-mismatch-testnet");
    assert!(new_guard(dir.path(), false, false).is_err());
    let dir = TestDir::new("e2e-match");
    assert!(new_guard(dir.path(), false, true).is_ok());
}

#[tokio::test]
async fn a_kill_file_left_in_place_latches_at_start() {
    let dir = TestDir::new("e2e-kill-start");
    std::fs::write(dir.path().join("kill"), "left over\n").unwrap();
    let guard = new_guard(dir.path(), false, true).unwrap();
    let status = guard.status().await;
    assert_eq!(status["killed"], "left over", "{status}");
}

fn kill_request(key: &GuardKey, reason: &str, nonce: u64) -> Value {
    let signature = key
        .sign_l1_action(
            SigningNetwork::Testnet,
            &zunder_guard_core::kill_wire(reason),
            nonce,
            None,
        )
        .unwrap();
    json!({
        "action": {"type": "zunderGuardKill", "reason": reason},
        "nonce": nonce,
        "signature": {"r": minimal_hex(&signature.r), "s": minimal_hex(&signature.s), "v": signature.v},
    })
}

#[tokio::test]
async fn a_signed_kill_request_pulls_the_switch_and_flattens() {
    let guard = start(false).await;
    let reply = post(&guard.url, "/exchange", &ccxt_market_buy("0.1", now())).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    // A stranger's signature: refused, nothing latched.
    let stranger = GuardKey::from_hex(&format!("0x{}", "77".repeat(32))).unwrap();
    let refused = post(
        &guard.url,
        "/guard/kill",
        &kill_request(&stranger, "x", now()),
    )
    .await;
    assert_eq!(refused["status"], "err", "{refused}");
    assert_eq!(refused["code"], "auth_unknown_signer", "{refused}");
    assert!(!guard.dir.path().join("kill").exists());
    // The client's: latched, written to the kill file, flattened at once.
    let client = GuardKey::from_hex(CLIENT_KEY).unwrap();
    let body = kill_request(&client, "agent saw a bug", now());
    let killed = post(&guard.url, "/guard/kill", &body).await;
    assert_eq!(killed["status"], "ok", "{killed}");
    assert!(
        killed["killed"]
            .as_str()
            .unwrap()
            .contains("agent saw a bug")
    );
    let file = std::fs::read_to_string(guard.dir.path().join("kill")).unwrap();
    assert!(file.contains("agent saw a bug"), "{file}");
    assert!(guard.venue().positions().is_empty());
    // The same request again is a replay; nothing resumes.
    let again = post(&guard.url, "/guard/kill", &body).await;
    assert_eq!(again["code"], "auth_replay", "{again}");
    let status: Value = reqwest::get(format!("{}/guard/status", guard.url))
        .await
        .unwrap()
        .json_text()
        .await;
    assert!(status["killed"].is_string(), "{status}");
    // And entries are refused, with the code as a field.
    let refused = post(&guard.url, "/exchange", &ccxt_market_buy("0.1", now())).await;
    assert_eq!(refused["code"], "kill_switch", "{refused}");
}

#[tokio::test]
async fn a_decision_can_be_looked_up_by_its_nonce() {
    let guard = start(true).await;
    let nonce = now();
    let reply = post(&guard.url, "/exchange", &ccxt_market_buy("10", nonce)).await;
    assert_eq!(reply["code"], "resized", "{reply}");
    assert_eq!(reply["verdict"], "resize", "{reply}");
    let client = GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex();
    for url in [
        format!("{}/guard/decision?nonce={nonce}", guard.url),
        format!("{}/guard/decision?nonce={nonce}&client={client}", guard.url),
    ] {
        let found: Value = reqwest::get(url).await.unwrap().json_text().await;
        assert_eq!(found["decision"]["nonce"], nonce, "{found}");
        assert_eq!(found["decision"]["code"], "resized", "{found}");
        assert_eq!(found["sent"], json!([]), "{found}");
    }
    let missing = reqwest::get(format!("{}/guard/decision?nonce=1", guard.url))
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    let other = format!("0x{}", "0".repeat(40));
    let wrong_client = reqwest::get(format!(
        "{}/guard/decision?nonce={nonce}&client={other}",
        guard.url
    ))
    .await
    .unwrap();
    assert_eq!(wrong_client.status(), 404);
}

#[tokio::test]
async fn the_status_is_schema_1_with_the_assumptions() {
    let guard = start(true).await;
    let status: Value = reqwest::get(format!("{}/guard/status", guard.url))
        .await
        .unwrap()
        .json_text()
        .await;
    assert_eq!(status["schema"], 1);
    assert_eq!(status["mode"], "paper");
    assert_eq!(status["risk"]["state"], "active", "{status}");
    assert!(status["rules"].as_str().unwrap().starts_with("zr1_"));
    assert_eq!(status["clients"].as_array().unwrap().len(), 1);
    assert!(status["last_event"].as_u64().unwrap() >= 1);
    assert!(status["equity_cap"].is_null());
    assert_eq!(status["assumptions"]["fee_bps"], "4.5", "{status}");
    assert_eq!(status["assumptions"]["exit_slippage"], "0.05", "{status}");
    assert!(status["kill_file"].as_str().unwrap().ends_with("kill"));
}
