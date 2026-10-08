// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! HIP-3 markets end to end, through the real server, over the in-memory
//! venue (`support`): HIP-3 dex `xyz` at index 1 (`xyz:GOLD` 110000 at a
//! mid of 4,000, 4 size decimals, 20x, isolated only; `xyz:URANIUM` 110002
//! halted) and `abc` at index 2 (`abc:FOO` 120000), which the rules do not
//! name.
//!
//! Account: 9,000 USDC on the main dex and 1,000 on xyz, all of it free:
//! 10,000 in all. Rules: every market of the main dex and of xyz
//! (`["*", "xyz:*"]`), the defaults otherwise.

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use rust_decimal::dec;
use serde_json::{Value, json};
use support::{FOO, GOLD, MemoryVenue, URANIUM};
use zunder_core::Timestamp;
use zunder_guard::{
    config::{GuardConfig, GuardMode, GuardNetwork},
    guard::{Clock, Guard, Limits, Mode, Setup, SystemClock},
    journal::DecisionJournal,
    server,
    testdir::TestDir,
};
use zunder_guard_core::{
    action::{Action, OrderKind, Tpsl},
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

struct Running {
    url: String,
    guard: Arc<Guard<MemoryVenue>>,
    dir: TestDir,
}

impl Running {
    fn venue(&self) -> &MemoryVenue {
        self.guard.upstream()
    }
}

async fn start(name: &str) -> Running {
    let dir = TestDir::new(name);
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: GuardMode::Testnet,
        account: Some(ACCOUNT.to_owned()),
        api_wallet: Some(api_key().address().to_hex()),
        state_dir: dir.path().to_owned(),
        auth: AuthConfig {
            clients: vec![GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex()],
            ..AuthConfig::default()
        },
        policy: Policy {
            markets: Markets::from_list(["*".to_owned(), "xyz:*".to_owned()]),
            ..Policy::default()
        },
        ..GuardConfig::default()
    };
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(false),
        config.policy.risk_limits(),
        &config.journal_scope(false).unwrap(),
        Timestamp::from_millis(SystemClock.now_ms() as i64),
        dec!(10000),
        "HIP-3 test",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(false)).unwrap();
    let venue = MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "9000",
    );
    venue.set_dex_equity("xyz", "1000");
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
    // Guard refuses nonces from before its start plus 5 s.
    tokio::time::sleep(std::time::Duration::from_millis(5_100)).await;
    let (addr, _) = server::bind(guard.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    Running {
        url: format!("http://{addr}"),
        guard,
        dir,
    }
}

/// A ccxt-style IOC buy of `size` of asset `asset` at `price`, no stop.
fn buy(asset: u64, price: &str, size: &str) -> Value {
    let action = Wire::Map(vec![
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
                    Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Ioc"))]))]),
                ),
            ])]),
        ),
        ("grouping", Wire::str("na")),
    ]);
    signed(action)
}

fn signed(action: Wire) -> Value {
    let nonce = SystemClock.now_ms();
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

async fn post(url: &str, path: &str, body: &Value) -> Value {
    // One millisecond apart at least: each request needs a fresh nonce.
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let text = reqwest::Client::new()
        .post(format!("{url}{path}"))
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

async fn status(url: &str) -> Value {
    let text = reqwest::get(format!("{url}/guard/status"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// The asset ids of every action the venue received but cancels.
fn assets_sent(venue: &MemoryVenue) -> Vec<u32> {
    venue
        .received()
        .iter()
        .flat_map(|sent| match &sent.action {
            Action::Order(order) => order.orders.iter().map(|o| o.asset).collect(),
            Action::Modify(modify) => vec![modify.order.asset],
            Action::UpdateLeverage { asset, .. } | Action::UpdateIsolatedMargin { asset, .. } => {
                vec![*asset]
            }
            _ => Vec::new(),
        })
        .collect()
}

#[tokio::test]
async fn a_hip3_entry_is_read_judged_and_sent_on_its_own_dex() {
    let running = start("hip3-entry").await;
    // Buy 10 xyz:GOLD at the 4,000 mid. Equity 9,000 + 1,000 = 10,000:
    // the attached stop 3,920 (2% below); GOLD's fee scale 1.0 doubles the
    // fee, so 80 + 4,000 × 10 bp × 2 = 88 at risk a unit, 2.2727 within 2% of
    // equity; isolated 4x (GOLD's 20x: 5x puts the liquidation 17.95% away,
    // short of the 17.98% the stop's worst fill 3,528 needs); xyz's 1,000
    // free margin 1.0 GOLD at 4x: 1.0.
    let reply = post(
        &running.url,
        "/exchange",
        &buy(u64::from(GOLD), "4000", "10"),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["code"], "resized", "{reply}");
    assert_eq!(reply["size"], "1", "{reply}");
    let received = running.venue().received();
    assert_eq!(received.len(), 2, "{received:?}");
    assert_eq!(
        received[0].action,
        Action::UpdateLeverage {
            asset: GOLD,
            is_cross: false,
            leverage: 4
        }
    );
    let Action::Order(order) = &received[1].action else {
        panic!("{:?}", received[1])
    };
    let (entry, stop) = (&order.orders[0], &order.orders[1]);
    assert_eq!((entry.asset, entry.size.raw()), (GOLD, "1"));
    assert_eq!(stop.asset, GOLD);
    assert!(matches!(
        &stop.kind,
        OrderKind::Trigger { tpsl: Tpsl::Sl, trigger_px, is_market: true } if trigger_px.raw() == "3920"
    ));
    // Guard read xyz with its name, and GOLD's book.
    let log = running.venue().info_log();
    for (kind, dex) in [
        ("perpDexs", None),
        ("meta", Some("xyz")),
        ("clearinghouseState", Some("xyz")),
        ("frontendOpenOrders", Some("xyz")),
        ("allMids", Some("xyz")),
        ("perpsAtOpenInterestCap", Some("xyz")),
    ] {
        assert!(
            log.iter()
                .any(|body| body["type"] == kind && body["dex"].as_str() == dex),
            "{kind} {dex:?}: {log:?}"
        );
    }
    assert!(
        log.iter()
            .any(|body| body["type"] == "l2Book" && body["coin"] == "xyz:GOLD")
    );
    // The status shows each dex's own account.
    running.guard.sync().await;
    let status = status(&running.url).await;
    assert_eq!(status["dexes"][0]["name"], "", "{status}");
    assert_eq!(status["dexes"][1]["name"], "xyz", "{status}");
    assert_eq!(status["dexes"][1]["index"], 1, "{status}");
    assert_eq!(status["dexes"][1]["positions"], 1, "{status}");
}

#[tokio::test]
async fn a_hip3_entry_is_sized_with_its_dexs_fee() {
    let running = start("hip3-fee").await;
    // 10,000 on xyz (19,000 in all): the margin carries 10 GOLD at 4x and
    // the book 500, so the budget binds: 2% of 19,000 = 380 at 88 a unit
    // (GOLD's doubled fee) is 4.3181. At the main dex's fee (84.4 a unit)
    // it would be 4.5023, a loss at the stop beyond the budget.
    running.venue().set_dex_equity("xyz", "10000");
    let reply = post(
        &running.url,
        "/exchange",
        &buy(u64::from(GOLD), "4000", "10"),
    )
    .await;
    assert_eq!(reply["size"], "4.3181", "{reply}");
}

#[tokio::test]
async fn a_dex_that_cannot_be_read_blinds_neither_protection_nor_the_others() {
    // Three ways xyz can fail: its meta does not parse, its account read
    // fails (HTTP 500), its open orders carry another dex's coin.
    for (name, how) in [("meta", 0), ("read", 1), ("orders", 2)] {
        let running = start(&format!("hip3-broken-{name}")).await;
        match how {
            0 => running.venue().break_dex("xyz"),
            1 => running.venue().fail_reads("xyz"),
            _ => running.venue().garble_orders("xyz"),
        }
        // An ETH long without a stop on the main dex.
        running.venue().add_position("ETH", "1");
        running.guard.sync().await;
        // The main dex's position still gets Guard's stop (2% below 3,000).
        let orders = running.venue().orders();
        assert!(
            orders
                .iter()
                .any(|order| order["coin"] == "ETH" && order["triggerPx"] == "2940"),
            "{name}: {orders:?}"
        );
        let status = status(&running.url).await;
        assert!(
            status["last_error"].as_str().unwrap_or("").contains("xyz"),
            "{name}: {status}"
        );
        // The risk engine was shown nothing: no equity in the status.
        assert!(status["equity"].is_null(), "{name}: {status}");
        // No entry is judged against part of the account.
        let reply = post(&running.url, "/exchange", &buy(1, "3000", "0.1")).await;
        assert_eq!(reply["code"], "account_unreadable", "{name}: {reply}");
    }
}

#[tokio::test]
async fn halted_and_capped_hip3_markets_are_refused() {
    let running = start("hip3-refused").await;
    let code = |reply: &Value| reply["code"].as_str().unwrap_or("").to_owned();
    // GOLD at its open-interest cap before Guard first reads the caps
    // (they are reused for a minute).
    running.venue().cap("xyz:GOLD");
    // Halted by its deployer.
    let reply = post(
        &running.url,
        "/exchange",
        &buy(u64::from(URANIUM), "80", "1"),
    )
    .await;
    assert_eq!(code(&reply), "market_halted", "{reply}");
    // At its open-interest cap.
    let reply = post(
        &running.url,
        "/exchange",
        &buy(u64::from(GOLD), "4000", "1"),
    )
    .await;
    assert_eq!(code(&reply), "open_interest_cap", "{reply}");
    // Nothing reached the venue.
    assert!(running.venue().received().is_empty());
}

#[tokio::test]
async fn an_unfunded_dex_refuses_its_entries() {
    let running = start("hip3-unfunded").await;
    // 1 USDC free on xyz (and 9,999 on the main dex: 10,000 in all, as the
    // day started): 0.001 GOLD at 4x, worth 3.53 at the stop's worst fill,
    // below the venue's 10.
    running.venue().set_equity("9999");
    running.venue().set_dex_equity("xyz", "1");
    let reply = post(
        &running.url,
        "/exchange",
        &buy(u64::from(GOLD), "4000", "1"),
    )
    .await;
    assert_eq!(reply["code"], "dex_margin", "{reply}");
    assert!(running.venue().received().is_empty());
}

#[tokio::test]
async fn a_dex_the_rules_do_not_name_is_refused_reported_and_never_touched() {
    let running = start("hip3-unmanaged").await;
    // A position on abc, opened elsewhere and without a stop.
    running.venue().add_position("abc:FOO", "5");
    running.venue().set_dex_equity("abc", "200");
    let reply = post(&running.url, "/exchange", &buy(u64::from(FOO), "10", "1")).await;
    assert_eq!(reply["code"], "dex_not_allowed", "{reply}");
    // Margin added there: refused too.
    let margin = signed(Wire::Map(vec![
        ("type", Wire::str("updateIsolatedMargin")),
        ("asset", Wire::UInt(u64::from(FOO))),
        ("isBuy", Wire::Bool(true)),
        ("ntli", Wire::Int(1_000_000)),
    ]));
    let reply = post(&running.url, "/exchange", &margin).await;
    assert_eq!(reply["code"], "dex_not_allowed", "{reply}");
    // The sync's sweep finds it and reports it; it never gets a stop.
    running.guard.sync().await;
    let status = status(&running.url).await;
    assert_eq!(status["unmanaged_dexes"][0]["dex"], "abc", "{status}");
    assert_eq!(status["unmanaged_dexes"][0]["coins"], json!(["abc:FOO"]));
    assert!(
        status["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|alert| alert.as_str().unwrap().contains("abc:FOO")),
        "{status}"
    );
    // A main-dex and an xyz position, and the kill switch: Guard flattens
    // those two and leaves abc's.
    running.venue().add_position("ETH", "1");
    running.venue().add_position("xyz:GOLD", "0.5");
    std::fs::write(running.dir.path().join("kill"), "test\n").unwrap();
    running.guard.sync().await;
    let positions: Vec<String> = running
        .venue()
        .positions()
        .iter()
        .map(|p| p["position"]["coin"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(positions, vec!["abc:FOO".to_owned()], "{positions:?}");
    let sent = assets_sent(running.venue());
    assert!(sent.contains(&GOLD) && sent.contains(&1), "{sent:?}");
    assert!(!sent.contains(&FOO), "{sent:?}");
}

#[tokio::test]
async fn a_kill_counts_only_the_readable_part_of_a_partial_account() {
    let running = start("hip3-kill-partial").await;
    running.venue().add_position("ETH", "1");
    running.venue().add_position("xyz:GOLD", "0.5");
    running.venue().fail_reads("xyz");
    let killed = post(
        &running.url,
        "/guard/kill",
        &signed(zunder_guard_core::kill_wire("partial account")),
    )
    .await;
    assert_eq!(killed["positions_at_kill"], 1, "{killed}");
    assert!(
        killed["last_error"].as_str().unwrap().contains("xyz"),
        "{killed}"
    );
    // One managed dex is unreadable; the count cannot claim its position
    // was observed or closed. The readable ETH position was closed.
    let positions = running.venue().positions();
    assert_eq!(positions.len(), 1, "{positions:?}");
    assert_eq!(positions[0]["position"]["coin"], "xyz:GOLD");
    assert!(running.dir.path().join("kill").exists());
}

#[tokio::test]
async fn guard_protects_hip3_positions_and_counts_their_losses_account_wide() {
    let running = start("hip3-protect").await;
    // An xyz:GOLD long found without a stop: Guard's own stop, 2% below the
    // 4,000 mid, on GOLD's own id.
    running.venue().add_position("xyz:GOLD", "0.5");
    running.guard.sync().await;
    let orders = running.venue().orders();
    assert!(
        orders.iter().any(|order| order["coin"] == "xyz:GOLD"
            && order["triggerPx"] == "3920"
            && order["sz"] == "0.5"),
        "{orders:?}"
    );
    assert!(
        assets_sent(running.venue())
            .iter()
            .all(|asset| *asset == GOLD)
    );
    // xyz's account falls from 1,000 to 300: 9,300 in all, 7% down on the
    // day, beyond the 6% daily stop, though the main dex lost nothing.
    // Guard halts and closes the GOLD position.
    running.venue().set_dex_equity("xyz", "300");
    tokio::time::sleep(std::time::Duration::from_millis(5_100)).await;
    running.guard.sync().await;
    // Held until a ledger read at least 2 s on shows no withdrawal.
    tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
    running.guard.sync().await;
    let status = status(&running.url).await;
    assert_eq!(status["risk"]["state"], "halted_for_day", "{status}");
    assert_eq!(status["equity"], "9300", "{status}");
    assert!(
        running.venue().positions().is_empty(),
        "{:?}",
        running.venue().positions()
    );
}
