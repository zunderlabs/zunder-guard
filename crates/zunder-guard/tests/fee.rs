// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The builder fee end to end, against the in-memory venue: the field on
//! every order Guard sends once the account approved it, entries refused
//! while it has not, exits never refused, the venue's refusal of a
//! withdrawn approval, paper mode, and a bot's attempts to strip, alter or
//! approve the fee.
//!
//! Account: 10,000 USDC, mids BTC 60,000, ETH 3,000, SOL 150; default
//! policy; Guard's test builder at 20 tenths of a bp (0.02%), sending on
//! testnet as a testnet builder would.

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use rust_decimal::{Decimal, dec};
use serde_json::{Value, json};
use support::MemoryVenue;
use zunder_core::Timestamp;
use zunder_guard::{
    config::{GuardConfig, GuardMode, GuardNetwork},
    guard::{Clock, Guard, Limits, Mode, Setup, SystemClock},
    journal::DecisionJournal,
    testdir::TestDir,
};
use zunder_guard_core::{
    action::{Action, Builder, OrderAction},
    auth::AuthConfig,
    licence::{self, BUILDER_ON_TRIGGERS, FeeMode, FeeNetwork, ON_DEMAND_RECHECK_MS, Terms},
    sign::{Address, GuardKey, SigningNetwork},
    wire::{Wire, minimal_hex},
};
use zunder_venue::PersistentRisk;

const CLIENT_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
const BUILDER: &str = "0x00000000000000000000000000000000000000bb";

fn api_key() -> GuardKey {
    GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap()
}

/// A decimal the reply carries as a string.
fn decimal(value: &Value) -> Decimal {
    value.as_str().unwrap().parse().unwrap()
}

fn builder() -> Builder {
    Builder {
        address: BUILDER.into(),
        fee_tenths_bp: 20,
    }
}

/// A clock the test moves.
#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct Running {
    guard: Arc<Guard<MemoryVenue, TestClock>>,
    clock: TestClock,
    dir: TestDir,
    /// Trigger orders carry the builder field (`BUILDER_ON_TRIGGERS`,
    /// unless a test switched it off).
    on_triggers: bool,
}

impl Running {
    async fn switch_off_triggers(&mut self) {
        self.guard.set_builder_on_triggers(false).await;
        self.on_triggers = false;
    }

    fn venue(&self) -> &MemoryVenue {
        self.guard.upstream()
    }

    fn now(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Send a client-signed action now; the clock moves a millisecond so
    /// that every nonce is new.
    async fn send(&self, action: Wire) -> Value {
        self.clock.advance(1);
        let key = GuardKey::from_hex(CLIENT_KEY).unwrap();
        let nonce = self.now();
        let signature = key
            .sign_l1_action(SigningNetwork::Testnet, &action, nonce, None)
            .unwrap();
        let body = json!({
            "action": action.to_value(),
            "nonce": nonce,
            "signature": {"r": minimal_hex(&signature.r), "s": minimal_hex(&signature.s), "v": signature.v},
        });
        self.guard.exchange(body, "http").await
    }

    /// The order actions the venue received after the first `skip`.
    fn orders_after(&self, skip: usize) -> Vec<OrderAction> {
        self.venue()
            .received()
            .into_iter()
            .skip(skip)
            .filter_map(|received| match received.action {
                Action::Order(order) => Some(order),
                _ => None,
            })
            .collect()
    }
}

async fn start(fee: FeeMode, paper: bool) -> Running {
    start_warned(fee, None, paper).await
}

/// The config the tests' Guard runs with.
fn base_config(dir: &TestDir, paper: bool) -> GuardConfig {
    GuardConfig {
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
        ..GuardConfig::default()
    }
}

async fn start_warned(fee: FeeMode, fee_warning: Option<String>, paper: bool) -> Running {
    start_configured(fee, fee_warning, paper, None).await
}

async fn start_configured(
    fee: FeeMode,
    fee_warning: Option<String>,
    paper: bool,
    licence: Option<String>,
) -> Running {
    let dir = TestDir::new(if paper { "fee-paper" } else { "fee" });
    let mut config = base_config(&dir, paper);
    config.licence = licence;
    let clock = TestClock(Arc::new(AtomicU64::new(SystemClock.now_ms())));
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(paper),
        config.policy.risk_limits(),
        &config.journal_scope(paper).unwrap(),
        Timestamp::from_millis(clock.now_ms() as i64),
        dec!(10000),
        "fee test",
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
            fee,
            fee_warning,
            // No venue request limit in memory.
            limits: Limits {
                request_weight_per_second: 1_000_000,
                request_weight_burst: 1_000_000,
            },
        },
        venue,
        clock.clone(),
    )
    .unwrap();
    // Nonces count from Guard's start plus 5 s.
    clock.advance(6_000);
    Running {
        guard,
        clock,
        dir,
        on_triggers: BUILDER_ON_TRIGGERS,
    }
}

fn limit(asset: u64, is_buy: bool, price: &str, size: &str, reduce_only: bool) -> Wire {
    Wire::Map(vec![
        ("a", Wire::UInt(asset)),
        ("b", Wire::Bool(is_buy)),
        ("p", Wire::str(price)),
        ("s", Wire::str(size)),
        ("r", Wire::Bool(reduce_only)),
        (
            "t",
            Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Ioc"))]))]),
        ),
    ])
}

fn stop(asset: u64, is_buy: bool, trigger: &str, limit_px: &str, size: &str) -> Wire {
    Wire::Map(vec![
        ("a", Wire::UInt(asset)),
        ("b", Wire::Bool(is_buy)),
        ("p", Wire::str(limit_px)),
        ("s", Wire::str(size)),
        ("r", Wire::Bool(true)),
        (
            "t",
            Wire::Map(vec![(
                "trigger",
                Wire::Map(vec![
                    ("isMarket", Wire::Bool(true)),
                    ("triggerPx", Wire::str(trigger)),
                    ("tpsl", Wire::str("sl")),
                ]),
            )]),
        ),
    ])
}

/// `order` with the client id `cloid`.
fn with_cloid(order: Wire, cloid: &str) -> Wire {
    let Wire::Map(mut fields) = order else {
        panic!("an order is a map")
    };
    fields.push(("c", Wire::str(cloid)));
    Wire::Map(fields)
}

fn order_action(orders: Vec<Wire>, builder: Option<(&str, u64)>) -> Wire {
    let mut fields = vec![
        ("type", Wire::str("order")),
        ("orders", Wire::Array(orders)),
        ("grouping", Wire::str("na")),
    ];
    if let Some((address, fee)) = builder {
        fields.push((
            "builder",
            Wire::Map(vec![("b", Wire::str(address)), ("f", Wire::UInt(fee))]),
        ));
    }
    Wire::Map(fields)
}

/// A ccxt-style market buy of `size` ETH: an IOC limit 5% above the mid.
fn market_buy_eth(size: &str) -> Wire {
    order_action(vec![limit(1, true, "3150", size, false)], None)
}

/// With trigger orders switched off (`BUILDER_ON_TRIGGERS`), nothing the
/// venue received that holds a trigger order carries the field.
fn assert_triggers_follow_the_switch(running: &Running) {
    if running.on_triggers {
        return;
    }
    for order in running.orders_after(0) {
        if order.orders.iter().any(|order| order.is_trigger()) {
            assert_eq!(order.builder, None, "{order:?}");
        }
    }
}

#[tokio::test]
async fn every_order_guard_sends_carries_the_fee_once_approved() {
    let running = start(FeeMode::Builder(builder()), false).await;
    running.venue().approve_builder(20);
    running.guard.sync().await;
    assert_eq!(running.venue().builder_checks(), 1);
    let status = running.guard.status().await;
    assert_eq!(status["fee"]["approval"]["state"], "approved", "{status}");
    assert_eq!(status["fee"]["charged"], true);
    assert_eq!(status["fee"]["on_triggers"], true);
    assert_eq!(status["fee"]["rate"], "0.02%");

    // An entry: the entry and Guard's attached stop in one action. Sized
    // with the fee: risk per unit 75 (3,015 to the stop at 2,940) + 3,015 ×
    // (4.5 + 2 + 1) bp × 2 = 4.5225, so 79.5225; 200 / 79.5225 = 2.51501,
    // down to 2.515 (ETH: 4 decimals). Without the fee it was 2.5537
    // (`end_to_end.rs`). The action, entry and stop, carries the field.
    let reply = running.send(market_buy_eth("10")).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(decimal(&reply["size"]), dec!(2.515), "{reply}");
    let orders = running.orders_after(0);
    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].orders.len(), 2);
    assert!(orders[0].orders[1].is_trigger());
    assert_eq!(orders[0].builder, Some(builder()));
    let entry_fee = dec!(2.515) * dec!(3015) * dec!(20) / dec!(100000);
    assert_eq!(entry_fee, dec!(1.516545));

    // The bot's reduce-only close of part of it: the field.
    let before = running.venue().received().len();
    let reply = running
        .send(order_action(vec![limit(1, false, "2900", "1", true)], None))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let orders = running.orders_after(before);
    assert_eq!(orders.len(), 1);
    assert!(orders[0].orders[0].reduce_only);
    assert_eq!(orders[0].builder, Some(builder()));

    // The bot's own stop for the rest: the field.
    let before = running.venue().received().len();
    let reply = running
        .send(order_action(
            vec![stop(1, false, "2950", "2650", "1.515")],
            None,
        ))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(running.orders_after(before)[0].builder, Some(builder()));

    // Guard's own protective stop for a position opened elsewhere: the
    // field.
    running.venue().add_position("SOL", "10");
    running.clock.advance(31_000);
    let before = running.venue().received().len();
    running.guard.sync().await;
    let orders = running.orders_after(before);
    assert_eq!(orders.len(), 1, "{orders:?}");
    assert!(orders[0].orders[0].reduce_only && orders[0].orders[0].is_trigger());
    assert_eq!(orders[0].builder, Some(builder()));

    // A flatten (the kill switch): every close carries the field; cancels
    // have no builder field at all.
    std::fs::write(running.dir.path().join("kill"), "fee test\n").unwrap();
    let before = running.venue().received().len();
    running.guard.sync().await;
    let received: Vec<_> = running
        .venue()
        .received()
        .into_iter()
        .skip(before)
        .collect();
    let closes: Vec<&OrderAction> = received
        .iter()
        .filter_map(|r| match &r.action {
            Action::Order(order) => Some(order),
            _ => None,
        })
        .collect();
    assert!(!closes.is_empty(), "{received:?}");
    assert!(closes.iter().all(|order| order.builder == Some(builder())));
    for r in &received {
        if !matches!(r.action, Action::Order(_)) {
            assert!(r.json.get("builder").is_none(), "{:?}", r.json);
        }
    }
    assert!(running.venue().positions().is_empty());
    assert_triggers_follow_the_switch(&running);
}

#[tokio::test]
async fn with_triggers_switched_off_an_entry_with_its_stop_goes_without() {
    let mut running = start(FeeMode::Builder(builder()), false).await;
    running.switch_off_triggers().await;
    running.venue().approve_builder(20);
    running.guard.sync().await;
    let reply = running.send(market_buy_eth("10")).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let orders = running.orders_after(0);
    assert_eq!(orders[0].orders.len(), 2);
    assert_eq!(orders[0].builder, None);
    // A close still carries it.
    let before = running.venue().received().len();
    let reply = running
        .send(order_action(vec![limit(1, false, "2900", "1", true)], None))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(running.orders_after(before)[0].builder, Some(builder()));
    assert_triggers_follow_the_switch(&running);
}

/// A modify (one field Guard has no way to add a builder to) rests the
/// order under a new oid with the same client id, as the venue does
/// (testnet, 6 Oct 2026): Guard keeps knowing its stop by the client id.
#[tokio::test]
async fn guards_stop_is_known_by_its_client_id_after_a_modify() {
    let running = start(FeeMode::Builder(builder()), false).await;
    running.venue().approve_builder(20);
    running.guard.sync().await;
    // Guard's stop for an ETH long of 1 opened elsewhere: 2,940.
    running.venue().add_position("ETH", "1");
    running.clock.advance(31_000);
    running.guard.sync().await;
    let guards = running.venue().orders()[0].clone();
    let cloid = guards["cloid"].as_str().unwrap().to_owned();
    assert!(cloid.starts_with("0x7a67"));
    assert_eq!(guards["triggerPx"], "2940");
    // A modify that would give Guard's stop another client id: refused.
    let modify = |order: Wire| {
        Wire::Map(vec![
            ("type", Wire::str("modify")),
            ("oid", Wire::str(&cloid)),
            ("order", order),
        ])
    };
    let reply = running
        .send(modify(with_cloid(
            stop(1, false, "2950", "2655", "1"),
            "0x00000000000000000000000000000002",
        )))
        .await;
    assert_eq!(reply["code"], "invalid", "{reply}");
    // The bot tightens it to 2,950 by a modify naming no client id: Guard
    // puts the stop's own on it, and the venue rests it under a new oid.
    let before_modify = running.venue().received().len();
    let reply = running
        .send(modify(stop(1, false, "2950", "2655", "1")))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = running.venue().received()[before_modify].json.clone();
    assert_eq!(sent["order"]["c"], cloid.as_str(), "{sent}");
    let modified = running.venue().orders()[0].clone();
    assert_ne!(modified["oid"], guards["oid"]);
    assert_eq!(modified["cloid"], guards["cloid"]);
    assert_eq!(modified["triggerPx"], "2950");
    // Still Guard's: the bot cannot cancel it by its new oid.
    let cancel = Wire::Map(vec![
        ("type", Wire::str("cancel")),
        (
            "cancels",
            Wire::Array(vec![Wire::Map(vec![
                ("a", Wire::UInt(1)),
                ("o", Wire::UInt(modified["oid"].as_u64().unwrap())),
            ])]),
        ),
    ]);
    let reply = running.send(cancel).await;
    assert_eq!(reply["code"], "guard_stop", "{reply}");
    // Still covering: the next protect stacks no second stop.
    let before = running.venue().received().len();
    running.clock.advance(31_000);
    running.guard.sync().await;
    assert_eq!(running.venue().received().len(), before);
    // A tighter, full stop of the bot's replaces it: Guard cancels its own
    // by the oid it has now (read fresh for the request).
    let reply = running
        .send(order_action(
            vec![stop(1, false, "2960", "2660", "1")],
            None,
        ))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let last = running.venue().received().pop().unwrap();
    assert!(
        matches!(&last.action, Action::Cancel(cancels) if cancels.len() == 1),
        "{last:?}"
    );
    let resting = running.venue().orders();
    assert_eq!(resting.len(), 1, "{resting:?}");
    assert_eq!(resting[0]["triggerPx"], "2960");
}

#[tokio::test]
async fn a_short_gets_its_buy_stop_and_buy_close_with_the_field() {
    let running = start(FeeMode::Builder(builder()), false).await;
    running.venue().approve_builder(20);
    running.guard.sync().await;
    // A short opened elsewhere: Guard's stop is a buy trigger 2% above the
    // mid 3,000 (3,060), with the field.
    running.venue().add_position("ETH", "-1");
    running.clock.advance(31_000);
    running.guard.sync().await;
    let orders = running.orders_after(0);
    assert_eq!(orders.len(), 1, "{orders:?}");
    let stop = &orders[0].orders[0];
    assert!(stop.is_buy && stop.reduce_only && stop.is_trigger());
    assert_eq!(orders[0].builder, Some(builder()));
    assert_eq!(running.venue().orders()[0]["triggerPx"], "3060");
    // The bot's buy close of part of it: with the field.
    let before = running.venue().received().len();
    let reply = running
        .send(order_action(
            vec![limit(1, true, "3100", "0.4", true)],
            None,
        ))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let orders = running.orders_after(before);
    assert!(orders[0].orders[0].is_buy);
    assert_eq!(orders[0].builder, Some(builder()));
    // A flatten: the buy close of the rest carries it.
    std::fs::write(running.dir.path().join("kill"), "fee test\n").unwrap();
    let before = running.venue().received().len();
    running.guard.sync().await;
    let closes: Vec<OrderAction> = running.orders_after(before);
    assert!(!closes.is_empty());
    assert!(
        closes
            .iter()
            .all(|order| order.builder == Some(builder()) && order.orders.iter().all(|o| o.is_buy))
    );
    assert!(running.venue().positions().is_empty());
    assert_triggers_follow_the_switch(&running);
}

#[tokio::test]
async fn a_resting_entry_carries_the_field_and_a_refused_stop_is_covered_at_the_next_sync() {
    let running = start(FeeMode::Builder(builder()), false).await;
    running.venue().approve_builder(20);
    running.guard.sync().await;
    // A Gtc buy below the mid rests, with Guard's stop waiting for it, the
    // field on both (BUILDER_ON_RESTING_AND_POSITION_TPSL).
    let gtc = Wire::Map(vec![
        ("a", Wire::UInt(1)),
        ("b", Wire::Bool(true)),
        ("p", Wire::str("2950")),
        ("s", Wire::str("0.1")),
        ("r", Wire::Bool(false)),
        (
            "t",
            Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Gtc"))]))]),
        ),
    ]);
    let reply = running.send(order_action(vec![gtc], None)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let orders = running.orders_after(0);
    assert_eq!(orders.len(), 1, "{orders:?}");
    assert!(orders[0].orders.iter().any(|order| order.is_trigger()));
    assert_eq!(orders[0].builder, Some(builder()));
    let entry = running
        .venue()
        .orders()
        .iter()
        .find(|order| order["isTrigger"] == false)
        .and_then(|order| order["oid"].as_u64())
        .unwrap();
    // The approval is withdrawn; Guard has not read it yet. The entry fills
    // and the venue refuses to activate its stop (the case the fourth
    // testnet run looks at): a position of 0.1 without a stop.
    running.venue().approve_builder(0);
    running.venue().fill_resting(entry, true);
    assert!(running.venue().orders().is_empty());
    // The market went on down to 2,930 meanwhile.
    running.venue().set_mid("ETH", "2930");
    // Guard's next sync (once its send has settled, 5 s) covers it with the
    // stop the entry was sized for: 2% below the lower of its limit 2,950
    // and the mid then (3,000), 2,891; not 2% below today's mid (2,871.4).
    // First with the field (refused whole), then again without, resting.
    let before = running.venue().received().len();
    running.clock.advance(6_000);
    running.guard.sync().await;
    let sent = running.orders_after(before);
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[0].builder, Some(builder()));
    assert_eq!(sent[1].builder, None);
    let resting = running.venue().orders();
    assert_eq!(resting.len(), 1, "{resting:?}");
    assert_eq!(resting[0]["triggerPx"], "2891");
    assert_eq!(resting[0]["sz"], "0.1");
    assert_eq!(resting[0]["reduceOnly"], true);
}

/// A Gtc buy of 0.1 ETH at 2,950 with Guard's stop waiting for it (2,891:
/// 2% below the lower of the limit and the mid 3,000), sent with the field
/// while approved; then the approval withdrawn. Returns the entry's oid.
async fn resting_entry_then_withdrawn(running: &Running) -> u64 {
    running.venue().approve_builder(20);
    running.guard.sync().await;
    let gtc = Wire::Map(vec![
        ("a", Wire::UInt(1)),
        ("b", Wire::Bool(true)),
        ("p", Wire::str("2950")),
        ("s", Wire::str("0.1")),
        ("r", Wire::Bool(false)),
        (
            "t",
            Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Gtc"))]))]),
        ),
    ]);
    let reply = running.send(order_action(vec![gtc], None)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    running.venue().approve_builder(0);
    running
        .venue()
        .orders()
        .iter()
        .find(|order| order["isTrigger"] == false)
        .and_then(|order| order["oid"].as_u64())
        .unwrap()
}

/// The one resting order now, after a sync 6 s on.
async fn after_a_sync(running: &Running) -> Vec<Value> {
    running.clock.advance(6_000);
    running.guard.sync().await;
    running.venue().orders()
}

#[tokio::test]
async fn a_part_filled_resting_entry_gets_its_own_stop() {
    let running = start(FeeMode::Builder(builder()), false).await;
    let entry = resting_entry_then_withdrawn(&running).await;
    // Half fills; its stop is not activated; the rest keeps resting.
    running.venue().fill_resting_part(entry, Some("0.05"), true);
    running.venue().set_mid("ETH", "2930");
    let orders = after_a_sync(&running).await;
    let stops: Vec<&Value> = orders.iter().filter(|o| o["isTrigger"] == true).collect();
    assert_eq!(stops.len(), 1, "{orders:?}");
    // The entry's stop, 2,891, for what filled; not 2% below 2,930.
    assert_eq!(stops[0]["triggerPx"], "2891");
    assert_eq!(stops[0]["sz"], "0.05");
}

#[tokio::test]
async fn a_planned_stop_the_price_is_through_never_closes() {
    let running = start(FeeMode::Builder(builder()), false).await;
    let entry = resting_entry_then_withdrawn(&running).await;
    running.venue().fill_resting(entry, true);
    // The market fell through the entry's stop (2,891) to 2,880.
    running.venue().set_mid("ETH", "2880");
    let before = running.venue().received().len();
    let orders = after_a_sync(&running).await;
    // No close: a stop 2% below the mid, 2,822.4.
    let sent = running.orders_after(before);
    assert!(
        sent.iter()
            .all(|order| order.orders.iter().all(|o| o.is_trigger())),
        "{sent:?}"
    );
    assert_eq!(running.venue().positions().len(), 1);
    assert_eq!(orders.len(), 1, "{orders:?}");
    assert_eq!(orders[0]["triggerPx"], "2822.4");
}

#[tokio::test]
async fn a_cancelled_entry_lends_its_stop_to_no_other_position() {
    let running = start(FeeMode::Builder(builder()), false).await;
    let entry = resting_entry_then_withdrawn(&running).await;
    // Another bot's long of 1 ETH, then the entry (and its stop) gone
    // without a fill.
    running.venue().add_position("ETH", "1");
    running.venue().drop_order(entry);
    for order in running.venue().orders() {
        running.venue().drop_order(order["oid"].as_u64().unwrap());
    }
    running.venue().set_mid("ETH", "2930");
    let orders = after_a_sync(&running).await;
    // The default stop, 2% below 2,930: the entry's 2,891 is not its.
    assert_eq!(orders.len(), 1, "{orders:?}");
    assert_eq!(orders[0]["triggerPx"], "2871.4");
    assert_eq!(orders[0]["sz"], "1");
}

#[tokio::test]
async fn a_position_tpsl_carries_the_field_and_a_refused_one_is_covered_at_the_next_sync() {
    let running = start(FeeMode::Builder(builder()), false).await;
    running.venue().approve_builder(20);
    running.guard.sync().await;
    // A long of 1 with the bot's positionTpsl stop at 2,950, with the field.
    running.venue().add_position("ETH", "1");
    let position_stop = Wire::Map(vec![
        ("type", Wire::str("order")),
        (
            "orders",
            Wire::Array(vec![stop(1, false, "2950", "2650", "1")]),
        ),
        ("grouping", Wire::str("positionTpsl")),
    ]);
    let reply = running.send(position_stop).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = running.orders_after(0);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].builder, Some(builder()));
    let oid = running.venue().orders()[0]["oid"].as_u64().unwrap();
    // Withdrawn, and the venue refuses the stop when it fires: the position
    // stays without one. Guard's next sync covers it.
    running.venue().approve_builder(0);
    running.venue().drop_order(oid);
    let before = running.venue().received().len();
    running.clock.advance(6_000);
    running.guard.sync().await;
    let sent = running.orders_after(before);
    assert!(!sent.is_empty(), "nothing sent");
    assert_eq!(sent.last().unwrap().builder, None);
    let resting = running.venue().orders();
    assert_eq!(resting.len(), 1, "{resting:?}");
    assert_eq!(resting[0]["isTrigger"], true);
    assert_eq!(resting[0]["sz"], "1");
}

#[tokio::test]
async fn while_unapproved_a_modify_is_refused_and_a_new_stop_goes() {
    let running = start(FeeMode::Builder(builder()), false).await;
    running.venue().approve_builder(20);
    running.guard.sync().await;
    // A position with the bot's own stop, placed with the field.
    running.venue().add_position("ETH", "1");
    let own = "0x00000000000000000000000000000001";
    let reply = running
        .send(order_action(
            vec![with_cloid(stop(1, false, "2950", "2650", "1"), own)],
            None,
        ))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(running.orders_after(0)[0].builder, Some(builder()));
    // Withdrawn, and Guard has read it.
    running.venue().approve_builder(0);
    running.clock.advance(300_000);
    running.guard.sync().await;
    // A modify of the stop: refused while unconfirmed (the replacement's
    // fate after a withdrawal is not verified), nothing sent.
    let before = running.venue().received().len();
    let modify = Wire::Map(vec![
        ("type", Wire::str("modify")),
        ("oid", Wire::str(own)),
        (
            "order",
            with_cloid(stop(1, false, "2960", "2660", "1"), own),
        ),
    ]);
    let reply = running.send(modify).await;
    assert_eq!(reply["code"], "fee_not_approved", "{reply}");
    assert_eq!(running.venue().received().len(), before);
    // A new, tighter stop goes, without the field.
    let reply = running
        .send(order_action(
            vec![stop(1, false, "2960", "2660", "1")],
            None,
        ))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = running.orders_after(before);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].builder, None);
    // A bot may not give its own order one of Guard's client ids.
    let modify = Wire::Map(vec![
        ("type", Wire::str("modify")),
        ("oid", Wire::str(own)),
        (
            "order",
            with_cloid(
                stop(1, false, "2955", "2655", "1"),
                "0x7a670000000000000000000000000001",
            ),
        ),
    ]);
    let reply = running.send(modify).await;
    assert_eq!(reply["code"], "invalid", "{reply}");
}

#[tokio::test]
async fn a_stop_refused_after_an_unnoticed_withdrawal_goes_again_without_the_field() {
    let running = start(FeeMode::Builder(builder()), false).await;
    running.venue().approve_builder(20);
    running.guard.sync().await;
    running.venue().add_position("ETH", "1");
    // Withdrawn in the wallet; Guard has not read it yet. The bot's stop
    // goes with the field, the venue refuses it whole, Guard sends it
    // again without, and it rests.
    running.venue().approve_builder(0);
    let reply = running
        .send(order_action(
            vec![stop(1, false, "2950", "2650", "1")],
            None,
        ))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert!(
        reply["response"]["data"]["statuses"][0]
            .get("resting")
            .is_some(),
        "{reply}"
    );
    let sent = running.orders_after(0);
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[0].builder, Some(builder()));
    assert_eq!(sent[1].builder, None);
    assert_eq!(running.venue().orders().len(), 1);
}

#[tokio::test]
async fn entries_wait_for_the_approval_and_exits_never_do() {
    let running = start(FeeMode::Builder(builder()), false).await;
    // Not approved (the venue answers 0).
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["fee"]["approval"]["state"], "not_approved");
    assert_eq!(status["fee"]["entries_blocked"], true);
    assert_eq!(
        status["fee"]["approve_url"],
        "https://zunderlabs.com/approve"
    );
    assert!(
        status["alerts"]
            .to_string()
            .contains("zunderlabs.com/approve"),
        "{status}"
    );

    // An entry is refused with its own code; nothing reaches the venue,
    // and no read happens in the request.
    let reply = running.send(market_buy_eth("1")).await;
    assert_eq!(reply["code"], "fee_not_approved", "{reply}");
    assert!(
        reply["response"]
            .as_str()
            .unwrap()
            .contains("https://zunderlabs.com/approve")
    );
    assert!(running.venue().received().is_empty());
    assert_eq!(running.venue().builder_checks(), 1);

    // A position opened elsewhere: Guard's protective stop goes, without
    // the builder field.
    running.venue().add_position("SOL", "10");
    running.clock.advance(31_000);
    running.guard.sync().await;
    let orders = running.orders_after(0);
    assert_eq!(orders.len(), 1, "{orders:?}");
    assert!(orders[0].orders[0].is_trigger());
    assert_eq!(orders[0].builder, None);
    // The bot's reduce-only close: forwarded, without the field.
    let before = running.venue().received().len();
    let reply = running
        .send(order_action(vec![limit(2, false, "140", "10", true)], None))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let orders = running.orders_after(before);
    assert_eq!(orders[0].builder, None);
    assert!(running.venue().positions().is_empty());

    // The person approves. The next entry is still refused, but asks for a
    // check (its last one is over 15 s old), which the next sync makes
    // outside the request; then entries go.
    running.venue().approve_builder(20);
    running.clock.advance(20_000);
    let checks = running.venue().builder_checks();
    let reply = running.send(market_buy_eth("1")).await;
    assert_eq!(reply["code"], "fee_not_approved", "{reply}");
    assert_eq!(running.venue().builder_checks(), checks);
    running.guard.sync().await;
    assert_eq!(running.venue().builder_checks(), checks + 1);
    let reply = running.send(market_buy_eth("1")).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_triggers_follow_the_switch(&running);
}

#[tokio::test]
async fn a_withdrawn_approval_never_blocks_an_exit() {
    let running = start(FeeMode::Builder(builder()), false).await;
    running.venue().approve_builder(20);
    running.guard.sync().await;
    let reply = running.send(market_buy_eth("1")).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(running.venue().positions().len(), 1);

    // Withdrawn in the wallet; Guard has not read it yet. The bot's close
    // goes with the field, the venue refuses it whole, Guard sends it again
    // without, and it fills.
    running.venue().approve_builder(0);
    let before = running.venue().received().len();
    let reply = running
        .send(order_action(vec![limit(1, false, "2900", "1", true)], None))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert!(
        reply["response"]["data"]["statuses"][0]
            .get("filled")
            .is_some(),
        "{reply}"
    );
    let orders = running.orders_after(before);
    assert_eq!(orders.len(), 2, "{orders:?}");
    assert_eq!(orders[0].builder, Some(builder()));
    assert_eq!(orders[1].builder, None);
    assert_eq!(orders[0].orders, orders[1].orders);
    let status = running.guard.status().await;
    assert_eq!(status["fee"]["approval"]["state"], "refused_by_venue");
    assert_eq!(
        status["fee"]["approval"]["venue"],
        "Builder fee has not been approved."
    );
    assert_eq!(status["fee"]["entries_blocked"], true);
    assert!(
        status["alerts"].to_string().contains("withdrawn"),
        "{status}"
    );
    // The journal shows what went out the second time.
    let events = running.guard.events(0).await;
    let resent = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "sent" && event.get("action").is_some())
        .count();
    assert_eq!(resent, 1, "{events}");

    // The next entry is refused without reaching the venue.
    running.clock.advance(ON_DEMAND_RECHECK_MS);
    let before = running.venue().received().len();
    let reply = running.send(market_buy_eth("1")).await;
    assert_eq!(reply["code"], "fee_not_approved", "{reply}");
    assert_eq!(running.venue().received().len(), before);
}

#[tokio::test]
async fn an_entry_the_venue_refuses_for_the_fee_is_reported_as_such() {
    let running = start(FeeMode::Builder(builder()), false).await;
    running.venue().approve_builder(20);
    running.guard.sync().await;
    // Lowered to 10 in the wallet; Guard still believes 20.
    running.venue().approve_builder(10);
    let reply = running.send(market_buy_eth("1")).await;
    assert_eq!(reply["code"], "fee_not_approved", "{reply}");
    // Nothing was placed, and nothing was sent again without the field.
    let orders = running.orders_after(0);
    assert_eq!(orders.len(), 1, "{orders:?}");
    assert_eq!(orders[0].builder, Some(builder()));
    assert!(running.venue().positions().is_empty());
    assert!(running.venue().orders().is_empty());
}

#[tokio::test]
async fn paper_mode_reports_the_fee_and_never_blocks() {
    let running = start(FeeMode::Builder(builder()), true).await;
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["fee"]["paper"], true);
    assert_eq!(status["fee"]["entries_blocked"], false);
    assert_eq!(status["fee"]["approval"]["state"], "not_approved");
    // Would resize, with the fee it would charge: 2.515 ETH at the worst
    // price 3,015 is 7,582.725 USDC; 0.02% of it is 1.516545 USDC.
    let reply = running.send(market_buy_eth("10")).await;
    assert!(
        reply["response"]
            .as_str()
            .unwrap()
            .contains("paper mode: would resize"),
        "{reply}"
    );
    assert_eq!(decimal(&reply["size"]), dec!(2.515), "{reply}");
    assert_eq!(reply["builder_fee"]["rate"], "0.02%");
    assert_eq!(
        decimal(&reply["builder_fee"]["entry_usdc_at_worst_price"]),
        dec!(1.516545)
    );
    assert_eq!(reply["builder_fee"]["approved"], false);
    assert!(running.venue().received().is_empty());
}

#[tokio::test]
async fn a_bot_cannot_strip_alter_or_approve_the_fee() {
    let running = start(FeeMode::Builder(builder()), false).await;
    running.venue().approve_builder(100);
    running.guard.sync().await;
    running.venue().add_position("ETH", "4");
    // Its own builder field, whatever it names (Guard's own address at a
    // lower fee, at zero, or another builder): refused on an entry;
    // removed from a close, which goes with Guard's own field.
    for builder_field in [
        (BUILDER, 0),
        (BUILDER, 10),
        (BUILDER, 20),
        ("0x00000000000000000000000000000000000000cc", 100),
    ] {
        let before = running.venue().received().len();
        let entry = order_action(
            vec![limit(1, true, "3150", "1", false)],
            Some(builder_field),
        );
        let reply = running.send(entry).await;
        assert_eq!(
            reply["code"], "client_builder",
            "{builder_field:?}: {reply}"
        );
        assert_eq!(running.venue().received().len(), before);
        let close = order_action(
            vec![limit(1, false, "2900", "1", true)],
            Some(builder_field),
        );
        let reply = running.send(close).await;
        assert_eq!(reply["status"], "ok", "{builder_field:?}: {reply}");
        let sent = running.orders_after(before);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].builder, Some(builder()), "{builder_field:?}");
    }
    assert!(running.venue().positions().is_empty());
    // Approving a builder fee or setting a referrer: refused by name.
    let before = running.venue().received().len();
    let approve = Wire::Map(vec![
        ("type", Wire::str("approveBuilderFee")),
        ("hyperliquidChain", Wire::str("Testnet")),
        ("signatureChainId", Wire::str("0x66eee")),
        ("maxFeeRate", Wire::str("0%")),
        ("builder", Wire::str(BUILDER)),
        ("nonce", Wire::UInt(running.now())),
    ]);
    let reply = running.send(approve).await;
    assert_eq!(reply["code"], "funds_or_permissions", "{reply}");
    let referrer = Wire::Map(vec![
        ("type", Wire::str("setReferrer")),
        ("code", Wire::str("SOMEONE")),
    ]);
    let reply = running.send(referrer).await;
    assert_eq!(reply["code"], "funds_or_permissions", "{reply}");
    assert_eq!(running.venue().received().len(), before);
}

#[tokio::test]
async fn without_a_builder_nothing_is_read_or_attached() {
    let running = start(FeeMode::Off("testnet".into()), false).await;
    running.guard.sync().await;
    assert_eq!(running.venue().builder_checks(), 0);
    let reply = running.send(market_buy_eth("1")).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(running.orders_after(0)[0].builder, None);
    // A fee-free licence: the same.
    let running = start(
        FeeMode::FeeFree {
            licensee: "Desk".into(),
        },
        false,
    )
    .await;
    running.guard.sync().await;
    assert_eq!(running.venue().builder_checks(), 0);
    let reply = running.send(market_buy_eth("1")).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(running.orders_after(0)[0].builder, None);
    assert_eq!(running.guard.status().await["fee"]["mode"], "fee_free");
}

/// Red team: a licence key issued for another account buys nothing here.
/// A fee-free key for 0x…01 given to the Guard of `ACCOUNT` (mainnet's fee
/// rules, the test's own signing key): Guard runs with the builder fee,
/// journals why, and the bot's orders carry the fee as without a key.
#[tokio::test]
async fn redteam_a_licence_for_another_account_buys_nothing() {
    let secret = [7u8; 32];
    let public = licence::public_key_of(&secret);
    let key = licence::issue(
        &Terms {
            licensee: "Someone Else GmbH".into(),
            expires_at_ms: 4_102_444_800_000,
            features: vec!["fee_free".into()],
            accounts: vec!["0x0000000000000000000000000000000000000001".into()],
            builder: None,
        },
        &secret,
    )
    .unwrap();
    let (mode, warning) = licence::fee_mode_with(
        FeeNetwork::Mainnet,
        Some(&key),
        Some(&public),
        SystemClock.now_ms() as i64,
        Address::from_hex(ACCOUNT).unwrap(),
        Some(BUILDER),
        None,
    );
    assert_eq!(mode, FeeMode::Builder(builder()));
    let warning = warning.unwrap();
    assert!(warning.contains("is not for account"), "{warning}");
    let running = start_warned(mode, Some(warning), false).await;
    running.venue().approve_builder(20);
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["fee"]["mode"], "builder", "{status}");
    let events = serde_json::to_string(&running.guard.events(0).await).unwrap();
    assert!(events.contains("is not for account"), "{events}");
    // The bot's reduce-only close carries the builder field.
    let reply = running
        .send(order_action(vec![limit(1, false, "2900", "1", true)], None))
        .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let orders = running.orders_after(0);
    assert_eq!(orders.last().unwrap().builder, Some(builder()));
}

/// A licence for the test account, signed with the test key, ending at
/// `expires_at_ms`.
fn licence_key(expires_at_ms: i64, accounts: &[&str]) -> String {
    licence::issue(
        &Terms {
            licensee: "Example GmbH".into(),
            expires_at_ms,
            features: vec!["fee_free".into()],
            accounts: accounts.iter().map(|a| (*a).to_owned()).collect(),
            builder: None,
        },
        &licence::test_key::SEED,
    )
    .unwrap()
}

fn alerts(status: &Value) -> Vec<String> {
    status["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|alert| alert.as_str().unwrap().to_owned())
        .collect()
}

/// The licence lifecycle (`licence.rs`, "Lifecycle"): a key written into
/// the config file applies at the next sync without a restart; Guard warns
/// 14, 7 and 1 days before it ends, one alert at a time; once it has
/// ended, the very next order already runs with the builder fee (an entry
/// then waits for the fee's approval), without waiting for a sync.
#[tokio::test]
async fn a_licence_applies_live_warns_before_it_ends_and_falls_back_at_the_next_order() {
    const DAY: u64 = 86_400_000;
    let running = start(FeeMode::Builder(builder()), false).await;
    running
        .guard
        .set_licence_keys_for_test(licence::test_key::public(), None, Some(BUILDER.into()))
        .await;
    let path = running.dir.path().join("guard.toml");
    let config = base_config(&running.dir, false);
    std::fs::write(&path, config.to_toml().unwrap()).unwrap();
    running.guard.watch_config(path.clone()).await;
    let entry = || order_action(vec![limit(1, true, "3000", "0.01", false)], None);
    // No licence, the fee not approved: entries wait.
    let reply = running.send(entry()).await;
    assert_eq!(reply["code"], "fee_not_approved", "{reply}");
    // `licence set`: the key in the config file, applied at the next sync.
    let ends = running.now() + 20 * DAY;
    let key = licence_key(ends as i64, &[ACCOUNT]);
    let licensed = GuardConfig {
        licence: Some(key),
        ..config.clone()
    };
    std::fs::write(&path, licensed.to_toml().unwrap()).unwrap();
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["fee"]["mode"], "fee_free", "{status}");
    assert_eq!(status["licence"]["state"], "active", "{status}");
    assert_eq!(status["licence"]["days_left"], 20, "{status}");
    assert_eq!(status["licence"]["auto_update"], false, "{status}");
    let reply = running.send(entry()).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(running.orders_after(0).last().unwrap().builder, None);
    // 13 days before the end: the 14-day warning.
    running.clock.advance(7 * DAY);
    running.guard.sync().await;
    let warned = alerts(&running.guard.status().await);
    assert!(
        warned
            .iter()
            .any(|alert| alert.contains("ends in 13 day(s)")),
        "{warned:?}"
    );
    // Half a day before: the last warning replaces it.
    running.clock.advance(12 * DAY + DAY / 2);
    running.guard.sync().await;
    let warned = alerts(&running.guard.status().await);
    let licence_alerts: Vec<&String> = warned
        .iter()
        .filter(|alert| alert.starts_with("licence: "))
        .collect();
    assert_eq!(licence_alerts.len(), 1, "{warned:?}");
    assert!(licence_alerts[0].contains("ends in 1 day(s)"), "{warned:?}");
    // It stays while it holds (other alerts go after an hour).
    running.clock.advance(2 * 3_600_000);
    running.guard.sync().await;
    let warned = alerts(&running.guard.status().await);
    assert!(
        warned
            .iter()
            .any(|alert| alert.contains("ends in 1 day(s)")),
        "{warned:?}"
    );
    let reply = running.send(entry()).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    // Ended: the next order already runs with the fee, before any sync.
    running.clock.advance(DAY / 2 - 2 * 3_600_000 + 1);
    let reply = running.send(entry()).await;
    assert_eq!(reply["code"], "fee_not_approved", "{reply}");
    let status = running.guard.status().await;
    assert_eq!(status["fee"]["mode"], "builder", "{status}");
    assert_eq!(status["licence"]["state"], "not_used", "{status}");
    assert!(
        alerts(&status)
            .iter()
            .any(|alert| alert.contains("the licence expired")),
        "{status}"
    );
    let events = running.guard.events(0).await;
    assert!(
        events.to_string().contains("the licence expired"),
        "journaled"
    );
}

#[tokio::test]
async fn startup_rechecks_a_licence_instead_of_retaining_the_callers_free_mode() {
    let expired = licence_key(SystemClock.now_ms() as i64 - 1, &[ACCOUNT]);
    let running = start_configured(
        FeeMode::FeeFree {
            licensee: "expired".into(),
        },
        None,
        false,
        Some(expired),
    )
    .await;
    assert_ne!(running.guard.status().await["fee"]["mode"], "fee_free");
}

#[tokio::test]
async fn expiry_during_an_account_read_refuses_the_entry_before_sending() {
    let running = start(FeeMode::Builder(builder()), false).await;
    running
        .guard
        .set_licence_keys_for_test(licence::test_key::public(), None, Some(BUILDER.into()))
        .await;
    let path = running.dir.path().join("guard.toml");
    let config = base_config(&running.dir, false);
    std::fs::write(&path, config.to_toml().unwrap()).unwrap();
    running.guard.watch_config(path.clone()).await;
    let config = GuardConfig {
        licence: Some(licence_key((running.now() + 100) as i64, &[ACCOUNT])),
        ..config
    };
    std::fs::write(&path, config.to_toml().unwrap()).unwrap();
    running.guard.sync().await;
    assert_eq!(running.guard.status().await["fee"]["mode"], "fee_free");
    running.venue().slow_reads(100);
    let before = running.venue().received().len();
    let clock = running.clock.clone();
    let (reply, ()) = tokio::join!(
        running.send(order_action(
            vec![limit(1, true, "3000", "0.01", false)],
            None
        )),
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            clock.advance(200);
        }
    );
    assert!(running.orders_after(before).is_empty(), "{reply}");
    assert_eq!(running.guard.status().await["fee"]["mode"], "builder");
}

/// A key for another account written into the config file is not used
/// (the fee stays), with an alert; a config file that cannot be read keeps
/// the key Guard runs with.
#[tokio::test]
async fn a_bad_new_licence_key_or_an_unreadable_config_changes_nothing() {
    const DAY: u64 = 86_400_000;
    let running = start(FeeMode::Builder(builder()), false).await;
    running
        .guard
        .set_licence_keys_for_test(licence::test_key::public(), None, Some(BUILDER.into()))
        .await;
    let path = running.dir.path().join("guard.toml");
    let config = base_config(&running.dir, false);
    let good = licence_key((running.now() + 30 * DAY) as i64, &[ACCOUNT]);
    std::fs::write(
        &path,
        GuardConfig {
            licence: Some(good),
            ..config.clone()
        }
        .to_toml()
        .unwrap(),
    )
    .unwrap();
    running.guard.watch_config(path.clone()).await;
    // A key installed while startup was waiting applies when watching begins.
    running.guard.sync().await;
    assert_eq!(running.guard.status().await["fee"]["mode"], "fee_free");
    // Changed: read, applied.
    let good = licence_key((running.now() + 31 * DAY) as i64, &[ACCOUNT]);
    std::fs::write(
        &path,
        GuardConfig {
            licence: Some(good),
            ..config.clone()
        }
        .to_toml()
        .unwrap(),
    )
    .unwrap();
    running.guard.sync().await;
    assert_eq!(running.guard.status().await["fee"]["mode"], "fee_free");
    // Unreadable: the key Guard runs with stays.
    std::fs::write(&path, "not toml at all [").unwrap();
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["fee"]["mode"], "fee_free", "{status}");
    assert!(
        alerts(&status)
            .iter()
            .any(|alert| alert.contains("could not be read")),
        "{status}"
    );
    // A key for another account: not used, the fee, an alert.
    let other = licence_key(
        (running.now() + 30 * DAY) as i64,
        &["0x0000000000000000000000000000000000000001"],
    );
    std::fs::write(
        &path,
        GuardConfig {
            licence: Some(other),
            ..config
        }
        .to_toml()
        .unwrap(),
    )
    .unwrap();
    running.guard.sync().await;
    let status = running.guard.status().await;
    assert_eq!(status["fee"]["mode"], "builder", "{status}");
    assert_eq!(status["licence"]["state"], "not_used", "{status}");
    assert!(
        alerts(&status)
            .iter()
            .any(|alert| alert.contains("not for account")),
        "{status}"
    );
}

/// A renewal and a wrong-account key have the same encoded length as the
/// original key: 13-digit expiry, one 42-character account and fixed signature.
/// Both must apply at the next sync even when the timestamp also stays equal.
async fn same_metadata_licence_changes_are_read(atomic: bool) {
    const DAY: u64 = 86_400_000;
    let running = start(FeeMode::Builder(builder()), false).await;
    running
        .guard
        .set_licence_keys_for_test(licence::test_key::public(), None, Some(BUILDER.into()))
        .await;
    let path = running.dir.path().join("guard.toml");
    let config = base_config(&running.dir, false);
    let first = licence_key((running.now() + 30 * DAY) as i64, &[ACCOUNT]);
    let text = GuardConfig {
        licence: Some(first),
        ..config.clone()
    }
    .to_toml()
    .unwrap();
    std::fs::write(&path, &text).unwrap();
    let original = std::fs::metadata(&path).unwrap();
    let modified = original.modified().unwrap();
    running.guard.watch_config(path.clone()).await;
    assert_eq!(running.guard.status().await["fee"]["mode"], "fee_free");

    let renewed_until = (running.now() + 31 * DAY) as i64;
    let renewed = licence_key(renewed_until, &[ACCOUNT]);
    let wrong_account = licence_key(
        (running.now() + 30 * DAY) as i64,
        &["0x0000000000000000000000000000000000000001"],
    );
    for (key, valid) in [(renewed, true), (wrong_account, false)] {
        let next = GuardConfig {
            licence: Some(key.clone()),
            ..config.clone()
        }
        .to_toml()
        .unwrap();
        assert_eq!(next.len() as u64, original.len());
        assert_ne!(std::fs::read_to_string(&path).unwrap(), next);
        if atomic {
            // Exercise the same synced atomic updater used by licence set/renewal.
            GuardConfig::update(&path, |current| current.licence = Some(key)).unwrap();
        } else {
            std::fs::write(&path, next).unwrap();
        }
        // Force the old cache fingerprint without sleeps or OS clock assumptions.
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        drop(file);
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(after.len(), original.len());
        assert_eq!(after.modified().unwrap(), modified);
        running.guard.sync().await;
        let status = running.guard.status().await;
        if valid {
            assert_eq!(
                status["licence"]["expires_at_ms"], renewed_until,
                "{status}"
            );
            assert_eq!(status["licence"]["state"], "active", "{status}");
            assert_eq!(status["fee"]["mode"], "fee_free", "{status}");
        } else {
            assert_eq!(status["licence"]["state"], "not_used", "{status}");
            assert_eq!(status["fee"]["mode"], "builder", "{status}");
            assert!(
                alerts(&status)
                    .iter()
                    .any(|alert| alert.contains("not for account")),
                "{status}"
            );
        }
    }
}

#[tokio::test]
async fn same_metadata_licence_rewrite_applies_at_the_next_sync() {
    same_metadata_licence_changes_are_read(false).await;
}

#[tokio::test]
async fn same_metadata_atomic_licence_replacement_applies_at_the_next_sync() {
    same_metadata_licence_changes_are_read(true).await;
}
