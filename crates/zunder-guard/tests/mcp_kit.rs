// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The agent kit (`zunder-guard-mcp`) end to end against the real Guard in
//! paper mode: the kit's MCP server, its signer and its contract module on
//! one side, Guard's real HTTP server, judge and journals on the other, the
//! in-memory venue behind Guard (reads only). Nothing can be sent.
//!
//! Account: 10,000 USDC, mids BTC 60,000, ETH 3,000, SOL 150; Guard's
//! default policy.

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use rust_decimal::dec;
use serde_json::{Value, json};
use support::MemoryVenue;
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
    sign::{Address, GuardKey},
};
use zunder_guard_mcp::{
    contract::{self, Mode as KitMode},
    guard::{GuardClient, GuardUrl},
    protocol,
    ratelimit::SystemClock as KitClock,
    sign::ClientKey,
    tools::{Config, Server},
};
use zunder_venue::PersistentRisk;

/// The agent's client key: the SDK tests' throwaway key.
const CLIENT_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

fn api_key() -> GuardKey {
    GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap()
}

struct Running {
    url: String,
    guard: Arc<Guard<MemoryVenue>>,
    _dir: TestDir,
}

async fn start_paper() -> Running {
    let dir = TestDir::new("mcp-kit");
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: GuardMode::Paper,
        account: Some(ACCOUNT.to_owned()),
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
        dec!(10000),
        "mcp kit test",
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
    // Nonces count from Guard's start plus 5 s, as for any client.
    tokio::time::sleep(std::time::Duration::from_millis(5_100)).await;
    guard.sync().await;
    let (addr, _) = server::bind(guard.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    Running {
        url: format!("http://{addr}"),
        guard,
        _dir: dir,
    }
}

fn kit(url: &str) -> Server {
    Server::new(
        Config {
            network: KitMode::Paper,
            kill_file: None,
            confirm_account: None,
            kill_confirm_wait_ms: 5_000,
        },
        GuardClient::new(GuardUrl::parse(url).unwrap()).unwrap(),
        Some(ClientKey::from_hex(CLIENT_KEY).unwrap()),
        Box::new(KitClock),
    )
}

/// A GET answered with JSON (blocking: the kit's side of the test runs on a
/// blocking thread, as the kit itself does).
fn get_json(url: &str) -> Value {
    let text = reqwest::blocking::get(url).unwrap().text().unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Call a tool on the kit.
fn call(server: &mut Server, name: &str, arguments: Value) -> (bool, Value) {
    let message = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}});
    let reply = protocol::handle(server, &message.to_string()).unwrap();
    let result = &reply["result"];
    (
        result["isError"].as_bool().unwrap(),
        result["structuredContent"].clone(),
    )
}

/// The agent's side: the kit's MCP server and plain GETs, on a blocking
/// thread. Returns the decision Guard journaled for the entry.
fn agent(url: &str) -> Value {
    // The kit reads Guard's status as schema 1, rules code and all.
    let status = get_json(&format!("{url}/guard/status"));
    let parsed = contract::parse_status(&status).unwrap();
    assert_eq!(parsed.mode, KitMode::Paper);
    assert!(!parsed.killed);
    let rules = contract::Rules::decode(&parsed.rules_code).unwrap();
    assert_eq!(rules.max_leverage, dec!(5));
    assert_eq!(rules.max_loss_at_stop_pct, dec!(2));

    let mut server = kit(url);
    let (error, overview) = call(&mut server, "account_overview", json!({}));
    assert!(!error, "{overview}");
    let (error, limits) = call(&mut server, "limits", json!({}));
    assert!(!error, "{limits}");

    // An entry through the kit: Guard judges it for real and, in paper
    // mode, sends nothing. 0.5 BTC with a stop at 58,800 is cut to what
    // 2% of 10,000 allows.
    let (_, placed) = call(
        &mut server,
        "place_order",
        json!({"coin": "BTC", "side": "buy", "stop": "58800", "size": "0.5"}),
    );
    println!("place_order: {placed}");
    let events = get_json(&format!("{url}/guard/events?since=0"));
    let decision = events
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|event| event["kind"] == "decision")
        .cloned()
        .unwrap();
    assert_eq!(decision["verdict"], "resize", "{decision}");
    // Found again by its nonce, from the journal on disk.
    let nonce = decision["nonce"].as_u64().unwrap();
    let client = GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex();
    let found = get_json(&format!(
        "{url}/guard/decision?nonce={nonce}&client={client}"
    ));
    assert_eq!(found["decision"]["seq"], decision["seq"]);

    let (error, recent) = call(&mut server, "recent_decisions", json!({}));
    assert!(!error, "{recent}");

    // The kill switch through Guard's signed endpoint: latched at once.
    let (error, pulled) = call(
        &mut server,
        "kill_switch",
        json!({"confirm": true, "reason": "agent test"}),
    );
    assert!(!error, "{pulled}");
    assert_eq!(pulled["pulled_through"], "guard_kill_endpoint", "{pulled}");
    assert_eq!(pulled["guard_reports_killed"], true, "{pulled}");
    // Entries are refused now.
    let (error, refused) = call(
        &mut server,
        "place_order",
        json!({"coin": "BTC", "side": "buy", "stop": "58800", "size": "0.01"}),
    );
    assert!(error, "{refused}");
    decision
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_kit_works_against_the_real_guard_in_paper_mode() {
    let running = start_paper().await;
    let url = running.url.clone();
    let decision = tokio::task::spawn_blocking(move || agent(&url))
        .await
        .unwrap();
    assert_eq!(decision["action"], "order");
    let status = running.guard.status().await;
    assert!(
        status["killed"].as_str().unwrap().contains("agent test"),
        "{status}"
    );
    // Paper: nothing reached the venue at any point.
    assert!(running.guard.upstream().received().is_empty());
}
