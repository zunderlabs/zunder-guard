// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The agent kit (`zunder-guard-mcp`) end to end against the real Guard in
//! paper mode: the kit's MCP server, its signer and its contract module on
//! one side, Guard's real HTTP server, judge and journals on the other, the
//! in-memory venue behind Guard (reads only). Nothing can be sent.
//!
//! One test also runs a testnet Guard on the in-memory venue (which records
//! what it is sent) behind the same address as a paper Guard, to show that
//! the kit's `expectedMode` stops a request meant for one mode from being
//! sent in another.
//!
//! Account: 10,000 USDC, mids BTC 60,000, ETH 3,000, SOL 150; Guard's
//! default policy.

#![allow(clippy::unwrap_used)]

mod support;

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
};

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
    sign::{Address, GuardKey, SigningNetwork},
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
    dir: TestDir,
}

async fn start_paper() -> Running {
    start(true).await
}

/// A Guard on the in-memory venue: paper (the venue only read), or testnet
/// (Guard signs with the API wallet key and sends to the in-memory venue).
async fn start(paper: bool) -> Running {
    let dir = TestDir::new(if paper { "mcp-kit" } else { "mcp-kit-testnet" });
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: if paper {
            GuardMode::Paper
        } else {
            GuardMode::Testnet
        },
        account: Some(ACCOUNT.to_owned()),
        api_wallet: (!paper).then(|| api_key().address().to_hex()),
        state_dir: dir.path().to_owned(),
        auth: AuthConfig {
            clients: vec![GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex()],
            ..AuthConfig::default()
        },
        ..GuardConfig::default()
    };
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(paper),
        config.policy.risk_limits(),
        &config.journal_scope(paper).unwrap(),
        Timestamp::from_millis(SystemClock.now_ms() as i64),
        dec!(10000),
        "mcp kit test",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(paper)).unwrap();
    let venue = MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "10000",
    );
    let venue = if paper { venue.read_only() } else { venue };
    let mode = if paper {
        Mode::Paper
    } else {
        Mode::Send {
            key: api_key(),
            network: SigningNetwork::Testnet,
        }
    };
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
    // Nonces count from Guard's start plus 5 s, as for any client.
    tokio::time::sleep(std::time::Duration::from_millis(5_100)).await;
    guard.sync().await;
    let (addr, _) = server::bind(guard.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    Running {
        url: format!("http://{addr}"),
        guard,
        dir,
    }
}

fn kit(url: &str) -> Server {
    kit_for(url, KitMode::Paper)
}

fn kit_for(url: &str, network: KitMode) -> Server {
    Server::new(
        Config {
            network,
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

/// One loopback address in front of two Guards: requests go to `first`
/// until it has answered a status, then to `then`, as when another Guard
/// takes over the port between a client's status read and its request.
fn switching_proxy(first: String, then: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let target = Arc::new(Mutex::new((first, Some(then))));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let target = target.clone();
            std::thread::spawn(move || relay(stream, &target));
        }
    });
    address
}

fn relay(stream: TcpStream, target: &Mutex<(String, Option<String>)>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header == "\r\n" || header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    // Held across the request, so requests pass one at a time, in order.
    let mut target = target.lock().unwrap();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let url = format!("{}{path}", target.0);
    let response = if method == "GET" {
        client.get(url).send()
    } else {
        client
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send()
    }
    .unwrap();
    let code = response.status().as_u16();
    let text = response.text().unwrap();
    if path.starts_with("/guard/status")
        && let Some(next) = target.1.take()
    {
        target.0 = next;
    }
    drop(target);
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.flush();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_testnet_guard_taking_over_the_address_refuses_the_paper_kits_order_and_sends_nothing() {
    let (paper, testnet) = tokio::join!(start(true), start(false));
    let (first, then) = (paper.url.clone(), testnet.url.clone());
    let order = json!({"coin": "BTC", "side": "buy", "stop": "58800", "size": "0.01"});
    let asked = order.clone();
    // The kit is started for paper and reads a paper Guard's status; the
    // order then reaches a testnet Guard, which would send it: paper
    // requests are signed for testnet, and Guard authenticates a client's
    // signature for either network.
    let (error, refused) = tokio::task::spawn_blocking(move || {
        let address = switching_proxy(first, then);
        let mut server = kit_for(&address, KitMode::Paper);
        call(&mut server, "place_order", asked)
    })
    .await
    .unwrap();
    assert!(error, "{refused}");
    assert_eq!(refused["error"]["code"], "mode_mismatch", "{refused}");
    assert_eq!(refused["outcome"], "vetoed_by_guard", "{refused}");
    assert_eq!(refused["sent"], false, "{refused}");
    // Nothing reached the venue, and Guard judged nothing.
    assert!(testnet.guard.upstream().received().is_empty());
    assert!(paper.guard.upstream().received().is_empty());
    let url = testnet.url.clone();
    let events =
        tokio::task::spawn_blocking(move || get_json(&format!("{url}/guard/events?since=0")))
            .await
            .unwrap();
    let decisions: Vec<&Value> = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "decision")
        .collect();
    assert_eq!(decisions.len(), 1, "{events}");
    assert_eq!(decisions[0]["code"], "mode_mismatch", "{events}");
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["kind"] != "sent")
    );

    // The same order from a kit started for testnet goes through that Guard
    // to the venue: the field beside the signed action changes nothing else.
    let url = testnet.url.clone();
    let (error, placed) = tokio::task::spawn_blocking(move || {
        let mut server = kit_for(&url, KitMode::Testnet);
        call(&mut server, "place_order", order)
    })
    .await
    .unwrap();
    assert!(!error, "{placed}");
    assert_eq!(placed["sent"], true, "{placed}");
    assert!(!testnet.guard.upstream().received().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_testnet_guard_taking_over_the_address_ignores_the_paper_kits_kill_switch() {
    let (paper, testnet) = tokio::join!(start(true), start(false));
    // The testnet Guard has a position its kill switch would close.
    testnet.guard.upstream().add_position("BTC", "0.01");
    testnet.guard.sync().await;
    assert_eq!(testnet.guard.upstream().positions().len(), 1);
    let (first, then) = (paper.url.clone(), testnet.url.clone());
    // The kit, started for paper, looks at the paper Guard's status (which
    // lists kill_expected_mode); the kill then reaches the testnet Guard.
    let (error, refused) = tokio::task::spawn_blocking(move || {
        let address = switching_proxy(first, then);
        let mut server = kit_for(&address, KitMode::Paper);
        call(
            &mut server,
            "kill_switch",
            json!({"confirm": true, "reason": "agent test"}),
        )
    })
    .await
    .unwrap();
    assert!(error, "{refused}");
    assert_eq!(refused["error"]["code"], "mode_mismatch", "{refused}");
    assert_eq!(refused["sent"], false, "{refused}");
    // The testnet Guard's kill switch is untouched and its position open.
    let status = testnet.guard.status().await;
    assert_eq!(status["killed"], Value::Null, "{status}");
    assert_eq!(
        status["capabilities"]["kill_expected_mode"], true,
        "{status}"
    );
    assert!(!testnet.dir.path().join("kill").exists());
    assert_eq!(testnet.guard.upstream().positions().len(), 1);
    let status = paper.guard.status().await;
    assert_eq!(status["killed"], Value::Null, "{status}");

    // The same kill from a kit started for testnet pulls that Guard's
    // switch and closes the position.
    let url = testnet.url.clone();
    let (error, pulled) = tokio::task::spawn_blocking(move || {
        let mut server = kit_for(&url, KitMode::Testnet);
        call(
            &mut server,
            "kill_switch",
            json!({"confirm": true, "reason": "agent test"}),
        )
    })
    .await
    .unwrap();
    assert!(!error, "{pulled}");
    assert_eq!(pulled["pulled_through"], "guard_kill_endpoint", "{pulled}");
    assert!(testnet.guard.upstream().positions().is_empty());
}
