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
//! The kit's `preview_order` is Guard's own `/guard/preview`: one test
//! holds it to Guard's decision on the same request sent to `/exchange`
//! (allow, resize, `max`, veto), another runs Guard on a clock it moves to
//! show Guard's one-a-second budget and its 60 s bound on the account view.
//!
//! Account: 10,000 USDC, mids BTC 60,000, ETH 3,000, SOL 150; Guard's
//! default policy.

#![allow(clippy::unwrap_used)]

mod support;

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use rust_decimal::{Decimal, dec};
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
    ratelimit::{Clock as _, SystemClock as KitClock},
    sign::{Action, ClientKey, Grouping, OrderType, OrderWire, Tif, signed_request},
    tools::{Config, PREVIEW_INTERVAL_MS, Server},
};
use zunder_venue::PersistentRisk;

/// The agent's client key: the SDK tests' throwaway key.
const CLIENT_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
/// Another client of the same Guard (a bot), whose requests the tests sign
/// themselves.
const OTHER_CLIENT_KEY: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

fn api_key() -> GuardKey {
    GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap()
}

struct Running<C: Clock = SystemClock> {
    url: String,
    guard: Arc<Guard<MemoryVenue, C>>,
    dir: TestDir,
}

async fn start_paper() -> Running {
    start(true).await
}

/// A Guard on the in-memory venue: paper (the venue only read), or testnet
/// (Guard signs with the API wallet key and sends to the in-memory venue).
async fn start(paper: bool) -> Running {
    // Nonces count from Guard's start plus 5 s, as for any client.
    start_on(paper, SystemClock, true).await
}

/// The same on `clock`; `settle`: wait until clients' nonces are accepted.
async fn start_on<C: Clock>(paper: bool, clock: C, settle: bool) -> Running<C> {
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
            clients: vec![
                GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex(),
                GuardKey::from_hex(OTHER_CLIENT_KEY)
                    .unwrap()
                    .address()
                    .to_hex(),
            ],
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
        clock,
    )
    .unwrap();
    if settle {
        tokio::time::sleep(std::time::Duration::from_millis(5_100)).await;
    }
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
            preview_interval_ms: PREVIEW_INTERVAL_MS,
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
/// until it has answered a request to a path starting with `after`, then
/// to `then`, as when another Guard takes over the port between a client's
/// status read (or preview) and its request.
fn switching_proxy(first: String, then: String, after: &'static str) -> String {
    proxy(first, Some(then), after, Arc::new(|_: &str| {}))
}

/// Run before a request is passed on, with its path.
type BeforeForward = Arc<dyn Fn(&str) + Send + Sync>;

/// A loopback address in front of `first` (switching to `then` as in
/// [`switching_proxy`]) that runs `before` on each request, in order,
/// before passing it on.
fn proxy(
    first: String,
    then: Option<String>,
    after: &'static str,
    before: BeforeForward,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let target = Arc::new(Mutex::new((first, then)));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let target = target.clone();
            let before = before.clone();
            std::thread::spawn(move || relay(stream, &target, after, &*before));
        }
    });
    address
}

fn relay(
    stream: TcpStream,
    target: &Mutex<(String, Option<String>)>,
    after: &str,
    before: &(dyn Fn(&str) + Send + Sync),
) {
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
    before(&path);
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
    if path.starts_with(after)
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
    // The kit is started for paper and reads a paper Guard's status and
    // preview; the order then reaches a testnet Guard, which would send it:
    // paper requests are signed for testnet, and Guard authenticates a
    // client's signature for either network.
    let (error, refused) = tokio::task::spawn_blocking(move || {
        let address = switching_proxy(first, then, "/guard/preview");
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

    // Taken over right after the status read: the testnet Guard answers
    // the preview, which names its mode, and the kit sends nothing at all.
    let (first, then) = (paper.url.clone(), testnet.url.clone());
    let asked = json!({"coin": "BTC", "side": "buy", "stop": "58800", "size": "0.01"});
    let (error, refused) = tokio::task::spawn_blocking(move || {
        let address = switching_proxy(first, then, "/guard/status");
        let mut server = kit_for(&address, KitMode::Paper);
        call(&mut server, "place_order", asked)
    })
    .await
    .unwrap();
    assert!(error, "{refused}");
    assert_eq!(refused["error"]["code"], "network_mismatch", "{refused}");
    assert_eq!(refused["sent"], false, "{refused}");
    assert!(testnet.guard.upstream().received().is_empty());
    let url = testnet.url.clone();
    let events =
        tokio::task::spawn_blocking(move || get_json(&format!("{url}/guard/events?since=0")))
            .await
            .unwrap();
    let decisions = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "decision")
        .count();
    assert_eq!(decisions, 1, "{events}");

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
        let address = switching_proxy(first, then, "/guard/status");
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

/// A clock for Guard that moves only when the test moves it.
#[derive(Debug, Clone)]
struct HandClock(Arc<AtomicU64>);

impl HandClock {
    fn now() -> Self {
        Self(Arc::new(AtomicU64::new(SystemClock.now_ms())))
    }

    fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for HandClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// The entry the kit builds for a BTC buy at mid 60,000 (`preview.rs`):
/// an IOC limit at 60,000 × 1.005 = 60,300 and its reduce-only stop-market,
/// worst fill 10% beyond the trigger, in one `normalTpsl` request.
fn btc_buy(size: &str, trigger: &str, worst: &str) -> Action {
    Action::Order {
        orders: vec![
            OrderWire {
                asset: 0,
                is_buy: true,
                price: "60300".into(),
                size: size.into(),
                reduce_only: false,
                order_type: OrderType::Limit { tif: Tif::Ioc },
                cloid: None,
            },
            OrderWire {
                asset: 0,
                is_buy: false,
                price: worst.into(),
                size: size.into(),
                reduce_only: true,
                order_type: OrderType::StopMarket {
                    trigger_px: trigger.into(),
                },
                cloid: None,
            },
        ],
        grouping: Grouping::NormalTpsl,
    }
}

/// `action` signed by the other client and sent to a paper Guard's
/// `/exchange`: Guard judges and journals it as it would send it, and
/// answers its decision (`verdict`, `code`, and for an entry the sizes).
fn decided(url: &str, action: &Action, nonce: u64) -> Value {
    let key = ClientKey::from_hex(OTHER_CLIENT_KEY).unwrap();
    let body = signed_request(
        &key,
        SigningNetwork::Testnet,
        action,
        nonce,
        Some(nonce + 20_000),
        KitMode::Paper,
    )
    .unwrap();
    let text = reqwest::blocking::Client::new()
        .post(format!("{url}/exchange"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .unwrap()
        .text()
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// What the kit's `preview_order` showed equals what Guard decided when the
/// same entry was sent: verdict, code and size.
/// (A paper Guard answers a forwarded decision with its verdict and sizes,
/// a veto as a veto.)
fn assert_preview_is_the_decision(shown: &Value, decision: &Value) {
    let preview = &shown["preview"];
    assert_eq!(preview["source"], "guard", "{shown}");
    let verdict = match decision.get("verdict") {
        Some(verdict) => verdict.clone(),
        None => {
            assert!(
                decision["response"]
                    .as_str()
                    .unwrap()
                    .starts_with("Zunder Guard veto ["),
                "{decision}"
            );
            json!("veto")
        }
    };
    assert_eq!(preview["verdict"], verdict, "{shown} {decision}");
    assert_eq!(preview["code"], decision["code"], "{shown} {decision}");
    let size = decision
        .get("size")
        .and_then(Value::as_str)
        .map(|size| size.parse::<Decimal>().unwrap().normalize().to_string());
    assert_eq!(
        preview["allowed_size"].as_str().map(str::to_owned),
        size,
        "{shown} {decision}"
    );
}

/// Guard's default policy, equity 10,000: 2% = 200 at the stop. A BTC buy
/// at 60,300 with its stop at 58,800 risks 1,500 + 60,300 × 0.0011 =
/// 1,566.33 per BTC, so 200 / 1,566.33 = 0.12768 BTC (the 0.00001 step,
/// down); the position cap (200% of equity: 0.33167) and the leverage cap
/// (5x: 0.82918) do not bind.
fn previews_and_decisions(url: &str) {
    let mut server = kit(url);
    let nonce = || KitClock.now_ms();
    // Allow: 0.01 BTC is within every rule.
    let (error, allow) = call(
        &mut server,
        "preview_order",
        json!({"coin": "BTC", "side": "buy", "stop": "58800", "size": "0.01"}),
    );
    assert!(!error, "{allow}");
    assert_eq!(allow["preview"]["verdict"], "allow", "{allow}");
    assert_eq!(allow["preview"]["allowed_size"], "0.01", "{allow}");
    let decision = decided(url, &btc_buy("0.01", "58800", "52920"), nonce());
    assert_preview_is_the_decision(&allow, &decision);

    // Resize: 0.5 BTC is cut to 0.12768.
    let (error, resize) = call(
        &mut server,
        "preview_order",
        json!({"coin": "BTC", "side": "buy", "stop": "58800", "size": "0.5"}),
    );
    assert!(!error, "{resize}");
    assert_eq!(resize["preview"]["verdict"], "resize", "{resize}");
    assert_eq!(resize["preview"]["allowed_size"], "0.12768", "{resize}");
    let decision = decided(url, &btc_buy("0.5", "58800", "52920"), nonce());
    assert_preview_is_the_decision(&resize, &decision);

    // "max": the kit asks for 200 × 10,000 / 60,300 = 33.16749 BTC, which
    // Guard cuts to the same 0.12768.
    let (error, max) = call(
        &mut server,
        "preview_order",
        json!({"coin": "BTC", "side": "buy", "stop": "58800"}),
    );
    assert!(!error, "{max}");
    assert_eq!(max["preview"]["allowed_size"], "0.12768", "{max}");
    let decision = decided(url, &btc_buy("33.16749", "58800", "52920"), nonce());
    assert_preview_is_the_decision(&max, &decision);

    // Veto: a buy's stop above the price.
    let (error, veto) = call(
        &mut server,
        "preview_order",
        json!({"coin": "BTC", "side": "buy", "stop": "61000", "size": "0.01"}),
    );
    assert!(!error, "{veto}");
    assert_eq!(veto["preview"]["verdict"], "veto", "{veto}");
    assert_eq!(veto["preview"]["code"], "stop_wrong_side", "{veto}");
    let decision = decided(url, &btc_buy("0.01", "61000", "54900"), nonce());
    assert_preview_is_the_decision(&veto, &decision);
    // And the kit sends nothing Guard's preview vetoes.
    let before = get_json(&format!("{url}/guard/events?since=0"))
        .as_array()
        .unwrap()
        .len();
    let (error, refused) = call(
        &mut server,
        "place_order",
        json!({"coin": "BTC", "side": "buy", "stop": "61000", "size": "0.01"}),
    );
    assert!(error, "{refused}");
    assert_eq!(refused["error"]["code"], "stop_wrong_side", "{refused}");
    assert_eq!(refused["sent"], false, "{refused}");
    let after = get_json(&format!("{url}/guard/events?since=0"))
        .as_array()
        .unwrap()
        .len();
    assert_eq!(before, after, "nothing was journaled");

    // The kit's own entry: Guard's decision on the send is the preview's.
    let (_, placed) = call(
        &mut server,
        "place_order",
        json!({"coin": "BTC", "side": "buy", "stop": "58800", "size": "0.5"}),
    );
    assert_eq!(placed["outcome"], "paper_mode_not_sent", "{placed}");
    assert_eq!(placed["guard_verdict"], "resize", "{placed}");
    assert_eq!(
        placed["order"]["guard_preview_before_sending"]["allowed_size"], "0.12768",
        "{placed}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_kits_preview_is_guards_decision_for_allow_resize_and_veto() {
    let running = start_paper().await;
    let url = running.url.clone();
    tokio::task::spawn_blocking(move || previews_and_decisions(&url))
        .await
        .unwrap();
    assert!(running.guard.upstream().received().is_empty());
}

/// Guard's budget (one preview a second of its clock, for all clients)
/// and its 60 s bound on the account view, on a clock the test moves.
#[tokio::test(flavor = "multi_thread")]
async fn the_preview_reports_guards_budget_and_a_stale_view_and_sends_nothing() {
    let clock = HandClock::now();
    let running = start_on(true, clock.clone(), false).await;
    let url = running.url.clone();
    let order = json!({"coin": "BTC", "side": "buy", "stop": "58800", "size": "0.01"});
    let asked = order.clone();
    let (first, busy, placed) = tokio::task::spawn_blocking(move || {
        let mut server = kit(&url);
        let first = call(&mut server, "preview_order", asked.clone());
        // Guard's clock stands still: its second's preview is spent, and
        // the kit's second try a second later finds it spent too.
        let busy = call(&mut server, "preview_order", asked.clone());
        let placed = call(&mut server, "place_order", asked);
        (first, busy, placed)
    })
    .await
    .unwrap();
    assert!(!first.0, "{}", first.1);
    assert_eq!(first.1["preview"]["verdict"], "allow");
    assert!(busy.0, "{}", busy.1);
    assert_eq!(
        busy.1["error"]["code"], "preview_rate_limited",
        "{}",
        busy.1
    );
    assert_eq!(busy.1["retry_after_ms"], 1000);
    assert!(placed.0, "{}", placed.1);
    assert_eq!(
        placed.1["error"]["code"], "preview_rate_limited",
        "{}",
        placed.1
    );
    assert_eq!(placed.1["sent"], false);

    // A second later on Guard's clock, the preview answers again.
    clock.advance(1_000);
    let url = running.url.clone();
    let asked = order.clone();
    let again = tokio::task::spawn_blocking(move || call(&mut kit(&url), "preview_order", asked))
        .await
        .unwrap();
    assert!(!again.0, "{}", again.1);

    // 61 s without a sync: Guard's view of the account is too old, so it
    // previews nothing and the kit sends nothing.
    // (Guard counts a refused preview against its second too, so the clock
    // moves a second between the two.)
    clock.advance(61_000);
    let url = running.url.clone();
    let asked = order.clone();
    let moved = clock.clone();
    let (stale, placed) = tokio::task::spawn_blocking(move || {
        let mut server = kit(&url);
        let stale = call(&mut server, "preview_order", asked.clone());
        moved.advance(1_000);
        (stale, call(&mut server, "place_order", asked))
    })
    .await
    .unwrap();
    assert!(stale.0, "{}", stale.1);
    assert_eq!(
        stale.1["error"]["code"], "preview_view_stale",
        "{}",
        stale.1
    );
    assert!(placed.0, "{}", placed.1);
    assert_eq!(
        placed.1["error"]["code"], "preview_view_stale",
        "{}",
        placed.1
    );
    assert_eq!(placed.1["sent"], false);

    // After a sync the view is fresh, and the preview answers.
    clock.advance(1_000);
    running.guard.sync().await;
    let url = running.url.clone();
    let fresh = tokio::task::spawn_blocking(move || call(&mut kit(&url), "preview_order", order))
        .await
        .unwrap();
    assert!(!fresh.0, "{}", fresh.1);
    assert_eq!(fresh.1["preview"]["view_age_ms"], 0, "{}", fresh.1);

    // No decision was journaled, and nothing reached the venue.
    let events = running.guard.events(0).await;
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["kind"] != "decision"),
        "{events}"
    );
    assert!(running.guard.upstream().received().is_empty());
}

/// A proxy in front of `url` that records the path of every request.
fn recording_proxy(url: String) -> (String, Arc<Mutex<Vec<String>>>) {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let seen = paths.clone();
    let address = proxy(
        url,
        None,
        "",
        Arc::new(move |path: &str| seen.lock().unwrap().push(path.to_owned())),
    );
    (address, paths)
}

/// The kit's own rule against the real testnet Guard: the caller last saw a
/// BTC long of 0.0002, but it is 0.0003 (or 0.0001, or a short of 0.0003) by the
/// time the kit reads it. The kit refuses, and no request reaches Guard's
/// `/exchange`; the venue gets nothing from the kit.
#[tokio::test(flavor = "multi_thread")]
async fn a_close_whose_expected_size_is_not_the_position_never_reaches_the_exchange() {
    let testnet = start(false).await;
    testnet.guard.upstream().add_position("BTC", "0.0002");
    testnet.guard.sync().await;
    // Guard protects the position with a stop of its own when it syncs.
    let before = testnet.guard.upstream().received().len();
    for now in ["0.0003", "0.0001", "-0.0003"] {
        testnet.guard.upstream().set_position("BTC", now);
        let url = testnet.url.clone();
        let (error, refused, paths) = tokio::task::spawn_blocking(move || {
            let (address, paths) = recording_proxy(url);
            let mut server = kit_for(&address, KitMode::Testnet);
            let (error, refused) = call(
                &mut server,
                "close_position",
                json!({"coin": "BTC", "expected_size": "0.0002"}),
            );
            let paths = paths.lock().unwrap().clone();
            (error, refused, paths)
        })
        .await
        .unwrap();
        assert!(error, "{refused}");
        assert_eq!(
            refused["error"]["code"], "position_size_mismatch",
            "{refused}"
        );
        assert_eq!(refused["sent"], false, "{refused}");
        assert_eq!(refused["expected_size"], "0.0002", "{refused}");
        assert_eq!(
            refused["position_size"],
            now.trim_start_matches('-'),
            "{refused}"
        );
        // The kit read the position through Guard and stopped there.
        assert!(paths.iter().any(|path| path == "/info"), "{paths:?}");
        assert!(!paths.iter().any(|path| path == "/exchange"), "{paths:?}");
    }
    assert_eq!(testnet.guard.upstream().received().len(), before);
}

/// A testnet Guard on the in-memory venue holds a BTC long of `held`; the
/// kit reads exactly `expected` = `held`, then the position changes to
/// `then` on the venue after that read, before the close reaches Guard.
/// What bounds the close then is not the kit's check but the order itself:
/// the kit sends exactly `expected` as a reduce-only IOC, Guard passes it
/// on (cut to the position when it sees a smaller one), and the venue fills
/// at most what is held. Returns the size the venue received and the
/// position left (signed, or `None` when flat).
async fn close_racing_a_change(
    held: &str,
    expected: &str,
    then: &'static str,
) -> (String, Option<String>) {
    let testnet = start(false).await;
    testnet.guard.upstream().add_position("BTC", held);
    testnet.guard.sync().await;
    let guard = testnet.guard.clone();
    let url = testnet.url.clone();
    let arguments = json!({"coin": "BTC", "expected_size": expected});
    let (error, closed) = tokio::task::spawn_blocking(move || {
        let address = proxy(
            url,
            None,
            "",
            Arc::new(move |path: &str| {
                if path == "/exchange" {
                    guard.upstream().set_position("BTC", then);
                }
            }),
        );
        let mut server = kit_for(&address, KitMode::Testnet);
        call(&mut server, "close_position", arguments)
    })
    .await
    .unwrap();
    assert!(!error, "{closed}");
    assert_eq!(closed["sent"], true, "{closed}");
    // The kit read the size it was told to expect and sent exactly that.
    assert_eq!(closed["close"]["position_size"], held, "{closed}");
    assert_eq!(closed["close"]["size_sent"], expected, "{closed}");
    // Guard itself protects the unprotected position with a resting stop
    // when it first syncs; the only other order is the kit's close.
    let received = testnet.guard.upstream().received();
    let closes: Vec<&Value> = received
        .iter()
        .map(|r| &r.json["orders"][0])
        .filter(|order| order["t"].get("trigger").is_none())
        .collect();
    assert_eq!(closes.len(), 1, "one close: {closes:?}");
    let order = closes[0];
    assert_eq!(order["r"], true, "{order}");
    assert_eq!(order["t"], json!({"limit": {"tif": "Ioc"}}), "{order}");
    assert_eq!(order["b"], false, "a sell closes the long: {order}");
    let left = testnet
        .guard
        .upstream()
        .positions()
        .iter()
        .find(|p| p["position"]["coin"] == "BTC")
        .map(|p| p["position"]["szi"].as_str().unwrap().to_owned());
    (order["s"].as_str().unwrap().to_owned(), left)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_position_changing_after_the_kits_read_is_closed_by_at_most_expected_size() {
    // The long grows from 0.0002 to 0.0003 after the kit's read: exactly
    // 0.0002 is sold, and 0.0003 - 0.0002 = 0.0001 stays open.
    let (sent, left) = close_racing_a_change("0.0002", "0.0002", "0.0003").await;
    assert_eq!(sent, "0.0002");
    assert_eq!(left.as_deref(), Some("0.0001"));
    // The long shrinks from 0.0003 to 0.0002: the kit's reduce-only sell of
    // 0.0003 reaches the venue as no more than 0.0003 (Guard cuts a
    // reduce-only order to the position it sees, here 0.0002), and the
    // venue fills only what is held: flat, never short.
    let (sent, left) = close_racing_a_change("0.0003", "0.0003", "0.0002").await;
    let sent: Decimal = sent.parse().unwrap();
    assert!(sent <= dec!(0.0003), "{sent}");
    assert_eq!(left, None);
}
