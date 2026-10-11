// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! A mock Guard: an in-process HTTP server that speaks Hyperliquid's
//! `/info` and `/exchange` formats and Guard's status and events, as the
//! MCP server's only peer. It checks every `/exchange` request the way
//! Guard does (the signature must recover to a registered client key) and
//! records it, so tests can assert what was and was not sent.

#![allow(dead_code)]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
};

use base64::Engine as _;
use rust_decimal::Decimal;
use serde_json::{Value, json};
use zunder_guard_mcp::{
    contract::Mode,
    guard::{GuardClient, GuardUrl},
    protocol,
    ratelimit::ManualClock,
    sign::{Action, ClientKey, Grouping, OrderType, OrderWire, Tif, recover_signer},
    tools::{Config, Server},
};
use zunder_hl_protocol::Network;

/// The Python SDK's throwaway test key: the agent's client key here.
pub const CLIENT_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
pub const CLIENT: &str = "0x14791697260e4c9a71f18484c9f997b308e59325";
pub const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
pub const NOW: u64 = 1_791_000_000_000;

/// A `zr1_` code for `json`.
pub fn rules_code(json: &str) -> String {
    format!(
        "zr1_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    )
}

/// Guard's defaults with `stopPolicy: "attach"`, as Guard writes them.
pub fn default_rules() -> String {
    rules_code(
        r#"{"v":1,"maxLeverage":5,"maxLossAtStopPct":2,"requireStop":true,"stopPolicy":"attach","minLiqDistancePct":10,"maxPositionPct":200,"maxOpenRiskPct":6,"dailyLossStopPct":6,"drawdownHaltPct":25,"markets":["*"],"defaultStopDistancePct":2}"#,
    )
}

/// One request the mock received.
#[derive(Debug, Clone)]
pub struct Received {
    pub method: String,
    pub path: String,
    pub body: Value,
}

#[derive(Debug)]
pub struct MockState {
    pub status: Value,
    pub meta: Value,
    pub mids: Value,
    pub account: Value,
    pub orders: Value,
    pub events: Vec<Value>,
    /// Replies to the next `/exchange` requests, in order; then the
    /// default (allowed and filled, or paper mode's answer).
    pub scripted: Vec<Value>,
    pub received: Vec<Received>,
    pub next_seq: u64,
    pub next_oid: u64,
    /// Signatures that did not recover to a registered client.
    pub bad_signatures: usize,
    /// Which phantom-agent source each authenticated request was signed for.
    pub sources: Vec<Network>,
    /// Raw HTTP replies (status, body) for the next `/exchange` requests,
    /// sent after the request is recorded and journaled as Guard would.
    pub http_failures: Vec<(u16, String)>,
    /// Guard's kill file: once it exists, the status reports `killed`.
    pub kill_file: Option<PathBuf>,
    /// The answer to `userRole` for the client key.
    pub client_role: Value,
    /// The mode the server under test was started for.
    pub pinned: Option<&'static str>,
    /// Every `/exchange` body that passed Guard's checks and went on to
    /// the venue (never in paper mode).
    pub forwarded: Vec<Value>,
    /// Once the next status has been answered, the mode of the service
    /// behind this address becomes this one: another Guard took over the
    /// port between the server's status read and its request.
    pub mode_after_status: Option<&'static str>,
    /// The same, once the next preview has been answered: another Guard
    /// took over between the server's preview and its request.
    pub mode_after_preview: Option<&'static str>,
    /// With `mode_after_status` or `mode_after_preview`: the Guard that
    /// takes over is an older one, without
    /// `capabilities.exchange_expected_mode`.
    pub older_after_status: bool,
    /// Whether the mock answers `POST /guard/kill` as Guard does (checking
    /// `expectedMode` against `kill_expected_mode` and the mode, then
    /// latching); otherwise the endpoint does not exist (an older Guard).
    pub kill_endpoint: bool,
    /// The next status reads answer HTTP 502.
    pub status_failures: usize,
    /// The next status reads answer only after this many milliseconds
    /// each (a Guard busy with the venue).
    pub status_delays: Vec<u64>,
    /// Whether the mock answers `POST /guard/preview`; otherwise HTTP 404,
    /// as an older Guard without it.
    pub preview_endpoint: bool,
    /// The `{"error": text}` alone, without a `code`, of a Guard from
    /// before the refusal code, for the next previews (its budget spent,
    /// no recent view), before anything is judged. The current Guard's
    /// `{"code", "error"}` goes in `preview_scripted`.
    pub preview_errors: Vec<String>,
    /// Replies to the next previews, verbatim.
    pub preview_scripted: Vec<Value>,
    /// The most Guard's rules allow per coin for the entries the tests ask
    /// about (the numbers in `end_to_end.rs`'s header).
    pub preview_max: Value,
    /// A veto (code, text) every preview of an entry ends in, after the
    /// checks below: the budgets, a position without its stop.
    pub preview_veto: Option<(String, String)>,
}

pub struct MockGuard {
    pub url: String,
    pub state: Arc<Mutex<MockState>>,
}

impl MockGuard {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let url = format!("http://{}", listener.local_addr().expect("local address"));
        let state = Arc::new(Mutex::new(MockState {
            status: json!({
                "schema": 1, "version": "0.1.0", "mode": "testnet", "network": "testnet",
                "account": ACCOUNT, "started_at_ms": NOW - 60_000, "killed": null,
                "risk": {"state": "active", "peak": "2000", "journal_ready": true},
                "equity": "2000", "positions": 1, "open_orders": 1, "last_sync_ms": NOW,
                "last_error": null, "rules": default_rules(),
                "fee": {"mode": "off", "why": "phase 1"}, "clients": [CLIENT],
                "last_event": 0, "journal_broken": false,
                "capabilities": {"exchange_expected_mode": true, "kill_expected_mode": true}
            }),
            meta: json!({"universe": [
                {"name": "BTC", "szDecimals": 5, "maxLeverage": 40},
                {"name": "ETH", "szDecimals": 4, "maxLeverage": 25},
                {"name": "OLD", "szDecimals": 1, "maxLeverage": 3, "isDelisted": true},
            ]}),
            mids: json!({"BTC": "60000", "ETH": "3000"}),
            account: json!({
                "marginSummary": {"accountValue": "2000", "totalNtlPos": "300"},
                "withdrawable": "1800",
                "assetPositions": [{"type": "oneWay", "position": {
                    "coin": "ETH", "szi": "0.1", "entryPx": "2950", "positionValue": "300",
                    "unrealizedPnl": "5", "liquidationPx": "2100",
                    "leverage": {"type": "isolated", "value": 3}, "marginUsed": "100"}}],
            }),
            orders: json!([
                {"coin": "ETH", "side": "A", "limitPx": "2646", "sz": "0.1", "oid": 9,
                 "timestamp": NOW - 30_000, "isTrigger": true, "triggerPx": "2940",
                 "orderType": "Stop Market", "reduceOnly": true, "isPositionTpsl": false,
                 "cloid": "0x7a670000000000000000000000000001", "tif": null},
                {"coin": "ETH", "side": "B", "limitPx": "2800", "sz": "0.05", "oid": 11,
                 "timestamp": NOW - 20_000, "isTrigger": false, "triggerPx": "0.0",
                 "orderType": "Limit", "reduceOnly": false, "isPositionTpsl": false,
                 "cloid": null, "tif": "Gtc"}
            ]),
            events: Vec::new(),
            scripted: Vec::new(),
            received: Vec::new(),
            next_seq: 1,
            next_oid: 1000,
            bad_signatures: 0,
            sources: Vec::new(),
            http_failures: Vec::new(),
            kill_file: None,
            client_role: json!({"role": "missing"}),
            pinned: None,
            forwarded: Vec::new(),
            mode_after_status: None,
            mode_after_preview: None,
            older_after_status: false,
            kill_endpoint: false,
            status_failures: 0,
            status_delays: Vec::new(),
            preview_endpoint: true,
            preview_errors: Vec::new(),
            preview_scripted: Vec::new(),
            preview_max: json!({"BTC": "0.02553", "ETH": "0.2"}),
            preview_veto: None,
        }));
        let shared = state.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let state = shared.clone();
                thread::spawn(move || serve(stream, &state));
            }
        });
        Self { url, state }
    }

    pub fn with<T>(&self, change: impl FnOnce(&mut MockState) -> T) -> T {
        change(&mut self.state.lock().expect("mock state"))
    }

    /// Every `/exchange` body received.
    pub fn exchanges(&self) -> Vec<Value> {
        self.with(|state| {
            state
                .received
                .iter()
                .filter(|r| r.path == "/exchange")
                .map(|r| r.body.clone())
                .collect()
        })
    }

    /// Every `/guard/preview` body received.
    pub fn previews(&self) -> Vec<Value> {
        self.with(|state| {
            state
                .received
                .iter()
                .filter(|r| r.path == "/guard/preview")
                .map(|r| r.body.clone())
                .collect()
        })
    }

    /// Every `/exchange` body that reached the venue.
    pub fn forwarded(&self) -> Vec<Value> {
        self.with(|state| state.forwarded.clone())
    }

    /// A server for this Guard, started for `network` (on mainnet with
    /// Guard's account confirmed).
    pub fn server(
        &self,
        network: Mode,
        key: bool,
        kill_file: Option<PathBuf>,
    ) -> (Server, ManualClock) {
        let confirm = (network == Mode::Mainnet).then(|| ACCOUNT.to_owned());
        self.server_with(network, key, kill_file, confirm)
    }

    pub fn server_with(
        &self,
        network: Mode,
        key: bool,
        kill_file: Option<PathBuf>,
        confirm_account: Option<String>,
    ) -> (Server, ManualClock) {
        if kill_file.is_some() {
            let path = kill_file.clone();
            self.with(|state| state.kill_file = path);
        }
        self.with(|state| state.pinned = Some(network.name()));
        let clock = ManualClock::at(NOW);
        let server = Server::new(
            Config {
                network,
                kill_file,
                confirm_account,
                kill_confirm_wait_ms: 1_000,
                preview_interval_ms: 0,
            },
            GuardClient::new(GuardUrl::parse(&self.url).expect("loopback url")).expect("client"),
            key.then(|| ClientKey::from_hex(CLIENT_KEY).expect("test key")),
            Box::new(clock.clone()),
        );
        (server, clock)
    }

    /// The invariants that hold for every request this server ever sends.
    pub fn assert_only_guarded_actions(&self) {
        for body in self.exchanges() {
            let kind = body["action"]["type"].as_str().expect("an action type");
            assert!(["order", "cancel", "modify"].contains(&kind), "{kind}");
            assert_eq!(body["vaultAddress"], Value::Null);
            assert!(
                !body.to_string().contains("\"builder\"") && body["action"].get("b").is_none(),
                "a builder field: {body}"
            );
            assert!(body["expiresAfter"].as_u64().is_some());
            // Every request names the mode the server was started for,
            // beside the signed fields.
            let pinned = self.with(|state| state.pinned).expect("a server");
            assert_eq!(body["expectedMode"], pinned, "{body}");
        }
        assert_eq!(
            self.with(|state| state.bad_signatures),
            0,
            "a request did not authenticate"
        );
    }
}

fn serve(stream: TcpStream, state: &Arc<Mutex<MockState>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
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
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    if path == "/guard/status" {
        let delay = {
            let mut state = state.lock().expect("mock state");
            (!state.status_delays.is_empty()).then(|| state.status_delays.remove(0))
        };
        if let Some(ms) = delay {
            thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
    let (code, text) = {
        let mut state = state.lock().expect("mock state");
        state.received.push(Received {
            method: method.clone(),
            path: path.to_owned(),
            body: body.clone(),
        });
        let reply = route(&mut state, &method, path, query, &body);
        if path == "/exchange" && !state.http_failures.is_empty() {
            state.http_failures.remove(0)
        } else if path == "/guard/preview" && !state.preview_endpoint {
            (
                404,
                "{\"error\":\"Guard serves /info, /exchange, /ws and /guard/*\"}".to_owned(),
            )
        } else if path == "/guard/status" && state.status_failures > 0 {
            state.status_failures -= 1;
            (502, "{\"error\":\"bad gateway\"}".to_owned())
        } else {
            (200, reply.to_string())
        }
    };
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        text.len(),
        text
    );
    let _ = stream.flush();
}

fn route(state: &mut MockState, method: &str, path: &str, query: &str, body: &Value) -> Value {
    match (method, path) {
        ("GET", "/guard/status") => {
            let mut status = state.status.clone();
            status["last_event"] = json!(state.next_seq - 1);
            if let Some(reason) = state
                .kill_file
                .as_ref()
                .and_then(|path| std::fs::read_to_string(path).ok())
            {
                status["killed"] = json!(reason.trim());
            }
            if let Some(mode) = state.mode_after_status.take() {
                take_over(state, mode);
            }
            status
        }
        ("GET", "/guard/events") => {
            let since: u64 = query
                .strip_prefix("since=")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            Value::Array(
                state
                    .events
                    .iter()
                    .filter(|event| event["seq"].as_u64().unwrap_or(0) > since)
                    .cloned()
                    .collect(),
            )
        }
        ("POST", "/info") => match body["type"].as_str() {
            Some("meta") => state.meta.clone(),
            Some("allMids") => state.mids.clone(),
            Some("clearinghouseState") => state.account.clone(),
            Some("frontendOpenOrders") => state.orders.clone(),
            Some("userRole") => state.client_role.clone(),
            _ => json!({"error": "unknown info type"}),
        },
        ("POST", "/exchange") => exchange(state, body),
        ("POST", "/guard/preview") if state.preview_endpoint => {
            let reply = preview(state, body);
            if let Some(mode) = state.mode_after_preview.take() {
                take_over(state, mode);
            }
            reply
        }
        ("POST", "/guard/kill") if state.kill_endpoint => kill(state, body),
        _ => json!({"error": "not found"}),
    }
}

/// Guard's `POST /guard/preview` for the one kind of action the tests
/// preview, an entry (with its stop in `normalTpsl`, or alone), judged in
/// Guard's order with the mock's numbers: the kill switch, the market, the
/// stop (Guard's own under `attach`, 2% beyond the lower of fill and mid
/// for a buy, the higher for a sell; refused under `refuse`), its side,
/// `preview_veto`, then the size cut to `preview_max`. The real judgement
/// is in `crates/zunder-guard/tests/mcp_kit.rs`.
fn preview(state: &mut MockState, body: &Value) -> Value {
    if !state.preview_errors.is_empty() {
        return json!({"error": state.preview_errors.remove(0)});
    }
    if !state.preview_scripted.is_empty() {
        return state.preview_scripted.remove(0);
    }
    let decimal = |value: &Value| value.as_str().and_then(|text| text.parse::<Decimal>().ok());
    let mode = state.status["mode"].clone();
    let veto = |code: &str, text: &str| {
        json!({"verdict": "veto", "code": code, "text": text, "changes": [], "entry": null,
               "pre": null, "forward": null, "post": null, "mode": mode, "view_age_ms": 1000})
    };
    let action = &body["action"];
    let Some(entry) = action["orders"].get(0) else {
        return json!({"error": "unsupported action"});
    };
    if !state.status["killed"].is_null() {
        return veto("kill_switch", "the kill switch is pulled");
    }
    let asset = entry["a"].as_u64().unwrap_or(u64::MAX);
    let Some(market) = usize::try_from(asset)
        .ok()
        .and_then(|index| state.meta["universe"].get(index))
    else {
        return veto("unknown_market", "no such asset");
    };
    if market["isDelisted"] == true {
        return veto("unknown_market", "delisted");
    }
    let coin = market["name"].as_str().unwrap_or_default().to_owned();
    let (Some(mid), Some(worst), Some(requested)) = (
        decimal(&state.mids[coin.as_str()]),
        decimal(&entry["p"]),
        decimal(&entry["s"]),
    ) else {
        return veto("no_price", "no mid");
    };
    let buy = entry["b"] == true;
    let attach = rules_json(&state.status).contains("\"stopPolicy\":\"attach\"");
    let (stop, attached) = match action["orders"].get(1) {
        Some(child) => (decimal(&child["t"]["trigger"]["triggerPx"]), false),
        None if attach => {
            let stop = if buy {
                worst.min(mid) * Decimal::new(98, 2)
            } else {
                worst.max(mid) * Decimal::new(102, 2)
            };
            (Some(stop.normalize()), true)
        }
        None => return veto("stop_required", "the stop policy is refuse"),
    };
    let Some(stop) = stop else {
        return veto("invalid", "unreadable stop");
    };
    if (buy && (stop >= mid || stop >= worst)) || (!buy && (stop <= mid || stop <= worst)) {
        return veto("stop_wrong_side", "the stop is on the wrong side");
    }
    if let Some((code, text)) = state.preview_veto.clone() {
        return veto(&code, &text);
    }
    let max = decimal(&state.preview_max[coin.as_str()]).unwrap_or(requested);
    let size = requested.min(max);
    let resized = size < requested || attached;
    json!({
        "verdict": if resized { "resize" } else { "allow" },
        "code": if resized { "resized" } else { "allowed" },
        "text": if resized { "forwarded with changes" } else { "within every rule" },
        "changes": if size < requested { json!([format!("size {requested} cut to {size}")]) } else { json!([]) },
        "entry": {"coin": coin, "side": if buy { "buy" } else { "sell" },
                  "requested_size": requested.normalize().to_string(),
                  "size": size.normalize().to_string(),
                  "worst_price": worst.normalize().to_string(),
                  "stop": stop.normalize().to_string(), "leverage": 3},
        "pre": [], "forward": action.clone(), "post": [],
        "mode": mode, "view_age_ms": 1000
    })
}

/// The rules code in a status, decoded.
fn rules_json(status: &Value) -> String {
    status["rules"]
        .as_str()
        .and_then(|code| code.strip_prefix("zr1_"))
        .and_then(|data| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(data)
                .ok()
        })
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default()
}

/// Another Guard, of `mode`, now answers at this address (an older one,
/// without the capabilities, with `older_after_status`).
fn take_over(state: &mut MockState, mode: &str) {
    state.status["mode"] = json!(mode);
    state.status["network"] = json!(if mode == "mainnet" {
        "mainnet"
    } else {
        "testnet"
    });
    if state.older_after_status
        && let Some(object) = state.status.as_object_mut()
    {
        object.remove("capabilities");
    }
}

fn push_event(state: &mut MockState, mut event: Value) -> u64 {
    let seq = state.next_seq;
    state.next_seq += 1;
    event["seq"] = json!(seq);
    event["at_ms"] = json!(NOW);
    state.events.push(event);
    seq
}

/// Guard's `POST /guard/kill`: `expectedMode` checked as Guard checks it
/// (unknown to a Guard without `kill_expected_mode`; anything but the three
/// names malformed; another mode pulls nothing), then the switch latched.
/// Unlike Guard, the mock does not authenticate the kill, track its nonce,
/// answer `already` or journal refusals; `crates/zunder-guard/tests/mcp_kit.rs`
/// runs the kill against the real Guard.
fn kill(state: &mut MockState, body: &Value) -> Value {
    if let Some(expected) = body.get("expectedMode") {
        if state.status["capabilities"]["kill_expected_mode"] != true
            || !matches!(expected.as_str(), Some("paper" | "testnet" | "mainnet"))
        {
            return json!({"status": "err", "code": "malformed", "response": "Zunder Guard veto [malformed]: the request has an unknown field `expectedMode`"});
        }
        if *expected != state.status["mode"] {
            return json!({"status": "err", "code": "mode_mismatch", "response": "Zunder Guard veto [mode_mismatch]: the request expects another mode; nothing was pulled"});
        }
    }
    let reason = body["action"]["reason"].as_str().unwrap_or("").to_owned();
    state.status["killed"] = json!(reason);
    json!({"status": "ok", "killed": reason})
}

fn exchange(state: &mut MockState, body: &Value) -> Value {
    let nonce = body["nonce"].as_u64().unwrap_or(0);
    let expires = body["expiresAfter"].as_u64();
    // `expectedMode` before the signature, as Guard checks it. (Guard
    // decodes the whole request first and checks the mode right after; the
    // mock skips that decoding, since this server's requests always
    // decode. What matters is the same: the mode before authentication.)
    // A Guard without the capability does not know the field and refuses
    // the request as malformed.
    if let Some(expected) = body.get("expectedMode") {
        if state.status["capabilities"]["exchange_expected_mode"] != true {
            return json!({"status": "err", "code": "malformed", "response": "Zunder Guard veto [malformed]: the request has an unknown field `expectedMode`"});
        }
        if !matches!(expected.as_str(), Some("paper" | "testnet" | "mainnet")) {
            return json!({"status": "err", "code": "malformed", "response": "Zunder Guard veto [malformed]: `expectedMode` must be \"paper\", \"testnet\" or \"mainnet\""});
        }
        if *expected != state.status["mode"] {
            push_event(
                state,
                json!({"kind": "decision", "via": "http", "client": null, "nonce": nonce,
                       "action": body["action"]["type"], "verdict": "veto", "code": "mode_mismatch",
                       "text": "the request expects another mode", "changes": []}),
            );
            return json!({"status": "err", "code": "mode_mismatch", "response": format!(
                "Zunder Guard veto [mode_mismatch]: the request expects {expected}, but Guard runs {}; nothing was judged or sent",
                state.status["mode"]
            )});
        }
    }
    // Authenticate as Guard does: the signature must recover to a client,
    // signed for either phantom-agent source.
    let action = decode_action(&body["action"]);
    let signer = |source| {
        recover_signer(
            action.as_ref()?,
            nonce,
            expires,
            source,
            body["signature"]["r"].as_str()?,
            body["signature"]["s"].as_str()?,
            body["signature"]["v"].as_u64()?,
        )
    };
    let clients = state.status["clients"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let source = [Network::Testnet, Network::Mainnet]
        .into_iter()
        .find(|source| {
            signer(*source).is_some_and(|address| clients.contains(&json!(address.to_hex())))
        });
    if let Some(source) = source {
        state.sources.push(source);
    } else {
        state.bad_signatures += 1;
        return json!({"status": "err", "response": "Zunder Guard veto [auth_unknown_signer]: the signer is not a client"});
    }
    if !state.scripted.is_empty() {
        let reply = state.scripted.remove(0);
        push_event(
            state,
            json!({"kind": "decision", "via": "http", "client": CLIENT, "nonce": nonce,
                   "action": body["action"]["type"], "verdict": "veto", "code": "scripted",
                   "text": "scripted reply", "changes": []}),
        );
        return reply;
    }
    let decision = push_event(
        state,
        json!({"kind": "decision", "via": "http", "client": CLIENT, "nonce": nonce,
               "action": body["action"]["type"], "verdict": "allow", "code": "allowed",
               "text": "allowed as asked", "changes": [], "request": body["action"].clone()}),
    );
    if state.status["mode"] == "paper" {
        return json!({"status": "err", "response": "Zunder Guard paper mode: would allow [allowed]: allowed as asked (nothing was sent)"});
    }
    state.forwarded.push(body.clone());
    let reply = match body["action"]["type"].as_str() {
        Some("order") => {
            let orders = body["action"]["orders"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let statuses: Vec<Value> = orders
                .iter()
                .enumerate()
                .map(|(index, order)| {
                    if index > 0 && body["action"]["grouping"] == "normalTpsl" {
                        json!("waitingForTrigger")
                    } else if order["t"].get("trigger").is_some() {
                        state.next_oid += 1;
                        json!({"resting": {"oid": state.next_oid}})
                    } else {
                        state.next_oid += 1;
                        json!({"filled": {"totalSz": order["s"], "avgPx": order["p"], "oid": state.next_oid}})
                    }
                })
                .collect();
            json!({"status": "ok", "response": {"type": "order", "data": {"statuses": statuses}}})
        }
        Some("cancel") => {
            json!({"status": "ok", "response": {"type": "cancel", "data": {"statuses": ["success"]}}})
        }
        Some("modify") => json!({"status": "ok", "response": {"type": "default"}}),
        _ => json!({"status": "err", "response": "unsupported"}),
    };
    push_event(
        state,
        json!({"kind": "sent", "decision": decision, "nonce": nonce + 1, "ok": true, "reply": reply.clone()}),
    );
    reply
}

/// The three actions this server can send, read back from JSON.
pub fn decode_action(value: &Value) -> Option<Action> {
    let order = |value: &Value| -> Option<OrderWire> {
        let order_type = if let Some(limit) = value["t"].get("limit") {
            OrderType::Limit {
                tif: match limit["tif"].as_str()? {
                    "Gtc" => Tif::Gtc,
                    "Ioc" => Tif::Ioc,
                    _ => return None,
                },
            }
        } else {
            let trigger = value["t"].get("trigger")?;
            if trigger["isMarket"] != true || trigger["tpsl"] != "sl" {
                return None;
            }
            OrderType::StopMarket {
                trigger_px: trigger["triggerPx"].as_str()?.to_owned(),
            }
        };
        Some(OrderWire {
            asset: u32::try_from(value["a"].as_u64()?).ok()?,
            is_buy: value["b"].as_bool()?,
            price: value["p"].as_str()?.to_owned(),
            size: value["s"].as_str()?.to_owned(),
            reduce_only: value["r"].as_bool()?,
            order_type,
            cloid: value.get("c").and_then(Value::as_str).map(str::to_owned),
        })
    };
    match value["type"].as_str()? {
        "order" => Some(Action::Order {
            orders: value["orders"]
                .as_array()?
                .iter()
                .map(order)
                .collect::<Option<Vec<_>>>()?,
            grouping: match value["grouping"].as_str()? {
                "na" => Grouping::Na,
                "normalTpsl" => Grouping::NormalTpsl,
                _ => return None,
            },
        }),
        "cancel" => {
            let cancel = value["cancels"].as_array()?.first()?;
            Some(Action::Cancel {
                asset: u32::try_from(cancel["a"].as_u64()?).ok()?,
                oid: cancel["o"].as_u64()?,
            })
        }
        "modify" => Some(Action::Modify {
            oid: value["oid"].as_u64()?,
            order: order(&value["order"])?,
        }),
        _ => None,
    }
}

/// Drive the protocol: one JSON-RPC request, its reply.
pub fn rpc(server: &mut Server, id: u64, method: &str, params: Value) -> Value {
    let message = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    protocol::handle(server, &message.to_string()).expect("a reply")
}

/// Call a tool; return (isError, structuredContent).
pub fn call(server: &mut Server, name: &str, arguments: Value) -> (bool, Value) {
    let reply = rpc(
        server,
        1,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    );
    let result = &reply["result"];
    assert!(result.is_object(), "no result: {reply}");
    let text = result["content"][0]["text"].as_str().expect("text content");
    let parsed: Value = serde_json::from_str(text).expect("the text is the JSON");
    assert_eq!(parsed, result["structuredContent"]);
    (
        result["isError"].as_bool().expect("isError"),
        result["structuredContent"].clone(),
    )
}

/// A fresh directory for a test.
pub fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "zunder-guard-mcp-e2e-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}
