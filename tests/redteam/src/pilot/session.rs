// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! One invocation's session with Guard: the refusals before anything is
//! sent, every request and answer logged, previews before orders, and the
//! caps on what a step may send.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::Write,
    time::{Duration, Instant},
};

use rust_decimal::Decimal;
use serde_json::{Value, json};

use super::checks::{self, EntryRisk, Expect, Facts, Frame, GuardMode};
use super::{CheckResult, Ending, Options, Outcome, Step, steps};
use crate::actions::{body_with_signature, signed_body};
use crate::hlsign::{Key, SigningNet, Wire, keccak256};
use crate::now_ms;

/// The longest a request to Guard may take before its outcome counts as
/// unknown. Guard's own path (leverage, order, read-back) takes a few round
/// trips to the venue.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest one invocation waits, in all, for Guard's `/info` budget to
/// refill.
const MAX_BUDGET_WAIT: Duration = Duration::from_secs(120);

/// How often one request refused `rate_limited` (nothing forwarded) is
/// previewed and sent again.
const MAX_RATE_LIMITED: u32 = 4;

/// When this client last sent a request, for the pacing across invocations.
const LAST_SEND_FILE: &str = "pilot-last-send";

/// How an action was planned, to preview it again the same way.
#[derive(Debug, Clone)]
enum Spec {
    Entry(String),
    Veto(Option<String>),
    Exit(Vec<String>),
}

/// Why a step stopped.
#[derive(Debug, Clone)]
pub(super) enum Stop {
    /// A precondition or a pre-send check did not hold.
    Refused(String),
    /// A check failed after something was sent.
    Failed(String),
    /// A request's outcome is unknown.
    Unknown(String),
}

/// What the preview of an action allows the client to send.
#[derive(Debug, Clone)]
pub(super) enum Plan {
    /// An entry Guard would forward, within the frame's caps.
    Entry(EntryRisk),
    /// An order Guard would refuse with this code.
    Veto(String),
    /// An order Guard would refuse (any code; recorded).
    VetoAny,
    /// An exit, a stop or a cancel: opens nothing.
    Exit,
    /// A request refused before it is judged (a nonce from before the
    /// restart): a cancel only, never an order.
    Unjudged,
}

/// Guard's answer to an `/exchange` request.
#[derive(Debug, Clone)]
pub(super) struct Answer {
    pub raw: Value,
    pub nonce: u64,
    pub code: Option<String>,
    pub requested: Option<Decimal>,
    pub size: Option<Decimal>,
    /// For a forwarded entry: Guard's decision, and the entry it forwarded
    /// as held to the caps.
    pub decision: Option<Value>,
    /// The plan the answered request was sent under: a new one when it was
    /// previewed again after `rate_limited`.
    pub plan: Option<Plan>,
    pub forwarded_entry: Option<EntryRisk>,
}

impl Answer {
    fn of(raw: Value, nonce: u64) -> Self {
        let decimal = |key: &str| raw.get(key).and_then(checks::decimal_of);
        Self {
            code: raw.get("code").and_then(Value::as_str).map(str::to_owned),
            requested: decimal("requested_size"),
            size: decimal("size"),
            raw,
            nonce,
            decision: None,
            forwarded_entry: None,
            plan: None,
        }
    }

    fn status(&self) -> Option<&str> {
        self.raw.get("status").and_then(Value::as_str)
    }

    fn verdict(&self) -> Option<&str> {
        self.raw.get("verdict").and_then(Value::as_str)
    }

    /// Forwarded to the venue, or in paper mode would be.
    pub fn forwarded(&self) -> bool {
        self.status() == Some("ok") || matches!(self.verdict(), Some("allow" | "resize"))
    }

    /// Refused by Guard (a veto, a refusal before judging, or in paper mode
    /// a "would veto").
    pub fn vetoed(&self) -> bool {
        self.status() == Some("err")
            && (self.verdict() == Some("veto")
                || self
                    .raw
                    .get("response")
                    .and_then(Value::as_str)
                    .is_some_and(|text| text.starts_with("Zunder Guard veto")))
    }

    pub fn code_is(&self, code: &str) -> bool {
        self.code.as_deref() == Some(code)
    }

    /// The venue's status for the client's first order.
    pub fn first_status(&self) -> Option<&Value> {
        self.raw.pointer("/response/data/statuses/0")
    }
}

/// A coin of the main dex, from `meta`.
#[derive(Debug, Clone, Copy)]
pub(super) struct Coin {
    pub asset: u64,
    pub sz_decimals: u32,
}

/// The account on the venue, read through Guard's `/info`.
#[derive(Debug, Clone, Default)]
pub(super) struct Holdings {
    /// Coin and signed size of each open position.
    pub positions: Vec<(String, Decimal)>,
    pub orders: Vec<Value>,
}

impl Holdings {
    pub fn flat(&self) -> bool {
        self.positions.is_empty() && self.orders.is_empty()
    }

    pub fn position(&self, coin: &str) -> Option<Decimal> {
        self.positions
            .iter()
            .find(|(name, _)| name == coin)
            .map(|(_, size)| *size)
    }

    /// Open orders on `coin` whose client id starts with `prefix`.
    pub fn orders_with(&self, coin: &str, prefix: &str) -> Vec<&Value> {
        self.orders
            .iter()
            .filter(|order| order.get("coin").and_then(Value::as_str) == Some(coin))
            .filter(|order| {
                order
                    .get("cloid")
                    .and_then(Value::as_str)
                    .is_some_and(|cloid| cloid.starts_with(prefix))
            })
            .collect()
    }
}

pub(super) struct Session<'a> {
    pub opts: &'a Options,
    key: &'a Key,
    net: SigningNet,
    http: reqwest::blocking::Client,
    base: String,
    log: Option<File>,
    lines: Vec<Value>,
    checks: Vec<CheckResult>,
    pub facts: Facts,
    pub frame: Frame,
    last_nonce: u64,
    last_preview: Option<Instant>,
    entries: usize,
    opened: usize,
    sent: usize,
    failed: bool,
    cloids: u64,
    meta: Option<HashMap<String, Coin>>,
    budget_waited: Duration,
    /// How each action was planned (its preview), by its JSON.
    specs: HashMap<String, Spec>,
    /// When this client last sent a request (ms).
    last_send_ms: u64,
    /// Every entry planned in this step, by its action's JSON: the latest
    /// plan of each (a plan made again after `rate_limited` replaces it).
    step_risks: Vec<(String, EntryRisk)>,
}

impl<'a> Session<'a> {
    pub fn run(options: &'a Options, key: &'a Key) -> Outcome {
        let mut lines = Vec::new();
        let refuse = |lines: &mut Vec<Value>, reason: String| {
            let line = json!({"at_ms": now_ms(), "step": options.step.name(), "kind": "end",
                "ending": "refused", "reason": reason, "sent": 0});
            if options.echo {
                echo(&line.to_string());
            }
            lines.push(line);
            Outcome {
                ending: Ending::Refused,
                reason: Some(reason),
                checks: Vec::new(),
                sent: 0,
                lines: std::mem::take(lines),
            }
        };
        // The command line first: nothing is read before these hold.
        if let Err(reason) = static_checks(options) {
            return refuse(&mut lines, reason);
        }
        let log = match open_log(options, "pilot.jsonl") {
            Ok(file) => file,
            Err(reason) => return refuse(&mut lines, reason),
        };
        let http = match reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(http) => http,
            Err(error) => return refuse(&mut lines, format!("no HTTP client: {error}")),
        };
        let mut session = Session::new(options, key, http, Some(log), lines);
        session.line(json!({"kind": "start", "url": session.base,
            "expect_mode": options.expect_mode.name(), "account": options.confirm_account,
            "client": key.address().to_hex()}));
        let result = session.begin().and_then(|()| steps::run(&mut session));
        session.finish(result)
    }

    /// A session before its status is read.
    fn new(
        options: &'a Options,
        key: &'a Key,
        http: reqwest::blocking::Client,
        log: Option<File>,
        lines: Vec<Value>,
    ) -> Self {
        let net = match options.expect_mode {
            GuardMode::Mainnet => SigningNet::Mainnet,
            GuardMode::Paper | GuardMode::Testnet => SigningNet::Testnet,
        };
        Session {
            opts: options,
            key,
            net,
            http,
            base: options.url.trim_end_matches('/').to_owned(),
            log,
            lines,
            checks: Vec::new(),
            facts: placeholder_facts(),
            frame: checks::PILOT,
            last_nonce: 0,
            last_preview: None,
            entries: 0,
            opened: 0,
            sent: 0,
            failed: false,
            cloids: 0,
            meta: None,
            budget_waited: Duration::ZERO,
            specs: HashMap::new(),
            // The last send of an earlier invocation, so that its entries
            // and this one's are spaced too.
            last_send_ms: read_last_send(&options.log_dir),
            step_risks: Vec::new(),
        }
    }

    /// Status prerequisites checked before each step.
    fn begin(&mut self) -> Result<(), Stop> {
        let started = now_ms();
        let (_, facts) = self.status()?;
        let step = self.opts.step;
        let expect = Expect {
            mode: self.opts.expect_mode,
            account: self.opts.confirm_account.clone(),
            client: self.key.address().to_hex(),
            rules: step.rules(),
        };
        self.frame = checks::check_status(&facts, &expect).map_err(Stop::Refused)?;
        // A step that sends works from Guard's view of the account (its
        // previews are judged on it): wait for a sync newer than this
        // invocation, so that the view holds what the last step did.
        let facts = if step.sends() {
            let facts = self.wait_sync_after(started).map_err(|stop| match stop {
                Stop::Failed(reason) => Stop::Refused(reason),
                other => other,
            })?;
            self.frame = checks::check_status(&facts, &expect).map_err(Stop::Refused)?;
            facts
        } else {
            facts
        };
        if step.needs_sending() && !facts.mode.sends() {
            return Err(Stop::Refused(format!(
                "step {} needs a Guard that sends (testnet or mainnet): a paper Guard holds no position and never blocks for the fee",
                step.name()
            )));
        }
        if step.sends() {
            let age = facts
                .last_sync_ms
                .map(|at| now_ms().saturating_sub(at))
                .ok_or_else(|| Stop::Refused("Guard has not synced yet".to_owned()))?;
            if age > checks::MAX_SYNC_AGE_MS {
                return Err(Stop::Refused(format!(
                    "Guard's last sync is {age} ms old (more than {} ms): its view of the account is stale",
                    checks::MAX_SYNC_AGE_MS
                )));
            }
        }
        self.facts = facts;
        Ok(())
    }

    fn finish(mut self, result: Result<(), Stop>) -> Outcome {
        let (ending, reason) = match result {
            Ok(()) if self.failed => (
                Ending::Failed,
                Some("a check failed (see the FAIL lines)".to_owned()),
            ),
            Ok(()) => (Ending::Passed, None),
            Err(Stop::Refused(reason)) if self.sent == 0 => (Ending::Refused, Some(reason)),
            Err(Stop::Refused(reason)) | Err(Stop::Failed(reason)) => (
                Ending::Failed,
                Some(format!(
                    "{reason}; the step stopped here. Inspect positions and open orders in the Hyperliquid app before continuing; do not resend blindly"
                )),
            ),
            Err(Stop::Unknown(reason)) => (
                Ending::Unknown,
                Some(format!(
                    "UNKNOWN OUTCOME: {reason}. Look at the account (positions and open orders through /info, the Hyperliquid app) before anything else; never resend blindly"
                )),
            ),
        };
        let count = |result: &str| {
            self.checks
                .iter()
                .filter(|check| check.result == result)
                .count()
        };
        let (pass, fail, skip) = (count("PASS"), count("FAIL"), count("SKIP"));
        let ending_name = match ending {
            Ending::Passed => "passed",
            Ending::Failed => "failed",
            Ending::Refused => "refused",
            Ending::Unknown => "unknown",
        };
        let sent = self.sent;
        self.line(
            json!({"kind": "end", "ending": ending_name, "reason": reason,
            "pass": pass, "fail": fail, "skip": skip, "sent": sent}),
        );
        Outcome {
            ending,
            reason,
            checks: self.checks,
            sent,
            lines: self.lines,
        }
    }

    // ---- output ---------------------------------------------------------

    /// Print and log one JSON line, with the time and the step.
    pub fn line(&mut self, mut value: Value) {
        if let Some(fields) = value.as_object_mut() {
            fields.insert("at_ms".into(), json!(now_ms()));
            fields.insert("step".into(), json!(self.opts.step.name()));
        }
        let text = value.to_string();
        // The log first: a standard output that went away (the SSM session
        // closed) must neither panic nor lose the record of what was sent.
        if let Some(log) = self.log.as_mut()
            && writeln!(log, "{text}").and_then(|()| log.flush()).is_err()
        {
            let _ = writeln!(
                std::io::stderr(),
                "zunder-guard-pilot: the log can no longer be written"
            );
            self.log = None;
        }
        if self.opts.echo {
            echo(&text);
        }
        self.lines.push(value);
    }

    /// Record one check: PASS or FAIL. A FAIL stops the step before its
    /// next order ([`Session::gate`]).
    pub fn check(&mut self, criterion: &str, check: &str, ok: bool, detail: impl Into<String>) {
        let detail = detail.into();
        let result = if ok { "PASS" } else { "FAIL" };
        if !ok {
            self.failed = true;
        }
        self.record(criterion, check, result, detail);
    }

    /// A check that cannot be made here (paper mode, the fee off), and why.
    pub fn skip(&mut self, criterion: &str, check: &str, why: impl Into<String>) {
        self.record(criterion, check, "SKIP", why.into());
    }

    fn record(&mut self, criterion: &str, check: &str, result: &str, detail: String) {
        self.line(
            json!({"result": result, "kind": "check", "criterion": criterion,
            "check": check, "detail": detail}),
        );
        self.checks.push(CheckResult {
            criterion: criterion.to_owned(),
            check: check.to_owned(),
            result: result.to_owned(),
            detail,
        });
    }

    pub fn note(&mut self, text: impl Into<String>) {
        self.line(json!({"kind": "note", "text": text.into()}));
    }

    /// Nothing more is sent once a check failed.
    pub fn gate(&self) -> Result<(), Stop> {
        if self.failed {
            return Err(Stop::Failed(
                "a check failed, so nothing more is sent".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn sending(&self) -> bool {
        self.facts.mode.sends()
    }

    // ---- reading ----------------------------------------------------------

    fn get(&mut self, path: &str) -> Result<(u16, Value), String> {
        let response = self
            .http
            .get(format!("{}{path}", self.base))
            .send()
            .map_err(|error| format!("GET {path}: {error}"))?;
        let status = response.status().as_u16();
        let text = response
            .text()
            .map_err(|error| format!("GET {path}: {error}"))?;
        let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        Ok((status, value))
    }

    /// Guard's status, logged, and its facts.
    pub fn status(&mut self) -> Result<(Value, Facts), Stop> {
        let (code, status) = self.get("/guard/status").map_err(|error| {
            Stop::Refused(format!(
                "Guard's status cannot be read ({error}); is Guard running at {}?",
                self.base
            ))
        })?;
        self.line(json!({"kind": "status", "http": code, "status": status}));
        if code != 200 {
            return Err(Stop::Refused(format!(
                "Guard's status answered HTTP {code}"
            )));
        }
        let facts = checks::parse_facts(&status).map_err(Stop::Refused)?;
        Ok((status, facts))
    }

    pub fn healthz(&mut self) -> Result<Value, Stop> {
        let (code, value) = self.get("/healthz").map_err(Stop::Refused)?;
        self.line(json!({"kind": "healthz", "http": code, "answer": value}));
        Ok(value)
    }

    /// Guard's decision on one of this client's requests, and what it sent.
    pub fn decision(&mut self, nonce: u64) -> Result<Value, Stop> {
        let path = format!(
            "/guard/decision?nonce={nonce}&client={}",
            self.key.address().to_hex()
        );
        let (code, value) = self.get(&path).map_err(Stop::Failed)?;
        self.line(json!({"kind": "decision", "nonce": nonce, "http": code, "answer": value}));
        Ok(if code == 200 { value } else { Value::Null })
    }

    pub fn events_since(&mut self, seq: u64) -> Result<Vec<Value>, Stop> {
        let (code, value) = self
            .get(&format!("/guard/events?since={seq}"))
            .map_err(Stop::Failed)?;
        self.line(json!({"kind": "events", "since": seq, "http": code, "answer": value}));
        Ok(value.as_array().cloned().unwrap_or_default())
    }

    /// An `/info` request through Guard's passthrough, logged. Guard passes
    /// reads within a budget of the venue's request weight (2 a second, a
    /// burst of 160); a read it refuses for that budget (HTTP 502) is read
    /// again once the budget has refilled for it, within
    /// [`MAX_BUDGET_WAIT`] per invocation. Reads only: an order is never
    /// sent twice.
    pub fn info(&mut self, body: Value) -> Result<Value, Stop> {
        loop {
            let result = self
                .http
                .post(format!("{}/info", self.base))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_string())
                .send()
                .map_err(|error| (None, error.to_string()))
                .and_then(|response| {
                    let status = response.status();
                    let text = response
                        .text()
                        .map_err(|error| (Some(status.as_u16()), error.to_string()))?;
                    if !status.is_success() {
                        return Err((Some(status.as_u16()), format!("HTTP {status}: {text}")));
                    }
                    serde_json::from_str::<Value>(&text)
                        .map_err(|error| (Some(status.as_u16()), error.to_string()))
                });
            match result {
                Ok(answer) => {
                    self.line(json!({"kind": "info", "request": body, "answer": answer}));
                    return Ok(answer);
                }
                Err((Some(502), error)) if error.contains("info requests within") => {
                    // Weight 2 for the light reads, 20 for the rest: refilled
                    // at 2 a second.
                    let kind = body.get("type").and_then(Value::as_str).unwrap_or("");
                    let weight = match kind {
                        "allMids" | "clearinghouseState" | "l2Book" | "orderStatus" => 2,
                        _ => 20,
                    };
                    let wait = Duration::from_millis(weight * 500 + 1_000);
                    self.budget_waited += wait;
                    self.line(json!({"kind": "info", "request": body, "budget_wait_ms":
                        wait.as_millis() as u64, "error": error}));
                    if self.budget_waited > MAX_BUDGET_WAIT {
                        return Err(Stop::Failed(format!(
                            "Guard's read budget stayed spent for more than {} s",
                            MAX_BUDGET_WAIT.as_secs()
                        )));
                    }
                    std::thread::sleep(wait);
                }
                Err((_, error)) => {
                    self.line(json!({"kind": "info", "request": body, "error": error}));
                    return Err(Stop::Failed(format!(
                        "the venue could not be read through Guard: {error}"
                    )));
                }
            }
        }
    }

    /// The main dex's coins by name: asset id and size decimals.
    pub fn coin(&mut self, name: &str) -> Result<Coin, Stop> {
        if !checks::ALLOWED_COINS.contains(&name) {
            return Err(Stop::Refused(format!("{name} is not a pilot market")));
        }
        if self.meta.is_none() {
            let meta = self.info(json!({"type": "meta"}))?;
            let universe = meta
                .get("universe")
                .and_then(Value::as_array)
                .ok_or_else(|| Stop::Refused("meta has no universe".to_owned()))?;
            let coins = universe
                .iter()
                .enumerate()
                .filter_map(|(index, asset)| {
                    let name = asset.get("name")?.as_str()?.to_owned();
                    let sz_decimals = u32::try_from(asset.get("szDecimals")?.as_u64()?).ok()?;
                    Some((
                        name,
                        Coin {
                            asset: index as u64,
                            sz_decimals,
                        },
                    ))
                })
                .collect();
            self.meta = Some(coins);
        }
        self.meta
            .as_ref()
            .and_then(|meta| meta.get(name).copied())
            .ok_or_else(|| Stop::Refused(format!("meta does not list {name}")))
    }

    /// The mid of a coin (`allMids`, through Guard), on the main dex or a
    /// HIP-3 dex by name.
    pub fn mid(&mut self, coin: &str, dex: Option<&str>) -> Result<Decimal, Stop> {
        let body = match dex {
            None => json!({"type": "allMids"}),
            Some(dex) => json!({"type": "allMids", "dex": dex}),
        };
        let mids = self.info(body)?;
        mids.get(coin)
            .and_then(checks::decimal_of)
            .filter(|mid| *mid > Decimal::ZERO)
            .ok_or_else(|| Stop::Refused(format!("no mid for {coin}")))
    }

    /// The account's positions and open orders on every dex Guard reads.
    pub fn holdings(&mut self) -> Result<Holdings, Stop> {
        self.read_account(true)
    }

    /// The account's positions only (`clearinghouseState`, weight 2: the
    /// open orders cost 20), on every dex Guard reads.
    pub fn positions(&mut self) -> Result<Holdings, Stop> {
        self.read_account(false)
    }

    fn read_account(&mut self, with_orders: bool) -> Result<Holdings, Stop> {
        let account = self.facts.account.clone();
        let mut dexes: Vec<Option<String>> = vec![None];
        dexes.extend(self.facts.hip3_dexes.iter().cloned().map(Some));
        let mut holdings = Holdings::default();
        for dex in dexes {
            let with_dex = |kind: &str| match &dex {
                None => json!({"type": kind, "user": account}),
                Some(dex) => json!({"type": kind, "user": account, "dex": dex}),
            };
            let state = self.info(with_dex("clearinghouseState"))?;
            let positions = state
                .get("assetPositions")
                .and_then(Value::as_array)
                .ok_or_else(|| Stop::Failed(format!("no assetPositions in {state}")))?;
            for position in positions {
                let coin = position
                    .pointer("/position/coin")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        Stop::Failed(format!("a position without a coin: {position}"))
                    })?;
                let size = position
                    .pointer("/position/szi")
                    .and_then(checks::decimal_of)
                    .ok_or_else(|| {
                        Stop::Failed(format!("a position without a size: {position}"))
                    })?;
                if !size.is_zero() {
                    holdings.positions.push((coin.to_owned(), size));
                }
            }
            if !with_orders {
                continue;
            }
            let orders = self.info(with_dex("frontendOpenOrders"))?;
            let orders = orders
                .as_array()
                .ok_or_else(|| Stop::Failed(format!("the open orders are not a list: {orders}")))?;
            holdings.orders.extend(orders.iter().cloned());
        }
        Ok(holdings)
    }

    /// Read the account until `done` holds, at most `wait_ms`; the last
    /// reading. Reads only: nothing is sent while waiting.
    /// With `orders` false, only the positions are read.
    pub fn wait_holdings(
        &mut self,
        wait_ms: u64,
        orders: bool,
        done: impl Fn(&Holdings) -> bool,
    ) -> Result<Holdings, Stop> {
        let until = Instant::now() + Duration::from_millis(wait_ms);
        loop {
            let holdings = self.read_account(orders)?;
            if done(&holdings) || Instant::now() >= until {
                return Ok(holdings);
            }
            std::thread::sleep(Duration::from_millis(self.opts.timing.poll_ms));
        }
    }

    /// Wait for a sync of Guard's after `after_ms` (its view then shows what
    /// the step did), at most the sync wait. The status then.
    pub fn wait_sync_after(&mut self, after_ms: u64) -> Result<Facts, Stop> {
        let until = Instant::now() + Duration::from_millis(self.opts.timing.sync_wait_ms);
        loop {
            let (_, facts) = self.status()?;
            if facts.last_sync_ms.is_some_and(|at| at > after_ms) {
                return Ok(facts);
            }
            if Instant::now() >= until {
                return Err(Stop::Failed(format!(
                    "Guard did not sync within {} ms",
                    self.opts.timing.sync_wait_ms
                )));
            }
            std::thread::sleep(Duration::from_millis(self.opts.timing.poll_ms));
        }
    }

    // ---- previews -----------------------------------------------------------

    /// `POST /guard/preview`: what Guard would decide now, read-only.
    pub fn preview(&mut self, label: &str, action: &Wire) -> Result<Value, Stop> {
        let preview = self.preview_once(label, action)?;
        // Guard answers one preview a second (any client's): asked again
        // once, after a second. A preview is read-only.
        let limited = preview
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|error| error.contains("previews a second"));
        let preview = if limited {
            self.last_preview = Some(Instant::now());
            self.preview_once(label, action)?
        } else {
            preview
        };
        if let Some(error) = preview.get("error") {
            return Err(Stop::Refused(format!(
                "Guard could not preview {label}: {error}"
            )));
        }
        Ok(preview)
    }

    fn preview_once(&mut self, label: &str, action: &Wire) -> Result<Value, Stop> {
        if let Some(last) = self.last_preview {
            let gap = Duration::from_millis(self.opts.timing.preview_gap_ms);
            if let Some(rest) = gap.checked_sub(last.elapsed()) {
                std::thread::sleep(rest);
            }
        }
        let body = json!({"action": action.to_json_value()});
        let result = self
            .http
            .post(format!("{}/guard/preview", self.base))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .map_err(|error| error.to_string())
            .and_then(|response| {
                let text = response.text().map_err(|error| error.to_string())?;
                serde_json::from_str::<Value>(&text).map_err(|error| error.to_string())
            });
        self.last_preview = Some(Instant::now());
        let preview = match result {
            Ok(preview) => preview,
            Err(error) => {
                self.line(
                    json!({"kind": "preview", "label": label, "request": body, "error": error}),
                );
                return Err(Stop::Refused(format!(
                    "the preview of {label} could not be read: {error}"
                )));
            }
        };
        self.line(json!({"kind": "preview", "label": label, "request": body, "answer": preview}));
        Ok(preview)
    }

    fn preview_code(preview: &Value) -> (Option<&str>, Option<&str>) {
        (
            preview.get("verdict").and_then(Value::as_str),
            preview.get("code").and_then(Value::as_str),
        )
    }

    /// Preview an entry Guard is expected to forward with `code`, held to
    /// the frame's caps. Not sent unless it holds.
    pub fn plan_entry(&mut self, label: &str, action: &Wire, code: &str) -> Result<Plan, Stop> {
        self.specs.insert(
            action.to_json_value().to_string(),
            Spec::Entry(code.to_owned()),
        );
        let preview = self.preview(label, action)?;
        let (verdict, got) = Self::preview_code(&preview);
        if !matches!(verdict, Some("allow" | "resize")) || got != Some(code) {
            return Err(Stop::Refused(format!(
                "the preview of {label} answers {} [{}], not a forward [{code}]: not sent",
                verdict.unwrap_or("?"),
                got.unwrap_or("?")
            )));
        }
        let entry = preview
            .get("entry")
            .filter(|entry| !entry.is_null())
            .ok_or_else(|| Stop::Refused(format!("the preview of {label} shows no entry")))?;
        let risk = checks::assess_long_entry(entry, &self.facts, &self.frame)
            .map_err(|why| Stop::Refused(format!("{label} not sent: {why}")))?;
        self.line(json!({"kind": "plan", "label": label, "coin": risk.coin,
            "size": risk.size, "worst_price": risk.worst, "stop": risk.stop,
            "notional_usd": risk.notional, "loss_at_stop_usd": risk.planned_loss,
            "loss_at_stop_limit_usd": risk.gap_loss, "frame": self.frame.name}));
        let key = action.to_json_value().to_string();
        self.step_risks.retain(|(planned, _)| *planned != key);
        self.step_risks.push((key, risk.clone()));
        Ok(Plan::Entry(risk))
    }

    /// Preview an order Guard is expected to refuse with `code` (any code
    /// when `None`). Not sent unless the preview refuses it.
    pub fn plan_veto(
        &mut self,
        label: &str,
        action: &Wire,
        code: Option<&str>,
    ) -> Result<Plan, Stop> {
        self.specs.insert(
            action.to_json_value().to_string(),
            Spec::Veto(code.map(str::to_owned)),
        );
        let preview = self.preview(label, action)?;
        let (verdict, got) = Self::preview_code(&preview);
        let refused = verdict == Some("veto") && preview.get("forward").is_none_or(Value::is_null);
        match code {
            Some(code) if refused && got == Some(code) => Ok(Plan::Veto(code.to_owned())),
            None if refused => Ok(Plan::VetoAny),
            _ => Err(Stop::Refused(format!(
                "the preview of {label} answers {} [{}], not the expected refusal [{}]: not sent",
                verdict.unwrap_or("?"),
                got.unwrap_or("?"),
                code.unwrap_or("any")
            ))),
        }
    }

    /// Preview an exit, a stop or a cancel: it must open nothing. With
    /// `codes`, Guard must forward it with one of them, and a `resized` one
    /// only with the action unchanged (Guard's change is then what follows
    /// it, as cancelling its own stop); with none, any answer that opens
    /// nothing (a reduce-only order Guard may refuse).
    pub fn plan_exit(&mut self, label: &str, action: &Wire, codes: &[&str]) -> Result<Plan, Stop> {
        if opens_anything(action) {
            return Err(Stop::Refused(format!(
                "{label} is not reduce-only: not sent as an exit"
            )));
        }
        self.specs.insert(
            action.to_json_value().to_string(),
            Spec::Exit(codes.iter().map(|code| (*code).to_owned()).collect()),
        );
        let preview = self.preview(label, action)?;
        if preview.get("entry").is_some_and(|entry| !entry.is_null()) {
            return Err(Stop::Refused(format!(
                "the preview of {label} shows an entry: not sent"
            )));
        }
        let (verdict, got) = Self::preview_code(&preview);
        if !codes.is_empty() {
            let expected = matches!(verdict, Some("allow" | "resize"))
                && got.is_some_and(|got| codes.contains(&got));
            // Guard's own builder field on the forward is not a change of
            // the action (it goes on every order Guard sends, stops too).
            let forward = preview.get("forward").cloned().map(|mut forward| {
                if let Some(fields) = forward.as_object_mut() {
                    fields.remove("builder");
                }
                forward
            });
            let unchanged = got != Some("resized") || forward == Some(action.to_json_value());
            if !expected || !unchanged {
                return Err(Stop::Refused(format!(
                    "the preview of {label} answers {} [{}]{}, not a forward [{}]: not sent",
                    verdict.unwrap_or("?"),
                    got.unwrap_or("?"),
                    if unchanged {
                        ""
                    } else {
                        " with the action changed"
                    },
                    codes.join(" or ")
                )));
            }
        }
        Ok(Plan::Exit)
    }

    /// The step's worst case, asserted before its first order and again
    /// whenever an entry is planned anew (after `rate_limited`): the sum of
    /// the losses of every entry planned in this step, with every stop
    /// filled at its limit.
    pub fn assert_worst_case(&mut self) -> Result<(), Stop> {
        let risks: Vec<EntryRisk> = self
            .step_risks
            .iter()
            .map(|(_, risk)| risk.clone())
            .collect();
        let caps = self.opts.step.caps();
        let worst: Decimal = risks.iter().map(|risk| risk.gap_loss).sum();
        let planned: Decimal = risks.iter().map(|risk| risk.planned_loss).sum();
        let cap = self.frame.max_gap_loss_usd * Decimal::from(caps.max_open_entries);
        self.line(json!({"kind": "worst_case", "entries": risks.len(),
            "loss_at_stops_usd": planned, "loss_at_stop_limits_usd": worst, "cap_usd": cap}));
        if risks.len() > caps.max_open_entries || worst > cap {
            return Err(Stop::Refused(format!(
                "the step's worst case is {} USDC over {} entries; its cap is {cap} USDC over {}: not sent",
                worst.round_dp(4),
                risks.len(),
                caps.max_open_entries
            )));
        }
        Ok(())
    }

    // ---- sending ------------------------------------------------------------

    fn next_nonce(&mut self) -> u64 {
        let nonce = now_ms().max(self.last_nonce + 1);
        self.last_nonce = nonce;
        nonce
    }

    /// A fresh client order id of the client's: `0x7a70` and 28 hex digits.
    pub fn cloid(&mut self) -> String {
        self.cloids += 1;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let seed = format!("{nanos}:{}:{}", std::process::id(), self.cloids);
        let hash = keccak256(seed.as_bytes());
        let digits: String = hash
            .iter()
            .take(14)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("{}{digits}", checks::CLOID_PREFIX)
    }

    /// Send one action to `/exchange`, once. The plan is what its preview
    /// allowed; the action types the client ever sends are orders, cancels
    /// and (in S3) a modify.
    pub fn send(&mut self, label: &str, action: &Wire, plan: &Plan) -> Result<Answer, Stop> {
        self.send_with(label, action, plan, None)
    }

    /// As [`Session::send`], with a nonce of the caller's: only for the
    /// request signed with a nonce from before Guard's restart (S7), which
    /// must be a cancel.
    pub fn send_stale(&mut self, label: &str, action: &Wire, nonce: u64) -> Result<Answer, Stop> {
        self.send_with(label, action, &Plan::Unjudged, Some(nonce))
    }

    fn send_with(
        &mut self,
        label: &str,
        action: &Wire,
        plan: &Plan,
        stale: Option<u64>,
    ) -> Result<Answer, Stop> {
        self.gate()?;
        let step = self.opts.step;
        if !step.sends() {
            return Err(Stop::Refused(format!("step {} sends nothing", step.name())));
        }
        let json = action.to_json_value();
        let kind = json.get("type").and_then(Value::as_str).unwrap_or("");
        match kind {
            "order" | "cancel" => {}
            "modify" if step == Step::StopChecks => {}
            other => {
                return Err(Stop::Refused(format!(
                    "the client never sends a {other} action"
                )));
            }
        }
        let entries = entry_count(&json);
        match plan {
            Plan::Entry(_) if entries != 1 => {
                return Err(Stop::Refused(format!("{label}: one entry per action")));
            }
            Plan::Veto(_) | Plan::VetoAny if entries > 1 => {
                return Err(Stop::Refused(format!("{label}: one entry per action")));
            }
            Plan::Exit if entries > 0 => {
                return Err(Stop::Refused(format!("{label} is not an exit")));
            }
            Plan::Unjudged if kind != "cancel" => {
                return Err(Stop::Refused(format!("{label} must be a cancel")));
            }
            _ => {}
        }
        let caps = step.caps();
        if self.entries + entries > caps.max_entries {
            return Err(Stop::Refused(format!(
                "{label}: step {} sends at most {} entries",
                step.name(),
                caps.max_entries
            )));
        }
        if matches!(plan, Plan::Entry(_)) && self.opened >= caps.max_open_entries {
            return Err(Stop::Refused(format!(
                "{label}: step {} opens at most {} entries",
                step.name(),
                caps.max_open_entries
            )));
        }
        self.entries += entries;
        // Guard refuses a request `rate_limited` when its budget of the
        // venue's request weight for bots is spent, and then forwards
        // nothing. Such a request is previewed and sent again, after the
        // budget has refilled, at most [`MAX_RATE_LIMITED`] times; a request
        // Guard forwarded (or may have) is never sent again.
        let mut plan = plan.clone();
        let mut retries = 0;
        let mut waited = false;
        let mut answer = loop {
            if entries > 0 && self.pace_entry(label) {
                waited = true;
            }
            // After any wait (the pacing, or the budget's refill after
            // `rate_limited`) the preview is stale: the step's whole plan
            // again, this action's preview and the step's worst case with
            // the new plan in it, before anything is sent.
            if std::mem::take(&mut waited) && stale.is_none() {
                plan = self.replan(label, action)?;
                if matches!(plan, Plan::Entry(_)) {
                    self.assert_worst_case()?;
                }
            }
            let nonce = stale.unwrap_or_else(|| self.next_nonce());
            let answer = self.post_exchange(label, action, &json, nonce)?;
            let limited = stale.is_none() && answer.vetoed() && answer.code_is("rate_limited");
            if !limited || retries >= MAX_RATE_LIMITED || !may_retry(&plan, &answer) {
                break answer;
            }
            // Positive proof that nothing went out: Guard's journaled
            // decision on this very nonce, a `rate_limited` veto with no
            // forward, and an empty list of what was sent. A lookup that
            // fails is no proof: the answer stands, nothing is sent again.
            let decision = self.decision(nonce).unwrap_or(Value::Null);
            if !proven_unsent(&decision, nonce) {
                self.line(json!({"kind": "note", "label": label, "nonce": nonce,
                    "text": "refused rate_limited, but Guard's decision gives no proof that nothing went out: not sent again"}));
                break answer;
            }
            retries += 1;
            let wait = self.opts.timing.rate_wait_ms;
            self.line(json!({"kind": "rate_limited", "label": label, "nonce": nonce,
                "retry": retries, "wait_ms": wait,
                "text": "proven unsent; waiting for Guard's request budget, then the step's plan again and the same action sent again"}));
            std::thread::sleep(Duration::from_millis(wait));
            waited = true;
        };
        answer.plan = Some(plan.clone());
        let plan = &plan;
        let nonce = answer.nonce;
        if matches!(plan, Plan::Entry(_) | Plan::Veto(_) | Plan::VetoAny)
            && entries == 1
            && answer.forwarded()
        {
            self.opened += 1;
            if self.opened > caps.max_open_entries {
                return Err(Stop::Failed(format!(
                    "{label} was forwarded although the step opens at most {} entries: abort, pull the kill switch and inspect positions and open orders",
                    caps.max_open_entries
                )));
            }
        }
        // An order its preview refused, forwarded all the same.
        let previewed = match plan {
            Plan::Veto(code) => Some(code.as_str()),
            Plan::VetoAny => Some("any"),
            _ => None,
        };
        if let Some(previewed) = previewed
            && answer.forwarded()
        {
            self.check(
                "caps",
                &format!("{label}: refused as previewed"),
                false,
                format!(
                    "previewed as refused [{previewed}], forwarded [{:?}]: ABORT now: pull the kill switch and inspect positions and open orders",
                    answer.code
                ),
            );
        }
        // An entry: what Guard actually forwarded, from its decision, held
        // to the same caps as the preview.
        if let Plan::Entry(risk) = plan
            && answer.forwarded()
        {
            let decision = self.decision(nonce)?;
            let forwarded = forwarded_entry(&decision, &risk.coin, answer.requested);
            let assessed = forwarded
                .as_ref()
                .ok_or_else(|| "the decision shows no forwarded entry".to_owned())
                .and_then(|entry| checks::assess_long_entry(entry, &self.facts, &self.frame));
            let within = assessed.is_ok()
                && answer
                    .size
                    .is_none_or(|size| size <= risk.size * Decimal::new(11, 1));
            self.check(
                "caps",
                &format!("{label}: what Guard forwarded is within the caps"),
                within,
                match &assessed {
                    Ok(sent) => format!(
                        "forwarded {} at worst {} with its stop at {} ({} USDC; previewed {})",
                        sent.size,
                        sent.worst,
                        sent.stop,
                        sent.notional.round_dp(2),
                        risk.size
                    ),
                    Err(why) => format!(
                        "{why}: ABORT now: pull the kill switch and inspect positions and open orders"
                    ),
                },
            );
            answer.forwarded_entry = assessed.ok();
            answer.decision = Some(decision);
        }
        Ok(answer)
    }

    /// One `/exchange` request, logged: Guard's answer, or an unknown
    /// outcome when none came (or Guard says the venue did not answer).
    fn post_exchange(
        &mut self,
        label: &str,
        action: &Wire,
        json: &Value,
        nonce: u64,
    ) -> Result<Answer, Stop> {
        let body = signed_body(self.key, self.net, action, nonce, None);
        self.line(
            json!({"kind": "request", "label": label, "path": "/exchange",
            "nonce": nonce, "action": json}),
        );
        let started = Instant::now();
        self.sent += 1;
        let result = self
            .http
            .post(format!("{}/exchange", self.base))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send();
        self.note_send();
        let rtt_ms = started.elapsed().as_millis() as u64;
        let raw = match result.map(|response| (response.status(), response.text())) {
            Ok((status, Ok(text))) if status.is_success() => serde_json::from_str::<Value>(&text)
                .map_err(|_| format!("HTTP {status}, not JSON: {text}")),
            Ok((status, Ok(text))) => Err(format!("HTTP {status}: {text}")),
            Ok((status, Err(error))) => Err(format!("HTTP {status}, unreadable: {error}")),
            Err(error) => Err(error.to_string()),
        };
        let raw = match raw {
            Ok(raw) => raw,
            Err(error) => {
                self.line(json!({"kind": "answer", "label": label, "nonce": nonce,
                    "rtt_ms": rtt_ms, "error": error}));
                return Err(Stop::Unknown(format!("{label} (nonce {nonce}): {error}")));
            }
        };
        self.line(json!({"kind": "answer", "label": label, "nonce": nonce,
            "rtt_ms": rtt_ms, "answer": raw}));
        let answer = Answer::of(raw, nonce);
        // Guard's own "no answer from the venue": the order may have
        // reached it. An unknown outcome, never an ordinary refusal.
        if answer.code_is("venue_unreachable") {
            return Err(Stop::Unknown(format!(
                "{label} (nonce {nonce}): Guard reports venue_unreachable, so it may have reached the venue"
            )));
        }
        Ok(answer)
    }

    /// Space the requests that hold an entry by Guard's request budget
    /// (4 of the venue's weight a second, a burst of 60; an entry costs up
    /// to 46 with the account read and the leverage set first; the budget is
    /// not in Guard's status): at least `entry_gap_ms` after this client's
    /// last request, in this invocation or the one before
    /// (`pilot-last-send` in the log directory). Exits are never held back.
    /// Whether it waited.
    fn pace_entry(&mut self, label: &str) -> bool {
        let gap = self.opts.timing.entry_gap_ms;
        let due = self.last_send_ms.saturating_add(gap);
        let now = now_ms();
        if due <= now {
            return false;
        }
        // Never more than one gap, whatever the file said.
        let wait = (due - now).min(gap);
        self.line(json!({"kind": "pace", "label": label, "wait_ms": wait,
            "text": "spacing entries by Guard's request budget; the plan is made again after the wait"}));
        std::thread::sleep(Duration::from_millis(wait));
        true
    }

    /// Record that a request went out, for the pacing of the next.
    fn note_send(&mut self) {
        self.last_send_ms = now_ms();
        if let Err(error) = write_last_send(&self.opts.log_dir, self.last_send_ms) {
            self.line(json!({"kind": "note",
                "text": format!("{LAST_SEND_FILE} could not be written: {error}")}));
        }
    }

    /// Preview `action` again as it was first planned.
    fn replan(&mut self, label: &str, action: &Wire) -> Result<Plan, Stop> {
        let key = action.to_json_value().to_string();
        match self.specs.get(&key).cloned() {
            Some(Spec::Entry(code)) => self.plan_entry(label, action, &code),
            Some(Spec::Veto(code)) => self.plan_veto(label, action, code.as_deref()),
            Some(Spec::Exit(codes)) => {
                let codes: Vec<&str> = codes.iter().map(String::as_str).collect();
                self.plan_exit(label, action, &codes)
            }
            None => Err(Stop::Failed(format!(
                "{label} was refused rate_limited and has no preview to repeat"
            ))),
        }
    }

    /// Pull the kill switch: the signed `POST /guard/kill`, sent once.
    pub fn kill(&mut self, reason: &str) -> Result<Value, Stop> {
        self.gate()?;
        if self.opts.step != Step::Kill {
            return Err(Stop::Refused(
                "only step kill pulls the kill switch".to_owned(),
            ));
        }
        let action = Wire::map(vec![
            ("type", Wire::str("zunderGuardKill")),
            ("reason", Wire::str(reason)),
        ]);
        let nonce = self.next_nonce();
        let sig = self
            .key
            .sign_l1_action(self.net, &action, nonce, None)
            .ok_or_else(|| Stop::Refused("the client key did not sign".to_owned()))?;
        let body = body_with_signature(&action, nonce, None, &sig);
        self.line(
            json!({"kind": "request", "label": "kill switch", "path": "/guard/kill",
            "nonce": nonce, "action": action.to_json_value()}),
        );
        self.sent += 1;
        let started = Instant::now();
        let result = self
            .http
            .post(format!("{}/guard/kill", self.base))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .map_err(|error| error.to_string())
            .and_then(|response| {
                let text = response.text().map_err(|error| error.to_string())?;
                serde_json::from_str::<Value>(&text).map_err(|_| format!("not JSON: {text}"))
            });
        let rtt_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(answer) => {
                self.line(
                    json!({"kind": "answer", "label": "kill switch", "nonce": nonce,
                    "rtt_ms": rtt_ms, "answer": answer}),
                );
                Ok(answer)
            }
            Err(error) => {
                self.line(
                    json!({"kind": "answer", "label": "kill switch", "nonce": nonce,
                    "rtt_ms": rtt_ms, "error": error}),
                );
                Err(Stop::Unknown(format!("the kill request: {error}")))
            }
        }
    }
}

/// The entry Guard forwarded, from its decision (`/guard/decision`), in the
/// shape of a preview's `entry`: the entry order's price is its worst price,
/// the stop child's trigger its stop, the leverage the update sent first.
pub(super) fn forwarded_entry(
    decision: &Value,
    coin: &str,
    requested: Option<Decimal>,
) -> Option<Value> {
    let event = decision.get("decision")?;
    let orders = event.pointer("/forward/orders")?.as_array()?;
    let entry = orders
        .iter()
        .find(|order| order.get("r").and_then(Value::as_bool) == Some(false))?;
    if entry.get("b").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let stop = orders
        .iter()
        .find_map(|order| order.pointer("/t/trigger/triggerPx"))?;
    let leverage = event
        .get("pre")
        .and_then(Value::as_array)
        .and_then(|pre| {
            pre.iter()
                .find(|action| action.get("type").and_then(Value::as_str) == Some("updateLeverage"))
        })
        .and_then(|update| update.get("leverage"))
        .cloned()
        .unwrap_or(Value::Null);
    let size = entry.get("s")?.clone();
    Some(json!({
        "coin": coin,
        "side": "buy",
        "requested_size": requested.map_or(size.clone(), |asked| json!(asked)),
        "size": size,
        "worst_price": entry.get("p")?,
        "stop": stop,
        "leverage": leverage,
    }))
}

/// Whether a request refused `rate_limited` may be previewed and sent
/// again. Entries and exits: yes. An order expected to be refused: only
/// when the refusal hides the expected one, so that the check still sees
/// it: Guard's budget for reading the account (refused before judging), or
/// the fee gate (Guard checks the fee after the budget of what a forward
/// sends). Never the request signed with a stale nonce.
fn may_retry(plan: &Plan, answer: &Answer) -> bool {
    let text = answer
        .raw
        .get("response")
        .and_then(Value::as_str)
        .unwrap_or("");
    let account_read = text.contains("Guard reads the account for at most")
        || text.contains("request-read budget is spent");
    match plan {
        Plan::Entry(_) | Plan::Exit => true,
        Plan::Veto(code) if code == "fee_not_approved" => true,
        Plan::Veto(_) | Plan::VetoAny => account_read,
        Plan::Unjudged => false,
    }
}

/// Whether Guard's decision (`/guard/decision`) on `nonce` proves that
/// nothing was sent for it: the decision event is there, for this nonce, a
/// `rate_limited` veto with no forward, and the list of sends is there and
/// empty. Anything else (no decision, a lookup error, a missing field) is
/// no proof.
pub(super) fn proven_unsent(decision: &Value, nonce: u64) -> bool {
    let Some(event) = decision.get("decision") else {
        return false;
    };
    event.get("nonce").and_then(Value::as_u64) == Some(nonce)
        && event.get("code").and_then(Value::as_str) == Some("rate_limited")
        && event.get("verdict").and_then(Value::as_str) == Some("veto")
        && event.get("forward").is_some_and(Value::is_null)
        && decision
            .get("sent")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
}

/// The last send of an earlier invocation (`pilot-last-send`): a regular
/// file of at most 32 bytes holding milliseconds; anything else, or a time
/// more than a minute ahead, counts as none.
fn read_last_send(dir: &std::path::Path) -> u64 {
    let path = dir.join(LAST_SEND_FILE);
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return 0;
    };
    if !meta.file_type().is_file() || meta.len() > 32 {
        return 0;
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .filter(|at| *at <= now_ms() + 60_000)
        .unwrap_or(0)
}

/// Record the last send: written to a fresh owner-only file beside it and
/// renamed over it, so that a link planted at either name is replaced, never
/// followed.
fn write_last_send(dir: &std::path::Path, at: u64) -> std::io::Result<()> {
    let path = dir.join(LAST_SEND_FILE);
    let fresh = dir.join(format!("{LAST_SEND_FILE}.new"));
    match std::fs::remove_file(&fresh) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut open = OpenOptions::new();
    open.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let mut file = open.open(&fresh)?;
    file.write_all(at.to_string().as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&fresh, &path)
}

/// One line on standard output; a closed output is ignored, never a panic.
fn echo(text: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}").and_then(|()| out.flush());
}

/// How many entries an action holds: orders that are not reduce-only and
/// not trigger orders (a stop child of an entry is reduce-only).
pub(super) fn entry_count(action: &Value) -> usize {
    if action.get("type").and_then(Value::as_str) != Some("order") {
        return 0;
    }
    action
        .get("orders")
        .and_then(Value::as_array)
        .map_or(0, |orders| {
            orders
                .iter()
                .filter(|order| order.get("r").and_then(Value::as_bool) != Some(true))
                .count()
        })
}

fn opens_anything(action: &Wire) -> bool {
    entry_count(&action.to_json_value()) > 0
}

/// The command line's own checks, before anything is read.
fn static_checks(options: &Options) -> Result<(), String> {
    if !checks::loopback_url(&options.url) {
        return Err(format!(
            "{} is not Guard on this machine: plain http on 127.0.0.1, localhost or [::1] only",
            options.url
        ));
    }
    if !checks::is_address(&options.confirm_account) {
        return Err(format!(
            "--confirm-account {} is not an address (0x and 40 hex digits)",
            options.confirm_account
        ));
    }
    if options.expect_mode == GuardMode::Mainnet {
        if !options.pilot_confirmed {
            return Err(
                "--expect-mode mainnet needs --i-am-jonas-and-this-is-the-pilot: mainnet runs only at the operator's go-ahead for this invocation"
                    .to_owned(),
            );
        }
        if options.url.trim_end_matches('/') != checks::PILOT_URL {
            return Err(format!(
                "on mainnet the client talks only to {}",
                checks::PILOT_URL
            ));
        }
    }
    Ok(())
}

/// Open `name` in the log directory for appending, creating it owner-only.
pub(super) fn open_log(options: &Options, name: &str) -> Result<File, String> {
    let path = options.log_dir.join(name);
    let mut open = OpenOptions::new();
    open.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    open.open(&path)
        .map_err(|error| format!("the log {} cannot be opened: {error}", path.display()))
}

/// Facts before the status is read; never acted on (`begin` replaces them
/// or the step is refused).
fn placeholder_facts() -> Facts {
    Facts {
        mode: GuardMode::Paper,
        account: String::new(),
        started_at_ms: 0,
        killed: None,
        risk_state: String::new(),
        equity: None,
        equity_cap: None,
        sizing_fee_bps: Decimal::ZERO,
        slippage_bps: Decimal::ZERO,
        stop_slippage: Decimal::ZERO,
        exit_slippage: Decimal::ZERO,
        hip3_dexes: Vec::new(),
        unmanaged_dexes: 0,
        positions: 0,
        open_orders: 0,
        last_sync_ms: None,
        last_error: None,
        alerts: Vec::new(),
        rules: String::new(),
        fee: checks::Fee {
            mode: String::new(),
            builder: None,
            fee_tenths_bp: None,
            approval: None,
            entries_blocked: false,
            on_triggers: false,
        },
        clients: Vec::new(),
        last_event: 0,
        journal_broken: false,
    }
}

#[cfg(test)]
#[path = "resend_tests.rs"]
mod resend_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{OrderSpec, cancel, order};

    #[test]
    fn entries_are_counted_by_their_reduce_only_flag() {
        let entry = order(&[OrderSpec::limit_buy(0, "60000", "0.01")], "na");
        assert_eq!(entry_count(&entry.to_json_value()), 1);
        let with_stop = order(
            &[
                OrderSpec::limit_buy(1, "2910", "0.25"),
                OrderSpec::stop(1, false, "2851.8", "0.25"),
            ],
            "normalTpsl",
        );
        assert_eq!(entry_count(&with_stop.to_json_value()), 1);
        let close = order(
            &[OrderSpec {
                reduce_only: true,
                ..OrderSpec::limit_sell(0, "57000", "0.00127")
            }],
            "na",
        );
        assert_eq!(entry_count(&close.to_json_value()), 0);
        assert!(!opens_anything(&close));
        assert_eq!(entry_count(&cancel(0, 5).to_json_value()), 0);
    }

    #[test]
    fn the_forwarded_entry_is_read_from_guards_decision() {
        // As Guard journals the S2 entry on the in-memory venue: the
        // leverage update first, the entry at its pulled-in worst price
        // with Guard's stop as a child.
        let decision = json!({"decision": {
            "pre": [{"type": "updateLeverage", "asset": 0, "isCross": false, "leverage": 3}],
            "forward": {"type": "order", "grouping": "normalTpsl", "orders": [
                {"a": 0, "b": true, "p": "60300", "s": "0.00125", "r": false,
                 "t": {"limit": {"tif": "Ioc"}}},
                {"a": 0, "b": false, "p": "52920", "s": "0.00125", "r": true,
                 "t": {"trigger": {"isMarket": true, "triggerPx": "58800", "tpsl": "sl"}}}]}},
            "sent": []});
        let entry = forwarded_entry(&decision, "BTC", Some(Decimal::new(1, 2))).unwrap();
        assert_eq!(entry["worst_price"], "60300");
        assert_eq!(entry["stop"], "58800");
        assert_eq!(entry["size"], "0.00125");
        assert_eq!(entry["leverage"], 3);
        assert_eq!(entry["requested_size"], "0.01");
        // A sell, or no entry at all, is not read as one.
        let mut sell = decision.clone();
        sell["decision"]["forward"]["orders"][0]["b"] = json!(false);
        assert!(forwarded_entry(&sell, "BTC", None).is_none());
        assert!(forwarded_entry(&json!({"decision": {"forward": null}}), "BTC", None).is_none());
    }

    fn options(mode: GuardMode, url: &str, confirmed: bool) -> Options {
        Options {
            url: url.to_owned(),
            step: Step::Look,
            expect_mode: mode,
            confirm_account: "0x5e9ee1089755c3435139848e47e6635505d5a13a".to_owned(),
            pilot_confirmed: confirmed,
            log_dir: std::env::temp_dir(),
            timing: super::super::Timing::default(),
            echo: false,
        }
    }

    #[test]
    fn mainnet_needs_the_flag_and_the_pilot_address() {
        assert!(
            static_checks(&options(GuardMode::Mainnet, checks::PILOT_URL, false))
                .unwrap_err()
                .contains("--i-am-jonas-and-this-is-the-pilot")
        );
        assert!(
            static_checks(&options(GuardMode::Mainnet, "http://127.0.0.1:9000", true))
                .unwrap_err()
                .contains("127.0.0.1:8547")
        );
        assert!(static_checks(&options(GuardMode::Mainnet, checks::PILOT_URL, true)).is_ok());
        // Testnet: any loopback port, no flag.
        assert!(
            static_checks(&options(GuardMode::Testnet, "http://127.0.0.1:9000", false)).is_ok()
        );
        assert!(
            static_checks(&options(
                GuardMode::Testnet,
                "http://example.com:8547",
                false
            ))
            .is_err()
        );
        let mut bad = options(GuardMode::Testnet, checks::PILOT_URL, false);
        bad.confirm_account = "P".to_owned();
        assert!(static_checks(&bad).unwrap_err().contains("not an address"));
    }
}
