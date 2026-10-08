// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! An in-memory Hyperliquid for Guard's end-to-end tests: it answers the
//! `info` requests Guard reads, and takes `exchange` requests only when
//! they are signed by the API wallet for testnet, exactly as the venue
//! checks them (same action hash, same phantom agent). Marketable limit
//! orders fill at once at their limit price; trigger orders and other
//! limits rest.
//!
//! Besides the main dex (BTC, ETH, SOL) it lists two HIP-3 dexes, as
//! `perpDexs` does: `xyz` at index 1 (`xyz:GOLD` 110000, `xyz:TSLA` 110001,
//! `xyz:URANIUM` 110002, halted) and `abc` at index 2 (`abc:FOO` 120000).
//! Each dex has its own margin account; answers with a `dex` show only
//! that dex's positions, orders and mids, as the venue's do.

#![allow(dead_code, clippy::unwrap_used)]

use std::{collections::HashMap, sync::Mutex};

use rust_decimal::Decimal;
use serde_json::{Value, json};
use zunder_guard::{
    guard::Clock,
    upstream::{Upstream, UpstreamError},
};
use zunder_guard_core::{
    action::{Action, OrderKind, decode_request},
    sign::{Address, SigningNetwork, action_hash, agent_digest, recover_signer},
};

/// What the venue received, decoded, with who signed it.
#[derive(Debug, Clone)]
pub struct Received {
    pub action: Action,
    pub json: Value,
    pub nonce: u64,
    pub signer: Address,
    /// The request's `expiresAfter`, if it has one.
    pub expires_after: Option<u64>,
}

/// A check run on every action the venue receives, before it acts on it.
type Check = std::sync::Arc<dyn Fn(&Value) + Send + Sync>;

#[derive(Clone, Default)]
struct Hook(Option<Check>);

impl std::fmt::Debug for Hook {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(if self.0.is_some() {
            "Hook(set)"
        } else {
            "Hook(none)"
        })
    }
}

#[derive(Debug, Default, Clone)]
struct State {
    before_send: Hook,
    equity: String,
    mids: Value,
    positions: Vec<Value>,
    orders: Vec<Value>,
    received: Vec<Received>,
    next_oid: u64,
    nonces: Vec<u64>,
    leverage: Vec<(String, u64)>,
    /// Refuse every stop loss (to see Guard close an unprotected fill).
    refuse_stops: bool,
    /// Each HIP-3 dex's account value (also what is withdrawable).
    dex_equity: HashMap<String, String>,
    /// HIP-3 coins at their open-interest cap.
    capped: Vec<String>,
    /// Books by coin; a coin without one gets a deep book around its mid.
    books: HashMap<String, Value>,
    /// Every info request received, for tests that count them.
    info_log: Vec<Value>,
    /// Dexes whose `meta` answers garbage (a deployer's malformed meta).
    broken: Vec<String>,
    /// Dexes whose `clearinghouseState` fails.
    failing: Vec<String>,
    /// Dexes whose open orders carry a foreign coin.
    garbled: Vec<String>,
    /// Open-order reads fail while the positions remain readable.
    orders_fail: bool,
    /// The account's approved maximum builder fee (tenths of a bp), as
    /// `maxBuilderFee` answers; an order whose builder fee is above it is
    /// refused whole, as Hyperliquid does ("Builder fee has not been
    /// approved.").
    builder_approval: u64,
    /// How many `maxBuilderFee` reads the venue answered.
    builder_checks: u32,
    /// The venue's WebSocket, once [`serve_ws`] serves it.
    ws_url: Option<String>,
    /// Orders the venue took: each is an `orderUpdates` event on the socket.
    events: u64,
    /// The ledger read over HTTP fails.
    ledger_fails: bool,
    flow_records_fails: bool,
    ledger_delay_ms: u64,
    flow_records_delay_ms: u64,
    book_delay_ms: u64,
    /// The ledger read over HTTP leaves out entries younger than this (ms):
    /// a node a little behind the account's.
    ledger_lag_ms: i64,
    /// Events for the socket, as the venue reports them: `orderUpdates`
    /// and fills of what it took, and other apps' (`outside_event`).
    ws_events: Vec<Value>,
    /// While set, the socket sends nothing (a stalled stream).
    ws_paused: bool,
    /// While set, the socket sends no snapshots (`clearinghouseState`,
    /// `openOrders`, `allMids`), only prices, books and events.
    ws_snapshots_paused: bool,
    /// The account's snapshots go out every this many ticks (0 or 1: every
    /// tick), as the venue's every 5 s against prices every second.
    ws_snapshot_every: u64,
    /// As recorded on testnet: a cancel or a close brings the account's
    /// snapshots in the same batch as its events (`ws_snapshot_now`); an
    /// entry's events bring them about 1 s later
    /// (`ws_snapshot_after_entry_ms`, `None`: only at the next periodic
    /// one), and the periodic ones count on from there.
    ws_snapshot_now: bool,
    ws_snapshot_due_ms: Option<u64>,
    ws_snapshot_after_entry_ms: Option<u64>,
    /// Stops placed as children of a resting entry (`normalTpsl`): the
    /// child's id and the entry's. The venue lists them as orders of their
    /// own and cancels them with the entry.
    children: Vec<(u64, u64)>,
    /// Every order that rested (its venue answer's order), and every order
    /// taken off the book with why: `canceled` by a cancel,
    /// `reduceOnlyCanceled` by the venue when a fill emptied the position.
    rested: Vec<Value>,
    removed: Vec<(u64, String)>,
    /// Orders that filled when placed, as `orderStatus` shows them.
    filled: Vec<Value>,
    /// While set, the venue takes an order action and answers nothing (a
    /// lost answer: the request reached it).
    swallow: bool,
    /// The next this many `orderStatus` reads answer `unknownOid`.
    status_lag: u32,
    /// Marks that differ from the mids, by coin (`activeAssetCtx`'s
    /// `markPx`; a position is valued at the mark).
    marks: HashMap<String, String>,
    /// Answer every order action holding a stop loss with this HTTP status
    /// (a 429, say), taking nothing.
    stop_status: Option<u16>,
    /// The account's non-funding ledger (deposits, withdrawals), oldest
    /// first, each with whether the socket reports it.
    ledger: Vec<(Value, bool)>,
    /// While set, the socket sends no prices (`activeAssetCtx`, `bbo`,
    /// `l2Book`), only snapshots and events.
    ws_prices_paused: bool,
    /// How long an account read (`clearinghouseState` over HTTP) takes.
    read_delay_ms: u64,
    /// How long an `orderStatus` read takes.
    status_delay_ms: u64,
    /// The main dex lists [`MORE_COINS`] too.
    more_coins: bool,
    /// While set, every account answer (HTTP and socket) carries this as
    /// its `time`: the venue's time of the account stuck.
    account_time: Option<i64>,
}

/// Coins the main dex lists after BTC, ETH and SOL when asked to
/// ([`MemoryVenue::add_coins`]): assets 3 to 9.
pub const MORE_COINS: [&str; 7] = ["AVAX", "DOGE", "LINK", "ARB", "OP", "SUI", "APT"];

pub struct MemoryVenue {
    pub api_wallet: Address,
    pub account: Address,
    /// Whether it takes orders (a sending Guard) or only answers reads.
    sends: bool,
    state: Mutex<State>,
}

pub fn meta() -> Value {
    json!({"universe": [
        {"name": "BTC", "szDecimals": 5, "maxLeverage": 40},
        {"name": "ETH", "szDecimals": 4, "maxLeverage": 25},
        {"name": "SOL", "szDecimals": 2, "maxLeverage": 20},
    ]})
}

/// `meta` of a HIP-3 dex, as the venue answers it with `"dex"`.
pub fn dex_meta(dex: &str) -> Value {
    match dex {
        "xyz" => json!({"universe": [
            {"name": "xyz:GOLD", "szDecimals": 4, "maxLeverage": 20, "onlyIsolated": true, "deployerFeeScale": "1.0",
             "marginMode": "noCross"},
            {"name": "xyz:TSLA", "szDecimals": 3, "maxLeverage": 10, "onlyIsolated": true,
             "marginMode": "strictIsolated"},
            {"name": "xyz:URANIUM", "szDecimals": 3, "maxLeverage": 10, "isDelisted": true,
             "onlyIsolated": true, "marginMode": "strictIsolated"},
        ], "marginTables": [], "collateralToken": 0}),
        "abc" => json!({"universe": [
            {"name": "abc:FOO", "szDecimals": 2, "maxLeverage": 10},
        ], "marginTables": [], "collateralToken": 0}),
        _ => json!({"error": "no such dex"}),
    }
}

/// The asset ids of the HIP-3 coins: 100000 + 10000 × dex + index.
pub const GOLD: u32 = 110_000;
pub const TSLA: u32 = 110_001;
pub const URANIUM: u32 = 110_002;
pub const FOO: u32 = 120_000;

/// Whether `coin` belongs to the dex an answer is for (`""`: the main dex).
fn on_dex(coin: &str, dex: &str) -> bool {
    match coin.split_once(':') {
        Some((prefix, _)) => prefix == dex,
        None => dex.is_empty(),
    }
}

impl MemoryVenue {
    pub fn new(api_wallet: Address, account: Address, equity: &str) -> Self {
        Self {
            api_wallet,
            account,
            sends: true,
            state: Mutex::new(State {
                equity: equity.to_owned(),
                mids: json!({"BTC": "60000", "ETH": "3000", "SOL": "150",
                    "xyz:GOLD": "4000", "xyz:TSLA": "400", "xyz:URANIUM": "80", "abc:FOO": "10"}),
                next_oid: 1_000,
                ws_snapshot_after_entry_ms: Some(1_000),
                dex_equity: [
                    ("xyz".to_owned(), "0".to_owned()),
                    ("abc".to_owned(), "0".to_owned()),
                ]
                .into(),
                ..State::default()
            }),
        }
    }

    /// The same venue for a Guard started again over it (a restart): the
    /// account, its positions, its orders and the nonces it saw carry over.
    pub fn fork(&self) -> Self {
        Self {
            api_wallet: self.api_wallet,
            account: self.account,
            sends: self.sends,
            state: Mutex::new(self.state.lock().unwrap().clone()),
        }
    }

    /// Set a HIP-3 dex's account value (all of it withdrawable).
    pub fn set_dex_equity(&self, dex: &str, value: &str) {
        self.state
            .lock()
            .unwrap()
            .dex_equity
            .insert(dex.to_owned(), value.to_owned());
    }

    /// Set the main dex's account value.
    pub fn set_equity(&self, value: &str) {
        self.state.lock().unwrap().equity = value.to_owned();
    }

    /// Put a HIP-3 coin at its open-interest cap.
    pub fn cap(&self, coin: &str) {
        self.state.lock().unwrap().capped.push(coin.to_owned());
    }

    /// Make a dex's `meta` unreadable.
    pub fn break_dex(&self, dex: &str) {
        self.state.lock().unwrap().broken.push(dex.to_owned());
    }

    /// Make a dex's `clearinghouseState` fail (HTTP 500).
    pub fn fail_reads(&self, dex: &str) {
        self.state.lock().unwrap().failing.push(dex.to_owned());
    }

    /// Make a dex's open orders carry a coin of another dex.
    pub fn garble_orders(&self, dex: &str) {
        self.state.lock().unwrap().garbled.push(dex.to_owned());
    }

    pub fn fail_orders(&self) {
        self.state.lock().unwrap().orders_fail = true;
    }

    /// The info requests received so far.
    pub fn info_log(&self) -> Vec<Value> {
        self.state.lock().unwrap().info_log.clone()
    }

    /// The venue as a paper Guard sees it: reads only.
    pub fn read_only(mut self) -> Self {
        self.sends = false;
        self
    }

    pub fn received(&self) -> Vec<Received> {
        self.state.lock().unwrap().received.clone()
    }

    pub fn positions(&self) -> Vec<Value> {
        self.state.lock().unwrap().positions.clone()
    }

    /// Run `hook` on every action received, before acting on it.
    pub fn before_send(&self, hook: impl Fn(&Value) + Send + Sync + 'static) {
        self.state.lock().unwrap().before_send = Hook(Some(std::sync::Arc::new(hook)));
    }

    /// The next `reads` reads of `orderStatus` answer `unknownOid` (the
    /// venue's info trailing its book).
    pub fn lag_order_status(&self, reads: u32) {
        self.state.lock().unwrap().status_lag = reads;
    }

    /// Take order actions but lose every answer (or answer again).
    pub fn swallow_answers(&self, on: bool) {
        self.state.lock().unwrap().swallow = on;
    }

    /// Every order that rested, as the venue lists it.
    pub fn rested(&self) -> Vec<Value> {
        self.state.lock().unwrap().rested.clone()
    }

    /// Every order taken off the book, and why (`canceled`,
    /// `reduceOnlyCanceled`).
    pub fn removed(&self) -> Vec<(u64, String)> {
        self.state.lock().unwrap().removed.clone()
    }

    pub fn orders(&self) -> Vec<Value> {
        self.state.lock().unwrap().orders.clone()
    }

    /// A position opened elsewhere, without a stop: `szi` signed.
    pub fn add_position(&self, coin: &str, szi: &str) {
        self.state
            .lock()
            .unwrap()
            .positions
            .push(json!({"type": "oneWay", "position": {
                "coin": coin, "szi": szi, "entryPx": "3000",
                "leverage": {"type": "isolated", "value": 5}, "liquidationPx": null,
            }}));
    }

    /// The account approves (or withdraws, with 0) a builder fee of at
    /// most `max_tenths_bp`.
    pub fn approve_builder(&self, max_tenths_bp: u64) {
        self.state.lock().unwrap().builder_approval = max_tenths_bp;
    }

    pub fn builder_checks(&self) -> u32 {
        self.state.lock().unwrap().builder_checks
    }

    pub fn refuse_stops(&self) {
        self.state.lock().unwrap().refuse_stops = true;
    }

    fn coin(asset: u64) -> &'static str {
        match asset {
            0..=2 => ["BTC", "ETH", "SOL"][asset as usize],
            3..=9 => MORE_COINS[asset as usize - 3],
            110_000..=110_002 => ["xyz:GOLD", "xyz:TSLA", "xyz:URANIUM"][asset as usize - 110_000],
            120_000 => "abc:FOO",
            _ => panic!("the in-memory venue lists no asset {asset}"),
        }
    }

    fn apply(&self, state: &mut State, action: &Action) -> Value {
        match action {
            Action::Order(order) => {
                let mut statuses = Vec::new();
                for placed in &order.orders {
                    state.next_oid += 1;
                    let oid = state.next_oid;
                    let coin = Self::coin(u64::from(placed.asset));
                    let mid: Decimal = state.mids[coin].as_str().unwrap().parse().unwrap();
                    let price = placed.price.value();
                    let marketable = if placed.is_buy {
                        price >= mid
                    } else {
                        price <= mid
                    };
                    match &placed.kind {
                        OrderKind::Limit { .. } if marketable => {
                            let signed = if placed.is_buy {
                                placed.size.value()
                            } else {
                                -placed.size.value()
                            };
                            // One position per coin: a fill adds to it,
                            // a reduce-only fill takes from it.
                            let held = state
                                .positions
                                .iter()
                                .position(|p| p["position"]["coin"] == coin);
                            let before: Decimal = held.map_or(Decimal::ZERO, |index| {
                                state.positions[index]["position"]["szi"]
                                    .as_str()
                                    .unwrap()
                                    .parse()
                                    .unwrap()
                            });
                            // Reduce-only never opens or flips: clipped to
                            // what is held, as the venue does.
                            let signed = if placed.reduce_only {
                                let opposite =
                                    before.is_sign_positive() != signed.is_sign_positive();
                                if before.is_zero() || !opposite {
                                    Decimal::ZERO
                                } else {
                                    let size = signed.abs().min(before.abs());
                                    if signed.is_sign_negative() {
                                        -size
                                    } else {
                                        size
                                    }
                                }
                            } else {
                                signed
                            };
                            let after = before + signed;
                            if let Some(index) = held {
                                state.positions.remove(index);
                            }
                            // A position emptied: the venue cancels the
                            // reduce-only orders resting on its coin, in
                            // the fill's batch.
                            if after.is_zero() && !before.is_zero() {
                                let now = zunder_guard::guard::SystemClock.now_ms();
                                let gone: Vec<Value> = state
                                    .orders
                                    .iter()
                                    .filter(|order| {
                                        order["coin"] == coin && order["reduceOnly"] == true
                                    })
                                    .cloned()
                                    .collect();
                                state.orders.retain(|order| {
                                    !(order["coin"] == coin && order["reduceOnly"] == true)
                                });
                                for order in gone {
                                    if let Some(oid) = order["oid"].as_u64() {
                                        state.removed.push((oid, "reduceOnlyCanceled".into()));
                                    }
                                    state.ws_events.push(json!({"channel": "orderUpdates", "data": [{
                                        "order": {"coin": coin, "oid": order["oid"], "cloid": order["cloid"],
                                            "side": order["side"], "limitPx": order["limitPx"], "sz": order["sz"]},
                                        "status": "reduceOnlyCanceled", "statusTimestamp": now}]}));
                                }
                            }
                            if after != Decimal::ZERO {
                                state.positions.push(json!({"type": "oneWay", "position": {
                                    "coin": coin, "szi": after.to_string(), "entryPx": price.to_string(),
                                    "leverage": {"type": "isolated", "value": 5}, "liquidationPx": null,
                                }}));
                            }
                            state.filled.push(json!({
                                "coin": coin, "side": if placed.is_buy { "B" } else { "A" },
                                "limitPx": placed.price.raw(), "sz": "0", "origSz": placed.size.raw(),
                                "oid": oid, "isTrigger": false, "triggerPx": "0.0",
                                "reduceOnly": placed.reduce_only,
                                "cloid": placed.cloid.as_ref().map(|cloid| cloid.as_str().to_owned()),
                                "timestamp": zunder_guard::guard::SystemClock.now_ms(),
                            }));
                            let mut filled = json!({
                                "totalSz": placed.size.raw(), "avgPx": placed.price.raw(), "oid": oid,
                            });
                            if let Some(cloid) = &placed.cloid {
                                filled["cloid"] = json!(cloid.as_str());
                            }
                            statuses.push(json!({"filled": filled}));
                        }
                        OrderKind::Trigger {
                            tpsl: zunder_guard_core::action::Tpsl::Sl,
                            ..
                        } if state.refuse_stops => {
                            statuses.push(json!({"error": "Order could not be placed (test)."}));
                        }
                        kind => {
                            let trigger = match kind {
                                OrderKind::Trigger {
                                    trigger_px, tpsl, ..
                                } => Some((trigger_px.raw().to_owned(), *tpsl)),
                                OrderKind::Limit { .. } => None,
                            };
                            let is_market = matches!(
                                kind,
                                OrderKind::Trigger {
                                    is_market: true,
                                    ..
                                }
                            );
                            state.orders.push(json!({
                                "coin": coin, "side": if placed.is_buy { "B" } else { "A" },
                                "limitPx": placed.price.raw(), "sz": placed.size.raw(), "oid": oid,
                                "isTrigger": trigger.is_some(),
                                "triggerPx": trigger.as_ref().map_or("0.0".to_owned(), |(px, _)| px.clone()),
                                "orderType": match (trigger.map(|(_, tpsl)| tpsl), is_market) {
                                    (Some(zunder_guard_core::action::Tpsl::Sl), true) => "Stop Market",
                                    (Some(zunder_guard_core::action::Tpsl::Sl), false) => "Stop Limit",
                                    (Some(zunder_guard_core::action::Tpsl::Tp), true) => "Take Profit Market",
                                    (Some(zunder_guard_core::action::Tpsl::Tp), false) => "Take Profit Limit",
                                    (None, _) => "Limit",
                                },
                                "reduceOnly": placed.reduce_only, "isPositionTpsl": false,
                                "cloid": placed.cloid.as_ref().map(|cloid| cloid.as_str().to_owned()),
                                "children": [],
                                "origSz": placed.size.raw(),
                                "timestamp": zunder_guard::guard::SystemClock.now_ms(),
                            }));
                            if let Some(order) = state.orders.last().cloned() {
                                state.rested.push(order);
                            }
                            // The venue echoes a client id in its answer.
                            let mut resting = json!({"oid": oid});
                            if let Some(cloid) = &placed.cloid {
                                resting["cloid"] = json!(cloid.as_str());
                            }
                            statuses.push(json!({"resting": resting}));
                        }
                    }
                }
                if order.grouping == zunder_guard_core::action::Grouping::NormalTpsl
                    && let Some(parent) = statuses
                        .first()
                        .and_then(|status| status.pointer("/resting/oid"))
                        .and_then(Value::as_u64)
                {
                    for status in statuses.iter().skip(1) {
                        if let Some(child) = status.pointer("/resting/oid").and_then(Value::as_u64)
                        {
                            state.children.push((child, parent));
                        }
                    }
                }
                json!({"status": "ok", "response": {"type": "order", "data": {"statuses": statuses}}})
            }
            Action::Cancel(cancels) | Action::CancelByCloid(cancels) => {
                let statuses: Vec<Value> = cancels
                    .iter()
                    .map(|cancel| {
                        let oid = match &cancel.order {
                            zunder_guard_core::action::OrderRef::Oid(oid) => *oid,
                            zunder_guard_core::action::OrderRef::Cloid(cloid) => {
                                let wanted = cloid.normalized();
                                state
                                    .orders
                                    .iter()
                                    .find(|order| {
                                        order["cloid"].as_str().map(str::to_ascii_lowercase)
                                            == Some(wanted.clone())
                                    })
                                    .and_then(|order| order["oid"].as_u64())
                                    .unwrap_or(0)
                            }
                        };
                        let before = state.orders.len();
                        state
                            .orders
                            .retain(|order| order["oid"].as_u64() != Some(oid));
                        if state.orders.len() < before {
                            state.removed.push((oid, "canceled".into()));
                            // Its waiting children go with it, reported in
                            // the same batch with their client ids.
                            let now = zunder_guard::guard::SystemClock.now_ms();
                            let children: Vec<u64> = state
                                .children
                                .iter()
                                .filter(|(_, parent)| *parent == oid)
                                .map(|(child, _)| *child)
                                .collect();
                            let gone: Vec<Value> = state
                                .orders
                                .iter()
                                .filter(|order| order["oid"].as_u64().is_some_and(|o| children.contains(&o)))
                                .cloned()
                                .collect();
                            state
                                .orders
                                .retain(|order| !order["oid"].as_u64().is_some_and(|o| children.contains(&o)));
                            for order in gone {
                                if let Some(child) = order["oid"].as_u64() {
                                    state.removed.push((child, "canceled".into()));
                                }
                                state.ws_events.push(json!({"channel": "orderUpdates", "data": [{
                                    "order": {"coin": order["coin"], "oid": order["oid"], "cloid": order["cloid"],
                                        "side": order["side"], "limitPx": order["limitPx"], "sz": order["sz"]},
                                    "status": "canceled", "statusTimestamp": now}]}));
                            }
                            json!("success")
                        } else {
                            json!({"error": "Order was never placed, already canceled, or filled."})
                        }
                    })
                    .collect();
                json!({"status": "ok", "response": {"type": "cancel", "data": {"statuses": statuses}}})
            }
            // As the venue does for a trigger (testnet, 6 Oct 2026): the
            // old oid is cancelled and the order rests again under a new
            // oid with the same client id, at the new trigger and limit.
            Action::Modify(modify) => {
                let found = state.orders.iter().position(|order| match &modify.oid {
                    zunder_guard_core::action::OrderRef::Oid(oid) => {
                        order["oid"].as_u64() == Some(*oid)
                    }
                    zunder_guard_core::action::OrderRef::Cloid(cloid) => {
                        order["cloid"].as_str().map(str::to_ascii_lowercase)
                            == Some(cloid.normalized())
                    }
                });
                let Some(index) = found else {
                    return json!({"status": "err", "response": "Cannot modify canceled or filled order"});
                };
                state.next_oid += 1;
                let oid = state.next_oid;
                let order = &mut state.orders[index];
                order["oid"] = json!(oid);
                order["limitPx"] = json!(modify.order.price.raw());
                order["sz"] = json!(modify.order.size.raw());
                if let OrderKind::Trigger { trigger_px, .. } = &modify.order.kind {
                    order["triggerPx"] = json!(trigger_px.raw());
                }
                json!({"status": "ok", "response": {"type": "default"}})
            }
            Action::UpdateLeverage {
                asset, leverage, ..
            } => {
                let coin = Self::coin(u64::from(*asset)).to_owned();
                state.leverage.retain(|(c, _)| *c != coin);
                state.leverage.push((coin, u64::from(*leverage)));
                json!({"status": "ok", "response": {"type": "default"}})
            }
            _ => json!({"status": "ok", "response": {"type": "default"}}),
        }
    }
}

impl Upstream for MemoryVenue {
    async fn info(&self, body: &Value) -> Result<Value, UpstreamError> {
        let delay = {
            let state = self.state.lock().unwrap();
            match body["type"].as_str() {
                Some("clearinghouseState") => state.read_delay_ms,
                Some("userNonFundingLedgerUpdates") => state.ledger_delay_ms,
                Some("userFillsByTime" | "userFunding") => state.flow_records_delay_ms,
                Some("l2Book") => state.book_delay_ms,
                _ => 0,
            }
        };
        if delay > 0 && body.get("_ws").is_none() {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        let delay = self.state.lock().unwrap().status_delay_ms;
        if delay > 0 && body["type"] == "orderStatus" {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        let mut state = self.state.lock().unwrap();
        if body["type"] == "maxBuilderFee" {
            state.builder_checks += 1;
            return Ok(json!(state.builder_approval));
        }
        // The WebSocket below reads the same answers without counting them.
        if body.get("_ws").is_none() {
            state.info_log.push(body.clone());
        }
        // The dex an answer is for: "" (or none) is the main dex.
        let dex = body["dex"].as_str().unwrap_or("");
        if body["type"] == "frontendOpenOrders" && state.orders_fail {
            return Err(UpstreamError::NotSent("orders unavailable".into()));
        }
        if body["type"] == "clearinghouseState" && state.failing.iter().any(|f| f == dex) {
            return Err(UpstreamError::Status {
                status: 500,
                body: "test".into(),
            });
        }
        if body["type"] == "frontendOpenOrders" && state.garbled.iter().any(|g| g == dex) {
            return Ok(json!([{"coin": "ETH", "side": "B", "limitPx": "1", "sz": "1", "oid": 1}]));
        }
        Ok(match body["type"].as_str() {
            Some("perpDexs") => json!([null,
                {"name": "xyz", "fullName": "XYZ", "deployer": "0x88806a71d74ad0a510b350545c9ae490912f0888"},
                {"name": "abc", "fullName": "ABC", "deployer": "0x0000000000000000000000000000000000000abc"}]),
            Some("meta") if state.broken.iter().any(|broken| broken == dex) => {
                json!({"universe": [{"name": "no prefix"}]})
            }
            Some("meta") if !dex.is_empty() => dex_meta(dex),
            Some("meta") if state.more_coins => {
                let mut meta = meta();
                if let Some(universe) = meta["universe"].as_array_mut() {
                    universe.extend(
                        MORE_COINS
                            .iter()
                            .map(|name| json!({"name": name, "szDecimals": 1, "maxLeverage": 10})),
                    );
                }
                meta
            }
            Some("meta") => meta(),
            Some("allMids") => Value::Object(
                state
                    .mids
                    .as_object()
                    .unwrap()
                    .iter()
                    .filter(|(coin, _)| on_dex(coin, dex))
                    .map(|(coin, mid)| (coin.clone(), mid.clone()))
                    .collect(),
            ),
            Some("perpsAtOpenInterestCap") => json!(
                state
                    .capped
                    .iter()
                    .filter(|coin| on_dex(coin, dex))
                    .collect::<Vec<_>>()
            ),
            Some("l2Book") => {
                let coin = body["coin"].as_str().unwrap_or("");
                match state.books.get(coin) {
                    Some(book) => book.clone(),
                    None => {
                        // A deep book: 1,000 a side 10% from the mid, where a
                        // stop 2% away fills (within its 10% slippage).
                        let mid: Decimal = state.mids[coin].as_str().unwrap().parse().unwrap();
                        let bid = (mid * Decimal::new(9, 1)).normalize().to_string();
                        let ask = (mid * Decimal::new(11, 1)).normalize().to_string();
                        json!({"coin": coin, "time": 1, "levels": [
                            [{"px": bid, "sz": "1000", "n": 1}],
                            [{"px": ask, "sz": "1000", "n": 1}]]})
                    }
                }
            }
            Some("userAbstraction") => json!("disabled"),
            // The API wallet is an agent of the account; any other key (a
            // Guard client key) is unknown to the venue.
            Some("userRole")
                if body["user"]
                    .as_str()
                    .is_some_and(|user| user.eq_ignore_ascii_case(&self.api_wallet.to_hex())) =>
            {
                json!({"role": "agent", "data": {"user": self.account.to_hex()}})
            }
            Some("userRole") => json!({"role": "missing"}),
            Some("clearinghouseState") => {
                let equity = if dex.is_empty() {
                    state.equity.clone()
                } else {
                    state.dex_equity.get(dex).cloned().unwrap_or("0".into())
                };
                // Each position valued at its coin's mid (the venue's mark).
                let positions: Vec<Value> = state
                    .positions
                    .iter()
                    .filter(|p| on_dex(p["position"]["coin"].as_str().unwrap_or(""), dex))
                    .map(|p| {
                        let mut p = p.clone();
                        let coin = p["position"]["coin"].as_str().unwrap().to_owned();
                        let szi: Decimal = p["position"]["szi"].as_str().unwrap().parse().unwrap();
                        let entry: Decimal =
                            p["position"]["entryPx"].as_str().unwrap().parse().unwrap();
                        let mid: Decimal =
                            state.mids[coin.as_str()].as_str().unwrap().parse().unwrap();
                        p["position"]["positionValue"] =
                            json!((szi.abs() * mid).normalize().to_string());
                        p["position"]["unrealizedPnl"] =
                            json!((szi * (mid - entry)).normalize().to_string());
                        p
                    })
                    .collect();
                json!({
                    "marginSummary": {"accountValue": equity},
                    "withdrawable": equity,
                    "assetPositions": positions,
                    "time": state
                        .account_time
                        .unwrap_or_else(|| zunder_guard::guard::SystemClock.now_ms() as i64),
                })
            }
            Some("frontendOpenOrders") => Value::Array(
                state
                    .orders
                    .iter()
                    .filter(|order| on_dex(order["coin"].as_str().unwrap_or(""), dex))
                    .cloned()
                    .collect(),
            ),
            Some("userFillsByTime" | "userFunding") if state.flow_records_fails => {
                return Err(UpstreamError::Status {
                    status: 500,
                    body: "test flow records unavailable".into(),
                });
            }
            Some("userFillsByTime" | "userFunding") => json!([]),
            Some("userNonFundingLedgerUpdates") if state.ledger_fails => {
                return Err(UpstreamError::Status {
                    status: 500,
                    body: "test".into(),
                });
            }
            Some("userNonFundingLedgerUpdates") => {
                let from = body["startTime"].as_i64().unwrap_or(0);
                let shown = zunder_guard::guard::SystemClock.now_ms() as i64 - state.ledger_lag_ms;
                Value::Array(
                    state
                        .ledger
                        .iter()
                        .map(|(entry, _)| entry)
                        .filter(|entry| {
                            let time = entry["time"].as_i64().unwrap_or(0);
                            time >= from && time <= shown
                        })
                        .cloned()
                        .collect(),
                )
            }
            Some("orderStatus") if state.status_lag > 0 => {
                // The venue's info trailing its book: not known yet.
                state.status_lag -= 1;
                json!({"status": "unknownOid"})
            }
            Some("orderStatus") => {
                // By venue id or client id: the order and what became of it.
                let wanted = &body["oid"];
                let matches = |order: &&Value| match wanted {
                    Value::String(cloid) => order["cloid"]
                        .as_str()
                        .is_some_and(|id| id.eq_ignore_ascii_case(cloid)),
                    other => order["oid"] == *other,
                };
                let found = state
                    .filled
                    .iter()
                    .find(matches)
                    .map(|order| (order.clone(), "filled".to_owned()))
                    .or_else(|| {
                        state.rested.iter().find(matches).map(|order| {
                            let oid = order["oid"].as_u64();
                            let status =
                                if state.orders.iter().any(|open| open["oid"].as_u64() == oid) {
                                    "open".to_owned()
                                } else {
                                    state
                                        .removed
                                        .iter()
                                        .rev()
                                        .find(|(gone, _)| Some(*gone) == oid)
                                        .map_or("filled".to_owned(), |(_, why)| why.clone())
                                };
                            (order.clone(), status)
                        })
                    });
                match found {
                    Some((order, status)) => json!({"status": "order", "order": {
                        "order": order, "status": status, "statusTimestamp": order["timestamp"]}}),
                    None => json!({"status": "unknownOid"}),
                }
            }
            Some("activeAssetData") => {
                let coin = body["coin"].as_str().unwrap_or("");
                let value = state
                    .leverage
                    .iter()
                    .find(|(c, _)| c == coin)
                    .map_or(20, |(_, value)| *value);
                json!({"leverage": {"type": "isolated", "value": value}})
            }
            _ => json!({"unknown": body}),
        })
    }

    async fn exchange(&self, body: Vec<u8>) -> Result<Value, UpstreamError> {
        if !self.sends {
            return Err(UpstreamError::Paper);
        }
        let request =
            decode_request(&body).map_err(|error| UpstreamError::NotJson(error.to_string()))?;
        // The venue's own check: the signer recovered from the action hash
        // and the testnet phantom agent must be the API wallet.
        let digest = agent_digest(
            SigningNetwork::Testnet,
            &action_hash(
                &request.action.to_wire(),
                request.nonce,
                None,
                request.expires_after,
            )
            .unwrap(),
        );
        let signer = recover_signer(&digest, &request.signature).unwrap_or(Address([0; 20]));
        let mut state = self.state.lock().unwrap();
        if signer != self.api_wallet {
            return Ok(
                json!({"status": "err", "response": format!("User or API Wallet {signer} does not exist.")}),
            );
        }
        if state.nonces.contains(&request.nonce) {
            return Ok(json!({"status": "err", "response": "Nonce already used"}));
        }
        state.nonces.push(request.nonce);
        if let (Some(status), Action::Order(order)) = (state.stop_status, &request.action)
            && order
                .orders
                .iter()
                .any(|order| order.protective_level().is_some())
        {
            return Err(UpstreamError::Status {
                status,
                body: "too many requests (test)".into(),
            });
        }
        let json: Value = serde_json::from_slice(&body).unwrap();
        if let Action::Order(order) = &request.action
            && let Some(builder) = &order.builder
            && builder.fee_tenths_bp > state.builder_approval
        {
            state.received.push(Received {
                action: request.action.clone(),
                json: json["action"].clone(),
                nonce: request.nonce,
                signer,
                expires_after: json["expiresAfter"].as_u64(),
            });
            return Ok(json!({"status": "err", "response": "Builder fee has not been approved."}));
        }
        state.received.push(Received {
            action: request.action.clone(),
            json: json["action"].clone(),
            nonce: request.nonce,
            signer,
            expires_after: json["expiresAfter"].as_u64(),
        });
        state.events += 1;
        if let Some(hook) = &state.before_send.0 {
            hook(&json["action"]);
        }
        let reply = self.apply(&mut state, &request.action);
        // What the venue's socket reports of it: each order it rested or
        // filled (and a fill), each order a cancel took; nothing for a
        // leverage or margin update.
        let now = zunder_guard::guard::SystemClock.now_ms();
        let statuses = reply["response"]["data"]["statuses"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        match &request.action {
            Action::Order(order) => {
                let mut fills = Vec::new();
                let mut updates = Vec::new();
                for (placed, status) in order.orders.iter().zip(&statuses) {
                    let coin = Self::coin(u64::from(placed.asset));
                    let cloid = placed.cloid.as_ref().map(|cloid| cloid.as_str().to_owned());
                    let update = |oid: u64, status: &str| {
                        json!({"order": {"coin": coin, "oid": oid, "cloid": cloid,
                            "side": if placed.is_buy { "B" } else { "A" },
                            "limitPx": placed.price.raw(), "sz": placed.size.raw()},
                            "status": status, "statusTimestamp": now})
                    };
                    if let Some(oid) = status.pointer("/resting/oid").and_then(Value::as_u64) {
                        updates.push(update(oid, "open"));
                    } else if let Some(oid) = status.pointer("/filled/oid").and_then(Value::as_u64)
                    {
                        fills.push(json!({"coin": coin, "oid": oid, "cloid": cloid,
                            "px": placed.price.raw(), "sz": placed.size.raw(), "time": now}));
                        updates.push(update(oid, "open"));
                        updates.push(update(oid, "filled"));
                    }
                }
                // The fills first, then the action's order updates in one
                // batch, as recorded (a venue cancel the fill brought,
                // `reduceOnlyCanceled`, is already queued: same tick).
                if !fills.is_empty() {
                    state
                        .ws_events
                        .push(json!({"channel": "user", "data": {"fills": fills}}));
                }
                if !updates.is_empty() {
                    state
                        .ws_events
                        .push(json!({"channel": "orderUpdates", "data": updates}));
                }
                // A close brings the snapshots with its events; an entry
                // about a second later.
                let closes =
                    order.orders.iter().zip(&statuses).any(|(placed, status)| {
                        placed.reduce_only && status.get("filled").is_some()
                    });
                if closes {
                    state.ws_snapshot_now = true;
                } else if let Some(after) = state.ws_snapshot_after_entry_ms {
                    let due = now + after;
                    state.ws_snapshot_due_ms =
                        Some(state.ws_snapshot_due_ms.map_or(due, |d| d.min(due)));
                }
            }
            Action::Cancel(cancels) => {
                for (cancel, status) in cancels.iter().zip(&statuses) {
                    if let (zunder_guard_core::action::OrderRef::Oid(oid), Some("success")) =
                        (&cancel.order, status.as_str())
                    {
                        state
                            .ws_events
                            .push(json!({"channel": "orderUpdates", "data": [{
                            "order": {"coin": Self::coin(u64::from(cancel.asset)), "oid": oid},
                            "status": "canceled", "statusTimestamp": now}]}));
                        state.ws_snapshot_now = true;
                    }
                }
            }
            _ => {}
        }
        if state.swallow && matches!(request.action, Action::Order(_)) {
            return Err(UpstreamError::NoAnswer("test: the answer was lost".into()));
        }
        Ok(reply)
    }

    fn ws_url(&self) -> Option<String> {
        self.state.lock().unwrap().ws_url.clone()
    }

    fn sends_to(&self) -> Option<SigningNetwork> {
        self.sends.then_some(SigningNetwork::Testnet)
    }
}

impl MemoryVenue {
    /// Make every account read over HTTP take `ms`.
    pub fn slow_reads(&self, ms: u64) {
        self.state.lock().unwrap().read_delay_ms = ms;
    }

    /// Make every `orderStatus` read take `ms`.
    pub fn slow_order_status(&self, ms: u64) {
        self.state.lock().unwrap().status_delay_ms = ms;
    }

    /// The main dex lists [`MORE_COINS`] too, each at 100.
    pub fn add_coins(&self) {
        let mut state = self.state.lock().unwrap();
        state.more_coins = true;
        for coin in MORE_COINS {
            state.mids[coin] = json!("100");
        }
    }

    pub fn slow_flow_reads(&self, ledger_ms: u64, records_ms: u64) {
        let mut state = self.state.lock().unwrap();
        state.ledger_delay_ms = ledger_ms;
        state.flow_records_delay_ms = records_ms;
    }

    pub fn slow_books(&self, ms: u64) {
        self.state.lock().unwrap().book_delay_ms = ms;
    }

    /// Hold the venue's `time` of the account at `at` (epoch ms), or let it
    /// run again (`None`).
    pub fn hold_account_time(&self, at: Option<i64>) {
        self.state.lock().unwrap().account_time = at;
    }

    /// Stop (or resume) every message on the venue's WebSocket.
    pub fn pause_ws(&self, paused: bool) {
        self.state.lock().unwrap().ws_paused = paused;
    }

    /// Stop (or resume) the account's snapshots on the WebSocket (prices
    /// go on).
    pub fn pause_ws_snapshots(&self, paused: bool) {
        self.state.lock().unwrap().ws_snapshots_paused = paused;
    }

    /// A deposit (`usdc` positive) or withdrawal (negative) booked now on
    /// the main dex's perp account, moving its value by that much; on the
    /// socket's `userNonFundingLedgerUpdates` too unless `quiet` (the HTTP
    /// ledger only).
    pub fn flow(&self, usdc: &str, quiet: bool) {
        self.flow_at(
            usdc,
            zunder_guard::guard::SystemClock.now_ms() as i64,
            quiet,
        );
    }

    /// [`MemoryVenue::flow`] booked at `time` (epoch ms) on the ledger.
    pub fn flow_at(&self, usdc: &str, time: i64, quiet: bool) {
        let mut state = self.state.lock().unwrap();
        let amount: Decimal = usdc.parse().unwrap();
        let equity: Decimal = state.equity.parse().unwrap();
        state.equity = (equity + amount).normalize().to_string();
        let n = state.ledger.len();
        let delta = if amount.is_sign_negative() {
            json!({"type": "withdraw", "usdc": (-amount).normalize().to_string(), "nonce": n, "fee": "1"})
        } else {
            json!({"type": "deposit", "usdc": amount.normalize().to_string()})
        };
        state.ledger.push((
            json!({"time": time, "hash": format!("0x{n:064x}"), "delta": delta}),
            !quiet,
        ));
    }

    /// Make the ledger read over HTTP fail (or work again).
    pub fn fail_ledger(&self, fails: bool) {
        self.state.lock().unwrap().ledger_fails = fails;
    }

    pub fn fail_flow_records(&self, fails: bool) {
        self.state.lock().unwrap().flow_records_fails = fails;
    }

    /// Serve the ledger over HTTP `ms` behind the account.
    pub fn lag_ledger(&self, ms: i64) {
        self.state.lock().unwrap().ledger_lag_ms = ms;
    }

    /// Answer order actions with a stop loss by HTTP `status`, taking
    /// nothing.
    pub fn stop_status(&self, status: u16) {
        self.state.lock().unwrap().stop_status = Some(status);
    }

    /// A coin's mark, apart from its mid (on the socket's `activeAssetCtx`).
    pub fn set_mark(&self, coin: &str, mark: &str) {
        self.state
            .lock()
            .unwrap()
            .marks
            .insert(coin.to_owned(), mark.to_owned());
    }

    /// Send the account's snapshots every `ticks` ticks of the socket only.
    /// How long after an entry's events the venue sends the account's
    /// snapshots (`None`: only at the next periodic one). 1 s by default.
    pub fn ws_snapshot_after_entry(&self, ms: Option<u64>) {
        self.state.lock().unwrap().ws_snapshot_after_entry_ms = ms;
    }

    pub fn ws_snapshot_every(&self, ticks: u64) {
        self.state.lock().unwrap().ws_snapshot_every = ticks;
    }

    /// Something happened on the account that Guard did not send (another
    /// app's order): an `orderUpdates` event on the socket.
    pub fn outside_event(&self) {
        let now = zunder_guard::guard::SystemClock.now_ms();
        let mut state = self.state.lock().unwrap();
        state.events += 1;
        state
            .ws_events
            .push(json!({"channel": "orderUpdates", "data": [{
            "order": {"coin": "BTC", "oid": 1, "side": "B", "limitPx": "1", "sz": "1"},
            "status": "open", "statusTimestamp": now}]}));
    }

    /// Stop (or resume) the prices on the WebSocket.
    pub fn pause_ws_prices(&self, paused: bool) {
        self.state.lock().unwrap().ws_prices_paused = paused;
    }

    /// Move a coin's mid (and so its mark, and the value of a position in
    /// it).
    pub fn set_mid(&self, coin: &str, mid: &str) {
        self.state.lock().unwrap().mids[coin] = json!(mid);
    }

    /// A position opened elsewhere at `entry`, isolated at 5x: `szi`
    /// signed.
    pub fn add_position_at(&self, coin: &str, szi: &str, entry: &str) {
        self.state
            .lock()
            .unwrap()
            .positions
            .push(json!({"type": "oneWay", "position": {
                "coin": coin, "szi": szi, "entryPx": entry,
                "leverage": {"type": "isolated", "value": 5}, "liquidationPx": null,
            }}));
    }

    /// Every position gone (a stop that fired, say), with no event.
    pub fn clear_positions(&self) {
        self.state.lock().unwrap().positions.clear();
    }

    /// Take stop losses again after [`MemoryVenue::refuse_stops`].
    pub fn accept_stops(&self) {
        self.state.lock().unwrap().refuse_stops = false;
    }

    /// A resting order, as `frontendOpenOrders` shows it.
    pub fn add_order(&self, order: Value) {
        self.state.lock().unwrap().orders.push(order);
    }

    /// An order resting on the book that `orderStatus` also knows (placed
    /// elsewhere).
    pub fn add_resting_order(&self, order: Value) {
        let mut state = self.state.lock().unwrap();
        state.orders.push(order.clone());
        state.rested.push(order);
    }

    /// The resting limit order `oid` fills in full at its limit (the market
    /// came to it), opening or adding to the position. Its waiting children
    /// (`normalTpsl` stops) become active, or with `refuse_children` the
    /// venue refuses to activate them and they are gone (the case of a
    /// builder-fee approval withdrawn before the fill, if the venue refused
    /// those).
    pub fn fill_resting(&self, oid: u64, refuse_children: bool) {
        self.fill_resting_part(oid, None, refuse_children);
    }

    /// [`MemoryVenue::fill_resting`] for `part` of the order only (the rest
    /// keeps resting), or all of it with `None`.
    pub fn fill_resting_part(&self, oid: u64, part: Option<&str>, refuse_children: bool) {
        let mut state = self.state.lock().unwrap();
        let Some(index) = state
            .orders
            .iter()
            .position(|order| order["oid"].as_u64() == Some(oid))
        else {
            panic!("order {oid} does not rest")
        };
        let order = state.orders[index].clone();
        let coin = order["coin"].as_str().unwrap().to_owned();
        let whole: Decimal = order["sz"].as_str().unwrap().parse().unwrap();
        let size: Decimal = part.map_or(whole, |part| part.parse().unwrap());
        if size >= whole {
            state.orders.remove(index);
        } else {
            state.orders[index]["sz"] = json!((whole - size).to_string());
        }
        let price = order["limitPx"].as_str().unwrap().to_owned();
        let signed = if order["side"] == "B" { size } else { -size };
        let held = state
            .positions
            .iter()
            .position(|p| p["position"]["coin"] == coin.as_str());
        let before: Decimal = held.map_or(Decimal::ZERO, |index| {
            state.positions[index]["position"]["szi"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap()
        });
        if let Some(index) = held {
            state.positions.remove(index);
        }
        state.positions.push(json!({"type": "oneWay", "position": {
            "coin": coin, "szi": (before + signed).to_string(), "entryPx": price,
            "leverage": {"type": "isolated", "value": 5}, "liquidationPx": null,
        }}));
        if size >= whole {
            state.removed.push((oid, "filled".into()));
        }
        let children: Vec<u64> = state
            .children
            .iter()
            .filter(|(_, parent)| *parent == oid)
            .map(|(child, _)| *child)
            .collect();
        state.children.retain(|(_, parent)| *parent != oid);
        if refuse_children {
            state
                .orders
                .retain(|order| !order["oid"].as_u64().is_some_and(|o| children.contains(&o)));
            for child in children {
                state.removed.push((child, "rejected".into()));
            }
        }
    }

    /// The resting order `oid` is gone without a fill: the venue refused
    /// it when it fired (the case of a stop placed with the builder field
    /// after the approval was withdrawn, if the venue refused those).
    pub fn drop_order(&self, oid: u64) {
        let mut state = self.state.lock().unwrap();
        state
            .orders
            .retain(|order| order["oid"].as_u64() != Some(oid));
        state.removed.push((oid, "rejected".into()));
    }
}

/// Serve the in-memory venue's WebSocket for `guard`: every `period_ms`, a
/// snapshot of every subscribed `clearinghouseState`, `openOrders` and
/// `allMids` (with their `dex`), the `activeAssetCtx`, `activeAssetData`, `bbo` and `l2Book` of every coin
/// subscribed, and an `orderUpdates` event for each order action the venue
/// took since. Confirms every subscription and unsubscription, answers
/// `ping`. The returned task serves every connection; aborting it closes
/// them.
pub async fn serve_ws(
    guard: std::sync::Arc<zunder_guard::guard::Guard<MemoryVenue>>,
    period_ms: u64,
) -> tokio::task::JoinHandle<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    guard.upstream().state.lock().unwrap().ws_url = Some(url);
    tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let guard = guard.clone();
            connections.spawn(async move {
                let Ok(socket) = tokio_tungstenite::accept_async(socket).await else {
                    return;
                };
                let (mut sink, mut source) = socket.split();
                let mut subscriptions: Vec<Value> = Vec::new();
                let mut tick = tokio::time::interval(std::time::Duration::from_millis(period_ms));
                let mut ticks: u64 = 0;
                let mut next_periodic: u64 = 0;
                let mut ledger_sent = guard.upstream().state.lock().unwrap().ledger.len();
                let user = guard.upstream().account.to_hex();
                loop {
                    tokio::select! {
                        message = source.next() => {
                            let Some(Ok(Message::Text(text))) = message else { return };
                            let value: Value = serde_json::from_str(text.as_str()).unwrap();
                            match value["method"].as_str() {
                                Some("subscribe") => {
                                    subscriptions.push(value["subscription"].clone());
                                    let reply = json!({"channel": "subscriptionResponse", "data": value});
                                    if sink.send(Message::text(reply.to_string())).await.is_err() { return; }
                                }
                                Some("unsubscribe") => {
                                    subscriptions.retain(|s| *s != value["subscription"]);
                                    let reply = json!({"channel": "subscriptionResponse", "data": value});
                                    if sink.send(Message::text(reply.to_string())).await.is_err() { return; }
                                }
                                Some("ping") => {
                                    let pong = sink.send(Message::text(json!({"channel": "pong"}).to_string())).await;
                                    if pong.is_err() { return; }
                                }
                                _ => {}
                            }
                        }
                        _ = tick.tick() => {
                            if guard.upstream().state.lock().unwrap().ws_paused {
                                continue;
                            }
                            let venue = guard.upstream();
                            let mut out = Vec::new();
                            ticks += 1;
                            // Events first, then the account's snapshots:
                            // periodic, with a cancel's or a close's events
                            // in the same tick, an entry's about a second
                            // later (the periodic ones count on from each).
                            let now = zunder_guard::guard::SystemClock.now_ms();
                            let events = std::mem::take(&mut venue.state.lock().unwrap().ws_events);
                            let (snapshots, prices_paused) = {
                                let mut state = venue.state.lock().unwrap();
                                let every = state.ws_snapshot_every.max(1);
                                let due = ticks >= next_periodic
                                    || state.ws_snapshot_now
                                    || state.ws_snapshot_due_ms.is_some_and(|due| now >= due);
                                let snapshots = !state.ws_snapshots_paused && due;
                                if snapshots {
                                    state.ws_snapshot_now = false;
                                    state.ws_snapshot_due_ms = None;
                                    next_periodic = ticks + every;
                                }
                                (snapshots, state.ws_prices_paused)
                            };
                            out.extend(events);
                            // New ledger entries the socket reports.
                            let fresh: Vec<Value> = {
                                let state = venue.state.lock().unwrap();
                                let fresh = state.ledger[ledger_sent..]
                                    .iter()
                                    .filter(|(_, on_socket)| *on_socket)
                                    .map(|(entry, _)| entry.clone())
                                    .collect();
                                ledger_sent = state.ledger.len();
                                fresh
                            };
                            let ledger_subscribed = subscriptions
                                .iter()
                                .any(|sub| sub["type"] == "userNonFundingLedgerUpdates");
                            if !fresh.is_empty() && ledger_subscribed {
                                out.push(json!({"channel": "userNonFundingLedgerUpdates",
                                    "data": {"user": user, "nonFundingLedgerUpdates": fresh}}));
                            }
                            for sub in &subscriptions {
                                let dex = sub["dex"].as_str().unwrap_or("");
                                let ask = |kind: &str| json!({"type": kind, "user": user, "dex": dex, "_ws": true});
                                let kind = sub["type"].as_str();
                                // `activeAssetData` comes with the snapshots, as the venue's
                                // (every 5 s when the account's figures do not move).
                                let snapshot = matches!(
                                    kind,
                                    Some("clearinghouseState" | "openOrders" | "allMids" | "activeAssetData")
                                );
                                if (snapshot && !snapshots) || (!snapshot && prices_paused) {
                                    continue;
                                }
                                match kind {
                                    // The open orders first, then the
                                    // account, as recorded.
                                    Some("clearinghouseState") => {
                                        let orders_subscribed = subscriptions.iter().any(|other| {
                                            other["type"] == "openOrders" && other["dex"].as_str().unwrap_or("") == dex
                                        });
                                        if orders_subscribed {
                                            let orders = venue.info(&ask("frontendOpenOrders")).await.unwrap();
                                            out.push(json!({"channel": "openOrders", "data": {"dex": dex, "user": user, "orders": orders}}));
                                        }
                                        let mut state = venue.info(&ask("clearinghouseState")).await.unwrap();
                                        let held = venue.state.lock().unwrap().account_time;
                                        state["time"] = json!(held.unwrap_or(now as i64));
                                        out.push(json!({"channel": "clearinghouseState", "data": {"dex": dex, "user": user, "clearinghouseState": state}}));
                                    }
                                    Some("openOrders") => {
                                        let state_subscribed = subscriptions.iter().any(|other| {
                                            other["type"] == "clearinghouseState" && other["dex"].as_str().unwrap_or("") == dex
                                        });
                                        if !state_subscribed {
                                            let orders = venue.info(&ask("frontendOpenOrders")).await.unwrap();
                                            out.push(json!({"channel": "openOrders", "data": {"dex": dex, "user": user, "orders": orders}}));
                                        }
                                    }
                                    Some("allMids") => {
                                        let mids = venue.info(&json!({"type": "allMids", "dex": dex, "_ws": true})).await.unwrap();
                                        out.push(json!({"channel": "allMids", "data": {"dex": dex, "mids": mids}}));
                                    }
                                    Some("bbo") => {
                                        let coin = sub["coin"].as_str().unwrap();
                                        let mid: Decimal = venue.state.lock().unwrap().mids[coin].as_str().unwrap().parse().unwrap();
                                        let bid = (mid * Decimal::new(9999, 4)).normalize().to_string();
                                        let ask = (mid * Decimal::new(10001, 4)).normalize().to_string();
                                        out.push(json!({"channel": "bbo", "data": {"coin": coin, "time": now,
                                            "bbo": [{"px": bid, "sz": "1", "n": 1}, {"px": ask, "sz": "1", "n": 1}]}}));
                                    }
                                    Some("l2Book") => {
                                        let mut book = venue.info(&json!({"type": "l2Book", "coin": sub["coin"], "nSigFigs": sub["nSigFigs"], "_ws": true})).await.unwrap();
                                        // The fast book has 5 levels a side, as the venue's.
                                        if sub["fast"] == true {
                                            for side in book["levels"].as_array_mut().into_iter().flatten() {
                                                if let Some(levels) = side.as_array_mut() {
                                                    levels.truncate(5);
                                                }
                                            }
                                        }
                                        out.push(json!({"channel": "l2Book", "data": book}));
                                    }
                                    Some("activeAssetData") => {
                                        let coin = sub["coin"].as_str().unwrap();
                                        let data = venue.info(&json!({"type": "activeAssetData", "user": user, "coin": coin, "_ws": true})).await.unwrap();
                                        out.push(json!({"channel": "activeAssetData", "data": {"user": user, "coin": coin,
                                            "leverage": data["leverage"]}}));
                                    }
                                    Some("activeAssetCtx") => {
                                        let coin = sub["coin"].as_str().unwrap();
                                        let (mid, mark) = {
                                            let state = venue.state.lock().unwrap();
                                            let mid = state.mids[coin].clone();
                                            let mark = state.marks.get(coin).map_or(mid.clone(), |mark| json!(mark));
                                            (mid, mark)
                                        };
                                        out.push(json!({"channel": "activeAssetCtx", "data": {"coin": coin,
                                            "ctx": {"markPx": mark, "midPx": mid, "oraclePx": mark}}}));
                                    }
                                    _ => {}
                                }
                            }
                            for message in out {
                                if sink.send(Message::text(message.to_string())).await.is_err() { return; }
                            }
                        }
                    }
                }
            });
        }
    })
}
