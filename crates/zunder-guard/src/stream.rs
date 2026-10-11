// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The account as the venue's WebSocket streams it, so that a request can
//! usually be judged without reading the account over HTTP first (one
//! round trip to Hyperliquid, about 240 ms from Frankfurt at the median).
//!
//! What Hyperliquid streams (measured on mainnet and testnet, 6 Oct 2026;
//! its documentation, "WebSocket", "Subscriptions"):
//!
//! - `clearinghouseState` and `openOrders`, each with `user` and `dex`: the
//!   same answers as the `info` requests of those names (`openOrders` in
//!   `frontendOpenOrders`' shape, triggers and children included), sent
//!   whole about every 5 s, changed or not, computed about 0.5 to 0.8 s
//!   before they arrive. `clearinghouseState` carries the venue's `time`.
//! - `allMids` with `dex`: every mid of a dex, about every 5 s.
//! - `activeAssetCtx` per coin: its mark (`markPx`) and mid (`midPx`),
//!   about every second (gaps of 1.02 s at the median, 1.45 s at most),
//!   changed or not.
//! - `activeAssetData` per user and coin: the account's leverage setting
//!   of the coin (`{type, value}`), every 5 s (4.99 to 5.07 s apart,
//!   measured on mainnet and testnet), more often while the account's
//!   figures in it move (about every second on an account holding
//!   positions, measured on testnet).
//! - `bbo` per coin: the best bid and ask, with the venue's `time`, at each
//!   block in which they change (every 0.1 s on BTC; nothing for 12 s on a
//!   quiet HIP-3 coin).
//! - `l2Book` per coin: the book about every 5.4 s; with `"fast": true`
//!   (echoed in the venue's answer, not in its documentation) about every
//!   0.54 s but 5 levels a side. Guard follows no book: a HIP-3 entry's
//!   book (20 levels) is read over HTTP for it.
//! - `orderUpdates`, `userEvents` (channel `user`: fills, funding,
//!   liquidations, cancels by the venue) and `userNonFundingLedgerUpdates`
//!   (transfers, deposits, withdrawals), each with `user`: events, as they
//!   happen, 0.2 to 0.9 s after the venue's time.
//! - Every subscription is answered by a `subscriptionResponse` echoing it
//!   (an unsubscription too, after which nothing more of it arrives). An
//!   unknown coin, a malformed or a repeated subscription is answered by an
//!   `error` (`Invalid subscription`, `Already subscribed`); an unknown dex
//!   by nothing at all.
//! - The venue's times run behind the wall clock by 0.45 to 1.1 s on
//!   `clearinghouseState` and 0.3 to 0.4 s on `bbo`.
//!
//! The snapshots lag the account by up to their period plus their delay.
//! Between two of them only the events say that the account changed, and
//! nothing says that prices moved. So a view built from the stream is used
//! for a judgement only when it is **clean** ([`StreamState::answers`]):
//!
//! - the socket is up, no `error` arrived on it, and every subscription the
//!   view needs was confirmed by the venue;
//! - every snapshot of every dex arrived within [`SNAPSHOT_MAX_AGE_MS`], and
//!   each `clearinghouseState` is no older than that by the venue's own
//!   clock (its `time` against the newest venue time seen on the socket);
//! - the venue's time on the socket's timed messages (`clearinghouseState`,
//!   `bbo`) was within [`MAX_VENUE_LAG_MS`] of the wall clock when they
//!   arrived: a server that lags the chain is not used;
//! - every snapshot arrived at least [`EVENT_MARGIN_MS`] after the last
//!   event of the account and after Guard last heard back from the venue on
//!   something it sent, and its `time` is not before the last event's: what
//!   changed has reached it;
//! - no `clearinghouseState` went back in time since the socket connected;
//! - every coin with a position or an open order, and the coin being
//!   judged, has a mark and a mid that arrived within [`PRICE_MAX_AGE_MS`]
//!   and a mid within [`MAX_MID_DRIFT`] of its dex's last `allMids`.
//!
//! The snapshot's positions are then **revalued** at those marks
//! ([`zunder_guard_core::account::revalue_clearinghouse`]): the equity the
//! judge and the risk engine see is the venue's formula at marks at most
//! [`PRICE_MAX_AGE_MS`] old, not the snapshot's, and the mids of those
//! coins are the fresh ones. Otherwise Guard reads the account over HTTP,
//! as it always did. Ages are measured on a monotonic clock
//! ([`monotonic_ms`]).

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
    time::Instant,
};

use rust_decimal::Decimal;
use serde_json::{Value, json};
use zunder_guard_core::{
    account::{Leverage, revalue_clearinghouse},
    sign::Address,
};

/// The oldest a snapshot may be for the view to be clean, by its arrival
/// and by the venue's clock: they come every 5 s (5.15 s apart at most,
/// measured), computed up to 0.8 s before.
pub const SNAPSHOT_MAX_AGE_MS: u64 = 6_000;
/// The oldest a coin's mark or mid may be: `activeAssetCtx` comes every
/// second (1.45 s apart at most, measured).
pub const PRICE_MAX_AGE_MS: u64 = 1_500;
/// The most the venue's time on a timed message may trail the wall clock
/// when it arrives (measured: 1.1 s at most).
pub const MAX_VENUE_LAG_MS: i64 = 3_000;
/// How long after an event of the account (or Guard's own send) a snapshot
/// must have arrived to count: one sent just before the event may arrive
/// just after it.
pub const EVENT_MARGIN_MS: u64 = 1_000;
/// Reconnect when nothing at all arrived for this long.
pub const SILENCE_MS: u64 = 10_000;
/// Most ledger entries kept for Guard between two of its takes.
const MAX_LEDGER: usize = 1_000;
/// Most coins the stream follows; beyond it the oldest no position or
/// order needs is dropped (coins with positions or orders never are).
pub const MAX_COINS: usize = 32;
/// The most a coin's fresh mid may differ from its dex's last `allMids`
/// (a fraction, 5%) before the stream's prices are not trusted: a bigger
/// move within a snapshot's period is read over HTTP.
pub const MAX_MID_DRIFT: Decimal = Decimal::from_parts(5, 0, 0, false, 2);

/// Milliseconds on a monotonic clock, from the first call in this process:
/// for ages, which a wall clock stepping back would shorten.
pub fn monotonic_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// One dex's latest snapshots, each with when it arrived.
#[derive(Debug, Clone, Default)]
struct DexStream {
    /// `(clearinghouseState, arrived, venue time, how far the venue time
    /// trailed the wall clock when it arrived)`.
    state: Option<(Value, u64, i64, Option<i64>)>,
    orders: Option<(Value, u64)>,
    mids: Option<(Value, u64)>,
    /// The socket's sequence numbers of the last `clearinghouseState` and
    /// `openOrders`: what arrived after an event, in the socket's order.
    state_seq: u64,
    orders_seq: u64,
    /// The dex's `clearinghouseState` and `openOrders` counted together,
    /// and the count at the last of each: the venue sends them one after
    /// the other, so the two latest belong together when they are next to
    /// each other in that count.
    snapshots: u64,
    state_n: u64,
    orders_n: u64,
}

/// An event of an order (an `orderUpdates` entry or a fill): its place on
/// the socket, when it arrived, the venue's time, the order and what
/// happened to it (`open`, `filled`, `canceled`, ..., `fill` for a fill).
#[derive(Debug, Clone)]
struct OrderEvent {
    seq: u64,
    at: u64,
    time: Option<i64>,
    oid: Option<u64>,
    cloid: Option<String>,
    status: String,
}

/// What one of Guard's own sends should bring on the socket, from the
/// venue's answer ([`StreamState::expect`]): the orders it rests or fills
/// and the orders it cancels. While every one of them has reported, and a
/// snapshot of its dex came after those reports and is no older by the
/// venue's clock, the view is clean again without waiting the
/// [`EVENT_MARGIN_MS`] and the next periodic snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    /// When Guard heard back ([`monotonic_ms`]), as it passes to
    /// [`StreamState::answers`] as the last send.
    pub sent: u64,
    /// The dex of the orders (`""` for the main dex).
    pub dex: String,
    /// Orders the answer says rest: an `open` each.
    pub resting: Vec<u64>,
    /// Orders the answer says filled: `open`, `filled` and fills.
    pub filled: Vec<u64>,
    /// Orders cancelled (and their waiting children): `canceled` each.
    pub cancelled: Vec<u64>,
    /// Client ids of stops attached to a cancelled entry (the venue lists
    /// them as orders of their own, not as its children): `canceled` each.
    pub cancelled_cloids: Vec<String>,
    /// The client ids of the orders sent (an attached stop's among them):
    /// `open` each, when the venue reports it.
    pub cloids: Vec<String>,
    /// Reduce-only orders resting on a coin the send filled on, which the
    /// venue cancels (`reduceOnlyCanceled`, in the fill's batch) when the
    /// fill empties the position: Guard's own, when they come; not
    /// awaited, since the position may not be empty.
    pub reduce_only: Vec<u64>,
}

/// How far before Guard heard back an event of its own send may arrive
/// (the socket can be faster than the answer), and how long after.
const OWN_EVENT_BEFORE_MS: u64 = 5_000;
const OWN_EVENT_AFTER_MS: u64 = 5_000;
/// How long order events and Guard's sends are kept.
const EVENTS_KEPT_MS: u64 = 30_000;

/// One of Guard's sends: when Guard heard back ([`monotonic_ms`]), and what
/// the socket should report of it, when Guard knows (`None` for a send
/// whose outcome is unknown, or one that raises no event: a leverage or
/// margin update, a modify).
#[derive(Debug, Clone)]
struct SendRecord {
    sent: u64,
    expectation: Option<Expectation>,
}

/// What the socket reported of one of Guard's sends: the newest venue time
/// and socket position of its events, and the dexes whose snapshots must
/// come after them.
struct Reported {
    time: i64,
    seq: u64,
    dexes: Vec<String>,
}

/// A coin the stream follows.
#[derive(Debug, Clone, Default)]
struct CoinStream {
    /// `activeAssetCtx`: `(markPx, arrived)` and `(midPx, arrived)`, the mid
    /// `None` when the book has no mid.
    mark: Option<(Decimal, u64)>,
    ctx_mid: Option<(Option<Decimal>, u64)>,
    /// The last `bbo`: its mid (`None` with a side empty), when it arrived,
    /// and the venue's time.
    bbo: Option<(Option<Decimal>, u64, i64)>,
    /// The account's leverage setting of the coin (`activeAssetData`), and
    /// when it arrived.
    leverage: Option<(Leverage, u64)>,
}

impl CoinStream {
    /// The newest mid of `activeAssetCtx` and `bbo`, and when it arrived.
    fn mid(&self) -> Option<(Option<Decimal>, u64)> {
        let from_bbo = self.bbo.map(|(mid, at, _)| (mid, at));
        match (self.ctx_mid, from_bbo) {
            (Some(ctx), Some(bbo)) => Some(if bbo.1 >= ctx.1 { bbo } else { ctx }),
            (one, other) => one.or(other),
        }
    }
}

/// What the stream knows, fed by [`StreamState::apply`].
#[derive(Debug, Clone)]
pub struct StreamState {
    user: Address,
    /// The dexes followed, by name (`""` for the main dex).
    dexes: BTreeMap<String, DexStream>,
    coins: BTreeMap<String, CoinStream>,
    /// Coins in the order they were last asked for, oldest first.
    coin_order: Vec<String>,
    connected: bool,
    /// The subscriptions asked for on this socket, and those the venue
    /// confirmed, by [`key`].
    asked: BTreeSet<String>,
    confirmed: BTreeSet<String>,
    /// The last event of the account that names no order (a funding
    /// payment, a transfer, a liquidation): when it arrived, and the newest
    /// venue time such events carried.
    last_event_ms: u64,
    last_event_time: Option<i64>,
    /// The socket's message counter.
    seq: u64,
    /// Recent events of orders, and what Guard's own recent sends should
    /// bring ([`StreamState::expect`]).
    order_events: std::collections::VecDeque<OrderEvent>,
    sends: std::collections::VecDeque<SendRecord>,
    /// The newest venue time seen on the socket.
    venue_time: Option<i64>,
    /// How far the venue's time trailed the wall clock on the last timed
    /// message (`clearinghouseState`, `bbo`).
    venue_lag: Option<i64>,
    /// When anything last arrived.
    last_message_ms: u64,
    /// Why the stream is unusable until the next connection: a snapshot
    /// out of order, an `error` from the venue.
    broken: Option<String>,
    /// Connections in a row that ended broken, and the last reason: the
    /// socket's task waits longer before each new one, and Guard alerts.
    pub breaks: u32,
    pub last_break: Option<String>,
    /// Entries of the account's non-funding ledger (deposits, withdrawals,
    /// transfers) that arrived and Guard has not taken yet
    /// ([`StreamState::take_ledger`]).
    ledger: Vec<Value>,
    /// Counters, for the status.
    pub messages: u64,
    pub reconnects: u64,
}

/// Why the stream's view is not used for a judgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotClean(pub String);

/// One dex's answers from the stream: `(dex, clearinghouseState revalued
/// at fresh marks, openOrders, allMids)`, shaped as the `info` requests
/// answer.
pub type DexSnapshot = (String, Value, Value, Value);

/// A clean view's parts.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamAnswers {
    pub dexes: Vec<DexSnapshot>,
    /// The fresh mid of every coin with a position or an order, and of the
    /// coin judged.
    pub mids: BTreeMap<String, Decimal>,
    /// The age of the oldest input, in ms: the snapshots' (the prices are
    /// younger).
    pub age_ms: u64,
    /// The account's leverage setting of the coin judged, when the venue
    /// showed it within [`PRICE_MAX_AGE_MS`] and after the account last
    /// changed (as the snapshots must be); `None` otherwise (the entry then
    /// sets leverage first, as after a read).
    pub leverage: Option<Leverage>,
}

/// A subscription's identity, as asked and as the venue echoes it (which
/// drops an empty `dex`).
pub fn key(subscription: &Value) -> String {
    let field = |name: &str| {
        subscription
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    let coin = subscription
        .get("coin")
        .and_then(Value::as_str)
        .unwrap_or("");
    let figs = subscription
        .get("nSigFigs")
        .and_then(Value::as_u64)
        .map_or_else(String::new, |figs| figs.to_string());
    format!(
        "{}|{}|{}|{}|{}",
        field("type"),
        field("user"),
        field("dex"),
        coin,
        figs
    )
}

/// Whether the stream can price `coin` at all: spot coins (`@1`,
/// `PURR/USDC`) and outcomes (`#`) have no perp `activeAssetCtx` (the venue
/// confirms one for `PURR/USDC` but sends `activeSpotAssetCtx`).
fn priced(coin: &str) -> bool {
    !coin.starts_with('@') && !coin.starts_with('#') && !coin.contains('/')
}

impl StreamState {
    /// Following the main dex and the HIP-3 dexes `dexes` of `user`.
    pub fn new(user: Address, dexes: &[String]) -> Self {
        let mut followed = BTreeMap::new();
        followed.insert(String::new(), DexStream::default());
        for dex in dexes {
            followed.insert(dex.clone(), DexStream::default());
        }
        Self {
            user,
            dexes: followed,
            coins: BTreeMap::new(),
            coin_order: Vec::new(),
            connected: false,
            asked: BTreeSet::new(),
            confirmed: BTreeSet::new(),
            last_event_ms: 0,
            last_event_time: None,
            seq: 0,
            order_events: std::collections::VecDeque::new(),
            sends: std::collections::VecDeque::new(),
            venue_time: None,
            venue_lag: None,
            last_message_ms: 0,
            broken: None,
            breaks: 0,
            last_break: None,
            ledger: Vec::new(),
            messages: 0,
            reconnects: 0,
        }
    }

    /// The account's subscriptions: its events first (so that no change
    /// can fall between a snapshot and the events), then each dex's
    /// snapshots.
    fn account_subscriptions(&self) -> Vec<Value> {
        let user = self.user.to_hex();
        let mut out = vec![
            json!({"type": "orderUpdates", "user": user}),
            json!({"type": "userEvents", "user": user}),
            json!({"type": "userNonFundingLedgerUpdates", "user": user}),
        ];
        for dex in self.dexes.keys() {
            out.push(json!({"type": "clearinghouseState", "user": user, "dex": dex}));
            out.push(json!({"type": "openOrders", "user": user, "dex": dex}));
            out.push(json!({"type": "allMids", "dex": dex}));
        }
        out
    }

    /// The subscriptions for a fresh socket: the account's, then the coins
    /// followed.
    pub fn subscriptions(&self) -> Vec<Value> {
        let mut out = self.account_subscriptions();
        let user = self.user.to_hex();
        for coin in self.coins.keys() {
            out.extend(coin_subscriptions(&user, coin));
        }
        out
    }

    /// The socket (re)connected at `now`, and [`StreamState::subscriptions`]
    /// are being asked for: everything known so far is old.
    pub fn connected(&mut self, now: u64) {
        for dex in self.dexes.values_mut() {
            *dex = DexStream::default();
        }
        for coin in self.coins.values_mut() {
            *coin = CoinStream::default();
        }
        self.asked = self.subscriptions().iter().map(key).collect();
        self.confirmed.clear();
        self.connected = true;
        self.broken = None;
        self.venue_time = None;
        self.venue_lag = None;
        self.last_event_time = None;
        self.order_events.clear();
        self.last_message_ms = now;
    }

    /// The socket closed; whether it was broken (an `error`, a snapshot
    /// out of order), which counts towards [`StreamState::breaks`].
    pub fn disconnected(&mut self) -> bool {
        self.connected = false;
        self.reconnects += 1;
        match self.broken.take() {
            Some(why) => {
                self.breaks = self.breaks.saturating_add(1);
                self.last_break = Some(why);
                true
            }
            None => {
                self.breaks = 0;
                false
            }
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Whether the socket should be dropped and opened again: silent too
    /// long, or broken (an `error` from the venue, a snapshot out of
    /// order).
    pub fn silent(&self, now: u64) -> bool {
        self.connected
            && (now.saturating_sub(self.last_message_ms) > SILENCE_MS || self.broken.is_some())
    }

    fn subscribe(&mut self, out: &mut Vec<(bool, Value)>, subscription: Value) {
        self.asked.insert(key(&subscription));
        out.push((true, subscription));
    }

    fn unsubscribe(&mut self, out: &mut Vec<(bool, Value)>, subscription: Value) {
        let key = key(&subscription);
        self.asked.remove(&key);
        self.confirmed.remove(&key);
        out.push((false, subscription));
    }

    /// Follow `coin` for an entry (its mark and mid). The subscriptions to
    /// send and drop.
    pub fn follow(&mut self, coin: &str) -> Vec<(bool, Value)> {
        let mut out = Vec::new();
        if !priced(coin) {
            return out;
        }
        self.coin_order.retain(|known| known != coin);
        self.coin_order.push(coin.to_owned());
        if !self.coins.contains_key(coin) {
            self.coins.insert(coin.to_owned(), CoinStream::default());
            for subscription in coin_subscriptions(&self.user.to_hex(), coin) {
                self.subscribe(&mut out, subscription);
            }
        }
        self.evict(&mut out);
        out
    }

    /// Follow every coin with a position or an order.
    fn follow_needed(&mut self) -> Vec<(bool, Value)> {
        let mut out = Vec::new();
        for coin in self.needed() {
            if !self.coins.contains_key(&coin) {
                out.extend(self.follow(&coin));
            }
        }
        out
    }

    /// Drop the oldest coins nothing needs beyond [`MAX_COINS`].
    fn evict(&mut self, out: &mut Vec<(bool, Value)>) {
        let needed = self.needed();
        while self.coins.len() > MAX_COINS {
            let Some(oldest) = self
                .coin_order
                .iter()
                .find(|coin| !needed.contains(*coin))
                .cloned()
            else {
                return;
            };
            self.coin_order.retain(|coin| *coin != oldest);
            if self.coins.remove(&oldest).is_some() {
                for subscription in coin_subscriptions(&self.user.to_hex(), &oldest) {
                    self.unsubscribe(out, subscription);
                }
            }
        }
    }

    /// The coins with a position or an open order in the last snapshots.
    fn needed(&self) -> BTreeSet<String> {
        let mut coins = BTreeSet::new();
        for dex in self.dexes.values() {
            if let Some((state, _, _, _)) = &dex.state {
                for entry in state["assetPositions"].as_array().into_iter().flatten() {
                    let position = &entry["position"];
                    let open = position["szi"]
                        .as_str()
                        .and_then(|szi| szi.parse::<Decimal>().ok())
                        .is_some_and(|szi| szi != Decimal::ZERO);
                    if open && let Some(coin) = position["coin"].as_str() {
                        coins.insert(coin.to_owned());
                    }
                }
            }
            if let Some((orders, _)) = &dex.orders {
                for order in orders.as_array().into_iter().flatten() {
                    if let Some(coin) = order["coin"].as_str() {
                        coins.insert(coin.to_owned());
                    }
                }
            }
        }
        coins.retain(|coin| priced(coin));
        coins
    }

    /// Take in one message from the socket, received at `now`. The
    /// subscriptions it makes necessary (coins a new position or order
    /// needs priced), to send.
    pub fn apply(&mut self, message: &Value, now: u64) -> Vec<(bool, Value)> {
        self.apply_at(message, now, None)
    }

    /// [`StreamState::apply`], with the wall clock (epoch ms) when the
    /// message arrived, against which the venue's times are bounded.
    pub fn apply_at(&mut self, message: &Value, now: u64, wall: Option<i64>) -> Vec<(bool, Value)> {
        self.last_message_ms = now;
        self.seq += 1;
        let seq = self.seq;
        self.messages += 1;
        let data = &message["data"];
        let user = self.user;
        let user_matches = || {
            data.get("user")
                .and_then(Value::as_str)
                .and_then(Address::from_hex)
                == Some(user)
        };
        let mut snapshot = false;
        match message["channel"].as_str() {
            Some("subscriptionResponse") => {
                let key = key(&data["subscription"]);
                if data["method"] == "subscribe" && self.asked.contains(&key) {
                    self.confirmed.insert(key);
                }
            }
            Some("error") => {
                let text = data
                    .as_str()
                    .map_or_else(|| data.to_string(), str::to_owned);
                self.broken = Some(format!("the venue answered an error: {text}"));
            }
            Some("clearinghouseState") if user_matches() => {
                let dex = data["dex"].as_str().unwrap_or("");
                let state = data["clearinghouseState"].clone();
                let Some(time) = state["time"].as_i64() else {
                    self.broken = Some("a clearinghouseState without its time".into());
                    return Vec::new();
                };
                let Some(stream) = self.dexes.get_mut(dex) else {
                    return Vec::new();
                };
                if stream
                    .state
                    .as_ref()
                    .is_some_and(|(_, _, last, _)| time < *last)
                {
                    self.broken = Some("a snapshot came out of order".into());
                    return Vec::new();
                }
                let lag = wall.map(|wall| wall.saturating_sub(time));
                stream.state = Some((state, now, time, lag));
                stream.state_seq = seq;
                stream.snapshots += 1;
                stream.state_n = stream.snapshots;
                self.venue_time = self.venue_time.max(Some(time));
                self.venue_lag = lag.or(self.venue_lag);
                snapshot = true;
            }
            Some("openOrders") if user_matches() => {
                let dex = data["dex"].as_str().unwrap_or("");
                if let Some(stream) = self.dexes.get_mut(dex) {
                    stream.orders = Some((data["orders"].clone(), now));
                    stream.orders_seq = seq;
                    stream.snapshots += 1;
                    stream.orders_n = stream.snapshots;
                    snapshot = true;
                }
            }
            Some("allMids") => {
                let dex = data["dex"].as_str().unwrap_or("");
                if let Some(stream) = self.dexes.get_mut(dex) {
                    stream.mids = Some((data["mids"].clone(), now));
                }
            }
            Some("activeAssetData") if user_matches() => {
                let Some(coin) = data["coin"].as_str() else {
                    return Vec::new();
                };
                if let Some(followed) = self.coins.get_mut(coin) {
                    let isolated = match data["leverage"]["type"].as_str() {
                        Some("isolated") => Some(true),
                        Some("cross") => Some(false),
                        _ => None,
                    };
                    let value = data["leverage"]["value"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok());
                    followed.leverage = isolated
                        .zip(value)
                        .map(|(isolated, value)| (Leverage { isolated, value }, now));
                }
            }
            Some("activeAssetCtx") => {
                let Some(coin) = data["coin"].as_str() else {
                    return Vec::new();
                };
                if let Some(followed) = self.coins.get_mut(coin) {
                    let number = |name: &str| {
                        data["ctx"][name]
                            .as_str()
                            .and_then(|text| text.parse::<Decimal>().ok())
                            .filter(|value| *value > Decimal::ZERO)
                    };
                    followed.mark = number("markPx").map(|mark| (mark, now));
                    followed.ctx_mid = Some((number("midPx"), now));
                }
            }
            Some("bbo") => {
                let (Some(coin), Some(time)) = (data["coin"].as_str(), data["time"].as_i64())
                else {
                    return Vec::new();
                };
                self.venue_time = self.venue_time.max(Some(time));
                self.venue_lag = wall
                    .map(|wall| wall.saturating_sub(time))
                    .or(self.venue_lag);
                if let Some(followed) = self.coins.get_mut(coin) {
                    // An older block's best prices after a newer one's: kept
                    // out.
                    if followed.bbo.is_some_and(|(_, _, last)| time < last) {
                        return Vec::new();
                    }
                    let level = |at: usize| {
                        data["bbo"][at]["px"]
                            .as_str()
                            .and_then(|px| px.parse::<Decimal>().ok())
                    };
                    let mid = level(0)
                        .zip(level(1))
                        .and_then(|(bid, ask)| bid.checked_add(ask))
                        .and_then(|sum| sum.checked_div(Decimal::TWO));
                    followed.bbo = Some((mid, now, time));
                }
            }
            // Events of the account: whatever changed reaches the snapshots
            // only later. A snapshot (`isSnapshot`) of past events is no
            // change.
            Some("orderUpdates") => {
                // Each update names its order: Guard's own sends' are told
                // apart in `answers`. One that names none counts as any
                // other event of the account.
                for update in data.as_array().into_iter().flatten() {
                    let order = &update["order"];
                    let oid = order["oid"].as_u64();
                    let cloid = order["cloid"].as_str().map(str::to_ascii_lowercase);
                    let status = update["status"].as_str().unwrap_or("").to_owned();
                    let time = update["statusTimestamp"].as_i64();
                    self.venue_time = self.venue_time.max(time);
                    if oid.is_none() || status.is_empty() {
                        self.event(now, time);
                        continue;
                    }
                    self.order_event(OrderEvent {
                        seq,
                        at: now,
                        time,
                        oid,
                        cloid,
                        status,
                    });
                }
                if data.as_array().is_none_or(Vec::is_empty) {
                    self.event(now, event_time(message));
                }
            }
            Some("user") if data["isSnapshot"].as_bool() != Some(true) => {
                // Fills name their orders; anything else (funding,
                // liquidations, the venue's cancels) counts as an event of
                // the account.
                let fills = data["fills"].as_array();
                let other = data
                    .as_object()
                    .is_some_and(|fields| fields.keys().any(|key| key != "fills" && key != "user"));
                for fill in fills.into_iter().flatten() {
                    let time = fill["time"].as_i64();
                    self.venue_time = self.venue_time.max(time);
                    match fill["oid"].as_u64() {
                        Some(oid) => self.order_event(OrderEvent {
                            seq,
                            at: now,
                            time,
                            oid: Some(oid),
                            cloid: fill["cloid"].as_str().map(str::to_ascii_lowercase),
                            status: "fill".into(),
                        }),
                        None => self.event(now, time),
                    }
                }
                if other || fills.is_none_or(Vec::is_empty) {
                    self.event(now, event_time(message));
                }
            }
            Some("userNonFundingLedgerUpdates")
                if data["isSnapshot"].as_bool() != Some(true) && user_matches() =>
            {
                self.event(now, event_time(message));
                for update in data["nonFundingLedgerUpdates"]
                    .as_array()
                    .into_iter()
                    .flatten()
                {
                    if self.ledger.len() < MAX_LEDGER {
                        self.ledger.push(update.clone());
                    }
                }
            }
            Some("user") | Some("userNonFundingLedgerUpdates")
                if data["isSnapshot"].as_bool() != Some(true) =>
            {
                self.event(now, event_time(message));
            }
            _ => {}
        }
        if snapshot {
            self.follow_needed()
        } else {
            Vec::new()
        }
    }

    fn order_event(&mut self, event: OrderEvent) {
        let now = event.at;
        self.order_events.push_back(event);
        while self
            .order_events
            .front()
            .is_some_and(|first| now.saturating_sub(first.at) > EVENTS_KEPT_MS)
        {
            self.order_events.pop_front();
        }
    }

    /// Guard heard back on a send at `sent` ([`monotonic_ms`]): what the
    /// socket should report of it, if Guard knows. Every send is recorded,
    /// before Guard notes it as its last send.
    pub fn sent(&mut self, sent: u64, expectation: Option<Expectation>) {
        self.sends.push_back(SendRecord { sent, expectation });
        while self
            .sends
            .front()
            .is_some_and(|first| sent.saturating_sub(first.sent) > EVENTS_KEPT_MS)
        {
            self.sends.pop_front();
        }
    }

    /// A send with what the socket should report of it.
    pub fn expect(&mut self, expectation: Expectation) {
        self.sent(expectation.sent, Some(expectation));
    }

    /// Whether an order event is one Guard's own send in `expectation`
    /// brought.
    fn own(expectation: &Expectation, event: &OrderEvent) -> bool {
        let window = event.at.saturating_add(OWN_EVENT_BEFORE_MS) >= expectation.sent
            && event.at <= expectation.sent.saturating_add(OWN_EVENT_AFTER_MS);
        if !window {
            return false;
        }
        let status = event.status.as_str();
        let by_oid = event.oid.is_some_and(|oid| {
            (expectation.resting.contains(&oid) && status == "open")
                || (expectation.filled.contains(&oid)
                    && matches!(status, "open" | "filled" | "fill"))
                || (expectation.cancelled.contains(&oid) && status == "canceled")
                || (expectation.reduce_only.contains(&oid) && status == "reduceOnlyCanceled")
        });
        let by_cloid = event.cloid.as_ref().is_some_and(|cloid| {
            (status == "open" && expectation.cloids.contains(cloid))
                || (status == "canceled" && expectation.cancelled_cloids.contains(cloid))
        });
        by_oid || by_cloid
    }

    /// What the socket reported of the send `expectation`, if it reported
    /// all of it: every order it rested, filled or cancelled, by id (or by
    /// client id for a cancelled entry's stop). `None` otherwise.
    fn reported(&self, expectation: &Expectation) -> Option<Reported> {
        let own: Vec<&OrderEvent> = self
            .order_events
            .iter()
            .filter(|event| Self::own(expectation, event))
            .collect();
        let has = |oid: u64, status: &str| {
            own.iter()
                .any(|event| event.oid == Some(oid) && event.status == status)
        };
        let complete = expectation.resting.iter().all(|oid| has(*oid, "open"))
            && expectation.filled.iter().all(|oid| has(*oid, "filled"))
            && expectation
                .cancelled
                .iter()
                .all(|oid| has(*oid, "canceled"))
            && expectation.cancelled_cloids.iter().all(|cloid| {
                own.iter().any(|event| {
                    event.cloid.as_deref() == Some(cloid.as_str()) && event.status == "canceled"
                })
            });
        if !complete || own.is_empty() {
            return None;
        }
        let time = own
            .iter()
            .map(|event| event.time)
            .collect::<Option<Vec<i64>>>()?
            .into_iter()
            .max()?;
        let seq = own.iter().map(|event| event.seq).max()?;
        // A dex the stream does not follow cannot show it.
        if !self.dexes.contains_key(&expectation.dex) {
            return None;
        }
        // A HIP-3 dex's orders may draw their margin from the main dex
        // (dex abstraction): its snapshot must show them too.
        let mut dexes = vec![expectation.dex.clone()];
        if !expectation.dex.is_empty() {
            dexes.push(String::new());
        }
        Some(Reported { time, seq, dexes })
    }

    fn event(&mut self, now: u64, time: Option<i64>) {
        self.last_event_ms = now;
        self.last_event_time = self.last_event_time.max(time);
        self.venue_time = self.venue_time.max(time);
    }

    /// Every dex's answers, if the stream is clean at `now` for a judgement
    /// of `coin` (none for an action naming no coin), given that Guard last
    /// heard back from the venue on something it sent at `last_send`
    /// (both on [`monotonic_ms`]'s clock): the snapshots revalued at fresh
    /// marks, and the fresh mids.
    pub fn answers(
        &self,
        now: u64,
        last_send: Option<u64>,
        coin: Option<&str>,
    ) -> Result<StreamAnswers, NotClean> {
        let not = |why: String| Err(NotClean(why));
        if !self.connected {
            return not("the stream is not connected".into());
        }
        if let Some(why) = &self.broken {
            return not(why.clone());
        }
        if let Some(missing) = self
            .account_subscriptions()
            .iter()
            .map(key)
            .find(|key| !self.confirmed.contains(key))
        {
            return not(format!("the venue has not confirmed {missing}"));
        }
        if let Some(lag) = self.venue_lag.filter(|lag| *lag > MAX_VENUE_LAG_MS) {
            return not(format!(
                "the venue's time on the socket trails the wall clock by {lag} ms"
            ));
        }
        // Every recent send of Guard's: one the socket reported in full
        // needs its dexes' snapshots to have come after its reports; any
        // other (outcome unknown, not all reported, a leverage or margin
        // update) counts as a change of the account at the send. A last
        // send Guard names that was never recorded counts as unreported.
        let mut unreported_at = match (last_send, self.sends.back()) {
            (Some(last), Some(newest)) if last <= newest.sent => 0,
            (last, _) => last.unwrap_or(0),
        };
        let mut required: BTreeMap<&str, (i64, u64)> = BTreeMap::new();
        let mut reported_sends = Vec::new();
        for send in &self.sends {
            let expectation = send.expectation.as_ref();
            match expectation.and_then(|expectation| self.reported(expectation)) {
                Some(reported) => {
                    reported_sends.extend(expectation);
                    for dex in &reported.dexes {
                        let Some((name, _)) = self.dexes.get_key_value(dex) else {
                            continue;
                        };
                        let entry = required.entry(name.as_str()).or_insert((i64::MIN, 0));
                        entry.0 = entry.0.max(reported.time);
                        entry.1 = entry.1.max(reported.seq);
                    }
                }
                None => unreported_at = unreported_at.max(send.sent),
            }
        }
        // Events no fully reported send of Guard's explains: the account
        // changed (an event a send not reported in full might explain is
        // no proof of anything).
        let outside: Vec<&OrderEvent> = self
            .order_events
            .iter()
            .filter(|event| !reported_sends.iter().any(|e| Self::own(e, event)))
            .collect();
        let outside_at = outside.iter().map(|event| event.at).max().unwrap_or(0);
        let outside_time = outside.iter().filter_map(|event| event.time).max();
        let changed = self.last_event_ms.max(outside_at).max(unreported_at);
        let last_event_time = self.last_event_time.max(outside_time);
        let venue_now = self.venue_time.unwrap_or(i64::MIN);
        let mut age_ms = 0;
        let mut snapshots = Vec::with_capacity(self.dexes.len());
        for (dex, stream) in &self.dexes {
            let label = if dex.is_empty() { "the main dex" } else { dex };
            let (
                Some((state, state_at, time, lag)),
                Some((orders, orders_at)),
                Some((mids, mids_at)),
            ) = (&stream.state, &stream.orders, &stream.mids)
            else {
                return not(format!("no snapshot of {label} yet"));
            };
            if let Some(lag) = lag.filter(|lag| *lag > MAX_VENUE_LAG_MS) {
                return not(format!(
                    "the account of {label} trailed the wall clock by {lag} ms"
                ));
            }
            for (what, at) in [
                ("account", state_at),
                ("orders", orders_at),
                ("mids", mids_at),
            ] {
                let age = now.saturating_sub(*at);
                if age > SNAPSHOT_MAX_AGE_MS {
                    return not(format!("the {what} of {label} is {age} ms old"));
                }
                age_ms = age_ms.max(age);
            }
            let behind = venue_now.saturating_sub(*time);
            if behind > SNAPSHOT_MAX_AGE_MS as i64 {
                return not(format!(
                    "the account of {label} is {behind} ms old by the venue's clock"
                ));
            }
            for at in [state_at, orders_at] {
                if *at < changed.saturating_add(EVENT_MARGIN_MS) {
                    return not(format!(
                        "the account changed {} ms ago; {label}'s snapshot is older",
                        now.saturating_sub(changed)
                    ));
                }
            }
            if last_event_time.is_some_and(|event| *time < event) {
                return not(format!(
                    "{label}'s snapshot predates the account's last event by the venue's clock"
                ));
            }
            // Guard's own sends, reported: their dexes' snapshots came after
            // the reports, together (the venue sends a dex's open orders and
            // account one after the other; only the account carries a
            // time), and no older by the venue's clock.
            if let Some((own_time, own_seq)) = required.get(dex.as_str()) {
                let after = stream.state_seq > *own_seq && stream.orders_seq > *own_seq;
                let paired = stream.state_n.abs_diff(stream.orders_n) == 1;
                if !after || !paired || *time < *own_time {
                    return not(format!("{label}'s snapshot predates what Guard just sent"));
                }
            }
            snapshots.push((dex, state, orders, mids));
        }
        // Every coin with a position or an order, and the coin judged:
        // fresh prices.
        let mut coins = self.needed();
        if let Some(coin) = coin {
            coins.insert(coin.to_owned());
        }
        let mut marks = BTreeMap::new();
        let mut fresh_mids = BTreeMap::new();
        for name in &coins {
            let Some(followed) = self.coins.get(name) else {
                return not(format!("{name} is not followed yet"));
            };
            let unconfirmed = coin_subscriptions(&self.user.to_hex(), name)
                .iter()
                .map(key)
                .find(|key| !self.confirmed.contains(key));
            if let Some(missing) = unconfirmed {
                return not(format!("the venue has not confirmed {missing}"));
            }
            let Some((mark, mark_at)) = followed.mark else {
                return not(format!("no mark of {name} yet"));
            };
            let Some((mid, mid_at)) = followed.mid() else {
                return not(format!("no mid of {name} yet"));
            };
            for (what, at) in [("mark", mark_at), ("mid", mid_at)] {
                let age = now.saturating_sub(at);
                if age > PRICE_MAX_AGE_MS {
                    return not(format!("the {what} of {name} is {age} ms old"));
                }
            }
            let Some(mid) = mid else {
                return not(format!("{name} has no bid or no ask"));
            };
            let dex = name.split_once(':').map_or("", |(dex, _)| dex);
            let snapshot_mid = self
                .dexes
                .get(dex)
                .and_then(|stream| stream.mids.as_ref())
                .and_then(|(mids, _)| mids[name.as_str()].as_str())
                .and_then(|text| text.parse::<Decimal>().ok())
                .filter(|mid| *mid > Decimal::ZERO);
            let Some(snapshot_mid) = snapshot_mid else {
                return not(format!("{name} has no mid in its dex's allMids"));
            };
            let drift = mid
                .checked_sub(snapshot_mid)
                .and_then(|moved| moved.abs().checked_div(snapshot_mid));
            if drift.is_none_or(|drift| drift > MAX_MID_DRIFT) {
                return not(format!(
                    "{name}'s mid {mid} is more than {MAX_MID_DRIFT} from its allMids {snapshot_mid}"
                ));
            }
            marks.insert(name.clone(), mark);
            fresh_mids.insert(name.clone(), mid);
        }
        let mut dexes = Vec::with_capacity(snapshots.len());
        for (dex, state, orders, mids) in snapshots {
            let revalued =
                revalue_clearinghouse(state, |coin| marks.get(coin).copied()).map_err(NotClean)?;
            dexes.push((dex.clone(), revalued, orders.clone(), mids.clone()));
        }
        let leverage = coin
            .and_then(|coin| self.coins.get(coin))
            .and_then(|followed| followed.leverage)
            .filter(|(_, at)| {
                now.saturating_sub(*at) <= PRICE_MAX_AGE_MS
                    && *at >= changed.saturating_add(EVENT_MARGIN_MS)
            })
            .map(|(leverage, _)| leverage);
        Ok(StreamAnswers {
            dexes,
            mids: fresh_mids,
            age_ms,
            leverage,
        })
    }

    /// A bot's read of its own account from the stream: the latest
    /// `clearinghouseState` and `openOrders` of `dex` as the venue sent
    /// them (not revalued: a document the venue sends any client), when
    /// the stream is clean at `now` ([`StreamState::answers`]).
    pub fn raw_snapshot(
        &self,
        now: u64,
        last_send: Option<u64>,
        dex: &str,
    ) -> Option<(Value, Value)> {
        self.answers(now, last_send, None).ok()?;
        let stream = self.dexes.get(dex)?;
        let (state, ..) = stream.state.as_ref()?;
        let (orders, _) = stream.orders.as_ref()?;
        Some((state.clone(), orders.clone()))
    }

    /// The ledger entries that arrived since the last call, oldest first.
    pub fn take_ledger(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.ledger)
    }

    /// The coins followed, for the status.
    pub fn coins(&self) -> BTreeSet<String> {
        self.coins.keys().cloned().collect()
    }
}

/// The newest venue time an event message carries: `orderUpdates`'
/// `statusTimestamp`, fills' and ledger updates' `time`, a funding's.
fn event_time(message: &Value) -> Option<i64> {
    let data = &message["data"];
    let mut times = Vec::new();
    for update in data.as_array().into_iter().flatten() {
        times.push(update["statusTimestamp"].as_i64());
    }
    for fill in data["fills"].as_array().into_iter().flatten() {
        times.push(fill["time"].as_i64());
    }
    for update in data["nonFundingLedgerUpdates"]
        .as_array()
        .into_iter()
        .flatten()
    {
        times.push(update["time"].as_i64());
    }
    times.push(data["funding"]["time"].as_i64());
    times.into_iter().flatten().max()
}

/// The stream as Guard holds it: the state, shared with the socket's task,
/// and a way to ask it to follow a coin.
pub struct Stream {
    pub state: std::sync::Arc<std::sync::Mutex<StreamState>>,
    follow: tokio::sync::mpsc::UnboundedSender<String>,
}

/// How long to wait for the venue's socket to connect.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How often to ping: the venue closes a socket silent for a minute.
const PING_EVERY: std::time::Duration = std::time::Duration::from_secs(20);
/// Waits between reconnects: 1 s, doubling to 30 s; after connections
/// that ended broken (an `error` from the venue), doubling on to 5 min.
const RECONNECT_MAX: std::time::Duration = std::time::Duration::from_secs(30);
const RECONNECT_BROKEN_MAX: std::time::Duration = std::time::Duration::from_secs(300);

impl Stream {
    /// Start following `user`'s account on the main dex and `dexes` at the
    /// venue's WebSocket `url`, reconnecting whenever the socket drops,
    /// goes silent or is broken. Times are [`monotonic_ms`]. Dropping the
    /// returned task's handle does not stop it; abort it.
    pub fn spawn(
        url: String,
        user: Address,
        dexes: &[String],
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let state = std::sync::Arc::new(std::sync::Mutex::new(StreamState::new(user, dexes)));
        let (follow, requests) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(run(url, state.clone(), requests));
        (Self { state, follow }, task)
    }

    /// Ask the stream to follow `coin`.
    pub fn follow(&self, coin: &str) {
        self.follow.send(coin.to_owned()).ok();
    }
}

fn lock(state: &std::sync::Mutex<StreamState>) -> std::sync::MutexGuard<'_, StreamState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn run(
    url: String,
    state: std::sync::Arc<std::sync::Mutex<StreamState>>,
    mut requests: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let mut wait = std::time::Duration::from_secs(1);
    loop {
        let connected = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_tungstenite::connect_async(url.as_str()),
        )
        .await;
        if let Ok(Ok((socket, _))) = connected {
            let (mut sink, mut source) = socket.split();
            let subscriptions = {
                let mut state = lock(&state);
                state.connected(monotonic_ms());
                state.subscriptions()
            };
            let mut ok = true;
            for subscription in subscriptions {
                let text = json!({"method": "subscribe", "subscription": subscription});
                if sink.send(Message::text(text.to_string())).await.is_err() {
                    ok = false;
                    break;
                }
            }
            let mut ping = tokio::time::interval(PING_EVERY);
            let mut check = tokio::time::interval(std::time::Duration::from_secs(1));
            while ok {
                let changes = tokio::select! {
                    message = source.next() => match message {
                        Some(Ok(Message::Text(text))) => {
                            match serde_json::from_str::<Value>(text.as_str()) {
                                Ok(value) => lock(&state).apply_at(&value, monotonic_ms(), Some(wall_ms())),
                                Err(_) => Vec::new(),
                            }
                        }
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        Some(Ok(_)) => Vec::new(),
                    },
                    request = requests.recv() => {
                        let Some(coin) = request else { return };
                        lock(&state).follow(&coin)
                    }
                    _ = ping.tick() => {
                        let text = json!({"method": "ping"}).to_string();
                        if sink.send(Message::text(text)).await.is_err() {
                            break;
                        }
                        Vec::new()
                    }
                    _ = check.tick() => {
                        if lock(&state).silent(monotonic_ms()) {
                            break;
                        }
                        Vec::new()
                    }
                };
                for (subscribe, subscription) in changes {
                    let method = if subscribe {
                        "subscribe"
                    } else {
                        "unsubscribe"
                    };
                    let text = json!({"method": method, "subscription": subscription});
                    if sink.send(Message::text(text.to_string())).await.is_err() {
                        ok = false;
                    }
                }
            }
            let broken = lock(&state).disconnected();
            if broken {
                // The venue refused something: the next connection would
                // likely be refused the same way; wait longer each time.
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(RECONNECT_BROKEN_MAX);
                continue;
            }
            wait = std::time::Duration::from_secs(1);
        } else {
            // Not connected: coins asked for meanwhile are followed from
            // the next connection on.
            while let Ok(coin) = requests.try_recv() {
                lock(&state).follow(&coin);
            }
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RECONNECT_MAX);
    }
}

/// The wall clock, epoch ms.
fn wall_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// A coin's subscriptions: its mark and mid, its best prices, and the
/// account's leverage setting of it.
fn coin_subscriptions(user: &str, coin: &str) -> Vec<Value> {
    vec![
        json!({"type": "activeAssetCtx", "coin": coin}),
        json!({"type": "bbo", "coin": coin}),
        json!({"type": "activeAssetData", "user": user, "coin": coin}),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rust_decimal::dec;

    use super::*;

    const USER: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

    fn user() -> Address {
        Address::from_hex(USER).unwrap()
    }

    fn state_with(dex: &str, time: i64, value: &str, positions: Value) -> Value {
        json!({"channel": "clearinghouseState", "data": {"dex": dex, "user": USER,
            "clearinghouseState": {"marginSummary": {"accountValue": value},
                "withdrawable": value, "assetPositions": positions, "time": time}}})
    }

    fn state(dex: &str, time: i64) -> Value {
        state_with(dex, time, "100", json!([]))
    }

    fn orders(dex: &str) -> Value {
        json!({"channel": "openOrders", "data": {"dex": dex, "user": USER, "orders": []}})
    }

    fn mids(dex: &str) -> Value {
        let mids = if dex.is_empty() {
            json!({"BTC": "60000", "ETH": "3000"})
        } else {
            json!({"xyz:GOLD": "4000"})
        };
        json!({"channel": "allMids", "data": {"dex": dex, "mids": mids}})
    }

    fn ctx(coin: &str, mark: &str, mid: &str) -> Value {
        json!({"channel": "activeAssetCtx", "data": {"coin": coin,
            "ctx": {"markPx": mark, "midPx": mid, "oraclePx": mark}}})
    }

    fn bbo(coin: &str, time: i64, bid: &str, ask: &str) -> Value {
        json!({"channel": "bbo", "data": {"coin": coin, "time": time,
            "bbo": [{"px": bid, "sz": "1", "n": 1}, {"px": ask, "sz": "1", "n": 1}]}})
    }

    /// The venue's confirmation of every subscription asked for (at the
    /// time of the last message).
    fn confirm(stream: &mut StreamState, subscriptions: &[Value]) {
        let at = stream.last_message_ms;
        for subscription in subscriptions {
            stream.apply(
                &json!({"channel": "subscriptionResponse",
                    "data": {"method": "subscribe", "subscription": subscription}}),
                at,
            );
        }
    }

    fn confirm_changes(stream: &mut StreamState, changes: &[(bool, Value)]) {
        let subscribed: Vec<Value> = changes
            .iter()
            .filter(|(subscribe, _)| *subscribe)
            .map(|(_, subscription)| subscription.clone())
            .collect();
        confirm(stream, &subscribed);
    }

    /// Connected at `at` with every subscription confirmed.
    fn connect(stream: &mut StreamState, at: u64) {
        stream.connected(at);
        let subscriptions = stream.subscriptions();
        confirm(stream, &subscriptions);
    }

    /// The main dex and xyz, snapshots at `at`.
    fn snapshots(stream: &mut StreamState, at: u64, time: i64) {
        for dex in ["", "xyz"] {
            stream.apply(&state(dex, time), at);
            stream.apply(&orders(dex), at);
            stream.apply(&mids(dex), at);
        }
    }

    #[test]
    fn a_fresh_quiet_stream_answers_and_a_stale_one_does_not() {
        let mut stream = StreamState::new(user(), &["xyz".to_owned()]);
        // The subscriptions: the account's three event channels first, then
        // three per dex.
        let subscriptions = stream.subscriptions();
        assert_eq!(subscriptions.len(), 9);
        assert_eq!(subscriptions[0]["type"], "orderUpdates");
        assert!(stream.answers(1_000, None, None).is_err(), "not connected");
        stream.connected(1_000);
        snapshots(&mut stream, 2_000, 10);
        // Not confirmed by the venue yet.
        let why = stream.answers(2_500, None, None).unwrap_err().0;
        assert!(why.contains("not confirmed"), "{why}");
        // The venue echoes `allMids` of the main dex without its `dex`.
        confirm(&mut stream, &subscriptions[..5]);
        confirm(&mut stream, &[json!({"type": "allMids"})]);
        assert!(
            stream.answers(2_500, None, None).is_err(),
            "xyz's still out"
        );
        confirm(&mut stream, &subscriptions[6..]);
        let answers = stream.answers(2_500, None, None).unwrap();
        assert_eq!(answers.dexes.len(), 2);
        assert_eq!(answers.age_ms, 500);
        // 6 s later still clean; 6.001 s later stale.
        assert!(stream.answers(8_000, None, None).is_ok());
        assert!(stream.answers(8_001, None, None).is_err());
    }

    #[test]
    fn an_event_or_a_send_waits_for_the_next_snapshots() {
        let mut stream = StreamState::new(user(), &[]);
        connect(&mut stream, 0);
        for message in [state("", 1), orders(""), mids("")] {
            stream.apply(&message, 1_000);
        }
        assert!(stream.answers(1_100, None, None).is_ok());
        // An order update at 1,200: the snapshots of 1,000 no longer count.
        stream.apply(
            &json!({"channel": "orderUpdates", "data": [{"status": "filled"}]}),
            1_200,
        );
        assert!(stream.answers(1_300, None, None).is_err());
        // A snapshot 0.5 s after the event: maybe sent before it; not yet.
        stream.apply(&state("", 2), 1_700);
        stream.apply(&orders(""), 1_700);
        assert!(stream.answers(1_800, None, None).is_err());
        // 1 s after it, the account but not yet the orders: not yet.
        stream.apply(&state("", 3), 2_200);
        assert!(stream.answers(2_300, None, None).is_err());
        // Both: clean again.
        stream.apply(&orders(""), 2_250);
        assert!(stream.answers(2_300, None, None).is_ok());
        // Guard's own send, answered at 2,400: the same.
        assert!(stream.answers(2_500, Some(2_400), None).is_err());
        stream.apply(&state("", 4), 3_400);
        stream.apply(&orders(""), 3_400);
        assert!(stream.answers(3_500, Some(2_400), None).is_ok());
        // A snapshot of past fills is no event; a fill is.
        stream.apply(
            &json!({"channel": "user", "data": {"isSnapshot": true, "fills": []}}),
            3_600,
        );
        assert!(stream.answers(3_700, Some(2_400), None).is_ok());
        stream.apply(&json!({"channel": "user", "data": {"fills": [{}]}}), 3_800);
        assert!(stream.answers(3_900, Some(2_400), None).is_err());
        // A transfer, likewise.
        stream.apply(&state("", 5), 4_900);
        stream.apply(&orders(""), 4_900);
        stream.apply(&mids(""), 4_900);
        assert!(stream.answers(5_000, None, None).is_ok());
        stream.apply(
            &json!({"channel": "userNonFundingLedgerUpdates", "data": {"nonFundingLedgerUpdates": []}}),
            5_100,
        );
        assert!(stream.answers(5_200, None, None).is_err());
        // A fill at venue time 1,000,000: a snapshot that arrives 1 s later
        // but whose time is before the fill's does not count either.
        stream.apply(
            &json!({"channel": "user", "data": {"fills": [{"time": 1_000_000}]}}),
            6_000,
        );
        stream.apply(&state("", 999_999), 7_100);
        stream.apply(&orders(""), 7_100);
        stream.apply(&mids(""), 7_100);
        let why = stream.answers(7_200, None, None).unwrap_err().0;
        assert!(why.contains("predates"), "{why}");
        stream.apply(&state("", 1_000_001), 7_300);
        assert!(stream.answers(7_400, None, None).is_ok());
    }

    #[test]
    fn a_venue_time_far_behind_the_wall_clock_is_not_used() {
        let mut stream = StreamState::new(user(), &[]);
        connect(&mut stream, 0);
        // The account's time 1,000 ms behind the wall clock: fine.
        stream.apply_at(&state("", 100_000), 1_000, Some(101_000));
        stream.apply(&orders(""), 1_000);
        stream.apply(&mids(""), 1_000);
        assert!(stream.answers(1_100, None, None).is_ok());
        // 3,001 ms behind: a server that lags; not used.
        stream.apply_at(&state("", 100_001), 1_200, Some(103_002));
        let why = stream.answers(1_300, None, None).unwrap_err().0;
        assert!(why.contains("wall clock"), "{why}");
        stream.apply_at(&state("", 103_000), 1_400, Some(103_500));
        assert!(stream.answers(1_500, None, None).is_ok());
        // A bbo 3,001 ms behind, likewise.
        stream.apply_at(&bbo("BTC", 100_000, "1", "2"), 1_600, Some(103_001));
        let why = stream.answers(1_700, None, None).unwrap_err().0;
        assert!(why.contains("wall clock"), "{why}");
        // An account 3,001 ms behind, then a timely bbo: the account's own
        // lag still counts.
        stream.apply_at(&state("", 104_000), 1_800, Some(107_001));
        stream.apply_at(&bbo("BTC", 107_400, "1", "2"), 1_850, Some(107_500));
        let why = stream.answers(1_900, None, None).unwrap_err().0;
        assert!(why.contains("account of the main dex trailed"), "{why}");
    }

    #[test]
    fn out_of_order_errors_disconnected_or_another_users_snapshots_never_count() {
        let mut stream = StreamState::new(user(), &[]);
        connect(&mut stream, 0);
        for message in [state("", 10), orders(""), mids("")] {
            stream.apply(&message, 1_000);
        }
        assert!(stream.answers(1_100, None, None).is_ok());
        // The venue's time going back: refused until a reconnect, which the
        // socket's task then makes.
        stream.apply(&state("", 9), 1_200);
        assert_eq!(
            stream.answers(1_300, None, None),
            Err(NotClean("a snapshot came out of order".into()))
        );
        assert!(stream.silent(1_300));
        stream.disconnected();
        assert!(stream.answers(1_400, None, None).is_err());
        connect(&mut stream, 2_000);
        assert!(
            stream.answers(2_000, None, None).is_err(),
            "old snapshots dropped"
        );
        // Another user's account is ignored.
        let other = json!({"channel": "clearinghouseState", "data": {"dex": "",
            "user": "0x0000000000000000000000000000000000000001",
            "clearinghouseState": {"marginSummary": {"accountValue": "1"}, "assetPositions": [], "time": 20}}});
        stream.apply(&other, 2_100);
        stream.apply(&orders(""), 2_100);
        stream.apply(&mids(""), 2_100);
        assert!(stream.answers(2_200, None, None).is_err());
        stream.apply(&state("", 20), 2_100);
        assert!(stream.answers(2_200, None, None).is_ok());
        // An error from the venue: unclean, and the socket is dropped.
        stream.apply(
            &json!({"channel": "error", "data": "Invalid subscription"}),
            2_300,
        );
        let why = stream.answers(2_400, None, None).unwrap_err().0;
        assert!(why.contains("Invalid subscription"), "{why}");
        assert!(stream.silent(2_400));
        // Broken connections count, in a row (the snapshot out of order,
        // then this); a clean end resets the count.
        assert!(stream.disconnected());
        assert_eq!(stream.breaks, 2);
        assert!(
            stream
                .last_break
                .as_deref()
                .unwrap()
                .contains("Invalid subscription")
        );
        connect(&mut stream, 2_500);
        assert!(!stream.disconnected());
        assert_eq!(stream.breaks, 0);
        // Silence.
        connect(&mut stream, 3_000);
        assert!(!stream.silent(3_000 + SILENCE_MS));
        assert!(stream.silent(3_001 + SILENCE_MS));
    }

    #[test]
    fn a_snapshot_behind_the_venues_clock_is_stale() {
        let mut stream = StreamState::new(user(), &[]);
        connect(&mut stream, 0);
        for message in [state("", 100_000), orders(""), mids("")] {
            stream.apply(&message, 1_000);
        }
        assert!(stream.answers(1_100, None, None).is_ok());
        // A bbo of venue time 106,001: the snapshot is 6,001 ms behind.
        stream.apply(&bbo("BTC", 106_001, "59999", "60001"), 1_200);
        let why = stream.answers(1_300, None, None).unwrap_err().0;
        assert!(why.contains("venue's clock"), "{why}");
    }

    #[test]
    fn a_coin_needs_its_own_fresh_mark_and_mid() {
        let mut stream = StreamState::new(user(), &["xyz".to_owned()]);
        connect(&mut stream, 0);
        snapshots(&mut stream, 1_000, 1);
        assert!(
            stream.answers(1_100, None, Some("BTC")).is_err(),
            "not followed"
        );
        let subscribe = stream.follow("BTC");
        assert_eq!(
            subscribe,
            vec![
                (true, json!({"type": "activeAssetCtx", "coin": "BTC"})),
                (true, json!({"type": "bbo", "coin": "BTC"})),
                (
                    true,
                    json!({"type": "activeAssetData", "user": USER, "coin": "BTC"})
                ),
            ]
        );
        assert!(stream.follow("BTC").is_empty(), "followed once");
        stream.apply(&ctx("BTC", "60010", "60000"), 1_050);
        let why = stream.answers(1_100, None, Some("BTC")).unwrap_err().0;
        assert!(why.contains("not confirmed"), "{why}");
        confirm_changes(&mut stream, &subscribe);
        let answers = stream.answers(1_100, None, Some("BTC")).unwrap();
        assert_eq!(answers.mids["BTC"], dec!(60000));
        // A newer bbo gives the mid; the mark stays the context's.
        stream.apply(&bbo("BTC", 5, "60099", "60101"), 1_200);
        let answers = stream.answers(1_300, None, Some("BTC")).unwrap();
        assert_eq!(answers.mids["BTC"], dec!(60100));
        // An older block's bbo after it is ignored.
        stream.apply(&bbo("BTC", 4, "1", "3"), 1_250);
        let answers = stream.answers(1_300, None, Some("BTC")).unwrap();
        assert_eq!(answers.mids["BTC"], dec!(60100));
        // 1.5 s after the context: still fresh; 1.501 s: stale.
        assert!(stream.answers(2_550, None, Some("BTC")).is_ok());
        let why = stream.answers(2_551, None, Some("BTC")).unwrap_err().0;
        assert!(why.contains("mark of BTC"), "{why}");
        // A mid more than 5% from allMids' 60,000: not trusted.
        stream.apply(&ctx("BTC", "63100", "63100"), 2_600);
        let why = stream.answers(2_700, None, Some("BTC")).unwrap_err().0;
        assert!(why.contains("allMids"), "{why}");
        stream.apply(&ctx("BTC", "62900", "62900"), 2_600);
        assert!(stream.answers(2_700, None, Some("BTC")).is_ok());
        // An empty side: no mid.
        stream.apply(
            &json!({"channel": "bbo", "data": {"coin": "BTC", "time": 6, "bbo": [null, {"px": "1", "sz": "1", "n": 1}]}}),
            2_650,
        );
        assert!(stream.answers(2_700, None, Some("BTC")).is_err());
        // A HIP-3 coin by its prefixed name, no book.
        let subscribe = stream.follow("xyz:GOLD");
        assert_eq!(subscribe.len(), 3);
        confirm_changes(&mut stream, &subscribe);
        stream.apply(&ctx("xyz:GOLD", "4000", "4000"), 2_700);
        assert!(stream.answers(2_800, None, Some("xyz:GOLD")).is_ok());
        // Spot and outcome coins are never followed.
        for coin in ["@107", "PURR/USDC", "#12"] {
            assert!(stream.follow(coin).is_empty(), "{coin}");
        }
        // A reconnect forgets the coins' prices until they answer again.
        connect(&mut stream, 5_000);
        snapshots(&mut stream, 5_100, 2);
        assert!(stream.answers(5_200, None, Some("xyz:GOLD")).is_err());
        assert_eq!(stream.subscriptions().len(), 9 + 3 + 3);
    }

    #[test]
    fn positions_and_orders_are_followed_and_revalued_at_fresh_marks() {
        let mut stream = StreamState::new(user(), &[]);
        connect(&mut stream, 0);
        // Equity 1,900 with a long of 0.16 BTC valued at 60,000 (9,600).
        let position = json!([{"position": {"coin": "BTC", "szi": "0.16",
            "positionValue": "9600", "unrealizedPnl": "0", "entryPx": "60000"}}]);
        let changes = stream.apply(&state_with("", 1, "1900", position), 1_000);
        // BTC is followed at once, for its position.
        assert_eq!(changes.len(), 3);
        stream.apply(&orders(""), 1_000);
        stream.apply(&mids(""), 1_000);
        let why = stream.answers(1_100, None, None).unwrap_err().0;
        assert!(why.contains("not confirmed"), "{why}");
        confirm_changes(&mut stream, &changes);
        let why = stream.answers(1_100, None, None).unwrap_err().0;
        assert!(why.contains("no mark of BTC"), "{why}");
        // The mark falls 1% (60,000 to 59,400) after the snapshot: the
        // equity is 1,900 + 0.16 × 59,400 − 9,600 = 1,804, not 1,900; at
        // the mid of 59,450 it would be 1,812. The mid is the mid.
        stream.apply(&ctx("BTC", "59400", "59450"), 1_200);
        let answers = stream.answers(1_300, None, None).unwrap();
        assert_eq!(answers.dexes[0].1["marginSummary"]["accountValue"], "1804");
        assert_eq!(answers.mids["BTC"], dec!(59450));
        // Without a fresh mark (1.5 s on), no view at all.
        assert!(stream.answers(2_701, None, None).is_err());
        // An open ETH order: ETH followed too, and needs its prices.
        let order = json!({"channel": "openOrders", "data": {"dex": "", "user": USER,
            "orders": [{"coin": "ETH", "oid": 7, "side": "B", "limitPx": "2900", "sz": "1"}]}});
        let changes = stream.apply(&order, 1_400);
        assert_eq!(changes.len(), 3);
        assert!(stream.coins().contains("ETH"));
    }

    #[test]
    fn the_leverage_setting_counts_only_fresh_and_after_the_last_change() {
        let mut stream = StreamState::new(user(), &[]);
        connect(&mut stream, 0);
        let changes = stream.follow("BTC");
        confirm_changes(&mut stream, &changes);
        let setting = |stream: &mut StreamState, kind: &str, at: u64| {
            stream.apply(
                &json!({"channel": "activeAssetData", "data": {"user": USER, "coin": "BTC",
                    "leverage": {"type": kind, "value": 3}}}),
                at,
            );
        };
        for message in [state("", 1), orders(""), mids("")] {
            stream.apply(&message, 1_000);
        }
        stream.apply(&ctx("BTC", "60000", "60000"), 1_000);
        // None yet: no setting.
        assert_eq!(
            stream.answers(1_100, None, Some("BTC")).unwrap().leverage,
            None
        );
        setting(&mut stream, "isolated", 1_050);
        assert_eq!(
            stream.answers(1_100, None, Some("BTC")).unwrap().leverage,
            Some(Leverage {
                isolated: true,
                value: 3
            })
        );
        // Another user's, or cross: not isolated 3x.
        stream.apply(
            &json!({"channel": "activeAssetData", "data": {"user": "0x0000000000000000000000000000000000000001",
                "coin": "BTC", "leverage": {"type": "cross", "value": 9}}}),
            1_060,
        );
        assert!(
            stream
                .answers(1_100, None, Some("BTC"))
                .unwrap()
                .leverage
                .unwrap()
                .isolated
        );
        setting(&mut stream, "cross", 1_070);
        assert!(
            !stream
                .answers(1_100, None, Some("BTC"))
                .unwrap()
                .leverage
                .unwrap()
                .isolated
        );
        setting(&mut stream, "isolated", 1_080);
        // Older than 1.5 s: not used (the view itself still is, with fresh
        // snapshots and prices).
        for message in [state("", 2), orders(""), mids("")] {
            stream.apply(&message, 2_500);
        }
        stream.apply(&ctx("BTC", "60000", "60000"), 2_500);
        let answers = stream.answers(2_580, None, Some("BTC")).unwrap();
        assert!(answers.leverage.is_some());
        let answers = stream.answers(2_581, None, Some("BTC")).unwrap();
        assert_eq!(answers.leverage, None);
        // Guard sent something at 7,100: a setting that arrived before
        // 8,100 does not count.
        setting(&mut stream, "isolated", 8_000);
        for message in [state("", 3), orders(""), mids("")] {
            stream.apply(&message, 8_200);
        }
        stream.apply(&ctx("BTC", "60000", "60000"), 8_200);
        let answers = stream.answers(8_300, Some(7_100), Some("BTC")).unwrap();
        assert_eq!(answers.leverage, None);
        setting(&mut stream, "isolated", 8_250);
        let answers = stream.answers(8_300, Some(7_100), Some("BTC")).unwrap();
        assert!(answers.leverage.is_some());
    }

    fn update(oid: u64, cloid: Option<&str>, status: &str, time: i64) -> Value {
        json!({"channel": "orderUpdates", "data": [{"order": {"coin": "BTC", "oid": oid,
            "cloid": cloid, "side": "B", "limitPx": "60000", "sz": "0.01"},
            "status": status, "statusTimestamp": time}]})
    }

    #[test]
    fn a_send_the_socket_reported_needs_no_wait_but_anything_else_does() {
        let mut stream = StreamState::new(user(), &[]);
        connect(&mut stream, 0);
        for message in [state("", 1_000), orders(""), mids("")] {
            stream.apply(&message, 1_000);
        }
        assert!(stream.answers(1_100, None, None).is_ok());
        // Guard heard back at 2,000 on an IOC buy that filled (oid 7) with
        // its stop attached (client id 0x7a67..).
        stream.expect(Expectation {
            sent: 2_000,
            dex: String::new(),
            resting: Vec::new(),
            filled: vec![7],
            cancelled: Vec::new(),
            cancelled_cloids: Vec::new(),
            cloids: vec!["0x7a67aa".into()],
            reduce_only: Vec::new(),
        });
        // Nothing reported yet: the old rule (1 s after the send and a
        // snapshot after that).
        let why = stream.answers(2_100, Some(2_000), None).unwrap_err().0;
        assert!(why.contains("changed"), "{why}");
        // Its events (one came before the answer), then the venue's
        // snapshot right after them, as of the fill's time: clean at once.
        stream.apply(&update(7, None, "open", 1_950), 1_990);
        stream.apply(&update(7, None, "filled", 1_950), 2_050);
        stream.apply(&update(8, Some("0x7a67aa"), "open", 1_950), 2_050);
        let why = stream.answers(2_060, Some(2_000), None).unwrap_err().0;
        assert!(
            why.contains("Guard just sent") || why.contains("changed"),
            "{why}"
        );
        stream.apply(&orders(""), 2_070);
        stream.apply(&state("", 1_950), 2_070);
        assert!(stream.answers(2_100, Some(2_000), None).is_ok());
        // A snapshot older by the venue's clock than the fill would not do.
        stream.apply(&update(7, None, "filled", 1_960), 2_110);
        let why = stream.answers(2_120, Some(2_000), None).unwrap_err().0;
        assert!(why.contains("Guard just sent"), "{why}");
        stream.apply(&orders(""), 2_130);
        stream.apply(&state("", 1_960), 2_130);
        assert!(stream.answers(2_140, Some(2_000), None).is_ok());
        // The stop filling (an event of Guard's order, but not one its send
        // brought): the account changed, so the old rule.
        stream.apply(&update(8, Some("0x7a67aa"), "filled", 2_200), 2_250);
        let why = stream.answers(2_300, Some(2_000), None).unwrap_err().0;
        assert!(why.contains("changed"), "{why}");
        // Another app's order: likewise, even right after a snapshot.
        let mut stream = StreamState::new(user(), &[]);
        connect(&mut stream, 0);
        for message in [state("", 1_000), orders(""), mids("")] {
            stream.apply(&message, 1_000);
        }
        stream.apply(&update(99, None, "open", 1_100), 1_200);
        stream.apply(&orders(""), 1_210);
        stream.apply(&state("", 1_100), 1_210);
        let why = stream.answers(1_300, None, None).unwrap_err().0;
        assert!(why.contains("changed"), "{why}");
        // A send whose reports are incomplete (the cancel's never came):
        // the old rule.
        stream.expect(Expectation {
            sent: 3_000,
            dex: String::new(),
            resting: vec![5],
            filled: Vec::new(),
            cancelled: vec![4],
            cancelled_cloids: Vec::new(),
            cloids: Vec::new(),
            reduce_only: Vec::new(),
        });
        stream.apply(&update(5, None, "open", 2_990), 3_010);
        stream.apply(&orders(""), 3_020);
        stream.apply(&state("", 2_990), 3_020);
        let why = stream.answers(3_100, Some(3_000), None).unwrap_err().0;
        assert!(why.contains("changed"), "{why}");
        stream.apply(&update(4, None, "canceled", 2_990), 3_110);
        stream.apply(&orders(""), 3_120);
        stream.apply(&state("", 2_990), 3_120);
        assert!(stream.answers(3_200, Some(3_000), None).is_ok());
        // A close (oid 9) that emptied the position: the venue cancels the
        // stop resting on it (oid 8) in the fill's batch, then the
        // snapshot; as recorded on testnet.
        stream.expect(Expectation {
            sent: 4_000,
            dex: String::new(),
            resting: Vec::new(),
            filled: vec![9],
            cancelled: Vec::new(),
            cancelled_cloids: Vec::new(),
            cloids: Vec::new(),
            reduce_only: vec![8],
        });
        stream.apply(&update(9, None, "open", 3_990), 4_010);
        stream.apply(&update(9, None, "filled", 3_990), 4_010);
        stream.apply(
            &update(8, Some("0x7a67aa"), "reduceOnlyCanceled", 3_990),
            4_010,
        );
        stream.apply(&orders(""), 4_010);
        stream.apply(&state("", 3_990), 4_010);
        assert!(stream.answers(4_100, Some(4_000), None).is_ok());
        // One arriving after the snapshot needs the next snapshot.
        stream.apply(
            &update(8, Some("0x7a67aa"), "reduceOnlyCanceled", 3_990),
            4_120,
        );
        let why = stream.answers(4_130, Some(4_000), None).unwrap_err().0;
        assert!(why.contains("Guard just sent"), "{why}");
        // Another order's reduce-only cancel (not resting on the coin
        // when Guard sent): the old rule.
        stream.apply(&update(77, None, "reduceOnlyCanceled", 3_990), 4_140);
        stream.apply(&orders(""), 4_150);
        stream.apply(&state("", 3_990), 4_150);
        let why = stream.answers(4_200, Some(4_000), None).unwrap_err().0;
        assert!(why.contains("changed"), "{why}");
    }

    fn exp(sent: u64, dex: &str) -> Expectation {
        Expectation {
            sent,
            dex: dex.to_owned(),
            resting: Vec::new(),
            filled: Vec::new(),
            cancelled: Vec::new(),
            cancelled_cloids: Vec::new(),
            cloids: Vec::new(),
            reduce_only: Vec::new(),
        }
    }

    /// A dex's account, open orders and mids arriving at `at`, the
    /// account as of venue time `time`.
    fn snap(stream: &mut StreamState, dex: &str, at: u64, time: i64) {
        stream.apply(&state(dex, time), at);
        stream.apply(&orders(dex), at);
        stream.apply(&mids(dex), at);
    }

    /// A clean stream of the main dex and xyz, snapshots at 1,000.
    fn quiet() -> StreamState {
        let mut stream = StreamState::new(user(), &["xyz".to_owned()]);
        connect(&mut stream, 0);
        snap(&mut stream, "", 1_000, 1_000);
        snap(&mut stream, "xyz", 1_000, 1_000);
        assert!(stream.answers(1_100, None, None).is_ok());
        stream
    }

    fn why(stream: &StreamState, now: u64, last: u64) -> String {
        stream.answers(now, Some(last), None).unwrap_err().0
    }

    #[test]
    fn every_reported_send_needs_its_own_dexes_snapshots_after_it() {
        // Send A on xyz filled (oid 7), reported at 1,990; send B on the
        // main dex cancelled oid 9, reported at 2,290 with the main dex's
        // snapshots after it. xyz's account is still the one from before
        // A: not clean, though B was the last send and is reported.
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            ..exp(2_000, "xyz")
        });
        stream.apply(&update(7, None, "open", 1_990), 1_990);
        stream.apply(&update(7, None, "filled", 1_990), 1_990);
        stream.expect(Expectation {
            cancelled: vec![9],
            ..exp(2_300, "")
        });
        stream.apply(&update(9, None, "canceled", 2_290), 2_290);
        snap(&mut stream, "", 2_310, 2_290);
        let reason = why(&stream, 2_350, 2_300);
        assert!(reason.contains("xyz's snapshot predates"), "{reason}");
        // xyz's snapshots after A: clean (A also needed the main dex's,
        // which came after it).
        snap(&mut stream, "xyz", 2_320, 2_290);
        assert!(stream.answers(2_350, Some(2_300), None).is_ok());

        // A main-dex send needs only the main dex's: xyz's from before it
        // do.
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            ..exp(2_000, "")
        });
        stream.apply(&update(7, None, "filled", 1_990), 1_990);
        snap(&mut stream, "", 2_010, 1_990);
        assert!(stream.answers(2_050, Some(2_000), None).is_ok());

        // An xyz send needs the main dex's too (its margin may come from
        // there).
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            ..exp(2_000, "xyz")
        });
        stream.apply(&update(7, None, "filled", 1_990), 1_990);
        snap(&mut stream, "xyz", 2_010, 1_990);
        let reason = why(&stream, 2_050, 2_000);
        assert!(
            reason.contains("the main dex's snapshot predates"),
            "{reason}"
        );
        snap(&mut stream, "", 2_020, 1_990);
        assert!(stream.answers(2_050, Some(2_000), None).is_ok());
    }

    #[test]
    fn a_send_without_reports_or_not_reported_in_full_counts_as_a_change() {
        // A send of the last two not reported (no events): the old rule,
        // though the one before it is.
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            ..exp(2_000, "")
        });
        stream.apply(&update(7, None, "filled", 1_990), 1_990);
        stream.expect(Expectation {
            resting: vec![8],
            ..exp(2_100, "")
        });
        snap(&mut stream, "", 2_150, 1_995);
        snap(&mut stream, "xyz", 2_150, 1_995);
        assert!(why(&stream, 2_200, 2_100).contains("changed"));
        // A send Guard names as its last that the stream never recorded:
        // the old rule.
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            ..exp(2_000, "")
        });
        stream.apply(&update(7, None, "filled", 1_990), 1_990);
        snap(&mut stream, "", 2_010, 1_990);
        assert!(stream.answers(2_050, Some(2_000), None).is_ok());
        assert!(why(&stream, 2_050, 2_040).contains("changed"));
        // A send on a dex the stream does not follow: the old rule.
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            ..exp(2_000, "abc")
        });
        stream.apply(&update(7, None, "filled", 1_990), 1_990);
        snap(&mut stream, "", 2_010, 1_990);
        snap(&mut stream, "xyz", 2_010, 1_990);
        assert!(why(&stream, 2_050, 2_000).contains("changed"));
        // A filled order reported only as open; a resting one reported
        // only as filled; a cancel reported as open: not in full.
        for (expected, status) in [
            (
                Expectation {
                    filled: vec![7],
                    ..exp(2_000, "")
                },
                "open",
            ),
            (
                Expectation {
                    resting: vec![7],
                    ..exp(2_000, "")
                },
                "filled",
            ),
            (
                Expectation {
                    cancelled: vec![7],
                    ..exp(2_000, "")
                },
                "open",
            ),
        ] {
            let mut stream = quiet();
            stream.expect(expected);
            stream.apply(&update(7, None, status, 1_990), 1_990);
            snap(&mut stream, "", 2_010, 1_990);
            snap(&mut stream, "xyz", 2_010, 1_990);
            assert!(why(&stream, 2_050, 2_000).contains("changed"), "{status}");
        }
        // A cancelled entry's attached stop (by client id) must report
        // its cancel too.
        let mut stream = quiet();
        stream.expect(Expectation {
            cancelled: vec![7],
            cancelled_cloids: vec!["0x7a67bb".into()],
            ..exp(2_000, "")
        });
        stream.apply(&update(7, None, "canceled", 1_990), 1_990);
        snap(&mut stream, "", 2_010, 1_990);
        assert!(why(&stream, 2_050, 2_000).contains("changed"));
        stream.apply(&update(8, Some("0x7a67bb"), "canceled", 1_990), 2_020);
        snap(&mut stream, "", 2_030, 1_990);
        assert!(stream.answers(2_050, Some(2_000), None).is_ok());
    }

    #[test]
    fn only_the_statuses_a_send_brings_are_its_own() {
        // Two orders rested; only one reported: not in full.
        let mut stream = quiet();
        stream.expect(Expectation {
            resting: vec![5, 6],
            ..exp(2_000, "")
        });
        stream.apply(&update(5, None, "open", 1_990), 1_990);
        snap(&mut stream, "", 2_010, 1_990);
        snap(&mut stream, "xyz", 2_010, 1_990);
        assert!(why(&stream, 2_050, 2_000).contains("changed"));
        // A rested order reported, then cancelled by the venue: the cancel
        // is not the send's.
        let mut stream = quiet();
        stream.expect(Expectation {
            resting: vec![5],
            ..exp(2_000, "")
        });
        stream.apply(&update(5, None, "open", 1_990), 1_990);
        stream.apply(&update(5, None, "canceled", 1_995), 2_000);
        snap(&mut stream, "", 2_010, 1_995);
        snap(&mut stream, "xyz", 2_010, 1_995);
        assert!(why(&stream, 2_050, 2_000).contains("changed"));
        // A cancelled entry's stop reported cancelled, then filled: the
        // fill is not the send's.
        let mut stream = quiet();
        stream.expect(Expectation {
            cancelled: vec![7],
            cancelled_cloids: vec!["0x7a67bb".into()],
            ..exp(2_000, "")
        });
        stream.apply(&update(7, None, "canceled", 1_990), 1_990);
        stream.apply(&update(8, Some("0x7a67bb"), "canceled", 1_990), 1_990);
        stream.apply(&update(8, Some("0x7a67bb"), "filled", 1_995), 2_000);
        snap(&mut stream, "", 2_010, 1_995);
        snap(&mut stream, "xyz", 2_010, 1_995);
        assert!(why(&stream, 2_050, 2_000).contains("changed"));
    }

    fn update_untimed(oid: u64, status: &str) -> Value {
        json!({"channel": "orderUpdates", "data": [{"order": {"coin": "BTC", "oid": oid,
            "side": "B", "limitPx": "60000", "sz": "0.01"}, "status": status}]})
    }

    #[test]
    fn the_newest_report_of_any_send_on_a_dex_is_what_its_snapshots_must_follow() {
        // Send A (2,000, oid 7) and send B (2,100, oid 8) on the main dex.
        // B's events came first (2,050), then the snapshot (2,060), then
        // A's (2,070): the snapshot predates A's reports.
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            ..exp(2_000, "")
        });
        stream.expect(Expectation {
            filled: vec![8],
            ..exp(2_100, "")
        });
        stream.apply(&update(8, None, "filled", 2_040), 2_050);
        snap(&mut stream, "", 2_060, 2_045);
        stream.apply(&update(7, None, "filled", 2_040), 2_070);
        assert!(why(&stream, 2_150, 2_100).contains("Guard just sent"));
        // A's reports first and later by the venue's clock (2,048) than the
        // snapshot after both (2,045): not yet either.
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            ..exp(2_000, "")
        });
        stream.expect(Expectation {
            filled: vec![8],
            ..exp(2_100, "")
        });
        stream.apply(&update(7, None, "filled", 2_048), 2_030);
        stream.apply(&update(8, None, "filled", 2_040), 2_050);
        snap(&mut stream, "", 2_060, 2_045);
        assert!(why(&stream, 2_150, 2_100).contains("Guard just sent"));
    }

    #[test]
    fn own_events_need_their_time_their_window_and_their_status() {
        // Reported without the venue's time: not in full.
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            ..exp(2_000, "")
        });
        stream.apply(&update_untimed(7, "filled"), 1_990);
        snap(&mut stream, "", 2_010, 1_990);
        snap(&mut stream, "xyz", 2_010, 1_990);
        assert!(why(&stream, 2_050, 2_000).contains("changed"));
        // An event of oid 7 more than 5 s after the send is not its.
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            ..exp(2_000, "")
        });
        stream.apply(&update(7, None, "filled", 1_990), 1_990);
        stream.apply(&update(7, None, "filled", 7_090), 7_100);
        snap(&mut stream, "", 7_110, 7_090);
        snap(&mut stream, "xyz", 7_110, 7_090);
        assert!(why(&stream, 7_150, 2_000).contains("changed"));
        // A cancelled order reported cancelled, then open again: not the
        // send's.
        let mut stream = quiet();
        stream.expect(Expectation {
            cancelled: vec![7],
            ..exp(2_000, "")
        });
        stream.apply(&update(7, None, "canceled", 1_990), 1_990);
        stream.apply(&update(7, None, "open", 1_995), 2_000);
        snap(&mut stream, "", 2_010, 1_995);
        snap(&mut stream, "xyz", 2_010, 1_995);
        assert!(why(&stream, 2_050, 2_000).contains("changed"));
        // A send not reported in full (oid 8 never came) explains nothing:
        // another app's order under one of its client ids is a change.
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            resting: vec![8],
            cloids: vec!["0xabc".into()],
            ..exp(2_000, "")
        });
        stream.apply(&update(7, None, "filled", 1_990), 1_990);
        snap(&mut stream, "", 3_010, 1_990);
        snap(&mut stream, "xyz", 3_010, 1_990);
        assert!(stream.answers(3_100, Some(2_000), None).is_ok());
        stream.apply(&update(99, Some("0xabc"), "open", 3_990), 4_000);
        assert!(why(&stream, 4_100, 2_000).contains("changed"));
    }

    #[test]
    fn events_a_send_did_not_bring_are_changes_of_the_account() {
        // Each of these after a fully reported fill of oid 7 (its client
        // id 0x7a74aa, a stop 0x7a67aa sent with it, a reduce-only order
        // 8 on its coin): the account changed, the old rule.
        let events = [
            // The stop itself triggering.
            update(9, Some("0x7a67aa"), "filled", 1_995),
            // The reduce-only order filling instead of being cancelled.
            update(8, None, "filled", 1_995),
            // Oid 7 again, but its order cancelled by the venue.
            update(7, None, "marginCanceled", 1_995),
        ];
        for event in events {
            let mut stream = quiet();
            stream.expect(Expectation {
                filled: vec![7],
                cloids: vec!["0x7a67aa".into()],
                reduce_only: vec![8],
                ..exp(2_000, "")
            });
            stream.apply(&update(7, None, "filled", 1_990), 1_990);
            stream.apply(&event, 2_000);
            snap(&mut stream, "", 2_010, 1_995);
            snap(&mut stream, "xyz", 2_010, 1_995);
            assert!(why(&stream, 2_050, 2_000).contains("changed"), "{event}");
        }
        // An event of oid 7 more than 5 s before the send is not its.
        let mut stream = quiet();
        stream.expect(Expectation {
            filled: vec![7],
            ..exp(8_000, "")
        });
        stream.apply(&update(7, None, "filled", 1_990), 1_990);
        snap(&mut stream, "", 8_010, 7_990);
        snap(&mut stream, "xyz", 8_010, 7_990);
        assert!(why(&stream, 8_050, 8_000).contains("changed"));
        // An outside event's venue time later than a snapshot that came a
        // second after it: the snapshot predates it.
        let mut stream = quiet();
        stream.apply(&update(99, None, "open", 5_000), 1_100);
        snap(&mut stream, "", 2_200, 4_000);
        snap(&mut stream, "xyz", 2_200, 4_000);
        let reason = stream.answers(2_300, None, None).unwrap_err().0;
        assert!(
            reason.contains("last event by the venue's clock"),
            "{reason}"
        );
    }

    #[test]
    fn a_reported_send_needs_its_dexs_snapshots_after_by_order_and_by_clock() {
        // The snapshots arrived after the events but as of a venue time
        // before them: not yet.
        let mut stream = quiet();
        stream.expect(Expectation {
            resting: vec![5],
            ..exp(2_000, "")
        });
        stream.apply(&update(5, None, "open", 2_000), 2_010);
        snap(&mut stream, "", 2_020, 1_990);
        assert!(why(&stream, 2_050, 2_000).contains("Guard just sent"));
        snap(&mut stream, "", 2_030, 2_000);
        assert!(stream.answers(2_050, Some(2_000), None).is_ok());
        // The open orders from before the events, the account after.
        let mut stream = quiet();
        stream.expect(Expectation {
            resting: vec![5],
            ..exp(2_000, "")
        });
        stream.apply(&orders(""), 2_005);
        stream.apply(&update(5, None, "open", 1_990), 2_010);
        stream.apply(&state("", 2_000), 2_020);
        assert!(why(&stream, 2_050, 2_000).contains("Guard just sent"));
        // The account from before, the open orders after.
        let mut stream = quiet();
        stream.expect(Expectation {
            resting: vec![5],
            ..exp(2_000, "")
        });
        stream.apply(&state("", 2_000), 2_005);
        stream.apply(&update(5, None, "open", 1_990), 2_010);
        stream.apply(&orders(""), 2_020);
        assert!(why(&stream, 2_050, 2_000).contains("Guard just sent"));
        // Both after, but not from one batch (open orders alone again,
        // after the account): not used.
        let mut stream = quiet();
        stream.expect(Expectation {
            resting: vec![5],
            ..exp(2_000, "")
        });
        stream.apply(&update(5, None, "open", 1_990), 2_010);
        stream.apply(&state("", 2_000), 2_020);
        stream.apply(&orders(""), 2_020);
        stream.apply(&orders(""), 2_030);
        assert!(why(&stream, 2_050, 2_000).contains("Guard just sent"));
        stream.apply(&state("", 2_000), 2_040);
        assert!(stream.answers(2_050, Some(2_000), None).is_ok());
    }

    #[test]
    fn a_leverage_update_keeps_the_setting_before_it_out_after_a_reported_order() {
        // Isolated 3x shown at 1,050; Guard sends updateLeverage (answered
        // at 1,200, nothing to report), then an entry resting as oid 5,
        // reported at once.
        let mut stream = StreamState::new(user(), &[]);
        connect(&mut stream, 0);
        let changes = stream.follow("BTC");
        confirm_changes(&mut stream, &changes);
        let setting = |stream: &mut StreamState, at: u64| {
            stream.apply(
                &json!({"channel": "activeAssetData", "data": {"user": USER, "coin": "BTC",
                    "leverage": {"type": "isolated", "value": 3}}}),
                at,
            );
        };
        snap(&mut stream, "", 1_000, 1_000);
        stream.apply(&ctx("BTC", "60000", "60000"), 1_000);
        setting(&mut stream, 1_050);
        stream.sent(1_200, None);
        stream.expect(Expectation {
            resting: vec![5],
            ..exp(1_400, "")
        });
        stream.apply(&update(5, None, "open", 1_390), 1_390);
        snap(&mut stream, "", 1_450, 1_390);
        stream.apply(&ctx("BTC", "60000", "60000"), 1_450);
        // The update counts as a change: snapshots from 2,200 on.
        assert!(why(&stream, 1_600, 1_400).contains("changed"));
        setting(&mut stream, 2_000);
        snap(&mut stream, "", 2_250, 1_900);
        stream.apply(&ctx("BTC", "60000", "60000"), 2_250);
        let answers = stream.answers(2_300, Some(1_400), Some("BTC")).unwrap();
        assert_eq!(answers.leverage, None, "shown before the update counts");
        setting(&mut stream, 2_260);
        let answers = stream.answers(2_300, Some(1_400), Some("BTC")).unwrap();
        assert!(answers.leverage.is_some());
    }

    #[test]
    fn coins_nothing_needs_are_dropped_beyond_the_most() {
        let mut stream = StreamState::new(user(), &[]);
        for n in 0..MAX_COINS {
            stream.follow(&format!("C{n}"));
        }
        let changes = stream.follow("NEW");
        // The new one subscribed, the oldest unsubscribed.
        assert_eq!(
            changes,
            vec![
                (true, json!({"type": "activeAssetCtx", "coin": "NEW"})),
                (true, json!({"type": "bbo", "coin": "NEW"})),
                (
                    true,
                    json!({"type": "activeAssetData", "user": USER, "coin": "NEW"})
                ),
                (false, json!({"type": "activeAssetCtx", "coin": "C0"})),
                (false, json!({"type": "bbo", "coin": "C0"})),
                (
                    false,
                    json!({"type": "activeAssetData", "user": USER, "coin": "C0"})
                ),
            ]
        );
        assert_eq!(stream.coins().len(), MAX_COINS);
        assert!(!stream.coins().contains("C0"));
        // A coin with a position is never dropped: C1 held, C2 goes.
        let position = json!([{"position": {"coin": "C1", "szi": "1",
            "positionValue": "1", "unrealizedPnl": "0"}}]);
        stream.connected(0);
        stream.apply(&state_with("", 1, "1", position), 1);
        stream.follow("NEWER");
        assert!(stream.coins().contains("C1"));
        assert!(!stream.coins().contains("C2"));
    }
}
