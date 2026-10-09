// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The local Guard: one account, one policy, one risk journal, one
//! decision journal, and the requests of its clients, one at a time.
//!
//! For each `/exchange` request (HTTP or a WebSocket `post`):
//!
//! 1. check the kill file, decode and authenticate the request
//!    ([`zunder_guard_core::admit`]);
//! 2. read the account fresh from the venue (meta cached for a minute);
//! 3. show the risk engine the account ([`PersistentRisk::observe_view`],
//!    written to the risk journal) and flatten if it halted or the kill
//!    switch is on;
//! 4. judge ([`zunder_guard_core::judge::judge`]);
//! 5. write the decision to the decision journal, synced;
//! 6. paper mode: answer what would have happened. Sending: sign each
//!    action with the API wallet key and a fresh Guard nonce; send the
//!    leverage update first and read it back; send the action; if an entry
//!    filled but its stop was refused, close it at once; record a filled,
//!    protected entry with the risk engine; cancel Guard's own stop once a
//!    tighter stop of the bot's rests; answer with the venue's reply in the
//!    bot's order.
//!
//! A background sync reads the account every `sync_seconds`, feeds the
//! risk engine and flattens on a halt or the kill switch, also when no bot
//! sends anything, and from the positions alone when the rest of the
//! account cannot be read.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::future::join_all;
use rust_decimal::Decimal;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use zunder_core::{Symbol, Timestamp};
use zunder_guard_core::{
    Refusal,
    account::{
        AccountView, AssetKind, Book, DexAnswers, Meta, asset_kind, book_sig_figs,
        confirms_isolated, parse_perp_dexs, requests,
    },
    action::{Action, ExchangeRequest, decode_action_value},
    admit,
    auth::{Authenticated, Authenticator},
    event::{EVENT_SCHEMA, EventBody},
    flow_value,
    judge::{Context, Decision, Forward, Verdict, judge, protect_actions_with},
    ledger::ledger_flow,
    licence::{self, FeeMode, FeeState},
    reply::{
        OrderStatus, action_ok, client_reply, close_action, flatten_actions, order_statuses,
        paper_reply, signed_request, veto_reply,
    },
    sign::{Address, GuardKey, SigningNetwork},
};
use zunder_risk::RiskState;
use zunder_venue::{Flow, FlowOutcome, PersistentRisk};

use crate::{
    config::GuardConfig,
    journal::DecisionJournal,
    rules,
    stream::{Expectation, Stream, monotonic_ms},
    upstream::{Upstream, UpstreamError},
};

/// How long an action Guard signs stays valid on the venue.
pub const ACTION_TTL_MS: u64 = 30_000;
/// How long `updateLeverage` stays valid: the session's 10 s.
pub const LEVERAGE_TTL_MS: u64 = 10_000;
/// How long the venue's `meta` is reused (the main dex's and each HIP-3
/// dex's: a deployer's halt shows there within this).
const META_TTL_MS: u64 = 60_000;
/// How long `perpDexs` (weight 20) is reused: the list only grows, and a
/// dex keeps its index.
const PERP_DEXS_TTL_MS: u64 = 600_000;
/// How long a HIP-3 dex's `perpsAtOpenInterestCap` (weight 20) is reused.
/// Stale only costs a needless veto, or a venue refusal: the venue itself
/// takes no order that adds to a capped market.
const OPEN_INTEREST_CAP_TTL_MS: u64 = 60_000;
/// How often the background sync looks at one perp dex Guard does not
/// manage (`clearinghouseState`, weight 2), to report positions there.
const SWEEP_EVERY_MS: u64 = 30_000;
/// The background sync's share of the venue's request weight a minute:
/// 288 for the reads themselves (24 a dex, every 5 s with the main dex
/// alone), and about 46 for what is cached (the account mode, the main
/// dex's `meta`, `perpDexs`, the sweep). Each HIP-3 dex adds 24 a read and
/// 40 a minute cached (its `meta` and its open-interest caps); the sync
/// slows down so that the total stays at this ([`crate::budget::plan`],
/// which also fits it to `ip_share`).
pub(crate) const SYNC_WEIGHT_PER_MINUTE: u64 = 334;
/// The cached part of the sync's weight a minute, besides the reads: 46
/// with the main dex alone, 40 more per HIP-3 dex.
pub(crate) const SYNC_CACHED_WEIGHT: u64 = 46;
pub(crate) const SYNC_CACHED_WEIGHT_PER_DEX: u64 = 40;
/// How long after Guard last heard back from the venue its view does not
/// count as settled: the risk engine's record then keeps what the view may
/// not show yet (a fill just reported, say).
pub const SETTLE_MS: u64 = 5_000;
/// Most refused requests journaled a minute; the rest are counted.
pub const REFUSALS_JOURNALED_PER_MINUTE: u32 = 60;
/// Vetoes journaled a minute at most for each client; beyond, they are
/// counted, and the count journaled the next minute. Per client: one bot
/// looping on refused orders does not leave another's vetoes unjournaled.
pub const VETOES_JOURNALED_PER_MINUTE: u32 = 600;
/// The venue's request weight a second that `/info` passthrough (HTTP and
/// WebSocket info posts, uncached) may spend on average: 2 of weight a
/// second, 120 of Hyperliquid's 1,200 a minute per IP. The worst minute,
/// every budget's burst spent in it: the sync 334
/// ([`SYNC_WEIGHT_PER_MINUTE`]) and one extra read of every dex after a send
/// overtook one (24 a dex); the requests ([`Limits::for_hip3_dexes`]:
/// reading the account, a HIP-3 entry's book, halted reads to flatten, and
/// every forwarded action with its leverage read-back); reduce-only orders
/// forwarded on a spent budget, at most 2 of weight a second and bursts of
/// 5 each ([`EXITS_PER_SECOND`]), 130; the passthrough 120 and a burst of
/// 160. Main dex alone: 334 + 24 + 240 + 60 + 130 + 280 = 1,068; one HIP-3
/// dex: 334 + 48 + 240 + 76 + 130 + 280 = 1,108; two: 334 + 72 + 180 +
/// 100 + 130 + 280 = 1,096. That leaves 92 at least for what no budget holds
/// (protection's and flattening's own sends, the sync's builder-fee check,
/// 20 a minute while unapproved, the ledger read, 20 a minute while the
/// account stream is down, a stop looked up after a send that got no
/// answer). These are the budgets of a Guard alone on its IP address
/// (`ip_share` 1); with a smaller share every one is fitted to it
/// ([`crate::budget::plan`]).
pub const INFO_WEIGHT_PER_SECOND: u64 = 2;
/// How much unspent passthrough weight may build up (a burst).
pub const INFO_WEIGHT_BURST: u64 = 160;
/// The venue's request weight a second that bots' requests may spend on
/// average: reading the account (24 a dex), a HIP-3 entry's book (2), and
/// what a forwarded request sends (1 an action, 20 more to read back
/// isolated leverage Guard set): 240 a minute with the main dex alone or
/// one HIP-3 dex, 180 with two ([`Limits::for_hip3_dexes`]).
/// Beyond it Guard refuses requests with `rate_limited` (reduce-only
/// orders still go, unjudged), so the background sync, protection and
/// flattening always keep their share.
pub const REQUEST_WEIGHT_PER_SECOND: u64 = 4;
/// Reduce-only orders that arrive on a spent request budget go within an
/// allowance of 1 of weight a second (a burst of 5); beyond that only one
/// that reduces a position the last view shows, within 1 of weight a second
/// more (a burst of 5). Those that go are charged to the request budget all
/// the same (into debt, at most one burst deep, so that the bot's other
/// requests wait); the others are refused `rate_limited` and cost nothing.
pub const EXITS_PER_SECOND: u64 = 1;
pub(crate) const EXITS_BURST: u64 = 5;
/// How much unspent request weight may build up: two reads and a half,
/// or 60 entries that need no leverage set first.
pub const REQUEST_WEIGHT_BURST: u64 = 60;
/// What one read of the account costs: `clearinghouseState` and `allMids`
/// 2 each, `frontendOpenOrders` 20 (the account mode and `meta` cached).
pub(crate) const ACCOUNT_READ_WEIGHT: u64 = 24;
/// The venue's request weight of an `l2Book` read.
pub(crate) const BOOK_READ_WEIGHT: u64 = 2;
/// The venue's request weight of reading isolated leverage back
/// (`activeAssetData`).
pub(crate) const LEVERAGE_READ_WEIGHT: u64 = 20;
/// The sync reads the account holding Guard's lock (one read, no chance
/// of being overtaken) when Guard heard back on a send this recently: a
/// bot that is sending will likely send again during an unlocked read.
const SYNC_LOCKED_AFTER_SEND_MS: u64 = 2_000;
/// How long Guard reuses the venue's account mode (`userAbstraction`,
/// weight 20), which changes only when a person changes it.
const MODE_TTL_MS: u64 = 60_000;
/// The oldest account view a preview answers from (it never reads the
/// venue itself).
const PREVIEW_VIEW_MAX_AGE_MS: u64 = 60_000;
/// The longest one account read made holding Guard's lock may take: the
/// sync's when a send overtook its read without the lock, a halted
/// request's to flatten (that one may also read the positions alone after
/// it, as long again, and then send the closes).
const LOCKED_READ_MS: u64 = 5_000;
/// While halted or killed, a request reads the account to flatten at most
/// this often (within the request-read budget); the sync retries anyway.
const HALT_READ_EVERY_MS: u64 = 3_000;
/// The ledger is read over HTTP when an observation would halt the
/// engine, at most this often (weight 20 each; once halted, no observation
/// would halt it again).
const LEDGER_READ_EVERY_MS: u64 = 1_000;
/// An entry Guard forwarded that rests with its stop, followed until it
/// fills and while its position is open ([`Guard::follow_resting`]).
#[derive(Debug, Clone)]
struct RestingEntry {
    oid: u64,
    coin: String,
    side: zunder_core::Side,
    /// Its size as forwarded.
    qty: rust_decimal::Decimal,
    /// The stop it was sized for.
    stop: rust_decimal::Decimal,
    /// The position on its side when it was sent.
    held_before: rust_decimal::Decimal,
    /// Its fill explains the position now (grown beyond `held_before` by
    /// at most `qty`).
    filled: bool,
    /// Complete reads in a row that found it gone without growth.
    gone_reads: u8,
}

/// How many resting entries' attached stops Guard remembers, to know a
/// cancel of the entry cancels them too.
const ATTACHED_KEPT: usize = 256;
/// After a read that failed, the next one waits this long (at most 4
/// attempts of 20 in a 10 s hold).
const LEDGER_RETRY_MS: u64 = 3_000;
/// And every minute while the account stream, which reports the ledger as
/// it changes, is not connected (20 a minute), every 5 minutes while it is
/// (4 a minute: an entry it missed), and after it reconnected.
const LEDGER_READ_WITHOUT_STREAM_MS: u64 = 60_000;
const LEDGER_READ_PERIODIC_MS: u64 = 300_000;
/// How long a loss that would halt the engine is held back while the
/// ledger cannot be read to tell it from a withdrawal, counted from the
/// first such view until a complete read: then it counts
/// (`docs/guard.md#deposits-and-withdrawals`).
const LEDGER_HOLD_MS: u64 = 10_000;
/// A ledger read tells a view's loss from a withdrawal only when it began
/// at least this long after the view was read: the ledger may be served by
/// a node a little behind the one that served the view (the margin the
/// spec allows the venue's times, `FLOW_TIME_MARGIN_MS`).
const LEDGER_LAG_MS: u64 = zunder_venue::FLOW_TIME_MARGIN_MS.unsigned_abs();
/// Each ledger read starts this far before the newest entry of the last
/// complete one, so that an entry the venue showed late is not missed
/// (duplicates are recognised by id).
const LEDGER_OVERLAP_MS: i64 = 60_000;
/// How long the risk engine may leave out every view (each one may or may
/// not show a flow: a stuck dex time, an emptied account) before new
/// positions are refused (D6).
const VIEWS_LEFT_OUT_MS: u64 = 10_000;
/// How long one ledger read may take (it runs under Guard's lock), all its
/// pages together.
const LEDGER_READ_MS: u64 = 3_000;
/// The venue's ledger page (Hyperliquid answers up to 2,000 entries; this
/// repository's adapter assumed 500), and how many pages one read takes
/// at most.
const LEDGER_PAGE_LEN: usize = 500;
const LEDGER_PAGES: usize = 4;

/// How long Guard waits for a settled view before protecting anyway: a bot
/// that sends every few seconds must not keep an unprotected position
/// unprotected.
pub(crate) const PROTECT_AT_LEAST_EVERY_MS: u64 = 30_000;
/// The venue's request weight of a `maxBuilderFee` read (an info request
/// of the default weight). The periodic check runs at most once a minute.
pub(crate) const FEE_CHECK_WEIGHT: u64 = 20;
/// How long an alert about a fill Guard had to close stays in the status.
const ALERT_KEEP_MS: u64 = 3_600_000;
/// Most previews a second.
pub const PREVIEWS_PER_SECOND: u32 = 1;
/// The bot's own account reads answered from the stream, at most this many
/// a second; beyond, the venue answers them (within the passthrough's
/// budget).
pub const STREAM_INFO_PER_SECOND: u32 = 20;

/// The licence key Guard runs with, and what it knows of it
/// (`licence.rs`, "Lifecycle").
#[derive(Debug, Clone)]
struct LicenceTrack {
    /// The key as configured (`licence` in the config file).
    key: Option<String>,
    network: licence::FeeNetwork,
    /// The key verified for Guard's account: its licensee and expiry.
    valid: Option<(String, i64)>,
    /// Why the configured key is not used, if it is not.
    error: Option<String>,
    /// The last expiry warning given: 14, 7 or 1 days.
    warned: Option<i64>,
    /// The config file read at each sync for a new licence key.
    file: Option<std::path::PathBuf>,
    /// The public key licences are checked against, and the builders a
    /// fallback charges (the production constants; tests' own).
    public_key: Option<[u8; 32]>,
    builders: (Option<String>, Option<String>),
    /// The config file could not be read for the licence (once an alert).
    file_error: Option<String>,
}

impl LicenceTrack {
    fn new(key: Option<String>, network: licence::FeeNetwork) -> Self {
        Self {
            key,
            network,
            valid: None,
            error: None,
            warned: None,
            file: None,
            public_key: licence::LICENCE_PUBLIC_KEY,
            builders: (
                licence::ORCASTRATE_BUILDER.map(str::to_owned),
                licence::ORCASTRATE_TESTNET_BUILDER.map(str::to_owned),
            ),
            file_error: None,
        }
    }

    /// The fee mode for the configured key at `now_ms`, and why the key is
    /// not used (if it is not); remembers the key's licensee and expiry.
    fn mode(&mut self, account: Address, now_ms: u64) -> (FeeMode, Option<String>) {
        let now = now_ms as i64;
        self.valid = match (&self.key, &self.public_key) {
            (Some(key), Some(public_key)) => licence::verify(key, public_key, now)
                .and_then(|licence| licence.for_account(account))
                .ok()
                .map(|licence| (licence.licensee, licence.expires_at_ms)),
            _ => None,
        };
        let (mode, warning) = licence::fee_mode_with(
            self.network,
            self.key.as_deref(),
            self.public_key.as_ref(),
            now,
            account,
            self.builders.0.as_deref(),
            self.builders.1.as_deref(),
        );
        self.error.clone_from(&warning);
        (mode, warning)
    }

    /// Whether the licence alert still says something true: a warning
    /// before the end, a key that is not used, a config file not read.
    fn alert_stays(&self) -> bool {
        self.file_error.is_some()
            || (self.key.is_some() && self.valid.is_none())
            || (self.valid.is_some() && self.warned.is_some())
    }

    /// For `/guard/status`.
    fn status(&self, now_ms: u64, auto_update: bool) -> Value {
        let now = now_ms as i64;
        let state = match (&self.key, &self.valid) {
            (None, _) => "none",
            (Some(_), Some((_, expires))) if now < *expires => "active",
            (Some(_), _) => "not_used",
        };
        json!({
            "state": state,
            "licensee": self.valid.as_ref().map(|(licensee, _)| licensee),
            "expires_at_ms": self.valid.as_ref().map(|(_, expires)| expires),
            "days_left": self.valid.as_ref().map(|(_, expires)| licence::days_left(*expires, now)),
            "error": self.error,
            "auto_update": auto_update,
        })
    }
}

/// Every licence alert starts with this, so that a newer one replaces it.
const LICENCE_ALERT: &str = "licence: ";

/// The longest recovery after a crash takes in all (waiting for expiry
/// included); what is left then is `unknown`, with an alert.
pub const RECOVERY_MS: u64 = 90_000;
/// How long recovery waits before reading an order the venue did not know
/// once more.
pub const RECOVERY_READ_AGAIN_MS: u64 = 2_000;
/// How long after an intent was written an action it names may still
/// expire, for the intent to cover it (J1): a send later than that (a slow
/// round of protection) gets an intent of its own. Recovery waits
/// [`crate::recover::MAX_TTL_MS`] after an intent, which leaves 15 s for
/// Guard's clock running ahead of the venue's.
pub const INTENT_COVERS_MS: u64 = ACTION_TTL_MS + 10_000;
// Recovery's expiry margin covers the longest an action Guard sends stays
// valid after its intent, plus 15 s of the two clocks.
const _: () = assert!(
    (INTENT_COVERS_MS as i64) + 15_000 <= crate::recover::MAX_TTL_MS
        && LEVERAGE_TTL_MS <= INTENT_COVERS_MS
        && INTENT_COVERS_MS as i64 == crate::recover::EXPIRES_WITHIN_MS
);

/// Hyperliquid's weight of an info request (its rate-limit documentation):
/// 2 for the light reads, 60 for `userRole`, 20 for the rest.
pub fn info_weight(kind: Option<&str>) -> u64 {
    match kind {
        Some(
            "l2Book"
            | "allMids"
            | "clearinghouseState"
            | "orderStatus"
            | "spotClearinghouseState"
            | "exchangeStatus",
        ) => 2,
        Some("userRole") => 60,
        _ => 20,
    }
}

/// Milliseconds since the epoch.
pub trait Clock: Send + Sync + 'static {
    fn now_ms(&self) -> u64;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// Whether Guard sends, and where.
pub enum Mode {
    /// Judges and journals, never sends.
    Paper,
    /// Sends, signed with `key` for `network`. [`Guard::new`] refuses it
    /// unless the upstream sends to that very network.
    Send {
        key: GuardKey,
        network: SigningNetwork,
    },
}

impl Mode {
    pub fn name(&self) -> &'static str {
        match self {
            Mode::Paper => "paper",
            Mode::Send {
                network: SigningNetwork::Testnet,
                ..
            } => "testnet",
            Mode::Send {
                network: SigningNetwork::Mainnet,
                ..
            } => "mainnet",
        }
    }
}

/// The request budget (`REQUEST_WEIGHT_PER_SECOND` and
/// `REQUEST_WEIGHT_BURST` by default, made to fit the HIP-3 dexes Guard
/// reads by [`Limits::for_hip3_dexes`] and to the config's `ip_share` by
/// [`crate::budget::plan`] when the default is given). Only tests against
/// an in-memory venue raise it, where no venue limit applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub request_weight_per_second: u64,
    pub request_weight_burst: u64,
}

impl Limits {
    /// The production budget for `hip3` HIP-3 dexes: a burst that holds
    /// one read of every dex (24 each), a HIP-3 entry's book (2) and
    /// isolated leverage set and read back (22), so a request can always go
    /// after a read: 60 with the main dex alone, 76 with one HIP-3 dex,
    /// 100 with two, the refill then 3 a second instead of 4 to keep the
    /// worst minute (`INFO_WEIGHT_PER_SECOND`).
    pub fn for_hip3_dexes(hip3: usize) -> Self {
        match hip3 {
            0 => Self::default(),
            1 => Self {
                request_weight_per_second: REQUEST_WEIGHT_PER_SECOND,
                request_weight_burst: 76,
            },
            _ => Self {
                request_weight_per_second: 3,
                request_weight_burst: 100,
            },
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request_weight_per_second: REQUEST_WEIGHT_PER_SECOND,
            request_weight_burst: REQUEST_WEIGHT_BURST,
        }
    }
}

/// Everything a Guard is started with.
pub struct Setup {
    pub config: GuardConfig,
    pub mode: Mode,
    pub risk: PersistentRisk,
    pub journal: DecisionJournal,
    pub fee: FeeMode,
    /// Shown once at start: a licence key that did not verify.
    pub fee_warning: Option<String>,
    pub limits: Limits,
}

struct Inner {
    config: GuardConfig,
    account: Address,
    mode: Mode,
    auth: Authenticator,
    risk: PersistentRisk,
    journal: DecisionJournal,
    /// The builder fee: its mode and the user's approval.
    fee: FeeState,
    /// The licence key and its lifecycle: expiry, warnings, a new key in
    /// the config file.
    licence: LicenceTrack,
    killed: Option<String>,
    /// Positions in the first flatten snapshot after the kill latch.
    /// Later account reads must not replace this with the post-close count.
    positions_at_kill: Option<usize>,
    /// What reading the account needs and caches: taken out of `Inner` by
    /// the background sync while it reads, so that requests do not wait
    /// for the venue's answers.
    caches: Caches,
    /// Positions on perp dexes Guard does not manage, by dex name: found
    /// by the sweep, reported, never touched.
    unmanaged: BTreeMap<String, Unmanaged>,
    /// The sweep's place in `perpDexs`, and when it last looked.
    sweep_at: usize,
    last_sweep_ms: Option<u64>,
    last_nonce: u64,
    last_view: Option<AccountView>,
    /// The last intent on disk (a decision to send, a protection, a
    /// flattening, an `intent`): its `seq`, its time, and the actions it
    /// named, as they go out. Guard sends only an action an intent on disk
    /// names, expiring within [`INTENT_COVERS_MS`] of it
    /// (`docs/guard.md#journals`).
    intent: Option<(u64, u64, Vec<Value>)>,
    /// Where protective sends made while the decision journal cannot be
    /// written are recorded (E1).
    emergency: Emergency,
    /// Stops Guard attached to resting entries (`normalTpsl`): the entry's
    /// id and the stops' client ids, the newest [`ATTACHED_KEPT`].
    attached: VecDeque<(u64, Vec<String>)>,
    /// Entries Guard forwarded that rest with their stop, the newest
    /// [`ATTACHED_KEPT`]: once one fills, its stop counts for its position
    /// in Guard's protect pass, which then places that stop (not one at the
    /// default distance) should the venue not activate the entry's own.
    resting_entries: VecDeque<RestingEntry>,
    last_sync_ms: Option<u64>,
    last_error: Option<String>,
    /// When Guard last heard back from the venue after sending.
    last_send_ms: Option<u64>,
    /// The halt last reported, so a paper Guard journals a flatten once.
    reported_halt: Option<String>,
    /// Positions Guard found without a stop and could not protect or close
    /// (or, in paper mode, would have protected); shown in the status until
    /// a sync finds every position covered.
    position_alert: Option<String>,
    /// Other things Guard could not fix or had to fix the hard way: kept
    /// while their order rests, or for an hour.
    alerts: Vec<Alert>,
    /// When the background sync last protected the positions.
    last_protect_ms: Option<u64>,
    /// Protect at the next sync whether settled or not (an entry was just
    /// cancelled and may have filled in part).
    protect_now: bool,
    /// `last_send_ms` on the stream's monotonic clock ([`monotonic_ms`]).
    last_send_mono: Option<u64>,
    /// How many times Guard heard back from the venue after sending: the
    /// sync tells by it whether a send overtook its read.
    sends: u64,
    /// Whether the last account read over HTTP showed anything to flatten
    /// (a position or an opening order).
    last_read_exposed: Option<bool>,
    /// When a halted request last read the account to flatten.
    last_halt_read_ms: Option<u64>,
    /// Deposits and withdrawals: the ledger read over HTTP from this time
    /// on (epoch ms; `None` before the first read), when it was last read,
    /// how many flows were applied, and the last one that was not.
    ledger_from_ms: Option<i64>,
    ledger_read_ms: Option<u64>,
    /// When the ledger was last read successfully (Guard's clock), the
    /// stream's reconnects then, and the views held back for want of a
    /// read (D5).
    ledger_ok_ms: Option<u64>,
    ledger_reconnects: u64,
    ledger_hold: Option<LedgerHold>,
    /// Since when every view the risk engine was shown has been left out.
    views_left_since: Option<u64>,
    flows_applied: u64,
    flow_note: Option<String>,
    /// The sync read twice in its last round (a send overtook its first
    /// read): its next round waits one interval longer, so that its reads
    /// stay within its share of the venue's weight.
    sync_read_twice: bool,
    /// A sync that reads holding the lock for its `ip_share`
    /// ([`crate::budget::Budgets::sync_reads_locked`]) could not read within
    /// [`LOCKED_READ_MS`]: its next round reads without the lock, as at
    /// share 1, so that a slow venue never stops the sync altogether.
    sync_unlock_next: bool,
    /// How many times the last sync round read the account (1, or 2 when a
    /// send overtook its first read), for the status.
    last_sync_reads: u8,
    /// A secret of this process for Guard's stop ids.
    salt: [u8; 16],
    /// Client ids Guard gave so far (with the salt, what makes the next
    /// one unique).
    client_ids: u64,
    /// Refusals this minute: (minute, journaled, not journaled).
    refusals: (u64, u32, u32),
    /// Vetoes this minute ([`VETOES_JOURNALED_PER_MINUTE`]): (minute,
    /// journaled by client, not journaled).
    vetoes: (u64, HashMap<String, u32>, u32),
}

/// Why the account could not be read for a request: Guard's own budget for
/// the venue's request weight (`rate_limited`), or the venue
/// (`account_unreadable`).
#[derive(Debug)]
enum ReadFailure {
    Budget(String),
    Venue(UpstreamError),
}

/// What reading the account needs besides the venue: the account, the
/// HIP-3 dexes the markets name, and what is cached between reads.
#[derive(Debug, Clone)]
struct Caches {
    account: Address,
    names: std::collections::BTreeSet<String>,
    meta: Option<(Meta, u64)>,
    /// The HIP-3 dexes `perpDexs` lists, `(index, name)`, and when read.
    perp_dexs: Option<(Vec<(u32, String)>, u64)>,
    /// Each HIP-3 dex's `meta` Guard reads, by dex index, and when read.
    dex_metas: HashMap<u32, (Meta, u64)>,
    /// Each HIP-3 dex's coins at their open-interest cap, and when read.
    open_interest_caps: HashMap<u32, (Value, u64)>,
    /// Dexes the markets name that `perpDexs` does not list.
    missing_dexes: Vec<String>,
    /// The account mode and when it was read.
    mode_cache: Option<(Value, u64)>,
}

impl Caches {
    /// Take each entry of `other` that was read later than this one's: a
    /// sync that read without the lock never puts older reference data
    /// over what a request read meanwhile.
    fn take_newer(&mut self, other: Caches) {
        fn newer<T>(mine: &mut Option<(T, u64)>, theirs: Option<(T, u64)>) -> bool {
            match theirs {
                Some(theirs) if mine.as_ref().is_none_or(|held| held.1 < theirs.1) => {
                    *mine = Some(theirs);
                    true
                }
                _ => false,
            }
        }
        fn newer_each<T>(mine: &mut HashMap<u32, (T, u64)>, theirs: HashMap<u32, (T, u64)>) {
            for (index, entry) in theirs {
                if mine.get(&index).is_none_or(|held| held.1 < entry.1) {
                    mine.insert(index, entry);
                }
            }
        }
        newer(&mut self.meta, other.meta);
        if newer(&mut self.perp_dexs, other.perp_dexs) {
            self.missing_dexes = other.missing_dexes;
        }
        newer(&mut self.mode_cache, other.mode_cache);
        newer_each(&mut self.dex_metas, other.dex_metas);
        newer_each(&mut self.open_interest_caps, other.open_interest_caps);
    }
}

/// Positions on a perp dex Guard does not manage.
#[derive(Debug, Clone)]
struct Unmanaged {
    index: u32,
    coins: Vec<String>,
    value: Decimal,
    seen_ms: u64,
}

/// Something Guard could not fix, for the status.
#[derive(Debug, Clone)]
struct Alert {
    text: String,
    at_ms: u64,
    /// Kept while this order rests.
    oid: Option<u64>,
}

fn fresh_flow_view(times: &BTreeMap<String, i64>, previous: &BTreeMap<String, i64>) -> bool {
    !times.is_empty()
        && previous
            .iter()
            .all(|(dex, time)| times.get(dex).is_some_and(|next| next > time))
}

/// Views held back from the risk engine because each would halt or stop
/// it and no ledger read could yet tell its loss from a withdrawal: a run
/// of them, one after the other (D5).
#[derive(Debug, Clone)]
struct LedgerHold {
    /// When the first was held (Guard's clock): a read must begin 2 s after
    /// it to tell, and the run is counted 10 s after it at the latest.
    since: u64,
    /// The deepest of them, and when it was held: given to the engine
    /// before the view that ends the run, so that its loss counts.
    deepest: AccountView,
    deepest_at: u64,
    latest: BTreeMap<String, i64>,
}

/// A simple per-second budget.
#[derive(Debug, Default)]
struct Budget {
    second: u64,
    used: u32,
}

/// A token bucket of request weight: `milli_per_second` thousandths of
/// weight refilled a second, at most `burst` held. Starts full.
#[derive(Debug)]
struct WeightBucket {
    /// Millionths of a unit of weight; below zero when in debt.
    micro: i64,
    at_ms: Option<u64>,
    milli_per_second: u64,
    burst: u64,
}

/// Millionths of weight in `weight`.
fn micro(weight: u64) -> i64 {
    i64::try_from(weight.saturating_mul(1_000_000)).unwrap_or(i64::MAX)
}

impl WeightBucket {
    #[cfg(test)]
    fn new() -> Self {
        Self::with(INFO_WEIGHT_PER_SECOND, INFO_WEIGHT_BURST)
    }

    /// `per_second` whole units of weight a second.
    #[cfg(any(test, feature = "test-hooks"))]
    fn with(per_second: u64, burst: u64) -> Self {
        Self::of(crate::budget::Bucket {
            milli_per_second: per_second.saturating_mul(1_000),
            burst,
        })
    }

    fn of(bucket: crate::budget::Bucket) -> Self {
        Self {
            micro: micro(bucket.burst),
            at_ms: None,
            milli_per_second: bucket.milli_per_second,
            burst: bucket.burst,
        }
    }

    fn refill(&mut self, now_ms: u64) {
        let elapsed = self.at_ms.map_or(0, |at| now_ms.saturating_sub(at));
        self.at_ms = Some(now_ms);
        // Milliseconds × thousandths a second = millionths.
        let added =
            i64::try_from(elapsed.saturating_mul(self.milli_per_second)).unwrap_or(i64::MAX);
        self.micro = self.micro.saturating_add(added).min(micro(self.burst));
    }

    fn take(&mut self, now_ms: u64, weight: u64) -> bool {
        self.refill(now_ms);
        let cost = micro(weight);
        if self.micro < cost {
            return false;
        }
        self.micro -= cost;
        true
    }

    /// Take `weight` if the bucket holds it; else how many milliseconds
    /// until it will (nothing taken).
    fn take_or_wait(&mut self, now_ms: u64, weight: u64) -> Result<(), u64> {
        if self.take(now_ms, weight) {
            return Ok(());
        }
        if weight > self.burst || self.milli_per_second == 0 {
            return Err(u64::MAX);
        }
        // Millionths missing, refilled at `milli_per_second` millionths a
        // millisecond.
        let missing = u64::try_from(micro(weight).saturating_sub(self.micro)).unwrap_or(0);
        Err(missing.div_ceil(self.milli_per_second).max(1))
    }

    /// Charge `weight` whatever is left: below zero, the debt is paid back
    /// before anything else is taken. The debt goes no deeper than one
    /// burst, so that it never holds a bot's other requests off for longer
    /// than one burst takes to refill.
    fn charge(&mut self, now_ms: u64, weight: u64) {
        self.refill(now_ms);
        let floor = micro(self.burst).saturating_neg();
        self.micro = self.micro.saturating_sub(micro(weight)).max(floor);
    }
}

impl Budget {
    fn take(&mut self, now_ms: u64, per_second: u32) -> bool {
        let second = now_ms / 1_000;
        if second != self.second {
            self.second = second;
            self.used = 0;
        }
        if self.used >= per_second {
            return false;
        }
        self.used += 1;
        true
    }
}

/// A running Guard. Cheap to share: clone the `Arc`.
pub struct Guard<U, C = SystemClock> {
    upstream: Arc<U>,
    clock: C,
    inner: Mutex<Inner>,
    cache: StdMutex<HashMap<String, (u64, Value)>>,
    /// Every budget of the venue's request weight, fitted to the config's
    /// `ip_share` ([`crate::budget::plan`]).
    budgets: crate::budget::Budgets,
    info_budget: StdMutex<WeightBucket>,
    request_budget: StdMutex<WeightBucket>,
    /// Reduce-only orders forwarded on a spent request budget, and those
    /// of them forwarded because they reduce a position the last view
    /// shows ([`EXITS_PER_SECOND`]).
    exit_allowance: StdMutex<WeightBucket>,
    known_exits: StdMutex<WeightBucket>,
    preview_budget: StdMutex<Budget>,
    /// The bot's reads answered from the stream ([`STREAM_INFO_PER_SECOND`]).
    stream_info_budget: StdMutex<Budget>,
    started_ms: u64,
    /// The account as the venue's WebSocket streams it, once started
    /// ([`Guard::start_stream`]).
    stream: StdMutex<Option<Stream>>,
    /// How requests were judged: from the stream, or after a read.
    judged: StdMutex<JudgedFrom>,
    /// The account Guard trades for, and when Guard last heard back on a
    /// send (on [`monotonic_ms`]'s clock, 0 before the first), for the
    /// `/info` passthrough to answer from the stream without Guard's lock.
    account: Address,
    last_send_mono: AtomicU64,
    /// Recovery after a restart is running ([`Guard::recover`]).
    recovering: AtomicBool,
    hold_started: tokio::sync::Notify,
    /// Broadcast deadline changes to every read already in flight.
    hold_changed: tokio::sync::Notify,
}

/// How many requests were judged from the stream and how many after an
/// account read, and why the last one could not use the stream.
#[derive(Debug, Default)]
struct JudgedFrom {
    stream: u64,
    read: u64,
    last_fallback: Option<String>,
    /// The bot's own `/info` reads answered from the stream.
    info_from_stream: u64,
}

impl<U: Upstream, C: Clock> Guard<U, C> {
    pub fn new(setup: Setup, upstream: U, clock: C) -> Result<Arc<Self>, String> {
        // The signature's network and the transport's network are one.
        match (&setup.mode, upstream.sends_to()) {
            (Mode::Paper, None) => {}
            (Mode::Send { network, .. }, Some(sends_to)) if *network == sends_to => {}
            _ => {
                return Err(
                    "the mode and the venue connection disagree on the network, or a paper Guard was given a sending connection".into(),
                );
            }
        }
        // And the config's mode is the mode it runs in.
        let sends_to = match &setup.mode {
            Mode::Paper => None,
            Mode::Send {
                network: SigningNetwork::Testnet,
                ..
            } => Some(crate::config::GuardNetwork::Testnet),
            Mode::Send {
                network: SigningNetwork::Mainnet,
                ..
            } => Some(crate::config::GuardNetwork::Mainnet),
        };
        if sends_to.is_some() && setup.config.mode.network() != sends_to {
            return Err(format!(
                "the config's mode is {}, not {}",
                setup.config.mode.name(),
                setup.mode.name()
            ));
        }
        // The production budgets, fitted to the HIP-3 dexes the markets name
        // and to the part of the IP address's request weight that is this
        // Guard's (`ip_share`); refused when the share is too small to keep
        // Guard safe. Tests against an in-memory venue may raise the request
        // budget alone.
        let mut budgets = crate::budget::plan(
            setup.config.ip_share,
            setup.config.policy.markets.hip3_dexes().len(),
        )
        .map_err(|error| error.to_string())?;
        if setup.limits != Limits::default() {
            budgets.requests = crate::budget::Bucket {
                milli_per_second: setup.limits.request_weight_per_second.saturating_mul(1_000),
                burst: setup.limits.request_weight_burst,
            };
        }
        let started_ms = clock.now_ms();
        let account = setup.config.account().map_err(|error| error.to_string())?;
        let auth = Authenticator::new(&setup.config.auth, started_ms).map_err(|e| e.to_string())?;
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|error| error.to_string())?;
        let fee_network = match setup.config.network() {
            Ok(crate::config::GuardNetwork::Mainnet) => licence::FeeNetwork::Mainnet,
            _ => licence::FeeNetwork::Testnet,
        };
        let mut licence_track = LicenceTrack::new(setup.config.licence.clone(), fee_network);
        // A key can expire while the caller waits for the API wallet key.
        // Resolve its mode again at construction, before accepting requests.
        let (current_fee, _) = licence_track.mode(account, clock.now_ms());
        let fee = FeeState::new(
            if setup.config.licence.is_some() {
                current_fee
            } else {
                setup.fee
            },
            sends_to.is_some(),
        );
        let mut inner = Inner {
            account,
            auth,
            licence: licence_track,
            killed: None,
            positions_at_kill: None,
            caches: Caches {
                account,
                names: setup.config.policy.markets.hip3_dexes(),
                meta: None,
                perp_dexs: None,
                dex_metas: HashMap::new(),
                open_interest_caps: HashMap::new(),
                missing_dexes: Vec::new(),
                mode_cache: None,
            },
            unmanaged: BTreeMap::new(),
            sweep_at: 0,
            last_sweep_ms: None,
            last_nonce: 0,
            last_view: None,
            intent: None,
            emergency: Emergency::new(crate::journal::EmergencyLog::new(
                &setup
                    .config
                    .emergency_log(matches!(setup.mode, Mode::Paper)),
            )),
            attached: VecDeque::new(),
            resting_entries: VecDeque::new(),
            last_sync_ms: None,
            last_error: None,
            last_send_ms: None,
            reported_halt: None,
            position_alert: None,
            alerts: Vec::new(),
            last_protect_ms: None,
            protect_now: false,
            last_send_mono: None,
            sends: 0,
            last_read_exposed: None,
            last_halt_read_ms: None,
            ledger_from_ms: None,
            ledger_read_ms: None,
            ledger_ok_ms: None,
            ledger_reconnects: 0,
            ledger_hold: None,
            views_left_since: None,
            flows_applied: 0,
            flow_note: None,
            sync_read_twice: false,
            sync_unlock_next: false,
            last_sync_reads: 0,
            salt,
            client_ids: 0,
            refusals: (0, 0, 0),
            vetoes: (0, HashMap::new(), 0),
            config: setup.config,
            mode: setup.mode,
            // Deposits and withdrawals are kept out of the account stops
            // (`docs/guard.md`): Guard's own choice, not the runner's.
            risk: setup.risk.with_flows(),
            journal: setup.journal,
            fee,
        };
        let started = EventBody::Started {
            schema: EVENT_SCHEMA,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            mode: inner.mode.name().to_owned(),
            account: account.to_hex(),
            rules: rules::encode(&inner.config.policy),
            clients: inner.auth.clients().map(Address::to_hex).collect(),
        };
        inner
            .journal
            .append(started_ms as i64, started)
            .map_err(|error| error.to_string())?;
        if let Some(warning) = setup.fee_warning {
            inner
                .journal
                .append(started_ms as i64, EventBody::Error { text: warning })
                .ok();
        }
        if let Some((bytes, aside)) = inner.journal.cut_on_open() {
            inner
                .journal
                .append(
                    started_ms as i64,
                    EventBody::Error {
                        text: format!(
                            "the decision journal ended in writes a crash cut short (never synced, so nothing was sent on their strength): {bytes} bytes moved to {}",
                            aside.display()
                        ),
                    },
                )
                .ok();
        }
        // A kill file left in place latches before anything is served.
        Self::check_kill(&mut inner, started_ms);
        Ok(Arc::new(Self {
            upstream: Arc::new(upstream),
            clock,
            inner: Mutex::new(inner),
            cache: StdMutex::new(HashMap::new()),
            info_budget: StdMutex::new(WeightBucket::of(budgets.info)),
            request_budget: StdMutex::new(WeightBucket::of(budgets.requests)),
            exit_allowance: StdMutex::new(WeightBucket::of(budgets.exits)),
            known_exits: StdMutex::new(WeightBucket::of(budgets.exits)),
            budgets,
            preview_budget: StdMutex::new(Budget::default()),
            stream_info_budget: StdMutex::new(Budget::default()),
            started_ms,
            stream: StdMutex::new(None),
            judged: StdMutex::new(JudgedFrom::default()),
            account,
            last_send_mono: AtomicU64::new(0),
            recovering: AtomicBool::new(false),
            hold_started: tokio::sync::Notify::new(),
            hold_changed: tokio::sync::Notify::new(),
        }))
    }

    pub fn upstream(&self) -> &U {
        &self.upstream
    }

    /// Latch the kill switch when the kill file exists, readable or not.
    fn check_kill(inner: &mut Inner, now: u64) {
        if inner.killed.is_some() {
            return;
        }
        let path = inner.config.kill_file();
        if std::fs::symlink_metadata(&path).is_err() {
            return;
        }
        let reason = std::fs::read_to_string(&path)
            .map(|text| text.trim().chars().take(200).collect::<String>())
            .unwrap_or_else(|_| format!("{} exists (unreadable)", path.display()));
        inner.killed = Some(reason.clone());
        inner
            .journal
            .append(now as i64, EventBody::Kill { reason })
            .ok();
    }

    /// Pass an `/info` request through, with a short cache for the
    /// requests whose answers change slowly, within the passthrough's
    /// budget of the venue's request weight ([`INFO_WEIGHT_PER_SECOND`] at
    /// `ip_share` 1).
    pub async fn info(&self, body: &Value) -> Result<Value, UpstreamError> {
        let kind = body.get("type").and_then(Value::as_str);
        let ttl = match kind {
            // `userRole` (weight 60) changes only when a person approves
            // or removes an agent.
            Some("meta" | "spotMeta" | "perpDexs" | "userRole") => 60_000,
            Some("allMids") => 500,
            _ => 0,
        };
        if let Some(answer) = self.info_from_stream(body) {
            return Ok(answer);
        }
        let key = body.to_string();
        let now = self.clock.now_ms();
        if ttl > 0
            && let Ok(cache) = self.cache.lock()
            && let Some((at, value)) = cache.get(&key)
            && now.saturating_sub(*at) < ttl
        {
            return Ok(value.clone());
        }
        let allowed = self
            .info_budget
            .lock()
            .map(|mut budget| budget.take(now, info_weight(kind)))
            .unwrap_or(false);
        if !allowed {
            return Err(UpstreamError::NotSent(format!(
                "Guard passes info requests within {} of the venue's request weight a second; try again shortly",
                crate::budget::thousandths(self.budgets.info.milli_per_second)
            )));
        }
        let value = self.upstream.info(body).await?;
        if ttl > 0
            && let Ok(mut cache) = self.cache.lock()
        {
            if cache.len() >= 64 {
                cache.clear();
            }
            cache.insert(key, (now, value.clone()));
        }
        Ok(value)
    }

    /// A bot's read of its own account (`clearinghouseState` or
    /// `frontendOpenOrders`, of the main dex or a HIP-3 dex the markets
    /// name), answered from the account stream when it is clean: the
    /// latest snapshot as the venue sent it (what its WebSocket sends any
    /// client, its `time` included), at most [`STREAM_INFO_PER_SECOND`] a
    /// second. It spends none of the venue's request weight. `None` (read
    /// from the venue) for anything else, another account, or a stream
    /// that is not clean.
    fn info_from_stream(&self, body: &Value) -> Option<Value> {
        let kind = body.get("type").and_then(Value::as_str)?;
        if !matches!(kind, "clearinghouseState" | "frontendOpenOrders") {
            return None;
        }
        let user = body
            .get("user")
            .and_then(Value::as_str)
            .and_then(Address::from_hex)?;
        if user != self.account {
            return None;
        }
        // Only the fields Hyperliquid's answer depends on.
        let allowed = body
            .as_object()?
            .keys()
            .all(|key| matches!(key.as_str(), "type" | "user" | "dex"));
        if !allowed {
            return None;
        }
        let dex = match body.get("dex") {
            None | Some(Value::Null) => "",
            Some(dex) => dex.as_str()?,
        };
        let last_send = match self.last_send_mono.load(Ordering::SeqCst) {
            0 => None,
            at => Some(at),
        };
        // A bot polling in a loop: beyond 20 a second, the venue answers
        // (within the passthrough's own budget).
        let allowed = self
            .stream_info_budget
            .lock()
            .map(|mut budget| budget.take(self.clock.now_ms(), STREAM_INFO_PER_SECOND))
            .unwrap_or(false);
        if !allowed {
            return None;
        }
        let (state, orders) = {
            let stream = self.stream.lock().ok()?;
            let state = stream.as_ref()?.state.lock().ok()?;
            state.raw_snapshot(monotonic_ms(), last_send, dex)?
        };
        if let Ok(mut judged) = self.judged.lock() {
            judged.info_from_stream += 1;
        }
        Some(if kind == "clearinghouseState" {
            state
        } else {
            orders
        })
    }

    /// What Guard would decide about an action (`{"action": {...}}`, no
    /// nonce, no signature), now: read-only. Nothing is journaled, sent or
    /// consumed, and the risk engine is not shown the account (the
    /// background sync does that).
    pub async fn preview(&self, body: Value) -> Value {
        let now = self.clock.now_ms();
        let allowed = self
            .preview_budget
            .lock()
            .map(|mut budget| budget.take(now, PREVIEWS_PER_SECOND))
            .unwrap_or(false);
        if !allowed {
            return json!({"error": format!("at most {PREVIEWS_PER_SECOND} previews a second")});
        }
        let action = match body.get("action").map(decode_action_value) {
            Some(Ok(action)) => action,
            Some(Err(error)) => return json!({"error": error.to_string()}),
            None => return json!({"error": "the body must be {\"action\": {...}}"}),
        };
        let request = ExchangeRequest {
            action,
            nonce: now,
            signature: zunder_guard_core::sign::Signature {
                r: [0; 32],
                s: [0; 32],
                v: 27,
            },
            expires_after: None,
        };
        // From the background sync's last view: a preview never spends the
        // venue's request budget for reading the account. A HIP-3 entry's
        // book (weight 2) is read from the `/info` passthrough budget,
        // outside the lock.
        let (account, view_age_ms) = {
            let mut inner = self.inner.lock().await;
            Self::check_kill(&mut inner, now);
            // The view's own age: since it was read, or for a view from the
            // stream, since its oldest snapshot arrived.
            let age = inner
                .last_view
                .as_ref()
                .map(|view| now.saturating_sub(u64::try_from(view.at_ms).unwrap_or(0)));
            let fresh = age.is_some_and(|age| age <= PREVIEW_VIEW_MAX_AGE_MS);
            let Some(account) = inner.last_view.clone().filter(|_| fresh) else {
                return json!({"error": "Guard has no recent view of the account yet; try again after the next sync"});
            };
            (account, age)
        };
        // Never a book an earlier request read: only this preview's own.
        let mut account = account;
        account.books.clear();
        if let Some(asset) = hip3_entry_asset(&request) {
            self.read_book(&mut account, asset, true).await;
        }
        let inner = self.inner.lock().await;
        let policy = licence::sizing_policy(&inner.config.policy, inner.fee.sizing_builder());
        let decision = judge(
            &Context {
                policy: &policy,
                engine: inner.risk.engine(),
                account: &account,
                killed: inner.killed.is_some(),
                builder: inner.fee.builder_for_orders(),
                salt: &inner.salt,
            },
            &request,
        );
        let mut decision = decision;
        let opens = decision
            .forward
            .as_ref()
            .is_some_and(|forward| forward.entry.is_some());
        if opens && let Err(error) = inner.risk.check_ready() {
            decision = Decision::veto(
                "journal",
                format!("the risk journal does not allow new positions: {error}"),
            );
        } else if opens && let Some(text) = inner.fee.entry_refusal() {
            decision = Decision::veto("fee_not_approved", text);
        } else if is_modify(&request)
            && let Some(text) = inner.fee.modify_refusal()
        {
            decision = Decision::veto("fee_not_approved", text);
        }
        Self::with_fee(&inner.fee, &mut decision);
        let forward = decision.forward.as_ref();
        let entry = forward.and_then(|forward| forward.entry.as_ref());
        json!({
            "verdict": decision.verdict,
            "code": decision.code,
            "text": decision.text,
            "changes": decision.changes,
            "entry": entry.map(|entry| json!({
                "coin": entry.coin,
                "side": entry.side,
                "requested_size": entry.requested_qty,
                "size": entry.qty,
                "worst_price": entry.worst_price,
                "stop": entry.stop,
                "leverage": entry.leverage,
            })),
            "pre": forward.map(|f| f.pre.iter().map(|a| a.to_wire().to_value()).collect::<Vec<_>>()),
            "forward": forward.map(|f| f.action.to_wire().to_value()),
            "post": forward.map(|f| f.post.iter().map(|a| a.to_wire().to_value()).collect::<Vec<_>>()),
            "mode": inner.mode.name(),
            "view_age_ms": view_age_ms,
        })
    }

    /// Handle one `/exchange` request; `via` is `http` or `ws`. The answer
    /// is always a Hyperliquid-shaped reply.
    pub async fn exchange(&self, body: Value, via: &str) -> Value {
        if self.recovering() {
            return veto_reply(
                "journal",
                "Guard is asking the venue what became of actions sent before a restart; requests wait until it is done (at most 90 s; protection goes on meanwhile)",
            );
        }
        let mut inner = self.inner.lock().await;
        let now = self.clock.now_ms();
        Self::check_kill(&mut inner, now);
        // An expired licence falls back to the fee at this order already.
        Self::licence_tick(&mut inner, now, false);
        let (request, client) = match admit(&mut inner.auth, &body, now) {
            Ok(admitted) => admitted,
            Err(refusal) => return self.refuse(&mut inner, now, via, &body, &refusal),
        };
        let (account, read) = match self.account_for_request(&mut inner, now, &request).await {
            Ok(account) => account,
            Err(error) => {
                let managed = Self::managed_indices(&inner);
                let refused = || match &error {
                    ReadFailure::Budget(text) => Decision::veto("rate_limited", text.clone()),
                    ReadFailure::Venue(error) => Decision::veto(
                        "account_unreadable",
                        format!("the account could not be read from the venue: {error}"),
                    ),
                };
                let decision = match unjudged_reduce_only(&request, &managed) {
                    Some(exit) => {
                        let weight = exit.forward.as_ref().map_or(1, forward_weight);
                        if self.admit_exit(&inner, now, &request, weight) {
                            exit
                        } else {
                            Decision::veto("rate_limited", self.exits_spent())
                        }
                    }
                    None => refused(),
                };
                return self
                    .decided(&mut inner, now, via, &request, &client, decision, None)
                    .await;
            }
        };
        // Stamped no earlier than the risk engine's last observation.
        let at = now.max(inner.last_sync_ms.unwrap_or(0));
        let held = !self.take_flows(&mut inner, at, &account).await;
        if !held {
            self.observe(&mut inner, at, &account);
        }
        self.halt(&mut inner, now, &account, read).await;
        // An entry is sized with the builder fee it pays on the way in and
        // out.
        let policy = licence::sizing_policy(&inner.config.policy, inner.fee.sizing_builder());
        let mut decision = judge(
            &Context {
                policy: &policy,
                engine: inner.risk.engine(),
                account: &account,
                killed: inner.killed.is_some(),
                builder: inner.fee.builder_for_orders(),
                salt: &inner.salt,
            },
            &request,
        );
        let opens = decision
            .forward
            .as_ref()
            .is_some_and(|forward| forward.entry.is_some());
        if opens && let Err(error) = inner.risk.check_ready() {
            decision = Decision::veto(
                "journal",
                format!("the risk journal does not allow new positions: {error}"),
            );
        }
        // A loss that would halt the engine, held back until the ledger
        // tells it from a withdrawal: no new positions meanwhile.
        if opens && held {
            decision = Decision::veto(
                "account_unreadable",
                "the account's ledger could not be read yet to tell a loss that would halt Guard from a withdrawal; new positions wait (at most 10 s)",
            );
        }
        // Every view left out for a while (each may or may not show a
        // deposit or withdrawal): the engine sees nothing new, so no new
        // positions until it does.
        if opens
            && inner
                .views_left_since
                .is_some_and(|since| now.saturating_sub(since) >= VIEWS_LEFT_OUT_MS)
        {
            decision = Decision::veto(
                "account_unreadable",
                "the account's views have all been left out for 10 s or more (each may or may not show a deposit or withdrawal); new positions wait for one that can be read",
            );
        }
        // What a forwarded request sends is the venue's weight too: within
        // the request budget, or refused (reduce-only orders always go).
        if let Some(forward) = decision.forward.as_ref() {
            let weight = forward_weight(forward);
            let managed = Self::managed_indices(&inner);
            let exit = unjudged_reduce_only(&request, &managed).is_some();
            let allowed = if exit {
                self.admit_exit(&inner, now, &request, weight)
            } else {
                self.request_budget
                    .lock()
                    .map(|mut budget| budget.take(now, weight))
                    .unwrap_or(false)
            };
            if !allowed {
                decision = Decision::veto(
                    "rate_limited",
                    if exit {
                        self.exits_spent()
                    } else {
                        BUDGET_SPENT.to_owned()
                    },
                );
            }
        }
        // New entries wait for the fee approval; exits never do. A person
        // who just approved it should not wait for the next periodic check:
        // the next sync looks again (outside the request's lock), at most
        // every 15 s and within the request budget.
        if opens
            && decision.forward.is_some()
            && let Some(text) = inner.fee.entry_refusal()
        {
            if inner.fee.on_demand_due(now)
                && self
                    .request_budget
                    .lock()
                    .map(|mut budget| budget.take(now, FEE_CHECK_WEIGHT))
                    .unwrap_or(false)
            {
                inner.fee.request_check();
            }
            decision = Decision::veto("fee_not_approved", text);
        }
        if is_modify(&request)
            && decision.forward.is_some()
            && let Some(text) = inner.fee.modify_refusal()
        {
            // Look again at the next sync: the approval may be back.
            if inner.fee.on_demand_due(now)
                && self
                    .request_budget
                    .lock()
                    .map(|mut budget| budget.take(now, FEE_CHECK_WEIGHT))
                    .unwrap_or(false)
            {
                inner.fee.request_check();
            }
            decision = Decision::veto("fee_not_approved", text);
        }
        self.decided(
            &mut inner,
            now,
            via,
            &request,
            &client,
            decision,
            Some(&account),
        )
        .await
    }

    /// The refusal of a reduce-only order beyond the request budget and
    /// both allowances.
    fn exits_spent(&self) -> String {
        let rate = crate::budget::thousandths(self.budgets.exits.milli_per_second);
        format!(
            "Guard's budget of the venue's request weight is spent, and so is its allowance for reduce-only orders beyond it ({rate} of weight a second, and {rate} more a second for one that reduces a position Guard last saw); try again in a second"
        )
    }

    /// Whether a reduce-only order of `weight` may go: within the request
    /// budget; else charged to it all the same (into debt) and forwarded
    /// within the exit allowance, or, beyond that, when it reduces a
    /// position the last view shows, at most [`EXITS_PER_SECOND`].
    fn admit_exit(&self, inner: &Inner, now: u64, request: &ExchangeRequest, weight: u64) -> bool {
        let Ok(mut budget) = self.request_budget.lock() else {
            return false;
        };
        if budget.take(now, weight) {
            return true;
        }
        drop(budget);
        // The allowances count weight (a batch of 41 orders or more is 2).
        let admitted = self
            .exit_allowance
            .lock()
            .map(|mut allowance| allowance.take(now, weight))
            .unwrap_or(false)
            || (inner
                .last_view
                .as_ref()
                .is_some_and(|view| reduces_a_position(view, request))
                && self
                    .known_exits
                    .lock()
                    .map(|mut known| known.take(now, weight))
                    .unwrap_or(false));
        // Charged only when it goes: a refused exit costs the venue nothing.
        if admitted && let Ok(mut budget) = self.request_budget.lock() {
            budget.charge(now, weight);
        }
        admitted
    }

    fn refuse(
        &self,
        inner: &mut Inner,
        now: u64,
        via: &str,
        body: &Value,
        refusal: &Refusal,
    ) -> Value {
        // Journal a bounded number a minute: a flood of junk must not fill
        // the disk or hold Guard up.
        let minute = now / 60_000;
        if inner.refusals.0 != minute {
            if inner.refusals.2 > 0 {
                inner
                    .journal
                    .append(
                        now as i64,
                        EventBody::Error {
                            text: format!(
                                "{} more refused requests in the last minute were not journaled",
                                inner.refusals.2
                            ),
                        },
                    )
                    .ok();
            }
            inner.refusals = (minute, 0, 0);
        }
        if inner.refusals.1 < REFUSALS_JOURNALED_PER_MINUTE {
            inner.refusals.1 += 1;
            let event = EventBody::Decision {
                via: via.to_owned(),
                client: None,
                signed_as: None,
                nonce: body.get("nonce").and_then(Value::as_u64),
                action: body
                    .pointer("/action/type")
                    .and_then(Value::as_str)
                    .map(|kind| kind.chars().take(40).collect()),
                verdict: Verdict::Veto,
                code: refusal.code().to_owned(),
                text: refusal.to_string(),
                changes: Vec::new(),
                request: None,
                pre: Vec::new(),
                forward: None,
                post: Vec::new(),
            };
            inner.journal.append(now as i64, event).ok();
        } else {
            inner.refusals.2 += 1;
        }
        veto_reply(refusal.code(), &refusal.to_string())
    }

    /// Journal a decision, then act on it.
    #[allow(clippy::too_many_arguments)]
    async fn decided(
        &self,
        inner: &mut Inner,
        now: u64,
        via: &str,
        request: &ExchangeRequest,
        client: &Authenticated,
        decision: Decision,
        account: Option<&AccountView>,
    ) -> Value {
        // The builder field as it goes out, journaled as sent.
        let mut decision = decision;
        Self::with_fee(&inner.fee, &mut decision);
        // Every order sent carries a client id, so that recovery can ask
        // the venue about it after a crash; those Guard gave the bot's
        // orders are taken out of the reply.
        let mut assigned = Vec::new();
        if let Some(forward) = decision.forward.as_mut() {
            for action in std::iter::once(&mut forward.action).chain(forward.post.iter_mut()) {
                let (with_ids, ids) =
                    with_client_ids(action, &mut inner.client_ids, &inner.salt, BOT_CLOID_PREFIX);
                *action = with_ids;
                assigned.extend(ids);
            }
        }
        let forward = decision.forward.as_ref();
        let wires = |actions: &[Action]| actions.iter().map(|a| a.to_wire().to_value()).collect();
        let event = EventBody::Decision {
            via: via.to_owned(),
            client: Some(client.client.to_hex()),
            signed_as: Some(client.signed_as),
            nonce: Some(client.nonce),
            action: Some(request.action.kind().to_owned()),
            verdict: decision.verdict,
            code: decision.code.to_owned(),
            text: decision.text.clone(),
            changes: decision.changes.clone(),
            request: Some(request.action.to_wire().to_value()),
            pre: forward.map(|f| wires(&f.pre)).unwrap_or_default(),
            forward: forward.map(|f| f.action.to_wire().to_value()),
            post: forward.map(|f| wires(&f.post)).unwrap_or_default(),
        };
        // Vetoes journaled a bounded number a minute: a bot looping on
        // refused orders must not flood the journal's writer.
        if decision.forward.is_none() {
            let minute = now / 60_000;
            if inner.vetoes.0 != minute {
                if inner.vetoes.2 > 0 {
                    let text = format!(
                        "{} more vetoes in the last minute were not journaled",
                        inner.vetoes.2
                    );
                    inner
                        .journal
                        .append(now as i64, EventBody::Error { text })
                        .ok();
                }
                inner.vetoes = (minute, HashMap::new(), 0);
            }
            let journaled = inner.vetoes.1.entry(client.client.to_hex()).or_default();
            let over = *journaled >= VETOES_JOURNALED_PER_MINUTE;
            if !over {
                *journaled += 1;
            }
            if over {
                inner.vetoes.2 += 1;
                return veto_reply(decision.code, &decision.text);
            }
        }
        // On disk before anything is sent; nothing is sent if it fails.
        let sends = decision.forward.is_some() && matches!(inner.mode, Mode::Send { .. });
        let named: Vec<Value> = forward
            .map(|f| {
                f.pre
                    .iter()
                    .chain(std::iter::once(&f.action))
                    .chain(f.post.iter())
                    .map(|action| action.to_wire().to_value())
                    .collect()
            })
            .unwrap_or_default();
        let journaled = if sends {
            match inner.journal.append_durable(now as i64, event) {
                Ok((seq, durable)) => durable.wait().await.map(|()| seq),
                Err(error) => Err(error),
            }
        } else {
            inner.journal.append(now as i64, event)
        };
        let seq = match journaled {
            Ok(seq) => seq,
            Err(error) => {
                return veto_reply(
                    "journal",
                    &format!("the decision could not be journaled, so nothing was sent: {error}"),
                );
            }
        };
        if sends {
            inner.intent = Some((seq, now, named));
        }
        let Some(forward) = decision.forward.clone() else {
            return veto_reply(decision.code, &decision.text);
        };
        if matches!(inner.mode, Mode::Paper) {
            inner
                .journal
                .append(now as i64, EventBody::Done { intent: seq })
                .ok();
            let mut reply = paper_reply(&decision);
            if let Some(fields) = reply.as_object_mut()
                && let Some(fee) = Self::paper_fee(&inner.fee, &forward)
            {
                fields.insert("builder_fee".into(), fee);
            }
            return reply;
        }
        let mut reply = self.send(inner, now, seq, &forward, account).await;
        // Its actions without a `sent` record were not sent.
        inner
            .journal
            .append(self.clock.now_ms() as i64, EventBody::Done { intent: seq })
            .ok();
        // Guard's verdict beside a reply the venue took, for tools that read
        // it (a resize shows otherwise only in the fill sizes), with the
        // entry's asked and forwarded size; a refusal on the way, or the
        // venue's own error, is left as it is.
        if let Some(fields) = reply.as_object_mut()
            && fields.get("status").and_then(Value::as_str) == Some("ok")
            && !fields.contains_key("code")
        {
            fields.insert("code".into(), json!(decision.code));
            fields.insert("verdict".into(), json!(decision.verdict));
            // The entry's sizes, or else the bot's first order's: asked,
            // and as forwarded (a reduce-only order may be cut to the
            // position).
            let sizes = match (&forward.entry, &request.action, &forward.action) {
                (Some(entry), _, _) => Some((entry.requested_qty, entry.qty)),
                (None, Action::Order(asked), Action::Order(sent)) => {
                    let at = forward.status_map.first().copied().unwrap_or(0);
                    asked
                        .orders
                        .first()
                        .zip(sent.orders.get(at))
                        .map(|(asked, sent)| (asked.size.value(), sent.size.value()))
                }
                _ => None,
            };
            if let Some((requested, size)) = sizes {
                fields.insert("requested_size".into(), json!(requested));
                fields.insert("size".into(), json!(size));
            }
        }
        strip_client_ids(&mut reply, &assigned);
        reply
    }

    /// Put the builder field Guard sends now on the forwarded order action
    /// (every order, entry or exit; none while the fee is not approved).
    fn with_fee(fee: &FeeState, decision: &mut Decision) {
        if let Some(forward) = decision.forward.as_mut() {
            forward.action = fee.apply(&forward.action);
        }
    }

    /// Paper mode: the builder fee the forwarded orders would carry, and
    /// for an entry what it would cost at its worst fill.
    fn paper_fee(fee: &FeeState, forward: &Forward) -> Option<Value> {
        let builder = fee.mode().builder()?;
        let Action::Order(_) = &forward.action else {
            return None;
        };
        let entry_usdc = forward.entry.as_ref().and_then(|entry| {
            entry
                .qty
                .checked_mul(entry.worst_price)
                .and_then(|notional| licence::fee_usdc(notional, builder.fee_tenths_bp))
        });
        Some(json!({
            "address": builder.address,
            "fee_tenths_bp": builder.fee_tenths_bp,
            "rate": licence::rate(builder.fee_tenths_bp),
            "entry_usdc_at_worst_price": entry_usdc,
            "approved": fee.approved(),
        }))
    }

    /// Record a `maxBuilderFee` answer and journal a change; a withdrawal
    /// is an alert.
    fn record_fee_check(inner: &mut Inner, ticket: u64, now: u64, answer: Result<&Value, String>) {
        let was_approved = inner.fee.approved();
        if let Some(text) = inner.fee.record_answer(ticket, now, answer) {
            if was_approved && !inner.fee.approved() {
                Self::add_alert(inner, now, &text, None);
            }
            inner
                .journal
                .append(now as i64, EventBody::Error { text })
                .ok();
        }
    }

    /// Tests only (feature `test-hooks`, never in a release build): whether
    /// trigger orders carry the builder field, as a build with
    /// [`licence::BUILDER_ON_TRIGGERS`] switched the other way would.
    #[cfg(feature = "test-hooks")]
    pub async fn set_builder_on_triggers(&self, on: bool) {
        self.inner.lock().await.fee.set_builder_on_triggers(on);
    }

    /// Tests only (feature `test-hooks`, never in a release build): up to
    /// where the decision journal's file is on disk, as it moves.
    #[cfg(feature = "test-hooks")]
    pub async fn journal_synced_for_test(&self) -> Arc<AtomicU64> {
        self.inner.lock().await.journal.synced_for_test()
    }

    /// Tests only (feature `test-hooks`, never in a release build): break
    /// the decision journal, as a failed write would.
    #[cfg(feature = "test-hooks")]
    pub async fn break_journal_for_test(&self) {
        self.inner.lock().await.journal.break_for_test();
    }

    /// Tests only (feature `test-hooks`, never in a release build): the
    /// decision journal's writer writes nothing until the returned sender
    /// is dropped.
    #[cfg(feature = "test-hooks")]
    pub async fn hold_journal_writer_for_test(&self) -> std::sync::mpsc::Sender<()> {
        self.inner.lock().await.journal.hold_writer_for_test()
    }

    /// Tests only (feature `test-hooks`, never in a release build): fill
    /// the decision journal's queue (hold its writer first).
    #[cfg(feature = "test-hooks")]
    pub async fn fill_journal_queue_for_test(&self) {
        self.inner.lock().await.journal.fill_queue_for_test();
    }

    /// Tests only (feature `test-hooks`, never in a release build): every
    /// emergency-log write waits at `gate` (a hung disk); returns how many
    /// writes were begun.
    #[cfg(feature = "test-hooks")]
    pub async fn hold_emergency_log_for_test(&self, gate: crate::journal::Gate) -> Arc<AtomicU64> {
        let inner = self.inner.lock().await;
        let mut log = inner
            .emergency
            .log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        log.hold_for_test(gate)
    }

    /// Tests only (feature `test-hooks`, never in a release build): the
    /// `/info` passthrough's budget, so that a test can run a client's
    /// reads back to back (the in-memory venue has no request limit).
    #[cfg(feature = "test-hooks")]
    pub fn set_info_budget(&self, per_second: u64, burst: u64) {
        if let Ok(mut budget) = self.info_budget.lock() {
            *budget = WeightBucket::with(per_second, burst);
        }
    }

    fn next_nonce(inner: &mut Inner, now: u64) -> u64 {
        inner.last_nonce = now.max(inner.last_nonce.saturating_add(1));
        inner.last_nonce
    }

    /// Sign and send one action with the builder field Guard sends now
    /// (on every order action; none while the fee is not approved), and
    /// journal what came back. When the venue refuses the builder field on
    /// an exit (the approval was withdrawn), Guard notes it and sends the
    /// exit again without the field: an exit never waits for the fee.
    async fn send_one(
        &self,
        inner: &mut Inner,
        now: u64,
        decision: u64,
        action: &Action,
        expires_after: u64,
    ) -> Result<Value, String> {
        Self::licence_tick(inner, self.clock.now_ms(), false);
        if !reduces_risk(action)
            && let Some(why) = inner.fee.entry_refusal()
        {
            return Err(format!("fee_not_approved: {why}"));
        }
        let action = inner.fee.apply(action);
        let carries_builder = matches!(&action, Action::Order(order) if order.builder.is_some());
        let result = self
            .send_signed(inner, now, decision, &action, expires_after, false)
            .await;
        let refusal = match &result {
            Ok(reply) if carries_builder => licence::builder_refusal_text(reply)
                .map(|text| (text, licence::nothing_placed(reply))),
            _ => None,
        };
        let Some((venue_text, nothing_placed)) = refusal else {
            return result;
        };
        if let Some(text) = inner.fee.record_venue_refusal(now, &venue_text) {
            Self::add_alert(inner, now, &text, None);
            inner
                .journal
                .append(now as i64, EventBody::Error { text })
                .ok();
        }
        // Again without the field, only when it is an exit and nothing of it
        // was placed (no order is ever doubled).
        if !licence::exits_only(&action) || !nothing_placed {
            return result;
        }
        let bare = licence::with_builder(&action, None);
        self.send_signed(
            inner,
            self.clock.now_ms().max(now),
            decision,
            &bare,
            expires_after,
            true,
        )
        .await
    }

    /// Sign and send one action as it is; journal what came back (and the
    /// action itself when `journal_action`: it differs from what the
    /// decision recorded).
    async fn send_signed(
        &self,
        inner: &mut Inner,
        now: u64,
        decision: u64,
        action: &Action,
        expires_after: u64,
        journal_action: bool,
    ) -> Result<Value, String> {
        let Mode::Send { .. } = &inner.mode else {
            return Err("paper mode sends nothing".into());
        };
        // J1: an intent on disk names this action as it goes out, written
        // no more than [`INTENT_COVERS_MS`] before it expires (recovery
        // waits that long after an intent); if none does, one is written
        // and waited for first.
        let wire = action.to_wire().to_value();
        let mut emergency = false;
        let named = inner.intent.as_ref().and_then(|(seq, at, actions)| {
            (*seq == decision && expires_after <= at.saturating_add(INTENT_COVERS_MS))
                .then(|| actions.iter().position(|named| *named == wire))
                .flatten()
        });
        let mut index = named.map(|index| index as u64);
        let decision = if named.is_some() {
            decision
        } else {
            let at = self.clock.now_ms();
            let written = inner
                .journal
                .append_durable_waiting(
                    at as i64,
                    EventBody::Intent {
                        of: decision,
                        action: wire.clone(),
                    },
                )
                .await;
            match written {
                Ok(seq) => {
                    inner.intent = Some((seq, at, vec![wire.clone()]));
                    index = Some(0);
                    seq
                }
                // Protection goes on while the
                // decision journal cannot be written (broken: a writer
                // merely behind is waited for above); the intent goes to
                // the emergency log first (where it can), with an alert.
                Err(error) if reduces_risk(action) => {
                    emergency = true;
                    let logged = inner
                        .emergency
                        .record(
                            at as i64,
                            EventBody::Intent {
                                of: decision,
                                action: wire.clone(),
                            },
                        )
                        .await;
                    let path = inner.emergency.path();
                    let text = match &logged {
                        Ok(()) => format!(
                            "the decision journal cannot be written ({error}); a protective action goes out recorded in the emergency log {path} only"
                        ),
                        Err(log_error) => format!(
                            "the decision journal ({error}) and the emergency log ({log_error}) cannot be written; a protective action goes out unrecorded: {wire}"
                        ),
                    };
                    eprintln!("zunder-guard: {text}");
                    Self::add_alert(inner, now, &text, None);
                    decision
                }
                Err(error) => {
                    return Err(format!(
                        "the action could not be journaled before sending, so it was not sent: {error}"
                    ));
                }
            }
        };
        // Durability may have waited across expiry. Recheck immediately
        // before signing; a changed protective action gets its own intent.
        Self::licence_tick(inner, self.clock.now_ms(), false);
        if !reduces_risk(action)
            && let Some(why) = inner.fee.entry_refusal()
        {
            return Err(format!("fee_not_approved: {why}"));
        }
        let current_action = inner.fee.apply(action);
        if current_action.to_wire().to_value() != wire {
            return Box::pin(self.send_signed(
                inner,
                self.clock.now_ms().max(now),
                decision,
                &current_action,
                expires_after,
                true,
            ))
            .await;
        }
        let nonce = Self::next_nonce(inner, now);
        let Mode::Send { key, network } = &inner.mode else {
            return Err("paper mode sends nothing".into());
        };
        let Some(body) = signed_request(key, *network, action, nonce, Some(expires_after)) else {
            return Err("the action could not be signed".into());
        };
        let result = self.upstream.exchange(body).await;
        // The settle window counts from the answer, not the request.
        let answered = self.clock.now_ms();
        let mono = monotonic_ms().max(1);
        // What the socket should report of it: the stream is clean again
        // once it has (`stream::Expectation`). Every send is recorded with
        // the stream before it is noted as the last send below.
        let expected = result.as_ref().ok().and_then(|reply| {
            expectation(
                inner
                    .caches
                    .perp_dexs
                    .as_ref()
                    .map(|(list, _)| list.as_slice()),
                inner.last_view.as_ref(),
                &inner.attached,
                action,
                reply,
                mono,
            )
        });
        if let Ok(reply) = &result
            && let Some(stops) = attached_stops(action, reply)
        {
            inner.attached.push_back(stops);
            while inner.attached.len() > ATTACHED_KEPT {
                inner.attached.pop_front();
            }
        }
        if let Ok(stream) = self.stream.lock()
            && let Some(stream) = stream.as_ref()
            && let Ok(mut state) = stream.state.lock()
        {
            state.sent(mono, expected);
        }
        inner.last_send_ms = Some(answered);
        inner.last_send_mono = Some(mono);
        self.last_send_mono.store(mono, Ordering::SeqCst);
        inner.sends = inner.sends.wrapping_add(1);
        let (ok, reply) = match &result {
            Ok(value) => (
                value.get("status").and_then(Value::as_str) == Some("ok"),
                value.clone(),
            ),
            Err(error) => (false, json!({"error": error.to_string()})),
        };
        // Not waited for: nothing is sent on the strength of this record
        // (the intent was on disk before the send); the journal writer
        // syncs it with the next intent or within a second, and after a
        // crash recovery asks the venue (`docs/guard.md#journals`).
        let sent = EventBody::Sent {
            decision,
            nonce,
            ok,
            reply: reply.clone(),
            action: journal_action.then(|| action.to_wire().to_value()),
            index,
        };
        // In the emergency log too, not waited for (it may be the disk that
        // stalled).
        if emergency {
            inner.emergency.record_later(answered as i64, sent.clone());
        }
        inner.journal.append(answered as i64, sent).ok();
        result.map_err(|error| match error {
            UpstreamError::NoAnswer(text) => format!(
                "no answer from the venue ({text}); the request may have reached it: check open orders before sending again"
            ),
            other => other.to_string(),
        })
    }

    async fn send(
        &self,
        inner: &mut Inner,
        now: u64,
        decision: u64,
        forward: &Forward,
        account: Option<&AccountView>,
    ) -> Value {
        for pre in &forward.pre {
            let result = self
                .send_one(inner, now, decision, pre, now + LEVERAGE_TTL_MS)
                .await;
            let mut refused = match &result {
                Ok(reply) => action_ok(reply).err(),
                Err(error) => Some(error.clone()),
            };
            // Confirmed only when read back.
            if refused.is_none()
                && let (Action::UpdateLeverage { leverage, .. }, Some(entry)) =
                    (pre, &forward.entry)
            {
                let read = self
                    .upstream
                    .info(&requests::active_asset_data(inner.account, &entry.coin))
                    .await;
                match read {
                    Ok(answer) if confirms_isolated(&answer, *leverage) => {}
                    Ok(answer) => {
                        refused = Some(format!(
                            "the venue shows {}",
                            answer.get("leverage").unwrap_or(&Value::Null)
                        ));
                    }
                    Err(error) => refused = Some(format!("reading the leverage back: {error}")),
                }
            }
            if let Some(why) = refused {
                return veto_reply(
                    "venue_refused_leverage",
                    &format!(
                        "isolated leverage was not confirmed, so the order was not sent: {why}"
                    ),
                );
            }
        }
        let expires = forward
            .expires_after
            .unwrap_or(u64::MAX)
            .min(now + ACTION_TTL_MS);
        let reply = match self
            .send_one(inner, now, decision, &forward.action, expires)
            .await
        {
            Ok(reply) => reply,
            Err(error) => {
                if error.starts_with("fee_not_approved:") {
                    return veto_reply("fee_not_approved", &error);
                }
                return veto_reply("venue_unreachable", &error);
            }
        };

        // A modify the venue refused may have cancelled the order it was to
        // replace (it cancels first), possibly because the approval was
        // withdrawn since Guard's last read: protect at the next sync,
        // settled or not, and read the approval then.
        if matches!(forward.action, Action::Modify(_) | Action::BatchModify(_))
            && let Err(error) = action_ok(&reply)
        {
            inner.protect_now = true;
            if inner.fee.mode().builder().is_some() {
                inner.fee.request_check();
            }
            if let Some(venue_text) = licence::builder_refusal_text(&reply)
                && let Some(text) = inner.fee.record_venue_refusal(now, &venue_text)
            {
                Self::add_alert(inner, now, &text, None);
                inner
                    .journal
                    .append(now as i64, EventBody::Error { text })
                    .ok();
            }
            inner
                .journal
                .append(
                    now as i64,
                    EventBody::Error {
                        text: format!(
                            "a modify was refused by the venue; Guard protects the position at the next sync: {error}"
                        ),
                    },
                )
                .ok();
        }
        let statuses = order_statuses(&reply).unwrap_or_default();
        // The venue refused the entry for its builder field: the approval
        // is gone (`send_one` noted it), and none of its orders was placed.
        if forward.entry.is_some()
            && licence::is_builder_refusal(&reply)
            && licence::nothing_placed(&reply)
            && statuses
                .iter()
                .all(|status| matches!(status, OrderStatus::Error(_)))
            && let Some(text) = inner.fee.entry_refusal()
        {
            return veto_reply("fee_not_approved", &format!("{text} (the venue: {reply})"));
        }
        if let (Some(entry), Action::Order(sent)) = (&forward.entry, &forward.action) {
            // Protected when some stop sent with the entry was not refused.
            let protected = sent
                .orders
                .iter()
                .enumerate()
                .filter(|(_, order)| order.protective_level().is_some())
                .any(|(index, _)| {
                    !matches!(statuses.get(index), Some(OrderStatus::Error(_)) | None)
                });
            match statuses.first() {
                Some(OrderStatus::Filled { total, average, .. }) if protected => {
                    let recorded = inner.risk.record_entry(
                        Timestamp::from_millis(now as i64),
                        Symbol::new(&entry.coin),
                        entry.side,
                        *total,
                        *average,
                        entry.stop,
                    );
                    if let Err(error) = recorded {
                        inner
                            .journal
                            .append(
                                now as i64,
                                EventBody::Error {
                                    text: format!(
                                        "the filled entry could not be recorded: {error}"
                                    ),
                                },
                            )
                            .ok();
                    }
                }
                Some(OrderStatus::Filled { total, .. }) => {
                    // The entry filled and its stop was refused: never leave
                    // it open without one.
                    let text = self
                        .close_unprotected(
                            inner,
                            now,
                            decision,
                            account,
                            &entry.coin,
                            entry.side,
                            *total,
                        )
                        .await;
                    let text = format!(
                        "the {} entry filled but its stop was refused: {text}",
                        entry.coin
                    );
                    Self::add_alert(inner, now, &text, None);
                    inner
                        .journal
                        .append(now as i64, EventBody::Error { text })
                        .ok();
                }
                Some(OrderStatus::Resting { oid }) if protected => {
                    // Remembered until it fills (or is gone): its stop is
                    // the one the entry was sized for.
                    let held_before = account
                        .and_then(|account| account.position(&entry.coin))
                        .filter(|position| position.side == entry.side)
                        .map_or(rust_decimal::Decimal::ZERO, |position| position.qty);
                    inner.resting_entries.push_back(RestingEntry {
                        oid: *oid,
                        coin: entry.coin.clone(),
                        side: entry.side,
                        qty: entry.qty,
                        stop: entry.stop,
                        held_before,
                        filled: false,
                        gone_reads: 0,
                    });
                    while inner.resting_entries.len() > ATTACHED_KEPT {
                        inner.resting_entries.pop_front();
                    }
                }
                Some(OrderStatus::Resting { oid }) if !protected => {
                    // The entry rests and its stop was refused: it could
                    // fill without one. Cancel it.
                    let asset = sent.orders.first().map_or(0, |order| order.asset);
                    let cancel = Action::Cancel(vec![zunder_guard_core::action::Cancel {
                        asset,
                        order: zunder_guard_core::action::OrderRef::Oid(*oid),
                    }]);
                    let cancelled = self
                        .send_one(
                            inner,
                            now,
                            decision,
                            &cancel,
                            self.clock.now_ms() + ACTION_TTL_MS,
                        )
                        .await
                        .and_then(|reply| action_ok(&reply));
                    // A resting order may have filled in part: protect what
                    // filled at the next sync, settled or not.
                    inner.protect_now = true;
                    let text = match cancelled {
                        Ok(()) => format!(
                            "the {} entry {oid} rested but its stop was refused: cancelled",
                            entry.coin
                        ),
                        Err(error) => {
                            let text = format!(
                                "the {} entry {oid} rests without its stop, and cancelling it failed: {error}; cancel it by hand",
                                entry.coin
                            );
                            Self::add_alert(inner, now, &text, Some(*oid));
                            text
                        }
                    };
                    inner
                        .journal
                        .append(now as i64, EventBody::Error { text })
                        .ok();
                }
                _ => {}
            }
        }
        // Guard's own stop goes only once the bot's replacement rests.
        let replacements_rest = !forward.post_after.is_empty()
            && forward
                .post_after
                .iter()
                .all(|index| matches!(statuses.get(*index), Some(OrderStatus::Resting { .. })));
        if replacements_rest {
            for post in &forward.post {
                if let Err(error) = self
                    .send_one(
                        inner,
                        now,
                        decision,
                        post,
                        self.clock.now_ms() + ACTION_TTL_MS,
                    )
                    .await
                    .and_then(|reply| action_ok(&reply))
                {
                    // Guard's looser stop still rests (and still protects);
                    // the bot cannot cancel it, so a person looks.
                    let text = format!(
                        "Guard's own stop could not be cancelled after the bot's tighter stop rested: {error}"
                    );
                    Self::add_alert(inner, now, &text, None);
                    inner
                        .journal
                        .append(now as i64, EventBody::Error { text })
                        .ok();
                }
            }
        }
        client_reply(reply, &forward.status_map)
    }

    /// Close `qty` of a position at once with a reduce-only IOC order, and
    /// say whether the venue reports it filled.
    #[allow(clippy::too_many_arguments)]
    async fn close_unprotected(
        &self,
        inner: &mut Inner,
        now: u64,
        decision: u64,
        account: Option<&AccountView>,
        coin: &str,
        side: zunder_core::Side,
        qty: rust_decimal::Decimal,
    ) -> String {
        let close = account
            .and_then(|account| close_action(account, &inner.config.policy, coin, side, qty));
        let Some(close) = close else {
            return "no close could be priced: close it by hand".to_owned();
        };
        let (close, _) = with_client_ids(
            &close,
            &mut inner.client_ids,
            &inner.salt,
            CLOSE_CLOID_PREFIX,
        );
        match self
            .send_one(
                inner,
                now,
                decision,
                &close,
                self.clock.now_ms() + ACTION_TTL_MS,
            )
            .await
        {
            Ok(reply) => match order_statuses(&reply).as_deref() {
                Ok([OrderStatus::Filled { total, .. }]) if *total >= qty => {
                    "closed at once".to_owned()
                }
                Ok([OrderStatus::Filled { total, .. }]) => {
                    format!("only {total} of {qty} closed: close the rest by hand")
                }
                Ok(statuses) => format!("the close did not fill ({statuses:?}): close it by hand"),
                Err(error) => format!("the close was refused ({error}): close it by hand"),
            },
            Err(error) => format!("closing it failed: {error}; close it by hand"),
        }
    }

    /// Add (or refresh) an alert; true when it is new.
    fn add_alert(inner: &mut Inner, now: u64, text: &str, oid: Option<u64>) -> bool {
        let before = inner.alerts.len();
        inner.alerts.retain(|alert| alert.text != text);
        let new = inner.alerts.len() == before;
        inner.alerts.push(Alert {
            text: text.to_owned(),
            at_ms: now,
            oid,
        });
        // Bounded: the oldest go first.
        if inner.alerts.len() > 20 {
            inner.alerts.remove(0);
        }
        new
    }

    /// Give every position no market stop covers in full Guard's own stop,
    /// and close a position whose stop the venue refuses. Runs from the
    /// background sync: once nothing Guard sent can still be on its way (a
    /// stop placed with a fill may not show yet), and at least every 30 s
    /// all the same. In paper mode it journals what it would do, once.
    async fn protect(&self, inner: &mut Inner, now: u64, account: &AccountView) {
        self.protect_planned(inner, now, account, true).await;
    }

    /// [`Guard::protect`]; `use_planned` false (a partial read) leaves the
    /// resting entries' stops out, as they were judged on an older view.
    async fn protect_planned(
        &self,
        inner: &mut Inner,
        now: u64,
        account: &AccountView,
        use_planned: bool,
    ) {
        inner.last_protect_ms = Some(now);
        inner.protect_now = false;
        let planned = if use_planned {
            Self::planned_stops(inner)
        } else {
            Vec::new()
        };
        let (actions, unpriced, notes) = protect_actions_with(
            account,
            &inner.config.policy,
            inner.risk.engine(),
            &inner.salt,
            now,
            &planned,
        );
        // What a person should look at (a stop beyond liquidation, Guard's
        // own stop resting without counting): kept as alerts while seen,
        // journaled once.
        for note in &notes {
            if Self::add_alert(inner, now, note, None) {
                inner
                    .journal
                    .append(now as i64, EventBody::Error { text: note.clone() })
                    .ok();
            }
        }
        if actions.is_empty() && unpriced.is_empty() {
            inner.position_alert = None;
            return;
        }
        let mut problems = notes;
        let mut coins: Vec<String> = actions.iter().map(|(coin, _)| coin.clone()).collect();
        coins.extend(unpriced.iter().cloned());
        let sends = matches!(inner.mode, Mode::Send { .. });
        let fee = inner.fee.clone();
        let summary = format!("positions without a stop: {}", coins.join(", "));
        if !sends && inner.position_alert.as_deref() == Some(summary.as_str()) {
            return;
        }
        problems.extend(
            unpriced
                .iter()
                .map(|coin| format!("{coin}: no stop could be placed (no price, or the price is already through the stop recorded for it)")),
        );
        let named: Vec<Value> = actions
            .iter()
            .map(|(_, action)| fee.apply(action).to_wire().to_value())
            .collect();
        let event = EventBody::Protect {
            coins: coins.clone(),
            actions: named.clone(),
            problems: problems.clone(),
            sent: sends,
        };
        // On disk before the stops are sent (a writer behind is waited
        // for); if the journal is broken, they go all the same (E1:
        // protection is never held up), each with its intent in the
        // emergency log.
        let seq = if sends {
            match inner
                .journal
                .append_durable_waiting(now as i64, event)
                .await
            {
                Ok(seq) => {
                    inner.intent = Some((seq, now, named));
                    seq
                }
                Err(_) => 0,
            }
        } else {
            inner.journal.append(now as i64, event).unwrap_or(0)
        };
        if !sends {
            inner.position_alert = Some(summary);
            return;
        }
        let mut to_close = unpriced;
        for (coin, action) in &actions {
            let result = self
                .send_one(inner, now, seq, action, self.clock.now_ms() + ACTION_TTL_MS)
                .await;
            let placed = match result.as_ref().map(order_statuses) {
                Ok(Ok(statuses))
                    if matches!(statuses.as_slice(), [OrderStatus::Resting { .. }]) =>
                {
                    true
                }
                // Refused outright: close.
                Ok(Ok(statuses)) if matches!(statuses.as_slice(), [OrderStatus::Error(_)]) => false,
                // Refused by HTTP status (a 4xx, such as 429): not placed;
                // looking for it would spend weight the venue is refusing.
                Err(error) if error.starts_with("HTTP 4") => false,
                // No answer, or one Guard cannot read: the stop may rest
                // all the same. Look for it before closing.
                _ => self.rests(inner, action).await,
            };
            if !placed {
                to_close.push(coin.clone());
            }
        }
        for coin in to_close {
            let Some(position) = account.position(&coin).cloned() else {
                continue;
            };
            let text = self
                .close_unprotected(
                    inner,
                    now,
                    seq,
                    Some(account),
                    &coin,
                    position.side,
                    position.qty,
                )
                .await;
            problems.push(format!("{coin}: Guard's stop was refused; {text}"));
        }
        if seq > 0 {
            inner
                .journal
                .append(self.clock.now_ms() as i64, EventBody::Done { intent: seq })
                .ok();
        }
        if problems.is_empty() {
            inner.position_alert = None;
        } else {
            let text = problems.join("; ");
            inner
                .journal
                .append(now as i64, EventBody::Error { text: text.clone() })
                .ok();
            inner.position_alert = Some(text);
        }
    }

    /// Follow the remembered resting entries. One whose position on its
    /// side has grown beyond what it held before, but by no more than the
    /// entry's own size, has filled (in part or in full): its stop counts
    /// for that position. Anything else cannot be told apart from other
    /// trading on the coin, so its stop does not count. An entry is
    /// forgotten once it no longer rests and its position is back at (or
    /// below) what it held before, or grown beyond what the entry explains;
    /// one gone without growth is kept for one more read (the open orders
    /// and the positions are read at slightly different moments).
    fn follow_resting(inner: &mut Inner, account: &AccountView) {
        let held = |entry: &RestingEntry| {
            account
                .position(&entry.coin)
                .filter(|position| position.side == entry.side)
                .map_or(rust_decimal::Decimal::ZERO, |position| position.qty)
        };
        inner.resting_entries.retain_mut(|entry| {
            let now_held = held(entry);
            let rests = account.order_by_oid(entry.oid).is_some();
            let explained = now_held > entry.held_before
                && now_held <= entry.held_before.saturating_add(entry.qty);
            entry.filled = explained;
            if rests || explained {
                entry.gone_reads = 0;
                return true;
            }
            entry.gone_reads += 1;
            entry.gone_reads < 2 && now_held <= entry.held_before
        });
    }

    /// The stops of the remembered entries that explain their position.
    fn planned_stops(inner: &Inner) -> Vec<(String, zunder_core::Side, rust_decimal::Decimal)> {
        inner
            .resting_entries
            .iter()
            .filter(|entry| entry.filled)
            .map(|entry| (entry.coin.clone(), entry.side, entry.stop))
            .collect()
    }

    /// Whether the order of `action` (one order with a client id) rests on
    /// the venue now.
    async fn rests(&self, inner: &Inner, action: &Action) -> bool {
        let Action::Order(order) = action else {
            return false;
        };
        let Some(cloid) = order.orders.first().and_then(|order| order.cloid.as_ref()) else {
            return false;
        };
        let wanted = cloid.as_str().to_ascii_lowercase();
        // A HIP-3 dex's orders are listed with its name only.
        let request = match order.orders.first().map(|order| asset_kind(order.asset)) {
            Some(AssetKind::Hip3 { dex }) => {
                let Some(name) = inner.caches.perp_dexs.as_ref().and_then(|(list, _)| {
                    list.iter()
                        .find(|(index, _)| *index == dex)
                        .map(|(_, name)| name.clone())
                }) else {
                    return false;
                };
                requests::frontend_open_orders_of(inner.account, &name)
            }
            _ => requests::frontend_open_orders(inner.account),
        };
        match self.upstream.info(&request).await {
            Ok(Value::Array(orders)) => orders.iter().any(|order| {
                order
                    .get("cloid")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id.to_ascii_lowercase() == wanted)
            }),
            _ => false,
        }
    }

    /// Start following the account over the venue's WebSocket (the main
    /// dex and every HIP-3 dex the markets name). Requests are then judged
    /// from the stream whenever it is clean ([`crate::stream`]), and after
    /// a read otherwise. `None` for a venue without a WebSocket (tests).
    pub async fn start_stream(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let url = self.upstream.ws_url()?;
        let (user, dexes) = {
            let inner = self.inner.lock().await;
            (
                inner.account,
                inner
                    .config
                    .policy
                    .markets
                    .hip3_dexes()
                    .into_iter()
                    .collect::<Vec<_>>(),
            )
        };
        let (stream, task) = Stream::spawn(url, user, &dexes);
        if let Ok(mut slot) = self.stream.lock() {
            *slot = Some(stream);
        }
        Some(task)
    }

    /// The account for a request, from the stream when it is clean, else
    /// read fresh ([`Guard::read_for_request`]); `true` with a view read
    /// from the venue just now. Either way the stream is asked to follow
    /// the entry's coin, so that the next judgement of it can use the
    /// stream.
    async fn account_for_request(
        &self,
        inner: &mut Inner,
        now: u64,
        request: &ExchangeRequest,
    ) -> Result<(AccountView, bool), ReadFailure> {
        // This entire helper only reads account/book data. Bound it while
        // holding the mutex; no journal, leverage, signer or send is here.
        let result = if inner.ledger_hold.is_some() {
            let deadline = self.flow_read_deadline(inner, LEDGER_HOLD_MS);
            tokio::time::timeout_at(
                deadline,
                self.account_for_request_inner(inner, now, request),
            )
            .await
            .unwrap_or_else(|_| {
                Err(ReadFailure::Venue(UpstreamError::NoAnswer(
                    "request account read reached loss-hold deadline".to_owned(),
                )))
            })
        } else {
            self.account_for_request_inner(inner, now, request).await
        };
        self.expire_hold(inner, self.clock.now_ms());
        result
    }

    async fn account_for_request_inner(
        &self,
        inner: &mut Inner,
        now: u64,
        request: &ExchangeRequest,
    ) -> Result<(AccountView, bool), ReadFailure> {
        let streaming = self
            .stream
            .lock()
            .map(|stream| stream.is_some())
            .unwrap_or(false);
        if !streaming {
            let view = self.read_for_request(inner, now, request).await?;
            return Ok((view, true));
        }
        let from_stream = self.stream_view(inner, now, request);
        let (view, read) = match from_stream {
            Ok(mut view) => {
                // A HIP-3 entry's book is read for it (20 levels; the
                // stream's fast book has 5, too few to reach a stop's worst
                // fill), within the request-read budget.
                if let Some(asset) = hip3_entry_asset(request) {
                    let allowed = self
                        .request_budget
                        .lock()
                        .map(|mut budget| budget.take(now, BOOK_READ_WEIGHT))
                        .unwrap_or(false);
                    if !allowed {
                        return Err(ReadFailure::Budget(
                            "Guard's request-read budget is spent; try again in a few seconds"
                                .into(),
                        ));
                    }
                    self.read_book(&mut view, asset, false).await;
                }
                if let Ok(mut judged) = self.judged.lock() {
                    judged.stream += 1;
                }
                (view, false)
            }
            Err(why) => {
                if let Ok(mut judged) = self.judged.lock() {
                    judged.read += 1;
                    judged.last_fallback = Some(why);
                }
                (self.read_for_request(inner, now, request).await?, true)
            }
        };
        if read {
            inner.last_read_exposed = Some(exposed(&view));
        }
        if let Some(coin) = entry_asset(request)
            .and_then(|asset| view.meta.by_index(asset))
            .map(|asset| asset.name.clone())
            && let Ok(stream) = self.stream.lock()
            && let Some(stream) = stream.as_ref()
        {
            stream.follow(&coin);
        }
        Ok((view, read))
    }

    /// The account from the stream, if it is clean for this request
    /// ([`crate::stream::StreamState::answers`]): every dex's latest
    /// snapshots revalued at marks at most 1.5 s old, the fresh mids of the
    /// coins with positions or orders and of the entry's, and the reference
    /// data Guard read (`meta`, the account mode, `perpDexs`, the caps)
    /// within their lifetimes. The reason otherwise.
    fn stream_view(
        &self,
        inner: &Inner,
        now: u64,
        request: &ExchangeRequest,
    ) -> Result<AccountView, String> {
        let fresh = |at: u64, ttl: u64| now.saturating_sub(at) < ttl;
        let meta = match &inner.caches.meta {
            Some((meta, at)) if fresh(*at, META_TTL_MS) => meta,
            _ => return Err("the venue's meta is not fresh".into()),
        };
        let mode = match &inner.caches.mode_cache {
            Some((mode, at)) if fresh(*at, MODE_TTL_MS) => mode,
            _ => return Err("the account mode is not fresh".into()),
        };
        // Each HIP-3 dex the markets name, by its index, with its meta and
        // caps.
        let mut hip3: HashMap<String, (&Meta, &Value)> = HashMap::new();
        let names = inner.config.policy.markets.hip3_dexes();
        if !names.is_empty() {
            let listed = match &inner.caches.perp_dexs {
                Some((listed, at)) if fresh(*at, PERP_DEXS_TTL_MS) => listed,
                _ => return Err("perpDexs is not fresh".into()),
            };
            for name in &names {
                let Some((index, _)) = listed.iter().find(|(_, listed)| listed == name) else {
                    return Err(format!("dex {name} is not listed"));
                };
                let (Some((dex_meta, meta_at)), Some((cap, cap_at))) = (
                    inner.caches.dex_metas.get(index),
                    inner.caches.open_interest_caps.get(index),
                ) else {
                    return Err(format!("dex {name} has not been read yet"));
                };
                if !fresh(*meta_at, META_TTL_MS) || !fresh(*cap_at, OPEN_INTEREST_CAP_TTL_MS) {
                    return Err(format!("dex {name}'s meta or caps are not fresh"));
                }
                hip3.insert(name.clone(), (dex_meta, cap));
            }
        }
        let coin = entry_asset(request).and_then(|asset| {
            meta.by_index(asset)
                .or_else(|| {
                    hip3.values()
                        .find_map(|(dex_meta, _)| dex_meta.by_index(asset))
                })
                .map(|asset| asset.name.clone())
        });
        let answers = {
            let stream = self
                .stream
                .lock()
                .map_err(|_| "the stream is poisoned".to_owned())?;
            let Some(stream) = stream.as_ref() else {
                return Err("no stream".into());
            };
            let state = stream
                .state
                .lock()
                .map_err(|_| "the stream is poisoned".to_owned())?;
            state
                .answers(monotonic_ms(), inner.last_send_mono, coin.as_deref())
                .map_err(|not| not.0)?
        };
        let mut parts = Vec::with_capacity(answers.dexes.len());
        for (dex, state, orders, mids) in &answers.dexes {
            let (dex_meta, cap) = if dex.is_empty() {
                (meta, None)
            } else {
                let Some((dex_meta, cap)) = hip3.get(dex) else {
                    return Err(format!("dex {dex} is not one the markets name"));
                };
                (*dex_meta, Some(*cap))
            };
            parts.push((dex.is_empty(), dex_meta, cap, state, orders, mids));
        }
        // The main dex first.
        parts.sort_by_key(|part| !part.0);
        let parts: Vec<DexAnswers<'_>> = parts
            .iter()
            .map(|(_, dex_meta, cap, state, orders, mids)| DexAnswers {
                meta: dex_meta,
                clearinghouse: state,
                open_orders: orders,
                mids,
                at_open_interest_cap: *cap,
            })
            .collect();
        // As old as its oldest snapshot.
        let at = now.saturating_sub(answers.age_ms) as i64;
        let mut view = AccountView::parse_dexes(at, mode, &parts)
            .map_err(|error| format!("the stream's answers do not parse: {error}"))?;
        view.mids.extend(answers.mids);
        if let (Some(coin), Some(leverage)) = (coin, answers.leverage) {
            view.leverage_settings.insert(coin, leverage);
        }
        Ok(view)
    }

    /// The account for a request, read fresh (a view even a second old can
    /// miss a fill), every dex Guard manages at once, within the request
    /// budget ([`Limits`]) of the venue's request weight; beyond
    /// it `NotSent`. A HIP-3 entry's book is read with it.
    async fn read_for_request(
        &self,
        inner: &mut Inner,
        now: u64,
        request: &ExchangeRequest,
    ) -> Result<AccountView, ReadFailure> {
        // Each dex is a read of 24; a HIP-3 entry's book 2 more.
        let dexes = 1 + inner.config.policy.markets.hip3_dexes().len() as u64;
        let hip3_entry = hip3_entry_asset(request);
        let weight = ACCOUNT_READ_WEIGHT * dexes + if hip3_entry.is_some() { 2 } else { 0 };
        let allowed = self
            .request_budget
            .lock()
            .map(|mut budget| budget.take(now, weight))
            .unwrap_or(false);
        if !allowed {
            return Err(ReadFailure::Budget(format!(
                "Guard reads the account for at most {} requests a minute on average (the venue's request limit is shared with Guard's own sync and protection); try again in a few seconds",
                self.request_budget
                    .lock()
                    .map_or(0, |budget| budget.milli_per_second * 60
                        / (ACCOUNT_READ_WEIGHT * dexes * 1_000))
            )));
        }
        let mut view = self
            .read_account(&mut inner.caches, now)
            .await
            .map_err(ReadFailure::Venue)?;
        if let Some(asset) = hip3_entry {
            self.read_book(&mut view, asset, false).await;
        }
        Ok(view)
    }

    /// Read the book of the coin of HIP-3 asset `asset` into `view`, when
    /// it is a coin of a dex the view holds. A failed read leaves no book:
    /// the judge then refuses the entry (`thin_book`). `passthrough` takes
    /// the weight from the `/info` passthrough budget (a preview).
    async fn read_book(&self, view: &mut AccountView, asset: u32, passthrough: bool) {
        let Some(coin) = view.meta.by_index(asset).map(|asset| asset.name.clone()) else {
            return;
        };
        let Some(mid) = view.mid(&coin) else {
            return;
        };
        // Aggregated, so that 20 levels reach the stop's worst fill.
        let sig_figs = book_sig_figs(mid);
        let body = requests::l2_book(&coin, sig_figs);
        let answer = if passthrough {
            self.info(&body).await
        } else {
            self.upstream.info(&body).await
        };
        if let Ok(book) = answer.and_then(|answer| {
            Book::parse_aggregated(&answer, &coin, sig_figs)
                .map_err(|error| UpstreamError::NotJson(error.to_string()))
        }) {
            view.books.insert(coin, book);
        }
    }

    /// The HIP-3 dexes `perpDexs` lists (cached for ten minutes).
    async fn perp_dexs(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<Vec<(u32, String)>, UpstreamError> {
        if let Some((list, at)) = &caches.perp_dexs
            && now.saturating_sub(*at) < PERP_DEXS_TTL_MS
        {
            return Ok(list.clone());
        }
        let value = self.upstream.info(&requests::perp_dexs()).await?;
        let list =
            parse_perp_dexs(&value).map_err(|error| UpstreamError::NotJson(error.to_string()))?;
        caches.perp_dexs = Some((list.clone(), now));
        Ok(list)
    }

    /// The HIP-3 dexes Guard manages: those the markets name, at their
    /// index in `perpDexs`. A name `perpDexs` does not list is remembered
    /// for the status and read nowhere.
    async fn managed_dexes(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<Vec<(u32, String)>, UpstreamError> {
        let names = caches.names.clone();
        if names.is_empty() {
            caches.missing_dexes.clear();
            return Ok(Vec::new());
        }
        let listed = self.perp_dexs(caches, now).await?;
        let mut managed = Vec::new();
        let mut missing = Vec::new();
        for name in names {
            match listed.iter().find(|(_, listed)| *listed == name) {
                Some((index, _)) => managed.push((*index, name)),
                None => missing.push(name),
            }
        }
        caches.missing_dexes = missing;
        Ok(managed)
    }

    /// The indices of the HIP-3 dexes Guard manages, from what it read
    /// last (no request).
    fn managed_indices(inner: &Inner) -> Vec<u32> {
        let names = &inner.caches.names;
        inner
            .caches
            .perp_dexs
            .as_ref()
            .map_or_else(Vec::new, |(list, _)| {
                list.iter()
                    .filter(|(_, name)| names.contains(name))
                    .map(|(index, _)| *index)
                    .collect()
            })
    }

    /// A HIP-3 dex's `meta` (cached for a minute).
    async fn dex_meta(
        &self,
        caches: &mut Caches,
        now: u64,
        index: u32,
        name: &str,
    ) -> Result<Meta, UpstreamError> {
        if let Some((meta, at)) = caches.dex_metas.get(&index)
            && now.saturating_sub(*at) < META_TTL_MS
        {
            return Ok(meta.clone());
        }
        let value = self.upstream.info(&requests::meta_of(name)).await?;
        let meta = Meta::parse_dex(&value, index, name)
            .map_err(|error| UpstreamError::NotJson(error.to_string()))?;
        caches.dex_metas.insert(index, (meta.clone(), now));
        Ok(meta)
    }

    /// A HIP-3 dex's coins at their open-interest cap (cached for a
    /// minute).
    async fn open_interest_cap(
        &self,
        caches: &mut Caches,
        now: u64,
        index: u32,
        name: &str,
    ) -> Result<Value, UpstreamError> {
        if let Some((value, at)) = caches.open_interest_caps.get(&index)
            && now.saturating_sub(*at) < OPEN_INTEREST_CAP_TTL_MS
        {
            return Ok(value.clone());
        }
        let value = self
            .upstream
            .info(&requests::perps_at_open_interest_cap(name))
            .await?;
        caches
            .open_interest_caps
            .insert(index, (value.clone(), now));
        Ok(value)
    }

    /// One dex's positions, orders and mids, concurrently: the main dex
    /// for `None` (the requests exactly as before HIP-3), a HIP-3 dex by
    /// name.
    async fn read_dex(
        &self,
        user: Address,
        dex: Option<&str>,
    ) -> Result<(Value, Value, Value), UpstreamError> {
        let (state, orders, mids) = match dex {
            None => (
                requests::clearinghouse_state(user),
                requests::frontend_open_orders(user),
                requests::all_mids(),
            ),
            Some(dex) => (
                requests::clearinghouse_state_of(user, dex),
                requests::frontend_open_orders_of(user, dex),
                requests::all_mids_of(dex),
            ),
        };
        let (state, orders, mids) = tokio::join!(
            self.upstream.info(&state),
            self.upstream.info(&orders),
            self.upstream.info(&mids),
        );
        Ok((state?, orders?, mids?))
    }

    /// Read the account fresh, every dex Guard manages: complete, or an
    /// error (a request is never judged against part of the account).
    async fn read_account(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<AccountView, UpstreamError> {
        let (view, unread) = self.read_account_parts(caches, now).await?;
        if unread.is_empty() {
            Ok(view)
        } else {
            Err(UpstreamError::NotJson(format!(
                "HIP-3 dex {} could not be read",
                unread.join(", ")
            )))
        }
    }

    /// Read the account fresh: meta (cached), mode, and each dex's
    /// positions, orders and mids, every dex at once, so that a transfer
    /// between two of them is not seen half done; merged into one view.
    /// The main dex must be read; a HIP-3 dex that cannot be (its `meta`,
    /// its caps, its answers, or `perpDexs`) is left out and named in the
    /// second value, so that one deployer's malformed answer never leaves
    /// the other dexes without protection.
    async fn read_account_parts(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<(AccountView, Vec<String>), UpstreamError> {
        let meta = self.meta(caches, now).await?;
        let mut unread: Vec<String> = Vec::new();
        let dexes = match self.managed_dexes(caches, now).await {
            Ok(dexes) => dexes,
            Err(_) => {
                unread.extend(caches.names.clone());
                Vec::new()
            }
        };
        let mut readable = Vec::with_capacity(dexes.len());
        let mut dex_metas = Vec::with_capacity(dexes.len());
        let mut caps = Vec::with_capacity(dexes.len());
        for (index, name) in dexes {
            let meta = self.dex_meta(caches, now, index, &name).await;
            let cap = self.open_interest_cap(caches, now, index, &name).await;
            match (meta, cap) {
                (Ok(meta), Ok(cap)) => {
                    dex_metas.push(meta);
                    caps.push(cap);
                    readable.push((index, name));
                }
                _ => unread.push(name),
            }
        }
        let dexes = readable;
        let user = caches.account;
        let cached_mode = caches
            .mode_cache
            .as_ref()
            .filter(|(_, at)| now.saturating_sub(*at) < MODE_TTL_MS)
            .map(|(mode, _)| mode.clone());
        let mode = match cached_mode {
            Some(mode) => mode,
            None => {
                let mode = self
                    .upstream
                    .info(&requests::user_abstraction(user))
                    .await?;
                caches.mode_cache = Some((mode.clone(), now));
                mode
            }
        };
        let answers = join_all(
            std::iter::once(None)
                .chain(dexes.iter().map(|(_, name)| Some(name.as_str())))
                .map(|dex| self.read_dex(user, dex)),
        )
        .await;
        let mut answers = answers.into_iter();
        let main = answers
            .next()
            .ok_or_else(|| UpstreamError::NotJson("no answer for the main dex".into()))??;
        let main_part = DexAnswers {
            meta: &meta,
            clearinghouse: &main.0,
            open_orders: &main.1,
            mids: &main.2,
            at_open_interest_cap: None,
        };
        // The main dex alone must parse.
        AccountView::parse_dexes(now as i64, &mode, &[main_part])
            .map_err(|error| UpstreamError::NotJson(error.to_string()))?;
        // Each HIP-3 dex must have answered and parse beside it, or it is
        // left out.
        type Read<'a> = (&'a Meta, &'a Value, &'a String, (Value, Value, Value));
        let mut read: Vec<Read<'_>> = Vec::new();
        for ((answer, (_, name)), (dex_meta, cap)) in
            answers.zip(&dexes).zip(dex_metas.iter().zip(caps.iter()))
        {
            match answer {
                Ok(answer) => read.push((dex_meta, cap, name, answer)),
                Err(_) => unread.push(name.clone()),
            }
        }
        let mut parts = vec![main_part];
        for (dex_meta, cap, name, (state, orders, mids)) in &read {
            let part = DexAnswers {
                meta: dex_meta,
                clearinghouse: state,
                open_orders: orders,
                mids,
                at_open_interest_cap: Some(cap),
            };
            if AccountView::parse_dexes(now as i64, &mode, &[main_part, part]).is_ok() {
                parts.push(part);
            } else {
                unread.push((*name).clone());
            }
        }
        let view = AccountView::parse_dexes(now as i64, &mode, &parts)
            .map_err(|error| UpstreamError::NotJson(error.to_string()))?;
        Ok((view, unread))
    }

    async fn meta(&self, caches: &mut Caches, now: u64) -> Result<Meta, UpstreamError> {
        if let Some((meta, at)) = &caches.meta
            && now.saturating_sub(*at) < META_TTL_MS
        {
            return Ok(meta.clone());
        }
        let value = self.upstream.info(&requests::meta()).await?;
        let meta =
            Meta::parse(&value).map_err(|error| UpstreamError::NotJson(error.to_string()))?;
        caches.meta = Some((meta.clone(), now));
        Ok(meta)
    }

    /// The positions alone, for flattening when the rest of the account
    /// cannot be read: no orders, no mode.
    async fn read_positions(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<AccountView, UpstreamError> {
        let meta = self.meta(caches, now).await?;
        let state = self
            .upstream
            .info(&requests::clearinghouse_state(caches.account))
            .await?;
        let mids = self.upstream.info(&requests::all_mids()).await?;
        let mut answers = vec![(meta, state, mids)];
        // The HIP-3 dexes Guard manages, as far as they can be read: a dex
        // that cannot be is left out rather than keeping the others open.
        if let Ok(dexes) = self.managed_dexes(caches, now).await {
            for (index, name) in dexes {
                let read = async {
                    let meta = self.dex_meta(caches, now, index, &name).await?;
                    let state = self
                        .upstream
                        .info(&requests::clearinghouse_state_of(caches.account, &name))
                        .await?;
                    let mids = self.upstream.info(&requests::all_mids_of(&name)).await?;
                    Ok::<_, UpstreamError>((meta, state, mids))
                };
                if let Ok(answer) = read.await {
                    answers.push(answer);
                }
            }
        }
        let no_orders = json!([]);
        let parts: Vec<DexAnswers<'_>> = answers
            .iter()
            .map(|(meta, state, mids)| DexAnswers {
                meta,
                clearinghouse: state,
                open_orders: &no_orders,
                mids,
                at_open_interest_cap: None,
            })
            .collect();
        AccountView::parse_dexes(now as i64, &json!("unknown"), &parts)
            .map_err(|error| UpstreamError::NotJson(error.to_string()))
    }

    /// Show the risk engine the account (its dexes at the venue's time of
    /// each, `view_times`). Flattening is [`Guard::halt`]'s.
    fn observe(&self, inner: &mut Inner, now: u64, account: &AccountView) {
        let before = inner.risk.state();
        let mut journal_error = None;
        let mut discrepancies = 0;
        if let Some(equity) = account.equity {
            // Settled only when nothing of Guard's can still be on its way
            // when the view was read (its own time, not the observation's
            // stamp): the record then takes the venue's view, also where it
            // shows less (a stop that fired, a position the bot closed).
            let read_at = u64::try_from(account.at_ms).unwrap_or(0);
            let settled = inner
                .last_send_ms
                .is_none_or(|sent| read_at.saturating_sub(sent) >= SETTLE_MS);
            let seen = inner.risk.observe_view_at(
                Timestamp::from_millis(now as i64),
                view_times(account),
                equity,
                &account.venue_view(),
                settled,
            );
            // A view left out, or one older than a view before it: the
            // engine sees nothing new either way.
            if seen.taken {
                inner.views_left_since = None;
            } else {
                inner.views_left_since.get_or_insert(now);
            }
            journal_error = seen.journal_error;
            discrepancies = seen.discrepancies.len();
            Self::note_flows(inner, now);
        }
        let state = inner.risk.state();
        if state != before || journal_error.is_some() {
            inner
                .journal
                .append(
                    now as i64,
                    EventBody::Risk {
                        state,
                        equity: account.equity,
                        open_positions: account.positions.len(),
                        discrepancies,
                        journal_error,
                    },
                )
                .ok();
        }
        inner.last_view = Some(account.clone());
        inner.last_sync_ms = Some(now);
    }

    /// Keep deposits and withdrawals out of the account stops, before the
    /// risk engine is shown `account`: the ledger entries the stream
    /// brought, and the ledger read over HTTP at the first observation
    /// (from the journal's last record on: what came or went while Guard
    /// was not running), whenever `account` would halt or stop the engine
    /// (so that a withdrawal the stream has not reported yet never halts
    /// it), and every minute while the stream is not connected. Each
    /// flow is applied once, on the journal ([`PersistentRisk::apply_flow`]).
    async fn take_flows(&self, inner: &mut Inner, now: u64, account: &AccountView) -> bool {
        let times = view_times(account);
        self.expire_hold(inner, self.clock.now_ms());
        // Requests may reuse an old stream snapshot: it cannot start or
        // end a run of fresh observations, even after wall time advanced.
        let previous = inner
            .ledger_hold
            .as_ref()
            .map(|hold| hold.latest.clone())
            .or_else(|| inner.last_view.as_ref().map(view_times));
        if previous
            .as_ref()
            .is_some_and(|previous| !fresh_flow_view(&times, previous))
        {
            return inner.ledger_hold.is_none();
        }
        let (mut entries, streaming, reconnects) = self
            .stream
            .lock()
            .ok()
            .and_then(|stream| {
                stream.as_ref().and_then(|stream| {
                    stream.state.lock().ok().map(|mut state| {
                        (state.take_ledger(), state.is_connected(), state.reconnects)
                    })
                })
            })
            .unwrap_or_default();
        let would_halt = account.equity.is_some_and(|equity| {
            inner
                .risk
                .would_halt(Timestamp::from_millis(now as i64), &times, equity)
        });
        // The view's own time: a ledger read must have begun after it, and
        // 2 s after the first view of the run of held views it belongs to,
        // for the view's loss to be known not to be a withdrawal.
        let view_ms = u64::try_from(account.at_ms).unwrap_or(0);
        let run = inner.ledger_hold.as_ref().map(|hold| hold.since);
        let checked = would_halt && ledger_checks(inner.ledger_ok_ms, view_ms, run);
        let since = inner.ledger_read_ms.map(|read| now.saturating_sub(read));
        let due = match since {
            None => true,
            Some(since) => {
                let failed = inner.ledger_ok_ms != inner.ledger_read_ms;
                let every = if failed {
                    LEDGER_RETRY_MS
                } else {
                    LEDGER_READ_EVERY_MS
                };
                (would_halt && !checked && since >= every)
                    || (!streaming && since >= LEDGER_READ_WITHOUT_STREAM_MS)
                    || since >= LEDGER_READ_PERIODIC_MS
                    || (inner.ledger_reconnects != reconnects
                        && since >= LEDGER_READ_WITHOUT_STREAM_MS)
            }
        };
        if due {
            inner.ledger_read_ms = Some(now);
            let read = self.read_ledger(inner, now).await;
            self.expire_hold(inner, self.clock.now_ms());
            if let Some((read, complete)) = read {
                if complete {
                    inner.ledger_ok_ms = Some(now);
                }
                inner.ledger_reconnects = reconnects;
                entries.extend(read);
            }
        }
        if !entries.is_empty() {
            self.apply_flows(inner, now, account, &entries).await;
        }
        let elapsed_now = self.clock.now_ms();
        self.expire_hold(inner, elapsed_now);
        if run.is_some_and(|since| elapsed_now.saturating_sub(since) >= LEDGER_HOLD_MS) {
            // This snapshot's run already expired while reading. A late
            // ledger answer must neither clear its proof nor restart it.
            return true;
        }
        // A loss that would halt the engine, with no ledger read since the
        // view to tell it from a withdrawal: held back (protection goes on
        // from the sync) for at most LEDGER_HOLD_MS, then counted.
        let still_halts = would_halt
            && account.equity.is_some_and(|equity| {
                inner
                    .risk
                    .would_halt(Timestamp::from_millis(now as i64), &times, equity)
            });
        let checked = ledger_checks(inner.ledger_ok_ms, view_ms, run);
        if still_halts && !checked {
            let hold = inner.ledger_hold.get_or_insert_with(|| LedgerHold {
                since: now,
                deepest: account.clone(),
                deepest_at: now,
                latest: times.clone(),
            });
            hold.latest = times.clone();
            self.hold_started.notify_one();
            self.hold_changed.notify_waiters();
            if account.equity < hold.deepest.equity {
                hold.deepest = account.clone();
                hold.deepest_at = now;
            }
            // Counted from the first view of the run until a complete read:
            // a loss that stays is held at most this long.
            if elapsed_now.saturating_sub(hold.since) < LEDGER_HOLD_MS {
                return false;
            }
        }
        // The run ends: a read told the loss from a withdrawal, the loss is
        // gone or explained (a withdrawal does not come back: a loss that
        // went was trading), or the hold's 10 s are over. Its deepest view
        // goes to the engine first, so that its loss counts.
        if let Some(hold) = inner.ledger_hold.take()
            && hold.deepest_at < now
        {
            self.observe(inner, hold.deepest_at, &hold.deepest);
        }
        true
    }

    fn expire_hold(&self, inner: &mut Inner, now: u64) {
        if inner
            .ledger_hold
            .as_ref()
            .is_some_and(|hold| now.saturating_sub(hold.since) >= LEDGER_HOLD_MS)
            && let Some(hold) = inner.ledger_hold.take()
        {
            self.observe(inner, hold.deepest_at, &hold.deepest);
        }
    }

    fn flow_read_deadline(&self, inner: &Inner, maximum_ms: u64) -> tokio::time::Instant {
        let remaining = inner.ledger_hold.as_ref().map_or(maximum_ms, |hold| {
            hold.since
                .saturating_add(LEDGER_HOLD_MS)
                .saturating_sub(self.clock.now_ms())
                .min(maximum_ms)
        });
        tokio::time::Instant::now() + Duration::from_millis(remaining)
    }

    /// The account's ledger over HTTP from where Guard last read it (at
    /// start, from the risk journal's last record or newest flow on), up
    /// to a few pages within [`LEDGER_READ_MS`] (it runs under Guard's
    /// lock), and whether that was all of it; its weight charged to the
    /// request budget as protection's own. `None` when the venue does not
    /// answer in time.
    async fn read_ledger(&self, inner: &mut Inner, now: u64) -> Option<(Vec<Value>, bool)> {
        let mut from = inner
            .ledger_from_ms
            .unwrap_or_else(|| inner.risk.flows_from_ms());
        let mut out = Vec::new();
        let deadline = self.flow_read_deadline(inner, LEDGER_READ_MS);
        let mut complete = false;
        for _ in 0..LEDGER_PAGES {
            let read = tokio::time::timeout_at(
                deadline,
                self.upstream
                    .info(&requests::ledger_updates(inner.account, from)),
            )
            .await;
            let Ok(Ok(Value::Array(page))) = read else {
                return None;
            };
            if let Ok(mut budget) = self.request_budget.lock() {
                budget.charge(now, 20 + page.len() as u64 / 20);
            }
            let newest = page
                .iter()
                .filter_map(|update| update["time"].as_i64())
                .max();
            let full = page.len() >= LEDGER_PAGE_LEN;
            out.extend(page);
            match newest {
                // A full page: what follows it, from its last time (entries
                // at that time again are duplicates by id).
                Some(newest) if full && newest > from => from = newest,
                Some(newest) => {
                    from = from.max(newest);
                    complete = true;
                    break;
                }
                None => {
                    complete = true;
                    break;
                }
            }
        }
        // The next read starts a little earlier than this one ended: an
        // entry the venue showed late comes again (a duplicate by id) rather
        // than never.
        inner.ledger_from_ms = Some(ledger_cursor(inner.ledger_from_ms, from, complete));
        Some((out, complete))
    }

    /// Apply the flows among ledger `entries` to the risk engine, in the
    /// order they happened.
    async fn apply_flows(
        &self,
        inner: &mut Inner,
        now: u64,
        account: &AccountView,
        entries: &[Value],
    ) {
        // The USDC perp accounts Guard's equity sums.
        let dexes: std::collections::BTreeSet<String> = if account.dexes.is_empty() {
            [String::new()].into()
        } else {
            account
                .dexes
                .iter()
                .filter(|dex| dex.usdc)
                .map(|dex| dex.name.clone())
                .collect()
        };
        let mut flows: Vec<_> = entries
            .iter()
            .filter_map(|update| ledger_flow(update, inner.account, &dexes))
            .collect();
        flows.sort_by_key(|flow| flow.time_ms);
        let deadline = self.flow_read_deadline(inner, 3_000);
        let mut weight = 0;
        for flow in flows {
            if inner.risk.knows_flow(&flow.id) {
                continue;
            }
            let value = self
                .reconstruct_flow(inner, now, &flow, &dexes, deadline, &mut weight)
                .await;
            self.expire_hold(inner, self.clock.now_ms());
            let applied = inner.risk.apply_flow(
                Timestamp::from_millis(now as i64),
                &Flow {
                    time_ms: flow.time_ms,
                    amount: flow.amount,
                    id: flow.id.clone(),
                    dex: flow.dex.clone(),
                    between: flow.between,
                    value,
                },
            );
            if let Err(error) = applied {
                inner.flow_note = Some(format!(
                    "a flow of {} USDC could not be recorded: {error}",
                    flow.amount
                ));
            }
        }
        Self::note_flows(inner, now);
    }

    /// Optional reconstruction shares passthrough's existing admission
    /// budget. Refuse before sending; failures/timeouts still spend weight.
    async fn flow_info(
        &self,
        _now: u64,
        body: Value,
        cost: u64,
        deadline: tokio::time::Instant,
        weight: &mut u64,
    ) -> Option<Value> {
        if weight.saturating_add(cost) > 240 {
            return None;
        }
        *weight += cost;
        if !self
            .info_budget
            .lock()
            .ok()?
            .take(self.clock.now_ms(), cost)
        {
            return None;
        }
        tokio::time::timeout_at(deadline, self.upstream.info(&body))
            .await
            .ok()?
            .ok()
    }

    async fn reconstruct_flow(
        &self,
        inner: &Inner,
        now: u64,
        flow: &zunder_guard_core::ledger::LedgerFlow,
        dexes: &std::collections::BTreeSet<String>,
        deadline: tokio::time::Instant,
        weight: &mut u64,
    ) -> Option<zunder_venue::ValueRange> {
        let now_ms = i64::try_from(now).ok()?;
        if flow.time_ms < now_ms.saturating_sub(86_400_000) || flow.time_ms > now_ms {
            return None;
        }
        let from = flow.time_ms;
        let mut anchors = Vec::new();
        let mut until = now_ms;
        for dex in dexes {
            let anchor = self
                .flow_info(
                    now,
                    requests::clearinghouse_state_of(inner.account, dex),
                    2,
                    deadline,
                    weight,
                )
                .await?;
            let at = anchor["time"].as_i64()?;
            if at < from || at.saturating_sub(from) > 86_400_000 {
                return None;
            }
            until = until.max(at);
            anchors.push((dex, anchor));
        }
        let fills = self.flow_info(now,json!({"type":"userFillsByTime","user":inner.account.to_hex(),"startTime":from,"endTime":until,"aggregateByTime":false}),45,deadline,weight).await?;
        let funding = self.flow_info(now,json!({"type":"userFunding","user":inner.account.to_hex(),"startTime":from,"endTime":until}),45,deadline,weight).await?;
        let ledger = self.flow_info(now,json!({"type":"userNonFundingLedgerUpdates","user":inner.account.to_hex(),"startTime":from,"endTime":until}),45,deadline,weight).await?;
        let fills = fills.as_array()?;
        let funding = funding.as_array()?;
        let ledger = ledger.as_array()?;
        if fills.len() >= 500 || funding.len() >= 500 || ledger.len() >= 500 {
            return None;
        }
        if !flow_value::valid_ledger(ledger) {
            return None;
        }
        if fills
            .iter()
            .any(|row| row["coin"].as_str().is_none() || row["time"].as_i64().is_none())
            || funding.iter().any(|row| {
                row["delta"]["coin"].as_str().is_none() || row["time"].as_i64().is_none()
            })
            || ledger.iter().any(|row| {
                row["time"].as_i64().is_none()
                    || row["delta"]["type"].as_str().is_none()
                    || row["delta"]["type"] == "liquidation"
            })
        {
            return None;
        }
        if !ledger
            .iter()
            .filter_map(|row| ledger_flow(row, inner.account, dexes))
            .any(|item| item.id == flow.id)
        {
            return None;
        }
        let mut equity = Decimal::ZERO;
        for (dex, anchor) in anchors {
            let on_dex = |coin: &str| {
                coin.split_once(':')
                    .map_or(dex.is_empty(), |(name, _)| name == dex)
            };
            let scoped_fills: Vec<Value> = fills
                .iter()
                .filter(|fill| fill["coin"].as_str().is_some_and(on_dex))
                .cloned()
                .collect();
            let scoped_funding: Vec<Value> = funding
                .iter()
                .filter(|row| row["delta"]["coin"].as_str().is_some_and(on_dex))
                .cloned()
                .collect();
            // Read each dex's own ledger effect, including the principal of
            // internal transfers. The summed reconstruction cancels it.
            let one = std::collections::BTreeSet::from([dex.clone()]);
            let mut other = Vec::new();
            let mut target_amount = Decimal::ZERO;
            for row in ledger {
                if let Some(item) = ledger_flow(row, inner.account, &one) {
                    if item.id != flow.id {
                        other.push((item.time_ms, item.amount));
                    } else {
                        target_amount = target_amount.checked_add(item.amount)?;
                    }
                }
            }
            let value = flow_value::reconstruct(
                &anchor,
                flow.time_ms,
                &scoped_fills,
                &scoped_funding,
                &other,
                target_amount,
            )?;
            equity = equity.checked_add(value)?;
        }
        Some(zunder_venue::ValueRange::cash_exact(equity))
    }

    /// Count and journal what became of flows (applied when known, or when
    /// an observation first showed them).
    fn note_flows(inner: &mut Inner, now: u64) {
        for (flow, outcome) in inner.risk.take_flow_outcomes() {
            match outcome {
                FlowOutcome::Applied => {
                    inner.flows_applied += 1;
                    inner.flow_note = None;
                    inner
                        .journal
                        .append(
                            now as i64,
                            EventBody::Error {
                                text: format!(
                                    "a flow of {} USDC (deposit, withdrawal or transfer) kept out of the account stops",
                                    flow.amount
                                ),
                            },
                        )
                        .ok();
                }
                FlowOutcome::Skipped(why) => {
                    inner.flow_note = Some(format!(
                        "a flow of {} USDC counts as a gain or loss: {why}",
                        flow.amount
                    ));
                }
                FlowOutcome::Duplicate | FlowOutcome::Pending => {}
            }
        }
        // A drawdown stop waived next to a withdrawal (the loss may have
        // come before it): the day halted instead. A person should know.
        for waived in inner.risk.take_waived_stops() {
            let text = if let Some(reason) = waived.reason {
                format!(
                    "account-flow arithmetic cannot be represented: {reason}; money stays pending and entries blocked; review may be needed"
                )
            } else if waived.measured {
                format!(
                    "account value at a flow is uncertain: measured ranges disagree, worst drawdown {}, retained {}; Guard halted the day (docs/guard.md#deposits-and-withdrawals, S5)",
                    percent(waived.waived),
                    percent(waived.kept)
                )
            } else {
                "account value at a flow is uncertain: complete exact reconstruction unavailable (positions open at transfer or incomplete records); Guard halted the day (docs/guard.md#deposits-and-withdrawals, S5)".to_owned()
            };
            inner
                .journal
                .append(now as i64, EventBody::Error { text: text.clone() })
                .ok();
            Self::add_alert(inner, now, &text, None);
        }
    }

    /// Flatten if the risk engine halted or the kill switch is on: from
    /// `account` when it was just read from the venue (`read`), else from
    /// one read now (within [`LOCKED_READ_MS`]; the positions alone if the
    /// account cannot be read). Never from the stream's view: closes are
    /// bounded around the mids, and those must be the venue's own of this
    /// moment. The read now is skipped when neither the stream's view nor
    /// the last read showed anything to flatten, when one was made in the
    /// last [`HALT_READ_EVERY_MS`], or when the request-read budget is
    /// spent: the background sync reads and flattens at its next round
    /// either way, and a bot that keeps sending while Guard is halted must
    /// not spend the venue's request limit that flattening needs.
    async fn halt(&self, inner: &mut Inner, now: u64, account: &AccountView, read: bool) {
        let Some(reason) = Self::halt_reason(inner) else {
            inner.reported_halt = None;
            return;
        };
        if read {
            self.flatten(inner, now, account, &reason).await;
            return;
        }
        // A paper Guard that reported this halt has nothing more to do.
        let sends = matches!(inner.mode, Mode::Send { .. });
        if !sends && inner.reported_halt.as_deref() == Some(reason.as_str()) {
            return;
        }
        if !halt_read_due(
            now,
            inner.last_halt_read_ms,
            exposed(account),
            inner.last_read_exposed,
        ) {
            return;
        }
        let dexes = 1 + inner.config.policy.markets.hip3_dexes().len() as u64;
        let allowed = self
            .request_budget
            .lock()
            .map(|mut budget| budget.take(now, ACCOUNT_READ_WEIGHT * dexes))
            .unwrap_or(false);
        if !allowed {
            return;
        }
        inner.last_halt_read_ms = Some(now);
        match self.read_locked(&mut inner.caches, now).await {
            Ok((account, _)) => {
                inner.last_read_exposed = Some(exposed(&account));
                self.flatten(inner, now, &account, &reason).await;
            }
            Err(error) => {
                let text = format!("reading the account to flatten: {error}");
                inner.last_error = Some(text);
                if let Ok(positions) = self.positions_locked(&mut inner.caches, now).await {
                    self.flatten(inner, now, &positions, &reason).await;
                }
            }
        }
    }

    /// [`Guard::read_account_parts`] within [`LOCKED_READ_MS`]: for reads
    /// made holding Guard's lock.
    async fn read_locked(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<(AccountView, Vec<String>), UpstreamError> {
        tokio::time::timeout(
            Duration::from_millis(LOCKED_READ_MS),
            self.read_account_parts(caches, now),
        )
        .await
        .unwrap_or_else(|_| {
            Err(UpstreamError::NoAnswer(format!(
                "no account within {LOCKED_READ_MS} ms"
            )))
        })
    }

    /// Bound only the read-only future while holding the lock. A request
    /// cannot start another hold until this lock is released.
    async fn sync_read_locked(
        &self,
        caches: &mut Caches,
        now: u64,
        deadline: Option<u64>,
    ) -> Result<(AccountView, Vec<String>), UpstreamError> {
        let remaining = deadline.map_or(LOCKED_READ_MS, |deadline| {
            deadline
                .saturating_sub(self.clock.now_ms())
                .min(LOCKED_READ_MS)
        });
        tokio::time::timeout(
            Duration::from_millis(remaining),
            self.read_locked(caches, now),
        )
        .await
        .unwrap_or_else(|_| {
            Err(UpstreamError::NoAnswer(
                "account read reached loss-hold deadline".to_owned(),
            ))
        })
    }

    /// A hold can begin on a request while this unlocked read waits.
    /// Register the broadcast before checking the current deadline to
    /// avoid missing that race. No journal, signer or send is cancelled.
    async fn sync_read_unlocked(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<(AccountView, Vec<String>), UpstreamError> {
        let read = self.read_account_parts(caches, now);
        tokio::pin!(read);
        loop {
            let changed = self.hold_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let deadline = self
                .inner
                .lock()
                .await
                .ledger_hold
                .as_ref()
                .map(|hold| hold.since.saturating_add(LEDGER_HOLD_MS));
            if let Some(deadline) = deadline {
                tokio::select! {
                    result = &mut read => return result,
                    _ = &mut changed => {},
                    _ = tokio::time::sleep(Duration::from_millis(deadline.saturating_sub(self.clock.now_ms()))) => {
                        let inner = self.inner.lock().await;
                        if inner.ledger_hold.as_ref().is_some_and(|hold| self.clock.now_ms().saturating_sub(hold.since) >= LEDGER_HOLD_MS) {
                            return Err(UpstreamError::NoAnswer("account read reached loss-hold deadline".to_owned()));
                        }
                    }
                }
            } else {
                tokio::select! { result = &mut read => return result, _ = &mut changed => {} }
            }
        }
    }

    /// [`Guard::read_positions`] within [`LOCKED_READ_MS`].
    async fn positions_locked(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<AccountView, UpstreamError> {
        tokio::time::timeout(
            Duration::from_millis(LOCKED_READ_MS),
            self.read_positions(caches, now),
        )
        .await
        .unwrap_or_else(|_| {
            Err(UpstreamError::NoAnswer(format!(
                "no positions within {LOCKED_READ_MS} ms"
            )))
        })
    }

    fn halt_reason(inner: &Inner) -> Option<String> {
        match (&inner.killed, inner.risk.state()) {
            (Some(reason), _) => Some(format!("kill switch: {reason}")),
            (None, RiskState::Active) => None,
            (None, RiskState::HaltedForDay { .. }) => Some("daily loss stop".to_owned()),
            (None, RiskState::Stopped { .. }) => Some("drawdown halt".to_owned()),
        }
    }

    async fn flatten(&self, inner: &mut Inner, now: u64, account: &AccountView, reason: &str) {
        if inner.killed.is_some() && inner.positions_at_kill.is_none() {
            inner.positions_at_kill = Some(account.positions.len());
        }
        if !exposed(account) {
            return;
        }
        let (actions, problems) = flatten_actions(account, &inner.config.policy);
        let actions: Vec<Action> = actions
            .iter()
            .map(|action| {
                with_client_ids(
                    action,
                    &mut inner.client_ids,
                    &inner.salt,
                    CLOSE_CLOID_PREFIX,
                )
                .0
            })
            .collect();
        let sends = matches!(inner.mode, Mode::Send { .. });
        let fee = inner.fee.clone();
        if !sends && inner.reported_halt.as_deref() == Some(reason) {
            return;
        }
        let named: Vec<Value> = actions
            .iter()
            .map(|action| fee.apply(action).to_wire().to_value())
            .collect();
        let event = EventBody::Flatten {
            reason: reason.to_owned(),
            actions: named.clone(),
            problems,
            sent: sends,
        };
        // On disk before the closes are sent (a writer behind is waited
        // for); if the journal is broken, they go all the same (E1:
        // closing is never held up), each with its intent in the emergency
        // log.
        let seq = if sends {
            match inner
                .journal
                .append_durable_waiting(now as i64, event)
                .await
            {
                Ok(seq) => {
                    inner.intent = Some((seq, now, named));
                    seq
                }
                Err(_) => 0,
            }
        } else {
            inner.journal.append(now as i64, event).unwrap_or(0)
        };
        inner.reported_halt = Some(reason.to_owned());
        if sends {
            for action in &actions {
                // Flattening goes on even when the journal cannot be
                // written: closing is never held up.
                let result = self
                    .send_one(inner, now, seq, action, self.clock.now_ms() + ACTION_TTL_MS)
                    .await;
                // A close the venue takes but fills nothing of is the likely
                // failure in a crash: an alert as much as a send error.
                let problem = match (&result, action) {
                    (Err(error), _) => Some(error.clone()),
                    (Ok(reply), Action::Order(_)) => match order_statuses(reply) {
                        Ok(statuses) => statuses
                            .iter()
                            .find(|status| !matches!(status, OrderStatus::Filled { .. }))
                            .map(|status| format!("a close did not fill: {status:?}")),
                        Err(error) => Some(error),
                    },
                    (Ok(reply), _) => action_ok(reply).err(),
                };
                if let Some(problem) = problem {
                    let text = format!("flattening: {problem}");
                    Self::add_alert(inner, now, &text, None);
                    inner.last_error = Some(text);
                }
            }
            if seq > 0 {
                inner
                    .journal
                    .append(self.clock.now_ms() as i64, EventBody::Done { intent: seq })
                    .ok();
            }
        }
    }

    /// The background sync: check the kill file, read the account, feed
    /// the risk engine, flatten if needed. When the account cannot be read
    /// and Guard is halted or killed, it flattens from the positions alone.
    pub async fn sync(&self) {
        let mut inner = self.inner.lock().await;
        let started = self.clock.now_ms();
        Self::check_kill(&mut inner, started);
        Self::licence_tick(&mut inner, started, true);
        self.expire_hold(&mut inner, started);
        let deadline = inner
            .ledger_hold
            .as_ref()
            .map(|hold| hold.since.saturating_add(LEDGER_HOLD_MS));
        // Read with Guard's lock released: a request meanwhile is judged
        // at once (from its own read or the stream), not after the sync's
        // round trips to the venue. Should Guard send anything meanwhile,
        // this read may predate the send: it is read again, holding the lock
        // (within LOCKED_READ_MS), so that the round always finishes, and
        // protection and flattening never act on a view older than Guard's
        // own sends, however often a bot sends.
        // A bot that sent within the last SYNC_LOCKED_AFTER_SEND_MS will
        // likely send again: then the sync reads holding the lock at once,
        // one read rather than two. So does a Guard whose `ip_share`
        // stretched the sync so far that a skipped round (after reading
        // twice) would leave more than 30 s between two reads; when such a
        // locked read fails (a venue slower than LOCKED_READ_MS), the next
        // round reads without the lock, whose read has no overall limit.
        let share_locked =
            self.budgets.sync_reads_locked() && !std::mem::take(&mut inner.sync_unlock_next);
        let sending = share_locked
            || inner
                .last_send_ms
                .is_some_and(|sent| started.saturating_sub(sent) < SYNC_LOCKED_AFTER_SEND_MS);
        let (mut inner, _read_started, read) = if sending {
            let read = self
                .sync_read_locked(&mut inner.caches, started, deadline)
                .await;
            inner.sync_read_twice = false;
            inner.last_sync_reads = 1;
            inner.sync_unlock_next = share_locked && read.is_err();
            (inner, started, read)
        } else {
            let mut caches = inner.caches.clone();
            let sent_before = inner.sends;
            drop(inner);
            let read = self.sync_read_unlocked(&mut caches, started).await;
            let mut inner = self.inner.lock().await;
            inner.caches.take_newer(caches);
            if inner.sends == sent_before {
                inner.sync_read_twice = false;
                inner.last_sync_reads = 1;
                (inner, started, read)
            } else {
                let now = self.clock.now_ms();
                let deadline = inner
                    .ledger_hold
                    .as_ref()
                    .map(|hold| hold.since.saturating_add(LEDGER_HOLD_MS));
                let read = self
                    .sync_read_locked(&mut inner.caches, now, deadline)
                    .await;
                inner.sync_read_twice = true;
                inner.last_sync_reads = 2;
                (inner, now, read)
            }
        };
        // Awaited reads may cross the hold deadline. Expire before any
        // success, failure, protection or flatten handling uses the result.
        let now = self.clock.now_ms();
        self.expire_hold(&mut inner, now);
        // A complete read of every dex Guard manages.
        let read_ok = matches!(&read, Ok((_, unread)) if unread.is_empty());
        match read {
            Ok((account, unread)) if !unread.is_empty() => {
                // Part of the account: the risk engine is not shown it (the
                // missing dexes' equity would read as a loss), and no request
                // is judged against it; what was read is still protected, and
                // flattened on a halt or the kill switch.
                let text = format!(
                    "reading the account: HIP-3 dex {} could not be read; its positions go unprotected by Guard until it can be, and no entry is judged",
                    unread.join(", ")
                );
                if inner.last_error.as_deref() != Some(text.as_str()) {
                    inner
                        .journal
                        .append(now as i64, EventBody::Error { text: text.clone() })
                        .ok();
                }
                inner.last_error = Some(text);
                // Protection waits as after a complete read: until nothing
                // Guard sent can still be on its way.
                let settled = inner
                    .last_send_ms
                    .is_none_or(|sent| now.saturating_sub(sent) >= SETTLE_MS);
                let overdue = inner
                    .last_protect_ms
                    .is_none_or(|at| now.saturating_sub(at) >= PROTECT_AT_LEAST_EVERY_MS);
                if let Some(reason) = Self::halt_reason(&inner) {
                    self.flatten(&mut inner, now, &account, &reason).await;
                } else if settled || overdue || inner.protect_now {
                    self.protect_planned(&mut inner, now, &account, false).await;
                }
            }
            Ok((account, _)) => {
                inner.last_error = None;
                inner.last_read_exposed = Some(exposed(&account));
                // Shown to the risk engine when it is newer than the view
                // it saw last (a request's from the stream may be older,
                // or newer: a request may have read while this was read),
                // stamped no earlier than its last observation, so that
                // its observations stay in time order.
                if inner
                    .last_view
                    .as_ref()
                    .is_none_or(|last| last.at_ms <= account.at_ms)
                {
                    let at = now.max(inner.last_sync_ms.unwrap_or(0));
                    if self.take_flows(&mut inner, at, &account).await {
                        self.observe(&mut inner, at, &account);
                    }
                }
                self.halt(&mut inner, now, &account, true).await;
                // A licence alert stays while what it says holds (an end
                // near, a key not used, a config not read); others an hour.
                let licence_stays = inner.licence.alert_stays();
                inner.alerts.retain(|alert| match alert.oid {
                    Some(oid) => account.open_orders.iter().any(|order| order.oid == oid),
                    None => {
                        (licence_stays && alert.text.starts_with(LICENCE_ALERT))
                            || now.saturating_sub(alert.at_ms) < ALERT_KEEP_MS
                    }
                });
                Self::follow_resting(&mut inner, &account);
                let settled = inner
                    .last_send_ms
                    .is_none_or(|sent| now.saturating_sub(sent) >= SETTLE_MS);
                let overdue = inner
                    .last_protect_ms
                    .is_none_or(|at| now.saturating_sub(at) >= PROTECT_AT_LEAST_EVERY_MS);
                if Self::halt_reason(&inner).is_some() {
                    // Flattening handles every position; its failures are
                    // alerts of their own.
                    inner.position_alert = None;
                } else if settled || overdue || inner.protect_now {
                    self.protect(&mut inner, now, &account).await;
                }
            }
            Err(error) => {
                let text = format!("reading the account: {error}");
                if inner.last_error.as_deref() != Some(text.as_str()) {
                    inner
                        .journal
                        .append(now as i64, EventBody::Error { text: text.clone() })
                        .ok();
                }
                inner.last_error = Some(text);
                if let Some(reason) = Self::halt_reason(&inner)
                    && let Ok(positions) = self.positions_locked(&mut inner.caches, now).await
                {
                    self.flatten(&mut inner, now, &positions, &reason).await;
                }
            }
        }
        // Optional unmanaged-account monitoring waits until the held
        // observation has settled; protective operations above still run.
        if inner.ledger_hold.is_none() {
            self.sweep(&mut inner, now).await;
        }
        // The builder fee approval, last and outside the lock, so that
        // protecting, flattening and requests never wait for it; only after
        // a good read of the account (a venue that cannot answer that gets
        // no further request). At start, then every few minutes (every
        // minute while it is missing, or at the next sync for an entry).
        // Not on a kill (its reply should not wait for it).
        let request = (read_ok && inner.killed.is_none() && inner.fee.check_due(now))
            .then(|| inner.fee.check_request(&inner.account.to_hex()))
            .flatten();
        let Some(request) = request else {
            return;
        };
        let ticket = inner.fee.begin_check(now);
        drop(inner);
        let answer = match tokio::time::timeout(
            Duration::from_millis(licence::CHECK_TIMEOUT_MS),
            self.upstream.info(&request),
        )
        .await
        {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => Err(format!("no answer within {} ms", licence::CHECK_TIMEOUT_MS)),
        };
        let mut inner = self.inner.lock().await;
        let now = self.clock.now_ms();
        Self::record_fee_check(
            &mut inner,
            ticket,
            now,
            answer.as_ref().map_err(Clone::clone),
        );
    }

    /// Look at one perp dex Guard does not manage, one every
    /// [`SWEEP_EVERY_MS`], in turn: positions there are reported in the
    /// status and as an alert, and never judged, protected or closed, not
    /// even by the kill switch (`docs/guard.md`, "HIP-3 markets").
    async fn sweep(&self, inner: &mut Inner, now: u64) {
        if inner
            .last_sweep_ms
            .is_some_and(|at| now.saturating_sub(at) < SWEEP_EVERY_MS)
        {
            return;
        }
        inner.last_sweep_ms = Some(now);
        let Ok(listed) = self.perp_dexs(&mut inner.caches, now).await else {
            return;
        };
        let managed = inner.config.policy.markets.hip3_dexes();
        let others: Vec<(u32, String)> = listed
            .into_iter()
            .filter(|(_, name)| !managed.contains(name))
            .collect();
        inner
            .unmanaged
            .retain(|name, _| others.iter().any(|(_, other)| other == name));
        if others.is_empty() {
            return;
        }
        let at = inner.sweep_at % others.len();
        inner.sweep_at = at + 1;
        let Some((index, name)) = others.get(at).cloned() else {
            return;
        };
        let Ok(state) = self
            .upstream
            .info(&requests::clearinghouse_state_of(inner.account, &name))
            .await
        else {
            return;
        };
        match unmanaged_positions(&state) {
            Some((value, coins)) if !coins.is_empty() => {
                let new = inner
                    .unmanaged
                    .get(&name)
                    .is_none_or(|seen| seen.coins != coins);
                if new {
                    inner
                        .journal
                        .append(
                            now as i64,
                            EventBody::Error {
                                text: unmanaged_text(&name, &coins),
                            },
                        )
                        .ok();
                }
                inner.unmanaged.insert(
                    name,
                    Unmanaged {
                        index,
                        coins,
                        value,
                        seen_ms: now,
                    },
                );
            }
            Some(_) => {
                inner.unmanaged.remove(&name);
            }
            None => {}
        }
    }

    /// Run [`Guard::sync`] every `sync_seconds` (slower with HIP-3 dexes
    /// and a smaller `ip_share`: [`crate::budget::Budgets::sync_interval_ms`])
    /// until the task is dropped.
    pub async fn sync_forever(self: Arc<Self>) {
        let interval = {
            let inner = self.inner.lock().await;
            self.budgets.sync_interval_ms(inner.config.sync_seconds)
        };
        let mut ticker = tokio::time::interval(Duration::from_millis(interval));
        // A slow read delays the next sync; missed ticks are not run back
        // to back.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let held = self.inner.lock().await.ledger_hold.is_some();
            if held {
                tokio::time::sleep(Duration::from_millis(LEDGER_READ_EVERY_MS)).await;
            } else {
                tokio::select! {
                    _ = ticker.tick() => {},
                    _ = self.hold_started.notified() => continue,
                }
            }
            self.sync().await;
            // A skipped normal round must not delay a pending hold.
            let mut inner = self.inner.lock().await;
            let skip = std::mem::take(&mut inner.sync_read_twice);
            if skip && inner.ledger_hold.is_none() {
                ticker.reset_at(
                    tokio::time::Instant::now() + Duration::from_millis(interval.saturating_mul(2)),
                );
            }
        }
    }

    /// The actions an intent named that nothing answers (a crash, a send
    /// in doubt): what [`Guard::recover`] asks the venue about. Take them
    /// before anything else runs, so that only the last run's are in it.
    pub async fn pending_for_recovery(&self) -> Vec<crate::recover::Pending> {
        let inner = self.inner.lock().await;
        if matches!(inner.mode, Mode::Send { .. }) {
            inner.journal.pending()
        } else {
            Vec::new()
        }
    }

    /// Mark Guard as recovering (or not) before it serves: bots' requests
    /// are refused from the first one on until [`Guard::recover`] ends.
    pub fn set_recovering(&self, on: bool) {
        self.recovering.store(on, Ordering::SeqCst);
    }

    /// Whether Guard is still recovering after a restart: bots' requests
    /// are refused until it is done; protection and flattening go on.
    pub fn recovering(&self) -> bool {
        self.recovering.load(Ordering::SeqCst)
    }

    /// Watch the config file at `path` for a new licence key (`zunder-guard
    /// licence set`): read at every sync, apply only a changed licence
    /// key; every other setting still needs a restart.
    pub async fn watch_config(&self, path: std::path::PathBuf) {
        let mut inner = self.inner.lock().await;
        // Startup can wait for key input after loading its config. Reconcile
        // now so a licence installed during that wait is applied before serving.
        inner.licence.file = Some(path);
        Self::licence_tick(&mut inner, self.clock.now_ms(), true);
    }

    /// The licence's lifecycle (`licence.rs`, "Lifecycle"): with
    /// `read_file`, a new key in the watched config file; then expiry (the
    /// fee from this moment on) and the warnings before it.
    fn licence_tick(inner: &mut Inner, now: u64, read_file: bool) {
        if read_file && let Some(path) = inner.licence.file.clone() {
            // Equal-length replacements can retain the same modification time.
            // Read the config itself at every sync; only a changed key is applied.
            match GuardConfig::load(&path) {
                Ok(config) => {
                    inner.licence.file_error = None;
                    if config.licence != inner.licence.key {
                        inner.licence.key = config.licence;
                        inner.licence.warned = None;
                        Self::licence_apply(inner, now, "a new licence key in the config file");
                    }
                }
                Err(error) => {
                    let text = format!(
                        "{LICENCE_ALERT}the config file could not be read for a new licence key ({error}); Guard keeps the key it runs with"
                    );
                    if inner.licence.file_error.as_deref() != Some(text.as_str()) {
                        inner.licence.file_error = Some(text.clone());
                        Self::licence_alert(inner, now, Some(&text));
                    }
                }
            }
        }
        let Some((licensee, expires)) = inner.licence.valid.clone() else {
            return;
        };
        if now as i64 >= expires {
            Self::licence_apply(inner, now, "the licence expired");
            return;
        }
        if let Some(stage) = licence::expiry_stage(expires, now as i64)
            && inner.licence.warned.is_none_or(|warned| stage < warned)
        {
            inner.licence.warned = Some(stage);
            let days = licence::days_left(expires, now as i64);
            let text = format!(
                "{LICENCE_ALERT}the licence for {licensee} ends in {days} day(s), at {}: renew it (zunderlabs.com/licence, then zunder-guard licence set), or Guard falls back to the builder fee then (entries then wait for the fee's approval; protection never does)",
                utc_text(expires)
            );
            eprintln!("zunder-guard: {text}");
            Self::licence_alert(inner, now, Some(&text));
        }
    }

    /// Run with the fee mode the configured key gives now, saying why
    /// (`why`) when the mode changes: in the journal, on standard error,
    /// and as an alert.
    fn licence_apply(inner: &mut Inner, now: u64, why: &str) {
        let account = inner.account;
        let (mode, warning) = inner.licence.mode(account, now);
        let changed = inner.fee.switch_mode(mode.clone());
        let mode_text = match &mode {
            FeeMode::FeeFree { licensee } => format!("fee-free, licensed to {licensee}"),
            FeeMode::Builder(builder) => format!(
                "the builder fee, {} to {} (entries wait until its approval is read)",
                licence::rate(builder.fee_tenths_bp),
                builder.address
            ),
            FeeMode::Off(text) => format!("no builder fee ({text})"),
        };
        let mut text = format!("{LICENCE_ALERT}{why}: Guard now runs {mode_text}");
        if let Some(warning) = &warning {
            text.push_str(&format!("; {warning}"));
        }
        if let Some((licensee, expires)) = &inner.licence.valid {
            text.push_str(&format!(
                "; licensed to {licensee} until {}",
                utc_text(*expires)
            ));
        }
        if changed || warning.is_some() {
            eprintln!("zunder-guard: {text}");
            inner
                .journal
                .append(now as i64, EventBody::Error { text: text.clone() })
                .ok();
            Self::licence_alert(inner, now, Some(&text));
        } else {
            Self::licence_alert(inner, now, None);
        }
    }

    /// Replace the licence alert (`None`: remove it).
    fn licence_alert(inner: &mut Inner, now: u64, text: Option<&str>) {
        inner
            .alerts
            .retain(|alert| !alert.text.starts_with(LICENCE_ALERT));
        if let Some(text) = text {
            Self::add_alert(inner, now, text, None);
        }
    }

    /// Tests only (feature `test-hooks`, never in a release build): check
    /// licences against `public_key` and fall back to these builders.
    #[cfg(feature = "test-hooks")]
    pub async fn set_licence_keys_for_test(
        &self,
        public_key: [u8; 32],
        mainnet_builder: Option<String>,
        testnet_builder: Option<String>,
    ) {
        let mut inner = self.inner.lock().await;
        inner.licence.public_key = Some(public_key);
        inner.licence.builders = (mainnet_builder, testnet_builder);
        let account = inner.account;
        let now = self.clock.now_ms();
        let (mode, _) = inner.licence.mode(account, now);
        inner.fee.switch_mode(mode);
    }

    /// A recovery that panicked: bots are served again (its flag cleared),
    /// so a person checks the account.
    pub async fn recovery_failed(&self) {
        let mut inner = self.inner.lock().await;
        let now = self.clock.now_ms();
        let text = "recovery after a restart failed: what became of the actions sent before it is not known; check the account";
        eprintln!("zunder-guard: {text}");
        Self::add_alert(&mut inner, now, text, None);
        inner
            .journal
            .append(now as i64, EventBody::Error { text: text.into() })
            .ok();
    }

    /// Wait until Guard's clock reads `at_ms`.
    async fn wait_until(&self, at_ms: u64) {
        loop {
            let now = self.clock.now_ms();
            if now >= at_ms {
                return;
            }
            tokio::time::sleep(Duration::from_millis((at_ms - now).clamp(1, 50))).await;
        }
    }

    /// Recovery after a crash (`docs/guard.md#journals`), run
    /// beside the background sync (which protects and flattens meanwhile):
    /// each of `pending` is looked up at the venue once it has expired,
    /// within [`RECOVERY_MS`] in all (what is left then is `unknown`), its
    /// reads charged to the request budget, and its outcome journaled:
    /// `happened`, `did_not_happen`, `moot` or `unknown` (with an alert).
    /// Bots' requests are refused until it is done. Returns how many were
    /// concluded.
    pub async fn recover(&self, pending: Vec<crate::recover::Pending>) -> usize {
        self.recover_after(pending, crate::recover::MAX_TTL_MS, RECOVERY_MS)
            .await
    }

    /// [`Guard::recover`], the actions taken as expired `ttl_ms` after
    /// their intent, within `bound_ms` (tests wait less than the venue's
    /// limit).
    #[doc(hidden)]
    pub async fn recover_after(
        &self,
        pending: Vec<crate::recover::Pending>,
        ttl_ms: i64,
        bound_ms: u64,
    ) -> usize {
        // Bots are served again when recovery ends, however it ends (a
        // panic included: then an alert says so).
        let _served = ClearOnDrop(&self.recovering);
        if pending.is_empty() {
            return 0;
        }
        self.recovering.store(true, Ordering::SeqCst);
        let started = self.clock.now_ms();
        let deadline = started.saturating_add(bound_ms);
        // Until every one has expired (or the bound): then the venue's
        // answer is final.
        let ready = pending
            .iter()
            .map(|pending| pending.at_ms.saturating_add(ttl_ms))
            .max()
            .unwrap_or(0)
            .min(deadline as i64);
        self.wait_until(u64::try_from(ready).unwrap_or(0)).await;
        let account = self.inner.lock().await.account;
        let mut concluded: Vec<Option<crate::recover::Conclusion>> = vec![None; pending.len()];
        // An order the venue did not know: read once more
        // RECOVERY_READ_AGAIN_MS later before concluding it never happened
        // (the venue's info may trail its book). Those reads go first when
        // due, so that a backlog the budget cannot read in time still
        // concludes what it reads. Without the time for the second read:
        // unknown.
        let mut again: VecDeque<(usize, u64, crate::recover::Conclusion)> = VecDeque::new();
        let mut next = 0;
        loop {
            let now = self.clock.now_ms();
            if let Some((_, due, _)) = again.front()
                && *due <= now
                && now < deadline
                && let Some((at, _, _)) = again.pop_front()
            {
                concluded[at] = Some(self.conclude(account, &pending[at], deadline).await);
                continue;
            }
            if let Some(item) = pending.get(next) {
                let conclusion = self.conclude(account, item, deadline).await;
                if conclusion.outcome == "did_not_happen"
                    && matches!(
                        crate::recover::identity(&item.action),
                        crate::recover::Identity::Orders(_)
                    )
                {
                    let due = self.clock.now_ms().saturating_add(RECOVERY_READ_AGAIN_MS);
                    again.push_back((next, due, conclusion));
                } else {
                    concluded[next] = Some(conclusion);
                }
                next += 1;
                continue;
            }
            match again.front() {
                Some((_, due, _)) if *due < deadline && now < deadline => {
                    self.wait_until(*due).await;
                }
                _ => break,
            }
        }
        for (at, _, first) in again {
            concluded[at] = Some(crate::recover::Conclusion {
                outcome: "unknown",
                evidence: json!({
                    "why": "recovery ran out of time for the second read",
                    "first_read": first.evidence,
                }),
            });
        }
        let mut inner = self.inner.lock().await;
        let now = self.clock.now_ms();
        let mut unwritten = 0;
        // One deadline for writing them all: Guard's lock is held while
        // the writer is waited for, and the sync (protection) waits for it.
        let until =
            std::time::Instant::now() + Duration::from_millis(crate::journal::ACK_DEADLINE_MS);
        for (item, conclusion) in pending.iter().zip(concluded) {
            let conclusion = conclusion.unwrap_or_else(|| crate::recover::Conclusion {
                outcome: "unknown",
                evidence: json!({"why": "recovery ran out of time"}),
            });
            if conclusion.outcome == "unknown" {
                let text = format!(
                    "after a restart, what became of an action sent before it is not known (intent {}, action {}): check the account; {}",
                    item.intent, item.index, item.action
                );
                Self::add_alert(&mut inner, now, &text, None);
            }
            // Waited for when the writer is behind (bots are refused
            // meanwhile), within the deadline: a conclusion is not dropped
            // lightly.
            let written = inner
                .journal
                .append_waiting(
                    now as i64,
                    EventBody::Recovered {
                        intent: item.intent,
                        index: item.index as u64,
                        action: item.action.clone(),
                        outcome: conclusion.outcome.to_owned(),
                        evidence: conclusion.evidence,
                    },
                    until,
                )
                .await;
            if written.is_err() {
                unwritten += 1;
            }
        }
        if unwritten > 0 {
            let text = format!(
                "after a restart, {unwritten} recovery conclusion(s) were not written to the decision journal (its writer was behind or broken): those actions stay open, and recovery asks the venue about them again at the next restart; check the account"
            );
            Self::add_alert(&mut inner, now, &text, None);
        }
        let durable = inner.journal.flush_when_room(until).await;
        drop(inner);
        // On disk before bots are served again; a writer still behind has
        // them queued (synced within a second), not lost.
        match durable.wait().await {
            Ok(()) | Err(crate::journal::JournalError::Busy) => {}
            Err(error) => {
                let text = format!(
                    "after a restart, recovery's conclusions could not be synced to the decision journal, which is now broken ({error}): nothing is forwarded until a restart on an intact journal"
                );
                let mut inner = self.inner.lock().await;
                Self::add_alert(&mut inner, now, &text, None);
            }
        }
        pending.len()
    }

    /// One read for recovery, within the request budget: it waits for the
    /// bucket to hold `weight` (bots' requests are refused meanwhile, so
    /// the budget is recovery's), and for the venue's answer, until
    /// `deadline` at most. `None` when the deadline came first.
    async fn recovery_read(&self, body: &Value, weight: u64, deadline: u64) -> Option<Value> {
        loop {
            let now = self.clock.now_ms();
            if now >= deadline {
                return None;
            }
            let wait = self
                .request_budget
                .lock()
                .map_or(Err(u64::MAX), |mut budget| budget.take_or_wait(now, weight));
            match wait {
                Ok(()) => break,
                Err(ms) => {
                    let ms = ms.min(deadline - now).clamp(1, 50);
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                }
            }
        }
        let left = deadline.saturating_sub(self.clock.now_ms());
        match tokio::time::timeout(Duration::from_millis(left), self.upstream.info(body)).await {
            Ok(Ok(answer)) => Some(answer),
            Ok(Err(error)) => Some(json!({"error": error.to_string()})),
            Err(_) => None,
        }
    }

    /// Ask the venue what became of one pending action, its reads done by
    /// `deadline` (else it is `unknown`).
    async fn conclude(
        &self,
        account: Address,
        item: &crate::recover::Pending,
        deadline: u64,
    ) -> crate::recover::Conclusion {
        use crate::recover::{
            Conclusion, Identity, conclude_cancel_action, conclude_leverage, conclude_order_action,
            identity, telling_orders,
        };
        let status =
            |id: Value| json!({"type": "orderStatus", "user": account.to_hex(), "oid": id});
        let unknown = |why: &str| Conclusion {
            outcome: "unknown",
            evidence: json!({"why": why}),
        };
        let out_of_time = || unknown("recovery ran out of time");
        match identity(&item.action) {
            Identity::Orders(_) => {
                let orders = telling_orders(&item.action);
                let mut answers = Vec::with_capacity(orders.len());
                for order in &orders {
                    answers.push(match order.get("c").and_then(Value::as_str) {
                        Some(cloid) => {
                            match self.recovery_read(&status(json!(cloid)), 2, deadline).await {
                                Some(answer) => answer,
                                None => return out_of_time(),
                            }
                        }
                        None => Value::Null,
                    });
                }
                let inner = self.inner.lock().await;
                let item = inner.journal.refreshed(item, &answers);
                conclude_order_action(&item, &answers, &|oid| inner.journal.answered_oid(oid))
            }
            Identity::Cancels(refs) => {
                let mut answers = Vec::with_capacity(refs.len());
                for order in refs {
                    let id = match order {
                        zunder_guard_core::action::OrderRef::Oid(oid) => json!(oid),
                        zunder_guard_core::action::OrderRef::Cloid(cloid) => json!(cloid.as_str()),
                    };
                    match self.recovery_read(&status(id), 2, deadline).await {
                        Some(answer) => answers.push(answer),
                        None => return out_of_time(),
                    }
                }
                let item = self.inner.lock().await.journal.refreshed(item, &answers);
                conclude_cancel_action(&item, &answers)
            }
            Identity::Leverage {
                asset,
                cross,
                leverage,
            } => {
                let coin = {
                    let inner = self.inner.lock().await;
                    inner
                        .last_view
                        .as_ref()
                        .and_then(|view| view.meta.by_index(asset))
                        .map(|asset| asset.name.clone())
                };
                let Some(coin) = coin else {
                    return unknown("the market of the leverage update could not be named");
                };
                let Some(answer) = self
                    .recovery_read(&requests::active_asset_data(account, &coin), 20, deadline)
                    .await
                else {
                    return out_of_time();
                };
                conclude_leverage(cross, leverage, &answer)
            }
            Identity::Untold => unknown("the venue keeps nothing that tells"),
        }
    }

    /// The local status, for the browser monitor (read-only).
    pub async fn status(&self) -> Value {
        let inner = self.inner.lock().await;
        let mut alerts: Vec<String> = inner
            .position_alert
            .iter()
            .chain(inner.alerts.iter().map(|alert| &alert.text))
            .cloned()
            .collect();
        if let Some(text) = inner.fee.entry_refusal() {
            alerts.push(text);
        }
        // Positions on dexes Guard does not manage, and dexes the markets
        // name that the venue does not list: for a person to see.
        alerts.extend(
            inner
                .unmanaged
                .iter()
                .map(|(dex, seen)| unmanaged_text(dex, &seen.coins)),
        );
        if let Some(text) = self.stream_alert() {
            alerts.push(text);
        }
        alerts.extend(inner.caches.missing_dexes.iter().map(|dex| {
            format!(
                "the markets name HIP-3 dex {dex}, which the venue does not list: nothing there is read or traded"
            )
        }));
        if inner.killed.is_some() && !inner.config.kill_file().exists() {
            alerts.insert(
                0,
                format!(
                    "the kill switch is latched in memory only: {} is missing, so a restart would release it; write it again with zunder-guard kill",
                    inner.config.kill_file().display()
                ),
            );
        }
        let engine = inner.risk.engine();
        let view = inner.last_view.as_ref();
        json!({
            "schema": EVENT_SCHEMA,
            "version": env!("CARGO_PKG_VERSION"),
            "mode": inner.mode.name(),
            "network": inner.config.network.map(|network| network.name()),
            "account": inner.account.to_hex(),
            "started_at_ms": self.started_ms,
            "killed": inner.killed,
            "risk": {
                "state": match engine.state() {
                    RiskState::Active => "active",
                    RiskState::HaltedForDay { .. } => "halted_for_day",
                    RiskState::Stopped { .. } => "stopped",
                },
                "detail": engine.state(),
                "peak": engine.peak(),
                "tracked": engine.positions().len(),
                "flows_applied": inner.flows_applied,
                "flow_note": inner.flow_note,
                "journal_ready": inner.risk.check_ready().is_ok(),
            },
            "equity_cap": inner.config.policy.max_trading_equity_usd,
            "assumptions": {
                "fee_bps": inner.config.policy.fee_bps,
                // What entries are sized with: `fee_bps` plus the builder fee.
                "sizing_fee_bps": licence::sizing_policy(&inner.config.policy, inner.fee.sizing_builder()).fee_bps,
                "slippage_bps": inner.config.policy.slippage_bps,
                "entry_price_bound": inner.config.policy.entry_price_bound,
                "stop_slippage": inner.config.policy.stop_slippage,
                "exit_slippage": inner.config.policy.exit_slippage,
                "default_stop_distance": inner.config.policy.default_stop_distance,
                "min_order_value": zunder_guard_core::account::MIN_NOTIONAL,
            },
            "equity": view.and_then(|view| view.equity),
            // Each dex Guard manages: the main dex (index 0, name "") and
            // the HIP-3 dexes its markets name, with its own margin account.
            "dexes": view.map_or_else(Vec::new, |view| view.dexes.iter().map(|dex| json!({
                "index": dex.index,
                "name": dex.name,
                "equity": dex.value,
                "withdrawable": dex.withdrawable,
                "usdc": dex.usdc,
                "positions": view.positions.iter().filter(|position| {
                    view.meta.by_name(&position.coin).is_some_and(|asset| asset.dex == dex.index)
                }).count(),
            })).collect::<Vec<_>>()),
            "unmanaged_dexes": inner.unmanaged.iter().map(|(dex, seen)| json!({
                "dex": dex,
                "index": seen.index,
                "coins": seen.coins,
                "equity": seen.value,
                "seen_ms": seen.seen_ms,
            })).collect::<Vec<_>>(),
            "positions": view.map_or(0, |view| view.positions.len()),
            "open_orders": view.map_or(0, |view| view.open_orders.len()),
            // This Guard's part of its IP address's request weight, and
            // every budget fitted to it.
            "ip_share": inner.config.ip_share,
            "budgets": self.budgets.to_json(inner.config.sync_seconds),
            "last_sync_ms": inner.last_sync_ms,
            "last_sync_reads": inner.last_sync_reads,
            "next_sync_delayed": inner.sync_read_twice,
            "last_error": inner.last_error,
            "alert": alerts.first(),
            "alerts": alerts,
            "kill_file": inner.config.kill_file(),
            "rules": rules::encode(&inner.config.policy),
            "fee": inner.fee.status(),
            "licence": inner.licence.status(self.clock.now_ms(), inner.config.licence_auto_update),
            "clients": inner.auth.clients().map(Address::to_hex).collect::<Vec<_>>(),
            "last_event": inner.journal.last_seq(),
            "journal_broken": inner.journal.is_broken(),
            // The writer behind: records nothing waited for that were not
            // taken, and intents refused (`docs/guard.md#journals`).
            "journal_dropped": inner.journal.dropped(),
            "journal_busy": inner.journal.busy(),
            "emergency_log_stalled": inner.emergency.stalled(),
            "stream": self.stream_status(),
        })
    }

    /// An alert when the venue keeps refusing the account stream (two
    /// connections in a row ended by an `error`): requests are then judged
    /// after reading the account, slower but as safely.
    fn stream_alert(&self) -> Option<String> {
        let stream = self.stream.lock().ok()?;
        let state = stream.as_ref()?.state.lock().ok()?;
        (state.breaks >= 2).then(|| {
            format!(
                "the venue keeps refusing the account stream ({} times in a row: {}); requests are judged after reading the account",
                state.breaks,
                state.last_break.as_deref().unwrap_or("unknown")
            )
        })
    }

    /// The account stream, for the status: whether it is up, and how
    /// requests were judged.
    fn stream_status(&self) -> Value {
        let (stream_count, read_count, last_fallback, info_count) =
            self.judged.lock().ok().map_or((0, 0, None, 0), |judged| {
                (
                    judged.stream,
                    judged.read,
                    judged.last_fallback.clone(),
                    judged.info_from_stream,
                )
            });
        let state = self.stream.lock().ok().and_then(|stream| {
            stream.as_ref().and_then(|stream| {
                stream.state.lock().ok().map(|state| {
                    json!({
                        "connected": state.is_connected(),
                        "messages": state.messages,
                        "reconnects": state.reconnects,
                        "coins": state.coins(),
                        "breaks": state.breaks,
                        "last_break": state.last_break,
                    })
                })
            })
        });
        json!({
            "on": state.is_some(),
            "state": state,
            "judged_from_stream": stream_count,
            "judged_after_read": read_count,
            "last_fallback": last_fallback,
            "info_from_stream": info_count,
        })
    }

    /// Guard's decision on the request with this client nonce (and what
    /// was sent for it), from the decision journal on disk.
    pub async fn decision(&self, nonce: u64, client: Option<&str>) -> Option<Value> {
        let (path, offset) = {
            let inner = self.inner.lock().await;
            // A recent one from memory: its records may not be written yet.
            if let Some(found) = inner.journal.recent_decision(nonce, client) {
                return Some(found);
            }
            inner.journal.decision_offset(nonce, client)?
        };
        // An older one from the file, read outside the lock: a lookup never
        // holds up a request.
        crate::journal::read_decision(&path, offset, nonce, client)
    }

    /// `POST /guard/kill`: a client-signed request that pulls the kill
    /// switch. It writes the kill file (so the switch survives a restart),
    /// latches it, and flattens at once. Nothing here releases it.
    pub async fn kill(&self, body: &Value) -> Value {
        let now = self.clock.now_ms();
        {
            let mut inner = self.inner.lock().await;
            let admitted = match zunder_guard_core::admit_kill(&mut inner.auth, body, now) {
                Ok(admitted) => admitted,
                Err(refusal) => {
                    return self.refuse(&mut inner, now, "kill", body, &refusal);
                }
            };
            // Already latched: say so, without writing or flattening again
            // (a retrying agent must not spend the venue's request budget
            // that flattening needs).
            if let Some(killed) = inner.killed.clone() {
                return json!({
                    "status": "ok",
                    "killed": killed,
                    "durable": inner.config.kill_file().exists(),
                    "already": true,
                });
            }
            let reason = format!(
                "{} (pulled by client {} through /guard/kill)",
                admitted.reason,
                admitted.client.client.to_hex()
            );
            let path = inner.config.kill_file();
            let written = path
                .parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| {
                    use std::io::Write;
                    let mut file = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)?;
                    writeln!(file, "{reason}")?;
                    file.sync_all()
                });
            if let Err(error) = written {
                // Latched in memory all the same; the file is what survives
                // a restart.
                let text = format!(
                    "the kill switch is latched, but {} could not be written: {error}",
                    path.display()
                );
                Self::add_alert(&mut inner, now, &text, None);
            }
            if inner.killed.is_none() {
                inner.killed = Some(reason.clone());
                inner
                    .journal
                    .append(now as i64, EventBody::Kill { reason })
                    .ok();
            }
        }
        // Flatten now, not at the next sync.
        self.sync().await;
        let inner = self.inner.lock().await;
        Self::kill_response(&inner)
    }

    fn kill_response(inner: &Inner) -> Value {
        json!({
            "status": "ok",
            "killed": inner.killed,
            "durable": inner.config.kill_file().exists(),
            "positions_at_kill": inner.positions_at_kill,
            "last_error": inner.last_error,
        })
    }

    /// Events after `since`, from memory.
    pub async fn events(&self, since: u64) -> Value {
        Value::Array(self.inner.lock().await.journal.since(since))
    }

    /// Record that Guard stops.
    pub async fn stopped(&self, reason: &str) {
        let mut inner = self.inner.lock().await;
        let now = self.clock.now_ms();
        inner
            .journal
            .append(
                now as i64,
                EventBody::Stopped {
                    reason: reason.to_owned(),
                },
            )
            .ok();
        // Everything queued written and synced, the unused tail given back.
        if let Err(error) = inner.journal.close().await {
            eprintln!("zunder-guard: closing the decision journal: {error}");
        }
    }
}

/// Refusal texts of the request budget.
const BUDGET_SPENT: &str = "Guard's budget of the venue's request weight is spent (it is kept for Guard's own protection); try again in a few seconds";

/// Whether every order of `request` is reduce-only and trades against a
/// position `view` shows in its coin.
fn reduces_a_position(view: &AccountView, request: &ExchangeRequest) -> bool {
    let Action::Order(order) = &request.action else {
        return false;
    };
    !order.orders.is_empty()
        && order.orders.iter().all(|placed| {
            placed.reduce_only
                && view
                    .meta
                    .by_index(placed.asset)
                    .and_then(|asset| view.position(&asset.name))
                    .is_some_and(|position| {
                        let buys = placed.is_buy;
                        match position.side {
                            zunder_core::Side::Buy => !buys,
                            zunder_core::Side::Sell => buys,
                        }
                    })
        })
}

/// Whether a halted request should read the account to flatten (the
/// budget aside): not when neither its view nor the last read showed
/// anything to flatten, nor within [`HALT_READ_EVERY_MS`] of the last such
/// read.
fn halt_read_due(
    now: u64,
    last_halt_read_ms: Option<u64>,
    view_exposed: bool,
    last_read_exposed: Option<bool>,
) -> bool {
    if !view_exposed && last_read_exposed == Some(false) {
        return false;
    }
    last_halt_read_ms.is_none_or(|at| now.saturating_sub(at) >= HALT_READ_EVERY_MS)
}

/// What the venue's socket should report of a send that `reply` answered,
/// sent at `sent` ([`monotonic_ms`]): the orders an order action rested or
/// filled (and the client ids it sent, and the reduce-only orders on a coin
/// it filled on, which the venue cancels when the position empties), the
/// orders a cancel by id cancelled with their waiting children and the
/// stops attached to them (`attached`, from Guard's own sends). `None` (the
/// stream then waits as after any change) for anything else: another
/// action, an answer of another shape, an order that failed while another
/// went, orders on more than one dex, a dex Guard cannot name.
/// `perp_dexs` is the venue's `perpDexs` by index, `view` the last view.
fn expectation(
    perp_dexs: Option<&[(u32, String)]>,
    view: Option<&AccountView>,
    attached: &VecDeque<(u64, Vec<String>)>,
    action: &Action,
    reply: &Value,
    sent: u64,
) -> Option<Expectation> {
    if reply.get("status").and_then(Value::as_str) != Some("ok") {
        return None;
    }
    let statuses = reply.pointer("/response/data/statuses")?.as_array()?;
    let dex_of = |asset: u32| -> Option<String> {
        match asset_kind(asset) {
            AssetKind::MainPerp => Some(String::new()),
            AssetKind::Hip3 { dex } => perp_dexs
                .and_then(|list| list.iter().find(|(index, _)| *index == dex))
                .map(|(_, name)| name.clone()),
            _ => None,
        }
    };
    let mut expectation = Expectation {
        sent,
        dex: String::new(),
        resting: Vec::new(),
        filled: Vec::new(),
        cancelled: Vec::new(),
        cancelled_cloids: Vec::new(),
        cloids: Vec::new(),
        reduce_only: Vec::new(),
    };
    match action {
        Action::Order(order) => {
            let first = order.orders.first()?;
            expectation.dex = dex_of(first.asset)?;
            if statuses.len() != order.orders.len()
                || order
                    .orders
                    .iter()
                    .any(|placed| dex_of(placed.asset).as_deref() != Some(expectation.dex.as_str()))
            {
                return None;
            }
            for status in statuses {
                if let Some(oid) = status.pointer("/resting/oid").and_then(Value::as_u64) {
                    expectation.resting.push(oid);
                } else if let Some(oid) = status.pointer("/filled/oid").and_then(Value::as_u64) {
                    expectation.filled.push(oid);
                } else if matches!(
                    status.as_str(),
                    Some("waitingForFill" | "waitingForTrigger")
                ) {
                    // A waiting child: reported by its client id, if at all.
                } else {
                    return None;
                }
            }
            expectation.cloids = order
                .orders
                .iter()
                .filter_map(|placed| placed.cloid.as_ref())
                .map(|cloid| cloid.as_str().to_ascii_lowercase())
                .collect();
            // A fill may empty a position: the venue then cancels the
            // reduce-only orders resting on its coin.
            if let Some(view) = view {
                let filled_coins: Vec<&str> = order
                    .orders
                    .iter()
                    .zip(statuses)
                    .filter(|(_, status)| status.get("filled").is_some())
                    .filter_map(|(placed, _)| view.meta.by_index(placed.asset))
                    .map(|asset| asset.name.as_str())
                    .collect();
                expectation.reduce_only = view
                    .all_orders()
                    .filter(|resting| {
                        (resting.reduce_only || resting.is_position_tpsl)
                            && filled_coins.contains(&resting.coin.as_str())
                    })
                    .map(|resting| resting.oid)
                    .collect();
            }
        }
        Action::Cancel(cancels) => {
            let first = cancels.first()?;
            expectation.dex = dex_of(first.asset)?;
            if statuses.len() != cancels.len() {
                return None;
            }
            for (cancel, status) in cancels.iter().zip(statuses) {
                let zunder_guard_core::action::OrderRef::Oid(oid) = cancel.order else {
                    return None;
                };
                if dex_of(cancel.asset).as_deref() != Some(expectation.dex.as_str())
                    || status.as_str() != Some("success")
                {
                    return None;
                }
                expectation.cancelled.push(oid);
                // Its waiting children go with it: as the view lists them,
                // and the stops Guard attached to it.
                if let Some(order) = view.and_then(|view| view.order_by_oid(oid)) {
                    expectation
                        .cancelled
                        .extend(order.children.iter().map(|child| child.oid));
                }
                if let Some((_, cloids)) = attached.iter().find(|(entry, _)| *entry == oid) {
                    expectation.cancelled_cloids.extend(cloids.iter().cloned());
                }
            }
        }
        _ => return None,
    }
    let nothing = expectation.resting.is_empty()
        && expectation.filled.is_empty()
        && expectation.cancelled.is_empty();
    (!nothing).then_some(expectation)
}

/// The stops a `normalTpsl` order action attached to its entry, when the
/// entry rests: the entry's id and the children's client ids. The venue
/// lists such a stop as an order of its own, and cancels it with the entry.
fn attached_stops(action: &Action, reply: &Value) -> Option<(u64, Vec<String>)> {
    let Action::Order(order) = action else {
        return None;
    };
    if order.grouping != zunder_guard_core::action::Grouping::NormalTpsl {
        return None;
    }
    let oid = reply
        .pointer("/response/data/statuses/0/resting/oid")
        .and_then(Value::as_u64)?;
    let cloids: Vec<String> = order
        .orders
        .iter()
        .skip(1)
        .filter_map(|placed| placed.cloid.as_ref())
        .map(|cloid| cloid.as_str().to_ascii_lowercase())
        .collect();
    (!cloids.is_empty()).then_some((oid, cloids))
}

/// The prefix of the client ids Guard gives a bot's orders that have none,
/// and of those it gives its own closes (`0x7a67` stays its stops').
pub const BOT_CLOID_PREFIX: &str = "7a68";
pub const CLOSE_CLOID_PREFIX: &str = "7a69";

/// `action` with a client id on every order (or modify's new order) that
/// has none: `0x` + `prefix` + 28 hex digits of Keccak-256 over Guard's
/// salt, the prefix and a counter. Returns the ids given.
fn with_client_ids(
    action: &Action,
    counter: &mut u64,
    salt: &[u8],
    prefix: &str,
) -> (Action, Vec<String>) {
    let mut given = Vec::new();
    let mut next = |given: &mut Vec<String>| {
        *counter += 1;
        let hash = zunder_guard_core::sign::keccak256(
            &[salt, prefix.as_bytes(), &counter.to_be_bytes()].concat(),
        );
        let digits: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
        let text = format!("0x{prefix}{}", &digits[..28]);
        given.push(text.clone());
        zunder_guard_core::action::Cloid::parse(&text)
    };
    let mut action = action.clone();
    match &mut action {
        Action::Order(order) => {
            for placed in &mut order.orders {
                if placed.cloid.is_none() {
                    placed.cloid = next(&mut given);
                }
            }
        }
        Action::Modify(modify) => {
            if modify.order.cloid.is_none() {
                modify.order.cloid = next(&mut given);
            }
        }
        Action::BatchModify(modifies) => {
            for modify in modifies {
                if modify.order.cloid.is_none() {
                    modify.order.cloid = next(&mut given);
                }
            }
        }
        _ => {}
    }
    (action, given)
}

/// Take the client ids in `given` out of a reply's order statuses: the
/// bot never set them.
fn strip_client_ids(reply: &mut Value, given: &[String]) {
    if given.is_empty() {
        return;
    }
    let Some(statuses) = reply
        .pointer_mut("/response/data/statuses")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for status in statuses {
        for kind in ["resting", "filled"] {
            if let Some(fields) = status.get_mut(kind).and_then(Value::as_object_mut)
                && fields
                    .get("cloid")
                    .and_then(Value::as_str)
                    .is_some_and(|cloid| given.iter().any(|id| id.eq_ignore_ascii_case(cloid)))
            {
                fields.remove("cloid");
            }
        }
    }
}

/// How long a protective send waits for its emergency-log record; then it
/// goes unrecorded, with an alert (a stalled disk never holds up closing).
pub const EMERGENCY_WRITE_MS: u64 = 2_000;

/// The emergency log (E1) as Guard writes it: off the async runtime, each
/// write waited for [`EMERGENCY_WRITE_MS`] at most. A write that takes
/// longer marks the log stalled: until that write finishes, nothing is
/// written to it or waits on it (a hung disk costs one wait and one
/// blocking thread, not one per protective send).
#[derive(Clone)]
struct Emergency {
    /// Locked by the blocking writes only (a hung one holds it): never on
    /// the async runtime.
    log: Arc<StdMutex<crate::journal::EmergencyLog>>,
    path: String,
    stalled: Arc<AtomicBool>,
}

impl Emergency {
    fn new(log: crate::journal::EmergencyLog) -> Self {
        Self {
            path: log.path().display().to_string(),
            log: Arc::new(StdMutex::new(log)),
            stalled: Arc::new(AtomicBool::new(false)),
        }
    }

    fn path(&self) -> String {
        self.path.clone()
    }

    /// A write that did not finish in time has not finished yet.
    fn stalled(&self) -> bool {
        self.stalled.load(Ordering::SeqCst)
    }

    /// Write `body`, synced, within [`EMERGENCY_WRITE_MS`].
    async fn record(&self, at_ms: i64, body: EventBody) -> Result<(), String> {
        if self.stalled() {
            return Err(format!(
                "the emergency log is stalled: a write has not finished after {EMERGENCY_WRITE_MS} ms"
            ));
        }
        let finished = Arc::new(AtomicBool::new(false));
        let write = tokio::task::spawn_blocking({
            let (log, stalled, finished) =
                (self.log.clone(), self.stalled.clone(), finished.clone());
            move || {
                let result = log
                    .lock()
                    .map_err(|_| "the emergency log is poisoned".to_owned())
                    .and_then(|mut log| {
                        log.append(at_ms, body)
                            .map(|_| ())
                            .map_err(|error| error.to_string())
                    });
                finished.store(true, Ordering::SeqCst);
                stalled.store(false, Ordering::SeqCst);
                result
            }
        });
        match tokio::time::timeout(Duration::from_millis(EMERGENCY_WRITE_MS), write).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => {
                self.stalled.store(true, Ordering::SeqCst);
                // Finished in between: not stalled after all.
                if finished.load(Ordering::SeqCst) {
                    self.stalled.store(false, Ordering::SeqCst);
                }
                Err(format!(
                    "the emergency log's write took longer than {EMERGENCY_WRITE_MS} ms"
                ))
            }
        }
    }

    /// Write `body` without waiting for it (a record nothing is sent on
    /// the strength of); nothing while the log is stalled.
    fn record_later(&self, at_ms: i64, body: EventBody) {
        if self.stalled() {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            this.record(at_ms, body).await.ok();
        });
    }
}

/// Clears a flag when dropped.
struct ClearOnDrop<'a>(&'a AtomicBool);

impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Whether an action can only reduce risk: reduce-only orders, cancels.
/// Such an action goes even while the journal is broken (E1 in
/// `docs/guard.md#journals`).
fn reduces_risk(action: &Action) -> bool {
    matches!(action, Action::Cancel(_) | Action::CancelByCloid(_)) || licence::exits_only(action)
}

/// Whether a view shows anything to flatten: a position, or an order that
/// could open one.
fn exposed(account: &AccountView) -> bool {
    !account.positions.is_empty() || account.open_orders.iter().any(|order| order.is_opening())
}

/// The venue's request weight of what a forwarded request sends: 1 an
/// action, 1 more for every 40 in a batch (orders, cancels, modifies;
/// Hyperliquid's rate-limit documentation), and reading back each isolated
/// leverage set first.
fn forward_weight(forward: &Forward) -> u64 {
    let action = |action: &Action| {
        let batch = match action {
            Action::Order(order) => order.orders.len(),
            Action::Cancel(cancels) | Action::CancelByCloid(cancels) => cancels.len(),
            Action::BatchModify(modifies) => modifies.len(),
            _ => 0,
        };
        1 + batch as u64 / 40
    };
    let leverage_reads = forward
        .pre
        .iter()
        .filter(|pre| matches!(pre, Action::UpdateLeverage { .. }))
        .count() as u64;
    forward
        .pre
        .iter()
        .chain(std::iter::once(&forward.action))
        .chain(forward.post.iter())
        .map(action)
        .sum::<u64>()
        + LEVERAGE_READ_WEIGHT * leverage_reads
}

/// The account value and the coins of the open positions in a
/// `clearinghouseState` answer; `None` when it cannot be read.
fn unmanaged_positions(state: &Value) -> Option<(Decimal, Vec<String>)> {
    let value = state
        .pointer("/marginSummary/accountValue")
        .and_then(Value::as_str)?
        .parse::<Decimal>()
        .ok()?;
    let mut coins = Vec::new();
    for entry in state.get("assetPositions")?.as_array()? {
        let position = entry.get("position")?;
        let size = position.get("szi")?.as_str()?.parse::<Decimal>().ok()?;
        if !size.is_zero() {
            coins.push(position.get("coin")?.as_str()?.to_owned());
        }
    }
    coins.sort();
    Some((value, coins))
}

/// The alert about positions on a dex Guard does not manage.
fn unmanaged_text(dex: &str, coins: &[String]) -> String {
    format!(
        "positions on HIP-3 dex {dex} ({}), which the rules' markets do not name: Guard neither judges nor protects them, and the kill switch leaves them",
        coins.join(", ")
    )
}

/// The asset of the entry in `request`: its first order that is not
/// reduce-only.
fn entry_asset(request: &ExchangeRequest) -> Option<u32> {
    let Action::Order(order) = &request.action else {
        return None;
    };
    order
        .orders
        .iter()
        .find(|order| !order.reduce_only)
        .map(|order| order.asset)
}

/// The asset of a HIP-3 entry in `request`: its first order that is not
/// reduce-only on a HIP-3 asset id, whose book Guard reads with the account.
fn hip3_entry_asset(request: &ExchangeRequest) -> Option<u32> {
    let Action::Order(order) = &request.action else {
        return None;
    };
    order
        .orders
        .iter()
        .find(|order| {
            !order.reduce_only && matches!(asset_kind(order.asset), AssetKind::Hip3 { .. })
        })
        .map(|order| order.asset)
}

/// A modify or batch modify.
fn is_modify(request: &ExchangeRequest) -> bool {
    matches!(request.action, Action::Modify(_) | Action::BatchModify(_))
}

/// When the account cannot be read, an order action of reduce-only orders
/// alone is forwarded as it is: it can only close, and closing must not
/// wait for the venue's info endpoint. Only on a main-dex perp or a perp of
/// a HIP-3 dex Guard manages (`managed`, by index). Everything else is
/// refused.
fn unjudged_reduce_only(request: &ExchangeRequest, managed: &[u32]) -> Option<Decision> {
    let Action::Order(order) = &request.action else {
        return None;
    };
    let closes_only = !zunder_guard_core::judge::uses_guard_cloid(order)
        && order.orders.iter().all(|order| order.reduce_only)
        && order
            .orders
            .iter()
            .all(|order| match asset_kind(order.asset) {
                AssetKind::MainPerp => true,
                AssetKind::Hip3 { dex } => managed.contains(&dex),
                _ => false,
            });
    closes_only.then(|| Decision {
        verdict: Verdict::Allow,
        code: "reduce_only_unjudged",
        text: "the account could not be read; reduce-only orders are forwarded as they are".into(),
        // A bot's own builder field never goes out: Guard's replaces it
        // when sent ([`FeeState::apply`]).
        changes: order
            .builder
            .as_ref()
            .map(|_| "the bot's builder field removed; only Guard's may appear".to_owned())
            .into_iter()
            .collect(),
        forward: Some(Forward {
            pre: Vec::new(),
            action: licence::with_builder(&request.action, None),
            expires_after: request.expires_after,
            status_map: (0..order.orders.len()).collect(),
            entry: None,
            post: Vec::new(),
            post_after: Vec::new(),
        }),
    })
}

/// `ms` (epoch milliseconds) as a UTC date and time, `2027-12-31 00:00 UTC`.
pub fn utc_text(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let minutes = ms.rem_euclid(86_400_000) / 60_000;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        minutes / 60,
        minutes % 60
    )
}

/// A fraction as a percentage with one decimal, for people.
fn percent(fraction: rust_decimal::Decimal) -> String {
    format!(
        "{}%",
        (fraction * rust_decimal::Decimal::ONE_HUNDRED).round_dp(1)
    )
}

/// Whether a complete ledger read begun at `ok` tells the loss of a view
/// read at `view` from a withdrawal, in a run of views that would halt the
/// engine begun at `halting` (Guard's clock): it began after the view, and
/// at least `LEDGER_LAG_MS` after the first view of the run (a withdrawal
/// that explains the loss is in that view already; a run ends at a view
/// that would not halt).
fn ledger_checks(ok: Option<u64>, view: u64, halting: Option<u64>) -> bool {
    ok.is_some_and(|ok| ok >= view && ok >= halting.unwrap_or(view).saturating_add(LEDGER_LAG_MS))
}

/// Where the next ledger read starts, after one that started at `started`
/// and reached `reached` (its newest entry's time, or where it started):
/// `LEDGER_OVERLAP_MS` before that when the read was complete, so that an
/// entry the venue showed late comes again (a duplicate by id) rather than
/// never, but never before where this read started; from `reached` itself
/// when the read stopped at its page limit (the rest is still to come).
fn ledger_cursor(started: Option<i64>, reached: i64, complete: bool) -> i64 {
    if complete {
        reached
            .saturating_sub(LEDGER_OVERLAP_MS)
            .max(started.unwrap_or(i64::MIN))
    } else {
        reached
    }
}

/// The venue's time of each dex's account in `account` (`""` for the main
/// dex): a flow at or before it, by the margin, is in it
/// (`docs/guard.md#deposits-and-withdrawals`). An account without them counts as read at
/// its own time.
fn view_times(account: &AccountView) -> std::collections::BTreeMap<String, i64> {
    let mut times: std::collections::BTreeMap<String, i64> = account
        .dexes
        .iter()
        .filter_map(|dex| dex.time.map(|time| (dex.name.clone(), time)))
        .collect();
    if times.is_empty() {
        times.insert(String::new(), account.at_ms);
    }
    times
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    struct UnreadableVenue;

    impl Upstream for UnreadableVenue {
        async fn info(&self, _: &Value) -> Result<Value, UpstreamError> {
            Err(UpstreamError::NotSent("account unavailable".into()))
        }

        async fn exchange(&self, _: Vec<u8>) -> Result<Value, UpstreamError> {
            panic!("the diagnostic snapshot tests must send nothing")
        }

        fn ws_url(&self) -> Option<String> {
            None
        }

        fn sends_to(&self) -> Option<SigningNetwork> {
            None
        }
    }

    fn kill_snapshot_guard() -> (Arc<Guard<UnreadableVenue>>, crate::testdir::TestDir) {
        let dir = crate::testdir::TestDir::new("kill-snapshot");
        let config = GuardConfig {
            network: Some(crate::config::GuardNetwork::Testnet),
            account: Some("0x5e9ee1089755c3435139848e47e6635505d5a13a".into()),
            state_dir: dir.path().to_owned(),
            auth: zunder_guard_core::auth::AuthConfig {
                clients: vec!["0x5e9ee1089755c3435139848e47e6635505d5a13a".into()],
                ..Default::default()
            },
            ..GuardConfig::default()
        };
        let risk = PersistentRisk::initialise_for(
            &config.risk_journal(true),
            config.policy.risk_limits(),
            &config.journal_scope(true).unwrap(),
            Timestamp::from_millis(SystemClock.now_ms() as i64),
            rust_decimal::dec!(10000),
            "kill snapshot test",
        )
        .unwrap();
        let journal = DecisionJournal::open(&config.decision_journal(true)).unwrap();
        let guard = Guard::new(
            Setup {
                config,
                mode: Mode::Paper,
                risk,
                journal,
                fee: FeeMode::Off("test".into()),
                fee_warning: None,
                limits: Limits::default(),
            },
            UnreadableVenue,
            SystemClock,
        )
        .unwrap();
        (guard, dir)
    }

    #[tokio::test]
    async fn the_kill_count_survives_a_post_flatten_account_read() {
        // The fixture contains exactly one BTC position. Reproduce the
        // later sync's flat view deterministically, without scheduler timing.
        for initially_flat in [false, true] {
            let (guard, _dir) = kill_snapshot_guard();
            let mut account = view_for_expectations();
            account.open_orders.clear();
            if initially_flat {
                account.positions.clear();
            }
            let expected = account.positions.len();
            let mut inner = guard.inner.lock().await;
            assert_eq!(inner.positions_at_kill, None);
            guard
                .flatten(&mut inner, 0, &account, "daily loss stop")
                .await;
            assert_eq!(inner.positions_at_kill, None);
            inner.killed = Some("test kill".into());
            guard.flatten(&mut inner, 1, &account, "test kill").await;
            // The ordinary sync can replace last_view before kill() obtains
            // its reply lock; it cannot change the original flatten snapshot.
            account.positions.clear();
            inner.last_view = Some(account.clone());
            guard.flatten(&mut inner, 2, &account, "test kill").await;
            assert_eq!(
                Guard::<UnreadableVenue>::kill_response(&inner)["positions_at_kill"],
                expected
            );
            assert_eq!(inner.last_view.as_ref().unwrap().positions.len(), 0);
            // A later nonempty snapshot cannot overwrite an initial zero.
            let later = view_for_expectations();
            guard.flatten(&mut inner, 3, &later, "test kill").await;
            assert_eq!(
                Guard::<UnreadableVenue>::kill_response(&inner)["positions_at_kill"],
                expected
            );
        }
    }

    #[tokio::test]
    async fn an_unreadable_kill_has_no_invented_position_count() {
        let (guard, _dir) = kill_snapshot_guard();
        {
            let mut inner = guard.inner.lock().await;
            inner.killed = Some("test kill".into());
            // A stale view is not evidence of the unreadable flatten snapshot.
            inner.last_view = Some(view_for_expectations());
        }
        guard.sync().await;
        let inner = guard.inner.lock().await;
        assert!(Guard::<UnreadableVenue>::kill_response(&inner)["positions_at_kill"].is_null());
        assert_eq!(inner.killed.as_deref(), Some("test kill"));
        assert!(inner.last_error.is_some());
    }

    #[cfg(feature = "test-hooks")]
    mod durable_expiry {
        use super::*;

        #[derive(Clone)]
        struct ExpiryClock(Arc<AtomicU64>);

        impl Clock for ExpiryClock {
            fn now_ms(&self) -> u64 {
                self.0.load(Ordering::SeqCst)
            }
        }

        #[derive(Default)]
        struct ExpiryVenue(std::sync::Mutex<Vec<Value>>);

        impl Upstream for ExpiryVenue {
            async fn info(&self, _: &Value) -> Result<Value, UpstreamError> {
                Err(UpstreamError::NotSent("unused in this test".into()))
            }

            async fn exchange(&self, body: Vec<u8>) -> Result<Value, UpstreamError> {
                self.0
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(&body).unwrap());
                Ok(json!({"status":"ok","response":{"type":"order","data":{"statuses":[]}}}))
            }

            fn ws_url(&self) -> Option<String> {
                None
            }
            fn sends_to(&self) -> Option<SigningNetwork> {
                Some(SigningNetwork::Testnet)
            }
        }

        #[tokio::test]
        async fn expiry_during_durability_blocks_entries_and_rejournals_protection() {
            use crate::config::{GuardMode, GuardNetwork};
            use zunder_guard_core::licence::{Terms, test_key};
            const NOW: u64 = 1_800_000_000_000;
            const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
            for reduce_only in [false, true] {
                let dir = crate::testdir::TestDir::new("licence-durable-expiry");
                let key = GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap();
                let config = GuardConfig {
                    network: Some(GuardNetwork::Testnet),
                    mode: GuardMode::Testnet,
                    account: Some(ACCOUNT.into()),
                    state_dir: dir.path().to_owned(),
                    auth: zunder_guard_core::auth::AuthConfig {
                        clients: vec![key.address().to_hex()],
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let path = config.decision_journal(false);
                let risk = zunder_venue::PersistentRisk::initialise_for(
                    &config.risk_journal(false),
                    config.policy.risk_limits(),
                    &config.journal_scope(false).unwrap(),
                    Timestamp::from_millis(NOW as i64),
                    rust_decimal::dec!(10000),
                    "test",
                )
                .unwrap();
                let clock = ExpiryClock(Arc::new(AtomicU64::new(NOW)));
                let guard = Guard::new(
                    Setup {
                        config,
                        mode: Mode::Send {
                            key,
                            network: SigningNetwork::Testnet,
                        },
                        risk,
                        journal: DecisionJournal::open(&path).unwrap(),
                        fee: FeeMode::Off("test".into()),
                        fee_warning: None,
                        limits: Limits::default(),
                    },
                    ExpiryVenue::default(),
                    clock.clone(),
                )
                .unwrap();
                let action = zunder_guard_core::action::decode_request(
                    json!({
                        "action": {"type":"order", "orders":[{"a":1,"b":false,"p":"3000",
                            "s":"1","r":reduce_only,"t":{"limit":{"tif":"Ioc"}}}],"grouping":"na"},
                        "nonce":NOW,"signature":{"r":"0x1","s":"0x2","v":27}
                    })
                    .to_string()
                    .as_bytes(),
                )
                .unwrap()
                .action;
                let mut inner = guard.inner.lock().await;
                inner.licence.key = Some(
                    licence::issue(
                        &Terms {
                            licensee: "test".into(),
                            expires_at_ms: (NOW + 100) as i64,
                            features: vec!["fee_free".into()],
                            accounts: vec![ACCOUNT.into()],
                            builder: None,
                        },
                        &test_key::SEED,
                    )
                    .unwrap(),
                );
                inner.licence.public_key = Some(test_key::public());
                inner.licence.builders = (
                    None,
                    Some("0x00000000000000000000000000000000000000bb".into()),
                );
                let (mode, _) = inner.licence.mode(Address::from_hex(ACCOUNT).unwrap(), NOW);
                inner.fee.switch_mode(mode);
                // Protection initially carries an alternate builder. Expiry
                // removes it, so the replacement intent must name the bare action.
                if reduce_only {
                    inner
                        .fee
                        .switch_mode(FeeMode::Builder(zunder_guard_core::action::Builder {
                            address: "0x00000000000000000000000000000000000000aa".into(),
                            fee_tenths_bp: 100,
                        }));
                    inner.fee.record_check(NOW, Ok(&json!(100)));
                }
                let held = inner.journal.hold_writer_for_test();
                let send = guard.send_one(&mut inner, NOW, 0, &action, NOW + ACTION_TTL_MS);
                let cross_expiry = async {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    clock.0.store(NOW + 200, Ordering::SeqCst);
                    drop(held);
                };
                let (result, ()) = tokio::join!(send, cross_expiry);
                inner.journal.flush().wait().await.unwrap();
                let sent = guard.upstream.0.lock().unwrap();
                if reduce_only {
                    assert!(result.is_ok(), "{result:?}");
                    assert_eq!(sent.len(), 1);
                    assert!(sent[0]["action"].get("builder").is_none());
                    let disk = std::fs::read_to_string(&path).unwrap();
                    let intents: Vec<Value> = disk
                        .lines()
                        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                        .filter(|line| line["event"]["kind"] == "intent")
                        .collect();
                    assert_eq!(intents.len(), 2, "{disk}");
                    assert_eq!(intents[1]["event"]["action"], sent[0]["action"]);
                } else {
                    assert!(result.unwrap_err().starts_with("fee_not_approved:"));
                    assert!(sent.is_empty());
                }
            }
        }
    }

    #[test]
    fn utc_text_is_the_civil_date() {
        // Hand-checked: 0 is 1970-01-01; 1_798_761_600_000 is 2027-01-01;
        // 951_782_400_000 is 2000-02-29 (a leap day); one minute before
        // 2028-01-01 is 23:59 on 2027-12-31.
        assert_eq!(super::utc_text(0), "1970-01-01 00:00 UTC");
        assert_eq!(super::utc_text(1_798_761_600_000), "2027-01-01 00:00 UTC");
        assert_eq!(super::utc_text(951_782_400_000), "2000-02-29 00:00 UTC");
        assert_eq!(
            super::utc_text(1_830_297_600_000 - 60_000),
            "2027-12-31 23:59 UTC"
        );
    }

    use super::*;

    #[test]
    fn an_unreadable_account_lets_only_closes_on_managed_dexes_through() {
        // A bot can make the account unreadable on purpose (by spending the
        // read budget); a reduce-only order then goes unjudged, but only on
        // a main-dex perp or a perp of a HIP-3 dex Guard manages: never on
        // spot (10107), a HIP-3 dex it does not manage (110000 here, dex 1)
        // or a HIP-4 outcome side (100000950).
        let close = |asset: u64| {
            let body = serde_json::json!({
                "action": {"type": "order", "orders": [{"a": asset, "b": false, "p": "0.4",
                    "s": "100", "r": true, "t": {"limit": {"tif": "Ioc"}}}], "grouping": "na"},
                "nonce": 1_791_000_000_000u64,
                "signature": {"r": "0x1", "s": "0x2", "v": 27},
                "vaultAddress": null,
                "expiresAfter": null,
            });
            zunder_guard_core::action::decode_request(body.to_string().as_bytes())
                .expect("a valid request")
        };
        let forwarded = unjudged_reduce_only(&close(1), &[]).expect("a main-dex close goes");
        assert_eq!(forwarded.code, "reduce_only_unjudged");
        for asset in [10_107, 110_000, 100_000_950] {
            assert!(
                unjudged_reduce_only(&close(asset), &[]).is_none(),
                "{asset}"
            );
        }
        // Dex 1 managed: its close goes; dex 2's (120000) still not.
        assert!(unjudged_reduce_only(&close(110_000), &[1]).is_some());
        assert!(unjudged_reduce_only(&close(120_000), &[1]).is_none());
    }

    /// A view with a BTC long, Guard's stop on it (oid 9, reduce-only), a
    /// bot's take profit (oid 10, reduce-only), a resting ETH buy (oid 11)
    /// and an ETH reduce-only order (oid 12).
    fn view_for_expectations() -> AccountView {
        let meta = serde_json::json!({"universe": [
            {"name": "BTC", "szDecimals": 5, "maxLeverage": 40},
            {"name": "ETH", "szDecimals": 4, "maxLeverage": 25},
        ]});
        let clearinghouse = serde_json::json!({
            "marginSummary": {"accountValue": "10000"},
            "assetPositions": [{"type": "oneWay", "position": {
                "coin": "BTC", "szi": "0.01", "entryPx": "60000", "positionValue": "600",
                "leverage": {"type": "isolated", "value": 5}, "liquidationPx": null,
                "unrealizedPnl": "0"}}],
            "withdrawable": "9000", "time": 1
        });
        let order = |coin: &str, oid: u64, trigger: bool, reduce_only: bool| {
            serde_json::json!({"coin": coin, "side": "A", "limitPx": "50000", "sz": "0.01",
                "oid": oid, "isTrigger": trigger,
                "triggerPx": if trigger { "58800" } else { "0.0" },
                "orderType": if trigger { "Stop Market" } else { "Limit" },
                "reduceOnly": reduce_only, "isPositionTpsl": false, "children": []})
        };
        let orders = serde_json::json!([
            order("BTC", 9, true, true),
            order("BTC", 10, false, true),
            order("ETH", 11, false, false),
            order("ETH", 12, false, true),
        ]);
        AccountView::parse(
            1,
            zunder_guard_core::account::Meta::parse(&meta).unwrap(),
            &serde_json::json!("default"),
            &clearinghouse,
            &orders,
            &serde_json::json!({"BTC": "60000", "ETH": "3000"}),
        )
        .unwrap()
    }

    fn action(value: Value) -> Action {
        zunder_guard_core::action::decode_action_value(&value).unwrap()
    }

    fn limit(asset: u32, reduce_only: bool, cloid: Option<&str>) -> Value {
        let mut order = serde_json::json!({"a": asset, "b": false, "p": "59000", "s": "0.01",
            "r": reduce_only, "t": {"limit": {"tif": "Ioc"}}});
        if let Some(cloid) = cloid {
            order["c"] = serde_json::json!(cloid);
        }
        order
    }

    fn statuses(kind: &str, statuses: Value) -> Value {
        serde_json::json!({"status": "ok", "response": {"type": kind, "data": {"statuses": statuses}}})
    }

    #[test]
    fn a_send_expects_what_its_answer_says_and_only_then() {
        let view = view_for_expectations();
        let dexes = [(1, "xyz".to_owned())];
        let none = VecDeque::new();
        let expect = |action: &Action, reply: &Value, attached: &VecDeque<(u64, Vec<String>)>| {
            expectation(Some(&dexes), Some(&view), attached, action, reply, 5)
        };
        // A BTC close that filled (oid 20): the reduce-only orders on BTC
        // (9, 10) may be cancelled by the venue; not ETH's (12).
        let close = action(serde_json::json!({"type": "order",
            "orders": [limit(0, true, Some("0x7a740000000000000000000000000001"))],
            "grouping": "na"}));
        let filled = statuses(
            "order",
            serde_json::json!([{"filled": {"totalSz": "0.01", "avgPx": "59000", "oid": 20}}]),
        );
        let got = expect(&close, &filled, &none).unwrap();
        assert_eq!(got.dex, "");
        assert_eq!(got.filled, vec![20]);
        assert_eq!(got.reduce_only, vec![9, 10]);
        assert_eq!(
            got.cloids,
            vec!["0x7a740000000000000000000000000001".to_owned()]
        );
        // Resting instead: nothing the venue cancels.
        let rested = statuses("order", serde_json::json!([{"resting": {"oid": 21}}]));
        let got = expect(&close, &rested, &none).unwrap();
        assert_eq!((got.resting, got.reduce_only), (vec![21], Vec::new()));
        // Not an `ok` answer, an error among the statuses, fewer statuses
        // than orders, an unknown status: nothing expected.
        let err = serde_json::json!({"status": "err", "response": "no"});
        assert!(expect(&close, &err, &none).is_none());
        // An error answer shaped like an order's: nothing either.
        let odd_err = serde_json::json!({"status": "err", "response": {"type": "order",
            "data": {"statuses": [{"resting": {"oid": 21}}]}}});
        assert!(expect(&close, &odd_err, &none).is_none());
        let two = action(serde_json::json!({"type": "order",
            "orders": [limit(0, true, None), limit(1, true, None)], "grouping": "na"}));
        let one_error = statuses(
            "order",
            serde_json::json!([{"resting": {"oid": 21}}, {"error": "Insufficient margin"}]),
        );
        assert!(expect(&two, &one_error, &none).is_none());
        assert!(expect(&two, &rested, &none).is_none());
        let odd = statuses(
            "order",
            serde_json::json!([{"resting": {"oid": 21}}, "somethingNew"]),
        );
        assert!(expect(&two, &odd, &none).is_none());
        let waiting = statuses(
            "order",
            serde_json::json!([{"resting": {"oid": 21}}, "waitingForFill"]),
        );
        assert_eq!(expect(&two, &waiting, &none).unwrap().resting, vec![21]);
        // Orders on two dexes (BTC and xyz's first coin, 110000): nothing.
        let mixed = action(serde_json::json!({"type": "order",
            "orders": [limit(0, true, None), limit(110_000, true, None)], "grouping": "na"}));
        let both = statuses(
            "order",
            serde_json::json!([{"resting": {"oid": 21}}, {"resting": {"oid": 22}}]),
        );
        assert!(expect(&mixed, &both, &none).is_none());
        // An xyz order alone: its dex by name.
        let xyz = action(serde_json::json!({"type": "order",
            "orders": [limit(110_000, true, None)], "grouping": "na"}));
        assert_eq!(expect(&xyz, &rested, &none).unwrap().dex, "xyz");
        // A cancel by id that worked: the order, and the stops Guard
        // attached to it; one that failed, or a cancel by client id,
        // nothing.
        let cancel = action(serde_json::json!({"type": "cancel", "cancels": [{"a": 0, "o": 30}]}));
        let attached: VecDeque<(u64, Vec<String>)> = [(30, vec!["0x7a67bb".to_owned()])].into();
        let got = expect(
            &cancel,
            &statuses("cancel", serde_json::json!(["success"])),
            &attached,
        )
        .unwrap();
        assert_eq!(got.cancelled, vec![30]);
        assert_eq!(got.cancelled_cloids, vec!["0x7a67bb".to_owned()]);
        // A cancel on two dexes: nothing.
        let two_dexes = action(serde_json::json!({"type": "cancel",
            "cancels": [{"a": 0, "o": 30}, {"a": 110_000, "o": 31}]}));
        let both = statuses("cancel", serde_json::json!(["success", "success"]));
        assert!(expect(&two_dexes, &both, &none).is_none());
        // The children the view lists under a cancelled entry go with it.
        let parent = view_for_expectations();
        let mut with_child = parent.clone();
        if let Some(entry) = with_child
            .open_orders
            .iter_mut()
            .find(|order| order.oid == 11)
        {
            let mut child = entry.clone();
            child.oid = 13;
            entry.children.push(child);
        }
        let cancel_11 =
            action(serde_json::json!({"type": "cancel", "cancels": [{"a": 1, "o": 11}]}));
        let got = expectation(
            Some(&dexes),
            Some(&with_child),
            &none,
            &cancel_11,
            &statuses("cancel", serde_json::json!(["success"])),
            5,
        )
        .unwrap();
        assert_eq!(got.cancelled, vec![11, 13]);
        let failed = statuses(
            "cancel",
            serde_json::json!([{"error": "Order was never placed"}]),
        );
        assert!(expect(&cancel, &failed, &attached).is_none());
        let by_cloid = action(serde_json::json!({"type": "cancelByCloid",
            "cancels": [{"asset": 0, "cloid": "0x7a740000000000000000000000000001"}]}));
        assert!(
            expect(
                &by_cloid,
                &statuses("cancel", serde_json::json!(["success"])),
                &none
            )
            .is_none()
        );
        // A leverage update: nothing to report.
        let leverage = action(serde_json::json!({"type": "updateLeverage", "asset": 0,
            "isCross": false, "leverage": 5}));
        let default = serde_json::json!({"status": "ok", "response": {"type": "default"}});
        assert!(expect(&leverage, &default, &none).is_none());
    }

    #[test]
    fn a_resting_entry_remembers_the_stops_attached_to_it() {
        let entry = action(serde_json::json!({"type": "order",
            "orders": [limit(0, false, None), {"a": 0, "b": false, "p": "50000", "s": "0.01",
                "r": true, "t": {"trigger": {"isMarket": true, "triggerPx": "58800", "tpsl": "sl"}},
                "c": "0x7a67000000000000000000000000000b"}],
            "grouping": "normalTpsl"}));
        let rested = statuses(
            "order",
            serde_json::json!([{"resting": {"oid": 40}}, "waitingForFill"]),
        );
        assert_eq!(
            attached_stops(&entry, &rested),
            Some((40, vec!["0x7a67000000000000000000000000000b".to_owned()]))
        );
        // Filled at once: nothing to cancel with it later.
        let filled = statuses(
            "order",
            serde_json::json!([{"filled": {"totalSz": "0.01", "avgPx": "59000", "oid": 40}}, "waitingForTrigger"]),
        );
        assert_eq!(attached_stops(&entry, &filled), None);
        // Not grouped: no children.
        let na = action(serde_json::json!({"type": "order",
            "orders": [limit(0, false, None), limit(0, true, Some("0x7a67000000000000000000000000000b"))],
            "grouping": "na"}));
        assert_eq!(attached_stops(&na, &rested), None);
    }

    #[test]
    fn the_sync_slows_down_to_keep_its_share_of_the_request_weight() {
        // 334 a minute: 46 cached with the main dex alone, 288 for reads of
        // 24 every 5 s. One HIP-3 dex: 86 cached, 248 for reads of 48:
        // 60,000 * 48 / 248 = 11,612.9 ms. Two: 126 cached, 208 for reads of
        // 72: 60,000 * 72 / 208 = 20,769.2 ms.
        let interval = |sync_seconds, dexes| {
            crate::budget::plan(Decimal::ONE, dexes)
                .unwrap()
                .sync_interval_ms(sync_seconds)
        };
        assert_eq!(interval(5, 0), 5_000);
        assert_eq!(interval(5, 1), 11_613);
        assert_eq!(interval(5, 2), 20_770);
        // A slower configured sync is kept.
        assert_eq!(interval(30, 2), 30_000);
        for dexes in 0..=zunder_guard_core::policy::MAX_HIP3_DEXES {
            let interval = interval(5, dexes) as f64;
            let reads = 60_000.0 / interval * (ACCOUNT_READ_WEIGHT * (1 + dexes as u64)) as f64;
            let cached = (SYNC_CACHED_WEIGHT + SYNC_CACHED_WEIGHT_PER_DEX * dexes as u64) as f64;
            assert!(
                reads + cached <= SYNC_WEIGHT_PER_MINUTE as f64 + 1e-9,
                "{dexes}"
            );
        }
    }

    #[test]
    fn a_halted_read_is_due_only_when_something_may_be_open_and_not_too_soon() {
        // Nothing in the view, nothing at the last read: never.
        assert!(!halt_read_due(10_000, None, false, Some(false)));
        // Something in the view, or at the last read, or no read yet: due,
        // once every 3 s.
        assert!(halt_read_due(10_000, None, true, Some(false)));
        assert!(halt_read_due(10_000, None, false, Some(true)));
        assert!(halt_read_due(10_000, None, false, None));
        assert!(!halt_read_due(10_000, Some(7_001), true, Some(true)));
        assert!(halt_read_due(10_000, Some(7_000), true, Some(true)));
    }

    #[test]
    fn what_a_forwarded_request_costs_the_venue() {
        use zunder_guard_core::action::{Cancel, OrderRef};
        let cancels = |n: u64| {
            Action::Cancel(
                (0..n)
                    .map(|oid| Cancel {
                        asset: 0,
                        order: OrderRef::Oid(oid),
                    })
                    .collect(),
            )
        };
        let forward = |pre: Vec<Action>, action: Action, post: Vec<Action>| Forward {
            pre,
            action,
            expires_after: None,
            status_map: Vec::new(),
            entry: None,
            post,
            post_after: Vec::new(),
        };
        // One cancel: 1. 39 in a batch: 1; 40: 2; 80: 3.
        assert_eq!(forward_weight(&forward(vec![], cancels(1), vec![])), 1);
        assert_eq!(forward_weight(&forward(vec![], cancels(39), vec![])), 1);
        assert_eq!(forward_weight(&forward(vec![], cancels(40), vec![])), 2);
        assert_eq!(forward_weight(&forward(vec![], cancels(80), vec![])), 3);
        // Isolated leverage first (1, and 20 to read it back), the action,
        // and a cancel after: 1 + 20 + 1 + 1 = 23.
        let leverage = Action::UpdateLeverage {
            asset: 0,
            is_cross: false,
            leverage: 5,
        };
        assert_eq!(
            forward_weight(&forward(vec![leverage], cancels(1), vec![cancels(1)])),
            23
        );
    }

    #[test]
    fn repeated_flow_batches_and_passthrough_share_the_info_minute_budget() {
        let mut budget = WeightBucket::with(INFO_WEIGHT_PER_SECOND, INFO_WEIGHT_BURST);
        let mut spent = 0;
        for now in (0..60_000).step_by(5_000) {
            // A concurrent public /info read, then a two-dex reconstruction.
            // Failed/timeout requests retain their reservation too: there
            // is deliberately no refund on either path.
            for cost in [20, 2, 2, 45, 45, 45] {
                if budget.take(now, cost) {
                    spent += cost;
                }
            }
        }
        assert!(spent <= INFO_WEIGHT_BURST + 60 * INFO_WEIGHT_PER_SECOND);
        assert!(spent < 12 * 139); //Cannot repeatedly send unadmitted batches.
        assert!(!budget.take(55_000, 45));
    }

    #[test]
    fn the_info_bucket_refills_at_its_rate_and_holds_a_burst() {
        let mut bucket = WeightBucket::new();
        // Full: 160 of weight, a userRole (60) and five requests of 20.
        assert!(bucket.take(1_000, 60));
        for _ in 0..5 {
            assert!(bucket.take(1_000, 20));
        }
        assert!(!bucket.take(1_000, 2));
        // 2 a second: 1 s later, 2 of weight.
        assert!(bucket.take(2_000, 2));
        assert!(!bucket.take(2_000, 2));
        // 10 s later: 20.
        assert!(bucket.take(12_000, 20));
        // Never more than the burst, however long it waits.
        assert!(bucket.take(1_000_000, 160));
        assert!(!bucket.take(1_000_000, 1));
        // The request reads: two reads of 24 at once, then one every 6 s
        // (4 a second; 12 of the burst of 60 left over).
        let mut reads = WeightBucket::with(REQUEST_WEIGHT_PER_SECOND, REQUEST_WEIGHT_BURST);
        for _ in 0..2 {
            assert!(reads.take(0, ACCOUNT_READ_WEIGHT));
        }
        assert!(reads.take(0, 12));
        assert!(!reads.take(0, ACCOUNT_READ_WEIGHT));
        assert!(!reads.take(5_999, ACCOUNT_READ_WEIGHT));
        assert!(reads.take(6_000, ACCOUNT_READ_WEIGHT));
        // Charged into debt: 10 owed at 6,000 ms is paid back by 8,500 ms
        // (4 a second), and only then is anything taken again.
        reads.charge(6_000, 10);
        assert!(!reads.take(8_499, 1));
        assert!(reads.take(8_750, 1));
        // The debt goes no deeper than one burst (60): 1,000 charged at
        // once owes 60, paid back in 15 s; 60 more after that.
        reads.charge(9_000, 1_000);
        assert!(!reads.take(23_999, 1));
        assert!(reads.take(24_250, 1));
        assert_eq!(info_weight(Some("l2Book")), 2);
        assert_eq!(info_weight(Some("userRole")), 60);
        assert_eq!(info_weight(Some("candleSnapshot")), 20);
        assert_eq!(info_weight(None), 20);
    }

    #[test]
    fn the_next_ledger_read_overlaps_the_last_complete_one_by_a_minute() {
        // A complete read from 1,000,000 that reached 1,500,000: the next
        // starts 60 s earlier, at 1,440,000.
        assert_eq!(ledger_cursor(Some(1_000_000), 1_500_000, true), 1_440_000);
        // Never before where the last one started.
        assert_eq!(ledger_cursor(Some(1_000_000), 1_010_000, true), 1_000_000);
        // A read cut at its page limit goes on from where it stopped.
        assert_eq!(ledger_cursor(Some(1_000_000), 1_500_000, false), 1_500_000);
        // The first read: 60 s before what it reached.
        assert_eq!(ledger_cursor(None, 1_500_000, true), 1_440_000);
    }

    #[test]
    fn a_ledger_read_checks_a_view_only_two_seconds_into_its_run() {
        // A view read at 10,000, the first of a run: a read from 12,000 on.
        assert!(!ledger_checks(Some(11_999), 10_000, None));
        assert!(ledger_checks(Some(12_000), 10_000, None));
        assert!(!ledger_checks(None, 10_000, None));
        // A later view of a run begun at 9,000: a read after it, and from
        // 11,000 on.
        assert!(ledger_checks(Some(11_000), 10_500, Some(9_000)));
        assert!(!ledger_checks(Some(10_999), 10_500, Some(9_000)));
        assert!(!ledger_checks(Some(11_000), 11_001, Some(9_000)));
    }

    /// A share's fractional refill (`ip_share` 0.5, main dex alone: the
    /// request budget 1.530 a second, a burst of 46; `budget.rs`): spent at
    /// 0, one unit of weight is back after 1,000 / 1.53 = 653.6 ms; taking
    /// one a millisecond for a minute gets the burst and 60 × 1.53 = 91.8,
    /// so 137 at most; no refill is lost to the failed tries in between.
    #[test]
    fn a_fractional_refill_is_exact() {
        let budgets = crate::budget::plan(rust_decimal::dec!(0.5), 0).unwrap();
        let mut bucket = WeightBucket::of(budgets.requests);
        assert!(bucket.take(0, 46));
        assert!(!bucket.take(653, 1));
        assert!(bucket.take(654, 1));
        let mut bucket = WeightBucket::of(budgets.requests);
        let taken = (0..60_000).filter(|ms| bucket.take(*ms, 1)).count();
        assert_eq!(taken, 137);
        assert!(taken as u64 * 1_000 <= budgets.requests.worst_minute_milli());
    }
    #[test]
    fn flow_view_requires_every_dex_time_to_advance() {
        let previous: BTreeMap<String, i64> = [(String::new(), 100), ("xyz".into(), 200)].into();
        assert!(!fresh_flow_view(&previous, &previous));
        assert!(!fresh_flow_view(
            &[(String::new(), 101), ("xyz".into(), 200)].into(),
            &previous
        ));
        assert!(!fresh_flow_view(&[(String::new(), 101)].into(), &previous));
        assert!(fresh_flow_view(
            &[(String::new(), 101), ("xyz".into(), 201)].into(),
            &previous
        ));
    }
}
