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
//!
//! The code, by what it does:
//!
//! - [`request`]: one `/exchange` request from admission to the reply, and
//!   `/guard/preview`;
//! - [`read`]: reading the venue: the account (from the stream or over
//!   HTTP), the reference data it needs and caches, books, and `/info`
//!   passthrough;
//! - [`observe`]: showing the risk engine the account, with deposits and
//!   withdrawals kept out of the account stops;
//! - [`send`]: signing and sending what a decision forwards, each action
//!   named by an intent on disk first;
//! - [`protect`]: Guard's own stops for positions without one, and closing
//!   what cannot be protected;
//! - [`emergency`]: the kill switch, halts and flattening, and the
//!   emergency log;
//! - [`sync`]: the background sync and its look at the dexes Guard does not
//!   manage;
//! - [`recovery`]: asking the venue what became of actions sent before a
//!   restart;
//! - [`limits`]: Guard's budgets of the venue's request weight;
//! - [`fee`]: the builder fee and the licence key's lifecycle;
//! - [`status`]: the local status, alerts, events and decision lookups;
//! - [`reason`]: the reason codes Guard decides on itself, and where a
//!   request came in;
//!
//! Guard's time, and every wait it makes on its own account, is
//! [`crate::clock`]'s.

mod emergency;
mod fee;
mod limits;
mod observe;
mod protect;
mod read;
mod reason;
mod recovery;
mod request;
mod send;
mod status;
mod sync;

pub use self::{
    emergency::EMERGENCY_WRITE_MS,
    fee::utc_text,
    limits::{
        EXITS_PER_SECOND, INFO_WEIGHT_BURST, INFO_WEIGHT_PER_SECOND, Limits, PREVIEWS_PER_SECOND,
        REQUEST_WEIGHT_BURST, REQUEST_WEIGHT_PER_SECOND, STREAM_INFO_PER_SECOND, info_weight,
    },
    observe::SETTLE_MS,
    reason::Via,
    recovery::{INTENT_COVERS_MS, RECOVERY_MS, RECOVERY_READ_AGAIN_MS},
    request::{
        PREVIEW_MALFORMED, PREVIEW_RATE_LIMITED, PREVIEW_VIEW_STALE, REFUSALS_JOURNALED_PER_MINUTE,
        VETOES_JOURNALED_PER_MINUTE,
    },
    send::{ACTION_TTL_MS, BOT_CLOID_PREFIX, CLOSE_CLOID_PREFIX, LEVERAGE_TTL_MS},
};
pub(crate) use self::{
    limits::{
        ACCOUNT_READ_WEIGHT, BOOK_READ_WEIGHT, EXITS_BURST, FEE_CHECK_WEIGHT, LEVERAGE_READ_WEIGHT,
        SYNC_CACHED_WEIGHT, SYNC_CACHED_WEIGHT_PER_DEX, SYNC_WEIGHT_PER_MINUTE,
    },
    protect::PROTECT_AT_LEAST_EVERY_MS,
};
pub use crate::clock::{Clock, SystemClock};

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64},
    },
};

use serde_json::Value;
use thiserror::Error;
use tokio::sync::Mutex;
use zunder_guard_core::{
    account::AccountView,
    action::RunMode,
    auth::Authenticator,
    event::{EVENT_SCHEMA, EventBody},
    licence::{FeeMode, FeeState},
    sign::{Address, GuardKey, SigningNetwork},
};
use zunder_venue::PersistentRisk;

use crate::{
    clock::{self, stamp},
    config::GuardConfig,
    journal::DecisionJournal,
    rules,
    stream::Stream,
    upstream::Upstream,
};

use self::{
    emergency::Emergency,
    fee::LicenceTrack,
    limits::Weights,
    observe::LedgerHold,
    protect::RestingEntry,
    read::{Cached, Caches},
    status::Alert,
    sync::Unmanaged,
};

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
    /// The mode as `/guard/status` names it and a request's
    /// `expectedMode` is compared with: derived from this very value, so
    /// the check and the send cannot disagree.
    pub fn run_mode(&self) -> RunMode {
        match self {
            Mode::Paper => RunMode::Paper,
            Mode::Send {
                network: SigningNetwork::Testnet,
                ..
            } => RunMode::Testnet,
            Mode::Send {
                network: SigningNetwork::Mainnet,
                ..
            } => RunMode::Mainnet,
        }
    }

    pub fn name(&self) -> &'static str {
        self.run_mode().name()
    }
}

/// Why a Guard could not start.
#[derive(Debug, Error)]
pub enum StartError {
    #[error(
        "the mode and the venue connection disagree on the network, or a paper Guard was given a sending connection"
    )]
    Network,
    #[error("the config's mode is {config}, not {running}")]
    Mode { config: String, running: String },
    #[error(transparent)]
    Budget(#[from] crate::budget::BudgetError),
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Auth(#[from] zunder_guard_core::auth::AuthConfigError),
    /// No secret for Guard's stop ids.
    #[error("{0}")]
    Random(String),
    #[error(transparent)]
    Journal(#[from] crate::journal::JournalError),
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

/// Everything a decision rests on, behind [`Guard`]'s `inner` lock, grouped
/// by what it is for.
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
    /// A secret of this process for Guard's stop ids.
    salt: [u8; 16],
    kill: KillSwitch,
    halt: HaltReads,
    /// What reading the account needs and caches: taken out of `Inner` by
    /// the background sync while it reads, so that requests do not wait
    /// for the venue's answers.
    caches: Caches,
    /// The account as the risk engine last saw it, when, and the last
    /// error reading it.
    last_view: Option<AccountView>,
    last_sync_ms: Option<u64>,
    last_error: Option<String>,
    sends: Sends,
    protection: Protection,
    /// Where protective sends made while the decision journal cannot be
    /// written are recorded (`docs/guard.md#journals`).
    emergency: Emergency,
    /// Other things Guard could not fix or had to fix the hard way: kept
    /// while their order rests, or for an hour.
    alerts: Vec<Alert>,
    ledger: Ledger,
    sync: SyncRounds,
    sweep: Sweep,
    journaled: Journaled,
}

/// The kill switch.
#[derive(Debug, Default)]
struct KillSwitch {
    /// Why it was pulled; `None` while it is not.
    reason: Option<String>,
    /// Positions in the first flatten snapshot after the kill latch.
    /// Later account reads must not replace this with the post-close count.
    positions: Option<usize>,
}

/// What a halted Guard last did to flatten.
#[derive(Debug, Default)]
struct HaltReads {
    /// The halt last reported, so a paper Guard journals a flatten once.
    reported: Option<String>,
    /// When a halted request last read the account to flatten.
    last_read_ms: Option<u64>,
    /// Whether the last account read over HTTP showed anything to flatten
    /// (a position or an opening order).
    last_read_exposed: Option<bool>,
}

/// What Guard sent and heard back.
#[derive(Debug, Default)]
struct Sends {
    /// The last nonce Guard signed with.
    last_nonce: u64,
    /// The last intent on disk. Guard sends only an action an intent on
    /// disk names, expiring within [`INTENT_COVERS_MS`] of it
    /// (`docs/guard.md#journals`).
    intent: Option<Intent>,
    /// Stops Guard attached to resting entries (`normalTpsl`), the newest
    /// [`send::ATTACHED_KEPT`].
    attached: VecDeque<AttachedStops>,
    /// When Guard last heard back from the venue after sending, on Guard's
    /// clock's time of day and on its monotonic clock
    /// ([`Clock::monotonic_ms`]).
    last_ms: Option<u64>,
    last_mono: Option<u64>,
    /// How many times Guard heard back from the venue after sending: the
    /// sync tells by it whether a send overtook its read.
    answered: u64,
    /// Client ids Guard gave so far (with the salt, what makes the next
    /// one unique).
    client_ids: u64,
    /// Entries whose outcome is unknown that may still reach the venue
    /// (`Guard::entry_may_arrive`): held until each is resolved.
    unknown_entries: Vec<PendingEntry>,
}

/// How long after its expiry an entry whose outcome is unknown still
/// holds new entries: the 15 s recovery allows for Guard's clock running
/// ahead of the venue's (`recovery.rs`), above the settle window in which
/// the venue's view may not show a fill yet.
pub(super) const ENTRY_EXPIRY_MARGIN_MS: u64 = 15_000;
const _: () = assert!(ENTRY_EXPIRY_MARGIN_MS > observe::SETTLE_MS);

/// An entry whose outcome is unknown (its answer lost or unreadable): on
/// `coin`, valid on the venue until `expires_ms` (Guard's clock), sent by
/// `sent_mono` (Guard's monotonic clock).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingEntry {
    coin: String,
    expires_ms: u64,
    sent_mono: u64,
}

/// A complete read of the account a sync round made: when it began, on
/// Guard's clock and on its monotonic clock, and the venue's time of its
/// account answers (the oldest dex's), when they carry one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompleteRead {
    wall: u64,
    mono: u64,
    venue_ms: Option<i64>,
}

impl PendingEntry {
    /// It can no longer arrive, and the account has been read since: Guard's
    /// clock at `now` is [`ENTRY_EXPIRY_MARGIN_MS`] past its expiry, and the
    /// complete read `read` began after it was sent (monotonic clock),
    /// at least that margin past its expiry (Guard's clock), and shows the
    /// venue's time more than the settle window past its expiry, when the
    /// answers carry it (the venue's view may lag a fill on its own clock
    /// too).
    fn resolved(&self, now: u64, read: Option<&CompleteRead>) -> bool {
        let after = self.expires_ms.saturating_add(ENTRY_EXPIRY_MARGIN_MS);
        let expired_at_venue = |venue: i64| {
            self.expires_ms
                .checked_add(observe::SETTLE_MS)
                .and_then(|settled| i64::try_from(settled).ok())
                .is_some_and(|settled| venue > settled)
        };
        now >= after
            && read.is_some_and(|read| {
                read.mono > self.sent_mono
                    && read.wall >= after
                    && read.venue_ms.is_none_or(expired_at_venue)
            })
    }
}

/// An intent on disk (a decision to send, a protection, a flattening, an
/// `intent` event): its `seq`, when it was written, and the actions it
/// named, as they go out.
#[derive(Debug, Clone)]
struct Intent {
    seq: u64,
    at_ms: u64,
    actions: Vec<Value>,
}

/// The stops a resting entry carries (`normalTpsl`): the entry's order id
/// and the stops' client ids. The venue cancels them with the entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AttachedStops {
    entry: u64,
    cloids: Vec<String>,
}

/// Guard's own protection of the positions.
#[derive(Debug, Default)]
struct Protection {
    /// Entries Guard forwarded that rest with their stop, the newest
    /// [`send::ATTACHED_KEPT`]: once one fills, its stop counts for its
    /// position in Guard's protect pass, which then places that stop (not
    /// one at the default distance) should the venue not activate the
    /// entry's own.
    resting_entries: VecDeque<RestingEntry>,
    /// Positions Guard found without a stop and could not protect or close
    /// (or, in paper mode, would have protected); shown in the status until
    /// a sync finds every position covered.
    alert: Option<String>,
    /// When the background sync last protected the positions.
    last_ms: Option<u64>,
    /// Protect at the next sync whether settled or not (an entry was just
    /// cancelled and may have filled in part, or what a send did is
    /// unknown).
    at_next_sync: bool,
    /// After a send whose outcome is unknown: `at_next_sync` stays set
    /// until a round whose complete read began at or after this time
    /// (Guard's monotonic clock: the send plus the settle window), so that a
    /// view that does not show the send yet does not use it up.
    until: Option<u64>,
}

/// Deposits and withdrawals: the account's ledger, and the views the risk
/// engine was not shown for want of it (`docs/guard.md`, "Deposits and
/// withdrawals").
#[derive(Debug, Default)]
struct Ledger {
    /// The ledger is read over HTTP from this time on (epoch ms; `None`
    /// before the first read).
    from_ms: Option<i64>,
    /// When it was last read, and last read successfully (Guard's clock).
    read_ms: Option<u64>,
    ok_ms: Option<u64>,
    /// The stream's reconnects at the last successful read.
    reconnects: u64,
    /// The views held back for want of a read (`docs/guard.md`,
    /// "Deposits and withdrawals").
    hold: Option<LedgerHold>,
    /// Since when every view the risk engine was shown has been left out.
    views_left_since: Option<u64>,
    /// How many flows were applied, and the last one that was not.
    flows_applied: u64,
    flow_note: Option<String>,
    /// The last ledger entry Guard could not account for (an unknown type,
    /// a malformed entry), and until when (Guard's clock, epoch ms: the end
    /// of the UTC day it was seen) it refuses new positions for it.
    unaccounted: Option<(String, u64)>,
    /// The ids of the entries reported so, the newest
    /// [`observe::UNACCOUNTED_KEPT`]: each is reported once.
    unaccounted_seen: VecDeque<String>,
}

/// How the background sync's last rounds read the account.
#[derive(Debug, Default)]
struct SyncRounds {
    /// The sync read twice in its last round (a send overtook its first
    /// read): its next round waits one interval longer, so that its reads
    /// stay within its share of the venue's weight.
    read_twice: bool,
    /// A sync that reads holding the lock for its `ip_share`
    /// ([`crate::budget::Budgets::sync_reads_locked`]) could not read within
    /// [`read::LOCKED_READ_MS`]: its next round reads without the lock, as
    /// at share 1, so that a slow venue never stops the sync altogether.
    unlock_next: bool,
    /// How many times the last sync round read the account (1, or 2 when a
    /// send overtook its first read), for the status.
    last_reads: u8,
    /// The newest complete read of the account a sync round made (by when
    /// it began on the monotonic clock): what resolves an entry whose
    /// outcome is unknown (`PendingEntry::resolved`).
    last_complete: Option<CompleteRead>,
}

/// The sweep of the perp dexes Guard does not manage.
#[derive(Debug, Default)]
struct Sweep {
    /// Positions found there, by dex name: reported, never touched.
    found: BTreeMap<String, Unmanaged>,
    /// Its place in `perpDexs`, and when it last looked.
    next: usize,
    last_ms: Option<u64>,
}

/// How many refusals and vetoes were journaled this minute.
#[derive(Debug, Default)]
struct Journaled {
    /// Refusals before judging ([`REFUSALS_JOURNALED_PER_MINUTE`]).
    refusals: MinuteCount,
    /// Vetoes ([`VETOES_JOURNALED_PER_MINUTE`]), each client's on its own.
    vetoes: VetoCount,
}

/// Records journaled in one minute, and those that were not.
#[derive(Debug, Default)]
struct MinuteCount {
    /// Minutes since the epoch.
    minute: u64,
    journaled: u32,
    dropped: u32,
}

/// Vetoes journaled in one minute, by client, and those that were not.
#[derive(Debug, Default)]
struct VetoCount {
    minute: u64,
    by_client: HashMap<String, u32>,
    dropped: u32,
}

/// A running Guard. Cheap to share: clone the `Arc`.
///
/// Its state is behind two kinds of lock. `inner` (a Tokio mutex) holds
/// everything a decision rests on: a request holds it from admission to
/// its reply, a sync round while it decides and sends, so that decisions
/// and sends never interleave. The rest are standard mutexes taken for a
/// few statements and never held across an await, each on its own:
/// `weights`, `cache`, `stream` and `judged` ([`crate::locks::lock`]).
pub struct Guard<U, C = SystemClock> {
    upstream: Arc<U>,
    /// Guard's one clock, shared with the account stream, the journals and
    /// the emergency log.
    clock: Arc<C>,
    inner: Mutex<Inner>,
    /// The `/info` passthrough's cache, by request body.
    cache: StdMutex<HashMap<String, Cached<Value>>>,
    /// Every budget of the venue's request weight, fitted to the config's
    /// `ip_share` ([`crate::budget::plan`]).
    budgets: crate::budget::Budgets,
    /// What is left of each of those budgets.
    weights: StdMutex<Weights>,
    started_ms: u64,
    /// The account as the venue's WebSocket streams it, once started
    /// ([`Guard::start_stream`]).
    stream: StdMutex<Option<Stream>>,
    /// How requests were judged: from the stream, or after a read.
    judged: StdMutex<JudgedFrom>,
    /// The account Guard trades for, and when Guard last heard back on a
    /// send (on [`Clock::monotonic_ms`], 0 before the first), for the
    /// `/info` passthrough to answer from the stream without Guard's lock.
    account: Address,
    last_send_mono: AtomicU64,
    /// Recovery after a restart is running ([`Guard::recover`]).
    recovering: AtomicBool,
    hold_started: tokio::sync::Notify,
    /// Broadcast deadline changes to every read already in flight.
    hold_changed: tokio::sync::Notify,
    /// Wakes the background sync at once: a send's outcome is unknown, so
    /// what it left open is protected now, not at the next round.
    protect_soon: tokio::sync::Notify,
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
    pub fn new(setup: Setup, upstream: U, clock: C) -> Result<Arc<Self>, StartError> {
        // The signature's network and the transport's network are one.
        match (&setup.mode, upstream.sends_to()) {
            (Mode::Paper, None) => {}
            (Mode::Send { network, .. }, Some(sends_to)) if *network == sends_to => {}
            _ => {
                return Err(StartError::Network);
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
            return Err(StartError::Mode {
                config: setup.config.mode.name().to_owned(),
                running: setup.mode.name().to_owned(),
            });
        }
        // The production budgets, fitted to the HIP-3 dexes the markets name
        // and to the part of the IP address's request weight that is this
        // Guard's (`ip_share`); refused when the share is too small to keep
        // Guard safe. Tests against an in-memory venue may raise the request
        // budget alone.
        let mut budgets = crate::budget::plan(
            setup.config.ip_share,
            setup.config.policy.markets.hip3_dexes().len(),
        )?;
        if setup.limits != Limits::default() {
            budgets.requests = crate::budget::Bucket {
                milli_per_second: setup.limits.request_weight_per_second.saturating_mul(1_000),
                burst: setup.limits.request_weight_burst,
            };
        }
        let clock = Arc::new(clock);
        let started_ms = clock.now_ms();
        let account = setup.config.account()?;
        let auth = Authenticator::new(&setup.config.auth, started_ms)?;
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|error| StartError::Random(error.to_string()))?;
        // The account's network; a config without one (which `validate`
        // refuses) is held to mainnet's rules, where only the production
        // licence key counts.
        let fee_network = crate::licence_life::licence_network(&setup.config);
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
            salt,
            kill: KillSwitch::default(),
            halt: HaltReads::default(),
            caches: Caches::new(account, setup.config.policy.markets.hip3_dexes()),
            last_view: None,
            last_sync_ms: None,
            last_error: None,
            sends: Sends::default(),
            protection: Protection::default(),
            emergency: Emergency::new(
                crate::journal::EmergencyLog::new(
                    &setup
                        .config
                        .emergency_log(matches!(setup.mode, Mode::Paper)),
                ),
                clock.clone(),
            ),
            alerts: Vec::new(),
            ledger: Ledger::default(),
            sync: SyncRounds::default(),
            sweep: Sweep::default(),
            journaled: Journaled::default(),
            config: setup.config,
            mode: setup.mode,
            // Deposits and withdrawals are kept out of the account stops
            // (`docs/guard.md`): Guard's own choice, not the runner's.
            risk: setup.risk.with_flows(),
            journal: setup.journal,
            fee,
        };
        // The journal's deadlines on Guard's clock.
        inner.journal.set_clock(clock.clone());
        let started = EventBody::Started {
            schema: EVENT_SCHEMA,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            mode: inner.mode.name().to_owned(),
            account: account.to_hex(),
            rules: rules::encode(&inner.config.policy),
            clients: inner.auth.clients().map(Address::to_hex).collect(),
        };
        inner.journal.append(stamp(started_ms), started)?;
        if let Some(warning) = setup.fee_warning {
            inner
                .journal
                .append(stamp(started_ms), EventBody::Error { text: warning })
                .ok();
        }
        if let Some((bytes, aside)) = inner.journal.cut_on_open() {
            inner
                .journal
                .append(
                    stamp(started_ms),
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
            weights: StdMutex::new(Weights::new(&budgets)),
            budgets,
            started_ms,
            stream: StdMutex::new(None),
            judged: StdMutex::new(JudgedFrom::default()),
            account,
            last_send_mono: AtomicU64::new(0),
            recovering: AtomicBool::new(false),
            hold_started: tokio::sync::Notify::new(),
            hold_changed: tokio::sync::Notify::new(),
            protect_soon: tokio::sync::Notify::new(),
        }))
    }

    pub fn upstream(&self) -> &U {
        &self.upstream
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

    /// Record that Guard stops.
    pub async fn stopped(&self, reason: &str) {
        let mut inner = self.inner.lock().await;
        let now = self.clock.now_ms();
        inner
            .journal
            .append(
                stamp(now),
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

#[cfg(test)]
mod pending_entry_tests {
    use super::{CompleteRead, PendingEntry};

    /// An entry sent at monotonic 1,000 that expires at 130,000 on Guard's
    /// clock: the hold ends at 130,000 + 15,000 = 145,000, for a read begun
    /// after monotonic 1,000, at or after 145,000, whose venue time (if any)
    /// is past 130,000 + 5,000 = 135,000.
    #[test]
    fn a_lost_entry_resolves_only_when_every_condition_holds() {
        let pending = PendingEntry {
            coin: "ETH".into(),
            expires_ms: 130_000,
            sent_mono: 1_000,
        };
        let read = |wall: u64, mono: u64, venue_ms: Option<i64>| CompleteRead {
            wall,
            mono,
            venue_ms,
        };
        let good = read(145_000, 2_000, Some(135_001));
        assert!(pending.resolved(145_000, Some(&good)));
        // Guard's clock 1 ms short of the margin.
        assert!(!pending.resolved(144_999, Some(&good)));
        // No complete read at all.
        assert!(!pending.resolved(200_000, None));
        // A read begun before the send (monotonic), however late its wall
        // start reads (a time of day stepped forward).
        assert!(!pending.resolved(200_000, Some(&read(200_000, 1_000, Some(150_000)))));
        // A read begun after the send but 1 ms before the margin's end.
        assert!(!pending.resolved(200_000, Some(&read(144_999, 2_000, Some(150_000)))));
        // The venue's time at 135,000: not past expiry plus the settle window.
        assert!(!pending.resolved(200_000, Some(&read(145_000, 2_000, Some(135_000)))));
        // Answers without the venue's time: Guard's clock decides.
        assert!(pending.resolved(145_000, Some(&read(145_000, 2_000, None))));
    }
}

/// What the tests of several modules share.
#[cfg(test)]
mod test_support {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// A view with a BTC long, Guard's stop on it (oid 9, reduce-only), a
    /// bot's take profit (oid 10, reduce-only), a resting ETH buy (oid 11)
    /// and an ETH reduce-only order (oid 12).
    pub(super) fn view_for_expectations() -> AccountView {
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
}
