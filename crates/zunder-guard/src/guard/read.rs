// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Reading the venue: the account for a request (from the account stream
//! when it is clean, else over HTTP), the background sync's reads, the
//! reference data they need and cache (`meta`, the account mode,
//! `perpDexs`, HIP-3 dexes' caps), books, and the `/info` passthrough.

use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
};

use futures_util::future::join_all;
use serde_json::{Value, json};
use thiserror::Error;
use zunder_guard_core::{
    account::{
        AccountView, AssetKind, Book, DexAnswers, Meta, asset_kind, book_sig_figs, parse_perp_dexs,
        requests,
    },
    action::{Action, ExchangeRequest},
    sign::Address,
};

use crate::{
    locks::lock,
    stream::Stream,
    upstream::{Upstream, UpstreamError},
};

use super::{
    Guard, Inner,
    clock::{self, Clock},
    emergency::exposed,
    limits::{ACCOUNT_READ_WEIGHT, BOOK_READ_WEIGHT, STREAM_INFO_PER_SECOND, info_weight},
    observe::LEDGER_HOLD_MS,
};

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

/// How long Guard reuses the venue's account mode (`userAbstraction`,
/// weight 20), which changes only when a person changes it.
const MODE_TTL_MS: u64 = 60_000;

/// The longest one account read made holding Guard's lock may take: the
/// sync's when a send overtook its read without the lock, a halted
/// request's to flatten (that one may also read the positions alone after
/// it, as long again, and then send the closes).
pub(super) const LOCKED_READ_MS: u64 = 5_000;

/// Why the account could not be read for a request: Guard's own budget for
/// the venue's request weight (`rate_limited`), or the venue
/// (`account_unreadable`).
#[derive(Debug)]
pub(super) enum ReadFailure {
    Budget(String),
    Venue(UpstreamError),
}

/// Why a request is not judged from the account stream (the status shows
/// the last as `stream.last_fallback`).
#[derive(Debug, Error)]
pub(super) enum StreamFallback {
    #[error("the venue's meta is not fresh")]
    MetaStale,
    #[error("the account mode is not fresh")]
    ModeStale,
    #[error("perpDexs is not fresh")]
    PerpDexsStale,
    #[error("dex {0} is not listed")]
    DexNotListed(String),
    #[error("dex {0} has not been read yet")]
    DexNotRead(String),
    #[error("dex {0}'s meta or caps are not fresh")]
    DexStale(String),
    #[error("no stream")]
    NoStream,
    /// The stream itself is not clean ([`crate::stream::NotClean`]).
    #[error("{0}")]
    NotClean(String),
    #[error("dex {0} is not one the markets name")]
    DexNotNamed(String),
    #[error("the stream's answers do not parse: {0}")]
    Unparsable(String),
}

/// Something read from the venue, and when (Guard's clock).
#[derive(Debug, Clone)]
pub(super) struct Cached<T> {
    pub(super) value: T,
    pub(super) at_ms: u64,
}

impl<T> Cached<T> {
    pub(super) fn new(value: T, at_ms: u64) -> Self {
        Self { value, at_ms }
    }

    /// The value while it is younger than `ttl_ms` at `now`.
    pub(super) fn fresh(&self, now: u64, ttl_ms: u64) -> Option<&T> {
        (now.saturating_sub(self.at_ms) < ttl_ms).then_some(&self.value)
    }
}

/// What reading the account needs besides the venue: the account, the
/// HIP-3 dexes the markets name, and what is cached between reads.
#[derive(Debug, Clone)]
pub(super) struct Caches {
    pub(super) account: Address,
    pub(super) names: std::collections::BTreeSet<String>,
    pub(super) meta: Option<Cached<Meta>>,
    /// The HIP-3 dexes `perpDexs` lists, `(index, name)`.
    pub(super) perp_dexs: Option<Cached<Vec<(u32, String)>>>,
    /// Each HIP-3 dex's `meta` Guard reads, by dex index.
    pub(super) dex_metas: HashMap<u32, Cached<Meta>>,
    /// Each HIP-3 dex's coins at their open-interest cap.
    pub(super) open_interest_caps: HashMap<u32, Cached<Value>>,
    /// Dexes the markets name that `perpDexs` does not list.
    pub(super) missing_dexes: Vec<String>,
    /// The account mode.
    pub(super) mode_cache: Option<Cached<Value>>,
}

impl Caches {
    /// Nothing read yet, for `account` and the HIP-3 dexes `names`.
    pub(super) fn new(account: Address, names: std::collections::BTreeSet<String>) -> Self {
        Self {
            account,
            names,
            meta: None,
            perp_dexs: None,
            dex_metas: HashMap::new(),
            open_interest_caps: HashMap::new(),
            missing_dexes: Vec::new(),
            mode_cache: None,
        }
    }

    /// The HIP-3 dexes `perpDexs` listed when last read, however old.
    pub(super) fn listed_dexes(&self) -> Option<&[(u32, String)]> {
        self.perp_dexs
            .as_ref()
            .map(|cached| cached.value.as_slice())
    }

    /// Take each entry of `other` that was read later than this one's: a
    /// sync that read without the lock never puts older reference data
    /// over what a request read meanwhile.
    pub(super) fn take_newer(&mut self, other: Caches) {
        fn newer<T>(mine: &mut Option<Cached<T>>, theirs: Option<Cached<T>>) -> bool {
            match theirs {
                Some(theirs) if mine.as_ref().is_none_or(|held| held.at_ms < theirs.at_ms) => {
                    *mine = Some(theirs);
                    true
                }
                _ => false,
            }
        }
        fn newer_each<T>(mine: &mut HashMap<u32, Cached<T>>, theirs: HashMap<u32, Cached<T>>) {
            for (index, entry) in theirs {
                if mine.get(&index).is_none_or(|held| held.at_ms < entry.at_ms) {
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

/// One dex's answers: its `clearinghouseState`, `frontendOpenOrders` and
/// `allMids`.
pub(super) struct DexReads {
    state: Value,
    orders: Value,
    mids: Value,
}

/// A read of the account: the view of every dex that could be read, and
/// the HIP-3 dexes that could not.
pub(super) struct AccountRead {
    pub(super) view: AccountView,
    pub(super) unread: Vec<String>,
}

/// The account a request is judged against, and whether it was read from
/// the venue just now (`fresh_read`) rather than taken from the stream.
pub(super) struct RequestView {
    pub(super) view: AccountView,
    pub(super) fresh_read: bool,
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
pub(super) fn hip3_entry_asset(request: &ExchangeRequest) -> Option<u32> {
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

impl<U: Upstream, C: Clock> Guard<U, C> {
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
            && let Some(value) = lock(&self.cache)
                .get(&key)
                .and_then(|cached| cached.fresh(now, ttl))
                .cloned()
        {
            return Ok(value);
        }
        let allowed = lock(&self.weights).info.take(now, info_weight(kind));
        if !allowed {
            return Err(UpstreamError::NotSent(format!(
                "Guard passes info requests within {} of the venue's request weight a second; try again shortly",
                crate::budget::thousandths(self.budgets.info.milli_per_second)
            )));
        }
        let value = self.upstream.info(body).await?;
        if ttl > 0 {
            let mut cache = lock(&self.cache);
            if cache.len() >= 64 {
                cache.clear();
            }
            cache.insert(key, Cached::new(value.clone(), now));
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
    pub(super) fn info_from_stream(&self, body: &Value) -> Option<Value> {
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
        let allowed = lock(&self.weights)
            .stream_info
            .take(self.clock.now_ms(), STREAM_INFO_PER_SECOND);
        if !allowed {
            return None;
        }
        let (state, orders) = {
            let stream = lock(&self.stream);
            let state = lock(&stream.as_ref()?.state);
            state.raw_snapshot(self.clock.monotonic_ms(), last_send, dex)?
        };
        lock(&self.judged).info_from_stream += 1;
        Some(if kind == "clearinghouseState" {
            state
        } else {
            orders
        })
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
        let (stream, task) = Stream::spawn(url, user, &dexes, self.clock.clone());
        *lock(&self.stream) = Some(stream);
        Some(task)
    }

    /// The account for a request, from the stream when it is clean, else
    /// read fresh ([`Guard::read_for_request`]). Either way the stream is asked to follow
    /// the entry's coin, so that the next judgement of it can use the
    /// stream.
    pub(super) async fn account_for_request(
        &self,
        inner: &mut Inner,
        now: u64,
        request: &ExchangeRequest,
    ) -> Result<RequestView, ReadFailure> {
        // This entire helper only reads account/book data. Bound it while
        // holding the mutex; no journal, leverage, signer or send is here.
        let result = if inner.ledger.hold.is_some() {
            let deadline = self.flow_read_deadline(inner, LEDGER_HOLD_MS);
            clock::timeout(
                &*self.clock,
                clock::left(&*self.clock, deadline),
                self.account_for_request_inner(inner, now, request),
            )
            .await
            .unwrap_or_else(|| {
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
    ) -> Result<RequestView, ReadFailure> {
        let streaming = lock(&self.stream).is_some();
        if !streaming {
            let view = self.read_for_request(inner, now, request).await?;
            return Ok(RequestView {
                view,
                fresh_read: true,
            });
        }
        let from_stream = self.stream_view(inner, now, request);
        let (view, read) = match from_stream {
            Ok(mut view) => {
                // A HIP-3 entry's book is read for it (20 levels; the
                // stream's fast book has 5, too few to reach a stop's worst
                // fill), within the request-read budget.
                if let Some(asset) = hip3_entry_asset(request) {
                    let allowed = lock(&self.weights).requests.take(now, BOOK_READ_WEIGHT);
                    if !allowed {
                        return Err(ReadFailure::Budget(
                            "Guard's request-read budget is spent; try again in a few seconds"
                                .into(),
                        ));
                    }
                    self.read_book(&mut view, asset, false).await;
                }
                lock(&self.judged).stream += 1;
                (view, false)
            }
            Err(why) => {
                {
                    let mut judged = lock(&self.judged);
                    judged.read += 1;
                    judged.last_fallback = Some(why.to_string());
                }
                (self.read_for_request(inner, now, request).await?, true)
            }
        };
        if read {
            inner.halt.last_read_exposed = Some(exposed(&view));
        }
        if let Some(coin) = entry_asset(request)
            .and_then(|asset| view.meta.by_index(asset))
            .map(|asset| asset.name.clone())
            && let Some(stream) = lock(&self.stream).as_ref()
        {
            stream.follow(&coin);
        }
        Ok(RequestView {
            view,
            fresh_read: read,
        })
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
    ) -> Result<AccountView, StreamFallback> {
        let Some(meta) = (inner.caches.meta.as_ref()).and_then(|meta| meta.fresh(now, META_TTL_MS))
        else {
            return Err(StreamFallback::MetaStale);
        };
        let Some(mode) =
            (inner.caches.mode_cache.as_ref()).and_then(|mode| mode.fresh(now, MODE_TTL_MS))
        else {
            return Err(StreamFallback::ModeStale);
        };
        // Each HIP-3 dex the markets name, by its index, with its meta and
        // caps.
        let mut hip3: HashMap<String, (&Meta, &Value)> = HashMap::new();
        let names = inner.config.policy.markets.hip3_dexes();
        if !names.is_empty() {
            let Some(listed) = (inner.caches.perp_dexs.as_ref())
                .and_then(|listed| listed.fresh(now, PERP_DEXS_TTL_MS))
            else {
                return Err(StreamFallback::PerpDexsStale);
            };
            for name in &names {
                let Some((index, _)) = listed.iter().find(|(_, listed)| listed == name) else {
                    return Err(StreamFallback::DexNotListed(name.clone()));
                };
                let (Some(dex_meta), Some(cap)) = (
                    inner.caches.dex_metas.get(index),
                    inner.caches.open_interest_caps.get(index),
                ) else {
                    return Err(StreamFallback::DexNotRead(name.clone()));
                };
                let (Some(dex_meta), Some(cap)) = (
                    dex_meta.fresh(now, META_TTL_MS),
                    cap.fresh(now, OPEN_INTEREST_CAP_TTL_MS),
                ) else {
                    return Err(StreamFallback::DexStale(name.clone()));
                };
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
            let stream = lock(&self.stream);
            let Some(stream) = stream.as_ref() else {
                return Err(StreamFallback::NoStream);
            };
            let state = lock(&stream.state);
            state
                .answers(
                    self.clock.monotonic_ms(),
                    inner.sends.last_mono,
                    coin.as_deref(),
                )
                .map_err(|not| StreamFallback::NotClean(not.0))?
        };
        let mut parts = Vec::with_capacity(answers.dexes.len());
        for (dex, state, orders, mids) in &answers.dexes {
            let (dex_meta, cap) = if dex.is_empty() {
                (meta, None)
            } else {
                let Some((dex_meta, cap)) = hip3.get(dex) else {
                    return Err(StreamFallback::DexNotNamed(dex.clone()));
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
            .map_err(|error| StreamFallback::Unparsable(error.to_string()))?;
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
        let allowed = lock(&self.weights).requests.take(now, weight);
        if !allowed {
            let per_minute = lock(&self.weights).requests.milli_per_second * 60
                / (ACCOUNT_READ_WEIGHT * dexes * 1_000);
            return Err(ReadFailure::Budget(format!(
                "Guard reads the account for at most {per_minute} requests a minute on average (the venue's request limit is shared with Guard's own sync and protection); try again in a few seconds",
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
    pub(super) async fn read_book(&self, view: &mut AccountView, asset: u32, passthrough: bool) {
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
    pub(super) async fn perp_dexs(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<Vec<(u32, String)>, UpstreamError> {
        if let Some(list) =
            (caches.perp_dexs.as_ref()).and_then(|list| list.fresh(now, PERP_DEXS_TTL_MS))
        {
            return Ok(list.clone());
        }
        let value = self.upstream.info(&requests::perp_dexs()).await?;
        let list =
            parse_perp_dexs(&value).map_err(|error| UpstreamError::NotJson(error.to_string()))?;
        caches.perp_dexs = Some(Cached::new(list.clone(), now));
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
    pub(super) fn managed_indices(inner: &Inner) -> Vec<u32> {
        let names = &inner.caches.names;
        inner.caches.listed_dexes().map_or_else(Vec::new, |list| {
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
        if let Some(meta) =
            (caches.dex_metas.get(&index)).and_then(|meta| meta.fresh(now, META_TTL_MS))
        {
            return Ok(meta.clone());
        }
        let value = self.upstream.info(&requests::meta_of(name)).await?;
        let meta = Meta::parse_dex(&value, index, name)
            .map_err(|error| UpstreamError::NotJson(error.to_string()))?;
        caches
            .dex_metas
            .insert(index, Cached::new(meta.clone(), now));
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
        if let Some(value) = (caches.open_interest_caps.get(&index))
            .and_then(|caps| caps.fresh(now, OPEN_INTEREST_CAP_TTL_MS))
        {
            return Ok(value.clone());
        }
        let value = self
            .upstream
            .info(&requests::perps_at_open_interest_cap(name))
            .await?;
        caches
            .open_interest_caps
            .insert(index, Cached::new(value.clone(), now));
        Ok(value)
    }

    /// One dex's positions, orders and mids, concurrently: the main dex
    /// for `None` (the requests exactly as before HIP-3), a HIP-3 dex by
    /// name.
    async fn read_dex(&self, user: Address, dex: Option<&str>) -> Result<DexReads, UpstreamError> {
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
        Ok(DexReads {
            state: state?,
            orders: orders?,
            mids: mids?,
        })
    }

    /// Read the account fresh, every dex Guard manages: complete, or an
    /// error (a request is never judged against part of the account).
    async fn read_account(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<AccountView, UpstreamError> {
        let AccountRead { view, unread } = self.read_account_parts(caches, now).await?;
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
    /// its caps, its answers, or `perpDexs`) is left out and named in
    /// `unread`, so that one deployer's malformed answer never leaves
    /// the other dexes without protection.
    async fn read_account_parts(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<AccountRead, UpstreamError> {
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
        let cached_mode = (caches.mode_cache.as_ref())
            .and_then(|mode| mode.fresh(now, MODE_TTL_MS))
            .cloned();
        let mode = match cached_mode {
            Some(mode) => mode,
            None => {
                let mode = self
                    .upstream
                    .info(&requests::user_abstraction(user))
                    .await?;
                caches.mode_cache = Some(Cached::new(mode.clone(), now));
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
            clearinghouse: &main.state,
            open_orders: &main.orders,
            mids: &main.mids,
            at_open_interest_cap: None,
        };
        // The main dex alone must parse.
        AccountView::parse_dexes(now as i64, &mode, &[main_part])
            .map_err(|error| UpstreamError::NotJson(error.to_string()))?;
        // Each HIP-3 dex must have answered and parse beside it, or it is
        // left out.
        type Read<'a> = (&'a Meta, &'a Value, &'a String, DexReads);
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
        for (dex_meta, cap, name, answers) in &read {
            let part = DexAnswers {
                meta: dex_meta,
                clearinghouse: &answers.state,
                open_orders: &answers.orders,
                mids: &answers.mids,
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
        Ok(AccountRead { view, unread })
    }

    pub(super) async fn meta(&self, caches: &mut Caches, now: u64) -> Result<Meta, UpstreamError> {
        if let Some(meta) = (caches.meta.as_ref()).and_then(|meta| meta.fresh(now, META_TTL_MS)) {
            return Ok(meta.clone());
        }
        let value = self.upstream.info(&requests::meta()).await?;
        let meta =
            Meta::parse(&value).map_err(|error| UpstreamError::NotJson(error.to_string()))?;
        caches.meta = Some(Cached::new(meta.clone(), now));
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

    /// [`Guard::read_account_parts`] within [`LOCKED_READ_MS`]: for reads
    /// made holding Guard's lock.
    pub(super) async fn read_locked(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<AccountRead, UpstreamError> {
        clock::timeout(
            &*self.clock,
            LOCKED_READ_MS,
            self.read_account_parts(caches, now),
        )
        .await
        .unwrap_or_else(|| {
            Err(UpstreamError::NoAnswer(format!(
                "no account within {LOCKED_READ_MS} ms"
            )))
        })
    }

    /// Bound only the read-only future while holding the lock. A request
    /// cannot start another hold until this lock is released.
    pub(super) async fn sync_read_locked(
        &self,
        caches: &mut Caches,
        now: u64,
        deadline: Option<u64>,
    ) -> Result<AccountRead, UpstreamError> {
        let remaining = deadline.map_or(LOCKED_READ_MS, |deadline| {
            deadline
                .saturating_sub(self.clock.now_ms())
                .min(LOCKED_READ_MS)
        });
        clock::timeout(&*self.clock, remaining, self.read_locked(caches, now))
            .await
            .unwrap_or_else(|| {
                Err(UpstreamError::NoAnswer(
                    "account read reached loss-hold deadline".to_owned(),
                ))
            })
    }

    /// A hold can begin on a request while this unlocked read waits.
    /// Register the broadcast before checking the current deadline to
    /// avoid missing that race. No journal, signer or send is cancelled.
    pub(super) async fn sync_read_unlocked(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<AccountRead, UpstreamError> {
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
                .ledger
                .hold
                .as_ref()
                .map(|hold| hold.since.saturating_add(LEDGER_HOLD_MS));
            if let Some(deadline) = deadline {
                tokio::select! {
                    result = &mut read => return result,
                    _ = &mut changed => {},
                    () = self.clock.sleep(deadline.saturating_sub(self.clock.now_ms())) => {
                        let inner = self.inner.lock().await;
                        if inner.ledger.hold.as_ref().is_some_and(|hold| self.clock.now_ms().saturating_sub(hold.since) >= LEDGER_HOLD_MS) {
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
    pub(super) async fn positions_locked(
        &self,
        caches: &mut Caches,
        now: u64,
    ) -> Result<AccountView, UpstreamError> {
        clock::timeout(
            &*self.clock,
            LOCKED_READ_MS,
            self.read_positions(caches, now),
        )
        .await
        .unwrap_or_else(|| {
            Err(UpstreamError::NoAnswer(format!(
                "no positions within {LOCKED_READ_MS} ms"
            )))
        })
    }
}
