// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The background sync: every `sync_seconds` it reads the account, feeds
//! the risk engine, flattens on a halt or the kill switch, protects, and
//! looks at one dex Guard does not manage.

use std::{collections::BTreeSet, sync::Arc};

use rust_decimal::Decimal;
use serde_json::Value;
use zunder_guard_core::{account::requests, event::EventBody, licence, sign::Address};

use crate::upstream::Upstream;

use super::{
    CompleteRead, Guard, Inner,
    clock::{self, Clock, stamp},
    emergency::exposed,
    fee::LICENCE_ALERT,
    observe::{LEDGER_HOLD_MS, LEDGER_READ_EVERY_MS, SETTLE_MS},
    protect::PROTECT_AT_LEAST_EVERY_MS,
    read::{AccountRead, Caches},
    status::ALERT_KEEP_MS,
};

/// How often the background sync looks at one perp dex Guard does not
/// manage (`clearinghouseState`, weight 2), to report positions there.
const SWEEP_EVERY_MS: u64 = 30_000;

/// The sync reads the account holding Guard's lock (one read, no chance
/// of being overtaken) when Guard heard back on a send this recently: a
/// bot that is sending will likely send again during an unlocked read.
const SYNC_LOCKED_AFTER_SEND_MS: u64 = 2_000;

/// The sync's cadence on Guard's monotonic clock: a tick every `interval`
/// ms, the first at once. A tick taken more than 5 ms late is followed by
/// the next a whole interval after it, so that missed ticks are not run
/// back to back (Tokio's `MissedTickBehavior::Delay`).
struct Cadence {
    next: u64,
    interval: u64,
}

impl Cadence {
    fn new(now: u64, interval: u64) -> Self {
        Self {
            next: now,
            interval,
        }
    }

    /// How long from `now` until the next tick.
    fn wait(&self, now: u64) -> u64 {
        self.next.saturating_sub(now)
    }

    /// The tick was taken at `now`.
    fn ticked(&mut self, now: u64) {
        self.next = if now > self.next.saturating_add(5) {
            now.saturating_add(self.interval)
        } else {
            self.next.saturating_add(self.interval)
        };
    }

    /// The next tick at `at` instead.
    fn reset(&mut self, at: u64) {
        self.next = at;
    }
}

/// What a look at a dex Guard does not manage takes from Guard's state:
/// the caches (for `perpDexs`), the dexes Guard manages, the sweep's place
/// in `perpDexs`, and the account.
struct SweepStart {
    caches: Caches,
    managed: BTreeSet<String>,
    next: usize,
    account: Address,
}

/// Positions on a perp dex Guard does not manage.
#[derive(Debug, Clone)]
pub(super) struct Unmanaged {
    pub(super) index: u32,
    pub(super) coins: Vec<String>,
    pub(super) value: Decimal,
    pub(super) seen_ms: u64,
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
pub(super) fn unmanaged_text(dex: &str, coins: &[String]) -> String {
    format!(
        "positions on HIP-3 dex {dex} ({}), which the rules' markets do not name: Guard neither judges nor protects them, and the kill switch leaves them",
        coins.join(", ")
    )
}

impl<U: Upstream, C: Clock> Guard<U, C> {
    /// The background sync: check the kill file, read the account, feed
    /// the risk engine, flatten if needed. When the account cannot be read
    /// and Guard is halted or killed, it flattens from the positions alone.
    pub async fn sync(&self) {
        let mut inner = self.inner.lock().await;
        let started = self.clock.now_ms();
        let started_mono = self.clock.monotonic_ms();
        Self::check_kill(&mut inner, started);
        Self::licence_tick(&mut inner, started, true);
        self.expire_hold(&mut inner, started);
        let deadline = inner
            .ledger
            .hold
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
            self.budgets.sync_reads_locked() && !std::mem::take(&mut inner.sync.unlock_next);
        let sending = share_locked
            || inner
                .sends
                .last_ms
                .is_some_and(|sent| started.saturating_sub(sent) < SYNC_LOCKED_AFTER_SEND_MS);
        // With each read, the count of entries that may have changed the
        // account mode its mode is good for (`Caches::mode_epoch` of the
        // caches it read with).
        let (mut inner, read_started, read_started_mono, read, mode_epoch) = if sending {
            let read = self
                .sync_read_locked(&mut inner.caches, started, deadline)
                .await;
            inner.sync.read_twice = false;
            inner.sync.last_reads = 1;
            inner.sync.unlock_next = share_locked && read.is_err();
            let epoch = inner.caches.mode_epoch;
            (inner, started, started_mono, read, epoch)
        } else {
            let mut caches = inner.caches.clone();
            let sent_before = inner.sends.answered;
            drop(inner);
            let read = self.sync_read_unlocked(&mut caches, started).await;
            let clone_epoch = caches.mode_epoch;
            let mut inner = self.inner.lock().await;
            inner.caches.take_newer(caches);
            if inner.sends.answered == sent_before {
                inner.sync.read_twice = false;
                inner.sync.last_reads = 1;
                (inner, started, started_mono, read, clone_epoch)
            } else {
                let now = self.clock.now_ms();
                let now_mono = self.clock.monotonic_ms();
                let deadline = inner
                    .ledger
                    .hold
                    .as_ref()
                    .map(|hold| hold.since.saturating_add(LEDGER_HOLD_MS));
                let read = self
                    .sync_read_locked(&mut inner.caches, now, deadline)
                    .await;
                inner.sync.read_twice = true;
                inner.sync.last_reads = 2;
                let epoch = inner.caches.mode_epoch;
                (inner, now, now_mono, read, epoch)
            }
        };
        // Awaited reads may cross the hold deadline. Expire before any
        // success, failure, protection or flatten handling uses the result.
        let now = self.clock.now_ms();
        self.expire_hold(&mut inner, now);
        // A complete read of every dex Guard manages.
        let read_ok = matches!(&read, Ok(read) if read.unread.is_empty());
        if let Ok(AccountRead { view, unread }) = &read
            && unread.is_empty()
        {
            let this = CompleteRead {
                wall: read_started,
                mono: read_started_mono,
                venue_ms: view.dexes.iter().filter_map(|dex| dex.time).min(),
            };
            // The newest by when it began: two syncs may overlap.
            if inner
                .sync
                .last_complete
                .is_none_or(|last| last.mono <= this.mono)
            {
                inner.sync.last_complete = Some(this);
            }
            // Entries whose outcome was unknown that this read resolves.
            let last = inner.sync.last_complete;
            inner
                .sends
                .unknown_entries
                .retain(|pending| !pending.resolved(now, last.as_ref()));
        }
        match read {
            Ok(AccountRead {
                view: account,
                unread,
            }) if !unread.is_empty() => {
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
                        .append(stamp(now), EventBody::Error { text: text.clone() })
                        .ok();
                }
                inner.last_error = Some(text);
                // Protection waits as after a complete read: until nothing
                // Guard sent can still be on its way.
                let settled = inner
                    .sends
                    .last_ms
                    .is_none_or(|sent| now.saturating_sub(sent) >= SETTLE_MS);
                let overdue = inner
                    .protection
                    .last_ms
                    .is_none_or(|at| now.saturating_sub(at) >= PROTECT_AT_LEAST_EVERY_MS);
                if let Some(reason) = Self::halt_reason(&inner) {
                    self.flatten(&mut inner, now, &account, &reason).await;
                } else if settled || overdue || inner.protection.at_next_sync {
                    // A partial read never ends the protection an unknown
                    // outcome keeps due.
                    self.protect_planned(&mut inner, now, &account, false, None)
                        .await;
                }
            }
            Ok(AccountRead { view: account, .. }) => {
                inner.last_error = None;
                inner.halt.last_read_exposed = Some(exposed(&account));
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
                        self.observe(&mut inner, at, &account, Some(mode_epoch));
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
                    .sends
                    .last_ms
                    .is_none_or(|sent| now.saturating_sub(sent) >= SETTLE_MS);
                let overdue = inner
                    .protection
                    .last_ms
                    .is_none_or(|at| now.saturating_sub(at) >= PROTECT_AT_LEAST_EVERY_MS);
                if Self::halt_reason(&inner).is_some() {
                    // Flattening handles every position; its failures are
                    // alerts of their own.
                    inner.protection.alert = None;
                } else if settled || overdue || inner.protection.at_next_sync {
                    self.protect(&mut inner, now, &account, Some(read_started_mono))
                        .await;
                }
            }
            Err(error) => {
                let text = format!("reading the account: {error}");
                if inner.last_error.as_deref() != Some(text.as_str()) {
                    inner
                        .journal
                        .append(stamp(now), EventBody::Error { text: text.clone() })
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
        let sweep = if inner.ledger.hold.is_none() {
            Self::sweep_start(&mut inner, now)
        } else {
            None
        };
        // The builder fee approval, last and outside the lock, so that
        // protecting, flattening and requests never wait for it; only after
        // a good read of the account (a venue that cannot answer that gets
        // no further request). At start, then every few minutes (every
        // minute while it is missing, or at the next sync for an entry).
        // Not on a kill (its reply should not wait for it).
        let fee_check = (read_ok && inner.kill.reason.is_none() && inner.fee.check_due(now))
            .then(|| inner.fee.check_request(&inner.account.to_hex()))
            .flatten()
            .map(|request| (request, inner.fee.begin_check(now)));
        drop(inner);
        if let Some(start) = sweep {
            self.sweep(start, now).await;
        }
        let Some((request, ticket)) = fee_check else {
            return;
        };
        let answer = match clock::timeout(
            &*self.clock,
            licence::CHECK_TIMEOUT_MS,
            self.upstream.info(&request),
        )
        .await
        {
            Some(Ok(value)) => Ok(value),
            Some(Err(error)) => Err(error.to_string()),
            None => Err(format!("no answer within {} ms", licence::CHECK_TIMEOUT_MS)),
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

    /// Whether a look at a perp dex Guard does not manage is due at `now`
    /// (one every [`SWEEP_EVERY_MS`]); if so, it is marked as begun, and
    /// what its reads need is taken from Guard's state.
    fn sweep_start(inner: &mut Inner, now: u64) -> Option<SweepStart> {
        if inner
            .sweep
            .last_ms
            .is_some_and(|at| now.saturating_sub(at) < SWEEP_EVERY_MS)
        {
            return None;
        }
        inner.sweep.last_ms = Some(now);
        Some(SweepStart {
            caches: inner.caches.clone(),
            managed: inner.config.policy.markets.hip3_dexes(),
            next: inner.sweep.next,
            account: inner.account,
        })
    }

    /// Look at one perp dex Guard does not manage, in turn: positions there
    /// are reported in the status and as an alert, and never judged,
    /// protected or closed, not even by the kill switch (`docs/guard.md`,
    /// "HIP-3 markets"). Its reads (`perpDexs` when not cached, one
    /// `clearinghouseState`) are made without Guard's lock: nothing is
    /// judged, sent or protected on their strength, so a request need not
    /// wait for them. What they found is recorded under the lock after.
    async fn sweep(&self, start: SweepStart, now: u64) {
        let SweepStart {
            mut caches,
            managed,
            next,
            account,
        } = start;
        let Ok(listed) = self.perp_dexs(&mut caches, now).await else {
            return;
        };
        let others: Vec<(u32, String)> = listed
            .into_iter()
            .filter(|(_, name)| !managed.contains(name))
            .collect();
        let picked = (!others.is_empty())
            .then(|| {
                let at = next % others.len();
                others.get(at).cloned().map(|dex| (at, dex))
            })
            .flatten();
        let state = match &picked {
            Some((_, (_, name))) => self
                .upstream
                .info(&requests::clearinghouse_state_of(account, name))
                .await
                .ok(),
            None => None,
        };
        let mut inner = self.inner.lock().await;
        inner.caches.take_newer(caches);
        inner
            .sweep
            .found
            .retain(|name, _| others.iter().any(|(_, other)| other == name));
        let Some((at, (index, name))) = picked else {
            return;
        };
        inner.sweep.next = at + 1;
        let Some(state) = state else {
            return;
        };
        match unmanaged_positions(&state) {
            Some((value, coins)) if !coins.is_empty() => {
                let new = inner
                    .sweep
                    .found
                    .get(&name)
                    .is_none_or(|seen| seen.coins != coins);
                if new {
                    inner
                        .journal
                        .append(
                            stamp(now),
                            EventBody::Error {
                                text: unmanaged_text(&name, &coins),
                            },
                        )
                        .ok();
                }
                inner.sweep.found.insert(
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
                inner.sweep.found.remove(&name);
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
        // A slow read delays the next sync; missed ticks are not run back
        // to back.
        let mut cadence = Cadence::new(self.clock.monotonic_ms(), interval);
        loop {
            let held = self.inner.lock().await.ledger.hold.is_some();
            if held {
                self.clock.sleep(LEDGER_READ_EVERY_MS).await;
            } else {
                let wait = cadence.wait(self.clock.monotonic_ms());
                tokio::select! {
                    () = self.clock.sleep(wait) => cadence.ticked(self.clock.monotonic_ms()),
                    _ = self.hold_started.notified() => continue,
                    // A send whose outcome is unknown: a round now (its
                    // protection runs settled or not), the cadence kept.
                    _ = self.protect_soon.notified() => {}
                }
            }
            self.sync().await;
            // A skipped normal round must not delay a pending hold.
            let mut inner = self.inner.lock().await;
            let skip = std::mem::take(&mut inner.sync.read_twice);
            if skip && inner.ledger.hold.is_none() {
                cadence.reset(
                    self.clock
                        .monotonic_ms()
                        .saturating_add(interval.saturating_mul(2)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cadence;

    #[test]
    fn the_cadence_ticks_every_interval_and_does_not_catch_up() {
        // Interval 5,000 from 1,000: the first tick at once, then 6,000.
        let mut cadence = Cadence::new(1_000, 5_000);
        assert_eq!(cadence.wait(1_000), 0);
        cadence.ticked(1_000);
        assert_eq!(cadence.wait(1_000), 5_000);
        // Taken on time (within 5 ms): the next 5,000 after the deadline.
        cadence.ticked(6_004);
        assert_eq!(cadence.wait(6_004), 4_996);
        // Taken 9 s late (a slow round): the next 5,000 after it, not at
        // once.
        cadence.ticked(20_000);
        assert_eq!(cadence.wait(20_000), 5_000);
        // A round that read twice puts the next two intervals away.
        cadence.reset(20_000 + 10_000);
        assert_eq!(cadence.wait(20_000), 10_000);
    }
}
