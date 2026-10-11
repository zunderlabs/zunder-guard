// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Showing the risk engine the account ([`PersistentRisk::observe_view`]),
//! with deposits and withdrawals kept out of the account stops: the ledger
//! the stream brings and the ledger read over HTTP, and a loss that would
//! halt the engine held back until a ledger read tells it from a
//! withdrawal (`docs/guard.md`, "Deposits and withdrawals").

use std::collections::BTreeMap;

use rust_decimal::Decimal;
use serde_json::{Value, json};

use zunder_guard_core::{
    account::{AccountView, requests},
    event::EventBody,
    flow_value,
    ledger::{LedgerFlow, LedgerProblem, Treated, classify, ledger_flow},
};
use zunder_venue::{Flow, FlowOutcome};

use crate::{locks::lock, upstream::Upstream};

use super::{
    Guard, Inner,
    clock::{self, Clock, stamp},
};

/// How long after Guard last heard back from the venue its view does not
/// count as settled: the risk engine's record then keeps what the view may
/// not show yet (a fill just reported, say).
pub const SETTLE_MS: u64 = 5_000;

/// The ledger is read over HTTP when an observation would halt the
/// engine, at most this often (weight 20 each; once halted, no observation
/// would halt it again).
pub(super) const LEDGER_READ_EVERY_MS: u64 = 1_000;

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
pub(super) const LEDGER_HOLD_MS: u64 = 10_000;
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
/// positions are refused (`docs/guard.md`, "Deposits and withdrawals").
pub(super) const VIEWS_LEFT_OUT_MS: u64 = 10_000;
/// How long one ledger read may take (it runs under Guard's lock), all its
/// pages together.
const LEDGER_READ_MS: u64 = 3_000;
/// The venue's ledger page (Hyperliquid answers up to 2,000 entries; this
/// repository's adapter assumed 500), and how many pages one read takes
/// at most.
const LEDGER_PAGE_LEN: usize = 500;
const LEDGER_PAGES: usize = 4;
/// How many ledger entries Guard could not account for it remembers, to
/// report each once.
pub(super) const UNACCOUNTED_KEPT: usize = 256;
/// A UTC day in milliseconds.
const DAY_MS: u64 = 86_400_000;

fn fresh_flow_view(times: &BTreeMap<String, i64>, previous: &BTreeMap<String, i64>) -> bool {
    !times.is_empty()
        && previous
            .iter()
            .all(|(dex, time)| times.get(dex).is_some_and(|next| next > time))
}

/// What one read of the account's ledger over HTTP brought, and whether
/// it reached the end (else it stopped at its page limit).
struct LedgerRead {
    entries: Vec<Value>,
    complete: bool,
}

/// Views held back from the risk engine because each would halt or stop
/// it and no ledger read could yet tell its loss from a withdrawal: a run
/// of them, one after the other (`docs/guard.md`, "Deposits and
/// withdrawals").
#[derive(Debug, Clone)]
pub(super) struct LedgerHold {
    /// When the first was held (Guard's clock): a read must begin 2 s after
    /// it to tell, and the run is counted 10 s after it at the latest.
    pub(super) since: u64,
    /// The deepest of them, and when it was held: given to the engine
    /// before the view that ends the run, so that its loss counts.
    deepest: AccountView,
    deepest_at: u64,
    pub(super) latest: BTreeMap<String, i64>,
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

impl<U: Upstream, C: Clock> Guard<U, C> {
    /// Show the risk engine the account (its dexes at the venue's time of
    /// each, `view_times`). Flattening is [`Guard::halt`]'s.
    pub(super) fn observe(&self, inner: &mut Inner, now: u64, account: &AccountView) {
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
                .sends
                .last_ms
                .is_none_or(|sent| read_at.saturating_sub(sent) >= SETTLE_MS);
            let seen = inner.risk.observe_view_at(
                stamp(now),
                view_times(account),
                equity,
                &account.venue_view(),
                settled,
            );
            // A view left out, or one older than a view before it: the
            // engine sees nothing new either way.
            if seen.taken {
                inner.ledger.views_left_since = None;
            } else {
                inner.ledger.views_left_since.get_or_insert(now);
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
                    stamp(now),
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
    pub(super) async fn take_flows(
        &self,
        inner: &mut Inner,
        now: u64,
        account: &AccountView,
    ) -> bool {
        let times = view_times(account);
        self.expire_hold(inner, self.clock.now_ms());
        // Requests may reuse an old stream snapshot: it cannot start or
        // end a run of fresh observations, even after wall time advanced.
        let previous = inner
            .ledger
            .hold
            .as_ref()
            .map(|hold| hold.latest.clone())
            .or_else(|| inner.last_view.as_ref().map(view_times));
        if previous
            .as_ref()
            .is_some_and(|previous| !fresh_flow_view(&times, previous))
        {
            return inner.ledger.hold.is_none();
        }
        let (mut entries, streaming, reconnects) = lock(&self.stream)
            .as_ref()
            .map(|stream| {
                let mut state = lock(&stream.state);
                (state.take_ledger(), state.is_connected(), state.reconnects)
            })
            .unwrap_or_default();
        let would_halt = account
            .equity
            .is_some_and(|equity| inner.risk.would_halt(stamp(now), &times, equity));
        // The view's own time: a ledger read must have begun after it, and
        // 2 s after the first view of the run of held views it belongs to,
        // for the view's loss to be known not to be a withdrawal.
        let view_ms = u64::try_from(account.at_ms).unwrap_or(0);
        let run = inner.ledger.hold.as_ref().map(|hold| hold.since);
        let checked = would_halt && ledger_checks(inner.ledger.ok_ms, view_ms, run);
        let since = inner.ledger.read_ms.map(|read| now.saturating_sub(read));
        let due = match since {
            None => true,
            Some(since) => {
                let failed = inner.ledger.ok_ms != inner.ledger.read_ms;
                let every = if failed {
                    LEDGER_RETRY_MS
                } else {
                    LEDGER_READ_EVERY_MS
                };
                (would_halt && !checked && since >= every)
                    || (!streaming && since >= LEDGER_READ_WITHOUT_STREAM_MS)
                    || since >= LEDGER_READ_PERIODIC_MS
                    || (inner.ledger.reconnects != reconnects
                        && since >= LEDGER_READ_WITHOUT_STREAM_MS)
            }
        };
        if due {
            inner.ledger.read_ms = Some(now);
            let read = self.read_ledger(inner, now).await;
            self.expire_hold(inner, self.clock.now_ms());
            if let Some(read) = read {
                if read.complete {
                    inner.ledger.ok_ms = Some(now);
                }
                inner.ledger.reconnects = reconnects;
                entries.extend(read.entries);
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
            && account
                .equity
                .is_some_and(|equity| inner.risk.would_halt(stamp(now), &times, equity));
        let checked = ledger_checks(inner.ledger.ok_ms, view_ms, run);
        if still_halts && !checked {
            let hold = inner.ledger.hold.get_or_insert_with(|| LedgerHold {
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
        if let Some(hold) = inner.ledger.hold.take()
            && hold.deepest_at < now
        {
            self.observe(inner, hold.deepest_at, &hold.deepest);
        }
        true
    }

    pub(super) fn expire_hold(&self, inner: &mut Inner, now: u64) {
        if inner
            .ledger
            .hold
            .as_ref()
            .is_some_and(|hold| now.saturating_sub(hold.since) >= LEDGER_HOLD_MS)
            && let Some(hold) = inner.ledger.hold.take()
        {
            self.observe(inner, hold.deepest_at, &hold.deepest);
        }
    }

    /// The deadline of a read made while a loss is held for the ledger:
    /// `maximum_ms` from now, or the hold's end if that comes first. On
    /// Guard's monotonic clock ([`Clock::monotonic_ms`]): armed now, it is
    /// not moved by the time of day stepping.
    pub(super) fn flow_read_deadline(&self, inner: &Inner, maximum_ms: u64) -> u64 {
        let remaining = inner.ledger.hold.as_ref().map_or(maximum_ms, |hold| {
            hold.since
                .saturating_add(LEDGER_HOLD_MS)
                .saturating_sub(self.clock.now_ms())
                .min(maximum_ms)
        });
        self.clock.monotonic_ms().saturating_add(remaining)
    }

    /// The account's ledger over HTTP from where Guard last read it (at
    /// start, from the risk journal's last record or newest flow on), up
    /// to a few pages within [`LEDGER_READ_MS`] (it runs under Guard's
    /// lock), and whether that was all of it; its weight charged to the
    /// request budget as protection's own. `None` when the venue does not
    /// answer in time.
    async fn read_ledger(&self, inner: &mut Inner, now: u64) -> Option<LedgerRead> {
        let mut from = inner
            .ledger
            .from_ms
            .unwrap_or_else(|| inner.risk.flows_from_ms());
        let mut out = Vec::new();
        let deadline = self.flow_read_deadline(inner, LEDGER_READ_MS);
        let mut complete = false;
        for _ in 0..LEDGER_PAGES {
            let read = clock::timeout(
                &*self.clock,
                clock::left(&*self.clock, deadline),
                self.upstream
                    .info(&requests::ledger_updates(inner.account, from)),
            )
            .await;
            let Some(Ok(Value::Array(page))) = read else {
                return None;
            };
            lock(&self.weights)
                .requests
                .charge(now, 20 + page.len() as u64 / 20);
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
        inner.ledger.from_ms = Some(ledger_cursor(inner.ledger.from_ms, from, complete));
        Some(LedgerRead {
            entries: out,
            complete,
        })
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
        // Every entry is checked as a reconstruction checks it; one Guard
        // cannot account for is reported, never skipped as no flow.
        let mut flows = Vec::new();
        for update in entries {
            match classify(update, inner.account, &dexes) {
                Ok(Some(flow)) => flows.push(flow),
                Ok(None) => {}
                Err(problem) => {
                    if let Some(flow) = Self::unaccounted(inner, now, &problem) {
                        flows.push(flow);
                    }
                }
            }
        }
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
                stamp(now),
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
                inner.ledger.flow_note = Some(format!(
                    "a flow of {} USDC could not be recorded: {error}",
                    flow.amount
                ));
            }
        }
        Self::note_flows(inner, now);
    }

    /// A ledger entry Guard cannot account for (`ledger::classify`): it may
    /// have moved money into or out of the account, by an amount Guard does
    /// not know. Fail closed, as for a flow whose value is unknown
    /// (`docs/guard.md`, "Deposits and withdrawals", "When it is unknown"):
    /// journaled and an alert, once per entry, and new positions refused
    /// until the end of the UTC day it was seen; exits and protection go on.
    /// An entry older than everything the risk journal replays from
    /// ([`PersistentRisk::flows_from_ms`]) is in the equity it started from
    /// already: journaled only.
    fn unaccounted(inner: &mut Inner, now: u64, problem: &LedgerProblem) -> Option<LedgerFlow> {
        let old = problem
            .time_ms
            .is_some_and(|time| time < inner.risk.flows_from_ms());
        // Applied as money in (the flow applies once: by its id).
        let inflow = match &problem.treated {
            Treated::Inflow(flow) if !old => Some(flow.as_ref().clone()),
            _ => None,
        };
        if inner.ledger.unaccounted_seen.contains(&problem.id) {
            return inflow;
        }
        inner.ledger.unaccounted_seen.push_back(problem.id.clone());
        while inner.ledger.unaccounted_seen.len() > UNACCOUNTED_KEPT {
            inner.ledger.unaccounted_seen.pop_front();
        }
        let text = if old {
            format!(
                "the account's ledger has an entry Guard cannot account for ({problem}), from before the risk journal's horizon: it is in the equity Guard started from"
            )
        } else if let Treated::Inflow(flow) = &problem.treated {
            let text = format!(
                "the account's ledger has an entry Guard cannot account for ({problem}): applied as money in ({} USDC), never as a trading gain; its effect on the account cannot be reconstructed, so under the flow rules the day halts",
                flow.amount
            );
            Self::add_alert(inner, now, &text, None);
            text
        } else {
            let until = now
                .saturating_div(DAY_MS)
                .saturating_add(1)
                .saturating_mul(DAY_MS);
            let until = inner
                .ledger
                .unaccounted
                .as_ref()
                .map_or(until, |(_, before)| until.max(*before));
            let what = match &problem.treated {
                // A type Guard does not know: that the account paid it rests
                // on field names Guard cannot vouch for.
                Treated::LeftAsLoss(amount) => format!(
                    "it reads as paid by the account ({amount} USDC) and stays in the equity as a loss, but its type is unknown"
                ),
                _ => "how much it moved cannot be read".to_owned(),
            };
            let text = format!(
                "the account's ledger has an entry Guard cannot account for ({problem}): {what}, so new positions are refused until the end of the UTC day; exits and protection go on, and the stops count the equity as it shows. Compare the account's history with the equity"
            );
            inner.ledger.unaccounted = Some((text.clone(), until));
            Self::add_alert(inner, now, &text, None);
            text
        };
        inner
            .journal
            .append(stamp(now), EventBody::Error { text })
            .ok();
        inflow
    }

    /// Why new positions are refused for a ledger entry Guard cannot
    /// account for, while they are (until the end of the UTC day it was
    /// seen).
    pub(super) fn unaccounted_refusal(inner: &Inner, now: u64) -> Option<String> {
        inner
            .ledger
            .unaccounted
            .as_ref()
            .filter(|(_, until)| now < *until)
            .map(|(text, _)| text.clone())
    }

    /// Optional reconstruction shares passthrough's existing admission
    /// budget. Refuse before sending; failures/timeouts still spend weight.
    async fn flow_info(
        &self,
        _now: u64,
        body: Value,
        cost: u64,
        deadline: u64,
        weight: &mut u64,
    ) -> Option<Value> {
        if weight.saturating_add(cost) > 240 {
            return None;
        }
        *weight += cost;
        if !lock(&self.weights).info.take(self.clock.now_ms(), cost) {
            return None;
        }
        clock::timeout(
            &*self.clock,
            clock::left(&*self.clock, deadline),
            self.upstream.info(&body),
        )
        .await?
        .ok()
    }

    async fn reconstruct_flow(
        &self,
        inner: &Inner,
        now: u64,
        flow: &zunder_guard_core::ledger::LedgerFlow,
        dexes: &std::collections::BTreeSet<String>,
        deadline: u64,
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
        if !flow_value::valid_ledger(ledger, inner.account, dexes) {
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
                    inner.ledger.flows_applied += 1;
                    inner.ledger.flow_note = None;
                    inner
                        .journal
                        .append(
                            stamp(now),
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
                    inner.ledger.flow_note = Some(format!(
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
                    "account value at a flow is uncertain: measured ranges disagree, worst drawdown {}, retained {}; Guard halted the day (docs/guard.md#deposits-and-withdrawals)",
                    percent(waived.waived),
                    percent(waived.kept)
                )
            } else {
                "account value at a flow is uncertain: complete exact reconstruction unavailable (positions open at transfer or incomplete records); Guard halted the day (docs/guard.md#deposits-and-withdrawals)".to_owned()
            };
            inner
                .journal
                .append(stamp(now), EventBody::Error { text: text.clone() })
                .ok();
            Self::add_alert(inner, now, &text, None);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

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
