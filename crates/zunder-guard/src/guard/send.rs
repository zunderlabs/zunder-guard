// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Sending what a decision forwards: each action signed with the API
//! wallet key and a fresh Guard nonce, named by an intent on disk before it
//! goes out; isolated leverage first and read back; a filled entry whose
//! stop was refused closed, a resting one cancelled; Guard's own stop
//! cancelled once the bot's tighter stop rests.

use std::{collections::VecDeque, sync::atomic::Ordering};

use serde_json::{Value, json};
use thiserror::Error;
use zunder_core::Symbol;
use zunder_guard_core::{
    account::{AccountView, AssetKind, asset_kind, confirms_isolated, requests},
    action::Action,
    event::EventBody,
    judge::Forward,
    licence,
    reply::{OrderStatus, action_ok, client_reply, order_statuses, signed_request},
};

use crate::{
    journal::JournalError,
    locks::lock,
    stream::Expectation,
    upstream::{Upstream, UpstreamError},
};

use super::{
    AttachedStops, Guard, Inner, Intent, Mode,
    clock::{Clock, stamp},
    protect::RestingEntry,
    reason::ReasonCode,
    recovery::INTENT_COVERS_MS,
};

/// Why an action was not sent, or no answer came back. The texts are what
/// a bot reads in a refusal (`venue_unreachable`, `fee_not_approved`) and a
/// person in an alert.
#[derive(Debug, Error)]
pub(super) enum SendError {
    /// A new position, or a modify, while the builder fee's approval is
    /// not confirmed.
    #[error("fee_not_approved: {0}")]
    FeeNotApproved(String),
    #[error("paper mode sends nothing")]
    Paper,
    #[error("the action could not be journaled before sending, so it was not sent: {0}")]
    NotJournaled(JournalError),
    #[error("the action could not be signed")]
    NotSigned,
    /// It may have reached the venue.
    #[error(
        "no answer from the venue ({0}); the request may have reached it: check open orders before sending again"
    )]
    NoAnswer(String),
    #[error(transparent)]
    Venue(UpstreamError),
}

impl SendError {
    /// Refused by the venue's HTTP status (a 4xx, such as 429): not placed.
    pub(super) fn refused_by_status(&self) -> bool {
        matches!(self, SendError::Venue(UpstreamError::Status { status, .. }) if (400..500).contains(status))
    }
}

/// How long an action Guard signs stays valid on the venue.
pub const ACTION_TTL_MS: u64 = 30_000;
/// How long `updateLeverage` stays valid: the session's 10 s.
pub const LEVERAGE_TTL_MS: u64 = 10_000;

/// How many resting entries' attached stops Guard remembers, to know a
/// cancel of the entry cancels them too.
pub(super) const ATTACHED_KEPT: usize = 256;

/// What the venue's socket should report of a send that `reply` answered,
/// sent at `sent` ([`Clock::monotonic_ms`]): the orders an order action rested or
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
    attached: &VecDeque<AttachedStops>,
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
                if let Some(stops) = attached.iter().find(|stops| stops.entry == oid) {
                    expectation
                        .cancelled_cloids
                        .extend(stops.cloids.iter().cloned());
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
fn attached_stops(action: &Action, reply: &Value) -> Option<AttachedStops> {
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
    (!cloids.is_empty()).then_some(AttachedStops { entry: oid, cloids })
}

/// The prefix of the client ids Guard gives a bot's orders that have none,
/// and of those it gives its own closes (`0x7a67` stays its stops').
pub const BOT_CLOID_PREFIX: &str = "7a68";
pub const CLOSE_CLOID_PREFIX: &str = "7a69";

/// `action` with a client id on every order (or modify's new order) that
/// has none: `0x` + `prefix` + 28 hex digits of Keccak-256 over Guard's
/// salt, the prefix and a counter. Returns the ids given.
pub(super) fn with_client_ids(
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
pub(super) fn strip_client_ids(reply: &mut Value, given: &[String]) {
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

/// Whether an action can only reduce risk: reduce-only orders, cancels.
/// Such an action goes even while the journal is broken, recorded in the
/// emergency log (`docs/guard.md#journals`).
fn reduces_risk(action: &Action) -> bool {
    matches!(action, Action::Cancel(_) | Action::CancelByCloid(_)) || licence::exits_only(action)
}

impl<U: Upstream, C: Clock> Guard<U, C> {
    fn next_nonce(inner: &mut Inner, now: u64) -> u64 {
        inner.sends.last_nonce = now.max(inner.sends.last_nonce.saturating_add(1));
        inner.sends.last_nonce
    }

    /// Sign and send one action with the builder field Guard sends now
    /// (on every order action; none while the fee is not approved), and
    /// journal what came back. When the venue refuses the builder field on
    /// an exit (the approval was withdrawn), Guard notes it and sends the
    /// exit again without the field: an exit never waits for the fee.
    pub(super) async fn send_one(
        &self,
        inner: &mut Inner,
        now: u64,
        decision: u64,
        action: &Action,
        expires_after: u64,
    ) -> Result<Value, SendError> {
        Self::licence_tick(inner, self.clock.now_ms(), false);
        if !reduces_risk(action)
            && let Some(why) = inner.fee.entry_refusal()
        {
            return Err(SendError::FeeNotApproved(why));
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
                .append(stamp(now), EventBody::Error { text })
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
    ) -> Result<Value, SendError> {
        let Mode::Send { .. } = &inner.mode else {
            return Err(SendError::Paper);
        };
        // An intent on disk names this action as it goes out, written
        // no more than [`INTENT_COVERS_MS`] before it expires (recovery
        // waits that long after an intent); if none does, one is written
        // and waited for first.
        let wire = action.to_wire().to_value();
        let mut emergency = false;
        let named = inner.sends.intent.as_ref().and_then(|intent| {
            (intent.seq == decision
                && expires_after <= intent.at_ms.saturating_add(INTENT_COVERS_MS))
            .then(|| intent.actions.iter().position(|named| *named == wire))
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
                    stamp(at),
                    EventBody::Intent {
                        of: decision,
                        action: wire.clone(),
                    },
                )
                .await;
            match written {
                Ok(seq) => {
                    inner.sends.intent = Some(Intent {
                        seq,
                        at_ms: at,
                        actions: vec![wire.clone()],
                    });
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
                            stamp(at),
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
                Err(error) => return Err(SendError::NotJournaled(error)),
            }
        };
        // Durability may have waited across expiry. Recheck immediately
        // before signing; a changed protective action gets its own intent.
        Self::licence_tick(inner, self.clock.now_ms(), false);
        if !reduces_risk(action)
            && let Some(why) = inner.fee.entry_refusal()
        {
            return Err(SendError::FeeNotApproved(why));
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
            return Err(SendError::Paper);
        };
        let Some(body) = signed_request(key, *network, action, nonce, Some(expires_after)) else {
            return Err(SendError::NotSigned);
        };
        let result = self.upstream.exchange(body).await;
        // The settle window counts from the answer, not the request.
        let answered = self.clock.now_ms();
        let mono = self.clock.monotonic_ms().max(1);
        // What the socket should report of it: the stream is clean again
        // once it has (`stream::Expectation`). Every send is recorded with
        // the stream before it is noted as the last send below.
        let expected = result.as_ref().ok().and_then(|reply| {
            expectation(
                inner.caches.listed_dexes(),
                inner.last_view.as_ref(),
                &inner.sends.attached,
                action,
                reply,
                mono,
            )
        });
        if let Ok(reply) = &result
            && let Some(stops) = attached_stops(action, reply)
        {
            inner.sends.attached.push_back(stops);
            while inner.sends.attached.len() > ATTACHED_KEPT {
                inner.sends.attached.pop_front();
            }
        }
        if let Some(stream) = lock(&self.stream).as_ref() {
            lock(&stream.state).sent(mono, expected);
        }
        inner.sends.last_ms = Some(answered);
        inner.sends.last_mono = Some(mono);
        self.last_send_mono.store(mono, Ordering::SeqCst);
        inner.sends.answered = inner.sends.answered.wrapping_add(1);
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
            inner.emergency.record_later(stamp(answered), sent.clone());
        }
        inner.journal.append(stamp(answered), sent).ok();
        result.map_err(|error| match error {
            UpstreamError::NoAnswer(text) => SendError::NoAnswer(text),
            other => SendError::Venue(other),
        })
    }

    pub(super) async fn send(
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
                Err(error) => Some(error.to_string()),
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
                return ReasonCode::VenueRefusedLeverage.reply(&format!(
                    "isolated leverage was not confirmed, so the order was not sent: {why}"
                ));
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
            Err(error @ SendError::FeeNotApproved(_)) => {
                return ReasonCode::FeeNotApproved.reply(&error.to_string());
            }
            Err(error) => return ReasonCode::VenueUnreachable.reply(&error.to_string()),
        };

        // A modify the venue refused may have cancelled the order it was to
        // replace (it cancels first), possibly because the approval was
        // withdrawn since Guard's last read: protect at the next sync,
        // settled or not, and read the approval then.
        if matches!(forward.action, Action::Modify(_) | Action::BatchModify(_))
            && let Err(error) = action_ok(&reply)
        {
            inner.protection.at_next_sync = true;
            if inner.fee.mode().builder().is_some() {
                inner.fee.request_check();
            }
            if let Some(venue_text) = licence::builder_refusal_text(&reply)
                && let Some(text) = inner.fee.record_venue_refusal(now, &venue_text)
            {
                Self::add_alert(inner, now, &text, None);
                inner
                    .journal
                    .append(stamp(now), EventBody::Error { text })
                    .ok();
            }
            inner
                .journal
                .append(
                    stamp(now),
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
            return ReasonCode::FeeNotApproved.reply(&format!("{text} (the venue: {reply})"));
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
                        stamp(now),
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
                                stamp(now),
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
                        .append(stamp(now), EventBody::Error { text })
                        .ok();
                }
                Some(OrderStatus::Resting { oid }) if protected => {
                    // Remembered until it fills (or is gone): its stop is
                    // the one the entry was sized for.
                    let held_before = account
                        .and_then(|account| account.position(&entry.coin))
                        .filter(|position| position.side == entry.side)
                        .map_or(rust_decimal::Decimal::ZERO, |position| position.qty);
                    inner.protection.resting_entries.push_back(RestingEntry {
                        oid: *oid,
                        coin: entry.coin.clone(),
                        side: entry.side,
                        qty: entry.qty,
                        stop: entry.stop,
                        held_before,
                        filled: false,
                        gone_reads: 0,
                    });
                    while inner.protection.resting_entries.len() > ATTACHED_KEPT {
                        inner.protection.resting_entries.pop_front();
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
                        .map_err(|error| error.to_string())
                        .and_then(|reply| action_ok(&reply));
                    // A resting order may have filled in part: protect what
                    // filled at the next sync, settled or not.
                    inner.protection.at_next_sync = true;
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
                        .append(stamp(now), EventBody::Error { text })
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
                    .map_err(|error| error.to_string())
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
                        .append(stamp(now), EventBody::Error { text })
                        .ok();
                }
            }
        }
        client_reply(reply, &forward.status_map)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::guard::test_support::view_for_expectations;

    #[cfg(feature = "test-hooks")]
    mod durable_expiry {
        use std::{
            sync::{Arc, atomic::AtomicU64},
            time::Duration,
        };

        use zunder_core::Timestamp;
        use zunder_guard_core::{
            licence::FeeMode,
            sign::{Address, GuardKey, SigningNetwork},
        };

        use super::*;
        use crate::{
            config::GuardConfig,
            guard::{Limits, Setup},
            journal::DecisionJournal,
        };

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
                let network = inner.licence.network;
                inner.licence.issuers =
                    licence::LicenceIssuers::for_test(network, Some(test_key::public()), None);
                inner.licence.builders = crate::guard::fee::FallbackBuilders {
                    mainnet: None,
                    testnet: Some("0x00000000000000000000000000000000000000bb".into()),
                };
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
                    assert!(
                        matches!(result, Err(SendError::FeeNotApproved(_))),
                        "{result:?}"
                    );
                    assert!(sent.is_empty());
                }
            }
        }
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
        let expect = |action: &Action, reply: &Value, attached: &VecDeque<AttachedStops>| {
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
        let attached: VecDeque<AttachedStops> = [AttachedStops {
            entry: 30,
            cloids: vec!["0x7a67bb".to_owned()],
        }]
        .into();
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
            Some(AttachedStops {
                entry: 40,
                cloids: vec!["0x7a67000000000000000000000000000b".to_owned()],
            })
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
}
