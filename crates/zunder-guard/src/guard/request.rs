// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! One `/exchange` request, from admission to the reply: decode and
//! authenticate, read the account, show it to the risk engine, judge,
//! check the budget and the fee, journal the decision, and send it or
//! answer what paper mode would have done. Also `/guard/preview`.

use serde_json::{Value, json};
use zunder_guard_core::{
    Refusal,
    account::{AccountView, AssetKind, asset_kind},
    action::{Action, ExchangeRequest, decode_action_value},
    admit,
    auth::Authenticated,
    event::EventBody,
    judge::{Context, Decision, Forward, Verdict, judge},
    licence,
    reply::{paper_reply, veto_reply},
};

use crate::{journal::JournalError, locks::lock, upstream::Upstream};

use super::{
    Guard, Inner, Intent, MinuteCount, Mode, VetoCount,
    clock::{Clock, stamp},
    limits::{BUDGET_SPENT, FEE_CHECK_WEIGHT, PREVIEWS_PER_SECOND, forward_weight},
    observe::VIEWS_LEFT_OUT_MS,
    read::{ReadFailure, hip3_entry_asset},
    reason::{ReasonCode, Via},
    send::{BOT_CLOID_PREFIX, strip_client_ids, with_client_ids},
};

/// Most refused requests journaled a minute; the rest are counted.
pub const REFUSALS_JOURNALED_PER_MINUTE: u32 = 60;
/// Vetoes journaled a minute at most for each client; beyond, they are
/// counted, and the count journaled the next minute. Per client: one bot
/// looping on refused orders does not leave another's vetoes unjournaled.
pub const VETOES_JOURNALED_PER_MINUTE: u32 = 600;

/// The oldest account view a preview answers from (it never reads the
/// venue itself).
const PREVIEW_VIEW_MAX_AGE_MS: u64 = 60_000;

/// The refusal of every request while recovery after a restart runs.
const RECOVERING: &str = "Guard is asking the venue what became of actions sent before a restart; requests wait until it is done (at most 90 s; protection goes on meanwhile)";

/// The refusal of a request whose decision could not be journaled.
fn not_journaled(error: &JournalError) -> String {
    format!("the decision could not be journaled, so nothing was sent: {error}")
}

/// The code of a preview refused for the previews' own budget
/// ([`PREVIEWS_PER_SECOND`]).
pub const PREVIEW_RATE_LIMITED: &str = "preview_rate_limited";
/// The code of a preview whose body is not `{"action": <an action as in
/// /exchange>}`: the same as `/exchange` refuses such an action with.
pub const PREVIEW_MALFORMED: &str = "malformed";
/// The code of a preview refused because the background sync's last view
/// of the account is missing or older than [`PREVIEW_VIEW_MAX_AGE_MS`].
pub const PREVIEW_VIEW_STALE: &str = "preview_view_stale";

/// A preview refused before it is judged: a stable `code` and the `error`
/// text it always had.
fn preview_refusal(code: &str, text: impl Into<String>) -> Value {
    json!({"code": code, "error": text.into()})
}

/// A preview's answer: `decision` as `/exchange` would act on it.
fn preview_answer(decision: &Decision, mode: &str, view_age_ms: Option<u64>) -> Value {
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
        "mode": mode,
        "view_age_ms": view_age_ms,
    })
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
        code: ReasonCode::ReduceOnlyUnjudged.as_str(),
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

impl<U: Upstream, C: Clock> Guard<U, C> {
    /// What `/exchange` would refuse every request for, whatever it is:
    /// recovery after a restart still running, or a decision journal that
    /// cannot be written. With the same code and text.
    fn refused_before_judging(&self, inner: &Inner) -> Option<Decision> {
        if self.recovering() {
            return Some(ReasonCode::Journal.veto(RECOVERING));
        }
        inner
            .journal
            .broken_error()
            .map(|error| ReasonCode::Journal.veto(not_journaled(&error)))
    }

    /// What Guard would decide about an action (`{"action": {...}}`, no
    /// nonce, no signature), now: read-only. Nothing is journaled, sent or
    /// consumed, and the risk engine is not shown the account (the
    /// background sync does that). While `/exchange` refuses every request
    /// (recovery running, the decision journal broken), so does a preview,
    /// with the same code and text.
    pub async fn preview(&self, body: Value) -> Value {
        let now = self.clock.now_ms();
        let allowed = lock(&self.weights).previews.take(now, PREVIEWS_PER_SECOND);
        if !allowed {
            return preview_refusal(
                PREVIEW_RATE_LIMITED,
                format!("at most {PREVIEWS_PER_SECOND} previews a second"),
            );
        }
        let action = match body.get("action").map(decode_action_value) {
            Some(Ok(action)) => action,
            Some(Err(error)) => return preview_refusal(PREVIEW_MALFORMED, error.to_string()),
            None => {
                return preview_refusal(PREVIEW_MALFORMED, "the body must be {\"action\": {...}}");
            }
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
            if let Some(refusal) = self.refused_before_judging(&inner) {
                return preview_answer(&refusal, inner.mode.name(), None);
            }
            Self::check_kill(&mut inner, now);
            // The view's own age: since it was read, or for a view from the
            // stream, since its oldest snapshot arrived.
            let age = inner
                .last_view
                .as_ref()
                .map(|view| now.saturating_sub(u64::try_from(view.at_ms).unwrap_or(0)));
            let fresh = age.is_some_and(|age| age <= PREVIEW_VIEW_MAX_AGE_MS);
            let Some(account) = inner.last_view.clone().filter(|_| fresh) else {
                return preview_refusal(
                    PREVIEW_VIEW_STALE,
                    "Guard has no recent view of the account yet; try again after the next sync",
                );
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
        // Either may have begun while the book was read.
        if let Some(refusal) = self.refused_before_judging(&inner) {
            return preview_answer(&refusal, inner.mode.name(), view_age_ms);
        }
        let policy = licence::sizing_policy(&inner.config.policy, inner.fee.sizing_builder());
        let decision = judge(
            &Context {
                policy: &policy,
                engine: inner.risk.engine(),
                account: &account,
                killed: inner.kill.reason.is_some(),
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
            decision = ReasonCode::Journal.veto(format!(
                "the risk journal does not allow new positions: {error}"
            ));
        } else if opens && let Some(text) = inner.fee.entry_refusal() {
            decision = ReasonCode::FeeNotApproved.veto(text);
        } else if is_modify(&request)
            && let Some(text) = inner.fee.modify_refusal()
        {
            decision = ReasonCode::FeeNotApproved.veto(text);
        }
        Self::with_fee(&inner.fee, &mut decision);
        preview_answer(&decision, inner.mode.name(), view_age_ms)
    }

    /// Handle one `/exchange` request, come in over `via`. The answer is
    /// always a Hyperliquid-shaped reply.
    pub async fn exchange(&self, body: Value, via: Via) -> Value {
        if self.recovering() {
            return ReasonCode::Journal.reply(RECOVERING);
        }
        let mut inner = self.inner.lock().await;
        let now = self.clock.now_ms();
        Self::check_kill(&mut inner, now);
        // An expired licence falls back to the fee at this order already.
        Self::licence_tick(&mut inner, now, false);
        // A request expecting another mode (`expectedMode`) is refused here,
        // before anything else is done for it. The mode compared is
        // `inner.mode`, which never changes and which the send below reads
        // under this same lock.
        let running = inner.mode.run_mode();
        let (request, client) = match admit(&mut inner.auth, &body, now, running) {
            Ok(admitted) => admitted,
            Err(refusal) => return self.refuse(&mut inner, now, via, &body, &refusal),
        };
        let (account, read) = match self.account_for_request(&mut inner, now, &request).await {
            Ok(read) => (read.view, read.fresh_read),
            Err(error) => {
                let managed = Self::managed_indices(&inner);
                let refused = || match &error {
                    ReadFailure::Budget(text) => ReasonCode::RateLimited.veto(text.clone()),
                    ReadFailure::Venue(error) => ReasonCode::AccountUnreadable.veto(format!(
                        "the account could not be read from the venue: {error}"
                    )),
                };
                let decision = match unjudged_reduce_only(&request, &managed) {
                    Some(exit) => {
                        let weight = exit.forward.as_ref().map_or(1, forward_weight);
                        if self.admit_exit(&inner, now, &request, weight) {
                            exit
                        } else {
                            ReasonCode::RateLimited.veto(self.exits_spent())
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
                killed: inner.kill.reason.is_some(),
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
            decision = ReasonCode::Journal.veto(format!(
                "the risk journal does not allow new positions: {error}"
            ));
        }
        // A loss that would halt the engine, held back until the ledger
        // tells it from a withdrawal: no new positions meanwhile.
        if opens && held {
            decision = ReasonCode::AccountUnreadable.veto(
                "the account's ledger could not be read yet to tell a loss that would halt Guard from a withdrawal; new positions wait (at most 10 s)",
            );
        }
        // Every view left out for a while (each may or may not show a
        // deposit or withdrawal): the engine sees nothing new, so no new
        // positions until it does.
        if opens
            && inner
                .ledger
                .views_left_since
                .is_some_and(|since| now.saturating_sub(since) >= VIEWS_LEFT_OUT_MS)
        {
            decision = ReasonCode::AccountUnreadable.veto(
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
                lock(&self.weights).requests.take(now, weight)
            };
            if !allowed {
                decision = ReasonCode::RateLimited.veto(if exit {
                    self.exits_spent()
                } else {
                    BUDGET_SPENT.to_owned()
                });
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
                && lock(&self.weights).requests.take(now, FEE_CHECK_WEIGHT)
            {
                inner.fee.request_check();
            }
            decision = ReasonCode::FeeNotApproved.veto(text);
        }
        if is_modify(&request)
            && decision.forward.is_some()
            && let Some(text) = inner.fee.modify_refusal()
        {
            // Look again at the next sync: the approval may be back.
            if inner.fee.on_demand_due(now)
                && lock(&self.weights).requests.take(now, FEE_CHECK_WEIGHT)
            {
                inner.fee.request_check();
            }
            decision = ReasonCode::FeeNotApproved.veto(text);
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

    pub(super) fn refuse(
        &self,
        inner: &mut Inner,
        now: u64,
        via: Via,
        body: &Value,
        refusal: &Refusal,
    ) -> Value {
        // Journal a bounded number a minute: a flood of junk must not fill
        // the disk or hold Guard up.
        let minute = now / 60_000;
        if inner.journaled.refusals.minute != minute {
            if inner.journaled.refusals.dropped > 0 {
                inner
                    .journal
                    .append(
                        stamp(now),
                        EventBody::Error {
                            text: format!(
                                "{} more refused requests in the last minute were not journaled",
                                inner.journaled.refusals.dropped
                            ),
                        },
                    )
                    .ok();
            }
            inner.journaled.refusals = MinuteCount {
                minute,
                ..MinuteCount::default()
            };
        }
        if inner.journaled.refusals.journaled < REFUSALS_JOURNALED_PER_MINUTE {
            inner.journaled.refusals.journaled += 1;
            let event = EventBody::Decision {
                via: via.as_str().to_owned(),
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
            inner.journal.append(stamp(now), event).ok();
        } else {
            inner.journaled.refusals.dropped += 1;
        }
        veto_reply(refusal.code(), &refusal.to_string())
    }

    /// Journal a decision, then act on it.
    #[allow(clippy::too_many_arguments)]
    async fn decided(
        &self,
        inner: &mut Inner,
        now: u64,
        via: Via,
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
                let (with_ids, ids) = with_client_ids(
                    action,
                    &mut inner.sends.client_ids,
                    &inner.salt,
                    BOT_CLOID_PREFIX,
                );
                *action = with_ids;
                assigned.extend(ids);
            }
        }
        let forward = decision.forward.as_ref();
        let wires = |actions: &[Action]| actions.iter().map(|a| a.to_wire().to_value()).collect();
        let event = EventBody::Decision {
            via: via.as_str().to_owned(),
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
            if inner.journaled.vetoes.minute != minute {
                if inner.journaled.vetoes.dropped > 0 {
                    let text = format!(
                        "{} more vetoes in the last minute were not journaled",
                        inner.journaled.vetoes.dropped
                    );
                    inner
                        .journal
                        .append(stamp(now), EventBody::Error { text })
                        .ok();
                }
                inner.journaled.vetoes = VetoCount {
                    minute,
                    ..VetoCount::default()
                };
            }
            let journaled = inner
                .journaled
                .vetoes
                .by_client
                .entry(client.client.to_hex())
                .or_default();
            let over = *journaled >= VETOES_JOURNALED_PER_MINUTE;
            if !over {
                *journaled += 1;
            }
            if over {
                inner.journaled.vetoes.dropped += 1;
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
            match inner.journal.append_durable(stamp(now), event) {
                Ok((seq, durable)) => durable.wait().await.map(|()| seq),
                Err(error) => Err(error),
            }
        } else {
            inner.journal.append(stamp(now), event)
        };
        let seq = match journaled {
            Ok(seq) => seq,
            Err(error) => {
                return ReasonCode::Journal.reply(&not_journaled(&error));
            }
        };
        if sends {
            inner.sends.intent = Some(Intent {
                seq,
                at_ms: now,
                actions: named,
            });
        }
        let Some(forward) = decision.forward.clone() else {
            return veto_reply(decision.code, &decision.text);
        };
        if matches!(inner.mode, Mode::Paper) {
            inner
                .journal
                .append(stamp(now), EventBody::Done { intent: seq })
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
            .append(stamp(self.clock.now_ms()), EventBody::Done { intent: seq })
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
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

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
}
