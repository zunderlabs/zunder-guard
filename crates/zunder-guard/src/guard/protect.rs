// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Guard's own stops: every position no market stop covers in full gets
//! one, and a position whose stop the venue refuses is closed at once.

use serde_json::Value;
use zunder_guard_core::{
    account::{AccountView, AssetKind, asset_kind, requests},
    action::Action,
    event::EventBody,
    judge::protect_actions_with,
    reply::{OrderStatus, close_action, order_statuses},
};

use crate::upstream::Upstream;

use super::{
    Guard, Inner, Intent, Mode,
    clock::{Clock, stamp},
    send::{ACTION_TTL_MS, CLOSE_CLOID_PREFIX, with_client_ids},
};

/// An entry Guard forwarded that rests with its stop, followed until it
/// fills and while its position is open ([`Guard::follow_resting`]).
#[derive(Debug, Clone)]
pub(super) struct RestingEntry {
    pub(super) oid: u64,
    pub(super) coin: String,
    pub(super) side: zunder_core::Side,
    /// Its size as forwarded.
    pub(super) qty: rust_decimal::Decimal,
    /// The stop it was sized for.
    pub(super) stop: rust_decimal::Decimal,
    /// The position on its side when it was sent.
    pub(super) held_before: rust_decimal::Decimal,
    /// Its fill explains the position now (grown beyond `held_before` by
    /// at most `qty`).
    pub(super) filled: bool,
    /// Complete reads in a row that found it gone without growth.
    pub(super) gone_reads: u8,
}

/// How long Guard waits for a settled view before protecting anyway: a bot
/// that sends every few seconds must not keep an unprotected position
/// unprotected.
pub(crate) const PROTECT_AT_LEAST_EVERY_MS: u64 = 30_000;

impl<U: Upstream, C: Clock> Guard<U, C> {
    /// Close `qty` of a position at once with a reduce-only IOC order, and
    /// say whether the venue reports it filled.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn close_unprotected(
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
            &mut inner.sends.client_ids,
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

    /// Give every position no market stop covers in full Guard's own stop,
    /// and close a position whose stop the venue refuses. Runs from the
    /// background sync: once nothing Guard sent can still be on its way (a
    /// stop placed with a fill may not show yet), and at least every 30 s
    /// all the same. In paper mode it journals what it would do, once.
    pub(super) async fn protect(
        &self,
        inner: &mut Inner,
        now: u64,
        account: &AccountView,
        read_started: Option<u64>,
    ) {
        self.protect_planned(inner, now, account, true, read_started)
            .await;
    }

    /// [`Guard::protect`]; `use_planned` false (a partial read) leaves the
    /// resting entries' stops out, as they were judged on an older view.
    /// `read_started`: when the complete read `account` comes from began, on
    /// Guard's monotonic clock (`None` for a partial read); only a complete
    /// read begun at or after `Protection::until` ends the protection an
    /// unknown outcome keeps due.
    pub(super) async fn protect_planned(
        &self,
        inner: &mut Inner,
        now: u64,
        account: &AccountView,
        use_planned: bool,
        read_started: Option<u64>,
    ) {
        inner.protection.last_ms = Some(now);
        match (inner.protection.until, read_started) {
            (_, None) if inner.protection.at_next_sync => {}
            (Some(until), Some(started)) if started < until => {}
            _ => {
                inner.protection.until = None;
                inner.protection.at_next_sync = false;
            }
        }
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
                    .append(stamp(now), EventBody::Error { text: note.clone() })
                    .ok();
            }
        }
        if actions.is_empty() && unpriced.is_empty() {
            inner.protection.alert = None;
            return;
        }
        let mut problems = notes;
        let mut coins: Vec<String> = actions.iter().map(|(coin, _)| coin.clone()).collect();
        coins.extend(unpriced.iter().cloned());
        let sends = matches!(inner.mode, Mode::Send { .. });
        let fee = inner.fee.clone();
        let summary = format!("positions without a stop: {}", coins.join(", "));
        if !sends && inner.protection.alert.as_deref() == Some(summary.as_str()) {
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
        // for); if the journal is broken, they go all the same (protection
        // is never held up), each with its intent in the emergency log.
        let seq = if sends {
            match inner
                .journal
                .append_durable_waiting(stamp(now), event)
                .await
            {
                Ok(seq) => {
                    inner.sends.intent = Some(Intent {
                        seq,
                        at_ms: now,
                        actions: named,
                    });
                    seq
                }
                Err(_) => 0,
            }
        } else {
            inner.journal.append(stamp(now), event).unwrap_or(0)
        };
        if !sends {
            inner.protection.alert = Some(summary);
            return;
        }
        // Each coin to close, with why it has no stop.
        let mut to_close: Vec<(String, &str)> = unpriced
            .into_iter()
            .map(|coin| (coin, "no stop could be priced"))
            .collect();
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
                Err(error) if error.refused_by_status() => false,
                // No answer, or one Guard cannot read: the stop may rest
                // all the same. Look for it before closing.
                _ => self.rests(inner, action).await,
            };
            if !placed {
                to_close.push((coin.clone(), "Guard's stop was refused"));
            }
        }
        for (coin, why) in to_close {
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
            problems.push(format!("{coin}: {why}; {text}"));
        }
        if seq > 0 {
            inner
                .journal
                .append(stamp(self.clock.now_ms()), EventBody::Done { intent: seq })
                .ok();
        }
        if problems.is_empty() {
            inner.protection.alert = None;
        } else {
            let text = problems.join("; ");
            inner
                .journal
                .append(stamp(now), EventBody::Error { text: text.clone() })
                .ok();
            inner.protection.alert = Some(text);
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
    pub(super) fn follow_resting(inner: &mut Inner, account: &AccountView) {
        let held = |entry: &RestingEntry| {
            account
                .position(&entry.coin)
                .filter(|position| position.side == entry.side)
                .map_or(rust_decimal::Decimal::ZERO, |position| position.qty)
        };
        inner.protection.resting_entries.retain_mut(|entry| {
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
            .protection
            .resting_entries
            .iter()
            .filter(|entry| entry.filled)
            .map(|entry| (entry.coin.clone(), entry.side, entry.stop))
            .collect()
    }

    /// Whether the order of `action` (one order with a client id) rests on
    /// the venue now.
    pub(super) async fn rests(&self, inner: &Inner, action: &Action) -> bool {
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
                let Some(name) = inner.caches.listed_dexes().and_then(|list| {
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
}
