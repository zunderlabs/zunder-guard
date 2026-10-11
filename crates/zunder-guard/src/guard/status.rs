// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! What Guard shows: the local status, alerts, the events in memory and
//! the decisions in the journal.

use serde_json::{Value, json};
use zunder_guard_core::{event::EVENT_SCHEMA, licence, sign::Address};
use zunder_risk::RiskState;

use crate::{locks::lock, rules, upstream::Upstream};

use super::{Guard, Inner, clock::Clock, sync::unmanaged_text};

/// How long an alert about a fill Guard had to close stays in the status.
pub(super) const ALERT_KEEP_MS: u64 = 3_600_000;

/// Something Guard could not fix, for the status.
#[derive(Debug, Clone)]
pub(super) struct Alert {
    pub(super) text: String,
    pub(super) at_ms: u64,
    /// Kept while this order rests.
    pub(super) oid: Option<u64>,
}

impl<U: Upstream, C: Clock> Guard<U, C> {
    /// Add (or refresh) an alert; true when it is new.
    pub(super) fn add_alert(inner: &mut Inner, now: u64, text: &str, oid: Option<u64>) -> bool {
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

    /// The local status, for the browser monitor (read-only).
    pub async fn status(&self) -> Value {
        let inner = self.inner.lock().await;
        let mut alerts: Vec<String> = inner
            .protection
            .alert
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
                .sweep
                .found
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
        if inner.kill.reason.is_some() && !inner.config.kill_file().exists() {
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
            // What this Guard understands beyond schema 1's first fields,
            // so a client can tell before relying on it: `/exchange` and
            // `/guard/kill` refuse a request whose `expectedMode` is not
            // `mode`.
            "capabilities": {"exchange_expected_mode": true, "kill_expected_mode": true},
            "network": inner.config.network.map(|network| network.name()),
            "account": inner.account.to_hex(),
            "started_at_ms": self.started_ms,
            "killed": inner.kill.reason,
            // The automation interface's summary (`docs/guard.md`, "Automation"): the kill switch is
            // pulled; the risk engine halts entries (for the day, or until
            // a person's review); neither journal is broken (whether the
            // risk journal allows new positions yet is
            // `risk.journal_ready`).
            "kill_switch": inner.kill.reason.is_some(),
            "halted": !matches!(engine.state(), RiskState::Active),
            "journal": {
                "ok": !inner.journal.is_broken()
                    && !matches!(inner.risk.check_ready(), Err(zunder_venue::JournalError::Broken(_))),
            },
            "risk": {
                "state": match engine.state() {
                    RiskState::Active => "active",
                    RiskState::HaltedForDay { .. } => "halted_for_day",
                    RiskState::Stopped { .. } => "stopped",
                },
                "detail": engine.state(),
                "peak": engine.peak(),
                "tracked": engine.positions().len(),
                "flows_applied": inner.ledger.flows_applied,
                "flow_note": inner.ledger.flow_note,
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
            "unmanaged_dexes": inner.sweep.found.iter().map(|(dex, seen)| json!({
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
            "last_sync_reads": inner.sync.last_reads,
            "next_sync_delayed": inner.sync.read_twice,
            "last_error": inner.last_error,
            "alert": alerts.first(),
            "alerts": alerts,
            "kill_file": inner.config.kill_file(),
            "rules": rules::encode(&inner.config.policy),
            "fee": inner.fee.status(),
            "licence": inner.licence.status(inner.account, self.clock.now_ms(), inner.config.licence_auto_update),
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
        let stream = lock(&self.stream);
        let state = lock(&stream.as_ref()?.state);
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
        let (stream_count, read_count, last_fallback, info_count) = {
            let judged = lock(&self.judged);
            (
                judged.stream,
                judged.read,
                judged.last_fallback.clone(),
                judged.info_from_stream,
            )
        };
        let state = lock(&self.stream).as_ref().map(|stream| {
            let state = lock(&stream.state);
            json!({
                "connected": state.is_connected(),
                "messages": state.messages,
                "reconnects": state.reconnects,
                "coins": state.coins(),
                "breaks": state.breaks,
                "last_break": state.last_break,
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

    /// Events after `since`, from memory.
    pub async fn events(&self, since: u64) -> Value {
        Value::Array(self.inner.lock().await.journal.since(since))
    }
}
