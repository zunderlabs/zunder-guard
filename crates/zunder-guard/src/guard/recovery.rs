// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Recovery after a restart: what became of the actions the decision
//! journal's intents named and nothing answered, asked of the venue once
//! they have expired (`docs/guard.md`, "Journals").

use std::{
    collections::VecDeque,
    sync::atomic::{AtomicBool, Ordering},
};

use serde_json::{Value, json};
use zunder_guard_core::{account::requests, event::EventBody, sign::Address};

use crate::{locks::lock, upstream::Upstream};

use super::{
    Guard, Mode,
    clock::{self, Clock, stamp},
    send::{ACTION_TTL_MS, LEVERAGE_TTL_MS},
};

/// The longest recovery after a crash takes in all (waiting for expiry
/// included); what is left then is `unknown`, with an alert.
pub const RECOVERY_MS: u64 = 90_000;
/// How long recovery waits before reading an order the venue did not know
/// once more.
pub const RECOVERY_READ_AGAIN_MS: u64 = 2_000;
/// How long after an intent was written an action it names may still
/// expire, for the intent to cover it: a send later than that (a slow
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

/// An order the venue did not know at the first read: `pending[index]`,
/// read again once Guard's clock reaches `due_ms`.
struct SecondRead {
    index: usize,
    due_ms: u64,
    first: crate::recover::Conclusion,
}

/// Clears a flag when dropped.
struct ClearOnDrop<'a>(&'a AtomicBool);

impl Drop for ClearOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl<U: Upstream, C: Clock> Guard<U, C> {
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
            .append(stamp(now), EventBody::Error { text: text.into() })
            .ok();
    }

    /// Wait until Guard's clock reads `at_ms`.
    async fn wait_until(&self, at_ms: u64) {
        loop {
            let now = self.clock.now_ms();
            if now >= at_ms {
                return;
            }
            self.clock.sleep((at_ms - now).clamp(1, 50)).await;
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
        let mut again: VecDeque<SecondRead> = VecDeque::new();
        let mut next = 0;
        loop {
            let now = self.clock.now_ms();
            if again.front().is_some_and(|read| read.due_ms <= now)
                && now < deadline
                && let Some(read) = again.pop_front()
            {
                concluded[read.index] =
                    Some(self.conclude(account, &pending[read.index], deadline).await);
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
                    again.push_back(SecondRead {
                        index: next,
                        due_ms: due,
                        first: conclusion,
                    });
                } else {
                    concluded[next] = Some(conclusion);
                }
                next += 1;
                continue;
            }
            match again.front().map(|read| read.due_ms) {
                Some(due) if due < deadline && now < deadline => {
                    self.wait_until(due).await;
                }
                _ => break,
            }
        }
        for read in again {
            concluded[read.index] = Some(crate::recover::Conclusion {
                outcome: "unknown",
                evidence: json!({
                    "why": "recovery ran out of time for the second read",
                    "first_read": read.first.evidence,
                }),
            });
        }
        let mut inner = self.inner.lock().await;
        let now = self.clock.now_ms();
        let mut unwritten = 0;
        // One deadline for writing them all: Guard's lock is held while
        // the writer is waited for, and the sync (protection) waits for it.
        let until = self
            .clock
            .monotonic_ms()
            .saturating_add(crate::journal::ACK_DEADLINE_MS);
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
                    stamp(now),
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
            let wait = lock(&self.weights).requests.take_or_wait(now, weight);
            match wait {
                Ok(()) => break,
                Err(ms) => {
                    self.clock.sleep(ms.min(deadline - now).clamp(1, 50)).await;
                }
            }
        }
        let left = deadline.saturating_sub(self.clock.now_ms());
        match clock::timeout(&*self.clock, left, self.upstream.info(body)).await {
            Some(Ok(answer)) => Some(answer),
            Some(Err(error)) => Some(json!({"error": error.to_string()})),
            None => None,
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
}
