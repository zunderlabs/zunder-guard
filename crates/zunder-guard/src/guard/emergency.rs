// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The kill switch, halts and flattening: the kill file latched at start
//! and before every request, `/guard/kill`, flattening when the risk engine
//! halted or the switch is pulled, and the emergency log that records
//! protective sends while the decision journal cannot be written.

use std::sync::{
    Arc, Mutex as StdMutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use serde_json::{Value, json};
use thiserror::Error;
use zunder_core::Timestamp;
use zunder_guard_core::{
    account::AccountView,
    action::Action,
    event::EventBody,
    reply::{OrderStatus, action_ok, flatten_actions, order_statuses},
};
use zunder_risk::RiskState;

use crate::{locks::lock, upstream::Upstream};

use super::{
    Guard, Inner, Intent, Mode,
    clock::{self, Clock, stamp},
    limits::ACCOUNT_READ_WEIGHT,
    read::AccountRead,
    reason::Via,
    send::{ACTION_TTL_MS, CLOSE_CLOID_PREFIX, with_client_ids},
};

/// While halted or killed, a request reads the account to flatten at most
/// this often (within the request-read budget); the sync retries anyway.
const HALT_READ_EVERY_MS: u64 = 3_000;

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

/// How long a protective send waits for its emergency-log record; then it
/// goes unrecorded, with an alert (a stalled disk never holds up closing).
pub const EMERGENCY_WRITE_MS: u64 = 2_000;

/// Why a record did not reach the emergency log.
#[derive(Debug, Error)]
pub(super) enum EmergencyLogError {
    #[error(
        "the emergency log is stalled: a write has not finished after {} ms",
        EMERGENCY_WRITE_MS
    )]
    Stalled,
    #[error("the emergency log's write took longer than {} ms", EMERGENCY_WRITE_MS)]
    Late,
    #[error(transparent)]
    Write(std::io::Error),
    #[error(transparent)]
    Task(tokio::task::JoinError),
}

/// The emergency log (`docs/guard.md#journals`) as Guard writes it: off
/// the async runtime, each
/// write waited for [`EMERGENCY_WRITE_MS`] at most. A write that takes
/// longer marks the log stalled: until that write finishes, nothing is
/// written to it or waits on it (a hung disk costs one wait and one
/// blocking thread, not one per protective send).
#[derive(Clone)]
pub(super) struct Emergency {
    /// Locked by the blocking writes only (a hung one holds it): never on
    /// the async runtime.
    pub(super) log: Arc<StdMutex<crate::journal::EmergencyLog>>,
    pub(super) path: String,
    pub(super) stalled: Arc<AtomicBool>,
    /// Guard's clock, which times each write.
    clock: Arc<dyn Clock>,
}

impl Emergency {
    pub(super) fn new(log: crate::journal::EmergencyLog, clock: Arc<dyn Clock>) -> Self {
        Self {
            path: log.path().display().to_string(),
            log: Arc::new(StdMutex::new(log)),
            stalled: Arc::new(AtomicBool::new(false)),
            clock,
        }
    }

    pub(super) fn path(&self) -> String {
        self.path.clone()
    }

    /// A write that did not finish in time has not finished yet.
    pub(super) fn stalled(&self) -> bool {
        self.stalled.load(Ordering::SeqCst)
    }

    /// Write `body`, synced, within [`EMERGENCY_WRITE_MS`].
    pub(super) async fn record(
        &self,
        at: Timestamp,
        body: EventBody,
    ) -> Result<(), EmergencyLogError> {
        if self.stalled() {
            return Err(EmergencyLogError::Stalled);
        }
        let finished = Arc::new(AtomicBool::new(false));
        let write = tokio::task::spawn_blocking({
            let (log, stalled, finished) =
                (self.log.clone(), self.stalled.clone(), finished.clone());
            move || {
                let result = lock(&log).append(at, body).map(|_| ());
                finished.store(true, Ordering::SeqCst);
                stalled.store(false, Ordering::SeqCst);
                result
            }
        });
        match clock::timeout(&*self.clock, EMERGENCY_WRITE_MS, write).await {
            Some(Ok(result)) => result.map_err(EmergencyLogError::Write),
            Some(Err(error)) => Err(EmergencyLogError::Task(error)),
            None => {
                self.stalled.store(true, Ordering::SeqCst);
                // Finished in between: not stalled after all.
                if finished.load(Ordering::SeqCst) {
                    self.stalled.store(false, Ordering::SeqCst);
                }
                Err(EmergencyLogError::Late)
            }
        }
    }

    /// Write `body` without waiting for it (a record nothing is sent on
    /// the strength of); nothing while the log is stalled.
    pub(super) fn record_later(&self, at: Timestamp, body: EventBody) {
        if self.stalled() {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            this.record(at, body).await.ok();
        });
    }
}

/// Whether a view shows anything to flatten: a position, or an order that
/// could open one.
pub(super) fn exposed(account: &AccountView) -> bool {
    !account.positions.is_empty() || account.open_orders.iter().any(|order| order.is_opening())
}

impl<U: Upstream, C: Clock> Guard<U, C> {
    /// Latch the kill switch when the kill file exists, readable or not.
    pub(super) fn check_kill(inner: &mut Inner, now: u64) {
        if inner.kill.reason.is_some() {
            return;
        }
        let path = inner.config.kill_file();
        if std::fs::symlink_metadata(&path).is_err() {
            return;
        }
        let reason = std::fs::read_to_string(&path)
            .map(|text| text.trim().chars().take(200).collect::<String>())
            .unwrap_or_else(|_| format!("{} exists (unreadable)", path.display()));
        inner.kill.reason = Some(reason.clone());
        inner
            .journal
            .append(stamp(now), EventBody::Kill { reason })
            .ok();
    }

    /// Tests only (feature `test-hooks`, never in a release build): every
    /// emergency-log write waits at `gate` (a hung disk); returns how many
    /// writes were begun.
    #[cfg(feature = "test-hooks")]
    pub async fn hold_emergency_log_for_test(&self, gate: crate::journal::Gate) -> Arc<AtomicU64> {
        let inner = self.inner.lock().await;
        lock(&inner.emergency.log).hold_for_test(gate)
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
    pub(super) async fn halt(
        &self,
        inner: &mut Inner,
        now: u64,
        account: &AccountView,
        read: bool,
    ) {
        let Some(reason) = Self::halt_reason(inner) else {
            inner.halt.reported = None;
            return;
        };
        if read {
            self.flatten(inner, now, account, &reason).await;
            return;
        }
        // A paper Guard that reported this halt has nothing more to do.
        let sends = matches!(inner.mode, Mode::Send { .. });
        if !sends && inner.halt.reported.as_deref() == Some(reason.as_str()) {
            return;
        }
        if !halt_read_due(
            now,
            inner.halt.last_read_ms,
            exposed(account),
            inner.halt.last_read_exposed,
        ) {
            return;
        }
        let dexes = 1 + inner.config.policy.markets.hip3_dexes().len() as u64;
        let allowed = lock(&self.weights)
            .requests
            .take(now, ACCOUNT_READ_WEIGHT * dexes);
        if !allowed {
            return;
        }
        inner.halt.last_read_ms = Some(now);
        match self.read_locked(&mut inner.caches, now).await {
            Ok(AccountRead { view: account, .. }) => {
                inner.halt.last_read_exposed = Some(exposed(&account));
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

    pub(super) fn halt_reason(inner: &Inner) -> Option<String> {
        match (&inner.kill.reason, inner.risk.state()) {
            (Some(reason), _) => Some(format!("kill switch: {reason}")),
            (None, RiskState::Active) => None,
            (None, RiskState::HaltedForDay { .. }) => Some("daily loss stop".to_owned()),
            (None, RiskState::Stopped { .. }) => Some("drawdown halt".to_owned()),
        }
    }

    pub(super) async fn flatten(
        &self,
        inner: &mut Inner,
        now: u64,
        account: &AccountView,
        reason: &str,
    ) {
        if inner.kill.reason.is_some() && inner.kill.positions.is_none() {
            inner.kill.positions = Some(account.positions.len());
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
                    &mut inner.sends.client_ids,
                    &inner.salt,
                    CLOSE_CLOID_PREFIX,
                )
                .0
            })
            .collect();
        let sends = matches!(inner.mode, Mode::Send { .. });
        let fee = inner.fee.clone();
        if !sends && inner.halt.reported.as_deref() == Some(reason) {
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
        // for); if the journal is broken, they go all the same (closing is
        // never held up), each with its intent in the emergency log.
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
        inner.halt.reported = Some(reason.to_owned());
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
                    (Err(error), _) => Some(error.to_string()),
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
                    .append(stamp(self.clock.now_ms()), EventBody::Done { intent: seq })
                    .ok();
            }
        }
    }

    /// `POST /guard/kill`: a client-signed request that pulls the kill
    /// switch. It writes the kill file (so the switch survives a restart),
    /// latches it, and flattens at once. Nothing here releases it.
    pub async fn kill(&self, body: &Value) -> Value {
        let now = self.clock.now_ms();
        {
            let mut inner = self.inner.lock().await;
            // A kill expecting another mode (`expectedMode`) is refused
            // before its signature is checked, as on /exchange: nothing is
            // pulled. `inner.mode` never changes.
            let running = inner.mode.run_mode();
            let admitted = match zunder_guard_core::admit_kill(&mut inner.auth, body, now, running)
            {
                Ok(admitted) => admitted,
                Err(refusal) => {
                    return self.refuse(&mut inner, now, Via::Kill, body, &refusal);
                }
            };
            // Already latched: say so, without writing or flattening again
            // (a retrying agent must not spend the venue's request budget
            // that flattening needs).
            if let Some(killed) = inner.kill.reason.clone() {
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
            if inner.kill.reason.is_none() {
                inner.kill.reason = Some(reason.clone());
                inner
                    .journal
                    .append(stamp(now), EventBody::Kill { reason })
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
            "killed": inner.kill.reason,
            "durable": inner.config.kill_file().exists(),
            "positions_at_kill": inner.kill.positions,
            "last_error": inner.last_error,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use zunder_guard_core::{licence::FeeMode, sign::SigningNetwork};
    use zunder_venue::PersistentRisk;

    use super::*;
    use crate::{
        config::GuardConfig,
        guard::{Limits, Setup, SystemClock, test_support::view_for_expectations},
        journal::DecisionJournal,
        upstream::UpstreamError,
    };

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
            assert_eq!(inner.kill.positions, None);
            guard
                .flatten(&mut inner, 0, &account, "daily loss stop")
                .await;
            assert_eq!(inner.kill.positions, None);
            inner.kill.reason = Some("test kill".into());
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
            inner.kill.reason = Some("test kill".into());
            // A stale view is not evidence of the unreadable flatten snapshot.
            inner.last_view = Some(view_for_expectations());
        }
        guard.sync().await;
        let inner = guard.inner.lock().await;
        assert!(Guard::<UnreadableVenue>::kill_response(&inner)["positions_at_kill"].is_null());
        assert_eq!(inner.kill.reason.as_deref(), Some("test kill"));
        assert!(inner.last_error.is_some());
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
}
