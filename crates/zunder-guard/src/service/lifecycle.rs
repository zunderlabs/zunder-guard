// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! A broker process has one terminal child-exit decision. SCM acknowledges a
//! stop only after it is latched under the same mutex used to commit recovery.
//! The recovery callback runs while locked: an accepted stop cannot fit between
//! deciding to recover and actually exiting the broker to request SCM recovery.
use std::sync::{Mutex, MutexGuard};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildExit {
    Success,
    Transient,
    Failure,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitDisposition {
    IntentionalStop,
    Completed,
    Failed,
    RecoveryRequested,
}
#[derive(Debug, Clone, Copy)]
enum State {
    Active,
    StopAccepted,
    Finished(ExitDisposition),
}
pub struct StopIntent(Mutex<State>);
impl Default for StopIntent {
    fn default() -> Self {
        Self(Mutex::new(State::Active))
    }
}
impl StopIntent {
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|poisoned| {
            // A poisoned lifecycle can never authorize another restart.
            let mut state = poisoned.into_inner();
            *state = State::StopAccepted;
            state
        })
    }

    /// True is the point at which SCM may acknowledge this Stop/Shutdown.
    /// After a terminal decision it must instead reject the control.
    pub fn accept_stop(&self) -> bool {
        let mut state = self.state();
        match *state {
            State::Active | State::StopAccepted => {
                *state = State::StopAccepted;
                true
            }
            State::Finished(_) => false,
        }
    }
    pub fn is_stopping(&self) -> bool {
        matches!(
            *self.state(),
            State::StopAccepted | State::Finished(ExitDisposition::IntentionalStop)
        )
    }

    /// The actual broker callback is process::exit(75), which does not return.
    /// A returning callback exists for synthetic tests; it still commits only
    /// once and late controls are rejected, never acknowledged then ignored.
    pub fn finish_child(
        &self,
        exit: ChildExit,
        admission_valid: bool,
        request_recovery: impl FnOnce(),
    ) -> ExitDisposition {
        let mut state = self.state();
        let disposition = match *state {
            State::Finished(disposition) => return disposition,
            State::StopAccepted => ExitDisposition::IntentionalStop,
            State::Active => match exit {
                ChildExit::Success => ExitDisposition::Completed,
                ChildExit::Transient if admission_valid => ExitDisposition::RecoveryRequested,
                ChildExit::Transient | ChildExit::Failure => ExitDisposition::Failed,
            },
        };
        *state = State::Finished(disposition);
        if disposition == ExitDisposition::RecoveryRequested {
            // Keep `state` alive until the irreversible recovery handoff occurs.
            request_recovery();
        }
        drop(state);
        disposition
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;

    #[test]
    fn accepted_stop_wins_when_transient_exit_is_already_observed() {
        let intent = Arc::new(StopIntent::default());
        let observed = Arc::new(Barrier::new(2));
        let acknowledged = Arc::new(Barrier::new(2));
        let worker = {
            let intent = intent.clone();
            let observed = observed.clone();
            let acknowledged = acknowledged.clone();
            std::thread::spawn(move || {
                // Same ordering as try_wait -> admission checks -> recovery.
                let exit = ChildExit::Transient;
                observed.wait();
                acknowledged.wait();
                intent.finish_child(exit, true, || panic!("accepted stop requested recovery"))
            })
        };
        observed.wait();
        assert!(intent.accept_stop()); // SCM may now report NoError.
        acknowledged.wait();
        assert_eq!(worker.join().unwrap(), ExitDisposition::IntentionalStop);
    }

    #[test]
    fn recovery_handoff_cannot_acknowledge_a_late_stop() {
        let intent = Arc::new(StopIntent::default());
        let (entered, inside) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let recovery = {
            let intent = intent.clone();
            std::thread::spawn(move || {
                intent.finish_child(ChildExit::Transient, true, || {
                    entered.send(()).unwrap();
                    wait.recv().unwrap();
                })
            })
        };
        inside.recv().unwrap();
        let (ack, received) = mpsc::channel();
        let control = {
            let intent = intent.clone();
            std::thread::spawn(move || ack.send(intent.accept_stop()).unwrap())
        };
        assert!(received.recv_timeout(Duration::from_millis(30)).is_err());
        release.send(()).unwrap();
        assert_eq!(recovery.join().unwrap(), ExitDisposition::RecoveryRequested);
        assert!(!received.recv().unwrap());
        control.join().unwrap();
    }

    #[derive(Clone, Copy)]
    enum Event {
        Stop,
        Exit(ChildExit, bool),
    }
    // Independent reference: scan the complete history for the first exit and
    // whether a human stop preceded it. No mutex or production state is reused.
    fn reference(events: &[Event]) -> (bool, Option<ExitDisposition>, usize) {
        let mut human_stop = false;
        for event in events {
            match *event {
                Event::Stop => human_stop = true,
                Event::Exit(exit, valid) => {
                    let result = if human_stop {
                        ExitDisposition::IntentionalStop
                    } else if exit == ChildExit::Success {
                        ExitDisposition::Completed
                    } else if exit == ChildExit::Transient && valid {
                        ExitDisposition::RecoveryRequested
                    } else {
                        ExitDisposition::Failed
                    };
                    return (
                        human_stop,
                        Some(result),
                        usize::from(result == ExitDisposition::RecoveryRequested),
                    );
                }
            }
        }
        (human_stop, None, 0)
    }

    #[test]
    fn random_lifecycle_histories_match_independent_first_exit_model() {
        let mut outcomes = [false; 4];
        for seed in 0..256 {
            let mut random = fastrand::Rng::with_seed(seed);
            let mut intent = StopIntent::default();
            let mut history = Vec::new();
            let mut recovery_requests = 0;
            for _ in 0..200 {
                let before = reference(&history);
                let event = match random.usize(0..7) {
                    0 | 1 => Event::Stop, // SCM Stop and Shutdown have the same intent.
                    2 => Event::Exit(ChildExit::Success, true),
                    3 => Event::Exit(ChildExit::Transient, true),
                    4 => Event::Exit(ChildExit::Transient, false),
                    5 => Event::Exit(ChildExit::Failure, true),
                    _ => {
                        // A new OS broker process, never an in-process resume.
                        intent = StopIntent::default();
                        history.clear();
                        recovery_requests = 0;
                        continue;
                    }
                };
                history.push(event);
                let expected = reference(&history);
                match event {
                    Event::Stop => assert_eq!(intent.accept_stop(), before.1.is_none()),
                    Event::Exit(exit, valid) => {
                        let got = intent.finish_child(exit, valid, || recovery_requests += 1);
                        assert_eq!(Some(got), expected.1, "seed {seed}");
                        outcomes[match got {
                            ExitDisposition::IntentionalStop => 0,
                            ExitDisposition::Completed => 1,
                            ExitDisposition::Failed => 2,
                            ExitDisposition::RecoveryRequested => 3,
                        }] = true;
                    }
                }
                assert_eq!(
                    recovery_requests, expected.2,
                    "one recovery handoff per broker epoch"
                );
                assert_eq!(intent.is_stopping(), expected.0);
            }
        }
        assert!(outcomes.into_iter().all(|seen| seen));
    }
}
