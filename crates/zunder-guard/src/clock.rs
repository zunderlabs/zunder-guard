// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Guard's one clock: the time of day (for nonces, journals, the risk
//! engine, the venue's times) and a monotonic clock with its timers (for
//! ages, deadlines and waits), behind one trait a test can replace and
//! move.
//!
//! Every wait Guard makes on its own account goes through [`Clock::sleep`]
//! and [`timeout`]: the account stream's ages and silence, the second
//! after an event, the deadlines of reads made while a loss is held for
//! the ledger, the locked reads' limits, the sync's cadence, the journal's
//! deadlines and the emergency log's. Timeouts on the network itself (a
//! connection, an HTTP request) stay with the transport.

use std::{
    future::Future,
    pin::Pin,
    sync::OnceLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use zunder_core::Timestamp;

/// A wait on a [`Clock`].
pub type Sleep = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Guard's time.
pub trait Clock: Send + Sync + 'static {
    /// Milliseconds since the epoch.
    fn now_ms(&self) -> u64;

    /// Milliseconds on a monotonic clock, for ages and deadlines, which a
    /// time of day stepping back would shorten. The process's own by
    /// default ([`monotonic_ms`]).
    fn monotonic_ms(&self) -> u64 {
        monotonic_ms()
    }

    /// Resolves once `ms` have passed on [`Clock::monotonic_ms`]. A Tokio
    /// timer by default; a clock a test moves wakes when it is moved
    /// ([`sleep_by_polling`]).
    fn sleep(&self, ms: u64) -> Sleep {
        Box::pin(tokio::time::sleep(Duration::from_millis(ms)))
    }
}

impl std::fmt::Debug for dyn Clock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Clock")
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// Milliseconds on the process's monotonic clock, from its first look at
/// it.
pub fn monotonic_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// [`Clock::sleep`] for a clock a test moves: it looks at
/// `clock.monotonic_ms()` every few milliseconds, so that moving the clock
/// ends the wait at once, and time passing ends it as well. As a Tokio
/// timer, it ends in the millisecond after `ms` have passed, never in the
/// last one: a deadline computed from the time of day has passed on that
/// clock too when the wait ends, whatever the two readings' rounding.
pub fn sleep_by_polling<C: Clock + Clone>(clock: &C, ms: u64) -> Sleep {
    let clock = clock.clone();
    let until = clock.monotonic_ms().saturating_add(ms);
    Box::pin(async move {
        loop {
            let now = clock.monotonic_ms();
            if now > until {
                return;
            }
            tokio::time::sleep(Duration::from_millis((until - now).clamp(1, 5))).await;
        }
    })
}

/// `future`'s output if it comes within `ms` on `clock`, else `None` (the
/// future is dropped). As `tokio::time::timeout`, the future is polled
/// first.
pub async fn timeout<C: Clock + ?Sized, F: Future>(
    clock: &C,
    ms: u64,
    future: F,
) -> Option<F::Output> {
    tokio::select! {
        biased;
        output = future => Some(output),
        () = clock.sleep(ms) => None,
    }
}

/// How long until `deadline` on `clock`'s monotonic clock (0 once it has
/// passed).
pub fn left<C: Clock + ?Sized>(clock: &C, deadline: u64) -> u64 {
    deadline.saturating_sub(clock.monotonic_ms())
}

/// A reading of a clock's time of day as the journals and the risk engine
/// take it.
pub(crate) fn stamp(ms: u64) -> Timestamp {
    Timestamp::from_millis(i64::try_from(ms).unwrap_or(i64::MAX))
}
