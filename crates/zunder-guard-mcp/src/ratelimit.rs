// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! A clock, and token buckets that limit how fast an agent can call tools.
//!
//! An agent in a loop (a misread instruction, a retry storm, an injected
//! "keep buying") should run into a wall long before Guard's own limits
//! matter. Two buckets: every call, and the calls that send something to
//! Guard's `/exchange`. The kill switch is in neither: pulling it only ever
//! reduces risk, and an emergency must never wait.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// UTC epoch milliseconds.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// A clock for tests, moved by hand.
#[derive(Debug, Clone, Default)]
pub struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    pub fn at(ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(ms)))
    }

    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Every tool call: a burst of 30, then one a second.
pub const CALLS_BURST: u32 = 30;
pub const CALLS_PER_MINUTE: u32 = 60;
/// Calls that send to `/exchange` (`place_order`, `move_stop`,
/// `close_position`, `cancel_order`): a burst of 4, then one every 6 s.
pub const ORDERS_BURST: u32 = 4;
pub const ORDERS_PER_MINUTE: u32 = 10;

/// One token, in the bucket's units: a token is 60,000 units, so that a
/// rate of `n` a minute adds exactly `n` units a millisecond.
const TOKEN: u64 = 60_000;

/// A token bucket, exact in integer units.
#[derive(Debug, Clone)]
pub struct Bucket {
    capacity: u64,
    per_minute: u64,
    units: u64,
    last_ms: u64,
}

impl Bucket {
    pub fn new(capacity: u32, per_minute: u32, now_ms: u64) -> Self {
        let capacity = u64::from(capacity) * TOKEN;
        Self {
            capacity,
            per_minute: u64::from(per_minute).max(1),
            units: capacity,
            last_ms: now_ms,
        }
    }

    fn refill(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_ms);
        let gained = elapsed.saturating_mul(self.per_minute);
        self.units = self.units.saturating_add(gained).min(self.capacity);
        self.last_ms = self.last_ms.max(now_ms);
    }

    /// Whether a token is available now (without taking it), and if not,
    /// how many milliseconds until one is.
    pub fn check(&mut self, now_ms: u64) -> Result<(), u64> {
        self.refill(now_ms);
        if self.units >= TOKEN {
            Ok(())
        } else {
            Err((TOKEN - self.units).div_ceil(self.per_minute))
        }
    }

    pub fn take(&mut self, now_ms: u64) {
        self.refill(now_ms);
        self.units = self.units.saturating_sub(TOKEN);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_then_the_refill_rate() {
        let mut bucket = Bucket::new(ORDERS_BURST, ORDERS_PER_MINUTE, 0);
        for _ in 0..4 {
            assert_eq!(bucket.check(0), Ok(()));
            bucket.take(0);
        }
        // 10 a minute is one every 6,000 ms.
        assert_eq!(bucket.check(0), Err(6000));
        assert_eq!(bucket.check(5999), Err(1));
        assert_eq!(bucket.check(6000), Ok(()));
        bucket.take(6000);
        assert_eq!(bucket.check(6000), Err(6000));
        // Never more than the burst, however long the pause.
        let mut idle = Bucket::new(2, 60, 0);
        assert_eq!(idle.check(10_000_000), Ok(()));
        idle.take(10_000_000);
        idle.take(10_000_000);
        assert!(idle.check(10_000_000).is_err());
    }
}
