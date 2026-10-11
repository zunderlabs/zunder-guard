// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Guard's share of the venue's request weight (`ip_share`).
//!
//! Hyperliquid allows 1,200 of request weight a minute per IP address, for
//! everything sent from it. A Guard alone on its address sizes its budgets
//! for all of it (`docs/guard.md`, the `/info` row): the background sync,
//! the bots' request budget, the reduce-only allowances, the `/info`
//! passthrough, and what is left over for protection, closes and
//! flattening, which no budget holds. Several Guards on one address (one
//! machine, several accounts) would together spend several times that, and
//! then even Guard's protective sends would meet the venue's 429.
//!
//! `ip_share` (in `(0, 1]`, default 1) is the part of the address's 1,200 a
//! Guard may spend: `1/N` each for N Guards on one address. [`plan`] fits
//! every budget into `1,200 × ip_share` a minute, in this order:
//!
//! 1. **Fixed, whatever the share** ([`Budgets::fixed_per_minute`]): what
//!    Guard reads on a timer that does not stretch, the sync's cached reads
//!    (the main dex's `meta`, the account mode, `perpDexs`, the sweep: 46 a
//!    minute; each HIP-3 dex's `meta` and open-interest caps: 40 more), one
//!    extra read of every dex a minute (24 a dex: a send overtook the sync's
//!    read), and the builder-fee check while unapproved (20 a minute).
//! 2. **Everything else, scaled**: the sync's account reads, the request
//!    budget, the two reduce-only allowances, the passthrough and the
//!    protection reserve each get [`Budgets::scale`] of what they get at
//!    share 1, where `scale = (1,200 × ip_share − fixed) / (1,200 − fixed)`
//!    (1 at share 1, so a Guard alone keeps today's budgets exactly).
//!    A bucket's burst keeps at least the largest single thing it pays for
//!    (the request budget: one read of every dex, a HIP-3 entry's book and
//!    isolated leverage set and read back; the passthrough: a `userRole`,
//!    60; an allowance: its share-1 burst, 5), and its refill gives up
//!    what that adds, so its worst minute stays at its share. The sync
//!    reads less often instead ([`Budgets::sync_min_interval_ms`]).
//!
//! A sync round that a send overtook reads twice and skips the next round
//! (its extra read is in the fixed part). Where the share stretched the
//! sync beyond 15 s, a skipped round would leave more than 30 s between two
//! reads: such a Guard's sync always reads holding Guard's lock
//! ([`Budgets::sync_reads_locked`]), one read a round, never skipping;
//! requests then wait for that read (one round trip) once a round.
//!
//! Every quantity is in thousandths of weight and rounded down, so a Guard
//! never spends more than its share; what rounding leaves over falls to the
//! protection reserve. Protection's own sends (Guard's stops, closes,
//! cancels, flattening) and the sync's reads are not taken from any bucket:
//! they never wait for a bot's spent budget, at any share.
//!
//! [`plan`] refuses a share too small to keep Guard safe:
//!
//! - the sync must read the account at least every
//!   [`MAX_SYNC_INTERVAL_MS`] (30 s, the longest Guard waits to protect an
//!   unprotected position when the account keeps changing): the share never
//!   stretches the gap between two sync reads beyond it (a configured
//!   `sync_seconds` above 15 may, as at share 1);
//! - the protection reserve must hold [`reserve_floor`] a minute: one
//!   info request of the default weight (a stop looked up by its client id
//!   after a send that got no answer, 20) and, for each dex, a cancel, a
//!   stop and a close (1 each);
//! - the request budget must refill at least one read of every dex a
//!   minute, so that a bot's request can be judged after a read at all.
//!
//! With today's weights that is a share of at least about 0.291 with the
//! main dex alone (three Guards on one address), 0.466 with one HIP-3 dex
//! (two), 0.748 with two (one).

use std::fmt;

use rust_decimal::{Decimal, prelude::ToPrimitive};
use serde_json::{Value, json};

use crate::guard::{
    ACCOUNT_READ_WEIGHT, BOOK_READ_WEIGHT, EXITS_BURST, EXITS_PER_SECOND, FEE_CHECK_WEIGHT,
    INFO_WEIGHT_BURST, INFO_WEIGHT_PER_SECOND, LEVERAGE_READ_WEIGHT, Limits,
    PROTECT_AT_LEAST_EVERY_MS, SYNC_CACHED_WEIGHT, SYNC_CACHED_WEIGHT_PER_DEX,
    SYNC_WEIGHT_PER_MINUTE, info_weight,
};

/// Hyperliquid's request weight a minute per IP address (its rate-limit
/// documentation).
pub const IP_WEIGHT_PER_MINUTE: u64 = 1_200;
/// The longest the share may stretch the sync's interval: Guard protects an
/// unprotected position at least this often, and the sync is what does it.
pub const MAX_SYNC_INTERVAL_MS: u64 = PROTECT_AT_LEAST_EVERY_MS;
/// The builder-fee check while unapproved: one `maxBuilderFee` read (20) a
/// minute (`zunder_guard_core::licence::UNAPPROVED_RECHECK_MS`).
const FEE_CHECK_PER_MINUTE: u64 =
    FEE_CHECK_WEIGHT * 60_000 / zunder_guard_core::licence::UNAPPROVED_RECHECK_MS;
/// A reduce-only allowance keeps its share-1 burst (5): a batch of up to
/// 199 orders (weight 1 + n / 40) still fits it at any share.
const EXIT_MIN_BURST: u64 = EXITS_BURST;
/// One thousandth of a unit of weight is the unit here.
const MILLI: u64 = 1_000;

/// The protection reserve Guard needs a minute at least, with `hip3`
/// HIP-3 dexes: one info request of the default weight (a stop looked up
/// by its client id after a send that got no answer, `frontendOpenOrders`,
/// 20) and, on each dex Guard manages, a cancel, a stop and a close (1
/// each): 23 with the main dex alone, 26 with one HIP-3 dex, 29 with two.
pub fn reserve_floor(hip3: usize) -> u64 {
    info_weight(None) + 3 * dexes(hip3)
}

fn dexes(hip3: usize) -> u64 {
    1 + hip3 as u64
}

/// `milli` thousandths as a decimal: `1.53`, `4`.
pub fn thousandths(milli: u64) -> Decimal {
    Decimal::new(i64::try_from(milli).unwrap_or(i64::MAX), 3).normalize()
}

/// A token bucket's size: its refill in thousandths of weight a second,
/// and the most it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    pub milli_per_second: u64,
    pub burst: u64,
}

impl Bucket {
    /// The most it lets through in a minute, in thousandths of weight: a
    /// full burst and a minute's refill.
    pub fn worst_minute_milli(&self) -> u64 {
        60 * self.milli_per_second + self.burst * MILLI
    }

    fn to_json(self) -> Value {
        json!({
            "per_second": thousandths(self.milli_per_second).to_string(),
            "burst": self.burst,
        })
    }
}

/// Every budget Guard spends against the venue, fitted to its share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budgets {
    pub ip_share: Decimal,
    pub hip3_dexes: usize,
    /// `1,200 × ip_share`, rounded down: all Guard may spend a minute.
    pub weight_per_minute: u64,
    /// Spent whatever the share (see the module).
    pub fixed_per_minute: u64,
    /// What every other budget gets of its size at share 1, in
    /// millionths, rounded down (for the status; the budgets are computed
    /// exactly).
    pub scale_millionths: u64,
    /// The sync's account reads a minute (24 a dex each).
    pub sync_reads_per_minute: u64,
    /// The sync reads no more often than this; `sync_seconds` may make it
    /// slower ([`Budgets::sync_interval_ms`]).
    pub sync_min_interval_ms: u64,
    /// Bots' requests: reading the account, a HIP-3 entry's book, halted
    /// reads to flatten, and what a forwarded request sends.
    pub requests: Bucket,
    /// Each of the two reduce-only allowances on a spent request budget.
    pub exits: Bucket,
    /// The `/info` passthrough.
    pub info: Bucket,
    /// What no budget holds, a minute: Guard's protective sends, closes and
    /// flattening (the builder-fee check is in `fixed_per_minute`).
    pub reserve_per_minute: u64,
}

/// Why a share cannot run Guard safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetError {
    /// Not in `(0, 1]`.
    OutOfRange(Decimal),
    /// The share does not cover what Guard reads whatever the share.
    BelowFixed {
        share: Decimal,
        weight: u64,
        fixed: u64,
    },
    /// The sync would read less often than every 30 s.
    SyncTooSlow { share: Decimal, interval_ms: u64 },
    /// Bots' requests could not be judged after a read even once a minute.
    RequestsTooSmall { share: Decimal },
    /// The passthrough or an allowance would refill nothing.
    BucketEmpty { share: Decimal, name: &'static str },
    /// Too little left for protection.
    ReserveTooSmall {
        share: Decimal,
        reserve: u64,
        floor: u64,
    },
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HOW: &str = "give each Guard on one IP address ip_share = 1/N, with N the number of Guards there; with fewer Guards per address, or fewer HIP-3 dexes in the markets, each gets more (docs/guard.md, \"Several Guards on one IP address\")";
        match self {
            BudgetError::OutOfRange(share) => {
                write!(f, "ip_share must be above 0 and at most 1, got {share}")
            }
            BudgetError::BelowFixed {
                share,
                weight,
                fixed,
            } => write!(
                f,
                "ip_share {share} gives Guard {weight} of the venue's {IP_WEIGHT_PER_MINUTE} a minute per IP address, less than the {fixed} it reads on a fixed timer whatever the share; {HOW}"
            ),
            BudgetError::SyncTooSlow { share, interval_ms } => write!(
                f,
                "ip_share {share} would let the background sync read the account only every {:.1} s; Guard needs it at least every {} s to protect positions; {HOW}",
                *interval_ms as f64 / 1_000.0,
                MAX_SYNC_INTERVAL_MS / 1_000
            ),
            BudgetError::RequestsTooSmall { share } => write!(
                f,
                "ip_share {share} leaves bots' requests less than one account read a minute; {HOW}"
            ),
            BudgetError::BucketEmpty { share, name } => {
                write!(f, "ip_share {share} leaves the {name} nothing; {HOW}")
            }
            BudgetError::ReserveTooSmall {
                share,
                reserve,
                floor,
            } => write!(
                f,
                "ip_share {share} leaves {reserve} of the venue's request weight a minute for Guard's own protection, closes and flattening; it needs at least {floor}; {HOW}"
            ),
        }
    }
}

impl std::error::Error for BudgetError {}

impl Budgets {
    /// How often the background sync reads, in milliseconds: every
    /// `sync_seconds`, but no more often than the share allows.
    pub fn sync_interval_ms(&self, sync_seconds: u64) -> u64 {
        sync_seconds
            .saturating_mul(1_000)
            .max(self.sync_min_interval_ms)
    }

    /// Whether the sync reads holding Guard's lock every round: when the
    /// share stretched it so far (beyond 15 s) that skipping a round after
    /// one that read twice would leave more than [`MAX_SYNC_INTERVAL_MS`]
    /// between two reads. Never at share 1 (unchanged there).
    pub fn sync_reads_locked(&self) -> bool {
        self.ip_share < Decimal::ONE
            && self.sync_min_interval_ms.saturating_mul(2) > MAX_SYNC_INTERVAL_MS
    }

    /// The most Guard spends in a minute with every budget spent, in
    /// thousandths of weight (the reserve not included).
    pub fn worst_minute_milli(&self) -> u64 {
        self.fixed_per_minute * MILLI
            + self.sync_reads_per_minute * MILLI
            + self.requests.worst_minute_milli()
            + 2 * self.exits.worst_minute_milli()
            + self.info.worst_minute_milli()
    }

    /// For `/guard/status`.
    pub fn to_json(&self, sync_seconds: u64) -> Value {
        json!({
            "weight_per_minute": self.weight_per_minute,
            "fixed_per_minute": self.fixed_per_minute,
            "scale": Decimal::new(i64::try_from(self.scale_millionths).unwrap_or(i64::MAX), 6)
                .round_dp(4)
                .normalize()
                .to_string(),
            "sync_interval_ms": self.sync_interval_ms(sync_seconds),
            "sync_min_interval_ms": self.sync_min_interval_ms,
            "sync_reads_per_minute": self.sync_reads_per_minute,
            "sync_reads_locked": self.sync_reads_locked(),
            "requests": self.requests.to_json(),
            "reduce_only_allowance": self.exits.to_json(),
            "info": self.info.to_json(),
            "reserve_per_minute": self.reserve_per_minute,
        })
    }
}

/// `x × num / den`, rounded down.
fn scaled(x: u64, num: u64, den: u64) -> u64 {
    let value = u128::from(x) * u128::from(num) / u128::from(den);
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// A bucket of `scale` of its share-1 size (`per_second` refill, `burst`
/// held): its worst minute scaled, its burst scaled but at least
/// `min_burst`, its refill what is left of the worst minute. `None` when
/// that leaves no refill.
fn fit(per_second: u64, burst: u64, min_burst: u64, num: u64, den: u64) -> Option<Bucket> {
    let worst = scaled(60 * per_second * MILLI + burst * MILLI, num, den);
    let burst = (scaled(burst * MILLI, num, den) / MILLI).max(min_burst);
    let milli_per_second = worst.checked_sub(burst * MILLI)? / 60;
    (milli_per_second > 0).then_some(Bucket {
        milli_per_second,
        burst,
    })
}

/// Every budget for a Guard with `ip_share` of its IP address's request
/// weight and `hip3` HIP-3 dexes besides the main dex; refused when the
/// share is too small to keep Guard safe (the module).
pub fn plan(ip_share: Decimal, hip3: usize) -> Result<Budgets, BudgetError> {
    if ip_share <= Decimal::ZERO || ip_share > Decimal::ONE {
        return Err(BudgetError::OutOfRange(ip_share));
    }
    let dexes = dexes(hip3);
    let read = ACCOUNT_READ_WEIGHT * dexes;
    let cached = SYNC_CACHED_WEIGHT + SYNC_CACHED_WEIGHT_PER_DEX * hip3 as u64;
    let fixed = cached + read + FEE_CHECK_PER_MINUTE;
    let total = IP_WEIGHT_PER_MINUTE * MILLI;
    let available = (Decimal::from(total) * ip_share)
        .floor()
        .to_u64()
        .unwrap_or(0)
        .min(total);
    let weight_per_minute = available / MILLI;
    // scale = num / den, exactly.
    let Some(num) = available.checked_sub(fixed * MILLI).filter(|num| *num > 0) else {
        return Err(BudgetError::BelowFixed {
            share: ip_share,
            weight: weight_per_minute,
            fixed,
        });
    };
    let den = total - fixed * MILLI;

    // The sync's reads: at share 1 its 334 a minute less the cached part.
    let reads_at_one = SYNC_WEIGHT_PER_MINUTE.saturating_sub(cached);
    let sync_reads_per_minute = scaled(reads_at_one * MILLI, num, den) / MILLI;
    let sync_min_interval_ms = if sync_reads_per_minute == 0 {
        u64::MAX
    } else {
        // 60,000 ms × the weight of one read / the reads' weight a minute,
        // rounded up.
        (60_000 * read).div_ceil(sync_reads_per_minute)
    };
    if sync_min_interval_ms > MAX_SYNC_INTERVAL_MS {
        return Err(BudgetError::SyncTooSlow {
            share: ip_share,
            interval_ms: sync_min_interval_ms,
        });
    }

    // The bots' request budget: its burst holds one read of every dex, a
    // HIP-3 entry's book and isolated leverage set (1) and read back (20)
    // with the entry itself (1), and it refills at least one read a minute.
    let at_one = Limits::for_hip3_dexes(hip3);
    let request_min_burst =
        read + if hip3 > 0 { BOOK_READ_WEIGHT } else { 0 } + LEVERAGE_READ_WEIGHT + 2;
    let requests = fit(
        at_one.request_weight_per_second,
        at_one.request_weight_burst,
        request_min_burst,
        num,
        den,
    )
    .filter(|bucket| 60 * bucket.milli_per_second >= read * MILLI)
    .ok_or(BudgetError::RequestsTooSmall { share: ip_share })?;
    let exits = fit(EXITS_PER_SECOND, EXITS_BURST, EXIT_MIN_BURST, num, den).ok_or(
        BudgetError::BucketEmpty {
            share: ip_share,
            name: "reduce-only allowance",
        },
    )?;
    let info = fit(
        INFO_WEIGHT_PER_SECOND,
        INFO_WEIGHT_BURST,
        info_weight(Some("userRole")),
        num,
        den,
    )
    .ok_or(BudgetError::BucketEmpty {
        share: ip_share,
        name: "/info passthrough",
    })?;

    let mut budgets = Budgets {
        ip_share,
        hip3_dexes: hip3,
        weight_per_minute,
        fixed_per_minute: fixed,
        scale_millionths: scaled(1_000_000, num, den),
        sync_reads_per_minute,
        sync_min_interval_ms,
        requests,
        exits,
        info,
        reserve_per_minute: 0,
    };
    let reserve = available.saturating_sub(budgets.worst_minute_milli()) / MILLI;
    let floor = reserve_floor(hip3);
    if reserve < floor {
        return Err(BudgetError::ReserveTooSmall {
            share: ip_share,
            reserve,
            floor,
        });
    }
    budgets.reserve_per_minute = reserve;
    Ok(budgets)
}

#[cfg(test)]
mod tests {
    use rust_decimal::dec;

    use super::*;

    fn bucket(milli_per_second: u64, burst: u64) -> Bucket {
        Bucket {
            milli_per_second,
            burst,
        }
    }

    /// Share 1 is today's budgets, unchanged (`docs/guard.md`, the `/info`
    /// row): requests 4 a second and a burst of 60 (76 with one HIP-3 dex,
    /// 3 a second and 100 with two), each allowance 1 a second and 5, the
    /// passthrough 2 a second and 160, the sync every 5 s (11,613 ms with
    /// one HIP-3 dex, 20,770 with two), and what is left of 1,200 after the
    /// worst minute (1,068, 1,108, 1,096) and the fee check (20): 112, 72,
    /// 84.
    #[test]
    fn share_one_keeps_todays_budgets() {
        let cases = [
            (0, 90, 288, 5_000, bucket(4_000, 60), 112),
            (1, 154, 248, 11_613, bucket(4_000, 76), 72),
            (2, 218, 208, 20_770, bucket(3_000, 100), 84),
        ];
        for (hip3, fixed, reads, interval, requests, reserve) in cases {
            let budgets = plan(Decimal::ONE, hip3).unwrap();
            assert_eq!(budgets.weight_per_minute, 1_200, "{hip3}");
            // 46 + 40 a HIP-3 dex cached, 24 a dex for the extra read, 20.
            assert_eq!(budgets.fixed_per_minute, fixed, "{hip3}");
            assert_eq!(budgets.scale_millionths, 1_000_000, "{hip3}");
            assert_eq!(budgets.sync_reads_per_minute, reads, "{hip3}");
            assert_eq!(budgets.sync_min_interval_ms, interval, "{hip3}");
            assert_eq!(budgets.requests, requests, "{hip3}");
            assert_eq!(budgets.exits, bucket(1_000, 5), "{hip3}");
            assert_eq!(budgets.info, bucket(2_000, 160), "{hip3}");
            assert_eq!(budgets.reserve_per_minute, reserve, "{hip3}");
            // The worst minute of the docs, the fee check besides.
            assert_eq!(
                budgets.worst_minute_milli() / MILLI,
                1_200 - reserve,
                "{hip3}"
            );
        }
        // Never a locked sync at share 1, whatever the interval.
        for hip3 in 0..=2 {
            assert!(!plan(Decimal::ONE, hip3).unwrap().sync_reads_locked());
        }
        // A slower configured sync is kept; a faster one is not.
        let two = plan(Decimal::ONE, 2).unwrap();
        assert_eq!(two.sync_interval_ms(5), 20_770);
        assert_eq!(two.sync_interval_ms(30), 30_000);
    }

    /// Share 0.5, main dex alone. Of 600 a minute, 90 are fixed (46 cached,
    /// 24 the extra read, 20 the fee check); everything else is scaled by
    /// (600 − 90) / (1,200 − 90) = 510 / 1,110 = 17/37 (0.459459…):
    ///
    /// - the sync's reads: 288 × 17/37 = 132.3 → 132 a minute, one read of
    ///   24 every 60,000 × 24 / 132 = 10,909.1 → 10,910 ms;
    /// - requests: worst minute 300 × 17/37 = 137.837; the burst 60 × 17/37
    ///   = 27.6, raised to 46 (a read of 24, the leverage set and read back
    ///   and the entry, 22); refill (137.837 − 46) / 60 = 1.5306 → 1.530 a
    ///   second;
    /// - each allowance: worst 65 × 17/37 = 29.864; burst kept at 5;
    ///   refill (29.864 − 5) / 60 = 0.4144 → 0.414;
    /// - passthrough: worst 280 × 17/37 = 128.648; burst 160 × 17/37 = 73.5
    ///   → 73; refill (128.648 − 73) / 60 = 0.9274 → 0.927;
    /// - reserve: 600 − 90 − 132 − (91.8 + 46) − 2 × (27.84 + 2) − (55.62 +
    ///   73) = 51.9 → 51 (17/37 of 112 is 51.5), at least 23 (the
    ///   allowances' 2 × (24.84 + 5) the same 59.68).
    ///
    /// The sync every 10.9 s: a skipped round leaves 21.8 s, so it reads
    /// without the lock, as at share 1.
    #[test]
    fn half_a_share_main_dex() {
        let budgets = plan(dec!(0.5), 0).unwrap();
        assert_eq!(budgets.weight_per_minute, 600);
        assert_eq!(budgets.fixed_per_minute, 90);
        assert_eq!(budgets.scale_millionths, 459_459);
        assert_eq!(budgets.sync_reads_per_minute, 132);
        assert_eq!(budgets.sync_min_interval_ms, 10_910);
        assert_eq!(budgets.requests, bucket(1_530, 46));
        assert_eq!(budgets.exits, bucket(414, 5));
        assert_eq!(budgets.info, bucket(927, 73));
        assert_eq!(budgets.reserve_per_minute, 51);
        assert!(!budgets.sync_reads_locked());
    }

    /// Share 0.5 with one HIP-3 dex. Of 600, 154 fixed (86 cached, 48 the
    /// extra read, 20); scale (600 − 154) / (1,200 − 154) = 446 / 1,046 =
    /// 223/523 (0.426386…):
    ///
    /// - reads: 248 × 223/523 = 105.7 → 105, a read of 48 every 60,000 × 48
    ///   / 105 = 27,428.6 → 27,429 ms (within 30 s);
    /// - requests: worst 316 × 223/523 = 134.738; burst 76 × 223/523 = 32.4
    ///   raised to 72 (48 + 2 + 22); refill (134.738 − 72) / 60 = 1.0456 →
    ///   1.045;
    /// - each allowance: worst 65 × 223/523 = 27.715; burst 5; refill
    ///   22.715 / 60 = 0.3786 → 0.378;
    /// - passthrough: worst 280 × 223/523 = 119.388; burst 68.2 → 68;
    ///   refill 51.388 / 60 = 0.8565 → 0.856;
    /// - reserve: 600 − 154 − 105 − (62.7 + 72) − 2 × (25.68 + 2) − (51.36 +
    ///   68) = 31.58 → 31, at least 26 (the allowances' 2 × (22.68 + 5)
    ///   the same 55.36).
    ///
    /// The sync every 27.4 s: a skipped round would leave 54.9 s, so it
    /// reads holding the lock every round.
    #[test]
    fn half_a_share_one_hip3_dex() {
        let budgets = plan(dec!(0.5), 1).unwrap();
        assert_eq!(budgets.fixed_per_minute, 154);
        assert_eq!(budgets.scale_millionths, 426_386);
        assert_eq!(budgets.sync_reads_per_minute, 105);
        assert_eq!(budgets.sync_min_interval_ms, 27_429);
        assert_eq!(budgets.requests, bucket(1_045, 72));
        assert_eq!(budgets.exits, bucket(378, 5));
        assert_eq!(budgets.info, bucket(856, 68));
        assert_eq!(budgets.reserve_per_minute, 31);
        assert!(budgets.sync_reads_locked());
    }

    /// Two HIP-3 dexes at 0.5: 218 fixed, scale 382 / 982; the reads get
    /// 208 × 382/982 = 80.9 → 80 a minute, a read of 72 every 54 s: too
    /// slow. Share 0.1 (120 a minute): main dex alone, the reads get 288 ×
    /// 30/1,110 = 7.8 → 7, a read every 205.7 s; with a HIP-3 dex the 154
    /// fixed alone exceed 120.
    #[test]
    fn too_small_a_share_is_refused_with_its_reason() {
        assert_eq!(
            plan(dec!(0.5), 2),
            Err(BudgetError::SyncTooSlow {
                share: dec!(0.5),
                interval_ms: 54_000
            })
        );
        assert_eq!(
            plan(dec!(0.1), 0),
            Err(BudgetError::SyncTooSlow {
                share: dec!(0.1),
                interval_ms: 205_715
            })
        );
        for hip3 in [1, 2] {
            assert!(matches!(
                plan(dec!(0.1), hip3),
                Err(BudgetError::BelowFixed { weight: 120, .. })
            ));
        }
        // The message says what to do.
        let text = plan(dec!(0.1), 0).unwrap_err().to_string();
        assert!(
            text.contains("every 205.7 s") && text.contains("1/N"),
            "{text}"
        );
    }

    /// The smallest shares (module docs): main dex alone the request budget
    /// binds, 300 × scale − 46 ≥ 24 (a read a minute), scale ≥ 0.2333, share
    /// ≥ (90 + 0.2333 × 1,110) / 1,200 = 0.2908; one HIP-3 dex the sync, 248
    /// × scale ≥ 96, share ≥ (154 + 0.3871 × 1,046) / 1,200 = 0.4657; two,
    /// 208 × scale ≥ 144, share ≥ (218 + 0.6923 × 982) / 1,200 = 0.7482.
    #[test]
    fn the_smallest_shares() {
        let smallest = |hip3| {
            (1..=1_000u32)
                .map(|k| Decimal::new(i64::from(k), 3))
                .find(|share| plan(*share, hip3).is_ok())
                .unwrap()
        };
        assert_eq!(smallest(0), dec!(0.291));
        assert_eq!(smallest(1), dec!(0.466));
        assert_eq!(smallest(2), dec!(0.749));
        // So: three Guards on one address with the main dex alone, two with
        // one HIP-3 dex, one with two.
        assert!(plan(Decimal::ONE / Decimal::from(3), 0).is_ok());
        assert!(plan(dec!(0.25), 0).is_err());
        assert!(plan(dec!(0.5), 1).is_ok());
        assert!(plan(Decimal::ONE / Decimal::from(3), 1).is_err());
    }

    #[test]
    fn the_share_must_be_above_zero_and_at_most_one() {
        for share in [dec!(0), dec!(-0.5), dec!(1.0001), dec!(2)] {
            assert_eq!(plan(share, 0), Err(BudgetError::OutOfRange(share)));
        }
        assert!(plan(dec!(1.000), 0).is_ok());
    }

    /// N Guards on one address, each at 1/N, every one spending all of
    /// every budget in the same minute and its reserve besides, stay within
    /// the venue's 1,200; so does any mix of dexes whose shares add up to
    /// at most 1. The worst minute here is counted from the buckets
    /// themselves and the sync's interval, not from the plan's reserve.
    #[test]
    fn n_guards_at_one_nth_stay_within_the_ip_limit() {
        // The sync's reads a minute at its interval; the extra read when a
        // send overtook one is in `fixed`.
        let worst = |budgets: &Budgets| {
            let read = ACCOUNT_READ_WEIGHT * dexes(budgets.hip3_dexes) * MILLI;
            budgets.fixed_per_minute * MILLI
                + 60_000 * read / budgets.sync_min_interval_ms
                + budgets.requests.worst_minute_milli()
                + 2 * budgets.exits.worst_minute_milli()
                + budgets.info.worst_minute_milli()
                + budgets.reserve_per_minute * MILLI
        };
        let mut started = 0;
        for hip3 in 0..=zunder_guard_core::policy::MAX_HIP3_DEXES {
            for n in 1..=20u32 {
                let share = Decimal::ONE / Decimal::from(n);
                let Ok(budgets) = plan(share, hip3) else {
                    continue;
                };
                started += 1;
                assert!(budgets.reserve_per_minute >= reserve_floor(hip3));
                let total = u64::from(n) * worst(&budgets);
                assert!(total <= 1_200 * MILLI, "{n} at {hip3}: {total}");
            }
        }
        // 1, 2, 3 main-dex Guards; 1, 2 with one HIP-3 dex; 1 with two.
        assert_eq!(started, 6);
        // A mix whose shares add up to 1: a Guard with one HIP-3 dex at 0.5
        // and one with the main dex alone at 0.5.
        let mix = [plan(dec!(0.5), 1).unwrap(), plan(dec!(0.5), 0).unwrap()];
        let total: u64 = mix.iter().map(worst).sum();
        assert!(total <= 1_200 * MILLI, "{total}");
        // Every share in thousandths: within its own part of 1,200, the
        // reserve at least its floor, and never more of anything than a
        // larger share gets.
        for hip3 in 0..=zunder_guard_core::policy::MAX_HIP3_DEXES {
            let mut last: Option<Budgets> = None;
            for k in 1..=1_000u32 {
                let share = Decimal::new(i64::from(k), 3);
                let Ok(budgets) = plan(share, hip3) else {
                    assert!(last.is_none(), "refused above a share that started");
                    continue;
                };
                assert!(worst(&budgets) <= u64::from(k) * 1_200, "{share} {hip3}");
                assert!(budgets.reserve_per_minute >= reserve_floor(hip3));
                if let Some(last) = &last {
                    assert!(budgets.sync_min_interval_ms <= last.sync_min_interval_ms);
                    for (now, before) in [
                        (budgets.requests, last.requests),
                        (budgets.exits, last.exits),
                        (budgets.info, last.info),
                    ] {
                        assert!(now.worst_minute_milli() >= before.worst_minute_milli());
                    }
                }
                last = Some(budgets);
            }
        }
    }
}
