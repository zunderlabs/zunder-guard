// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Guard's budgets of the venue's request weight: `/info` passthrough,
//! bots' requests, reduce-only orders on a spent budget, previews and the
//! bot's own reads answered from the stream (`docs/guard.md`, "Endpoints"
//! and "Several Guards on one IP address").

use zunder_guard_core::{
    account::AccountView,
    action::{Action, ExchangeRequest},
    judge::Forward,
};

use crate::{locks::lock, upstream::Upstream};

use super::{Guard, Inner, clock::Clock};

/// The background sync's share of the venue's request weight a minute:
/// 288 for the reads themselves (24 a dex, every 5 s with the main dex
/// alone), and about 46 for what is cached (the account mode, the main
/// dex's `meta`, `perpDexs`, the sweep). Each HIP-3 dex adds 24 a read and
/// 40 a minute cached (its `meta` and its open-interest caps); the sync
/// slows down so that the total stays at this ([`crate::budget::plan`],
/// which also fits it to `ip_share`).
pub(crate) const SYNC_WEIGHT_PER_MINUTE: u64 = 334;
/// The cached part of the sync's weight a minute, besides the reads: 46
/// with the main dex alone, 40 more per HIP-3 dex.
pub(crate) const SYNC_CACHED_WEIGHT: u64 = 46;
pub(crate) const SYNC_CACHED_WEIGHT_PER_DEX: u64 = 40;

/// The venue's request weight a second that `/info` passthrough (HTTP and
/// WebSocket info posts, uncached) may spend on average: 2 of weight a
/// second, 120 of Hyperliquid's 1,200 a minute per IP. The worst minute,
/// every budget's burst spent in it: the sync 334
/// ([`SYNC_WEIGHT_PER_MINUTE`]) and one extra read of every dex after a send
/// overtook one (24 a dex); the requests ([`Limits::for_hip3_dexes`]:
/// reading the account, a HIP-3 entry's book, halted reads to flatten, and
/// every forwarded action with its leverage read-back); reduce-only orders
/// forwarded on a spent budget, at most 2 of weight a second and bursts of
/// 5 each ([`EXITS_PER_SECOND`]), 130; the passthrough 120 and a burst of
/// 160. Main dex alone: 334 + 24 + 240 + 60 + 130 + 280 = 1,068; one HIP-3
/// dex: 334 + 48 + 240 + 76 + 130 + 280 = 1,108; two: 334 + 72 + 180 +
/// 100 + 130 + 280 = 1,096. That leaves 92 at least for what no budget holds
/// (protection's and flattening's own sends, the sync's builder-fee check,
/// 20 a minute while unapproved, the ledger read, 20 a minute while the
/// account stream is down, a stop looked up after a send that got no
/// answer). These are the budgets of a Guard alone on its IP address
/// (`ip_share` 1); with a smaller share every one is fitted to it
/// ([`crate::budget::plan`]).
pub const INFO_WEIGHT_PER_SECOND: u64 = 2;
/// How much unspent passthrough weight may build up (a burst).
pub const INFO_WEIGHT_BURST: u64 = 160;
/// The venue's request weight a second that bots' requests may spend on
/// average: reading the account (24 a dex), a HIP-3 entry's book (2), and
/// what a forwarded request sends (1 an action, 20 more to read back
/// isolated leverage Guard set): 240 a minute with the main dex alone or
/// one HIP-3 dex, 180 with two ([`Limits::for_hip3_dexes`]).
/// Beyond it Guard refuses requests with `rate_limited` (reduce-only
/// orders still go, unjudged), so the background sync, protection and
/// flattening always keep their share.
pub const REQUEST_WEIGHT_PER_SECOND: u64 = 4;
/// Reduce-only orders that arrive on a spent request budget go within an
/// allowance of 1 of weight a second (a burst of 5); beyond that only one
/// that reduces a position the last view shows, within 1 of weight a second
/// more (a burst of 5). Those that go are charged to the request budget all
/// the same (into debt, at most one burst deep, so that the bot's other
/// requests wait); the others are refused `rate_limited` and cost nothing.
pub const EXITS_PER_SECOND: u64 = 1;
pub(crate) const EXITS_BURST: u64 = 5;
/// How much unspent request weight may build up: two reads and a half,
/// or 60 entries that need no leverage set first.
pub const REQUEST_WEIGHT_BURST: u64 = 60;
/// What one read of the account costs: `clearinghouseState` and `allMids`
/// 2 each, `frontendOpenOrders` 20 (the account mode and `meta` cached).
pub(crate) const ACCOUNT_READ_WEIGHT: u64 = 24;
/// The venue's request weight of an `l2Book` read.
pub(crate) const BOOK_READ_WEIGHT: u64 = 2;
/// The venue's request weight of reading isolated leverage back
/// (`activeAssetData`).
pub(crate) const LEVERAGE_READ_WEIGHT: u64 = 20;

/// The venue's request weight of a `maxBuilderFee` read (an info request
/// of the default weight). The periodic check runs at most once a minute.
pub(crate) const FEE_CHECK_WEIGHT: u64 = 20;

/// Most previews a second.
pub const PREVIEWS_PER_SECOND: u32 = 1;
/// The bot's own account reads answered from the stream, at most this many
/// a second; beyond, the venue answers them (within the passthrough's
/// budget).
pub const STREAM_INFO_PER_SECOND: u32 = 20;

/// Hyperliquid's weight of an info request (its rate-limit documentation):
/// 2 for the light reads, 60 for `userRole`, 20 for the rest.
pub fn info_weight(kind: Option<&str>) -> u64 {
    match kind {
        Some(
            "l2Book"
            | "allMids"
            | "clearinghouseState"
            | "orderStatus"
            | "spotClearinghouseState"
            | "exchangeStatus",
        ) => 2,
        Some("userRole") => 60,
        _ => 20,
    }
}

/// The request budget (`REQUEST_WEIGHT_PER_SECOND` and
/// `REQUEST_WEIGHT_BURST` by default, made to fit the HIP-3 dexes Guard
/// reads by [`Limits::for_hip3_dexes`] and to the config's `ip_share` by
/// [`crate::budget::plan`] when the default is given). Only tests against
/// an in-memory venue raise it, where no venue limit applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub request_weight_per_second: u64,
    pub request_weight_burst: u64,
}

impl Limits {
    /// The production budget for `hip3` HIP-3 dexes: a burst that holds
    /// one read of every dex (24 each), a HIP-3 entry's book (2) and
    /// isolated leverage set and read back (22), so a request can always go
    /// after a read: 60 with the main dex alone, 76 with one HIP-3 dex,
    /// 100 with two, the refill then 3 a second instead of 4 to keep the
    /// worst minute (`INFO_WEIGHT_PER_SECOND`).
    pub fn for_hip3_dexes(hip3: usize) -> Self {
        match hip3 {
            0 => Self::default(),
            1 => Self {
                request_weight_per_second: REQUEST_WEIGHT_PER_SECOND,
                request_weight_burst: 76,
            },
            _ => Self {
                request_weight_per_second: 3,
                request_weight_burst: 100,
            },
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request_weight_per_second: REQUEST_WEIGHT_PER_SECOND,
            request_weight_burst: REQUEST_WEIGHT_BURST,
        }
    }
}

/// A simple per-second budget.
#[derive(Debug, Default)]
pub(super) struct Budget {
    pub(super) second: u64,
    pub(super) used: u32,
}

/// A token bucket of request weight: `milli_per_second` thousandths of
/// weight refilled a second, at most `burst` held. Starts full.
#[derive(Debug)]
pub(super) struct WeightBucket {
    /// Millionths of a unit of weight; below zero when in debt.
    micro: i64,
    pub(super) at_ms: Option<u64>,
    pub(super) milli_per_second: u64,
    pub(super) burst: u64,
}

/// Millionths of weight in `weight`.
fn micro(weight: u64) -> i64 {
    i64::try_from(weight.saturating_mul(1_000_000)).unwrap_or(i64::MAX)
}

impl WeightBucket {
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self::with(INFO_WEIGHT_PER_SECOND, INFO_WEIGHT_BURST)
    }

    /// `per_second` whole units of weight a second.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn with(per_second: u64, burst: u64) -> Self {
        Self::of(crate::budget::Bucket {
            milli_per_second: per_second.saturating_mul(1_000),
            burst,
        })
    }

    pub(super) fn of(bucket: crate::budget::Bucket) -> Self {
        Self {
            micro: micro(bucket.burst),
            at_ms: None,
            milli_per_second: bucket.milli_per_second,
            burst: bucket.burst,
        }
    }

    fn refill(&mut self, now_ms: u64) {
        let elapsed = self.at_ms.map_or(0, |at| now_ms.saturating_sub(at));
        self.at_ms = Some(now_ms);
        // Milliseconds × thousandths a second = millionths.
        let added =
            i64::try_from(elapsed.saturating_mul(self.milli_per_second)).unwrap_or(i64::MAX);
        self.micro = self.micro.saturating_add(added).min(micro(self.burst));
    }

    pub(super) fn take(&mut self, now_ms: u64, weight: u64) -> bool {
        self.refill(now_ms);
        let cost = micro(weight);
        if self.micro < cost {
            return false;
        }
        self.micro -= cost;
        true
    }

    /// Take `weight` if the bucket holds it; else how many milliseconds
    /// until it will (nothing taken).
    pub(super) fn take_or_wait(&mut self, now_ms: u64, weight: u64) -> Result<(), u64> {
        if self.take(now_ms, weight) {
            return Ok(());
        }
        if weight > self.burst || self.milli_per_second == 0 {
            return Err(u64::MAX);
        }
        // Millionths missing, refilled at `milli_per_second` millionths a
        // millisecond.
        let missing = u64::try_from(micro(weight).saturating_sub(self.micro)).unwrap_or(0);
        Err(missing.div_ceil(self.milli_per_second).max(1))
    }

    /// Charge `weight` whatever is left: below zero, the debt is paid back
    /// before anything else is taken. The debt goes no deeper than one
    /// burst, so that it never holds a bot's other requests off for longer
    /// than one burst takes to refill.
    pub(super) fn charge(&mut self, now_ms: u64, weight: u64) {
        self.refill(now_ms);
        let floor = micro(self.burst).saturating_neg();
        self.micro = self.micro.saturating_sub(micro(weight)).max(floor);
    }
}

impl Budget {
    pub(super) fn take(&mut self, now_ms: u64, per_second: u32) -> bool {
        let second = now_ms / 1_000;
        if second != self.second {
            self.second = second;
            self.used = 0;
        }
        if self.used >= per_second {
            return false;
        }
        self.used += 1;
        true
    }
}

/// Every budget of the venue's request weight Guard spends, behind one
/// lock ([`Guard`]'s `weights`, never held across an await): a decision
/// that looks at several of them (an exit beyond the request budget) is
/// one step.
#[derive(Debug)]
pub(super) struct Weights {
    /// `/info` passthrough: HTTP and WebSocket info posts, uncached.
    pub(super) info: WeightBucket,
    /// Bots' requests: reading the account, a HIP-3 entry's book, what a
    /// forwarded request sends; also recovery's reads and the ledger.
    pub(super) requests: WeightBucket,
    /// Reduce-only orders forwarded on a spent request budget, and those
    /// of them forwarded because they reduce a position the last view
    /// shows ([`EXITS_PER_SECOND`]).
    pub(super) exit_allowance: WeightBucket,
    pub(super) known_exits: WeightBucket,
    /// Previews ([`PREVIEWS_PER_SECOND`]).
    pub(super) previews: Budget,
    /// The bot's reads answered from the stream ([`STREAM_INFO_PER_SECOND`]).
    pub(super) stream_info: Budget,
}

impl Weights {
    pub(super) fn new(budgets: &crate::budget::Budgets) -> Self {
        Self {
            info: WeightBucket::of(budgets.info),
            requests: WeightBucket::of(budgets.requests),
            exit_allowance: WeightBucket::of(budgets.exits),
            known_exits: WeightBucket::of(budgets.exits),
            previews: Budget::default(),
            stream_info: Budget::default(),
        }
    }

    /// Whether a reduce-only order of `weight` may go: within the request
    /// budget; else charged to it all the same (into debt) and forwarded
    /// within the exit allowance, or, beyond that, when it reduces a
    /// position the last view shows (`reduces`), at most
    /// [`EXITS_PER_SECOND`].
    pub(super) fn admit_exit(&mut self, now: u64, weight: u64, reduces: bool) -> bool {
        if self.requests.take(now, weight) {
            return true;
        }
        // The allowances count weight (a batch of 41 orders or more is 2).
        let admitted = self.exit_allowance.take(now, weight)
            || (reduces && self.known_exits.take(now, weight));
        // Charged only when it goes: a refused exit costs the venue nothing.
        if admitted {
            self.requests.charge(now, weight);
        }
        admitted
    }
}

/// Refusal texts of the request budget.
pub(super) const BUDGET_SPENT: &str = "Guard's budget of the venue's request weight is spent (it is kept for Guard's own protection); try again in a few seconds";

/// Whether every order of `request` is reduce-only and trades against a
/// position `view` shows in its coin.
fn reduces_a_position(view: &AccountView, request: &ExchangeRequest) -> bool {
    let Action::Order(order) = &request.action else {
        return false;
    };
    !order.orders.is_empty()
        && order.orders.iter().all(|placed| {
            placed.reduce_only
                && view
                    .meta
                    .by_index(placed.asset)
                    .and_then(|asset| view.position(&asset.name))
                    .is_some_and(|position| {
                        let buys = placed.is_buy;
                        match position.side {
                            zunder_core::Side::Buy => !buys,
                            zunder_core::Side::Sell => buys,
                        }
                    })
        })
}

/// The venue's request weight of what a forwarded request sends: 1 an
/// action, 1 more for every 40 in a batch (orders, cancels, modifies;
/// Hyperliquid's rate-limit documentation), and reading back each isolated
/// leverage set first.
pub(super) fn forward_weight(forward: &Forward) -> u64 {
    let action = |action: &Action| {
        let batch = match action {
            Action::Order(order) => order.orders.len(),
            Action::Cancel(cancels) | Action::CancelByCloid(cancels) => cancels.len(),
            Action::BatchModify(modifies) => modifies.len(),
            _ => 0,
        };
        1 + batch as u64 / 40
    };
    let leverage_reads = forward
        .pre
        .iter()
        .filter(|pre| matches!(pre, Action::UpdateLeverage { .. }))
        .count() as u64;
    forward
        .pre
        .iter()
        .chain(std::iter::once(&forward.action))
        .chain(forward.post.iter())
        .map(action)
        .sum::<u64>()
        + LEVERAGE_READ_WEIGHT * leverage_reads
}

impl<U: Upstream, C: Clock> Guard<U, C> {
    /// The refusal of a reduce-only order beyond the request budget and
    /// both allowances.
    pub(super) fn exits_spent(&self) -> String {
        let rate = crate::budget::thousandths(self.budgets.exits.milli_per_second);
        format!(
            "Guard's budget of the venue's request weight is spent, and so is its allowance for reduce-only orders beyond it ({rate} of weight a second, and {rate} more a second for one that reduces a position Guard last saw); try again in a second"
        )
    }

    /// Whether a reduce-only order of `weight` may go: within the request
    /// budget; else charged to it all the same (into debt) and forwarded
    /// within the exit allowance, or, beyond that, when it reduces a
    /// position the last view shows, at most [`EXITS_PER_SECOND`].
    pub(super) fn admit_exit(
        &self,
        inner: &Inner,
        now: u64,
        request: &ExchangeRequest,
        weight: u64,
    ) -> bool {
        let reduces = inner
            .last_view
            .as_ref()
            .is_some_and(|view| reduces_a_position(view, request));
        lock(&self.weights).admit_exit(now, weight, reduces)
    }

    /// Tests only (feature `test-hooks`, never in a release build): the
    /// `/info` passthrough's budget, so that a test can run a client's
    /// reads back to back (the in-memory venue has no request limit).
    #[cfg(feature = "test-hooks")]
    pub fn set_info_budget(&self, per_second: u64, burst: u64) {
        lock(&self.weights).info = WeightBucket::with(per_second, burst);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rust_decimal::Decimal;

    use super::*;

    #[test]
    fn the_sync_slows_down_to_keep_its_share_of_the_request_weight() {
        // 334 a minute: 46 cached with the main dex alone, 288 for reads of
        // 24 every 5 s. One HIP-3 dex: 86 cached, 248 for reads of 48:
        // 60,000 * 48 / 248 = 11,612.9 ms. Two: 126 cached, 208 for reads of
        // 72: 60,000 * 72 / 208 = 20,769.2 ms.
        let interval = |sync_seconds, dexes| {
            crate::budget::plan(Decimal::ONE, dexes)
                .unwrap()
                .sync_interval_ms(sync_seconds)
        };
        assert_eq!(interval(5, 0), 5_000);
        assert_eq!(interval(5, 1), 11_613);
        assert_eq!(interval(5, 2), 20_770);
        // A slower configured sync is kept.
        assert_eq!(interval(30, 2), 30_000);
        for dexes in 0..=zunder_guard_core::policy::MAX_HIP3_DEXES {
            let interval = interval(5, dexes) as f64;
            let reads = 60_000.0 / interval * (ACCOUNT_READ_WEIGHT * (1 + dexes as u64)) as f64;
            let cached = (SYNC_CACHED_WEIGHT + SYNC_CACHED_WEIGHT_PER_DEX * dexes as u64) as f64;
            assert!(
                reads + cached <= SYNC_WEIGHT_PER_MINUTE as f64 + 1e-9,
                "{dexes}"
            );
        }
    }

    #[test]
    fn what_a_forwarded_request_costs_the_venue() {
        use zunder_guard_core::action::{Cancel, OrderRef};
        let cancels = |n: u64| {
            Action::Cancel(
                (0..n)
                    .map(|oid| Cancel {
                        asset: 0,
                        order: OrderRef::Oid(oid),
                    })
                    .collect(),
            )
        };
        let forward = |pre: Vec<Action>, action: Action, post: Vec<Action>| Forward {
            pre,
            action,
            expires_after: None,
            status_map: Vec::new(),
            entry: None,
            post,
            post_after: Vec::new(),
        };
        // One cancel: 1. 39 in a batch: 1; 40: 2; 80: 3.
        assert_eq!(forward_weight(&forward(vec![], cancels(1), vec![])), 1);
        assert_eq!(forward_weight(&forward(vec![], cancels(39), vec![])), 1);
        assert_eq!(forward_weight(&forward(vec![], cancels(40), vec![])), 2);
        assert_eq!(forward_weight(&forward(vec![], cancels(80), vec![])), 3);
        // Isolated leverage first (1, and 20 to read it back), the action,
        // and a cancel after: 1 + 20 + 1 + 1 = 23.
        let leverage = Action::UpdateLeverage {
            asset: 0,
            is_cross: false,
            leverage: 5,
        };
        assert_eq!(
            forward_weight(&forward(vec![leverage], cancels(1), vec![cancels(1)])),
            23
        );
    }

    #[test]
    fn repeated_flow_batches_and_passthrough_share_the_info_minute_budget() {
        let mut budget = WeightBucket::with(INFO_WEIGHT_PER_SECOND, INFO_WEIGHT_BURST);
        let mut spent = 0;
        for now in (0..60_000).step_by(5_000) {
            // A concurrent public /info read, then a two-dex reconstruction.
            // Failed/timeout requests retain their reservation too: there
            // is deliberately no refund on either path.
            for cost in [20, 2, 2, 45, 45, 45] {
                if budget.take(now, cost) {
                    spent += cost;
                }
            }
        }
        assert!(spent <= INFO_WEIGHT_BURST + 60 * INFO_WEIGHT_PER_SECOND);
        assert!(spent < 12 * 139); //Cannot repeatedly send unadmitted batches.
        assert!(!budget.take(55_000, 45));
    }

    #[test]
    fn the_info_bucket_refills_at_its_rate_and_holds_a_burst() {
        let mut bucket = WeightBucket::new();
        // Full: 160 of weight, a userRole (60) and five requests of 20.
        assert!(bucket.take(1_000, 60));
        for _ in 0..5 {
            assert!(bucket.take(1_000, 20));
        }
        assert!(!bucket.take(1_000, 2));
        // 2 a second: 1 s later, 2 of weight.
        assert!(bucket.take(2_000, 2));
        assert!(!bucket.take(2_000, 2));
        // 10 s later: 20.
        assert!(bucket.take(12_000, 20));
        // Never more than the burst, however long it waits.
        assert!(bucket.take(1_000_000, 160));
        assert!(!bucket.take(1_000_000, 1));
        // The request reads: two reads of 24 at once, then one every 6 s
        // (4 a second; 12 of the burst of 60 left over).
        let mut reads = WeightBucket::with(REQUEST_WEIGHT_PER_SECOND, REQUEST_WEIGHT_BURST);
        for _ in 0..2 {
            assert!(reads.take(0, ACCOUNT_READ_WEIGHT));
        }
        assert!(reads.take(0, 12));
        assert!(!reads.take(0, ACCOUNT_READ_WEIGHT));
        assert!(!reads.take(5_999, ACCOUNT_READ_WEIGHT));
        assert!(reads.take(6_000, ACCOUNT_READ_WEIGHT));
        // Charged into debt: 10 owed at 6,000 ms is paid back by 8,500 ms
        // (4 a second), and only then is anything taken again.
        reads.charge(6_000, 10);
        assert!(!reads.take(8_499, 1));
        assert!(reads.take(8_750, 1));
        // The debt goes no deeper than one burst (60): 1,000 charged at
        // once owes 60, paid back in 15 s; 60 more after that.
        reads.charge(9_000, 1_000);
        assert!(!reads.take(23_999, 1));
        assert!(reads.take(24_250, 1));
        assert_eq!(info_weight(Some("l2Book")), 2);
        assert_eq!(info_weight(Some("userRole")), 60);
        assert_eq!(info_weight(Some("candleSnapshot")), 20);
        assert_eq!(info_weight(None), 20);
    }

    /// A share's fractional refill (`ip_share` 0.5, main dex alone: the
    /// request budget 1.530 a second, a burst of 46; `budget.rs`): spent at
    /// 0, one unit of weight is back after 1,000 / 1.53 = 653.6 ms; taking
    /// one a millisecond for a minute gets the burst and 60 × 1.53 = 91.8,
    /// so 137 at most; no refill is lost to the failed tries in between.
    #[test]
    fn a_fractional_refill_is_exact() {
        let budgets = crate::budget::plan(rust_decimal::dec!(0.5), 0).unwrap();
        let mut bucket = WeightBucket::of(budgets.requests);
        assert!(bucket.take(0, 46));
        assert!(!bucket.take(653, 1));
        assert!(bucket.take(654, 1));
        let mut bucket = WeightBucket::of(budgets.requests);
        let taken = (0..60_000).filter(|ms| bucket.take(*ms, 1)).count();
        assert_eq!(taken, 137);
        assert!(taken as u64 * 1_000 <= budgets.requests.worst_minute_milli());
    }
}
