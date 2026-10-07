// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Property tests: random request sequences against an in-memory account.
//!
//! 1. Whatever a bot sends, in any order, nothing Guard forwards breaks a
//!    rule. Each forwarded action is applied to a model of the account
//!    (entries fill at once at their limit price, stops rest, cancels and
//!    modifies take effect), prices stay put, and after every step:
//!    every position has a stop covering all of it; the risk to the stops
//!    is within the open-risk budget; every position is within the
//!    position cap; every forwarded entry is in an allowed market, no
//!    larger than the bot asked for, its loss at the stop within the
//!    per-trade budget, and on isolated leverage within the cap with the
//!    liquidation far enough away; and nothing opens while halted or
//!    killed. The account spans the main dex and HIP-3 dex `xyz`; bots
//!    also aim at dex 2, which Guard does not read: nothing but a cancel
//!    is ever forwarded for it, a HIP-3 entry never needs more margin than
//!    its dex has free, nor more than half the book's depth to its stop.
//! 2. A replayed or reordered request is always refused, a fresh one
//!    accepted at most once.

use fastrand::Rng;
use rust_decimal::{Decimal, dec};
use zunder_core::{Side, Timestamp};

use crate::{
    account::{AccountView, AssetKind, Book, Leverage, OpenOrderView, PositionView, asset_kind},
    action::{
        Action, Cancel, ExchangeRequest, Grouping, Modify, Order, OrderAction, OrderKind, OrderRef,
        Px, Tif, Tpsl,
    },
    auth::tests::{START, authenticator, client_key, signed},
    judge::{Context, HIP3_BOOK_SHARE, Verdict, judge, tests as fixtures},
    policy::{Markets, Policy, StopPolicy},
    sign::SigningNetwork,
};

/// The coins bots aim at: three of the main dex, two of HIP-3 dex `xyz`
/// (read), one of dex 2 (not read: no mid, no meta).
const COINS: [(&str, u32); 6] = [
    ("BTC", 0),
    ("ETH", 1),
    ("SOL", 2),
    ("xyz:GOLD", 110_000),
    ("xyz:TSLA", 110_001),
    ("abc:FOO", 120_000),
];
/// The coins Guard reads.
const READ: usize = 5;

/// The account: `equity` in all, 80% on the main dex, 20% on xyz (all of
/// it free), books for both xyz coins.
fn account(equity: Decimal) -> AccountView {
    let xyz = (equity * dec!(0.2)).round_dp(0);
    let mut account = fixtures::hip3::hip3_account(equity - xyz, xyz, xyz);
    account.books.insert(
        "xyz:TSLA".into(),
        Book {
            bids: vec![(dec!(399.9), dec!(20)), (dec!(380), dec!(50))],
            asks: vec![(dec!(400.1), dec!(20)), (dec!(420), dec!(50))],
            sig_figs: None,
        },
    );
    account
}

fn random_decimal(rng: &mut Rng, low: Decimal, high: Decimal, scale: u32) -> Decimal {
    let steps = ((high - low) * Decimal::from(10u64.pow(scale))).to_string();
    let steps: u64 = steps.split('.').next().unwrap_or("1").parse().unwrap_or(1);
    low + Decimal::new(rng.u64(0..=steps.max(1)) as i64, scale)
}

fn policy(rng: &mut Rng) -> Policy {
    let max_loss_at_stop = random_decimal(rng, dec!(0.002), dec!(0.05), 3);
    let max_leverage = Decimal::from(rng.u32(1..=10));
    let default_stop_distance = random_decimal(rng, dec!(0.005), dec!(0.1), 3);
    let policy = Policy {
        max_leverage,
        max_loss_at_stop,
        max_open_risk: (max_loss_at_stop * Decimal::from(rng.u32(1..=5))).min(dec!(0.2)),
        stop: if rng.bool() {
            StopPolicy::Attach
        } else {
            StopPolicy::Refuse
        },
        default_stop_distance,
        // Beyond the default stop, as validate() demands.
        min_liquidation_distance: default_stop_distance
            + random_decimal(rng, dec!(0.01), dec!(0.2), 2),
        max_position_of_account: random_decimal(rng, dec!(0.1), max_leverage, 1).max(dec!(0.1)),
        markets: match rng.u8(..4) {
            0 => Markets::All,
            1 => Markets::Only(["BTC".to_owned(), "ETH".to_owned()].into()),
            2 => Markets::from_list(["*".to_owned(), "xyz:*".to_owned()]),
            _ => Markets::from_list(["xyz:GOLD".to_owned(), "ETH".to_owned()]),
        },
        ..Policy::default()
    };
    policy.validate().expect("random policy within bounds");
    policy
}

fn random_order(rng: &mut Rng, account: &AccountView) -> (Order, Option<Order>) {
    let (coin, asset) = COINS[rng.usize(..COINS.len())];
    let mid = account.mid(coin).unwrap_or(Decimal::ONE);
    let is_buy = rng.bool();
    let price = (mid * random_decimal(rng, dec!(0.9), dec!(1.1), 3)).round_dp(1);
    let size = random_decimal(rng, dec!(0.001), dec!(20), 3);
    let order = Order {
        asset,
        is_buy,
        price: Px::from_decimal(price).unwrap(),
        size: Px::from_decimal(size).unwrap(),
        reduce_only: rng.u8(..10) == 0,
        kind: if rng.u8(..20) == 0 {
            OrderKind::Trigger {
                is_market: true,
                trigger_px: Px::from_decimal(price).unwrap(),
                tpsl: Tpsl::Sl,
            }
        } else {
            OrderKind::Limit {
                tif: [Tif::Ioc, Tif::Gtc, Tif::Alo][rng.usize(..3)],
            }
        },
        cloid: None,
    };
    let stop = rng.bool().then(|| {
        // Mostly on the losing side, sometimes not.
        let distance = random_decimal(rng, dec!(-0.02), dec!(0.3), 3);
        let trigger = if is_buy {
            mid * (Decimal::ONE - distance)
        } else {
            mid * (Decimal::ONE + distance)
        }
        .round_dp(1)
        .max(dec!(0.1));
        // A third are stop-limits, with their limit on either side of the
        // trigger: some can fill, some never would.
        let is_market = rng.u8(..3) != 0;
        let limit = if is_market {
            trigger
        } else {
            (trigger * random_decimal(rng, dec!(0.9), dec!(1.1), 3))
                .round_dp(1)
                .max(dec!(0.1))
        };
        Order {
            asset,
            is_buy: !is_buy,
            price: Px::from_decimal(limit).unwrap(),
            size: Px::from_decimal(size).unwrap(),
            reduce_only: true,
            kind: OrderKind::Trigger {
                is_market,
                trigger_px: Px::from_decimal(trigger).unwrap(),
                tpsl: Tpsl::Sl,
            },
            cloid: None,
        }
    });
    (order, stop)
}

fn random_action(rng: &mut Rng, account: &AccountView) -> Action {
    let existing: Vec<&OpenOrderView> = account.all_orders().collect();
    match rng.u8(..10) {
        0..=4 => {
            let (order, stop) = random_order(rng, account);
            let mut orders = vec![order];
            orders.extend(stop);
            if rng.u8(..4) == 0 {
                orders.reverse();
            }
            Action::Order(OrderAction {
                orders,
                grouping: [Grouping::Na, Grouping::NormalTpsl][rng.usize(..2)],
                builder: None,
            })
        }
        5 if !existing.is_empty() => {
            let order = existing[rng.usize(..existing.len())];
            Action::Cancel(vec![Cancel {
                asset: COINS
                    .iter()
                    .find(|(coin, _)| *coin == order.coin)
                    .map_or(0, |c| c.1),
                order: OrderRef::Oid(order.oid),
            }])
        }
        6 if !existing.is_empty() => {
            let order = existing[rng.usize(..existing.len())];
            let asset = COINS
                .iter()
                .find(|(coin, _)| *coin == order.coin)
                .map_or(0, |c| c.1);
            let trigger = (order.trigger.map_or(order.limit_px, |(px, _)| px)
                * random_decimal(rng, dec!(0.9), dec!(1.1), 3))
            .round_dp(1);
            Action::Modify(Modify {
                oid: OrderRef::Oid(order.oid),
                order: Order {
                    asset,
                    is_buy: order.side == Side::Buy,
                    price: Px::from_decimal(trigger).unwrap(),
                    size: Px::from_decimal(
                        (order.qty * random_decimal(rng, dec!(0.5), dec!(1.5), 2)).round_dp(4),
                    )
                    .unwrap(),
                    reduce_only: rng.u8(..5) != 0,
                    kind: if order.trigger.is_some() || rng.bool() {
                        OrderKind::Trigger {
                            // Sometimes a stop-limit whose limit (the
                            // price above) may lie on the wrong side.
                            is_market: rng.u8(..3) != 0,
                            trigger_px: Px::from_decimal(
                                (trigger * random_decimal(rng, dec!(0.95), dec!(1.05), 3))
                                    .round_dp(1)
                                    .max(dec!(0.1)),
                            )
                            .unwrap(),
                            tpsl: Tpsl::Sl,
                        }
                    } else {
                        OrderKind::Limit { tif: Tif::Gtc }
                    },
                    cloid: None,
                },
            })
        }
        7 => Action::UpdateLeverage {
            asset: COINS[rng.usize(..COINS.len())].1,
            is_cross: rng.u8(..4) == 0,
            leverage: rng.u32(1..=12),
        },
        8 => Action::UpdateIsolatedMargin {
            asset: COINS[rng.usize(..COINS.len())].1,
            is_buy: true,
            ntli: rng.i64(-5_000_000..5_000_000),
        },
        _ => Action::ScheduleCancel {
            time: rng.bool().then_some(START),
        },
    }
}

/// The model of the venue: apply a forwarded action. Prices stay at their
/// mids. An order that would trade at or through the mid fills at once at
/// its limit price (never better than the mid for the bot); one that would
/// not rests, an entry with its TP/SL waiting as children.
struct Venue {
    account: AccountView,
    next_oid: u64,
    /// Leverage set per coin by `updateLeverage`.
    leverage: Vec<(String, u32)>,
}

impl Venue {
    fn coin(&self, asset: u32) -> String {
        self.account.meta.by_index(asset).unwrap().name.clone()
    }

    fn rest(&mut self, order: &Order) -> OpenOrderView {
        self.next_oid += 1;
        OpenOrderView {
            oid: self.next_oid,
            cloid: order.cloid.as_ref().map(|cloid| cloid.normalized()),
            coin: self.coin(order.asset),
            side: if order.is_buy { Side::Buy } else { Side::Sell },
            qty: order.size.value(),
            limit_px: order.price.value(),
            reduce_only: order.reduce_only,
            trigger: match &order.kind {
                OrderKind::Trigger {
                    trigger_px, tpsl, ..
                } => Some((trigger_px.value(), *tpsl)),
                OrderKind::Limit { .. } => None,
            },
            is_market: matches!(
                order.kind,
                OrderKind::Trigger {
                    is_market: true,
                    ..
                }
            ),
            is_position_tpsl: false,
            children: Vec::new(),
        }
    }

    fn marketable(&self, order: &Order) -> bool {
        let mid = self.account.mid(&self.coin(order.asset)).unwrap();
        if order.is_buy {
            order.price.value() >= mid
        } else {
            order.price.value() <= mid
        }
    }

    fn fill(&mut self, order: &Order) {
        let coin = self.coin(order.asset);
        let side = if order.is_buy { Side::Buy } else { Side::Sell };
        let qty = order.size.value();
        let price = order.price.value();
        let leverage = self
            .leverage
            .iter()
            .find(|(c, _)| *c == coin)
            .map_or(1, |(_, value)| *value);
        match self.account.positions.iter_mut().find(|p| p.coin == coin) {
            Some(position) if position.side == side => {
                if order.reduce_only {
                    return;
                }
                let total = position.qty + qty;
                position.entry = (position.entry * position.qty + price * qty) / total;
                position.qty = total;
            }
            Some(position) => {
                position.qty -= qty.min(position.qty);
            }
            None if !order.reduce_only => self.account.positions.push(PositionView {
                coin,
                side,
                qty,
                entry: price,
                leverage: Leverage {
                    isolated: true,
                    value: leverage,
                },
                liquidation_px: None,
            }),
            None => {}
        }
        self.account
            .positions
            .retain(|position| position.qty > Decimal::ZERO);
        // Reduce-only orders of closed positions go with them.
        let open: Vec<String> = self
            .account
            .positions
            .iter()
            .map(|p| p.coin.clone())
            .collect();
        self.account
            .open_orders
            .retain(|order| !order.reduce_only || open.contains(&order.coin));
    }

    fn place(&mut self, order: &Order) {
        match order.kind {
            OrderKind::Limit { .. } if self.marketable(order) => self.fill(order),
            _ => {
                let resting = self.rest(order);
                self.account.open_orders.push(resting);
            }
        }
    }

    fn apply(&mut self, action: &Action) {
        match action {
            Action::Order(order) => {
                let entry_with_children = order.grouping == Grouping::NormalTpsl
                    && order.orders.first().is_some_and(|first| !first.reduce_only);
                if entry_with_children {
                    let (entry, children) = order.orders.split_first().unwrap();
                    if self.marketable(entry) {
                        self.fill(entry);
                        for child in children {
                            let resting = self.rest(child);
                            self.account.open_orders.push(resting);
                        }
                    } else {
                        let mut parent = self.rest(entry);
                        for child in children {
                            let resting = self.rest(child);
                            parent.children.push(resting);
                        }
                        self.account.open_orders.push(parent);
                    }
                } else {
                    for placed in &order.orders {
                        self.place(placed);
                    }
                }
            }
            Action::Cancel(cancels) | Action::CancelByCloid(cancels) => {
                for cancel in cancels {
                    let oid = match &cancel.order {
                        OrderRef::Oid(oid) => Some(*oid),
                        OrderRef::Cloid(cloid) => {
                            self.account.order_by_cloid(cloid.as_str()).map(|o| o.oid)
                        }
                    };
                    if let Some(oid) = oid {
                        self.account.open_orders.retain(|order| order.oid != oid);
                        for order in &mut self.account.open_orders {
                            order.children.retain(|child| child.oid != oid);
                        }
                    }
                }
            }
            Action::Modify(modify) => self.modify(modify),
            Action::BatchModify(modifies) => modifies.iter().for_each(|m| self.modify(m)),
            Action::UpdateLeverage {
                asset, leverage, ..
            } => {
                let coin = self.coin(*asset);
                self.leverage.retain(|(c, _)| *c != coin);
                self.leverage.push((coin, *leverage));
            }
            Action::UpdateIsolatedMargin { .. } | Action::ScheduleCancel { .. } => {}
        }
    }

    fn modify(&mut self, modify: &Modify) {
        let OrderRef::Oid(oid) = modify.oid else {
            return;
        };
        let replacement = self.rest(&modify.order);
        for order in &mut self.account.open_orders {
            if order.oid == oid {
                let children = std::mem::take(&mut order.children);
                *order = OpenOrderView {
                    oid,
                    children,
                    ..replacement.clone()
                };
            }
            for child in &mut order.children {
                if child.oid == oid {
                    *child = OpenOrderView {
                        oid,
                        ..replacement.clone()
                    };
                }
            }
        }
    }
}

/// `(1/L - l) / (1 -+ l)`: the liquidation distance of an isolated
/// position at leverage `L` with the venue's maximum `max`.
fn liquidation_distance(leverage: u32, max: u32, side: Side) -> Decimal {
    let l = Decimal::ONE / Decimal::from(2 * max);
    let room = Decimal::ONE / Decimal::from(leverage) - l;
    match side {
        Side::Buy => room / (Decimal::ONE - l),
        Side::Sell => room / (Decimal::ONE + l),
    }
}

#[test]
fn no_sequence_of_requests_makes_guard_forward_a_rule_break() {
    let mut forwarded_entries = 0;
    let mut hip3_entries = 0;
    let mut vetoes = 0;
    for seed in 0..300u64 {
        let mut rng = Rng::with_seed(seed);
        let policy = policy(&mut rng);
        let equity = random_decimal(&mut rng, dec!(200), dec!(50000), 0);
        let mut engine = fixtures::engine(&policy, equity);
        let killed = rng.u8(..10) == 0;
        if rng.u8(..10) == 0 {
            // Halted for the day.
            engine.observe(
                Timestamp::from_millis(1_791_000_100_000),
                equity * (Decimal::ONE - policy.daily_loss_stop),
            );
        }
        let mut venue = Venue {
            account: account(equity),
            next_oid: 1_000,
            leverage: Vec::new(),
        };
        for step in 0..40 {
            let action = random_action(&mut rng, &venue.account);
            let request = ExchangeRequest {
                action: action.clone(),
                nonce: 1,
                signature: crate::sign::Signature {
                    r: [0; 32],
                    s: [0; 32],
                    v: 27,
                },
                expires_after: None,
            };
            let decision = judge(
                &Context {
                    policy: &policy,
                    engine: &engine,
                    account: &venue.account,
                    killed,
                    builder: None,
                    salt: b"test",
                },
                &request,
            );
            let Some(forward) = decision.forward.clone() else {
                assert_eq!(decision.verdict, Verdict::Veto);
                vetoes += 1;
                continue;
            };
            let context = format!("seed {seed} step {step}: {action:?} -> {decision:?}");
            if let Some(entry) = &forward.entry {
                forwarded_entries += 1;
                assert!(!killed, "{context}");
                assert_eq!(engine.state(), zunder_risk::RiskState::Active, "{context}");
                assert!(policy.markets.allows(&entry.coin), "{context}");
                let asset = venue.account.meta.by_name(&entry.coin).unwrap();
                let mid = venue.account.mid(&entry.coin).unwrap();
                // Not larger than asked.
                let Action::Order(sent) = &action else {
                    panic!("{context}")
                };
                let asked = sent
                    .orders
                    .iter()
                    .find(|o| !o.reduce_only)
                    .unwrap()
                    .size
                    .value();
                assert!(entry.qty <= asked, "{context}");
                // Loss at the stop, costs included, within the budget.
                let distance = match entry.side {
                    Side::Buy => entry.worst_price - entry.stop,
                    Side::Sell => entry.stop - entry.worst_price,
                };
                assert!(distance > Decimal::ZERO, "{context}");
                let cost = policy
                    .round_trip_cost_scaled(entry.worst_price, asset.fee_scale)
                    .unwrap();
                assert!(
                    entry.qty * (distance + cost) <= equity * policy.max_loss_at_stop,
                    "{context}"
                );
                // The worst fill within the bound of the mid.
                let off = (entry.worst_price - mid).abs() / mid;
                let pulled_in = match entry.side {
                    Side::Buy => {
                        entry.worst_price <= mid * (Decimal::ONE + policy.entry_price_bound)
                    }
                    Side::Sell => {
                        entry.worst_price >= mid * (Decimal::ONE - policy.entry_price_bound)
                    }
                };
                assert!(pulled_in, "{context}: {off}");
                // Isolated, within the caps, the liquidation far enough.
                let leverage = forward
                    .pre
                    .iter()
                    .find_map(|pre| match pre {
                        Action::UpdateLeverage {
                            is_cross, leverage, ..
                        } => {
                            assert!(!is_cross, "{context}");
                            Some(*leverage)
                        }
                        _ => None,
                    })
                    .or_else(|| {
                        venue
                            .account
                            .position(&entry.coin)
                            .map(|p| p.leverage.value)
                    })
                    .unwrap();
                assert!(Decimal::from(leverage) <= policy.max_leverage, "{context}");
                assert!(leverage <= asset.max_leverage, "{context}");
                assert!(
                    liquidation_distance(leverage, asset.max_leverage, entry.side)
                        >= policy.min_liquidation_distance,
                    "{context}"
                );
                // A stop goes with it, covering all of it.
                let Action::Order(out) = &forward.action else {
                    panic!("{context}")
                };
                let stop = out
                    .orders
                    .iter()
                    .find(|o| o.protective_level() == Some(entry.stop))
                    .unwrap_or_else(|| panic!("{context}: no stop at {}", entry.stop));
                assert!(
                    stop.reduce_only && stop.size.value() >= entry.qty,
                    "{context}"
                );
                // A HIP-3 entry: within its dex's free margin at the leverage
                // set, and with what is held or rests on its side within the
                // book's share down to the stop's worst fill.
                if asset.dex != 0 {
                    hip3_entries += 1;
                    let dex = venue.account.dex_account(asset.dex).unwrap();
                    let free = dex.withdrawable.unwrap();
                    assert!(
                        entry.qty * entry.worst_price <= free * Decimal::from(leverage),
                        "{context}: margin"
                    );
                    let worst_exit = match entry.side {
                        Side::Buy => entry.stop * (Decimal::ONE - policy.stop_slippage),
                        Side::Sell => entry.stop * (Decimal::ONE + policy.stop_slippage),
                    };
                    let depth = venue.account.books[&entry.coin]
                        .exit_depth(entry.side, entry.stop, worst_exit)
                        .unwrap();
                    let held = venue
                        .account
                        .position(&entry.coin)
                        .filter(|p| p.side == entry.side)
                        .map_or(Decimal::ZERO, |p| p.qty)
                        + venue
                            .account
                            .open_orders
                            .iter()
                            .filter(|o| {
                                o.coin == entry.coin && o.is_opening() && o.side == entry.side
                            })
                            .map(|o| o.qty)
                            .sum::<Decimal>();
                    assert!(
                        entry.qty + held <= depth * HIP3_BOOK_SHARE,
                        "{context}: book"
                    );
                }
            } else if let Action::Order(out) = &forward.action {
                // No entry: nothing that could open a position.
                assert!(out.orders.iter().all(|o| o.reduce_only), "{context}");
            }
            // Never a larger size than the bot asked for, order by order
            // (Guard's own attached stop is not one of the bot's).
            match (&action, &forward.action) {
                (Action::Order(asked), Action::Order(sent)) => {
                    for (index, requested) in asked.orders.iter().enumerate() {
                        let at = forward.status_map.get(index).copied().unwrap_or(index);
                        let out = &sent.orders[at];
                        assert!(out.size.value() <= requested.size.value(), "{context}");
                    }
                }
                (asked, sent) => {
                    // Forwarded as asked, but for a market stop's limit,
                    // which Guard only ever widens, and a modify of Guard's
                    // own stop that named no client id, which keeps the
                    // stop's.
                    let target_cloid = |oid: &OrderRef| -> Option<String> {
                        match oid {
                            OrderRef::Oid(oid) => venue.account.order_by_oid(*oid),
                            OrderRef::Cloid(cloid) => venue.account.order_by_cloid(cloid.as_str()),
                        }
                        .and_then(|order| order.cloid.clone())
                    };
                    let widened_only = |asked: &Order, sent: &Order, target: Option<String>| {
                        let mut same = asked.clone();
                        same.price = sent.price.clone();
                        if asked.cloid.is_none()
                            && let Some(cloid) = &sent.cloid
                            && crate::judge::is_guard_cloid(cloid.as_str())
                            && target.as_deref() == Some(cloid.normalized().as_str())
                        {
                            same.cloid = sent.cloid.clone();
                        }
                        same == *sent
                            && (asked.price == sent.price
                                || (asked.is_market_stop()
                                    && if asked.is_buy {
                                        sent.price.value() > asked.price.value()
                                    } else {
                                        sent.price.value() < asked.price.value()
                                    }))
                    };
                    match (asked, sent) {
                        (Action::Modify(a), Action::Modify(b)) => {
                            assert_eq!(a.oid, b.oid, "{context}");
                            assert!(
                                widened_only(&a.order, &b.order, target_cloid(&a.oid)),
                                "{context}"
                            );
                        }
                        (Action::BatchModify(a), Action::BatchModify(b)) => {
                            assert_eq!(a.len(), b.len(), "{context}");
                            for (a, b) in a.iter().zip(b) {
                                assert_eq!(a.oid, b.oid, "{context}");
                                assert!(
                                    widened_only(&a.order, &b.order, target_cloid(&a.oid)),
                                    "{context}"
                                );
                            }
                        }
                        (asked, sent) => assert_eq!(asked, sent, "{context}"),
                    }
                }
            }
            // Nothing but a cancel ever goes to a dex Guard does not read.
            let named = |action: &Action| -> Vec<u32> {
                match action {
                    Action::Order(order) => order.orders.iter().map(|o| o.asset).collect(),
                    Action::Modify(modify) => vec![modify.order.asset],
                    Action::BatchModify(modifies) => {
                        modifies.iter().map(|m| m.order.asset).collect()
                    }
                    Action::UpdateLeverage { asset, .. }
                    | Action::UpdateIsolatedMargin { asset, .. } => vec![*asset],
                    Action::Cancel(_)
                    | Action::CancelByCloid(_)
                    | Action::ScheduleCancel { .. } => Vec::new(),
                }
            };
            for sent in forward
                .pre
                .iter()
                .chain(std::iter::once(&forward.action))
                .chain(&forward.post)
            {
                for asset in named(sent) {
                    let read = match asset_kind(asset) {
                        AssetKind::MainPerp => true,
                        AssetKind::Hip3 { dex } => {
                            venue.account.meta.dex(dex).is_some_and(|read| {
                                policy.markets.hip3_dexes().contains(&read.name)
                            })
                        }
                        _ => false,
                    };
                    assert!(
                        read,
                        "{context}: asset {asset} on a dex Guard does not read"
                    );
                }
            }
            for pre in &forward.pre {
                venue.apply(pre);
            }
            venue.apply(&forward.action);
            for post in &forward.post {
                venue.apply(post);
            }

            // The account after the step.
            let budget = equity * policy.max_open_risk;
            let mut risk = Decimal::ZERO;
            for position in &venue.account.positions {
                let stop = venue.account.covering_stop(&position.coin, &[]);
                let Some(stop) = stop else {
                    panic!("{context}: {} has no stop", position.coin)
                };
                let mid = venue.account.mid(&position.coin).unwrap();
                let distance = match position.side {
                    Side::Buy => mid - stop,
                    Side::Sell => stop - mid,
                };
                risk += position.qty * distance.max(Decimal::ZERO);
            }
            // The position cap, counting what resting entries could add.
            for (coin, _) in &COINS[..READ] {
                let coin = *coin;
                let mid = venue.account.mid(coin).unwrap();
                for side in [Side::Buy, Side::Sell] {
                    let held = venue
                        .account
                        .position(coin)
                        .filter(|position| position.side == side)
                        .map_or(Decimal::ZERO, |position| position.qty * mid);
                    let resting: Decimal = venue
                        .account
                        .open_orders
                        .iter()
                        .filter(|o| o.coin == coin && o.is_opening() && o.side == side)
                        .map(|o| o.qty * o.limit_px.max(mid))
                        .sum();
                    assert!(
                        held + resting <= equity * policy.max_position_of_account,
                        "{context}: position cap in {coin}"
                    );
                }
            }
            // Resting entries count at their limit and waiting stop.
            let resting = venue
                .account
                .resting_entry_exposure()
                .unwrap_or_else(|oid| {
                    panic!(
                        "{context}: entry {oid} rests without a stop: {:#?}",
                        venue.account.open_orders
                    )
                });
            risk += resting.risk;
            assert!(risk <= budget, "{context}: risk {risk} over {budget}");
            // Guard's own orders (protection, flattening) only touch the
            // dexes it reads.
            let (protect, _, _) =
                crate::judge::protect_actions(&venue.account, &policy, &engine, b"t", 1);
            let (flatten, _) = crate::reply::flatten_actions(&venue.account, &policy);
            for action in protect
                .iter()
                .map(|(_, action)| action)
                .chain(flatten.iter())
            {
                let assets: Vec<u32> = match action {
                    Action::Order(order) => order.orders.iter().map(|o| o.asset).collect(),
                    Action::Cancel(cancels) => cancels.iter().map(|c| c.asset).collect(),
                    _ => Vec::new(),
                };
                for asset in assets {
                    assert!(
                        COINS[..READ].iter().any(|(_, id)| *id == asset),
                        "{context}: Guard's own order on asset {asset}"
                    );
                }
            }
        }
    }
    // The generator reaches both sides.
    assert!(forwarded_entries > 100, "{forwarded_entries}");
    assert!(hip3_entries > 20, "{hip3_entries}");
    assert!(vetoes > 1_000, "{vetoes}");
}

#[test]
fn replays_are_always_refused() {
    for seed in 0..200u64 {
        let mut rng = Rng::with_seed(seed);
        let mut auth = authenticator();
        let key = client_key();
        let mut sent: Vec<ExchangeRequest> = Vec::new();
        let mut accepted: Vec<u64> = Vec::new();
        let mut now = START + 10_000;
        for _ in 0..60 {
            now += rng.u64(0..2_000);
            let request = if !sent.is_empty() && rng.u8(..3) == 0 {
                // Replay anything sent before, accepted or not.
                sent[rng.usize(..sent.len())].clone()
            } else {
                let nonce = now - 40_000 + rng.u64(0..50_000);
                signed(
                    &key,
                    [SigningNetwork::Testnet, SigningNetwork::Mainnet][rng.usize(..2)],
                    Action::ScheduleCancel { time: None },
                    nonce,
                    None,
                )
            };
            sent.push(request.clone());
            if let Ok(ok) = auth.authenticate(&request, now) {
                // Never accepted twice, always above everything accepted.
                assert!(
                    !accepted.contains(&ok.nonce),
                    "seed {seed}: replay of {}",
                    ok.nonce
                );
                assert!(
                    accepted.iter().all(|nonce| *nonce < ok.nonce),
                    "seed {seed}"
                );
                assert!(
                    ok.nonce + 30_000 >= now && ok.nonce <= now + 5_000,
                    "seed {seed}"
                );
                accepted.push(ok.nonce);
            }
        }
        // Every accepted request, replayed now, is refused.
        for request in &sent {
            if accepted.contains(&request.nonce) {
                assert!(auth.authenticate(request, now).is_err(), "seed {seed}");
            }
        }
    }
}
