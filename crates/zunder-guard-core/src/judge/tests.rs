// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The judge with hand-computed numbers. Every case starts from an account
//! of 10,000 USDC in standard mode, mids BTC 60,000, ETH 3,000 and SOL
//! 150, the venue's `meta` of `account::tests::meta_json` (BTC: 5 size
//! decimals, 40x; ETH: 4, 25x; SOL: 2, 20x) and the default policy (2% per
//! trade, 6% open risk, 5x, 200% per position, 10% to liquidation, a 2%
//! default stop, fees 4.5 bp and slippage 1 bp per side).

use rust_decimal::dec;
use zunder_core::Timestamp;

use super::*;
use crate::{
    account::{Leverage, Meta, OpenOrderView, PositionView, tests::meta_json},
    action::{Cloid, Tif},
    policy::Markets,
};

const BTC: u32 = 0;
const ETH: u32 = 1;
const SOL: u32 = 2;

pub(crate) fn account(equity: Decimal) -> AccountView {
    AccountView {
        at_ms: 0,
        equity: Some(equity),
        mode: "disabled".into(),
        positions: Vec::new(),
        open_orders: Vec::new(),
        mids: [
            ("BTC".to_owned(), dec!(60000)),
            ("ETH".to_owned(), dec!(3000)),
            ("SOL".to_owned(), dec!(150)),
        ]
        .into(),
        meta: Meta::parse(&meta_json()).unwrap(),
        ..AccountView::default()
    }
}

pub(crate) fn engine(policy: &Policy, equity: Decimal) -> RiskEngine {
    RiskEngine::new(
        policy.risk_limits(),
        Timestamp::from_millis(1_791_000_000_000),
        equity,
    )
    .unwrap()
}

pub(crate) fn limit(asset: u32, is_buy: bool, price: &str, size: &str, tif: Tif) -> Order {
    Order {
        asset,
        is_buy,
        price: Px::parse(price).unwrap(),
        size: Px::parse(size).unwrap(),
        reduce_only: false,
        kind: OrderKind::Limit { tif },
        cloid: None,
    }
}

/// A reduce-only market stop loss whose limit lies at Guard's worst fill,
/// 10% beyond the trigger (as Guard would widen it).
pub(crate) fn stop_loss(asset: u32, is_buy: bool, trigger: &str, size: &str) -> Order {
    let at: Decimal = trigger.parse().unwrap();
    let limit = if is_buy {
        at * dec!(1.1)
    } else {
        at * dec!(0.9)
    };
    Order {
        asset,
        is_buy,
        price: Px::from_decimal(limit.normalize()).unwrap(),
        size: Px::parse(size).unwrap(),
        reduce_only: true,
        kind: OrderKind::Trigger {
            is_market: true,
            trigger_px: Px::parse(trigger).unwrap(),
            tpsl: Tpsl::Sl,
        },
        cloid: None,
    }
}

fn request(action: Action) -> ExchangeRequest {
    ExchangeRequest {
        action,
        nonce: 1,
        signature: crate::sign::Signature {
            r: [0; 32],
            s: [0; 32],
            v: 27,
        },
        expires_after: None,
    }
}

fn orders(orders: Vec<Order>, grouping: Grouping) -> ExchangeRequest {
    request(Action::Order(OrderAction {
        orders,
        grouping,
        builder: None,
    }))
}

fn judged(policy: &Policy, account: &AccountView, request: &ExchangeRequest) -> Decision {
    let engine = engine(policy, account.equity.unwrap_or(dec!(1)));
    judge(
        &Context {
            policy,
            engine: &engine,
            account,
            killed: false,
            builder: None,
            salt: b"test",
        },
        request,
    )
}

fn forwarded_orders(decision: &Decision) -> &OrderAction {
    match &decision.forward.as_ref().expect("forwarded").action {
        Action::Order(order) => order,
        other => panic!("{other:?}"),
    }
}

/// An ETH long of 10 at 3,000, isolated 5x, covered by a stop at 2,940.
fn eth_long_with_stop(account: &mut AccountView) {
    account.positions.push(PositionView {
        coin: "ETH".into(),
        side: Side::Buy,
        qty: dec!(10),
        entry: dec!(3000),
        leverage: Leverage {
            isolated: true,
            value: 5,
        },
        liquidation_px: Some(dec!(2450)),
    });
    account.open_orders.push(OpenOrderView {
        oid: 100,
        cloid: None,
        coin: "ETH".into(),
        side: Side::Sell,
        qty: dec!(10),
        limit_px: dec!(2646),
        reduce_only: true,
        trigger: Some((dec!(2940), Tpsl::Sl)),
        is_market: true,
        is_position_tpsl: false,
        children: Vec::new(),
    });
}

#[test]
fn an_entry_without_a_stop_gets_one_and_is_sized_from_it() {
    // Buy 10 ETH at 3,000 (the mid), IOC, no stop.
    // Attached stop: 3,000 * 0.98 = 2,940. Cost per unit: 3,000 * 5.5 bp
    // * 2 = 3.3. Risk per unit: 60 + 3.3 = 63.3. Budget: 2% of 10,000 =
    // 200, so 200 / 63.3 = 3.15955... ETH, down to the 0.0001 step: 3.1595.
    // Position cap: 20,000 / 3,000 = 6.67; leverage room 50,000 / 3,000.
    let policy = Policy::default();
    let decision = judged(
        &policy,
        &account(dec!(10000)),
        &orders(vec![limit(ETH, true, "3000", "10", Tif::Ioc)], Grouping::Na),
    );
    assert_eq!(decision.verdict, Verdict::Resize, "{decision:?}");
    let forward = decision.forward.as_ref().unwrap();
    let action = forwarded_orders(&decision);
    assert_eq!(action.grouping, Grouping::NormalTpsl);
    let (entry, stop) = (&action.orders[0], &action.orders[1]);
    assert_eq!(entry.size.value(), dec!(3.1595));
    assert_eq!(entry.price.raw(), "3000");
    assert!(!entry.reduce_only);
    assert_eq!(stop.stop_trigger(), Some(dec!(2940)));
    assert!(stop.reduce_only && !stop.is_buy);
    assert_eq!(stop.size.value(), dec!(3.1595));
    assert!(stop.cloid.as_ref().unwrap().as_str().starts_with("0x7a67"));
    // The stop's worst fill: 2,940 * 0.90 = 2,646 (10% stop slippage).
    assert_eq!(stop.price.value(), dec!(2646));
    // Loss at the stop, costs included: 3.1595 * 63.3 = 199.99635 <= 200.
    assert!(dec!(3.1595) * dec!(63.3) <= dec!(200));
    // Isolated leverage: the stop's worst fill is 354 / 3,000 = 11.8%
    // below; with 10% of that as room and 5% for funding the liquidation
    // must lie 17.98% away (more than the policy's 10%). ETH's maintenance
    // margin at 25x is 2%: at 5x the liquidation lies (0.2 - 0.02) / 0.98 =
    // 18.37% below, enough. 5x is the cap.
    assert_eq!(
        forward.pre,
        vec![Action::UpdateLeverage {
            asset: ETH,
            is_cross: false,
            leverage: 5
        }]
    );
    assert_eq!(forward.status_map, vec![0]);
    assert_eq!(
        forward.entry,
        Some(EntryPlan {
            coin: "ETH".into(),
            side: Side::Buy,
            requested_qty: dec!(10),
            qty: dec!(3.1595),
            worst_price: dec!(3000),
            stop: dec!(2940),
            leverage: Some(5),
        })
    );
}

#[test]
fn an_isolated_setting_the_entry_allows_needs_no_leverage_update() {
    // The entry above allows 5x isolated on ETH (worked out there). The
    // venue shows ETH set to isolated 3x moments ago: kept, nothing sent
    // first, the entry planned at 3x (less leverage, the liquidation
    // further away). The size does not depend on it: 3.1595 as above.
    let policy = Policy::default();
    let request = orders(vec![limit(ETH, true, "3000", "10", Tif::Ioc)], Grouping::Na);
    let with = |isolated: bool, value: u32| {
        let mut account = account(dec!(10000));
        account
            .leverage_settings
            .insert("ETH".to_owned(), Leverage { isolated, value });
        judged(&policy, &account, &request)
    };
    let decision = with(true, 3);
    let forward = decision.forward.as_ref().unwrap();
    assert!(forward.pre.is_empty(), "{forward:?}");
    assert_eq!(forward.entry.as_ref().unwrap().leverage, Some(3));
    assert_eq!(forward.entry.as_ref().unwrap().qty, dec!(3.1595));
    // Exactly 5x: kept as well.
    let decision = with(true, 5);
    assert!(decision.forward.as_ref().unwrap().pre.is_empty());
    // Isolated 7x (above the 5x the stop allows), cross 3x, or 0: set to
    // isolated 5x first, as without a setting.
    for (isolated, value) in [(true, 7), (false, 3), (true, 0)] {
        let decision = with(isolated, value);
        let forward = decision.forward.as_ref().unwrap();
        assert_eq!(
            forward.pre,
            vec![Action::UpdateLeverage {
                asset: ETH,
                is_cross: false,
                leverage: 5
            }],
            "{isolated} {value}"
        );
        assert_eq!(forward.entry.as_ref().unwrap().leverage, Some(5));
    }
}

#[test]
fn an_entry_within_every_rule_is_allowed_unchanged() {
    // Buy 1 ETH at 3,000 with its own stop at 2,940 as normalTpsl: 1 *
    // 63.3 = 63.3 at risk, well within 200.
    let decision = judged(
        &Policy::default(),
        &account(dec!(10000)),
        &orders(
            vec![
                limit(ETH, true, "3000", "1", Tif::Gtc),
                stop_loss(ETH, false, "2940", "1"),
            ],
            Grouping::NormalTpsl,
        ),
    );
    assert_eq!(decision.verdict, Verdict::Allow, "{decision:?}");
    let action = forwarded_orders(&decision);
    assert_eq!(action.orders.len(), 2);
    assert_eq!(action.orders[0].size.raw(), "1");
}

#[test]
fn the_position_cap_binds_before_the_risk_budget_with_a_tight_stop() {
    // Buy 1 BTC at 60,000 with a stop at 59,700: risk per unit 300 + 66
    // (60,000 * 11 bp) = 366, so the engine allows 200 / 366 = 0.54644
    // BTC (32,786 USDC). The position cap is 2 * 10,000 = 20,000 USDC:
    // 20,000 / 60,000 = 0.333333..., down to 0.33333.
    let decision = judged(
        &Policy::default(),
        &account(dec!(10000)),
        &orders(
            vec![
                limit(BTC, true, "60000", "1", Tif::Gtc),
                stop_loss(BTC, false, "59700", "1"),
            ],
            Grouping::NormalTpsl,
        ),
    );
    assert_eq!(decision.verdict, Verdict::Resize);
    let action = forwarded_orders(&decision);
    assert_eq!(action.orders[0].size.value(), dec!(0.33333));
    // The bot's stop follows the entry's size.
    assert_eq!(action.orders[1].size.value(), dec!(0.33333));
    assert!(decision.text.contains("position cap"), "{}", decision.text);
}

#[test]
fn a_limit_far_beyond_the_mid_is_pulled_in() {
    // Buy at 3,200 with the mid at 3,000: the bound is 3,000 * 1.005 =
    // 3,015. The attached stop goes 2% below the mid (the lower of mid and
    // worst fill): 2,940.
    let decision = judged(
        &Policy::default(),
        &account(dec!(10000)),
        &orders(
            vec![limit(ETH, true, "3200", "0.1", Tif::Ioc)],
            Grouping::Na,
        ),
    );
    let action = forwarded_orders(&decision);
    assert_eq!(action.orders[0].price.value(), dec!(3015));
    assert_eq!(action.orders[1].stop_trigger(), Some(dec!(2940)));
    assert!(
        decision
            .changes
            .iter()
            .any(|change| change.contains("pulled in"))
    );
    // A sell below the mid is bounded at 3,000 * 0.995 = 2,985; its stop
    // 2% above the mid: 3,060.
    let decision = judged(
        &Policy::default(),
        &account(dec!(10000)),
        &orders(
            vec![limit(ETH, false, "2500", "0.1", Tif::Ioc)],
            Grouping::Na,
        ),
    );
    let action = forwarded_orders(&decision);
    assert_eq!(action.orders[0].price.value(), dec!(2985));
    assert_eq!(action.orders[1].stop_trigger(), Some(dec!(3060)));
    assert!(action.orders[1].is_buy);
}

#[test]
fn open_risk_and_unprotected_positions_refuse_entries() {
    // The ETH long of 10 risks 10 * (3,000 - 2,940) = 600 = 6% of 10,000:
    // the open-risk budget is used up.
    let mut full = account(dec!(10000));
    eth_long_with_stop(&mut full);
    let entry = orders(
        vec![limit(BTC, true, "60000", "0.01", Tif::Ioc)],
        Grouping::Na,
    );
    let decision = judged(&Policy::default(), &full, &entry);
    assert_eq!(decision.code, "open_risk", "{decision:?}");
    // Without its stop the position has no bounded risk: nothing opens.
    let mut naked = full.clone();
    naked.open_orders.clear();
    assert_eq!(
        judged(&Policy::default(), &naked, &entry).code,
        "unprotected_position"
    );
    // A resting entry without a stop blocks too.
    let mut resting = account(dec!(10000));
    resting.open_orders.push(OpenOrderView {
        oid: 7,
        cloid: None,
        coin: "SOL".into(),
        side: Side::Buy,
        qty: dec!(1),
        limit_px: dec!(140),
        reduce_only: false,
        trigger: None,
        is_market: false,
        is_position_tpsl: false,
        children: Vec::new(),
    });
    assert_eq!(
        judged(&Policy::default(), &resting, &entry).code,
        "unprotected_order"
    );
}

#[test]
fn halts_the_kill_switch_and_the_market_list_refuse_entries_but_not_closes() {
    let policy = Policy::default();
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    let entry = orders(vec![limit(SOL, true, "150", "1", Tif::Ioc)], Grouping::Na);
    let close = orders(
        vec![Order {
            reduce_only: true,
            ..limit(ETH, false, "2990", "10", Tif::Ioc)
        }],
        Grouping::Na,
    );

    // A loss of 6.5% today halts for the day.
    let mut halted_engine = engine(&policy, dec!(10000));
    halted_engine.observe(Timestamp::from_millis(1_791_000_100_000), dec!(9350));
    let judge_with = |engine: &RiskEngine, killed: bool, request: &ExchangeRequest| {
        judge(
            &Context {
                policy: &policy,
                engine,
                account: &held,
                killed,
                builder: None,
                salt: b"test",
            },
            request,
        )
    };
    assert_eq!(
        judge_with(&halted_engine, false, &entry).code,
        "daily_loss_stop"
    );
    assert_eq!(
        judge_with(&halted_engine, false, &close).verdict,
        Verdict::Allow
    );
    // A fall of 25% from the peak stops until a review.
    let mut stopped = engine(&policy, dec!(10000));
    stopped.observe(Timestamp::from_millis(1_791_000_100_000), dec!(7500));
    assert_eq!(judge_with(&stopped, false, &entry).code, "drawdown_halt");
    // The kill switch.
    let active = engine(&policy, dec!(10000));
    assert_eq!(judge_with(&active, true, &entry).code, "kill_switch");
    assert_eq!(judge_with(&active, true, &close).verdict, Verdict::Allow);
    let cancel = request(Action::Cancel(vec![Cancel {
        asset: SOL,
        order: OrderRef::Oid(5),
    }]));
    assert_eq!(judge_with(&active, true, &cancel).verdict, Verdict::Allow);

    // Markets outside the list.
    let only_btc = Policy {
        markets: Markets::Only(["BTC".to_owned()].into()),
        ..Policy::default()
    };
    assert_eq!(
        judged(&only_btc, &account(dec!(10000)), &entry).code,
        "market_not_allowed"
    );
    // Spot and unknown assets.
    let spot = orders(vec![limit(10_107, true, "36", "1", Tif::Ioc)], Grouping::Na);
    assert_eq!(
        judged(&policy, &account(dec!(10000)), &spot).code,
        "unsupported_market"
    );
    let unknown = orders(vec![limit(99, true, "36", "1", Tif::Ioc)], Grouping::Na);
    assert_eq!(
        judged(&policy, &account(dec!(10000)), &unknown).code,
        "unknown_market"
    );
}

#[test]
fn only_a_listed_perp_of_a_dex_guard_reads_gets_through() {
    // Hyperliquid's documented asset ids ("Asset IDs", including HIP-4): spot 10,000 + pair index, a HIP-3 dex's perp 100,000 +
    // 10,000 × dex + index, an outcome side 100,000,000 + 10 × outcome +
    // side. Every action that names an asset, reduce-only or not, and while
    // halted too, is refused for spot and outcomes, and for a HIP-3 dex
    // Guard does not read (here: none, the default markets); a cancel only
    // removes an order and still goes.
    let policy = Policy::default();
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    const SPOT: u32 = 10_107;
    const HIP3: u32 = 110_000;
    const OUTCOME: u32 = 100_000_950;
    let code = |asset: u32| {
        if asset == HIP3 {
            "dex_not_allowed"
        } else {
            "unsupported_market"
        }
    };
    let engine = engine(&policy, dec!(10000));
    let killed = |request: &ExchangeRequest| {
        judge(
            &Context {
                policy: &policy,
                engine: &engine,
                account: &held,
                killed: true,
                builder: None,
                salt: b"test",
            },
            request,
        )
    };
    for asset in [SPOT, HIP3, OUTCOME] {
        let entry = orders(
            vec![limit(asset, true, "0.5", "100", Tif::Ioc)],
            Grouping::Na,
        );
        let mut close = limit(asset, false, "0.4", "100", Tif::Ioc);
        close.reduce_only = true;
        let close = orders(vec![close], Grouping::Na);
        let stop = orders(vec![stop_loss(asset, false, "0.3", "100")], Grouping::Na);
        let modify = request(Action::Modify(Modify {
            oid: OrderRef::Oid(100),
            order: limit(asset, true, "0.5", "100", Tif::Gtc),
        }));
        let leverage = request(Action::UpdateLeverage {
            asset,
            is_cross: false,
            leverage: 1,
        });
        let margin = request(Action::UpdateIsolatedMargin {
            asset,
            is_buy: true,
            ntli: 1_000_000,
        });
        for (what, request) in [
            ("entry", &entry),
            ("reduce-only close", &close),
            ("stop", &stop),
            ("modify", &modify),
            ("updateLeverage", &leverage),
            ("updateIsolatedMargin", &margin),
        ] {
            let decision = judged(&policy, &held, request);
            assert_eq!(decision.code, code(asset), "{asset} {what}");
            assert!(decision.forward.is_none(), "{asset} {what}");
            // Killed: still refused, not let through as a close.
            let decision = killed(request);
            assert_eq!(decision.code, code(asset), "{asset} {what}, killed");
        }
        let cancel = request(Action::Cancel(vec![Cancel {
            asset,
            order: OrderRef::Oid(5),
        }]));
        assert_eq!(judged(&policy, &held, &cancel).verdict, Verdict::Allow);
    }
    // Margin on a main-dex index the venue does not list.
    let margin = request(Action::UpdateIsolatedMargin {
        asset: 99,
        is_buy: true,
        ntli: 1_000_000,
    });
    assert_eq!(judged(&policy, &held, &margin).code, "unknown_market");
    // An id in the HIP-3 range for "dex 0", which has none.
    let margin = request(Action::UpdateIsolatedMargin {
        asset: 100_005,
        is_buy: true,
        ntli: 1_000_000,
    });
    assert_eq!(judged(&policy, &held, &margin).code, "unknown_market");
}

#[test]
fn the_stop_policy_refuse_requires_a_stop() {
    let policy = Policy {
        stop: StopPolicy::Refuse,
        ..Policy::default()
    };
    let decision = judged(
        &policy,
        &account(dec!(10000)),
        &orders(vec![limit(ETH, true, "3000", "1", Tif::Ioc)], Grouping::Na),
    );
    assert_eq!(decision.code, "stop_required");
    // A stop above the mid for a long is no stop.
    let decision = judged(
        &policy,
        &account(dec!(10000)),
        &orders(
            vec![
                limit(ETH, true, "3000", "1", Tif::Ioc),
                stop_loss(ETH, false, "3001", "1"),
            ],
            Grouping::NormalTpsl,
        ),
    );
    assert_eq!(decision.code, "stop_wrong_side");
}

#[test]
fn a_stop_too_far_for_even_1x_is_refused() {
    // Short 0.05 ETH at 3,000 with a stop at 6,000: the stop's worst fill
    // (10% stop slippage) 6,600 is 120% above. Needed: 1.2 * 1.1 + 0.05 =
    // 1.37 of the price; at 1x a short is liquidated (1 - 0.02) / 1.02 =
    // 96% above. The
    // engine sizes it (200 / 3,003.3 = 0.0665 ETH), the liquidation rule
    // refuses it.
    let decision = judged(
        &Policy::default(),
        &account(dec!(10000)),
        &orders(
            vec![
                limit(ETH, false, "3000", "0.05", Tif::Ioc),
                stop_loss(ETH, true, "6000", "0.05"),
            ],
            Grouping::NormalTpsl,
        ),
    );
    assert_eq!(decision.code, "liquidation_too_close", "{decision:?}");
}

#[test]
fn the_min_liquidation_distance_lowers_the_leverage() {
    // Buy 1 ETH at 3,000, stop 2,940. With a min liquidation distance of
    // 50%: (1/L - 0.02) / 0.98 >= 0.5 needs 1/L >= 0.51, L <= 1.96: 1x.
    let policy = Policy {
        min_liquidation_distance: dec!(0.5),
        ..Policy::default()
    };
    let decision = judged(
        &policy,
        &account(dec!(10000)),
        &orders(
            vec![
                limit(ETH, true, "3000", "1", Tif::Gtc),
                stop_loss(ETH, false, "2940", "1"),
            ],
            Grouping::NormalTpsl,
        ),
    );
    assert_eq!(
        decision.forward.unwrap().pre,
        vec![Action::UpdateLeverage {
            asset: ETH,
            is_cross: false,
            leverage: 1
        }]
    );
}

#[test]
fn isolated_leverage_matches_hand_computed_cases() {
    // Long at 100, stop 95, no stop slippage: distance 5%, needed 5.5% +
    // 5% = 10.5%. Venue max 50 (l = 1%): (1/L - 0.01) / 0.99 >= 0.105 ->
    // 1/L >= 0.11395 -> L <= 8.77: 8, but the policy caps at 5.
    assert_eq!(
        isolated_leverage(
            50,
            dec!(5),
            Side::Buy,
            dec!(100),
            dec!(95),
            dec!(0),
            dec!(0.05)
        ),
        Some(5)
    );
    assert_eq!(
        isolated_leverage(
            50,
            dec!(20),
            Side::Buy,
            dec!(100),
            dec!(95),
            dec!(0),
            dec!(0.05)
        ),
        Some(8)
    );
    // Short at 100, stop 105: (1/L - 0.01) / 1.01 >= 0.105 -> 1/L >=
    // 0.11605 -> L <= 8.6: 8.
    assert_eq!(
        isolated_leverage(
            50,
            dec!(20),
            Side::Sell,
            dec!(100),
            dec!(105),
            dec!(0),
            dec!(0.05)
        ),
        Some(8)
    );
    // A min distance of 30% wins over the stop's 10.5%: 1/L >= 0.307 ->
    // L <= 3.26: 3.
    assert_eq!(
        isolated_leverage(
            50,
            dec!(20),
            Side::Buy,
            dec!(100),
            dec!(95),
            dec!(0),
            dec!(0.3)
        ),
        Some(3)
    );
    // A stop on the wrong side.
    assert_eq!(
        isolated_leverage(
            50,
            dec!(5),
            Side::Buy,
            dec!(100),
            dec!(101),
            dec!(0),
            dec!(0.05)
        ),
        None
    );
}

#[test]
fn adding_to_a_position_keeps_its_isolated_leverage_or_refuses() {
    // An ETH long of 5 (15,000 USDC, under the 20,000 cap) with its stop
    // at 2,995: 5 * 5 = 25 at risk. Adding 0.1 with a stop at 2,940 risks
    // 6.33, within every budget, and keeps the position's 5x: at 5x the
    // liquidation is 18.37% away, more than the 17.98% needed; the venue's
    // liquidation price 2,450 is below the stop's worst fill 2,646 and
    // 18% below the mid.
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    held.positions[0].qty = dec!(5);
    held.open_orders[0].qty = dec!(5);
    held.open_orders[0].trigger = Some((dec!(2995), Tpsl::Sl));
    held.positions[0].liquidation_px = Some(dec!(2450));
    let add = orders(
        vec![
            limit(ETH, true, "3000", "0.1", Tif::Ioc),
            stop_loss(ETH, false, "2940", "0.1"),
        ],
        Grouping::NormalTpsl,
    );
    let decision = judged(&Policy::default(), &held, &add);
    assert_eq!(decision.verdict, Verdict::Allow, "{decision:?}");
    // No leverage change while a position is open.
    assert!(decision.forward.unwrap().pre.is_empty());
    // On cross margin: refused.
    let mut cross = held.clone();
    cross.positions[0].leverage.isolated = false;
    assert_eq!(
        judged(&Policy::default(), &cross, &add).code,
        "cross_margin"
    );
    // Liquidation at 2,930 lies above the stop's worst fill (2,940 x 0.9 =
    // 2,646).
    let mut close_liquidation = held.clone();
    close_liquidation.positions[0].liquidation_px = Some(dec!(2930));
    assert_eq!(
        judged(&Policy::default(), &close_liquidation, &add).code,
        "liquidation_too_close"
    );
    // At 2,680 it is 10.7% below the 3,000 mid, beyond the 10% minimum
    // distance, but still above the stop's worst fill of 2,646: refused
    // on that alone. At 2,600 both hold.
    close_liquidation.positions[0].liquidation_px = Some(dec!(2680));
    assert_eq!(
        judged(&Policy::default(), &close_liquidation, &add).code,
        "liquidation_too_close"
    );
    close_liquidation.positions[0].liquidation_px = Some(dec!(2600));
    assert_eq!(
        judged(&Policy::default(), &close_liquidation, &add).verdict,
        Verdict::Allow
    );
}

#[test]
fn closes_are_made_reduce_only_and_flips_refused() {
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    // A plain sell of 4 against the long of 10: a close.
    let decision = judged(
        &Policy::default(),
        &held,
        &orders(vec![limit(ETH, false, "2990", "4", Tif::Ioc)], Grouping::Na),
    );
    assert_eq!(decision.verdict, Verdict::Resize);
    assert!(forwarded_orders(&decision).orders[0].reduce_only);
    // A sell of 12 would turn it into a short.
    let decision = judged(
        &Policy::default(),
        &held,
        &orders(
            vec![limit(ETH, false, "2990", "12", Tif::Ioc)],
            Grouping::Na,
        ),
    );
    assert_eq!(decision.code, "flip");
}

#[test]
fn cancels_may_not_strip_a_position_of_its_stop() {
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    let cancel_stop = request(Action::Cancel(vec![Cancel {
        asset: ETH,
        order: OrderRef::Oid(100),
    }]));
    assert_eq!(
        judged(&Policy::default(), &held, &cancel_stop).code,
        "stop_removed"
    );
    // With a second stop covering all of it at 2,960 the first may go:
    // risk 10 * 40 = 400 <= 600.
    let mut doubled = held.clone();
    let mut second = doubled.open_orders[0].clone();
    second.oid = 101;
    second.trigger = Some((dec!(2960), Tpsl::Sl));
    doubled.open_orders.push(second.clone());
    assert_eq!(
        judged(&Policy::default(), &doubled, &cancel_stop).verdict,
        Verdict::Allow
    );
    // A second stop far away (2,900: 10 * 100 = 1,000 > 600) leaves too
    // much risk: removing the near one loosens it.
    let mut far = held.clone();
    second.trigger = Some((dec!(2900), Tpsl::Sl));
    far.open_orders.push(second);
    assert_eq!(
        judged(&Policy::default(), &far, &cancel_stop).code,
        "stop_loosened"
    );
    // A partial stop does not cover: still refused.
    let mut partial = held.clone();
    let mut small = partial.open_orders[0].clone();
    small.oid = 102;
    small.qty = dec!(5);
    partial.open_orders.push(small);
    assert_eq!(
        judged(&Policy::default(), &partial, &cancel_stop).code,
        "stop_removed"
    );
    // Equity unknown: no budget to measure against, so a cancel may only
    // lower the risk to the stops. With stops at 2,940 and 2,960, dropping
    // the looser 2,940 keeps 10 * 40 = 400: allowed. Dropping the 2,960
    // raises it from 400 to 10 * 60 = 600: refused.
    let mut unknown_equity = doubled.clone();
    unknown_equity.equity = None;
    assert_eq!(
        judged(&Policy::default(), &unknown_equity, &cancel_stop).verdict,
        Verdict::Allow
    );
    let cancel_tighter = request(Action::Cancel(vec![Cancel {
        asset: ETH,
        order: OrderRef::Oid(101),
    }]));
    assert_eq!(
        judged(&Policy::default(), &unknown_equity, &cancel_tighter).code,
        "stop_loosened"
    );
    // A stop-limit is no stop: with only one beside Guard's market stop,
    // the market stop may not go.
    let mut with_stop_limit = held.clone();
    let mut limit_stop = with_stop_limit.open_orders[0].clone();
    limit_stop.oid = 103;
    limit_stop.is_market = false;
    limit_stop.trigger = Some((dec!(2960), Tpsl::Sl));
    limit_stop.limit_px = dec!(2950);
    with_stop_limit.open_orders.push(limit_stop);
    assert_eq!(
        judged(&Policy::default(), &with_stop_limit, &cancel_stop).code,
        "stop_removed"
    );
    // By cloid, and an unknown order passes (the venue will say so).
    let mut by_cloid = held.clone();
    by_cloid.open_orders[0].cloid = Some("0x0000000000000000000000000000000a".into());
    let cancel = request(Action::CancelByCloid(vec![Cancel {
        asset: ETH,
        order: OrderRef::Cloid(Cloid::parse("0x0000000000000000000000000000000A").unwrap()),
    }]));
    assert_eq!(
        judged(&Policy::default(), &by_cloid, &cancel).code,
        "stop_removed"
    );
    let unknown = request(Action::Cancel(vec![Cancel {
        asset: ETH,
        order: OrderRef::Oid(999),
    }]));
    assert_eq!(
        judged(&Policy::default(), &held, &unknown).verdict,
        Verdict::Allow
    );
}

#[test]
fn stops_only_tighten_through_modify() {
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    let modify = |trigger: &str, size: &str| {
        request(Action::Modify(Modify {
            oid: OrderRef::Oid(100),
            order: stop_loss(ETH, false, trigger, size),
        }))
    };
    assert_eq!(
        judged(&Policy::default(), &held, &modify("2950", "10")).verdict,
        Verdict::Allow
    );
    assert_eq!(
        judged(&Policy::default(), &held, &modify("2940", "10")).verdict,
        Verdict::Allow
    );
    assert_eq!(
        judged(&Policy::default(), &held, &modify("2930", "10")).code,
        "stop_loosened"
    );
    assert_eq!(
        judged(&Policy::default(), &held, &modify("2950", "9")).code,
        "stop_loosened"
    );
    let unknown = request(Action::Modify(Modify {
        oid: OrderRef::Oid(5),
        order: stop_loss(ETH, false, "2950", "10"),
    }));
    assert_eq!(
        judged(&Policy::default(), &held, &unknown).code,
        "unknown_order"
    );
    // Into a take profit or a plain order: refused.
    let mut into_limit = limit(ETH, false, "3100", "10", Tif::Gtc);
    into_limit.reduce_only = true;
    let to_limit = request(Action::Modify(Modify {
        oid: OrderRef::Oid(100),
        order: into_limit,
    }));
    assert_eq!(
        judged(&Policy::default(), &held, &to_limit).code,
        "stop_loosened"
    );
}

#[test]
fn leverage_margin_and_scheduled_cancels() {
    let policy = Policy::default();
    let flat = account(dec!(10000));
    let leverage = |is_cross: bool, leverage: u32| {
        request(Action::UpdateLeverage {
            asset: ETH,
            is_cross,
            leverage,
        })
    };
    assert_eq!(
        judged(&policy, &flat, &leverage(false, 3)).verdict,
        Verdict::Allow
    );
    assert_eq!(
        judged(&policy, &flat, &leverage(false, 5)).verdict,
        Verdict::Allow
    );
    assert_eq!(judged(&policy, &flat, &leverage(false, 6)).code, "leverage");
    assert_eq!(
        judged(&policy, &flat, &leverage(true, 3)).code,
        "cross_margin"
    );
    let mut held = flat.clone();
    eth_long_with_stop(&mut held);
    held.positions[0].leverage.value = 3;
    assert_eq!(
        judged(&policy, &held, &leverage(false, 2)).verdict,
        Verdict::Allow
    );
    assert_eq!(judged(&policy, &held, &leverage(false, 4)).code, "leverage");
    let margin = |ntli: i64| {
        request(Action::UpdateIsolatedMargin {
            asset: ETH,
            is_buy: true,
            ntli,
        })
    };
    assert_eq!(
        judged(&policy, &held, &margin(1_000_000)).verdict,
        Verdict::Allow
    );
    assert_eq!(
        judged(&policy, &held, &margin(-1_000_000)).code,
        "margin_removal"
    );
    let schedule = |time| request(Action::ScheduleCancel { time });
    assert_eq!(
        judged(&policy, &held, &schedule(None)).verdict,
        Verdict::Allow
    );
    assert_eq!(
        judged(&policy, &held, &schedule(Some(5))).code,
        "schedule_cancel"
    );
}

#[test]
fn below_the_venue_minimum_is_refused() {
    // 10 USDC of equity: 0.2 / 63.3 = 0.00315 ETH, 0.0031 * 3,000 = 9.3,
    // under the 10 USDC minimum.
    let decision = judged(
        &Policy::default(),
        &account(dec!(10)),
        &orders(vec![limit(ETH, true, "3000", "1", Tif::Ioc)], Grouping::Na),
    );
    assert_eq!(decision.code, "below_minimum", "{decision:?}");
    // The stop counts at its worst fill: 0.0036 ETH with the stop at
    // 2,940 sells at no less than 2,940 x 0.9 = 2,646, 0.0036 x 2,646 =
    // 9.53 USDC, under 10. 0.0038 x 2,646 = 10.05 passes.
    let small = |size: &str| {
        judged(
            &Policy::default(),
            &account(dec!(10000)),
            &orders(vec![limit(ETH, true, "3000", size, Tif::Ioc)], Grouping::Na),
        )
    };
    assert_eq!(small("0.0036").code, "below_minimum");
    assert_eq!(small("0.0038").verdict, Verdict::Resize);
}

#[test]
fn an_unknown_account_mode_refuses_entries() {
    let mut unified = account(dec!(10000));
    unified.equity = None;
    unified.mode = "unifiedAccount".into();
    let decision = judged(
        &Policy::default(),
        &unified,
        &orders(vec![limit(ETH, true, "3000", "1", Tif::Ioc)], Grouping::Na),
    );
    assert_eq!(decision.code, "account_unknown");
}

#[test]
fn a_stop_sent_before_its_entry_in_na_becomes_its_child() {
    // [stop, entry] in "na": forwarded as [entry, stop] normalTpsl; the
    // bot's first status is the venue's second.
    let decision = judged(
        &Policy::default(),
        &account(dec!(10000)),
        &orders(
            vec![
                stop_loss(ETH, false, "2940", "1"),
                limit(ETH, true, "3000", "1", Tif::Gtc),
            ],
            Grouping::Na,
        ),
    );
    let forward = decision.forward.as_ref().unwrap();
    assert_eq!(forward.status_map, vec![1, 0]);
    let action = forwarded_orders(&decision);
    assert_eq!(action.grouping, Grouping::NormalTpsl);
    assert!(!action.orders[0].reduce_only);
    assert!(action.orders[1].reduce_only);
    // Two entries, or an entry with an unrelated order, are refused.
    let two = orders(
        vec![
            limit(ETH, true, "3000", "1", Tif::Gtc),
            limit(SOL, true, "150", "1", Tif::Gtc),
        ],
        Grouping::Na,
    );
    assert_eq!(
        judged(&Policy::default(), &account(dec!(10000)), &two).code,
        "one_entry_per_action"
    );
}

#[test]
fn a_bots_later_stop_replaces_guards_only_when_tighter() {
    // The ETH long of 10 is protected by Guard's attached stop at 2,940.
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    held.open_orders[0].cloid = Some("0x7a6700000000000000000000000000aa".into());
    // Freqtrade's stop on the exchange, sent after the entry: reduce-only,
    // "na". At 2,960 it is tighter and covers all 10: forwarded, and
    // Guard's stop is cancelled once it rests.
    let tighter = judged(
        &Policy::default(),
        &held,
        &orders(vec![stop_loss(ETH, false, "2960", "10")], Grouping::Na),
    );
    assert_eq!(tighter.verdict, Verdict::Resize, "{tighter:?}");
    assert_eq!(
        tighter.forward.as_ref().unwrap().post,
        vec![Action::Cancel(vec![Cancel {
            asset: ETH,
            order: OrderRef::Oid(100)
        }])]
    );
    // At 2,900 it is looser: forwarded too (it only adds protection), but
    // Guard's stays.
    let looser = judged(
        &Policy::default(),
        &held,
        &orders(vec![stop_loss(ETH, false, "2900", "10")], Grouping::Na),
    );
    assert!(looser.forward.as_ref().unwrap().post.is_empty());
    assert!(looser.text.contains("stays"), "{}", looser.text);
    // Tighter but for half the position: Guard's stays.
    let partial = judged(
        &Policy::default(),
        &held,
        &orders(vec![stop_loss(ETH, false, "2960", "5")], Grouping::Na),
    );
    assert!(partial.forward.as_ref().unwrap().post.is_empty());
    // The bot cannot cancel Guard's stop while the position is open.
    let cancel = request(Action::Cancel(vec![Cancel {
        asset: ETH,
        order: OrderRef::Oid(100),
    }]));
    assert_eq!(
        judged(&Policy::default(), &held, &cancel).code,
        "guard_stop"
    );
    // But tighten it, like any stop.
    let modify = request(Action::Modify(Modify {
        oid: OrderRef::Oid(100),
        order: stop_loss(ETH, false, "2950", "10"),
    }));
    assert_eq!(
        judged(&Policy::default(), &held, &modify).verdict,
        Verdict::Allow
    );
}

#[test]
fn both_stop_policies_on_an_entry_without_a_stop() {
    let entry = orders(vec![limit(SOL, true, "150", "10", Tif::Ioc)], Grouping::Na);
    // Attach: sized from the default stop 2% below, 147, and the stop sent
    // with it. Risk per unit 3 + 150 * 11 bp = 3.165; 200 / 3.165 = 63.19
    // SOL; the cap 20,000 / 150 = 133.33; the bot's 10 fits.
    let attach = judged(&Policy::default(), &account(dec!(10000)), &entry);
    let action = forwarded_orders(&attach);
    assert_eq!(action.orders[0].size.value(), dec!(10));
    assert_eq!(action.orders[1].stop_trigger(), Some(dec!(147)));
    // A 5% default stop: 142.5.
    let wider = Policy {
        default_stop_distance: dec!(0.05),
        ..Policy::default()
    };
    let attach = judged(&wider, &account(dec!(10000)), &entry);
    assert_eq!(
        forwarded_orders(&attach).orders[1].stop_trigger(),
        Some(dec!(142.5))
    );
    // Refuse: vetoed.
    let refuse = Policy {
        stop: StopPolicy::Refuse,
        ..Policy::default()
    };
    assert_eq!(
        judged(&refuse, &account(dec!(10000)), &entry).code,
        "stop_required"
    );
}

#[test]
fn only_guards_builder_may_appear() {
    let mut request = orders(
        vec![
            limit(ETH, true, "3000", "1", Tif::Gtc),
            stop_loss(ETH, false, "2940", "1"),
        ],
        Grouping::NormalTpsl,
    );
    if let Action::Order(order) = &mut request.action {
        order.builder = Some(Builder {
            address: "0x6530512a6c89c7cfcebc3ba7fcd9ada5f30827a6".into(),
            fee_tenths_bp: 10,
        });
    }
    // A builder field from the bot (ccxt's, say) is refused.
    let decision = judged(&Policy::default(), &account(dec!(10000)), &request);
    assert_eq!(decision.code, "client_builder");
    if let Action::Order(order) = &mut request.action {
        order.builder = None;
    }
    let decision = judged(&Policy::default(), &account(dec!(10000)), &request);
    assert_eq!(forwarded_orders(&decision).builder, None);
    // Guard's own builder (from the fee mode) is attached.
    let ours = Builder {
        address: "0x00000000000000000000000000000000000000aa".into(),
        fee_tenths_bp: 20,
    };
    let policy = Policy::default();
    let account = account(dec!(10000));
    let engine = engine(&policy, dec!(10000));
    let decision = judge(
        &Context {
            policy: &policy,
            engine: &engine,
            account: &account,
            killed: false,
            builder: Some(&ours),
            salt: b"test",
        },
        &request,
    );
    assert_eq!(forwarded_orders(&decision).builder, Some(ours.clone()));
    // Only on actions with an entry: a close goes without it.
    let mut held = account.clone();
    eth_long_with_stop(&mut held);
    let close = orders(vec![limit(ETH, false, "2990", "4", Tif::Ioc)], Grouping::Na);
    let decision = judge(
        &Context {
            policy: &policy,
            engine: &engine,
            account: &held,
            killed: false,
            builder: Some(&ours),
            salt: b"test",
        },
        &close,
    );
    assert_eq!(forwarded_orders(&decision).builder, None);
    // A close carrying the bot's own builder field is not refused: the field
    // is removed (Guard puts its own on what it sends).
    let mut close = close;
    if let Action::Order(order) = &mut close.action {
        order.builder = Some(Builder {
            address: "0x6530512a6c89c7cfcebc3ba7fcd9ada5f30827a6".into(),
            fee_tenths_bp: 10,
        });
    }
    let decision = judged(&policy, &held, &close);
    assert_ne!(decision.code, "client_builder");
    assert_eq!(forwarded_orders(&decision).builder, None);
    assert!(
        decision
            .changes
            .iter()
            .any(|change| change.contains("builder field")),
        "{:?}",
        decision.changes
    );
}

/// A reduce-only sell stop-limit for ETH.
fn stop_limit(trigger: &str, limit: &str, size: &str) -> Order {
    Order {
        asset: ETH,
        is_buy: false,
        price: Px::parse(limit).unwrap(),
        size: Px::parse(size).unwrap(),
        reduce_only: true,
        kind: OrderKind::Trigger {
            is_market: false,
            trigger_px: Px::parse(trigger).unwrap(),
            tpsl: Tpsl::Sl,
        },
        cloid: None,
    }
}

#[test]
fn a_stop_limit_is_never_protection() {
    // The ETH long of 10 with Guard's market stop at 2,940.
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    held.open_orders[0].cloid = Some("0x7a6700000000000000000000000000aa".into());
    // Guard's stop modified into any stop-limit: refused, however tight.
    // (Trigger 3,100, limit 3,050 above a 3,000 market would trigger at
    // once and rest unfilled while the price falls.)
    for (trigger, limit_px) in [("2950", "3100"), ("2970", "2960"), ("3100", "3050")] {
        let modify = request(Action::Modify(Modify {
            oid: OrderRef::Oid(100),
            order: stop_limit(trigger, limit_px, "10"),
        }));
        assert_eq!(
            judged(&Policy::default(), &held, &modify).code,
            "stop_loosened",
            "{trigger}/{limit_px}"
        );
    }
    // Sent on their own in "na", stop-limits are forwarded (they only
    // reduce) but never replace Guard's market stop: not Freqtrade's kind
    // (2,970 with its limit 1% lower), not one triggering through the
    // market.
    for order in [
        stop_limit("2970", "2940.3", "10"),
        stop_limit("3100", "3050", "10"),
    ] {
        let sent = judged(
            &Policy::default(),
            &held,
            &orders(vec![order], Grouping::Na),
        );
        let forward = sent.forward.unwrap();
        assert!(forward.post.is_empty());
        assert!(
            sent.text.contains("stays") || sent.changes.is_empty(),
            "{}",
            sent.text
        );
    }
    // As an entry's only stop, a stop-limit counts for nothing: under
    // `refuse` the entry is refused, under `attach` Guard adds its own
    // market stop and sizes from it.
    let entry = orders(
        vec![
            limit(SOL, true, "150", "1", Tif::Gtc),
            Order {
                asset: SOL,
                ..stop_limit("147", "145", "1")
            },
        ],
        Grouping::NormalTpsl,
    );
    let refuse = Policy {
        stop: StopPolicy::Refuse,
        ..Policy::default()
    };
    assert_eq!(
        judged(&refuse, &account(dec!(10000)), &entry).code,
        "stop_required"
    );
    let attach = judged(&Policy::default(), &account(dec!(10000)), &entry);
    let action = forwarded_orders(&attach);
    assert_eq!(action.orders.len(), 3);
    assert_eq!(action.orders[2].protective_level(), Some(dec!(147)));
    assert_eq!(action.orders[1].protective_level(), None);
}

#[test]
fn a_waiting_child_stop_never_replaces_guards() {
    // normalTpsl with a reduce-only sell limit at 5,000 as the parent and a
    // stop at 2,960 waiting for it: the stop is not active, Guard's stays.
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    held.open_orders[0].cloid = Some("0x7a6700000000000000000000000000aa".into());
    let mut parent = limit(ETH, false, "5000", "10", Tif::Gtc);
    parent.reduce_only = true;
    let decision = judged(
        &Policy::default(),
        &held,
        &orders(
            vec![parent, stop_loss(ETH, false, "2960", "10")],
            Grouping::NormalTpsl,
        ),
    );
    assert!(decision.forward.unwrap().post.is_empty());
}

#[test]
fn a_position_stop_keeps_covering_the_whole_position() {
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    held.open_orders[0].is_position_tpsl = true;
    held.open_orders[0].qty = dec!(0);
    let modify = |size: &str| {
        request(Action::Modify(Modify {
            oid: OrderRef::Oid(100),
            order: stop_loss(ETH, false, "2950", size),
        }))
    };
    assert_eq!(
        judged(&Policy::default(), &held, &modify("0.0001")).code,
        "stop_loosened"
    );
    assert_eq!(
        judged(&Policy::default(), &held, &modify("10")).verdict,
        Verdict::Allow
    );
}

#[test]
fn leverage_suits_every_entry_resting_on_the_coin() {
    // A GTC buy of 1 ETH resting at 2,990 with its stop waiting at 2,400:
    // the stop's worst fill 2,160 is 27.76% below; needed 27.76% * 1.1 +
    // 5% = 35.54%; (1/L - 0.02) / 0.98 >= 0.3554 -> 1/L >= 0.3683 -> 2x.
    let mut resting = account(dec!(10000));
    resting.open_orders.push(OpenOrderView {
        oid: 7,
        cloid: None,
        coin: "ETH".into(),
        side: Side::Buy,
        qty: dec!(1),
        limit_px: dec!(2990),
        reduce_only: false,
        trigger: None,
        is_market: false,
        is_position_tpsl: false,
        children: vec![OpenOrderView {
            oid: 8,
            cloid: None,
            coin: "ETH".into(),
            side: Side::Sell,
            qty: dec!(1),
            limit_px: dec!(2160),
            reduce_only: true,
            trigger: Some((dec!(2400), Tpsl::Sl)),
            is_market: true,
            is_position_tpsl: false,
            children: Vec::new(),
        }],
    });
    // The bot raising ETH to 5x: refused; 2x passes.
    let leverage = |value| {
        request(Action::UpdateLeverage {
            asset: ETH,
            is_cross: false,
            leverage: value,
        })
    };
    assert_eq!(
        judged(&Policy::default(), &resting, &leverage(5)).code,
        "liquidation_too_close"
    );
    assert_eq!(
        judged(&Policy::default(), &resting, &leverage(2)).verdict,
        Verdict::Allow
    );
    // A new entry with a 2% stop would allow 5x alone; Guard sets 2x.
    let decision = judged(
        &Policy::default(),
        &resting,
        &orders(
            vec![
                limit(ETH, true, "3000", "0.1", Tif::Ioc),
                stop_loss(ETH, false, "2940", "0.1"),
            ],
            Grouping::NormalTpsl,
        ),
    );
    assert_eq!(
        decision.forward.unwrap().pre,
        vec![Action::UpdateLeverage {
            asset: ETH,
            is_cross: false,
            leverage: 2
        }]
    );
}

#[test]
fn a_modify_cannot_make_an_unsized_entry() {
    // A buy trigger for 1 ETH placed elsewhere (trigger 3,100, limit
    // 3,200), and a plain resting buy without a stop.
    let mut placed = account(dec!(10000));
    let trigger = OpenOrderView {
        oid: 9,
        cloid: None,
        coin: "ETH".into(),
        side: Side::Buy,
        qty: dec!(1),
        limit_px: dec!(3200),
        reduce_only: false,
        trigger: Some((dec!(3100), Tpsl::Tp)),
        is_market: false,
        is_position_tpsl: false,
        children: Vec::new(),
    };
    let plain = OpenOrderView {
        oid: 10,
        trigger: None,
        limit_px: dec!(2900),
        ..trigger.clone()
    };
    // And a resting limit buy with its stop waiting (a child at 2,800,
    // limit 2,520): before, a smaller or less aggressive modify of this
    // one was allowed; now every modify of an entry is refused, since the
    // venue may not carry the waiting stop over.
    let with_stop = OpenOrderView {
        oid: 11,
        trigger: None,
        limit_px: dec!(2950),
        children: vec![OpenOrderView {
            oid: 12,
            side: Side::Sell,
            limit_px: dec!(2520),
            reduce_only: true,
            trigger: Some((dec!(2800), Tpsl::Sl)),
            is_market: true,
            children: Vec::new(),
            ..plain.clone()
        }],
        ..plain.clone()
    };
    placed.open_orders.push(trigger);
    placed.open_orders.push(plain);
    placed.open_orders.push(with_stop);
    for (oid, price, size) in [(9, "2800", "1"), (10, "2800", "1"), (11, "2900", "0.5")] {
        let modify = request(Action::Modify(Modify {
            oid: OrderRef::Oid(oid),
            order: limit(ETH, true, price, size, Tif::Gtc),
        }));
        assert_eq!(
            judged(&Policy::default(), &placed, &modify).code,
            "modify_entry",
            "{oid}"
        );
    }
}

#[test]
fn a_reduce_only_order_never_asks_for_more_than_the_position() {
    // The ETH long of 10: a reduce-only sell of 25 is cut to 10; one of 4
    // goes as sent; a stop for 12 is cut to 10.
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    let mut close = limit(ETH, false, "2990", "25", Tif::Ioc);
    close.reduce_only = true;
    let decision = judged(
        &Policy::default(),
        &held,
        &orders(vec![close.clone()], Grouping::Na),
    );
    assert_eq!(decision.verdict, Verdict::Resize, "{decision:?}");
    assert_eq!(forwarded_orders(&decision).orders[0].size.value(), dec!(10));
    close.size = Px::parse("4").unwrap();
    let decision = judged(
        &Policy::default(),
        &held,
        &orders(vec![close], Grouping::Na),
    );
    assert_eq!(forwarded_orders(&decision).orders[0].size.value(), dec!(4));
    // A stop for 12 is left as it is: a stop never needs cutting (the
    // venue cannot flip with it) and the position may have grown since
    // Guard read it.
    let decision = judged(
        &Policy::default(),
        &held,
        &orders(vec![stop_loss(ETH, false, "2950", "12")], Grouping::Na),
    );
    assert_eq!(forwarded_orders(&decision).orders[0].size.value(), dec!(12));
}

#[test]
fn a_fractional_leverage_cap_allows_its_whole_part_on_the_venue() {
    // 2.5x: a new SOL entry gets isolated 2x (the whole part); adding to a
    // 2x position is fine, setting 3x is not. 0.5x: 1x on the venue, and
    // adding to a 1x position is not refused for leverage.
    for (cap, venue) in [(dec!(2.5), 2u32), (dec!(0.5), 1u32)] {
        let policy = Policy {
            max_leverage: cap,
            max_position_of_account: cap.min(dec!(2)),
            ..Policy::default()
        };
        let entry = orders(vec![limit(SOL, true, "150", "1", Tif::Ioc)], Grouping::Na);
        let decision = judged(&policy, &account(dec!(10000)), &entry);
        let pre = &decision.forward.as_ref().unwrap().pre;
        assert_eq!(
            pre,
            &vec![Action::UpdateLeverage {
                asset: SOL,
                is_cross: false,
                leverage: venue
            }],
            "{cap}"
        );
        let set = |leverage: u32| {
            request(Action::UpdateLeverage {
                asset: SOL,
                is_cross: false,
                leverage,
            })
        };
        assert_eq!(
            judged(&policy, &account(dec!(10000)), &set(venue)).verdict,
            Verdict::Allow
        );
        assert_eq!(
            judged(&policy, &account(dec!(10000)), &set(venue + 1)).code,
            "leverage"
        );
    }
}

#[test]
fn a_bots_order_may_not_use_guards_id_prefix() {
    let mut stop = stop_loss(ETH, false, "2940", "10");
    stop.cloid = Some(Cloid::parse("0x7A6700000000000000000000000000aa").unwrap());
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    assert_eq!(
        judged(&Policy::default(), &held, &orders(vec![stop], Grouping::Na)).code,
        "invalid"
    );
}

#[test]
fn guards_stop_ids_depend_on_its_secret() {
    let request = orders(vec![limit(ETH, true, "3000", "1", Tif::Ioc)], Grouping::Na);
    let policy = Policy::default();
    let account = account(dec!(10000));
    let engine = engine(&policy, dec!(10000));
    let cloid = |salt: &[u8]| {
        let decision = judge(
            &Context {
                policy: &policy,
                engine: &engine,
                account: &account,
                killed: false,
                builder: None,
                salt,
            },
            &request,
        );
        forwarded_orders(&decision).orders[1].cloid.clone().unwrap()
    };
    assert_ne!(cloid(b"one"), cloid(b"two"));
    assert_eq!(cloid(b"one"), cloid(b"one"));
}

#[test]
fn guard_never_forwards_more_than_the_bot_asked_for() {
    // Under "attach" the rules would allow 3.1595 ETH (see the first test);
    // the bot asks for 0.5: 0.5 goes, never more.
    let decision = judged(
        &Policy::default(),
        &account(dec!(10000)),
        &orders(
            vec![limit(ETH, true, "3000", "0.5", Tif::Ioc)],
            Grouping::Na,
        ),
    );
    let action = forwarded_orders(&decision);
    assert_eq!(action.orders[0].size.value(), dec!(0.5));
    // A bot stop smaller than its entry cuts the entry to it: 0.3, and the
    // stop stays at its own 0.3.
    let decision = judged(
        &Policy::default(),
        &account(dec!(10000)),
        &orders(
            vec![
                limit(ETH, true, "3000", "0.5", Tif::Gtc),
                stop_loss(ETH, false, "2940", "0.3"),
            ],
            Grouping::NormalTpsl,
        ),
    );
    let action = forwarded_orders(&decision);
    assert_eq!(action.orders[0].size.value(), dec!(0.3));
    assert_eq!(action.orders[1].size.value(), dec!(0.3));
}

#[test]
fn an_unprotected_position_gets_guards_market_stop() {
    // The ETH long of 10 without its stop: Guard's stop 2% below the 3,000
    // mid at 2,940, worst fill 2,940 x 0.9 = 2,646, for all 10.
    let policy = Policy::default();
    let blank = engine(&policy, dec!(10000));
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    held.open_orders.clear();
    let (actions, unpriced, problems) = protect_actions(&held, &policy, &blank, b"test", 7);
    assert!(unpriced.is_empty() && problems.is_empty());
    assert_eq!(actions.len(), 1);
    let Action::Order(order) = &actions[0].1 else {
        panic!("{actions:?}");
    };
    let stop = &order.orders[0];
    assert_eq!(stop.protective_level(), Some(dec!(2940)));
    assert_eq!(stop.price.value(), dec!(2646));
    assert_eq!(stop.size.value(), dec!(10));
    assert!(!stop.is_buy && stop.reduce_only);
    assert!(
        stop.cloid
            .as_ref()
            .unwrap()
            .as_str()
            .starts_with(GUARD_CLOID_PREFIX)
    );
    // The engine recorded the position's stop at 2,970: tighter than 2,940,
    // so that one. One at 2,900 is looser: 2,940. One the price has gone
    // through (at or above the 3,000 mid) is never widened: no stop, the
    // caller closes.
    for (recorded, expected) in [
        ("2970", Some(dec!(2970))),
        ("2900", Some(dec!(2940))),
        ("3000", None),
        ("3050", None),
    ] {
        let mut tracked = engine(&policy, dec!(10000));
        tracked
            .record_entry(
                Symbol::new("ETH"),
                Side::Buy,
                dec!(10),
                dec!(3000),
                recorded.parse().unwrap(),
            )
            .ok();
        let (actions, unpriced, _) = protect_actions(&held, &policy, &tracked, b"test", 7);
        match expected {
            Some(expected) => {
                let Action::Order(order) = &actions[0].1 else {
                    panic!("{actions:?}");
                };
                assert_eq!(
                    order.orders[0].protective_level(),
                    Some(expected),
                    "{recorded}"
                );
            }
            None => {
                assert!(actions.is_empty(), "{recorded}");
                assert_eq!(unpriced, vec!["ETH".to_owned()], "{recorded}");
            }
        }
    }
    // Guard's own stop rests but the venue shows its limit at the trigger:
    // not counted, and not stacked again; reported.
    let mut stuck = account(dec!(10000));
    eth_long_with_stop(&mut stuck);
    stuck.open_orders[0].limit_px = dec!(2940);
    stuck.open_orders[0].cloid = Some("0x7a6700000000000000000000000000aa".into());
    let (actions, unpriced, problems) = protect_actions(&stuck, &policy, &blank, b"test", 7);
    assert!(actions.is_empty() && unpriced.is_empty());
    assert!(problems[0].contains("does not count"), "{problems:?}");
    // A Guard stop for 10 under a position grown to 15 (it counts, but not
    // for all of it): a full-size Guard stop beside it, no note.
    let mut grown = account(dec!(10000));
    eth_long_with_stop(&mut grown);
    grown.open_orders[0].cloid = Some("0x7A6700000000000000000000000000aa".into());
    grown.positions[0].qty = dec!(15);
    let (actions, _, problems) = protect_actions(&grown, &policy, &blank, b"test", 7);
    assert_eq!(actions.len(), 1, "{problems:?}");
    assert!(problems.is_empty(), "{problems:?}");
    let Action::Order(order) = &actions[0].1 else {
        panic!("{actions:?}");
    };
    assert_eq!(order.orders[0].size.value(), dec!(15));
    // A short whose recorded stop the price went through (3,000 at or below
    // the mid): no stop, closed by the caller.
    let mut short = account(dec!(10000));
    eth_long_with_stop(&mut short);
    short.open_orders.clear();
    short.positions[0].side = Side::Sell;
    let mut tracked = engine(&policy, dec!(10000));
    tracked
        .record_entry(
            Symbol::new("ETH"),
            Side::Sell,
            dec!(10),
            dec!(2900),
            dec!(3000),
        )
        .ok();
    let (actions, unpriced, _) = protect_actions(&short, &policy, &tracked, b"test", 7);
    assert!(actions.is_empty());
    assert_eq!(unpriced, vec!["ETH".to_owned()]);
    // Liquidation at 2,700 lies above the worst fill 2,646: placed, and
    // reported.
    let mut close = held.clone();
    close.positions[0].liquidation_px = Some(dec!(2700));
    let (actions, _, problems) = protect_actions(&close, &policy, &blank, b"test", 7);
    assert_eq!(actions.len(), 1);
    assert!(problems[0].contains("liquidation"), "{problems:?}");
    // A short of 10: 3,060, worst 3,366.
    held.positions[0].side = Side::Sell;
    let (actions, _, _) = protect_actions(&held, &policy, &blank, b"test", 7);
    let Action::Order(order) = &actions[0].1 else {
        panic!("{actions:?}");
    };
    assert_eq!(order.orders[0].protective_level(), Some(dec!(3060)));
    assert_eq!(order.orders[0].price.value(), dec!(3366));
    assert!(order.orders[0].is_buy);
    // Covered: nothing to do. A stop-limit does not cover, nor a market
    // stop whose limit sits within 5% of its trigger (2,940 x 0.95 = 2,793).
    let mut covered = account(dec!(10000));
    eth_long_with_stop(&mut covered);
    assert!(
        protect_actions(&covered, &policy, &blank, b"test", 7)
            .0
            .is_empty()
    );
    covered.open_orders[0].limit_px = dec!(2793);
    assert!(
        protect_actions(&covered, &policy, &blank, b"test", 7)
            .0
            .is_empty()
    );
    covered.open_orders[0].limit_px = dec!(2794);
    assert_eq!(
        protect_actions(&covered, &policy, &blank, b"test", 7)
            .0
            .len(),
        1
    );
    covered.open_orders[0].limit_px = dec!(2646);
    covered.open_orders[0].is_market = false;
    assert_eq!(
        protect_actions(&covered, &policy, &blank, b"test", 7)
            .0
            .len(),
        1
    );
}

#[test]
fn a_market_stop_capped_at_its_trigger_is_widened() {
    // The ETH long of 10 with Guard's stop (oid 100, 2,940, limit 2,646).
    let mut held = account(dec!(10000));
    eth_long_with_stop(&mut held);
    held.open_orders[0].cloid = Some("0x7a6700000000000000000000000000aa".into());
    // The bot modifies Guard's stop to a market stop at 2,940 with its
    // limit at 2,939.9: the limit is widened to 2,940 x 0.9 = 2,646, so the
    // stop still fills in a gap. Allowed, as a resize.
    let mut capped = stop_loss(ETH, false, "2940", "10");
    capped.price = Px::parse("2939.9").unwrap();
    let modify = request(Action::Modify(Modify {
        oid: OrderRef::Oid(100),
        order: capped.clone(),
    }));
    let decision = judged(&Policy::default(), &held, &modify);
    assert_eq!(decision.verdict, Verdict::Resize, "{decision:?}");
    let Action::Modify(forwarded) = &decision.forward.unwrap().action else {
        panic!()
    };
    assert_eq!(forwarded.order.price.value(), dec!(2646));
    // As a replacement in "na": widened too (2,941 x 0.9 = 2,646.9), and
    // then a tighter full-size market stop that may replace Guard's.
    let mut replacement = stop_loss(ETH, false, "2941", "10");
    replacement.price = Px::parse("2941").unwrap();
    let decision = judged(
        &Policy::default(),
        &held,
        &orders(vec![replacement], Grouping::Na),
    );
    let forward = decision.forward.unwrap();
    let Action::Order(sent) = &forward.action else {
        panic!()
    };
    assert_eq!(sent.orders[0].price.value(), dec!(2646.9));
    assert_eq!(forward.post.len(), 1);
    // A buy stop for a short: 3,060 x 1.1 = 3,366.
    let mut short_stop = stop_loss(ETH, true, "3060", "1");
    short_stop.price = Px::parse("3060").unwrap();
    let mut short = account(dec!(10000));
    eth_long_with_stop(&mut short);
    short.positions[0].side = Side::Sell;
    short.open_orders.clear();
    let decision = judged(
        &Policy::default(),
        &short,
        &orders(vec![short_stop], Grouping::Na),
    );
    let Action::Order(sent) = &decision.forward.unwrap().action else {
        panic!()
    };
    assert_eq!(sent.orders[0].price.value(), dec!(3366));
    // A limit already wider is left as it is.
    let mut wide = stop_loss(ETH, false, "2940", "10");
    wide.price = Px::parse("2500").unwrap();
    let decision = judged(&Policy::default(), &held, &orders(vec![wide], Grouping::Na));
    let Action::Order(sent) = &decision.forward.unwrap().action else {
        panic!()
    };
    assert_eq!(sent.orders[0].price.value(), dec!(2500));
}

pub(crate) mod hip3;
