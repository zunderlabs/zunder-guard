// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! HIP-3 markets with hand-computed numbers. The account: the main dex
//! (10,000 USDC unless a case says otherwise, mids as in the parent module)
//! and HIP-3 dex `xyz` at index 1 of `perpDexs`, read as Guard reads them
//! ([`AccountView::parse_dexes`] over the venue's answers):
//!
//! | Asset | Id | szDecimals | maxLeverage | marginMode | fee scale | Mid |
//! |---|---|---|---|---|---|---|
//! | `xyz:GOLD` | 110000 | 4 | 20 | noCross | 1.0: 2x the main dex's fee | 4,000 |
//! | `xyz:TSLA` | 110001 | 3 | 10 | strictIsolated | 0.5: 1.5x | 400 |
//! | `xyz:URANIUM` | 110002 | 3 | 10 | delisted (halted) | none: 6x | 80 |
//!
//! Ids are `100000 + 10000 × 1 + index` (Hyperliquid's "Asset IDs": the
//! docs' own example is `test:ABC`, dex 1, index 0 = 110000). Asset 120000
//! is on dex 2, which Guard does not read. GOLD's taker fee is 2 × 4.5 =
//! 9 bp (fee scale 1.0: `2s × 4.5 bp`), so with 1 bp slippage an entry at
//! 4,000 costs 4,000 × 10 bp × 2 = 8 a unit there and back.

use serde_json::{Value, json};

use super::*;
use crate::account::{Book, DexAnswers, MarginMode};

pub(crate) const GOLD: u32 = 110_000;
pub(crate) const TSLA: u32 = 110_001;
pub(crate) const URANIUM: u32 = 110_002;
pub(crate) const OTHER_DEX: u32 = 120_000;

pub(crate) fn xyz_meta_json() -> Value {
    json!({"universe": [
        {"name": "xyz:GOLD", "szDecimals": 4, "maxLeverage": 20, "marginTableId": 20,
         "onlyIsolated": true, "marginMode": "noCross", "deployerFeeScale": "1.0"},
        {"name": "xyz:TSLA", "szDecimals": 3, "maxLeverage": 10, "marginTableId": 10,
         "onlyIsolated": true, "marginMode": "strictIsolated", "growthMode": "enabled",
         "deployerFeeScale": "0.5"},
        {"name": "xyz:URANIUM", "szDecimals": 3, "maxLeverage": 10, "isDelisted": true,
         "onlyIsolated": true, "marginMode": "strictIsolated"},
    ], "marginTables": [], "collateralToken": 0})
}

/// The book of `xyz:GOLD` around its 4,000 mid, at exact prices. For a
/// long's stop at 3,920 (worst fill 3,528) only the 3 at 3,910 and the 5 at
/// 3,600 count: 8. The 3 bid at 3,999 and 3,990 will have traded before the
/// stop fires, the 100 at 3,500 lie beyond its worst fill. For a short's at
/// 4,080 (worst 4,488): 3 at 4,100 and 5 at 4,400.
pub(crate) fn gold_book() -> Book {
    Book {
        bids: vec![
            (dec!(3999), dec!(1)),
            (dec!(3990), dec!(2)),
            (dec!(3910), dec!(3)),
            (dec!(3600), dec!(5)),
            (dec!(3500), dec!(100)),
        ],
        asks: vec![
            (dec!(4001), dec!(1)),
            (dec!(4010), dec!(2)),
            (dec!(4100), dec!(3)),
            (dec!(4400), dec!(5)),
            (dec!(4500), dec!(100)),
        ],
        sig_figs: None,
    }
}

/// The main dex with `main` USDC and dex `xyz` with `xyz` USDC, `free` of
/// it withdrawable; no positions, no orders; `xyz:GOLD`'s book read.
pub(crate) fn hip3_account(main: Decimal, xyz: Decimal, free: Decimal) -> AccountView {
    let main_meta = Meta::parse(&meta_json()).unwrap();
    let xyz_meta = Meta::parse_dex(&xyz_meta_json(), 1, "xyz").unwrap();
    let state = |value: Decimal, free: Decimal| {
        json!({"marginSummary": {"accountValue": value.to_string()},
               "withdrawable": free.to_string(), "assetPositions": []})
    };
    let main_state = state(main, main);
    let xyz_state = state(xyz, free);
    let main_mids = json!({"BTC": "60000", "ETH": "3000", "SOL": "150", "@107": "36"});
    let xyz_mids = json!({"xyz:GOLD": "4000", "xyz:TSLA": "400", "xyz:URANIUM": "80"});
    let mut view = AccountView::parse_dexes(
        0,
        &json!("disabled"),
        &[
            DexAnswers {
                meta: &main_meta,
                clearinghouse: &main_state,
                open_orders: &json!([]),
                mids: &main_mids,
                at_open_interest_cap: None,
            },
            DexAnswers {
                meta: &xyz_meta,
                clearinghouse: &xyz_state,
                open_orders: &json!([]),
                mids: &xyz_mids,
                at_open_interest_cap: Some(&json!([])),
            },
        ],
    )
    .unwrap();
    view.books.insert("xyz:GOLD".into(), gold_book());
    view
}

/// Every market of the main dex and of dex `xyz`.
fn xyz_policy() -> Policy {
    Policy {
        markets: Markets::from_list(["*".to_owned(), "xyz:*".to_owned()]),
        ..Policy::default()
    }
}

fn judged_with(
    policy: &Policy,
    account: &AccountView,
    engine: &RiskEngine,
    r: &ExchangeRequest,
) -> Decision {
    judge(
        &Context {
            policy,
            engine,
            account,
            killed: false,
            builder: None,
            salt: b"test",
        },
        r,
    )
}

#[test]
fn the_view_sums_equity_over_the_dexes_and_maps_hip3_ids() {
    let view = hip3_account(dec!(9000), dec!(1000), dec!(1000));
    // 9,000 on the main dex plus 1,000 on xyz.
    assert_eq!(view.equity, Some(dec!(10000)));
    assert_eq!(view.dexes.len(), 2);
    assert_eq!(view.dex_account(1).unwrap().withdrawable, Some(dec!(1000)));
    let gold = view.meta.by_index(GOLD).unwrap();
    assert_eq!(
        (gold.name.as_str(), gold.dex, gold.max_leverage),
        ("xyz:GOLD", 1, 20)
    );
    assert_eq!(gold.margin_mode, MarginMode::NoCross);
    assert_eq!(
        view.meta.by_index(TSLA).unwrap().margin_mode,
        MarginMode::StrictIsolated
    );
    assert!(view.meta.by_index(URANIUM).unwrap().delisted);
    // The main dex's ids are untouched by the merge.
    assert_eq!(view.meta.by_index(1).unwrap().name, "ETH");
    assert_eq!(view.mid("xyz:GOLD"), Some(dec!(4000)));
    assert!(view.meta.by_index(OTHER_DEX).is_none());
}

#[test]
fn a_hip3_entry_is_sized_account_wide_and_capped_by_its_dexs_margin() {
    // Buy 10 xyz:GOLD at 4,000 (the mid), IOC, no stop. Equity is the sum
    // over the dexes: 9,000 + 1,000 = 10,000.
    // Attached stop: 4,000 * 0.98 = 3,920. Cost per unit at GOLD's doubled
    // fee: 8; risk per unit 80 + 8 = 88; the budget 2% of 10,000 = 200:
    // 200 / 88 = 2.2727..., 2.2727 at GOLD's 0.0001 step.
    // Position cap: 20,000 / 4,000 = 5.
    // Leverage: the stop's worst fill 3,920 * 0.9 = 3,528 lies 11.8% below;
    // the liquidation must lie 11.8% * 1.1 + 5% = 17.98% away. GOLD's 20x
    // gives a maintenance margin of 1/40 = 2.5%: at 5x (0.2 - 0.025) /
    // 0.975 = 17.95%, short; at 4x (0.25 - 0.025) / 0.975 = 23.08%: 4x.
    // xyz's own margin account: 800 of its 1,000 withdrawable, * 4 / 4,000
    // = 0.8 GOLD: binds.
    // The book: 3 + 5 = 8 GOLD bid between the trigger and the worst fill;
    // half is 4: does not bind.
    let policy = xyz_policy();
    let account = hip3_account(dec!(9000), dec!(1000), dec!(800));
    let engine = engine(&policy, dec!(10000));
    let decision = judged_with(
        &policy,
        &account,
        &engine,
        &orders(
            vec![limit(GOLD, true, "4000", "10", Tif::Ioc)],
            Grouping::Na,
        ),
    );
    assert_eq!(decision.code, "resized", "{decision:?}");
    assert!(
        decision.text.contains("xyz dex's margin account"),
        "{}",
        decision.text
    );
    let forward = decision.forward.as_ref().unwrap();
    assert_eq!(
        forward.pre,
        vec![Action::UpdateLeverage {
            asset: GOLD,
            is_cross: false,
            leverage: 4
        }]
    );
    let action = forwarded_orders(&decision);
    let (entry, stop) = (&action.orders[0], &action.orders[1]);
    assert_eq!((entry.asset, entry.size.value()), (GOLD, dec!(0.8)));
    assert_eq!(stop.asset, GOLD);
    assert_eq!(stop.stop_trigger(), Some(dec!(3920)));
    assert_eq!(stop.price.value(), dec!(3528));
    assert_eq!(stop.size.value(), dec!(0.8));
    let plan = forward.entry.as_ref().unwrap();
    assert_eq!(
        (plan.coin.as_str(), plan.requested_qty, plan.qty),
        ("xyz:GOLD", dec!(10), dec!(0.8))
    );
    // GOLD's fee scale 1.0 doubles the fee; TSLA's 0.5 makes it 1.5x;
    // URANIUM's meta names none: the most a deployer may set, 6x.
    assert_eq!(
        policy.round_trip_cost_scaled(dec!(4000), account.meta.by_index(GOLD).unwrap().fee_scale),
        Some(dec!(8))
    );
    assert_eq!(account.meta.by_index(TSLA).unwrap().fee_scale, dec!(1.5));
    assert_eq!(account.meta.by_index(URANIUM).unwrap().fee_scale, dec!(6));

    // With 10,000 free on xyz (and 19,000 in all) the margin allows 10:
    // the risk budget binds again, 2% of 19,000 = 380: 380 / 88 =
    // 4.3181..., 4.3181; the position cap 38,000 / 4,000 = 9.5 and the
    // book's 4 (half of 8): the book binds at 4.
    let account = hip3_account(dec!(9000), dec!(10000), dec!(10000));
    let engine = super::engine(&policy, dec!(19000));
    let decision = judged_with(
        &policy,
        &account,
        &engine,
        &orders(
            vec![limit(GOLD, true, "4000", "10", Tif::Ioc)],
            Grouping::Na,
        ),
    );
    assert_eq!(forwarded_orders(&decision).orders[0].size.value(), dec!(4));
    assert!(
        decision.text.contains("the book shows"),
        "{}",
        decision.text
    );
    // A deeper book (20 between the trigger and the worst fill, so 10):
    // the budget binds at 4.3181, by GOLD's fee. At the main dex's fee (cost
    // 4.4 a unit) it would be 380 / 84.4 = 4.5023, beyond the budget.
    let mut account = account;
    account.books.insert(
        "xyz:GOLD".into(),
        Book {
            bids: vec![(dec!(3900), dec!(20))],
            asks: Vec::new(),
            sig_figs: None,
        },
    );
    let decision = judged_with(
        &policy,
        &account,
        &engine,
        &orders(
            vec![limit(GOLD, true, "4000", "10", Tif::Ioc)],
            Grouping::Na,
        ),
    );
    let size = forwarded_orders(&decision).orders[0].size.value();
    assert_eq!(size, dec!(4.3181));
    // Loss at the stop, GOLD's real costs included: 4.3181 * 88 = 379.99.
    assert!(size * dec!(88) <= dec!(380));
}

#[test]
fn a_short_is_capped_by_the_asks_its_stop_buys_from() {
    // Sell 10 xyz:GOLD at 4,000. The stop attached at 4,080 (2% above),
    // its worst fill 4,488. Leverage: 4,488 lies 12.2% above; the
    // liquidation must lie 12.2% * 1.1 + 5% = 18.42% away; a short at 4x
    // is liquidated (0.25 - 0.025) / 1.025 = 21.95% above, at 5x 17.07%:
    // 4x. Margin: 1,000 * 4 / 4,000 = 1.0. Budget: 200 / 88 = 2.2727.
    // Asks between 4,080 and 4,488: 0.6 at 4,100 and 0.4 at 4,400, so half
    // of 1.0 is 0.5; the 2 at 4,010 trade before the stop fires.
    let policy = xyz_policy();
    let engine = engine(&policy, dec!(10000));
    let mut account = hip3_account(dec!(9000), dec!(1000), dec!(1000));
    account.books.insert(
        "xyz:GOLD".into(),
        Book {
            bids: Vec::new(),
            asks: vec![
                (dec!(4010), dec!(2)),
                (dec!(4100), dec!(0.6)),
                (dec!(4400), dec!(0.4)),
            ],
            sig_figs: None,
        },
    );
    let decision = judged_with(
        &policy,
        &account,
        &engine,
        &orders(
            vec![limit(GOLD, false, "4000", "10", Tif::Ioc)],
            Grouping::Na,
        ),
    );
    let action = forwarded_orders(&decision);
    assert_eq!(action.orders[0].size.value(), dec!(0.5), "{decision:?}");
    assert_eq!(action.orders[1].stop_trigger(), Some(dec!(4080)));
    assert_eq!(
        decision.forward.as_ref().unwrap().pre,
        vec![Action::UpdateLeverage {
            asset: GOLD,
            is_cross: false,
            leverage: 4
        }]
    );
}

#[test]
fn the_book_counts_what_is_held_and_a_dex_without_margin_refuses() {
    let policy = xyz_policy();
    // A thin book: between the stop 3,920 and its worst fill 3,528 only 1.0
    // at 3,900 and 0.5 at 3,600 (the 5 at 3,999 trade first, the 50 at 3,000
    // lie beyond): half of 1.5 is 0.75.
    let mut account = hip3_account(dec!(9000), dec!(1000), dec!(1000));
    account.books.insert(
        "xyz:GOLD".into(),
        Book {
            bids: vec![
                (dec!(3999), dec!(5)),
                (dec!(3900), dec!(1)),
                (dec!(3600), dec!(0.5)),
                (dec!(3000), dec!(50)),
            ],
            asks: vec![(dec!(4001), dec!(0.5))],
            sig_figs: None,
        },
    );
    let engine = engine(&policy, dec!(10000));
    let buy = orders(
        vec![limit(GOLD, true, "4000", "10", Tif::Ioc)],
        Grouping::Na,
    );
    let decision = judged_with(&policy, &account, &engine, &buy);
    assert_eq!(
        forwarded_orders(&decision).orders[0].size.value(),
        dec!(0.75)
    );
    // A long of 0.5 already held (isolated 4x, covered by a stop at 3,920):
    // 0.75 - 0.5 = 0.25 left for the new entry.
    account.positions.push(PositionView {
        coin: "xyz:GOLD".into(),
        side: Side::Buy,
        qty: dec!(0.5),
        entry: dec!(4000),
        leverage: Leverage {
            isolated: true,
            value: 4,
        },
        liquidation_px: None,
    });
    account.open_orders.push(OpenOrderView {
        oid: 7,
        cloid: None,
        coin: "xyz:GOLD".into(),
        side: Side::Sell,
        qty: dec!(0.5),
        limit_px: dec!(3528),
        reduce_only: true,
        trigger: Some((dec!(3920), Tpsl::Sl)),
        is_market: true,
        is_position_tpsl: false,
        children: Vec::new(),
    });
    let decision = judged_with(&policy, &account, &engine, &buy);
    assert_eq!(
        forwarded_orders(&decision).orders[0].size.value(),
        dec!(0.25),
        "{decision:?}"
    );
    // Held at half the depth already: nothing left.
    account.positions[0].qty = dec!(0.75);
    account.open_orders[0].qty = dec!(0.75);
    assert_eq!(
        judged_with(&policy, &account, &engine, &buy).code,
        "thin_book"
    );
    // No position, but a buy of 0.5 resting with its stop at 3,920: it
    // counts as held too, 0.75 - 0.5 = 0.25.
    account.positions.clear();
    account.open_orders = vec![OpenOrderView {
        oid: 8,
        cloid: None,
        coin: "xyz:GOLD".into(),
        side: Side::Buy,
        qty: dec!(0.5),
        limit_px: dec!(3990),
        reduce_only: false,
        trigger: None,
        is_market: false,
        is_position_tpsl: false,
        children: vec![OpenOrderView {
            oid: 9,
            cloid: None,
            coin: "xyz:GOLD".into(),
            side: Side::Sell,
            qty: dec!(0.5),
            limit_px: dec!(3528),
            reduce_only: true,
            trigger: Some((dec!(3920), Tpsl::Sl)),
            is_market: true,
            is_position_tpsl: false,
            children: Vec::new(),
        }],
    }];
    let decision = judged_with(&policy, &account, &engine, &buy);
    assert_eq!(
        forwarded_orders(&decision).orders[0].size.value(),
        dec!(0.25),
        "{decision:?}"
    );

    // 1 USDC free on xyz: 1 * 4 / 4,000 = 0.001 GOLD, worth 3.53 at the
    // stop's worst fill: below the venue's 10 USDC.
    let account = hip3_account(dec!(9999), dec!(1), dec!(1));
    let decision = judged_with(&policy, &account, &engine, &buy);
    assert_eq!(decision.code, "dex_margin", "{decision:?}");
    assert!(decision.forward.is_none());
    // No book read: refused rather than sized blind.
    let mut account = hip3_account(dec!(9000), dec!(1000), dec!(1000));
    account.books.clear();
    assert_eq!(
        judged_with(&policy, &account, &engine, &buy).code,
        "thin_book"
    );
}

#[test]
fn halts_caps_other_dexes_and_the_market_list_refuse_hip3_entries() {
    let policy = xyz_policy();
    let engine = engine(&policy, dec!(10000));
    let account = hip3_account(dec!(9000), dec!(1000), dec!(1000));
    let code = |policy: &Policy, account: &AccountView, request: &ExchangeRequest| {
        judged_with(policy, account, &engine, request).code
    };
    let buy = |asset| {
        orders(
            vec![limit(asset, true, "4000", "1", Tif::Ioc)],
            Grouping::Na,
        )
    };
    // Halted by its deployer (delisted in xyz's meta).
    assert_eq!(code(&policy, &account, &buy(URANIUM)), "market_halted");
    // At the open-interest cap.
    let mut capped = account.clone();
    capped.at_open_interest_cap.insert("xyz:GOLD".into());
    assert_eq!(code(&policy, &capped, &buy(GOLD)), "open_interest_cap");
    // A dex margined in another token than USDC.
    let mut usdh = account.clone();
    usdh.dexes[1].usdc = false;
    assert_eq!(code(&policy, &usdh, &buy(GOLD)), "unsupported_market");
    // The default markets are the main dex's only: even with xyz in the
    // view, the judge holds to the policy, for every action on it.
    assert_eq!(
        code(&Policy::default(), &account, &buy(GOLD)),
        "dex_not_allowed"
    );
    let leverage = request(Action::UpdateLeverage {
        asset: GOLD,
        is_cross: false,
        leverage: 1,
    });
    assert_eq!(
        code(&Policy::default(), &account, &leverage),
        "dex_not_allowed"
    );
    // One coin of the dex: the others, and the main dex, are not allowed.
    let gold_only = Policy {
        markets: Markets::from_list(["xyz:GOLD".to_owned()]),
        ..Policy::default()
    };
    assert_eq!(code(&gold_only, &account, &buy(GOLD)), "resized");
    assert_eq!(code(&gold_only, &account, &buy(TSLA)), "market_not_allowed");
    assert_eq!(
        code(
            &gold_only,
            &account,
            &orders(
                vec![limit(BTC, true, "60000", "0.01", Tif::Ioc)],
                Grouping::Na
            )
        ),
        "market_not_allowed"
    );

    // Dex 2, which Guard does not read: everything but a cancel refused,
    // reduce-only, while killed, margin added: the wrong arithmetic (an id
    // one dex off) lands here too.
    let mut close = limit(OTHER_DEX, false, "1", "1", Tif::Ioc);
    close.reduce_only = true;
    for (what, request) in [
        ("entry", buy(OTHER_DEX)),
        ("close", orders(vec![close], Grouping::Na)),
        (
            "stop",
            orders(vec![stop_loss(OTHER_DEX, false, "1", "1")], Grouping::Na),
        ),
        (
            "modify",
            request(Action::Modify(Modify {
                oid: OrderRef::Oid(5),
                order: limit(OTHER_DEX, true, "1", "1", Tif::Gtc),
            })),
        ),
        (
            "leverage",
            request(Action::UpdateLeverage {
                asset: OTHER_DEX,
                is_cross: false,
                leverage: 1,
            }),
        ),
        (
            "margin",
            request(Action::UpdateIsolatedMargin {
                asset: OTHER_DEX,
                is_buy: true,
                ntli: 1_000_000,
            }),
        ),
    ] {
        assert_eq!(
            code(&policy, &account, &request),
            "dex_not_allowed",
            "{what}"
        );
    }
    let cancel = request(Action::Cancel(vec![Cancel {
        asset: OTHER_DEX,
        order: OrderRef::Oid(5),
    }]));
    assert_eq!(
        judged_with(&policy, &account, &engine, &cancel).verdict,
        Verdict::Allow
    );
}

#[test]
fn an_entry_on_one_dex_carries_no_stop_on_another() {
    let policy = xyz_policy();
    let engine = engine(&policy, dec!(10000));
    let account = hip3_account(dec!(9000), dec!(1000), dec!(1000));
    // The entry on xyz:GOLD, its "stop" on BTC (a coin of the main dex):
    // not the entry's TP/SL.
    let decision = judged_with(
        &policy,
        &account,
        &engine,
        &orders(
            vec![
                limit(GOLD, true, "4000", "1", Tif::Ioc),
                stop_loss(BTC, false, "3920", "1"),
            ],
            Grouping::NormalTpsl,
        ),
    );
    assert_eq!(decision.code, "invalid", "{decision:?}");
    // ...or on dex 2: refused for the dex before anything else.
    let decision = judged_with(
        &policy,
        &account,
        &engine,
        &orders(
            vec![
                limit(GOLD, true, "4000", "1", Tif::Ioc),
                stop_loss(OTHER_DEX, false, "3920", "1"),
            ],
            Grouping::NormalTpsl,
        ),
    );
    assert_eq!(decision.code, "dex_not_allowed", "{decision:?}");
}

#[test]
fn hip3_positions_stay_isolated_and_keep_their_margin() {
    let policy = xyz_policy();
    let engine = engine(&policy, dec!(10000));
    let account = hip3_account(dec!(9000), dec!(1000), dec!(1000));
    let leverage = |is_cross, leverage| {
        request(Action::UpdateLeverage {
            asset: GOLD,
            is_cross,
            leverage,
        })
    };
    // xyz:GOLD is isolated-only (noCross): cross is refused, as everywhere.
    assert_eq!(
        judged_with(&policy, &account, &engine, &leverage(true, 3)).code,
        "cross_margin"
    );
    assert_eq!(
        judged_with(&policy, &account, &engine, &leverage(false, 3)).verdict,
        Verdict::Allow
    );
    // The policy's 5x cap, below GOLD's 20x.
    assert_eq!(
        judged_with(&policy, &account, &engine, &leverage(false, 6)).code,
        "leverage"
    );
    // xyz:TSLA is strictIsolated: margin may be added, never removed.
    let margin = |ntli| {
        request(Action::UpdateIsolatedMargin {
            asset: TSLA,
            is_buy: true,
            ntli,
        })
    };
    assert_eq!(
        judged_with(&policy, &account, &engine, &margin(1_000_000)).verdict,
        Verdict::Allow
    );
    assert_eq!(
        judged_with(&policy, &account, &engine, &margin(-1_000_000)).code,
        "margin_removal"
    );
}

#[test]
fn a_loss_on_a_hip3_dex_counts_toward_the_daily_stop() {
    // Start of the day: 9,000 + 1,000 = 10,000. The xyz account falls to
    // 300: 9,300 in all, a 7% loss, beyond the 6% daily stop. On the main
    // dex alone nothing was lost.
    let policy = xyz_policy();
    let mut engine = engine(&policy, dec!(10000));
    let account = hip3_account(dec!(9000), dec!(300), dec!(300));
    assert_eq!(account.equity, Some(dec!(9300)));
    let state = engine.observe(
        Timestamp::from_millis(1_791_000_060_000),
        account.equity.unwrap(),
    );
    assert!(
        matches!(state, zunder_risk::RiskState::HaltedForDay { .. }),
        "{state:?}"
    );
    let decision = judged_with(
        &policy,
        &account,
        &engine,
        &orders(
            vec![limit(BTC, true, "60000", "0.01", Tif::Ioc)],
            Grouping::Na,
        ),
    );
    assert_eq!(decision.code, "daily_loss_stop");
}

#[test]
fn guard_protects_hip3_positions_on_their_own_asset_ids() {
    let policy = xyz_policy();
    let engine = engine(&policy, dec!(10000));
    let mut account = hip3_account(dec!(9000), dec!(1000), dec!(1000));
    for (coin, qty) in [("xyz:GOLD", dec!(0.5)), ("xyz:URANIUM", dec!(2))] {
        account.positions.push(PositionView {
            coin: coin.into(),
            side: Side::Buy,
            qty,
            entry: dec!(4000),
            leverage: Leverage {
                isolated: true,
                value: 3,
            },
            liquidation_px: None,
        });
    }
    // An unprotected HIP-3 position blocks every entry, on any dex: open
    // risk is account-wide.
    let decision = judged_with(
        &policy,
        &account,
        &engine,
        &orders(
            vec![limit(BTC, true, "60000", "0.01", Tif::Ioc)],
            Grouping::Na,
        ),
    );
    assert_eq!(decision.code, "unprotected_position", "{decision:?}");
    let (actions, unpriced, problems) = protect_actions(&account, &policy, &engine, b"s", 1);
    assert!(unpriced.is_empty());
    // GOLD gets Guard's stop at 4,000 * 0.98 = 3,920 on asset 110000;
    // the halted URANIUM gets none (its market takes no orders), only a
    // note for a person.
    assert_eq!(actions.len(), 1, "{actions:?}");
    let (coin, Action::Order(stop)) = &actions[0] else {
        panic!("{actions:?}")
    };
    assert_eq!(coin, "xyz:GOLD");
    assert_eq!(stop.orders[0].asset, GOLD);
    assert_eq!(stop.orders[0].stop_trigger(), Some(dec!(3920)));
    assert_eq!(stop.orders[0].size.value(), dec!(0.5));
    assert!(
        problems.iter().any(|note| note.contains("xyz:URANIUM")),
        "{problems:?}"
    );
    // Flattening closes GOLD on its own id, in an action of xyz's orders
    // only after the main dex's; the halted URANIUM is reported, not sent.
    account.positions.push(PositionView {
        coin: "ETH".into(),
        side: Side::Sell,
        qty: dec!(1),
        entry: dec!(3000),
        leverage: Leverage {
            isolated: true,
            value: 3,
        },
        liquidation_px: None,
    });
    let (flatten, problems) = crate::reply::flatten_actions(&account, &policy);
    let ids: Vec<Vec<u32>> = flatten
        .iter()
        .map(|action| match action {
            Action::Order(order) => order.orders.iter().map(|order| order.asset).collect(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(ids, vec![vec![ETH], vec![GOLD]]);
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("xyz:URANIUM"))
    );
}
