// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The steps of an entry's judgement one by one, with hand-computed
//! numbers. The account, the venue's `meta` and the policy are the parent
//! module's: 10,000 USDC, ETH at a mid of 3,000 with 4 size decimals (a
//! quantity step of 0.0001) and prices on Hyperliquid's perp grid of five
//! significant figures and at most 6 - 4 = 2 decimals ("Tick and lot
//! size"), 25x on the venue; the default policy: a 0.5% entry price
//! bound, a 2% default stop, 10% stop slippage, 200% per position, 5x,
//! 10% to liquidation, fees 4.5 bp and slippage 1 bp per side.

use super::*;

fn eth(account: &AccountView) -> &AssetInfo {
    account.meta.by_index(ETH).unwrap()
}

fn context<'a>(
    policy: &'a Policy,
    engine: &'a RiskEngine,
    account: &'a AccountView,
) -> Context<'a> {
    Context {
        policy,
        engine,
        account,
        killed: false,
        builder: None,
        salt: b"test",
    }
}

/// An ETH entry on `side` at `worst` with its stop at `stop`, on the
/// account's equity and ETH mid.
fn terms(account: &AccountView, side: Side, worst: Decimal, stop: Decimal) -> EntryTerms<'_> {
    EntryTerms {
        asset: eth(account),
        asset_id: ETH,
        side,
        equity: account.equity.unwrap(),
        mid: account.mid("ETH").unwrap(),
        worst,
        stop,
    }
}

fn code<T>(result: Judged<T>) -> &'static str {
    result.err().expect("a veto").code
}

#[test]
fn step_2_refuses_a_market_off_the_list() {
    let policy = Policy {
        markets: Markets::Only(["BTC".to_owned()].into()),
        ..Policy::default()
    };
    let account = account(dec!(10000));
    let engine = engine(&policy, dec!(10000));
    let ctx = context(&policy, &engine, &account);
    assert_eq!(entry_market(&ctx, BTC).unwrap().name, "BTC");
    assert_eq!(code(entry_market(&ctx, ETH)), "market_not_allowed");
    // An id no dex lists.
    assert_eq!(code(entry_market(&ctx, 9_999)), "unknown_market");
}

#[test]
fn an_entry_is_a_limit_order() {
    assert_eq!(
        entry_tif(&limit(ETH, true, "3000", "1", Tif::Ioc)).unwrap(),
        Tif::Ioc
    );
    let mut trigger = stop_loss(ETH, true, "3100", "1");
    trigger.reduce_only = false;
    assert_eq!(code(entry_tif(&trigger)), "unsupported_order");
}

#[test]
fn step_3_needs_a_positive_equity_and_a_mid() {
    let mut account = account(dec!(10000));
    assert_eq!(
        entry_account(&account, "ETH").unwrap(),
        EntryAccount {
            equity: dec!(10000),
            mid: dec!(3000)
        }
    );
    assert_eq!(code(entry_account(&account, "DOGE")), "no_price");
    for equity in [None, Some(Decimal::ZERO), Some(dec!(-1))] {
        account.equity = equity;
        assert_eq!(code(entry_account(&account, "ETH")), "account_unknown");
    }
}

#[test]
fn step_4_pulls_a_far_limit_in_to_the_bound_rounded_towards_the_mid() {
    let account = account(dec!(10000));
    let asset = eth(&account);
    let policy = Policy::default();
    let fill = |side: Side, mid: Decimal, limit: &str, changes: &mut Vec<String>| {
        worst_fill(
            &policy,
            asset,
            side,
            mid,
            &Px::parse(limit).unwrap(),
            changes,
        )
        .unwrap()
    };

    // A buy at the mid lies within 3,000 x 1.005 = 3,015: kept as sent, the
    // bot's own price text included.
    let mut changes = Vec::new();
    let kept = fill(Side::Buy, dec!(3000), "3000.0", &mut changes);
    assert_eq!(kept.worst, dec!(3000));
    assert_eq!(kept.price.raw(), "3000.0");
    assert!(changes.is_empty());

    // A buy at 3,200: pulled in to 3,015.
    let pulled = fill(Side::Buy, dec!(3000), "3200", &mut changes);
    assert_eq!(pulled.worst, dec!(3015));
    assert_eq!(pulled.price.value(), dec!(3015));
    assert_eq!(
        changes,
        vec!["limit price 3200 pulled in to 3015, 0.5% from the mid 3000".to_owned()]
    );

    // Off the grid: a mid of 3,001.23. A buy's bound 3,001.23 x 1.005 =
    // 3,016.23615 rounds down to five figures, 3,016.2; a sell's,
    // 3,001.23 x 0.995 = 2,986.22385, up to 2,986.3: both towards the mid.
    let mut changes = Vec::new();
    assert_eq!(
        fill(Side::Buy, dec!(3001.23), "3100", &mut changes).worst,
        dec!(3016.2)
    );
    assert_eq!(
        fill(Side::Sell, dec!(3001.23), "2900", &mut changes).worst,
        dec!(2986.3)
    );
    // A sell above the bound is its own worst fill.
    assert_eq!(
        fill(Side::Sell, dec!(3000), "3010", &mut changes).worst,
        dec!(3010)
    );
}

#[test]
fn step_5_attaches_a_stop_rounded_towards_the_price() {
    let account = account(dec!(10000));
    let asset = eth(&account);
    let policy = Policy::default();
    let attach = |side: Side, worst: Decimal, mid: Decimal, changes: &mut Vec<String>| {
        entry_stop(&policy, asset, side, Prices { worst, mid }, &[], changes).unwrap()
    };

    // A long at the mid: 3,000 x 0.98 = 2,940.
    let mut changes = Vec::new();
    assert_eq!(
        attach(Side::Buy, dec!(3000), dec!(3000), &mut changes),
        EntryStop {
            trigger: dec!(2940),
            attached: true
        }
    );
    assert_eq!(
        changes,
        vec!["a reduce-only stop at 2940 (2% from 3000) is attached".to_owned()]
    );
    // From the lower of the worst fill and the mid: 2,990 x 0.98 = 2,930.2.
    assert_eq!(
        attach(Side::Buy, dec!(2990), dec!(3000), &mut changes).trigger,
        dec!(2930.2)
    );
    // A short from the higher: 3,010 x 1.02 = 3,070.2.
    assert_eq!(
        attach(Side::Sell, dec!(3010), dec!(3000), &mut changes).trigger,
        dec!(3070.2)
    );
    // Off the grid, rounded towards the price, never looser than 2%:
    // 3,001.23 x 0.98 = 2,941.2054 up to 2,941.3; 3,001.23 x 1.02 =
    // 3,061.2546 down to 3,061.2.
    assert_eq!(
        attach(Side::Buy, dec!(3001.23), dec!(3005), &mut changes).trigger,
        dec!(2941.3)
    );
    assert_eq!(
        attach(Side::Sell, dec!(3001.23), dec!(3000), &mut changes).trigger,
        dec!(3061.2)
    );
}

#[test]
fn step_5_takes_the_bots_one_market_stop_on_the_losing_side() {
    let account = account(dec!(10000));
    let asset = eth(&account);
    let refuse = Policy {
        stop: StopPolicy::Refuse,
        ..Policy::default()
    };
    let at = |worst: Decimal, mid: Decimal| Prices { worst, mid };
    let own = stop_loss(ETH, false, "2900", "1");
    let mut changes = Vec::new();

    // The bot's own stop, under either policy, unchanged.
    assert_eq!(
        entry_stop(
            &refuse,
            asset,
            Side::Buy,
            at(dec!(3000), dec!(3000)),
            &[(1, &own)],
            &mut changes
        )
        .unwrap(),
        EntryStop {
            trigger: dec!(2900),
            attached: false
        }
    );
    assert!(changes.is_empty());

    // None under `refuse`; a stop-limit is none.
    let limit_only = stop_limit("2900", "2850", "1");
    for children in [vec![], vec![(1, &limit_only)]] {
        assert_eq!(
            code(entry_stop(
                &refuse,
                asset,
                Side::Buy,
                at(dec!(3000), dec!(3000)),
                &children,
                &mut changes
            )),
            "stop_required"
        );
    }
    // Two market stops.
    let second = stop_loss(ETH, false, "2950", "1");
    assert_eq!(
        code(entry_stop(
            &refuse,
            asset,
            Side::Buy,
            at(dec!(3000), dec!(3000)),
            &[(1, &own), (2, &second)],
            &mut changes
        )),
        "invalid"
    );

    // Below the fill of 3,000 but above the mid of 2,990: a long's stop
    // must lie below both. A short's at 3,005, above the fill of 3,000 but
    // below the mid of 3,010, likewise; and one at the price itself.
    let long_stop = stop_loss(ETH, false, "2995", "1");
    let short_stop = stop_loss(ETH, true, "3005", "1");
    let at_price = stop_loss(ETH, false, "3000", "1");
    let short_at_price = stop_loss(ETH, true, "3000", "1");
    for (side, prices, stop) in [
        (Side::Buy, at(dec!(3000), dec!(2990)), &long_stop),
        (Side::Sell, at(dec!(3000), dec!(3010)), &short_stop),
        (Side::Buy, at(dec!(3000), dec!(3000)), &at_price),
        (Side::Sell, at(dec!(3000), dec!(3000)), &short_at_price),
    ] {
        assert_eq!(
            code(entry_stop(
                &refuse,
                asset,
                side,
                prices,
                &[(1, stop)],
                &mut changes
            )),
            "stop_wrong_side"
        );
    }
}

#[test]
fn step_6_sizes_by_the_risk_engine() {
    // A long at 3,000 with its stop at 2,940 risks 60 + 3,000 x 5.5 bp x
    // 2 = 63.3 a unit; 2% of 10,000 = 200 allows 200 / 63.3 = 3.15955...,
    // down to the step: 3.1595 (as in the parent module's first case).
    let policy = Policy::default();
    let mut account = account(dec!(10000));
    let engine = engine(&policy, dec!(10000));
    let entry = terms(&account, Side::Buy, dec!(3000), dec!(2940));
    assert_eq!(
        risk_size(&context(&policy, &engine, &account), &entry).unwrap(),
        dec!(3.1595)
    );
    // An ETH long of 10 to a stop at 2,940 already risks 600, the whole
    // 6% open-risk budget.
    eth_long_with_stop(&mut account);
    let entry = terms(&account, Side::Buy, dec!(3000), dec!(2940));
    assert_eq!(
        code(risk_size(&context(&policy, &engine, &account), &entry)),
        "open_risk"
    );
}

#[test]
fn step_7_leaves_room_up_to_the_position_cap() {
    let policy = Policy::default();
    let mut account = account(dec!(10000));
    let engine = engine(&policy, dec!(10000));
    let cap = |account: &AccountView, policy: &Policy, engine: &RiskEngine, worst: Decimal| {
        position_cap(
            &context(policy, engine, account),
            &terms(account, Side::Buy, worst, dec!(2940)),
        )
    };

    // Nothing held: 200% of 10,000 = 20,000, / 3,000 = 6.666..., 6.6666.
    assert_eq!(
        cap(&account, &policy, &engine, dec!(3000)).unwrap(),
        dec!(6.6666)
    );
    // A long of 2 at the mid of 3,000 holds 6,000; the room of 14,000 at
    // the higher of a 3,015 fill and the mid: 14,000 / 3,015 =
    // 4.643449..., 4.6434.
    account.positions.push(PositionView {
        coin: "ETH".into(),
        side: Side::Buy,
        qty: dec!(2),
        entry: dec!(2900),
        leverage: Leverage {
            isolated: true,
            value: 5,
        },
        liquidation_px: None,
    });
    assert_eq!(
        cap(&account, &policy, &engine, dec!(3015)).unwrap(),
        dec!(4.6434)
    );
    // A resting buy of 1 at 3,100 adds 3,100 (above the mid); a resting
    // sell adds nothing: 10,900 / 3,015 = 3.615257..., 3.6152.
    for (side, limit_px) in [(Side::Buy, dec!(3100)), (Side::Sell, dec!(3200))] {
        account.open_orders.push(OpenOrderView {
            oid: 7,
            cloid: None,
            coin: "ETH".into(),
            side,
            qty: dec!(1),
            limit_px,
            reduce_only: false,
            trigger: None,
            is_market: false,
            is_position_tpsl: false,
            children: Vec::new(),
        });
    }
    assert_eq!(
        cap(&account, &policy, &engine, dec!(3015)).unwrap(),
        dec!(3.6152)
    );

    // From the lower of the account's equity and the engine's last, under
    // the equity cap: an engine that last saw 8,000 allows 16,000 / 3,000
    // = 5.3333; an equity cap of 1,000 allows 2,000 / 3,000 = 0.6666.
    let fresh = super::account(dec!(10000));
    let lower = super::engine(&policy, dec!(8000));
    assert_eq!(
        cap(&fresh, &policy, &lower, dec!(3000)).unwrap(),
        dec!(5.3333)
    );
    let capped = Policy {
        max_trading_equity_usd: Some(dec!(1000)),
        ..Policy::default()
    };
    assert_eq!(
        cap(&fresh, &capped, &engine, dec!(3000)).unwrap(),
        dec!(0.6666)
    );

    // Exactly at the cap: a long of 5 at the mid holds 15,000 and a
    // resting buy of 1 at 5,000 adds 5,000, so 20,000 leaves no room.
    let mut at_cap = super::account(dec!(10000));
    at_cap.positions.push(PositionView {
        coin: "ETH".into(),
        side: Side::Buy,
        qty: dec!(5),
        entry: dec!(3000),
        leverage: Leverage {
            isolated: true,
            value: 5,
        },
        liquidation_px: None,
    });
    at_cap.open_orders.push(OpenOrderView {
        oid: 8,
        cloid: None,
        coin: "ETH".into(),
        side: Side::Buy,
        qty: dec!(1),
        limit_px: dec!(5000),
        reduce_only: false,
        trigger: None,
        is_market: false,
        is_position_tpsl: false,
        children: Vec::new(),
    });
    assert_eq!(
        code(cap(&at_cap, &policy, &engine, dec!(3000))),
        "position_cap"
    );

    // An ETH long of 10 at the mid holds 30,000: over the cap.
    let mut full = super::account(dec!(10000));
    eth_long_with_stop(&mut full);
    assert_eq!(
        code(cap(&full, &policy, &engine, dec!(3000))),
        "position_cap"
    );
}

#[test]
fn step_8_sets_a_new_positions_leverage_and_keeps_an_open_ones() {
    // A long at 3,000 to a stop at 2,940 allows 5x isolated (worked out in
    // the parent module's first case: the liquidation must lie 17.98%
    // away; at 5x it lies 18.37% away).
    let policy = Policy::default();
    let engine = engine(&policy, dec!(10000));
    let mut account = account(dec!(10000));
    let leverage = |account: &AccountView, stop: Decimal| {
        entry_leverage(
            &context(&policy, &engine, account),
            &terms(account, Side::Buy, dec!(3000), stop),
        )
    };
    assert_eq!(
        leverage(&account, dec!(2940)).unwrap(),
        EntryLeverage {
            leverage: 5,
            pre: vec![Action::UpdateLeverage {
                asset: ETH,
                is_cross: false,
                leverage: 5
            }]
        }
    );
    // Set to isolated 3x already: kept, nothing sent first.
    account.leverage_settings.insert(
        "ETH".to_owned(),
        Leverage {
            isolated: true,
            value: 3,
        },
    );
    assert_eq!(
        leverage(&account, dec!(2940)).unwrap(),
        EntryLeverage {
            leverage: 3,
            pre: Vec::new()
        }
    );

    // Adding to the ETH long of 10 (isolated 5x, liquidation 2,450, its
    // stop at 2,940) with a stop at 2,950: checked at the looser 2,940,
    // which 5x suits, and the liquidation lies below both that stop's
    // worst fill, 2,940 x 0.9 = 2,646, and 3,000 x 0.9 = 2,700.
    let mut held = super::account(dec!(10000));
    eth_long_with_stop(&mut held);
    assert_eq!(
        leverage(&held, dec!(2950)).unwrap(),
        EntryLeverage {
            leverage: 5,
            pre: Vec::new()
        }
    );
    // A liquidation at 2,650 lies above 2,646.
    held.positions[0].liquidation_px = Some(dec!(2650));
    assert_eq!(code(leverage(&held, dec!(2950))), "liquidation_too_close");
    // At 7x, above the cap of 5x; on cross margin.
    held.positions[0].liquidation_px = Some(dec!(2450));
    held.positions[0].leverage.value = 7;
    assert_eq!(code(leverage(&held, dec!(2950))), "leverage");
    held.positions[0].leverage = Leverage {
        isolated: false,
        value: 5,
    };
    assert_eq!(code(leverage(&held, dec!(2950))), "cross_margin");
}

#[test]
fn step_9_takes_the_smallest_size_and_names_the_rule_that_bound_it() {
    let policy = Policy::default();
    let engine = engine(&policy, dec!(10000));
    let account = account(dec!(10000));
    let ctx = context(&policy, &engine, &account);
    let long = terms(&account, Side::Buy, dec!(3000), dec!(2940));
    let caps = |sized: Decimal, by_cap: Decimal| SizeCaps {
        sized,
        by_cap,
        leverage: 5,
    };
    let quantity =
        |entry: &Order, children: &[(usize, &Order)], caps: SizeCaps, changes: &mut Vec<String>| {
            entry_quantity(&ctx, &long, entry, children, caps, changes)
        };
    let ten = limit(ETH, true, "3000", "10", Tif::Ioc);

    // The engine's 3.1595 binds.
    let mut changes = Vec::new();
    let cut = quantity(&ten, &[], caps(dec!(3.1595), dec!(6.6666)), &mut changes).unwrap();
    assert_eq!(cut.qty, dec!(3.1595));
    assert_eq!(cut.size.value(), dec!(3.1595));
    assert_eq!(
        changes,
        vec![
            "size 10 cut to 3.1595 ETH for a loss at the stop within 2% of equity and open risk within 6%"
                .to_owned()
        ]
    );
    // The position cap's 2 binds.
    let mut changes = Vec::new();
    let cut = quantity(&ten, &[], caps(dec!(5), dec!(2)), &mut changes).unwrap();
    assert_eq!(cut.qty, dec!(2));
    assert_eq!(
        changes,
        vec!["size 10 cut to 2 ETH for the position cap of 200%".to_owned()]
    );
    // The bot's own stop for 0.5 binds: the entry is cut to what it covers.
    let own = stop_loss(ETH, false, "2940", "0.5");
    let mut changes = Vec::new();
    let cut = quantity(&ten, &[(1, &own)], caps(dec!(5), dec!(6)), &mut changes).unwrap();
    assert_eq!(cut.qty, dec!(0.5));
    // The request binds: kept as sent, no change.
    let one = limit(ETH, true, "3000", "1.00", Tif::Ioc);
    let mut changes = Vec::new();
    let kept = quantity(&one, &[], caps(dec!(3.1595), dec!(6.6666)), &mut changes).unwrap();
    assert_eq!(kept.qty, dec!(1));
    assert_eq!(kept.size.raw(), "1.00");
    assert!(changes.is_empty());

    // Worth the venue's 10 USDC at the lower of the fill and the stop's
    // worst fill, 2,940 x 0.9 = 2,646: 0.0037 x 2,646 = 9.79 is refused
    // (though worth 11.10 at 3,000); 0.0038 x 2,646 = 10.05 goes.
    let small = |size: &str| limit(ETH, true, "3000", size, Tif::Ioc);
    let mut changes = Vec::new();
    assert_eq!(
        code(quantity(
            &small("0.0037"),
            &[],
            caps(dec!(1), dec!(1)),
            &mut changes
        )),
        "below_minimum"
    );
    assert_eq!(
        quantity(&small("0.0038"), &[], caps(dec!(1), dec!(1)), &mut changes)
            .unwrap()
            .qty,
        dec!(0.0038)
    );
    // Exactly the minimum goes: a short filling at 2,500 (below its stop
    // at 3,060) is worth 0.004 x 2,500 = 10 USDC; 0.0039 x 2,500 = 9.75
    // is refused.
    let low_fill = terms(&account, Side::Sell, dec!(2500), dec!(3060));
    let at_2500 = |size: &str| limit(ETH, false, "2500", size, Tif::Ioc);
    assert_eq!(
        entry_quantity(
            &ctx,
            &low_fill,
            &at_2500("0.004"),
            &[],
            caps(dec!(1), dec!(1)),
            &mut changes
        )
        .unwrap()
        .qty,
        dec!(0.004)
    );
    assert_eq!(
        code(entry_quantity(
            &ctx,
            &low_fill,
            &at_2500("0.0039"),
            &[],
            caps(dec!(1), dec!(1)),
            &mut changes
        )),
        "below_minimum"
    );
    // A short's stop is valued at its trigger: at 3,060 against a fill of
    // 3,000, the fill is lower. 0.0033 x 3,000 = 9.9 is refused, 0.0034 x
    // 3,000 = 10.2 goes.
    let short = terms(&account, Side::Sell, dec!(3000), dec!(3060));
    let sell = |size: &str| limit(ETH, false, "3000", size, Tif::Ioc);
    assert_eq!(
        code(entry_quantity(
            &ctx,
            &short,
            &sell("0.0033"),
            &[],
            caps(dec!(1), dec!(1)),
            &mut changes
        )),
        "below_minimum"
    );
    assert_eq!(
        entry_quantity(
            &ctx,
            &short,
            &sell("0.0034"),
            &[],
            caps(dec!(1), dec!(1)),
            &mut changes
        )
        .unwrap()
        .qty,
        dec!(0.0034)
    );
}

#[test]
fn children_only_shrink_to_the_entry() {
    let quantity = Quantity {
        qty: dec!(2),
        size: Px::parse("2").unwrap(),
    };
    let mut take_profit = stop_loss(ETH, false, "3300", "5");
    take_profit.kind = OrderKind::Trigger {
        is_market: true,
        trigger_px: Px::parse("3300").unwrap(),
        tpsl: Tpsl::Tp,
    };
    let stop = stop_loss(ETH, false, "2940", "1.5");
    let mut changes = Vec::new();
    let cut = cut_children(&[(1, &take_profit), (2, &stop)], &quantity, &mut changes);
    assert_eq!(cut[0].0, 1);
    assert_eq!(cut[0].1.size.raw(), "2");
    // Smaller than the entry: left as it is.
    assert_eq!(cut[1], (2, stop.clone()));
    assert_eq!(
        changes,
        vec!["the take profit child cut from 5 to the entry's 2".to_owned()]
    );
}

#[test]
fn guards_attached_stop_fills_within_the_stop_slippage() {
    let policy = Policy::default();
    let engine = engine(&policy, dec!(10000));
    let account = account(dec!(10000));
    let ctx = context(&policy, &engine, &account);
    let size = Px::parse("3.1595").unwrap();
    let cloid = guard_cloid_of(b"test", b"entry");

    // A long's stop at 2,941.3 sells down to 2,941.3 x 0.9 = 2,647.17,
    // rounded away from the price to 2,647.1.
    let buy = limit(ETH, true, "3000", "10", Tif::Ioc);
    let stop = attached_stop(
        &ctx,
        &terms(&account, Side::Buy, dec!(3000), dec!(2941.3)),
        &buy,
        &size,
        cloid.clone(),
    )
    .unwrap();
    assert!(!stop.is_buy && stop.reduce_only);
    assert_eq!(stop.asset, ETH);
    assert_eq!(stop.price.value(), dec!(2647.1));
    assert_eq!(stop.stop_trigger(), Some(dec!(2941.3)));
    assert!(stop.is_market_stop());
    assert_eq!(stop.size, size);
    assert_eq!(stop.cloid, Some(cloid.clone()));
    // A short's at 3,070.2 buys up to 3,070.2 x 1.1 = 3,377.22, rounded
    // to 3,377.3.
    let sell = limit(ETH, false, "3000", "10", Tif::Ioc);
    let stop = attached_stop(
        &ctx,
        &terms(&account, Side::Sell, dec!(3000), dec!(3070.2)),
        &sell,
        &size,
        cloid,
    )
    .unwrap();
    assert!(stop.is_buy);
    assert_eq!(stop.price.value(), dec!(3377.3));
}

#[test]
fn step_1_halts_come_before_every_other_check() {
    // Killed, with ETH off the market list and no mid for it: the kill
    // switch is the reason, not the market or the price.
    let policy = Policy {
        markets: Markets::Only(["BTC".to_owned()].into()),
        ..Policy::default()
    };
    let mut account = account(dec!(10000));
    account.mids.remove("ETH");
    let engine = engine(&policy, dec!(10000));
    let ctx = Context {
        killed: true,
        ..context(&policy, &engine, &account)
    };
    let entry = limit(ETH, true, "3000", "1", Tif::Ioc);
    let request = orders(vec![entry.clone()], Grouping::Na);
    assert_eq!(
        code(judge_entry(&ctx, &entry, &[], &request)),
        "kill_switch"
    );
    // Not killed: the market is.
    let ctx = context(&policy, &engine, &account);
    assert_eq!(
        code(judge_entry(&ctx, &entry, &[], &request)),
        "market_not_allowed"
    );
}
