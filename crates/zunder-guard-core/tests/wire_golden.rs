// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Every action Guard core decodes and re-signs, byte for byte: each
//! supported action type in the shapes bots send (every grouping, time in
//! force and trigger kind, a builder, oids and cloids, negative margin,
//! prices with trailing zeros kept as sent), plus orders Guard writes itself
//! from decimals. For each: the MessagePack of `Action::to_wire` (what the
//! signature covers) and the body `reply::signed_request` writes (what is
//! sent). Compared with golden lines captured before the action model
//! moved into `zunder-hl-protocol` (11 Oct 2026).
//!
//! A difference here is a change to what is signed or sent; never update a
//! golden line to make a refactor pass.

// Test code: a failed unwrap is a failed test.
#![allow(clippy::unwrap_used)]

use rust_decimal::dec;
use serde_json::{Value, json};
use zunder_guard_core::{
    action::{
        Action, Builder, Cloid, Grouping, Order, OrderAction, OrderKind, Px, Tif, Tpsl,
        decode_action_value,
    },
    reply::signed_request,
    sign::{GuardKey, Network},
};

/// The throwaway key of the Python SDK's signing tests.
const SDK_TEST_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
const NONCE: u64 = 1_791_000_000_000;

/// Captured before the move (see the module comment).
const GOLDEN: &str = include_str!("golden/guard_core_bodies.txt");

fn bot_actions() -> Vec<(&'static str, Value)> {
    let cloid = "0x00000000000000000000000000000001";
    let builder = "0x8c967e73e7b15087c42a10d344cff4c96d877f1d";
    vec![
        (
            "order_sdk_gtc_cloid",
            json!({"type": "order", "orders": [{"a": 1, "b": true, "p": "100", "s": "100", "r": false,
                "t": {"limit": {"tif": "Gtc"}}, "c": cloid}], "grouping": "na"}),
        ),
        (
            "order_ioc_text_kept",
            json!({"type": "order", "orders": [{"a": 0, "b": false, "p": "65000.0", "s": "0.00100", "r": false,
                "t": {"limit": {"tif": "Ioc"}}}], "grouping": "na"}),
        ),
        (
            "order_alo_shuffled_keys",
            json!({"grouping": "na", "type": "order", "orders": [{"t": {"limit": {"tif": "Alo"}},
                "c": "0xABCDEF0123456789abcdef0123456789", "r": false, "s": "12.5", "p": "0.001234", "b": true, "a": 10107}]}),
        ),
        (
            "order_normal_tpsl_entry_sl_tp",
            json!({"type": "order", "orders": [
                {"a": 1, "b": true, "p": "3101.5", "s": "0.5", "r": false, "t": {"limit": {"tif": "Ioc"}}, "c": cloid},
                {"a": 1, "b": false, "p": "2646", "s": "0.5", "r": true,
                 "t": {"trigger": {"isMarket": true, "triggerPx": "2940", "tpsl": "sl"}}},
                {"a": 1, "b": false, "p": "3400", "s": "0.5", "r": true,
                 "t": {"trigger": {"isMarket": false, "triggerPx": "3390.0", "tpsl": "tp"}}}],
                "grouping": "normalTpsl"}),
        ),
        (
            "order_position_tpsl_builder",
            json!({"type": "order", "orders": [
                {"a": 110000, "b": true, "p": "72600", "s": "0", "r": true,
                 "t": {"trigger": {"isMarket": true, "triggerPx": "66000", "tpsl": "sl"}}}],
                "grouping": "positionTpsl", "builder": {"b": builder, "f": 10}}),
        ),
        (
            "order_builder_null",
            json!({"type": "order", "orders": [{"a": 4, "b": true, "p": "1670.1", "s": "0.0147", "r": false,
                "t": {"limit": {"tif": "Ioc"}}, "c": null}], "grouping": "na", "builder": null}),
        ),
        (
            "cancel_two",
            json!({"type": "cancel", "cancels": [{"a": 3, "o": 77738308}, {"o": 18446744073709551615u64, "a": 4294967295u32}]}),
        ),
        (
            "cancel_by_cloid",
            json!({"type": "cancelByCloid", "cancels": [{"asset": 3, "cloid": "0x7a6e6472010300000000000000000001"},
                {"cloid": cloid, "asset": 10107}]}),
        ),
        (
            "modify_by_oid",
            json!({"type": "modify", "oid": 5, "order": {"a": 1, "b": true, "p": "100", "s": "1", "r": false,
                "t": {"limit": {"tif": "Alo"}}}}),
        ),
        (
            "modify_by_cloid_stop",
            json!({"type": "modify", "oid": "0x7a6e6472010300000000000000000001", "order": {"a": 0, "b": false,
                "p": "52920", "s": "0.01", "r": true,
                "t": {"trigger": {"isMarket": true, "triggerPx": "58800", "tpsl": "sl"}}, "c": cloid}}),
        ),
        (
            "batch_modify",
            json!({"type": "batchModify", "modifies": [
                {"oid": 1, "order": {"a": 1, "b": true, "p": "100", "s": "1", "r": false, "t": {"limit": {"tif": "Gtc"}}}},
                {"oid": "0x7a6e6472010300000000000000000002", "order": {"a": 1, "b": false, "p": "90", "s": "1", "r": true,
                 "t": {"trigger": {"isMarket": false, "triggerPx": "91", "tpsl": "sl"}}}}]}),
        ),
        (
            "update_leverage_isolated",
            json!({"type": "updateLeverage", "asset": 3, "isCross": false, "leverage": 5}),
        ),
        (
            "update_leverage_cross",
            json!({"type": "updateLeverage", "asset": 200, "isCross": true, "leverage": 50}),
        ),
        (
            "isolated_margin_remove",
            json!({"type": "updateIsolatedMargin", "asset": 3, "isBuy": true, "ntli": -1000000}),
        ),
        (
            "isolated_margin_add",
            json!({"type": "updateIsolatedMargin", "asset": 3, "isBuy": false, "ntli": 2500000000u64}),
        ),
        (
            "schedule_cancel_at",
            json!({"type": "scheduleCancel", "time": 1791000000000u64}),
        ),
        ("schedule_cancel_clear", json!({"type": "scheduleCancel"})),
    ]
}

/// Orders Guard writes itself, from decimals (`Px::from_decimal`) and
/// cloids it parsed: a flatten and a stop it attaches.
fn guard_actions() -> Vec<(&'static str, Action)> {
    let px = |value| Px::from_decimal(value).unwrap();
    vec![
        (
            "guard_flatten_ioc",
            Action::Order(OrderAction {
                orders: vec![Order {
                    asset: 1,
                    is_buy: false,
                    price: px(dec!(1670.10)),
                    size: px(dec!(0.50000)),
                    reduce_only: true,
                    kind: OrderKind::Limit { tif: Tif::Ioc },
                    cloid: Cloid::parse("0x7a670000000000000000000000000001"),
                }],
                grouping: Grouping::Na,
                builder: None,
            }),
        ),
        (
            "guard_entry_and_stop_with_builder",
            Action::Order(OrderAction {
                orders: vec![
                    Order {
                        asset: 0,
                        is_buy: true,
                        price: px(dec!(65000)),
                        size: px(dec!(0.001)),
                        reduce_only: false,
                        kind: OrderKind::Limit { tif: Tif::Gtc },
                        cloid: None,
                    },
                    Order {
                        asset: 0,
                        is_buy: false,
                        price: px(dec!(58500.00)),
                        size: px(dec!(0.001)),
                        reduce_only: true,
                        kind: OrderKind::Trigger {
                            is_market: true,
                            trigger_px: px(dec!(61750)),
                            tpsl: Tpsl::Sl,
                        },
                        cloid: Cloid::parse("0x7a67abcdefabcdefabcdefabcdefabcd"),
                    },
                ],
                grouping: Grouping::NormalTpsl,
                builder: Some(Builder {
                    address: "0x8c967e73e7b15087c42a10d344cff4c96d877f1d".to_owned(),
                    fee_tenths_bp: 25,
                }),
            }),
        ),
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn every_action_guard_signs_matches_its_golden_bytes() {
    let key = GuardKey::from_hex(SDK_TEST_KEY).unwrap();
    let mut actions: Vec<(&str, Action)> = bot_actions()
        .into_iter()
        .map(|(name, value)| {
            let action = decode_action_value(&value)
                .unwrap_or_else(|error| panic!("{name}: {error} {value}"));
            (name, action)
        })
        .collect();
    actions.extend(guard_actions());
    let mut rendered = String::new();
    for (index, (name, action)) in actions.iter().enumerate() {
        let nonce = NONCE + index as u64;
        let wire = action.to_wire();
        rendered.push_str(&format!(
            "{name}.msgpack {}\n",
            hex(&wire.to_msgpack().unwrap())
        ));
        for (label, network, expires) in [
            ("testnet", Network::Testnet, Some(nonce + 30_000)),
            ("mainnet", Network::Mainnet, None),
        ] {
            let body = signed_request(&key, network, action, nonce, expires).unwrap();
            rendered.push_str(&format!(
                "{name}.{label} {}\n",
                String::from_utf8(body).unwrap()
            ));
        }
    }
    if rendered != GOLDEN {
        let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("guard_core_bodies.txt");
        std::fs::write(&path, &rendered).unwrap();
        let first = rendered
            .lines()
            .zip(GOLDEN.lines())
            .find(|(built, golden)| built != golden);
        panic!(
            "the bytes differ from tests/golden/guard_core_bodies.txt (first difference: {first:?}); what was built is in {}",
            path.display()
        );
    }
}
