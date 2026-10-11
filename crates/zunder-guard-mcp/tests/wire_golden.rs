// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Every kind of request this server signs, byte for byte: orders (a
//! limit at each time in force, an entry with its stop in `normalTpsl`),
//! the cancel and the modify, as `sign::signed_request` writes them for
//! each mode, and the action JSON Guard previews (`sign::action_json`).
//! Compared with golden bodies captured before the action model moved
//! into `zunder-hl-protocol` (11 Oct 2026).
//!
//! The key, nonces and expiries are fixed, so each body's signature
//! (deterministic, RFC 6979) pins the MessagePack that is hashed as well
//! as the JSON that is sent. A difference here is a change to what is
//! signed or sent; never update a golden line to make a refactor pass.

// Test code: a failed unwrap is a failed test.
#![allow(clippy::unwrap_used)]

use zunder_guard_mcp::{
    contract::Mode,
    sign::{Action, ClientKey, Grouping, OrderType, OrderWire, Tif, action_json, signed_request},
};
use zunder_hl_protocol::Network;

/// The throwaway key of the Python SDK's signing tests.
const SDK_TEST_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
const NONCE: u64 = 1_791_000_000_000;

/// Captured before the move (see the module comment).
const GOLDEN: &str = include_str!("golden/mcp_bodies.txt");

fn wire(
    asset: u32,
    is_buy: bool,
    price: &str,
    size: &str,
    reduce_only: bool,
    order_type: OrderType,
    cloid: Option<&str>,
) -> OrderWire {
    OrderWire {
        asset,
        is_buy,
        price: price.to_owned(),
        size: size.to_owned(),
        reduce_only,
        order_type,
        cloid: cloid.map(str::to_owned),
    }
}

fn stop(trigger: &str) -> OrderType {
    OrderType::StopMarket {
        trigger_px: trigger.to_owned(),
    }
}

fn actions() -> Vec<(&'static str, Action)> {
    let cloid = Some("0x7a6d6370000000000000018fd2a1b2c3");
    vec![
        (
            "order_ioc_entry",
            Action::Order {
                orders: vec![wire(
                    1,
                    true,
                    "3101.5",
                    "0.0123",
                    false,
                    OrderType::Limit { tif: Tif::Ioc },
                    cloid,
                )],
                grouping: Grouping::Na,
            },
        ),
        (
            "order_gtc_no_cloid",
            Action::Order {
                orders: vec![wire(
                    0,
                    false,
                    "65000",
                    "0.001",
                    false,
                    OrderType::Limit { tif: Tif::Gtc },
                    None,
                )],
                grouping: Grouping::Na,
            },
        ),
        (
            "order_entry_with_stop_normal_tpsl",
            Action::Order {
                orders: vec![
                    wire(
                        1,
                        true,
                        "3101.5",
                        "0.5",
                        false,
                        OrderType::Limit { tif: Tif::Ioc },
                        cloid,
                    ),
                    wire(1, false, "2646", "0.5", true, stop("2940"), None),
                ],
                grouping: Grouping::NormalTpsl,
            },
        ),
        (
            "order_spot_close",
            Action::Order {
                orders: vec![wire(
                    10_107,
                    false,
                    "36.5",
                    "0.3",
                    true,
                    OrderType::Limit { tif: Tif::Ioc },
                    cloid,
                )],
                grouping: Grouping::Na,
            },
        ),
        (
            "order_stop_alone_big_asset",
            Action::Order {
                orders: vec![wire(
                    110_000,
                    true,
                    "0.00012345",
                    "12345678",
                    true,
                    stop("0.0001122"),
                    cloid,
                )],
                grouping: Grouping::Na,
            },
        ),
        (
            "cancel",
            Action::Cancel {
                asset: 3,
                oid: 77_738_308,
            },
        ),
        (
            "cancel_large_oid",
            Action::Cancel {
                asset: 255,
                oid: u64::MAX,
            },
        ),
        (
            "modify_stop",
            Action::Modify {
                oid: 5,
                order: wire(0, false, "52920", "0.01", true, stop("58800"), None),
            },
        ),
        (
            "modify_limit_with_cloid",
            Action::Modify {
                oid: 1_000_000_000_000,
                order: wire(
                    4,
                    true,
                    "1670.1",
                    "0.0147",
                    false,
                    OrderType::Limit { tif: Tif::Gtc },
                    cloid,
                ),
            },
        ),
    ]
}

#[test]
fn every_request_this_server_signs_matches_its_golden_body() {
    let key = ClientKey::from_hex(SDK_TEST_KEY).unwrap();
    let mut rendered = String::new();
    for (index, (name, action)) in actions().into_iter().enumerate() {
        let offset = index as u64;
        let json = serde_json::to_string(&action_json(&action)).unwrap();
        rendered.push_str(&format!("{name}.action_json {json}\n"));
        for (mode, source, expires) in [
            (
                Mode::Testnet,
                Network::Testnet,
                Some(NONCE + offset + 30_000),
            ),
            (Mode::Paper, Network::Testnet, None),
            (
                Mode::Mainnet,
                Network::Mainnet,
                Some(NONCE + offset + 30_000),
            ),
        ] {
            let body =
                signed_request(&key, source, &action, NONCE + offset, expires, mode).unwrap();
            rendered.push_str(&format!(
                "{name}.{} {}\n",
                mode.name(),
                String::from_utf8(body).unwrap()
            ));
        }
    }
    if rendered != GOLDEN {
        let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("mcp_bodies.txt");
        std::fs::write(&path, &rendered).unwrap();
        let first = rendered
            .lines()
            .zip(GOLDEN.lines())
            .find(|(built, golden)| built != golden);
        panic!(
            "the bodies differ from tests/golden/mcp_bodies.txt (first difference: {first:?}); what was built is in {}",
            path.display()
        );
    }
}
