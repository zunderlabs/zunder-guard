// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The clean-up after a failed pilot run, straight on the venue with the
//! API wallet (Guard may be the thing that failed): the run's resting
//! entries cancelled, every position closed with a reduce-only IOC 5%
//! beyond the mid, then the stops (client ids `0x7a70`, the client's, and
//! `0x7a67`, Guard's) of the coins now flat cancelled ([`cleanup`]). Used
//! by `pilot_live.rs` on the runner's testnet account (flat before the run,
//! so whatever is open is the run's), and tested against the in-memory
//! venue in `pilot.rs`.
//!
//! It never panics: a read that fails ends the clean-up with a line that
//! says so, and the caller's flat check then fails with the account as it
//! is.

#![allow(dead_code)]

use rust_decimal::{Decimal, dec};
use serde_json::{Value, json};
use zunder_guard::upstream::Upstream;
use zunder_guard_core::{
    account::requests,
    sign::{Address, GuardKey, SigningNetwork},
    wire::{Wire, minimal_hex},
};
use zunder_redteam::pilot::checks::{round_price, round_size_down};

/// The client ids of the run's own orders and of Guard's stops.
const RUN_PREFIXES: [&str; 2] = ["0x7a70", "0x7a67"];

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// Sign `action` with the API wallet for testnet and send it once: the
/// venue's answer, or `{"error"}`.
pub async fn send<U: Upstream>(upstream: &U, key: &GuardKey, action: Wire, nonce: u64) -> Value {
    let Some(signature) = key.sign_l1_action(SigningNetwork::Testnet, &action, nonce, None) else {
        return json!({"error": "the action could not be signed"});
    };
    let body = json!({
        "action": action.to_value(),
        "nonce": nonce,
        "signature": {"r": minimal_hex(&signature.r), "s": minimal_hex(&signature.s), "v": signature.v},
        "vaultAddress": null,
    });
    upstream
        .exchange(body.to_string().into_bytes())
        .await
        .unwrap_or_else(|error| json!({"error": error.to_string()}))
}

/// An info read; an error or a venue error as text.
async fn read<U: Upstream>(upstream: &U, body: &Value) -> Result<Value, String> {
    upstream
        .info(body)
        .await
        .map_err(|error| format!("{} could not be read: {error}", body["type"]))
}

/// The account's non-zero positions: coin and signed size.
async fn positions<U: Upstream>(
    upstream: &U,
    account: Address,
) -> Result<Vec<(String, Decimal)>, String> {
    let state = read(upstream, &requests::clearinghouse_state(account)).await?;
    let listed = state["assetPositions"]
        .as_array()
        .ok_or_else(|| format!("no assetPositions in {state}"))?;
    let mut held = Vec::new();
    for position in listed {
        let name = position["position"]["coin"]
            .as_str()
            .ok_or_else(|| format!("a position without a coin: {position}"))?;
        let szi: Decimal = position["position"]["szi"]
            .as_str()
            .and_then(|szi| szi.parse().ok())
            .ok_or_else(|| format!("a position without a size: {position}"))?;
        if !szi.is_zero() {
            held.push((name.to_owned(), szi));
        }
    }
    Ok(held)
}

async fn open_orders<U: Upstream>(upstream: &U, account: Address) -> Result<Vec<Value>, String> {
    let orders = read(upstream, &requests::frontend_open_orders(account)).await?;
    orders
        .as_array()
        .cloned()
        .ok_or_else(|| format!("the open orders are not a list: {orders}"))
}

fn is_runs(order: &Value) -> bool {
    order["cloid"]
        .as_str()
        .is_some_and(|cloid| RUN_PREFIXES.iter().any(|prefix| cloid.starts_with(prefix)))
}

fn cancel_action(asset: u64, oid: u64) -> Wire {
    Wire::Map(vec![
        ("type", Wire::str("cancel")),
        (
            "cancels",
            Wire::Array(vec![Wire::Map(vec![
                ("a", Wire::UInt(asset)),
                ("o", Wire::UInt(oid)),
            ])]),
        ),
    ])
}

/// What the clean-up did, one line each; empty when the account was flat.
///
/// In this order, so that nothing opens and no position is left without
/// its stop while it is open:
/// 1. cancel the run's resting entries (orders that are not reduce-only),
///    so that none fills while the positions are closed;
/// 2. close every position reduce-only, 5% beyond the mid;
/// 3. read the account again, and cancel the run's reduce-only orders
///    (stops) only on coins with no position left; a stop on a coin still
///    held stays, and the position is reported.
pub async fn cleanup<U: Upstream>(upstream: &U, key: &GuardKey, account: Address) -> Vec<String> {
    let mut done = Vec::new();
    if let Err(error) = clean(upstream, key, account, &mut done).await {
        done.push(format!("the clean-up stopped: {error}"));
    }
    done
}

async fn clean<U: Upstream>(
    upstream: &U,
    key: &GuardKey,
    account: Address,
    done: &mut Vec<String>,
) -> Result<(), String> {
    let mut nonce = now_ms();
    let mut next = || {
        nonce = now_ms().max(nonce + 1);
        nonce
    };
    let meta = read(upstream, &json!({"type": "meta"})).await?;
    let universe = meta["universe"].as_array().cloned().unwrap_or_default();
    let coin = |name: &str| {
        universe.iter().enumerate().find_map(|(index, asset)| {
            (asset["name"] == name).then(|| {
                (
                    index as u64,
                    asset["szDecimals"].as_u64().unwrap_or(0) as u32,
                )
            })
        })
    };
    // 1. The run's resting entries.
    for order in open_orders(upstream, account).await? {
        let name = order["coin"].as_str().unwrap_or("").to_owned();
        if order["reduceOnly"] == true {
            continue;
        }
        let (Some((asset, _)), Some(oid), true) =
            (coin(&name), order["oid"].as_u64(), is_runs(&order))
        else {
            done.push(format!("left an order that is not the run's: {order}"));
            continue;
        };
        let reply = send(upstream, key, cancel_action(asset, oid), next()).await;
        done.push(format!("cancelled entry {oid} on {name}: {reply}"));
    }
    // 2. Every position, reduce-only.
    let mids = read(upstream, &json!({"type": "allMids"})).await?;
    for (name, szi) in positions(upstream, account).await? {
        let (Some((asset, sz_decimals)), Some(mid)) = (
            coin(&name),
            mids[&name]
                .as_str()
                .and_then(|mid| mid.parse::<Decimal>().ok()),
        ) else {
            done.push(format!("could not close {szi} {name}: no market or mid"));
            continue;
        };
        let long = szi > Decimal::ZERO;
        let price = if long {
            round_price(mid * dec!(0.95), sz_decimals, false)
        } else {
            round_price(mid * dec!(1.05), sz_decimals, true)
        };
        let size = round_size_down(szi.abs(), sz_decimals);
        let action = Wire::Map(vec![
            ("type", Wire::str("order")),
            (
                "orders",
                Wire::Array(vec![Wire::Map(vec![
                    ("a", Wire::UInt(asset)),
                    ("b", Wire::Bool(!long)),
                    ("p", Wire::str(price.normalize().to_string())),
                    ("s", Wire::str(size.normalize().to_string())),
                    ("r", Wire::Bool(true)),
                    (
                        "t",
                        Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Ioc"))]))]),
                    ),
                ])]),
            ),
            ("grouping", Wire::str("na")),
        ]);
        let reply = send(upstream, key, action, next()).await;
        done.push(format!(
            "closed {szi} {name} reduce-only at {price}: {reply}"
        ));
    }
    // 3. Read again; the stops of coins now flat.
    let held = positions(upstream, account).await?;
    for (name, szi) in &held {
        done.push(format!(
            "still open after the close: {szi} {name}; its stops stay"
        ));
    }
    for order in open_orders(upstream, account).await? {
        let name = order["coin"].as_str().unwrap_or("").to_owned();
        if order["reduceOnly"] != true {
            if !is_runs(&order) {
                continue; // reported in step 1
            }
            done.push(format!(
                "an entry of the run's appeared during the clean-up: {order}"
            ));
            continue;
        }
        if held.iter().any(|(coin, _)| *coin == name) {
            continue;
        }
        let (Some((asset, _)), Some(oid), true) =
            (coin(&name), order["oid"].as_u64(), is_runs(&order))
        else {
            done.push(format!("left an order that is not the run's: {order}"));
            continue;
        };
        let reply = send(upstream, key, cancel_action(asset, oid), next()).await;
        done.push(format!("cancelled stop {oid} on {name}: {reply}"));
    }
    Ok(())
}
