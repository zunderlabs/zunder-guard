// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! What goes to the venue and what goes back to the bot: the re-signed
//! request, Hyperliquid-shaped vetoes, the venue's reply put back into the
//! bot's order, and the orders Guard sends itself when it flattens.

use std::collections::BTreeMap;

use rust_decimal::Decimal;
use serde_json::{Value, json};
use zunder_core::Side;

use crate::{
    account::AccountView,
    action::{Action, Cancel, Grouping, Order, OrderAction, OrderKind, OrderRef, Px, Tif},
    judge::Decision,
    policy::Policy,
    sign::{GuardKey, SigningNetwork},
    wire::{Wire, minimal_hex},
};

/// The body of a request to `/exchange` for `action`, signed with `key`
/// for `network`: in the Python SDK's field order (action, nonce,
/// signature, vaultAddress, expiresAfter). `None` when it cannot be
/// signed (an action too large, or the one-in-2^127 recovery id).
pub fn signed_request(
    key: &GuardKey,
    network: SigningNetwork,
    action: &Action,
    nonce: u64,
    expires_after: Option<u64>,
) -> Option<Vec<u8>> {
    let wire = action.to_wire();
    let signature = key.sign_l1_action(network, &wire, nonce, expires_after)?;
    let request = Wire::Map(vec![
        ("action", wire),
        ("nonce", Wire::UInt(nonce)),
        (
            "signature",
            Wire::Map(vec![
                ("r", Wire::str(minimal_hex(&signature.r))),
                ("s", Wire::str(minimal_hex(&signature.s))),
                ("v", Wire::UInt(u64::from(signature.v))),
            ]),
        ),
        ("vaultAddress", Wire::Null),
        ("expiresAfter", expires_after.map_or(Wire::Null, Wire::UInt)),
    ]);
    request.to_json().ok()
}

/// A refusal as Hyperliquid answers one (`{"status": "err", "response":
/// "..."}`), which every SDK and ccxt surface as an error with the text,
/// plus Guard's reason `code` as a field of its own for tools that read
/// it (SDKs ignore fields they do not know).
pub fn veto_reply(code: &str, text: &str) -> Value {
    json!({
        "status": "err",
        "code": code,
        "response": format!("Zunder Guard veto [{code}]: {text}"),
    })
}

/// The reply to a decision in paper mode: nothing was sent.
pub fn paper_reply(decision: &Decision) -> Value {
    let entry = decision
        .forward
        .as_ref()
        .and_then(|forward| forward.entry.as_ref());
    let mut reply = json!({
        "status": "err",
        "code": decision.code,
        "verdict": decision.verdict,
        "response": format!(
            "Zunder Guard paper mode: would {} [{}]: {} (nothing was sent)",
            match decision.verdict {
                crate::judge::Verdict::Allow => "allow",
                crate::judge::Verdict::Resize => "resize",
                crate::judge::Verdict::Veto => "veto",
            },
            decision.code,
            decision.text
        ),
    });
    // The entry's size asked and the size Guard would send.
    if let (Some(entry), Some(fields)) = (entry, reply.as_object_mut()) {
        fields.insert("requested_size".into(), json!(entry.requested_qty));
        fields.insert("size".into(), json!(entry.qty));
    }
    reply
}

/// The venue's reply to a forwarded order action, with its statuses put
/// back in the bot's order and Guard's own orders (an attached stop) left
/// out. Anything that is not an `ok` order reply passes unchanged.
pub fn client_reply(venue: Value, status_map: &[usize]) -> Value {
    if status_map.is_empty() {
        return venue;
    }
    let Some(statuses) = venue
        .pointer("/response/data/statuses")
        .and_then(Value::as_array)
    else {
        return venue;
    };
    let mapped: Option<Vec<Value>> = status_map
        .iter()
        .map(|index| statuses.get(*index).cloned())
        .collect();
    let Some(mapped) = mapped else {
        return venue;
    };
    let mut reply = venue.clone();
    if let Some(slot) = reply.pointer_mut("/response/data/statuses") {
        *slot = Value::Array(mapped);
    }
    reply
}

/// What the venue said about one forwarded order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderStatus {
    Filled {
        total: Decimal,
        average: Decimal,
        oid: u64,
    },
    Resting {
        oid: u64,
    },
    Error(String),
    Other(String),
}

/// The statuses of an `ok` order reply, in the forwarded order; `Err`
/// with the text of an `err` reply or of a reply Guard cannot read.
pub fn order_statuses(venue: &Value) -> Result<Vec<OrderStatus>, String> {
    if venue.get("status").and_then(Value::as_str) != Some("ok") {
        return Err(venue.get("response").map_or_else(
            || venue.to_string(),
            |response| match response {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            },
        ));
    }
    let statuses = venue
        .pointer("/response/data/statuses")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("no statuses in {venue}"))?;
    Ok(statuses
        .iter()
        .map(|status| {
            let decimal = |value: Option<&Value>| {
                value
                    .and_then(Value::as_str)
                    .and_then(|text| text.parse::<Decimal>().ok())
            };
            if let Some(filled) = status.get("filled") {
                match (
                    decimal(filled.get("totalSz")),
                    decimal(filled.get("avgPx")),
                    filled.get("oid").and_then(Value::as_u64),
                ) {
                    (Some(total), Some(average), Some(oid)) => OrderStatus::Filled {
                        total,
                        average,
                        oid,
                    },
                    _ => OrderStatus::Other(status.to_string()),
                }
            } else if let Some(oid) = status.pointer("/resting/oid").and_then(Value::as_u64) {
                OrderStatus::Resting { oid }
            } else if let Some(error) = status.get("error").and_then(Value::as_str) {
                OrderStatus::Error(error.to_owned())
            } else {
                OrderStatus::Other(status.to_string())
            }
        })
        .collect())
}

/// Whether a reply to a non-order action (`updateLeverage`, a cancel)
/// says it worked: `{"status": "ok"}` without per-item errors.
pub fn action_ok(venue: &Value) -> Result<(), String> {
    if venue.get("status").and_then(Value::as_str) != Some("ok") {
        return Err(venue.to_string());
    }
    let errors: Vec<&Value> = venue
        .pointer("/response/data/statuses")
        .and_then(Value::as_array)
        .map(|statuses| {
            statuses
                .iter()
                .filter(|status| status.get("error").is_some())
                .collect()
        })
        .unwrap_or_default();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(venue.to_string())
    }
}

/// A reduce-only IOC order closing `qty` of the position on `side` in
/// `coin`, bounded at [`Policy::exit_slippage`] from the mid: what Guard
/// sends when an entry filled but its stop was refused. `None` without a
/// market or a mid.
pub fn close_action(
    account: &AccountView,
    policy: &Policy,
    coin: &str,
    side: Side,
    qty: Decimal,
) -> Option<Action> {
    let asset = account.meta.by_name(coin)?;
    let mid = account.mid(coin)?;
    let closing = side.opposite();
    let bound = match closing {
        Side::Sell => mid
            .checked_mul(Decimal::ONE - policy.exit_slippage)
            .and_then(|price| asset.round_price(price, false)),
        Side::Buy => mid
            .checked_mul(Decimal::ONE + policy.exit_slippage)
            .and_then(|price| asset.round_price(price, true)),
    }?;
    Some(Action::Order(OrderAction {
        orders: vec![Order {
            asset: asset.index,
            is_buy: closing == Side::Buy,
            price: Px::from_decimal(bound)?,
            size: Px::from_decimal(qty)?,
            reduce_only: true,
            kind: OrderKind::Limit { tif: Tif::Ioc },
            cloid: None,
        }],
        grouping: Grouping::Na,
        builder: None,
    }))
}

/// The actions that flatten the account: cancel every order that could
/// open or grow a position, then close every position with a reduce-only
/// IOC order bounded at [`Policy::exit_slippage`] from the mid (rounded
/// towards the aggressive side, so rounding never blocks the close). A
/// position without a mid, or in a coin the venue does not list, is
/// reported in the second value instead: a person has to close it. Each
/// action holds one dex's orders only (the main dex's first), so that a dex
/// that refuses an action cannot hold up another's closes; a halted HIP-3
/// market takes no orders and is reported, not sent to.
pub fn flatten_actions(account: &AccountView, policy: &Policy) -> (Vec<Action>, Vec<String>) {
    let mut actions = Vec::new();
    let mut problems = Vec::new();
    let mut cancels: BTreeMap<u32, Vec<Cancel>> = BTreeMap::new();
    for order in account
        .open_orders
        .iter()
        .filter(|order| order.is_opening())
    {
        match account.meta.by_name(&order.coin) {
            Some(asset) => cancels.entry(asset.dex).or_default().push(Cancel {
                asset: asset.index,
                order: OrderRef::Oid(order.oid),
            }),
            None => problems.push(format!(
                "order {} in {} is in no listed market",
                order.oid, order.coin
            )),
        }
    }
    for dex in cancels.values() {
        for chunk in dex.chunks(crate::action::MAX_BATCH) {
            actions.push(Action::Cancel(chunk.to_vec()));
        }
    }
    let mut closes: BTreeMap<u32, Vec<Order>> = BTreeMap::new();
    for position in &account.positions {
        let (Some(asset), Some(mid)) = (
            account.meta.by_name(&position.coin),
            account.mid(&position.coin),
        ) else {
            problems.push(format!(
                "no market or price to close {} {}",
                position.qty, position.coin
            ));
            continue;
        };
        if asset.dex != 0 && asset.delisted {
            problems.push(format!(
                "{} {} is on a market its deployer halted: it takes no orders, and the venue settles the position at the mark",
                position.qty, position.coin
            ));
            continue;
        }
        let closing = position.side.opposite();
        let bound = match closing {
            Side::Sell => mid
                .checked_mul(Decimal::ONE - policy.exit_slippage)
                .and_then(|price| asset.round_price(price, false)),
            Side::Buy => mid
                .checked_mul(Decimal::ONE + policy.exit_slippage)
                .and_then(|price| asset.round_price(price, true)),
        };
        let (Some(price), Some(size)) = (
            bound.and_then(Px::from_decimal),
            Px::from_decimal(position.qty),
        ) else {
            problems.push(format!(
                "cannot price a close of {} {}",
                position.qty, position.coin
            ));
            continue;
        };
        closes.entry(asset.dex).or_default().push(Order {
            asset: asset.index,
            is_buy: closing == Side::Buy,
            price,
            size,
            reduce_only: true,
            kind: OrderKind::Limit { tif: Tif::Ioc },
            cloid: None,
        });
    }
    for dex in closes.values() {
        for chunk in dex.chunks(crate::action::MAX_BATCH) {
            actions.push(Action::Order(OrderAction {
                orders: chunk.to_vec(),
                grouping: Grouping::Na,
                builder: None,
            }));
        }
    }
    (actions, problems)
}

#[cfg(test)]
mod tests {
    use rust_decimal::dec;

    use super::*;
    use crate::{
        account::{Leverage, Meta, PositionView, tests::meta_json},
        action::decode_request,
        sign::{
            SigningNetwork, action_hash, agent_digest, recover_signer, tests::SDK_TEST_ADDRESS,
        },
    };

    #[test]
    fn a_signed_request_decodes_and_recovers_to_the_signer() {
        let key = GuardKey::from_hex(crate::sign::tests::SDK_TEST_KEY).unwrap();
        let action = Action::UpdateLeverage {
            asset: 1,
            is_cross: false,
            leverage: 3,
        };
        let body = signed_request(&key, SigningNetwork::Testnet, &action, 42, Some(99)).unwrap();
        let text = String::from_utf8(body.clone()).unwrap();
        assert!(text.starts_with(r#"{"action":{"type":"updateLeverage","asset":1,"isCross":false,"leverage":3},"nonce":42,"signature":{"r":"0x"#), "{text}");
        assert!(
            text.ends_with(r#""vaultAddress":null,"expiresAfter":99}"#),
            "{text}"
        );
        let decoded = decode_request(&body).unwrap();
        assert_eq!(decoded.action, action);
        let digest = agent_digest(
            SigningNetwork::Testnet,
            &action_hash(&action.to_wire(), 42, None, Some(99)).unwrap(),
        );
        assert_eq!(
            recover_signer(&digest, &decoded.signature)
                .unwrap()
                .to_hex(),
            SDK_TEST_ADDRESS
        );
    }

    #[test]
    fn vetoes_look_like_hyperliquid_errors() {
        let reply = veto_reply("open_risk", "the open-risk budget is used up");
        assert_eq!(reply["status"], "err");
        assert_eq!(
            reply["response"],
            "Zunder Guard veto [open_risk]: the open-risk budget is used up"
        );
    }

    #[test]
    fn statuses_go_back_in_the_bots_order_without_guards_stop() {
        // The bot sent [stop, entry] in "na"; Guard forwarded [entry, stop,
        // attached?] as normalTpsl: map bot 0 -> 1, bot 1 -> 0.
        let venue = json!({"status": "ok", "response": {"type": "order", "data": {"statuses": [
            {"filled": {"totalSz": "0.02", "avgPx": "1891.4", "oid": 77}},
            "waitingForFill",
            "waitingForFill"
        ]}}});
        let reply = client_reply(venue.clone(), &[1, 0]);
        assert_eq!(
            reply["response"]["data"]["statuses"],
            json!(["waitingForFill", {"filled": {"totalSz": "0.02", "avgPx": "1891.4", "oid": 77}}])
        );
        assert_eq!(
            order_statuses(&venue).unwrap()[0],
            OrderStatus::Filled {
                total: dec!(0.02),
                average: dec!(1891.4),
                oid: 77
            }
        );
        // An error reply passes unchanged.
        let error = json!({"status": "err", "response": "User or API Wallet does not exist."});
        assert_eq!(client_reply(error.clone(), &[0]), error);
        assert_eq!(
            order_statuses(&error),
            Err("User or API Wallet does not exist.".to_owned())
        );
        assert!(action_ok(&json!({"status": "ok", "response": {"type": "default"}})).is_ok());
        assert!(action_ok(&json!({"status": "ok", "response": {"type": "cancel", "data": {"statuses": [{"error": "x"}]}}})).is_err());
    }

    #[test]
    fn flattening_cancels_entries_and_closes_at_a_bounded_price() {
        let meta = Meta::parse(&meta_json()).unwrap();
        let account = AccountView {
            at_ms: 0,
            equity: Some(dec!(1000)),
            mode: "disabled".into(),
            positions: vec![PositionView {
                coin: "ETH".into(),
                side: Side::Buy,
                qty: dec!(0.5),
                entry: dec!(3000),
                leverage: Leverage {
                    isolated: true,
                    value: 3,
                },
                liquidation_px: None,
            }],
            open_orders: Vec::new(),
            mids: [("ETH".to_owned(), dec!(3010.55))].into(),
            meta,
            ..AccountView::default()
        };
        let (actions, problems) = flatten_actions(&account, &Policy::default());
        assert!(problems.is_empty());
        let Action::Order(order) = &actions[0] else {
            panic!("{actions:?}")
        };
        let close = &order.orders[0];
        // A sell bounded 5% below the mid: 3010.55 * 0.95 = 2860.0225,
        // rounded down to ETH's 2 decimals and 5 figures: 2860.
        assert_eq!(
            (close.asset, close.is_buy, close.reduce_only),
            (1, false, true)
        );
        assert_eq!(close.price.value(), dec!(2860));
        assert_eq!(close.size.value(), dec!(0.5));
    }
}
