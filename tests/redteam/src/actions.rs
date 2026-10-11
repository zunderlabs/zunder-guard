// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Hyperliquid action values the attacks build, and the signed request
//! body that wraps one. Field order follows the official SDKs, which Guard
//! follows too; order-shaped actions therefore authenticate against a real
//! Guard and reach the risk rules. Fund-movement and unknown actions need
//! only reach Guard's action-type check, so their exact encoding does not
//! have to match Guard's canonical one: a mismatch there fails
//! authentication first, which is still a refusal.

use serde_json::{Value, json};

use crate::hlsign::{Key, Sig, SigningNet, Wire, minimal_hex};

/// The asset ids of the mock venue (and common perps): BTC 0, ETH 1, SOL 2.
pub const BTC: u64 = 0;
pub const ETH: u64 = 1;
pub const SOL: u64 = 2;
/// The first perp of the first HIP-3 dex: `100000 + 10000 × 1 + 0`.
pub const HIP3_ASSET: u64 = 110_000;
/// Side 0 of HIP-4 outcome 95: `100000000 + 10 × 95 + 0`.
pub const OUTCOME_ASSET: u64 = 100_000_950;

/// One order in an `order` action.
pub struct OrderSpec {
    pub asset: u64,
    pub is_buy: bool,
    pub price: String,
    pub size: String,
    pub reduce_only: bool,
    /// `None` for a plain limit; `Some((is_market, trigger_px, tpsl))` for a
    /// trigger order. `tpsl` is `"sl"` or `"tp"`.
    pub trigger: Option<(bool, String, &'static str)>,
    pub cloid: Option<String>,
    pub tif: &'static str,
}

impl OrderSpec {
    pub fn limit_buy(asset: u64, price: &str, size: &str) -> Self {
        Self {
            asset,
            is_buy: true,
            price: price.to_owned(),
            size: size.to_owned(),
            reduce_only: false,
            trigger: None,
            cloid: None,
            tif: "Gtc",
        }
    }

    pub fn limit_sell(asset: u64, price: &str, size: &str) -> Self {
        Self {
            is_buy: false,
            ..Self::limit_buy(asset, price, size)
        }
    }

    pub fn stop(asset: u64, is_buy: bool, trigger_px: &str, size: &str) -> Self {
        Self {
            asset,
            is_buy,
            price: trigger_px.to_owned(),
            size: size.to_owned(),
            reduce_only: true,
            trigger: Some((true, trigger_px.to_owned(), "sl")),
            cloid: None,
            tif: "Gtc",
        }
    }

    pub fn to_wire(&self) -> Wire {
        let order_type = match &self.trigger {
            None => Wire::map(vec![(
                "limit",
                Wire::map(vec![("tif", Wire::str(self.tif))]),
            )]),
            Some((is_market, trigger_px, tpsl)) => Wire::map(vec![(
                "trigger",
                Wire::map(vec![
                    ("isMarket", Wire::Bool(*is_market)),
                    ("triggerPx", Wire::str(trigger_px.clone())),
                    ("tpsl", Wire::str(*tpsl)),
                ]),
            )]),
        };
        let mut fields = vec![
            ("a".to_owned(), Wire::UInt(self.asset)),
            ("b".to_owned(), Wire::Bool(self.is_buy)),
            ("p".to_owned(), Wire::str(self.price.clone())),
            ("s".to_owned(), Wire::str(self.size.clone())),
            ("r".to_owned(), Wire::Bool(self.reduce_only)),
            ("t".to_owned(), order_type),
        ];
        if let Some(cloid) = &self.cloid {
            fields.push(("c".to_owned(), Wire::str(cloid.clone())));
        }
        Wire::Map(fields)
    }
}

/// An `order` action with `grouping` (`"na"`, `"normalTpsl"` or
/// `"positionTpsl"`).
pub fn order(orders: &[OrderSpec], grouping: &str) -> Wire {
    Wire::map(vec![
        ("type", Wire::str("order")),
        (
            "orders",
            Wire::Array(orders.iter().map(OrderSpec::to_wire).collect()),
        ),
        ("grouping", Wire::str(grouping)),
    ])
}

/// A single limit-buy order action, the baseline for most attacks.
pub fn buy(asset: u64, price: &str, size: &str) -> Wire {
    order(&[OrderSpec::limit_buy(asset, price, size)], "na")
}

pub fn cancel(asset: u64, oid: u64) -> Wire {
    Wire::map(vec![
        ("type", Wire::str("cancel")),
        (
            "cancels",
            Wire::Array(vec![Wire::map(vec![
                ("a", Wire::UInt(asset)),
                ("o", Wire::UInt(oid)),
            ])]),
        ),
    ])
}

pub fn update_leverage(asset: u64, is_cross: bool, leverage: u64) -> Wire {
    Wire::map(vec![
        ("type", Wire::str("updateLeverage")),
        ("asset", Wire::UInt(asset)),
        ("isCross", Wire::Bool(is_cross)),
        ("leverage", Wire::UInt(leverage)),
    ])
}

pub fn update_isolated_margin(asset: u64, is_buy: bool, ntli: i64) -> Wire {
    Wire::map(vec![
        ("type", Wire::str("updateIsolatedMargin")),
        ("asset", Wire::UInt(asset)),
        ("isBuy", Wire::Bool(is_buy)),
        ("ntli", Wire::Int(ntli)),
    ])
}

/// A generic action with a `type` and extra string/number fields, for the
/// fund-movement and unknown-type attacks.
pub fn typed(kind: &str, extra: Vec<(&str, Wire)>) -> Wire {
    let mut fields = vec![("type".to_owned(), Wire::str(kind))];
    for (key, value) in extra {
        fields.push((key.to_owned(), value));
    }
    Wire::Map(fields)
}

/// The signed `/exchange` request body for `action`.
pub fn signed_body(
    key: &Key,
    net: SigningNet,
    action: &Wire,
    nonce: u64,
    expires_after: Option<u64>,
) -> Vec<u8> {
    let sig = key
        .sign_l1_action(net, action, nonce, expires_after)
        .expect("the throwaway test key always signs");
    body_with_signature(action, nonce, expires_after, &sig)
}

/// A request body with a caller-supplied signature (for forged, unsigned
/// and tampered signatures).
pub fn body_with_signature(
    action: &Wire,
    nonce: u64,
    expires_after: Option<u64>,
    sig: &Sig,
) -> Vec<u8> {
    let body = json!({
        "action": action.to_json_value(),
        "nonce": nonce,
        "signature": {
            "r": minimal_hex(&sig.r),
            "s": minimal_hex(&sig.s),
            "v": sig.v,
        },
        "vaultAddress": Value::Null,
        "expiresAfter": expires_after,
    });
    serde_json::to_vec(&body).expect("a JSON object serialises")
}

/// A WebSocket `post` frame carrying an `/exchange` payload, as a client
/// sends over Guard's `/ws`.
pub fn ws_post(body: &[u8], id: u64) -> String {
    let payload: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    json!({
        "method": "post",
        "id": id,
        "request": {"type": "action", "payload": payload},
    })
    .to_string()
}
