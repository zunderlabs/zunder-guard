// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! A deliberately naive Hyperliquid proxy, to prove the suite bites.
//!
//! It stands in for Guard before Guard's checks exist: it parses the body
//! and "forwards" every action, with **no** signature check, **no** nonce
//! check and **no** risk rule. It enforces only what any HTTP server does
//! for free — a body-size cap and JSON parsing — so the only attacks it
//! refuses are the ones a plain JSON endpoint refuses anyway (malformed
//! bodies, NaN/Infinity literals, oversized bodies). Every other attack
//! gets through, and the suite records that as a failure the real Guard
//! must not repeat.
//!
//! The mock is not a correctness model of Hyperliquid. It answers just
//! enough for the suite to see whether an action was let through.

use serde_json::{Value, json};

use crate::target::{Reply, Target};

/// The largest body the mock accepts, matching Guard's 1 MiB cap. This is
/// the one robustness protection the naive mock keeps.
const MAX_BODY: usize = 1 << 20;

#[derive(Default)]
pub struct NaiveMock {
    forwarded: usize,
}

impl NaiveMock {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many actions the mock let through: a blunt measure of how much
    /// damage a real Guard would have prevented.
    pub fn forwarded(&self) -> usize {
        self.forwarded
    }
}

impl Target for NaiveMock {
    fn exchange(&mut self, body: &[u8]) -> Reply {
        if body.len() > MAX_BODY {
            return Reply::HttpStatus(413);
        }
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            // serde_json rejects NaN and Infinity too, so those land here.
            return Reply::Json(json!({"status": "err", "response": "the body is not JSON"}));
        };
        let action = value.get("action").cloned().unwrap_or(Value::Null);
        let kind = action.get("type").and_then(Value::as_str).unwrap_or("");
        if kind.is_empty() {
            return Reply::Json(json!({"status": "err", "response": "no action type"}));
        }
        // Naive: anything with a type is forwarded, whatever it is and
        // whoever (or nothing) signed it.
        self.forwarded += 1;
        match kind {
            "order" => {
                let orders = action
                    .get("orders")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                let statuses: Vec<Value> = orders
                    .iter()
                    .enumerate()
                    .map(|(index, _)| json!({"resting": {"oid": 1000 + index as u64}}))
                    .collect();
                Reply::Json(json!({
                    "status": "ok",
                    "response": {"type": "order", "data": {"statuses": statuses}},
                }))
            }
            "cancel" | "modify" | "batchModify" => Reply::Json(json!({
                "status": "ok",
                "response": {"type": "cancel", "data": {"statuses": ["success"]}},
            })),
            _ => Reply::Json(json!({"status": "ok", "response": {"type": "default"}})),
        }
    }

    fn info(&mut self, body: &[u8]) -> Reply {
        let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let reply = match value.get("type").and_then(Value::as_str) {
            Some("meta") => json!({"universe": [
                {"name": "BTC", "szDecimals": 5, "maxLeverage": 40},
                {"name": "ETH", "szDecimals": 4, "maxLeverage": 25},
                {"name": "SOL", "szDecimals": 2, "maxLeverage": 20},
            ]}),
            Some("allMids") => json!({"BTC": "60000", "ETH": "3000", "SOL": "150"}),
            Some("clearinghouseState") => json!({
                "marginSummary": {"accountValue": "2000"},
                "assetPositions": [],
            }),
            _ => json!({"ok": true}),
        };
        Reply::Json(reply)
    }

    fn healthy(&mut self) -> bool {
        true
    }

    fn label(&self) -> String {
        "naive mock proxy".to_owned()
    }
}
