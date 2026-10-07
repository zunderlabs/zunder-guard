// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Guard's events: what the decision journal records, line by line, and
//! what the local status endpoint serves to the browser monitor.
//!
//! Every event is one JSON object with a sequence number, the time in
//! epoch milliseconds and a `kind`; `docs/guard.md` ("Events") documents
//! each kind. The schema is versioned by [`EVENT_SCHEMA`]: fields may be
//! added within a version, never removed or changed in meaning.

use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::Value;
use zunder_risk::RiskState;

use crate::{judge::Verdict, sign::SigningNetwork};

/// The schema version of [`GuardEvent`].
pub const EVENT_SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GuardEvent {
    pub seq: u64,
    pub at_ms: i64,
    #[serde(flatten)]
    pub body: EventBody,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventBody {
    /// Guard started.
    Started {
        schema: u32,
        version: String,
        /// `paper`, `testnet` or `mainnet`.
        mode: String,
        account: String,
        /// The policy's nine rules as a `zr1_` code.
        rules: String,
        clients: Vec<String>,
    },
    /// A request was judged, or refused before it could be: then `client`
    /// is empty and `verdict` is `veto`.
    Decision {
        /// `http` or `ws`.
        via: String,
        client: Option<String>,
        signed_as: Option<SigningNetwork>,
        nonce: Option<u64>,
        /// The action's `type`, when it could be read.
        action: Option<String>,
        verdict: Verdict,
        code: String,
        text: String,
        changes: Vec<String>,
        /// The bot's action as it sent it, when it could be decoded.
        request: Option<Value>,
        /// What Guard sends (or would send in paper mode): actions sent
        /// first, then the action, then what follows it (cancelling Guard's
        /// own stop once a tighter one of the bot's rests).
        pre: Vec<Value>,
        forward: Option<Value>,
        post: Vec<Value>,
    },
    /// A request went to the venue (never in paper mode), with what came
    /// back. `decision` is the decision event's `seq`.
    Sent {
        decision: u64,
        nonce: u64,
        ok: bool,
        reply: Value,
        /// The action as sent, when it is not the one the decision (or the
        /// protect or flatten event) recorded: an exit sent again without
        /// the builder field after the venue refused the field.
        #[serde(skip_serializing_if = "Option::is_none")]
        action: Option<Value>,
        /// The action's place among the actions the intent `decision`
        /// named (`docs/guard.md#journals`); none for a send no intent
        /// on disk named (exception E1).
        #[serde(skip_serializing_if = "Option::is_none")]
        index: Option<u64>,
    },
    /// An action Guard is about to send that no earlier decision,
    /// protection or flattening named as it goes out (closing an entry
    /// whose stop was refused, an exit sent again without the builder
    /// field): on disk before it is sent. `of` is the event it serves.
    Intent { of: u64, action: Value },
    /// Guard finished acting on intent `intent` (a decision, a
    /// protection, a flattening): its actions without a `sent` record were
    /// not sent.
    Done { intent: u64 },
    /// After a crash: what the venue says became of an action an intent
    /// named and no `sent` record answers (`docs/guard.md#journals`,
    /// J3). `intent` is the intent's `seq`, `index` the action's place in
    /// it; `outcome` is `happened`, `did_not_happen` or `unknown`, with the
    /// venue's evidence.
    Recovered {
        intent: u64,
        index: u64,
        action: Value,
        outcome: String,
        evidence: Value,
    },
    /// The risk engine saw the account.
    Risk {
        state: RiskState,
        equity: Option<Decimal>,
        open_positions: usize,
        discrepancies: usize,
        journal_error: Option<String>,
    },
    /// Guard flattened, or in paper mode would have.
    Flatten {
        reason: String,
        actions: Vec<Value>,
        problems: Vec<String>,
        sent: bool,
    },
    /// Positions no market stop covered in full: Guard attached its own
    /// (`actions`), closed those it could not protect, or in paper mode
    /// would have. `problems` says what did not work.
    Protect {
        coins: Vec<String>,
        actions: Vec<Value>,
        problems: Vec<String>,
        sent: bool,
    },
    /// The kill switch latched.
    Kill { reason: String },
    /// Something went wrong outside a request: a read of the account, a
    /// journal write.
    Error { text: String },
    /// Guard stopped.
    Stopped { reason: String },
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn events_serialise_flat_with_their_kind() {
        let event = GuardEvent {
            seq: 3,
            at_ms: 1_791_000_000_000,
            body: EventBody::Kill {
                reason: "manual".into(),
            },
        };
        assert_eq!(
            serde_json::to_value(&event).unwrap(),
            json!({"seq": 3, "at_ms": 1_791_000_000_000i64, "kind": "kill", "reason": "manual"})
        );
        let decision = GuardEvent {
            seq: 4,
            at_ms: 1,
            body: EventBody::Decision {
                via: "http".into(),
                client: Some("0x01".into()),
                signed_as: Some(SigningNetwork::Testnet),
                nonce: Some(5),
                action: Some("order".into()),
                verdict: Verdict::Resize,
                code: "resized".into(),
                text: "size cut".into(),
                changes: vec!["size cut".into()],
                request: None,
                pre: Vec::new(),
                forward: None,
                post: Vec::new(),
            },
        };
        let value = serde_json::to_value(&decision).unwrap();
        assert_eq!(value["kind"], "decision");
        assert_eq!(value["verdict"], "resize");
        assert_eq!(value["signed_as"], "testnet");
    }
}
