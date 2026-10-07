// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Zunder Guard's core: a risk firewall between a trading bot and
//! Hyperliquid, without I/O, so that the local Guard (`zunder-guard`) and
//! the browser Guard (WebAssembly) run the same code.
//!
//! The path of one `/exchange` request:
//!
//! 1. [`action::decode_request`]: the bot's request, decoded strictly.
//!    Anything but orders, cancels, modifies, leverage, isolated margin and
//!    scheduled cancels is refused, fund movements and permissions by name.
//! 2. [`auth::Authenticator::authenticate`]: the signer, recovered exactly
//!    as Hyperliquid recovers it, must be a Guard client key; the nonce
//!    must be fresh, increasing and never reused.
//! 3. [`judge::judge`]: the policy and the risk engine decide: allow,
//!    resize or veto, with a reason code and a text.
//! 4. [`reply::signed_request`]: an allowed or resized action is signed
//!    again with the real API wallet key and a fresh Guard nonce.
//!
//! [`admit`] runs steps 1 and 2. The caller reads the account
//! ([`account::AccountView`]), keeps the risk engine (persisted through
//! `zunder-venue`'s `PersistentRisk` in the local Guard), journals each
//! decision ([`event`]) before forwarding it, and sends.

pub mod account;
pub mod action;
pub mod auth;
pub mod codes;
pub mod event;
pub mod flow_value;
pub mod judge;
pub mod ledger;
pub mod licence;
pub mod policy;
pub mod reply;
pub mod sign;
pub mod wire;

use serde_json::Value;

use crate::{
    action::{DecodeError, ExchangeRequest},
    auth::{AuthError, Authenticated, Authenticator},
};

/// Why a request was refused before it could be judged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Auth(#[from] AuthError),
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::Decode(DecodeError::FundsOrPermissions(_)) => "funds_or_permissions",
            Refusal::Decode(DecodeError::Unsupported(_)) => "unsupported_action",
            Refusal::Decode(DecodeError::Vault) => "vault",
            Refusal::Decode(_) => "malformed",
            Refusal::Auth(error) => error.code(),
        }
    }
}

/// The type of Guard's own signed kill request (`POST /guard/kill`): not a
/// Hyperliquid action, signed the same way with a client key. It can only
/// pull the kill switch; nothing releases it but a person.
pub const KILL_ACTION: &str = "zunderGuardKill";
/// Longest reason a kill request may carry.
pub const MAX_KILL_REASON: usize = 200;

/// A kill request, admitted: its reason and its sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillRequest {
    pub reason: String,
    pub client: Authenticated,
}

/// The wire form a client signs for a kill request:
/// `{"type": "zunderGuardKill", "reason": reason}`, in that order.
pub fn kill_wire(reason: &str) -> wire::Wire {
    wire::Wire::Map(vec![
        ("type", wire::Wire::str(KILL_ACTION)),
        ("reason", wire::Wire::str(reason)),
    ])
}

/// Decode and authenticate a kill request: `{"action": {"type":
/// "zunderGuardKill", "reason": "..."}, "nonce", "signature",
/// "expiresAfter"?}`, strictly (no other fields, no vault), the reason at
/// most [`MAX_KILL_REASON`] printable characters. The nonce is the client's
/// one sequence, shared with `/exchange`.
pub fn admit_kill(
    auth: &mut Authenticator,
    body: &Value,
    now_ms: u64,
) -> Result<KillRequest, Refusal> {
    let bad = |text: &str| Refusal::Decode(DecodeError::Malformed(text.to_owned()));
    let fields = body
        .as_object()
        .ok_or_else(|| bad("the request must be a JSON object"))?;
    if let Some(key) = fields.keys().find(|key| {
        ![
            "action",
            "nonce",
            "signature",
            "expiresAfter",
            "vaultAddress",
        ]
        .contains(&key.as_str())
    }) {
        return Err(bad(&format!("the request has an unknown field `{key}`")));
    }
    if !matches!(fields.get("vaultAddress"), None | Some(Value::Null)) {
        return Err(Refusal::Decode(DecodeError::Vault));
    }
    let action = fields
        .get("action")
        .and_then(Value::as_object)
        .ok_or_else(|| bad("the request has no `action` object"))?;
    if action.len() != 2 || action.get("type").and_then(Value::as_str) != Some(KILL_ACTION) {
        return Err(bad(
            "the action must be {\"type\": \"zunderGuardKill\", \"reason\": ...}",
        ));
    }
    let reason = action
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("the reason must be a string"))?;
    if reason.trim().is_empty()
        || reason.chars().count() > MAX_KILL_REASON
        || reason.chars().any(char::is_control)
    {
        return Err(bad("the reason must be 1 to 200 printable characters"));
    }
    let nonce = fields
        .get("nonce")
        .and_then(Value::as_u64)
        .ok_or_else(|| bad("the nonce must be an unsigned integer"))?;
    let expires_after = match fields.get("expiresAfter") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .ok_or_else(|| bad("expiresAfter must be an unsigned integer"))?,
        ),
    };
    let signature = action::decode_signature(
        fields
            .get("signature")
            .ok_or_else(|| bad("the request has no `signature`"))?,
    )?;
    let client =
        auth.authenticate_wire(&kill_wire(reason), nonce, &signature, expires_after, now_ms)?;
    Ok(KillRequest {
        reason: reason.to_owned(),
        client,
    })
}

/// Decode and authenticate a `/exchange` request (JSON already parsed).
/// `now_ms` is Guard's clock. On success the client's nonce is consumed.
pub fn admit(
    auth: &mut Authenticator,
    body: &Value,
    now_ms: u64,
) -> Result<(ExchangeRequest, Authenticated), Refusal> {
    let request = action::decode_request_value(body)?;
    let client = auth.authenticate(&request, now_ms)?;
    Ok((request, client))
}

#[cfg(test)]
mod bench;
#[cfg(test)]
mod properties;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::json;

    use super::*;
    use crate::{
        auth::tests::{START, authenticator, client_key},
        sign::{GuardKey, SigningNetwork},
        wire::minimal_hex,
    };

    fn kill_body(key: &GuardKey, reason: &str, nonce: u64) -> Value {
        let signature = key
            .sign_l1_action(SigningNetwork::Mainnet, &kill_wire(reason), nonce, None)
            .unwrap();
        json!({
            "action": {"type": KILL_ACTION, "reason": reason},
            "nonce": nonce,
            "signature": {"r": minimal_hex(&signature.r), "s": minimal_hex(&signature.s), "v": signature.v},
        })
    }

    #[test]
    fn a_kill_request_needs_a_client_signature_and_a_fresh_nonce() {
        let mut auth = authenticator();
        let now = START + 10_000;
        let body = kill_body(&client_key(), "agent saw a bug", now);
        let admitted = admit_kill(&mut auth, &body, now).unwrap();
        assert_eq!(admitted.reason, "agent saw a bug");
        assert_eq!(admitted.client.client, client_key().address());
        // The same request again: a replay.
        assert_eq!(
            admit_kill(&mut auth, &body, now).unwrap_err().code(),
            "auth_replay"
        );
        // Another reason under the same signature: someone else's signer.
        let mut changed = kill_body(&client_key(), "agent saw a bug", now + 1);
        changed["action"]["reason"] = json!("something else");
        assert!(admit_kill(&mut auth, &changed, now).is_err());
        // A stranger's key.
        let stranger = GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap();
        assert_eq!(
            admit_kill(&mut auth, &kill_body(&stranger, "x", now + 2), now)
                .unwrap_err()
                .code(),
            "auth_unknown_signer"
        );
        // Shapes: another type, an extra field, an empty or overlong
        // reason, a vault.
        let mut other = kill_body(&client_key(), "x", now + 3);
        other["action"]["type"] = json!("order");
        assert_eq!(
            admit_kill(&mut auth, &other, now).unwrap_err().code(),
            "malformed"
        );
        let mut extra = kill_body(&client_key(), "x", now + 4);
        extra["action"]["resume"] = json!(true);
        assert_eq!(
            admit_kill(&mut auth, &extra, now).unwrap_err().code(),
            "malformed"
        );
        for reason in ["", " ", &"x".repeat(201), "a\nb"] {
            let body = kill_body(&client_key(), reason, now + 5);
            assert_eq!(
                admit_kill(&mut auth, &body, now).unwrap_err().code(),
                "malformed",
                "{reason:?}"
            );
        }
        let mut vault = kill_body(&client_key(), "x", now + 6);
        vault["vaultAddress"] = json!("0x0000000000000000000000000000000000000001");
        assert_eq!(
            admit_kill(&mut auth, &vault, now).unwrap_err().code(),
            "vault"
        );
        // The kill and /exchange share one nonce sequence per client.
        let later = kill_body(&client_key(), "again", now + 7);
        assert!(admit_kill(&mut auth, &later, now).is_ok());
    }
}
