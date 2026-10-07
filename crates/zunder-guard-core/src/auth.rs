// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Who sent a request, and that it is fresh.
//!
//! A bot signs its requests with a Guard-issued client key, exactly as it
//! would sign for Hyperliquid. Guard recovers the signer from the action
//! hash and the phantom agent ([`crate::sign`]) and accepts only the
//! configured client addresses. Clients choose the phantom agent's source
//! themselves (the Python SDK signs as testnet whenever its URL is not
//! mainnet's; ccxt follows its sandbox flag; the TypeScript SDK its
//! `isTestnet` flag), so both sources are tried. Either way the signer must
//! be a Guard client: a signature is authentication here, not an order the
//! venue would accept, since a client key is no API wallet of the account.
//!
//! # Nonces
//!
//! A nonce is accepted once, and only when
//!
//! - it is larger than every nonce this client used before (monotonic,
//!   which also makes it never reused),
//! - it lies within the window `[now - max_age, now + max_ahead]` of
//!   Guard's clock, and
//! - it is at or above the floor set when this process started: the start
//!   time plus `max_ahead`. No request signed before the start, even one
//!   dated slightly ahead, can be replayed after a restart, although the
//!   per-client record lives in memory only.
//!
//! The nonce is consumed as soon as the signature checks out, whatever is
//! decided about the request afterwards: a vetoed request replayed later,
//! when the limits might allow it, is refused as a replay.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    action::ExchangeRequest,
    sign::{Address, SigningNetwork, action_hash, agent_digest, recover_signer},
};

/// Default oldest nonce accepted, in milliseconds before now.
pub const DEFAULT_NONCE_MAX_AGE_MS: u64 = 30_000;
/// Default newest nonce accepted, in milliseconds after now.
pub const DEFAULT_NONCE_MAX_AHEAD_MS: u64 = 5_000;
/// Bounds of the two windows that `validate` accepts.
pub const MAX_NONCE_MAX_AGE_MS: u64 = 300_000;
pub const MAX_NONCE_MAX_AHEAD_MS: u64 = 60_000;
/// Most client addresses a Guard accepts.
pub const MAX_CLIENTS: usize = 64;

/// The authentication settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// The client keys' addresses, `0x` and 40 hex digits each.
    pub clients: Vec<String>,
    pub nonce_max_age_ms: u64,
    pub nonce_max_ahead_ms: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            clients: Vec::new(),
            nonce_max_age_ms: DEFAULT_NONCE_MAX_AGE_MS,
            nonce_max_ahead_ms: DEFAULT_NONCE_MAX_AHEAD_MS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthConfigError {
    #[error("no client addresses: run `zunder-guard init` to issue a client key")]
    NoClients,
    #[error("more than {MAX_CLIENTS} client addresses")]
    TooManyClients,
    #[error("client address `{0}` is not 0x and 40 hex digits")]
    BadClient(String),
    #[error("nonce_max_age_ms must be between 1000 and {MAX_NONCE_MAX_AGE_MS}, got {0}")]
    MaxAge(u64),
    #[error("nonce_max_ahead_ms must be between 100 and {MAX_NONCE_MAX_AHEAD_MS}, got {0}")]
    MaxAhead(u64),
}

impl AuthConfig {
    pub fn validate(&self) -> Result<BTreeSet<Address>, AuthConfigError> {
        if self.clients.is_empty() {
            return Err(AuthConfigError::NoClients);
        }
        if self.clients.len() > MAX_CLIENTS {
            return Err(AuthConfigError::TooManyClients);
        }
        if !(1_000..=MAX_NONCE_MAX_AGE_MS).contains(&self.nonce_max_age_ms) {
            return Err(AuthConfigError::MaxAge(self.nonce_max_age_ms));
        }
        if !(100..=MAX_NONCE_MAX_AHEAD_MS).contains(&self.nonce_max_ahead_ms) {
            return Err(AuthConfigError::MaxAhead(self.nonce_max_ahead_ms));
        }
        self.clients
            .iter()
            .map(|text| {
                Address::from_hex(text).ok_or_else(|| AuthConfigError::BadClient(text.clone()))
            })
            .collect()
    }
}

/// Why a request was not authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthError {
    #[error("the signature does not recover any key")]
    BadSignature,
    #[error(
        "the request is signed by {testnet} (as a testnet signature; {mainnet} as a mainnet one), which is not a Guard client key: sign with the key `zunder-guard init` printed"
    )]
    UnknownSigner { testnet: String, mainnet: String },
    #[error(
        "nonce {nonce} is not above this client's last nonce {last}: a replay or a request out of order"
    )]
    NotIncreasing { nonce: u64, last: u64 },
    #[error("nonce {nonce} is older than the {max_age_ms} ms Guard accepts (now {now})")]
    TooOld {
        nonce: u64,
        now: u64,
        max_age_ms: u64,
    },
    #[error("nonce {nonce} lies more than {max_ahead_ms} ms ahead of Guard's clock (now {now})")]
    TooNew {
        nonce: u64,
        now: u64,
        max_ahead_ms: u64,
    },
    #[error(
        "nonce {nonce} is from before Guard started (accepted from {floor}): requests signed before a restart are not accepted"
    )]
    BeforeStart { nonce: u64, floor: u64 },
    #[error("the request expired at {expires_after} (now {now})")]
    Expired { expires_after: u64, now: u64 },
    #[error("the action is too large to hash")]
    TooLarge,
}

impl AuthError {
    /// A short code for the decision journal and the event stream.
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::BadSignature => "auth_bad_signature",
            AuthError::UnknownSigner { .. } => "auth_unknown_signer",
            AuthError::NotIncreasing { .. } => "auth_replay",
            AuthError::TooOld { .. } => "auth_nonce_too_old",
            AuthError::TooNew { .. } => "auth_nonce_too_new",
            AuthError::BeforeStart { .. } => "auth_nonce_before_start",
            AuthError::Expired { .. } => "auth_expired",
            AuthError::TooLarge => "auth_too_large",
        }
    }
}

/// An authenticated request's sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Authenticated {
    pub client: Address,
    /// The phantom agent source the client signed with.
    pub signed_as: SigningNetwork,
    pub nonce: u64,
}

impl Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

/// The client addresses and every client's last nonce.
#[derive(Debug, Clone)]
pub struct Authenticator {
    clients: BTreeSet<Address>,
    max_age_ms: u64,
    max_ahead_ms: u64,
    floor: u64,
    last: HashMap<Address, u64>,
}

impl Authenticator {
    /// For a process started at `start_ms` (epoch milliseconds).
    pub fn new(config: &AuthConfig, start_ms: u64) -> Result<Self, AuthConfigError> {
        let clients = config.validate()?;
        Ok(Self {
            clients,
            max_age_ms: config.nonce_max_age_ms,
            max_ahead_ms: config.nonce_max_ahead_ms,
            floor: start_ms.saturating_add(config.nonce_max_ahead_ms),
            last: HashMap::new(),
        })
    }

    pub fn clients(&self) -> impl Iterator<Item = &Address> {
        self.clients.iter()
    }

    /// The signer of `request` if it is a client, and its nonce consumed;
    /// or why not. `now_ms` is Guard's clock.
    pub fn authenticate(
        &mut self,
        request: &ExchangeRequest,
        now_ms: u64,
    ) -> Result<Authenticated, AuthError> {
        self.authenticate_wire(
            &request.action.to_wire(),
            request.nonce,
            &request.signature,
            request.expires_after,
            now_ms,
        )
    }

    /// [`Authenticator::authenticate`] for any L1-signed action given as
    /// its wire form (Guard's own `zunderGuardKill`, say): the same signer
    /// recovery and the same nonce rules, one nonce sequence per client.
    pub fn authenticate_wire(
        &mut self,
        wire: &crate::wire::Wire,
        nonce: u64,
        signature: &crate::sign::Signature,
        expires_after: Option<u64>,
        now_ms: u64,
    ) -> Result<Authenticated, AuthError> {
        let connection_id =
            action_hash(wire, nonce, None, expires_after).map_err(|_| AuthError::TooLarge)?;
        let mut recovered = Vec::with_capacity(2);
        let mut found = None;
        for network in [SigningNetwork::Testnet, SigningNetwork::Mainnet] {
            let signer = recover_signer(&agent_digest(network, &connection_id), signature);
            if let Some(signer) = signer
                && self.clients.contains(&signer)
            {
                found = Some((signer, network));
                break;
            }
            recovered.push(signer);
        }
        let Some((client, signed_as)) = found else {
            let shown = |signer: Option<&Option<Address>>| {
                signer
                    .copied()
                    .flatten()
                    .map_or_else(|| "nobody".to_owned(), |address| address.to_hex())
            };
            if recovered.iter().all(Option::is_none) {
                return Err(AuthError::BadSignature);
            }
            return Err(AuthError::UnknownSigner {
                testnet: shown(recovered.first()),
                mainnet: shown(recovered.get(1)),
            });
        };

        if let Some(&last) = self.last.get(&client)
            && nonce <= last
        {
            return Err(AuthError::NotIncreasing { nonce, last });
        }
        if nonce < self.floor {
            return Err(AuthError::BeforeStart {
                nonce,
                floor: self.floor,
            });
        }
        if nonce < now_ms.saturating_sub(self.max_age_ms) {
            return Err(AuthError::TooOld {
                nonce,
                now: now_ms,
                max_age_ms: self.max_age_ms,
            });
        }
        if nonce > now_ms.saturating_add(self.max_ahead_ms) {
            return Err(AuthError::TooNew {
                nonce,
                now: now_ms,
                max_ahead_ms: self.max_ahead_ms,
            });
        }
        if let Some(expires_after) = expires_after
            && now_ms > expires_after
        {
            return Err(AuthError::Expired {
                expires_after,
                now: now_ms,
            });
        }
        self.last.insert(client, nonce);
        Ok(Authenticated {
            client,
            signed_as,
            nonce,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        action::Action,
        sign::{GuardKey, tests::SDK_TEST_KEY},
        wire::minimal_hex,
    };

    pub(crate) const START: u64 = 1_791_000_000_000;

    pub(crate) fn client_key() -> GuardKey {
        GuardKey::from_hex(SDK_TEST_KEY).unwrap()
    }

    /// A request for `action` signed by `key` with `nonce`.
    pub(crate) fn signed(
        key: &GuardKey,
        network: SigningNetwork,
        action: Action,
        nonce: u64,
        expires_after: Option<u64>,
    ) -> ExchangeRequest {
        let signature = key
            .sign_l1_action(network, &action.to_wire(), nonce, expires_after)
            .unwrap();
        ExchangeRequest {
            action,
            nonce,
            signature,
            expires_after,
        }
    }

    pub(crate) fn authenticator() -> Authenticator {
        Authenticator::new(
            &AuthConfig {
                clients: vec![client_key().address().to_hex()],
                ..AuthConfig::default()
            },
            START,
        )
        .unwrap()
    }

    fn noop() -> Action {
        Action::ScheduleCancel { time: None }
    }

    #[test]
    fn a_client_signature_is_accepted_on_either_source() {
        let mut auth = authenticator();
        let now = START + 10_000;
        for (offset, network) in [(0, SigningNetwork::Testnet), (1, SigningNetwork::Mainnet)] {
            let request = signed(&client_key(), network, noop(), now + offset, None);
            let accepted = auth.authenticate(&request, now).unwrap();
            assert_eq!(accepted.client, client_key().address());
            assert_eq!(accepted.signed_as, network);
        }
    }

    #[test]
    fn replays_and_reordered_nonces_are_refused() {
        let mut auth = authenticator();
        let now = START + 10_000;
        let request = signed(&client_key(), SigningNetwork::Testnet, noop(), now, None);
        assert!(auth.authenticate(&request, now).is_ok());
        assert_eq!(
            auth.authenticate(&request, now),
            Err(AuthError::NotIncreasing {
                nonce: now,
                last: now
            })
        );
        let earlier = signed(
            &client_key(),
            SigningNetwork::Testnet,
            noop(),
            now - 1,
            None,
        );
        assert!(matches!(
            auth.authenticate(&earlier, now),
            Err(AuthError::NotIncreasing { .. })
        ));
    }

    #[test]
    fn nonces_outside_the_window_or_before_the_start_are_refused() {
        let mut auth = authenticator();
        let now = START + 100_000;
        // 30 s back and 5 s ahead are the edges; one millisecond beyond fails.
        let old = signed(
            &client_key(),
            SigningNetwork::Testnet,
            noop(),
            now - 30_001,
            None,
        );
        assert!(matches!(
            auth.authenticate(&old, now),
            Err(AuthError::TooOld { .. })
        ));
        let ahead = signed(
            &client_key(),
            SigningNetwork::Testnet,
            noop(),
            now + 5_001,
            None,
        );
        assert!(matches!(
            auth.authenticate(&ahead, now),
            Err(AuthError::TooNew { .. })
        ));
        let edge = signed(
            &client_key(),
            SigningNetwork::Testnet,
            noop(),
            now - 30_000,
            None,
        );
        assert!(auth.authenticate(&edge, now).is_ok());
        // A fresh process: nonces below start + 5 s are refused, even a
        // request signed one second before the restart and dated 4 s ahead.
        let mut restarted = authenticator();
        let signed_before = signed(
            &client_key(),
            SigningNetwork::Testnet,
            noop(),
            START + 4_000,
            None,
        );
        assert_eq!(
            restarted.authenticate(&signed_before, START + 1_000),
            Err(AuthError::BeforeStart {
                nonce: START + 4_000,
                floor: START + 5_000
            })
        );
    }

    #[test]
    fn forged_or_foreign_signatures_are_refused() {
        let mut auth = authenticator();
        let now = START + 10_000;
        let stranger = GuardKey::from_hex(&format!("0x{}", "11".repeat(32))).unwrap();
        let foreign = signed(&stranger, SigningNetwork::Testnet, noop(), now, None);
        assert!(matches!(
            auth.authenticate(&foreign, now),
            Err(AuthError::UnknownSigner { .. })
        ));
        // A client's signature over one action does not cover another.
        let mut swapped = signed(&client_key(), SigningNetwork::Testnet, noop(), now, None);
        swapped.action = Action::ScheduleCancel {
            time: Some(now + 60_000),
        };
        assert!(auth.authenticate(&swapped, now).is_err());
        // Nor another nonce.
        let mut renonced = signed(&client_key(), SigningNetwork::Testnet, noop(), now, None);
        renonced.nonce += 1;
        assert!(auth.authenticate(&renonced, now).is_err());
        // Nor without its expiry.
        let mut unexpired = signed(
            &client_key(),
            SigningNetwork::Testnet,
            noop(),
            now,
            Some(now + 1),
        );
        unexpired.expires_after = None;
        assert!(auth.authenticate(&unexpired, now).is_err());
        // A refused request does not consume the client's nonce.
        let good = signed(&client_key(), SigningNetwork::Testnet, noop(), now, None);
        assert!(auth.authenticate(&good, now).is_ok());
        let zeroed = ExchangeRequest {
            signature: crate::sign::Signature {
                r: [0; 32],
                s: [0; 32],
                v: 27,
            },
            ..good
        };
        assert_eq!(
            auth.authenticate(&zeroed, now),
            Err(AuthError::BadSignature)
        );
        assert_eq!(minimal_hex(&[0; 32]), "0x0");
    }

    #[test]
    fn an_expired_request_is_refused() {
        let mut auth = authenticator();
        let now = START + 10_000;
        let request = signed(
            &client_key(),
            SigningNetwork::Testnet,
            noop(),
            now - 2,
            Some(now - 1),
        );
        assert!(matches!(
            auth.authenticate(&request, now),
            Err(AuthError::Expired { .. })
        ));
    }

    #[test]
    fn the_config_is_bounded() {
        let ok = AuthConfig {
            clients: vec![client_key().address().to_hex()],
            ..AuthConfig::default()
        };
        assert!(ok.validate().is_ok());
        assert_eq!(
            AuthConfig::default().validate(),
            Err(AuthConfigError::NoClients)
        );
        let bad = AuthConfig {
            clients: vec!["0x12".into()],
            ..ok.clone()
        };
        assert!(matches!(bad.validate(), Err(AuthConfigError::BadClient(_))));
        for age in [999, MAX_NONCE_MAX_AGE_MS + 1] {
            let bad = AuthConfig {
                nonce_max_age_ms: age,
                ..ok.clone()
            };
            assert_eq!(bad.validate(), Err(AuthConfigError::MaxAge(age)));
        }
        let bad = AuthConfig {
            nonce_max_ahead_ms: MAX_NONCE_MAX_AHEAD_MS + 1,
            ..ok
        };
        assert!(matches!(bad.validate(), Err(AuthConfigError::MaxAhead(_))));
    }
}
