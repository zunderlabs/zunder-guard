// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Guard's signing key, and the L1 action signatures it makes and checks.
//!
//! The protocol (the action hash, the phantom agent's EIP-712 digest,
//! signing and recovering a signer, addresses and the network) is
//! `zunder-hl-protocol`'s, the one implementation that Zunder's executor,
//! Guard and its MCP server share; it is re-exported here at the paths
//! `zunder-guard` uses. Hyperliquid recovers the signer from the signature
//! and that digest; so does [`recover_signer`]. The unit tests pin
//! [`GuardKey`] against the signatures in the Python SDK's own test suite.

use std::fmt;

use k256::ecdsa::SigningKey;
use zeroize::Zeroizing;
pub use zunder_hl_protocol::{
    Address, Network, Signature,
    sign::{action_hash, address_of_public_key, agent_digest, keccak256, recover_signer},
};

use crate::wire::Wire;

/// The network a signature is for, by its old name in `zunder-guard`.
pub use zunder_hl_protocol::Network as SigningNetwork;

/// Why a key could not be loaded. Never contains any part of the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("a private key must be 64 hex digits, optionally prefixed with 0x")]
    Malformed,
    #[error("not a valid secp256k1 private key")]
    Invalid,
}

/// A private key Guard signs with: the API wallet's (the real key), or a
/// client key in tests and in `zunder-guard init`. It is never printed,
/// logged or serialised: no `Display`, no `Serialize`, no `Clone`, and its
/// `Debug` shows the address only. The secret scalar is wiped when dropped.
pub struct GuardKey {
    key: SigningKey,
    address: Address,
}

impl GuardKey {
    /// A key from hex, with an optional `0x` and whitespace around it. The
    /// copy of the digits made here is wiped.
    pub fn from_hex(secret: &str) -> Result<Self, KeyError> {
        let secret = secret.trim();
        let digits = secret.strip_prefix("0x").unwrap_or(secret);
        if digits.len() != 64 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(KeyError::Malformed);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        for (index, byte) in bytes.iter_mut().enumerate() {
            let pair = digits
                .get(2 * index..2 * index + 2)
                .ok_or(KeyError::Malformed)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| KeyError::Malformed)?;
        }
        Self::from_bytes(&bytes)
    }

    /// A key from its 32 secret bytes (fresh randomness in `zunder-guard
    /// init`). The caller wipes its copy.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeyError> {
        let key = SigningKey::from_slice(bytes).map_err(|_| KeyError::Invalid)?;
        let address = zunder_hl_protocol::sign::address_of(&key);
        Ok(Self { key, address })
    }

    /// The key's own address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Sign a 32-byte digest. Deterministic (RFC 6979) and low-S, as
    /// Ethereum expects. `None` for the one-in-2^127 recovery id that `v`
    /// cannot carry.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Option<Signature> {
        zunder_hl_protocol::sign::sign_digest(&self.key, digest)
    }

    /// Sign `action` with `nonce` for `network`, as an L1 action without a
    /// vault. `None` when it cannot be signed.
    pub fn sign_l1_action(
        &self,
        network: Network,
        action: &Wire,
        nonce: u64,
        expires_after: Option<u64>,
    ) -> Option<Signature> {
        zunder_hl_protocol::sign::sign_l1_action(&self.key, network, action, nonce, expires_after)
            .ok()
    }
}

impl fmt::Debug for GuardKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardKey")
            .field("address", &self.address)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::wire::minimal_hex;

    /// The throwaway key of the official Python SDK's signing tests
    /// ([hyperliquid-python-sdk](https://github.com/hyperliquid-dex/hyperliquid-python-sdk/blob/master/tests/signing_test.py), MIT).
    pub(crate) const SDK_TEST_KEY: &str =
        "0x0123456789012345678901234567890123456789012345678901234567890123";
    /// Its address: eth_account gives 0x14791697260E4c9A71f18484C9f997B308e59325.
    pub(crate) const SDK_TEST_ADDRESS: &str = "0x14791697260e4c9a71f18484c9f997b308e59325";

    fn key() -> GuardKey {
        GuardKey::from_hex(SDK_TEST_KEY).unwrap()
    }

    fn parse_hex32(text: &str) -> [u8; 32] {
        let digits = text.trim_start_matches("0x");
        let padded = format!("{digits:0>64}");
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&padded[2 * index..2 * index + 2], 16).unwrap();
        }
        out
    }

    fn sdk_signature(r: &str, s: &str, v: u8) -> Signature {
        Signature {
            r: parse_hex32(r),
            s: parse_hex32(s),
            v,
        }
    }

    fn dummy_action() -> Wire {
        // {"type": "dummy", "num": float_to_int_for_hashing(1000)}.
        Wire::Map(vec![
            ("type", Wire::str("dummy")),
            ("num", Wire::UInt(100_000_000_000)),
        ])
    }

    /// `{"type":"order","orders":[{a:1,b:true,p:"100",s:"100",r:false,t:..}],"grouping":"na"}`.
    pub(crate) fn sdk_order(order_type: Wire, cloid: Option<&str>) -> Wire {
        let mut order = vec![
            ("a", Wire::UInt(1)),
            ("b", Wire::Bool(true)),
            ("p", Wire::str("100")),
            ("s", Wire::str("100")),
            ("r", Wire::Bool(false)),
            ("t", order_type),
        ];
        if let Some(cloid) = cloid {
            order.push(("c", Wire::str(cloid)));
        }
        Wire::Map(vec![
            ("type", Wire::str("order")),
            ("orders", Wire::Array(vec![Wire::Map(order)])),
            ("grouping", Wire::str("na")),
        ])
    }

    pub(crate) fn gtc() -> Wire {
        Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Gtc"))]))])
    }

    fn sl_103() -> Wire {
        Wire::Map(vec![(
            "trigger",
            Wire::Map(vec![
                ("isMarket", Wire::Bool(true)),
                ("triggerPx", Wire::str("103")),
                ("tpsl", Wire::str("sl")),
            ]),
        )])
    }

    /// The SDK's vectors (hyperliquid-python-sdk, tests/signing_test.py,
    /// read 6 Oct 2026): action, network, r, s, v.
    fn sdk_vectors() -> Vec<(Wire, Network, &'static str, &'static str, u8)> {
        use Network::{Mainnet, Testnet};
        vec![
            (
                dummy_action(),
                Mainnet,
                "0x53749d5b30552aeb2fca34b530185976545bb22d0b3ce6f62e31be961a59298",
                "0x755c40ba9bf05223521753995abb2f73ab3229be8ec921f350cb447e384d8ed8",
                27,
            ),
            (
                dummy_action(),
                Testnet,
                "0x542af61ef1f429707e3c76c5293c80d01f74ef853e34b76efffcb57e574f9510",
                "0x17b8b32f086e8cdede991f1e2c529f5dd5297cbe8128500e00cbaf766204a613",
                28,
            ),
            (
                sdk_order(gtc(), None),
                Mainnet,
                "0xd65369825a9df5d80099e513cce430311d7d26ddf477f5b3a33d2806b100d78e",
                "0x2b54116ff64054968aa237c20ca9ff68000f977c93289157748a3162b6ea940e",
                28,
            ),
            (
                sdk_order(gtc(), None),
                Testnet,
                "0x82b2ba28e76b3d761093aaded1b1cdad4960b3af30212b343fb2e6cdfa4e3d54",
                "0x6b53878fc99d26047f4d7e8c90eb98955a109f44209163f52d8dc4278cbbd9f5",
                27,
            ),
            (
                sdk_order(gtc(), Some("0x00000000000000000000000000000001")),
                Mainnet,
                "0x41ae18e8239a56cacbc5dad94d45d0b747e5da11ad564077fcac71277a946e3",
                "0x3c61f667e747404fe7eea8f90ab0e76cc12ce60270438b2058324681a00116da",
                27,
            ),
            (
                sdk_order(gtc(), Some("0x00000000000000000000000000000001")),
                Testnet,
                "0xeba0664bed2676fc4e5a743bf89e5c7501aa6d870bdb9446e122c9466c5cd16d",
                "0x7f3e74825c9114bc59086f1eebea2928c190fdfbfde144827cb02b85bbe90988",
                28,
            ),
            (
                sdk_order(sl_103(), None),
                Mainnet,
                "0x98343f2b5ae8e26bb2587daad3863bc70d8792b09af1841b6fdd530a2065a3f9",
                "0x6b5bb6bb0633b710aa22b721dd9dee6d083646a5f8e581a20b545be6c1feb405",
                27,
            ),
            (
                sdk_order(sl_103(), None),
                Testnet,
                "0x971c554d917c44e0e1b6cc45d8f9404f32172a9d3b3566262347d0302896a2e4",
                "0x206257b104788f80450f8e786c329daa589aa0b32ba96948201ae556d5637eac",
                28,
            ),
        ]
    }

    #[test]
    fn signing_matches_every_sdk_vector() {
        for (action, network, r, s, v) in sdk_vectors() {
            let signature = key().sign_l1_action(network, &action, 0, None).unwrap();
            assert_eq!(minimal_hex(&signature.r), r, "{network:?}");
            assert_eq!(minimal_hex(&signature.s), s, "{network:?}");
            assert_eq!(signature.v, v, "{network:?}");
        }
    }

    #[test]
    fn recovery_finds_the_sdk_key_in_every_sdk_signature() {
        for (action, network, r, s, v) in sdk_vectors() {
            let digest = agent_digest(network, &action_hash(&action, 0, None, None).unwrap());
            let signer = recover_signer(&digest, &sdk_signature(r, s, v)).unwrap();
            assert_eq!(signer.to_hex(), SDK_TEST_ADDRESS, "{network:?}");
            // The same signature read for the other network names someone
            // else: a testnet signature never passes as a mainnet one.
            let other = match network {
                Network::Mainnet => Network::Testnet,
                Network::Testnet => Network::Mainnet,
            };
            let digest = agent_digest(other, &action_hash(&action, 0, None, None).unwrap());
            assert_ne!(
                recover_signer(&digest, &sdk_signature(r, s, v)).map(|a| a.to_hex()),
                Some(SDK_TEST_ADDRESS.to_owned())
            );
        }
    }

    #[test]
    fn connection_id_matches_production() {
        // test_phantom_agent_creation_matches_production: ETH as asset 4,
        // buy 0.0147 at 1670.1, IOC, nonce 1677777606040.
        let action = Wire::Map(vec![
            ("type", Wire::str("order")),
            (
                "orders",
                Wire::Array(vec![Wire::Map(vec![
                    ("a", Wire::UInt(4)),
                    ("b", Wire::Bool(true)),
                    ("p", Wire::str("1670.1")),
                    ("s", Wire::str("0.0147")),
                    ("r", Wire::Bool(false)),
                    (
                        "t",
                        Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Ioc"))]))]),
                    ),
                ])]),
            ),
            ("grouping", Wire::str("na")),
        ]);
        let hash = action_hash(&action, 1_677_777_606_040, None, None).unwrap();
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "0fcbeda5ae3c4950a548021552a4fea2226858c4453571bf3f24ba017eac2908"
        );
    }

    #[test]
    fn vault_and_expiry_change_the_hash_in_the_sdk_layout() {
        // action_hash in signing.py: msgpack ‖ nonce ‖ (0x00 | 0x01 ‖ vault)
        // ‖ (0x00 ‖ expires_after).
        let action = dummy_action();
        let vault = Address::from_hex(SDK_TEST_ADDRESS).unwrap();
        let mut data = action.to_msgpack().unwrap();
        data.extend_from_slice(&5u64.to_be_bytes());
        data.push(0x01);
        data.extend_from_slice(vault.as_bytes());
        data.push(0x00);
        data.extend_from_slice(&9u64.to_be_bytes());
        assert_eq!(
            action_hash(&action, 5, Some(vault), Some(9)).unwrap(),
            keccak256(&data)
        );
    }

    #[test]
    fn a_bad_signature_recovers_nobody() {
        let digest = [7u8; 32];
        let good = key().sign_digest(&digest).unwrap();
        assert_eq!(
            recover_signer(&digest, &good).unwrap().to_hex(),
            SDK_TEST_ADDRESS
        );
        for bad in [
            Signature { v: 26, ..good },
            Signature { v: 29, ..good },
            Signature { r: [0; 32], ..good },
            Signature { s: [0; 32], ..good },
            Signature {
                r: [0xff; 32],
                ..good
            },
        ] {
            assert_ne!(
                recover_signer(&digest, &bad).map(|a| a.to_hex()),
                Some(SDK_TEST_ADDRESS.to_owned())
            );
        }
    }

    #[test]
    fn the_secret_never_shows() {
        let key = key();
        let shown = format!("{key:?} {key:#?}");
        assert!(shown.contains(SDK_TEST_ADDRESS));
        assert!(!shown.contains("0123456789012345"));
        assert_eq!(GuardKey::from_hex("0x12").unwrap_err(), KeyError::Malformed);
        assert_eq!(
            GuardKey::from_hex(&"0".repeat(64)).unwrap_err(),
            KeyError::Invalid
        );
    }
}
