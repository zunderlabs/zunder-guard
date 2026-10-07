// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! An independent implementation of Hyperliquid's L1-action signing.
//!
//! This exists so the red-team suite can forge, sign and send requests
//! exactly as a bot would, **without** sharing any code with the Guard it
//! attacks. A bug in Guard's own signer therefore cannot hide a matching
//! bug here. The byte layout is pinned against the official Python SDK's
//! signing vectors in the tests at the bottom of this file, the same
//! vectors Zunder's own executor and `zunder-guard-core` pin against.
//!
//! An action is encoded as MessagePack; the nonce follows as 8 big-endian
//! bytes, then `0x00` for "no vault", then, if the action expires, `0x00`
//! and the expiry as 8 big-endian bytes. The Keccak-256 of that is the
//! `connectionId`. A phantom agent `{source, connectionId}` is then signed
//! as EIP-712 typed data (domain `Exchange`, version `1`, chainId 1337,
//! verifyingContract zero); `source` is `"a"` for mainnet and `"b"` for
//! testnet.

use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// A secp256k1/Keccak Ethereum-style address (20 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(42);
        out.push_str("0x");
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    pub fn from_hex(text: &str) -> Option<Self> {
        let digits = text.strip_prefix("0x").unwrap_or(text);
        if digits.len() != 40 {
            return None;
        }
        let mut bytes = [0u8; 20];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::from_str_radix(digits.get(2 * index..2 * index + 2)?, 16).ok()?;
        }
        Some(Address(bytes))
    }
}

/// The phantom-agent source a request is signed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningNet {
    Mainnet,
    Testnet,
}

impl SigningNet {
    pub fn source(self) -> &'static str {
        match self {
            SigningNet::Mainnet => "a",
            SigningNet::Testnet => "b",
        }
    }
}

/// An ECDSA signature in Hyperliquid's `{r, s, v}` form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sig {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

/// A value in the exact shape Hyperliquid hashes and accepts: one `Wire`
/// is both MessagePack-hashed for the signature and JSON-encoded for the
/// body, so what is signed is what is sent, field for field and in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wire {
    Null,
    Bool(bool),
    UInt(u64),
    Int(i64),
    Str(String),
    Array(Vec<Wire>),
    /// Keys in encoding order.
    Map(Vec<(String, Wire)>),
}

impl Wire {
    pub fn str(text: impl Into<String>) -> Self {
        Wire::Str(text.into())
    }

    pub fn map(entries: Vec<(&str, Wire)>) -> Self {
        Wire::Map(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    pub fn to_msgpack(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Wire::Null => out.push(0xc0),
            Wire::Bool(false) => out.push(0xc2),
            Wire::Bool(true) => out.push(0xc3),
            Wire::UInt(value) => encode_uint(*value, out),
            Wire::Int(value) => encode_int(*value, out),
            Wire::Str(text) => encode_str(text, out),
            Wire::Array(items) => {
                encode_len(items.len(), 0x90, 0xdc, 0xdd, out);
                for item in items {
                    item.encode(out);
                }
            }
            Wire::Map(entries) => {
                encode_len(entries.len(), 0x80, 0xde, 0xdf, out);
                for (key, value) in entries {
                    encode_str(key, out);
                    value.encode(out);
                }
            }
        }
    }

    pub fn to_json_value(&self) -> serde_json::Value {
        use serde_json::Value;
        match self {
            Wire::Null => Value::Null,
            Wire::Bool(value) => Value::Bool(*value),
            Wire::UInt(value) => Value::from(*value),
            Wire::Int(value) => Value::from(*value),
            Wire::Str(text) => Value::String(text.clone()),
            Wire::Array(items) => Value::Array(items.iter().map(Wire::to_json_value).collect()),
            Wire::Map(entries) => Value::Object(
                entries
                    .iter()
                    .map(|(key, value)| (key.clone(), value.to_json_value()))
                    .collect(),
            ),
        }
    }
}

fn encode_uint(value: u64, out: &mut Vec<u8>) {
    if value < 0x80 {
        out.push(value as u8);
    } else if let Ok(byte) = u8::try_from(value) {
        out.push(0xcc);
        out.push(byte);
    } else if let Ok(short) = u16::try_from(value) {
        out.push(0xcd);
        out.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(word) = u32::try_from(value) {
        out.push(0xce);
        out.extend_from_slice(&word.to_be_bytes());
    } else {
        out.push(0xcf);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_int(value: i64, out: &mut Vec<u8>) {
    if value >= 0 {
        encode_uint(value as u64, out);
    } else if value >= -32 {
        out.push((value as i8) as u8);
    } else if let Ok(byte) = i8::try_from(value) {
        out.push(0xd0);
        out.push(byte as u8);
    } else if let Ok(short) = i16::try_from(value) {
        out.push(0xd1);
        out.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(word) = i32::try_from(value) {
        out.push(0xd2);
        out.extend_from_slice(&word.to_be_bytes());
    } else {
        out.push(0xd3);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_str(text: &str, out: &mut Vec<u8>) {
    let bytes = text.as_bytes();
    let len = bytes.len();
    if len < 32 {
        out.push(0xa0 | len as u8);
    } else if let Ok(byte) = u8::try_from(len) {
        out.push(0xd9);
        out.push(byte);
    } else if let Ok(short) = u16::try_from(len) {
        out.push(0xda);
        out.extend_from_slice(&short.to_be_bytes());
    } else {
        out.push(0xdb);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}

fn encode_len(len: usize, fix: u8, with16: u8, with32: u8, out: &mut Vec<u8>) {
    if len < 16 {
        out.push(fix | len as u8);
    } else if let Ok(short) = u16::try_from(len) {
        out.push(with16);
        out.extend_from_slice(&short.to_be_bytes());
    } else {
        out.push(with32);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

/// The `connectionId` of an action.
pub fn action_hash(action: &Wire, nonce: u64, expires_after: Option<u64>) -> [u8; 32] {
    let mut data = action.to_msgpack();
    data.extend_from_slice(&nonce.to_be_bytes());
    data.push(0x00);
    if let Some(expires_after) = expires_after {
        data.push(0x00);
        data.extend_from_slice(&expires_after.to_be_bytes());
    }
    keccak256(&data)
}

/// The EIP-712 digest of the phantom agent.
pub fn agent_digest(network: SigningNet, connection_id: &[u8; 32]) -> [u8; 32] {
    let domain_type = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let mut chain_id = [0u8; 32];
    chain_id[24..].copy_from_slice(&1337u64.to_be_bytes());
    let domain_separator = keccak256(
        &[
            &domain_type[..],
            &keccak256(b"Exchange"),
            &keccak256(b"1"),
            &chain_id,
            &[0u8; 32],
        ]
        .concat(),
    );
    let agent_type = keccak256(b"Agent(string source,bytes32 connectionId)");
    let struct_hash = keccak256(
        &[
            &agent_type[..],
            &keccak256(network.source().as_bytes()),
            connection_id,
        ]
        .concat(),
    );
    keccak256(&[&[0x19, 0x01][..], &domain_separator, &struct_hash].concat())
}

fn address_of_public_key(key: &VerifyingKey) -> Address {
    let point = key.to_sec1_point(false);
    let public = point.as_bytes();
    let hash = keccak256(public.get(1..).unwrap_or_default());
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    Address(address)
}

/// The address that signed `digest`, as Hyperliquid recovers it; `None`
/// for a signature that recovers no key.
pub fn recover_signer(digest: &[u8; 32], sig: &Sig) -> Option<Address> {
    let recovery = RecoveryId::from_byte(sig.v.checked_sub(27)?)?;
    let ecdsa = EcdsaSignature::from_slice(&[sig.r, sig.s].concat()).ok()?;
    let key = VerifyingKey::recover_from_prehash(digest, &ecdsa, recovery).ok()?;
    Some(address_of_public_key(&key))
}

/// A signing key the suite uses to play a bot.
pub struct Key {
    key: SigningKey,
    address: Address,
}

impl Key {
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let key = SigningKey::from_slice(bytes).ok()?;
        let address = address_of_public_key(key.verifying_key());
        Some(Self { key, address })
    }

    pub fn from_hex(secret: &str) -> Option<Self> {
        let digits = secret.trim().strip_prefix("0x").unwrap_or(secret.trim());
        if digits.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::from_str_radix(digits.get(2 * index..2 * index + 2)?, 16).ok()?;
        }
        Self::from_bytes(&bytes)
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> Option<Sig> {
        let (signature, recovery) = self.key.sign_prehash_recoverable(digest);
        let recovery = u8::from(recovery);
        if recovery > 1 {
            return None;
        }
        let (r, s) = signature.split_bytes();
        Some(Sig {
            r: r.into(),
            s: s.into(),
            v: 27 + recovery,
        })
    }

    pub fn sign_l1_action(
        &self,
        network: SigningNet,
        action: &Wire,
        nonce: u64,
        expires_after: Option<u64>,
    ) -> Option<Sig> {
        let connection_id = action_hash(action, nonce, expires_after);
        self.sign_digest(&agent_digest(network, &connection_id))
    }
}

/// `0x`-prefixed hex of a 32-byte scalar with leading zero bytes trimmed,
/// as Hyperliquid's SDK writes `r` and `s` in a request body.
pub fn minimal_hex(bytes: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(66);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDK_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn order_action(asset: u64, is_buy: bool, price: &str, size: &str, tif: &str) -> Wire {
        Wire::map(vec![
            ("type", Wire::str("order")),
            (
                "orders",
                Wire::Array(vec![Wire::map(vec![
                    ("a", Wire::UInt(asset)),
                    ("b", Wire::Bool(is_buy)),
                    ("p", Wire::str(price)),
                    ("s", Wire::str(size)),
                    ("r", Wire::Bool(false)),
                    (
                        "t",
                        Wire::map(vec![("limit", Wire::map(vec![("tif", Wire::str(tif))]))]),
                    ),
                ])]),
            ),
            ("grouping", Wire::str("na")),
        ])
    }

    #[test]
    fn connection_id_matches_the_sdk_production_vector() {
        // test_phantom_agent_creation_matches_production in the Python SDK.
        let action = order_action(4, true, "1670.1", "0.0147", "Ioc");
        assert_eq!(
            hex(&action_hash(&action, 1_677_777_606_040, None)),
            "0fcbeda5ae3c4950a548021552a4fea2226858c4453571bf3f24ba017eac2908"
        );
    }

    #[test]
    fn dummy_action_matches_the_sdk_testnet_signature() {
        // test_l1_action_signing_matches, testnet half.
        let action = Wire::map(vec![
            ("type", Wire::str("dummy")),
            ("num", Wire::UInt(100_000_000_000)),
        ]);
        let key = Key::from_hex(SDK_KEY).unwrap();
        let sig = key
            .sign_l1_action(SigningNet::Testnet, &action, 0, None)
            .unwrap();
        assert_eq!(
            minimal_hex(&sig.r),
            "0x542af61ef1f429707e3c76c5293c80d01f74ef853e34b76efffcb57e574f9510"
        );
        assert_eq!(
            minimal_hex(&sig.s),
            "0x17b8b32f086e8cdede991f1e2c529f5dd5297cbe8128500e00cbaf766204a613"
        );
        assert_eq!(sig.v, 28);
    }

    #[test]
    fn a_signature_recovers_the_signer() {
        let action = order_action(1, true, "100", "100", "Gtc");
        let key = Key::from_hex(SDK_KEY).unwrap();
        let sig = key
            .sign_l1_action(SigningNet::Testnet, &action, 0, None)
            .unwrap();
        let digest = agent_digest(SigningNet::Testnet, &action_hash(&action, 0, None));
        assert_eq!(recover_signer(&digest, &sig), Some(key.address()));
    }
}
