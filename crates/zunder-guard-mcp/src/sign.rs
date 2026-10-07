// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Signing the three actions this server can send, with Guard's client key,
//! exactly as the official Python SDK signs an L1 action.
//!
//! 1. The action is encoded as MessagePack in the SDK's field order; the
//!    nonce follows as 8 big-endian bytes, then `0x00` ("no vault"), then,
//!    when the request expires, `0x00` and the expiry as 8 big-endian bytes.
//!    The Keccak-256 hash of that is the `connectionId`.
//! 2. The phantom agent `{source, connectionId}` is signed as EIP-712 typed
//!    data (`Agent(string source,bytes32 connectionId)`, domain `Exchange`,
//!    version `1`, chain id 1337, verifying contract zero). `source` is `"a"`
//!    for mainnet and `"b"` otherwise.
//!
//! **What can be signed is closed by type.** [`Action`] has three variants:
//! an `order`, a `cancel` and a `modify`. There is no variant, constructor or
//! escape hatch for any other action: no transfer, withdrawal, approval,
//! leverage update, vault action or raw JSON. A client signature only
//! authenticates the agent to Guard; Guard decides, re-signs with the real
//! API wallet key, and refuses anything it does not forward.
//!
//! The unit tests pin this against the signatures in the Python SDK's own
//! test suite (the same vectors Zunder's own executor pins).

use std::fmt;

use k256::ecdsa::SigningKey;
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;
use zunder_venue::hyperliquid::Address;

/// The phantom agent's source: which network a signature is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningSource {
    /// `"a"`.
    Mainnet,
    /// `"b"`: testnet, and paper (Guard accepts either source from a client;
    /// it signs the real action for its own network itself).
    Testnet,
}

impl SigningSource {
    fn letter(self) -> &'static str {
        match self {
            SigningSource::Mainnet => "a",
            SigningSource::Testnet => "b",
        }
    }
}

/// A value inside an action or request, in the order it is encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Wire {
    Null,
    Bool(bool),
    UInt(u64),
    Str(String),
    Array(Vec<Wire>),
    Map(Vec<(&'static str, Wire)>),
}

impl Wire {
    fn str(text: impl Into<String>) -> Self {
        Wire::Str(text.into())
    }

    /// MessagePack with the smallest encoding for every integer, string,
    /// array and map length, as Python's `msgpack.packb` writes it. `None`
    /// for something too large for 32-bit lengths.
    pub(crate) fn to_msgpack(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Some(out)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Option<()> {
        match self {
            Wire::Null => out.push(0xc0),
            Wire::Bool(false) => out.push(0xc2),
            Wire::Bool(true) => out.push(0xc3),
            Wire::UInt(value) => encode_uint(*value, out),
            Wire::Str(text) => encode_str(text, out)?,
            Wire::Array(items) => {
                encode_len(items.len(), 0x90, 0xdc, 0xdd, out)?;
                for item in items {
                    item.encode(out)?;
                }
            }
            Wire::Map(entries) => {
                encode_len(entries.len(), 0x80, 0xde, 0xdf, out)?;
                for (key, value) in entries {
                    encode_str(key, out)?;
                    value.encode(out)?;
                }
            }
        }
        Some(())
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

fn encode_str(text: &str, out: &mut Vec<u8>) -> Option<()> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    if len < 32 {
        out.push(0xa0 | len as u8);
    } else if let Ok(len) = u8::try_from(len) {
        out.push(0xd9);
        out.push(len);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(0xda);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        let len = u32::try_from(len).ok()?;
        out.push(0xdb);
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(bytes);
    Some(())
}

fn encode_len(len: usize, fix: u8, marker16: u8, marker32: u8, out: &mut Vec<u8>) -> Option<()> {
    if len < 16 {
        out.push(fix | len as u8);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(marker16);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        let len = u32::try_from(len).ok()?;
        out.push(marker32);
        out.extend_from_slice(&len.to_be_bytes());
    }
    Some(())
}

impl Serialize for Wire {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Wire::Null => serializer.serialize_unit(),
            Wire::Bool(value) => serializer.serialize_bool(*value),
            Wire::UInt(value) => serializer.serialize_u64(*value),
            Wire::Str(text) => serializer.serialize_str(text),
            Wire::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Wire::Map(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

/// `t` of an order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderType {
    /// `"Gtc"` or `"Ioc"`.
    Limit { tif: Tif },
    /// A stop loss (`tpsl: "sl"`), executed as a market order. There is no
    /// take-profit variant: this server never sends one.
    StopMarket { trigger_px: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tif {
    Gtc,
    Ioc,
}

impl Tif {
    fn name(self) -> &'static str {
        match self {
            Tif::Gtc => "Gtc",
            Tif::Ioc => "Ioc",
        }
    }
}

/// One order, prices and sizes already on the venue's grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderWire {
    pub asset: u32,
    pub is_buy: bool,
    pub price: String,
    pub size: String,
    pub reduce_only: bool,
    pub order_type: OrderType,
    /// `0x` and 32 hex digits.
    pub cloid: Option<String>,
}

impl OrderWire {
    fn to_wire(&self) -> Wire {
        let order_type = match &self.order_type {
            OrderType::Limit { tif } => Wire::Map(vec![(
                "limit",
                Wire::Map(vec![("tif", Wire::str(tif.name()))]),
            )]),
            OrderType::StopMarket { trigger_px } => Wire::Map(vec![(
                "trigger",
                Wire::Map(vec![
                    ("isMarket", Wire::Bool(true)),
                    ("triggerPx", Wire::str(trigger_px.clone())),
                    ("tpsl", Wire::str("sl")),
                ]),
            )]),
        };
        let mut fields = vec![
            ("a", Wire::UInt(u64::from(self.asset))),
            ("b", Wire::Bool(self.is_buy)),
            ("p", Wire::str(self.price.clone())),
            ("s", Wire::str(self.size.clone())),
            ("r", Wire::Bool(self.reduce_only)),
            ("t", order_type),
        ];
        if let Some(cloid) = &self.cloid {
            fields.push(("c", Wire::str(cloid.clone())));
        }
        Wire::Map(fields)
    }
}

/// How the orders of one `order` action belong together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grouping {
    /// Independent orders.
    Na,
    /// An entry followed by its stop loss, as the SDKs send TP/SL.
    NormalTpsl,
}

/// Everything this server can sign. Three variants, on purpose: see the
/// module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Order {
        orders: Vec<OrderWire>,
        grouping: Grouping,
    },
    Cancel {
        asset: u32,
        oid: u64,
    },
    Modify {
        oid: u64,
        order: OrderWire,
    },
}

impl Action {
    /// The action's `type`.
    pub fn kind(&self) -> &'static str {
        match self {
            Action::Order { .. } => "order",
            Action::Cancel { .. } => "cancel",
            Action::Modify { .. } => "modify",
        }
    }

    /// In the Python SDK's field order.
    pub(crate) fn to_wire(&self) -> Wire {
        match self {
            Action::Order { orders, grouping } => Wire::Map(vec![
                ("type", Wire::str("order")),
                (
                    "orders",
                    Wire::Array(orders.iter().map(OrderWire::to_wire).collect()),
                ),
                (
                    "grouping",
                    Wire::str(match grouping {
                        Grouping::Na => "na",
                        Grouping::NormalTpsl => "normalTpsl",
                    }),
                ),
            ]),
            Action::Cancel { asset, oid } => Wire::Map(vec![
                ("type", Wire::str("cancel")),
                (
                    "cancels",
                    Wire::Array(vec![Wire::Map(vec![
                        ("a", Wire::UInt(u64::from(*asset))),
                        ("o", Wire::UInt(*oid)),
                    ])]),
                ),
            ]),
            Action::Modify { oid, order } => Wire::Map(vec![
                ("type", Wire::str("modify")),
                ("oid", Wire::UInt(*oid)),
                ("order", order.to_wire()),
            ]),
        }
    }
}

/// An ECDSA signature in Ethereum's form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// 27 or 28.
    pub v: u8,
}

/// Guard's client key for this agent: it authenticates requests to Guard
/// and nothing else. It is no API wallet of the account; the venue would
/// refuse its signature. Never printed, logged or serialised: no `Display`,
/// no `Serialize`, no `Clone`, a `Debug` that shows the address only; the
/// secret scalar is wiped when dropped (k256's `SigningKey`).
pub struct ClientKey {
    key: SigningKey,
    address: Address,
}

impl ClientKey {
    /// Parse 64 hex digits, optionally with `0x` and whitespace around them.
    /// The error never contains any of the input.
    pub fn from_hex(secret: &str) -> Result<Self, KeyParseError> {
        let secret = secret.trim();
        let digits = secret.strip_prefix("0x").unwrap_or(secret);
        if digits.len() != 64 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(KeyParseError::Malformed);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        for (index, byte) in bytes.iter_mut().enumerate() {
            let pair = digits
                .get(2 * index..2 * index + 2)
                .ok_or(KeyParseError::Malformed)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| KeyParseError::Malformed)?;
        }
        let key = SigningKey::from_slice(bytes.as_ref()).map_err(|_| KeyParseError::Invalid)?;
        let address = address_of(&key);
        Ok(Self { key, address })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Option<Signature> {
        let (signature, recovery) = self.key.sign_prehash_recoverable(digest);
        let recovery = u8::from(recovery);
        // Ids 2 and 3 cannot be written as an Ethereum `v` (about 2^-127).
        if recovery > 1 {
            return None;
        }
        let (r, s) = signature.split_bytes();
        Some(Signature {
            r: r.into(),
            s: s.into(),
            v: 27 + recovery,
        })
    }
}

impl fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientKey")
            .field("address", &self.address)
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyParseError {
    #[error("the client key must be 64 hex digits, optionally prefixed with 0x")]
    Malformed,
    #[error("the client key is not a valid secp256k1 private key")]
    Invalid,
}

fn address_of(key: &SigningKey) -> Address {
    address_of_public_key(key.verifying_key())
}

/// Ethereum address of a public key.
pub(crate) fn address_of_public_key(key: &k256::ecdsa::VerifyingKey) -> Address {
    let point = key.to_sec1_point(false);
    let public = point.as_bytes();
    let hash = Keccak256::digest(public.get(1..).unwrap_or_default());
    let hex: String = hash
        .get(12..32)
        .unwrap_or_default()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    // 40 hex digits always parse; the fallback is never taken.
    Address::from_hex(&format!("0x{hex}")).unwrap_or_else(|| {
        Address::from_hex("0x0000000000000000000000000000000000000000")
            .expect("the zero address parses")
    })
}

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// The `connectionId` of an action.
pub(crate) fn action_hash(
    action: &Wire,
    nonce: u64,
    expires_after: Option<u64>,
) -> Option<[u8; 32]> {
    let mut data = action.to_msgpack()?;
    data.extend_from_slice(&nonce.to_be_bytes());
    data.push(0x00);
    if let Some(expires_after) = expires_after {
        data.push(0x00);
        data.extend_from_slice(&expires_after.to_be_bytes());
    }
    Some(keccak256(&data))
}

/// The EIP-712 digest of the phantom agent.
pub(crate) fn agent_digest(source: SigningSource, connection_id: &[u8; 32]) -> [u8; 32] {
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
            &keccak256(source.letter().as_bytes()),
            connection_id,
        ]
        .concat(),
    );
    keccak256(&[&[0x19, 0x01][..], &domain_separator, &struct_hash].concat())
}

pub(crate) fn sign_wire(
    key: &ClientKey,
    source: SigningSource,
    action: &Wire,
    nonce: u64,
    expires_after: Option<u64>,
) -> Option<Signature> {
    let connection_id = action_hash(action, nonce, expires_after)?;
    key.sign_digest(&agent_digest(source, &connection_id))
}

/// The JSON body of a request to `/exchange`, in the Python SDK's field
/// order (action, nonce, signature, vaultAddress, expiresAfter). The vault
/// address is always null. `None` when it cannot be signed.
pub fn signed_request(
    key: &ClientKey,
    source: SigningSource,
    action: &Action,
    nonce: u64,
    expires_after: Option<u64>,
) -> Option<Vec<u8>> {
    let wire = action.to_wire();
    let signature = sign_wire(key, source, &wire, nonce, expires_after)?;
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
    serde_json::to_vec(&request).ok()
}

/// The body of Guard's own kill request (`POST /guard/kill`): the action
/// `{"type": "zunderGuardKill", "reason": reason}`, signed exactly as an L1
/// action. It is not a Hyperliquid action and not an [`Action`]: it can
/// only pull Guard's kill switch, which nothing but a person releases.
/// `None` when it cannot be signed.
pub fn signed_kill_request(
    key: &ClientKey,
    source: SigningSource,
    reason: &str,
    nonce: u64,
) -> Option<Vec<u8>> {
    let wire = Wire::Map(vec![
        ("type", Wire::str("zunderGuardKill")),
        ("reason", Wire::str(reason)),
    ]);
    let signature = sign_wire(key, source, &wire, nonce, None)?;
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
    ]);
    serde_json::to_vec(&request).ok()
}

/// The action as JSON, exactly as it is sent.
pub fn action_json(action: &Action) -> serde_json::Value {
    serde_json::to_value(action.to_wire()).unwrap_or(serde_json::Value::Null)
}

/// The address that signed `action` with this nonce and expiry: what Guard
/// does to authenticate a client. Used by the tests' mock Guard to check
/// every request this server sends.
pub fn recover_signer(
    action: &Action,
    nonce: u64,
    expires_after: Option<u64>,
    source: SigningSource,
    r: &str,
    s: &str,
    v: u64,
) -> Option<Address> {
    let fixed = |text: &str| -> Option<[u8; 32]> {
        let digits = text.strip_prefix("0x")?;
        if digits.is_empty() || digits.len() > 64 {
            return None;
        }
        let padded = format!("{digits:0>64}");
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(padded.get(2 * index..2 * index + 2)?, 16).ok()?;
        }
        Some(out)
    };
    let rs = [fixed(r)?, fixed(s)?].concat();
    let recovery = u8::try_from(v.checked_sub(27)?).ok()?;
    let digest = agent_digest(
        source,
        &action_hash(&action.to_wire(), nonce, expires_after)?,
    );
    let signer = k256::ecdsa::VerifyingKey::recover_from_prehash(
        &digest,
        &k256::ecdsa::Signature::from_slice(&rs).ok()?,
        k256::ecdsa::RecoveryId::from_byte(recovery)?,
    )
    .ok()?;
    Some(address_of_public_key(&signer))
}

/// A 256-bit number as `0x` and hex without leading zeros, as the SDKs send
/// `r` and `s`.
pub(crate) fn minimal_hex(bytes: &[u8; 32]) -> String {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
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

    /// The throwaway key of the Python SDK's signing tests
    /// ([hyperliquid-python-sdk](https://github.com/hyperliquid-dex/hyperliquid-python-sdk/blob/master/tests/signing_test.py), MIT).
    const SDK_TEST_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";

    fn key() -> ClientKey {
        ClientKey::from_hex(SDK_TEST_KEY).unwrap()
    }

    fn assert_signature(signature: Signature, r: &str, s: &str, v: u8) {
        assert_eq!(minimal_hex(&signature.r), r);
        assert_eq!(minimal_hex(&signature.s), s);
        assert_eq!(signature.v, v);
    }

    fn sdk_order(order_type: OrderType, cloid: Option<&str>) -> Wire {
        Action::Order {
            orders: vec![OrderWire {
                asset: 1,
                is_buy: true,
                price: "100".into(),
                size: "100".into(),
                reduce_only: false,
                order_type,
                cloid: cloid.map(str::to_owned),
            }],
            grouping: Grouping::Na,
        }
        .to_wire()
    }

    #[test]
    fn the_address_matches_the_ethereum_derivation() {
        // eth_account: 0x14791697260E4c9A71f18484C9f997B308e59325.
        assert_eq!(
            key().address().to_hex(),
            "0x14791697260e4c9a71f18484c9f997b308e59325"
        );
    }

    #[test]
    fn the_secret_never_shows() {
        let shown = format!("{:?}", key());
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains("0123456789012345"));
    }

    #[test]
    fn malformed_keys_are_refused_without_echo() {
        for secret in [
            "0x0123",
            "",
            "0xzz23456789012345678901234567890123456789012345678901234567890123",
        ] {
            let error = ClientKey::from_hex(secret).unwrap_err();
            assert_eq!(error, KeyParseError::Malformed);
            assert!(!error.to_string().contains("0123"));
        }
        assert_eq!(
            ClientKey::from_hex(&"0".repeat(64)).unwrap_err(),
            KeyParseError::Invalid
        );
    }

    #[test]
    fn connection_id_matches_production() {
        // test_phantom_agent_creation_matches_production: asset 4, buy
        // 0.0147 at 1670.1, IOC, nonce 1677777606040.
        let action = Action::Order {
            orders: vec![OrderWire {
                asset: 4,
                is_buy: true,
                price: "1670.1".into(),
                size: "0.0147".into(),
                reduce_only: false,
                order_type: OrderType::Limit { tif: Tif::Ioc },
                cloid: None,
            }],
            grouping: Grouping::Na,
        };
        let hash = action_hash(&action.to_wire(), 1_677_777_606_040, None).unwrap();
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "0fcbeda5ae3c4950a548021552a4fea2226858c4453571bf3f24ba017eac2908"
        );
    }

    #[test]
    fn dummy_action_matches_the_sdk_signatures() {
        // test_l1_action_signing_matches: {"type": "dummy", "num": 10^11}.
        let dummy = Wire::Map(vec![
            ("type", Wire::str("dummy")),
            ("num", Wire::UInt(100_000_000_000)),
        ]);
        assert_signature(
            sign_wire(&key(), SigningSource::Testnet, &dummy, 0, None).unwrap(),
            "0x542af61ef1f429707e3c76c5293c80d01f74ef853e34b76efffcb57e574f9510",
            "0x17b8b32f086e8cdede991f1e2c529f5dd5297cbe8128500e00cbaf766204a613",
            28,
        );
        assert_signature(
            sign_wire(&key(), SigningSource::Mainnet, &dummy, 0, None).unwrap(),
            "0x53749d5b30552aeb2fca34b530185976545bb22d0b3ce6f62e31be961a59298",
            "0x755c40ba9bf05223521753995abb2f73ab3229be8ec921f350cb447e384d8ed8",
            27,
        );
    }

    #[test]
    fn orders_match_the_sdk_testnet_signatures() {
        // test_l1_action_signing_order_matches and
        // test_l1_action_signing_tpsl_order_matches, testnet halves.
        assert_signature(
            sign_wire(
                &key(),
                SigningSource::Testnet,
                &sdk_order(OrderType::Limit { tif: Tif::Gtc }, None),
                0,
                None,
            )
            .unwrap(),
            "0x82b2ba28e76b3d761093aaded1b1cdad4960b3af30212b343fb2e6cdfa4e3d54",
            "0x6b53878fc99d26047f4d7e8c90eb98955a109f44209163f52d8dc4278cbbd9f5",
            27,
        );
        assert_signature(
            sign_wire(
                &key(),
                SigningSource::Testnet,
                &sdk_order(
                    OrderType::StopMarket {
                        trigger_px: "103".into(),
                    },
                    None,
                ),
                0,
                None,
            )
            .unwrap(),
            "0x971c554d917c44e0e1b6cc45d8f9404f32172a9d3b3566262347d0302896a2e4",
            "0x206257b104788f80450f8e786c329daa589aa0b32ba96948201ae556d5637eac",
            28,
        );
        // With a client order id.
        assert_signature(
            sign_wire(
                &key(),
                SigningSource::Testnet,
                &sdk_order(
                    OrderType::Limit { tif: Tif::Gtc },
                    Some("0x00000000000000000000000000000001"),
                ),
                0,
                None,
            )
            .unwrap(),
            "0xeba0664bed2676fc4e5a743bf89e5c7501aa6d870bdb9446e122c9466c5cd16d",
            "0x7f3e74825c9114bc59086f1eebea2928c190fdfbfde144827cb02b85bbe90988",
            28,
        );
    }

    #[test]
    fn cancel_and_modify_follow_the_sdk_field_order() {
        let cancel = Action::Cancel {
            asset: 3,
            oid: 77_738_308,
        };
        assert_eq!(
            serde_json::to_string(&cancel.to_wire()).unwrap(),
            r#"{"type":"cancel","cancels":[{"a":3,"o":77738308}]}"#
        );
        let modify = Action::Modify {
            oid: 5,
            order: OrderWire {
                asset: 0,
                is_buy: false,
                price: "52920".into(),
                size: "0.01".into(),
                reduce_only: true,
                order_type: OrderType::StopMarket {
                    trigger_px: "58800".into(),
                },
                cloid: None,
            },
        };
        assert_eq!(
            serde_json::to_string(&modify.to_wire()).unwrap(),
            concat!(
                r#"{"type":"modify","oid":5,"order":{"a":0,"b":false,"p":"52920","s":"0.01","r":true,"#,
                r#""t":{"trigger":{"isMarket":true,"triggerPx":"58800","tpsl":"sl"}}}}"#
            )
        );
    }

    #[test]
    fn a_signed_request_recovers_to_the_client_key() {
        let action = Action::Cancel { asset: 1, oid: 9 };
        let body = signed_request(
            &key(),
            SigningSource::Testnet,
            &action,
            1_791_000_000_000,
            Some(1_791_000_030_000),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["vaultAddress"], serde_json::Value::Null);
        assert_eq!(value["expiresAfter"], 1_791_000_030_000u64);
        let fixed = |text: &str| {
            let digits = text.trim_start_matches("0x");
            let padded = format!("{digits:0>64}");
            let mut out = [0u8; 32];
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&padded[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        };
        let rs = [
            fixed(value["signature"]["r"].as_str().unwrap()),
            fixed(value["signature"]["s"].as_str().unwrap()),
        ]
        .concat();
        let v = value["signature"]["v"].as_u64().unwrap() as u8;
        let digest = agent_digest(
            SigningSource::Testnet,
            &action_hash(
                &action.to_wire(),
                1_791_000_000_000,
                Some(1_791_000_030_000),
            )
            .unwrap(),
        );
        let signer = k256::ecdsa::VerifyingKey::recover_from_prehash(
            &digest,
            &k256::ecdsa::Signature::from_slice(&rs).unwrap(),
            k256::ecdsa::RecoveryId::from_byte(v - 27).unwrap(),
        )
        .unwrap();
        assert_eq!(address_of_public_key(&signer), key().address());
    }
}
