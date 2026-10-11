// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Signing the three actions this server can send, with Guard's client key,
//! exactly as the official Python SDK signs an L1 action:
//! `zunder-hl-protocol`'s signer (MessagePack, the `connectionId`, the
//! phantom agent's EIP-712 digest), the one implementation Zunder's
//! executor and Guard share. The phantom agent's source is `"a"` for
//! [`Network::Mainnet`] and `"b"` for [`Network::Testnet`], which paper uses
//! too (Guard accepts either source from a client; it signs the real action
//! for its own network itself).
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
use zeroize::Zeroizing;
use zunder_hl_protocol::{
    Network, Signature, Wire,
    sign::{self as hl_sign, parse_hex32},
    wire::minimal_hex,
};
use zunder_venue::hyperliquid::Address;

use crate::contract::Mode;

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
        let address = hl_sign::address_of(&key);
        Ok(Self { key, address })
    }

    pub fn address(&self) -> Address {
        self.address
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

pub(crate) fn sign_wire(
    key: &ClientKey,
    source: Network,
    action: &Wire,
    nonce: u64,
    expires_after: Option<u64>,
) -> Option<Signature> {
    hl_sign::sign_l1_action(&key.key, source, action, nonce, expires_after).ok()
}

/// `{"r", "s", "v"}` of a request body.
fn signature_wire(signature: &Signature) -> Wire {
    Wire::Map(vec![
        ("r", Wire::str(minimal_hex(&signature.r))),
        ("s", Wire::str(minimal_hex(&signature.s))),
        ("v", Wire::UInt(u64::from(signature.v))),
    ])
}

/// The JSON body of a request to `/exchange`, in the Python SDK's field
/// order (action, nonce, signature, vaultAddress, expiresAfter), followed
/// by Guard's `expectedMode`: the mode this server was started for. The
/// vault address is always null. `None` when it cannot be signed.
///
/// `expectedMode` sits beside the signed fields and is not signed: the
/// signature covers exactly what the SDK's would. Guard refuses the request
/// (`mode_mismatch`) before judging or sending anything when it runs in
/// another mode, so a request meant for one network is never sent on
/// another, even when another Guard took over the address after this
/// server last read its status.
pub fn signed_request(
    key: &ClientKey,
    source: Network,
    action: &Action,
    nonce: u64,
    expires_after: Option<u64>,
    expected_mode: Mode,
) -> Option<Vec<u8>> {
    let wire = action.to_wire();
    let signature = sign_wire(key, source, &wire, nonce, expires_after)?;
    let request = Wire::Map(vec![
        ("action", wire),
        ("nonce", Wire::UInt(nonce)),
        ("signature", signature_wire(&signature)),
        ("vaultAddress", Wire::Null),
        ("expiresAfter", expires_after.map_or(Wire::Null, Wire::UInt)),
        ("expectedMode", Wire::str(expected_mode.name())),
    ]);
    request.to_json().ok()
}

/// The body of Guard's own kill request (`POST /guard/kill`): the action
/// `{"type": "zunderGuardKill", "reason": reason}`, signed exactly as an L1
/// action. It is not a Hyperliquid action and not an [`Action`]: it can
/// only pull Guard's kill switch, which nothing but a person releases.
/// With `expected_mode`, the body ends with Guard's `expectedMode` (not
/// signed), which a Guard listing `capabilities.kill_expected_mode`
/// enforces: one in another mode pulls nothing (`mode_mismatch`). Sent only
/// to such a Guard; an older one refuses the field. `None` when it cannot
/// be signed.
pub fn signed_kill_request(
    key: &ClientKey,
    source: Network,
    reason: &str,
    nonce: u64,
    expected_mode: Option<Mode>,
) -> Option<Vec<u8>> {
    let wire = Wire::Map(vec![
        ("type", Wire::str("zunderGuardKill")),
        ("reason", Wire::str(reason)),
    ]);
    let signature = sign_wire(key, source, &wire, nonce, None)?;
    let mut fields = vec![
        ("action", wire),
        ("nonce", Wire::UInt(nonce)),
        ("signature", signature_wire(&signature)),
        ("vaultAddress", Wire::Null),
    ];
    if let Some(mode) = expected_mode {
        fields.push(("expectedMode", Wire::str(mode.name())));
    }
    Wire::Map(fields).to_json().ok()
}

/// The action as JSON, exactly as it is sent.
pub fn action_json(action: &Action) -> serde_json::Value {
    action.to_wire().to_value()
}

/// The address that signed `action` with this nonce and expiry: what Guard
/// does to authenticate a client. Used by the tests' mock Guard to check
/// every request this server sends.
pub fn recover_signer(
    action: &Action,
    nonce: u64,
    expires_after: Option<u64>,
    source: Network,
    r: &str,
    s: &str,
    v: u64,
) -> Option<Address> {
    let signature = Signature {
        r: parse_hex32(r)?,
        s: parse_hex32(s)?,
        v: u8::try_from(v).ok()?,
    };
    let connection_id = hl_sign::action_hash(&action.to_wire(), nonce, None, expires_after).ok()?;
    hl_sign::recover_signer(&hl_sign::agent_digest(source, &connection_id), &signature)
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
        let hash = hl_sign::action_hash(&action.to_wire(), 1_677_777_606_040, None, None).unwrap();
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
            sign_wire(&key(), Network::Testnet, &dummy, 0, None).unwrap(),
            "0x542af61ef1f429707e3c76c5293c80d01f74ef853e34b76efffcb57e574f9510",
            "0x17b8b32f086e8cdede991f1e2c529f5dd5297cbe8128500e00cbaf766204a613",
            28,
        );
        assert_signature(
            sign_wire(&key(), Network::Mainnet, &dummy, 0, None).unwrap(),
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
                Network::Testnet,
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
                Network::Testnet,
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
                Network::Testnet,
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
    fn a_kill_request_carries_the_expected_mode_only_when_asked() {
        let body = |mode| {
            let bytes =
                signed_kill_request(&key(), Network::Testnet, "stop", 1_791_000_000_000, mode)
                    .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            (bytes, value)
        };
        let (_, plain) = body(None);
        assert!(plain.get("expectedMode").is_none());
        let (bytes, with) = body(Some(Mode::Mainnet));
        assert!(bytes.ends_with(br#","expectedMode":"mainnet"}"#));
        // Not signed: the signature and the action are the same.
        assert_eq!(with["signature"], plain["signature"]);
        assert_eq!(with["action"], plain["action"]);
        assert_eq!(body(Some(Mode::Paper)).1["expectedMode"], "paper");
    }

    #[test]
    fn a_signed_request_recovers_to_the_client_key() {
        let action = Action::Cancel { asset: 1, oid: 9 };
        let body = signed_request(
            &key(),
            Network::Testnet,
            &action,
            1_791_000_000_000,
            Some(1_791_000_030_000),
            Mode::Testnet,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["vaultAddress"], serde_json::Value::Null);
        assert_eq!(value["expiresAfter"], 1_791_000_030_000u64);
        // The expected mode rides beside the signed fields, last; the
        // signature below recovers from the action, nonce and expiry alone.
        assert_eq!(value["expectedMode"], "testnet");
        assert!(body.ends_with(br#","expectedMode":"testnet"}"#));
        for (mode, name) in [
            (Mode::Paper, "paper"),
            (Mode::Testnet, "testnet"),
            (Mode::Mainnet, "mainnet"),
        ] {
            let other = signed_request(
                &key(),
                Network::Testnet,
                &action,
                1_791_000_000_000,
                Some(1_791_000_030_000),
                mode,
            )
            .unwrap();
            let other: serde_json::Value = serde_json::from_slice(&other).unwrap();
            assert_eq!(other["expectedMode"], name);
            // Signing is deterministic (RFC 6979): the mode changes no
            // signed byte.
            assert_eq!(other["signature"], value["signature"]);
            assert_eq!(other["action"], value["action"]);
        }
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
        let digest = hl_sign::agent_digest(
            Network::Testnet,
            &hl_sign::action_hash(
                &action.to_wire(),
                1_791_000_000_000,
                None,
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
        assert_eq!(hl_sign::address_of_public_key(&signer), key().address());
    }

    /// A deterministic generator (xorshift64*), so that a failure reproduces.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }

        fn coin(&mut self) -> bool {
            self.next() & 1 == 1
        }
    }

    fn number(rng: &mut Rng) -> String {
        let value =
            rust_decimal::Decimal::new(1 + rng.below(999_999_999) as i64, rng.below(9) as u32);
        zunder_hl_protocol::wire::decimal(value).unwrap()
    }

    fn random_order(rng: &mut Rng) -> OrderWire {
        let order_type = match rng.below(3) {
            0 => OrderType::Limit { tif: Tif::Gtc },
            1 => OrderType::Limit { tif: Tif::Ioc },
            _ => OrderType::StopMarket {
                trigger_px: number(rng),
            },
        };
        OrderWire {
            asset: [0, 1, 4, 127, 128, 255, 10_107, 110_000][rng.below(8) as usize],
            is_buy: rng.coin(),
            price: number(rng),
            size: number(rng),
            reduce_only: rng.coin(),
            order_type,
            cloid: rng
                .coin()
                .then(|| format!("0x{:016x}{:016x}", rng.next(), rng.next())),
        }
    }

    /// Every action this server builds, re-encoded by Guard core's decoder
    /// (which writes the venue's own field order whatever order a bot's
    /// JSON used): the same MessagePack, so the same connection id. The
    /// builders here, in Zunder's executor and in Guard core are separate
    /// code; this holds this server's to Guard's on random orders, cancels
    /// and modifies beyond the SDK's fixed vectors.
    #[test]
    fn every_action_built_here_is_encoded_as_guard_core_encodes_it() {
        let mut rng = Rng(0x5eed_0005);
        for case in 0..500 {
            let action = match rng.below(4) {
                0 => Action::Cancel {
                    asset: rng.below(200_000) as u32,
                    oid: rng.next() >> rng.below(64),
                },
                1 => Action::Modify {
                    oid: rng.next() >> rng.below(64),
                    order: random_order(&mut rng),
                },
                _ => Action::Order {
                    orders: (0..1 + rng.below(3))
                        .map(|_| random_order(&mut rng))
                        .collect(),
                    grouping: if rng.coin() {
                        Grouping::Na
                    } else {
                        Grouping::NormalTpsl
                    },
                },
            };
            let wire = action.to_wire();
            let json = action_json(&action);
            let decoded = zunder_guard_core::action::decode_action_value(&json)
                .unwrap_or_else(|error| panic!("{case}: {error} {json}"));
            assert_eq!(
                decoded.to_wire().to_msgpack().unwrap(),
                wire.to_msgpack().unwrap(),
                "{case}: {json}"
            );
        }
    }
}
