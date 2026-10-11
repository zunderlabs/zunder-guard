// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The signer against the official Python SDK's own signing vectors
//! (hyperliquid-python-sdk, `tests/signing_test.py`, MIT, read 6 Oct 2026),
//! in both directions: signing gives the SDK's `(r, s, v)`, and recovering
//! the SDK's signatures gives the SDK's key. Until this crate existed, three crates
//! implemented this; a cross-check showed them equal on these vectors, 300
//! random orders and cancels and 400 random MessagePack trees before they
//! were merged into this crate.

#![allow(clippy::unwrap_used)]

use k256::ecdsa::SigningKey;
use zunder_hl_protocol::{
    Address, Network, Signature, Wire,
    sign::{
        action_hash, address_of, agent_digest, keccak256, parse_hex32, recover_signer, sign_digest,
        sign_l1_action,
    },
    wire::{decimal, minimal_hex},
};

/// The throwaway key of the SDK's signing tests.
const SDK_TEST_KEY: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01,
    0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23,
];
/// Its address: eth_account gives 0x14791697260E4c9A71f18484C9f997B308e59325.
const SDK_TEST_ADDRESS: &str = "0x14791697260e4c9a71f18484c9f997b308e59325";

fn key() -> SigningKey {
    SigningKey::from_slice(&SDK_TEST_KEY).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn dummy_action() -> Wire {
    // {"type": "dummy", "num": float_to_int_for_hashing(1000)}.
    Wire::Map(vec![
        ("type", Wire::str("dummy")),
        ("num", Wire::UInt(100_000_000_000)),
    ])
}

/// `{"type":"order","orders":[{a:1,b:true,p:"100",s:"100",r:false,t:..}],"grouping":"na"}`.
fn sdk_order(order_type: Wire, cloid: Option<&str>) -> Wire {
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

fn gtc() -> Wire {
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

/// Action, network, r, s, v: every L1 vector in the SDK's tests.
fn sdk_vectors() -> Vec<(Wire, Network, &'static str, &'static str, u8)> {
    use Network::{Mainnet, Testnet};
    let cloid = Some("0x00000000000000000000000000000001");
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
            sdk_order(gtc(), cloid),
            Mainnet,
            "0x41ae18e8239a56cacbc5dad94d45d0b747e5da11ad564077fcac71277a946e3",
            "0x3c61f667e747404fe7eea8f90ab0e76cc12ce60270438b2058324681a00116da",
            27,
        ),
        (
            sdk_order(gtc(), cloid),
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

fn sdk_signature(r: &str, s: &str, v: u8) -> Signature {
    Signature {
        r: parse_hex32(r).unwrap(),
        s: parse_hex32(s).unwrap(),
        v,
    }
}

#[test]
fn the_key_has_the_sdk_address() {
    assert_eq!(address_of(&key()).to_hex(), SDK_TEST_ADDRESS);
}

#[test]
fn signing_matches_every_sdk_vector() {
    for (action, network, r, s, v) in sdk_vectors() {
        let signature = sign_l1_action(&key(), network, &action, 0, None).unwrap();
        assert_eq!(minimal_hex(&signature.r), r, "{network:?}");
        assert_eq!(minimal_hex(&signature.s), s, "{network:?}");
        assert_eq!(signature.v, v, "{network:?}");
        assert_eq!(signature, sdk_signature(r, s, v));
    }
}

#[test]
fn recovery_finds_the_sdk_key_in_every_sdk_signature_and_only_on_its_network() {
    for (action, network, r, s, v) in sdk_vectors() {
        let connection_id = action_hash(&action, 0, None, None).unwrap();
        let signer = recover_signer(
            &agent_digest(network, &connection_id),
            &sdk_signature(r, s, v),
        );
        assert_eq!(
            signer.map(|a| a.to_hex()).as_deref(),
            Some(SDK_TEST_ADDRESS)
        );
        // The same signature read for the other network names someone
        // else: a testnet signature never passes as a mainnet one.
        let other = match network {
            Network::Mainnet => Network::Testnet,
            Network::Testnet => Network::Mainnet,
        };
        assert_ne!(
            recover_signer(
                &agent_digest(other, &connection_id),
                &sdk_signature(r, s, v)
            ),
            signer
        );
        assert_ne!(
            agent_digest(other, &connection_id),
            agent_digest(network, &connection_id)
        );
    }
}

#[test]
fn connection_id_matches_production() {
    // test_phantom_agent_creation_matches_production: ETH as asset 4, buy
    // 0.0147 at 1670.1, IOC, nonce 1677777606040.
    let action = Wire::Map(vec![
        ("type", Wire::str("order")),
        (
            "orders",
            Wire::Array(vec![Wire::Map(vec![
                ("a", Wire::UInt(4)),
                ("b", Wire::Bool(true)),
                (
                    "p",
                    Wire::str(decimal(rust_decimal::dec!(1670.10)).unwrap()),
                ),
                ("s", Wire::str(decimal(rust_decimal::dec!(0.0147)).unwrap())),
                ("r", Wire::Bool(false)),
                (
                    "t",
                    Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Ioc"))]))]),
                ),
            ])]),
        ),
        ("grouping", Wire::str("na")),
    ]);
    assert_eq!(
        hex(&action_hash(&action, 1_677_777_606_040, None, None).unwrap()),
        "0fcbeda5ae3c4950a548021552a4fea2226858c4453571bf3f24ba017eac2908"
    );
}

#[test]
fn expiry_and_vault_change_the_connection_id() {
    // No signed vector exists for expiresAfter or a vault in the SDK
    // tests; the byte layout is pinned in the unit tests of `sign`.
    let action = dummy_action();
    let plain = action_hash(&action, 5, None, None).unwrap();
    assert_ne!(
        action_hash(&action, 5, None, Some(1_000_000)).unwrap(),
        plain
    );
    let vault = Address::from_hex(SDK_TEST_ADDRESS).unwrap();
    assert_ne!(action_hash(&action, 5, Some(vault), None).unwrap(), plain);
    assert_ne!(action_hash(&action, 6, None, None).unwrap(), plain);
}

/// A spot order differs from a perp order only in its asset id,
/// `10000 + pair index`, which MessagePack writes as a uint16 (`cd`)
/// instead of a fixint. Neither SDK has a spot vector (checked 5 Oct
/// 2026); this pins the bytes as `msgpack.packb` writes them and checks
/// that the signature recovers to the key.
#[test]
fn spot_orders_hash_with_a_uint16_asset_and_sign_like_any_order() {
    // HYPE/USDC on mainnet is `@107`: asset 10107 = 0x277b. Sell 0.3 at
    // 36.5, IOC, with a client order id.
    let cloid = "0x7a6e6472010200000000000000000007";
    let action = Wire::Map(vec![
        ("type", Wire::str("order")),
        (
            "orders",
            Wire::Array(vec![Wire::Map(vec![
                ("a", Wire::UInt(10_107)),
                ("b", Wire::Bool(false)),
                ("p", Wire::str("36.5")),
                ("s", Wire::str("0.3")),
                ("r", Wire::Bool(false)),
                (
                    "t",
                    Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Ioc"))]))]),
                ),
                ("c", Wire::str(cloid)),
            ])]),
        ),
        ("grouping", Wire::str("na")),
    ]);
    let expected: Vec<u8> = [
        &[0x83][..],
        &[0xa4],
        b"type",
        &[0xa5],
        b"order",
        &[0xa6],
        b"orders",
        &[0x91, 0x87],
        &[0xa1],
        b"a",
        &[0xcd, 0x27, 0x7b],
        &[0xa1],
        b"b",
        &[0xc2],
        &[0xa1],
        b"p",
        &[0xa4],
        b"36.5",
        &[0xa1],
        b"s",
        &[0xa3],
        b"0.3",
        &[0xa1],
        b"r",
        &[0xc2],
        &[0xa1],
        b"t",
        &[0x81, 0xa5],
        b"limit",
        &[0x81, 0xa3],
        b"tif",
        &[0xa3],
        b"Ioc",
        &[0xa1],
        b"c",
        &[0xd9, 34],
        cloid.as_bytes(),
        &[0xa8],
        b"grouping",
        &[0xa2],
        b"na",
    ]
    .concat();
    assert_eq!(action.to_msgpack().unwrap(), expected);
    let nonce = 1_791_115_200_000u64;
    let mut data = expected;
    data.extend_from_slice(&nonce.to_be_bytes());
    data.push(0x00);
    let connection_id = action_hash(&action, nonce, None, None).unwrap();
    assert_eq!(connection_id, keccak256(&data));
    let signature = sign_l1_action(&key(), Network::Testnet, &action, nonce, None).unwrap();
    let digest = agent_digest(Network::Testnet, &connection_id);
    assert_eq!(
        recover_signer(&digest, &signature),
        Some(address_of(&key()))
    );
    assert_eq!(sign_digest(&key(), &digest), Some(signature));
}
