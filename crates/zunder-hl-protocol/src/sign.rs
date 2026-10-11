// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! L1 action signatures, exactly as Hyperliquid computes them and the
//! official Python SDK's `sign_l1_action` signs them.
//!
//! 1. The action is encoded as MessagePack; the nonce follows as 8
//!    big-endian bytes, then `0x00` for "no vault address" (or `0x01` and
//!    the 20 address bytes), then, if the action expires, `0x00` and the
//!    expiry as 8 big-endian bytes. The Keccak-256 hash of that is the
//!    `connectionId` ([`action_hash`]; `action_hash` in `signing.py`).
//! 2. A "phantom agent" `{source, connectionId}` is signed as EIP-712 typed
//!    data, type `Agent(string source,bytes32 connectionId)`, in the domain
//!    `Exchange`, version `1`, chain id 1337, verifying contract zero
//!    ([`agent_digest`]). `source` is `"a"` for mainnet and `"b"` for
//!    testnet ([`Network::phantom_agent_source`]); nothing else differs.
//!
//! Hyperliquid recovers the signer from the signature and that digest; so
//! does [`recover_signer`]. Keys stay with the caller: [`sign_digest`] and
//! [`sign_l1_action`] borrow a `k256` signing key and keep no copy.

use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

use crate::{
    address::Address,
    network::Network,
    wire::{TooLarge, Wire},
};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// An ECDSA signature in Ethereum's form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// 27 or 28.
    pub v: u8,
}

/// Why an action could not be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    #[error("the action is too large to encode")]
    TooLarge,
    /// The signature's recovery id cannot be written as an Ethereum `v`
    /// (ids 2 and 3, about one in 2^127).
    #[error("the signature's recovery id cannot be written as v")]
    Unrepresentable,
}

impl From<TooLarge> for SignError {
    fn from(_: TooLarge) -> Self {
        SignError::TooLarge
    }
}

/// The `connectionId` of an action: Keccak-256 of its MessagePack, the
/// nonce, the vault flag (and address) and, if it expires, the expiry.
pub fn action_hash(
    action: &Wire,
    nonce: u64,
    vault: Option<Address>,
    expires_after: Option<u64>,
) -> Result<[u8; 32], TooLarge> {
    let mut data = action.to_msgpack()?;
    data.extend_from_slice(&nonce.to_be_bytes());
    match vault {
        None => data.push(0x00),
        Some(vault) => {
            data.push(0x01);
            data.extend_from_slice(vault.as_bytes());
        }
    }
    if let Some(expires_after) = expires_after {
        data.push(0x00);
        data.extend_from_slice(&expires_after.to_be_bytes());
    }
    Ok(keccak256(&data))
}

/// The EIP-712 digest of the phantom agent for `connection_id` on
/// `network`.
pub fn agent_digest(network: Network, connection_id: &[u8; 32]) -> [u8; 32] {
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
            // verifyingContract: the zero address, left-padded to 32 bytes.
            &[0u8; 32],
        ]
        .concat(),
    );
    let agent_type = keccak256(b"Agent(string source,bytes32 connectionId)");
    let struct_hash = keccak256(
        &[
            &agent_type[..],
            &keccak256(network.phantom_agent_source().as_bytes()),
            connection_id,
        ]
        .concat(),
    );
    keccak256(&[&[0x19, 0x01][..], &domain_separator, &struct_hash].concat())
}

/// Sign a 32-byte digest with `key`. Deterministic (RFC 6979) and low-S, as
/// Ethereum expects. `None` for the one-in-2^127 recovery id that `v`
/// cannot carry.
pub fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> Option<Signature> {
    let (signature, recovery) = key.sign_prehash_recoverable(digest);
    let recovery = u8::from(recovery);
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

/// Sign `action` with `nonce` for `network` with `key`, as an L1 action
/// without a vault.
pub fn sign_l1_action(
    key: &SigningKey,
    network: Network,
    action: &Wire,
    nonce: u64,
    expires_after: Option<u64>,
) -> Result<Signature, SignError> {
    let connection_id = action_hash(action, nonce, None, expires_after)?;
    sign_digest(key, &agent_digest(network, &connection_id)).ok_or(SignError::Unrepresentable)
}

/// Ethereum address of a public key: the last 20 bytes of the Keccak-256
/// hash of the uncompressed point without its `0x04` prefix.
pub fn address_of_public_key(key: &VerifyingKey) -> Address {
    let point = key.to_sec1_point(false);
    let public = point.as_bytes();
    let hash = keccak256(public.get(1..).unwrap_or_default());
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    Address::from_bytes(address)
}

/// The address of a signing key.
pub fn address_of(key: &SigningKey) -> Address {
    address_of_public_key(key.verifying_key())
}

/// The address that signed `digest`, as Hyperliquid recovers it; `None`
/// for a signature that recovers no key (a bad `v`, `r` or `s`).
pub fn recover_signer(digest: &[u8; 32], signature: &Signature) -> Option<Address> {
    let recovery = RecoveryId::from_byte(signature.v.checked_sub(27)?)?;
    let ecdsa = EcdsaSignature::from_slice(&[signature.r, signature.s].concat()).ok()?;
    let key = VerifyingKey::recover_from_prehash(digest, &ecdsa, recovery).ok()?;
    Some(address_of_public_key(&key))
}

/// A 256-bit number written as `0x` and 1 to 64 hex digits, leading zeros
/// optional (as `r` and `s` are sent), left-padded to 32 bytes. `None` for
/// anything else.
pub fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    let digits = text.strip_prefix("0x")?;
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let padded = format!("{digits:0>64}");
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(padded.get(2 * index..2 * index + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex32_accepts_what_the_sdks_send_and_nothing_else() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(parse_hex32("0x1"), Some(one));
        assert_eq!(parse_hex32(&format!("0x{}1", "0".repeat(63))), Some(one));
        assert_eq!(
            parse_hex32(&format!("0x{}", "F".repeat(64))),
            Some([0xff; 32])
        );
        for bad in ["", "0x", "1", "0x+1", "0xg", "0x 1"] {
            assert_eq!(parse_hex32(bad), None, "{bad}");
        }
        assert_eq!(parse_hex32(&format!("0x{}", "1".repeat(65))), None);
    }

    #[test]
    fn a_bad_signature_recovers_nobody() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let digest = [9u8; 32];
        let good = sign_digest(&key, &digest).unwrap();
        assert_eq!(recover_signer(&digest, &good), Some(address_of(&key)));
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
            assert_ne!(recover_signer(&digest, &bad), Some(address_of(&key)));
        }
    }

    #[test]
    fn vault_and_expiry_are_hashed_in_the_sdk_layout() {
        // action_hash in signing.py: msgpack ‖ nonce ‖ (0x00 | 0x01 ‖ vault)
        // ‖ (0x00 ‖ expires_after).
        let action = Wire::Map(vec![("type", Wire::str("dummy"))]);
        let vault = Address::from_bytes([0xab; 20]);
        let msgpack = action.to_msgpack().unwrap();
        let layout = |tail: &[&[u8]]| {
            let mut data = msgpack.clone();
            data.extend_from_slice(&5u64.to_be_bytes());
            for part in tail {
                data.extend_from_slice(part);
            }
            keccak256(&data)
        };
        assert_eq!(action_hash(&action, 5, None, None), Ok(layout(&[&[0x00]])));
        assert_eq!(
            action_hash(&action, 5, None, Some(9)),
            Ok(layout(&[&[0x00, 0x00], &9u64.to_be_bytes()]))
        );
        assert_eq!(
            action_hash(&action, 5, Some(vault), Some(9)),
            Ok(layout(&[
                &[0x01],
                &[0xab; 20],
                &[0x00],
                &9u64.to_be_bytes()
            ]))
        );
    }
}
