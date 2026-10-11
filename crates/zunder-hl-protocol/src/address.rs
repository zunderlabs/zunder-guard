// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Account and wallet addresses.

use std::fmt;

/// An account or wallet address: 20 bytes, written as `0x` and 40 lowercase
/// hex digits. Lowercase is what Hyperliquid recommends for signing.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address([u8; 20]);

impl Address {
    /// Parse `0x` followed by 40 hex digits, in either case, with
    /// whitespace around them.
    pub fn from_hex(text: &str) -> Option<Self> {
        let digits = text.trim().strip_prefix("0x")?;
        if digits.len() != 40 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut bytes = [0u8; 20];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(digits.get(2 * index..2 * index + 2)?, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// The address with these 20 bytes, such as the last 20 bytes of the
    /// Keccak-256 hash of a public key.
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Its 20 bytes, as a vault address is hashed into an action.
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(42);
        hex.push_str("0x");
        for byte in self.0 {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_hex())
    }
}

/// As its lowercase hex string (Guard's events and status).
impl serde::Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_parse_strictly_and_print_lowercase() {
        let address = Address::from_hex("0x14791697260E4c9A71f18484C9f997B308e59325").unwrap();
        assert_eq!(
            address.to_string(),
            "0x14791697260e4c9a71f18484c9f997b308e59325"
        );
        assert_eq!(
            format!("{address:?}"),
            "Address(0x14791697260e4c9a71f18484c9f997b308e59325)"
        );
        assert_eq!(
            Address::from_hex(" 0x14791697260e4c9a71f18484c9f997b308e59325\n"),
            Some(address)
        );
        assert!(Address::from_hex("14791697260e4c9a71f18484c9f997b308e59325").is_none());
        assert!(Address::from_hex("0x14791697260e4c9a71f18484c9f997b308e5932").is_none());
        assert!(Address::from_hex("0x14791697260e4c9a71f18484c9f997b308e5932z").is_none());
        assert!(Address::from_hex("0x+4791697260e4c9a71f18484c9f997b308e59325").is_none());
        assert!(Address::from_hex("0x14791697260e4c9a71f18484c9f997b308e593250").is_none());
        assert_eq!(Address::from_bytes(*address.as_bytes()), address);
        assert_eq!(
            serde_json::to_string(&address).unwrap(),
            "\"0x14791697260e4c9a71f18484c9f997b308e59325\""
        );
    }
}
