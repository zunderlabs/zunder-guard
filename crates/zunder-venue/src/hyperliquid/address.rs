// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Account and wallet addresses.

use std::{env, fmt};

use thiserror::Error;

/// An account or wallet address: 20 bytes, written as `0x` and 40 lowercase
/// hex digits. Lowercase is what Hyperliquid recommends for signing.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address([u8; 20]);

impl Address {
    /// Parse `0x` followed by 40 hex digits, in either case.
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

    /// Read an address from the environment variable `var`.
    pub fn from_env(var: &'static str) -> Result<Self, KeyError> {
        let value = env::var(var).map_err(|error| match error {
            env::VarError::NotPresent => KeyError::Missing(var),
            env::VarError::NotUnicode(_) => KeyError::NotUnicode(var),
        })?;
        Self::from_hex(&value).ok_or(KeyError::MalformedAddress(var))
    }

    /// The address with these 20 bytes, such as the last 20 bytes of the
    /// Keccak-256 hash of a public key.
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
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

/// Why a key or address could not be loaded. Carries the variable's name,
/// never its value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyError {
    #[error("{0} is not set (see https://zunderlabs.com/docs/deploy/ssh/)")]
    Missing(&'static str),
    #[error("{0} is not valid Unicode")]
    NotUnicode(&'static str),
    #[error("{0} must hold a private key as 64 hex digits, optionally prefixed with 0x")]
    Malformed(&'static str),
    #[error("{0} does not hold a valid secp256k1 private key")]
    Invalid(&'static str),
    #[error("{0} must hold an address: 0x followed by 40 hex digits")]
    MalformedAddress(&'static str),
    #[error("nothing was read from {0}")]
    Empty(&'static str),
    #[error("{0} could not be read")]
    Unreadable(&'static str),
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
        assert!(Address::from_hex("14791697260e4c9a71f18484c9f997b308e59325").is_none());
        assert!(Address::from_hex("0x14791697260e4c9a71f18484c9f997b308e5932").is_none());
        assert!(Address::from_hex("0x14791697260e4c9a71f18484c9f997b308e5932z").is_none());
    }
}
