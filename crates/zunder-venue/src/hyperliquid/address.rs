// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Reading an account address from the environment, and why a key or an
//! address could not be loaded. [`Address`] itself is
//! `zunder-hl-protocol`'s.

use std::env;

use thiserror::Error;
use zunder_hl_protocol::Address;

/// Read an address from the environment variable `var`.
pub fn address_from_env(var: &'static str) -> Result<Address, KeyError> {
    let value = env::var(var).map_err(|error| match error {
        env::VarError::NotPresent => KeyError::Missing(var),
        env::VarError::NotUnicode(_) => KeyError::NotUnicode(var),
    })?;
    Address::from_hex(&value).ok_or(KeyError::MalformedAddress(var))
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
    fn a_missing_variable_is_named_without_a_value() {
        let var = "ZUNDER_TEST_UNSET_ADDRESS_VARIABLE";
        assert_eq!(address_from_env(var), Err(KeyError::Missing(var)));
    }
}
