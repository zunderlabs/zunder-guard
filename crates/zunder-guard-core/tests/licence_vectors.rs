// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The licence key vectors in `licence_vectors.json`, checked against
//! this crate's `issue` and `verify`. Other implementations of the
//! `zgl1_` format (the website's checkout verifies keys before it emails
//! them, its issuer signs them) check the same file, so a drift in any of
//! them fails a test. The seed is public (the crate's test key, 32 bytes
//! of 7): the keys prove nothing.

use serde_json::Value;
use zunder_guard_core::licence::{LicenceError, Terms, issue, public_key_of, verify};

const VECTORS: &str = include_str!("licence_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("licence_vectors.json is JSON")
}

fn bytes32(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "32 bytes of hex");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex digits");
    }
    out
}

fn text<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is a string"))
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("an array")
        .iter()
        .map(|s| s.as_str().expect("a string").to_owned())
        .collect()
}

/// The name of an error variant, as the vectors write it.
fn kind(error: &LicenceError) -> &'static str {
    match error {
        LicenceError::NoPublicKey => "NoPublicKey",
        LicenceError::Prefix => "Prefix",
        LicenceError::TooLong => "TooLong",
        LicenceError::Malformed => "Malformed",
        LicenceError::Forged => "Forged",
        LicenceError::Expired { .. } => "Expired",
        LicenceError::Builder => "Builder",
        LicenceError::Accounts => "Accounts",
        LicenceError::NotForAccount { .. } => "NotForAccount",
    }
}

#[test]
fn the_public_key_belongs_to_the_seed() {
    let v = vectors();
    let seed = bytes32(text(&v, "seed_hex"));
    assert_eq!(public_key_of(&seed), bytes32(text(&v, "public_key_hex")));
}

#[test]
fn issue_writes_exactly_the_pinned_keys() {
    let v = vectors();
    let seed = bytes32(text(&v, "seed_hex"));
    let issued = v["issued"].as_array().expect("issued vectors");
    assert!(issued.len() >= 3);
    for vector in issued {
        let terms: Terms =
            serde_json::from_value(vector["terms"].clone()).expect("the terms parse as Terms");
        assert_eq!(
            issue(&terms, &seed).expect("issues"),
            text(vector, "key"),
            "{}",
            text(vector, "name")
        );
        // The issuer's end date is the expiry's UTC day.
        let end = text(vector, "end");
        let days = terms.expires_at_ms / 86_400_000;
        assert_eq!(terms.expires_at_ms % 86_400_000, 0, "{end}: midnight UTC");
        assert_eq!(civil(days), end, "{}", text(vector, "name"));
    }
}

#[test]
fn verify_reads_or_refuses_each_key_as_pinned() {
    let v = vectors();
    let public = bytes32(text(&v, "public_key_hex"));
    let now = v["now_ms"].as_i64().expect("now_ms");
    let verified = v["verified"].as_array().expect("verified vectors");
    assert!(verified.len() >= 20);
    for vector in verified {
        let name = text(vector, "name");
        let expected = text(vector, "guard");
        match verify(text(vector, "key"), &public, now) {
            Ok(licence) => {
                assert_eq!(expected, "ok", "{name}: verified, expected {expected}");
                let terms = &vector["terms"];
                assert_eq!(licence.licensee, text(terms, "licensee"), "{name}");
                assert_eq!(
                    Some(licence.expires_at_ms),
                    terms["expires_at_ms"].as_i64(),
                    "{name}"
                );
                assert_eq!(
                    licence.fee_free,
                    strings(&terms["features"]).iter().any(|f| f == "fee_free"),
                    "{name}"
                );
                let accounts: Vec<String> = licence.accounts.iter().map(|a| a.to_hex()).collect();
                assert_eq!(accounts, strings(&terms["accounts"]), "{name}");
                assert_eq!(licence.builder, None, "{name}");
            }
            Err(error) => assert_eq!(kind(&error), expected, "{name}: {error}"),
        }
    }
}

/// `YYYY-MM-DD` of a day number since 1970-01-01 (Howard Hinnant's civil_from_days).
fn civil(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}
