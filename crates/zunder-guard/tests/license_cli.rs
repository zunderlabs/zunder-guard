// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `zunder-license`: keygen, issue and verify round-trip through the
//! binary; forged and tampered keys fail.

#![allow(clippy::unwrap_used)]

use std::{
    io::Write,
    process::{Command, Stdio},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use zunder_guard_core::licence;

fn license(args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zunder-license"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = stdin {
        // A command refused before it reads standard input closes it: the
        // write may then fail, which is fine.
        child.stdin.take().unwrap().write_all(input.as_bytes()).ok();
    } else {
        drop(child.stdin.take());
    }
    let output = child.wait_with_output().unwrap();
    (
        output.status.success(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

fn keygen() -> (String, String) {
    let (ok, stdout, stderr) = license(&["keygen"], None);
    assert!(ok, "{stderr}");
    let private = stdout.trim().to_owned();
    let public = stderr
        .lines()
        .find_map(|line| line.strip_prefix("public key: "))
        .unwrap()
        .to_owned();
    // The private key appears once, on standard output only.
    assert!(!stderr.contains(&private[2..]));
    (private, public)
}

fn public_bytes(hex: &str) -> [u8; 32] {
    let digits = hex.trim_start_matches("0x");
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[2 * index..2 * index + 2], 16).unwrap();
    }
    out
}

const NOW: i64 = 1_791_000_000_000;

#[test]
fn issued_keys_verify_and_forgeries_do_not() {
    let (private, public) = keygen();
    let (ok, token, stderr) = license(
        &[
            "issue",
            "--licensee",
            "Example GmbH",
            "--expires",
            "2027-12-31",
            "--features",
            "fee_free",
            "--accounts",
            "0x5e9ee1089755c3435139848e47e6635505d5a13a,0x00000000000000000000000000000000000000AA",
        ],
        Some(&format!("{private}\n")),
    );
    assert!(ok, "{stderr}");
    let token = token.trim();
    // The private key is never echoed.
    assert!(!token.contains(&private[2..]) && !stderr.contains(&private[2..]));
    let verified = licence::verify(token, &public_bytes(&public), NOW).unwrap();
    assert_eq!(verified.licensee, "Example GmbH");
    assert!(verified.fee_free);
    // 2027-12-31 00:00 UTC.
    assert_eq!(verified.expires_at_ms, 1_830_211_200_000);
    let (ok, stdout, _) = license(&["verify", "--public-key", &public, token], None);
    assert!(ok && stdout.contains("Example GmbH"), "{stdout}");
    // Named in lowercase; checked against an account.
    assert!(
        stdout.contains(
            "0x5e9ee1089755c3435139848e47e6635505d5a13a, 0x00000000000000000000000000000000000000aa"
        ),
        "{stdout}"
    );
    let (ok, _, _) = license(
        &[
            "verify",
            "--public-key",
            &public,
            "--account",
            "0x00000000000000000000000000000000000000aa",
            token,
        ],
        None,
    );
    assert!(ok);
    let (ok, _, stderr) = license(
        &[
            "verify",
            "--public-key",
            &public,
            "--account",
            "0x0000000000000000000000000000000000000001",
            token,
        ],
        None,
    );
    assert!(!ok && stderr.contains("is not for account"), "{stderr}");

    // Another key pair's public key: forged.
    let (_, other_public) = keygen();
    assert_eq!(
        licence::verify(token, &public_bytes(&other_public), NOW),
        Err(licence::LicenceError::Forged)
    );
    let (ok, _, _) = license(&["verify", "--public-key", &other_public, token], None);
    assert!(!ok);
    // A field changed after signing: forged.
    let (payload, signature) = token
        .strip_prefix("zgl1_")
        .unwrap()
        .split_once('.')
        .unwrap();
    let text = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    let edited = text.replace("Example GmbH", "Someone Else");
    let tampered = format!("zgl1_{}.{signature}", URL_SAFE_NO_PAD.encode(edited));
    assert_eq!(
        licence::verify(&tampered, &public_bytes(&public), NOW),
        Err(licence::LicenceError::Forged)
    );
}

#[test]
fn issue_takes_the_key_on_standard_input_only_and_refuses_bad_terms() {
    let (private, _) = keygen();
    // No key piped: refused.
    let (ok, _, stderr) = license(
        &[
            "issue",
            "--licensee",
            "X",
            "--expires",
            "2027-01-01",
            "--features",
            "fee_free",
            "--accounts",
            "0x5e9ee1089755c3435139848e47e6635505d5a13a",
        ],
        Some(""),
    );
    assert!(!ok, "{stderr}");
    // An unknown feature: refused.
    let (ok, _, _) = license(
        &[
            "issue",
            "--licensee",
            "X",
            "--expires",
            "2027-01-01",
            "--features",
            "unlimited",
            "--accounts",
            "0x5e9ee1089755c3435139848e47e6635505d5a13a",
        ],
        Some(&private),
    );
    assert!(!ok);
    // A builder fee above the venue's maximum: refused.
    let (ok, _, _) = license(
        &[
            "issue",
            "--licensee",
            "X",
            "--expires",
            "2027-01-01",
            "--features",
            "fee_free",
            "--builder",
            "0x00000000000000000000000000000000000000ab",
            "--builder-fee",
            "101",
            "--accounts",
            "0x5e9ee1089755c3435139848e47e6635505d5a13a",
        ],
        Some(&private),
    );
    assert!(!ok);
    // No account, or one that is no address: refused.
    let (ok, _, stderr) = license(
        &[
            "issue",
            "--licensee",
            "X",
            "--expires",
            "2027-01-01",
            "--features",
            "fee_free",
        ],
        Some(&private),
    );
    assert!(!ok && stderr.contains("--accounts"), "{stderr}");
    let (ok, _, stderr) = license(
        &[
            "issue",
            "--licensee",
            "X",
            "--expires",
            "2027-01-01",
            "--features",
            "fee_free",
            "--accounts",
            "0x123",
        ],
        Some(&private),
    );
    assert!(!ok && stderr.contains("accounts"), "{stderr}");
    // The good terms: issued.
    let (ok, _, stderr) = license(
        &[
            "issue",
            "--licensee",
            "X",
            "--expires",
            "2027-01-01",
            "--features",
            "fee_free",
            "--accounts",
            "0x5e9ee1089755c3435139848e47e6635505d5a13a",
        ],
        Some(&private),
    );
    assert!(ok, "{stderr}");
}
