//! Offline rehearsal verifier. This example is not a Guard release or an activation path.
//! Input is a bounded JSON object on stdin; stdout contains only a boolean receipt.
use std::io::{self, Read};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use zunder_guard_core::licence::{self, LICENCE_PUBLIC_KEY};
use zunder_guard_core::sign::Address;

const MAX_INPUT: usize = 16 * 1024;
const PRODUCTION_PUBLIC_KEY: &str =
    "7e298d8aa9921205f1ef0995b8dc6fedd86a4365fe183825127f8cd56a82af46";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    key: String,
    public_key: String,
    owner: String,
    expected_licensee: String,
}

fn public_key(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * index..2 * index + 2)?, 16).ok()?;
    }
    Some(bytes)
}

fn check() -> Result<(), ()> {
    // Refuse argv inputs so a caller cannot accidentally expose a licence in process listings.
    if std::env::args_os().len() != 1 {
        return Err(());
    }
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    if input.len() > MAX_INPUT {
        return Err(());
    }
    let input: Input = serde_json::from_slice(&input).map_err(|_| ())?;
    let public_key = public_key(&input.public_key).ok_or(())?;
    if input.public_key.eq_ignore_ascii_case(PRODUCTION_PUBLIC_KEY)
        || Some(public_key) == LICENCE_PUBLIC_KEY
    {
        return Err(());
    }
    let owner = Address::from_hex(&input.owner).ok_or(())?;
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_millis(),
    )
    .map_err(|_| ())?;
    let verified = licence::verify(&input.key, &public_key, now_ms)
        .and_then(|value| value.for_account(owner))
        .map_err(|_| ())?;
    if verified.licensee != input.expected_licensee
        || !verified.fee_free
        || verified.builder.is_some()
    {
        return Err(());
    }
    Ok(())
}

fn main() -> ExitCode {
    if check().is_ok() {
        println!("{{\"ok\":true}}");
        ExitCode::SUCCESS
    } else {
        println!("{{\"ok\":false}}");
        ExitCode::FAILURE
    }
}
