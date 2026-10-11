// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! LICENCE-KEY FUNCTIONALITY (Elastic License 2.0, "Limitations"; see
//! `zunder_guard_core::licence`): the licence key's lifecycle outside the
//! running Guard.
//!
//! - `zunder-guard licence set` and `init --licence`: a key is checked
//!   ([`check_key`]) before it is written into `guard.toml`; a running
//!   Guard applies it at its next sync (`Guard::watch_config`).
//! - `zunder-guard licence show`: what the key in `guard.toml` is
//!   ([`describe`]).
//! - Automatic renewal, **off unless the user switches it on**
//!   (`licence_auto_update` with `licence_renewal_token`): while the key is
//!   missing or within [`RENEW_WITHIN_DAYS`] of its end, Guard asks
//!   Orcastrate's licence service ([`RENEWAL_URL`]) for the licence's
//!   newest key, at most every [`RETRY_MS`], and writes it into
//!   `guard.toml` when it verifies for this account and runs longer
//!   ([`renew_once`]). The request carries the renewal token and the
//!   account address, nothing else. Off, Guard calls nobody but the venue.

use std::{future::Future, path::Path};

use serde::Serialize;
use serde_json::{Value, json};
use zunder_guard_core::{
    licence::{self, FeeNetwork, Licence, LicenceError, LicenceIssuers},
    sign::Address,
};

use crate::config::{GuardConfig, GuardNetwork};

/// Orcastrate's licence service: the newest key of a licence, for its
/// renewal token and one of its accounts.
pub const RENEWAL_URL: &str = "https://zunderlabs.com/api/licence/renewal";
/// A renewal is asked for this many days before the key ends (when the
/// first reminder goes out, `licence::WARN_DAYS`).
pub const RENEW_WITHIN_DAYS: i64 = 14;
/// The least time between two requests to the licence service.
pub const RETRY_MS: u64 = 6 * 3_600_000;
/// How often the renewal task looks whether one is due.
pub const LOOK_EVERY_MS: u64 = 3_600_000;
/// The longest a request to the licence service may take.
pub const REQUEST_TIMEOUT_MS: u64 = 15_000;
/// The largest answer read from it.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// The network a config's licence is checked for: testnet only when the
/// account's network is testnet (sending there, or paper reading a
/// testnet account); anything else is held to mainnet's rule.
pub fn licence_network(config: &GuardConfig) -> FeeNetwork {
    match config.network() {
        Ok(GuardNetwork::Testnet) => FeeNetwork::Testnet,
        _ => FeeNetwork::Mainnet,
    }
}

/// The issuer keys built in for the config's network
/// ([`LicenceIssuers::built_in`]): the production key, and on testnet the
/// staging issuer's too.
pub fn issuers_for(config: &GuardConfig) -> LicenceIssuers {
    LicenceIssuers::built_in(licence_network(config))
}

/// The licence `key` verified against `issuers` at `now_ms` for
/// `account`.
pub fn verified(
    key: &str,
    issuers: &LicenceIssuers,
    account: Address,
    now_ms: i64,
) -> Result<Licence, LicenceError> {
    licence::verify_issued(key, issuers, now_ms).and_then(|licence| licence.for_account(account))
}

/// The licence `key` verified against `issuers` at `now_ms` for
/// `account`; why not, in words, otherwise.
pub fn check_key(
    key: &str,
    issuers: &LicenceIssuers,
    account: Address,
    now_ms: i64,
) -> Result<Licence, String> {
    verified(key, issuers, account, now_ms).map_err(|error| error.to_string())
}

/// Most bytes `licence set --stdin` reads: the longest key and a line end
/// (`\r\n`).
pub const MAX_KEY_LINE: usize = licence::MAX_KEY_LEN + 2;

/// Why `licence set --stdin` read no key. No message holds any of what was
/// read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyLineError {
    #[error("nothing was read from standard input")]
    Empty,
    #[error("standard input could not be read")]
    Unreadable,
    #[error("standard input is not text")]
    NotText,
    #[error(
        "standard input must hold exactly one line, the licence key (a trailing newline is allowed)"
    )]
    MultiLine,
    #[error(
        "standard input holds more than a licence key: at most {} characters",
        licence::MAX_KEY_LEN
    )]
    TooLong,
}

/// The licence key as one line read from `reader` until its end
/// (`licence set --stdin`): one trailing `\n` or `\r\n` is allowed, any
/// other line break is refused, and so is more than [`MAX_KEY_LINE`]
/// bytes. The key is checked afterwards exactly as the positional form's.
pub fn read_key_line(reader: &mut impl std::io::Read) -> Result<String, KeyLineError> {
    use std::io::Read;
    let mut bytes = Vec::with_capacity(MAX_KEY_LINE + 1);
    reader
        .take(MAX_KEY_LINE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| KeyLineError::Unreadable)?;
    if bytes.len() > MAX_KEY_LINE {
        return Err(KeyLineError::TooLong);
    }
    let text = String::from_utf8(bytes).map_err(|_| KeyLineError::NotText)?;
    let line = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    if line.contains(['\n', '\r']) {
        return Err(KeyLineError::MultiLine);
    }
    if line.trim().is_empty() {
        return Err(KeyLineError::Empty);
    }
    Ok(line.to_owned())
}

/// What a licence key is, in the automation contract's words
/// (`docs/guard.md`, "Automation").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenceState {
    /// It verifies for this account now.
    Valid,
    /// It verified, but its end has passed.
    Expired,
    /// It does not verify (forged, malformed, another issuer, other
    /// accounts, no public key built in).
    Invalid,
    /// There is no key.
    None,
}

/// Where the licence key comes from: the config file as a person wrote it
/// (`init --licence`, `licence set`), or kept current by automatic renewal
/// (`licence_auto_update`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenceSource {
    File,
    AutoUpdate,
}

/// The licence object of the automation contract (C3): what `zunder-guard
/// licence show --json` prints and `status --json` carries as `licence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LicenceView {
    pub state: LicenceState,
    /// Valid or expired: the licensee the key names.
    pub licensee: Option<String>,
    /// Valid or expired: the key's end.
    pub expires_at_ms: Option<i64>,
    /// Whether the key, valid now, waives the builder fee.
    pub fee_free: bool,
    pub source: LicenceSource,
}

/// The [`LicenceView`] of `key` for `account` at `now_ms`, checked
/// against `issuers`; `auto_update`: the config's `licence_auto_update`.
pub fn view(
    key: Option<&str>,
    issuers: &LicenceIssuers,
    account: Address,
    now_ms: i64,
    auto_update: bool,
) -> LicenceView {
    let source = if auto_update {
        LicenceSource::AutoUpdate
    } else {
        LicenceSource::File
    };
    let (state, licensee, expires_at_ms, fee_free) = match key {
        None => (LicenceState::None, None, None, false),
        Some(key) => match verified(key, issuers, account, now_ms) {
            Ok(licence) => (
                LicenceState::Valid,
                Some(licence.licensee),
                Some(licence.expires_at_ms),
                licence.fee_free,
            ),
            Err(LicenceError::Expired {
                licensee,
                expires_at_ms,
            }) => (
                LicenceState::Expired,
                Some(licensee),
                Some(expires_at_ms),
                false,
            ),
            Err(_) => (LicenceState::Invalid, None, None, false),
        },
    };
    LicenceView {
        state,
        licensee,
        expires_at_ms,
        fee_free,
        source,
    }
}

/// The [`LicenceView`] of the config's key, checked with the issuer keys
/// built in for its network.
pub fn view_of(
    config: &GuardConfig,
    now_ms: i64,
) -> Result<LicenceView, crate::config::ConfigError> {
    Ok(view(
        config.licence.as_deref(),
        &issuers_for(config),
        config.account()?,
        now_ms,
        config.licence_auto_update,
    ))
}

/// Lines describing the key `key` for `account` at `now_ms`, for `licence
/// show`.
pub fn describe(
    key: Option<&str>,
    issuers: &LicenceIssuers,
    account: Address,
    now_ms: i64,
) -> Vec<String> {
    let Some(key) = key else {
        return vec![
            "no licence key in guard.toml: Guard runs with the builder fee".to_owned(),
            "set one with: zunder-guard licence set zgl1_…".to_owned(),
        ];
    };
    match check_key(key, issuers, account, now_ms) {
        Ok(licence) => {
            let days = licence::days_left(licence.expires_at_ms, now_ms);
            let mut lines = vec![
                format!("licensee: {}", licence.licensee),
                format!(
                    "valid until: {} ({days} day(s) left)",
                    crate::guard::utc_text(licence.expires_at_ms)
                ),
                format!(
                    "fee: {}",
                    if licence.fee_free {
                        "none (fee-free licence)".to_owned()
                    } else if let Some(builder) = &licence.builder {
                        format!(
                            "{} to builder {} (mainnet)",
                            licence::rate(builder.fee_tenths_bp),
                            builder.address
                        )
                    } else {
                        "the builder fee (this licence has no fee-free feature)".to_owned()
                    }
                ),
                format!(
                    "accounts: {} (this Guard's {} is one of them)",
                    licence
                        .accounts
                        .iter()
                        .map(Address::to_hex)
                        .collect::<Vec<_>>()
                        .join(", "),
                    account.to_hex()
                ),
            ];
            if let Some(stage) = licence::expiry_stage(licence.expires_at_ms, now_ms) {
                lines.push(format!(
                    "renew it: it ends within {stage} day(s) (zunderlabs.com/licence, or the link in the licence email)"
                ));
            }
            lines
        }
        Err(error) => vec![
            format!("the licence key in guard.toml is not used: {error}"),
            "Guard runs with the builder fee".to_owned(),
        ],
    }
}

/// Whether a renewal is worth asking for: no key that verifies for
/// `account`, or one within [`RENEW_WITHIN_DAYS`] of its end. The second
/// value is the current key's end, if it verifies.
pub fn renewal_due(
    key: Option<&str>,
    issuers: &LicenceIssuers,
    account: Address,
    now_ms: i64,
) -> (bool, Option<i64>) {
    match key.map(|key| check_key(key, issuers, account, now_ms)) {
        Some(Ok(licence)) => (
            licence.expires_at_ms - now_ms <= RENEW_WITHIN_DAYS * licence::DAY_MS,
            Some(licence.expires_at_ms),
        ),
        _ => (true, None),
    }
}

/// The request body for the licence service.
pub fn request_body(token: &str, account: Address) -> Value {
    json!({"token": token, "account": account.to_hex()})
}

/// What the licence service's answer (`status`, `body`) means for a Guard
/// whose key ends at `current_end` (if it has a valid one): a newer key
/// to write (`Ok(Some)`), nothing new yet (`Ok(None)`: the renewal is not
/// paid yet), or why it cannot be used (`Err`).
pub fn judge_answer(
    status: u16,
    body: &Value,
    current_end: Option<i64>,
    issuers: &LicenceIssuers,
    account: Address,
    now_ms: i64,
) -> Result<Option<(String, Licence)>, String> {
    match status {
        200 => {}
        404 => {
            return Err(
                "the licence service knows no licence for this renewal token and account (check licence_renewal_token, and that the licence names this account)"
                    .to_owned(),
            );
        }
        429 => return Err("the licence service asks to wait (rate limited)".to_owned()),
        other => return Err(format!("the licence service answered HTTP {other}")),
    }
    let Some(key) = body.get("key").and_then(Value::as_str) else {
        return Err("the licence service's answer holds no key".to_owned());
    };
    let licence = check_key(key, issuers, account, now_ms)
        .map_err(|error| format!("the key the licence service sent is not used: {error}"))?;
    if current_end.is_some_and(|end| licence.expires_at_ms <= end) {
        return Ok(None);
    }
    Ok(Some((key.to_owned(), licence)))
}

/// What one look at renewal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Renewal {
    /// `licence_auto_update` is off (or no token): nothing asked.
    Off,
    /// The key is valid for longer than [`RENEW_WITHIN_DAYS`]: nothing asked.
    NotDue,
    /// Asked; no newer key yet.
    NotYet,
    /// A newer key, written into the config file (the running Guard applies
    /// it at its next sync).
    Renewed {
        licensee: String,
        expires_at_ms: i64,
    },
}

/// Look at the config at `path` and, when renewal is on and due, ask the
/// licence service through `post` (the body; the answer's HTTP status and
/// JSON) and write a newer key into the config file.
pub async fn renew_once<F, Fut>(
    path: &Path,
    issuers: &LicenceIssuers,
    now_ms: i64,
    post: F,
) -> Result<Renewal, String>
where
    F: FnOnce(Value) -> Fut,
    Fut: Future<Output = Result<(u16, Value), String>>,
{
    let config = GuardConfig::load(path).map_err(|error| error.to_string())?;
    let (true, Some(token)) = (config.licence_auto_update, &config.licence_renewal_token) else {
        return Ok(Renewal::Off);
    };
    let account = config.account().map_err(|error| error.to_string())?;
    // Keys are checked as on the config's network: the staging issuer's
    // never counts for a mainnet account.
    let issuers = &issuers.on(licence_network(&config));
    let (due, end) = renewal_due(config.licence.as_deref(), issuers, account, now_ms);
    if !due {
        return Ok(Renewal::NotDue);
    }
    let (status, body) = post(request_body(token, account)).await?;
    let Some((key, licence)) = judge_answer(status, &body, end, issuers, account, now_ms)? else {
        return Ok(Renewal::NotYet);
    };
    let mut installed = false;
    GuardConfig::update(path, |current| {
        // The HTTP request ran without the config lock. Respect changes
        // made meanwhile, including disabling renewal or setting a newer key.
        if !current.licence_auto_update
            || current.licence_renewal_token.as_ref() != Some(token)
            || current.account().ok() != Some(account)
        {
            return;
        }
        let (_, current_end) = renewal_due(current.licence.as_deref(), issuers, account, now_ms);
        if current_end.is_some_and(|end| end >= licence.expires_at_ms) {
            return;
        }
        current.licence = Some(key);
        installed = true;
    })
    .map_err(|error| format!("writing the renewed key into the config: {error}"))?;
    if !installed {
        return Ok(Renewal::NotYet);
    }
    Ok(Renewal::Renewed {
        licensee: licence.licensee,
        expires_at_ms: licence.expires_at_ms,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use zunder_guard_core::licence::{Terms, issue, test_key};

    use super::*;

    const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
    const DAY: i64 = licence::DAY_MS;
    const NOW: i64 = 1_800_000_000_000;
    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

    fn line(input: &[u8]) -> Result<String, KeyLineError> {
        read_key_line(&mut &input[..])
    }

    /// `licence set --stdin`: one line, a trailing newline allowed; what
    /// is refused names the problem and none of the input.
    #[test]
    fn a_key_line_is_one_line() {
        assert_eq!(line(b"zgl1_abc").unwrap(), "zgl1_abc");
        assert_eq!(line(b"zgl1_abc\n").unwrap(), "zgl1_abc");
        assert_eq!(line(b"zgl1_abc\r\n").unwrap(), "zgl1_abc");
        for (input, error) in [
            (&b""[..], KeyLineError::Empty),
            (b"\n", KeyLineError::Empty),
            (b"  \r\n", KeyLineError::Empty),
            (b"zgl1_abc\n\n", KeyLineError::MultiLine),
            (b"zgl1_abc\nzgl1_def", KeyLineError::MultiLine),
            (b"zgl1_abc\nzgl1_def\n", KeyLineError::MultiLine),
            (b"\nzgl1_abc", KeyLineError::MultiLine),
            (b"zgl1_abc\r", KeyLineError::MultiLine),
            (b"zgl1_\xff\n", KeyLineError::NotText),
        ] {
            assert_eq!(line(input), Err(error.clone()), "{input:?}");
            assert!(!error.to_string().contains("zgl1"), "{error}");
        }
        // The longest key fits with its line end; one byte more does not.
        let longest = format!("zgl1_{}", "a".repeat(licence::MAX_KEY_LEN - 5));
        assert_eq!(line(format!("{longest}\r\n").as_bytes()).unwrap(), longest);
        assert_eq!(
            line(format!("{longest}a\r\n").as_bytes()),
            Err(KeyLineError::TooLong)
        );
        // A reader that fails.
        struct Broken;
        impl std::io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("closed"))
            }
        }
        assert_eq!(read_key_line(&mut Broken), Err(KeyLineError::Unreadable));
    }

    fn account() -> Address {
        Address::from_hex(ACCOUNT).unwrap()
    }

    fn key(licensee: &str, expires_at_ms: i64, accounts: &[&str]) -> String {
        issue(
            &Terms {
                licensee: licensee.into(),
                expires_at_ms,
                features: vec!["fee_free".into()],
                accounts: accounts.iter().map(|a| (*a).to_owned()).collect(),
                builder: None,
            },
            &test_key::SEED,
        )
        .unwrap()
    }

    /// The test key as the only (production) issuer.
    fn keys() -> LicenceIssuers {
        LicenceIssuers::for_test(FeeNetwork::Mainnet, Some(test_key::public()), None)
    }

    /// A staging issuer's key, hand-made (its seed is here).
    const STAGING_SEED: [u8; 32] = [21u8; 32];

    fn staging_key(expires_at_ms: i64) -> String {
        issue(
            &Terms {
                licensee: "Staging Test".into(),
                expires_at_ms,
                features: vec!["fee_free".into()],
                accounts: vec![ACCOUNT.into()],
                builder: None,
            },
            &STAGING_SEED,
        )
        .unwrap()
    }

    /// The C3 licence object: each state, with the licensee and end where
    /// the key verified, and where the key comes from.
    #[test]
    fn the_contract_view_names_each_state() {
        let public = keys();
        let good = key("Example GmbH", NOW + 30 * DAY, &[ACCOUNT]);
        assert_eq!(
            view(Some(&good), &public, account(), NOW, false),
            LicenceView {
                state: LicenceState::Valid,
                licensee: Some("Example GmbH".into()),
                expires_at_ms: Some(NOW + 30 * DAY),
                fee_free: true,
                source: LicenceSource::File,
            }
        );
        let expired = key("Old", NOW - 1, &[ACCOUNT]);
        assert_eq!(
            view(Some(&expired), &public, account(), NOW, true),
            LicenceView {
                state: LicenceState::Expired,
                licensee: Some("Old".into()),
                expires_at_ms: Some(NOW - 1),
                fee_free: false,
                source: LicenceSource::AutoUpdate,
            }
        );
        let other = key(
            "Other",
            NOW + 30 * DAY,
            &["0x0000000000000000000000000000000000000001"],
        );
        for bad in [other.as_str(), "zgl1_nonsense", "not a key"] {
            let seen = view(Some(bad), &public, account(), NOW, false);
            assert_eq!(seen.state, LicenceState::Invalid, "{bad}");
            assert_eq!(
                (seen.licensee, seen.expires_at_ms, seen.fee_free),
                (None, None, false)
            );
        }
        // A good key with no issuer key built in does not verify.
        let none = LicenceIssuers::for_test(FeeNetwork::Mainnet, None, None);
        assert_eq!(
            view(Some(&good), &none, account(), NOW, false).state,
            LicenceState::Invalid
        );
        assert_eq!(
            view(None, &public, account(), NOW, false).state,
            LicenceState::None
        );
        // The JSON names, exactly as C3 has them.
        assert_eq!(
            serde_json::to_value(view(None, &public, account(), NOW, true)).unwrap(),
            json!({"state": "none", "licensee": null, "expires_at_ms": null, "fee_free": false, "source": "auto_update"})
        );
        for (state, text) in [
            (LicenceState::Valid, "valid"),
            (LicenceState::Expired, "expired"),
            (LicenceState::Invalid, "invalid"),
            (LicenceState::None, "none"),
        ] {
            assert_eq!(serde_json::to_value(state).unwrap(), json!(text));
        }
        assert_eq!(
            serde_json::to_value(LicenceSource::File).unwrap(),
            json!("file")
        );
    }

    /// A staging issuer's key counts for a testnet config only: checked,
    /// viewed and renewed as valid there; invalid for a mainnet account.
    #[test]
    fn a_staging_key_counts_for_a_testnet_config_only() {
        let staging_public = zunder_guard_core::licence::public_key_of(&STAGING_SEED);
        let both = |network| {
            LicenceIssuers::for_test(network, Some(test_key::public()), Some(staging_public))
        };
        let staged = staging_key(NOW + 30 * DAY);
        let testnet = GuardConfig {
            network: Some(GuardNetwork::Testnet),
            account: Some(ACCOUNT.into()),
            licence: Some(staged.clone()),
            ..GuardConfig::default()
        };
        let mainnet = GuardConfig {
            network: Some(GuardNetwork::Mainnet),
            ..testnet.clone()
        };
        assert_eq!(licence_network(&testnet), FeeNetwork::Testnet);
        assert_eq!(licence_network(&mainnet), FeeNetwork::Mainnet);
        // No network named: mainnet's rule.
        let unnamed = GuardConfig {
            network: None,
            ..testnet.clone()
        };
        assert_eq!(licence_network(&unnamed), FeeNetwork::Mainnet);

        let on_testnet = both(licence_network(&testnet));
        let on_mainnet = both(licence_network(&mainnet));
        assert_eq!(
            check_key(&staged, &on_testnet, account(), NOW)
                .unwrap()
                .licensee,
            "Staging Test"
        );
        assert!(
            check_key(&staged, &on_mainnet, account(), NOW)
                .unwrap_err()
                .contains("not issued by Orcastrate")
        );
        assert_eq!(
            view(Some(&staged), &on_testnet, account(), NOW, false).state,
            LicenceState::Valid
        );
        assert_eq!(
            view(Some(&staged), &on_mainnet, account(), NOW, false).state,
            LicenceState::Invalid
        );
        // The built-in set follows the same rule: the staging key (none is
        // built in yet) is never in mainnet's.
        assert!(
            issuers_for(&mainnet)
                .keys()
                .all(|key| Some(*key) == licence::LICENCE_PUBLIC_KEY)
        );

        // Renewal restricts the keys it is given to the config's network:
        // a staging key from the service is refused for a mainnet account.
        let dir = crate::testdir::TestDir::new("licence-staging-renewal");
        let path = dir.path().join("guard.toml");
        let near = key("x", NOW + 3 * DAY, &[ACCOUNT]);
        let config = GuardConfig {
            network: Some(GuardNetwork::Mainnet),
            account: Some(ACCOUNT.into()),
            licence: Some(near.clone()),
            licence_auto_update: true,
            licence_renewal_token: Some(TOKEN.into()),
            auth: zunder_guard_core::auth::AuthConfig {
                clients: vec!["0x00000000000000000000000000000000000000c1".into()],
                ..Default::default()
            },
            ..GuardConfig::default()
        };
        {
            use std::io::Write;
            let mut file = zunder_venue::owner_only::create(&path).unwrap();
            file.write_all(config.to_toml().unwrap().as_bytes())
                .unwrap();
        }
        let renewed = staging_key(NOW + 365 * DAY);
        let result = runtime().block_on(renew_once(
            &path,
            &both(FeeNetwork::Testnet),
            NOW,
            move |_| async move { Ok((200, json!({"key": renewed}))) },
        ));
        assert!(result.unwrap_err().contains("not issued by Orcastrate"));
        assert_eq!(
            GuardConfig::load(&path).unwrap().licence.as_deref(),
            Some(near.as_str())
        );
    }

    #[test]
    fn a_key_is_checked_for_this_account_and_described() {
        let public = keys();
        let good = key("Example GmbH", NOW + 30 * DAY, &[ACCOUNT]);
        assert_eq!(
            check_key(&good, &public, account(), NOW).unwrap().licensee,
            "Example GmbH"
        );
        let other = key(
            "Other",
            NOW + 30 * DAY,
            &["0x0000000000000000000000000000000000000001"],
        );
        assert!(check_key(&other, &public, account(), NOW).is_err());
        let expired = key("Old", NOW - 1, &[ACCOUNT]);
        assert!(
            check_key(&expired, &public, account(), NOW)
                .unwrap_err()
                .contains("expired")
        );
        assert!(
            check_key(
                &good,
                &LicenceIssuers::for_test(FeeNetwork::Mainnet, None, None),
                account(),
                NOW
            )
            .is_err()
        );
        assert!(check_key("zgl1_nonsense", &public, account(), NOW).is_err());
        let lines = describe(Some(&good), &public, account(), NOW);
        assert!(lines[1].contains("30 day(s) left"), "{lines:?}");
        assert!(lines[2].contains("fee-free"), "{lines:?}");
        assert!(!lines.iter().any(|line| line.starts_with("renew")));
        let soon = key("Example GmbH", NOW + 3 * DAY, &[ACCOUNT]);
        let lines = describe(Some(&soon), &public, account(), NOW);
        assert!(
            lines.last().unwrap().contains("within 7 day(s)"),
            "{lines:?}"
        );
        assert!(describe(None, &public, account(), NOW)[0].contains("no licence key"));
        assert!(describe(Some(&other), &public, account(), NOW)[0].contains("not used"));
    }

    #[test]
    fn renewal_is_due_without_a_key_or_within_14_days() {
        let public = keys();
        let long = key("x", NOW + 15 * DAY, &[ACCOUNT]);
        assert_eq!(
            renewal_due(Some(&long), &public, account(), NOW),
            (false, Some(NOW + 15 * DAY))
        );
        let near = key("x", NOW + 14 * DAY, &[ACCOUNT]);
        assert_eq!(
            renewal_due(Some(&near), &public, account(), NOW),
            (true, Some(NOW + 14 * DAY))
        );
        assert_eq!(renewal_due(None, &public, account(), NOW), (true, None));
        let expired = key("x", NOW - DAY, &[ACCOUNT]);
        assert_eq!(
            renewal_due(Some(&expired), &public, account(), NOW),
            (true, None)
        );
    }

    #[test]
    fn only_a_longer_key_for_this_account_is_taken() {
        let public = keys();
        let end = NOW + 5 * DAY;
        let newer = key("x", NOW + 400 * DAY, &[ACCOUNT]);
        let answer = json!({"ok": true, "key": newer});
        let (taken, licence) = judge_answer(200, &answer, Some(end), &public, account(), NOW)
            .unwrap()
            .unwrap();
        assert_eq!(taken, newer);
        assert_eq!(licence.expires_at_ms, NOW + 400 * DAY);
        // The same key again (the renewal is not paid yet): nothing new.
        let same = key("x", end, &[ACCOUNT]);
        assert_eq!(
            judge_answer(
                200,
                &json!({"key": same}),
                Some(end),
                &public,
                account(),
                NOW
            )
            .unwrap(),
            None
        );
        // Without a valid key now, any valid key is taken.
        assert!(
            judge_answer(200, &json!({"key": same}), None, &public, account(), NOW)
                .unwrap()
                .is_some()
        );
        // A key for another account, a forged one, an expired one: refused.
        let other = key(
            "x",
            NOW + 400 * DAY,
            &["0x0000000000000000000000000000000000000001"],
        );
        for bad in [other.as_str(), "zgl1_x.y", &key("x", NOW - 1, &[ACCOUNT])] {
            assert!(
                judge_answer(
                    200,
                    &json!({"key": bad}),
                    Some(end),
                    &public,
                    account(),
                    NOW
                )
                .is_err()
            );
        }
        for status in [404, 429, 500] {
            assert!(judge_answer(status, &answer, Some(end), &public, account(), NOW).is_err());
        }
        assert!(
            judge_answer(
                200,
                &json!({"ok": true}),
                Some(end),
                &public,
                account(),
                NOW
            )
            .is_err()
        );
        assert_eq!(
            request_body(TOKEN, account()),
            json!({"token": TOKEN, "account": ACCOUNT})
        );
    }

    fn write_config(dir: &Path, licence: Option<&str>, auto: bool) -> std::path::PathBuf {
        let path = dir.join("guard.toml");
        let config = GuardConfig {
            network: Some(crate::config::GuardNetwork::Testnet),
            account: Some(ACCOUNT.into()),
            licence: licence.map(str::to_owned),
            licence_auto_update: auto,
            licence_renewal_token: Some(TOKEN.into()),
            auth: zunder_guard_core::auth::AuthConfig {
                clients: vec!["0x00000000000000000000000000000000000000c1".into()],
                ..Default::default()
            },
            ..GuardConfig::default()
        };
        use std::io::Write;
        std::fs::remove_file(&path).ok();
        let mut file = zunder_venue::owner_only::create(&path).unwrap();
        file.write_all(config.to_toml().unwrap().as_bytes())
            .unwrap();
        path
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn renewal_asks_only_when_on_and_due_and_writes_a_newer_key() {
        let dir = crate::testdir::TestDir::new("licence-renewal");
        let public = keys();
        let near = key("x", NOW + 3 * DAY, &[ACCOUNT]);
        let newer = key("x", NOW + 368 * DAY, &[ACCOUNT]);
        let never = |_: Value| async { Err::<(u16, Value), String>("asked".into()) };
        // Off: nothing asked.
        let path = write_config(dir.path(), Some(&near), false);
        assert_eq!(
            runtime().block_on(renew_once(&path, &public, NOW, never)),
            Ok(Renewal::Off)
        );
        // On, but valid for longer than 14 days: nothing asked.
        let long = key("x", NOW + 60 * DAY, &[ACCOUNT]);
        let path = write_config(dir.path(), Some(&long), true);
        assert_eq!(
            runtime().block_on(renew_once(&path, &public, NOW, never)),
            Ok(Renewal::NotDue)
        );
        // On and due: asked with the token and the account, the newer key
        // written.
        let path = write_config(dir.path(), Some(&near), true);
        let asked = std::sync::Arc::new(std::sync::Mutex::new(None));
        let answer = newer.clone();
        let seen = asked.clone();
        let result = runtime().block_on(renew_once(&path, &public, NOW, move |body| {
            *seen.lock().unwrap() = Some(body);
            async move { Ok((200, json!({"ok": true, "key": answer}))) }
        }));
        assert_eq!(
            result,
            Ok(Renewal::Renewed {
                licensee: "x".into(),
                expires_at_ms: NOW + 368 * DAY
            })
        );
        assert_eq!(
            asked.lock().unwrap().clone().unwrap(),
            json!({"token": TOKEN, "account": ACCOUNT})
        );
        let config = GuardConfig::load(&path).unwrap();
        assert_eq!(config.licence.as_deref(), Some(newer.as_str()));
        assert!(config.licence_auto_update);
        // Not paid yet: the same key back, nothing written.
        let path = write_config(dir.path(), Some(&near), true);
        let same = near.clone();
        assert_eq!(
            runtime().block_on(renew_once(&path, &public, NOW, move |_| async move {
                Ok((200, json!({"key": same})))
            })),
            Ok(Renewal::NotYet)
        );
        assert_eq!(
            GuardConfig::load(&path).unwrap().licence.as_deref(),
            Some(near.as_str())
        );
        // A refusal is an error, the config unchanged.
        assert!(
            runtime()
                .block_on(renew_once(&path, &public, NOW, |_| async {
                    Ok((404, json!({"ok": false})))
                }))
                .is_err()
        );
        assert_eq!(
            GuardConfig::load(&path).unwrap().licence.as_deref(),
            Some(near.as_str())
        );
    }

    #[test]
    fn an_in_flight_renewal_respects_newer_keys_and_opt_out() {
        let dir = crate::testdir::TestDir::new("licence-renewal-race");
        let public = keys();
        let near = key("x", NOW + 3 * DAY, &[ACCOUNT]);
        let reply_key = key("x", NOW + 30 * DAY, &[ACCOUNT]);
        let manual = key("x", NOW + 365 * DAY, &[ACCOUNT]);
        let path = write_config(dir.path(), Some(&near), true);
        let result = runtime().block_on(renew_once(&path, &public, NOW, |_| async {
            GuardConfig::update(&path, |config| config.licence = Some(manual.clone())).unwrap();
            Ok((200, json!({"key": reply_key})))
        }));
        assert_eq!(result, Ok(Renewal::NotYet));
        assert_eq!(GuardConfig::load(&path).unwrap().licence, Some(manual));

        let path = write_config(dir.path(), Some(&near), true);
        let result = runtime().block_on(renew_once(&path, &public, NOW, |_| async {
            GuardConfig::update(&path, |config| config.licence_auto_update = false).unwrap();
            Ok((200, json!({"key": reply_key})))
        }));
        assert_eq!(result, Ok(Renewal::NotYet));
        let config = GuardConfig::load(&path).unwrap();
        assert!(!config.licence_auto_update);
        assert_eq!(config.licence.as_deref(), Some(near.as_str()));
    }
}
