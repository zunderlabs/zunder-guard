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

use serde_json::{Value, json};
use zunder_guard_core::{
    licence::{self, Licence, LicenceError},
    sign::Address,
};

use crate::config::GuardConfig;

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

/// The licence `key` verified against `public_key` at `now_ms` for
/// `account`; why not, in words, otherwise.
pub fn check_key(
    key: &str,
    public_key: Option<&[u8; 32]>,
    account: Address,
    now_ms: i64,
) -> Result<Licence, String> {
    let public_key = public_key.ok_or_else(|| LicenceError::NoPublicKey.to_string())?;
    licence::verify(key, public_key, now_ms)
        .and_then(|licence| licence.for_account(account))
        .map_err(|error| error.to_string())
}

/// Lines describing the key `key` for `account` at `now_ms`, for `licence
/// show`.
pub fn describe(
    key: Option<&str>,
    public_key: Option<&[u8; 32]>,
    account: Address,
    now_ms: i64,
) -> Vec<String> {
    let Some(key) = key else {
        return vec![
            "no licence key in guard.toml: Guard runs with the builder fee".to_owned(),
            "set one with: zunder-guard licence set zgl1_…".to_owned(),
        ];
    };
    match check_key(key, public_key, account, now_ms) {
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
    public_key: Option<&[u8; 32]>,
    account: Address,
    now_ms: i64,
) -> (bool, Option<i64>) {
    match key.map(|key| check_key(key, public_key, account, now_ms)) {
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
    public_key: Option<&[u8; 32]>,
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
    let licence = check_key(key, public_key, account, now_ms)
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
    public_key: Option<&[u8; 32]>,
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
    let (due, end) = renewal_due(config.licence.as_deref(), public_key, account, now_ms);
    if !due {
        return Ok(Renewal::NotDue);
    }
    let (status, body) = post(request_body(token, account)).await?;
    let Some((key, licence)) = judge_answer(status, &body, end, public_key, account, now_ms)?
    else {
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
        let (_, current_end) = renewal_due(current.licence.as_deref(), public_key, account, now_ms);
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

    #[test]
    fn a_key_is_checked_for_this_account_and_described() {
        let public = test_key::public();
        let good = key("Example GmbH", NOW + 30 * DAY, &[ACCOUNT]);
        assert_eq!(
            check_key(&good, Some(&public), account(), NOW)
                .unwrap()
                .licensee,
            "Example GmbH"
        );
        let other = key(
            "Other",
            NOW + 30 * DAY,
            &["0x0000000000000000000000000000000000000001"],
        );
        assert!(check_key(&other, Some(&public), account(), NOW).is_err());
        let expired = key("Old", NOW - 1, &[ACCOUNT]);
        assert!(
            check_key(&expired, Some(&public), account(), NOW)
                .unwrap_err()
                .contains("expired")
        );
        assert!(check_key(&good, None, account(), NOW).is_err());
        assert!(check_key("zgl1_nonsense", Some(&public), account(), NOW).is_err());
        let lines = describe(Some(&good), Some(&public), account(), NOW);
        assert!(lines[1].contains("30 day(s) left"), "{lines:?}");
        assert!(lines[2].contains("fee-free"), "{lines:?}");
        assert!(!lines.iter().any(|line| line.starts_with("renew")));
        let soon = key("Example GmbH", NOW + 3 * DAY, &[ACCOUNT]);
        let lines = describe(Some(&soon), Some(&public), account(), NOW);
        assert!(
            lines.last().unwrap().contains("within 7 day(s)"),
            "{lines:?}"
        );
        assert!(describe(None, Some(&public), account(), NOW)[0].contains("no licence key"));
        assert!(describe(Some(&other), Some(&public), account(), NOW)[0].contains("not used"));
    }

    #[test]
    fn renewal_is_due_without_a_key_or_within_14_days() {
        let public = test_key::public();
        let long = key("x", NOW + 15 * DAY, &[ACCOUNT]);
        assert_eq!(
            renewal_due(Some(&long), Some(&public), account(), NOW),
            (false, Some(NOW + 15 * DAY))
        );
        let near = key("x", NOW + 14 * DAY, &[ACCOUNT]);
        assert_eq!(
            renewal_due(Some(&near), Some(&public), account(), NOW),
            (true, Some(NOW + 14 * DAY))
        );
        assert_eq!(
            renewal_due(None, Some(&public), account(), NOW),
            (true, None)
        );
        let expired = key("x", NOW - DAY, &[ACCOUNT]);
        assert_eq!(
            renewal_due(Some(&expired), Some(&public), account(), NOW),
            (true, None)
        );
    }

    #[test]
    fn only_a_longer_key_for_this_account_is_taken() {
        let public = test_key::public();
        let end = NOW + 5 * DAY;
        let newer = key("x", NOW + 400 * DAY, &[ACCOUNT]);
        let answer = json!({"ok": true, "key": newer});
        let (taken, licence) = judge_answer(200, &answer, Some(end), Some(&public), account(), NOW)
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
                Some(&public),
                account(),
                NOW
            )
            .unwrap(),
            None
        );
        // Without a valid key now, any valid key is taken.
        assert!(
            judge_answer(
                200,
                &json!({"key": same}),
                None,
                Some(&public),
                account(),
                NOW
            )
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
                    Some(&public),
                    account(),
                    NOW
                )
                .is_err()
            );
        }
        for status in [404, 429, 500] {
            assert!(
                judge_answer(status, &answer, Some(end), Some(&public), account(), NOW).is_err()
            );
        }
        assert!(
            judge_answer(
                200,
                &json!({"ok": true}),
                Some(end),
                Some(&public),
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
        let public = test_key::public();
        let near = key("x", NOW + 3 * DAY, &[ACCOUNT]);
        let newer = key("x", NOW + 368 * DAY, &[ACCOUNT]);
        let never = |_: Value| async { Err::<(u16, Value), String>("asked".into()) };
        // Off: nothing asked.
        let path = write_config(dir.path(), Some(&near), false);
        assert_eq!(
            runtime().block_on(renew_once(&path, Some(&public), NOW, never)),
            Ok(Renewal::Off)
        );
        // On, but valid for longer than 14 days: nothing asked.
        let long = key("x", NOW + 60 * DAY, &[ACCOUNT]);
        let path = write_config(dir.path(), Some(&long), true);
        assert_eq!(
            runtime().block_on(renew_once(&path, Some(&public), NOW, never)),
            Ok(Renewal::NotDue)
        );
        // On and due: asked with the token and the account, the newer key
        // written.
        let path = write_config(dir.path(), Some(&near), true);
        let asked = std::sync::Arc::new(std::sync::Mutex::new(None));
        let answer = newer.clone();
        let seen = asked.clone();
        let result = runtime().block_on(renew_once(&path, Some(&public), NOW, move |body| {
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
            runtime().block_on(renew_once(&path, Some(&public), NOW, move |_| async move {
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
                .block_on(renew_once(&path, Some(&public), NOW, |_| async {
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
        let public = test_key::public();
        let near = key("x", NOW + 3 * DAY, &[ACCOUNT]);
        let reply_key = key("x", NOW + 30 * DAY, &[ACCOUNT]);
        let manual = key("x", NOW + 365 * DAY, &[ACCOUNT]);
        let path = write_config(dir.path(), Some(&near), true);
        let result = runtime().block_on(renew_once(&path, Some(&public), NOW, |_| async {
            GuardConfig::update(&path, |config| config.licence = Some(manual.clone())).unwrap();
            Ok((200, json!({"key": reply_key})))
        }));
        assert_eq!(result, Ok(Renewal::NotYet));
        assert_eq!(GuardConfig::load(&path).unwrap().licence, Some(manual));

        let path = write_config(dir.path(), Some(&near), true);
        let result = runtime().block_on(renew_once(&path, Some(&public), NOW, |_| async {
            GuardConfig::update(&path, |config| config.licence_auto_update = false).unwrap();
            Ok((200, json!({"key": reply_key})))
        }));
        assert_eq!(result, Ok(Renewal::NotYet));
        let config = GuardConfig::load(&path).unwrap();
        assert!(!config.licence_auto_update);
        assert_eq!(config.licence.as_deref(), Some(near.as_str()));
    }
}
