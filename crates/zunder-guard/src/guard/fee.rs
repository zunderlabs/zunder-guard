// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The builder fee and the licence key's lifecycle: the fee on what Guard
//! sends, the user's approval of it, and a licence key's expiry, warnings
//! and replacement in the config file.

use serde_json::{Value, json};
use zunder_guard_core::{
    action::Action,
    event::EventBody,
    judge::{Decision, Forward},
    licence::{self, FeeMode, FeeState},
    sign::Address,
};

use crate::{config::GuardConfig, upstream::Upstream};

use super::{
    Guard, Inner,
    clock::{Clock, stamp},
};

/// The licence key Guard runs with, and what it knows of it
/// (`licence.rs`, "Lifecycle").
#[derive(Debug, Clone)]
pub(super) struct LicenceTrack {
    /// The key as configured (`licence` in the config file).
    pub(super) key: Option<String>,
    pub(super) network: licence::FeeNetwork,
    /// The key verified for Guard's account.
    pub(super) valid: Option<ValidLicence>,
    /// Why the configured key is not used, if it is not.
    pub(super) error: Option<String>,
    /// The last expiry warning given: 14, 7 or 1 days.
    warned: Option<i64>,
    /// The config file read at each sync for a new licence key.
    pub(super) file: Option<std::path::PathBuf>,
    /// The issuer keys licences are checked against (those built in for
    /// `network`; tests' own), and the builders a fallback charges (the
    /// production constants; tests' own).
    pub(super) issuers: licence::LicenceIssuers,
    pub(super) builders: FallbackBuilders,
    /// The config file could not be read for the licence (once an alert).
    file_error: Option<String>,
}

/// A licence key verified for Guard's account: whom it is for and when it
/// ends (epoch ms).
#[derive(Debug, Clone)]
pub(super) struct ValidLicence {
    pub(super) licensee: String,
    pub(super) expires_at_ms: i64,
}

/// The builder each network's fee goes to when no licence key is used.
#[derive(Debug, Clone)]
pub(super) struct FallbackBuilders {
    pub(super) mainnet: Option<String>,
    pub(super) testnet: Option<String>,
}

impl LicenceTrack {
    pub(super) fn new(key: Option<String>, network: licence::FeeNetwork) -> Self {
        Self {
            key,
            network,
            valid: None,
            error: None,
            warned: None,
            file: None,
            issuers: licence::LicenceIssuers::built_in(network),
            builders: FallbackBuilders {
                mainnet: licence::ORCASTRATE_BUILDER.map(str::to_owned),
                testnet: licence::ORCASTRATE_TESTNET_BUILDER.map(str::to_owned),
            },
            file_error: None,
        }
    }

    /// The fee mode for the configured key at `now_ms`, and why the key is
    /// not used (if it is not); remembers the key's licensee and expiry.
    pub(super) fn mode(&mut self, account: Address, now_ms: u64) -> (FeeMode, Option<String>) {
        let now = now_ms as i64;
        let issuers = self.issuers.on(self.network);
        self.valid = self.key.as_deref().and_then(|key| {
            crate::licence_life::verified(key, &issuers, account, now)
                .ok()
                .map(|licence| ValidLicence {
                    licensee: licence.licensee,
                    expires_at_ms: licence.expires_at_ms,
                })
        });
        let (mode, warning) = licence::fee_mode_issued(
            self.network,
            self.key.as_deref(),
            &issuers,
            now,
            account,
            self.builders.mainnet.as_deref(),
            self.builders.testnet.as_deref(),
        );
        self.error.clone_from(&warning);
        (mode, warning)
    }

    /// Whether the licence alert still says something true: a warning
    /// before the end, a key that is not used, a config file not read.
    pub(super) fn alert_stays(&self) -> bool {
        self.file_error.is_some()
            || (self.key.is_some() && self.valid.is_none())
            || (self.valid.is_some() && self.warned.is_some())
    }

    /// For `/guard/status`. `contract` is the automation interface's view
    /// of the same key (`docs/guard.md`, "Automation"), which `zunder-guard status --json`
    /// prints as the licence object.
    pub(super) fn status(&self, account: Address, now_ms: u64, auto_update: bool) -> Value {
        let now = now_ms as i64;
        let state = match (&self.key, &self.valid) {
            (None, _) => "none",
            (Some(_), Some(valid)) if now < valid.expires_at_ms => "active",
            (Some(_), _) => "not_used",
        };
        let view = crate::licence_life::view(
            self.key.as_deref(),
            &self.issuers.on(self.network),
            account,
            now,
            auto_update,
        );
        json!({
            "state": state,
            "licensee": self.valid.as_ref().map(|valid| &valid.licensee),
            "expires_at_ms": self.valid.as_ref().map(|valid| valid.expires_at_ms),
            "days_left": self.valid.as_ref().map(|valid| licence::days_left(valid.expires_at_ms, now)),
            "error": self.error,
            "auto_update": auto_update,
            "contract": view,
        })
    }
}

/// Every licence alert starts with this, so that a newer one replaces it.
pub(super) const LICENCE_ALERT: &str = "licence: ";

/// `ms` (epoch milliseconds) as a UTC date and time, `2027-12-31 00:00 UTC`.
pub fn utc_text(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let minutes = ms.rem_euclid(86_400_000) / 60_000;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        minutes / 60,
        minutes % 60
    )
}

impl<U: Upstream, C: Clock> Guard<U, C> {
    /// Put the builder field Guard sends now on the forwarded order action
    /// (every order, entry or exit; none while the fee is not approved).
    pub(super) fn with_fee(fee: &FeeState, decision: &mut Decision) {
        if let Some(forward) = decision.forward.as_mut() {
            forward.action = fee.apply(&forward.action);
        }
    }

    /// Paper mode: the builder fee the forwarded orders would carry, and
    /// for an entry what it would cost at its worst fill.
    pub(super) fn paper_fee(fee: &FeeState, forward: &Forward) -> Option<Value> {
        let builder = fee.mode().builder()?;
        let Action::Order(_) = &forward.action else {
            return None;
        };
        let entry_usdc = forward.entry.as_ref().and_then(|entry| {
            entry
                .qty
                .checked_mul(entry.worst_price)
                .and_then(|notional| licence::fee_usdc(notional, builder.fee_tenths_bp))
        });
        Some(json!({
            "address": builder.address,
            "fee_tenths_bp": builder.fee_tenths_bp,
            "rate": licence::rate(builder.fee_tenths_bp),
            "entry_usdc_at_worst_price": entry_usdc,
            "approved": fee.approved(),
        }))
    }

    /// Record a `maxBuilderFee` answer and journal a change; a withdrawal
    /// is an alert.
    pub(super) fn record_fee_check(
        inner: &mut Inner,
        ticket: u64,
        now: u64,
        answer: Result<&Value, String>,
    ) {
        let was_approved = inner.fee.approved();
        if let Some(text) = inner.fee.record_answer(ticket, now, answer) {
            if was_approved && !inner.fee.approved() {
                Self::add_alert(inner, now, &text, None);
            }
            inner
                .journal
                .append(stamp(now), EventBody::Error { text })
                .ok();
        }
    }

    /// Tests only (feature `test-hooks`, never in a release build): whether
    /// trigger orders carry the builder field, as a build with
    /// [`licence::BUILDER_ON_TRIGGERS`] switched the other way would.
    #[cfg(feature = "test-hooks")]
    pub async fn set_builder_on_triggers(&self, on: bool) {
        self.inner.lock().await.fee.set_builder_on_triggers(on);
    }

    /// Watch the config file at `path` for a new licence key (`zunder-guard
    /// licence set`): read at every sync, apply only a changed licence
    /// key; every other setting still needs a restart.
    pub async fn watch_config(&self, path: std::path::PathBuf) {
        let mut inner = self.inner.lock().await;
        // Startup can wait for key input after loading its config. Reconcile
        // now so a licence installed during that wait is applied before serving.
        inner.licence.file = Some(path);
        Self::licence_tick(&mut inner, self.clock.now_ms(), true);
    }

    /// The licence's lifecycle (`licence.rs`, "Lifecycle"): with
    /// `read_file`, a new key in the watched config file; then expiry (the
    /// fee from this moment on) and the warnings before it.
    pub(super) fn licence_tick(inner: &mut Inner, now: u64, read_file: bool) {
        if read_file && let Some(path) = inner.licence.file.clone() {
            // Equal-length replacements can retain the same modification time.
            // Read the config itself at every sync; only a changed key is applied.
            match GuardConfig::load(&path) {
                Ok(config) => {
                    inner.licence.file_error = None;
                    if config.licence != inner.licence.key {
                        inner.licence.key = config.licence;
                        inner.licence.warned = None;
                        Self::licence_apply(inner, now, "a new licence key in the config file");
                    }
                }
                Err(error) => {
                    let text = format!(
                        "{LICENCE_ALERT}the config file could not be read for a new licence key ({error}); Guard keeps the key it runs with"
                    );
                    if inner.licence.file_error.as_deref() != Some(text.as_str()) {
                        inner.licence.file_error = Some(text.clone());
                        Self::licence_alert(inner, now, Some(&text));
                    }
                }
            }
        }
        let Some(ValidLicence {
            licensee,
            expires_at_ms: expires,
        }) = inner.licence.valid.clone()
        else {
            return;
        };
        if now as i64 >= expires {
            Self::licence_apply(inner, now, "the licence expired");
            return;
        }
        if let Some(stage) = licence::expiry_stage(expires, now as i64)
            && inner.licence.warned.is_none_or(|warned| stage < warned)
        {
            inner.licence.warned = Some(stage);
            let days = licence::days_left(expires, now as i64);
            let text = format!(
                "{LICENCE_ALERT}the licence for {licensee} ends in {days} day(s), at {}: renew it (zunderlabs.com/licence, then zunder-guard licence set), or Guard falls back to the builder fee then (entries then wait for the fee's approval; protection never does)",
                utc_text(expires)
            );
            eprintln!("zunder-guard: {text}");
            Self::licence_alert(inner, now, Some(&text));
        }
    }

    /// Run with the fee mode the configured key gives now, saying why
    /// (`why`) when the mode changes: in the journal, on standard error,
    /// and as an alert.
    fn licence_apply(inner: &mut Inner, now: u64, why: &str) {
        let account = inner.account;
        let (mode, warning) = inner.licence.mode(account, now);
        let changed = inner.fee.switch_mode(mode.clone());
        let mode_text = match &mode {
            FeeMode::FeeFree { licensee } => format!("fee-free, licensed to {licensee}"),
            FeeMode::Builder(builder) => format!(
                "the builder fee, {} to {} (entries wait until its approval is read)",
                licence::rate(builder.fee_tenths_bp),
                builder.address
            ),
            FeeMode::Off(text) => format!("no builder fee ({text})"),
        };
        let mut text = format!("{LICENCE_ALERT}{why}: Guard now runs {mode_text}");
        if let Some(warning) = &warning {
            text.push_str(&format!("; {warning}"));
        }
        if let Some(valid) = &inner.licence.valid {
            text.push_str(&format!(
                "; licensed to {} until {}",
                valid.licensee,
                utc_text(valid.expires_at_ms)
            ));
        }
        if changed || warning.is_some() {
            eprintln!("zunder-guard: {text}");
            inner
                .journal
                .append(stamp(now), EventBody::Error { text: text.clone() })
                .ok();
            Self::licence_alert(inner, now, Some(&text));
        } else {
            Self::licence_alert(inner, now, None);
        }
    }

    /// Replace the licence alert (`None`: remove it).
    fn licence_alert(inner: &mut Inner, now: u64, text: Option<&str>) {
        inner
            .alerts
            .retain(|alert| !alert.text.starts_with(LICENCE_ALERT));
        if let Some(text) = text {
            Self::add_alert(inner, now, text, None);
        }
    }

    /// Tests only (feature `test-hooks`, never in a release build): check
    /// licences against `public_key` (as the production issuer's, the only
    /// one) and fall back to these builders.
    #[cfg(feature = "test-hooks")]
    pub async fn set_licence_keys_for_test(
        &self,
        public_key: [u8; 32],
        mainnet_builder: Option<String>,
        testnet_builder: Option<String>,
    ) {
        let mut inner = self.inner.lock().await;
        let network = inner.licence.network;
        inner.licence.issuers = licence::LicenceIssuers::for_test(network, Some(public_key), None);
        inner.licence.builders = FallbackBuilders {
            mainnet: mainnet_builder,
            testnet: testnet_builder,
        };
        let account = inner.account;
        let now = self.clock.now_ms();
        let (mode, _) = inner.licence.mode(account, now);
        inner.fee.switch_mode(mode);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    #[test]
    fn utc_text_is_the_civil_date() {
        // Hand-checked: 0 is 1970-01-01; 1_798_761_600_000 is 2027-01-01;
        // 951_782_400_000 is 2000-02-29 (a leap day); one minute before
        // 2028-01-01 is 23:59 on 2027-12-31.
        assert_eq!(super::utc_text(0), "1970-01-01 00:00 UTC");
        assert_eq!(super::utc_text(1_798_761_600_000), "2027-01-01 00:00 UTC");
        assert_eq!(super::utc_text(951_782_400_000), "2000-02-29 00:00 UTC");
        assert_eq!(
            super::utc_text(1_830_297_600_000 - 60_000),
            "2027-12-31 23:59 UTC"
        );
    }
}

#[cfg(test)]
mod licence_track_tests {
    #![allow(clippy::unwrap_used)]

    use zunder_guard_core::licence::{FeeNetwork, LicenceIssuers, Terms, issue};

    use super::*;

    const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
    const NOW: u64 = 1_800_000_000_000;

    /// A running Guard takes a staging issuer's key fee-free on testnet
    /// only; on mainnet it falls back to the fee and reports the key
    /// invalid. Hand-made production and staging keys (seeds here).
    #[test]
    fn a_staging_licence_is_fee_free_on_testnet_only() {
        let production = [31u8; 32];
        let staging = [32u8; 32];
        let key = issue(
            &Terms {
                licensee: "Staging Test".into(),
                expires_at_ms: (NOW + 86_400_000) as i64,
                features: vec!["fee_free".into()],
                accounts: vec![ACCOUNT.into()],
                builder: None,
            },
            &staging,
        )
        .unwrap();
        let account = Address::from_hex(ACCOUNT).unwrap();
        let track = |network| {
            let mut track = LicenceTrack::new(Some(key.clone()), network);
            track.issuers = LicenceIssuers::for_test(
                FeeNetwork::Testnet,
                Some(licence::public_key_of(&production)),
                Some(licence::public_key_of(&staging)),
            );
            track.builders = FallbackBuilders {
                mainnet: Some("0x00000000000000000000000000000000000000aa".into()),
                testnet: Some("0x00000000000000000000000000000000000000bb".into()),
            };
            track
        };
        let mut testnet = track(FeeNetwork::Testnet);
        let (mode, warning) = testnet.mode(account, NOW);
        assert!(matches!(mode, FeeMode::FeeFree { .. }), "{mode:?}");
        assert_eq!(warning, None);
        let status = testnet.status(account, NOW, false);
        assert_eq!(status["state"], "active");
        assert_eq!(status["contract"]["state"], "valid");
        assert_eq!(status["contract"]["fee_free"], true);
        assert_eq!(status["contract"]["source"], "file");

        // The same set handed to a mainnet track: the staging key is dropped.
        let mut mainnet = track(FeeNetwork::Mainnet);
        let (mode, warning) = mainnet.mode(account, NOW);
        assert!(matches!(mode, FeeMode::Builder(_)), "{mode:?}");
        assert!(warning.unwrap().contains("not issued by Orcastrate"));
        let status = mainnet.status(account, NOW, true);
        assert_eq!(status["state"], "not_used");
        assert_eq!(status["contract"]["state"], "invalid");
        assert_eq!(status["contract"]["fee_free"], false);
        assert_eq!(status["contract"]["source"], "auto_update");
    }
}
