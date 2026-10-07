// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `guard.toml`: where Guard listens, which account and network it guards,
//! its clients, its policy and its state directory.
//!
//! Decimals are strings; bare floats and TOML dates are refused, as in every
//! Zunder config. Unknown keys are refused. `validate()` checks every bound,
//! the policy's included, and the mainnet guards (`check_mainnet`).

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zunder_guard_core::{
    auth::{AuthConfig, AuthConfigError},
    policy::{Policy, PolicyError},
    sign::Address,
};
use zunder_venue::hyperliquid::Network;

/// The port Guard listens on by default.
pub const DEFAULT_PORT: u16 = 8547;
/// Fastest and slowest account sync Guard accepts, in seconds.
/// At least 5 s: each sync costs about 24 of the venue's request weight,
/// and the venue allows 1,200 a minute per IP for everything.
pub const MIN_SYNC_SECONDS: u64 = 5;
pub const MAX_SYNC_SECONDS: u64 = 300;

/// The network the guarded account lives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardNetwork {
    Testnet,
    Mainnet,
}

impl GuardNetwork {
    pub const fn name(self) -> &'static str {
        match self {
            GuardNetwork::Testnet => "testnet",
            GuardNetwork::Mainnet => "mainnet",
        }
    }

    pub const fn venue(self) -> Network {
        match self {
            GuardNetwork::Testnet => Network::Testnet,
            GuardNetwork::Mainnet => Network::Mainnet,
        }
    }
}

/// What Guard does with what it judges: `paper` (sends nothing), or send
/// on `testnet` or `mainnet`. `run` sends only when told the same network
/// on its command line (`--network`, or `ZUNDER_GUARD_NETWORK`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardMode {
    #[default]
    Paper,
    Testnet,
    Mainnet,
}

impl GuardMode {
    pub const fn name(self) -> &'static str {
        match self {
            GuardMode::Paper => "paper",
            GuardMode::Testnet => "testnet",
            GuardMode::Mainnet => "mainnet",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "paper" => Some(GuardMode::Paper),
            "testnet" => Some(GuardMode::Testnet),
            "mainnet" => Some(GuardMode::Mainnet),
            _ => None,
        }
    }

    /// The network a sending mode sends to.
    pub const fn network(self) -> Option<GuardNetwork> {
        match self {
            GuardMode::Paper => None,
            GuardMode::Testnet => Some(GuardNetwork::Testnet),
            GuardMode::Mainnet => Some(GuardNetwork::Mainnet),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GuardConfig {
    /// The network of the account: `"testnet"` or `"mainnet"`. Required.
    pub network: Option<GuardNetwork>,
    /// `"paper"` (the default), `"testnet"` or `"mainnet"`: a sending mode
    /// must be the account's network.
    pub mode: GuardMode,
    /// The account's own address (the main wallet), not the API wallet's.
    pub account: Option<String>,
    /// The API wallet whose key Guard gets on standard input. Required to
    /// send; the key's address must be this one.
    pub api_wallet: Option<String>,
    /// Required, set to true, for a mainnet config (with every other
    /// mainnet guard, `check_mainnet`).
    pub allow_mainnet: bool,
    /// Where Guard listens: a loopback address only.
    pub listen: String,
    /// The risk journal, the decision journal, the kill file. A relative
    /// path is taken from the config file's directory, not from wherever a
    /// command runs, so `run` and `kill` always agree.
    pub state_dir: PathBuf,
    /// Seconds between two reads of the account by the background sync.
    pub sync_seconds: u64,
    /// Where Guard records protective sends it makes while the decision
    /// journal cannot be written (the emergency log, `docs/guard.md`):
    /// best a directory on another disk that Guard may write. Default:
    /// `<state_dir>/emergency`, inside the state directory (writable in
    /// every shipped setup). It must not be the state directory itself. A
    /// relative path is taken from the config file's directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emergency_dir: Option<PathBuf>,
    /// The part of the IP address's request weight (Hyperliquid's 1,200 a
    /// minute) this Guard may spend, in `(0, 1]`: 1 for a Guard alone on
    /// its address, `1/N` for each of N Guards on one. Every budget is
    /// fitted to it ([`crate::budget::plan`]); too small a share to keep
    /// Guard safe is refused.
    pub ip_share: Decimal,
    /// A licence key (`zgl1_…`), not a secret; see `docs/guard.md`. A
    /// running Guard applies a new one at its next sync (`zunder-guard
    /// licence set`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub licence: Option<String>,
    /// Fetch a renewed licence key from Orcastrate when the one here is
    /// within 14 days of its end (or missing), with
    /// `licence_renewal_token`. Off by default: then Guard calls nobody
    /// but the venue.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub licence_auto_update: bool,
    /// The renewal token from the licence email's renewal link (the part
    /// after `#renew=`): it fetches this licence's newest key. Never shown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub licence_renewal_token: Option<String>,
    /// SHA3-256 of the browser monitor's pairing code, hex. The code itself
    /// was shown once by `zunder-guard init`. Pairing is phase 2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_sha3: Option<String>,
    pub auth: AuthConfig,
    pub policy: Policy,
}

/// Whether `token` has the shape of a renewal token: 43 base64url
/// characters (an HMAC-SHA-256, as the licence service issues them).
pub fn renewal_token_shape(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            network: None,
            mode: GuardMode::Paper,
            account: None,
            api_wallet: None,
            allow_mainnet: false,
            listen: format!("127.0.0.1:{DEFAULT_PORT}"),
            state_dir: PathBuf::from("guard-state"),
            sync_seconds: 5,
            emergency_dir: None,
            ip_share: Decimal::ONE,
            licence: None,
            licence_auto_update: false,
            licence_renewal_token: None,
            pairing_sha3: None,
            auth: AuthConfig::default(),
            policy: Policy::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {message}")]
    Read { path: PathBuf, message: String },
    #[error("invalid config: {0}")]
    Parse(String),
    #[error("`{0}` is a floating-point number; write decimals as strings, for example \"0.02\"")]
    Float(String),
    #[error("`{0}` is a TOML date; Guard has no dates in its config")]
    Date(String),
    #[error("network is missing: \"testnet\" or \"mainnet\", the network of the account")]
    NoNetwork,
    #[error("account is missing or not 0x and 40 hex digits")]
    Account,
    #[error("api_wallet is not 0x and 40 hex digits")]
    ApiWallet,
    #[error("listen must be a loopback address with a port, like 127.0.0.1:8547; got `{0}`")]
    Listen(String),
    #[error("sync_seconds must be between {MIN_SYNC_SECONDS} and {MAX_SYNC_SECONDS}, got {0}")]
    SyncSeconds(u64),
    #[error(
        "emergency_dir must name a directory other than state_dir, where the decision journal is"
    )]
    EmergencyDir,
    #[error("state_dir is empty")]
    StateDir,
    #[error("{0}")]
    IpShare(#[from] crate::budget::BudgetError),
    #[error("pairing_sha3 must be 64 hex digits")]
    Pairing,
    #[error("{0}")]
    Renewal(&'static str),
    #[error(
        "the config's mode is {mode}; sending on {command} needs a config for it (zunder-guard init)"
    )]
    NotSending {
        mode: &'static str,
        command: &'static str,
    },
    #[error("the config is for {config}, but the command is for {command}")]
    WrongNetwork {
        config: &'static str,
        command: &'static str,
    },
    #[error("a mainnet config needs {0} (docs/guard.md, \"Mainnet\")")]
    MainnetNeeds(&'static str),
    #[error(
        "the config names no api_wallet: record the key's address first with `zunder-guard key check --key-stdin`"
    )]
    NoApiWallet,
    #[error(
        "{0} exists and is not plainly a testnet journal; earlier builds gave mainnet's risk journal that name. If it is this account's mainnet journal, rename it to risk-mainnet.jsonl (and decisions.jsonl to decisions-mainnet.jsonl); otherwise move it out of the state directory"
    )]
    OldMainnetJournal(PathBuf),
    #[error(
        "on mainnet the policy may not be looser than the mainnet ceiling (Zunder's default risk frame and Guard's pinned limits); policy.{0} is"
    )]
    MainnetLooser(&'static str),
    #[error("mode {mode} does not fit an account on {network}")]
    ModeNetwork {
        mode: &'static str,
        network: &'static str,
    },
    #[error("allow_mainnet is set in a testnet config")]
    AllowMainnetOnTestnet,
    #[error(transparent)]
    Auth(#[from] AuthConfigError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("the key's API wallet {key} is not the config's api_wallet {expected}")]
    ApiWalletDiffers { expected: String, key: String },
}

impl GuardConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|error| ConfigError::Read {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
        let mut config = Self::parse(&text)?;
        if config.licence_renewal_token.is_some()
            && zunder_venue::owner_only::check(path)
                .map_err(|message| ConfigError::Read {
                    path: path.to_owned(),
                    message,
                })?
                .is_some()
        {
            return Err(ConfigError::Read {
                path: path.to_owned(),
                message: "a config containing a renewal token must be readable and writable only by its owner".into(),
            });
        }
        if config.state_dir.is_relative() {
            let base = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let base = base.canonicalize().unwrap_or_else(|_| base.to_owned());
            config.state_dir = base.join(&config.state_dir);
        }
        if let Some(dir) = config
            .emergency_dir
            .as_ref()
            .filter(|dir| dir.is_relative())
        {
            let base = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let base = base.canonicalize().unwrap_or_else(|_| base.to_owned());
            config.emergency_dir = Some(base.join(dir));
        }
        Ok(config)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        // TOML diagnostics can include the source line and secret values.
        let table: toml::Table =
            toml::from_str(text).map_err(|_| ConfigError::Parse("invalid TOML syntax".into()))?;
        if let Some(key) = first_value(&table, &|value| matches!(value, toml::Value::Float(_))) {
            return Err(ConfigError::Float(key));
        }
        if let Some(key) = first_value(&table, &|value| matches!(value, toml::Value::Datetime(_))) {
            return Err(ConfigError::Date(key));
        }
        let config: Self = table.try_into().map_err(|_: toml::de::Error| {
            ConfigError::Parse("unknown field or invalid config field type".into())
        })?;
        config.validate()?;
        Ok(config)
    }

    /// The config as TOML, as `zunder-guard init` writes it.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|error| ConfigError::Parse(error.to_string()))
    }

    /// Change the config file at `path` in place: read it as written (a
    /// relative `state_dir` stays relative), apply `change`, validate, and
    /// replace the file atomically (a new file beside it, synced, renamed
    /// over it), readable and writable only by its owner.
    pub fn update(path: &Path, change: impl FnOnce(&mut Self)) -> Result<(), ConfigError> {
        let write_error = |message: String| ConfigError::Read {
            path: path.to_owned(),
            message,
        };
        let mut temporary = path.as_os_str().to_owned();
        temporary.push(".new");
        let temporary = PathBuf::from(temporary);
        // The new file is the lock: created before the config is read, so
        // a second update at the same time fails rather than losing the
        // first one's change.
        let mut file = zunder_venue::owner_only::create(&temporary)
            .map_err(|error| {
                write_error(format!(
                    "{} exists or cannot be created ({error}): another update may be running; remove it if not",
                    temporary.display()
                ))
            })?;
        let result = (|| {
            use std::io::Write;
            let text =
                std::fs::read_to_string(path).map_err(|error| write_error(error.to_string()))?;
            let mut config = Self::parse(&text)?;
            change(&mut config);
            config.validate()?;
            let text = config.to_toml()?;
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
                .and_then(|()| std::fs::rename(&temporary, path))
                .map_err(|error| write_error(format!("writing: {error}")))
        })();
        if result.is_err() {
            std::fs::remove_file(&temporary).ok();
        }
        result
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let network = self.network()?;
        self.account()?;
        if let Some(wallet) = &self.api_wallet
            && Address::from_hex(wallet).is_none()
        {
            return Err(ConfigError::ApiWallet);
        }
        self.listen_addr()?;
        if !(MIN_SYNC_SECONDS..=MAX_SYNC_SECONDS).contains(&self.sync_seconds) {
            return Err(ConfigError::SyncSeconds(self.sync_seconds));
        }
        if self.state_dir.as_os_str().is_empty() {
            return Err(ConfigError::StateDir);
        }
        if let Some(dir) = &self.emergency_dir {
            let same = |a: &Path, b: &Path| {
                let a = a.canonicalize().unwrap_or_else(|_| a.to_owned());
                let b = b.canonicalize().unwrap_or_else(|_| b.to_owned());
                a == b
            };
            if dir.as_os_str().is_empty() || same(dir, &self.state_dir) {
                return Err(ConfigError::EmergencyDir);
            }
        }
        self.budgets()?;
        if let Some(hash) = &self.pairing_sha3
            && (hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(ConfigError::Pairing);
        }
        if let Some(token) = &self.licence_renewal_token
            && !renewal_token_shape(token)
        {
            return Err(ConfigError::Renewal(
                "licence_renewal_token must be the 43 characters after #renew= in the licence email's renewal link",
            ));
        }
        if self.licence_auto_update && self.licence_renewal_token.is_none() {
            return Err(ConfigError::Renewal(
                "licence_auto_update needs licence_renewal_token (from the licence email's renewal link)",
            ));
        }
        self.auth.validate()?;
        self.policy.validate()?;
        if let Some(sends_to) = self.mode.network()
            && sends_to != network
        {
            return Err(ConfigError::ModeNetwork {
                mode: self.mode.name(),
                network: network.name(),
            });
        }
        if network == GuardNetwork::Testnet && self.allow_mainnet {
            return Err(ConfigError::AllowMainnetOnTestnet);
        }
        // Every mainnet guard for a config that may send on mainnet; a
        // paper config may read a mainnet account without them.
        if self.mode == GuardMode::Mainnet {
            self.check_mainnet()?;
        }
        Ok(())
    }

    /// The mainnet guards of the config, as the runner's: `allow_mainnet`,
    /// the equity cap, the account and the API
    /// wallet. The person's confirmation (`ZUNDER_MAINNET_CONFIRM`), a
    /// journal scoped to mainnet and this account, and the key on standard
    /// input are checked at start (`zunder-guard run --network mainnet`).
    pub fn check_mainnet(&self) -> Result<(), ConfigError> {
        if !self.allow_mainnet {
            return Err(ConfigError::MainnetNeeds("allow_mainnet = true"));
        }
        // The limits may not exceed the default frame on mainnet ("Mainnet
        // code path"), and Guard's own rules no looser than pinned for mainnet
        // (`Policy::mainnet_ceiling`, independent of Guard's default preset).
        if let Err(field) = self.policy.within_mainnet_ceiling() {
            return Err(ConfigError::MainnetLooser(field));
        }
        if self.policy.max_trading_equity_usd.is_none() {
            return Err(ConfigError::MainnetNeeds(
                "policy.max_trading_equity_usd (the equity cap)",
            ));
        }
        if self.account.is_none() {
            return Err(ConfigError::MainnetNeeds("account"));
        }
        if self.api_wallet.is_none() {
            return Err(ConfigError::MainnetNeeds("api_wallet"));
        }
        Ok(())
    }

    /// Every budget of the venue's request weight for this config's
    /// `ip_share` and HIP-3 dexes; refused when the share is out of
    /// `(0, 1]` or too small to keep Guard safe.
    pub fn budgets(&self) -> Result<crate::budget::Budgets, ConfigError> {
        Ok(crate::budget::plan(
            self.ip_share,
            self.policy.markets.hip3_dexes().len(),
        )?)
    }

    pub fn network(&self) -> Result<GuardNetwork, ConfigError> {
        self.network.ok_or(ConfigError::NoNetwork)
    }

    /// Refuse the config unless it is for `command`'s network: `run
    /// --network testnet` runs testnet configs only, `--network mainnet`
    /// mainnet configs only (the runner's `require_network`), and only
    /// configs whose mode sends there.
    pub fn require_network(&self, command: GuardNetwork) -> Result<(), ConfigError> {
        let config = self.network()?;
        if config != command {
            return Err(ConfigError::WrongNetwork {
                config: config.name(),
                command: command.name(),
            });
        }
        if self.mode.network() != Some(command) {
            return Err(ConfigError::NotSending {
                mode: self.mode.name(),
                command: command.name(),
            });
        }
        Ok(())
    }

    pub fn account(&self) -> Result<Address, ConfigError> {
        self.account
            .as_deref()
            .and_then(Address::from_hex)
            .ok_or(ConfigError::Account)
    }

    /// Refuse a key whose address is not the config's API wallet; refuse
    /// any key when the config names none.
    pub fn check_api_wallet(&self, key: Address) -> Result<(), ConfigError> {
        let expected = self
            .api_wallet
            .as_deref()
            .and_then(Address::from_hex)
            .ok_or(ConfigError::NoApiWallet)?;
        if expected != key {
            return Err(ConfigError::ApiWalletDiffers {
                expected: expected.to_hex(),
                key: key.to_hex(),
            });
        }
        Ok(())
    }

    pub fn listen_addr(&self) -> Result<SocketAddr, ConfigError> {
        let addr: SocketAddr = self
            .listen
            .parse()
            .map_err(|_| ConfigError::Listen(self.listen.clone()))?;
        if !addr.ip().is_loopback() {
            return Err(ConfigError::Listen(self.listen.clone()));
        }
        Ok(addr)
    }

    /// The risk journal: paper keeps its own, so that a paper run never
    /// touches the journal real orders are judged by, and a mainnet config
    /// its own name (`risk-mainnet.jsonl`), so that a testnet journal left
    /// in the same directory can never pass for mainnet's.
    pub fn risk_journal(&self, paper: bool) -> PathBuf {
        self.state_dir.join(match (paper, self.mode) {
            (true, _) => "risk-paper.jsonl",
            (false, GuardMode::Mainnet) => "risk-mainnet.jsonl",
            (false, _) => "risk.jsonl",
        })
    }

    /// The decision journal, named as the risk journal.
    pub fn decision_journal(&self, paper: bool) -> PathBuf {
        self.state_dir.join(match (paper, self.mode) {
            (true, _) => "decisions-paper.jsonl",
            (false, GuardMode::Mainnet) => "decisions-mainnet.jsonl",
            (false, _) => "decisions.jsonl",
        })
    }

    /// For a mainnet config: refuses while `risk.jsonl` (testnet's name,
    /// and mainnet's in earlier builds) exists and is not plainly a testnet
    /// journal, so that a fresh `risk-mainnet.jsonl` never starts beside an
    /// old mainnet journal and drops its halts, peak and day start. Fails
    /// closed: a file it cannot read or parse is refused too.
    pub fn check_no_old_mainnet_journal(&self) -> Result<(), ConfigError> {
        if self.mode != GuardMode::Mainnet {
            return Ok(());
        }
        let old = self.state_dir.join("risk.jsonl");
        match std::fs::symlink_metadata(&old) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            _ => {}
        }
        let network = std::fs::read_to_string(&old).ok().and_then(|text| {
            let first: serde_json::Value = serde_json::from_str(text.lines().next()?).ok()?;
            first
                .pointer("/event/scope/network")?
                .as_str()
                .map(str::to_owned)
        });
        if network.as_deref() == Some("testnet") {
            Ok(())
        } else {
            Err(ConfigError::OldMainnetJournal(old))
        }
    }

    /// The kill file: while it exists, Guard opens nothing and flattens.
    /// The emergency log of the decision journal of the same mode, in
    /// [`GuardConfig::emergency_dir`]: `emergency-` and the journal's file
    /// name, so that it is never the journal's own file, whatever the
    /// directory resolves to.
    pub fn emergency_log(&self, paper: bool) -> PathBuf {
        let dir = self
            .emergency_dir
            .clone()
            .unwrap_or_else(|| self.state_dir.join("emergency"));
        let journal = self.decision_journal(paper);
        let name = journal
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        dir.join(format!("emergency-{name}"))
    }

    pub fn kill_file(&self) -> PathBuf {
        self.state_dir.join("kill")
    }

    /// The risk journal's scope: the network (`paper-` in front for paper
    /// mode) and the account.
    pub fn journal_scope(&self, paper: bool) -> Result<zunder_venue::JournalScope, ConfigError> {
        let network = self.network()?.name();
        Ok(zunder_venue::JournalScope {
            network: if paper {
                format!("paper-{network}")
            } else {
                network.to_owned()
            },
            account: self.account()?.to_hex(),
        })
    }
}

fn first_value(table: &toml::Table, matches: &dyn Fn(&toml::Value) -> bool) -> Option<String> {
    table
        .iter()
        .find_map(|(key, value)| first_in(value, matches).map(|path| format!("{key}{path}")))
}

fn first_in(value: &toml::Value, matches: &dyn Fn(&toml::Value) -> bool) -> Option<String> {
    if matches(value) {
        return Some(String::new());
    }
    match value {
        toml::Value::Table(table) => first_value(table, matches).map(|path| format!(".{path}")),
        toml::Value::Array(items) => items.iter().enumerate().find_map(|(index, item)| {
            first_in(item, matches).map(|path| format!("[{index}]{path}"))
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = "0x14791697260e4c9a71f18484c9f997b308e59325";
    const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

    fn minimal() -> String {
        format!(
            "network = \"testnet\"\naccount = \"{ACCOUNT}\"\n[auth]\nclients = [\"{CLIENT}\"]\n"
        )
    }

    #[test]
    fn parse_errors_never_quote_a_renewal_token() {
        let token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
        for line in [
            format!("licence_renewal_token = \"{token}\" trailing"),
            format!("licence_auto_update = \"{token}\""),
        ] {
            let error = GuardConfig::parse(&format!("{line}\n{}", minimal()))
                .unwrap_err()
                .to_string();
            assert!(!error.contains(token), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn token_configs_must_be_private_and_updates_make_them_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::testdir::TestDir::new("private-renewal-config");
        let path = dir.path().join("guard.toml");
        let text = format!(
            "licence_renewal_token = \"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ\"\n{}",
            minimal()
        );
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(GuardConfig::load(&path).is_err());
        GuardConfig::update(&path, |_| {}).unwrap();
        assert_eq!(zunder_venue::owner_only::check(&path).unwrap(), None);
        assert!(GuardConfig::load(&path).is_ok());
    }

    #[test]
    fn a_mainnet_journal_never_starts_beside_an_old_one() {
        let dir = crate::testdir::TestDir::new("old-mainnet-journal");
        let mut config = GuardConfig::parse(&minimal()).unwrap();
        config.state_dir = dir.path().to_owned();
        config.mode = GuardMode::Mainnet;
        let old = dir.path().join("risk.jsonl");
        // No old journal: fine.
        config.check_no_old_mainnet_journal().unwrap();
        // A testnet journal under testnet's name: fine.
        let testnet = r#"{"check":"x","event":{"kind":"initialised","scope":{"network":"testnet","account":"0x"}}}"#;
        std::fs::write(&old, format!("{testnet}\n")).unwrap();
        config.check_no_old_mainnet_journal().unwrap();
        // A mainnet journal an earlier build named so, a journal without a
        // scope, and a file that is not a journal: refused.
        for first in [
            testnet.replace("testnet", "mainnet"),
            r#"{"check":"x","event":{"kind":"initialised"}}"#.to_owned(),
            "not json".to_owned(),
        ] {
            std::fs::write(&old, format!("{first}\n")).unwrap();
            assert!(matches!(
                config.check_no_old_mainnet_journal(),
                Err(ConfigError::OldMainnetJournal(_))
            ));
        }
        // Not a mainnet config: never refused.
        config.mode = GuardMode::Testnet;
        config.check_no_old_mainnet_journal().unwrap();
    }

    #[test]
    fn a_minimal_config_takes_the_defaults() {
        let config = GuardConfig::parse(&minimal()).unwrap();
        assert_eq!(config.listen_addr().unwrap().port(), DEFAULT_PORT);
        assert_eq!(config.policy, Policy::default());
        assert_eq!(config.network().unwrap(), GuardNetwork::Testnet);
        // Written and read back, the same.
        assert_eq!(
            GuardConfig::parse(&config.to_toml().unwrap()).unwrap(),
            config
        );
    }

    #[test]
    fn floats_dates_unknown_keys_and_bad_values_are_refused() {
        let cases = [
            format!("{}[policy]\nmax_leverage = 5.0\n", minimal()),
            format!("{}when = 2026-10-06\n", minimal()),
            format!("{}color = \"blue\"\n", minimal()),
            format!("{}[policy]\nmax_leverage = \"60\"\n", minimal()),
            format!("{}listen = \"0.0.0.0:8547\"\n", minimal()),
            format!("{}listen = \"192.168.1.5:8547\"\n", minimal()),
            format!("sync_seconds = 4\n{}", minimal()),
            format!("ip_share = 0.5\n{}", minimal()),
            format!("ip_share = \"0\"\n{}", minimal()),
            format!("ip_share = \"-0.5\"\n{}", minimal()),
            format!("ip_share = \"1.01\"\n{}", minimal()),
            format!("ip_share = \"half\"\n{}", minimal()),
            format!("ip_share = \"0.25\"\n{}", minimal()),
            format!("{}allow_mainnet = true\n", minimal()),
            minimal().replace("network = \"testnet\"\n", ""),
            minimal().replace(ACCOUNT, "0x12"),
            minimal().replace(CLIENT, "nobody"),
        ];
        for case in cases {
            assert!(GuardConfig::parse(&case).is_err(), "{case}");
        }
    }

    /// `ip_share`: 1 by default; any share in (0, 1] that keeps Guard safe
    /// with the markets' HIP-3 dexes (`budget.rs`: at least 0.291 with the
    /// main dex alone, 0.466 with one HIP-3 dex, 0.749 with two); the
    /// reason given when not.
    #[test]
    fn ip_share_is_a_decimal_in_its_bounds() {
        assert_eq!(
            GuardConfig::parse(&minimal()).unwrap().ip_share,
            Decimal::ONE
        );
        for (share, markets) in [
            ("1", "\"all\""),
            ("0.5", "\"all\""),
            ("0.3333", "\"all\""),
            ("0.291", "\"all\""),
            ("0.5", "[\"*\", \"xyz:*\"]"),
            ("0.749", "[\"*\", \"xyz:*\", \"flx:*\"]"),
        ] {
            let text = format!(
                "ip_share = \"{share}\"\n{}[policy]\nmarkets = {markets}\n",
                minimal()
            );
            let config =
                GuardConfig::parse(&text).unwrap_or_else(|error| panic!("{text}: {error}"));
            assert_eq!(config.ip_share.to_string(), share);
            // Written and read back, the same.
            assert_eq!(
                GuardConfig::parse(&config.to_toml().unwrap()).unwrap(),
                config
            );
        }
        for (share, markets, reason) in [
            ("0.29", "\"all\"", "less than one account read a minute"),
            ("0.25", "\"all\"", "less than one account read a minute"),
            ("0.4", "[\"*\", \"xyz:*\"]", "only every"),
            ("0.5", "[\"*\", \"xyz:*\", \"flx:*\"]", "only every"),
            ("0.1", "[\"*\", \"xyz:*\"]", "fixed timer"),
            ("0", "\"all\"", "above 0 and at most 1"),
            ("1.5", "\"all\"", "above 0 and at most 1"),
        ] {
            let text = format!(
                "ip_share = \"{share}\"\n{}[policy]\nmarkets = {markets}\n",
                minimal()
            );
            let error = GuardConfig::parse(&text).unwrap_err().to_string();
            assert!(error.contains(reason), "{share} {markets}: {error}");
            assert!(error.contains("ip_share"), "{error}");
        }
    }

    #[test]
    fn mainnet_needs_every_guard() {
        let base = format!(
            "mode = \"mainnet\"\n{}",
            minimal().replace("\"testnet\"", "\"mainnet\"")
        );
        // Without allow_mainnet, the cap and the API wallet: refused.
        assert!(matches!(
            GuardConfig::parse(&base),
            Err(ConfigError::MainnetNeeds(_))
        ));
        let allowed = format!("allow_mainnet = true\n{base}");
        assert!(matches!(
            GuardConfig::parse(&allowed),
            Err(ConfigError::MainnetNeeds(_))
        ));
        let capped = format!("{allowed}[policy]\nmax_trading_equity_usd = \"2000\"\n");
        assert!(matches!(
            GuardConfig::parse(&capped),
            Err(ConfigError::MainnetNeeds("api_wallet"))
        ));
        let complete = format!("api_wallet = \"{CLIENT}\"\n{capped}");
        let config = GuardConfig::parse(&complete).unwrap();
        // The testnet command refuses it, and the other way round.
        assert!(config.require_network(GuardNetwork::Mainnet).is_ok());
        assert!(matches!(
            config.require_network(GuardNetwork::Testnet),
            Err(ConfigError::WrongNetwork { .. })
        ));
        let testnet = GuardConfig::parse(&minimal()).unwrap();
        assert!(testnet.require_network(GuardNetwork::Mainnet).is_err());
        // A paper config sends nowhere; it may read a mainnet account
        // without the mainnet guards.
        assert!(matches!(
            testnet.require_network(GuardNetwork::Testnet),
            Err(ConfigError::NotSending { .. })
        ));
        let paper_mainnet = minimal().replace("\"testnet\"", "\"mainnet\"");
        assert!(GuardConfig::parse(&paper_mainnet).is_ok());
        let wrong = format!("mode = \"testnet\"\n{paper_mainnet}");
        assert!(matches!(
            GuardConfig::parse(&wrong),
            Err(ConfigError::ModeNetwork { .. })
        ));
    }

    #[test]
    fn mainnet_takes_no_looser_policy() {
        let complete = format!(
            "allow_mainnet = true\nmode = \"mainnet\"\napi_wallet = \"{CLIENT}\"\n{}[policy]\nmax_trading_equity_usd = \"2000\"\n",
            minimal().replace("\"testnet\"", "\"mainnet\"")
        );
        assert!(GuardConfig::parse(&complete).is_ok());
        for looser in [
            "max_leverage = \"6\"",
            "max_loss_at_stop = \"0.03\"",
            "drawdown_halt = \"0.3\"",
            "fee_bps = \"0\"",
        ] {
            let text = format!("{complete}{looser}\n");
            assert!(
                matches!(
                    GuardConfig::parse(&text),
                    Err(ConfigError::MainnetLooser(_))
                ),
                "{looser}"
            );
        }
        // On testnet the same values are the user's choice.
        assert!(
            GuardConfig::parse(&format!("{}[policy]\nmax_leverage = \"6\"\n", minimal())).is_ok()
        );
    }

    /// Automatic licence renewal is off unless switched on, and then needs
    /// a renewal token of the right shape; off, nothing about it is
    /// written into the file.
    #[test]
    fn licence_renewal_is_off_by_default_and_needs_a_token() {
        let dir = crate::testdir::TestDir::new("config-renewal");
        let path = dir.path().join("guard.toml");
        std::fs::write(&path, minimal()).unwrap();
        let config = GuardConfig::load(&path).unwrap();
        assert!(!config.licence_auto_update);
        assert!(config.licence_renewal_token.is_none());
        let text = config.to_toml().unwrap();
        assert!(!text.contains("licence_auto_update"), "{text}");
        let token = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN-_Q";
        let on = GuardConfig {
            licence_auto_update: true,
            licence_renewal_token: Some(token.into()),
            ..config.clone()
        };
        assert!(on.validate().is_ok());
        assert!(on.to_toml().unwrap().contains("licence_auto_update = true"));
        let no_token = GuardConfig {
            licence_renewal_token: None,
            ..on.clone()
        };
        assert!(matches!(no_token.validate(), Err(ConfigError::Renewal(_))));
        for bad in [
            "short",
            &format!("{token}x"),
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN+/Q",
        ] {
            let bad = GuardConfig {
                licence_renewal_token: Some(bad.to_owned()),
                ..on.clone()
            };
            assert!(matches!(bad.validate(), Err(ConfigError::Renewal(_))));
        }
    }

    #[test]
    fn the_emergency_log_is_inside_the_state_dir_and_never_the_journals_dir() {
        // `init` writes state_dir = "." (Docker: /data, systemd:
        // /var/lib/zunder-guard): the default emergency log lies inside it,
        // where Guard may write.
        let dir = crate::testdir::TestDir::new("config-emergency");
        let path = dir.path().join("guard.toml");
        std::fs::write(&path, format!("state_dir = \".\"\n{}", minimal())).unwrap();
        let config = GuardConfig::load(&path).unwrap();
        let home = dir.path().canonicalize().unwrap();
        let log = config.emergency_log(false);
        assert!(log.starts_with(&home), "{}", log.display());
        let journal = config.decision_journal(false);
        assert_eq!(
            log.file_name().unwrap().to_string_lossy(),
            format!(
                "emergency-{}",
                journal.file_name().unwrap().to_string_lossy()
            )
        );
        assert_ne!(log.parent(), journal.parent());
        // A directory that resolves to the state directory (the check
        // compares paths, which `x/..` gets past while `x` does not exist):
        // still another file than the journal.
        let mut around = config.clone();
        around.emergency_dir = Some(config.state_dir.join("x").join(".."));
        assert!(around.validate().is_ok());
        assert_ne!(around.emergency_log(false).file_name(), journal.file_name());
        // Named as the state directory itself: refused.
        let mut same = config.clone();
        same.emergency_dir = Some(config.state_dir.clone());
        assert!(matches!(same.validate(), Err(ConfigError::EmergencyDir)));
        let mut elsewhere = config;
        elsewhere.emergency_dir = Some(home.join("other"));
        assert!(elsewhere.validate().is_ok());
    }

    #[test]
    fn a_relative_state_dir_is_the_config_files() {
        let dir = crate::testdir::TestDir::new("config-state");
        let path = dir.path().join("guard.toml");
        std::fs::write(&path, minimal()).unwrap();
        let config = GuardConfig::load(&path).unwrap();
        assert!(config.state_dir.is_absolute());
        assert!(
            config
                .kill_file()
                .starts_with(dir.path().canonicalize().unwrap())
        );
        // An update keeps it relative (the directory may move), keeps the
        // file owner-only and leaves no temporary file behind.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        GuardConfig::update(&path, |config| {
            config.api_wallet = Some(CLIENT.to_owned());
        })
        .unwrap();
        let raw = GuardConfig::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(raw.state_dir, PathBuf::from("guard-state"));
        assert_eq!(raw.api_wallet.as_deref(), Some(CLIENT));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(!dir.path().join("guard.toml.new").exists());
        // An update that would not validate changes nothing.
        let before = std::fs::read_to_string(&path).unwrap();
        assert!(
            GuardConfig::update(&path, |config| {
                config.policy.max_leverage = rust_decimal::dec!(500);
            })
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn the_key_must_be_the_configs_api_wallet() {
        let config =
            GuardConfig::parse(&format!("api_wallet = \"{CLIENT}\"\n{}", minimal())).unwrap();
        assert!(
            config
                .check_api_wallet(Address::from_hex(CLIENT).unwrap())
                .is_ok()
        );
        assert!(
            config
                .check_api_wallet(Address::from_hex(ACCOUNT).unwrap())
                .is_err()
        );
        // No api_wallet in the config: no key is accepted to send.
        let bare = GuardConfig::parse(&minimal()).unwrap();
        assert!(
            bare.check_api_wallet(Address::from_hex(CLIENT).unwrap())
                .is_err()
        );
    }

    #[test]
    fn paper_and_real_journals_are_apart() {
        let config = GuardConfig::parse(&minimal()).unwrap();
        assert_ne!(config.risk_journal(true), config.risk_journal(false));
        assert_eq!(config.journal_scope(true).unwrap().network, "paper-testnet");
        assert_eq!(config.journal_scope(false).unwrap().network, "testnet");
        assert_eq!(config.journal_scope(false).unwrap().account, ACCOUNT);
    }
}
