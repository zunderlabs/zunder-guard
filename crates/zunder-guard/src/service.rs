// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Admission shared by OS-supervised mainnet installations.
//!
//! This module never initializes or resumes a journal and never sends an order.
//! Platform admission precedes credential input. The runtime repeats its normal
//! mainnet checks and accepts a key only through its owned standard-input pipe.

use crate::config::{GuardConfig, GuardMode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};
use zeroize::Zeroizing;
use zunder_guard_core::sign::{Address, GuardKey};

pub mod acl;
#[cfg(any(windows, test))]
pub(crate) mod lifecycle;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("service refused: {0}")]
    Refused(String),
    #[error("service I/O: {0}")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, ServiceError>;
pub fn refused(message: impl Into<String>) -> ServiceError {
    ServiceError::Refused(message.into())
}

/// Public metadata only. Never serialize credential plaintext into this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBinding {
    pub version: u32,
    pub credential_id: String,
    pub mode: String,
    pub account: String,
    pub api_wallet: String,
    pub home: PathBuf,
    pub config: PathBuf,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub admission_config_sha256: String,
    pub identity: ServiceIdentity,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "platform", rename_all = "lowercase", deny_unknown_fields)]
pub enum ServiceIdentity {
    Windows {
        service_name: String,
        service_sid: String,
    },
    Macos {
        uid: u32,
        gid: u32,
    },
}

impl ServiceBinding {
    pub fn validate(&self) -> Result<GuardConfig> {
        self.validate_shape()?;
        for path in [&self.home, &self.config, &self.executable] {
            if fs::canonicalize(path)? != *path {
                return Err(refused("service paths must use their canonical spelling"));
            }
        }
        if hash_file(&self.executable)? != self.executable_sha256 {
            return Err(refused(
                "service executable differs from the admitted release",
            ));
        }
        #[cfg(windows)]
        let config = windows::load_config(self)?;
        #[cfg(not(windows))]
        let config =
            GuardConfig::load(&self.config).map_err(|_| refused("invalid service config"))?;
        self.validate_runtime_config(&config)?;
        Ok(config)
    }

    /// Validate the exact normalized snapshot that will construct Guard. A
    /// later read matching admission cannot authorize an earlier changed read.
    /// Paths/platform/image checks remain in validate()/verify_child().
    pub fn validate_runtime_config(&self, config: &GuardConfig) -> Result<()> {
        self.validate_shape()?;
        config
            .validate()
            .map_err(|_| refused("invalid runtime service config"))?;
        if config.mode != GuardMode::Mainnet {
            return Err(refused("service config is not mainnet"));
        }
        config
            .check_mainnet()
            .map_err(|_| refused("mainnet config guards failed"))?;
        if config.account().map_err(|_| refused("invalid account"))? != address(&self.account)? {
            return Err(refused("configured account differs from service consent"));
        }
        config
            .check_api_wallet(address(&self.api_wallet)?)
            .map_err(|_| refused("configured API wallet differs from service binding"))?;
        if config_fingerprint(config)? != self.admission_config_sha256 {
            return Err(refused(
                "service config changed outside licence renewal; stop and explicitly readmit the service",
            ));
        }
        if fs::canonicalize(&config.state_dir)? != self.home {
            return Err(refused("runtime state differs from admitted service home"));
        }
        Ok(())
    }

    pub fn validate_journal(&self) -> Result<()> {
        let config = self.validate()?;
        let path = config.risk_journal(false);
        if !path.is_file() {
            return Err(refused(
                "mainnet journal must be explicitly initialized before service start",
            ));
        }
        zunder_venue::PersistentRisk::open_for(
            &path,
            &config.policy.risk_limits(),
            &config
                .journal_scope(false)
                .map_err(|_| refused("invalid mainnet journal scope"))?,
        )
        .map_err(|_| {
            refused("mainnet journal could not be admitted; no automatic reset or resume")
        })?;
        Ok(())
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self.version != 1 || self.mode != "mainnet" {
            return Err(refused("unsupported service binding version or mode"));
        }
        if self.credential_id.is_empty()
            || self.credential_id.len() > 80
            || !self
                .credential_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err(refused("invalid credential identity"));
        }
        address(&self.account)?;
        address(&self.api_wallet)?;
        if [&self.executable_sha256, &self.admission_config_sha256]
            .iter()
            .any(|hash| {
                hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            })
        {
            return Err(refused("invalid executable digest"));
        }
        for path in [&self.home, &self.config, &self.executable] {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(refused(
                    "service paths must be absolute, without parent traversal",
                ));
            }
        }
        match &self.identity {
            ServiceIdentity::Windows {
                service_name,
                service_sid,
            } => {
                if service_name != &format!("ZunderGuard-{}", self.credential_id)
                    || !service_sid.starts_with("S-1-5-80-")
                    || !service_sid
                        .bytes()
                        .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
                {
                    return Err(refused("invalid virtual service identity"));
                }
            }
            ServiceIdentity::Macos { uid, gid } if *uid == 0 || *gid == 0 => {
                return Err(refused("Guard child must not run as root"));
            }
            ServiceIdentity::Macos { .. } => {}
        }
        Ok(())
    }

    pub fn check_key(&self, bytes: &[u8]) -> Result<()> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| refused("invalid credential encoding"))?;
        let key = GuardKey::from_hex(text).map_err(|_| refused("invalid credential"))?;
        if key.address() != address(&self.api_wallet)? {
            return Err(refused("credential does not match the admitted API wallet"));
        }
        Ok(())
    }

    /// Stable credential scope. A verified release upgrade may change its image digest;
    /// account, wallet, paths and OS identity still require reprovisioning.
    pub fn digest(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&(
            self.version,
            &self.credential_id,
            &self.mode,
            &self.account,
            &self.api_wallet,
            &self.home,
            &self.config,
            &self.executable,
            &self.identity,
        ))
        .map_err(|_| refused("invalid binding metadata"))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    /// Explicit arguments only. No ambient ZUNDER_* network/key/config override.
    pub fn child_command(&self, binding_path: &Path) -> Command {
        let mut cmd = Command::new(&self.executable);
        cmd.env_clear()
            .arg("--home")
            .arg(&self.home)
            .arg("--config")
            .arg(&self.config)
            .args([
                "run",
                "--network",
                "mainnet",
                "--key-stdin",
                "--supervised-stdin",
                "--service-binding",
            ])
            .arg(binding_path)
            .env(zunder_venue::hyperliquid::CONFIRM_VAR, &self.account);
        cmd
    }
}

/// Only these three fields may change under automatic licence delivery/renewal.
/// All other normalized fields, including future fields, are pinned by default.
pub fn config_fingerprint(config: &GuardConfig) -> Result<String> {
    let mut value = serde_json::to_value(config)
        .map_err(|_| refused("config admission serialization failed"))?;
    let map = value
        .as_object_mut()
        .ok_or_else(|| refused("invalid config admission"))?;
    for field in ["licence", "licence_auto_update", "licence_renewal_token"] {
        map.remove(field);
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&value)
                .map_err(|_| refused("config admission serialization failed"))?
        )
    ))
}

fn address(value: &str) -> Result<Address> {
    Address::from_hex(value).ok_or_else(|| refused("invalid service account address"))
}

pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = [0; 16384];
    loop {
        let count = file.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        hasher.update(&bytes[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// One bounded frame. Consumes no byte after LF, so the same reader can
/// watch parent liveness without losing buffered input. Default keyread is unchanged.
pub fn read_key_frame(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(68));
    loop {
        let mut next = [0u8; 1];
        match reader.read(&mut next) {
            Ok(0) => return Err(refused("supervised key frame ended before newline")),
            Ok(_) if next[0] == b'\n' => break,
            Ok(_) => {
                bytes.push(next[0]);
                if bytes.len() > 67 {
                    return Err(refused("supervised key frame is too long"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(refused("supervised key frame could not be read")),
        }
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| refused("invalid key frame"))?;
    GuardKey::from_hex(text).map_err(|_| refused("invalid key frame"))?;
    Ok(bytes)
}

/// After the key, only EOF is legal. Any data/error is also a shutdown,
/// never a command, account change or extension to the credential.
pub fn await_parent_close(reader: &mut impl Read) -> &'static str {
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => return "supervisor closed standard input",
            Ok(_) => return "unexpected supervisor input",
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return "supervisor input failed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "0123456789012345678901234567890123456789012345678901234567890123";
    #[test]
    fn framing_preserves_every_byte_after_the_key() {
        let text = format!("{KEY}\nnever-a-command");
        let mut input = std::io::Cursor::new(text.as_bytes());
        assert_eq!(
            read_key_frame(&mut input).unwrap().as_slice(),
            KEY.as_bytes()
        );
        assert_eq!(input.position(), 65);
        assert_eq!(
            await_parent_close(&mut input),
            "unexpected supervisor input"
        );
        let mut input = std::io::Cursor::new(format!("{KEY}\n"));
        read_key_frame(&mut input).unwrap();
        assert_eq!(
            await_parent_close(&mut input),
            "supervisor closed standard input"
        );
    }
    #[test]
    fn framing_refuses_eof_overlong_and_malformed_without_echo() {
        for input in [
            KEY.to_owned(),
            format!("{}\n", "f".repeat(68)),
            "secret-invalid\n".into(),
            "\n".into(),
        ] {
            let error = read_key_frame(&mut input.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(!error.contains(KEY));
            assert!(!error.contains("secret-invalid"));
        }
    }
}

/// Read public metadata, then enforce the OS ownership boundary before any key
/// access. JSON diagnostics are deliberately not echoed.
pub fn load_binding(path: &Path) -> Result<ServiceBinding> {
    if fs::metadata(path)?.len() > 32768 {
        return Err(refused("service binding is oversized"));
    }
    #[cfg(target_os = "macos")]
    macos::validate_binding_file(path)?;
    let binding: ServiceBinding = serde_json::from_slice(&fs::read(path)?)
        .map_err(|_| refused("invalid service binding JSON"))?;
    binding.validate_shape()?;
    #[cfg(windows)]
    windows::validate_paths(&binding, path)?;
    Ok(binding)
}

pub fn enforce_no_core_dumps() -> Result<()> {
    #[cfg(windows)]
    {
        windows::enforce_no_core_dumps()
    }
    #[cfg(target_os = "macos")]
    {
        macos::enforce_no_core_dumps()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err(refused(
            "this service credential backend is supported on Windows and macOS only",
        ))
    }
}

pub fn provision(binding: &ServiceBinding, key: &Zeroizing<Vec<u8>>, replace: bool) -> Result<()> {
    #[cfg(windows)]
    {
        windows::provision(binding, key, replace)
    }
    #[cfg(target_os = "macos")]
    {
        macos::provision(binding, key, replace)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (binding, key, replace);
        Err(refused("unsupported service credential platform"))
    }
}

pub fn check(binding: &ServiceBinding) -> Result<()> {
    #[cfg(windows)]
    {
        windows::check(binding)
    }
    #[cfg(target_os = "macos")]
    {
        macos::check(binding)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = binding;
        Err(refused("unsupported service credential platform"))
    }
}

pub fn remove(binding: &ServiceBinding) -> Result<()> {
    #[cfg(windows)]
    {
        windows::remove(binding)
    }
    #[cfg(target_os = "macos")]
    {
        macos::remove(binding)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = binding;
        Err(refused("unsupported service credential platform"))
    }
}

pub fn verify_child(binding: &ServiceBinding) -> Result<()> {
    binding.validate()?;
    if fs::canonicalize(std::env::current_exe()?)? != binding.executable {
        return Err(refused("service child is not the admitted executable"));
    }
    #[cfg(windows)]
    {
        windows::enforce_no_core_dumps()?;
        windows::verify_service_identity(binding)
    }
    #[cfg(target_os = "macos")]
    {
        macos::verify_child(binding)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err(refused("unsupported supervised child platform"))
    }
}

pub fn run(binding: &ServiceBinding, binding_path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        windows::run(binding, binding_path)
    }
    #[cfg(target_os = "macos")]
    {
        macos::run(binding, binding_path)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (binding, binding_path);
        Err(refused("unsupported service platform"))
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    #[test]
    fn only_licence_fields_can_change_without_readmission() {
        let original = GuardConfig::default();
        let baseline = config_fingerprint(&original).unwrap();
        let mut renewal = original.clone();
        renewal.licence = Some("synthetic-licence".into());
        renewal.licence_auto_update = !renewal.licence_auto_update;
        renewal.licence_renewal_token = Some("synthetic-token".into());
        assert_eq!(config_fingerprint(&renewal).unwrap(), baseline);
        let mut account = original.clone();
        account.account = Some("0x1111111111111111111111111111111111111111".into());
        let mut wallet = original.clone();
        wallet.api_wallet = Some("0x1111111111111111111111111111111111111111".into());
        let mut mode = original.clone();
        mode.mode = GuardMode::Mainnet;
        let mut consent = original.clone();
        consent.allow_mainnet = !consent.allow_mainnet;
        let mut interval = original.clone();
        interval.sync_seconds += 1;
        let mut policy = original.clone();
        policy.policy.max_trading_equity_usd = Some(rust_decimal::Decimal::from(100));
        let mut auth = original.clone();
        auth.auth
            .clients
            .push("0x1111111111111111111111111111111111111111".into());
        let mut network = original.clone();
        network.network = Some(crate::config::GuardNetwork::Mainnet);
        for changed in [
            account, wallet, mode, consent, interval, policy, auth, network,
        ] {
            assert_ne!(config_fingerprint(&changed).unwrap(), baseline);
        }
        let mut changed = original;
        changed.listen = "127.0.0.1:9999".into();
        assert_ne!(config_fingerprint(&changed).unwrap(), baseline);
    }
    #[test]
    fn framing_matches_independent_boundary_model_for_every_length() {
        for length in 0..300 {
            let text = format!("{}\ntrailing", "1".repeat(length));
            let accepted_by_model = length == 64;
            let result = read_key_frame(&mut text.as_bytes());
            assert_eq!(result.is_ok(), accepted_by_model, "length {length}");
        }
    }
}

/// Platform preflight must precede the hidden-input/stdin credential prompt.
pub fn validate_provision(binding: &ServiceBinding) -> Result<()> {
    #[cfg(windows)]
    {
        windows::validate_provision(binding)
    }
    #[cfg(target_os = "macos")]
    {
        macos::validate_provision(binding)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = binding;
        Err(refused("unsupported service credential platform"))
    }
}

pub fn load_config(binding: &ServiceBinding) -> Result<GuardConfig> {
    #[cfg(windows)]
    {
        windows::load_config(binding)
    }
    #[cfg(target_os = "macos")]
    {
        macos::load_config(binding)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = binding;
        Err(refused("unsupported service platform"))
    }
}
pub fn validate_management_stopped(binding: &ServiceBinding) -> Result<()> {
    #[cfg(windows)]
    {
        windows::validate_management_stopped(binding)
    }
    #[cfg(target_os = "macos")]
    {
        macos::validate_management_stopped(binding)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = binding;
        Err(refused("unsupported service platform"))
    }
}
pub fn write_binding(path: &Path, binding: &ServiceBinding) -> Result<()> {
    #[cfg(windows)]
    {
        windows::write_binding(path, binding)
    }
    #[cfg(target_os = "macos")]
    {
        macos::write_binding(path, binding)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (path, binding);
        Err(refused("unsupported service platform"))
    }
}
pub fn write_config(
    binding: &ServiceBinding,
    expected: &GuardConfig,
    next: &GuardConfig,
) -> Result<()> {
    #[cfg(windows)]
    {
        windows::write_config(binding, expected, next)
    }
    #[cfg(target_os = "macos")]
    {
        macos::write_config(binding, expected, next)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (binding, expected, next);
        Err(refused("unsupported service platform"))
    }
}

#[cfg(test)]
mod runtime_snapshot_tests {
    use super::*;
    use crate::{config::GuardNetwork, testdir::TestDir};
    use zunder_guard_core::policy::Policy;

    fn fixture(home: &Path) -> (ServiceBinding, GuardConfig) {
        let home = fs::canonicalize(home).unwrap();
        let mut policy = Policy::mainnet_ceiling();
        policy.max_trading_equity_usd = Some(100.into());
        let mut config = GuardConfig {
            network: Some(GuardNetwork::Mainnet),
            mode: GuardMode::Mainnet,
            account: Some("0x1111111111111111111111111111111111111111".into()),
            api_wallet: Some("0x2222222222222222222222222222222222222222".into()),
            allow_mainnet: true,
            state_dir: home.clone(),
            policy,
            ..GuardConfig::default()
        };
        config
            .auth
            .clients
            .push("0x3333333333333333333333333333333333333333".into());
        config.validate().unwrap();
        config.check_mainnet().unwrap();
        let executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let binding = ServiceBinding {
            version: 1,
            credential_id: "ci-snapshot".into(),
            mode: "mainnet".into(),
            account: config.account.clone().unwrap(),
            api_wallet: config.api_wallet.clone().unwrap(),
            config: home.join("guard.toml"),
            home,
            executable_sha256: hash_file(&executable).unwrap(),
            executable,
            admission_config_sha256: config_fingerprint(&config).unwrap(),
            identity: ServiceIdentity::Windows {
                service_name: "ZunderGuard-ci-snapshot".into(),
                service_sid: "S-1-5-80-1-2-3-4-5".into(),
            },
        };
        (binding, config)
    }

    #[test]
    fn restoring_admitted_disk_config_does_not_admit_changed_first_snapshot() {
        let directory = TestDir::new("service-snapshot-race");
        let (binding, admitted) = fixture(directory.path());
        for change_client in [true, false] {
            let mut supplied = admitted.clone();
            if change_client {
                supplied
                    .auth
                    .clients
                    .push("0x4444444444444444444444444444444444444444".into());
            } else {
                supplied.policy.max_trading_equity_usd = Some(200.into());
            }
            fs::write(&binding.config, supplied.to_toml().unwrap()).unwrap();
            // run() owns this snapshot; no later file read replaces its Setup.
            let first = GuardConfig::load(&binding.config).unwrap();
            fs::write(&binding.config, admitted.to_toml().unwrap()).unwrap();
            let later = GuardConfig::load(&binding.config).unwrap();
            assert!(binding.validate_runtime_config(&later).is_ok());
            assert!(
                binding.validate_runtime_config(&first).is_err(),
                "restoring the file must not admit a changed first read"
            );
        }
        assert!(
            !admitted.risk_journal(false).exists(),
            "snapshot admission must not initialize a journal"
        );
    }

    #[test]
    fn random_snapshot_interleavings_match_independent_config_equality_model() {
        let directory = TestDir::new("service-snapshot-model");
        let (binding, admitted) = fixture(directory.path());
        let mut rejected = 0;
        let mut accepted = 0;
        for seed in 0..128 {
            let mut random = fastrand::Rng::with_seed(seed);
            for _ in 0..32 {
                let mut used = admitted.clone();
                for _ in 0..random.usize(0..5) {
                    match random.usize(0..7) {
                        0 => used.licence = Some("synthetic-signed-key-placeholder".into()),
                        1 => {
                            used.licence_auto_update = true;
                            used.licence_renewal_token =
                                Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".into());
                        }
                        2 => used
                            .auth
                            .clients
                            .push("0x4444444444444444444444444444444444444444".into()),
                        3 => used.policy.max_trading_equity_usd = Some(200.into()),
                        4 => used.listen = "127.0.0.1:8999".into(),
                        5 => used.ip_share = rust_decimal::Decimal::new(5, 1),
                        _ => {
                            used.account = Some("0x5555555555555555555555555555555555555555".into())
                        }
                    }
                }
                // Independent reference compares typed fields, not hashes or
                // validation helpers. Only the three documented metadata fields
                // are neutralized; restoring a later snapshot is irrelevant.
                let mut model = used.clone();
                model.licence = admitted.licence.clone();
                model.licence_auto_update = admitted.licence_auto_update;
                model.licence_renewal_token = admitted.licence_renewal_token.clone();
                let expected = model == admitted;
                let later = if random.bool() { &admitted } else { &used };
                let _later_read = binding.validate_runtime_config(later);
                let got = binding.validate_runtime_config(&used).is_ok();
                assert_eq!(
                    got, expected,
                    "seed {seed}: validate the used snapshot, irrespective of later read"
                );
                if got {
                    accepted += 1;
                } else {
                    rejected += 1;
                }
            }
        }
        assert!(accepted > 0 && rejected > 0);
    }
}
