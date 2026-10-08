// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Mainnet service credentials in the macOS System Keychain.
//!
//! No API returns a printable credential. The shared service broker owns the
//! sole caller of `read`: an anonymous stdin pipe to the admitted Guard child.
//! This module does not start a service, initialize a journal, or grant consent.

use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
};

use nix::{
    sys::resource::{Resource, getrlimit, setrlimit},
    unistd::geteuid,
};
use security_framework::os::macos::keychain::SecKeychain;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;
use zunder_guard_core::sign::{Address, GuardKey};

use super::{Result, ServiceBinding, ServiceIdentity, refused};

const KEYCHAIN: &str = "/Library/Keychains/System.keychain";
const SERVICE: &str = "com.zunderlabs.guard.mainnet.v2";
// Documented OSStatus errSecItemNotFound, not a generic lookup failure.
const ITEM_NOT_FOUND: i32 = -25300;

/// Must run before hidden input/decryption, even outside launchd. The hard
/// zero is inherited across sudo/exec and cannot be raised by the Guard user.
pub fn enforce_no_core_dumps() -> Result<()> {
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|_| refused("could not disable service core dumps"))?;
    verify_no_core_dumps()
}

/// The supervised child calls this before reading its first credential byte.
pub fn verify_no_core_dumps() -> Result<()> {
    match getrlimit(Resource::RLIMIT_CORE) {
        Ok((0, 0)) => Ok(()),
        _ => Err(refused(
            "service requires soft and hard core limits of zero",
        )),
    }
}

/// Admit immutable root-owned JSON before the shared module reads it.
/// Symlinks and writable ancestors are refused; the privileged broker must
/// never trust a user's home or Homebrew cellar as an executable/config root.
pub fn validate_binding_file(path: &Path) -> Result<()> {
    trusted_root_path(path, false)
}

fn trusted_root_path(path: &Path, executable: bool) -> Result<()> {
    if !path.is_absolute() {
        return Err(refused("service path must be absolute"));
    }
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return Err(refused(
            "service path must be canonical and contain no symlinks",
        ));
    }
    for (index, component) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(component)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || (index == 0 && !metadata.is_file())
            || (index > 0 && !metadata.is_dir())
        {
            return Err(refused(
                "service path must be root-owned and not writable by others",
            ));
        }
        if index == 0 && executable && metadata.mode() & 0o111 == 0 {
            return Err(refused("service executable is not executable"));
        }
    }
    Ok(())
}

fn prepare(binding: &ServiceBinding) -> Result<String> {
    enforce_no_core_dumps()?;
    if !geteuid().is_root() {
        return Err(refused("System Keychain service management requires root"));
    }
    let ServiceIdentity::Macos { uid, gid } = &binding.identity else {
        return Err(refused("service binding belongs to another platform"));
    };
    if *uid == 0 || *gid == 0 {
        return Err(refused(
            "Guard child must use a dedicated non-root identity",
        ));
    }
    binding.validate()?;
    trusted_root_path(&binding.executable, true)?;
    // Do not allow another privileged process to use its own creator ACL to
    // provision an item intended for this release's actual executable.
    if fs::canonicalize(std::env::current_exe()?)? != binding.executable {
        return Err(refused(
            "run service management from the admitted installed executable",
        ));
    }
    credential_account(binding)
}

fn credential_account(binding: &ServiceBinding) -> Result<String> {
    if binding.credential_id.is_empty()
        || binding.credential_id.len() > 64
        || !binding
            .credential_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(refused("invalid service credential identifier"));
    }
    let account =
        Address::from_hex(&binding.account).ok_or_else(|| refused("invalid service account"))?;
    let wallet = Address::from_hex(&binding.api_wallet)
        .ok_or_else(|| refused("invalid service API wallet"))?;
    // Length framing avoids concatenation aliases. The home, venue account,
    // API wallet, named admission and exact release participate in the slot.
    // A new release gets its own creator ACL via internal pipe migration.
    let mut hash = Sha3_256::new();
    for field in [
        binding.home.to_string_lossy().as_ref(),
        &account.to_string(),
        &wallet.to_string(),
        &binding.credential_id,
        &binding.executable_sha256,
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    Ok(format!("mainnet-{:x}", hash.finalize()))
}

/// The label is public metadata and contains no wallet credential.
pub fn launchd_label(binding: &ServiceBinding) -> Result<String> {
    binding.validate_shape()?;
    Ok(format!("com.zunderlabs.guard.{}", binding.credential_id))
}

fn require_stopped(binding: &ServiceBinding) -> Result<()> {
    let result = Command::new("/bin/launchctl")
        .args(["print", &format!("system/{}", launchd_label(binding)?)])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    // launchctl print exits nonzero for a missing job; do not infer a stopped
    // process from a loaded job's text. Removal/replacement requires bootout.
    if result.success() {
        return Err(refused(
            "boot out the service before replacing or removing its credential",
        ));
    }
    // An error is not proof of absence. The helper must use the exact status
    // launchctl returns for an absent system-domain service (113 on macOS).
    if result.code() != Some(113) {
        return Err(refused("could not establish that the service is unloaded"));
    }
    Ok(())
}

fn validate_key(binding: &ServiceBinding, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(refused("invalid service credential length"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| refused("service credential is not valid text"))?;
    let key = GuardKey::from_hex(text.trim())
        .map_err(|_| refused("service credential is not a valid API wallet key"))?;
    if Some(key.address()) != Address::from_hex(&binding.api_wallet) {
        return Err(refused(
            "service credential does not match the admitted API wallet",
        ));
    }
    Ok(())
}

/// Shared CLI calls this before asking for or reading any plaintext key.
pub fn validate_provision(binding: &ServiceBinding) -> Result<()> {
    prepare(binding)?;
    require_stopped(binding)
}

/// Provision from hidden input/stdin already captured by the shared CLI after
/// no-core enforcement and complete configuration/consent preflight.
pub fn provision(binding: &ServiceBinding, key: &Zeroizing<Vec<u8>>, replace: bool) -> Result<()> {
    let account = prepare(binding)?;
    validate_key(binding, key)?;
    require_stopped(binding)?;
    // No system authentication prompt from the privileged background path.
    // Administrative Keychain access must already be authorized; denial never
    // silently writes into the login Keychain or changes item access control.
    let _interaction = SecKeychain::disable_user_interaction()
        .map_err(|_| refused("could not disable Keychain interaction"))?;
    let keychain =
        SecKeychain::open(KEYCHAIN).map_err(|_| refused("could not open the System Keychain"))?;
    match keychain.find_generic_password(SERVICE, &account) {
        Ok((old, mut item)) => {
            drop(old);
            if !replace {
                return Err(refused(
                    "service credential already exists; explicit replacement required",
                ));
            }
            // Preserve the existing ACL; never delete/recreate on an access
            // error. New code identity may need interactive re-admission.
            item.set_password(key)
                .map_err(|_| refused("System Keychain credential update refused"))?;
        }
        Err(error) if error.code() == ITEM_NOT_FOUND => {
            // SecKeychainAddGenericPassword creates the default creator ACL.
            // No all-app access, security CLI, or password-bearing argv.
            keychain
                .add_generic_password(SERVICE, &account, key)
                .map_err(|_| refused("System Keychain credential creation refused"))?;
        }
        Err(_) => {
            return Err(refused(
                "System Keychain credential lookup refused; nothing changed",
            ));
        }
    }
    drop(_interaction);
    check(binding)
}

/// Returns only to the shared broker; never format or write these bytes to a
/// console, diagnostic event, file or environment variable.
pub fn read(binding: &ServiceBinding) -> Result<Zeroizing<Vec<u8>>> {
    let account = prepare(binding)?;
    let _interaction = SecKeychain::disable_user_interaction()
        .map_err(|_| refused("could not disable Keychain interaction"))?;
    let keychain =
        SecKeychain::open(KEYCHAIN).map_err(|_| refused("could not open the System Keychain"))?;
    let (password, _) = keychain
        .find_generic_password(SERVICE, &account)
        .map_err(|_| {
            refused("System Keychain service credential unavailable; service not started")
        })?;
    let key = Zeroizing::new(password.as_ref().to_vec());
    drop(password);
    validate_key(binding, &key)?;
    Ok(key)
}

/// Success proves this installed executable can currently read the exact item;
/// it does not by itself prove the separate ACL/reboot/release evidence gates.
pub fn check(binding: &ServiceBinding) -> Result<()> {
    drop(read(binding)?);
    Ok(())
}

pub fn remove(binding: &ServiceBinding) -> Result<()> {
    let account = prepare(binding)?;
    require_stopped(binding)?;
    let _interaction = SecKeychain::disable_user_interaction()
        .map_err(|_| refused("could not disable Keychain interaction"))?;
    let keychain =
        SecKeychain::open(KEYCHAIN).map_err(|_| refused("could not open the System Keychain"))?;
    match keychain.find_generic_password(SERVICE, &account) {
        Ok((password, item)) => {
            drop(password);
            // The safe wrapper's delete API omits OSStatus. Verify exact-item
            // absence afterwards and report any ambiguous failure.
            item.delete();
            match keychain.find_generic_password(SERVICE, &account) {
                Err(error) if error.code() == ITEM_NOT_FOUND => Ok(()),
                _ => Err(refused(
                    "System Keychain did not confirm credential removal",
                )),
            }
        }
        Err(error) if error.code() == ITEM_NOT_FOUND => Ok(()),
        Err(_) => Err(refused(
            "System Keychain credential lookup refused; nothing removed",
        )),
    }
}

/// The child must have lost root and all privileged supplementary groups
/// before it reads even one byte from its supervised pipe.
pub fn verify_child(binding: &ServiceBinding) -> Result<()> {
    use nix::unistd::{getegid, getgroups};
    verify_no_core_dumps()?;
    let ServiceIdentity::Macos { uid, gid } = &binding.identity else {
        return Err(refused("service binding belongs to another platform"));
    };
    if *uid == 0 || *gid == 0 || geteuid().as_raw() != *uid || getegid().as_raw() != *gid {
        return Err(refused(
            "Guard child has not assumed its admitted service identity",
        ));
    }
    let groups = getgroups().map_err(|_| refused("cannot inspect child groups"))?;
    if groups.iter().any(|group| matches!(group.as_raw(), 0 | 80)) {
        return Err(refused(
            "Guard child retained a privileged supplementary group",
        ));
    }
    if fs::canonicalize(std::env::current_exe()?)? != binding.executable {
        return Err(refused(
            "Guard child executable differs from service admission",
        ));
    }
    binding.validate()?;
    Ok(())
}

/// A same-process broker owns the pipe for the whole child's lifetime.
/// launchd restarts this process; it never launches a detached Guard.
pub fn run(binding: &ServiceBinding, binding_path: &Path) -> Result<()> {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;
    use signal_hook::{
        consts::{SIGINT, SIGTERM},
        iterator::Signals,
    };
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    enforce_no_core_dumps()?;
    validate_binding_file(binding_path)?;
    prepare(binding)?;
    binding.validate_journal()?;
    let ServiceIdentity::Macos { uid, gid } = &binding.identity else {
        return Err(refused("service binding belongs to another platform"));
    };
    let mut signals = Signals::new([SIGTERM, SIGINT])?;
    let mut command = Command::new("/usr/bin/sudo");
    command
        .env_clear()
        .args([
            "-n",
            "-u",
            &format!("#{uid}"),
            "-g",
            &format!("#{gid}"),
            "--",
            "/usr/bin/env",
            "-i",
        ])
        .arg(format!("ZUNDER_MAINNET_CONFIRM={}", binding.account))
        .arg(&binding.executable)
        .arg("--home")
        .arg(&binding.home)
        .arg("--config")
        .arg(&binding.config)
        .args([
            "run",
            "--network",
            "mainnet",
            "--key-stdin",
            "--supervised-stdin",
            "--service-binding",
        ])
        .arg(binding_path)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command.spawn()?;
    let group = Pid::from_raw(
        i32::try_from(child.id()).map_err(|_| refused("service child PID out of range"))?,
    );
    let mut pipe = child.stdin.take();
    // Spawn is keyless. Any failure below closes the pipe before terminating
    // the process group; the child cannot obtain a partial usable credential.
    let delivery = (|| -> Result<()> {
        let key = read(binding)?;
        let input = pipe
            .as_mut()
            .ok_or_else(|| refused("service child pipe missing"))?;
        input.write_all(&key)?;
        input.write_all(b"\n")?;
        input.flush()?;
        drop(key);
        Ok(())
    })();
    if let Err(error) = delivery {
        drop(pipe.take());
        let _ = killpg(group, Signal::SIGKILL);
        let _ = child.wait();
        return Err(error);
    }
    let mut stopping: Option<Instant> = None;
    loop {
        let polled = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                drop(pipe.take());
                let _ = killpg(group, Signal::SIGKILL);
                let _ = child.wait();
                return Err(error.into());
            }
        };
        if let Some(status) = polled {
            drop(pipe.take());
            // Do not signal a process-group number after reaping its leader:
            // PID reuse could target an unrelated process. EOF closes Guard's
            // liveness channel; launchd owns final job-group cleanup.
            return if stopping.is_some() || status.success() {
                Ok(())
            } else {
                Err(refused("supervised Guard stopped unexpectedly"))
            };
        }
        if signals.pending().next().is_some() && stopping.is_none() {
            drop(pipe.take());
            stopping = Some(Instant::now());
        }
        if let Some(started) = stopping {
            if started.elapsed() >= Duration::from_secs(30) {
                let _ = killpg(group, Signal::SIGKILL);
                let _ = child.wait();
                return Err(refused("supervised Guard exceeded its shutdown deadline"));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Upgrade credentials entirely inside two admitted processes. The old
/// executable remains at its immutable path with its original creator ACL.
pub fn migrate(binding: &ServiceBinding, next_path: &Path, confirm: &str) -> Result<()> {
    use std::io::Write;
    enforce_no_core_dumps()?;
    prepare(binding)?;
    require_stopped(binding)?;
    validate_binding_file(next_path)?;
    let next: ServiceBinding = serde_json::from_slice(&fs::read(next_path)?)
        .map_err(|_| refused("invalid next service binding"))?;
    next.validate()?;
    trusted_root_path(&next.executable, true)?;
    if binding.version != next.version
        || binding.mode != next.mode
        || binding.credential_id != next.credential_id
        || binding.home != next.home
        || binding.config != next.config
        || binding.account != next.account
        || binding.api_wallet != next.api_wallet
        || binding.identity != next.identity
        || binding.admission_config_sha256 != next.admission_config_sha256
        || Address::from_hex(confirm) != Address::from_hex(&binding.account)
        || binding.executable_sha256 == next.executable_sha256
    {
        return Err(refused(
            "credential migration may change only the admitted executable release",
        ));
    }
    let mut child = Command::new(&next.executable)
        .env_clear()
        .args(["service", "provision", "--binding"])
        .arg(next_path)
        .args(["--confirm-mainnet", &binding.account, "--key-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    let transfer = (|| -> Result<()> {
        let key = read(binding)?;
        let mut pipe = child
            .stdin
            .take()
            .ok_or_else(|| refused("migration pipe missing"))?;
        pipe.write_all(&key)?;
        pipe.write_all(b"\n")?;
        drop(pipe);
        drop(key);
        Ok(())
    })();
    if let Err(error) = transfer {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let started = std::time::Instant::now();
    loop {
        let polled = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        };
        if let Some(status) = polled {
            if !status.success() {
                return Err(refused(
                    "new release credential admission failed; old item retained",
                ));
            }
            break;
        }
        if started.elapsed() >= std::time::Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(refused(
                "new release credential admission timed out; old item retained",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let checked = Command::new(&next.executable)
        .env_clear()
        .args(["service", "check", "--binding"])
        .arg(next_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()?;
    if !checked.success() {
        return Err(refused(
            "new release credential readback failed; old item retained",
        ));
    }
    Ok(())
}

/// Administrative readmission must still work after an intentional pairing
/// change. Validate protected identity/executable, not the old config fingerprint.
pub fn validate_management_stopped(binding: &ServiceBinding) -> Result<()> {
    enforce_no_core_dumps()?;
    if !geteuid().is_root() {
        return Err(refused("service management requires root"));
    }
    binding.validate_shape()?;
    if !matches!(binding.identity, ServiceIdentity::Macos { .. }) {
        return Err(refused("service binding belongs to another platform"));
    }
    trusted_root_path(&binding.executable, true)?;
    if fs::canonicalize(std::env::current_exe()?)? != binding.executable
        || super::hash_file(&binding.executable)? != binding.executable_sha256
    {
        return Err(refused(
            "service management executable differs from admission",
        ));
    }
    require_stopped(binding)
}

pub fn load_config(binding: &ServiceBinding) -> Result<crate::config::GuardConfig> {
    if fs::canonicalize(&binding.config)? != binding.config
        || fs::canonicalize(&binding.home)? != binding.home
        || binding.config.parent() != Some(binding.home.as_path())
    {
        return Err(refused(
            "service configuration must be in its canonical admitted home",
        ));
    }
    crate::config::GuardConfig::load(&binding.config)
        .map_err(|_| refused("invalid service configuration"))
}

/// Root-private same-directory staging: create_new is also the serialization
/// lock. Only metadata is written; credentials never pass through this path.
pub fn write_binding(path: &Path, binding: &ServiceBinding) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    validate_binding_file(path)?;
    validate_management_stopped(binding)?;
    binding.validate()?;
    let parent = path
        .parent()
        .ok_or_else(|| refused("binding has no parent"))?;
    let staged = path.with_extension("json.new");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&staged)?;
    let result = (|| -> Result<()> {
        let bytes =
            serde_json::to_vec_pretty(binding).map_err(|_| refused("cannot serialize binding"))?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        // Admission metadata is non-secret; the unprivileged child must be
        // able to read it even when the administrator uses umask 077.
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.sync_all()?;
        fs::rename(&staged, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

/// Native administrative helpers must not make the service's config root-owned
/// when applying a licence. Chown the already-open descriptor, never an attacker-
/// replaceable pathname in the service-writable directory.
pub fn write_config(
    binding: &ServiceBinding,
    expected: &crate::config::GuardConfig,
    config: &crate::config::GuardConfig,
) -> Result<()> {
    use nix::unistd::{Gid, Uid, fchown};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if !geteuid().is_root() {
        return Err(refused(
            "administrative service configuration writes require root",
        ));
    }
    binding.validate_shape()?;
    load_config(binding)?;
    config
        .check_mainnet()
        .map_err(|_| refused("updated configuration fails mainnet guards"))?;
    if config.account().ok() != Address::from_hex(&binding.account) {
        return Err(refused(
            "configuration change names another service account",
        ));
    }
    config
        .check_api_wallet(
            Address::from_hex(&binding.api_wallet)
                .ok_or_else(|| refused("invalid admitted API wallet"))?,
        )
        .map_err(|_| refused("configuration change names another API wallet"))?;
    if super::config_fingerprint(config)? != binding.admission_config_sha256 {
        validate_management_stopped(binding)?;
    }
    let ServiceIdentity::Macos { uid, gid } = &binding.identity else {
        return Err(refused("configuration belongs to another platform"));
    };
    let mut staging_name = binding.config.as_os_str().to_owned();
    staging_name.push(".new");
    let staged = std::path::PathBuf::from(staging_name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)?;
    let result = (|| -> Result<()> {
        // Guard's automatic renewal uses the same .new lock. Re-read after
        // acquiring it so an admin never overwrites a newer licence/token.
        if &load_config(binding)? != expected {
            return Err(refused(
                "configuration changed concurrently; reload and retry",
            ));
        }
        if fs::canonicalize(&config.state_dir)? != binding.home {
            return Err(refused(
                "configuration cannot move the admitted service state",
            ));
        }
        let text = Zeroizing::new(
            toml::to_string_pretty(config)
                .map_err(|_| refused("cannot serialize service configuration"))?,
        );
        file.write_all(text.as_bytes())?;
        fchown(&file, Some(Uid::from_raw(*uid)), Some(Gid::from_raw(*gid)))
            .map_err(|_| refused("cannot preserve service configuration ownership"))?;
        file.sync_all()?;
        fs::rename(&staged, &binding.config)?;
        fs::File::open(&binding.home)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;
    use security_framework::os::macos::keychain::CreateOptions;

    const FIXTURE_SERVICE: &str = "com.zunderlabs.guard.native-ci.synthetic";
    const FIXTURE_ACCOUNT: &str = "fixture-only-never-a-venue-account";
    const FIXTURE_PASSWORD: &[u8] = b"synthetic-keychain-fixture-not-a-wallet-key";

    /// A separate executable identity invokes just this test. It can only
    /// inspect this CI fixture namespace, never production Keychain entries.
    #[test]
    fn different_executable_cannot_read_fixture() {
        let Some(path) = std::env::var_os("ZUNDER_MACOS_SYNTHETIC_KEYCHAIN") else {
            return;
        };
        enforce_no_core_dumps().expect("disable fixture cores");
        let _interaction = SecKeychain::disable_user_interaction().expect("disable UI");
        let keychain = SecKeychain::open(path).expect("open fixture Keychain");
        assert!(
            keychain
                .find_generic_password(FIXTURE_SERVICE, FIXTURE_ACCOUNT)
                .is_err(),
            "a different code identity must not read a creator-only credential"
        );
    }

    /// Must run natively on macOS. This is an ACL feasibility gate, not a
    /// simulated Keychain and not evidence of pre-login System Keychain access.
    #[test]
    fn creator_acl_refuses_a_different_ad_hoc_code_identity() {
        enforce_no_core_dumps().expect("disable fixture cores");
        let directory = TestDir::new("macos-creator-acl");
        let path = directory.path().join("synthetic.keychain");
        let keychain = CreateOptions::new()
            .password("synthetic-ci-fixture-password-no-real-credential")
            .create(&path)
            .expect("create private fixture Keychain");
        keychain
            .add_generic_password(FIXTURE_SERVICE, FIXTURE_ACCOUNT, FIXTURE_PASSWORD)
            .expect("creator writes fixture");
        {
            let _interaction = SecKeychain::disable_user_interaction().expect("disable UI");
            let (password, _) = keychain
                .find_generic_password(FIXTURE_SERVICE, FIXTURE_ACCOUNT)
                .expect("creator reads fixture without UI");
            assert!(
                password.as_ref() == FIXTURE_PASSWORD,
                "fixture round trip mismatch"
            );
        }
        let probe = directory.path().join("different-code-identity");
        fs::copy(std::env::current_exe().expect("test executable"), &probe).expect("copy probe");
        let signed = Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--identifier",
                "com.zunderlabs.guard.synthetic-untrusted",
            ])
            .arg(&probe)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("ad hoc sign distinct probe");
        assert!(
            signed.success(),
            "could not create distinct executable identity"
        );
        let status = Command::new(&probe)
            .args([
                "--exact",
                "service::macos::tests::different_executable_cannot_read_fixture",
            ])
            .env("ZUNDER_MACOS_SYNTHETIC_KEYCHAIN", &path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run distinct identity probe");
        assert!(
            status.success(),
            "creator ACL did not reject a distinct executable identity"
        );
        let (password, item) = keychain
            .find_generic_password(FIXTURE_SERVICE, FIXTURE_ACCOUNT)
            .expect("creator retains access");
        drop(password);
        item.delete();
    }

    #[test]
    fn privileged_paths_refuse_user_writes_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = TestDir::new("macos-service-paths");
        let file = directory.path().join("binding.json");
        fs::write(&file, b"public fixture metadata").expect("write fixture");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666)).expect("fixture mode");
        assert!(validate_binding_file(&file).is_err());
        let link = directory.path().join("linked.json");
        symlink(&file, &link).expect("fixture symlink");
        assert!(validate_binding_file(&link).is_err());
        assert!(validate_binding_file(Path::new("relative.json")).is_err());
    }

    #[test]
    fn core_hard_and_soft_limits_are_zero_before_credentials() {
        enforce_no_core_dumps().expect("disable cores");
        assert_eq!(
            getrlimit(Resource::RLIMIT_CORE).expect("read limits"),
            (0, 0)
        );
        let output = Command::new("/bin/sh")
            .args([
                "-c",
                "test \"$(ulimit -Sc)\" = 0 && test \"$(ulimit -Hc)\" = 0",
            ])
            .stdin(Stdio::null())
            .output()
            .expect("check inherited child limits");
        assert!(
            output.status.success(),
            "child did not inherit both zero limits"
        );
    }

    #[test]
    fn synthetic_crash_probe() {
        if std::env::var_os("ZUNDER_MACOS_SYNTHETIC_CRASH").is_none() {
            return;
        }
        use std::io::Read;
        enforce_no_core_dumps().expect("disable crash fixture cores");
        let mut marker = Zeroizing::new(Vec::new());
        std::io::stdin()
            .take(256)
            .read_to_end(&mut marker)
            .expect("read synthetic marker");
        assert!(!marker.is_empty(), "synthetic marker was not supplied");
        // Intentionally abort while a synthetic marker is resident. Never a
        // venue key; the parent scans only this fixture's diagnostic artifacts.
        std::hint::black_box(&marker);
        std::process::abort();
    }

    #[test]
    fn broker_and_child_synthetic_crashes_leave_no_core_file() {
        use std::io::Write;
        use std::os::unix::process::ExitStatusExt;
        enforce_no_core_dumps().expect("disable fixture cores");
        let directory = TestDir::new("macos-core-crash");
        let core_setting = Command::new("/usr/sbin/sysctl")
            .args(["-n", "kern.corefile"])
            .output()
            .expect("read core path");
        assert!(
            core_setting.status.success(),
            "cannot inspect core dump target"
        );
        let pattern = String::from_utf8(core_setting.stdout).expect("core path encoding");
        let pattern = pattern.trim();
        assert!(
            pattern.starts_with('/') && pattern.replace("%P", "").find('%').is_none(),
            "unsupported core filename expansion; native gate needs explicit inspection"
        );
        for role in ["broker", "child"] {
            let mut process = Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", "service::macos::tests::synthetic_crash_probe"])
                .env("ZUNDER_MACOS_SYNTHETIC_CRASH", role)
                .current_dir(directory.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn synthetic crash");
            let core_path =
                std::path::PathBuf::from(pattern.replace("%P", &process.id().to_string()));
            assert!(
                !core_path.exists(),
                "core target already exists; isolated native fixture required"
            );
            let mut input = process.stdin.take().expect("fixture stdin");
            input
                .write_all(b"SYNTHETIC-CRASH-MARKER-NOT-A-WALLET-KEY")
                .expect("send marker");
            drop(input);
            let status = process.wait().expect("wait for fixture crash");
            assert!(status.signal().is_some(), "fixture did not crash");
            assert!(
                !core_path.exists(),
                "synthetic credential process wrote a core file"
            );
        }
        // Full broker→dedicated-user and DiagnosticReports artifact scanning
        // remain native service lifecycle gates; this test proves hard-limit
        // inheritance and each executable crash case, not system boot behavior.
    }
}
