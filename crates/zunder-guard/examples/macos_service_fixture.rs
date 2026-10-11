// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Native CI only. No HTTP, venue transport, Guard runtime or order code is called.
//! Not copied into release archives. Synthetic keys here are deliberately public.
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("macOS fixture only");
    std::process::exit(2);
}

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    use std::{
        fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };
    use zunder_guard::{
        config::{GuardConfig, GuardMode, GuardNetwork},
        service::{self, ServiceBinding, ServiceIdentity, macos},
    };
    use zunder_guard_core::{policy::Policy, sign::GuardKey};
    const KEY: &str = "0123456789012345678901234567890123456789012345678901234567890123";
    const ACCOUNT: &str = "0x1111111111111111111111111111111111111111";
    const PREFIX: &str = "/Library/Application Support/Zunder Guard Native CI/";
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |name: &str| -> anyhow::Result<String> {
        let index = args
            .iter()
            .position(|arg| arg == name)
            .context("fixture argument missing")?;
        args.get(index + 1)
            .cloned()
            .context("fixture argument value missing")
    };
    let scope = |path: &Path| -> anyhow::Result<()> {
        if !path.to_string_lossy().starts_with(PREFIX) || fs::canonicalize(path)? != path {
            bail!("fixture refuses a non-canonical or non-fixture path");
        }
        Ok(())
    };
    macos::enforce_no_core_dumps()?;
    if args.first().map(String::as_str) == Some("prepare-fixture") {
        if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
            || std::env::var("RUNNER_OS").as_deref() != Ok("macOS")
            || !nix::unistd::geteuid().is_root()
        {
            bail!("disposable hosted CI root only");
        }
        let home = PathBuf::from(value("--home")?);
        scope(&home)?;
        let config_path = home.join("guard.toml");
        if !config_path.exists() {
            let mut policy = Policy::mainnet_ceiling();
            policy.max_trading_equity_usd = Some(rust_decimal::Decimal::from(100));
            let mut config = GuardConfig {
                network: Some(GuardNetwork::Mainnet),
                mode: GuardMode::Mainnet,
                account: Some(ACCOUNT.into()),
                api_wallet: Some(GuardKey::from_hex(KEY)?.address().to_hex()),
                allow_mainnet: true,
                state_dir: home.clone(),
                policy,
                ..GuardConfig::default()
            };
            config
                .auth
                .clients
                .push(GuardKey::from_hex(KEY)?.address().to_hex());
            fs::write(&config_path, toml::to_string_pretty(&config)?)?;
            fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
            // Pure local journal initialization with hand-picked synthetic equity.
            zunder_venue::PersistentRisk::initialise_for(
                &config.risk_journal(false),
                config.policy.risk_limits(),
                &config.journal_scope(false)?,
                zunder_core::Timestamp::from_millis(1),
                rust_decimal::Decimal::from(100),
                "native CI synthetic fixture; no venue account",
            )?;
        }
        let config = GuardConfig::load(&config_path)?;
        let executable = fs::canonicalize(std::env::current_exe()?)?;
        let binding = ServiceBinding {
            version: 1,
            credential_id: value("--id")?,
            mode: "mainnet".into(),
            account: ACCOUNT.into(),
            api_wallet: config.api_wallet.clone().context("fixture wallet")?,
            home,
            config: config_path,
            executable_sha256: service::hash_file(&executable)?,
            executable,
            admission_config_sha256: service::config_fingerprint(&config)?,
            identity: ServiceIdentity::Macos {
                uid: value("--uid")?.parse()?,
                gid: value("--gid")?.parse()?,
            },
        };
        binding.validate()?;
        println!("{}", serde_json::to_string_pretty(&binding)?);
        return Ok(());
    }
    let path = PathBuf::from(value("--service-binding").or_else(|_| value("--binding"))?);
    let binding = service::load_binding(&path)?;
    scope(&binding.home)?;
    if binding.account != ACCOUNT
        || binding.api_wallet != GuardKey::from_hex(KEY)?.address().to_hex()
        || !binding.credential_id.starts_with("ci-")
    {
        bail!("fixture admission refused");
    }
    if let Some(operation @ ("acl-write" | "acl-denied" | "acl-clean")) =
        args.get(1).map(String::as_str)
    {
        use security_framework::os::macos::keychain::SecKeychain;
        if !nix::unistd::geteuid().is_root() {
            bail!("root fixture only");
        }
        let _interaction = SecKeychain::disable_user_interaction()?;
        let keychain = SecKeychain::open("/Library/Keychains/System.keychain")?;
        let service = "com.zunderlabs.guard.native-ci-only";
        let account = &binding.credential_id;
        match operation {
            "acl-write" => {
                keychain.add_generic_password(service, account, b"public-synthetic-ci-marker")?;
                let (bytes, _) = keychain.find_generic_password(service, account)?;
                if bytes.as_ref() != b"public-synthetic-ci-marker" {
                    bail!("fixture roundtrip failed");
                }
            }
            "acl-denied" => {
                if keychain.find_generic_password(service, account).is_ok() {
                    bail!("foreign code identity read creator item");
                }
            }
            "acl-clean" => {
                let (bytes, item) = keychain.find_generic_password(service, account)?;
                drop(bytes);
                item.delete();
                if keychain.find_generic_password(service, account).is_ok() {
                    bail!("fixture cleanup failed");
                }
            }
            _ => bail!("unsupported fixture ACL command"),
        }
        return Ok(());
    }
    if args.iter().any(|arg| arg == "--supervised-stdin") {
        macos::verify_child(&binding)?;
        let mut stdin = std::io::stdin().lock();
        let key = service::read_key_frame(&mut stdin)?;
        binding.check_key(&key)?;
        if key.as_slice() != KEY.as_bytes() {
            bail!("non-synthetic fixture key refused");
        }
        // This public synthetic fixture key deliberately remains resident until
        // EOF. Native CI sends SIGABRT after "started" to inspect reports from
        // a key-resident child; production key lifetimes are unchanged.
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(binding.home.join("lifecycle.log"))?;
        writeln!(log, "started {}", std::process::id())?;
        log.sync_all()?;
        let _ = service::await_parent_close(&mut stdin);
        std::hint::black_box(&key);
        drop(key);
        writeln!(log, "stopped {}", std::process::id())?;
        log.sync_all()?;
        return Ok(());
    }
    // Root operations still use the production metadata/path/core/Keychain guards.
    match args.get(1).map(String::as_str) {
        Some("provision") => {
            let key = if args.iter().any(|a| a == "--key-stdin") {
                service::read_key_frame(&mut std::io::stdin().lock())?
            } else {
                zeroize::Zeroizing::new(KEY.as_bytes().to_vec())
            };
            if key.as_slice() != KEY.as_bytes() {
                bail!("non-synthetic fixture key refused");
            }
            macos::provision(&binding, &key, false)?;
        }
        Some("check") => macos::check(&binding)?,
        Some("run") => macos::run(&binding, &path)?,
        Some("remove-credential") => macos::remove(&binding)?,
        Some("migrate-credential") => {
            macos::migrate(&binding, Path::new(&value("--next-binding")?), ACCOUNT)?
        }
        _ => bail!("unsupported fixture command"),
    }
    Ok(())
}
