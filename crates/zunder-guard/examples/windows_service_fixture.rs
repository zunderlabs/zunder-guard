// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Native CI-only SCM probe. Never starts Guard, opens HTTP or contacts a venue.
//! This example is not packaged in release archives; its key/account are public fixtures.
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows fixture only");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    use std::{fs, io::Write, path::PathBuf};
    use zunder_guard::{
        config::{GuardConfig, GuardMode, GuardNetwork},
        service::{self, ServiceBinding, ServiceIdentity, windows},
    };
    use zunder_guard_core::{policy::Policy, sign::GuardKey};
    const KEY: &str = "0123456789012345678901234567890123456789012345678901234567890123";
    const ACCOUNT: &str = "0x1111111111111111111111111111111111111111";
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
    windows::enforce_no_core_dumps()?;
    if args.first().map(String::as_str) == Some("prepare-fixture") {
        if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
            || std::env::var("RUNNER_OS").as_deref() != Ok("Windows")
        {
            bail!("disposable hosted CI only");
        }
        let id = value("--id")?;
        if !id.starts_with("ci-") {
            bail!("synthetic fixture ID required");
        }
        let home = fs::canonicalize(value("--home")?)?;
        let config_path = home.join("guard.toml");
        windows::validate_setup(&home, &config_path, &id)?;
        if config_path.exists() {
            bail!("fixture config already exists");
        }
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
        // Hand-picked synthetic equity; no venue call and never a real account journal.
        zunder_venue::PersistentRisk::initialise_for(
            &config.risk_journal(false),
            config.policy.risk_limits(),
            &config.journal_scope(false)?,
            zunder_core::Timestamp::from_millis(1),
            rust_decimal::Decimal::from(100),
            "native CI only; no venue account",
        )?;
        let executable = fs::canonicalize(std::env::current_exe()?)?;
        let binding = ServiceBinding {
            version: 1,
            credential_id: id,
            mode: "mainnet".into(),
            account: ACCOUNT.into(),
            api_wallet: config.api_wallet.clone().context("fixture wallet")?,
            home,
            config: config_path,
            executable_sha256: service::hash_file(&executable)?,
            executable,
            admission_config_sha256: service::config_fingerprint(&config)?,
            identity: ServiceIdentity::Windows {
                service_name: value("--service-name")?,
                service_sid: value("--service-sid")?,
            },
        };
        println!("{}", serde_json::to_string_pretty(&binding)?);
        return Ok(());
    }
    let path = fs::canonicalize(PathBuf::from(
        value("--service-binding").or_else(|_| value("--binding"))?,
    ))?;
    let binding = service::load_binding(&path)?;
    if !binding.credential_id.starts_with("ci-")
        || binding.account != ACCOUNT
        || binding.api_wallet != GuardKey::from_hex(KEY)?.address().to_hex()
    {
        bail!("synthetic fixture admission refused");
    }
    if args.iter().any(|arg| arg == "--supervised-stdin") {
        service::verify_child(&binding)?;
        let mut input = std::io::stdin().lock();
        let key = service::read_key_frame(&mut input)?;
        if key.as_slice() != KEY.as_bytes() {
            bail!("non-synthetic fixture key refused");
        }
        let transient = binding.home.join("fixture-transient-count");
        if transient.exists() {
            let count: u32 = fs::read_to_string(&transient)?.trim().parse()?;
            if count > 0 {
                fs::write(transient, (count - 1).to_string())?;
                std::process::exit(75);
            }
        }
        if binding.home.join("fixture-crash").exists() {
            std::hint::black_box(&key);
            std::process::abort();
        }
        drop(key);
        if binding.home.join("fixture-renew").exists() {
            GuardConfig::update(&binding.config, |config| {
                config.licence = Some("synthetic-renewed-fixture".into())
            })?;
        }
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(binding.home.join("lifecycle.log"))?;
        writeln!(log, "started {}", std::process::id())?;
        log.sync_all()?;
        if binding.home.join("fixture-stop-transient").exists() {
            // Native driver first gets an acknowledged SCM Stop, then releases
            // this independent transient exit. No Guard or venue code runs.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
            while !binding.home.join("fixture-exit-now").exists() {
                if std::time::Instant::now() >= deadline {
                    bail!("synthetic stop race deadline");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            writeln!(log, "transient-after-stop {}", std::process::id())?;
            log.sync_all()?;
            std::process::exit(75);
        }
        let _ = service::await_parent_close(&mut input);
        writeln!(log, "stopped {}", std::process::id())?;
        log.sync_all()?;
        return Ok(());
    }
    match args
        .iter()
        .position(|arg| arg == "service")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
    {
        Some("provision") => {
            service::validate_provision(&binding)?;
            windows::provision(
                &binding,
                &zeroize::Zeroizing::new(KEY.as_bytes().to_vec()),
                false,
            )?;
        }
        Some("run") => windows::run(&binding, &path)?,
        Some("check") => windows::check(&binding)?,
        Some("renew-fixture") => {
            windows::verify_service_identity(&binding)?;
            GuardConfig::update(&binding.config, |config| {
                config.licence = Some("synthetic-renewed-fixture".into())
            })?;
        }
        Some("remove-credential") => windows::remove(&binding)?,
        _ => bail!("unsupported synthetic fixture operation"),
    }
    Ok(())
}
