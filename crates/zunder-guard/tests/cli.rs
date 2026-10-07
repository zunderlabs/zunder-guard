// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The binary's guards, in order, without a network: each refusal happens
//! before the key on standard input is read or anything is sent.

#![allow(clippy::unwrap_used)]

use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

use zunder_guard::testdir::TestDir;

const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
const WALLET: &str = "0x14791697260e4c9a71f18484c9f997b308e59325";
/// The SDK tests' throwaway key, piped in to show it is never read.
const KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";

fn testnet_config() -> String {
    format!(
        "network = \"testnet\"\nmode = \"testnet\"\naccount = \"{ACCOUNT}\"\napi_wallet = \"{WALLET}\"\n[auth]\nclients = [\"{WALLET}\"]\n"
    )
}

fn paper_config() -> String {
    testnet_config().replace("mode = \"testnet\"\n", "")
}

fn mainnet_config() -> String {
    format!(
        "network = \"mainnet\"\nmode = \"mainnet\"\nallow_mainnet = true\naccount = \"{ACCOUNT}\"\napi_wallet = \"{WALLET}\"\n[auth]\nclients = [\"{WALLET}\"]\n[policy]\nmax_trading_equity_usd = \"2000\"\n"
    )
}

fn guard(dir: &Path, config: &str, args: &[&str], confirm: Option<&str>) -> Output {
    let path = dir.join("guard.toml");
    std::fs::write(&path, config).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_zunder-guard"));
    command
        .args(args)
        .arg("--config")
        .arg(&path)
        .env_remove("ZUNDER_MAINNET_CONFIRM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(confirm) = confirm {
        command.env("ZUNDER_MAINNET_CONFIRM", confirm);
    }
    let mut child = command.spawn().unwrap();
    // A key on standard input: none of these starts may read it.
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{KEY}\n").as_bytes())
        .ok();
    child.wait_with_output().unwrap()
}

fn refused_with(output: &Output, text: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Every refusal exits with 2, the packaging's "do not restart" code.
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains(text), "expected `{text}` in: {stderr}");
    assert!(!stderr.contains(&KEY[2..]), "{stderr}");
}

#[test]
fn the_networks_do_not_mix() {
    let dir = TestDir::new("cli-networks");
    let output = guard(
        dir.path(),
        &testnet_config(),
        &["run", "--network", "mainnet", "--key-stdin"],
        Some(ACCOUNT),
    );
    // Windows refuses mainnet before it looks at the config's network.
    refused_with(
        &output,
        if cfg!(windows) {
            "not offered on Windows"
        } else {
            "the config is for testnet"
        },
    );
    let output = guard(
        dir.path(),
        &mainnet_config(),
        &["run", "--network", "testnet", "--key-stdin"],
        None,
    );
    refused_with(&output, "the config is for mainnet");
}

#[cfg(not(windows))]
#[test]
fn mainnet_needs_the_confirmation_then_the_journal_before_the_key() {
    let dir = TestDir::new("cli-mainnet");
    let output = guard(
        dir.path(),
        &mainnet_config(),
        &["run", "--network", "mainnet", "--key-stdin"],
        None,
    );
    refused_with(&output, "ZUNDER_MAINNET_CONFIRM");
    // Naming another account is no confirmation.
    let output = guard(
        dir.path(),
        &mainnet_config(),
        &["run", "--network", "mainnet", "--key-stdin"],
        Some(WALLET),
    );
    refused_with(&output, "ZUNDER_MAINNET_CONFIRM");
    // Confirmed, but no journal started for mainnet: refused before the key.
    let output = guard(
        dir.path(),
        &mainnet_config(),
        &["run", "--network", "mainnet", "--key-stdin"],
        Some(ACCOUNT),
    );
    refused_with(&output, "no risk journal");
    // A looser policy is refused on mainnet whatever else is in place.
    let loose = format!("{}max_leverage = \"10\"\n", mainnet_config());
    let output = guard(
        dir.path(),
        &loose,
        &["run", "--network", "mainnet", "--key-stdin"],
        Some(ACCOUNT),
    );
    refused_with(&output, "looser than the mainnet ceiling");
}

/// Windows (1.0): mainnet is refused by `run`, whatever is in place
/// (confirmation, journal), before the key is read; and by `init`, before
/// anything is written.
#[cfg(windows)]
#[test]
fn windows_refuses_mainnet_in_run_and_init() {
    let dir = TestDir::new("cli-windows-mainnet");
    for confirm in [None, Some(ACCOUNT)] {
        let output = guard(
            dir.path(),
            &mainnet_config(),
            &["run", "--network", "mainnet", "--key-stdin"],
            confirm,
        );
        refused_with(&output, "not offered on Windows");
    }
    let config = dir.path().join("fresh").join("guard.toml");
    let mut child = Command::new(env!("CARGO_BIN_EXE_zunder-guard"))
        .args([
            "init",
            "--non-interactive",
            "--rules",
            "zr1_eyJ2IjoxfQ",
            "--network",
            "mainnet",
            "--account",
            ACCOUNT,
            "--confirm-mainnet",
            ACCOUNT,
            "--equity-cap",
            "2000",
            "--key-stdin",
            "--config",
        ])
        .arg(&config)
        .env_remove("ZUNDER_MAINNET_CONFIRM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{KEY}\n").as_bytes())
        .ok();
    let output = child.wait_with_output().unwrap();
    refused_with(&output, "not offered on Windows");
    assert!(!config.exists(), "init wrote a config");
}

#[test]
fn paper_reads_no_key_and_sending_needs_a_journal_first() {
    let dir = TestDir::new("cli-paper");
    let output = guard(dir.path(), &paper_config(), &["run", "--key-stdin"], None);
    refused_with(&output, "paper mode reads no key");
    // A testnet config does not quietly run as paper either.
    let output = guard(dir.path(), &testnet_config(), &["run"], None);
    refused_with(&output, "pass --network testnet");
    let output = guard(
        dir.path(),
        &testnet_config(),
        &["run", "--network", "testnet", "--key-stdin"],
        None,
    );
    refused_with(&output, "no risk journal");
    let output = guard(
        dir.path(),
        &testnet_config(),
        &["run", "--network", "testnet"],
        None,
    );
    refused_with(&output, "the API wallet key");
}

#[test]
fn kill_writes_next_to_the_config_wherever_it_runs() {
    let dir = TestDir::new("cli-kill");
    let elsewhere = TestDir::new("cli-kill-cwd");
    let path = dir.path().join("guard.toml");
    std::fs::write(&path, testnet_config()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zunder-guard"))
        .args(["kill", "--reason", "drill", "--config"])
        .arg(&path)
        .current_dir(elsewhere.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let kill = dir.path().join("guard-state").join("kill");
    assert_eq!(std::fs::read_to_string(kill).unwrap(), "drill\n");
    assert!(!elsewhere.path().join("guard-state").exists());
}

#[test]
fn a_refusal_does_not_wait_for_standard_input() {
    // Standard input held open and never written: the refusals come before
    // any read, so the process exits on its own.
    let dir = TestDir::new("cli-stdin-open");
    let path = dir.path().join("guard.toml");
    std::fs::write(&path, testnet_config()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_zunder-guard"))
        .args(["run", "--network", "testnet", "--key-stdin", "--config"])
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            child.kill().ok();
            panic!("still waiting for standard input");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    drop(stdin);
    assert_eq!(status.code(), Some(2));
}

#[test]
fn a_journal_from_another_scope_is_refused_before_the_key() {
    use rust_decimal::dec;
    use zunder_core::Timestamp;
    use zunder_guard::config::GuardConfig;
    use zunder_venue::PersistentRisk;
    let dir = TestDir::new("cli-scope");
    let path = dir.path().join("guard.toml");
    std::fs::write(&path, testnet_config()).unwrap();
    let config = GuardConfig::load(&path).unwrap();
    // The testnet journal's place, started with the paper scope.
    std::fs::create_dir_all(&config.state_dir).unwrap();
    PersistentRisk::initialise_for(
        &config.risk_journal(false),
        config.policy.risk_limits(),
        &config.journal_scope(true).unwrap(),
        Timestamp::from_millis(1_791_000_000_000),
        dec!(1000),
        "scope test",
    )
    .unwrap();
    let output = guard(
        dir.path(),
        &testnet_config(),
        &["run", "--network", "testnet", "--key-stdin"],
        None,
    );
    refused_with(&output, "never moves to another network or account");
}

#[test]
fn kill_works_with_a_broken_config_and_warns_without_a_guard() {
    let dir = TestDir::new("cli-kill-broken");
    let path = dir.path().join("guard.toml");
    // Valid TOML, invalid config (an unknown key), its own state directory
    // and a port nothing listens on.
    std::fs::write(
        &path,
        format!(
            "{}state_dir = \"elsewhere\"\nlisten = \"127.0.0.1:9\"\nunknown = 1\n",
            testnet_config().split("[auth]").next().unwrap()
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zunder-guard"))
        .args(["kill", "--reason", "drill", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("does not validate"), "{stderr}");
    assert!(stderr.contains("no Guard answers"), "{stderr}");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("elsewhere").join("kill")).unwrap(),
        "drill\n"
    );
}

#[test]
fn client_add_writes_an_owner_only_key_file_and_the_config() {
    let dir = TestDir::new("cli-client-add");
    let path = dir.path().join("guard.toml");
    std::fs::write(&path, paper_config()).unwrap();
    let out = dir.path().join("agent.key");
    let output = Command::new(env!("CARGO_BIN_EXE_zunder-guard"))
        .args(["client", "add", "--out"])
        .arg(&out)
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let key = std::fs::read_to_string(&out).unwrap();
    let key = key.trim();
    assert_eq!(key.len(), 66);
    // Never shown.
    assert!(!stdout.contains(&key[2..]), "{stdout}");
    // Mode 0600 on Unix; on Windows an ACL with this user alone.
    assert_eq!(zunder_venue::owner_only::check(&out).unwrap(), None);
    let config = std::fs::read_to_string(&path).unwrap();
    let address = zunder_guard_core::sign::GuardKey::from_hex(key)
        .unwrap()
        .address()
        .to_hex();
    assert!(config.contains(&address), "{config}");
    // An existing file is never replaced.
    let again = Command::new(env!("CARGO_BIN_EXE_zunder-guard"))
        .args(["client", "add", "--out"])
        .arg(&out)
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(again.status.code(), Some(2));
    assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), key);
}

/// `zunder-guard` with `args` against the config at `path`.
fn run_with(path: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zunder-guard"))
        .args(args)
        .arg("--config")
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn client_list_and_revoke_keep_one_client_at_least() {
    const OTHER: &str = "0x00000000000000000000000000000000000000aa";
    let dir = TestDir::new("cli-client-revoke");
    let path = dir.path().join("guard.toml");
    // Nothing listens on port 1: no running Guard to compare with.
    let config = format!(
        "listen = \"127.0.0.1:1\"\n{}",
        paper_config().replace(
            &format!("clients = [\"{WALLET}\"]"),
            &format!("clients = [\"{WALLET}\", \"{OTHER}\"]")
        )
    );
    std::fs::write(&path, config).unwrap();
    let listed = run_with(&path, &["client", "list"]);
    assert!(listed.status.success());
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(
        stdout.contains(WALLET) && stdout.contains(OTHER),
        "{stdout}"
    );
    assert!(String::from_utf8_lossy(&listed.stderr).contains("no Guard answers"));
    // Not an address, not a client: refused, the config unchanged.
    refused_with(
        &run_with(&path, &["client", "revoke", "0x12"]),
        "not an address",
    );
    refused_with(
        &run_with(
            &path,
            &[
                "client",
                "revoke",
                "0x00000000000000000000000000000000000000cc",
            ],
        ),
        "not a client",
    );
    // Revoked (in any case of hex digits), and gone from the config.
    let revoked = run_with(
        &path,
        &[
            "client",
            "revoke",
            "0x00000000000000000000000000000000000000AA",
        ],
    );
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let config = std::fs::read_to_string(&path).unwrap();
    assert!(
        !config.contains(OTHER) && config.contains(WALLET),
        "{config}"
    );
    // The last client stays: Guard needs one.
    refused_with(
        &run_with(&path, &["client", "revoke", WALLET]),
        "the last client",
    );
    assert!(std::fs::read_to_string(&path).unwrap().contains(WALLET));
}

#[test]
fn status_without_a_running_guard_is_refused() {
    let dir = TestDir::new("cli-status");
    let path = dir.path().join("guard.toml");
    std::fs::write(
        &path,
        format!("listen = \"127.0.0.1:1\"\n{}", paper_config()),
    )
    .unwrap();
    refused_with(
        &run_with(&path, &["status"]),
        "no Guard answers on 127.0.0.1:1",
    );
    refused_with(
        &run_with(&path, &["status", "--url", "http://127.0.0.1:1", "--json"]),
        "no Guard answers",
    );
}

#[test]
fn journal_resume_refuses_durable_pending_flows_before_equity_http() {
    use rust_decimal::dec;
    use zunder_core::Timestamp;
    use zunder_guard::config::GuardConfig;
    use zunder_risk::{RiskState, VenueView};
    use zunder_venue::{
        PersistentRisk,
        flows::{Flow, ValueRange},
    };

    let dir = TestDir::new("cli-review-pending");
    let path = dir.path().join("guard.toml");
    std::fs::write(&path, testnet_config()).unwrap();
    let config = GuardConfig::load(&path).unwrap();
    std::fs::create_dir_all(&config.state_dir).unwrap();
    let journal = config.risk_journal(false);
    let mut risk = PersistentRisk::initialise_for(
        &journal,
        config.policy.risk_limits(),
        &config.journal_scope(false).unwrap(),
        Timestamp::from_millis(0),
        dec!(10000),
        "pending review test",
    )
    .unwrap()
    .with_flows();
    // Exact30% loss proves Stop before500 deposit; unknown7500 withdrawal
    // empties the account and leaves its immutable origin pending.
    for flow in [
        Flow {
            time_ms: 3_600_000,
            amount: dec!(500),
            id: "prefix".into(),
            dex: String::new(),
            between: false,
            value: Some(ValueRange::cash_exact(dec!(7000))),
        },
        Flow {
            time_ms: 7_200_000,
            amount: dec!(-7500),
            id: "empty".into(),
            dex: String::new(),
            between: false,
            value: None,
        },
    ] {
        risk.apply_flow(Timestamp::from_millis(7_200_000), &flow)
            .unwrap();
    }
    let out = risk.observe_view_at(
        Timestamp::from_millis(10_800_000),
        [(String::new(), 10_800_000)].into(),
        dec!(0),
        &VenueView::default(),
        true,
    );
    assert!(out.journal_error.is_none());
    assert!(matches!(risk.state(), RiskState::Stopped { .. }));
    let snapshot = risk.engine().snapshot();
    drop(risk);
    let bytes = std::fs::read(&journal).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_zunder-guard"))
        .args([
            "journal-resume",
            "--mode",
            "testnet",
            "--note",
            "human review",
            "--config",
        ])
        .arg(&path)
        // A regression cannot contact the venue: a local closed proxy fails
        // any accidentally attempted equity HTTP, with a different error.
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            child.kill().ok();
            panic!("pending review did not refuse before equity HTTP");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    refused_with(
        &child.wait_with_output().unwrap(),
        "known account flows are still pending",
    );
    assert_eq!(std::fs::read(&journal).unwrap(), bytes);
    let restored = PersistentRisk::open_for(
        &journal,
        &config.policy.risk_limits(),
        &config.journal_scope(false).unwrap(),
    )
    .unwrap();
    assert_eq!(restored.engine().snapshot(), snapshot);
    assert!(restored.check_review_ready().is_err());
}
