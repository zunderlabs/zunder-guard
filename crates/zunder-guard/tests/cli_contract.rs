// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The command line for automation (`docs/guard.md`, "Automation"):
//! every command and field harnesses
//! and installers rely on, pinned against the built binary in paper mode,
//! in temporary directories, without a network. A change here is a change
//! to the contract: the release harness keeps a copy of these shapes.
//!
//! `status --json` and `health` ask an in-process paper Guard over HTTP
//! (an in-memory venue), the way they ask a running one.

#![allow(clippy::unwrap_used)]

mod support;

use std::{
    net::TcpListener,
    path::Path,
    process::{Command, Output, Stdio},
    sync::Arc,
};

use rust_decimal::dec;
use serde_json::{Value, json};
use support::MemoryVenue;
use zunder_core::Timestamp;
use zunder_guard::{
    config::{GuardConfig, GuardMode, GuardNetwork},
    guard::{Clock, Guard, Limits, Mode, Setup, SystemClock},
    journal::DecisionJournal,
    server,
    testdir::TestDir,
};
use zunder_guard_core::{
    auth::AuthConfig,
    licence::{FeeMode, Terms, issue, test_key},
    sign::Address,
};
use zunder_venue::PersistentRisk;

const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
const CLIENT: &str = "0x14791697260e4c9a71f18484c9f997b308e59325";
/// The smallest rules code: version 1, every rule at its default.
const RULES: &str = "zr1_eyJ2IjoxfQ";

/// The binary with `args`, none of the environment variables that would
/// answer for a flag.
fn guard(args: &[&str]) -> Output {
    binary().args(args).output().unwrap()
}

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zunder-guard"));
    for var in [
        "ZUNDER_GUARD_HOME",
        "ZUNDER_GUARD_NETWORK",
        "ZUNDER_GUARD_RULES",
        "ZUNDER_GUARD_ACCOUNT",
        "ZUNDER_GUARD_LISTEN",
        "ZUNDER_GUARD_LICENCE",
        "ZUNDER_GUARD_KEY_FILE",
        "ZUNDER_GUARD_IP_SHARE",
        "ZUNDER_MAINNET_CONFIRM",
    ] {
        command.env_remove(var);
    }
    command
}

/// The binary with `args` and `input` on its standard input.
fn guard_with_stdin(args: &[&str], input: &[u8]) -> Output {
    use std::io::Write;
    let mut child = binary()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // A refusal may come before everything is read (the input too long):
    // a closed pipe is no failure here.
    stdin.write_all(input).ok();
    drop(stdin);
    child.wait_with_output().unwrap()
}

fn home_args<'a>(home: &'a Path, args: &[&'a str]) -> Vec<&'a str> {
    let mut all = vec!["--home", home.to_str().unwrap()];
    all.extend_from_slice(args);
    all
}

/// Standard output as exactly one JSON document.
fn json_out(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "exit {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "not one JSON document ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

/// The licence object of C3, field by field.
fn assert_licence_object(licence: &Value) {
    let state = licence["state"].as_str().unwrap();
    assert!(
        ["valid", "expired", "invalid", "none"].contains(&state),
        "{licence}"
    );
    assert!(
        ["file", "auto_update"].contains(&licence["source"].as_str().unwrap()),
        "{licence}"
    );
    assert!(licence["fee_free"].is_boolean(), "{licence}");
    assert!(
        licence["licensee"].is_string() || licence["licensee"].is_null(),
        "{licence}"
    );
    assert!(
        licence["expires_at_ms"].is_i64() || licence["expires_at_ms"].is_null(),
        "{licence}"
    );
}

/// A licence key for `ACCOUNT` signed with the public test key: valid only
/// where the test key is trusted (never in the binary, whose built-in
/// issuer keys are Orcastrate's).
fn test_licence(expires_at_ms: i64) -> String {
    issue(
        &Terms {
            licensee: "Contract Test".into(),
            expires_at_ms,
            features: vec!["fee_free".into()],
            accounts: vec![ACCOUNT.into()],
            builder: None,
        },
        &test_key::SEED,
    )
    .unwrap()
}

fn now_ms() -> i64 {
    SystemClock.now_ms() as i64
}

/// A loopback address nothing listens on.
fn closed_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr.to_string()
}

#[test]
fn version_is_one_line() {
    let output = guard(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("zunder-guard {}\n", env!("CARGO_PKG_VERSION"))
    );
}

/// Every command and flag of C3 exists (its `--help` answers, naming the
/// flags), including each `service` subcommand `docs/guard.md` lists.
#[test]
fn every_contract_command_and_flag_exists() {
    let cases: &[(&[&str], &[&str])] = &[
        (
            &["init"],
            &[
                "--non-interactive",
                "--network",
                "--rules",
                "--account",
                "--no-key",
                "--licence",
            ],
        ),
        (&["pair"], &["--json"]),
        (&["run"], &["--network", "--key-stdin"]),
        (&["health"], &["--url"]),
        (&["status"], &["--json", "--url"]),
        (&["licence", "set"], &["--stdin"]),
        (&["licence", "show"], &["--json"]),
        (&["mcp"], &[]),
        (&["service", "prepare"], &["--credential-id"]),
        (&["service", "provision"], &["--binding", "--key-stdin"]),
        (&["service", "check"], &["--binding", "--json"]),
        (&["service", "run"], &["--binding"]),
        (&["service", "migrate-credential"], &["--binding"]),
        (&["service", "readmit"], &["--binding"]),
        (&["service", "licence-set"], &["--binding", "--key"]),
        (&["service", "licence-show"], &["--binding", "--json"]),
        (&["service", "pair"], &["--binding"]),
        (&["service", "remove-credential"], &["--binding"]),
    ];
    for (command, flags) in cases {
        let mut args = command.to_vec();
        args.push("--help");
        let output = guard(&args);
        let help = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{command:?}: {help}");
        for flag in *flags {
            assert!(help.contains(flag), "{command:?} lacks {flag}: {help}");
        }
    }
}

/// `init --non-interactive` writes the config (exit 0), or refuses with
/// exit 2 and the reason on standard error, writing nothing. Paper reads
/// the account's equity for a new risk journal; one started beforehand is
/// kept, so no network is needed here.
#[test]
fn init_pair_and_licence_show() {
    let dir = TestDir::new("cli-contract-init");
    let home = dir.path().join("home");

    // A refusal: a rules code that is none.
    let refused = guard(&home_args(
        &home,
        &[
            "init",
            "--non-interactive",
            "--network",
            "paper",
            "--rules",
            "zr1_not-a-code",
            "--account",
            ACCOUNT,
            "--no-key",
        ],
    ));
    assert_eq!(refused.status.code(), Some(2));
    assert!(!refused.stderr.is_empty());
    assert!(!home.join("guard.toml").exists());

    // The paper risk journal, as `init` would start it (paper reads a
    // mainnet account by default).
    let scope = GuardConfig {
        network: Some(GuardNetwork::Mainnet),
        account: Some(ACCOUNT.into()),
        ..GuardConfig::default()
    };
    std::fs::create_dir_all(&home).unwrap();
    PersistentRisk::initialise_for(
        &home.join("risk-paper.jsonl"),
        scope.policy.risk_limits(),
        &scope.journal_scope(true).unwrap(),
        Timestamp::from_millis(now_ms()),
        dec!(10000),
        "contract test",
    )
    .unwrap();
    let output = guard(&home_args(
        &home,
        &[
            "init",
            "--non-interactive",
            "--network",
            "paper",
            "--rules",
            RULES,
            "--account",
            ACCOUNT,
            "--no-key",
        ],
    ));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The journal started above was kept: nothing was read from the venue.
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("is kept"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let config_path = home.join("guard.toml");
    let config = GuardConfig::load(&config_path).unwrap();
    assert_eq!(config.mode, GuardMode::Paper);
    assert_eq!(config.account().unwrap().to_hex(), ACCOUNT);
    let clients_before = config.auth.clients.len();

    // `pair --json`: exactly the two fields, the key for the address, the
    // address in the config.
    let paired = json_out(&guard(&home_args(&home, &["pair", "--json"])));
    assert_eq!(keys(&paired), ["client_address", "client_key"]);
    let address = paired["client_address"].as_str().unwrap();
    let client_key = paired["client_key"].as_str().unwrap();
    assert!(
        address.starts_with("0x") && address.len() == 42,
        "{address}"
    );
    assert!(
        client_key.starts_with("0x") && client_key.len() == 66,
        "the key's shape"
    );
    assert_eq!(
        zunder_guard_core::sign::GuardKey::from_hex(client_key)
            .unwrap()
            .address(),
        Address::from_hex(address).unwrap()
    );
    let config = GuardConfig::load(&config_path).unwrap();
    assert_eq!(config.auth.clients.len(), clients_before + 1);
    assert!(config.auth.clients.iter().any(|client| client == address));

    // `licence show --json`: the licence object and nothing else.
    let none = json_out(&guard(&home_args(&home, &["licence", "show", "--json"])));
    assert_eq!(
        none,
        json!({"state": "none", "licensee": null, "expires_at_ms": null,
            "fee_free": false, "source": "file"})
    );
    // A key this binary's issuers did not sign: refused by `licence set`
    // (exit 2, config unchanged) ...
    let key = test_licence(now_ms() + 30 * 86_400_000);
    let refused = guard(&home_args(&home, &["licence", "set", &key]));
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(GuardConfig::load(&config_path).unwrap().licence, None);
    // ... and `invalid` when it is in the config anyway; automatic renewal
    // on makes the source `auto_update`.
    GuardConfig::update(&config_path, |config| {
        config.licence = Some(key.clone());
        config.licence_auto_update = true;
        config.licence_renewal_token = Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".into());
    })
    .unwrap();
    let invalid = json_out(&guard(&home_args(&home, &["licence", "show", "--json"])));
    assert_licence_object(&invalid);
    assert_eq!(
        invalid,
        json!({"state": "invalid", "licensee": null, "expires_at_ms": null,
            "fee_free": false, "source": "auto_update"})
    );
}

/// A paper home made by `init --non-interactive`, its risk journal started
/// beforehand so that nothing is read from the venue.
fn init_paper_home(home: &Path) {
    let scope = GuardConfig {
        network: Some(GuardNetwork::Mainnet),
        account: Some(ACCOUNT.into()),
        ..GuardConfig::default()
    };
    std::fs::create_dir_all(home).unwrap();
    PersistentRisk::initialise_for(
        &home.join("risk-paper.jsonl"),
        scope.policy.risk_limits(),
        &scope.journal_scope(true).unwrap(),
        Timestamp::from_millis(now_ms()),
        dec!(10000),
        "contract test",
    )
    .unwrap();
    let output = guard(&home_args(
        home,
        &[
            "init",
            "--non-interactive",
            "--network",
            "paper",
            "--rules",
            RULES,
            "--account",
            ACCOUNT,
            "--no-key",
        ],
    ));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `licence set --stdin` (C3): exactly one line from standard input, a
/// trailing newline allowed; checked as the positional form checks it; the
/// key never appears in what the binary prints, refused or not. A key this
/// binary accepts would need Orcastrate's issuer, so the success path is
/// the positional form's (`licence_set`, shared) and the line reading is
/// unit-tested (`licence_life::read_key_line`).
#[test]
fn licence_set_reads_one_line_from_stdin() {
    let dir = TestDir::new("cli-contract-licence-stdin");
    let home = dir.path().join("home");
    init_paper_home(&home);
    let config_path = home.join("guard.toml");
    let before = std::fs::read(&config_path).unwrap();
    let key = test_licence(now_ms() + 30 * 86_400_000);
    let silent = |output: &Output, secrets: &[&str]| {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        for secret in secrets {
            assert!(
                !stdout.contains(secret) && !stderr.contains(secret),
                "the input was echoed: {stdout} / {stderr}"
            );
        }
    };
    let refused_unchanged = |output: &Output| {
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stderr.is_empty());
        assert_eq!(std::fs::read(&config_path).unwrap(), before);
    };

    // The same key, the same validation: refused alike (this binary's
    // issuers did not sign it), with the same reason, from the argument and
    // from standard input, with or without a line end.
    let positional = guard(&home_args(&home, &["licence", "set", &key]));
    refused_unchanged(&positional);
    for input in [format!("{key}\n"), format!("{key}\r\n"), key.clone()] {
        let piped = guard_with_stdin(
            &home_args(&home, &["licence", "set", "--stdin"]),
            input.as_bytes(),
        );
        refused_unchanged(&piped);
        silent(&piped, &[&key]);
        assert_eq!(piped.stderr, positional.stderr);
        assert!(
            String::from_utf8_lossy(&piped.stderr)
                .contains("licence key refused, config unchanged"),
            "{}",
            String::from_utf8_lossy(&piped.stderr)
        );
    }

    // More than one line, nothing, junk, too much: refused, named, not
    // echoed.
    let other = test_licence(now_ms() + 60 * 86_400_000);
    let junk = "not-a-licence-key-4f9a";
    let long = "x".repeat(5_000);
    for (input, reason) in [
        (format!("{key}\n{other}\n"), "exactly one line"),
        (format!("{key}\n\n"), "exactly one line"),
        (format!("\n{key}"), "exactly one line"),
        (String::new(), "nothing was read"),
        ("\n".to_owned(), "nothing was read"),
        (format!("{junk}\n"), "licence key refused"),
        (long.clone(), "more than a licence key"),
    ] {
        let piped = guard_with_stdin(
            &home_args(&home, &["licence", "set", "--stdin"]),
            input.as_bytes(),
        );
        refused_unchanged(&piped);
        silent(&piped, &[&key, &other, junk, &long[..64]]);
        let stderr = String::from_utf8_lossy(&piped.stderr);
        assert!(stderr.contains(reason), "{reason}: {stderr}");
    }

    // Both forms at once, or neither: a usage error (exit 2), the key not
    // repeated.
    let both = guard_with_stdin(
        &home_args(&home, &["licence", "set", &key, "--stdin"]),
        key.as_bytes(),
    );
    refused_unchanged(&both);
    silent(&both, &[&key]);
    let neither = guard(&home_args(&home, &["licence", "set"]));
    refused_unchanged(&neither);
}

/// A paper Guard serving on loopback, its licence checked against the test
/// key, as a running Guard answers `status` and `health`.
async fn serve(dir: &Path, licence: Option<String>) -> (Arc<Guard<MemoryVenue>>, String) {
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: GuardMode::Paper,
        account: Some(ACCOUNT.into()),
        state_dir: dir.to_owned(),
        licence,
        auth: AuthConfig {
            clients: vec![CLIENT.into()],
            ..AuthConfig::default()
        },
        ..GuardConfig::default()
    };
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(true),
        config.policy.risk_limits(),
        &config.journal_scope(true).unwrap(),
        Timestamp::from_millis(now_ms()),
        dec!(10000),
        "contract test",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(true)).unwrap();
    let venue = MemoryVenue::new(
        Address::from_hex(CLIENT).unwrap(),
        Address::from_hex(ACCOUNT).unwrap(),
        "10000",
    )
    .read_only();
    let guard = Guard::new(
        Setup {
            config,
            mode: Mode::Paper,
            risk,
            journal,
            fee: FeeMode::Off("test".into()),
            fee_warning: None,
            limits: Limits {
                request_weight_per_second: 1_000_000,
                request_weight_burst: 1_000_000,
            },
        },
        venue,
        SystemClock,
    )
    .unwrap();
    guard
        .set_licence_keys_for_test(test_key::public(), None, None)
        .await;
    let (addr, _) = server::bind(guard.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    (guard, format!("http://{addr}"))
}

/// The binary, run off the async runtime (it blocks on HTTP to the Guard
/// this runtime serves).
async fn guard_blocking(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        guard(&args)
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_json_and_health() {
    let dir = TestDir::new("cli-contract-status");
    let home = dir.path().join("empty-home");
    let expires = now_ms() + 30 * 86_400_000;
    let (_guard, url) = serve(dir.path(), Some(test_licence(expires))).await;
    let home = home.to_str().unwrap().to_owned();

    // `health`: 0 while Guard answers, 1 when nothing does, 2 for a
    // malformed address (a refusal).
    let healthy = guard_blocking(vec![
        "--home".into(),
        home.clone(),
        "health".into(),
        "--url".into(),
        url.clone(),
    ])
    .await;
    assert_eq!(
        healthy.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&healthy.stderr)
    );
    let closed = format!("http://{}", closed_address());
    let unhealthy = guard_blocking(vec![
        "--home".into(),
        home.clone(),
        "health".into(),
        "--url".into(),
        closed,
    ])
    .await;
    assert_eq!(unhealthy.status.code(), Some(1));
    let malformed = guard_blocking(vec![
        "--home".into(),
        home.clone(),
        "health".into(),
        "--url".into(),
        "ftp://127.0.0.1:1".into(),
    ])
    .await;
    assert_eq!(malformed.status.code(), Some(2));

    // `status --json`: at least C3's fields, with their types.
    let status = json_out(
        &guard_blocking(vec![
            "--home".into(),
            home.clone(),
            "status".into(),
            "--json".into(),
            "--url".into(),
            url.clone(),
        ])
        .await,
    );
    assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(status["network"], "testnet");
    assert_eq!(status["account"], ACCOUNT);
    assert_eq!(status["mode"], "paper");
    assert_eq!(status["halted"], false);
    assert_eq!(status["kill_switch"], false);
    assert_eq!(status["journal"]["ok"], true);
    // `/exchange` and `/guard/kill` take `expectedMode`, and say so.
    assert_eq!(
        status["capabilities"],
        json!({"exchange_expected_mode": true, "kill_expected_mode": true}),
        "{status}"
    );
    let licence = &status["licence"];
    assert_licence_object(licence);
    assert_eq!(licence["state"], "valid", "{licence}");
    assert_eq!(licence["licensee"], "Contract Test");
    assert_eq!(licence["expires_at_ms"], expires);
    assert_eq!(licence["fee_free"], true);
    assert_eq!(licence["source"], "file");
    // The rest of Guard's answer is kept.
    for kept in ["risk", "fee", "alerts", "clients", "rules", "killed"] {
        assert!(status.get(kept).is_some(), "{kept} missing: {status}");
    }

    // Without a licence key: `none`.
    let dir = TestDir::new("cli-contract-status-none");
    let (_guard, url) = serve(dir.path(), None).await;
    let status = json_out(
        &guard_blocking(vec![
            "--home".into(),
            home,
            "status".into(),
            "--json".into(),
            "--url".into(),
            url,
        ])
        .await,
    );
    assert_licence_object(&status["licence"]);
    assert_eq!(status["licence"]["state"], "none");
    assert_eq!(status["licence"]["licensee"], Value::Null);
    assert_eq!(status["licence"]["fee_free"], false);
}
