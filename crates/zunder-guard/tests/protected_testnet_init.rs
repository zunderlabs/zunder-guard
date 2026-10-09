// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Protected Testnet CLI admission without a venue, private key or service operation.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

use nix::sys::resource::{Resource, getrlimit};
use zunder_guard::testdir::TestDir;

const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

#[test]
fn interactive_protected_testnet_cli_refuses_redirected_input_before_key_read() {
    let dir = TestDir::new("cli-interactive-protected-testnet");
    let output = Command::new(env!("CARGO_BIN_EXE_zunder-guard"))
        .env_clear()
        .env("HOME", dir.path())
        .arg("--home")
        .arg(dir.path())
        .args([
            "init",
            "--network",
            "testnet",
            "--interactive",
            "--no-key",
            "--service-key-check",
            "--account",
            ACCOUNT,
            "--equity-cap",
            "40",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("run it on a terminal"), "{stderr}");
    assert!(!dir.path().join("guard.toml").exists());
    assert!(!dir.path().join("risk.jsonl").exists());
}

fn protected_init(dir: &TestDir, cap: &str, input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zunder-guard"))
        .env_clear()
        .env("HOME", dir.path())
        .arg("--home")
        .arg(dir.path())
        .args([
            "init",
            "--network",
            "testnet",
            "--non-interactive",
            "--no-key",
            "--key-stdin",
            "--service-key-check",
            "--account",
            ACCOUNT,
        ])
        .arg(format!("--equity-cap={cap}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).ok();
    child.wait_with_output().unwrap()
}

#[test]
fn actual_linux_service_key_check_reaches_framed_input_after_core_limit_protection() {
    let dir = TestDir::new("cli-linux-protected-testnet");
    // An invalid frame stops before userRole or any other venue request. Reaching
    // this refusal establishes the actual CLI passed Linux core-limit admission.
    let output = protected_init(&dir, "40", b"invalid frame\n");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("invalid key frame"), "{stderr}");
    assert!(!stderr.contains("unsupported"), "{stderr}");
    assert!(
        !stderr.contains("invalid frame"),
        "credential input must not be echoed"
    );
    assert!(!dir.path().join("guard.toml").exists());
    assert!(!dir.path().join("risk.jsonl").exists());
}

#[test]
fn actual_linux_protected_testnet_cli_refuses_invalid_caps_before_reading_stdin() {
    for cap in ["not-a-number", "0", "-1", "2500.01"] {
        let dir = TestDir::new("cli-linux-testnet-invalid-cap");
        // Empty stdin would produce a framing refusal if the invalid cap were
        // ignored. It must instead fail on the cap before opening that boundary.
        let output = protected_init(&dir, cap, b"");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{stderr}");
        assert!(
            stderr.contains("not a number") || stderr.contains("max_trading_equity_usd"),
            "{stderr}"
        );
        assert!(!stderr.contains("key frame"), "{stderr}");
        assert!(!dir.path().join("guard.toml").exists());
        assert!(!dir.path().join("risk.jsonl").exists());
    }
}

#[test]
fn linux_soft_and_hard_core_limits_are_read_back_zero_in_an_isolated_child() {
    const MARKER: &str = "ZUNDER_TEST_CORE_LIMIT_READBACK_CHILD";
    if std::env::var_os(MARKER).as_deref() == Some(std::ffi::OsStr::new("1")) {
        zunder_guard::service::enforce_no_core_dumps().unwrap();
        assert_eq!(getrlimit(Resource::RLIMIT_CORE).unwrap(), (0, 0));
        return;
    }
    let before = getrlimit(Resource::RLIMIT_CORE).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "linux_soft_and_hard_core_limits_are_read_back_zero_in_an_isolated_child",
        ])
        .env(MARKER, "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        getrlimit(Resource::RLIMIT_CORE).unwrap(),
        before,
        "hard-limit mutation must remain isolated from the parent test process"
    );
}
