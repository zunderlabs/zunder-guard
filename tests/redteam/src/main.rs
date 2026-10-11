// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The red-team runner.
//!
//! ```sh
//! # Against the naive mock (proves the suite bites; places no orders):
//! cargo run -p zunder-redteam -- --mock
//!
//! # Against a running Guard in paper mode (judges every rule, sends nothing):
//! cargo run -p zunder-redteam -- --url http://127.0.0.1:8547 \
//!     --client-key 0x<client-key> --json report.json --report report.txt
//! ```
//!
//! A run against a Guard that is not in paper mode would let resized orders
//! reach the venue, so the runner refuses a testnet target unless
//! `--testnet-ok` is given, and refuses a mainnet target outright.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;

use zunder_redteam::catalogue::{self, Ctx};
use zunder_redteam::hlsign::{Key, SigningNet};
use zunder_redteam::mock::NaiveMock;
use zunder_redteam::runner::{self, Profile, Status, TargetKind};
use zunder_redteam::target::{HttpTarget, Target};
use zunder_redteam::{DEFAULT_ATTACKER_KEY, DEFAULT_CLIENT_KEY, now_ms, report};

#[derive(Parser)]
#[command(
    name = "zunder-redteam",
    about = "Black-box red-team suite for Zunder Guard: every attack must be refused."
)]
struct Args {
    /// Attack the built-in naive mock proxy instead of a running Guard.
    #[arg(long, conflicts_with = "url")]
    mock: bool,

    /// The Guard to attack, for example http://127.0.0.1:8547.
    #[arg(long)]
    url: Option<String>,

    /// The Guard-issued client key to sign with (0x and 64 hex digits).
    #[arg(long)]
    client_key: Option<String>,

    /// Allow a run against a Guard in testnet mode, which lets resized
    /// orders reach the testnet venue. Off by default.
    #[arg(long)]
    testnet_ok: bool,

    /// Treat the target as having a market allowlist set (runs the
    /// allowlist cases). Inferred from the status endpoint otherwise.
    #[arg(long)]
    allowlist: bool,

    /// Treat the target as already halted (runs the halt cases).
    #[arg(long)]
    halted: bool,

    /// Run only the cases whose id starts with this (for example
    /// `market_hip3`).
    #[arg(long)]
    only: Option<String>,

    /// Wait this long between cases, so that each is judged on its merits
    /// rather than meeting Guard's request-read budget (`rate_limited`).
    #[arg(long, default_value_t = 0)]
    pace_ms: u64,

    /// Write the machine-readable JSON report here.
    #[arg(long)]
    json: Option<PathBuf>,

    /// Write the human report here (also printed to stdout).
    #[arg(long)]
    report: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let client = Key::from_hex(args.client_key.as_deref().unwrap_or(DEFAULT_CLIENT_KEY))
        .context("the client key is not 64 hex digits")?;
    let attacker = Key::from_hex(DEFAULT_ATTACKER_KEY).expect("the built-in attacker key parses");

    if args.mock {
        let ctx = Ctx::new(client, attacker, SigningNet::Testnet, now_ms())
            .with_hip3(Some(catalogue::Hip3Target::synthetic()));
        let cases = catalogue::all(&ctx);
        let mut mock = NaiveMock::new();
        let results = runner::run(&mut mock, &Profile::mock(), &cases);
        emit(&mock.label(), &results, &args)?;
        // The mock is a demonstrator: it is meant to fail. Never a failure
        // exit here.
        println!(
            "\n(the mock let {} action(s) through; see the report)",
            mock.forwarded()
        );
        return Ok(());
    }

    let Some(url) = args.url.as_deref() else {
        bail!("pass --mock, or --url <guard> with --client-key <key>");
    };
    if args.client_key.is_none() {
        bail!("a running Guard needs --client-key (the key `zunder-guard init` issued)");
    }
    let mut target = HttpTarget::new(url)?;
    let status = target
        .status()
        .context("could not read /guard/status; is Guard running at that URL?")?;
    let mode = status.get("mode").and_then(|value| value.as_str());
    let kind = TargetKind::from_mode(mode);
    match kind {
        TargetKind::Mainnet => bail!(
            "refusing to run against a Guard in mainnet mode: the suite is for paper or testnet only"
        ),
        TargetKind::Testnet if !args.testnet_ok => bail!(
            "this Guard is in testnet mode, where resized orders reach the venue; re-run with --testnet-ok to allow that, or point it at a paper-mode Guard"
        ),
        _ => {}
    }
    let net = if kind == TargetKind::Mainnet {
        SigningNet::Mainnet
    } else {
        SigningNet::Testnet
    };
    let rules_text = status
        .get("rules")
        .map(|value| value.to_string())
        .unwrap_or_default();
    let allowlist_set =
        args.allowlist || (rules_text.contains("markets") && !rules_text.contains("\"all\""));
    let halted = args.halted
        || status
            .pointer("/risk/state")
            .and_then(|value| value.as_str())
            .is_some_and(|state| state != "active");
    // A HIP-3 dex the rules name, for the HIP-3 cases; none skips them.
    let hip3 = target.discover_hip3();
    let profile = Profile {
        kind,
        allowlist_set,
        halted,
        hip3: hip3.is_some(),
        hip3_halted: hip3.as_ref().is_some_and(|hip3| hip3.halted.is_some()),
    };

    let ctx = Ctx::new(client, attacker, net, now_ms()).with_hip3(hip3);
    let cases: Vec<_> = catalogue::all(&ctx)
        .into_iter()
        .filter(|case| {
            args.only
                .as_deref()
                .is_none_or(|only| case.id.starts_with(only))
        })
        .collect();
    let results = if args.pace_ms == 0 {
        runner::run(&mut target, &profile, &cases)
    } else {
        // Each case built again just before it runs, so that its nonce is
        // fresh (Guard takes nonces up to 30 s old).
        let ids: Vec<&str> = cases.iter().map(|case| case.id).collect();
        let mut results = Vec::with_capacity(ids.len());
        for id in ids {
            let fresh = Ctx::new(
                Key::from_hex(args.client_key.as_deref().unwrap_or(DEFAULT_CLIENT_KEY))
                    .context("the client key is not 64 hex digits")?,
                Key::from_hex(DEFAULT_ATTACKER_KEY).expect("the built-in attacker key parses"),
                net,
                now_ms(),
            )
            .with_hip3(ctx.hip3.clone());
            let case: Vec<_> = catalogue::all(&fresh)
                .into_iter()
                .filter(|case| case.id == id)
                .collect();
            results.extend(runner::run(&mut target, &profile, &case));
            std::thread::sleep(std::time::Duration::from_millis(args.pace_ms));
        }
        results
    };
    let label = target.label();
    emit(&label, &results, &args)?;

    let failed = results
        .iter()
        .filter(|result| result.status == Status::Fail)
        .count();
    if failed > 0 {
        bail!("{failed} attack(s) were NOT refused by {label}");
    }
    Ok(())
}

fn emit(label: &str, results: &[runner::CaseResult], args: &Args) -> Result<()> {
    let now = now_ms();
    let human = report::human(label, results);
    print!("{human}");
    if let Some(path) = &args.report {
        std::fs::write(path, &human).with_context(|| format!("writing {}", path.display()))?;
    }
    if let Some(path) = &args.json {
        let json = report::to_json(label, now, results);
        std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}
