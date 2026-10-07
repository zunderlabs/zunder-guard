// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `zunder-guard-pilot`: the scripted test client of Guard's first mainnet
//! pilot (`docs/guard.md#paper-testnet-mainnet`). One step per invocation:
//!
//! ```sh
//! zunder-guard-pilot --step look --expect-mode testnet --confirm-account 0x<P> \
//!     --client-key-file /var/lib/zunder-guard/pilot-client.key
//!
//! # Mainnet requires explicit operator approval for this invocation:
//! zunder-guard-pilot --step entry --expect-mode mainnet --confirm-account 0x<P> \
//!     --client-key-file /var/lib/zunder-guard/pilot-client.key \
//!     --i-am-jonas-and-this-is-the-pilot
//! ```
//!
//! The steps: look, fee-gate, entry, stop-checks, close, tighten-and-fire,
//! kill, restart-before, restart-after, fee-withdrawn-open,
//! fee-withdrawn-close, drill-entry, drill-after, hip3-off, flat, watch.
//!
//! The client key comes from a file only its owner can read
//! (`--client-key-file`) or from standard input (`--key-stdin`), never from
//! an argument or the environment. Exit status: 0 every check passed, 1 a
//! check failed, 2 refused before anything was sent, 3 an outcome is
//! unknown (look at the account before anything else).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use zunder_redteam::pilot::{self, GuardMode, Options, Step, Timing, key};

#[derive(Parser)]
#[command(
    name = "zunder-guard-pilot",
    about = "The scripted test client of Guard's mainnet pilot: one step per invocation, every order previewed and capped first."
)]
struct Args {
    /// The step to run (docs/guard.md#paper-testnet-mainnet).
    #[arg(long, value_parser = parse_step)]
    step: Step,

    /// The mode Guard must report: paper, testnet or mainnet.
    #[arg(long, value_parser = parse_mode)]
    expect_mode: GuardMode,

    /// The account Guard must trade (the pilot account P).
    #[arg(long, alias = "expect-account")]
    confirm_account: String,

    /// Explicit operator consent for a mainnet pilot invocation.
    #[arg(long)]
    i_am_jonas_and_this_is_the_pilot: bool,

    /// The client key: a file readable by its owner only.
    #[arg(long, conflicts_with = "key_stdin")]
    client_key_file: Option<PathBuf>,

    /// The client key: on standard input.
    #[arg(long)]
    key_stdin: bool,

    /// Guard's address (on mainnet only http://127.0.0.1:8547).
    #[arg(long, default_value = "http://127.0.0.1:8547")]
    url: String,

    /// Where pilot.jsonl and watch.jsonl are appended.
    #[arg(long, default_value = "/var/lib/zunder-guard/pilot")]
    log_dir: PathBuf,

    /// How long --step watch runs, in minutes (at most 720).
    #[arg(long, default_value_t = 240, value_parser = clap::value_parser!(u64).range(1..=720))]
    watch_minutes: u64,
}

fn parse_step(text: &str) -> Result<Step, String> {
    Step::parse(text).ok_or_else(|| {
        let names: Vec<&str> = Step::ALL.iter().map(|step| step.name()).collect();
        format!("unknown step; one of {}", names.join(", "))
    })
}

fn parse_mode(text: &str) -> Result<GuardMode, String> {
    GuardMode::parse(text).ok_or_else(|| "paper, testnet or mainnet".to_owned())
}

fn main() -> ExitCode {
    let args = Args::parse();
    let key = match (&args.client_key_file, args.key_stdin) {
        (Some(path), false) => key::from_file(path),
        (None, true) => key::from_reader(&mut std::io::stdin().lock()),
        _ => {
            eprintln!(
                "zunder-guard-pilot: pass --client-key-file FILE (mode 0600) or --key-stdin; never the key itself"
            );
            return ExitCode::from(2);
        }
    };
    let key = match key {
        Ok(key) => key,
        Err(error) => {
            eprintln!("zunder-guard-pilot: {error}");
            return ExitCode::from(2);
        }
    };
    let options = Options {
        url: args.url,
        step: args.step,
        expect_mode: args.expect_mode,
        confirm_account: args.confirm_account,
        pilot_confirmed: args.i_am_jonas_and_this_is_the_pilot,
        log_dir: args.log_dir,
        timing: Timing {
            watch_ms: args.watch_minutes * 60_000,
            ..Timing::default()
        },
        echo: true,
    };
    let outcome = pilot::run(&options, &key);
    if let Some(reason) = &outcome.reason {
        // A closed standard error is ignored: the step is over, its record
        // is in pilot.jsonl.
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "zunder-guard-pilot: {reason}");
    }
    ExitCode::from(u8::try_from(outcome.ending.exit_code()).unwrap_or(1))
}
