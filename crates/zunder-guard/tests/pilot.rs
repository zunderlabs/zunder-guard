// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The pilot client (`zunder-guard-pilot`, `tests/redteam/src/pilot`)
//! against the real Guard, over HTTP, in paper and testnet modes over the
//! in-memory venue: every step of the pilot sequence, the drill, and the client's
//! refusals. Nothing here can reach a real venue.
//!
//! The Guard runs the pilot's rules (the drill's for the drill) on an
//! account of 200 USDC with the equity cap of 200; mids BTC 60,000 and ETH
//! 3,000. Its `/info` budget is lifted (the in-memory venue has no request
//! limit) except in the test that runs the client within the real one.

#![allow(clippy::unwrap_used)]

mod pilot_cleanup;
mod support;

use std::{path::PathBuf, sync::Arc, time::Duration};

use rust_decimal::dec;
use serde_json::Value;
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
    action::Builder,
    auth::AuthConfig,
    licence::FeeMode,
    policy::{Markets, Policy, StopPolicy},
    sign::{Address, GuardKey, SigningNetwork},
    wire::Wire,
};
use zunder_redteam::{
    hlsign::Key,
    pilot::{self, Ending, GuardMode as Expected, Options, Outcome, Step, Timing},
};
use zunder_venue::PersistentRisk;

const CLIENT_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
const BUILDER: &str = "0x00000000000000000000000000000000000000bb";

fn api_key() -> GuardKey {
    GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap()
}

/// The pilot's fixed test policy.
fn pilot_policy() -> Policy {
    Policy {
        max_leverage: dec!(3),
        max_loss_at_stop: dec!(0.01),
        stop: StopPolicy::Attach,
        default_stop_distance: dec!(0.02),
        min_liquidation_distance: dec!(0.15),
        max_position_of_account: dec!(1),
        max_open_risk: dec!(0.02),
        daily_loss_stop: dec!(0.03),
        drawdown_halt: dec!(0.10),
        markets: Markets::Only(["BTC".to_owned(), "ETH".to_owned()].into()),
        max_trading_equity_usd: Some(dec!(200)),
        ..Policy::default()
    }
}

/// The drill's: the pilot's with three changes.
fn drill_policy() -> Policy {
    Policy {
        max_loss_at_stop: dec!(0.005),
        daily_loss_stop: dec!(0.0001),
        markets: Markets::Only(["BTC".to_owned()].into()),
        ..pilot_policy()
    }
}

fn builder_fee() -> FeeMode {
    FeeMode::Builder(Builder {
        address: BUILDER.into(),
        fee_tenths_bp: 20,
    })
}

/// A Guard home: its directory, mode, rules and fee.
struct Home {
    dir: TestDir,
    paper: bool,
    policy: Policy,
    fee: FeeMode,
    logs: PathBuf,
}

impl Home {
    fn new(name: &str, paper: bool, policy: Policy, fee: FeeMode) -> Self {
        let dir = TestDir::new(name);
        let logs = dir.path().join("pilot-logs");
        std::fs::create_dir_all(&logs).unwrap();
        Self {
            dir,
            paper,
            policy,
            fee,
            logs,
        }
    }

    fn config(&self) -> GuardConfig {
        GuardConfig {
            network: Some(GuardNetwork::Testnet),
            mode: if self.paper {
                GuardMode::Paper
            } else {
                GuardMode::Testnet
            },
            account: Some(ACCOUNT.to_owned()),
            api_wallet: Some(api_key().address().to_hex()),
            state_dir: self.dir.path().to_owned(),
            auth: AuthConfig {
                clients: vec![GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex()],
                ..AuthConfig::default()
            },
            policy: self.policy.clone(),
            ..GuardConfig::default()
        }
    }

    fn venue(&self, equity: &str) -> MemoryVenue {
        let venue = MemoryVenue::new(
            api_key().address(),
            Address::from_hex(ACCOUNT).unwrap(),
            equity,
        );
        if self.paper { venue.read_only() } else { venue }
    }

    fn expected(&self) -> Expected {
        if self.paper {
            Expected::Paper
        } else {
            Expected::Testnet
        }
    }
}

/// Guard's budgets of the venue's request weight in a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Budget {
    /// Both lifted: the in-memory venue has no request limit.
    Lifted,
    /// The production budgets: requests 4 a second with a burst of 60,
    /// `/info` passthrough 2 a second with a burst of 160.
    Real,
    /// A request budget tighter than production (the passthrough lifted),
    /// so that the client meets `rate_limited`.
    Tight { per_second: u64, burst: u64 },
}

/// A Guard serving on a loopback port, with its background sync.
struct Running {
    guard: Arc<Guard<MemoryVenue>>,
    url: String,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    /// Start Guard over `venue`; `first` starts its risk journal, otherwise
    /// it opens the one there (a restart). Waits past the nonce floor
    /// (Guard's start plus 5 s).
    async fn start(home: &Home, venue: MemoryVenue, first: bool, budget: Budget) -> Self {
        let config = home.config();
        let limits = home.policy.risk_limits();
        let scope = config.journal_scope(home.paper).unwrap();
        let risk = if first {
            PersistentRisk::initialise_for(
                &config.risk_journal(home.paper),
                limits,
                &scope,
                Timestamp::from_millis(SystemClock.now_ms() as i64),
                dec!(200),
                "pilot client test",
            )
            .unwrap()
        } else {
            PersistentRisk::open_for(&config.risk_journal(home.paper), &limits, &scope).unwrap()
        };
        let journal = DecisionJournal::open(&config.decision_journal(home.paper)).unwrap();
        let mode = if home.paper {
            Mode::Paper
        } else {
            Mode::Send {
                key: api_key(),
                network: SigningNetwork::Testnet,
            }
        };
        let guard = Guard::new(
            Setup {
                config,
                mode,
                risk,
                journal,
                fee: home.fee.clone(),
                fee_warning: None,
                limits: match budget {
                    Budget::Lifted => Limits {
                        request_weight_per_second: 1_000_000,
                        request_weight_burst: 1_000_000,
                    },
                    Budget::Real => Limits::default(),
                    Budget::Tight { per_second, burst } => Limits {
                        request_weight_per_second: per_second,
                        request_weight_burst: burst,
                    },
                },
            },
            venue,
            SystemClock,
        )
        .unwrap();
        if budget != Budget::Real {
            guard.set_info_budget(1_000, 1_000_000);
        }
        let (addr, serve) = server::bind(guard.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let sync = tokio::spawn(guard.clone().sync_forever());
        tokio::time::sleep(Duration::from_millis(5_300)).await;
        Self {
            guard,
            url: format!("http://{addr}"),
            tasks: vec![serve, sync],
        }
    }

    fn venue(&self) -> &MemoryVenue {
        self.guard.upstream()
    }

    /// Stop Guard (as `systemctl restart` does) and hand back its venue.
    async fn stop(self) -> MemoryVenue {
        let venue = self.guard.upstream().fork();
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
        // Connection tasks hold Guard until their connections close.
        for _ in 0..200 {
            if Arc::strong_count(&self.guard) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(Arc::strong_count(&self.guard), 1, "Guard is still in use");
        drop(self.guard);
        venue
    }

    async fn step(&self, home: &Home, step: Step) -> Outcome {
        run_step(&self.url, home, step, home.expected(), ACCOUNT, CLIENT_KEY).await
    }

    async fn status(&self) -> Value {
        self.guard.status().await
    }

    /// Wait (up to `secs`) until the status satisfies `done`.
    async fn wait_status(&self, secs: u64, done: impl Fn(&Value) -> bool) -> Value {
        for _ in 0..secs * 2 {
            let status = self.status().await;
            if done(&status) {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        self.status().await
    }
}

async fn run_step(
    url: &str,
    home: &Home,
    step: Step,
    expect: Expected,
    account: &str,
    key: &str,
) -> Outcome {
    let timing = Timing {
        watch_ms: 3_000,
        ..Timing::default()
    };
    run_step_with(url, home, step, expect, account, key, timing).await
}

async fn run_step_with(
    url: &str,
    home: &Home,
    step: Step,
    expect: Expected,
    account: &str,
    key: &str,
    timing: Timing,
) -> Outcome {
    let options = Options {
        url: url.to_owned(),
        step,
        expect_mode: expect,
        confirm_account: account.to_owned(),
        pilot_confirmed: false,
        log_dir: home.logs.clone(),
        timing,
        echo: true,
    };
    let key = key.to_owned();
    tokio::task::spawn_blocking(move || pilot::run(&options, &Key::from_hex(&key).unwrap()))
        .await
        .unwrap()
}

#[track_caller]
fn passed(step: Step, outcome: &Outcome) {
    assert_eq!(
        outcome.ending,
        Ending::Passed,
        "{}: {:?}\nfailed: {:#?}",
        step.name(),
        outcome.reason,
        outcome.with("FAIL")
    );
}

#[track_caller]
fn refused(step: Step, outcome: &Outcome, says: &str) {
    assert_eq!(
        outcome.ending,
        Ending::Refused,
        "{}: {:?} {:#?}",
        step.name(),
        outcome.reason,
        outcome.checks
    );
    assert_eq!(
        outcome.sent,
        0,
        "{}: a refused step sends nothing",
        step.name()
    );
    let reason = outcome.reason.clone().unwrap_or_default();
    assert!(reason.contains(says), "{}: {reason}", step.name());
}

fn btc_position(venue: &MemoryVenue) -> Option<String> {
    venue
        .positions()
        .iter()
        .find(|position| position["position"]["coin"] == "BTC")
        .map(|position| position["position"]["szi"].as_str().unwrap().to_owned())
}

fn flat(venue: &MemoryVenue) -> bool {
    venue.positions().is_empty() && venue.orders().is_empty()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_step_on_testnet_over_the_in_memory_venue() {
    let home = Home::new("pilot-testnet", false, pilot_policy(), builder_fee());
    let mut guard = Running::start(&home, home.venue("200"), true, Budget::Real).await;

    // Pre-flight: the fee is not approved yet, so the preview is refused
    // and the hand calculation waits for S2.
    let look = guard.step(&home, Step::Look).await;
    passed(Step::Look, &look);
    assert_eq!(look.with("SKIP").len(), 1, "{:#?}", look.checks);
    assert_eq!(look.sent, 0);

    // S1: refused, nothing reaches the venue.
    passed(Step::FeeGate, &guard.step(&home, Step::FeeGate).await);
    assert!(guard.venue().received().is_empty());

    // the operator approves; Guard sees it within a minute.
    guard.venue().approve_builder(20);
    let status = guard
        .wait_status(70, |status| {
            status["fee"]["approval"]["state"] == "approved"
        })
        .await;
    assert_eq!(status["fee"]["approval"]["state"], "approved", "{status}");

    // S2: 0.01 BTC asked, cut to 2 / (60,300 - 58,800 + 2 x 7.5 bp x 60,300)
    // = 2 / 1,590.45 = 0.0012575 -> 0.00125 (fee 4.5 + builder 2 + slippage 1 bp).
    passed(Step::Entry, &guard.step(&home, Step::Entry).await);
    assert_eq!(btc_position(guard.venue()).as_deref(), Some("0.00125"));
    let orders = guard.venue().orders();
    assert_eq!(orders.len(), 1, "{orders:?}");
    assert_eq!(orders[0]["triggerPx"], "58800");
    // Isolated at 3x at most.
    let leverage: Vec<_> = guard
        .venue()
        .received()
        .into_iter()
        .filter(|received| received.json["type"] == "updateLeverage")
        .collect();
    assert_eq!(leverage.len(), 1);
    assert_eq!(leverage[0].json["isCross"], false);
    assert!(leverage[0].json["leverage"].as_u64().unwrap() <= 3);

    // S3: the stop can be neither cancelled nor loosened.
    let received = guard.venue().received().len();
    passed(Step::StopChecks, &guard.step(&home, Step::StopChecks).await);
    assert_eq!(
        guard.venue().received().len(),
        received,
        "nothing reached the venue"
    );
    assert_eq!(guard.venue().orders()[0]["triggerPx"], "58800");

    // S4: closed with the builder field, the stop cancelled, flat.
    passed(Step::Close, &guard.step(&home, Step::Close).await);
    assert!(flat(guard.venue()), "{:?}", guard.venue().orders());
    let close = guard
        .venue()
        .received()
        .into_iter()
        .rev()
        .find(|received| {
            received.json["type"] == "order" && received.json["orders"][0]["r"] == true
        })
        .unwrap();
    assert_eq!(close.json["builder"]["f"], 20);

    // S5: the client's tighter stop replaces Guard's (it does not fire in
    // memory: the runbook's fallback, close, follows).
    passed(
        Step::TightenAndFire,
        &guard.step(&home, Step::TightenAndFire).await,
    );
    let orders = guard.venue().orders();
    assert_eq!(orders.len(), 1, "{orders:?}");
    assert!(orders[0]["cloid"].as_str().unwrap().starts_with("0x7a70"));
    passed(Step::Close, &guard.step(&home, Step::Close).await);
    assert!(flat(guard.venue()));

    // S6: two entries, the kill switch, an entry refused; flat.
    let kill = guard.step(&home, Step::Kill).await;
    passed(Step::Kill, &kill);
    assert!(
        flat(guard.venue()),
        "{:?} {:?}",
        guard.venue().positions(),
        guard.venue().orders()
    );
    // Released only by removing the kill file and restarting.
    let kill_file = home.config().kill_file();
    assert!(kill_file.exists());
    std::fs::remove_file(&kill_file).unwrap();
    let venue = guard.stop().await;
    guard = Running::start(&home, venue, false, Budget::Real).await;
    assert!(guard.status().await["killed"].is_null());

    // S7: a position across a restart.
    passed(
        Step::RestartBefore,
        &guard.step(&home, Step::RestartBefore).await,
    );
    let venue = guard.stop().await;
    guard = Running::start(&home, venue, false, Budget::Real).await;
    passed(
        Step::RestartAfter,
        &guard.step(&home, Step::RestartAfter).await,
    );
    assert!(flat(guard.venue()));

    // S8: the operator withdraws the approval while a position is open.
    passed(
        Step::FeeWithdrawnOpen,
        &guard.step(&home, Step::FeeWithdrawnOpen).await,
    );
    guard.venue().approve_builder(0);
    passed(
        Step::FeeWithdrawnClose,
        &guard.step(&home, Step::FeeWithdrawnClose).await,
    );
    assert!(flat(guard.venue()));

    // H0 and the end.
    let before = guard.venue().received().len();
    passed(Step::Hip3Off, &guard.step(&home, Step::Hip3Off).await);
    assert_eq!(guard.venue().received().len(), before);
    passed(Step::Flat, &guard.step(&home, Step::Flat).await);
    passed(Step::Watch, &guard.step(&home, Step::Watch).await);

    // Every request and answer went to pilot.jsonl, and watch.jsonl filled.
    let log = std::fs::read_to_string(home.logs.join("pilot.jsonl")).unwrap();
    assert!(
        log.lines()
            .any(|line| line.contains("\"kind\":\"request\""))
    );
    assert!(
        log.lines()
            .all(|line| serde_json::from_str::<Value>(line).is_ok())
    );
    assert!(!log.contains(CLIENT_KEY.trim_start_matches("0x")));
    let watch = std::fs::read_to_string(home.logs.join("watch.jsonl")).unwrap();
    assert!(watch.lines().count() >= 2);
    // Every entry carried the client's id (Guard's own closes of the
    // flatten carry none, its stops 0x7a67).
    for received in guard.venue().received() {
        if received.json["type"] == "order" {
            for order in received.json["orders"].as_array().unwrap() {
                if order["r"] == false {
                    let cloid = order["c"].as_str().unwrap_or("");
                    assert!(cloid.starts_with("0x7a70"), "{order}");
                }
            }
        }
    }
    guard.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn every_step_on_paper_or_refused_there() {
    let home = Home::new("pilot-paper", true, pilot_policy(), builder_fee());
    let venue = home.venue("200");
    venue.approve_builder(20);
    let guard = Running::start(&home, venue, true, Budget::Real).await;
    // The steps a paper Guard can judge: answered as "would", nothing sent.
    for step in [
        Step::Look,
        Step::Entry,
        Step::RestartBefore,
        Step::FeeWithdrawnOpen,
        Step::Hip3Off,
        Step::Flat,
        Step::Watch,
        Step::Kill,
    ] {
        let outcome = guard.step(&home, step).await;
        passed(step, &outcome);
    }
    // The steps that need a position or the fee gate: refused, nothing sent.
    for step in [
        Step::FeeGate,
        Step::StopChecks,
        Step::Close,
        Step::TightenAndFire,
        Step::RestartAfter,
        Step::FeeWithdrawnClose,
    ] {
        refused(
            step,
            &guard.step(&home, step).await,
            "needs a Guard that sends",
        );
    }
    // The drill steps refuse the pilot's rules.
    refused(
        Step::DrillEntry,
        &guard.step(&home, Step::DrillEntry).await,
        "drill's rules",
    );
    assert!(guard.venue().received().is_empty());
    guard.stop().await;
}

/// D1 to D3 under the drill's rules: the entry, the halt and its flatten,
/// the vetoes, and the halt kept across a restart.
async fn drill(paper: bool) {
    let home = Home::new(
        if paper {
            "pilot-drill-paper"
        } else {
            "pilot-drill"
        },
        paper,
        drill_policy(),
        FeeMode::Off("test".into()),
    );
    let mut guard = Running::start(&home, home.venue("200"), true, Budget::Real).await;
    passed(Step::DrillEntry, &guard.step(&home, Step::DrillEntry).await);
    if !paper {
        // 1 / (1,500 + 2 x 5.5 bp x 60,300) = 1 / 1,566.33 = 0.000638 -> 0.00063.
        assert_eq!(btc_position(guard.venue()).as_deref(), Some("0.00063"));
    }
    // The fees of the entry: 0.1 USDC is far beyond 0.01% of 200.
    guard.venue().set_equity("199.9");
    let status = guard
        .wait_status(30, |status| status["risk"]["state"] == "halted_for_day")
        .await;
    assert_eq!(status["risk"]["state"], "halted_for_day", "{status}");
    if !paper {
        for _ in 0..30 {
            if btc_position(guard.venue()).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert_eq!(btc_position(guard.venue()), None, "the halt flattens");
    }
    passed(Step::DrillAfter, &guard.step(&home, Step::DrillAfter).await);
    // D3: still halted after a restart.
    let venue = guard.stop().await;
    guard = Running::start(&home, venue, false, Budget::Real).await;
    passed(Step::DrillAfter, &guard.step(&home, Step::DrillAfter).await);
    // The pilot's steps refuse the drill's rules.
    refused(
        Step::Entry,
        &guard.step(&home, Step::Entry).await,
        "pilot's rules",
    );
    guard.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_drill_on_testnet() {
    drill(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_drill_on_paper() {
    drill(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_refuses_before_sending_anything() {
    let home = Home::new(
        "pilot-refusals",
        false,
        pilot_policy(),
        FeeMode::Off("test".into()),
    );
    let guard = Running::start(&home, home.venue("200"), true, Budget::Lifted).await;
    let url = guard.url.clone();
    let other = "0x0000000000000000000000000000000000000001";

    // The wrong account.
    let outcome = run_step(
        &url,
        &home,
        Step::Entry,
        Expected::Testnet,
        other,
        CLIENT_KEY,
    )
    .await;
    refused(Step::Entry, &outcome, "--confirm-account");
    // The wrong mode.
    let outcome = run_step(
        &url,
        &home,
        Step::Entry,
        Expected::Paper,
        ACCOUNT,
        CLIENT_KEY,
    )
    .await;
    refused(Step::Entry, &outcome, "not paper");
    // Mainnet without the flag: refused before Guard is even asked.
    let outcome = run_step(
        &url,
        &home,
        Step::Entry,
        Expected::Mainnet,
        ACCOUNT,
        CLIENT_KEY,
    )
    .await;
    refused(Step::Entry, &outcome, "--i-am-jonas-and-this-is-the-pilot");
    assert!(
        outcome.lines.iter().all(|line| line["kind"] != "status"),
        "the status was read"
    );
    // A key Guard does not know.
    let stranger = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let outcome = run_step(
        &url,
        &home,
        Step::Entry,
        Expected::Testnet,
        ACCOUNT,
        stranger,
    )
    .await;
    refused(Step::Entry, &outcome, "does not accept this client key");
    // A step whose precondition does not hold: no position to check.
    let outcome = guard.step(&home, Step::StopChecks).await;
    refused(Step::StopChecks, &outcome, "exactly one BTC long");
    // The fee gate with the fee off.
    let outcome = guard.step(&home, Step::FeeGate).await;
    refused(Step::FeeGate, &outcome, "not builder");
    assert!(guard.venue().received().is_empty());
    guard.stop().await;

    // Mainnet with the flag, but not at the pilot's address.
    let options = Options {
        url,
        step: Step::Look,
        expect_mode: Expected::Mainnet,
        confirm_account: ACCOUNT.to_owned(),
        pilot_confirmed: true,
        log_dir: home.logs.clone(),
        timing: Timing::default(),
        echo: false,
    };
    let outcome = pilot::run(&options, &Key::from_hex(CLIENT_KEY).unwrap());
    assert_eq!(outcome.ending, Ending::Refused);
    assert!(outcome.reason.unwrap().contains("127.0.0.1:8547"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversize_step_is_refused_before_it_sends() {
    // The pilot's rules on a 300 USDC account with a cap of 300 (the most
    // the client takes): the budget is 3 USDC, so the entry would be
    // 3 / 1,566.33 = 0.00191 BTC, 115.2 USDC, above the 100 USDC cap.
    let home = Home::new(
        "pilot-oversize",
        false,
        Policy {
            max_trading_equity_usd: Some(dec!(300)),
            ..pilot_policy()
        },
        FeeMode::Off("test".into()),
    );
    let guard = Running::start(&home, home.venue("300"), true, Budget::Lifted).await;
    for step in [
        Step::Entry,
        Step::TightenAndFire,
        Step::Kill,
        Step::DrillEntry,
    ] {
        let outcome = guard.step(&home, step).await;
        let says = if step == Step::DrillEntry {
            "drill's rules"
        } else {
            "the pilot cap is 100"
        };
        refused(step, &outcome, says);
    }
    assert!(
        guard.venue().received().is_empty(),
        "nothing reached the venue"
    );
    guard.stop().await;

    // Rules that are not the pilot's (the defaults, with the cap).
    let home = Home::new(
        "pilot-other-rules",
        false,
        Policy {
            max_trading_equity_usd: Some(dec!(200)),
            ..Policy::default()
        },
        FeeMode::Off("test".into()),
    );
    let guard = Running::start(&home, home.venue("200"), true, Budget::Lifted).await;
    refused(
        Step::Entry,
        &guard.step(&home, Step::Entry).await,
        "pilot's rules",
    );
    refused(
        Step::Look,
        &guard.step(&home, Step::Look).await,
        "pilot's rules",
    );
    assert!(guard.venue().received().is_empty());
    guard.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_lives_within_guards_read_budget() {
    // Guard's real /info budget (2 a second, a burst of 160): S2, S3 and S4
    // back to back read more than the burst; the client waits for the
    // budget to refill and never resends an order.
    let home = Home::new(
        "pilot-budget",
        false,
        pilot_policy(),
        FeeMode::Off("test".into()),
    );
    let guard = Running::start(&home, home.venue("200"), true, Budget::Real).await;
    for step in [Step::Entry, Step::StopChecks, Step::Close] {
        passed(step, &guard.step(&home, step).await);
    }
    assert!(flat(guard.venue()));
    // One entry, one close, one cancel: each order sent once.
    let orders = guard
        .venue()
        .received()
        .into_iter()
        .filter(|received| received.json["type"] == "order")
        .count();
    assert_eq!(orders, 2);
    guard.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rate_limited_entry_is_previewed_and_sent_again_never_twice() {
    // The live failure of 7 Oct 2026: S6's ETH entry right after the BTC
    // entry met a spent request budget and was refused `rate_limited`.
    // Here the budget is tighter than production (2 a second, a burst of
    // 50: one entry costs 46, the account read and the leverage set first)
    // and the client's spacing is cut to 1 s, so the ETH entry is refused
    // the same way. The client sees nothing was forwarded, waits, previews
    // it again and sends it again; each entry reaches the venue once.
    let home = Home::new(
        "pilot-rate-limited",
        false,
        pilot_policy(),
        FeeMode::Off("test".into()),
    );
    let guard = Running::start(
        &home,
        home.venue("200"),
        true,
        Budget::Tight {
            per_second: 2,
            burst: 50,
        },
    )
    .await;
    let timing = Timing {
        entry_gap_ms: 1_000,
        rate_wait_ms: 15_000,
        ..Timing::default()
    };
    let outcome = run_step_with(
        &guard.url,
        &home,
        Step::Kill,
        Expected::Testnet,
        ACCOUNT,
        CLIENT_KEY,
        timing,
    )
    .await;
    passed(Step::Kill, &outcome);
    let limited = outcome
        .lines
        .iter()
        .filter(|line| line["kind"] == "rate_limited")
        .count();
    assert!(limited >= 1, "the budget was never met");
    // Every entry the venue received, by asset: BTC once, ETH once (the
    // entry after the kill is refused by Guard before it reaches it).
    let entries: Vec<u64> = guard
        .venue()
        .received()
        .into_iter()
        .filter(|received| received.json["type"] == "order")
        .flat_map(|received| {
            received.json["orders"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|order| order["r"] == false)
                .map(|order| order["a"].as_u64().unwrap())
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(entries, vec![0, 1], "{entries:?}");
    assert!(flat(guard.venue()));
    guard.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_live_cleanup_leaves_the_account_flat() {
    // What pilot_live.rs does after a failed step: Guard stopped, the BTC
    // long with Guard's stop left on the venue, closed reduce-only and the
    // stop cancelled straight on the venue with the API wallet.
    let home = Home::new(
        "pilot-cleanup",
        false,
        pilot_policy(),
        FeeMode::Off("test".into()),
    );
    let guard = Running::start(&home, home.venue("200"), true, Budget::Real).await;
    passed(Step::Entry, &guard.step(&home, Step::Entry).await);
    let venue = guard.stop().await;
    assert_eq!(btc_position(&venue).as_deref(), Some("0.00127"));
    assert_eq!(venue.orders().len(), 1);
    let account = Address::from_hex(ACCOUNT).unwrap();
    let done = pilot_cleanup::cleanup(&venue, &api_key(), account).await;
    // The close; the venue cancels the reduce-only stop of an emptied
    // position itself, so there is nothing left to cancel.
    assert_eq!(done.len(), 1, "{done:#?}");
    assert!(done[0].starts_with("closed 0.00127 BTC"), "{done:#?}");
    assert!(flat(&venue), "{:?} {:?}", venue.positions(), venue.orders());
    // On a flat account it does nothing.
    let again = pilot_cleanup::cleanup(&venue, &api_key(), account).await;
    assert!(again.is_empty(), "{again:#?}");

    // In order: the run's resting entry (as S6's ETH entry) cancelled
    // first; an order with another client id left alone and reported; a
    // reduce-only stop of the run's on a coin with no position (as the
    // venue may leave after a flatten) cancelled after the closes.
    let order =
        |asset: u64, is_buy: bool, price: &str, reduce_only: bool, kind: Wire, cloid: &str| {
            Wire::Map(vec![
                ("type", Wire::str("order")),
                (
                    "orders",
                    Wire::Array(vec![Wire::Map(vec![
                        ("a", Wire::UInt(asset)),
                        ("b", Wire::Bool(is_buy)),
                        ("p", Wire::str(price)),
                        ("s", Wire::str("0.01")),
                        ("r", Wire::Bool(reduce_only)),
                        ("t", kind),
                        ("c", Wire::str(cloid)),
                    ])]),
                ),
                ("grouping", Wire::str("na")),
            ])
        };
    let gtc = || Wire::Map(vec![("limit", Wire::Map(vec![("tif", Wire::str("Gtc"))]))]);
    let stop = Wire::Map(vec![(
        "trigger",
        Wire::Map(vec![
            ("isMarket", Wire::Bool(true)),
            ("triggerPx", Wire::str("2800")),
            ("tpsl", Wire::str("sl")),
        ]),
    )]);
    // Nonces in the past: the clean-up's own start at the clock.
    let now = SystemClock.now_ms();
    for (offset, action) in [
        (
            1,
            order(
                1,
                true,
                "2900",
                false,
                gtc(),
                "0x7a700000000000000000000000000001",
            ),
        ),
        (
            2,
            order(
                1,
                true,
                "2900",
                false,
                gtc(),
                "0x12340000000000000000000000000001",
            ),
        ),
        (
            3,
            order(
                1,
                false,
                "2520",
                true,
                stop,
                "0x7a670000000000000000000000000001",
            ),
        ),
    ] {
        let reply = pilot_cleanup::send(&venue, &api_key(), action, now - 10_000 + offset).await;
        assert_eq!(reply["status"], "ok", "{reply}");
    }
    assert_eq!(venue.orders().len(), 3);
    let done = pilot_cleanup::cleanup(&venue, &api_key(), account).await;
    assert_eq!(done.len(), 3, "{done:#?}");
    assert!(done[0].starts_with("cancelled entry"), "{done:#?}");
    assert!(
        done[1].starts_with("left an order that is not the run's"),
        "{done:#?}"
    );
    assert!(done[2].starts_with("cancelled stop"), "{done:#?}");
    let left = venue.orders();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0]["cloid"], "0x12340000000000000000000000000001");
}

/// The record of what Guard sent is written without waiting for the disk
/// (the decision before it was synced before the send). A crash that loses
/// it, or leaves it half written: Guard starts again, moves the unfinished
/// line and says so, and takes the position from the venue, as after any
/// restart.
#[tokio::test(flavor = "multi_thread")]
async fn a_half_written_sent_record_after_a_crash_is_cut_and_the_venue_rules() {
    let home = Home::new(
        "pilot-torn-sent",
        false,
        pilot_policy(),
        FeeMode::Off("test".into()),
    );
    let venue = home.venue("200");
    let guard = Running::start(&home, venue, true, Budget::Lifted).await;
    passed(
        Step::RestartBefore,
        &guard.step(&home, Step::RestartBefore).await,
    );
    let venue = guard.stop().await;
    // The journal as a crash right after the last send may leave it: that
    // send's record half written, nothing after it.
    let path = home.config().decision_journal(false);
    let text = std::fs::read_to_string(&path).unwrap();
    let mut start = 0;
    let mut sent = None;
    for line in text.split_inclusive('\n') {
        if line.contains("\"kind\":\"sent\"") {
            sent = Some((start, line.len()));
        }
        start += line.len();
    }
    let (at, len) = sent.expect("a sent record");
    std::fs::write(&path, &text.as_bytes()[..at + len / 2]).unwrap();
    let guard = Running::start(&home, venue, false, Budget::Lifted).await;
    let events = guard.guard.events(0).await;
    assert!(
        events.as_array().unwrap().iter().any(|event| event["text"]
            .as_str()
            .is_some_and(|text| text.contains("cut short"))),
        "{events}"
    );
    passed(
        Step::RestartAfter,
        &guard.step(&home, Step::RestartAfter).await,
    );
    assert!(flat(guard.venue()));
    guard.stop().await;
}
