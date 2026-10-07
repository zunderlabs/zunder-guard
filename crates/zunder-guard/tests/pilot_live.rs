// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The pilot client's whole sequence against Hyperliquid TESTNET, through a real Guard in testnet
//! mode with the pilot's rules and equity cap. Ignored: an operator
//! runs it alone, with the testnet runner paused, as the other live checks
//! (`docs/guard.md`, "Live testnet checks"):
//!
//! ```sh
//! set -a; . ./.env; set +a
//! ZUNDER_GUARD_LIVE=1 cargo test -p zunder-guard --test pilot_live -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! It needs `ZUNDER_HL_TESTNET_KEY` and `ZUNDER_HL_TESTNET_ACCOUNT`; the
//! upstream is built from `VenueNetwork::testnet()`, so nothing can reach
//! mainnet. The client key is generated here and handed to the client
//! through a 0600 file, as on the pilot host. It refuses to start unless
//! the account is flat with no open orders, and checks it flat at the end
//! (`account flat` lines). When a step fails or anything panics, the
//! failure is printed, Guard is stopped, and the run is cleaned up straight
//! on the venue (`pilot_cleanup`: its resting entries cancelled, its
//! positions closed reduce-only, then the stops of the coins now flat
//! cancelled); the account is checked flat, and only then does the test
//! fail. A run that passed but needed that clean-up fails too. It takes
//! about 8 to 12 minutes (entries are spaced 18 s apart by Guard's request
//! budget; S5 waits up to a minute for its stop, the drill up to two for
//! its halt), longer than the runner's 10-minute health-alarm window:
//! expect that alarm. Resume the runner only after the second `account
//! flat` line.
//!
//! On testnet no builder account exists (`ORCASTRATE_TESTNET_BUILDER` is
//! unset), so the fee is off: S1 and S8 are refused by the client before
//! they send anything, and C5/C6 are not covered here.

#![allow(clippy::unwrap_used)]

mod pilot_cleanup;

use std::{panic::AssertUnwindSafe, path::PathBuf, sync::Arc, time::Duration};

use futures_util::FutureExt as _;

use rust_decimal::{Decimal, dec};
use serde_json::Value;
use zunder_core::Timestamp;
use zunder_guard::{
    config::{GuardConfig, GuardMode, GuardNetwork},
    guard::{Clock, Guard, Mode, Setup, SystemClock},
    journal::DecisionJournal,
    server,
    testdir::TestDir,
    upstream::{Hyperliquid, Upstream},
};
use zunder_guard_core::{
    account::{check_api_wallet_role, requests},
    auth::AuthConfig,
    licence::FeeMode,
    policy::{Markets, Policy, StopPolicy},
    sign::{Address, GuardKey, SigningNetwork},
};
use zunder_redteam::pilot::{self, Ending, GuardMode as Expected, Options, Outcome, Step, Timing};
use zunder_venue::{PersistentRisk, hyperliquid::VenueNetwork};

fn enabled() -> bool {
    std::env::var("ZUNDER_GUARD_LIVE").as_deref() == Ok("1")
}

fn env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is not set (https://zunderlabs.com/docs/deploy/ssh/)"))
}

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

fn drill_policy() -> Policy {
    Policy {
        max_loss_at_stop: dec!(0.005),
        daily_loss_stop: dec!(0.0001),
        markets: Markets::Only(["BTC".to_owned()].into()),
        ..pilot_policy()
    }
}

/// One Guard home on the runner's testnet account.
struct Home {
    dir: TestDir,
    policy: Policy,
    key_file: PathBuf,
    client: GuardKey,
    logs: PathBuf,
}

impl Home {
    fn new(name: &str, policy: Policy) -> Self {
        let dir = TestDir::new(name);
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let client = GuardKey::from_bytes(&seed).unwrap();
        // The client key goes to a 0600 file, as `client add --out` writes it.
        let key_file = dir.path().join("pilot-client.key");
        {
            use std::io::Write;
            let digits: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
            let mut file = zunder_venue::owner_only::create(&key_file).unwrap();
            writeln!(file, "0x{digits}").unwrap();
        }
        let logs = dir.path().join("pilot-logs");
        std::fs::create_dir_all(&logs).unwrap();
        Self {
            dir,
            policy,
            key_file,
            client,
            logs,
        }
    }

    fn config(&self, key: &GuardKey, account: Address) -> GuardConfig {
        GuardConfig {
            network: Some(GuardNetwork::Testnet),
            mode: GuardMode::Testnet,
            account: Some(account.to_hex()),
            api_wallet: Some(key.address().to_hex()),
            state_dir: self.dir.path().to_owned(),
            auth: AuthConfig {
                clients: vec![self.client.address().to_hex()],
                ..AuthConfig::default()
            },
            policy: self.policy.clone(),
            ..GuardConfig::default()
        }
    }
}

struct Running {
    guard: Arc<Guard<Hyperliquid>>,
    url: String,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

fn account() -> Address {
    Address::from_hex(&env("ZUNDER_HL_TESTNET_ACCOUNT")).expect("an address")
}

impl Running {
    async fn start(home: &Home, first: bool) -> Self {
        let key = GuardKey::from_hex(&env("ZUNDER_HL_TESTNET_KEY")).expect("a testnet key");
        let upstream = Hyperliquid::sending(VenueNetwork::testnet()).unwrap();
        let role = upstream
            .info(&requests::user_role(key.address()))
            .await
            .unwrap();
        check_api_wallet_role(&role, key.address(), account()).unwrap();
        let config = home.config(&key, account());
        let limits = home.policy.risk_limits();
        let scope = config.journal_scope(false).unwrap();
        let risk = if first {
            let state = upstream
                .info(&requests::clearinghouse_state(account()))
                .await
                .unwrap();
            let equity: Decimal = state["marginSummary"]["accountValue"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            PersistentRisk::initialise_for(
                &config.risk_journal(false),
                limits,
                &scope,
                Timestamp::from_millis(SystemClock.now_ms() as i64),
                equity,
                "pilot client live testnet run",
            )
            .unwrap()
        } else {
            PersistentRisk::open_for(&config.risk_journal(false), &limits, &scope).unwrap()
        };
        let journal = DecisionJournal::open(&config.decision_journal(false)).unwrap();
        let guard = Guard::new(
            Setup {
                config,
                mode: Mode::Send {
                    key,
                    network: SigningNetwork::Testnet,
                },
                risk,
                journal,
                fee: FeeMode::Off("testnet".into()),
                fee_warning: None,
                limits: Default::default(),
            },
            upstream,
            SystemClock,
        )
        .unwrap();
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

    /// Stop Guard, as `systemctl restart` does.
    async fn stop(self) {
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
        for _ in 0..200 {
            if Arc::strong_count(&self.guard) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(Arc::strong_count(&self.guard), 1, "Guard is still in use");
    }

    async fn step(&self, home: &Home, step: Step) -> Outcome {
        let options = Options {
            url: self.url.clone(),
            step,
            expect_mode: Expected::Testnet,
            confirm_account: account().to_hex(),
            pilot_confirmed: false,
            log_dir: home.logs.clone(),
            timing: Timing {
                watch_ms: 5_000,
                ..Timing::default()
            },
            echo: true,
        };
        let key_file = home.key_file.clone();
        tokio::task::spawn_blocking(move || {
            let key = pilot::key::from_file(&key_file).unwrap();
            pilot::run(&options, &key)
        })
        .await
        .unwrap()
    }

    async fn status(&self) -> Value {
        self.guard.status().await
    }
}

/// A step that must pass: its failure, for the report, otherwise.
fn passed(step: Step, outcome: &Outcome) -> Result<(), String> {
    if outcome.ending == Ending::Passed {
        return Ok(());
    }
    Err(format!(
        "{}: {:?} {:?}\nfailed: {:#?}",
        step.name(),
        outcome.ending,
        outcome.reason,
        outcome.with("FAIL")
    ))
}

/// The account's positions and open orders, straight from the venue.
async fn holdings() -> (Vec<Value>, Vec<Value>) {
    let upstream = Hyperliquid::paper(zunder_venue::hyperliquid::Network::Testnet).unwrap();
    let state = upstream
        .info(&requests::clearinghouse_state(account()))
        .await
        .unwrap();
    let positions: Vec<Value> = state["assetPositions"]
        .as_array()
        .unwrap_or_else(|| panic!("ABORT: no assetPositions: {state}"))
        .iter()
        .filter(|position| {
            position["position"]["szi"]
                .as_str()
                .and_then(|szi| szi.parse::<Decimal>().ok())
                .is_some_and(|szi| !szi.is_zero())
        })
        .cloned()
        .collect();
    let orders = upstream
        .info(&requests::frontend_open_orders(account()))
        .await
        .unwrap();
    let orders = orders
        .as_array()
        .unwrap_or_else(|| panic!("ABORT: the open orders are not a list: {orders}"))
        .clone();
    (positions, orders)
}

async fn assert_flat(when: &str) {
    let (positions, orders) = holdings().await;
    assert!(
        positions.is_empty() && orders.is_empty(),
        "ABORT {when}: the account is not flat ({} positions, {} open orders); pause the testnet runner and flatten by hand first: {positions:?} {orders:?}",
        positions.len(),
        orders.len()
    );
    println!(
        "account flat {when}: 0 positions, 0 open orders ({})",
        account()
    );
}

/// Wait up to `secs` for the account to hold no position.
async fn wait_no_position(secs: u64) {
    for _ in 0..secs {
        if holdings().await.0.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Stop the Guard in `slot`, if any (as `systemctl stop` does).
async fn stop(slot: &mut Option<Running>) {
    if let Some(guard) = slot.take() {
        guard.stop().await;
    }
}

/// Start a Guard in `slot` and hand it back.
async fn start<'a>(slot: &'a mut Option<Running>, home: &Home, first: bool) -> &'a Running {
    stop(slot).await;
    slot.insert(Running::start(home, first).await)
}

/// The whole sequence; the first failure, as text. Every Guard it starts
/// is left in `slot`, so that the caller can stop it before cleaning up.
async fn sequence(slot: &mut Option<Running>) -> Result<(), String> {
    let home = Home::new("pilot-live", pilot_policy());
    let guard = start(slot, &home, true).await;
    passed(Step::Look, &guard.step(&home, Step::Look).await)?;
    // No testnet builder: the fee steps are refused before anything is sent.
    for step in [Step::FeeGate, Step::FeeWithdrawnOpen] {
        let outcome = guard.step(&home, step).await;
        if outcome.ending != Ending::Refused || outcome.sent != 0 {
            return Err(format!(
                "{}: expected a refusal with nothing sent: {:?} {:?}",
                step.name(),
                outcome.ending,
                outcome.reason
            ));
        }
    }
    passed(Step::Entry, &guard.step(&home, Step::Entry).await)?;
    passed(Step::StopChecks, &guard.step(&home, Step::StopChecks).await)?;
    passed(Step::Close, &guard.step(&home, Step::Close).await)?;

    // S5: the client's stop 0.15% below the mid; up to a minute for it to
    // fire, then the runbook's fallback, close.
    passed(
        Step::TightenAndFire,
        &guard.step(&home, Step::TightenAndFire).await,
    )?;
    wait_no_position(60).await;
    println!(
        "S5: the client's stop fired: {}",
        holdings().await.0.is_empty()
    );
    passed(Step::Close, &guard.step(&home, Step::Close).await)?;

    // S6, then the kill file removed and Guard restarted.
    passed(Step::Kill, &guard.step(&home, Step::Kill).await)?;
    let kill_file = home
        .config(
            &GuardKey::from_hex(&env("ZUNDER_HL_TESTNET_KEY")).unwrap(),
            account(),
        )
        .kill_file();
    stop(slot).await;
    std::fs::remove_file(&kill_file).map_err(|error| format!("the kill file: {error}"))?;
    let guard = start(slot, &home, false).await;
    if !guard.status().await["killed"].is_null() {
        return Err("still killed after removing the kill file".to_owned());
    }

    // S7.
    passed(
        Step::RestartBefore,
        &guard.step(&home, Step::RestartBefore).await,
    )?;
    let guard = start(slot, &home, false).await;
    passed(
        Step::RestartAfter,
        &guard.step(&home, Step::RestartAfter).await,
    )?;

    // H0 (testnet lists HIP-3 dex xyz) and the end.
    passed(Step::Hip3Off, &guard.step(&home, Step::Hip3Off).await)?;
    passed(Step::Flat, &guard.step(&home, Step::Flat).await)?;

    // The drill, as its own Guard home started right before it (D1).
    let drill = Home::new("pilot-live-drill", drill_policy());
    let guard = start(slot, &drill, true).await;
    passed(
        Step::DrillEntry,
        &guard.step(&drill, Step::DrillEntry).await,
    )?;
    let mut halted = false;
    for _ in 0..120 {
        if guard.status().await["risk"]["state"] == "halted_for_day" {
            halted = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    if !halted {
        // The price moved our way: close; the realised fee halts it.
        println!("D1: no halt within 2 minutes; closing by the client");
        passed(Step::Close, &guard.step(&drill, Step::Close).await)?;
        for _ in 0..60 {
            if guard.status().await["risk"]["state"] == "halted_for_day" {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    wait_no_position(15).await;
    passed(
        Step::DrillAfter,
        &guard.step(&drill, Step::DrillAfter).await,
    )?;
    let guard = start(slot, &drill, false).await;
    passed(
        Step::DrillAfter,
        &guard.step(&drill, Step::DrillAfter).await,
    )?;
    // Stops the venue left on the flat account: cancelled by the client.
    let outcome = guard.step(&drill, Step::Close).await;
    println!("drill cleanup: {:?} {:?}", outcome.ending, outcome.reason);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live testnet: an operator runs it with the runner paused"]
async fn live_the_pilot_sequence_on_testnet() {
    if !enabled() {
        eprintln!("set ZUNDER_GUARD_LIVE=1 to run the live testnet check");
        return;
    }
    assert_flat("before the test").await;
    let mut slot = None;
    // A panic anywhere in the sequence (a client step, a Guard start) is
    // caught like a failed step, so the clean-up below always runs.
    let result = match AssertUnwindSafe(sequence(&mut slot)).catch_unwind().await {
        Ok(result) => result,
        Err(panic) => Err(format!(
            "panicked: {}",
            panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                .unwrap_or_else(|| "(no message)".to_owned())
        )),
    };
    // Guard stopped first, so that nothing of its races the clean-up.
    stop(&mut slot).await;
    if let Err(failure) = &result {
        println!("FAILED: {failure}");
        println!(
            "cleaning up: cancelling this run's entries, closing its positions reduce-only, cancelling its stops"
        );
    }
    // Always, also after a pass: the account was flat before the run and
    // the runner is paused, so whatever is open is this run's.
    let key = GuardKey::from_hex(&env("ZUNDER_HL_TESTNET_KEY")).expect("a testnet key");
    let upstream = Hyperliquid::sending(VenueNetwork::testnet()).unwrap();
    let mut cleaned = Vec::new();
    // A short settle first: the venue's own cancels (stops of an emptied
    // position) and the last fills show within seconds; only what is still
    // there after 15 s is a leftover.
    for _ in 0..15 {
        let (positions, orders) = holdings().await;
        if positions.is_empty() && orders.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    for round in 0..3 {
        let (positions, orders) = holdings().await;
        if positions.is_empty() && orders.is_empty() {
            break;
        }
        for line in pilot_cleanup::cleanup(&upstream, &key, account()).await {
            println!("cleanup {round}: {line}");
            cleaned.push(line);
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    assert_flat("after the test").await;
    if let Err(failure) = result {
        panic!("the pilot sequence failed (the account was cleaned up): {failure}");
    }
    // A pass that left anything behind is a failure all the same.
    assert!(
        cleaned.is_empty(),
        "the pilot sequence passed but left positions or orders, cleaned up: {cleaned:#?}"
    );
}
