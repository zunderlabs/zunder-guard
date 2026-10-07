// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The red-team suite (`tests/redteam`, black box over HTTP and WebSocket)
//! against the real Guard: its server, judge and journals, in testnet mode
//! over the in-memory venue, so the cases that need a position run and
//! nothing can reach a real venue. The account holds a BTC long of 0.1
//! with Guard's stop; the market allowlist is BTC, ETH and every market of
//! HIP-3 dex xyz (so the HIP-3 cases run, against xyz and the unmanaged
//! dex abc); the request-read budget is raised (no venue limit applies in
//! memory).
//!
//! The same suite also runs against a paper Guard on a public testnet
//! account (`deploy/guard/test/redteam-paper.sh`); this test
//! keeps the full catalogue in the gate.

#![allow(clippy::unwrap_used)]

mod support;

use std::sync::Arc;

use rust_decimal::dec;
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
    licence::FeeMode,
    policy::{Markets, Policy},
    sign::{Address, GuardKey, SigningNetwork},
};
use zunder_redteam::{
    DEFAULT_ATTACKER_KEY, catalogue,
    hlsign::{Key, SigningNet},
    now_ms,
    runner::{self, Profile, Status, TargetKind},
    target::HttpTarget,
};
use zunder_venue::PersistentRisk;

const CLIENT_KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";
const ACCOUNT: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";

fn api_key() -> GuardKey {
    GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap()
}

async fn start() -> (String, Arc<Guard<MemoryVenue>>, TestDir) {
    let dir = TestDir::new("redteam");
    let config = GuardConfig {
        network: Some(GuardNetwork::Testnet),
        mode: GuardMode::Testnet,
        account: Some(ACCOUNT.to_owned()),
        api_wallet: Some(api_key().address().to_hex()),
        state_dir: dir.path().to_owned(),
        auth: AuthConfig {
            clients: vec![GuardKey::from_hex(CLIENT_KEY).unwrap().address().to_hex()],
            ..AuthConfig::default()
        },
        policy: Policy {
            markets: Markets::Only(["BTC".to_owned(), "ETH".to_owned(), "xyz:*".to_owned()].into()),
            ..Policy::default()
        },
        ..GuardConfig::default()
    };
    let risk = PersistentRisk::initialise_for(
        &config.risk_journal(false),
        config.policy.risk_limits(),
        &config.journal_scope(false).unwrap(),
        Timestamp::from_millis(SystemClock.now_ms() as i64),
        dec!(10000),
        "red-team test",
    )
    .unwrap();
    let journal = DecisionJournal::open(&config.decision_journal(false)).unwrap();
    // 9,000 on the main dex and 1,000 on HIP-3 dex xyz: 10,000 in all.
    let venue = MemoryVenue::new(
        api_key().address(),
        Address::from_hex(ACCOUNT).unwrap(),
        "9000",
    );
    venue.set_dex_equity("xyz", "1000");
    let guard = Guard::new(
        Setup {
            config,
            mode: Mode::Send {
                key: api_key(),
                network: SigningNetwork::Testnet,
            },
            risk,
            journal,
            fee: FeeMode::Off("test".into()),
            fee_warning: None,
            limits: Limits {
                request_weight_per_second: 10_000,
                request_weight_burst: 1_000_000,
            },
        },
        venue,
        SystemClock,
    )
    .unwrap();
    // A BTC long of 0.1, which the first sync gives Guard's own stop: oid
    // 1001, the stop the catalogue's position cases aim at.
    guard.upstream().add_position("BTC", "0.1");
    guard.sync().await;
    assert_eq!(guard.upstream().orders().len(), 1);
    tokio::time::sleep(std::time::Duration::from_millis(5_100)).await;
    let (addr, _) = server::bind(guard.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    (format!("http://{addr}"), guard, dir)
}

/// Run the catalogue with `profile`; the summary and the cases that got
/// through.
fn run(url: &str, profile: Profile) -> (usize, usize, usize, Vec<String>) {
    let mut target = HttpTarget::new(url).unwrap();
    // Found through Guard's public interface, as a run against any Guard.
    let hip3 = target.discover_hip3();
    assert_eq!(
        hip3,
        Some(catalogue::Hip3Target {
            dex: 1,
            name: "xyz".into(),
            index: 0,
            asset: 110_000,
            mid: "4000".into(),
            other_dex: 2,
            halted: Some(110_002),
        })
    );
    let ctx = catalogue::Ctx::new(
        Key::from_hex(CLIENT_KEY).unwrap(),
        Key::from_hex(DEFAULT_ATTACKER_KEY).unwrap(),
        SigningNet::Testnet,
        now_ms(),
    )
    .with_hip3(hip3);
    let cases = catalogue::all(&ctx);
    let results = runner::run(&mut target, &profile, &cases);
    let count = |status| results.iter().filter(|r| r.status == status).count();
    let through = results
        .iter()
        .filter(|r| r.status == Status::Fail)
        .map(|r| {
            format!(
                "{}: {:?} {:?} {}",
                r.id, r.verdict, r.observed_code, r.detail
            )
        })
        .collect();
    for result in &results {
        println!(
            "{:?} {} {:?} {:?}",
            result.status, result.id, result.verdict, result.observed_code
        );
    }
    (
        count(Status::Pass),
        count(Status::Fail),
        count(Status::Skipped),
        through,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn every_red_team_attack_is_refused_by_the_real_guard() {
    let (url, guard, _dir) = start().await;
    let profile = Profile {
        kind: TargetKind::Testnet,
        allowlist_set: true,
        halted: false,
        hip3: true,
        hip3_halted: true,
    };
    let at = url.clone();
    let (passed, failed, skipped, through) = tokio::task::spawn_blocking(move || run(&at, profile))
        .await
        .unwrap();
    println!("red team: {passed} refused (pass), {failed} got through, {skipped} skipped");
    // Every case passes, `stop_cancel_replace_loosen` included: the
    // suite reads that sequence as Guard handles it (the cancel of Guard's
    // stop refused, the looser stop forwarded beside the kept one).
    assert!(through.is_empty(), "{through:#?}");
    assert_eq!(passed, 74);
    assert_eq!(skipped, 1, "only the halt case needs a halted engine");
    // Nothing that names Guard's stop for the BTC long (oid 1001, at
    // 58,800, 2% below the 60,000 mid) or any of Guard's stops by client
    // id (`0x7a67...`) reached the venue: no cancel, cancel by client id,
    // modify or batch modify. So the cancel and the loosening modify in
    // those cases were refused. (The venue itself cancels the stop once a
    // later case's close empties the position, as Hyperliquid does, so
    // the stop no longer rests at the end.)
    use zunder_guard_core::action::{Action, OrderRef};
    let names_guards_stop = |order: &OrderRef| match order {
        OrderRef::Oid(oid) => *oid == 1001,
        OrderRef::Cloid(cloid) => cloid.as_str().to_ascii_lowercase().starts_with("0x7a67"),
    };
    let touched: Vec<_> = guard
        .upstream()
        .received()
        .into_iter()
        .filter(|received| match &received.action {
            Action::Cancel(cancels) | Action::CancelByCloid(cancels) => cancels
                .iter()
                .any(|cancel| names_guards_stop(&cancel.order)),
            Action::Modify(modify) => names_guards_stop(&modify.oid),
            Action::BatchModify(modifies) => {
                modifies.iter().any(|modify| names_guards_stop(&modify.oid))
            }
            _ => false,
        })
        .collect();
    assert!(touched.is_empty(), "{touched:?}");
    // Oid 1001 is Guard's stop for the BTC long, at 58,800, and it left
    // the book, if at all, only by the venue's own cancel when a close
    // emptied the position: never by a cancel.
    let rested = guard.upstream().rested();
    let stop = rested
        .iter()
        .find(|order| order["oid"] == 1001)
        .expect("oid 1001 rested");
    assert_eq!(stop["triggerPx"], "58800", "{stop}");
    assert!(
        stop["cloid"]
            .as_str()
            .is_some_and(|cloid| cloid.to_ascii_lowercase().starts_with("0x7a67")),
        "{stop}"
    );
    let removed = guard.upstream().removed();
    assert!(
        removed
            .iter()
            .filter(|(oid, _)| *oid == 1001)
            .all(|(_, why)| why == "reduceOnlyCanceled"),
        "{removed:?}"
    );
    let events = guard.events(0).await;
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["code"] == "guard_stop"),
        "the cancel of Guard's stop was refused"
    );
    // Nothing but a cancel reached the venue for an asset other than a
    // main-dex perp (below 10000) or a perp of xyz, the HIP-3 dex the rules
    // name (110000 to 119999): Guard refused the spot, outcome and other
    // dexes' cases itself, not the venue.
    for sent in guard.upstream().received() {
        use zunder_guard_core::action::Action;
        let assets: Vec<u32> = match &sent.action {
            Action::Order(order) => order.orders.iter().map(|o| o.asset).collect(),
            Action::Modify(modify) => vec![modify.order.asset],
            Action::BatchModify(modifies) => modifies.iter().map(|m| m.order.asset).collect(),
            Action::UpdateLeverage { asset, .. } | Action::UpdateIsolatedMargin { asset, .. } => {
                vec![*asset]
            }
            _ => Vec::new(),
        };
        assert!(
            assets
                .iter()
                .all(|asset| *asset < 10_000 || (110_000..120_000).contains(asset)),
            "{:?}",
            sent.action
        );
    }
    // The oversize HIP-3 entry reached the venue cut to at most what xyz's
    // 1,000 free margin carries at 4x, 1 GOLD at 4,000 (less: the earlier
    // cases' entries have used most of the account-wide budgets).
    let gold: Vec<_> = guard
        .upstream()
        .received()
        .into_iter()
        .filter_map(|sent| match sent.action {
            zunder_guard_core::action::Action::Order(order) => order
                .orders
                .iter()
                .find(|o| o.asset == 110_000 && !o.reduce_only)
                .map(|o| o.size.value()),
            _ => None,
        })
        .collect();
    assert_eq!(gold.len(), 1, "{gold:?}");
    assert!(gold[0] > dec!(0) && gold[0] <= dec!(1), "{gold:?}");
    // Whatever reached the venue: no order that could open a position was
    // worth more than the 200% position cap (20,000 of 10,000 equity).
    for sent in guard.upstream().received() {
        if let zunder_guard_core::action::Action::Order(order) = &sent.action {
            for placed in order.orders.iter().filter(|o| !o.reduce_only) {
                let value = placed.size.value() * placed.price.value();
                assert!(value <= dec!(20000), "{placed:?}");
            }
        }
    }
    // Everything that reached the venue was signed by Guard's API wallet.
    for sent in guard.upstream().received() {
        assert_eq!(sent.signer, api_key().address());
    }

    // Halted (the kill switch): the halt cases too.
    std::fs::write(_dir.path().join("kill"), "red team\n").unwrap();
    guard.sync().await;
    let halted = Profile {
        kind: TargetKind::Testnet,
        allowlist_set: true,
        halted: true,
        hip3: true,
        hip3_halted: true,
    };
    let at = url.clone();
    let (passed, failed, _, through) = tokio::task::spawn_blocking(move || run(&at, halted))
        .await
        .unwrap();
    println!("red team, halted: {passed} refused (pass), {failed} got through");
    // The halt case is what this run is for: the kill switch flattened the
    // BTC long, so the position cases have nothing left to aim at.
    let halt: Vec<&String> = through
        .iter()
        .filter(|line| line.starts_with("halt_"))
        .collect();
    assert!(halt.is_empty(), "{through:#?}");
    assert!(passed > 50, "{passed}");
}
