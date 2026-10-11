// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Proof that the suite bites: run the whole catalogue against the naive
//! mock and assert it catches the attacks the mock lets through, while the
//! attacks a bare JSON endpoint stops (malformed bodies, NaN/Infinity,
//! oversized bodies) still pass. If this test ever goes green with the mock
//! "passing" everything, the suite has stopped testing anything.

use std::collections::HashMap;

use zunder_redteam::catalogue::{self, Ctx};
use zunder_redteam::hlsign::{Key, SigningNet};
use zunder_redteam::mock::NaiveMock;
use zunder_redteam::runner::{self, Profile, Status};
use zunder_redteam::{DEFAULT_ATTACKER_KEY, DEFAULT_CLIENT_KEY, now_ms};

fn run_against_mock() -> HashMap<&'static str, Status> {
    let client = Key::from_hex(DEFAULT_CLIENT_KEY).expect("the built-in test key parses");
    let attacker = Key::from_hex(DEFAULT_ATTACKER_KEY).expect("the built-in test key parses");
    let ctx = Ctx::new(client, attacker, SigningNet::Testnet, now_ms());
    let cases = catalogue::all(&ctx);
    let mut mock = NaiveMock::new();
    let results = runner::run(&mut mock, &Profile::mock(), &cases);
    results
        .into_iter()
        .map(|result| (result.id, result.status))
        .collect()
}

#[test]
fn the_catalogue_is_large() {
    let client = Key::from_hex(DEFAULT_CLIENT_KEY).expect("the built-in test key parses");
    let attacker = Key::from_hex(DEFAULT_ATTACKER_KEY).expect("the built-in test key parses");
    let ctx = Ctx::new(client, attacker, SigningNet::Testnet, now_ms());
    let cases = catalogue::all(&ctx);
    assert!(
        cases.len() >= 60,
        "the catalogue should have at least 60 cases, has {}",
        cases.len()
    );
}

#[test]
fn the_mock_lets_many_attacks_through() {
    let results = run_against_mock();
    let failed = results
        .values()
        .filter(|status| **status == Status::Fail)
        .count();
    assert!(
        failed >= 30,
        "the naive mock should fail at least 30 attacks, failed {failed}"
    );
}

#[test]
fn the_mock_fails_the_attacks_it_cannot_stop() {
    let results = run_against_mock();
    // The mock has no authentication, no risk rules and forwards every
    // action type, so each of these must get through (status Fail).
    for id in [
        "auth_unsigned",
        "auth_wrong_key",
        "auth_forged_signature",
        "auth_tampered_action",
        "auth_nonce_replay",
        "auth_nonce_too_old",
        "fund_usd_send",
        "fund_withdraw3",
        "fund_approve_agent",
        "fund_unknown_action",
        "size_oversize_single",
        "size_batch_grouped",
        "stop_wrong_side",
        "lev_update_leverage",
        "market_bad_asset_index",
        "builder_client_supplied",
        "robust_ws_fund_movement",
        "agent_negative_size",
    ] {
        assert_eq!(
            results.get(id),
            Some(&Status::Fail),
            "{id} should be caught (Fail) against the naive mock"
        );
    }
}

#[test]
fn json_level_and_robustness_cases_pass_even_on_the_mock() {
    let results = run_against_mock();
    // These do not depend on Guard's logic: a bare JSON endpoint refuses
    // them, and the mock keeps a body-size cap and stays up.
    for id in [
        "agent_nan_literal",
        "agent_infinity_literal",
        "robust_huge_body",
        "robust_malformed_json",
        "robust_request_flood",
        "robust_info_no_key_leak",
    ] {
        assert_eq!(
            results.get(id),
            Some(&Status::Pass),
            "{id} should pass even against the naive mock"
        );
    }
}
