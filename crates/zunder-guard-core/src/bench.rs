// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The latency Guard adds to a request before it leaves the machine: the
//! full path of decoding the bot's JSON, recovering and checking its
//! signer and nonce, judging the entry (risk engine sizing, attached stop,
//! isolated leverage) and signing the forwarded action with the real key.
//! Run on the Linux build host, release mode:
//! `cargo test --release -p zunder-guard-core latency_of_the_full_request_path -- --ignored --nocapture`.
//! CPU time only: reading the account and the network to the venue are not
//! included.

use std::time::{Duration, Instant};

use rust_decimal::dec;

use crate::{
    action::{Action, Grouping, OrderAction, Tif},
    admit,
    auth::tests::{START, authenticator, client_key},
    judge::{Context, Verdict, judge, tests as fixtures},
    policy::Policy,
    reply::signed_request,
    sign::{GuardKey, SigningNetwork},
};

fn percentiles(name: &str, samples: &mut [Duration]) {
    samples.sort();
    let at =
        |q: f64| samples[((samples.len() as f64 - 1.0) * q) as usize].as_nanos() as f64 / 1000.0;
    println!(
        "{name:>12}: p50 {:>7.1} us  p99 {:>7.1} us  p99.9 {:>7.1} us",
        at(0.50),
        at(0.99),
        at(0.999)
    );
}

#[test]
#[ignore = "benchmark: run explicitly in release mode"]
fn latency_of_the_full_request_path() {
    let policy = Policy::default();
    let account = fixtures::account(dec!(10000));
    let engine = fixtures::engine(&policy, dec!(10000));
    let real_key = GuardKey::from_hex(&format!("0x{}", "42".repeat(32))).unwrap();
    let client = client_key();
    let rounds: u64 = 20_000;
    // What ccxt sends for a market buy of 0.5 ETH: an IOC limit 5% above
    // the mid, no stop (Guard attaches one and sizes from it).
    let action = Action::Order(OrderAction {
        orders: vec![fixtures::limit(1, true, "3150", "0.5", Tif::Ioc)],
        grouping: Grouping::Na,
        builder: None,
    });
    // Nonces from 20 s ago up to now: all fresh, all after the start.
    let now = START + 30_000;
    let bodies: Vec<serde_json::Value> = (0..rounds)
        .map(|i| {
            let body = signed_request(
                &client,
                SigningNetwork::Testnet,
                &action,
                now - 20_000 + i,
                None,
            )
            .unwrap();
            serde_json::from_slice(&body).unwrap()
        })
        .collect();
    let mut auth = authenticator();
    let (mut admitting, mut judging, mut signing, mut total) = (
        Vec::with_capacity(rounds as usize),
        Vec::with_capacity(rounds as usize),
        Vec::with_capacity(rounds as usize),
        Vec::with_capacity(rounds as usize),
    );
    for (i, body) in bodies.iter().enumerate() {
        let start = Instant::now();
        let (request, _) = admit(&mut auth, body, now).unwrap();
        let admitted = Instant::now();
        let decision = judge(
            &Context {
                policy: &policy,
                engine: &engine,
                account: &account,
                killed: false,
                builder: None,
                salt: b"test",
            },
            &request,
        );
        let judged = Instant::now();
        assert_eq!(decision.verdict, Verdict::Resize);
        let forward = decision.forward.unwrap();
        let mut bytes = 0;
        for pre in &forward.pre {
            bytes += signed_request(
                &real_key,
                SigningNetwork::Testnet,
                pre,
                now + 2 * i as u64,
                None,
            )
            .unwrap()
            .len();
        }
        bytes += signed_request(
            &real_key,
            SigningNetwork::Testnet,
            &forward.action,
            now + 2 * i as u64 + 1,
            None,
        )
        .unwrap()
        .len();
        let done = Instant::now();
        std::hint::black_box(bytes);
        admitting.push(admitted - start);
        judging.push(judged - admitted);
        signing.push(done - judged);
        total.push(done - start);
    }
    println!("{rounds} requests: decode+auth, judge, re-sign (leverage update and order), total");
    percentiles("decode+auth", &mut admitting);
    percentiles("judge", &mut judging);
    percentiles("re-sign", &mut signing);
    percentiles("total", &mut total);
}
