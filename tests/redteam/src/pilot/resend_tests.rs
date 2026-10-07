// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The client never sends a request again that Guard forwarded, or may
//! have: against a scripted fake Guard (a plain HTTP server answering
//! `/guard/preview`, `/exchange` and `/guard/decision` as told), every way a
//! `rate_limited` answer can fail to prove that nothing went out is sent
//! once, and only a proven refusal is previewed and sent again.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use serde_json::{Value, json};

use super::*;
use crate::actions::{OrderSpec, cancel, order};
use crate::pilot::{Options, Step, Timing};

const KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";

/// A scripted decision lookup: the answer for a nonce.
type DecisionFn = dyn Fn(u64) -> (u16, Value) + Send + Sync;

/// What the fake Guard was asked, in order: (path with query, body).
type Calls = Arc<Mutex<Vec<(String, String)>>>;

/// A fake Guard on a loopback port answering with `route(path, body,
/// calls so far)`: (HTTP status, JSON body).
fn fake_guard(
    route: impl Fn(&str, &Value, &[(String, String)]) -> (u16, Value) + Send + Sync + 'static,
) -> (String, Calls) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let calls: Calls = Arc::default();
    let seen = calls.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_owned();
            let mut length = 0usize;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let (status, answer) = {
                let mut calls = seen.lock().unwrap();
                let reply = route(&path, &parsed, &calls);
                calls.push((path.clone(), body));
                reply
            };
            let text = answer.to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            );
        }
    });
    (url, calls)
}

fn options(url: &str, step: Step, dir: PathBuf) -> Options {
    Options {
        url: url.to_owned(),
        step,
        expect_mode: GuardMode::Testnet,
        confirm_account: "0x5e9ee1089755c3435139848e47e6635505d5a13a".to_owned(),
        pilot_confirmed: false,
        log_dir: dir,
        timing: Timing {
            rate_wait_ms: 10,
            entry_gap_ms: 0,
            preview_gap_ms: 0,
            poll_ms: 10,
            ..Timing::default()
        },
        echo: false,
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "zunder-pilot-{name}-{}-{}",
        std::process::id(),
        crate::now_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A preview of an entry Guard would forward within the caps: 0.00127 BTC
/// at 60,300 with its stop at 58,800, isolated at 3x.
fn entry_preview() -> Value {
    json!({"verdict": "resize", "code": "resized", "changes": [], "forward": {},
        "entry": {"coin": "BTC", "side": "buy", "requested_size": "0.01", "size": "0.00127",
            "worst_price": "60300", "stop": "58800", "leverage": 3}})
}

fn veto_preview(code: &str) -> Value {
    json!({"verdict": "veto", "code": code, "forward": null, "entry": null})
}

const SPENT: &str = "Zunder Guard veto [rate_limited]: Guard's budget of the venue's request weight is spent (it is kept for Guard's own protection); try again in a few seconds";
const READ_SPENT: &str = "Zunder Guard veto [rate_limited]: Guard reads the account for at most 10 requests a minute on average (the venue's request limit is shared with Guard's own sync and protection); try again in a few seconds";

fn rate_limited(text: &str) -> Value {
    json!({"status": "err", "code": "rate_limited", "response": text})
}

/// The nonce of the last `/exchange` request.
fn last_nonce(calls: &[(String, String)]) -> u64 {
    calls
        .iter()
        .rev()
        .find(|(path, _)| path == "/exchange")
        .and_then(|(_, body)| serde_json::from_str::<Value>(body).ok())
        .and_then(|body| body["nonce"].as_u64())
        .unwrap_or(0)
}

/// Guard's decision proving nothing went out for `nonce`.
fn unsent(nonce: u64) -> Value {
    json!({"decision": {"kind": "decision", "nonce": nonce, "verdict": "veto",
        "code": "rate_limited", "forward": null}, "sent": []})
}

fn exchanges(calls: &Calls) -> usize {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(path, _)| path == "/exchange")
        .count()
}

fn btc_entry() -> Wire {
    let mut spec = OrderSpec::limit_buy(0, "63000", "0.01");
    spec.tif = "Ioc";
    order(&[spec], "na")
}

/// Plan `action` with `plan_kind` and send it once through a session on
/// the fake Guard; the answer's code.
fn run(
    url: &str,
    step: Step,
    action: &Wire,
    plan_kind: &str,
    stale: Option<u64>,
) -> Option<String> {
    let dir = scratch("resend");
    let opts = options(url, step, dir.clone());
    let key = Key::from_hex(KEY).unwrap();
    let http = reqwest::blocking::Client::builder().build().unwrap();
    let mut session = Session::new(&opts, &key, http, None, Vec::new());
    let answer = match stale {
        Some(nonce) => session.send_stale("stale", action, nonce),
        None => {
            let plan = match plan_kind {
                "entry" => session.plan_entry("entry", action, "resized"),
                "exit" => session.plan_exit("exit", action, &["allowed"]),
                code => session.plan_veto("probe", action, Some(code)),
            }
            .unwrap();
            session.send("order", action, &plan)
        }
    };
    let _ = std::fs::remove_dir_all(&dir);
    answer.ok().and_then(|answer| answer.code)
}

/// A fake Guard that previews `preview`, answers every `/exchange` with
/// `exchange`, and every decision lookup with `decision(nonce, calls)`.
fn guard_with(
    preview: Value,
    exchange: impl Fn(usize) -> Value + Send + Sync + 'static,
    decision: impl Fn(u64, usize) -> (u16, Value) + Send + Sync + 'static,
) -> (String, Calls) {
    fake_guard(move |path, _, calls| {
        let sends = calls.iter().filter(|(p, _)| p == "/exchange").count();
        if path == "/guard/preview" {
            (200, preview.clone())
        } else if path == "/exchange" {
            (200, exchange(sends))
        } else if path.starts_with("/guard/decision") {
            decision(last_nonce(calls), sends)
        } else {
            (404, json!({"error": "not here"}))
        }
    })
}

#[test]
fn a_proven_refusal_is_sent_again_at_most_four_times_with_new_nonces() {
    let (url, calls) = guard_with(
        entry_preview(),
        |_| rate_limited(SPENT),
        |nonce, _| (200, unsent(nonce)),
    );
    let code = run(&url, Step::Kill, &btc_entry(), "entry", None);
    assert_eq!(code.as_deref(), Some("rate_limited"));
    // Once, then four times again; each previewed again first.
    assert_eq!(exchanges(&calls), 5);
    let calls = calls.lock().unwrap();
    let previews = calls
        .iter()
        .filter(|(path, _)| path == "/guard/preview")
        .count();
    assert_eq!(previews, 5);
    let nonces: Vec<u64> = calls
        .iter()
        .filter(|(path, _)| path == "/exchange")
        .map(|(_, body)| {
            serde_json::from_str::<Value>(body).unwrap()["nonce"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert!(
        nonces.windows(2).all(|pair| pair[0] < pair[1]),
        "{nonces:?}"
    );
    // The same action every time.
    let actions: Vec<Value> = calls
        .iter()
        .filter(|(path, _)| path == "/exchange")
        .map(|(_, body)| serde_json::from_str::<Value>(body).unwrap()["action"].clone())
        .collect();
    assert!(actions.iter().all(|action| *action == actions[0]));
}

#[test]
fn once_forwarded_it_is_never_sent_again() {
    // Refused once (proven), then forwarded: two sends, no third.
    let (url, calls) = guard_with(
        entry_preview(),
        |sends| {
            if sends == 0 {
                rate_limited(SPENT)
            } else {
                json!({"status": "ok", "code": "resized", "requested_size": "0.01", "size": "0.00127",
                    "response": {"type": "order", "data": {"statuses": [{"filled": {"totalSz": "0.00127", "avgPx": "60300", "oid": 1}}]}}})
            }
        },
        |nonce, sends| {
            if sends <= 1 {
                (200, unsent(nonce))
            } else {
                (
                    200,
                    json!({"decision": {"nonce": nonce, "verdict": "resize", "code": "resized"}, "sent": [{"ok": true}]}),
                )
            }
        },
    );
    let code = run(&url, Step::Kill, &btc_entry(), "entry", None);
    assert_eq!(code.as_deref(), Some("resized"));
    assert_eq!(exchanges(&calls), 2);
}

#[test]
fn without_positive_proof_nothing_is_sent_again() {
    let cases: Vec<(&str, Box<DecisionFn>)> = vec![
        (
            "a sent event",
            Box::new(|nonce| {
                let mut decision = unsent(nonce);
                decision["sent"] = json!([{"ok": false, "reply": {}}]);
                (200, decision)
            }),
        ),
        (
            "no decision (404)",
            Box::new(|_| (404, json!({"error": "no decision"}))),
        ),
        (
            "no list of sends",
            Box::new(|nonce| {
                let mut decision = unsent(nonce);
                decision.as_object_mut().unwrap().remove("sent");
                (200, decision)
            }),
        ),
        (
            "another nonce's decision",
            Box::new(|nonce| (200, unsent(nonce + 1))),
        ),
        (
            "a forward in the decision",
            Box::new(|nonce| {
                let mut decision = unsent(nonce);
                decision["decision"]["forward"] = json!({"type": "order"});
                (200, decision)
            }),
        ),
        (
            "another code",
            Box::new(|nonce| {
                let mut decision = unsent(nonce);
                decision["decision"]["code"] = json!("venue_refused_leverage");
                (200, decision)
            }),
        ),
        (
            "a broken answer",
            Box::new(|_| (200, json!("not a decision"))),
        ),
    ];
    for (case, decision) in cases {
        let (url, calls) = guard_with(
            entry_preview(),
            |_| rate_limited(SPENT),
            move |nonce, _| decision(nonce),
        );
        let code = run(&url, Step::Kill, &btc_entry(), "entry", None);
        assert_eq!(code.as_deref(), Some("rate_limited"), "{case}");
        assert_eq!(exchanges(&calls), 1, "{case}: sent again");
    }
}

#[test]
fn a_forwarded_answer_is_never_looked_at_for_a_retry() {
    let (url, calls) = guard_with(
        entry_preview(),
        |_| {
            json!({"status": "ok", "code": "resized", "requested_size": "0.01", "size": "0.00127",
            "response": {"type": "order", "data": {"statuses": [{"error": "rate limited"}]}}})
        },
        |nonce, _| (200, unsent(nonce)),
    );
    run(&url, Step::Kill, &btc_entry(), "entry", None);
    assert_eq!(exchanges(&calls), 1);
}

#[test]
fn an_expected_refusal_is_sent_again_only_when_the_budget_hides_it() {
    // The kill switch's probe: refused for the budget of what a forward
    // sends, which a refused order never spends: not hidden, not again.
    let (url, calls) = guard_with(
        veto_preview("kill_switch"),
        |_| rate_limited(SPENT),
        |nonce, _| (200, unsent(nonce)),
    );
    run(&url, Step::Kill, &btc_entry(), "kill_switch", None);
    assert_eq!(exchanges(&calls), 1);
    // Refused for the account-read budget, before it was judged: again,
    // until it gets its own answer.
    let (url, calls) = guard_with(
        veto_preview("kill_switch"),
        |sends| {
            if sends == 0 {
                rate_limited(READ_SPENT)
            } else {
                json!({"status": "err", "code": "kill_switch", "response": "Zunder Guard veto [kill_switch]: pulled"})
            }
        },
        |nonce, _| (200, unsent(nonce)),
    );
    let code = run(&url, Step::Kill, &btc_entry(), "kill_switch", None);
    assert_eq!(code.as_deref(), Some("kill_switch"));
    assert_eq!(exchanges(&calls), 2);
    // The fee gate: Guard checks the fee after the budget, so a budget
    // refusal hides it: again.
    let (url, calls) = guard_with(
        veto_preview("fee_not_approved"),
        |sends| {
            if sends == 0 {
                rate_limited(SPENT)
            } else {
                json!({"status": "err", "code": "fee_not_approved", "response": "Zunder Guard veto [fee_not_approved]: approve"})
            }
        },
        |nonce, _| (200, unsent(nonce)),
    );
    let code = run(&url, Step::FeeGate, &btc_entry(), "fee_not_approved", None);
    assert_eq!(code.as_deref(), Some("fee_not_approved"));
    assert_eq!(exchanges(&calls), 2);
}

#[test]
fn an_exit_is_sent_again_and_a_stale_request_never() {
    let close = order(
        &[OrderSpec {
            reduce_only: true,
            tif: "Ioc",
            ..OrderSpec::limit_sell(0, "57000", "0.00127")
        }],
        "na",
    );
    let (url, calls) = guard_with(
        json!({"verdict": "allow", "code": "allowed", "forward": {}, "entry": null}),
        |sends| {
            if sends == 0 {
                rate_limited(SPENT)
            } else {
                json!({"status": "ok", "code": "allowed", "response": {"type": "order", "data": {"statuses": [{"filled": {"totalSz": "0.00127", "avgPx": "57000", "oid": 2}}]}}})
            }
        },
        |nonce, _| (200, unsent(nonce)),
    );
    let code = run(&url, Step::Close, &close, "exit", None);
    assert_eq!(code.as_deref(), Some("allowed"));
    assert_eq!(exchanges(&calls), 2);
    // S7's request signed with a nonce from before the restart: once.
    let (url, calls) = guard_with(
        json!({}),
        |_| rate_limited(READ_SPENT),
        |nonce, _| (200, unsent(nonce)),
    );
    run(&url, Step::RestartAfter, &cancel(0, 0), "", Some(1_000));
    assert_eq!(exchanges(&calls), 1);
}

#[test]
fn proof_needs_every_field() {
    assert!(proven_unsent(&unsent(7), 7));
    assert!(!proven_unsent(&unsent(7), 8));
    assert!(!proven_unsent(&Value::Null, 7));
    let mut no_forward_field = unsent(7);
    no_forward_field["decision"]
        .as_object_mut()
        .unwrap()
        .remove("forward");
    assert!(!proven_unsent(&no_forward_field, 7));
}

#[cfg(unix)]
#[test]
fn the_pacing_file_is_never_followed_or_trusted_blindly() {
    let dir = scratch("pace");
    let path = dir.join(LAST_SEND_FILE);
    // Missing, garbage, too long, or more than a minute ahead: none.
    assert_eq!(read_last_send(&dir), 0);
    std::fs::write(&path, "soon").unwrap();
    assert_eq!(read_last_send(&dir), 0);
    std::fs::write(&path, "1".repeat(40)).unwrap();
    assert_eq!(read_last_send(&dir), 0);
    std::fs::write(&path, (crate::now_ms() + 3_600_000).to_string()).unwrap();
    assert_eq!(read_last_send(&dir), 0);
    write_last_send(&dir, 1_234).unwrap();
    assert_eq!(read_last_send(&dir), 1_234);
    // A link planted at the name is replaced, never followed or read.
    let target = dir.join("victim");
    std::fs::write(&target, "keep").unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert_eq!(read_last_send(&dir), 0);
    write_last_send(&dir, 5_678).unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    assert_eq!(read_last_send(&dir), 5_678);
    // And one planted at the temporary name too.
    std::os::unix::fs::symlink(&target, dir.join(format!("{LAST_SEND_FILE}.new"))).unwrap();
    write_last_send(&dir, 9_999).unwrap();
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    assert_eq!(read_last_send(&dir), 9_999);
    std::fs::remove_dir_all(&dir).unwrap();
}
