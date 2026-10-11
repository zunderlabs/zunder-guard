// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Runs the catalogue against a target and judges each case.

use crate::catalogue::{Case, Category, Expect, Probe, Requires};
use crate::target::{Read, Reply, Target, Verdict};

/// What kind of target the suite is pointed at. Decides which cases can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Mock,
    Paper,
    Testnet,
    Mainnet,
    Unknown,
}

impl TargetKind {
    pub fn from_mode(mode: Option<&str>) -> Self {
        match mode {
            Some("paper") => TargetKind::Paper,
            Some("testnet") => TargetKind::Testnet,
            Some("mainnet") => TargetKind::Mainnet,
            _ => TargetKind::Unknown,
        }
    }
}

/// What the target can offer, so the runner knows which cases are meaningful.
#[derive(Debug, Clone, Copy)]
pub struct Profile {
    pub kind: TargetKind,
    pub allowlist_set: bool,
    pub halted: bool,
    /// The target manages a HIP-3 dex (the catalogue's context names it).
    pub hip3: bool,
    /// ...and that dex lists a halted market.
    pub hip3_halted: bool,
}

impl Profile {
    pub fn mock() -> Self {
        // The mock forwards everything, so every case is meaningful: it is
        // the demonstrator that proves the suite bites.
        Self {
            kind: TargetKind::Mock,
            allowlist_set: true,
            halted: true,
            hip3: true,
            hip3_halted: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The attack was refused as required.
    Pass,
    /// The attack got through: a problem the target must fix.
    Fail,
    /// The attack could not be run against this target.
    Skipped,
}

#[derive(Debug, Clone)]
pub struct CaseResult {
    pub id: &'static str,
    pub category: Category,
    pub rule: &'static str,
    pub about: &'static str,
    pub expected_code: &'static str,
    pub expect: Expect,
    pub status: Status,
    pub verdict: Option<Verdict>,
    pub observed_code: Option<String>,
    pub detail: String,
}

fn skip_reason(requires: Requires, profile: &Profile) -> Option<&'static str> {
    match requires {
        Requires::Nothing => None,
        Requires::Fills => {
            if profile.kind == TargetKind::Paper {
                Some("needs open positions; paper Guard holds none")
            } else {
                None
            }
        }
        Requires::Allowlist => {
            if profile.allowlist_set {
                None
            } else {
                Some("needs a market allowlist; policy allows all markets")
            }
        }
        Requires::Halt => {
            if profile.halted {
                None
            } else {
                Some("needs the engine to be halted first")
            }
        }
        Requires::Hip3 => {
            if profile.hip3 {
                None
            } else {
                Some("needs a HIP-3 dex the rules name; the target manages none")
            }
        }
        Requires::Hip3Halted => {
            if profile.hip3 && profile.hip3_halted {
                None
            } else {
                Some("needs a halted market on a HIP-3 dex the rules name")
            }
        }
    }
}

/// Run every case in order, judging each.
pub fn run(target: &mut dyn Target, profile: &Profile, cases: &[Case]) -> Vec<CaseResult> {
    cases
        .iter()
        .map(|case| run_one(target, profile, case))
        .collect()
}

fn run_one(target: &mut dyn Target, profile: &Profile, case: &Case) -> CaseResult {
    if let Some(reason) = skip_reason(case.requires, profile) {
        return CaseResult {
            id: case.id,
            category: case.category,
            rule: case.rule,
            about: case.about,
            expected_code: case.expected_code,
            expect: case.expect,
            status: Status::Skipped,
            verdict: None,
            observed_code: None,
            detail: reason.to_owned(),
        };
    }

    if let Expect::StopKept { oid } = case.expect {
        // Readable open orders without the stop: there is nothing to keep
        // on this target, so the case is not run (and not reported as
        // unreadable).
        let original = match target.open_orders() {
            Some(orders) => match stop_of(&orders, oid) {
                Some(stop) => Some(stop),
                None => {
                    return CaseResult {
                        id: case.id,
                        category: case.category,
                        rule: case.rule,
                        about: case.about,
                        expected_code: case.expected_code,
                        expect: case.expect,
                        status: Status::Skipped,
                        verdict: None,
                        observed_code: None,
                        detail: format!("order {oid} is not resting before the case"),
                    };
                }
            },
            None => None,
        };
        let (status, read, detail) = stop_kept(target, &case.probe, oid, original);
        return CaseResult {
            id: case.id,
            category: case.category,
            rule: case.rule,
            about: case.about,
            expected_code: case.expected_code,
            expect: case.expect,
            status,
            verdict: Some(read.verdict),
            observed_code: read.code.clone(),
            detail: trim(&detail),
        };
    }
    let (read, healthy) = probe(target, &case.probe);
    let status = judge(case.expect, &read, healthy, &case.probe);
    CaseResult {
        id: case.id,
        category: case.category,
        rule: case.rule,
        about: case.about,
        expected_code: case.expected_code,
        expect: case.expect,
        status,
        verdict: Some(read.verdict),
        observed_code: read.code.clone(),
        detail: trim(&read.detail),
    }
}

/// Send a probe and read the (last) reply, plus whether the target is still
/// healthy afterwards.
fn probe(target: &mut dyn Target, probe: &Probe) -> (Read, bool) {
    let reply = match probe {
        Probe::Exchange(body) => target.exchange(body),
        Probe::ExchangeText(text) => target.exchange(text.as_bytes()),
        Probe::Info(body) => target.info(body),
        Probe::Ws(frame) => target.ws_action(frame),
        Probe::Sequence(bodies) => {
            let mut last = Reply::NoAnswer("empty sequence".to_owned());
            for body in bodies {
                last = target.exchange(body);
            }
            last
        }
        Probe::Flood { body, count } => {
            let mut rejected = 0usize;
            let mut last = Reply::NoAnswer("no requests".to_owned());
            for _ in 0..*count {
                last = target.exchange(body);
                if matches!(Read::of(&last).verdict, Verdict::Rejected | Verdict::Vetoed) {
                    rejected += 1;
                }
            }
            Reply::NoAnswer(format!(
                "{rejected}/{count} rejected; last: {}",
                Read::of(&last).detail
            ))
        }
        Probe::HugeBody { size } => target.exchange(&vec![b'x'; *size]),
        Probe::Slowloris => target.slowloris(),
        Probe::RawPost { path, body } => target.raw_post(path, body),
    };
    let read = Read::of(&reply);
    let healthy = target.healthy();
    (read, healthy)
}

fn judge(expect: Expect, read: &Read, healthy: bool, _probe: &Probe) -> Status {
    let pass = match expect {
        Expect::Refused => matches!(read.verdict, Verdict::Vetoed | Verdict::Rejected),
        Expect::NotFullSize => read.verdict != Verdict::Allowed,
        Expect::Handled => healthy,
        Expect::NoLeak => !leaks_key(&read.detail),
        // Judged in `stop_kept`.
        Expect::StopKept { .. } => false,
    };
    if pass { Status::Pass } else { Status::Fail }
}

/// The order `oid` in `orders` as `(trigger, size)`, both as written.
fn stop_of(orders: &[serde_json::Value], oid: u64) -> Option<(String, String)> {
    let order = orders
        .iter()
        .find(|order| order["oid"].as_u64() == Some(oid))?;
    Some((
        order["triggerPx"].as_str()?.to_owned(),
        order["sz"].as_str()?.to_owned(),
    ))
}

/// The `StopKept` judgement: the first request (the cancel) refused, and
/// the stop aimed at (`original`, its trigger and size before the case)
/// still resting afterwards with its trigger and size unchanged (read from
/// the open orders). Whatever else was forwarded then only adds to it. A
/// target that cannot show its open orders (`original` is `None`: the mock)
/// passes only when every request was refused.
fn stop_kept(
    target: &mut dyn Target,
    probe: &Probe,
    oid: u64,
    original: Option<(String, String)>,
) -> (Status, Read, String) {
    let Probe::Sequence(bodies) = probe else {
        let read = Read::of(&Reply::NoAnswer("not a sequence".to_owned()));
        return (
            Status::Fail,
            read,
            "a StopKept case needs a sequence".to_owned(),
        );
    };
    let reads: Vec<Read> = bodies
        .iter()
        .map(|body| Read::of(&target.exchange(body)))
        .collect();
    let Some(first) = reads.first() else {
        let read = Read::of(&Reply::NoAnswer("empty sequence".to_owned()));
        return (Status::Fail, read, "empty sequence".to_owned());
    };
    let refused = |read: &Read| matches!(read.verdict, Verdict::Vetoed | Verdict::Rejected);
    let last = reads.last().unwrap_or(first).clone();
    if !refused(first) {
        return (
            Status::Fail,
            first.clone(),
            format!("the cancel was not refused: {}", first.detail),
        );
    }
    let cancel_code = first.code.clone().unwrap_or_default();
    let Some((trigger, size)) = original else {
        // Nothing to compare: only a sequence refused throughout passes.
        return if reads.iter().all(refused) {
            (
                Status::Pass,
                last,
                format!(
                    "cancel refused ({cancel_code}); the rest refused too; open orders not readable"
                ),
            )
        } else {
            (
                Status::Fail,
                last,
                format!(
                    "a request was forwarded and order {oid} could not be read to check it stayed"
                ),
            )
        };
    };
    let after = target.open_orders().unwrap_or_default();
    match stop_of(&after, oid) {
        Some((now_trigger, now_size)) if now_trigger == trigger && now_size == size => (
            Status::Pass,
            last,
            format!(
                "cancel refused ({cancel_code}); order {oid} still rests at {trigger} for {size}"
            ),
        ),
        Some((now_trigger, now_size)) => (
            Status::Fail,
            last,
            format!(
                "order {oid} changed from {trigger} for {size} to {now_trigger} for {now_size}"
            ),
        ),
        None => (
            Status::Fail,
            last,
            format!("order {oid} (the stop at {trigger}) no longer rests"),
        ),
    }
}

/// A crude scan for a 64-hex-digit secret (a private key) in a reply.
fn leaks_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut run = 0usize;
    for &byte in bytes {
        if byte.is_ascii_hexdigit() {
            run += 1;
            if run >= 64 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn trim(text: &str) -> String {
    const MAX: usize = 300;
    if text.len() <= MAX {
        return text.to_owned();
    }
    let end = text
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= MAX)
        .last()
        .unwrap_or(0);
    format!("{}…", &text[..end])
}
