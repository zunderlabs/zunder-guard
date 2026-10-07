// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The two outputs: machine JSON and a human report.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Value, json};

use crate::catalogue::{Category, Expect};
use crate::runner::{CaseResult, Status};

fn expect_label(expect: Expect) -> &'static str {
    match expect {
        Expect::Refused => "refused",
        Expect::NotFullSize => "not_forwarded_at_full_size",
        Expect::Handled => "handled_no_crash",
        Expect::NoLeak => "no_key_leak",
        Expect::StopKept { .. } => "cancel_refused_stop_kept",
    }
}

fn status_label(status: Status) -> &'static str {
    match status {
        Status::Pass => "pass",
        Status::Fail => "fail",
        Status::Skipped => "skipped",
    }
}

pub struct Summary {
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub skipped: usize,
}

pub fn summarise(results: &[CaseResult]) -> Summary {
    let mut summary = Summary {
        total: results.len(),
        pass: 0,
        fail: 0,
        skipped: 0,
    };
    for result in results {
        match result.status {
            Status::Pass => summary.pass += 1,
            Status::Fail => summary.fail += 1,
            Status::Skipped => summary.skipped += 1,
        }
    }
    summary
}

pub fn to_json(label: &str, now_ms: u64, results: &[CaseResult]) -> String {
    let summary = summarise(results);
    let cases: Vec<Value> = results
        .iter()
        .map(|result| {
            json!({
                "id": result.id,
                "category": result.category.label(),
                "rule": result.rule,
                "about": result.about,
                "expected_code": result.expected_code,
                "expect": expect_label(result.expect),
                "status": status_label(result.status),
                "observed_verdict": result.verdict.map(|verdict| verdict.to_string()),
                "observed_code": result.observed_code,
                "detail": result.detail,
            })
        })
        .collect();
    let value = json!({
        "schema": "zunder-redteam-report",
        "version": 1,
        "target": label,
        "generated_ms": now_ms,
        "summary": {
            "total": summary.total,
            "pass": summary.pass,
            "fail": summary.fail,
            "skipped": summary.skipped,
        },
        "cases": cases,
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_owned())
}

pub fn human(label: &str, results: &[CaseResult]) -> String {
    let summary = summarise(results);
    let mut out = String::new();
    let _ = writeln!(out, "Zunder Guard red-team suite");
    let _ = writeln!(out, "Target: {label}");
    let _ = writeln!(
        out,
        "{} cases: {} refused (pass), {} got through (FAIL), {} skipped",
        summary.total, summary.pass, summary.fail, summary.skipped
    );
    let _ = writeln!(out);

    // Group by category, preserving the catalogue's category order.
    let mut by_category: BTreeMap<usize, (Category, Vec<&CaseResult>)> = BTreeMap::new();
    let order = [
        Category::Authentication,
        Category::FundMovement,
        Category::Sizing,
        Category::Stops,
        Category::Leverage,
        Category::Markets,
        Category::Halts,
        Category::BuilderField,
        Category::Robustness,
        Category::AgentContent,
    ];
    for result in results {
        let index = order
            .iter()
            .position(|category| *category == result.category)
            .unwrap_or(usize::MAX);
        by_category
            .entry(index)
            .or_insert_with(|| (result.category, Vec::new()))
            .1
            .push(result);
    }

    for (_, (category, cases)) in by_category {
        let _ = writeln!(out, "== {} ==", category.label());
        for result in cases {
            let mark = match result.status {
                Status::Pass => "ok  ",
                Status::Fail => "FAIL",
                Status::Skipped => "skip",
            };
            let observed = match (&result.verdict, &result.observed_code) {
                (Some(verdict), Some(code)) => format!("{verdict} [{code}]"),
                (Some(verdict), None) => verdict.to_string(),
                _ => "-".to_owned(),
            };
            let _ = writeln!(
                out,
                "  {mark}  {:<34}  {}",
                result.id,
                match result.status {
                    Status::Skipped => result.detail.clone(),
                    _ => format!("want {}; got {observed}", expect_label(result.expect)),
                }
            );
            let _ = writeln!(out, "         {}", result.about);
            let _ = writeln!(
                out,
                "         rule: {}  |  expected: {}",
                result.rule, result.expected_code
            );
        }
        let _ = writeln!(out);
    }

    if summary.fail > 0 {
        let _ = writeln!(
            out,
            "{} attack(s) were NOT refused. Against the naive mock this is expected and",
            summary.fail
        );
        let _ = writeln!(
            out,
            "proves the suite works. Against a real Guard every one is a bug to fix."
        );
    } else {
        let _ = writeln!(out, "Every applicable attack was refused.");
    }
    out
}
