// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `zunder-guard status`: `/guard/status` for a person, one fact a line.
//! Reads only; the JSON is the contract (`docs/guard.md`), this is a view
//! of it that tolerates missing fields.

use serde_json::Value;

fn text(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "-".to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

/// The lines `zunder-guard status` prints for a `/guard/status` answer.
pub fn describe(status: &Value) -> Vec<String> {
    let get = |pointer: &str| status.pointer(pointer);
    let mut lines = vec![format!(
        "Zunder Guard {} in {} mode, account {} on {}",
        text(get("/version")),
        text(get("/mode")),
        text(get("/account")),
        text(get("/network")),
    )];
    match get("/killed") {
        Some(Value::String(reason)) => lines.push(format!(
            "KILL SWITCH LATCHED: {reason} (opens nothing; remove the kill file and restart to release)"
        )),
        _ => lines.push("kill switch: off".to_owned()),
    }
    lines.push(format!(
        "risk: {}{}",
        text(get("/risk/state")),
        if get("/risk/journal_ready") == Some(&Value::Bool(false)) {
            " (the risk journal does not allow new positions)"
        } else {
            ""
        }
    ));
    lines.push(format!(
        "equity: {} USDC (cap {}), {} position(s), {} open order(s)",
        text(get("/equity")),
        text(get("/equity_cap")),
        text(get("/positions")),
        text(get("/open_orders")),
    ));
    lines.push(format!("fee: {}", fee_line(get("/fee"))));
    if let Some(licence) = get("/licence") {
        lines.push(format!("licence: {}", licence_line(licence)));
    }
    lines.push(format!("rules: {}", text(get("/rules"))));
    let clients = get("/clients")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    lines.push(format!("clients: {clients}"));
    lines.push(format!(
        "last sync: {} ms; last error: {}",
        text(get("/last_sync_ms")),
        text(get("/last_error"))
    ));
    if get("/budgets").is_some() {
        lines.push(format!(
            "ip_share {}: {} of the IP address's 1,200 request weight a minute; sync every {} ms, bots' requests {} a second (burst {}), reserve for protection {} a minute",
            text(get("/ip_share")),
            text(get("/budgets/weight_per_minute")),
            text(get("/budgets/sync_interval_ms")),
            text(get("/budgets/requests/per_second")),
            text(get("/budgets/requests/burst")),
            text(get("/budgets/reserve_per_minute")),
        ));
    }
    if get("/journal_broken") == Some(&Value::Bool(true)) {
        lines.push(
            "DECISION JOURNAL BROKEN: nothing is forwarded until a restart on an intact journal"
                .to_owned(),
        );
    }
    let count = |pointer: &str| get(pointer).and_then(Value::as_u64).unwrap_or(0);
    let (dropped, busy) = (count("/journal_dropped"), count("/journal_busy"));
    if dropped > 0 || busy > 0 {
        lines.push(format!(
            "decision journal's writer fell behind: {dropped} record(s) not written, {busy} request(s) refused"
        ));
    }
    if get("/emergency_log_stalled") == Some(&Value::Bool(true)) {
        lines.push(
            "EMERGENCY LOG STALLED: a write to it has not finished; protective actions go out unrecorded"
                .to_owned(),
        );
    }
    let alerts = get("/alerts").and_then(Value::as_array);
    match alerts {
        Some(alerts) if !alerts.is_empty() => {
            lines.push(format!("alerts ({}):", alerts.len()));
            lines.extend(
                alerts
                    .iter()
                    .map(|alert| format!("  - {}", text(Some(alert)))),
            );
        }
        _ => lines.push("alerts: none".to_owned()),
    }
    lines
}

fn licence_line(licence: &Value) -> String {
    let renewal = if licence["auto_update"] == true {
        "; renewed automatically"
    } else {
        ""
    };
    match licence["state"].as_str() {
        Some("active") => format!(
            "{}, until {} ({} day(s) left){renewal}",
            text(licence.get("licensee")),
            licence["expires_at_ms"]
                .as_i64()
                .map_or_else(|| "?".to_owned(), crate::guard::utc_text),
            text(licence.get("days_left")),
        ),
        Some("not_used") => format!("not used ({}){renewal}", text(licence.get("error"))),
        Some("none") => format!("none{renewal}"),
        _ => text(Some(licence)),
    }
}

fn fee_line(fee: Option<&Value>) -> String {
    let Some(fee) = fee else {
        return "-".to_owned();
    };
    let get = |key: &str| fee.get(key);
    match get("mode").and_then(Value::as_str) {
        Some("builder") => {
            let approval = text(fee.pointer("/approval/state"));
            let mut line = format!(
                "{} builder fee (builder {}), approval {approval}",
                text(get("rate")),
                text(get("address")),
            );
            if get("paper") == Some(&Value::Bool(true)) {
                line.push_str("; paper mode: reported, never charged or blocking");
            } else if get("entries_blocked") == Some(&Value::Bool(true)) {
                line.push_str(&format!(
                    "; NEW ENTRIES REFUSED until approved at {} (exits are never blocked)",
                    text(get("approve_url"))
                ));
            } else if get("charged") == Some(&Value::Bool(true)) {
                line.push_str("; charged on every order Guard sends");
            }
            line
        }
        Some("fee_free") => format!("none (fee-free licence: {})", text(get("licensee"))),
        Some("off") => format!("off ({})", text(get("why"))),
        _ => text(Some(fee)),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_blocked_fee_and_alerts_are_spelled_out() {
        let status = json!({
            "version": "0.1.0", "mode": "mainnet", "network": "mainnet",
            "account": "0xabc", "killed": null,
            "risk": {"state": "active", "journal_ready": true},
            "equity": "1000", "equity_cap": "2000", "positions": 1, "open_orders": 2,
            "fee": {"mode": "builder", "address": "0xbb", "fee_tenths_bp": 20, "rate": "0.02%",
                "approval": {"state": "not_approved"}, "charged": false, "paper": false,
                "entries_blocked": true, "approve_url": "https://zunderlabs.com/approve"},
            "rules": "zr1_x", "clients": ["0x1", "0x2"], "last_sync_ms": 5, "last_error": null,
            "alerts": ["one"], "journal_broken": false,
        });
        let lines = describe(&status);
        assert_eq!(
            lines[0],
            "Zunder Guard 0.1.0 in mainnet mode, account 0xabc on mainnet"
        );
        assert!(lines.contains(&"kill switch: off".to_owned()));
        assert!(lines.contains(&"clients: 2".to_owned()));
        let fee = lines.iter().find(|line| line.starts_with("fee:")).unwrap();
        assert!(!lines.iter().any(|line| line.starts_with("licence:")));
        assert!(fee.contains("0.02% builder fee"), "{fee}");
        assert!(
            fee.contains("NEW ENTRIES REFUSED until approved at https://zunderlabs.com/approve")
        );
        assert!(lines.contains(&"  - one".to_owned()));
        // No budgets in the answer (an older Guard): no line for them.
        assert!(!lines.iter().any(|line| line.starts_with("ip_share")));
    }

    #[test]
    fn the_ip_share_and_its_budgets_are_one_line() {
        let status = json!({"ip_share": "0.5", "budgets": {"weight_per_minute": 600,
            "sync_interval_ms": 10910, "requests": {"per_second": "1.53", "burst": 46},
            "reserve_per_minute": 51}, "alerts": []});
        let lines = describe(&status);
        assert!(lines.contains(&"ip_share 0.5: 600 of the IP address's 1,200 request weight a minute; sync every 10910 ms, bots' requests 1.53 a second (burst 46), reserve for protection 51 a minute".to_owned()), "{lines:?}");
    }

    #[test]
    fn a_kill_and_a_broken_journal_stand_out() {
        let status = json!({"killed": "manual", "journal_broken": true,
            "journal_dropped": 3, "journal_busy": 1, "emergency_log_stalled": true,
            "fee": {"mode": "off", "why": "testnet: no builder fee"}, "alerts": [],
            "licence": {"state": "active", "licensee": "Example GmbH",
                "expires_at_ms": 1_798_761_600_000_i64, "days_left": 3, "auto_update": true}});
        let lines = describe(&status);
        assert!(lines[1].starts_with("KILL SWITCH LATCHED: manual"));
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("DECISION JOURNAL BROKEN"))
        );
        assert!(lines.contains(
            &"decision journal's writer fell behind: 3 record(s) not written, 1 request(s) refused"
                .to_owned()
        ));
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("EMERGENCY LOG STALLED"))
        );
        assert!(lines.contains(&"fee: off (testnet: no builder fee)".to_owned()));
        assert!(lines.contains(
            &"licence: Example GmbH, until 2027-01-01 00:00 UTC (3 day(s) left); renewed automatically"
                .to_owned()
        ));
        assert!(lines.contains(&"alerts: none".to_owned()));
    }
}
