// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Deposits, withdrawals and transfers: which entries of Hyperliquid's
//! non-funding ledger (`userNonFundingLedgerUpdates`) moved money into or
//! out of the equity Guard judges by, the USDC perp accounts of the dexes
//! it manages, and by how much. External cash flows are excluded from
//! trading PnL: withdrawals are not losses and deposits are not gains.
//! See `docs/guard.md#deposits-and-withdrawals`.
//!
//! Ledger entries are classified on the combined perpetual-account basis
//! of every dex Guard manages:
//!
//! - in: `deposit`, `vaultWithdraw` (`netWithdrawnUsd`), `vaultDistribution`,
//!   `rewardsClaim`, a transfer from another account, money moved from spot
//!   to perps (`accountClassTransfer` with `toPerp`), a `send` into one of
//!   the managed dexes from outside them;
//! - out: `withdraw`, `vaultDeposit`, `vaultCreate` (with its fee), a
//!   transfer to another account (with its fee), money moved from perps to
//!   spot, a `send` out of the managed dexes (with its fee);
//! - for a vault's own ledger the vault's side of the same entries;
//! - nothing: `liquidation` (trading), `spotTransfer` (spot only),
//!   `spotGenesis`, `cStakingTransfer`, `borrowLend`, a `send` between two
//!   managed dexes (less its fee, which is money out).

use std::{collections::BTreeSet, str::FromStr};

use rust_decimal::Decimal;
use serde_json::Value;

use crate::sign::Address;

/// One flow: when the venue booked it (epoch ms), its amount (positive in,
/// negative out), and an id for it (the entry's hash and type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerFlow {
    pub time_ms: i64,
    pub amount: Decimal,
    pub id: String,
    /// The dex whose account it moved (`""` for the main dex): for a
    /// `send`, the dex money came into, or went out of.
    pub dex: String,
    /// A `send` between two of the managed dexes (its amount the fee, or
    /// nothing): a read of the dexes on either side of it shows the money
    /// twice or not at all.
    pub between: bool,
}

fn decimal(value: &Value) -> Option<Decimal> {
    value.as_str().and_then(|text| Decimal::from_str(text).ok())
}

/// The flow a ledger entry is for the equity of `user`'s USDC perp
/// accounts on `dexes` (`""` for the main dex), if any.
pub fn ledger_flow(update: &Value, user: Address, dexes: &BTreeSet<String>) -> Option<LedgerFlow> {
    let time_ms = update.get("time")?.as_i64()?;
    let delta = update.get("delta")?;
    let kind = delta.get("type")?.as_str()?;
    let me = |field: &str| {
        delta
            .get(field)
            .and_then(Value::as_str)
            .and_then(Address::from_hex)
            == Some(user)
    };
    let usdc = || decimal(&delta["usdc"]);
    let fee = decimal(&delta["fee"]).unwrap_or(Decimal::ZERO);
    let main = dexes.contains("");
    // A dex field that is missing names no account Guard manages (as the
    // website replay reads it).
    let managed = |field: &str| {
        delta
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|dex| dexes.contains(dex))
    };
    let mut dex = String::new();
    let mut between = false;
    let amount = match kind {
        "deposit" if main => usdc()?,
        "withdraw" if main => -usdc()?,
        "accountClassTransfer" if main => {
            let usdc = usdc()?;
            if delta["toPerp"].as_bool() == Some(true) {
                usdc
            } else {
                -usdc
            }
        }
        "subAccountTransfer" | "internalTransfer" if main => {
            let usdc = usdc()?;
            let fee = if kind == "internalTransfer" {
                fee
            } else {
                Decimal::ZERO
            };
            match (me("user"), me("destination")) {
                (false, true) => usdc,
                (true, false) => -usdc.checked_add(fee)?,
                _ => return None,
            }
        }
        "send" => {
            let value = decimal(&delta["usdcValue"])?;
            let mut net = Decimal::ZERO;
            let side = |field: &str| {
                delta
                    .get(field)
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned()
            };
            if me("user") && managed("sourceDex") {
                net = net.checked_sub(value.checked_add(fee)?)?;
                dex = side("sourceDex");
            }
            if me("destination") && managed("destinationDex") {
                between = net < Decimal::ZERO;
                net = net.checked_add(value)?;
                if net > Decimal::ZERO {
                    dex = side("destinationDex");
                }
            }
            net
        }
        "vaultCreate" if main => {
            let usdc = usdc()?;
            if me("vault") {
                usdc
            } else {
                -usdc.checked_add(fee)?
            }
        }
        "vaultDeposit" if main => {
            let usdc = usdc()?;
            if me("vault") { usdc } else { -usdc }
        }
        "vaultWithdraw" if main => {
            if me("vault") {
                -decimal(&delta["requestedUsd"])?
            } else {
                decimal(&delta["netWithdrawnUsd"])?
            }
        }
        "vaultDistribution" if main => {
            let usdc = usdc()?;
            if me("vault") { -usdc } else { usdc }
        }
        "vaultLeaderCommission" if main && me("user") => usdc()?,
        "rewardsClaim" if main => decimal(&delta["amount"])?,
        _ => return None,
    };
    if amount == Decimal::ZERO && !between {
        return None;
    }
    let hash = update.get("hash").and_then(Value::as_str).unwrap_or("");
    Some(LedgerFlow {
        time_ms,
        amount,
        id: format!("{hash}:{time_ms}:{kind}"),
        dex,
        between,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rust_decimal::dec;
    use serde_json::json;

    use super::*;

    const ME: &str = "0x5e9ee1089755c3435139848e47e6635505d5a13a";
    const OTHER: &str = "0x0000000000000000000000000000000000000001";

    fn me() -> Address {
        Address::from_hex(ME).unwrap()
    }

    fn entry(delta: Value) -> Value {
        json!({"time": 1_000, "hash": "0xabc", "delta": delta})
    }

    fn dexes(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn flow(delta: Value, names: &[&str]) -> Option<Decimal> {
        ledger_flow(&entry(delta), me(), &dexes(names)).map(|flow| flow.amount)
    }

    #[test]
    fn deposits_withdrawals_and_transfers_move_the_perp_equity() {
        let main = &[""];
        assert_eq!(
            flow(json!({"type": "deposit", "usdc": "500.0"}), main),
            Some(dec!(500))
        );
        assert_eq!(
            flow(
                json!({"type": "withdraw", "usdc": "1000", "nonce": 1, "fee": "1"}),
                main
            ),
            Some(dec!(-1000))
        );
        // Spot to perps in, perps to spot out.
        assert_eq!(
            flow(
                json!({"type": "accountClassTransfer", "usdc": "20", "toPerp": true}),
                main
            ),
            Some(dec!(20))
        );
        assert_eq!(
            flow(
                json!({"type": "accountClassTransfer", "usdc": "20", "toPerp": false}),
                main
            ),
            Some(dec!(-20))
        );
        // To another account, with its fee: out 101; from another: in 100.
        assert_eq!(
            flow(
                json!({"type": "internalTransfer", "usdc": "100", "user": ME, "destination": OTHER, "fee": "1"}),
                main
            ),
            Some(dec!(-101))
        );
        assert_eq!(
            flow(
                json!({"type": "internalTransfer", "usdc": "100", "user": OTHER, "destination": ME, "fee": "1"}),
                main
            ),
            Some(dec!(100))
        );
        assert_eq!(
            flow(
                json!({"type": "subAccountTransfer", "usdc": "50", "user": ME, "destination": OTHER}),
                main
            ),
            Some(dec!(-50))
        );
        // Vaults, seen from a depositor.
        assert_eq!(
            flow(
                json!({"type": "vaultDeposit", "vault": OTHER, "usdc": "30"}),
                main
            ),
            Some(dec!(-30))
        );
        assert_eq!(
            flow(
                json!({"type": "vaultWithdraw", "vault": OTHER, "user": ME, "requestedUsd": "31", "netWithdrawnUsd": "30.5"}),
                main
            ),
            Some(dec!(30.5))
        );
        assert_eq!(
            flow(json!({"type": "rewardsClaim", "amount": "2"}), main),
            Some(dec!(2))
        );
        // Trading and spot-only entries are no flow.
        assert_eq!(
            flow(json!({"type": "liquidation", "accountValue": "10"}), main),
            None
        );
        assert_eq!(
            flow(
                json!({"type": "spotTransfer", "token": "USDC", "amount": "5", "usdcValue": "5", "user": ME, "destination": OTHER}),
                main
            ),
            None
        );
        // Entries without a usable amount or time are none either.
        assert_eq!(flow(json!({"type": "deposit"}), main), None);
        assert!(
            ledger_flow(
                &json!({"delta": {"type": "deposit", "usdc": "1"}}),
                me(),
                &dexes(main)
            )
            .is_none()
        );
    }

    #[test]
    fn a_send_counts_only_across_the_managed_dexes() {
        // From the main dex to xyz, both managed: only the fee (1) leaves.
        let send = |source: &str, destination: &str| {
            json!({"type": "send", "user": ME, "destination": ME, "sourceDex": source,
                "destinationDex": destination, "token": "USDC", "amount": "100", "usdcValue": "100", "fee": "1"})
        };
        assert_eq!(flow(send("", "xyz"), &["", "xyz"]), Some(dec!(-1)));
        // A transfer between two managed dexes: its fee, booked on the
        // source, marked as between them; one with no fee still counts.
        let inner = ledger_flow(&entry(send("", "xyz")), me(), &dexes(&["", "xyz"])).unwrap();
        assert_eq!((inner.dex.as_str(), inner.between), ("", true));
        let free = json!({"type": "send", "user": ME, "destination": ME, "sourceDex": "xyz",
            "destinationDex": "", "usdcValue": "100", "fee": "0"});
        let free = ledger_flow(&entry(free), me(), &dexes(&["", "xyz"])).unwrap();
        assert_eq!(
            (free.amount, free.dex.as_str(), free.between),
            (Decimal::ZERO, "xyz", true)
        );
        // Into a managed dex from an unmanaged one: not between.
        let from_abc = ledger_flow(&entry(send("abc", "xyz")), me(), &dexes(&["", "xyz"])).unwrap();
        assert_eq!((from_abc.dex.as_str(), from_abc.between), ("xyz", false));
        // To a dex Guard does not manage: 101 out; back from it: 100 in.
        assert_eq!(flow(send("", "abc"), &["", "xyz"]), Some(dec!(-101)));
        assert_eq!(flow(send("abc", ""), &["", "xyz"]), Some(dec!(100)));
        // Between two dexes Guard does not manage: nothing.
        assert_eq!(flow(send("abc", "def"), &["", "xyz"]), None);
        // From another account into xyz: 100 in, on xyz.
        let from_other = json!({"type": "send", "user": OTHER, "destination": ME, "sourceDex": "",
            "destinationDex": "xyz", "usdcValue": "100", "fee": "1"});
        assert_eq!(flow(from_other.clone(), &["", "xyz"]), Some(dec!(100)));
        let on = ledger_flow(&entry(from_other), me(), &dexes(&["", "xyz"])).unwrap();
        assert_eq!(on.dex, "xyz");
        // Out of xyz to an unmanaged dex: on xyz. A dex field missing
        // names no managed account.
        let out = ledger_flow(&entry(send("xyz", "abc")), me(), &dexes(&["", "xyz"])).unwrap();
        assert_eq!((out.amount, out.dex.as_str()), (dec!(-101), "xyz"));
        let unnamed = json!({"type": "send", "user": ME, "destination": OTHER,
            "usdcValue": "100", "fee": "1"});
        assert_eq!(flow(unnamed, &["", "xyz"]), None);
    }

    #[test]
    fn a_flow_carries_its_time_and_an_id() {
        let flow = ledger_flow(
            &entry(json!({"type": "deposit", "usdc": "5"})),
            me(),
            &dexes(&[""]),
        )
        .unwrap();
        assert_eq!(flow.time_ms, 1_000);
        assert_eq!(flow.id, "0xabc:1000:deposit");
    }
}
