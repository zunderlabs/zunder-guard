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
//!   managed dexes (less its fee, which is money out);
//! - unknown ([`LedgerProblem`]): any other type, and an entry without its
//!   time, hash or type, with an amount that is not a non-negative decimal
//!   string, or without a field its flow needs (the fee the account pays
//!   among them). Guard cannot tell whether it moved money, so it refuses
//!   new positions for the day rather than guess (`docs/guard.md`,
//!   "Deposits and withdrawals").

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

/// What Guard does with a ledger entry it cannot account for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Treated {
    /// How much it moved cannot be read (no USD amount, a malformed or
    /// missing field of a known type): new positions are refused for the
    /// day it was seen.
    Unread,
    /// A type Guard does not know whose USD amount (`usdc`, else
    /// `usdcValue`) reads, and which the account did not pay as far as its
    /// addresses tell: applied as money in, never counted as a trading
    /// gain, so a loss it could hide still counts. Treating a payment as
    /// money in only makes the stops stricter.
    Inflow(Box<LedgerFlow>),
    /// A type Guard does not know that the account paid (it names the
    /// account as the sender and another as the receiver), of this USD
    /// amount: left in the equity as the loss it shows.
    LeftAsLoss(Decimal),
}

/// A ledger entry Guard cannot account for: its type is not one Guard
/// knows, or a field it needs is missing or malformed (`docs/guard.md`,
/// "Deposits and withdrawals").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerProblem {
    /// The entry's type, as the venue names it, when it names one.
    pub kind: Option<String>,
    /// When the venue booked it (epoch ms), when it says.
    pub time_ms: Option<i64>,
    /// An id for it: as a flow's (hash, time and type) when it has them,
    /// else the entry itself (cut to 200 characters).
    pub id: String,
    pub why: String,
    /// What Guard does with it.
    pub treated: Treated,
}

impl std::fmt::Display for LedgerProblem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            Some(kind) => write!(
                formatter,
                "ledger entry of type {kind} ({}): {}",
                self.id, self.why
            ),
            None => write!(formatter, "ledger entry {}: {}", self.id, self.why),
        }
    }
}

/// The amount fields a ledger entry may carry: each, when present, must be
/// a non-negative decimal string (signs come from the entry's type).
const AMOUNT_FIELDS: [&str; 6] = [
    "fee",
    "usdc",
    "usdcValue",
    "requestedUsd",
    "netWithdrawnUsd",
    "amount",
];

/// The checks every ledger entry passes before it is read, on both paths
/// (a flow applied to the account stops, and a ledger read to reconstruct
/// one: [`crate::flow_value::valid_ledger`]): a time, a hash, a type, and
/// every amount it carries a non-negative decimal string. The entry's
/// type when it passes, why not otherwise.
pub fn check_entry(update: &Value) -> Result<&str, String> {
    if update["time"].as_i64().is_none() {
        return Err("no time".into());
    }
    if update["hash"].as_str().is_none_or(str::is_empty) {
        return Err("no hash".into());
    }
    let delta = &update["delta"];
    let kind = delta["type"].as_str().ok_or("no type")?;
    for key in AMOUNT_FIELDS {
        if let Some(value) = delta.get(key)
            && decimal(value).is_none_or(|value| value < Decimal::ZERO)
        {
            return Err(format!("{key} is not a non-negative decimal string"));
        }
    }
    Ok(kind)
}

/// The flow a ledger entry is for the equity of `user`'s USDC perp
/// accounts on `dexes` (`""` for the main dex), if any.
///
/// `Ok(None)`: an entry Guard knows that moved none of that money
/// (trading, spot only, another account's, a transfer between two of the
/// managed dexes without a fee). `Err`: an entry Guard cannot account for:
/// a type it does not know (refused, never skipped: Hyperliquid adds types,
/// and one may move money), or a field it needs missing or malformed, a fee
/// the account pays among them (never taken as zero).
pub fn classify(
    update: &Value,
    user: Address,
    dexes: &BTreeSet<String>,
) -> Result<Option<LedgerFlow>, LedgerProblem> {
    let kind_named = update["delta"]["type"].as_str().map(str::to_owned);
    let time_named = update["time"].as_i64();
    let id = match (update["hash"].as_str(), time_named, &kind_named) {
        (Some(hash), Some(time), Some(kind)) if !hash.is_empty() => {
            format!("{hash}:{time}:{kind}")
        }
        _ => update.to_string().chars().take(200).collect(),
    };
    let problem = |why: String| LedgerProblem {
        kind: kind_named.clone(),
        time_ms: time_named,
        id: id.clone(),
        why,
        treated: Treated::Unread,
    };
    let kind = check_entry(update).map_err(&problem)?;
    let time_ms = time_named.ok_or_else(|| problem("no time".into()))?;
    let delta = &update["delta"];
    let field = |name: &str| decimal(&delta[name]).ok_or_else(|| problem(format!("no {name}")));
    let address = |name: &str| {
        delta[name]
            .as_str()
            .and_then(Address::from_hex)
            .ok_or_else(|| problem(format!("{name} is not an address")))
    };
    let me = |name: &str| {
        delta
            .get(name)
            .and_then(Value::as_str)
            .and_then(Address::from_hex)
            == Some(user)
    };
    let main = dexes.contains("");
    let mut dex = String::new();
    let mut between = false;
    let amount = match kind {
        // No money of the perp accounts: trading, spot only, staking.
        "liquidation" | "spotTransfer" | "spotGenesis" | "cStakingTransfer" | "borrowLend" => {
            return Ok(None);
        }
        // The main dex's own money, when Guard does not manage it.
        "deposit"
        | "withdraw"
        | "accountClassTransfer"
        | "subAccountTransfer"
        | "internalTransfer"
        | "vaultCreate"
        | "vaultDeposit"
        | "vaultWithdraw"
        | "vaultDistribution"
        | "vaultLeaderCommission"
        | "rewardsClaim"
            if !main =>
        {
            return Ok(None);
        }
        "deposit" => field("usdc")?,
        "withdraw" => -field("usdc")?,
        "accountClassTransfer" => {
            let usdc = field("usdc")?;
            match delta["toPerp"].as_bool() {
                Some(true) => usdc,
                Some(false) => -usdc,
                None => return Err(problem("toPerp is not true or false".into())),
            }
        }
        "subAccountTransfer" | "internalTransfer" => {
            let usdc = field("usdc")?;
            let (from, to) = (address("user")?, address("destination")?);
            match (from == user, to == user) {
                (false, true) => usdc,
                (true, false) => {
                    let fee = if kind == "internalTransfer" {
                        field("fee")?
                    } else {
                        Decimal::ZERO
                    };
                    -usdc
                        .checked_add(fee)
                        .ok_or_else(|| problem("too large".into()))?
                }
                _ => return Ok(None),
            }
        }
        "send" => {
            let (from, to) = (address("user")?, address("destination")?);
            let named = |name: &str| {
                delta[name]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| problem(format!("{name} is not a dex name")))
            };
            let (source, destination) = (named("sourceDex")?, named("destinationDex")?);
            let out_of = from == user && dexes.contains(&source);
            let into = to == user && dexes.contains(&destination);
            if !out_of && !into {
                // Between accounts Guard does not manage (spot, another
                // dex): none of the perp accounts' money.
                return Ok(None);
            }
            let value = field("usdcValue")?;
            let overflow = || problem("too large".into());
            let mut net = Decimal::ZERO;
            if out_of {
                let out = value.checked_add(field("fee")?).ok_or_else(overflow)?;
                net = net.checked_sub(out).ok_or_else(overflow)?;
                dex = source;
            }
            if into {
                between = net < Decimal::ZERO;
                net = net.checked_add(value).ok_or_else(overflow)?;
                if net > Decimal::ZERO {
                    dex = destination;
                }
            }
            net
        }
        "vaultCreate" => {
            let usdc = field("usdc")?;
            if me("vault") {
                usdc
            } else {
                -usdc
                    .checked_add(field("fee")?)
                    .ok_or_else(|| problem("too large".into()))?
            }
        }
        "vaultDeposit" => {
            let usdc = field("usdc")?;
            if me("vault") { usdc } else { -usdc }
        }
        "vaultWithdraw" => {
            if me("vault") {
                -field("requestedUsd")?
            } else {
                field("netWithdrawnUsd")?
            }
        }
        "vaultDistribution" => {
            let usdc = field("usdc")?;
            if me("vault") { -usdc } else { usdc }
        }
        "vaultLeaderCommission" if me("user") => field("usdc")?,
        "vaultLeaderCommission" => return Ok(None),
        "rewardsClaim" => field("amount")?,
        other => {
            let why = format!("Guard does not know the type {other}");
            let usd = decimal(&delta["usdc"]).or_else(|| decimal(&delta["usdcValue"]));
            let (Some(usd), true) = (usd, main) else {
                return Err(problem(format!(
                    "{why}, and it carries no USD amount (usdc or usdcValue) Guard can book on the main dex"
                )));
            };
            let paid = me("user")
                && delta
                    .get("destination")
                    .and_then(Value::as_str)
                    .and_then(Address::from_hex)
                    .is_some_and(|to| to != user);
            let treated = if paid || usd == Decimal::ZERO {
                Treated::LeftAsLoss(usd)
            } else {
                Treated::Inflow(Box::new(LedgerFlow {
                    time_ms,
                    amount: usd,
                    id: id.clone(),
                    dex: String::new(),
                    between: false,
                }))
            };
            return Err(LedgerProblem {
                treated,
                ..problem(why)
            });
        }
    };
    if amount == Decimal::ZERO && !between {
        return Ok(None);
    }
    Ok(Some(LedgerFlow {
        time_ms,
        amount,
        id,
        dex,
        between,
    }))
}

/// [`classify`] where an entry Guard cannot account for is no flow: for a
/// ledger already checked whole ([`crate::flow_value::valid_ledger`]).
pub fn ledger_flow(update: &Value, user: Address, dexes: &BTreeSet<String>) -> Option<LedgerFlow> {
    classify(update, user, dexes).ok().flatten()
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
    fn unknown_types_and_malformed_entries_are_problems_not_skipped() {
        let main = dexes(&[""]);
        let problem = |delta: Value| classify(&entry(delta), me(), &main).unwrap_err();
        // A type Guard does not know (Hyperliquid's `welcomeBonus`, say):
        // named, never taken as no flow.
        let unknown = problem(json!({"type": "welcomeBonus", "usdc": "5"}));
        assert_eq!(unknown.kind.as_deref(), Some("welcomeBonus"));
        assert_eq!(unknown.id, "0xabc:1000:welcomeBonus");
        // Its USD amount reads and nothing says the account paid it: money
        // in, 5 on the main dex, never a trading gain.
        assert_eq!(
            unknown.treated,
            Treated::Inflow(Box::new(LedgerFlow {
                time_ms: 1_000,
                amount: dec!(5),
                id: "0xabc:1000:welcomeBonus".into(),
                dex: String::new(),
                between: false,
            }))
        );
        // `usdcValue` when there is no `usdc`.
        assert!(matches!(
            problem(json!({"type": "hip3LiquidatorDeposit", "usdcValue": "7"})).treated,
            Treated::Inflow(flow) if flow.amount == dec!(7)
        ));
        // The account paid it to another: left as the loss it shows.
        assert_eq!(
            problem(json!({"type": "newPayment", "usdc": "3", "user": ME, "destination": OTHER}))
                .treated,
            Treated::LeftAsLoss(dec!(3))
        );
        // Paid to the account by another: money in.
        assert!(matches!(
            problem(json!({"type": "newPayment", "usdc": "3", "user": OTHER, "destination": ME}))
                .treated,
            Treated::Inflow(_)
        ));
        // No USD amount (a token amount is no USD amount): unread.
        assert_eq!(
            problem(json!({"type": "activateDexAbstraction"})).treated,
            Treated::Unread
        );
        assert_eq!(
            problem(json!({"type": "deployGasAuction", "token": "HYPE", "amount": "2"})).treated,
            Treated::Unread
        );
        // Guard managing only a HIP-3 dex cannot book it on the main dex.
        assert_eq!(
            classify(
                &entry(json!({"type": "welcomeBonus", "usdc": "5"})),
                me(),
                &dexes(&["xyz"])
            )
            .unwrap_err()
            .treated,
            Treated::Unread
        );
        assert_eq!(unknown.time_ms, Some(1_000));
        assert!(unknown.to_string().contains("welcomeBonus"), "{unknown}");
        // A transfer out without its fee: the fee is never taken as zero.
        let feeless = problem(
            json!({"type": "internalTransfer", "usdc": "100", "user": ME, "destination": OTHER}),
        );
        assert!(feeless.why.contains("fee"), "{feeless}");
        // The same fee is not needed for money coming in.
        assert_eq!(
            classify(
                &entry(
                    json!({"type": "internalTransfer", "usdc": "100", "user": OTHER, "destination": ME})
                ),
                me(),
                &main
            )
            .unwrap()
            .map(|flow| flow.amount),
            Some(dec!(100))
        );
        // A send out of a managed dex without its fee, a send without its
        // dexes, a vault created without its fee.
        let xyz = dexes(&["", "xyz"]);
        let send = json!({"type": "send", "user": ME, "destination": OTHER, "sourceDex": "",
            "destinationDex": "", "usdcValue": "100"});
        assert!(classify(&entry(send), me(), &xyz).is_err());
        let unnamed = json!({"type": "send", "user": ME, "destination": OTHER,
            "usdcValue": "100", "fee": "1"});
        assert!(classify(&entry(unnamed), me(), &xyz).is_err());
        // A send that touches no managed account needs neither its value
        // nor its fee: none of the perp accounts' money.
        let elsewhere = json!({"type": "send", "user": ME, "destination": OTHER,
            "sourceDex": "spot", "destinationDex": "spot", "token": "HYPE", "amount": "1"});
        assert_eq!(classify(&entry(elsewhere), me(), &xyz), Ok(None));
        assert!(
            classify(
                &entry(json!({"type": "vaultCreate", "vault": OTHER, "usdc": "100"})),
                me(),
                &main
            )
            .is_err()
        );
        // Malformed: a negative or numeric amount, no toPerp, no hash, no
        // time, no type, a missing amount.
        for delta in [
            json!({"type": "deposit", "usdc": "-5"}),
            json!({"type": "deposit", "usdc": 5}),
            json!({"type": "accountClassTransfer", "usdc": "20"}),
            json!({"type": "deposit"}),
            json!({"usdc": "5"}),
        ] {
            assert!(
                classify(&entry(delta.clone()), me(), &main).is_err(),
                "{delta}"
            );
        }
        assert!(
            classify(
                &json!({"time": 1_000, "delta": {"type": "deposit", "usdc": "1"}}),
                me(),
                &main
            )
            .is_err()
        );
        let timeless = classify(
            &json!({"hash": "0xabc", "delta": {"type": "deposit", "usdc": "1"}}),
            me(),
            &main,
        )
        .unwrap_err();
        assert_eq!(timeless.time_ms, None);
        // Known types that move none of the perp accounts' money are no
        // flow, and no problem.
        for delta in [
            json!({"type": "liquidation", "accountValue": "10"}),
            json!({"type": "borrowLend", "interestAmount": "0.1"}),
            json!({"type": "cStakingTransfer", "token": "HYPE", "amount": "1"}),
        ] {
            assert_eq!(
                classify(&entry(delta.clone()), me(), &main),
                Ok(None),
                "{delta}"
            );
        }
        // Main-dex money when Guard manages only a HIP-3 dex: none.
        assert_eq!(
            classify(
                &entry(json!({"type": "deposit", "usdc": "5"})),
                me(),
                &dexes(&["xyz"])
            ),
            Ok(None)
        );
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
