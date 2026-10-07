// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Pure reconstruction of equity immediately before a ledger flow.
//! All inputs are venue records; missing coverage is an error, never zero PnL.
use rust_decimal::Decimal;
use serde_json::Value;
use std::collections::BTreeMap;

fn number(value: &Value) -> Option<Decimal> {
    value.as_str()?.parse().ok()
}
fn interval(time: i64, anchor: i64, target: i64) -> bool {
    if target > anchor {
        time > anchor && time < target
    } else {
        time >= target && time <= anchor
    }
}
fn quantity(position: &Value) -> Option<Decimal> {
    number(&position["szi"])
}

/// Refuse ledger data that the permissive display-oriented flow parser
/// could otherwise skip or treat as a zero fee during exact reconstruction.
pub fn valid_ledger(rows: &[Value]) -> bool {
    let mut ids = std::collections::BTreeSet::new();
    rows.iter().all(|row| {
        let (Some(time), Some(hash), Some(kind)) = (
            row["time"].as_i64(),
            row["hash"].as_str(),
            row["delta"]["type"].as_str(),
        ) else {
            return false;
        };
        if hash.is_empty() || !ids.insert((time, hash, kind)) {
            return false;
        }
        let delta = &row["delta"];
        for key in [
            "fee",
            "usdc",
            "usdcValue",
            "requestedUsd",
            "netWithdrawnUsd",
            "amount",
        ] {
            if let Some(value) = delta.get(key)
                && number(value).is_none_or(|value| value < Decimal::ZERO)
            {
                return false;
            }
        }
        let fields: &[&str] = match kind {
            "deposit"
            | "withdraw"
            | "vaultCreate"
            | "vaultDeposit"
            | "vaultDistribution"
            | "vaultLeaderCommission" => &["usdc"],
            "accountClassTransfer" => {
                if delta["toPerp"].as_bool().is_none() {
                    return false;
                }
                &["usdc"]
            }
            "internalTransfer" | "subAccountTransfer" | "send" => {
                if ["user", "destination"].into_iter().any(|key| {
                    delta[key]
                        .as_str()
                        .and_then(crate::sign::Address::from_hex)
                        .is_none()
                }) {
                    return false;
                }
                if kind == "send" {
                    if delta
                        .get("token")
                        .is_some_and(|token| token.as_str() != Some("USDC"))
                    {
                        return false;
                    }
                    if delta["sourceDex"].as_str().is_none()
                        || delta["destinationDex"].as_str().is_none()
                    {
                        return false;
                    }
                    &["usdcValue"]
                } else {
                    &["usdc"]
                }
            }
            "vaultWithdraw" => &["requestedUsd", "netWithdrawnUsd"],
            "rewardsClaim" => &["amount"],
            "spotTransfer" | "spotGenesis" | "cStakingTransfer" => &[],
            _ => return false,
        };
        fields.iter().all(|key| number(&delta[*key]).is_some())
    })
}

/// Signed target positions after undoing/redoing all interval fills.
/// Fills and funding at the target time have unknown ordering and are refused.
fn target_sizes(anchor: &Value, target: i64, fills: &[Value]) -> Option<BTreeMap<String, Decimal>> {
    let at = anchor["time"].as_i64()?;
    if target == at {
        return None;
    }
    let direction = if target > at {
        Decimal::ONE
    } else {
        -Decimal::ONE
    };
    let mut sizes = BTreeMap::new();
    for row in anchor["assetPositions"].as_array()? {
        let position = &row["position"];
        let coin = position["coin"].as_str()?.to_owned();
        if sizes.insert(coin, quantity(position)?).is_some() {
            return None;
        }
    }
    let mut ids = std::collections::BTreeSet::new();
    for fill in fills {
        let time = fill["time"].as_i64()?;
        if time == target {
            return None;
        }
        if !interval(time, at, target) {
            continue;
        }
        if !ids.insert(fill["tid"].as_u64()?) {
            return None;
        }
        let coin = fill["coin"].as_str()?.to_owned();
        let size = number(&fill["sz"])?;
        if size <= Decimal::ZERO {
            return None;
        }
        let delta = match fill["side"].as_str()? {
            "B" => size,
            "A" => -size,
            _ => return None,
        };
        let old = sizes.entry(coin).or_default();
        *old = old.checked_add(delta.checked_mul(direction)?)?;
    }
    sizes.retain(|_, size| !size.is_zero());
    Some(sizes)
}

/// Reconstruct one USDC margin account. `other_flows` is complete for the
/// interval, excludes the target flow, and carries its own signed amounts.
/// A nonzero target position makes historical equity unknown: trade candles
/// are not historical mark bounds and never feed a risk decision.
pub fn reconstruct(
    anchor: &Value,
    target: i64,
    fills: &[Value],
    funding: &[Value],
    other_flows: &[(i64, Decimal)],
    target_amount: Decimal,
) -> Option<Decimal> {
    let at = anchor["time"].as_i64()?;
    if !target_sizes(anchor, target, fills)?.is_empty() {
        return None;
    }
    let direction = if target > at {
        Decimal::ONE
    } else {
        -Decimal::ONE
    };
    let mut cash = number(&anchor["marginSummary"]["accountValue"])?;
    if target < at {
        cash = cash.checked_sub(target_amount)?;
    }
    for row in anchor["assetPositions"].as_array()? {
        let position = &row["position"];
        let size = quantity(position)?;
        let value = number(&position["positionValue"])?;
        if value < Decimal::ZERO || (size.is_zero() && !value.is_zero()) {
            return None;
        }
        let signed = if size < Decimal::ZERO { -value } else { value };
        cash = cash.checked_sub(signed)?;
    }
    for fill in fills {
        let time = fill["time"].as_i64()?;
        if !interval(time, at, target) {
            continue;
        }
        if fill["feeToken"].as_str()? != "USDC" {
            return None;
        }
        let size = number(&fill["sz"])?;
        let price = number(&fill["px"])?;
        if price <= Decimal::ZERO {
            return None;
        }
        let delta = match fill["side"].as_str()? {
            "B" => size,
            "A" => -size,
            _ => return None,
        };
        let builder = if fill.get("builderFee").is_some() {
            number(&fill["builderFee"])?
        } else {
            Decimal::ZERO
        };
        if builder < Decimal::ZERO {
            return None;
        }
        // Hyperliquid fee is the signed TOTAL, inclusive of builderFee.
        // Builder metadata is validated above but never charged twice.
        let paid = delta
            .checked_mul(price)?
            .checked_add(number(&fill["fee"])?)?;
        cash = cash.checked_sub(paid.checked_mul(direction)?)?;
    }
    let mut settlements = std::collections::BTreeSet::new();
    for row in funding {
        let time = row["time"].as_i64()?;
        if !settlements.insert((time, row["delta"]["coin"].as_str()?)) {
            return None;
        }
        if time == target {
            return None;
        }
        if interval(time, at, target) {
            cash = cash.checked_add(number(&row["delta"]["usdc"])?.checked_mul(direction)?)?;
        }
    }
    for (time, amount) in other_flows {
        if *time == target {
            return None;
        }
        if interval(*time, at, target) {
            cash = cash.checked_add(amount.checked_mul(direction)?)?;
        }
    }
    Some(cash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn d(value: &str) -> Decimal {
        value.parse().unwrap()
    }

    #[test]
    fn malformed_duplicate_or_unknown_ledger_cannot_be_exact() {
        let row = json!({"time":100000,"hash":"flow","delta":{"type":"deposit","usdc":"50"}});
        assert!(valid_ledger(std::slice::from_ref(&row)));
        assert!(!valid_ledger(&[row.clone(), row.clone()]));
        let mut malformed = row.clone();
        malformed["delta"]["fee"] = json!("bad");
        assert!(!valid_ledger(&[malformed]));
        let mut unknown = row;
        unknown["delta"]["type"] = json!("newCollateralMovement");
        assert!(!valid_ledger(&[unknown]));
    }

    #[test]
    fn forward_flat_is_exact_and_rebates_count() {
        // Long1 marked100, equity1000. Sell110, signed total rebate1 includes
        // builder2 (venue rebate3 minus builder2): cash900+110+1=1011.
        // Funding-4 and withdrawal-50 leave957. Do not double-charge builder.
        let anchor = json!({"time":60000,"marginSummary":{"accountValue":"1000"},"assetPositions":[{"position":{"coin":"X","szi":"1","positionValue":"100"}}]});
        let fill = json!({"time":70000,"tid":1,"coin":"X","side":"A","sz":"1","px":"110","fee":"-1","builderFee":"2","feeToken":"USDC"});
        let funding = json!({"time":75000,"delta":{"coin":"X","usdc":"-4"}});
        assert_eq!(
            reconstruct(
                &anchor,
                90000,
                std::slice::from_ref(&fill),
                &[funding],
                &[(80000, d("-50"))],
                Decimal::ZERO
            ),
            Some(d("957"))
        );
        assert!(
            reconstruct(
                &anchor,
                70000,
                std::slice::from_ref(&fill),
                &[],
                &[],
                Decimal::ZERO
            )
            .is_none()
        );
        assert!(
            reconstruct(
                &anchor,
                90000,
                &[fill.clone(), fill],
                &[],
                &[],
                Decimal::ZERO
            )
            .is_none()
        );
    }

    #[test]
    fn backwards_short_anchor_recovers_exact_flat_target() {
        // Target flat cash1000. Sell2*90, totalfee2 inclusivebuilder1,
        // funding4, deposit50 => cash1232; short2 marked100 => equity1032.
        let anchor = json!({"time":120001,"marginSummary":{"accountValue":"1032"},"assetPositions":[{"position":{"coin":"X","szi":"-2","positionValue":"200"}}]});
        let fill = json!({"time":100000,"tid":1,"coin":"X","side":"A","sz":"2","px":"90","fee":"2","builderFee":"1","feeToken":"USDC"});
        let funding = json!({"time":110000,"delta":{"coin":"X","usdc":"4"}});
        assert_eq!(
            reconstruct(
                &anchor,
                90000,
                &[fill],
                &[funding],
                &[(115000, d("50"))],
                Decimal::ZERO
            ),
            Some(d("1000"))
        );
    }

    #[test]
    fn inclusive_builder_fee_preserves_a_proved_predeposit_stop() {
        // True flat cash699 plus deposit1000, then flat roundtrip at100
        // with totalfees10 inclusivebuilder10 leaves anchor1689. Undo
        // fees once gives699 (30.1% loss from1000), never709.
        let anchor =
            json!({"time":120001,"marginSummary":{"accountValue":"1689"},"assetPositions":[]});
        let fills = [
            json!({"time":100000,"tid":1,"coin":"X","side":"B","sz":"1","px":"100","fee":"5","builderFee":"5","feeToken":"USDC"}),
            json!({"time":110000,"tid":2,"coin":"X","side":"A","sz":"1","px":"100","fee":"5","builderFee":"5","feeToken":"USDC"}),
        ];
        let exact = reconstruct(&anchor, 90000, &fills, &[], &[], d("1000")).unwrap();
        assert_eq!(exact, d("699"));
        let mut risk = zunder_risk::RiskEngine::new(
            zunder_risk::RiskLimits::default(),
            zunder_core::Timestamp::from_millis(0),
            d("1000"),
        )
        .unwrap();
        assert!(
            matches!(risk.observe(zunder_core::Timestamp::from_millis(90000),exact),zunder_risk::RiskState::Stopped { drawdown, .. } if drawdown == d("0.301"))
        );
    }

    #[test]
    fn historical_open_positions_are_unknown_even_if_the_anchor_is_flat() {
        let anchor =
            json!({"time":120001,"marginSummary":{"accountValue":"1000"},"assetPositions":[]});
        let fill = json!({"time":100000,"tid":1,"coin":"X","side":"A","sz":"1","px":"100","fee":"0","feeToken":"USDC"});
        assert!(reconstruct(&anchor, 90000, &[fill], &[], &[], Decimal::ZERO).is_none());
        // Reviewer mark-vs-trade counterexample: actual mark100, trade94.
        // No historical trade price is accepted, including a singleton.
        let exposed = json!({"time":120001,"marginSummary":{"accountValue":"11000"},"assetPositions":[{"position":{"coin":"X","szi":"500","positionValue":"50000"}}]});
        assert!(reconstruct(&exposed, 90000, &[], &[], &[], d("1000")).is_none());
    }

    #[test]
    fn backwards_subtracts_the_target_deposit_and_withdrawal() {
        // No trading: 1000 before +500 deposit becomes1500. Undo target too.
        for (amount, after) in [(500i32, 1500i32), (-500, 500)] {
            let anchor = json!({"time":120001,"marginSummary":{"accountValue":after.to_string()},"assetPositions":[]});
            assert_eq!(
                reconstruct(&anchor, 90000, &[], &[], &[], Decimal::from(amount)),
                Some(Decimal::from(1000))
            );
        }
    }

    #[test]
    fn ambiguous_boundary_or_malformed_account_is_unknown() {
        let anchor =
            json!({"time":120001,"marginSummary":{"accountValue":"1000"},"assetPositions":[]});
        assert!(reconstruct(&anchor, 120001, &[], &[], &[], Decimal::ZERO).is_none());
        assert!(reconstruct(&anchor, 90000, &[], &[], &[(90000, d("1"))], Decimal::ZERO).is_none());
        let funding = json!({"time":90000,"delta":{"coin":"X","usdc":"4"}});
        assert!(reconstruct(&anchor, 90000, &[], &[funding], &[], Decimal::ZERO).is_none());
        let malformed = json!({"time":120001,"marginSummary":{"accountValue":"1000"},"assetPositions":[{"position":{"coin":"X","szi":"1"}}]});
        assert!(reconstruct(&malformed, 90000, &[], &[], &[], Decimal::ZERO).is_none());
    }

    #[test]
    fn four_thousand_exact_cash_ledgers_match_independent_bookkeeping() {
        // Start with a flat target cash ledger, independently advance a signed
        // fill and its signed total fee (inclusive builder) to an exposed anchor.
        let cases = std::env::var("ZUNDER_FLOWS_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4000usize);
        let mut rng = fastrand::Rng::with_seed(0x66706c6f77);
        for index in 0..cases {
            let cash = Decimal::from(rng.i32(1000..100000));
            let delta = Decimal::from(rng.i32(1..11))
                * if rng.bool() {
                    Decimal::ONE
                } else {
                    -Decimal::ONE
                };
            let price = Decimal::from(rng.i32(30..300));
            let mark = Decimal::from(rng.i32(30..300));
            let fee = Decimal::from(rng.i32(-2..6));
            let builder = Decimal::from(rng.i32(0..4));
            let fund = Decimal::from(rng.i32(-10..11));
            let other = Decimal::from(rng.i32(-100..101));
            let target = Decimal::from(rng.i32(-100..101));
            let anchor_cash = cash + target - delta * price - fee + fund + other;
            let anchor_equity = anchor_cash + delta * mark;
            let anchor = json!({"time":120001,"marginSummary":{"accountValue":anchor_equity.to_string()},"assetPositions":[{"position":{"coin":"X","szi":delta.to_string(),"positionValue":(delta.abs()*mark).to_string()}}]});
            let fill = json!({"time":100000,"tid":index as u64,"coin":"X","side":if delta>Decimal::ZERO {"B"} else {"A"},"sz":delta.abs().to_string(),"px":price.to_string(),"fee":fee.to_string(),"builderFee":builder.to_string(),"feeToken":"USDC"});
            let funding = json!({"time":110000,"delta":{"coin":"X","usdc":fund.to_string()}});
            assert_eq!(
                reconstruct(
                    &anchor,
                    90000,
                    &[fill],
                    &[funding],
                    &[(115000, other)],
                    target
                ),
                Some(cash),
                "case {index}"
            );
        }
    }
}
