// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Every reason code Guard answers with: in replies (`"code"`), in the
//! decision journal's events and on `/guard/decision`. One list, so the
//! documentation is generated from it (`docs/guard.md` and the website's
//! `reference/veto-codes.mdx`) and a test fails when code and list drift
//! apart (`crates/zunder-guard/tests/codes.rs`, which scans the sources).
//!
//! Codes are `snake_case`, stable and never change meaning; new ones may be
//! added.

/// What a code means for the request it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Forwarded (or, in paper mode, would be).
    Forwarded,
    /// Refused before it could be judged: not decoded or not authenticated.
    /// The request did not count, apart from consuming a valid nonce.
    RefusedBeforeJudging,
    /// Judged and refused.
    Vetoed,
    /// Allowed, but not sent: Guard could not send it safely.
    NotSent,
}

impl Outcome {
    pub fn name(self) -> &'static str {
        match self {
            Outcome::Forwarded => "forwarded",
            Outcome::RefusedBeforeJudging => "refused before judging",
            Outcome::Vetoed => "vetoed",
            Outcome::NotSent => "not sent",
        }
    }
}

/// `(code, outcome, meaning)`, in the order the documentation lists them.
pub const CODES: &[(&str, Outcome, &str)] = &[
    // Forwarded.
    (
        "allowed",
        Outcome::Forwarded,
        "within every rule; forwarded as sent",
    ),
    (
        "resized",
        Outcome::Forwarded,
        "forwarded with changes, listed in `changes`: a size cut to the rules, a stop attached, a limit price pulled in, a stop's limit widened, an order made reduce-only or cut to the position",
    ),
    (
        "reduce_only_unjudged",
        Outcome::Forwarded,
        "the account could not be read; reduce-only orders are forwarded as sent, unjudged, so closing never waits",
    ),
    // Before judging.
    (
        "malformed",
        Outcome::RefusedBeforeJudging,
        "the request is not a well-formed Hyperliquid request (unknown fields, wrong types, bad prices, too many orders)",
    ),
    (
        "funds_or_permissions",
        Outcome::RefusedBeforeJudging,
        "an action that moves funds or grants permissions (withdrawals, transfers, agent or builder approvals, referrers, vaults, staking): never forwarded",
    ),
    (
        "unsupported_action",
        Outcome::RefusedBeforeJudging,
        "an action Guard does not forward (TWAP and others)",
    ),
    (
        "vault",
        Outcome::RefusedBeforeJudging,
        "a request for a vault or sub-account (`vaultAddress`): Guard trades the configured account only",
    ),
    (
        "auth_bad_signature",
        Outcome::RefusedBeforeJudging,
        "the signature recovers no key",
    ),
    (
        "auth_unknown_signer",
        Outcome::RefusedBeforeJudging,
        "the signature recovers a key that is not one of Guard's clients",
    ),
    (
        "auth_replay",
        Outcome::RefusedBeforeJudging,
        "the nonce is not above every nonce this client used before",
    ),
    (
        "auth_nonce_too_old",
        Outcome::RefusedBeforeJudging,
        "the nonce lies more than 30 s behind Guard's clock",
    ),
    (
        "auth_nonce_too_new",
        Outcome::RefusedBeforeJudging,
        "the nonce lies more than 5 s ahead of Guard's clock",
    ),
    (
        "auth_nonce_before_start",
        Outcome::RefusedBeforeJudging,
        "the nonce is from before Guard's start (plus 5 s): no request survives a restart",
    ),
    (
        "auth_expired",
        Outcome::RefusedBeforeJudging,
        "the request's `expiresAfter` has passed",
    ),
    (
        "auth_too_large",
        Outcome::RefusedBeforeJudging,
        "the request is too large to hash and check",
    ),
    // Vetoed: halts.
    (
        "kill_switch",
        Outcome::Vetoed,
        "the kill switch is pulled: nothing opens until a person removes the kill file and restarts Guard",
    ),
    (
        "daily_loss_stop",
        Outcome::Vetoed,
        "the daily loss stop is reached: nothing opens until the next UTC day",
    ),
    (
        "drawdown_halt",
        Outcome::Vetoed,
        "the drawdown halt is reached: nothing opens until a person's review",
    ),
    (
        "journal",
        Outcome::Vetoed,
        "a journal does not allow it: when the risk journal is not ready, entries are refused; when a decision cannot be written to the decision journal (or its sync takes longer than 2 s), every request is refused, closes and cancels included, until a restart on an intact journal (Guard's own flattening and protection go on, recorded in the emergency log)",
    ),
    // Vetoed: the market and the account.
    (
        "market_not_allowed",
        Outcome::Vetoed,
        "the market is not on the rules' market list",
    ),
    (
        "unknown_market",
        Outcome::Vetoed,
        "the asset is not a perp the venue lists",
    ),
    (
        "unsupported_market",
        Outcome::Vetoed,
        "a spot pair or a HIP-4 outcome (Guard trades perps), or a HIP-3 dex that margins in another token than USDC",
    ),
    (
        "dex_not_allowed",
        Outcome::Vetoed,
        "a HIP-3 dex's perp on a dex the rules' markets do not name (`dex:*` or `dex:COIN`): Guard neither reads nor forwards anything there but cancels",
    ),
    (
        "market_halted",
        Outcome::Vetoed,
        "a HIP-3 market its deployer halted and settled (or delisted): nothing opens there",
    ),
    (
        "open_interest_cap",
        Outcome::Vetoed,
        "a HIP-3 market at its open-interest cap: the venue takes no order that adds to it",
    ),
    (
        "dex_margin",
        Outcome::Vetoed,
        "the HIP-3 dex's own margin account cannot fund the venue's minimum order at the leverage Guard sets: move USDC to that dex first",
    ),
    (
        "thin_book",
        Outcome::Vetoed,
        "a HIP-3 book too thin for the stop: the position, with what rests on its side, may take at most half the depth between the price and the stop's worst fill (or the book could not be read)",
    ),
    (
        "unsupported_order",
        Outcome::Vetoed,
        "an entry that is not a limit order (a trigger entry)",
    ),
    (
        "account_unknown",
        Outcome::Vetoed,
        "the account is not in standard mode, or its equity is not positive: entries cannot be sized",
    ),
    (
        "account_unreadable",
        Outcome::Vetoed,
        "the account could not be read from the venue (reduce-only orders still go, as `reduce_only_unjudged`); or its ledger not yet, after a loss that would halt Guard (a withdrawal is no loss: up to 10 s); or every view for 10 s may or may not show a deposit or withdrawal: no new positions meanwhile",
    ),
    ("no_price", Outcome::Vetoed, "no mid price for the market"),
    (
        "rate_limited",
        Outcome::Vetoed,
        "Guard's budget of the venue's request weight for bots' requests is spent (reading the account, a HIP-3 entry's book, and what a forwarded request sends; the rest of the venue's limit is kept for Guard's own protection); try again in a few seconds (reduce-only orders still go, unjudged)",
    ),
    // Vetoed: stops.
    (
        "stop_required",
        Outcome::Vetoed,
        "an entry without a stop under the stop policy `refuse` (a stop-limit is no stop)",
    ),
    (
        "stop_wrong_side",
        Outcome::Vetoed,
        "the stop is not on the losing side of the entry and the mid",
    ),
    (
        "stop_removed",
        Outcome::Vetoed,
        "a cancel or modify would leave a position, or a resting entry, without a stop covering all of it",
    ),
    (
        "stop_loosened",
        Outcome::Vetoed,
        "a modify would move a stop further away, shrink it, or turn it into something that is not a market stop; or the change would raise the risk to the stops beyond the open-risk budget",
    ),
    (
        "guard_stop",
        Outcome::Vetoed,
        "a cancel of Guard's own stop while its position is open",
    ),
    // Vetoed: sizing and liquidation.
    (
        "open_risk",
        Outcome::Vetoed,
        "the open-risk budget is used up (risk engine)",
    ),
    (
        "leverage",
        Outcome::Vetoed,
        "the leverage cap is reached (risk engine); an open position runs above the cap; or a leverage update above the cap, or one that raises an open position's leverage",
    ),
    (
        "position_cap",
        Outcome::Vetoed,
        "the position is at the rules' largest position already",
    ),
    (
        "liquidation_too_close",
        Outcome::Vetoed,
        "no isolated leverage of 1x or more puts the liquidation beyond the stop's worst fill and the minimum distance; adding to an open position would leave its liquidation too close; or a leverage update an entry resting on the coin could not take",
    ),
    (
        "cross_margin",
        Outcome::Vetoed,
        "the position is on cross margin, or a leverage update asks for cross: Guard trades isolated",
    ),
    (
        "below_minimum",
        Outcome::Vetoed,
        "the size the rules allow (or its stop, at its worst fill) is worth less than the venue's minimum order",
    ),
    (
        "unprotected_position",
        Outcome::Vetoed,
        "a position has no stop covering all of it: no new entry until it has one",
    ),
    (
        "unprotected_order",
        Outcome::Vetoed,
        "an order rests that could open a position without a stop: no new entry until it is cancelled or has one",
    ),
    // Vetoed: the shape of the request.
    (
        "flip",
        Outcome::Vetoed,
        "the order would turn a position around: close it first (reduce-only), then enter",
    ),
    (
        "one_entry_per_action",
        Outcome::Vetoed,
        "more than one entry in one action",
    ),
    (
        "modify_entry",
        Outcome::Vetoed,
        "a modify of a resting entry: cancel it and send a new one",
    ),
    (
        "unknown_order",
        Outcome::Vetoed,
        "a modify of an order Guard cannot see resting",
    ),
    (
        "margin_removal",
        Outcome::Vetoed,
        "`updateIsolatedMargin` that removes margin",
    ),
    (
        "schedule_cancel",
        Outcome::Vetoed,
        "`scheduleCancel` that sets a time (it would cancel the stops too); clearing it is allowed",
    ),
    (
        "client_builder",
        Outcome::Vetoed,
        "an entry carrying a builder field of its own (in ccxt: `options.builderFee = false`); from an exit the field is removed instead",
    ),
    (
        "fee_not_approved",
        Outcome::Vetoed,
        "a new entry, or a modify, while Guard charges its builder fee and the account's approval of it (`maxBuilderFee`) is not confirmed: approve it with the main wallet at https://zunderlabs.com/approve; exits, closes, new stops and flattens are never refused for it",
    ),
    (
        "invalid",
        Outcome::Vetoed,
        "the request cannot be judged as sent: TP/SL that do not belong to the entry, two stops, the entry not first in `normalTpsl`, Guard's stop-id prefix, a change of market or side in a modify, numbers out of range",
    ),
    // Allowed, not sent.
    (
        "venue_refused_leverage",
        Outcome::NotSent,
        "the venue did not confirm the isolated leverage the entry needs, so the entry was not sent",
    ),
    (
        "venue_unreachable",
        Outcome::NotSent,
        "the venue could not be reached or answered with an error, or the request could not be signed; when no answer came at all it may have reached the venue, so check open orders before sending again",
    ),
];

/// The meaning of `code`, if it is one of Guard's.
pub fn meaning(code: &str) -> Option<&'static str> {
    CODES
        .iter()
        .find(|(name, _, _)| *name == code)
        .map(|(_, _, meaning)| *meaning)
}

/// The Markdown table of [`CODES`], as the documentation shows it.
pub fn markdown_table() -> String {
    let mut out = String::from("| Code | Outcome | When |\n|---|---|---|\n");
    for (code, outcome, meaning) in CODES {
        out.push_str(&format!("| `{code}` | {} | {meaning} |\n", outcome.name()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_snake_case_and_listed_once() {
        let mut seen = std::collections::BTreeSet::new();
        for (code, _, meaning) in CODES {
            assert!(
                code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{code}"
            );
            assert!(!meaning.is_empty() && !meaning.contains('|'), "{code}");
            assert!(seen.insert(*code), "{code} twice");
        }
        assert!(meaning("guard_stop").is_some());
        assert_eq!(meaning("nothing"), None);
    }
}
