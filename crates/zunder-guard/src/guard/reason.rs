// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The reason codes Guard decides on itself, beside the judge's and
//! admission's (`zunder_guard_core`), and where a request came in.

use serde_json::Value;
use zunder_guard_core::{judge::Decision, reply::veto_reply};

/// A reason code Guard answers with on its own: an account it could not
/// read, a budget spent, a journal, the fee, the venue. Each is in
/// `zunder_guard_core::codes::CODES`, from which `docs/guard.md` ("Reason
/// codes") is generated; `tests/codes.rs` keeps the two equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReasonCode {
    /// Reduce-only orders forwarded unjudged: the account could not be
    /// read.
    ReduceOnlyUnjudged,
    /// A journal does not allow it.
    Journal,
    /// The account (or its ledger) could not be read.
    AccountUnreadable,
    /// Guard's budget of the venue's request weight is spent.
    RateLimited,
    /// The builder fee's approval is not confirmed.
    FeeNotApproved,
    /// The venue did not confirm the isolated leverage an entry needs.
    VenueRefusedLeverage,
    /// The venue could not be reached, or answered with an error.
    VenueUnreachable,
}

impl ReasonCode {
    /// The code as it goes on the wire and into the journal.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            ReasonCode::ReduceOnlyUnjudged => "reduce_only_unjudged",
            ReasonCode::Journal => "journal",
            ReasonCode::AccountUnreadable => "account_unreadable",
            ReasonCode::RateLimited => "rate_limited",
            ReasonCode::FeeNotApproved => "fee_not_approved",
            ReasonCode::VenueRefusedLeverage => "venue_refused_leverage",
            ReasonCode::VenueUnreachable => "venue_unreachable",
        }
    }

    /// A veto with this code.
    pub(crate) fn veto(self, text: impl Into<String>) -> Decision {
        Decision::veto(self.as_str(), text)
    }

    /// Hyperliquid's error shape with this code
    /// ([`zunder_guard_core::reply::veto_reply`]).
    pub(crate) fn reply(self, text: &str) -> Value {
        veto_reply(self.as_str(), text)
    }
}

/// Where a request came in: it is journaled with each decision (`via`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// `POST /exchange`.
    Http,
    /// A WebSocket `post` of type `action`.
    WebSocket,
    /// `POST /guard/kill`.
    Kill,
}

impl Via {
    /// The name the decision journal records.
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Http => "http",
            Via::WebSocket => "ws",
            Via::Kill => "kill",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_guard_decides_on_is_listed() {
        let all = [
            ReasonCode::ReduceOnlyUnjudged,
            ReasonCode::Journal,
            ReasonCode::AccountUnreadable,
            ReasonCode::RateLimited,
            ReasonCode::FeeNotApproved,
            ReasonCode::VenueRefusedLeverage,
            ReasonCode::VenueUnreachable,
        ];
        for code in all {
            assert!(
                zunder_guard_core::codes::CODES
                    .iter()
                    .any(|(listed, _, _)| *listed == code.as_str()),
                "{code:?}"
            );
        }
    }

    #[test]
    fn the_journal_names_where_a_request_came_in_as_before() {
        assert_eq!(Via::Http.as_str(), "http");
        assert_eq!(Via::WebSocket.as_str(), "ws");
        assert_eq!(Via::Kill.as_str(), "kill");
    }
}
