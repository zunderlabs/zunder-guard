// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The journal's format: one JSON record per line, led by a SHA3-256
//! checksum of the exact bytes of the rest of the line and chained to the
//! record before it.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zunder_core::Timestamp;
use zunder_risk::{RiskLimits, RiskSnapshot};

#[cfg(doc)]
use super::PersistentRisk;
use crate::flows::{Flow, Horizon, RebaseBudget, SeenView};

/// The `format` of every journal line.
pub const JOURNAL_FORMAT: &str = "zunder-risk-journal";

/// The journal version this build writes and the newest it reads. Version
/// 2 (6 Oct 2026) adds the journal's network and account ([`JournalScope`]);
/// version 3 (7 Oct 2026) the records of an engine that takes deposits and
/// withdrawals ([`PersistentRisk::with_flows`]: the horizon, the view, and
/// [`JournalEvent::Flowed`]), the only records written as version 3: an
/// engine without flows (the runner) writes version 2 as before, so an
/// older build still reads its journal. Version 4 (Guard 1.0.2) is version
/// 3 whose flows may stand for ledger entries the caller cannot account
/// for (`flows::UNKNOWN_TYPE_ID_PREFIX`, with `Flow::unaccounted`) and carry the
/// day's re-base budget (`budget`), which a
/// version 3 build would replay differently: the records of an engine that
/// takes flows are written as version 4 since, and only they may list such
/// a flow. Older journals are still read (a version 3 journal goes on as
/// version 4), and an older build refuses a newer record as too new rather
/// than misreading it.
pub const JOURNAL_VERSION: u32 = 4;

/// The first version whose records carry an engine's flow fields (the
/// horizon, the view, `flowed` records).
pub(super) const FLOWS_VERSION: u32 = 3;

/// The first version whose `flowed` records may list a flow for a ledger
/// entry the caller cannot account for.
pub(super) const UNACCOUNTED_VERSION: u32 = 4;

/// The version every record of an engine without flows is written as.
pub(super) const RECORD_VERSION: u32 = 2;

/// How every line starts: the checksum of the rest comes first.
pub(super) const CHECK_PREFIX: &str = "{\"check\":\"";

/// Hex digits in a SHA3-256 checksum.
const CHECK_LEN: usize = 64;

/// Where a journal's engine trades: the network and the account. Recorded
/// in the first record and checked whenever the journal is opened, so that
/// a journal never moves to another network or account (a testnet journal
/// copied into a mainnet state directory, say): its peak, day start and
/// halts belong to the account it was written for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalScope {
    /// `"testnet"` or `"mainnet"`.
    pub network: String,
    /// The account's address, as `0x` and 40 lowercase hex digits.
    pub account: String,
}

/// Why a journal record was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum JournalEvent {
    /// A person started the journal, under these limits, for this network
    /// and account when it says. Always the first record, and only the
    /// first.
    Initialised {
        limits: RiskLimits,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<JournalScope>,
        note: String,
    },
    /// The engine's state changed: an observation, a fill, a
    /// reconciliation.
    Updated,
    /// A person reviewed a drawdown stop and resumed trading.
    ResumedAfterReview { note: String },
    /// A person cut off a record whose write had been interrupted.
    Repaired { cut_bytes: u64, note: String },
    /// A person recorded the network and account of a journal started
    /// without them ([`PersistentRisk::adopt_scope`]). Only in a journal
    /// whose first record names none, at most once, and it changes no
    /// state.
    Scoped { scope: JournalScope, note: String },
    /// Deposits, withdrawals or transfers changed the engine
    /// (`docs/guard.md#deposits-and-withdrawals`): its state is
    /// [`crate::flows::replay`] from the state of record `base` (and its
    /// horizon) through `views`, every view since that record, with
    /// `flows`, every flow not in that state, then
    /// [`crate::flows::settle`] against the record before this one. Only an
    /// engine that takes flows ([`PersistentRisk::with_flows`]) writes it.
    Flowed {
        base: u64,
        views: Vec<SeenView>,
        flows: Vec<Flow>,
    },
}

/// What a record's checksum covers: everything but the checksum.
#[derive(Serialize)]
struct Body<'a> {
    format: &'a str,
    version: u32,
    seq: u64,
    at: Timestamp,
    event: &'a JournalEvent,
    state: &'a RiskSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    horizon: Option<&'a Horizon>,
    #[serde(skip_serializing_if = "Option::is_none")]
    view: Option<&'a SeenView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    budget: Option<&'a RebaseBudget>,
    prev: &'a str,
}

/// One line of the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    /// SHA3-256, in hex, of the exact bytes of the rest of the line.
    pub check: String,
    pub format: String,
    pub version: u32,
    /// 1, 2, 3, ... without gaps.
    pub seq: u64,
    /// When the change happened, by the caller's clock.
    pub at: Timestamp,
    pub event: JournalEvent,
    /// The engine's state after the change.
    pub state: RiskSnapshot,
    /// For an engine that takes flows: for each dex, the latest venue time
    /// of any view so far (version 3 and later only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub horizon: Option<Horizon>,
    /// For an engine that takes flows, a record written for a view: that
    /// view (version 3 and later only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<SeenView>,
    /// For an engine that takes flows, from version 4 on: the day's budget
    /// for re-bases of ledger entries it cannot account for
    /// ([`RebaseBudget`]); changed only by a `flowed` record, cleared by a
    /// review.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<RebaseBudget>,
    /// The previous record's checksum; empty for the first.
    pub prev: String,
}

/// What an engine that takes flows adds to a record.
#[derive(Debug, Clone, Default)]
pub(super) struct FlowFields {
    pub(super) horizon: Option<Horizon>,
    pub(super) view: Option<SeenView>,
    pub(super) budget: Option<RebaseBudget>,
}

impl JournalRecord {
    /// A record and the line that holds it, newline included.
    pub(super) fn new(
        seq: u64,
        at: Timestamp,
        event: JournalEvent,
        state: RiskSnapshot,
        prev: String,
        fields: FlowFields,
    ) -> Result<(Self, String), String> {
        let FlowFields {
            horizon,
            view,
            budget,
        } = fields;
        let version = if horizon.is_some() {
            JOURNAL_VERSION
        } else {
            RECORD_VERSION
        };
        let body = serde_json::to_string(&Body {
            format: JOURNAL_FORMAT,
            version,
            seq,
            at,
            event: &event,
            state: &state,
            horizon: horizon.as_ref(),
            view: view.as_ref(),
            budget: budget.as_ref(),
            prev: &prev,
        })
        .map_err(|error| error.to_string())?;
        let rest = body
            .strip_prefix('{')
            .ok_or_else(|| "a record must be a JSON object".to_owned())?;
        let check = hex(&Sha3_256::digest(body.as_bytes()));
        let line = format!("{CHECK_PREFIX}{check}\",{rest}\n");
        let record = Self {
            check,
            format: JOURNAL_FORMAT.to_owned(),
            version,
            seq,
            at,
            event,
            state,
            horizon,
            view,
            budget,
            prev,
        };
        Ok((record, line))
    }
}

/// Check a line's checksum against the exact bytes after it.
pub(super) fn verify_line(line: &str) -> Result<(), String> {
    let wrong = || "the checksum does not match: the record was changed or damaged".to_owned();
    let after = line.strip_prefix(CHECK_PREFIX).ok_or_else(wrong)?;
    let (check, rest) = after.split_at_checked(CHECK_LEN).ok_or_else(wrong)?;
    let rest = rest.strip_prefix("\",").ok_or_else(wrong)?;
    let body = format!("{{{rest}");
    if hex(&Sha3_256::digest(body.as_bytes())) == check {
        Ok(())
    } else {
        Err(wrong())
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}
