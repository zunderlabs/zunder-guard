// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Reading a journal's bytes: every line parsed and checked, in order, as
//! the module documentation describes. No file access: the caller reads.

use std::path::Path;

use zunder_risk::{RiskEngine, RiskLimits};

use super::{
    JournalError,
    check::{Checks, check_flowed, check_step, reach},
    record::{
        JOURNAL_FORMAT, JOURNAL_VERSION, JournalEvent, JournalRecord, JournalScope, verify_line,
    },
};
use crate::flows::Horizon;

/// Parse and check complete journal lines. See the module documentation
/// for what is checked.
#[allow(clippy::type_complexity)]
pub(super) fn parse(
    path: &Path,
    bytes: &[u8],
) -> Result<(Header, Vec<JournalRecord>, Checks), JournalError> {
    let malformed = |line: usize, message: String| JournalError::Malformed {
        path: path.to_owned(),
        line,
        message,
    };
    let inconsistent = |line: usize, message: String| JournalError::Inconsistent {
        path: path.to_owned(),
        line,
        message,
    };
    let text = std::str::from_utf8(bytes).map_err(|error| malformed(0, error.to_string()))?;
    let mut records: Vec<JournalRecord> = Vec::new();
    let mut limits: Option<RiskLimits> = None;
    let mut scope: Option<JournalScope> = None;
    let mut checks = Checks::default();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        // The format and version first: a newer version may not parse.
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|error| malformed(number, error.to_string()))?;
        if value.get("format").and_then(serde_json::Value::as_str) != Some(JOURNAL_FORMAT) {
            return Err(malformed(number, format!("not a {JOURNAL_FORMAT} record")));
        }
        let version = value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| malformed(number, "no version".into()))?;
        if version > u64::from(JOURNAL_VERSION) {
            return Err(JournalError::UnsupportedVersion {
                path: path.to_owned(),
                line: number,
                version,
            });
        }
        if version == 0 {
            return Err(malformed(number, "version 0 does not exist".into()));
        }
        verify_line(line).map_err(|message| inconsistent(number, message))?;
        let record: JournalRecord =
            serde_json::from_value(value).map_err(|error| malformed(number, error.to_string()))?;

        let expected = records.len() as u64 + 1;
        if record.seq != expected {
            return Err(inconsistent(
                number,
                format!(
                    "sequence number {} where {expected} was expected",
                    record.seq
                ),
            ));
        }
        let prev = records.last().map_or("", |last| last.check.as_str());
        if record.prev != prev {
            return Err(inconsistent(
                number,
                "the record does not follow the one before it".into(),
            ));
        }
        let limits = match (&record.event, &limits) {
            (
                JournalEvent::Initialised {
                    limits: first,
                    scope: first_scope,
                    ..
                },
                None,
            ) => {
                scope.clone_from(first_scope);
                limits.insert(first.clone()).clone()
            }
            (_, None) => {
                return Err(inconsistent(
                    number,
                    "the first record must be `initialised`".into(),
                ));
            }
            (JournalEvent::Initialised { .. }, Some(_)) => {
                return Err(inconsistent(
                    number,
                    "only the first record may be `initialised`".into(),
                ));
            }
            (JournalEvent::Scoped { scope: adopted, .. }, Some(limits)) => {
                if scope.is_some() {
                    return Err(inconsistent(
                        number,
                        "the journal's network and account are already recorded".into(),
                    ));
                }
                scope = Some(adopted.clone());
                limits.clone()
            }
            (_, Some(limits)) => limits.clone(),
        };
        RiskEngine::restore(limits.clone(), record.state.clone())
            .map_err(|error| inconsistent(number, error.to_string()))?;
        if let Some(previous) = records.last() {
            check_step(previous, &record).map_err(|message| inconsistent(number, message))?;
        }
        checks
            .listings
            .check_review(&record.event)
            .map_err(|message| inconsistent(number, message))?;
        if let JournalEvent::Flowed {
            base,
            views,
            flows: listed,
        } = &record.event
        {
            let previous = records
                .last()
                .ok_or_else(|| inconsistent(number, "a flowed record first".into()))?;
            let base_record = usize::try_from(*base)
                .ok()
                .and_then(|base| base.checked_sub(1))
                .and_then(|index| records.get(index))
                .filter(|base_record| base_record.seq < record.seq)
                .ok_or_else(|| {
                    inconsistent(
                        number,
                        format!("a flowed record from record {base}, which is not before it"),
                    )
                })?;
            let empty = Horizon::new();
            let horizon = base_record.horizon.as_ref().unwrap_or(&empty);
            checks
                .trail
                .check(*base, record.seq, views)
                .map_err(|message| inconsistent(number, message))?;
            checks
                .listings
                .check(*base, &reach(base_record), listed)
                .map_err(|message| inconsistent(number, message))?;
            let replayed = check_flowed(
                &limits,
                &base_record.state,
                horizon,
                base_record.budget.as_ref(),
                previous,
                &record,
            )
            .map_err(|message| inconsistent(number, message))?;
            checks.listings.record(record.seq, listed, &replayed.placed);
        }
        checks.trail.record(&record);
        records.push(record);
    }
    match limits {
        Some(limits) => Ok((Header { limits, scope }, records, checks)),
        None => Err(malformed(0, "the journal is empty".into())),
    }
}

/// What a journal's first record fixes.
#[derive(Debug)]
pub(super) struct Header {
    limits: RiskLimits,
    scope: Option<JournalScope>,
}

impl Header {
    /// Refuse other limits, or another network or account.
    pub(super) fn check(
        &self,
        limits: &RiskLimits,
        scope: Option<&JournalScope>,
    ) -> Result<(), JournalError> {
        if self.limits != *limits {
            return Err(JournalError::LimitsDiffer {
                journal: Box::new(self.limits.clone()),
                configured: Box::new(limits.clone()),
            });
        }
        if self.scope.as_ref() != scope {
            return Err(JournalError::ScopeDiffers {
                journal: self.scope.clone(),
                configured: scope.cloned(),
            });
        }
        Ok(())
    }
}
