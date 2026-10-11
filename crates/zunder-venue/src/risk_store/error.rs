// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Why a journal cannot be opened, read or written.

use std::path::PathBuf;

use thiserror::Error;
use zunder_risk::RiskLimits;

use super::record::{JOURNAL_VERSION, JournalScope};

/// Why the journal refused: what a person has to look at, or why new
/// positions are not allowed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum JournalError {
    #[error(
        "no risk journal at {0}: starting one is a decision for a person (PersistentRisk::initialise)"
    )]
    Missing(PathBuf),
    #[error("{0} already exists; a risk journal is never overwritten")]
    Exists(PathBuf),
    #[error("the risk journal {0} is open in another process")]
    Locked(PathBuf),
    #[error(
        "{0} exists: a write to the risk journal failed earlier, and what it held may be lost; a person has to compare the journal with the account's history, then remove the marker"
    )]
    MarkedBroken(PathBuf),
    #[error("{path}: {message}")]
    Io { path: PathBuf, message: String },
    #[error("{path}, line {line}: {message}")]
    Malformed {
        path: PathBuf,
        line: usize,
        message: String,
    },
    #[error(
        "{path}: the last {bytes} bytes are a record whose write was interrupted; a person has to repair the journal (PersistentRisk::repair_torn_tail)"
    )]
    TornTail { path: PathBuf, bytes: u64 },
    #[error(
        "{path}, line {line}: journal version {version}, newer than this build reads ({JOURNAL_VERSION})"
    )]
    UnsupportedVersion {
        path: PathBuf,
        line: usize,
        version: u64,
    },
    #[error("{path}, line {line}: {message}")]
    Inconsistent {
        path: PathBuf,
        line: usize,
        message: String,
    },
    #[error(
        "the journal was written under the limits {journal:?}, not the configured {configured:?}"
    )]
    LimitsDiffer {
        journal: Box<RiskLimits>,
        configured: Box<RiskLimits>,
    },
    #[error(
        "the journal was started for {journal:?}, not {configured:?} (network and account): a journal never moves to another network or account; start a new one"
    )]
    ScopeDiffers {
        journal: Option<JournalScope>,
        configured: Option<JournalScope>,
    },
    #[error("{0}")]
    Invalid(String),
    #[error(
        "writing the risk journal failed ({0}); no new positions until a person has looked at it"
    )]
    Broken(String),
    #[error("the risk engine has not observed the venue since the journal was opened: sync first")]
    NotObserved,
    #[error("known account flows are still pending a fresh, fully settled positive view")]
    PendingFlows,
}
