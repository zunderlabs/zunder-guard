// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The journal on disk: creating it, opening and locking it, reading it,
//! appending to it, and the marker a failed write leaves.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(not(windows))]
use std::fs::TryLockError;

use zunder_core::Timestamp;
use zunder_risk::{RiskEngine, RiskLimits, RiskSnapshot};

#[cfg(doc)]
use super::check::reach;
use super::{
    JournalError,
    check::{Checks, check_flowed, check_step},
    parse::parse,
    record::{FlowFields, JournalEvent, JournalRecord},
};
use crate::flows::{Horizon, RebaseBudget};

/// The marker a failed write leaves next to the journal at `path`.
pub fn broken_marker(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(ToOwned::to_owned).unwrap_or_default();
    name.push(".broken");
    path.with_file_name(name)
}

/// The journal file, open, locked, and positioned for appending.
#[derive(Debug)]
pub(super) struct RiskJournal {
    pub(super) path: PathBuf,
    pub(super) file: File,
    pub(super) limits: RiskLimits,
    /// The last record in the file.
    pub(super) last: JournalRecord,
    /// What the reader keeps to check `flowed` records.
    pub(super) checks: Checks,
}

impl RiskJournal {
    /// Read through the writer's existing handle, keeping its cursor and lock.
    /// A pathname lookup could refer to a different file after a namespace change.
    pub(super) fn records(&mut self) -> Result<Vec<JournalRecord>, JournalError> {
        let io = |error: io::Error| JournalError::Io {
            path: self.path.clone(),
            message: error.to_string(),
        };
        let position = self.file.stream_position().map_err(io)?;
        let read = (|| {
            self.file.seek(SeekFrom::Start(0)).map_err(io)?;
            let (bytes, complete) = read_all(&self.path, &mut self.file)?;
            refuse_torn(&self.path, &bytes, complete)?;
            let records = parse(&self.path, &bytes)?.1;
            if records.last() != Some(&self.last) {
                return Err(JournalError::Inconsistent {
                    path: self.path.clone(),
                    line: records.len(),
                    message: "the journal changed while its writer was open".into(),
                });
            }
            Ok(records)
        })();
        // Attempt restoration even if reading or parsing failed. Either failure
        // is returned to the caller, which latches the existing broken state.
        let restored = self.file.seek(SeekFrom::Start(position)).map_err(io);
        let records = read?;
        restored?;
        Ok(records)
    }

    /// Append one record, after checking that the reader would accept it.
    /// A `flowed` record is checked against `base`, the state, horizon and
    /// reach ([`reach`]) of the record it names, as the reader finds them.
    pub(super) fn append(
        &mut self,
        at: Timestamp,
        event: JournalEvent,
        state: RiskSnapshot,
        fields: FlowFields,
        base: Option<(&RiskSnapshot, &Horizon, &Horizon, Option<&RebaseBudget>)>,
    ) -> Result<(), JournalError> {
        let seq = self.last.seq + 1;
        let refuse = |message: String| JournalError::Inconsistent {
            path: self.path.clone(),
            line: usize::try_from(seq).unwrap_or(usize::MAX),
            message: format!("refusing to write: {message}"),
        };
        let (record, line) =
            JournalRecord::new(seq, at, event, state, self.last.check.clone(), fields)
                .map_err(refuse)?;
        RiskEngine::restore(self.limits.clone(), record.state.clone())
            .map_err(|error| refuse(error.to_string()))?;
        check_step(&self.last, &record).map_err(refuse)?;
        self.checks
            .listings
            .check_review(&record.event)
            .map_err(refuse)?;
        let mut placed = None;
        if let JournalEvent::Flowed {
            base: base_seq,
            views,
            flows: listed,
        } = &record.event
        {
            let (state, horizon, reached, budget) =
                base.ok_or_else(|| refuse("a flowed record without its base".into()))?;
            self.checks
                .trail
                .check(*base_seq, record.seq, views)
                .map_err(refuse)?;
            self.checks
                .listings
                .check(*base_seq, reached, listed)
                .map_err(refuse)?;
            let replayed = check_flowed(&self.limits, state, horizon, budget, &self.last, &record)
                .map_err(refuse)?;
            placed = Some(replayed.placed);
        }
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_data())
            .map_err(|error| JournalError::Io {
                path: self.path.clone(),
                message: error.to_string(),
            })?;
        if let (Some(placed), JournalEvent::Flowed { flows: listed, .. }) = (placed, &record.event)
        {
            self.checks.listings.record(record.seq, listed, &placed);
        }
        self.checks.trail.record(&record);
        self.last = record;
        Ok(())
    }
}

/// Sync the directory holding `path`, so that a new name in it is durable.
/// Not every platform can; the data is synced either way.
pub(super) fn sync_dir(path: &Path) {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    if let Ok(dir) = File::open(dir) {
        dir.sync_all().ok();
    }
}

/// Leave the marker for a failed write. Best effort: if even an empty file
/// cannot be created, the failure lives on in the running process only,
/// which refuses new positions.
pub(super) fn mark_broken(path: &Path, reason: &str) {
    if let Ok(mut marker) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(broken_marker(path))
    {
        marker.write_all(reason.as_bytes()).ok();
        marker.sync_all().ok();
    }
    sync_dir(path);
}

/// Open `path` for reading and appending, and lock it.
pub(super) fn open_locked(path: &Path) -> Result<File, JournalError> {
    open_locked_mode(path, false)
}

/// Only manual repair needs truncation rights; its handle never leaves repair.
pub(super) fn open_locked_mode(path: &Path, repair: bool) -> Result<File, JournalError> {
    let mut options = OpenOptions::new();
    options.read(true).write(repair).append(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Atomically exclude other writers and delete/rename handles while
        // allowing read-only inspection. Windows byte locks also block the
        // locking process's separate inspection handles.
        options.share_mode(0x0000_0001); // FILE_SHARE_READ
        if repair {
            // Windows append mode omits FILE_WRITE_DATA, which set_len needs.
            // Repair explicitly seeks to EOF before appending its audit record.
            options.access_mode(0xc000_0000); // GENERIC_READ | GENERIC_WRITE
        }
    }
    let file = options.open(path).map_err(|error| {
        #[cfg(windows)]
        if error.raw_os_error() == Some(32) {
            // ERROR_SHARING_VIOLATION: another incompatible handle is open.
            return JournalError::Locked(path.to_owned());
        }
        match error.kind() {
            io::ErrorKind::NotFound => JournalError::Missing(path.to_owned()),
            _ => JournalError::Io {
                path: path.to_owned(),
                message: error.to_string(),
            },
        }
    })?;
    #[cfg(windows)]
    {
        Ok(file)
    }
    #[cfg(not(windows))]
    {
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(TryLockError::WouldBlock) => Err(JournalError::Locked(path.to_owned())),
            Err(TryLockError::Error(error)) => Err(JournalError::Io {
                path: path.to_owned(),
                message: format!("locking: {error}"),
            }),
        }
    }
}

/// Read every byte of `file`, and the length of its complete lines.
pub(super) fn read_all(path: &Path, file: &mut File) -> Result<(Vec<u8>, usize), JournalError> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| JournalError::Io {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
    let complete = complete_len(&bytes);
    Ok((bytes, complete))
}

/// Length of the complete lines at the start of `bytes`.
pub(super) fn complete_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |newline| newline + 1)
}

/// Refuse to start a journal at `path` when anything is there already, or a
/// marker of a failed write.
pub(super) fn refuse_existing(path: &Path) -> Result<(), JournalError> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(JournalError::Exists(path.to_owned()));
    }
    refuse_marked(path)
}

/// Refuse a journal whose marker of a failed write is there.
pub(super) fn refuse_marked(path: &Path) -> Result<(), JournalError> {
    let marker = broken_marker(path);
    if fs::symlink_metadata(&marker).is_ok() {
        return Err(JournalError::MarkedBroken(marker));
    }
    Ok(())
}

/// Write a new journal holding `line` at `path`: to a temporary file,
/// synced, then linked into place in one step that fails if anything
/// exists there already, so that a journal is never overwritten.
pub(super) fn create(path: &Path, line: &str) -> Result<(), JournalError> {
    let io = |message: String| JournalError::Io {
        path: path.to_owned(),
        message,
    };
    let mut name = path.file_name().map(ToOwned::to_owned).unwrap_or_default();
    name.push(format!(".init-{}", std::process::id()));
    let temporary = path.with_file_name(name);
    let written = File::create_new(&temporary).and_then(|mut file| {
        file.write_all(line.as_bytes())?;
        file.sync_all()
    });
    // Linking fails if the journal appeared meanwhile: never overwrite.
    let linked = written.and_then(|()| fs::hard_link(&temporary, path));
    fs::remove_file(&temporary).ok();
    match linked {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(JournalError::Exists(path.to_owned()));
        }
        Err(error) => return Err(io(error.to_string())),
    }
    sync_dir(path);
    Ok(())
}

/// Open the journal at `path` for appending, locked, and read it: refused
/// when its last record is torn.
pub(super) fn open_complete(path: &Path) -> Result<(File, Vec<u8>), JournalError> {
    let mut file = open_locked(path)?;
    let (bytes, complete) = read_all(path, &mut file)?;
    refuse_torn(path, &bytes, complete)?;
    Ok((file, bytes))
}

/// Read the journal at `path` without locking it, for inspection: refused
/// when its last record is torn.
pub(super) fn read_complete(path: &Path) -> Result<Vec<u8>, JournalError> {
    let bytes = fs::read(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => JournalError::Missing(path.to_owned()),
        _ => JournalError::Io {
            path: path.to_owned(),
            message: error.to_string(),
        },
    })?;
    let complete = complete_len(&bytes);
    refuse_torn(path, &bytes, complete)?;
    Ok(bytes)
}

/// Refuse `bytes` whose complete lines end before they do: a record whose
/// write was interrupted.
fn refuse_torn(path: &Path, bytes: &[u8], complete: usize) -> Result<(), JournalError> {
    if complete < bytes.len() {
        return Err(JournalError::TornTail {
            path: path.to_owned(),
            bytes: (bytes.len() - complete) as u64,
        });
    }
    Ok(())
}

/// Cut `file`, the journal at `path` opened for repair, to its first `len`
/// bytes, sync that, and position it for appending.
pub(super) fn truncate(path: &Path, file: &mut File, len: u64) -> Result<(), JournalError> {
    let io = |error: io::Error| JournalError::Io {
        path: path.to_owned(),
        message: error.to_string(),
    };
    file.set_len(len).map_err(io)?;
    file.sync_all().map_err(io)?;
    file.seek(SeekFrom::End(0)).map_err(io)?;
    Ok(())
}
