// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The decision journal: every event Guard records, one JSON line each,
//! chained by checksum, written by one thread (the file's only writer) in
//! the order Guard produced them (`docs/guard.md#journals`).
//!
//! An intent (a decision to send, a protection, a flattening, any other
//! action Guard sends) is on disk before Guard sends anything for it:
//! [`DecisionJournal::append_durable`] hands it to the writer and Guard
//! waits on the [`Durable`] it returns. The writer takes whatever is
//! queued, writes it in order and syncs once for all of it (group commit).
//! Every other record ([`DecisionJournal::append`]: what was sent and the
//! venue's answer, errors, risk events) is synced with the next intent, or
//! within [`FLUSH_MS`]; a crash may lose those, and recovery asks the venue
//! (spec J3). The file is extended with zeros in steps of
//! [`ALLOCATE_STEP`], so that a sync commits data only; a clean stop gives
//! the unused zeros back.
//!
//! A line is `{"check": c, "prev": p, "event": e}`: `c` is the SHA3-256 of
//! `p` followed by the exact text of `e`, and `p` is the previous line's
//! `c` (empty for the first). Opening a journal checks every whole record;
//! what follows the last one (zeros, or a write a crash cut short, which
//! was never synced, so nothing was sent on its strength) is cleared, and
//! [`DecisionJournal::cut_on_open`] says so. A whole record that does not
//! check out, or a missing or reordered one, is refused, and a person
//! moves the file aside. After a failed write or sync, or a writer that
//! fell behind, the journal counts as broken: Guard then forwards nothing
//! for a bot until it is restarted on an intact journal.

use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use serde_json::Value;
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use zunder_guard_core::event::{EventBody, GuardEvent};

use crate::recover::Tracker;

/// How many events the event endpoint can serve.
pub const RECENT_EVENTS: usize = 1_000;
/// How many lines after a decision a lookup reads for what was sent for it
/// (Guard sends at most a few actions per decision, right after it).
pub const SENT_LOOKAHEAD: usize = 64;
/// Longest journal line a lookup reads.
const MAX_LINE: usize = 1 << 20;
/// Most decisions indexed for lookups: the latest by nonce (nonces are
/// milliseconds, so the smallest are the oldest).
pub const MAX_INDEXED: usize = 200_000;

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("{path}: {message}")]
    Io { path: PathBuf, message: String },
    #[error("{path} line {line}: {message}; move the file aside after looking at it")]
    Damaged {
        path: PathBuf,
        line: usize,
        message: String,
    },
    #[error("the decision journal is broken after a failed write: {0}")]
    Broken(String),
    /// The writer is behind ([`QUEUE`] records waiting): this record was
    /// not taken. The journal is not broken.
    #[error("the decision journal's writer is behind; try again in a moment")]
    Busy,
}

/// Index a decision event at `offset`.
fn index_decision(decisions: &mut BTreeMap<u64, Vec<(String, u64)>>, event: &Value, offset: u64) {
    if event["kind"] != "decision" {
        return;
    }
    let (Some(nonce), Some(client)) = (event["nonce"].as_u64(), event["client"].as_str()) else {
        return;
    };
    decisions
        .entry(nonce)
        .or_default()
        .push((client.to_ascii_lowercase(), offset));
    while decisions.len() > MAX_INDEXED {
        decisions.pop_first();
    }
}

/// Read the decision at `offset` of the journal at `path`, check that it
/// is the one asked for (`nonce`, and `client` if given), and gather what
/// was sent for it: `{"decision": event, "sent": [events]}`.
pub fn read_decision(path: &Path, offset: u64, nonce: u64, client: Option<&str>) -> Option<Value> {
    let mut file = File::open(path).ok()?;
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut lines =
        BufReader::new(file.take(MAX_LINE as u64 * (SENT_LOOKAHEAD as u64 + 1))).lines();
    let decision: Value = serde_json::from_str::<Value>(&lines.next()?.ok()?)
        .ok()?
        .get("event")?
        .clone();
    let matches = decision["kind"] == "decision"
        && decision["nonce"].as_u64() == Some(nonce)
        && client.is_none_or(|client| {
            decision["client"]
                .as_str()
                .is_some_and(|by| by.eq_ignore_ascii_case(client))
        });
    if !matches {
        return None;
    }
    let seq = decision["seq"].as_u64()?;
    // What was sent for it: under the decision, or under an `intent` that
    // serves it (an action the decision did not name as it went out).
    let mut serving = vec![seq];
    let mut sent = Vec::new();
    for event in lines
        .take(SENT_LOOKAHEAD)
        .map_while(Result::ok)
        .map_while(|line| serde_json::from_str::<Value>(&line).ok())
        .filter_map(|line| line.get("event").cloned())
    {
        if event["kind"] == "intent"
            && event["of"].as_u64() == Some(seq)
            && let Some(intent) = event["seq"].as_u64()
        {
            serving.push(intent);
        }
        if event["kind"] == "sent"
            && event["decision"]
                .as_u64()
                .is_some_and(|decision| serving.contains(&decision))
        {
            sent.push(event);
        }
    }
    Some(serde_json::json!({"decision": decision, "sent": sent}))
}

/// Make the directory entry of `path` durable (a new file, a renamed or
/// created one); nothing to do where directories cannot be synced.
fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
            File::open(dir)?.sync_all()?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn check_of(prev: &str, event: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(prev.as_bytes());
    hasher.update(event.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// How much the journal file is extended by at a time, with zeros, so that
/// a sync commits data only (`docs/guard.md#journals`).
pub const ALLOCATE_STEP: u64 = 4 << 20;
/// Most records waiting for the writer; beyond it the journal is broken
/// and requests are refused, never sent unlogged.
pub const QUEUE: usize = 1_024;
/// Longest a record written without waiting stays unsynced.
pub const FLUSH_MS: u64 = 1_000;
/// Longest an intent waits for its sync; then the journal is broken.
pub const ACK_DEADLINE_MS: u64 = 2_000;

/// Where the writer thread keeps the journal: a file, or in tests a
/// simulated disk.
pub trait Storage: Send + 'static {
    /// Write `bytes` at `offset` (within the allocated length).
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()>;
    /// Make everything written so far durable.
    fn sync(&mut self) -> io::Result<()>;
    /// The allocated length.
    fn allocated(&self) -> u64;
    /// Extend the allocated length to `len` with zeros, durably.
    fn allocate(&mut self, len: u64) -> io::Result<()>;
    /// Give back what lies after `len` (a clean shutdown), durably.
    fn trim(&mut self, len: u64) -> io::Result<()>;
}

/// The journal file.
pub struct FileStorage {
    file: File,
    len: u64,
}

impl FileStorage {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }
}

impl Storage for FileStorage {
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(bytes)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }

    fn allocated(&self) -> u64 {
        self.len
    }

    fn allocate(&mut self, len: u64) -> io::Result<()> {
        // Real zeros, not a sparse extension: writing into blocks that
        // exist changes no metadata.
        self.file.seek(SeekFrom::Start(self.len))?;
        let zeros = vec![0u8; 1 << 20];
        let mut at = self.len;
        while at < len {
            let size = usize::try_from((len - at).min(zeros.len() as u64)).unwrap_or(zeros.len());
            self.file.write_all(&zeros[..size])?;
            at += size as u64;
        }
        self.file.sync_all()?;
        self.len = len;
        Ok(())
    }

    fn trim(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.file.sync_all()?;
        self.len = len;
        Ok(())
    }
}

/// Waiting for a record to be durable ([`DecisionJournal::append_durable`]).
#[derive(Debug)]
pub struct Durable {
    /// `None`: the writer was behind and took no flush (not an error of
    /// the journal: what was appended is synced within [`FLUSH_MS`]).
    done: Option<tokio::sync::oneshot::Receiver<Result<(), String>>>,
    broken: Broken,
}

type Broken = std::sync::Arc<std::sync::Mutex<Option<String>>>;

impl Durable {
    /// Wait until the record, and every record before it, is on disk: at
    /// most [`ACK_DEADLINE_MS`]; a sync that takes longer breaks the
    /// journal (a stalled disk must not hold Guard up).
    pub async fn wait(self) -> Result<(), JournalError> {
        let deadline = std::time::Duration::from_millis(ACK_DEADLINE_MS);
        let Some(done) = self.done else {
            return Err(JournalError::Busy);
        };
        let why = match tokio::time::timeout(deadline, done).await {
            Ok(Ok(Ok(()))) => return Ok(()),
            Ok(Ok(Err(why))) => why,
            Ok(Err(_)) => "the journal writer stopped".to_owned(),
            Err(_) => format!("the journal's sync took longer than {ACK_DEADLINE_MS} ms"),
        };
        if let Ok(mut broken) = self.broken.lock() {
            broken.get_or_insert_with(|| why.clone());
        }
        Err(JournalError::Broken(why))
    }

    /// A wait that fails at once.
    fn failed(why: String, broken: Broken) -> Self {
        let (ack, done) = tokio::sync::oneshot::channel();
        ack.send(Err(why)).ok();
        Self {
            done: Some(done),
            broken,
        }
    }
}

type Ack = tokio::sync::oneshot::Sender<Result<(), String>>;

enum Job {
    /// A record's bytes, with an ack when its writer waits for it.
    Line(Vec<u8>, Option<Ack>),
    /// Sync now, then ack.
    Flush(Ack),
    /// Sync, give back the unused tail, ack, and stop.
    Stop(Option<Ack>),
    /// Tests only: write nothing more until the sender is dropped.
    #[cfg(feature = "test-hooks")]
    Hold(std::sync::mpsc::Receiver<()>),
}

/// The writer thread: the journal file's only writer. It takes whatever is
/// queued, writes it in order, syncs once for all of it, then acks each
/// record that waits; records that do not wait are synced with the next
/// that does, or within [`FLUSH_MS`]. After any write or sync error it is
/// broken: every ack then fails, and nothing is written again.
fn writer<S: Storage>(
    mut storage: S,
    mut end: u64,
    jobs: std::sync::mpsc::Receiver<Job>,
    broken: Broken,
    synced: std::sync::Arc<std::sync::atomic::AtomicU64>,
    step: u64,
) {
    let flush = std::time::Duration::from_millis(FLUSH_MS);
    let mut unsynced_since: Option<std::time::Instant> = None;
    let mut failed: Option<String> = None;
    loop {
        let wait = unsynced_since.map_or(std::time::Duration::from_secs(3_600), |since| {
            flush.saturating_sub(since.elapsed())
        });
        let first = match jobs.recv_timeout(wait) {
            Ok(job) => Some(job),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Some(Job::Stop(None)),
        };
        let mut batch: Vec<Job> = first.into_iter().collect();
        while batch.len() < QUEUE
            && let Ok(job) = jobs.try_recv()
        {
            batch.push(job);
        }
        let mut acks = Vec::new();
        let mut sync_now = unsynced_since.is_some_and(|since| since.elapsed() >= flush);
        let mut stop = None;
        for job in batch {
            match job {
                Job::Line(bytes, ack) => {
                    if failed.is_none() {
                        let need = end + bytes.len() as u64;
                        // Ahead of need; on a full disk, exactly what the
                        // record needs.
                        let written = if need > storage.allocated() {
                            storage
                                .allocate(need.max(storage.allocated() + step))
                                .or_else(|_| storage.allocate(need))
                        } else {
                            Ok(())
                        }
                        .and_then(|()| storage.write_at(end, &bytes));
                        match written {
                            Ok(()) => {
                                end = need;
                                unsynced_since.get_or_insert_with(std::time::Instant::now);
                            }
                            Err(error) => failed = Some(format!("writing the journal: {error}")),
                        }
                    }
                    if let Some(ack) = ack {
                        sync_now = true;
                        acks.push(ack);
                    }
                }
                Job::Flush(ack) => {
                    sync_now = true;
                    acks.push(ack);
                }
                Job::Stop(ack) => {
                    sync_now = true;
                    stop = Some(ack);
                }
                #[cfg(feature = "test-hooks")]
                Job::Hold(release) => {
                    release.recv().ok();
                }
            }
        }
        if sync_now && failed.is_none() && unsynced_since.is_some() {
            match storage.sync() {
                Ok(()) => {
                    unsynced_since = None;
                    synced.store(end, std::sync::atomic::Ordering::SeqCst);
                }
                Err(error) => failed = Some(format!("syncing the journal: {error}")),
            }
        }
        if let Some(why) = &failed
            && let Ok(mut broken) = broken.lock()
        {
            broken.get_or_insert_with(|| why.clone());
        }
        let result = failed.clone().map_or(Ok(()), Err);
        for ack in acks {
            ack.send(result.clone()).ok();
        }
        // Room ahead of need, while nothing waits (a failure here breaks
        // nothing: the next record allocates what it needs).
        if failed.is_none() && stop.is_none() && storage.allocated().saturating_sub(end) < step / 4
        {
            storage.allocate(storage.allocated() + step).ok();
        }
        if let Some(ack) = stop {
            let trimmed = if failed.is_none() {
                storage
                    .trim(end)
                    .map_err(|error| format!("trimming the journal: {error}"))
            } else {
                result
            };
            if let Some(ack) = ack {
                ack.send(trimmed).ok();
            }
            return;
        }
    }
}

#[derive(Debug)]
pub struct DecisionJournal {
    path: PathBuf,
    prev: String,
    seq: u64,
    recent: VecDeque<Value>,
    /// Why the journal can no longer be written: set here when the queue is
    /// full or the writer is gone, by the writer on a write or sync error,
    /// and by a [`Durable`] whose sync missed its deadline.
    broken: Broken,
    /// Where the next record starts.
    len: u64,
    /// Up to where the file is durable (the writer moves it after each
    /// sync): each record carries it, for the reader after a crash.
    synced: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Every decision's place in the file by the client's nonce:
    /// `nonce -> [(client, offset)]`, oldest first.
    decisions: BTreeMap<u64, Vec<(String, u64)>>,
    /// The intents not yet resolved (recovery's input after a crash).
    tracker: Tracker,
    /// Records nothing waited for, not taken because the writer was behind.
    dropped: u64,
    /// Intents refused because the writer was behind (a protective one
    /// that waited counts once).
    busy: u64,
    /// Intents a record of which (a `sent`) was not taken: their `done` is
    /// not written either, so that recovery asks the venue about them.
    /// One entry per dropped `sent` at most; such an intent stays open in
    /// the tracker for the run anyway.
    lost: HashSet<u64>,
    /// What an earlier run left after its last whole record that was not
    /// zeros, moved aside when the journal was opened: the bytes, and the
    /// file they went to.
    cut: Option<(u64, PathBuf)>,
    jobs: Option<std::sync::mpsc::SyncSender<Job>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// What reading a journal found.
struct Contents {
    prev: String,
    seq: u64,
    recent: VecDeque<Value>,
    decisions: BTreeMap<u64, Vec<(String, u64)>>,
    tracker: Tracker,
    /// Where the last whole record ends.
    end: u64,
    /// The last whole record lacks its newline.
    needs_newline: bool,
    /// The bytes after `end` that are not zeros.
    tail: u64,
}

/// One line read: `None` when it is no record (not JSON, or without its
/// fields); else its check, prev, durable mark and event.
fn record_of(body: &[u8]) -> Option<(String, String, Option<u64>, Value)> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    let check = value.get("check")?.as_str()?.to_owned();
    let prev = value.get("prev")?.as_str()?.to_owned();
    let event = value.get("event")?.clone();
    Some((
        check,
        prev,
        value.get("durable").and_then(Value::as_u64),
        event,
    ))
}

/// Whether the line `body` is a record in itself (its checksum fits its
/// own `prev` and event) whose durable mark lies beyond `offset`: then the
/// bytes at `offset` were on disk when it was written.
/// Zeros a filesystem left in place of lost bytes may run into a record
/// on the same line: each run between zeros is looked at.
/// A whole record without a mark (written before marks existed, synced on
/// its own) proves the same.
fn proves_durable(body: &[u8], offset: u64) -> bool {
    body.split(|byte| *byte == 0).any(|part| {
        record_of(part).is_some_and(|(check, prev, mark, event)| {
            mark.is_none_or(|mark| mark > offset) && check_of(&prev, &event.to_string()) == check
        })
    })
}

/// Read a journal: every record that continues the chain. The first line
/// that does not (no record, a changed or reordered one) ends the
/// journal's records if it starts at or after the durable mark of the
/// last record before it: what follows was never synced (a crash), and is
/// the tail. Before the mark it is damage, refused. Records written before
/// the mark existed (no `durable`) count as durable to their own end.
fn read_records<R: Read>(source: R, path: &Path) -> Result<Contents, JournalError> {
    let io = |error: io::Error| JournalError::Io {
        path: path.to_owned(),
        message: error.to_string(),
    };
    let mut reader = BufReader::new(source);
    let mut read = Contents {
        prev: String::new(),
        seq: 0,
        recent: VecDeque::with_capacity(RECENT_EVENTS),
        decisions: BTreeMap::new(),
        tracker: Tracker::default(),
        end: 0,
        needs_newline: false,
        tail: 0,
    };
    let mut durable = 0u64;
    let mut line = Vec::new();
    let mut index = 0;
    loop {
        line.clear();
        let size = reader.read_until(b'\n', &mut line).map_err(io)?;
        if size == 0 {
            return Ok(read);
        }
        index += 1;
        let complete = line.last() == Some(&b'\n');
        let body = if complete {
            &line[..size - 1]
        } else {
            &line[..]
        };
        let damaged = |message: &str| JournalError::Damaged {
            path: path.to_owned(),
            line: index,
            message: message.to_owned(),
        };
        let continues = record_of(body).and_then(|(check, line_prev, mark, event)| {
            let fits = !read.needs_newline
                && line_prev == read.prev
                && check_of(&line_prev, &event.to_string()) == check
                && event["seq"].as_u64() == Some(read.seq + 1);
            fits.then_some((check, mark, event))
        });
        let Some((check, mark, event)) = continues else {
            // A record that says it was written after this point was on
            // disk proves this is damage, not a crash: the record before
            // it (`durable`), this one, or any later one.
            let why = match record_of(body) {
                None => "not a record",
                Some(_) => {
                    "the chain or the checksum does not match (a line was changed, removed or moved)"
                }
            };
            let bad_at = read.end;
            // A whole record written before the mark existed was synced on
            // its own: damage too.
            let old_format = record_of(body).is_some_and(|(_, _, mark, _)| mark.is_none());
            if bad_at < durable || old_format || proves_durable(body, bad_at) {
                return Err(damaged(why));
            }
            // From here on, what an earlier run never synced (or the
            // zeros the writer allocated).
            read.tail = line.iter().filter(|byte| **byte != 0).count() as u64;
            let mut rest = Vec::new();
            loop {
                rest.clear();
                let size = reader.read_until(b'\n', &mut rest).map_err(io)?;
                if size == 0 {
                    return Ok(read);
                }
                let body = rest.strip_suffix(b"\n").unwrap_or(&rest);
                if proves_durable(body, bad_at) {
                    return Err(damaged(why));
                }
                read.tail += rest.iter().filter(|byte| **byte != 0).count() as u64;
            }
        };
        let seq = event["seq"].as_u64().unwrap_or(0);
        read.seq = seq;
        read.prev = check;
        index_decision(&mut read.decisions, &event, read.end);
        read.end += size as u64;
        read.needs_newline = !complete;
        match mark {
            Some(mark) => {
                durable = durable.max(mark);
                read.tracker.observe(&event);
            }
            // Before the mark existed: synced record by record, and before
            // recovery existed.
            None => durable = durable.max(read.end),
        }
        if read.recent.len() == RECENT_EVENTS {
            read.recent.pop_front();
        }
        read.recent.push_back(event);
    }
}

impl DecisionJournal {
    /// Open the journal at `path`, creating it if it does not exist, after
    /// checking every record, and start its writer thread. What follows
    /// the last whole record (a write a crash cut short, zeros) is never
    /// read as records: bytes there that are not zeros are cleared, and
    /// [`DecisionJournal::cut_on_open`] says how many.
    pub fn open(path: &Path) -> Result<Self, JournalError> {
        let io = |error: io::Error| JournalError::Io {
            path: path.to_owned(),
            message: error.to_string(),
        };
        let read = if path.exists() {
            read_records(File::open(path).map_err(io)?, path)?
        } else {
            read_records(io::empty(), path)?
        };
        let new = !path.exists();
        let mut storage = FileStorage::open(path).map_err(io)?;
        if new {
            sync_dir(path).map_err(io)?;
        }
        let mut end = read.end;
        let mut cut = None;
        if read.tail > 0 {
            // What an earlier run never synced: kept aside, never deleted,
            // and cleared here so that it can never be read as records
            // after the next ones.
            let mut tail = Vec::new();
            let mut file = File::open(path).map_err(io)?;
            file.seek(SeekFrom::Start(end)).map_err(io)?;
            file.read_to_end(&mut tail).map_err(io)?;
            while tail.last() == Some(&0) {
                tail.pop();
            }
            let at_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_millis());
            let mut aside = path.as_os_str().to_owned();
            aside.push(format!(".cut-{at_ms}"));
            let aside = PathBuf::from(aside);
            let mut kept = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&aside)
                .map_err(io)?;
            kept.write_all(&tail)
                .and_then(|()| kept.sync_all())
                .and_then(|()| sync_dir(&aside))
                .map_err(io)?;
            let len = storage.allocated();
            let zeros = vec![0u8; usize::try_from(len - end).unwrap_or(0)];
            storage.write_at(end, &zeros).map_err(io)?;
            cut = Some((read.tail, aside));
        }
        if read.needs_newline {
            if storage.allocated() <= end {
                storage.allocate(end + 1).map_err(io)?;
            }
            storage.write_at(end, b"\n").map_err(io)?;
            end += 1;
        }
        // Room ahead, before anything waits on the writer; on a nearly
        // full disk the writer allocates what each record needs.
        if storage.allocated().saturating_sub(end) < ALLOCATE_STEP / 4 {
            storage
                .allocate(storage.allocated().max(end) + ALLOCATE_STEP)
                .ok();
        }
        storage.sync().map_err(io)?;
        let mut journal = Self::start(path, read, end, storage, ALLOCATE_STEP);
        journal.cut = cut;
        Ok(journal)
    }

    /// Start the writer thread on `storage`, the next record at `end`.
    fn start<S: Storage>(path: &Path, read: Contents, end: u64, storage: S, step: u64) -> Self {
        let broken: Broken = std::sync::Arc::new(std::sync::Mutex::new(None));
        let synced = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(end));
        let (jobs, queue) = std::sync::mpsc::sync_channel(QUEUE);
        let writer_broken = broken.clone();
        let writer_synced = synced.clone();
        let thread = std::thread::Builder::new()
            .name("guard-journal".into())
            .spawn(move || writer(storage, end, queue, writer_broken, writer_synced, step));
        let (jobs, thread) = match thread {
            Ok(thread) => (Some(jobs), Some(thread)),
            Err(error) => {
                if let Ok(mut broken) = broken.lock() {
                    *broken = Some(format!("the journal writer could not start: {error}"));
                }
                (None, None)
            }
        };
        Self {
            path: path.to_owned(),
            prev: read.prev,
            seq: read.seq,
            recent: read.recent,
            broken,
            len: end,
            synced,
            decisions: read.decisions,
            tracker: read.tracker,
            dropped: 0,
            busy: 0,
            lost: HashSet::new(),
            cut: None,
            jobs,
            thread,
        }
    }

    /// The bytes an earlier run left after its last whole record that were
    /// not zeros (unsynced writes a crash cut short), and the file they
    /// were moved to when the journal was opened: for Guard to record.
    pub fn cut_on_open(&self) -> Option<(u64, PathBuf)> {
        self.cut.clone()
    }

    /// The actions intents named that nothing answers yet (after a crash:
    /// what recovery asks the venue about).
    pub fn pending(&self) -> Vec<crate::recover::Pending> {
        self.tracker.pending()
    }

    /// `item` as the journal shows it now, given the venue's answers on
    /// its orders: shared also when an action written after it was taken
    /// names the same order, or another action names it by another name
    /// the answers show (an order id for a client id, or back).
    pub fn refreshed(
        &self,
        item: &crate::recover::Pending,
        answers: &[Value],
    ) -> crate::recover::Pending {
        let aliases = crate::recover::aliases(answers);
        crate::recover::Pending {
            shared: item.shared
                || self.tracker.shared(item.intent, item.index)
                || self.tracker.named_elsewhere(&item.action, &aliases),
            ..item.clone()
        }
    }

    /// Whether an answered send in the journal returned order id `oid`.
    pub fn answered_oid(&self, oid: u64) -> bool {
        self.tracker.answered_oid(oid)
    }

    fn broken_why(&self) -> Option<String> {
        self.broken.lock().ok().and_then(|broken| broken.clone())
    }

    fn set_broken(&self, why: &str) -> JournalError {
        if let Ok(mut broken) = self.broken.lock() {
            broken.get_or_insert_with(|| why.to_owned());
        }
        JournalError::Broken(why.to_owned())
    }

    /// Append an event; it is written by the writer thread and on disk
    /// within [`FLUSH_MS`], or with the next record that waits for the
    /// disk. Returns its sequence number. Only for a record nothing is sent
    /// on the strength of.
    pub fn append(&mut self, at_ms: i64, body: EventBody) -> Result<u64, JournalError> {
        self.enqueue(at_ms, body, None)
    }

    /// Append an intent Guard acts on whatever bots do (a protection, a
    /// flattening, a protective send) and wait until it is on disk. A
    /// writer behind (`Busy`) is waited for, at most
    /// [`ACK_DEADLINE_MS`] in all; one still behind then breaks the
    /// journal, as a sync that takes too long does (then the emergency log
    /// takes over, E1). Returns the record's `seq`.
    pub async fn append_durable_waiting(
        &mut self,
        at_ms: i64,
        body: EventBody,
    ) -> Result<u64, JournalError> {
        let started = std::time::Instant::now();
        let deadline = std::time::Duration::from_millis(ACK_DEADLINE_MS);
        let mut waited = false;
        loop {
            let appended = self.append_durable(at_ms, body.clone());
            // One refusal counted for the whole wait.
            if waited && matches!(appended, Err(JournalError::Busy)) {
                self.busy = self.busy.saturating_sub(1);
            }
            waited = true;
            match appended {
                Ok((seq, durable)) => {
                    let left = deadline.saturating_sub(started.elapsed());
                    return match tokio::time::timeout(left, durable.wait()).await {
                        Ok(result) => result.map(|()| seq),
                        Err(_) => Err(self.set_broken(&format!(
                            "the journal's sync took longer than {ACK_DEADLINE_MS} ms"
                        ))),
                    };
                }
                Err(JournalError::Busy) if started.elapsed() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(JournalError::Busy) => {
                    return Err(self.set_broken(&format!(
                        "the journal's writer stayed behind for {ACK_DEADLINE_MS} ms"
                    )));
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Append a record nothing waits for, waiting for a writer that is
    /// behind until `until` at most (then `Busy`, counted as dropped, the
    /// journal not broken): for records that must not be dropped
    /// (recovery's, which share one deadline).
    pub async fn append_waiting(
        &mut self,
        at_ms: i64,
        body: EventBody,
        until: std::time::Instant,
    ) -> Result<u64, JournalError> {
        loop {
            match self.append(at_ms, body.clone()) {
                Err(JournalError::Busy) if std::time::Instant::now() < until => {
                    // Not dropped yet: counted only if it stays out.
                    self.dropped = self.dropped.saturating_sub(1);
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                result => return result,
            }
        }
    }

    /// [`DecisionJournal::flush`], waiting for room in a writer that is
    /// behind until `until` at most; the returned wait (made without the
    /// journal) answers `Busy` if there was none (what is queued is synced
    /// within [`FLUSH_MS`] all the same).
    pub async fn flush_when_room(&mut self, until: std::time::Instant) -> Durable {
        loop {
            let durable = self.flush();
            if durable.done.is_some() || std::time::Instant::now() >= until {
                return durable;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// Append an event that must be on disk before Guard acts on it (an
    /// intent: a decision to send, a protection or a flattening): wait on
    /// the returned [`Durable`] before sending.
    pub fn append_durable(
        &mut self,
        at_ms: i64,
        body: EventBody,
    ) -> Result<(u64, Durable), JournalError> {
        let (ack, done) = tokio::sync::oneshot::channel();
        let seq = self.enqueue(at_ms, body, Some(ack))?;
        Ok((
            seq,
            Durable {
                done: Some(done),
                broken: self.broken.clone(),
            },
        ))
    }

    /// Everything appended so far, on disk. A writer behind takes no
    /// flush: the wait then answers `Busy` at once, and the journal is not
    /// broken (the writer syncs what it has within [`FLUSH_MS`]).
    pub fn flush(&mut self) -> Durable {
        let (ack, done) = tokio::sync::oneshot::channel();
        let sent = match &self.jobs {
            Some(jobs) => jobs.try_send(Job::Flush(ack)),
            None => Err(std::sync::mpsc::TrySendError::Disconnected(Job::Flush(ack))),
        };
        match sent {
            Ok(()) => Durable {
                done: Some(done),
                broken: self.broken.clone(),
            },
            Err(std::sync::mpsc::TrySendError::Full(_)) => Durable {
                done: None,
                broken: self.broken.clone(),
            },
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => Durable::failed(
                self.broken_why()
                    .unwrap_or_else(|| "the journal writer is gone".into()),
                self.broken.clone(),
            ),
        }
    }

    fn enqueue(
        &mut self,
        at_ms: i64,
        body: EventBody,
        ack: Option<Ack>,
    ) -> Result<u64, JournalError> {
        if let Some(why) = self.broken_why() {
            return Err(JournalError::Broken(why));
        }
        // An intent that lost a record stays open: no `done` for it.
        if let EventBody::Done { intent } = &body
            && self.lost.remove(intent)
        {
            return Err(JournalError::Busy);
        }
        let lost = match &body {
            EventBody::Sent { decision, .. } => Some(*decision),
            _ => None,
        };
        let event = GuardEvent {
            seq: self.seq + 1,
            at_ms,
            body,
        };
        let value = serde_json::to_value(&event).map_err(|error| JournalError::Io {
            path: self.path.clone(),
            message: error.to_string(),
        })?;
        // The text as written is the text read back: serde_json writes a
        // `Value` the same way both times.
        let text = value.to_string();
        let check = check_of(&self.prev, &text);
        let durable = self.synced.load(std::sync::atomic::Ordering::SeqCst);
        let line = format!(
            "{{\"check\":\"{check}\",\"prev\":\"{}\",\"durable\":{durable},\"event\":{text}}}\n",
            self.prev
        );
        let Some(jobs) = &self.jobs else {
            return Err(self.set_broken("the journal writer is gone"));
        };
        let size = line.len() as u64;
        match jobs.try_send(Job::Line(line.into_bytes(), ack)) {
            Ok(()) => {}
            // Behind: not taken, the chain unchanged; an intent's request
            // is refused, a record nothing waits for is dropped and
            // counted (recovery asks the venue about a lost `sent`).
            Err(std::sync::mpsc::TrySendError::Full(job)) => {
                if matches!(job, Job::Line(_, Some(_))) {
                    self.busy = self.busy.saturating_add(1);
                } else {
                    self.dropped = self.dropped.saturating_add(1);
                    if let Some(intent) = lost {
                        self.lost.insert(intent);
                    }
                }
                return Err(JournalError::Busy);
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                return Err(self.set_broken("the journal writer is gone"));
            }
        }
        self.seq = event.seq;
        self.prev = check;
        index_decision(&mut self.decisions, &value, self.len);
        self.tracker.observe(&value);
        self.len += size;
        if self.recent.len() == RECENT_EVENTS {
            self.recent.pop_front();
        }
        self.recent.push_back(value);
        Ok(self.seq)
    }

    /// Records not taken because the writer was behind, since the journal
    /// was opened.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Intents refused because the writer was behind, since the journal
    /// was opened.
    pub fn busy(&self) -> u64 {
        self.busy
    }

    /// Guard's decision on the request with `nonce` (from `client`, if
    /// given), and what was sent for it, from memory: the last
    /// [`RECENT_EVENTS`] events, whether the writer has written them yet
    /// or not. `None` when it is older (then [`read_decision`] finds it
    /// on disk).
    pub fn recent_decision(&self, nonce: u64, client: Option<&str>) -> Option<Value> {
        let decision = self.recent.iter().rev().find(|event| {
            event["kind"] == "decision"
                && event["nonce"].as_u64() == Some(nonce)
                && client.is_none_or(|client| {
                    event["client"]
                        .as_str()
                        .is_some_and(|by| by.eq_ignore_ascii_case(client))
                })
        })?;
        let seq = decision["seq"].as_u64()?;
        let mut serving = vec![seq];
        let mut sent = Vec::new();
        for event in self
            .recent
            .iter()
            .filter(|event| event["seq"].as_u64().is_some_and(|at| at > seq))
            .take(SENT_LOOKAHEAD)
        {
            if event["kind"] == "intent"
                && event["of"].as_u64() == Some(seq)
                && let Some(intent) = event["seq"].as_u64()
            {
                serving.push(intent);
            }
            if event["kind"] == "sent"
                && event["decision"]
                    .as_u64()
                    .is_some_and(|decision| serving.contains(&decision))
            {
                sent.push(event.clone());
            }
        }
        Some(serde_json::json!({"decision": decision, "sent": sent}))
    }

    /// Tests only (feature `test-hooks`): up to where the file is on disk.
    #[cfg(feature = "test-hooks")]
    pub fn synced_for_test(&self) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        self.synced.clone()
    }

    /// Tests only (feature `test-hooks`): the writer writes nothing more
    /// until the returned sender is dropped.
    #[cfg(feature = "test-hooks")]
    pub fn hold_writer_for_test(&self) -> std::sync::mpsc::Sender<()> {
        let (release, held) = std::sync::mpsc::channel();
        if let Some(jobs) = &self.jobs {
            jobs.send(Job::Hold(held)).ok();
        }
        release
    }

    /// Tests only (feature `test-hooks`): fill the writer's queue with
    /// records (hold the writer first).
    #[cfg(feature = "test-hooks")]
    pub fn fill_queue_for_test(&mut self) {
        while self
            .append(
                0,
                EventBody::Error {
                    text: "filler".into(),
                },
            )
            .is_ok()
        {}
    }

    /// Tests only (feature `test-hooks`): break the journal, as a failed
    /// write would.
    #[cfg(feature = "test-hooks")]
    pub fn break_for_test(&self) {
        self.set_broken("broken by a test");
    }

    /// Write and sync everything queued, give back the unused tail, and
    /// stop the writer.
    pub async fn close(&mut self) -> Result<(), JournalError> {
        let (ack, done) = tokio::sync::oneshot::channel();
        let Some(jobs) = self.jobs.take() else {
            return Err(JournalError::Broken(
                self.broken_why()
                    .unwrap_or_else(|| "the journal writer is gone".into()),
            ));
        };
        // A writer behind gets the stop when it has room (waited for off the
        // runtime, within the wait below); a gone one never.
        let stopped = match jobs.try_send(Job::Stop(Some(ack))) {
            Ok(()) => true,
            Err(std::sync::mpsc::TrySendError::Full(job)) => std::thread::Builder::new()
                .name("guard-journal-stop".into())
                .spawn(move || jobs.send(job).ok())
                .is_ok(),
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
        };
        if !stopped {
            // Never joined: a writer stuck on a hung disk must not hold
            // up the process's exit.
            self.thread.take();
            return Err(self.set_broken("the journal writer is gone"));
        }
        let closed = Durable {
            done: Some(done),
            broken: self.broken.clone(),
        }
        .wait()
        .await;
        let thread = self.thread.take();
        if closed.is_ok()
            && let Some(thread) = thread
        {
            // It acked its stop: it returns at once.
            thread.join().ok();
        }
        closed
    }

    /// The events after `since`, oldest first, from memory.
    pub fn since(&self, since: u64) -> Vec<Value> {
        self.recent
            .iter()
            .filter(|event| event["seq"].as_u64().is_some_and(|seq| seq > since))
            .cloned()
            .collect()
    }

    /// Where Guard's decision on the request with this client `nonce`
    /// (from `client`, if given; else the latest with that nonce) starts in
    /// the journal file, for [`read_decision`].
    pub fn decision_offset(&self, nonce: u64, client: Option<&str>) -> Option<(PathBuf, u64)> {
        let client = client.map(str::to_ascii_lowercase);
        let offset = self
            .decisions
            .get(&nonce)?
            .iter()
            .rev()
            .find(|(by, _)| client.as_ref().is_none_or(|client| client == by))
            .map(|(_, offset)| *offset)?;
        Some((self.path.clone(), offset))
    }

    /// [`DecisionJournal::decision_offset`] and [`read_decision`] at once.
    pub fn find_decision(&self, nonce: u64, client: Option<&str>) -> Option<Value> {
        if let Some(found) = self.recent_decision(nonce, client) {
            return Some(found);
        }
        let (path, offset) = self.decision_offset(nonce, client)?;
        read_decision(&path, offset, nonce, client)
    }

    pub fn last_seq(&self) -> u64 {
        self.seq
    }

    pub fn is_broken(&self) -> bool {
        self.broken_why().is_some()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DecisionJournal {
    /// Stop the writer after it wrote and synced what is queued.
    fn drop(&mut self) {
        if let Some(jobs) = self.jobs.take() {
            jobs.send(Job::Stop(None)).ok();
        }
        if let Some(thread) = self.thread.take() {
            thread.join().ok();
        }
    }
}

/// The emergency log (`docs/guard.md#journals`, E1): where Guard
/// records a protective send (a flattening, a protective stop, a close)
/// it makes while the decision journal cannot be written, before sending
/// it where it can. Its own file, best on another disk; the same record
/// shape, chained in itself; each record written and synced on its own
/// (it is rare, and the decision journal's writer is the one that
/// failed).
#[derive(Debug)]
pub struct EmergencyLog {
    path: PathBuf,
    prev: String,
    seq: u64,
    /// Tests only: a hung disk (each write waits until the gate is open),
    /// and how many writes were begun.
    #[cfg(feature = "test-hooks")]
    hold: Option<Gate>,
    #[cfg(feature = "test-hooks")]
    attempts: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

/// Tests only: a gate a write waits at until it is open (`true`).
#[cfg(feature = "test-hooks")]
pub type Gate = std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>;

impl EmergencyLog {
    /// The log at `path`, continuing its chain if it exists (read lazily:
    /// nothing is created until the first record).
    pub fn new(path: &Path) -> Self {
        let mut prev = String::new();
        let mut seq = 0;
        if let Ok(file) = File::open(path) {
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                if let Some((check, _, _, event)) = record_of(line.as_bytes()) {
                    prev = check;
                    seq = event["seq"].as_u64().unwrap_or(seq);
                }
            }
        }
        Self {
            path: path.to_owned(),
            prev,
            seq,
            #[cfg(feature = "test-hooks")]
            hold: None,
            #[cfg(feature = "test-hooks")]
            attempts: Default::default(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Tests only (feature `test-hooks`): every write from now on waits at
    /// `gate` (a hung disk); returns how many writes were begun, as it
    /// moves.
    #[cfg(feature = "test-hooks")]
    pub fn hold_for_test(&mut self, gate: Gate) -> std::sync::Arc<std::sync::atomic::AtomicU64> {
        self.hold = Some(gate);
        self.attempts.clone()
    }

    /// Append `body` and sync it.
    pub fn append(&mut self, at_ms: i64, body: EventBody) -> io::Result<u64> {
        #[cfg(feature = "test-hooks")]
        {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(gate) = &self.hold {
                let (open, opened) = &**gate;
                let mut is_open = open.lock().map_err(|_| io::Error::other("poisoned"))?;
                while !*is_open {
                    is_open = opened
                        .wait(is_open)
                        .map_err(|_| io::Error::other("poisoned"))?;
                }
            }
        }
        let event = GuardEvent {
            seq: self.seq + 1,
            at_ms,
            body,
        };
        let text = serde_json::to_value(&event)
            .map_err(io::Error::other)?
            .to_string();
        let check = check_of(&self.prev, &text);
        let line = format!(
            "{{\"check\":\"{check}\",\"prev\":\"{}\",\"event\":{text}}}\n",
            self.prev
        );
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let new = !self.path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        // Written: the next record follows it, whether this sync succeeds
        // or not.
        self.seq = event.seq;
        self.prev = check;
        file.sync_data()?;
        if new {
            sync_dir(&self.path)?;
        }
        Ok(self.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdir::TestDir;

    fn kill(reason: &str) -> EventBody {
        EventBody::Kill {
            reason: reason.into(),
        }
    }

    #[test]
    fn events_chain_and_reopen() {
        let dir = TestDir::new("journal-chain");
        let path = dir.path().join("decisions.jsonl");
        let mut journal = DecisionJournal::open(&path).unwrap();
        assert_eq!(journal.append(1, kill("a")).unwrap(), 1);
        assert_eq!(journal.append(2, kill("b")).unwrap(), 2);
        drop(journal);
        let mut reopened = DecisionJournal::open(&path).unwrap();
        assert_eq!(reopened.last_seq(), 2);
        assert_eq!(reopened.append(3, kill("c")).unwrap(), 3);
        assert_eq!(reopened.since(1).len(), 2);
        assert_eq!(reopened.since(0)[0]["reason"], "a");
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn an_intent_is_on_disk_when_its_wait_returns() {
        let dir = TestDir::new("journal-durable");
        let path = dir.path().join("decisions.jsonl");
        let mut journal = DecisionJournal::open(&path).unwrap();
        journal.append(1, kill("not waited for")).unwrap();
        let (seq, durable) = journal.append_durable(2, kill("intent")).unwrap();
        assert_eq!(seq, 2);
        runtime().block_on(durable.wait()).unwrap();
        // On disk, both (the file is allocated ahead: zeros after them).
        let bytes = std::fs::read(&path).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("not waited for") && text.contains("intent"));
        assert!(bytes.len() as u64 >= ALLOCATE_STEP);
        runtime().block_on(journal.flush().wait()).unwrap();
        runtime().block_on(journal.close()).unwrap();
        drop(journal);
        // A clean close gives the zeros back.
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert!(!bytes.contains(&0));
        let reopened = DecisionJournal::open(&path).unwrap();
        assert_eq!((reopened.last_seq(), reopened.cut_on_open()), (2, None));
    }

    #[test]
    fn a_full_queue_or_a_gone_writer_breaks_the_journal() {
        let dir = TestDir::new("journal-gone");
        let path = dir.path().join("decisions.jsonl");
        let mut journal = DecisionJournal::open(&path).unwrap();
        runtime().block_on(journal.close()).unwrap();
        assert!(journal.append(1, kill("after")).is_err());
        assert!(journal.is_broken());
        assert!(runtime().block_on(journal.flush().wait()).is_err());
    }

    /// The files beside the journal that hold what an open moved aside.
    fn cut_files(dir: &TestDir) -> Vec<Vec<u8>> {
        let mut files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".cut-"))
            .map(|entry| std::fs::read(entry.path()).unwrap())
            .collect();
        files.sort();
        files
    }

    /// What a crash can leave after the last durable record: nothing,
    /// part of a record, zeros, records kept out of order. The journal
    /// opens at the last record that continues the chain, moves what
    /// follows aside (never deletes it), clears it, and the chain goes on.
    #[test]
    fn what_a_crash_leaves_after_the_last_durable_record_is_moved_aside() {
        let dir = TestDir::new("journal-crash");
        let path = dir.path().join("decisions.jsonl");
        let mut journal = DecisionJournal::open(&path).unwrap();
        journal.append(1, kill("decision")).unwrap();
        journal.append(2, kill("sent")).unwrap();
        drop(journal);
        let full = std::fs::read(&path).unwrap();
        let first_end = full.iter().position(|byte| *byte == b'\n').unwrap() + 1;
        // Lost entirely: nothing to cut.
        std::fs::write(&path, &full[..first_end]).unwrap();
        let journal = DecisionJournal::open(&path).unwrap();
        assert_eq!((journal.last_seq(), journal.cut_on_open()), (1, None));
        drop(journal);
        // Half of it: moved aside.
        let half = first_end + (full.len() - first_end) / 2;
        std::fs::write(&path, &full[..half]).unwrap();
        let mut journal = DecisionJournal::open(&path).unwrap();
        assert_eq!(journal.last_seq(), 1);
        let (bytes, aside) = journal.cut_on_open().unwrap();
        assert_eq!(bytes, (half - first_end) as u64);
        assert_eq!(std::fs::read(aside).unwrap(), full[first_end..half]);
        assert_eq!(journal.append(3, kill("again")).unwrap(), 2);
        drop(journal);
        assert_eq!(DecisionJournal::open(&path).unwrap().last_seq(), 2);
        // Zeros where it was, then the writer's allocated zeros.
        let mut zeros = full[..first_end].to_vec();
        zeros.extend(std::iter::repeat_n(0u8, 3 * (full.len() - first_end)));
        std::fs::write(&path, &zeros).unwrap();
        let journal = DecisionJournal::open(&path).unwrap();
        assert_eq!((journal.last_seq(), journal.cut_on_open()), (1, None));
        drop(journal);
        // Part of it, zeros, then the whole record again (a power loss
        // that kept a later page): all of it after the first record moved
        // aside and cleared.
        let mut mixed = full[..half].to_vec();
        mixed.extend(std::iter::repeat_n(0u8, 40));
        mixed.extend_from_slice(&full[first_end..]);
        std::fs::write(&path, &mixed).unwrap();
        let journal = DecisionJournal::open(&path).unwrap();
        assert_eq!(journal.last_seq(), 1);
        assert!(journal.cut_on_open().is_some());
        drop(journal);
        assert_eq!(std::fs::read(&path).unwrap(), full[..first_end]);
        // Whole but for its newline: kept, the newline added.
        std::fs::write(&path, &full[..full.len() - 1]).unwrap();
        let journal = DecisionJournal::open(&path).unwrap();
        assert_eq!((journal.last_seq(), journal.cut_on_open()), (2, None));
        drop(journal);
        assert_eq!(std::fs::read(&path).unwrap(), full);
        // The only line unfinished: nothing left of it.
        std::fs::write(&path, &full[..first_end / 2]).unwrap();
        let journal = DecisionJournal::open(&path).unwrap();
        assert_eq!(journal.last_seq(), 0);
        assert_eq!(journal.cut_on_open().unwrap().0, (first_end / 2) as u64);
        drop(journal);
        // The last record changed: it was written after the last durable
        // mark (nothing was synced before it), so a crash could have left
        // it so: moved aside as well.
        let text = String::from_utf8(full.clone()).unwrap();
        std::fs::write(&path, text.replacen("\"sent\"", "\"sEnt\"", 1)).unwrap();
        let journal = DecisionJournal::open(&path).unwrap();
        assert_eq!(journal.last_seq(), 1);
        drop(journal);
        assert_eq!(cut_files(&dir).len(), 4);
    }

    /// A record before the last durable mark (a later record says it was on
    /// disk) that does not check out is damage, not a crash: refused.
    #[test]
    fn damage_before_the_durable_mark_is_refused() {
        let dir = TestDir::new("journal-durable-damage");
        let path = dir.path().join("decisions.jsonl");
        let mut journal = DecisionJournal::open(&path).unwrap();
        journal.append(1, kill("first")).unwrap();
        runtime().block_on(journal.flush().wait()).unwrap();
        journal.append(2, kill("second")).unwrap();
        drop(journal);
        let text = std::fs::read_to_string(&path).unwrap();
        // The first, changed, or gone, or zeroed.
        std::fs::write(&path, text.replacen("\"first\"", "\"FIRST\"", 1)).unwrap();
        assert!(matches!(
            DecisionJournal::open(&path),
            Err(JournalError::Damaged { line: 1, .. })
        ));
        // Gone: the second's mark says the first was on disk.
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, format!("{}\n", lines[1])).unwrap();
        assert!(matches!(
            DecisionJournal::open(&path),
            Err(JournalError::Damaged { line: 1, .. })
        ));
        // Zeroed: likewise.
        let mut zeroed = vec![0u8; lines[0].len() + 1];
        zeroed.extend_from_slice(lines[1].as_bytes());
        zeroed.push(b'\n');
        std::fs::write(&path, &zeroed).unwrap();
        assert!(DecisionJournal::open(&path).is_err());
        // The second alone changed (after the mark, written after the last
        // sync): a crash may leave that; moved aside.
        std::fs::write(&path, text.replacen("\"second\"", "\"SECOND\"", 1)).unwrap();
        let journal = DecisionJournal::open(&path).unwrap();
        assert_eq!(journal.last_seq(), 1);
    }

    /// A journal written before the durable mark existed (every record
    /// synced on its own): each record counts as durable to its end, so a
    /// changed one is refused, not cut.
    #[test]
    fn a_journal_from_before_the_mark_counts_every_record_as_durable() {
        let dir = TestDir::new("journal-old-format");
        let path = dir.path().join("decisions.jsonl");
        let mut prev = String::new();
        let mut text = String::new();
        for seq in 1..=2u64 {
            let event =
                serde_json::json!({"seq": seq, "at_ms": seq, "kind": "kill", "reason": "x"});
            let body = event.to_string();
            let check = check_of(&prev, &body);
            text.push_str(&format!(
                "{{\"check\":\"{check}\",\"prev\":\"{prev}\",\"event\":{body}}}\n"
            ));
            prev = check;
        }
        std::fs::write(&path, &text).unwrap();
        assert_eq!(DecisionJournal::open(&path).unwrap().last_seq(), 2);
        std::fs::write(&path, text.replacen("\"x\"", "\"y\"", 1)).unwrap();
        assert!(matches!(
            DecisionJournal::open(&path),
            Err(JournalError::Damaged { line: 1, .. })
        ));
        // The last one changed: also refused (it was synced on its own).
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(
            &path,
            format!("{}\n{}\n", lines[0], lines[1].replacen("\"x\"", "\"y\"", 1)),
        )
        .unwrap();
        assert!(DecisionJournal::open(&path).is_err());
        // A line garbled in the middle with a whole record of the old
        // format after it: that one was synced on its own, so the garbled
        // line was on disk before it. Damage, not what a crash cut short.
        let event =
            serde_json::json!({"seq": 3, "at_ms": 3, "kind": "kill", "reason": "x"}).to_string();
        let check = check_of(&prev, &event);
        let third = format!("{{\"check\":\"{check}\",\"prev\":\"{prev}\",\"event\":{event}}}\n");
        std::fs::write(&path, format!("{}\ngarbled\n{third}", lines[0])).unwrap();
        assert!(matches!(
            DecisionJournal::open(&path),
            Err(JournalError::Damaged { line: 2, .. })
        ));
    }

    #[test]
    fn a_changed_or_missing_line_is_refused() {
        let dir = TestDir::new("journal-damage");
        let path = dir.path().join("decisions.jsonl");
        let mut journal = DecisionJournal::open(&path).unwrap();
        for at in 1..=3 {
            journal.append(at, kill("x")).unwrap();
            runtime().block_on(journal.flush().wait()).unwrap();
        }
        drop(journal);
        let text = std::fs::read_to_string(&path).unwrap();
        // A changed reason.
        std::fs::write(&path, text.replacen("\"x\"", "\"y\"", 1)).unwrap();
        assert!(matches!(
            DecisionJournal::open(&path),
            Err(JournalError::Damaged { line: 1, .. })
        ));
        // A missing middle line.
        let lines: Vec<&str> = text.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(matches!(
            DecisionJournal::open(&path),
            Err(JournalError::Damaged { line: 2, .. })
        ));
    }
}

#[cfg(test)]
mod lookup_tests {
    use zunder_guard_core::judge::Verdict;

    use super::*;
    use crate::testdir::TestDir;

    fn decision(nonce: u64, client: &str, text: &str) -> EventBody {
        EventBody::Decision {
            via: "http".into(),
            client: Some(client.into()),
            signed_as: None,
            nonce: Some(nonce),
            action: Some("order".into()),
            verdict: Verdict::Veto,
            code: "open_risk".into(),
            text: text.into(),
            changes: Vec::new(),
            request: None,
            pre: Vec::new(),
            forward: None,
            post: Vec::new(),
        }
    }

    #[test]
    fn decisions_are_found_by_nonce_after_a_reopen_and_checked() {
        let dir = TestDir::new("journal-lookup");
        let path = dir.path().join("decisions.jsonl");
        let mut journal = DecisionJournal::open(&path).unwrap();
        // Multi-byte text before and between: offsets count bytes.
        journal
            .append(1, decision(100, "0xAA", "Größe über dem Budget, 2 € — ✓"))
            .unwrap();
        let seq = journal.append(2, decision(200, "0xaa", "zweite")).unwrap();
        journal
            .append(
                3,
                EventBody::Sent {
                    decision: seq,
                    nonce: 9,
                    ok: true,
                    reply: serde_json::json!({"status": "ok"}),
                    action: None,
                    index: None,
                },
            )
            .unwrap();
        journal
            .append(4, decision(200, "0xbb", "another bot, same nonce"))
            .unwrap();
        drop(journal);
        let journal = DecisionJournal::open(&path).unwrap();
        let found = journal.find_decision(200, Some("0xAA")).unwrap();
        assert_eq!(found["decision"]["text"], "zweite");
        assert_eq!(found["sent"].as_array().unwrap().len(), 1);
        // Without a client: the latest with that nonce.
        assert_eq!(
            journal.find_decision(200, None).unwrap()["decision"]["client"],
            "0xbb"
        );
        assert_eq!(
            journal.find_decision(100, None).unwrap()["decision"]["text"],
            "Größe über dem Budget, 2 € — ✓"
        );
        assert!(journal.find_decision(300, None).is_none());
        assert!(journal.find_decision(100, Some("0xcc")).is_none());
        // An offset that does not hold the decision asked for: nothing.
        let (path, _) = journal.decision_offset(200, Some("0xaa")).unwrap();
        assert!(read_decision(&path, 0, 200, None).is_none());
    }

    #[test]
    fn a_last_line_without_its_newline_gets_one() {
        let dir = TestDir::new("journal-newline");
        let path = dir.path().join("decisions.jsonl");
        let mut journal = DecisionJournal::open(&path).unwrap();
        journal.append(1, decision(100, "0xaa", "one")).unwrap();
        drop(journal);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.trim_end_matches('\n')).unwrap();
        let mut journal = DecisionJournal::open(&path).unwrap();
        journal.append(2, decision(200, "0xaa", "two")).unwrap();
        drop(journal);
        let journal = DecisionJournal::open(&path).unwrap();
        assert_eq!(journal.last_seq(), 2);
        assert_eq!(
            journal.find_decision(200, None).unwrap()["decision"]["text"],
            "two"
        );
    }
}

/// Crash injection (`docs/guard.md#journals`): the
/// journal runs on a simulated disk that keeps what was synced apart from
/// what was only written; a model of Guard sends intents and actions in
/// random sequences; at every send the disk image a power loss would
/// leave must hold the intent (J1); at random points a crash leaves one
/// of several images (nothing unsynced kept, a prefix of it, random pages
/// kept or zeroed, all of it), which must open (J7), keep the chain (J5),
/// and leave every action the venue executed either answered or pending
/// for recovery (J3), with no answer claiming an action that did not
/// happen (J2).
#[cfg(test)]
mod crash_tests {
    use std::{
        collections::BTreeSet,
        io::Cursor,
        sync::{Arc, Mutex},
    };

    use serde_json::{Value, json};
    use zunder_guard_core::event::EventBody;

    use super::*;
    use crate::recover::{intent_actions, pending};

    /// What was written, and what a sync made durable.
    #[derive(Debug, Default, Clone)]
    struct Disk {
        written: Vec<u8>,
        durable: Vec<u8>,
    }

    #[derive(Clone)]
    struct MemStorage(Arc<Mutex<Disk>>);

    impl Storage for MemStorage {
        fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
            let mut disk = self.0.lock().unwrap();
            let start = usize::try_from(offset).unwrap();
            let end = start + bytes.len();
            assert!(end <= disk.written.len(), "a write past the allocated end");
            disk.written[start..end].copy_from_slice(bytes);
            Ok(())
        }

        fn sync(&mut self) -> io::Result<()> {
            let mut disk = self.0.lock().unwrap();
            disk.durable = disk.written.clone();
            Ok(())
        }

        fn allocated(&self) -> u64 {
            self.0.lock().unwrap().written.len() as u64
        }

        fn allocate(&mut self, len: u64) -> io::Result<()> {
            let mut disk = self.0.lock().unwrap();
            let len = usize::try_from(len).unwrap();
            // Durably, as the real allocation syncs it (zeros only).
            disk.written.resize(len, 0);
            let durable_len = disk.durable.len().max(len);
            disk.durable.resize(durable_len, 0);
            Ok(())
        }

        fn trim(&mut self, len: u64) -> io::Result<()> {
            let mut disk = self.0.lock().unwrap();
            let len = usize::try_from(len).unwrap();
            disk.written.truncate(len);
            disk.durable.truncate(len);
            Ok(())
        }
    }

    /// The images a crash may leave of `disk`.
    fn crash_images(disk: &Disk, rng: &mut fastrand::Rng) -> Vec<Vec<u8>> {
        let len = disk.written.len().max(disk.durable.len());
        let mut durable = disk.durable.clone();
        durable.resize(len, 0);
        let mut written = disk.written.clone();
        written.resize(len, 0);
        let differs: Vec<usize> = (0..len).filter(|at| durable[*at] != written[*at]).collect();
        let mut images = vec![durable.clone(), written.clone()];
        if let (Some(first), Some(last)) = (differs.first(), differs.last()) {
            // A prefix of what was not synced.
            let cut = rng.usize(*first..=*last);
            let mut prefix = durable.clone();
            prefix[*first..cut].copy_from_slice(&written[*first..cut]);
            images.push(prefix);
            // Sectors written or not at random (a sector is written whole
            // or not at all: one that also holds synced bytes keeps them
            // either way; where nothing was synced the old content is the
            // allocated zeros).
            const SECTOR: usize = 512;
            let mut pages = durable.clone();
            let mut at = *first - *first % SECTOR;
            while at <= *last {
                let end = (at + SECTOR).min(len);
                if rng.bool() {
                    pages[at..end].copy_from_slice(&written[at..end]);
                }
                at = end;
            }
            images.push(pages);
        }
        images
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// The intents' actions a reader finds in `image`.
    fn named(image: &[u8]) -> Vec<Value> {
        let read = read_records(Cursor::new(image), Path::new("image")).unwrap();
        read.recent
            .iter()
            .filter_map(intent_actions)
            .flatten()
            .collect()
    }

    /// One random run: returns how many crash images were checked.
    fn run(seed: u64) -> usize {
        let mut rng = fastrand::Rng::with_seed(seed);
        let disk = Arc::new(Mutex::new(Disk::default()));
        let storage = MemStorage(disk.clone());
        let empty = read_records(io::empty(), Path::new("image")).unwrap();
        let mut journal = DecisionJournal::start(Path::new("image"), empty, 0, storage, 1_024);
        let runtime = runtime();
        // What the model venue executed, and what Guard answered.
        let mut executed: BTreeSet<String> = BTreeSet::new();
        let mut next = 0u64;
        let mut images = 0;
        let ops = rng.usize(5..40);
        for op in 0..ops {
            match rng.u8(0..10) {
                // Records nothing waits for.
                0..=2 => {
                    journal
                        .append(
                            op as i64,
                            EventBody::Error {
                                text: "x".repeat(rng.usize(1..300)),
                            },
                        )
                        .unwrap();
                }
                3 => {
                    runtime.block_on(journal.flush().wait()).unwrap();
                }
                // An intent with one to three actions, sent one by one.
                _ => {
                    let actions: Vec<Value> = (0..rng.usize(1..4))
                        .map(|_| {
                            next += 1;
                            json!({"type": "order", "id": format!("a{next}"), "pad": "y".repeat(rng.usize(0..200))})
                        })
                        .collect();
                    let (seq, durable) = journal
                        .append_durable(
                            op as i64,
                            EventBody::Flatten {
                                reason: "test".into(),
                                actions: actions.clone(),
                                problems: Vec::new(),
                                sent: true,
                            },
                        )
                        .unwrap();
                    runtime.block_on(durable.wait()).unwrap();
                    for (index, action) in actions.iter().enumerate() {
                        // Guard may stop before sending the rest.
                        if rng.u8(0..10) == 0 {
                            break;
                        }
                        // J1: what a power loss leaves now holds the intent.
                        let image = disk.lock().unwrap().durable.clone();
                        assert!(
                            named(&image).contains(action),
                            "seed {seed}: {action} sent without its intent on disk"
                        );
                        executed.insert(action["id"].as_str().unwrap().to_owned());
                        let reply = if rng.u8(0..5) == 0 {
                            json!({"error": "no answer"})
                        } else {
                            json!({"status": "ok"})
                        };
                        journal
                            .append(
                                op as i64,
                                EventBody::Sent {
                                    decision: seq,
                                    nonce: 0,
                                    ok: reply.get("status").is_some(),
                                    reply,
                                    action: None,
                                    index: Some(index as u64),
                                },
                            )
                            .unwrap();
                    }
                    if rng.u8(0..10) != 0 {
                        journal
                            .append(op as i64, EventBody::Done { intent: seq })
                            .unwrap();
                    }
                }
            }
            // A crash now, sometimes; the writer may be mid-batch.
            if rng.u8(0..4) == 0 {
                let snapshot = disk.lock().unwrap().clone();
                for image in crash_images(&snapshot, &mut rng) {
                    check(seed, &image, &executed);
                    images += 1;
                }
            }
        }
        images
    }

    /// J7, J5, J3 and J2 on one crash image.
    fn check(seed: u64, image: &[u8], executed: &BTreeSet<String>) {
        let read = read_records(Cursor::new(image), Path::new("image"))
            .unwrap_or_else(|error| panic!("seed {seed}: a crash image does not open: {error}"));
        let events: Vec<Value> = read.recent.iter().cloned().collect();
        let pending: BTreeSet<String> = pending(&events)
            .iter()
            .filter_map(|pending| pending.action["id"].as_str().map(str::to_owned))
            .collect();
        // Answered: a `sent` with the venue's parsed answer, by intent and
        // index.
        let mut answered = BTreeSet::new();
        for event in &events {
            if event["kind"] == "sent" && event["reply"].get("status").is_some() {
                let intent = event["decision"].as_u64().unwrap();
                let index = usize::try_from(event["index"].as_u64().unwrap()).unwrap();
                let action = events
                    .iter()
                    .find(|intent_event| intent_event["seq"].as_u64() == Some(intent))
                    .and_then(intent_actions)
                    .and_then(|actions| actions.get(index).cloned())
                    .unwrap();
                let id = action["id"].as_str().unwrap().to_owned();
                // J2: an answer only for what the venue executed.
                assert!(
                    executed.contains(&id),
                    "seed {seed}: {id} answered, never executed"
                );
                answered.insert(id);
            }
        }
        // J3: every executed action whose intent survived is answered or
        // pending.
        for actions in events.iter().filter_map(intent_actions) {
            for action in actions {
                let id = action["id"].as_str().unwrap().to_owned();
                if executed.contains(&id) {
                    assert!(
                        answered.contains(&id) || pending.contains(&id),
                        "seed {seed}: {id} executed, neither answered nor pending"
                    );
                }
            }
        }
        // J1 at the crash: every executed action's intent survived.
        let named: BTreeSet<String> = events
            .iter()
            .filter_map(intent_actions)
            .flatten()
            .filter_map(|action| action["id"].as_str().map(str::to_owned))
            .collect();
        for id in executed {
            assert!(
                named.contains(id),
                "seed {seed}: {id} executed, its intent lost"
            );
        }
    }

    /// A disk whose sync takes 3 s.
    #[derive(Clone)]
    struct SlowStorage(MemStorage);

    impl Storage for SlowStorage {
        fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
            self.0.write_at(offset, bytes)
        }
        fn sync(&mut self) -> io::Result<()> {
            std::thread::sleep(std::time::Duration::from_secs(3));
            self.0.sync()
        }
        fn allocated(&self) -> u64 {
            self.0.allocated()
        }
        fn allocate(&mut self, len: u64) -> io::Result<()> {
            self.0.allocate(len)
        }
        fn trim(&mut self, len: u64) -> io::Result<()> {
            self.0.trim(len)
        }
    }

    /// A disk whose writes wait until the test opens the gate.
    #[derive(Clone)]
    struct GatedStorage(
        MemStorage,
        Arc<(Mutex<bool>, std::sync::Condvar)>,
        Option<std::sync::mpsc::SyncSender<()>>,
    );

    impl Storage for GatedStorage {
        fn write_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
            let (open, opened) = &*self.1;
            let mut is_open = open.lock().unwrap();
            while !*is_open {
                if let Some(blocked) = self.2.take() {
                    blocked
                        .send(())
                        .expect("test awaits writer-blocked handshake");
                }
                is_open = opened.wait(is_open).unwrap();
            }
            drop(is_open);
            self.0.write_at(offset, bytes)
        }
        fn sync(&mut self) -> io::Result<()> {
            self.0.sync()
        }
        fn allocated(&self) -> u64 {
            self.0.allocated()
        }
        fn allocate(&mut self, len: u64) -> io::Result<()> {
            self.0.allocate(len)
        }
        fn trim(&mut self, len: u64) -> io::Result<()> {
            self.0.trim(len)
        }
    }

    fn open_gate(gate: &Arc<(Mutex<bool>, std::sync::Condvar)>) {
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
    }

    /// Opens the gate when dropped: a failing test never leaves the writer
    /// waiting (dropping the journal joins it).
    struct OpenOnDrop(Arc<(Mutex<bool>, std::sync::Condvar)>);

    impl Drop for OpenOnDrop {
        fn drop(&mut self) {
            open_gate(&self.0);
        }
    }

    /// A writer that falls behind does not break the journal: records
    /// nothing waits for are dropped and counted, an intent is refused
    /// (`Busy`), and once it catches up records are taken again. A
    /// decision the writer has not written yet is found from memory.
    #[test]
    fn a_writer_behind_drops_and_refuses_but_never_breaks() {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let disk = Arc::new(Mutex::new(Disk::default()));
        let storage = GatedStorage(MemStorage(disk), gate.clone(), None);
        let empty = read_records(io::empty(), Path::new("image")).unwrap();
        // The step large enough that the writer's first write is the
        // record (allocation is not gated).
        let mut journal = DecisionJournal::start(Path::new("image"), empty, 0, storage, 1 << 20);
        // Declared after the journal: dropped (the gate opened) before it.
        let _open = OpenOnDrop(gate.clone());
        let decision = EventBody::Decision {
            via: "http".into(),
            client: Some("0xaa".into()),
            signed_as: None,
            nonce: Some(77),
            action: Some("order".into()),
            verdict: zunder_guard_core::judge::Verdict::Veto,
            code: "open_risk".into(),
            text: "kept in memory".into(),
            changes: Vec::new(),
            request: None,
            pre: Vec::new(),
            forward: None,
            post: Vec::new(),
        };
        journal.append(1, decision).unwrap();
        let found = journal.find_decision(77, Some("0xAA")).unwrap();
        assert_eq!(found["decision"]["text"], "kept in memory");
        // The writer may take a whole queue into its batch before its first
        // write waits: up to twice the queue fits.
        let mut busy = 0;
        for at in 0..(3 * QUEUE as i64) {
            match journal.append(at, EventBody::Error { text: "x".into() }) {
                Ok(_) => {}
                Err(JournalError::Busy) => busy += 1,
                Err(other) => panic!("{other}"),
            }
        }
        assert!(busy > 0);
        assert_eq!(journal.dropped(), busy);
        assert!(!journal.is_broken());
        assert!(matches!(
            journal.append_durable(
                1,
                EventBody::Error {
                    text: "intent".into()
                }
            ),
            Err(JournalError::Busy)
        ));
        // Counted apart: an intent refused, records dropped.
        assert_eq!(journal.busy(), 1);
        assert_eq!(journal.dropped(), busy);
        // A `sent` not taken: its intent's `done` is not written either, so
        // that the intent stays open and recovery asks the venue.
        let sent = |decision: u64| EventBody::Sent {
            decision,
            nonce: 1,
            ok: false,
            reply: Value::Null,
            action: None,
            index: Some(0),
        };
        assert!(matches!(
            journal.append(3, sent(5)),
            Err(JournalError::Busy)
        ));
        // A flush the writer has no room for: `Busy`, not broken.
        assert!(matches!(
            runtime().block_on(journal.flush().wait()),
            Err(JournalError::Busy)
        ));
        assert!(!journal.is_broken());
        open_gate(&gate);
        let flusher = runtime();
        while let Err(error) = flusher.block_on(journal.flush().wait()) {
            assert!(matches!(error, JournalError::Busy), "{error}");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(matches!(
            journal.append(4, EventBody::Done { intent: 5 }),
            Err(JournalError::Busy)
        ));
        journal.append(4, EventBody::Done { intent: 6 }).unwrap();
        let (_, durable) = journal
            .append_durable(
                2,
                EventBody::Error {
                    text: "intent".into(),
                },
            )
            .unwrap();
        runtime().block_on(durable.wait()).unwrap();
        assert!(!journal.is_broken());
    }

    /// Recovery's records wait for a writer that is behind instead of being
    /// dropped, and so does its flush; a writer still behind after the
    /// deadline: `Busy`, counted, the journal not broken.
    #[test]
    fn records_that_must_not_be_dropped_wait_for_the_writer() {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let storage = GatedStorage(
            MemStorage(Arc::new(Mutex::new(Disk::default()))),
            gate.clone(),
            None,
        );
        let empty = read_records(io::empty(), Path::new("image")).unwrap();
        let mut journal = DecisionJournal::start(Path::new("image"), empty, 0, storage, 1 << 20);
        let _open = OpenOnDrop(gate.clone());
        while journal
            .append(1, EventBody::Error { text: "x".into() })
            .is_ok()
        {}
        let dropped = journal.dropped();
        let record = || EventBody::Error {
            text: "recovered".into(),
        };
        // Still behind at the deadline: `Busy`, counted once.
        let started = std::time::Instant::now();
        let until =
            || std::time::Instant::now() + std::time::Duration::from_millis(ACK_DEADLINE_MS);
        let result = runtime().block_on(journal.append_waiting(2, record(), until()));
        assert!(matches!(result, Err(JournalError::Busy)), "{result:?}");
        assert!(started.elapsed() >= std::time::Duration::from_millis(ACK_DEADLINE_MS));
        assert_eq!(journal.dropped(), dropped + 1);
        assert!(!journal.is_broken());
        // Caught up after 300 ms: the flush waits for room, and so does a
        // record, then taken.
        let opener = {
            let gate = gate.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(300));
                open_gate(&gate);
            })
        };
        // No room by the deadline: a wait that answers `Busy`, the journal
        // not broken.
        let soon = std::time::Instant::now() + std::time::Duration::from_millis(50);
        let busy = runtime().block_on(journal.flush_when_room(soon));
        assert!(matches!(
            runtime().block_on(busy.wait()),
            Err(JournalError::Busy)
        ));
        assert!(!journal.is_broken());
        let durable = runtime().block_on(journal.flush_when_room(until()));
        runtime().block_on(durable.wait()).unwrap();
        let seq = runtime()
            .block_on(journal.append_waiting(3, record(), until()))
            .unwrap();
        assert_eq!(seq, journal.last_seq());
        assert_eq!(journal.dropped(), dropped + 1);
        opener.join().unwrap();
    }

    /// A clean stop with the writer's queue full waits for room: everything
    /// queued is written and the stop acked once the writer catches up.
    #[test]
    fn a_stop_with_the_queue_full_waits_for_the_writer() {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let disk = Arc::new(Mutex::new(Disk::default()));
        let storage = GatedStorage(MemStorage(disk.clone()), gate.clone(), None);
        let empty = read_records(io::empty(), Path::new("image")).unwrap();
        let mut journal = DecisionJournal::start(Path::new("image"), empty, 0, storage, 1 << 20);
        let _open = OpenOnDrop(gate.clone());
        let mut taken = 0;
        while journal
            .append(1, EventBody::Error { text: "x".into() })
            .is_ok()
        {
            taken += 1;
        }
        let opener = {
            let gate = gate.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(300));
                open_gate(&gate);
            })
        };
        runtime().block_on(journal.close()).unwrap();
        assert!(!journal.is_broken());
        opener.join().unwrap();
        let durable = disk.lock().unwrap().durable.clone();
        let read = read_records(Cursor::new(durable), Path::new("image")).unwrap();
        assert_eq!(read.seq, taken);
    }

    /// A protective intent waits for a writer that is behind: written once
    /// it catches up within [`ACK_DEADLINE_MS`]; after that the journal is
    /// broken (and the emergency log takes over), never left `Busy`.
    #[test]
    fn a_protective_intent_waits_for_a_writer_behind_then_breaks_the_journal() {
        let intent = || EventBody::Error {
            text: "intent".into(),
        };
        let behind = |gate: &Arc<(Mutex<bool>, std::sync::Condvar)>| {
            let (blocked, writer_blocked) = std::sync::mpsc::sync_channel(1);
            let storage = GatedStorage(
                MemStorage(Arc::new(Mutex::new(Disk::default()))),
                gate.clone(),
                Some(blocked),
            );
            let empty = read_records(io::empty(), Path::new("image")).unwrap();
            let mut journal =
                DecisionJournal::start(Path::new("image"), empty, 0, storage, 1 << 20);
            let open_on_failure = OpenOnDrop(gate.clone());
            // Seed one write and wait until storage actually holds the writer.
            // A full queue alone is insufficient: its first batch may still drain.
            journal
                .append(
                    1,
                    EventBody::Error {
                        text: "seed".into(),
                    },
                )
                .unwrap();
            if let Err(error) = writer_blocked.recv_timeout(std::time::Duration::from_secs(5)) {
                open_gate(gate); // Never deadlock journal drop on a failed handshake.
                panic!("writer did not reach the closed storage gate: {error}");
            }
            for _ in 0..QUEUE {
                journal
                    .append(1, EventBody::Error { text: "x".into() })
                    .unwrap();
            }
            assert!(matches!(
                journal.append(
                    1,
                    EventBody::Error {
                        text: "full".into()
                    }
                ),
                Err(JournalError::Busy)
            ));
            (journal, open_on_failure)
        };
        // Caught up after 300 ms: written.
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let (mut journal, _open) = behind(&gate);
        let waiting_runtime = runtime();
        let (pending, first_pending) = std::sync::mpsc::sync_channel(1);
        let opener = {
            let gate = gate.clone();
            std::thread::spawn(move || {
                if let Err(error) = first_pending.recv_timeout(std::time::Duration::from_secs(5)) {
                    open_gate(&gate);
                    panic!("intent was not polled to Pending: {error}");
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
                open_gate(&gate);
            })
        };
        let started = std::time::Instant::now();
        let seq = waiting_runtime
            .block_on(async {
                use std::future::Future;
                let mut waiting = std::pin::pin!(journal.append_durable_waiting(2, intent()));
                let mut first = true;
                std::future::poll_fn(|context| {
                    let result = waiting.as_mut().poll(context);
                    if first {
                        assert!(
                            result.is_pending(),
                            "protective intent must first wait for room"
                        );
                        pending.send(()).expect("opener awaits first Pending");
                        first = false;
                    }
                    result
                })
                .await
            })
            .unwrap();
        assert!(started.elapsed() >= std::time::Duration::from_millis(250));
        assert_eq!(seq, journal.last_seq());
        assert!(!journal.is_broken());
        // Refused many times while it waited: counted once.
        assert_eq!(journal.busy(), 1);
        opener.join().unwrap();
        // Never caught up: broken after the deadline.
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let (mut journal, _open) = behind(&gate);
        let deadline_runtime = runtime();
        let started = std::time::Instant::now();
        let result = deadline_runtime.block_on(journal.append_durable_waiting(2, intent()));
        assert!(matches!(result, Err(JournalError::Broken(_))), "{result:?}");
        assert!(journal.is_broken());
        let waited = started.elapsed();
        assert!(
            waited >= std::time::Duration::from_millis(ACK_DEADLINE_MS)
                && waited < std::time::Duration::from_millis(ACK_DEADLINE_MS + 1_000),
            "{waited:?}"
        );
    }

    #[test]
    fn an_intent_waits_two_seconds_at_most_then_the_journal_is_broken() {
        let storage = SlowStorage(MemStorage(Arc::new(Mutex::new(Disk::default()))));
        let empty = read_records(io::empty(), Path::new("image")).unwrap();
        let mut journal = DecisionJournal::start(Path::new("image"), empty, 0, storage, 1_024);
        let (_, durable) = journal
            .append_durable(
                1,
                EventBody::Error {
                    text: "intent".into(),
                },
            )
            .unwrap();
        let started = std::time::Instant::now();
        assert!(runtime().block_on(durable.wait()).is_err());
        let waited = started.elapsed();
        assert!(
            waited < std::time::Duration::from_millis(2_500),
            "{waited:?}"
        );
        assert!(journal.is_broken());
        assert!(
            journal
                .append(
                    2,
                    EventBody::Error {
                        text: "after".into()
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn crashes_at_random_points_keep_j1_j2_j3_j5_j7() {
        let mut images = 0;
        for seed in 0..300 {
            images += run(seed);
        }
        assert!(images > 1_000, "{images}");
    }
}
