// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! `zunder-guard-pilot`: the scripted test client of Guard's first mainnet
//! pilot. See `docs/guard.md#paper-testnet-mainnet`. It talks to
//! a local Guard only through Guard's public interface, as any bot does,
//! and signs with this crate's own Hyperliquid signer ([`crate::hlsign`]),
//! which shares no code with Guard.
//!
//! What it holds to, whatever Guard says:
//!
//! - **One step per invocation**, from the fixed list in [`Step`]. No "run
//!   all". A request Guard forwarded, or may have, is never sent again; the
//!   one exception is a request Guard refused `rate_limited`, with positive
//!   proof that nothing went out (its journaled decision on that nonce is a
//!   `rate_limited` veto with no forward and an empty list of sends): an
//!   entry, an exit, or an expected refusal the budget hid (the account-read
//!   budget, or the fee gate) is planned again (preview, caps, the step's
//!   worst case) and sent again once the budget has refilled, at most four
//!   times. Entries are spaced by that budget (18 s after the client's last
//!   request). After an unknown outcome (a timeout, an unreadable answer,
//!   `venue_unreachable`) the step stops and says to look at the account
//!   first.
//! - **Refusals before anything is sent**: Guard's status must name the
//!   expected mode and the account given on the command line, an equity cap
//!   of at most 300, the pilot's rules (the drill's for the drill steps),
//!   this client among its clients and an intact journal; on mainnet also
//!   `--i-am-jonas-and-this-is-the-pilot` and Guard at
//!   `http://127.0.0.1:8547`. Then the step's own precondition, usually
//!   flat with no open orders on every dex Guard reads.
//! - **Every order previewed first** (`POST /guard/preview`, read-only), and
//!   sent only when Guard's preview gives the expected answer: an entry
//!   only when what Guard would forward is within the caps of
//!   [`checks::Frame`] (worth at most 100 USDC, at most 2 USDC lost at its
//!   stop and 12 if the stop fills at its 10% limit, at most 3x isolated;
//!   the drill half of each); an order expected to be refused only when the
//!   preview refuses it with the expected code; an exit only when the
//!   preview opens nothing. A step's worst case (the sum of its entries'
//!   gap losses) is asserted before its first order.
//! - **BTC and ETH only** (asset ids read from `meta` by name), at most the
//!   step's declared number of entries, of which at most one stays open
//!   (two in the `kill` step). The H0 probe on a HIP-3
//!   market asks for one size step and is sent only when the preview
//!   refuses it.
//! - **Only orders, cancels, one modify (S3) and the kill switch.** Never a
//!   leverage or margin update, a transfer, a withdrawal or an approval:
//!   Guard sets an entry's isolated leverage itself.
//! - Every request and every answer is printed as one JSON line and
//!   appended to `pilot.jsonl`; every check prints one line with `"result":
//!   "PASS"`, `"FAIL"` or `"SKIP"`. A FAIL stops the step before its next
//!   order.

pub mod checks;
pub mod key;
mod session;
mod steps;

use std::path::PathBuf;

pub use checks::GuardMode;

use crate::hlsign::Key;

/// The pilot steps in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Pre-flight: status, `/healthz`, a preview of the S2 entry. Sends nothing.
    Look,
    /// S1: an entry while the builder fee is not approved.
    FeeGate,
    /// S2: an entry, resized, isolated, with Guard's stop.
    Entry,
    /// S3: a cancel and a loosening modify of Guard's stop.
    StopChecks,
    /// S4: a reduce-only close, then the cancel of the stops left.
    Close,
    /// S5: an entry and a tighter stand-alone market stop of the client's.
    TightenAndFire,
    /// S6: two entries, the kill switch, an entry after it.
    Kill,
    /// S7, before the restart: an entry.
    RestartBefore,
    /// S7, after the restart: a request with a nonce from before it, then the close.
    RestartAfter,
    /// S8, first half: an entry while the fee is approved.
    FeeWithdrawnOpen,
    /// S8, second half (after the operator withdrew the approval): the close, then an entry.
    FeeWithdrawnClose,
    /// D1: an entry under the drill rules.
    DrillEntry,
    /// D2 and D3: an entry and a tiny reduce-only order while halted.
    DrillAfter,
    /// H0: an entry on a HIP-3 market, which mainnet refuses.
    Hip3Off,
    /// The end: no position and no open order on any dex. Sends nothing.
    Flat,
    /// C7: polls the status once a second, writes `watch.jsonl`. Sends nothing.
    Watch,
}

impl Step {
    pub const ALL: [Step; 16] = [
        Step::Look,
        Step::FeeGate,
        Step::Entry,
        Step::StopChecks,
        Step::Close,
        Step::TightenAndFire,
        Step::Kill,
        Step::RestartBefore,
        Step::RestartAfter,
        Step::FeeWithdrawnOpen,
        Step::FeeWithdrawnClose,
        Step::DrillEntry,
        Step::DrillAfter,
        Step::Hip3Off,
        Step::Flat,
        Step::Watch,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Step::Look => "look",
            Step::FeeGate => "fee-gate",
            Step::Entry => "entry",
            Step::StopChecks => "stop-checks",
            Step::Close => "close",
            Step::TightenAndFire => "tighten-and-fire",
            Step::Kill => "kill",
            Step::RestartBefore => "restart-before",
            Step::RestartAfter => "restart-after",
            Step::FeeWithdrawnOpen => "fee-withdrawn-open",
            Step::FeeWithdrawnClose => "fee-withdrawn-close",
            Step::DrillEntry => "drill-entry",
            Step::DrillAfter => "drill-after",
            Step::Hip3Off => "hip3-off",
            Step::Flat => "flat",
            Step::Watch => "watch",
        }
    }

    pub fn parse(name: &str) -> Option<Step> {
        Step::ALL.into_iter().find(|step| step.name() == name)
    }

    /// The rules Guard must run for this step.
    pub fn rules(self) -> checks::RulesSet {
        match self {
            Step::DrillEntry | Step::DrillAfter => checks::RulesSet::Drill,
            // The end check, and the close (it opens nothing), run against
            // either home: D1's fallback closes on the drill Guard.
            Step::Flat | Step::Close => checks::RulesSet::PilotOrDrill,
            Step::Watch => checks::RulesSet::Any,
            _ => checks::RulesSet::Pilot,
        }
    }

    /// Whether the step needs a Guard that sends: it works on a position or
    /// on the fee approval, which a paper Guard never has.
    pub fn needs_sending(self) -> bool {
        matches!(
            self,
            Step::FeeGate
                | Step::StopChecks
                | Step::Close
                | Step::TightenAndFire
                | Step::RestartAfter
                | Step::FeeWithdrawnClose
        )
    }

    /// The step's caps: how many entries it may send (forwarded or
    /// expected to be refused), how many of them may be forwarded and stay
    /// open, and so the most its entries may lose with every stop filled at
    /// its limit (that many times the frame's gap cap).
    pub fn caps(self) -> StepCaps {
        let (entries, open) = match self {
            Step::Look | Step::StopChecks | Step::Close | Step::RestartAfter => (0, 0),
            Step::Flat | Step::Watch => (0, 0),
            Step::FeeGate | Step::FeeWithdrawnClose | Step::DrillAfter | Step::Hip3Off => (1, 0),
            Step::Entry
            | Step::TightenAndFire
            | Step::RestartBefore
            | Step::FeeWithdrawnOpen
            | Step::DrillEntry => (1, 1),
            // S6: the BTC entry and the resting ETH entry, then one entry
            // the kill switch refuses.
            Step::Kill => (3, 2),
        };
        StepCaps {
            max_entries: entries,
            max_open_entries: open,
        }
    }

    /// Whether the step may send anything at all.
    pub fn sends(self) -> bool {
        !matches!(self, Step::Look | Step::Flat | Step::Watch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepCaps {
    pub max_entries: usize,
    pub max_open_entries: usize,
}

/// How long the client waits for what it reads (never for a resend).
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Waiting for Guard's next sync to show what a step just did.
    pub sync_wait_ms: u64,
    /// One more look for Guard's stop after an entry (C1: within 5 s).
    pub stop_recheck_ms: u64,
    /// Waiting for the account to be flat after a close or the kill (15 s).
    pub flat_wait_ms: u64,
    /// Between two previews (Guard answers at most one a second).
    pub preview_gap_ms: u64,
    /// Between two reads while waiting.
    pub poll_ms: u64,
    /// How long `watch` runs.
    pub watch_ms: u64,
    /// The least time between a request holding an entry and this client's
    /// request before it (Guard's request budget: 4 of the venue's weight a
    /// second, a burst of 60; an entry costs up to 46).
    pub entry_gap_ms: u64,
    /// The wait after a request refused `rate_limited` (nothing forwarded)
    /// before it is previewed and sent again.
    pub rate_wait_ms: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            sync_wait_ms: 15_000,
            stop_recheck_ms: 5_000,
            flat_wait_ms: 15_000,
            preview_gap_ms: 1_100,
            poll_ms: 1_000,
            watch_ms: 4 * 3_600_000,
            entry_gap_ms: 18_000,
            rate_wait_ms: 15_000,
        }
    }
}

/// One invocation.
#[derive(Debug, Clone)]
pub struct Options {
    /// Guard's address: plain HTTP on loopback; on mainnet exactly
    /// [`checks::PILOT_URL`].
    pub url: String,
    pub step: Step,
    pub expect_mode: GuardMode,
    /// The pilot account P, as the person named it.
    pub confirm_account: String,
    /// `--i-am-jonas-and-this-is-the-pilot`: required on mainnet.
    pub pilot_confirmed: bool,
    /// Where `pilot.jsonl` and `watch.jsonl` are appended.
    pub log_dir: PathBuf,
    pub timing: Timing,
    /// Print the JSON lines on standard output (the binary does; tests may not).
    pub echo: bool,
}

/// How an invocation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// Every check passed.
    Passed,
    /// A check failed; the step stopped before its next order.
    Failed,
    /// Refused before anything was sent.
    Refused,
    /// A request's outcome is unknown: look at the account first, never resend blindly.
    Unknown,
}

impl Ending {
    /// The process exit status: 0, 1, 2 (as Guard's own refusals) and 3.
    pub fn exit_code(self) -> i32 {
        match self {
            Ending::Passed => 0,
            Ending::Failed => 1,
            Ending::Refused => 2,
            Ending::Unknown => 3,
        }
    }
}

/// One check's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub criterion: String,
    pub check: String,
    /// `PASS`, `FAIL` or `SKIP`.
    pub result: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub ending: Ending,
    /// Why it was refused, failed or stopped, for a person.
    pub reason: Option<String>,
    pub checks: Vec<CheckResult>,
    /// How many requests went to `/exchange` or `/guard/kill`.
    pub sent: usize,
    /// Every JSON line written, in order.
    pub lines: Vec<serde_json::Value>,
}

impl Outcome {
    /// The checks with this result.
    pub fn with(&self, result: &str) -> Vec<&CheckResult> {
        self.checks
            .iter()
            .filter(|check| check.result == result)
            .collect()
    }
}

/// Run one step.
pub fn run(options: &Options, key: &Key) -> Outcome {
    session::Session::run(options, key)
}
