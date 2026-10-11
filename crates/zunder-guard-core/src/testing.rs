// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Seeds and case counts for the randomised tests (tests only, feature
//! `test-hooks`; never in a release build).
//!
//! Every randomised test runs the same cases on every run unless asked
//! otherwise, so that a failure in the required checks is a real one and
//! can be run again:
//!
//! - `PROPTEST_RNG_SEED` (a `u64`) picks the cases. Unset, or set to
//!   [`GATE_SEED`], each test runs the cases it was written against; any
//!   other value shifts every test's seeds. A scheduled run that wants fresh
//!   cases sets a new value each time and prints it, so that a failure can be
//!   reproduced with the same value.
//! - `ZUNDER_FLOWS_CASES` (a count) sets how many cases the larger
//!   generated runs try.
//!
//! A value that does not parse fails the test rather than being ignored.

/// The seed of the required checks.
pub const GATE_SEED: u64 = 20_261_010;

/// The run's seed: `PROPTEST_RNG_SEED`, or [`GATE_SEED`] when unset.
///
/// # Panics
///
/// When `PROPTEST_RNG_SEED` is set but is not a `u64`.
#[must_use]
pub fn run_seed() -> u64 {
    match std::env::var("PROPTEST_RNG_SEED") {
        Ok(value) => value
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("PROPTEST_RNG_SEED must be a u64, got {value:?}")),
        Err(_) => GATE_SEED,
    }
}

/// The seed a test with built-in seed `base` uses on this run: `base` itself
/// under [`GATE_SEED`], shifted by any other run seed.
#[must_use]
pub fn seed(base: u64) -> u64 {
    base ^ run_seed() ^ GATE_SEED
}

/// How many cases a generated run tries: `ZUNDER_FLOWS_CASES`, or `default`.
///
/// # Panics
///
/// When `ZUNDER_FLOWS_CASES` is set but is not a count.
#[must_use]
pub fn cases(default: usize) -> usize {
    match std::env::var("ZUNDER_FLOWS_CASES") {
        Ok(value) => value
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("ZUNDER_FLOWS_CASES must be a count, got {value:?}")),
        Err(_) => default,
    }
}
