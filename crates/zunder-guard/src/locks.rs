// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! One way to take the crate's standard mutexes.
//!
//! A standard mutex is poisoned when a thread panicked while holding it.
//! Every critical section here leaves its data consistent between two
//! statements (counters, caches, flags, the stream's latest snapshots), so
//! the data behind a poisoned lock is taken as it is. Refusing it instead
//! would make one panic permanent: a poisoned request budget, for one,
//! would refuse every reduce-only order until a restart.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Lock `mutex`, poisoned or not.
pub(crate) fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
