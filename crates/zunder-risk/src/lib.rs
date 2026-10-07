// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Deterministic risk limits.
//!
//! Everything here is plain arithmetic on purpose: no model, no network, no
//! clock. The engine sizes every entry and can veto it, and it decides when
//! the bot has to go flat. Nothing else in the system is allowed to override
//! it. Changing a default below is a recorded decision, not a refactoring.

mod book;
mod engine;
mod limits;

pub use book::{
    CombinedExposure, Exposure, PositionDiscrepancy, TrackedPosition, VenuePosition, VenueView,
};
pub use engine::{RestoreError, RiskEngine, RiskSnapshot, RiskState, SizeRequest, Veto};
pub use limits::{RiskConfigError, RiskLimits};
