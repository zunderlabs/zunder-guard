// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The checks every record passes, in the reader and, before it appends,
//! in the writer: the step from the record before ([`check_step`]), and for
//! a `flowed` record its base, its lists of views and flows, and the state
//! the flows give ([`Trail`], [`Listings`], [`check_flowed`]).

use std::collections::{BTreeMap, BTreeSet};

use zunder_risk::{RiskLimits, RiskSnapshot, RiskState};

use super::record::{JOURNAL_VERSION, JournalEvent, JournalRecord};
use crate::flows::{self, Flow, Horizon, SeenView};

/// Whether the engine can get from `before` to `after` in one record. A
/// `flowed` record is checked further by [`check_flowed`].
pub(super) fn check_step(before: &JournalRecord, after: &JournalRecord) -> Result<(), String> {
    let (old, new) = (&before.state, &after.state);
    if new.day < old.day {
        return Err(format!("the day went back from {} to {}", old.day, new.day));
    }
    // The fields of an engine that takes flows, only in version 3.
    let flowed = matches!(after.event, JournalEvent::Flowed { .. });
    if (after.version >= JOURNAL_VERSION) != after.horizon.is_some() {
        return Err("a horizon in a record of version 3, and only there".into());
    }
    if (flowed || after.view.is_some()) && after.horizon.is_none() {
        return Err("a flowed record or a view without a horizon".into());
    }
    if flowed && after.view.is_some() {
        return Err("a flowed record lists its views in the event".into());
    }
    if let Some(horizon) = &after.horizon {
        if let Some(previous) = &before.horizon
            && previous
                .iter()
                .any(|(dex, time)| horizon.get(dex).is_none_or(|now| now < time))
        {
            return Err("the horizon went back".into());
        }
        if let Some(view) = &after.view {
            if view.at != after.at {
                return Err("a view observed at another time than its record".into());
            }
            if let Some(previous) = &before.horizon
                && flows::goes_back(&view.times, previous)
            {
                return Err("a view that goes back in venue time".into());
            }
            if view
                .times
                .iter()
                .any(|(dex, time)| horizon.get(dex).is_none_or(|latest| latest < time))
            {
                return Err("a view beyond the horizon".into());
            }
        }
    }
    match &after.event {
        JournalEvent::Flowed { .. } => Ok(()),
        JournalEvent::Initialised { .. } => Err("a second `initialised` record".into()),
        JournalEvent::Repaired { .. } => {
            if new == old {
                Ok(())
            } else {
                Err("a repair changed the state".into())
            }
        }
        JournalEvent::Scoped { .. } => {
            if new == old {
                Ok(())
            } else {
                Err("recording the scope changed the state".into())
            }
        }
        JournalEvent::ResumedAfterReview { .. } => {
            // The record of positions may have caught up with the session
            // since the last record; the rest is the review itself.
            let resumed = matches!(old.state, RiskState::Stopped { .. })
                && new.state == RiskState::Active
                && new.peak == new.last
                && new.day_start == new.last
                && new.day == after.at.utc_day();
            if resumed {
                Ok(())
            } else {
                Err("a review record that is not a resumption from a drawdown stop".into())
            }
        }
        JournalEvent::Updated => {
            if new.peak < old.peak {
                return Err(format!("the peak fell from {} to {}", old.peak, new.peak));
            }
            match (old.state, new.state) {
                (RiskState::Stopped { .. }, _) if new.state != old.state => {
                    Err("a drawdown stop was cleared or changed without a review".into())
                }
                (
                    RiskState::HaltedForDay { day },
                    RiskState::Active | RiskState::HaltedForDay { .. },
                ) if new.day == day && new.state != old.state => {
                    Err(format!("the halt for day {day} was cleared on that day"))
                }
                _ => Ok(()),
            }
        }
    }
}

/// The views on the journal and where `flowed` records may start from: what
/// the reader needs to check that a `flowed` record's base can be replayed
/// from and that it lists every view the journal holds since that base. The
/// writer keeps the same, from the same records, back to its oldest base.
#[derive(Debug, Clone, Default)]
pub(super) struct Trail {
    /// The views on the journal, in order, from the `first`-th on.
    pub(super) views: Vec<SeenView>,
    pub(super) first: usize,
    /// For each record kept: how many views the journal held after it.
    pub(super) after: BTreeMap<u64, usize>,
    /// The newest record nothing before which can be replayed: the first,
    /// a review, or one written without flows.
    pub(super) reset: u64,
    /// For each `flowed` record kept: its base.
    pub(super) flowed: BTreeMap<u64, u64>,
}

impl Trail {
    /// Whether a `flowed` record `seq` may start from record `base` and
    /// list `views`.
    pub(super) fn check(&self, base: u64, seq: u64, views: &[SeenView]) -> Result<(), String> {
        if base < self.reset {
            return Err(format!(
                "a flowed record from record {base}, before record {} (a review, or written without flows)",
                self.reset
            ));
        }
        if let Some((later, from)) = self
            .flowed
            .range(base.saturating_add(1)..seq)
            .find(|(_, from)| **from < base)
        {
            return Err(format!(
                "a flowed record from record {base}, which record {later} replaced (from record {from})"
            ));
        }
        let start = self
            .after
            .get(&base)
            .and_then(|count| count.checked_sub(self.first))
            .ok_or_else(|| format!("a flowed record from record {base}, which is not kept"))?;
        let mut listed = views.iter();
        for journaled in self.views.iter().skip(start) {
            if !listed.any(|view| view == journaled) {
                return Err(format!(
                    "a flowed record from record {base} leaves out a view on the journal since"
                ));
            }
        }
        Ok(())
    }

    /// Note a record checked and kept.
    pub(super) fn record(&mut self, record: &JournalRecord) {
        match &record.event {
            JournalEvent::Flowed { base, views, .. } => {
                if let Some(count) = self.after.get(base) {
                    self.views.truncate(count.saturating_sub(self.first));
                }
                self.views.extend(views.iter().cloned());
                self.flowed.insert(record.seq, *base);
            }
            _ => {
                if let Some(view) = &record.view {
                    self.views.push(view.clone());
                }
            }
        }
        let count = self.first + self.views.len();
        if record.horizon.is_none()
            || matches!(record.event, JournalEvent::ResumedAfterReview { .. })
        {
            // Nothing before it is replayed again: forget it.
            self.reset = record.seq;
            self.first = count;
            self.views.clear();
            self.after.clear();
            self.flowed.clear();
        }
        self.after.insert(record.seq, count);
    }

    /// Forget what lies before record `oldest`: no record before it is a
    /// base any more (the writer's).
    pub(super) fn prune(&mut self, oldest: u64) {
        let Some(count) = self.after.get(&oldest).copied() else {
            return;
        };
        let drop = count.saturating_sub(self.first).min(self.views.len());
        self.views.drain(..drop);
        self.first += drop;
        self.after = self.after.split_off(&oldest);
        self.flowed = self.flowed.split_off(&oldest);
    }
}

/// Which `flowed` records listed each flow, and whether each applied it:
/// what the reader needs to check that a record's base and its list of
/// flows agree with the records before it (`docs/guard.md#deposits-and-withdrawals`).
/// The writer keeps the same, from the same records.
#[derive(Debug, Clone, Default)]
pub(super) struct Listings {
    /// For each flow id: the flow as first listed, and each listing's
    /// record and whether it applied the flow, in order.
    flows: BTreeMap<String, (Flow, Vec<(u64, bool)>)>,
}

impl Listings {
    /// Latest durable placement, independent of whether the caller enables
    /// reconstruction in memory. A review must not discard this money origin.
    pub(super) fn pending(&self) -> bool {
        self.flows
            .values()
            .any(|(_, listings)| listings.last().is_some_and(|(_, applied)| !applied))
    }

    pub(super) fn check_review(&self, event: &JournalEvent) -> Result<(), String> {
        if matches!(event, JournalEvent::ResumedAfterReview { .. }) && self.pending() {
            return Err("a review cannot discard pending account flows".into());
        }
        Ok(())
    }

    /// Whether a `flowed` record `seq` from record `base` (with that
    /// horizon) may list `listed`: no flow it lists first is one the base's
    /// views reached, none is listed again after the latest listing at or
    /// before the base applied it, none known and not applied at the base,
    /// or listed since, is left out, and none changed.
    pub(super) fn check(
        &self,
        base: u64,
        base_horizon: &Horizon,
        listed: &[Flow],
    ) -> Result<(), String> {
        let mut ids = BTreeSet::new();
        for flow in listed {
            if !ids.insert(flow.id.as_str()) {
                return Err(format!("the flow {} listed twice", flow.id));
            }
            let latest = match self.flows.get(&flow.id) {
                Some((first, listings)) => {
                    if first != flow {
                        return Err(format!("the flow {} changed since it was listed", flow.id));
                    }
                    listings.iter().rev().find(|(seq, _)| *seq <= base)
                }
                None => None,
            };
            match latest {
                Some((_, true)) => {
                    return Err(format!(
                        "the flow {} listed again, although applied at or before record {base}",
                        flow.id
                    ));
                }
                Some((_, false)) => {}
                None => {
                    if !flows::before_horizon(flow, base_horizon) {
                        return Err(format!(
                            "record {base} had seen past the flow {} it did not know",
                            flow.id
                        ));
                    }
                }
            }
        }
        for (id, (_, listings)) in &self.flows {
            if ids.contains(id.as_str()) {
                continue;
            }
            let pending_at_base = listings
                .iter()
                .rev()
                .find(|(seq, _)| *seq <= base)
                .is_some_and(|(_, applied)| !applied);
            if pending_at_base || listings.iter().any(|(seq, _)| *seq > base) {
                return Err(format!("the flow {id}, not in record {base}, is left out"));
            }
        }
        Ok(())
    }

    /// Note record `seq` listing `listed`, applied where `placed` says.
    pub(super) fn record(&mut self, seq: u64, listed: &[Flow], placed: &[Option<usize>]) {
        for (flow, place) in listed.iter().zip(placed) {
            self.flows
                .entry(flow.id.clone())
                .or_insert_with(|| (flow.clone(), Vec::new()))
                .1
                .push((seq, place.is_some()));
        }
    }
}

/// What the reader keeps across records to check `flowed` records, and the
/// writer with it.
#[derive(Debug, Clone, Default)]
pub(super) struct Checks {
    pub(super) trail: Trail,
    pub(super) listings: Listings,
}

/// How far the views a record knew of reached, for whether a flow learned
/// later contradicts it: its horizon; for the first record, a review, or a
/// record written without flows, also the time it was written at (the
/// equity it holds was read then, every flow before it in it).
pub(super) fn reach(record: &JournalRecord) -> Horizon {
    let mut reach = record.horizon.clone().unwrap_or_default();
    if record.horizon.is_none()
        || matches!(
            record.event,
            JournalEvent::Initialised { .. } | JournalEvent::ResumedAfterReview { .. }
        )
    {
        let at = record.at.as_millis();
        let main = reach.entry(String::new()).or_insert(at);
        *main = (*main).max(at);
    }
    reach
}

/// Whether a `flowed` record holds exactly what its inputs give: the replay
/// from its base's state and horizon through its views with its flows
/// ([`flows::replay`]), settled against the record before it
/// ([`flows::settle`]), with the later of the two horizons. The writer runs
/// this before it appends, the reader when it loads: they compute the same.
/// The replay, for where it applied each flow.
pub(super) fn check_flowed(
    limits: &RiskLimits,
    base: &RiskSnapshot,
    base_horizon: &Horizon,
    before: &JournalRecord,
    after: &JournalRecord,
) -> Result<flows::Replayed, String> {
    let JournalEvent::Flowed {
        base: seq,
        views,
        flows: flow_list,
    } = &after.event
    else {
        return Err("not a flowed record".into());
    };
    if *seq >= after.seq {
        return Err(format!(
            "a flowed record from record {seq}, which is not before it"
        ));
    }
    if views.windows(2).any(|pair| pair[1].at < pair[0].at) {
        return Err("views out of order".into());
    }
    let mut latest = base_horizon.clone();
    for view in views {
        if flows::goes_back(&view.times, &latest) {
            return Err("a view that goes back in venue time".into());
        }
        for (dex, time) in &view.times {
            let entry = latest.entry(dex.clone()).or_insert(*time);
            *entry = (*entry).max(*time);
        }
    }
    let replayed = flows::replay(limits, base, base_horizon, views, flow_list)?;
    let settled = flows::settle(limits, &before.state, &replayed.snapshot)?;
    if settled != after.state {
        return Err(format!(
            "the flows give {settled:?}, the record holds {:?}",
            after.state
        ));
    }
    let mut horizon = replayed.horizon.clone();
    for (dex, time) in before.horizon.iter().flatten() {
        let latest = horizon.entry(dex.clone()).or_insert(*time);
        *latest = (*latest).max(*time);
    }
    if after.horizon.as_ref() != Some(&horizon) {
        return Err("the horizon is not the one the flows give".into());
    }
    Ok(replayed)
}
