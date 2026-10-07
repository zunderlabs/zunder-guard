// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Recovery after a crash (`docs/guard.md#journals`): which
//! actions the decision journal's intents named that no outcome answers,
//! and what the venue's evidence says became of each. Pure: Guard asks
//! the venue ([`crate::guard::Guard::recover`]) and journals the
//! conclusions.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use serde_json::{Value, json};
use zunder_guard_core::action::{Action, OrderRef, decode_action_value};

/// An action an intent named that no `sent`, `recovered` or `done` record
/// answers.
#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    /// The intent's `seq`, and the action's place in it.
    pub intent: u64,
    pub index: usize,
    /// When the intent was written (Guard's clock, epoch ms): the action
    /// expires at the latest [`EXPIRES_WITHIN_MS`] after it (recovery
    /// waits [`MAX_TTL_MS`], for the clocks).
    pub at_ms: i64,
    pub action: Value,
    /// Another action in the journal names one of the same orders (a
    /// client id or an order id): evidence at the venue could be either's.
    pub shared: bool,
}

/// How many recent actions' order names, and answered order ids, are
/// kept to tell whether evidence is shared, besides those of the intents
/// still open (kept until they are resolved, however long that takes).
const NAMES_KEPT: usize = 50_000;

/// The orders an action names: `cloid:…` for client ids, `oid:…` for
/// venue ids (a modify's target, a cancel's), lowercase.
pub fn order_names(action: &Value) -> Vec<String> {
    let mut names = Vec::new();
    let mut cloid = |value: &Value| {
        if let Some(id) = value.as_str() {
            names.push(format!("cloid:{}", id.to_ascii_lowercase()));
        }
    };
    for order in action["orders"].as_array().into_iter().flatten() {
        cloid(&order["c"]);
    }
    cloid(&action["order"]["c"]);
    for modify in action["modifies"].as_array().into_iter().flatten() {
        cloid(&modify["order"]["c"]);
    }
    for cancel in action["cancels"].as_array().into_iter().flatten() {
        cloid(&cancel["cloid"]);
    }
    let mut oid = |value: &Value| match value {
        Value::Number(number) => names.push(format!("oid:{number}")),
        Value::String(text) if text.starts_with("0x") => {
            names.push(format!("cloid:{}", text.to_ascii_lowercase()));
        }
        _ => {}
    };
    oid(&action["oid"]);
    for modify in action["modifies"].as_array().into_iter().flatten() {
        oid(&modify["oid"]);
    }
    for cancel in action["cancels"].as_array().into_iter().flatten() {
        oid(&cancel["o"]);
    }
    names
}

/// How long recovery waits after an intent before asking the venue: an
/// action it names expires at most [`EXPIRES_WITHIN_MS`] after it, and
/// Guard's clock may run up to 15 s ahead of the venue's.
pub const MAX_TTL_MS: i64 = 55_000;

/// The latest an action expires after the intent naming it
/// (`expiresAfter`, J1: [`crate::guard::INTENT_COVERS_MS`]). The venue
/// takes nothing after it, so its evidence of the action (an order placed,
/// a cancel) is no later.
pub const EXPIRES_WITHIN_MS: i64 = 40_000;

/// The actions an intent event names, in the order Guard sends them, or
/// `None` for an event that is no intent.
pub fn intent_actions(event: &Value) -> Option<Vec<Value>> {
    let list = |field: &str| -> Vec<Value> { event[field].as_array().cloned().unwrap_or_default() };
    match event["kind"].as_str()? {
        "decision" => {
            let forward = event.get("forward").filter(|forward| !forward.is_null())?;
            let mut actions = list("pre");
            actions.push(forward.clone());
            actions.extend(list("post"));
            Some(actions)
        }
        "protect" | "flatten" if event["sent"] == true => Some(list("actions")),
        "intent" => Some(vec![event.get("action")?.clone()]),
        _ => None,
    }
}

/// An intent's actions and what is known of each.
#[derive(Debug, Clone, PartialEq)]
struct Open {
    at_ms: i64,
    actions: Vec<Value>,
    /// Actions the venue answered (a parsed answer) or recovery concluded.
    answered: BTreeSet<usize>,
    /// Actions sent without a parsed answer (a transport error): in doubt.
    doubt: BTreeSet<usize>,
    /// Guard finished acting on it: actions with no `sent` were not sent.
    done: bool,
    /// Actions another action in the journal names an order of (before
    /// this intent, or after it while it is open, however much later).
    shared: BTreeSet<usize>,
    /// Order ids its answered sends returned.
    oids: Vec<u64>,
}

impl Open {
    /// The actions nothing answers yet.
    fn unresolved(&self) -> Vec<usize> {
        (0..self.actions.len())
            .filter(|index| !self.answered.contains(index))
            .filter(|index| !self.done || self.doubt.contains(index))
            .collect()
    }
}

/// The intents not resolved yet, fed every record in order: an intent is
/// resolved once each of its actions has a parsed venue answer or a
/// recovery conclusion, or Guard finished with it (`done`) and none of
/// its sends is in doubt. Only unresolved intents are kept.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tracker {
    open: BTreeMap<u64, Open>,
    /// How many of the last [`NAMES_KEPT`] order names are each name, and
    /// the names in the order they came (the oldest forgotten first).
    names: HashMap<String, u32>,
    name_order: VecDeque<String>,
    /// Every order name of the open intents' actions, with the actions
    /// naming it (intent, index): never forgotten while the intent is
    /// open, so that a retry however much later still marks it shared.
    open_names: HashMap<String, Vec<(u64, usize)>>,
    /// Order ids recent answered sends returned, oldest first (an open
    /// intent's own are kept in it until it is resolved).
    answered_oids: HashSet<u64>,
    oid_order: VecDeque<u64>,
}

impl Tracker {
    /// Take in one record's event.
    pub fn observe(&mut self, event: &Value) {
        let seq = event["seq"].as_u64().unwrap_or(0);
        let index = |field: &str| {
            event[field]
                .as_u64()
                .and_then(|index| usize::try_from(index).ok())
        };
        match event["kind"].as_str() {
            Some("sent") => {
                let (Some(intent), Some(index)) = (event["decision"].as_u64(), index("index"))
                else {
                    return;
                };
                let oids: Vec<u64> = event
                    .pointer("/reply/response/data/statuses")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .flat_map(|status| {
                        ["resting", "filled"]
                            .into_iter()
                            .filter_map(|kind| status[kind]["oid"].as_u64())
                    })
                    .collect();
                if let Some(open) = self.open.get_mut(&intent) {
                    if event["reply"].get("status").is_some() {
                        open.answered.insert(index);
                    } else {
                        open.doubt.insert(index);
                    }
                    open.oids.extend(&oids);
                }
                for oid in oids {
                    if self.answered_oids.insert(oid) {
                        self.oid_order.push_back(oid);
                        if self.oid_order.len() > NAMES_KEPT
                            && let Some(old) = self.oid_order.pop_front()
                        {
                            self.answered_oids.remove(&old);
                        }
                    }
                }
                self.resolve(intent);
            }
            Some("recovered") => {
                let (Some(intent), Some(index)) = (event["intent"].as_u64(), index("index")) else {
                    return;
                };
                if let Some(open) = self.open.get_mut(&intent) {
                    open.answered.insert(index);
                }
                self.resolve(intent);
            }
            Some("done") => {
                let Some(intent) = event["intent"].as_u64() else {
                    return;
                };
                if let Some(open) = self.open.get_mut(&intent) {
                    open.done = true;
                }
                self.resolve(intent);
            }
            _ => {
                if let Some(actions) = intent_actions(event)
                    && !actions.is_empty()
                {
                    let mut shared = BTreeSet::new();
                    for (index, action) in actions.iter().enumerate() {
                        for name in order_names(action) {
                            // Named before, recently or by an intent still
                            // open: this action is shared, and so is every
                            // open one naming it.
                            if self.names.contains_key(&name) {
                                shared.insert(index);
                            }
                            if let Some(holders) = self.open_names.get(&name) {
                                shared.insert(index);
                                for (intent, at) in holders.clone() {
                                    if intent == seq {
                                        shared.insert(at);
                                    } else if let Some(open) = self.open.get_mut(&intent) {
                                        open.shared.insert(at);
                                    }
                                }
                            }
                            self.open_names
                                .entry(name.clone())
                                .or_default()
                                .push((seq, index));
                            self.remember(name);
                        }
                    }
                    self.open.insert(
                        seq,
                        Open {
                            at_ms: event["at_ms"].as_i64().unwrap_or(0),
                            actions,
                            answered: BTreeSet::new(),
                            doubt: BTreeSet::new(),
                            done: false,
                            shared,
                            oids: Vec::new(),
                        },
                    );
                }
            }
        }
    }

    /// Count `name` among the last [`NAMES_KEPT`].
    fn remember(&mut self, name: String) {
        *self.names.entry(name.clone()).or_default() += 1;
        self.name_order.push_back(name);
        if self.name_order.len() > NAMES_KEPT
            && let Some(old) = self.name_order.pop_front()
            && let Some(count) = self.names.get_mut(&old)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.names.remove(&old);
            }
        }
    }

    fn resolve(&mut self, intent: u64) {
        if !self
            .open
            .get(&intent)
            .is_some_and(|open| open.unresolved().is_empty())
        {
            return;
        }
        let Some(open) = self.open.remove(&intent) else {
            return;
        };
        for name in open.actions.iter().flat_map(order_names) {
            if let Some(holders) = self.open_names.get_mut(&name) {
                holders.retain(|(holder, _)| *holder != intent);
                if holders.is_empty() {
                    self.open_names.remove(&name);
                }
            }
        }
    }

    /// The actions nothing answers, oldest intent first.
    pub fn pending(&self) -> Vec<Pending> {
        self.open
            .iter()
            .flat_map(|(intent, open)| {
                open.unresolved().into_iter().map(move |index| Pending {
                    intent: *intent,
                    index,
                    at_ms: open.at_ms,
                    action: open.actions[index].clone(),
                    shared: open.shared.contains(&index),
                })
            })
            .collect()
    }

    /// Whether an answered send returned order id `oid` (so an order the
    /// venue shows under it was placed by that send).
    pub fn answered_oid(&self, oid: u64) -> bool {
        self.answered_oids.contains(&oid) || self.open.values().any(|open| open.oids.contains(&oid))
    }

    /// Whether action `index` of the open intent `intent` shares an order
    /// with another action, as the journal shows it now (actions sent
    /// after a [`Pending`] was taken included); `false` once resolved.
    pub fn shared(&self, intent: u64, index: usize) -> bool {
        self.open
            .get(&intent)
            .is_some_and(|open| open.shared.contains(&index))
    }

    /// Whether an action in the journal names one of `aliases` (the names
    /// the venue's answers give the orders `action` names: their order ids
    /// and client ids) that `action` itself does not name: another way of
    /// naming the same order (a cancel by order id of an order a cancel by
    /// client id names, say).
    pub fn named_elsewhere(&self, action: &Value, aliases: &[String]) -> bool {
        let own = order_names(action);
        aliases
            .iter()
            .filter(|alias| !own.contains(alias))
            .any(|alias| self.names.contains_key(alias) || self.open_names.contains_key(alias))
    }

    /// The oldest unresolved intent's `seq`.
    pub fn oldest(&self) -> Option<u64> {
        self.open.keys().next().copied()
    }
}

/// [`Tracker::pending`] of `events`, oldest first.
pub fn pending(events: &[Value]) -> Vec<Pending> {
    let mut tracker = Tracker::default();
    for event in events {
        tracker.observe(event);
    }
    tracker.pending()
}

/// How the venue can tell whether an action happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// An order action: its orders' client ids (`None` for an order
    /// without one: then nothing tells).
    Orders(Vec<Option<String>>),
    /// A cancel of the orders with these venue or client ids.
    Cancels(Vec<OrderRef>),
    /// Isolated (or cross) leverage set on an asset.
    Leverage {
        asset: u32,
        cross: bool,
        leverage: u32,
    },
    /// Nothing the venue keeps tells (a margin update, a dead man's switch).
    Untold,
}

/// The identity of the action `action` (its wire form, as journaled).
pub fn identity(action: &Value) -> Identity {
    let Ok(decoded) = decode_action_value(action) else {
        return Identity::Untold;
    };
    match decoded {
        Action::Order(order) => Identity::Orders(
            order
                .orders
                .iter()
                .map(|order| {
                    order
                        .cloid
                        .as_ref()
                        .map(|cloid| cloid.as_str().to_ascii_lowercase())
                })
                .collect(),
        ),
        Action::Cancel(cancels) | Action::CancelByCloid(cancels) => {
            Identity::Cancels(cancels.into_iter().map(|cancel| cancel.order).collect())
        }
        Action::Modify(modify) => Identity::Orders(vec![
            modify
                .order
                .cloid
                .as_ref()
                .map(|cloid| cloid.as_str().to_ascii_lowercase()),
        ]),
        Action::BatchModify(modifies) => Identity::Orders(
            modifies
                .iter()
                .map(|modify| {
                    modify
                        .order
                        .cloid
                        .as_ref()
                        .map(|cloid| cloid.as_str().to_ascii_lowercase())
                })
                .collect(),
        ),
        Action::UpdateLeverage {
            asset,
            is_cross,
            leverage,
        } => Identity::Leverage {
            asset,
            cross: is_cross,
            leverage,
        },
        _ => Identity::Untold,
    }
}

/// What recovery concluded of one action.
#[derive(Debug, Clone, PartialEq)]
pub struct Conclusion {
    /// `happened`, `did_not_happen`, `moot` or `unknown`.
    pub outcome: &'static str,
    pub evidence: Value,
}

/// How far before the intent the venue's timestamp of an order may be
/// and still be the intent's (the two clocks).
pub const CLOCK_SKEW_MS: i64 = 60_000;

/// The venue's answer to `orderStatus` for one id: known (with the
/// order's status), unknown, or not read.
fn order_known(answer: &Value) -> Option<bool> {
    match answer["status"].as_str() {
        Some("order") => Some(true),
        Some("unknownOid") => Some(false),
        _ => None,
    }
}

fn same_number(a: &Value, b: &Value) -> bool {
    let number = |value: &Value| -> Option<rust_decimal::Decimal> {
        match value {
            Value::String(text) => text.parse().ok(),
            Value::Number(number) => number.to_string().parse().ok(),
            _ => None,
        }
    };
    matches!((number(a), number(b)), (Some(a), Some(b)) if a == b)
}

/// Whether the venue's order (an `orderStatus` answer) is the order
/// `intended` (its wire form) placed by an intent at `at_ms`: the same
/// side, price, size, reduce-only and trigger, placed no earlier than the
/// intent (less the clocks' skew) and no later than the action's expiry
/// ([`EXPIRES_WITHIN_MS`] after it: an order placed later is another
/// action's).
/// A client id alone is no proof: bots reuse them, and a modify of
/// Guard's stop keeps its id.
pub fn order_matches(intended: &Value, at_ms: i64, answer: &Value) -> bool {
    let order = &answer["order"]["order"];
    let trigger = intended["t"].get("trigger");
    let side = if intended["b"] == true { "B" } else { "A" };
    order["side"].as_str() == Some(side)
        && same_number(&order["limitPx"], &intended["p"])
        && same_number(&order["origSz"], &intended["s"])
        && order["reduceOnly"].as_bool().unwrap_or(false)
            == intended["r"].as_bool().unwrap_or(false)
        && order["isTrigger"].as_bool().unwrap_or(false) == trigger.is_some()
        && trigger.is_none_or(|trigger| same_number(&order["triggerPx"], &trigger["triggerPx"]))
        && order["timestamp"].as_i64().is_some_and(|placed| {
            placed >= at_ms - CLOCK_SKEW_MS && placed <= at_ms + EXPIRES_WITHIN_MS
        })
}

/// What else bears on an order action's evidence.
#[derive(Clone, Copy, Default)]
pub struct Context<'a> {
    /// Another action names the same orders.
    pub shared: bool,
    /// For a modify, the order id it replaces: an order the venue shows
    /// under that id is the old order, no evidence of the modify.
    pub replaced: Option<u64>,
    /// Whether an answered send returned this order id.
    pub answered: Option<&'a dyn Fn(u64) -> bool>,
}

/// Conclude an order action from the venue's `orderStatus` answers, one
/// per order that tells (`orders`: the wire forms; for a `normalTpsl`
/// action only the parent, whose children wait for its fill), read after
/// the action expired and, where unknown, read again. Conservative: an
/// order known and matching → happened, but moot when another action
/// names the same order or an answered send returned its id (the effect
/// holds; which action placed it, the venue cannot say), and unknown when
/// it is a modify's old order; every one unknown → did not happen;
/// anything else (a known order that is not this one, an order without a
/// client id, an answer not read) → unknown.
pub fn conclude_orders(
    orders: &[Value],
    at_ms: i64,
    answers: &[Value],
    context: Context<'_>,
) -> Conclusion {
    let evidence = json!({"orders": orders, "order_status": answers});
    let unknown = |evidence: Value| Conclusion {
        outcome: "unknown",
        evidence,
    };
    if orders.is_empty() || orders.len() != answers.len() {
        return unknown(evidence);
    }
    let mut matched = false;
    let mut attributed_elsewhere = false;
    let mut all_unknown = true;
    for (order, answer) in orders.iter().zip(answers) {
        if order.get("c").and_then(Value::as_str).is_none() {
            all_unknown = false;
            continue;
        }
        match order_known(answer) {
            Some(true) => {
                all_unknown = false;
                let oid = answer["order"]["order"]["oid"].as_u64();
                if oid.is_some() && oid == context.replaced {
                    // The old order of a modify: no evidence either way.
                    continue;
                }
                if order_matches(order, at_ms, answer) {
                    matched = true;
                    if oid.is_some_and(|oid| context.answered.is_some_and(|answered| answered(oid)))
                    {
                        attributed_elsewhere = true;
                    }
                }
            }
            Some(false) => {}
            None => all_unknown = false,
        }
    }
    let outcome = if matched && (context.shared || attributed_elsewhere) {
        "moot"
    } else if matched {
        "happened"
    } else if all_unknown {
        "did_not_happen"
    } else {
        "unknown"
    };
    Conclusion { outcome, evidence }
}

/// Conclude a cancel from the named orders' `orderStatus` answers (one
/// each, in order), read after the cancel expired, for a cancel whose
/// intent was written at `at_ms`. Conservative: every one `canceled` at a
/// time within the cancel's validity (from the intent, less the clocks'
/// skew, to its expiry, [`EXPIRES_WITHIN_MS`]) and no other action naming
/// them → happened; every
/// one gone (filled, cancelled by the venue, cancelled at another time or
/// by whoever) → moot; every one still open → did not happen; anything
/// else (unknown, unread, a mix with open) → unknown.
pub fn conclude_cancels(answers: &[Value], at_ms: i64, shared: bool) -> Conclusion {
    let status = |answer: &Value| -> Option<(String, Option<i64>)> {
        (order_known(answer) == Some(true)).then(|| {
            (
                answer["order"]["status"].as_str().unwrap_or("").to_owned(),
                answer["order"]["statusTimestamp"].as_i64(),
            )
        })
    };
    let statuses: Vec<Option<(String, Option<i64>)>> = answers.iter().map(status).collect();
    let in_window = |time: Option<i64>| {
        time.is_some_and(|time| time >= at_ms - CLOCK_SKEW_MS && time <= at_ms + EXPIRES_WITHIN_MS)
    };
    let gone = |status: &str| status.ends_with("anceled") || status == "filled";
    let outcome = if statuses.is_empty() {
        "unknown"
    } else if !shared
        && statuses.iter().all(|status| {
            status
                .as_ref()
                .is_some_and(|(status, time)| status == "canceled" && in_window(*time))
        })
    {
        "happened"
    } else if statuses
        .iter()
        .all(|status| status.as_ref().is_some_and(|(status, _)| gone(status)))
    {
        "moot"
    } else if statuses
        .iter()
        .all(|status| status.as_ref().is_some_and(|(status, _)| status == "open"))
    {
        "did_not_happen"
    } else {
        "unknown"
    };
    Conclusion {
        outcome,
        evidence: json!({"order_status": answers}),
    }
}

/// Conclude a leverage update from the venue's `activeAssetData` answer,
/// read after it expired. Conservative: the setting is the one asked for
/// → moot (in place; whether this update did it, the venue cannot say);
/// another, or unread → unknown (a later update may have changed it).
pub fn conclude_leverage(cross: bool, leverage: u32, answer: &Value) -> Conclusion {
    let shown = &answer["leverage"];
    let outcome = match (shown["type"].as_str(), shown["value"].as_u64()) {
        (Some(kind), Some(value)) if (kind == "cross") == cross && value == u64::from(leverage) => {
            "moot"
        }
        _ => "unknown",
    };
    Conclusion {
        outcome,
        evidence: json!({"active_asset_data": answer}),
    }
}

/// The names the venue's `orderStatus` answers give their orders: each
/// one's order id (`oid:…`) and client id (`cloid:…`, lowercase).
pub fn aliases(answers: &[Value]) -> Vec<String> {
    let mut names = Vec::new();
    for answer in answers {
        let order = &answer["order"]["order"];
        if let Some(oid) = order["oid"].as_u64() {
            names.push(format!("oid:{oid}"));
        }
        if let Some(cloid) = order["cloid"].as_str() {
            names.push(format!("cloid:{}", cloid.to_ascii_lowercase()));
        }
    }
    names
}

/// Conclude the order action (an order, a modify, a batch modify) of
/// `item` from the venue's `orderStatus` answers, one for each of its
/// [`telling_orders`] (`Value::Null` for one without a client id), with
/// what the journal knows: whether another action names the same orders,
/// the order a modify replaces, and whether an answered send returned an
/// order id (`answered`).
pub fn conclude_order_action(
    item: &Pending,
    answers: &[Value],
    answered: &dyn Fn(u64) -> bool,
) -> Conclusion {
    conclude_orders(
        &telling_orders(&item.action),
        item.at_ms,
        answers,
        Context {
            shared: item.shared,
            replaced: replaced_oid(&item.action),
            answered: Some(answered),
        },
    )
}

/// Conclude the cancel of `item` from the named orders' `orderStatus`
/// answers, in order.
pub fn conclude_cancel_action(item: &Pending, answers: &[Value]) -> Conclusion {
    conclude_cancels(answers, item.at_ms, item.shared)
}

/// The order id a modify (or the first of a batch modify) replaces, when
/// it names one by id.
pub fn replaced_oid(action: &Value) -> Option<u64> {
    match action["type"].as_str() {
        Some("modify") => action["oid"].as_u64(),
        Some("batchModify") => action["modifies"][0]["oid"].as_u64(),
        _ => None,
    }
}

/// The wire forms of the orders that tell whether `action` (an order
/// action, a modify, a batch modify) happened: every order, or for a
/// `normalTpsl` action its parent alone.
pub fn telling_orders(action: &Value) -> Vec<Value> {
    match action["type"].as_str() {
        Some("order") => {
            let orders = action["orders"].as_array().cloned().unwrap_or_default();
            if action["grouping"] == "normalTpsl" {
                orders.into_iter().take(1).collect()
            } else {
                orders
            }
        }
        Some("modify") => vec![action["order"].clone()],
        Some("batchModify") => action["modifies"]
            .as_array()
            .map(|modifies| {
                modifies
                    .iter()
                    .map(|modify| modify["order"].clone())
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64, kind: &str, fields: Value) -> Value {
        let mut event = json!({"seq": seq, "at_ms": 1_000 + seq, "kind": kind});
        if let (Some(event), Some(fields)) = (event.as_object_mut(), fields.as_object()) {
            event.extend(fields.clone());
        }
        event
    }

    #[test]
    fn pending_are_the_actions_no_answer_resolves() {
        let a = json!({"type": "a"});
        let b = json!({"type": "b"});
        let c = json!({"type": "c"});
        let ok = json!({"status": "ok"});
        let lost = json!({"error": "no answer"});
        let events = vec![
            event(1, "started", json!({})),
            // Two actions, one answered: the second pending.
            event(2, "decision", json!({"pre": [a], "forward": b, "post": []})),
            event(3, "sent", json!({"decision": 2, "index": 0, "reply": ok})),
            // Done: what was not sent is resolved; nothing pending.
            event(4, "decision", json!({"pre": [], "forward": a, "post": [c]})),
            event(5, "sent", json!({"decision": 4, "index": 0, "reply": ok})),
            event(6, "done", json!({"intent": 4})),
            // Done, but a send in doubt: that one pending.
            event(7, "decision", json!({"pre": [a], "forward": b, "post": []})),
            event(8, "sent", json!({"decision": 7, "index": 0, "reply": ok})),
            event(9, "sent", json!({"decision": 7, "index": 1, "reply": lost})),
            event(10, "done", json!({"intent": 7})),
            // A veto: no intent. Protect not sent (paper): none.
            event(
                11,
                "decision",
                json!({"pre": [], "forward": null, "post": []}),
            ),
            event(12, "protect", json!({"actions": [a], "sent": false})),
            // A flattening: one recovered, one pending.
            event(13, "flatten", json!({"actions": [a, b], "sent": true})),
            event(14, "recovered", json!({"intent": 13, "index": 0})),
            event(15, "intent", json!({"of": 2, "action": c})),
            // A clean stop resolves nothing by itself.
            event(16, "stopped", json!({})),
        ];
        let found: Vec<(u64, usize)> = pending(&events)
            .iter()
            .map(|pending| (pending.intent, pending.index))
            .collect();
        assert_eq!(found, vec![(2, 1), (7, 1), (13, 1), (15, 0)]);
        let mut tracker = Tracker::default();
        for event in &events {
            tracker.observe(event);
        }
        assert_eq!(tracker.oldest(), Some(2));
        // Answered later: resolved and forgotten.
        tracker.observe(&event(
            17,
            "sent",
            json!({"decision": 2, "index": 1, "reply": ok}),
        ));
        tracker.observe(&event(18, "recovered", json!({"intent": 7, "index": 1})));
        tracker.observe(&event(19, "recovered", json!({"intent": 13, "index": 1})));
        tracker.observe(&event(
            20,
            "sent",
            json!({"decision": 15, "index": 0, "reply": ok}),
        ));
        assert!(tracker.pending().is_empty());
        assert_eq!(tracker.oldest(), None);
    }

    fn venue_order(side: &str, px: &str, sz: &str, at: i64, status: &str) -> Value {
        json!({"status": "order", "order": {"status": status, "statusTimestamp": at,
            "order": {"side": side, "limitPx": px, "origSz": sz, "sz": "0", "reduceOnly": false,
                "isTrigger": false, "triggerPx": "0.0", "timestamp": at, "oid": 7, "cloid": "0x1"}}})
    }

    #[test]
    fn an_order_happened_only_with_matching_evidence() {
        let buy = json!({"a": 0, "b": true, "p": "60000", "s": "0.01", "r": false,
            "t": {"limit": {"tif": "Ioc"}}, "c": "0x1"});
        let unknown = json!({"status": "unknownOid"});
        // Placed after the intent, the same order: happened.
        let same = venue_order("B", "60000.0", "0.0100", 10_000, "filled");
        assert_eq!(
            conclude_orders(
                std::slice::from_ref(&buy),
                9_000,
                std::slice::from_ref(&same),
                Context::default()
            )
            .outcome,
            "happened"
        );
        // Unknown after expiry (read twice by the caller): did not happen.
        assert_eq!(
            conclude_orders(
                std::slice::from_ref(&buy),
                9_000,
                std::slice::from_ref(&unknown),
                Context::default()
            )
            .outcome,
            "did_not_happen"
        );
        // The same client id on another order (a bot that reuses ids, a
        // modify that kept it): no proof either way.
        let other_price = venue_order("B", "59000", "0.01", 10_000, "open");
        let other_side = venue_order("A", "60000", "0.01", 10_000, "open");
        let older = venue_order("B", "60000", "0.01", 9_000 - CLOCK_SKEW_MS - 1, "open");
        for answer in [other_price, other_side, older] {
            assert_eq!(
                conclude_orders(
                    std::slice::from_ref(&buy),
                    9_000,
                    &[answer],
                    Context::default()
                )
                .outcome,
                "unknown"
            );
        }
        // No client id, an answer not read: unknown.
        let bare = json!({"a": 0, "b": true, "p": "60000", "s": "0.01", "r": false,
            "t": {"limit": {"tif": "Ioc"}}});
        assert_eq!(
            conclude_orders(
                &[bare],
                9_000,
                std::slice::from_ref(&unknown),
                Context::default()
            )
            .outcome,
            "unknown"
        );
        assert_eq!(
            conclude_orders(
                std::slice::from_ref(&buy),
                9_000,
                &[json!({"error": "x"})],
                Context::default()
            )
            .outcome,
            "unknown"
        );
        // A stop: its trigger must match too.
        let stop = json!({"a": 0, "b": false, "p": "50000", "s": "0.01", "r": true,
            "t": {"trigger": {"isMarket": true, "triggerPx": "58800", "tpsl": "sl"}}, "c": "0x2"});
        let mut rests = venue_order("A", "50000", "0.01", 10_000, "open");
        rests["order"]["order"]["isTrigger"] = json!(true);
        rests["order"]["order"]["reduceOnly"] = json!(true);
        rests["order"]["order"]["triggerPx"] = json!("58800.0");
        assert_eq!(
            conclude_orders(
                std::slice::from_ref(&stop),
                9_000,
                std::slice::from_ref(&rests),
                Context::default()
            )
            .outcome,
            "happened"
        );
        rests["order"]["order"]["triggerPx"] = json!("58000");
        assert_eq!(
            conclude_orders(&[stop], 9_000, &[rests], Context::default()).outcome,
            "unknown"
        );
        // A normalTpsl action tells by its parent alone.
        let grouped = json!({"type": "order", "orders": [buy.clone(), {"c": "0x7a67"}],
            "grouping": "normalTpsl"});
        assert_eq!(telling_orders(&grouped), vec![buy]);
    }

    #[test]
    fn ambiguous_evidence_is_never_happened() {
        let buy = json!({"a": 0, "b": true, "p": "60000", "s": "0.01", "r": false,
            "t": {"limit": {"tif": "Ioc"}}, "c": "0x1"});
        let same = venue_order("B", "60000", "0.01", 10_000, "filled");
        // Another action names the same client id (a bot's retry): moot.
        let shared = Context {
            shared: true,
            ..Context::default()
        };
        assert_eq!(
            conclude_orders(
                std::slice::from_ref(&buy),
                9_000,
                std::slice::from_ref(&same),
                shared
            )
            .outcome,
            "moot"
        );
        // An answered send returned this order's id: moot.
        let answered = |oid: u64| oid == 7;
        let elsewhere = Context {
            answered: Some(&answered),
            ..Context::default()
        };
        assert_eq!(
            conclude_orders(
                std::slice::from_ref(&buy),
                9_000,
                std::slice::from_ref(&same),
                elsewhere
            )
            .outcome,
            "moot"
        );
        // A modify's old order (the client id kept): no evidence.
        let modify = Context {
            replaced: Some(7),
            ..Context::default()
        };
        assert_eq!(
            conclude_orders(
                std::slice::from_ref(&buy),
                9_000,
                std::slice::from_ref(&same),
                modify
            )
            .outcome,
            "unknown"
        );
        // Reduce-only differs: not this order.
        let mut reducing = same.clone();
        reducing["order"]["order"]["reduceOnly"] = json!(true);
        assert_eq!(
            conclude_orders(
                std::slice::from_ref(&buy),
                9_000,
                &[reducing],
                Context::default()
            )
            .outcome,
            "unknown"
        );
        assert_eq!(replaced_oid(&json!({"type": "modify", "oid": 7})), Some(7));
        // Shared names are found in the journal's intents.
        let mut tracker = Tracker::default();
        let cancel = json!({"type": "cancel", "cancels": [{"a": 0, "o": 7}]});
        tracker
            .observe(&json!({"seq": 1, "at_ms": 1, "kind": "intent", "of": 0, "action": cancel}));
        tracker
            .observe(&json!({"seq": 2, "at_ms": 2, "kind": "intent", "of": 0, "action": cancel}));
        assert!(tracker.pending().iter().all(|pending| pending.shared));
        let order = json!({"type": "order", "orders": [{"c": "0xAB"}], "grouping": "na"});
        tracker.observe(&json!({"seq": 3, "at_ms": 3, "kind": "intent", "of": 0, "action": order}));
        assert!(!tracker.pending().last().unwrap().shared);
        tracker.observe(&json!({"seq": 4, "kind": "sent", "decision": 3, "index": 0,
            "reply": {"status": "ok", "response": {"data": {"statuses": [{"resting": {"oid": 42}}]}}}}));
        assert!(tracker.answered_oid(42));
    }

    #[test]
    fn cancels_and_leverage_conclude_from_what_the_venue_shows() {
        let order = |status: &str, time: i64| json!({"status": "order", "order": {"status": status, "statusTimestamp": time}});
        let at = 100_000;
        assert_eq!(
            conclude_cancels(
                &[order("canceled", at + 10), order("canceled", at + 20)],
                at,
                false
            )
            .outcome,
            "happened"
        );
        // Cancelled outside the cancel's validity, or another action names
        // the order, or no time: moot.
        assert_eq!(
            conclude_cancels(&[order("canceled", at + EXPIRES_WITHIN_MS + 1)], at, false).outcome,
            "moot"
        );
        assert_eq!(
            conclude_cancels(&[order("canceled", at - CLOCK_SKEW_MS - 1)], at, false).outcome,
            "moot"
        );
        assert_eq!(
            conclude_cancels(&[order("canceled", at + 10)], at, true).outcome,
            "moot"
        );
        assert_eq!(
            conclude_cancels(
                &[json!({"status": "order", "order": {"status": "canceled"}})],
                at,
                false
            )
            .outcome,
            "moot"
        );
        assert_eq!(
            conclude_cancels(&[order("filled", at)], at, false).outcome,
            "moot"
        );
        assert_eq!(
            conclude_cancels(
                &[order("canceled", at), order("reduceOnlyCanceled", at)],
                at,
                false
            )
            .outcome,
            "moot"
        );
        assert_eq!(
            conclude_cancels(&[order("open", at)], at, false).outcome,
            "did_not_happen"
        );
        assert_eq!(
            conclude_cancels(&[order("canceled", at), order("open", at)], at, false).outcome,
            "unknown"
        );
        assert_eq!(
            conclude_cancels(&[json!({"status": "unknownOid"})], at, false).outcome,
            "unknown"
        );
        assert_eq!(conclude_cancels(&[], at, false).outcome, "unknown");
        let three = json!({"leverage": {"type": "isolated", "value": 3}});
        assert_eq!(conclude_leverage(false, 3, &three).outcome, "moot");
        assert_eq!(conclude_leverage(false, 5, &three).outcome, "unknown");
        assert_eq!(conclude_leverage(true, 3, &three).outcome, "unknown");
        assert_eq!(conclude_leverage(false, 3, &Value::Null).outcome, "unknown");
    }

    fn limit_buy(cloid: &str) -> Value {
        json!({"a": 0, "b": true, "p": "60000", "s": "0.01", "r": false,
            "t": {"limit": {"tif": "Gtc"}}, "c": cloid})
    }

    fn order_action(cloid: &str) -> Value {
        json!({"type": "order", "orders": [limit_buy(cloid)], "grouping": "na"})
    }

    fn intent(seq: u64, at_ms: i64, action: Value) -> Value {
        json!({"seq": seq, "at_ms": at_ms, "kind": "intent", "of": 0, "action": action})
    }

    fn answered(seq: u64, decision: u64, status: Value) -> Value {
        json!({"seq": seq, "kind": "sent", "decision": decision, "index": 0,
            "reply": {"status": "ok", "response": {"data": {"statuses": [status]}}}})
    }

    /// Regression case: a send in
    /// doubt (intent 1, client id X), the bot's retry with X filled as
    /// order 77, then 50,001 more orders before a restart. The retry still
    /// marks the send in doubt shared, and its order id is still known:
    /// recovery says `moot`, never `happened` (which would journal two
    /// buys where one executed).
    #[test]
    fn a_retry_long_after_a_send_in_doubt_still_makes_it_moot() {
        let cloid = "0x00000000000000000000000000000abc";
        let mut tracker = Tracker::default();
        tracker.observe(&intent(1, 9_000, order_action(cloid)));
        tracker.observe(&json!({"seq": 2, "kind": "sent", "decision": 1, "index": 0,
            "reply": {"error": "timeout"}}));
        tracker.observe(&json!({"seq": 3, "kind": "done", "intent": 1}));
        tracker.observe(&intent(4, 9_500, order_action(cloid)));
        tracker.observe(&answered(
            5,
            4,
            json!({"filled": {"oid": 77, "totalSz": "0.01", "avgPx": "60000"}}),
        ));
        // A filled order's id counts as answered as a resting one's does.
        assert!(tracker.answered_oid(77));
        // Another intent left open: its first action answered (order 5),
        // its second in doubt.
        let pair = json!({"type": "order", "orders": [limit_buy("0x5")], "grouping": "na"});
        tracker.observe(&json!({"seq": 900_000, "at_ms": 9_600, "kind": "flatten",
            "sent": true, "actions": [pair, order_action("0x6")]}));
        tracker.observe(&answered(900_001, 900_000, json!({"resting": {"oid": 5}})));
        tracker.observe(&json!({"seq": 900_002, "kind": "sent", "decision": 900_000,
            "index": 1, "reply": {"error": "timeout"}}));
        let mut seq = 6;
        for i in 0..50_001u64 {
            tracker.observe(&intent(
                seq,
                10_000,
                order_action(&format!("0x{:032x}", 1_000_000 + i)),
            ));
            tracker.observe(&answered(
                seq + 1,
                seq,
                json!({"resting": {"oid": 1_000 + i}}),
            ));
            seq += 2;
        }
        let pending = tracker.pending();
        assert_eq!(pending.len(), 2);
        let item = &pending[0];
        assert_eq!(item.intent, 1);
        assert!(item.shared);
        assert_eq!((pending[1].intent, pending[1].shared), (900_000, false));
        // The retry's order id has left the window (its intent is
        // resolved); its name, shared with the open intent, has not, and
        // an open intent's own answered order id has not either.
        assert!(!tracker.answered_oid(77));
        assert!(tracker.answered_oid(5));
        let answer = json!({"status": "order", "order": {"status": "filled", "order": {
            "side": "B", "limitPx": "60000", "origSz": "0.01", "reduceOnly": false,
            "isTrigger": false, "timestamp": 9_500, "oid": 77}}});
        let known = |oid: u64| tracker.answered_oid(oid);
        assert_eq!(
            conclude_order_action(item, std::slice::from_ref(&answer), &known).outcome,
            "moot"
        );
        let known = |oid: u64| oid == 77;
        // Either alone makes it moot: the journal's names, and the order id
        // an answered send returned.
        let unshared = Pending {
            shared: false,
            ..item.clone()
        };
        assert_eq!(
            conclude_order_action(&unshared, std::slice::from_ref(&answer), &known).outcome,
            "moot"
        );
        assert_eq!(
            conclude_order_action(item, std::slice::from_ref(&answer), &|_| false).outcome,
            "moot"
        );
        assert_eq!(
            conclude_order_action(&unshared, std::slice::from_ref(&answer), &|_| false).outcome,
            "happened"
        );
        // An order placed after the action expired is another action's.
        let mut later = answer.clone();
        later["order"]["order"]["timestamp"] = json!(9_000 + EXPIRES_WITHIN_MS + 1);
        assert_eq!(
            conclude_order_action(&unshared, &[later], &|_| false).outcome,
            "unknown"
        );
        let mut last = answer;
        last["order"]["order"]["timestamp"] = json!(9_000 + EXPIRES_WITHIN_MS);
        assert_eq!(
            conclude_order_action(&unshared, &[last], &|_| false).outcome,
            "happened"
        );
        // Resolved, an intent's names are forgotten like any others.
        tracker.observe(&json!({"seq": seq, "kind": "recovered", "intent": 1, "index": 0}));
        tracker.observe(
            &json!({"seq": seq + 1, "kind": "recovered", "intent": 900_000,
            "index": 1}),
        );
        assert!(tracker.pending().is_empty());
        assert!(tracker.open_names.is_empty());
        assert!(!tracker.answered_oid(5));
    }

    /// Two sends in doubt with one client id (a bot's retry that got no
    /// answer either): both shared, whichever came first.
    #[test]
    fn two_sends_in_doubt_with_one_client_id_are_both_shared() {
        let cloid = "0x00000000000000000000000000000abd";
        let mut tracker = Tracker::default();
        for seq in [1, 3] {
            tracker.observe(&intent(seq, 9_000, order_action(cloid)));
            tracker.observe(&json!({"seq": seq + 1, "kind": "sent", "decision": seq,
                "index": 0, "reply": {"error": "timeout"}}));
        }
        // An unrelated one is not.
        tracker.observe(&intent(5, 9_000, order_action("0x1")));
        let shared: Vec<(u64, bool)> = tracker
            .pending()
            .iter()
            .map(|pending| (pending.intent, pending.shared))
            .collect();
        assert_eq!(shared, vec![(1, true), (3, true), (5, false)]);
        // Within one intent too: a batch naming one client id twice.
        let twice = json!({"type": "order", "orders": [limit_buy("0x2"), limit_buy("0x2")],
            "grouping": "na"});
        let mut tracker = Tracker::default();
        tracker.observe(&intent(1, 9_000, twice));
        tracker.observe(&intent(2, 9_000, order_action("0x3")));
        // Two actions of one intent naming one order (an order and a
        // cancel of it by client id): both.
        let cancel = json!({"type": "cancelByCloid", "cancels": [{"asset": 0, "cloid": "0x4"}]});
        tracker.observe(
            &json!({"seq": 3, "at_ms": 9_000, "kind": "flatten", "sent": true,
            "actions": [order_action("0x4"), cancel]}),
        );
        let shared: Vec<bool> = tracker
            .pending()
            .iter()
            .map(|pending| pending.shared)
            .collect();
        assert_eq!(shared, vec![true, false, true, true]);
    }

    /// A send answered shortly before an intent naming the same client id
    /// (the bot reused it): shared while it is among the last
    /// [`NAMES_KEPT`] names.
    #[test]
    fn an_earlier_send_with_the_same_client_id_makes_it_shared() {
        let cloid = "0x00000000000000000000000000000abe";
        let mut tracker = Tracker::default();
        tracker.observe(&intent(1, 8_000, order_action(cloid)));
        tracker.observe(&answered(2, 1, json!({"resting": {"oid": 5}})));
        let mut seq = 3;
        for i in 0..5u64 {
            tracker.observe(&intent(seq, 8_500, order_action(&format!("0x{i:x}"))));
            tracker.observe(&answered(seq + 1, seq, json!({"resting": {"oid": 10 + i}})));
            seq += 2;
        }
        tracker.observe(&intent(seq, 9_000, order_action(cloid)));
        let pending = tracker.pending();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].shared);
        assert!(tracker.answered_oid(5) && tracker.answered_oid(14));
        assert!(!tracker.answered_oid(99));
    }

    /// An action naming the same order after the pending ones were taken
    /// (a send after a restart, before recovery reads) marks it shared in
    /// the live tracker, which recovery asks.
    #[test]
    fn a_later_action_marks_a_pending_one_shared() {
        let cancel = json!({"type": "cancel", "cancels": [{"a": 1, "o": 1001}]});
        let mut tracker = Tracker::default();
        tracker.observe(&intent(1, 9_000, cancel.clone()));
        let pending = tracker.pending();
        assert!(!pending[0].shared);
        assert!(!tracker.shared(1, 0));
        tracker.observe(&intent(2, 9_500, cancel));
        assert!(tracker.shared(1, 0));
        assert!(!tracker.shared(7, 0));
    }

    /// Regression case: a cancel by client
    /// id, and the kill switch's flattening cancelling the same order by
    /// order id. The names differ; the venue's answer gives both, and
    /// another action names one of them.
    #[test]
    fn another_name_for_the_same_order_counts() {
        let by_cloid =
            json!({"type": "cancelByCloid", "cancels": [{"asset": 1, "cloid": "0xABC"}]});
        let by_oid = json!({"type": "cancel", "cancels": [{"a": 1, "o": 1001}]});
        let answer = json!({"status": "order", "order": {"status": "canceled",
            "statusTimestamp": 9_100, "order": {"oid": 1001, "cloid": "0xabc"}}});
        let aliases = aliases(std::slice::from_ref(&answer));
        assert_eq!(
            aliases,
            vec!["oid:1001".to_owned(), "cloid:0xabc".to_owned()]
        );
        let mut tracker = Tracker::default();
        tracker.observe(&intent(1, 9_000, by_cloid.clone()));
        // Its own name alone: not elsewhere.
        assert!(!tracker.named_elsewhere(&by_cloid, &aliases));
        tracker.observe(&intent(2, 9_050, by_oid));
        assert!(tracker.named_elsewhere(&by_cloid, &aliases));
        // A resolved one counts while among the last names too.
        let mut tracker = Tracker::default();
        tracker.observe(&intent(1, 9_000, by_cloid.clone()));
        tracker.observe(&intent(2, 9_050, order_action("0x1")));
        tracker.observe(&answered(3, 2, json!({"resting": {"oid": 7}})));
        let other = aliases_of(7, "0x1");
        assert!(tracker.named_elsewhere(&by_cloid, &other));
        assert!(!tracker.named_elsewhere(&by_cloid, &aliases_of(8, "0x2")));
    }

    /// An alias that only an open intent still names (its name long gone
    /// from the last 50,000): still elsewhere.
    #[test]
    fn an_alias_an_open_intent_names_counts_however_old() {
        let by_oid = json!({"type": "cancel", "cancels": [{"a": 1, "o": 1001}]});
        let by_cloid =
            json!({"type": "cancelByCloid", "cancels": [{"asset": 1, "cloid": "0xabc"}]});
        let mut tracker = Tracker::default();
        tracker.observe(&intent(1, 9_000, by_oid));
        tracker.observe(&json!({"seq": 2, "kind": "sent", "decision": 1, "index": 0,
            "reply": {"error": "timeout"}}));
        let mut seq = 3;
        for i in 0..50_001u64 {
            tracker.observe(&intent(seq, 9_100, order_action(&format!("0x{:032x}", i))));
            tracker.observe(&answered(
                seq + 1,
                seq,
                json!({"resting": {"oid": 10_000 + i}}),
            ));
            seq += 2;
        }
        tracker.observe(&intent(seq, 9_200, by_cloid.clone()));
        assert!(tracker.named_elsewhere(&by_cloid, &aliases_of(1001, "0xabc")));
        // Once that intent is resolved, forgotten.
        tracker.observe(&json!({"seq": seq + 1, "kind": "recovered", "intent": 1, "index": 0}));
        assert!(!tracker.named_elsewhere(&by_cloid, &aliases_of(1001, "0xabc")));
    }

    fn aliases_of(oid: u64, cloid: &str) -> Vec<String> {
        aliases(&[json!({"status": "order", "order": {"order": {"oid": oid, "cloid": cloid}}})])
    }

    #[test]
    fn a_modify_replaces_the_order_it_names_by_id() {
        assert_eq!(replaced_oid(&json!({"type": "modify", "oid": 7})), Some(7));
        assert_eq!(
            replaced_oid(&json!({"type": "batchModify", "modifies": [{"oid": 8}, {"oid": 9}]})),
            Some(8)
        );
        assert_eq!(
            replaced_oid(&json!({"type": "modify", "oid": "0x7a67"})),
            None
        );
        assert_eq!(replaced_oid(&order_action("0x1")), None);
        // A batch modify's old order is no evidence of it.
        let modify = json!({"type": "batchModify", "modifies": [
            {"oid": 7, "order": limit_buy("0x1")}]});
        let item = Pending {
            intent: 1,
            index: 0,
            at_ms: 9_000,
            action: modify,
            shared: false,
        };
        let old = venue_order("B", "60000", "0.01", 10_000, "open");
        assert_eq!(
            conclude_order_action(&item, &[old], &|_| false).outcome,
            "unknown"
        );
    }

    #[test]
    fn a_shared_cancel_is_never_happened() {
        let cancel = json!({"type": "cancel", "cancels": [{"a": 0, "o": 7}]});
        let item = Pending {
            intent: 1,
            index: 0,
            at_ms: 100_000,
            action: cancel,
            shared: false,
        };
        let cancelled =
            json!({"status": "order", "order": {"status": "canceled", "statusTimestamp": 100_010}});
        assert_eq!(
            conclude_cancel_action(&item, std::slice::from_ref(&cancelled)).outcome,
            "happened"
        );
        let shared = Pending {
            shared: true,
            ..item
        };
        assert_eq!(
            conclude_cancel_action(&shared, &[cancelled]).outcome,
            "moot"
        );
    }
}
