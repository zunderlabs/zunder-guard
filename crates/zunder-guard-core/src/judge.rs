// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Judging one authenticated request: allow, resize or veto, and the
//! action to forward.
//!
//! # Entries
//!
//! An entry is an order that is not reduce-only and does not close an
//! opposite position. Guard handles one entry per action, a limit order
//! (an IOC limit is how the SDKs and ccxt send market orders), optionally
//! with its TP/SL. It is judged in this order; the first refusal wins:
//!
//! 1. The kill switch and the risk engine's state (daily loss stop,
//!    drawdown halt) refuse every entry.
//! 2. The market: a perp of the main dex or of a HIP-3 dex the policy's
//!    markets name, listed, not delisted (on a HIP-3 dex: not halted by its
//!    deployer), and in the policy's markets; on a HIP-3 dex also margined
//!    in USDC and not at its open-interest cap. Spot and HIP-4 outcome
//!    assets are refused (below, "Everything else").
//! 3. The account: standard mode with a readable equity (summed over the
//!    dexes Guard reads), a mid price for the coin.
//! 4. The worst fill: the limit price, pulled in to
//!    [`Policy::entry_price_bound`] beyond the mid when it lies further out.
//! 5. The stop: the entry's own stop loss (a `normalTpsl` child, or a
//!    reduce-only stop loss in the same action), or, with
//!    [`StopPolicy::Attach`], one Guard attaches at
//!    [`Policy::default_stop_distance`]; with [`StopPolicy::Refuse`], no
//!    stop is a veto. A stop at or through the mid is refused.
//! 6. Size, by the risk engine (`RiskEngine::size_entry`): loss at the
//!    stop within the per-trade budget including fees and slippage, open
//!    risk within its budget, total position value within the leverage
//!    cap. Open risk counts every position (the engine's record or the
//!    venue's, whichever holds more) and every resting entry at its limit
//!    price and waiting stop; a position or resting entry without a stop
//!    refuses every entry.
//! 7. The position cap: the coin's position value at most
//!    [`Policy::max_position_of_account`] times equity.
//! 8. Liquidation: on a new position Guard sets isolated margin at the
//!    highest whole leverage within the policy's and the venue's caps whose
//!    liquidation lies beyond the stop's worst fill (with room for fees and
//!    funding) and at least [`Policy::min_liquidation_distance`] from the
//!    entry; an existing position must already be isolated within the
//!    caps, and its liquidation that far away. The venue's leverage cap is
//!    the coin's own dex's (`maxLeverage` in that dex's `meta`).
//! 9. On a HIP-3 dex: the size its own margin account can fund at that
//!    leverage (`withdrawable` of the dex's `clearinghouseState`), and
//!    [`HIP3_BOOK_SHARE`] of the depth the book shows on the stop's side
//!    down to the stop's worst fill, less what is held or rests there.
//!
//! The account-wide rules (loss at the stop, open risk, leverage, the
//! position cap, the daily loss stop and the drawdown halt) measure equity
//! and positions over every dex Guard reads together: a loss on a HIP-3
//! dex counts toward the daily loss stop like one on the main dex.
//!
//! The bot's size is kept when it fits, and cut otherwise (a resize, never
//! an increase); quantities round down.
//!
//! # Everything else
//!
//! Reduce-only orders, closes and cancels are allowed even while halted
//! or killed, except where they would remove protection: a cancel or a
//! modify may not leave a position without a stop covering all of it, may
//! not loosen a stop, and may not push open risk over its budget. An
//! opposite order no larger than the position is forwarded as reduce-only.
//! `updateLeverage` must stay isolated and within the caps, and may only
//! lower the leverage of an open position. `updateIsolatedMargin` may only
//! add margin. Every order, modify, `updateLeverage` and
//! `updateIsolatedMargin` must name a listed perp of a dex Guard reads: the
//! main dex (asset id below 10,000, its index in `meta`) or a HIP-3 dex the
//! markets name (100,000 + 10,000 × dex + index, `dex_not_allowed`
//! otherwise). Spot pairs (10,000 + index) and HIP-4 outcomes
//! (100,000,000 plus 10 × outcome + side) are refused, reduce-only or not. Cancels are
//! allowed on any asset: they only remove orders. `scheduleCancel` may only
//! be cleared: setting it would one day cancel the stops too.

use rust_decimal::{Decimal, dec, prelude::ToPrimitive};
use serde::Serialize;
use zunder_core::{Side, Symbol};
use zunder_risk::{RiskEngine, RiskState, SizeRequest, Veto};

use crate::{
    account::{AccountView, AssetInfo, AssetKind, MIN_NOTIONAL, asset_kind},
    action::{
        Action, Builder, Cancel, Cloid, ExchangeRequest, Grouping, Modify, Order, OrderAction,
        OrderKind, OrderRef, Px, Tpsl,
    },
    policy::{Policy, StopPolicy},
};

/// How far beyond the stop's worst fill, as a multiple of the distance to
/// it, the liquidation price has to lie (the rule of Zunder's own trading
/// session)...
pub const LIQUIDATION_ROOM: Decimal = dec!(1.1);
/// ...plus this fraction of the price, for fees and funding.
pub const FUNDING_ROOM: Decimal = dec!(0.05);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Forwarded as the bot sent it (apart from Guard's own nonce,
    /// signature and builder field).
    Allow,
    /// Forwarded with changes: a smaller size, a nearer limit price, an
    /// attached stop, a close made reduce-only. `changes` lists them.
    Resize,
    Veto,
}

/// What to send to the venue for an allowed or resized request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    /// Actions to send first, each of which must succeed: setting isolated
    /// leverage before an entry.
    pub pre: Vec<Action>,
    pub action: Action,
    pub expires_after: Option<u64>,
    /// For an order action: where each of the bot's orders went in the
    /// forwarded one, so the reply's statuses can be put back in the bot's
    /// order. Orders Guard added (an attached stop) are not in it.
    pub status_map: Vec<usize>,
    /// The entry, to record with the risk engine once it fills.
    pub entry: Option<EntryPlan>,
    /// Actions to send after the action succeeded: cancelling Guard's own
    /// stop once a tighter stop of the bot's rests.
    pub post: Vec<Action>,
    /// The forwarded orders whose status must be `resting` for `post` to be
    /// sent: the bot's replacing stops.
    pub post_after: Vec<usize>,
}

/// A forwarded entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntryPlan {
    pub coin: String,
    pub side: Side,
    /// The size the bot asked for.
    pub requested_qty: Decimal,
    /// The size forwarded: never more than `requested_qty`.
    pub qty: Decimal,
    pub worst_price: Decimal,
    pub stop: Decimal,
    pub leverage: Option<u32>,
}

/// The decision about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub verdict: Verdict,
    /// A short, stable reason code (`allowed`, `resized`, `stop_required`,
    /// `open_risk`, ...).
    pub code: &'static str,
    /// For a person and for the bot's log.
    pub text: String,
    /// For a resize: what was changed.
    pub changes: Vec<String>,
    pub forward: Option<Forward>,
}

impl Decision {
    pub fn veto(code: &'static str, text: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Veto,
            code,
            text: text.into(),
            changes: Vec::new(),
            forward: None,
        }
    }

    fn pass(forward: Forward, changes: Vec<String>) -> Self {
        let (verdict, code, text) = if changes.is_empty() {
            (Verdict::Allow, "allowed", "within every rule".to_owned())
        } else {
            (Verdict::Resize, "resized", changes.join("; "))
        };
        Self {
            verdict,
            code,
            text,
            changes,
            forward: Some(forward),
        }
    }
}

/// What a request is judged against.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    pub policy: &'a Policy,
    pub engine: &'a RiskEngine,
    pub account: &'a AccountView,
    /// The kill switch: no entries, no leverage increases.
    pub killed: bool,
    /// The builder field a forwarded entry carries: Orcastrate's or a
    /// licence's ([`crate::licence::FeeState::builder_for_orders`]); none
    /// without a fee or a confirmed approval. Guard sets the same field on
    /// every other order it sends when it sends them
    /// ([`crate::licence::with_builder`]), so the judge leaves it off the
    /// rest.
    pub builder: Option<&'a Builder>,
    /// A secret of this Guard process, mixed into the client order ids of
    /// the stops it attaches, so that a bot cannot predict one and take it
    /// first.
    pub salt: &'a [u8],
}

/// A refusal is boxed: a `Decision` is large.
type Judged<T> = Result<T, Box<Decision>>;

fn veto<T>(code: &'static str, text: impl Into<String>) -> Judged<T> {
    Err(Box::new(Decision::veto(code, text)))
}

/// `None` from checked arithmetic on a bot's numbers.
fn overflow() -> Box<Decision> {
    Box::new(Decision::veto(
        "invalid",
        "the order's numbers are too large to judge",
    ))
}

/// Judge `request`, which has been authenticated.
pub fn judge(ctx: &Context<'_>, request: &ExchangeRequest) -> Decision {
    let (widened, widen_changes) = widen_market_stops(ctx, request);
    let widened = keep_guard_cloids(ctx, widened);
    let request = &widened;
    let result = match &request.action {
        Action::Order(order) => judge_order(ctx, order, request),
        Action::Cancel(cancels) | Action::CancelByCloid(cancels) => {
            judge_cancels(ctx, cancels).map(|()| Decision::pass(plain(request), Vec::new()))
        }
        Action::Modify(modify) => judge_modifies(ctx, std::slice::from_ref(modify))
            .map(|()| Decision::pass(plain(request), Vec::new())),
        Action::BatchModify(modifies) => {
            judge_modifies(ctx, modifies).map(|()| Decision::pass(plain(request), Vec::new()))
        }
        Action::UpdateLeverage {
            asset,
            is_cross,
            leverage,
        } => judge_leverage(ctx, *asset, *is_cross, *leverage)
            .map(|()| Decision::pass(plain(request), Vec::new())),
        // Margin only for a perp of a dex Guard reads, like every other
        // action that names an asset: Guard sees no other dex's account.
        Action::UpdateIsolatedMargin {
            asset: index, ntli, ..
        } => {
            if let Err(decision) = asset(ctx, *index) {
                Err(decision)
            } else if *ntli > 0 {
                Ok(Decision::pass(plain(request), Vec::new()))
            } else {
                veto(
                    "margin_removal",
                    "removing isolated margin moves the liquidation price towards the position; Guard only lets margin be added",
                )
            }
        }
        Action::ScheduleCancel { time } => match time {
            None => Ok(Decision::pass(plain(request), Vec::new())),
            Some(_) => veto(
                "schedule_cancel",
                "a scheduled cancel would also cancel the protective stops; Guard only lets one be cleared",
            ),
        },
    };
    let mut decision = result.unwrap_or_else(|decision| *decision);
    if !widen_changes.is_empty() && decision.forward.is_some() {
        decision.text = format!("{}; {}", decision.text, widen_changes.join("; "));
        decision.changes.splice(0..0, widen_changes);
        if decision.verdict == Verdict::Allow {
            decision.verdict = Verdict::Resize;
            decision.code = "resized";
        }
    }
    decision
}

/// Widen the limit of every reduce-only market stop loss in the request to
/// the policy's stop slippage beyond its trigger (rounded towards filling),
/// where the bot's lies closer: a market stop capped near its trigger may
/// not fill in a gap, like a stop-limit. Everything after this sees, judges
/// and forwards the widened stops.
fn widen_market_stops(
    ctx: &Context<'_>,
    request: &ExchangeRequest,
) -> (ExchangeRequest, Vec<String>) {
    let mut request = request.clone();
    let mut changes = Vec::new();
    let slippage = ctx.policy.stop_slippage;
    let mut widen = |order: &mut Order| {
        if !order.is_market_stop() {
            return;
        }
        let OrderKind::Trigger { trigger_px, .. } = &order.kind else {
            return;
        };
        let trigger = trigger_px.value();
        let Some(asset) = ctx.account.meta.by_index(order.asset) else {
            return;
        };
        let bound = if order.is_buy {
            trigger
                .checked_mul(Decimal::ONE + slippage)
                .and_then(|price| asset.round_price(price, true))
        } else {
            trigger
                .checked_mul(Decimal::ONE - slippage)
                .and_then(|price| asset.round_price(price, false))
        };
        let Some(bound) = bound else {
            return;
        };
        let closer = if order.is_buy {
            order.price.value() < bound
        } else {
            order.price.value() > bound
        };
        if closer && let Some(price) = Px::from_decimal(bound) {
            changes.push(format!(
                "the stop's limit {} widened to {bound}, {} beyond its trigger {trigger}, so it fills in a gap",
                order.price,
                percent(slippage)
            ));
            order.price = price;
        }
    };
    match &mut request.action {
        Action::Order(action) => action.orders.iter_mut().for_each(&mut widen),
        Action::Modify(modify) => widen(&mut modify.order),
        Action::BatchModify(modifies) => modifies
            .iter_mut()
            .for_each(|modify| widen(&mut modify.order)),
        _ => {}
    }
    (request, changes)
}

/// A modify of one of Guard's stops that names no client id gets the
/// stop's own, so the replacement keeps it whatever the venue does with a
/// modify that names none (Guard knows its stops by it). A modify that
/// names another one is refused in [`judge_modifies`].
fn keep_guard_cloids(ctx: &Context<'_>, mut request: ExchangeRequest) -> ExchangeRequest {
    let keep = |modify: &mut Modify| {
        if modify.order.cloid.is_some() {
            return;
        }
        let existing = match &modify.oid {
            OrderRef::Oid(oid) => ctx.account.order_by_oid(*oid),
            OrderRef::Cloid(cloid) => ctx.account.order_by_cloid(cloid.as_str()),
        };
        if let Some(cloid) = existing
            .and_then(|order| order.cloid.as_deref())
            .filter(|cloid| is_guard_cloid(cloid))
            .and_then(Cloid::parse)
        {
            modify.order.cloid = Some(cloid);
        }
    };
    match &mut request.action {
        Action::Modify(modify) => keep(modify),
        Action::BatchModify(modifies) => modifies.iter_mut().for_each(keep),
        _ => {}
    }
    request
}

/// The request's action forwarded as it is.
fn plain(request: &ExchangeRequest) -> Forward {
    Forward {
        pre: Vec::new(),
        action: request.action.clone(),
        expires_after: request.expires_after,
        status_map: Vec::new(),
        entry: None,
        post: Vec::new(),
        post_after: Vec::new(),
    }
}

fn halted(ctx: &Context<'_>) -> Option<Decision> {
    if ctx.killed {
        return Some(Decision::veto(
            "kill_switch",
            "the kill switch is on: Guard opens nothing until a person restarts it without the kill file",
        ));
    }
    match ctx.engine.state() {
        RiskState::Active => None,
        RiskState::HaltedForDay { .. } => Some(Decision::veto(
            "daily_loss_stop",
            format!(
                "the daily loss stop ({}) has fired: no new positions until the next UTC day",
                percent(ctx.policy.daily_loss_stop)
            ),
        )),
        RiskState::Stopped { drawdown, .. } => Some(Decision::veto(
            "drawdown_halt",
            format!(
                "the drawdown halt ({}) fired at a drawdown of {}: no new positions until a person reviews it",
                percent(ctx.policy.drawdown_halt),
                percent(drawdown)
            ),
        )),
    }
}

fn percent(fraction: Decimal) -> String {
    match fraction.checked_mul(dec!(100)) {
        Some(value) => format!("{}%", value.round_dp(2).normalize()),
        None => format!("{fraction} (as a fraction)"),
    }
}

/// The perp an asset id names, on a dex Guard reads. Spot pairs and HIP-4
/// outcomes are refused; a HIP-3 id is accepted only on a dex the policy's
/// markets name (Guard read its `meta`, so the id maps to the coin the
/// venue will trade, by Hyperliquid's own arithmetic), else
/// `dex_not_allowed`.
fn asset<'a>(ctx: &Context<'a>, index: u32) -> Judged<&'a AssetInfo> {
    let listed = || match ctx.account.meta.by_index(index) {
        Some(asset) => Ok(asset),
        None => veto(
            "unknown_market",
            format!("asset {index} is not a perp the venue lists"),
        ),
    };
    // A dex the view holds and the policy's markets name: both, so that the
    // judge holds to the policy even if a view carries more.
    let managed = |dex: u32| {
        ctx.account
            .meta
            .dex(dex)
            .is_some_and(|read| ctx.policy.markets.hip3_dexes().contains(&read.name))
    };
    match asset_kind(index) {
        AssetKind::MainPerp => listed(),
        AssetKind::Hip3 { dex } if managed(dex) => listed(),
        AssetKind::Hip3 { dex } => veto(
            "dex_not_allowed",
            format!(
                "asset {index} is a perp of HIP-3 dex #{dex}, which the rules do not allow: Guard reads, judges and forwards only the dexes its markets name (\"dex:*\" or \"dex:COIN\")"
            ),
        ),
        AssetKind::Spot | AssetKind::Outcome => veto(
            "unsupported_market",
            format!("asset {index} is a spot pair or a HIP-4 outcome; Guard trades perps only"),
        ),
        AssetKind::Invalid => veto("unknown_market", format!("asset {index} names no perp dex")),
    }
}

/// The prefix of the client order ids of the stops Guard attaches: `zg`.
pub const GUARD_CLOID_PREFIX: &str = "0x7a67";

/// Whether a client order id is one of Guard's.
/// Whether a bot's new orders carry an id with the prefix of Guard's own
/// stops: refused, so nothing of a bot's passes for one of Guard's.
pub fn uses_guard_cloid(action: &OrderAction) -> bool {
    action.orders.iter().any(|order| {
        order
            .cloid
            .as_ref()
            .is_some_and(|cloid| is_guard_cloid(cloid.as_str()))
    })
}

pub fn is_guard_cloid(cloid: &str) -> bool {
    cloid
        .get(..GUARD_CLOID_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(GUARD_CLOID_PREFIX))
}

/// The client order id of the stop Guard attaches to the entry in
/// `request`: the prefix and 28 hex digits of a hash of Guard's secret
/// salt, the request's nonce and its signature: unique because a client's
/// nonces are, and unpredictable to the bot.
fn guard_cloid(salt: &[u8], request: &ExchangeRequest) -> Cloid {
    let mut data = request.nonce.to_be_bytes().to_vec();
    data.extend_from_slice(&request.signature.r);
    data.extend_from_slice(&request.signature.s);
    guard_cloid_of(salt, &data)
}

/// A Guard cloid from its secret salt and `data`.
fn guard_cloid_of(salt: &[u8], data: &[u8]) -> Cloid {
    let hash = crate::sign::keccak256(&[salt, data].concat());
    let mut text = GUARD_CLOID_PREFIX.to_owned();
    for byte in &hash[..14] {
        text.push_str(&format!("{byte:02x}"));
    }
    // `0x`, 4 and 28 hex digits.
    Cloid::from_hex_digits(text)
}

/// One order of an `order` action, and what Guard makes of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Reduce-only: a close, a stop, a take profit.
    Reducing,
    /// Not reduce-only, but opposite to a position and no larger: a close.
    Closing,
    Entry,
}

fn role(ctx: &Context<'_>, order: &Order, coin: &str) -> Judged<Role> {
    if order.reduce_only {
        return Ok(Role::Reducing);
    }
    let side = side_of(order.is_buy);
    match ctx.account.position(coin) {
        Some(position) if position.side != side => {
            if order.size.value() <= position.qty && !order.is_trigger() {
                Ok(Role::Closing)
            } else {
                veto(
                    "flip",
                    format!(
                        "the order would turn the {coin} position around; close it first (reduce-only), then enter"
                    ),
                )
            }
        }
        _ => Ok(Role::Entry),
    }
}

/// The highest isolated leverage the venue may be set to under a policy cap:
/// the cap's whole part, at least 1x, at most the venue's maximum.
fn venue_leverage_cap(policy_max: Decimal, venue_max: u32) -> Decimal {
    policy_max
        .floor()
        .max(Decimal::ONE)
        .min(Decimal::from(venue_max.max(1)))
}

fn side_of(is_buy: bool) -> Side {
    if is_buy { Side::Buy } else { Side::Sell }
}

fn judge_order(
    ctx: &Context<'_>,
    action: &OrderAction,
    request: &ExchangeRequest,
) -> Judged<Decision> {
    let expires_after = request.expires_after;
    if uses_guard_cloid(action) {
        return veto(
            "invalid",
            "client order ids starting 0x7a67 are reserved for Guard's own stops",
        );
    }
    let mut changes = Vec::new();
    let mut roles = Vec::with_capacity(action.orders.len());
    let mut coins = Vec::with_capacity(action.orders.len());
    for order in &action.orders {
        let asset = asset(ctx, order.asset)?;
        coins.push(asset.name.clone());
        roles.push(role(ctx, order, &asset.name)?);
    }
    let entries: Vec<usize> = (0..roles.len())
        .filter(|index| roles[*index] == Role::Entry)
        .collect();
    // A builder field of the bot's own: an entry carrying one is refused;
    // from an exit it is removed (an exit is never refused for it), and
    // Guard's own field goes on what it sends.
    if let Some(sent) = &action.builder {
        if !entries.is_empty() {
            return veto(
                "client_builder",
                format!(
                    "the order carries a builder field ({} at {} tenths of a bp); only Guard's configured builder may appear. In ccxt set options.builderFee = false",
                    sent.address, sent.fee_tenths_bp
                ),
            );
        }
        changes.push(format!(
            "the bot's builder field ({} at {} tenths of a bp) removed from its exit; only Guard's may appear",
            sent.address, sent.fee_tenths_bp
        ));
    }
    if entries.len() > 1 {
        return veto(
            "one_entry_per_action",
            "Guard judges one entry per order action; send each entry with its own TP/SL",
        );
    }
    if action.grouping == Grouping::PositionTpsl && !entries.is_empty() {
        return veto(
            "invalid",
            "a positionTpsl action holds only reduce-only TP/SL orders",
        );
    }

    let Some(&entry_index) = entries.first() else {
        // Only closes, stops and take profits.
        let mut orders = action.orders.clone();
        for ((order, role), coin) in orders.iter_mut().zip(&roles).zip(&coins) {
            if *role == Role::Closing {
                order.reduce_only = true;
                changes.push(format!(
                    "the {coin} order no larger than the opposite position is sent reduce-only"
                ));
            }
            // A reduce-only order standing on its own never asks for more
            // than the position it reduces: cut to the position's size (a
            // flip it could not do anyway, a stop for more than is held).
            if action.grouping == Grouping::Na
                && order.reduce_only
                && !order.is_trigger()
                && let Some(position) = ctx.account.position(coin)
                && side_of(order.is_buy) != position.side
                && order.size.value() > position.qty
            {
                changes.push(format!(
                    "the reduce-only {coin} order cut from {} to the position's {}",
                    order.size, position.qty
                ));
                order.size = px(position.qty)?;
            }
        }
        // Only stops standing on their own replace Guard's: a stop that is
        // the child of a reduce-only parent waits for that parent to fill.
        let (post, post_after) = if action.grouping == Grouping::Na {
            replace_guard_stops(ctx, &orders, &coins, &mut changes)
        } else {
            (Vec::new(), Vec::new())
        };
        let forwarded = OrderAction {
            orders,
            grouping: action.grouping,
            builder: None,
        };
        return Ok(Decision::pass(
            Forward {
                pre: Vec::new(),
                status_map: (0..action.orders.len()).collect(),
                action: Action::Order(forwarded),
                expires_after,
                entry: None,
                post,
                post_after,
            },
            changes,
        ));
    };

    // An entry: the others must be its TP/SL, on the same asset, opposite
    // side, reduce-only triggers.
    let entry = &action.orders[entry_index];
    if action.grouping == Grouping::NormalTpsl && entry_index != 0 {
        return veto("invalid", "in a normalTpsl action the entry comes first");
    }
    for (index, order) in action.orders.iter().enumerate() {
        if index == entry_index {
            continue;
        }
        let tpsl = order.reduce_only
            && order.is_trigger()
            && order.asset == entry.asset
            && order.is_buy != entry.is_buy;
        if !tpsl {
            return veto(
                "invalid",
                "an entry may only be sent with its own TP/SL (reduce-only trigger orders on the same market, opposite side); send other orders separately",
            );
        }
    }
    if let Some(stopped) = halted(ctx) {
        return Err(Box::new(stopped));
    }
    let children: Vec<(usize, &Order)> = action
        .orders
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != entry_index)
        .collect();
    let judged = judge_entry(ctx, entry, &children, request)?;
    changes.extend(judged.changes);

    // Forward: the entry first, then the bot's TP/SL, then Guard's stop.
    let mut orders = vec![judged.entry];
    let mut status_map = vec![0; action.orders.len()];
    for (index, child) in judged.children {
        status_map[index] = orders.len();
        orders.push(child);
    }
    if let Some(stop) = judged.attached_stop {
        orders.push(stop);
    }
    let grouping = if orders.len() > 1 {
        if action.grouping != Grouping::NormalTpsl {
            changes.push("the entry and its stop are sent as one normalTpsl group".to_owned());
        }
        Grouping::NormalTpsl
    } else {
        Grouping::Na
    };
    let forwarded = OrderAction {
        orders,
        grouping,
        builder: ctx.builder.cloned(),
    };
    Ok(Decision::pass(
        Forward {
            pre: judged.pre,
            action: Action::Order(forwarded),
            expires_after,
            status_map,
            entry: Some(judged.plan),
            post: Vec::new(),
            post_after: Vec::new(),
        },
        changes,
    ))
}

/// For each stop loss the bot sends for an open position that a stop of
/// Guard's protects: when the bot's covers the whole position and is
/// tighter than every one of Guard's, Guard's are cancelled after it rests
/// (the returned actions); otherwise Guard's stay, being tighter. Stops
/// only tighten either way.
fn replace_guard_stops(
    ctx: &Context<'_>,
    orders: &[Order],
    coins: &[String],
    changes: &mut Vec<String>,
) -> (Vec<Action>, Vec<usize>) {
    let account = ctx.account;
    let mut post = Vec::new();
    let mut post_after = Vec::new();
    for (index, (order, coin)) in orders.iter().zip(coins).enumerate() {
        // A stop-limit that might never fill is no stop.
        let Some(trigger) = order.protective_level() else {
            continue;
        };
        let Some(position) = account.position(coin) else {
            continue;
        };
        if side_of(order.is_buy) != position.side.opposite() {
            continue;
        }
        let guards: Vec<&crate::account::OpenOrderView> = account
            .open_orders
            .iter()
            .filter(|resting| {
                resting.coin == *coin
                    && resting.is_protective_stop()
                    && resting.cloid.as_deref().is_some_and(is_guard_cloid)
            })
            .collect();
        if guards.is_empty() {
            continue;
        }
        let tighter = guards.iter().all(|guard| {
            guard
                .protective_level()
                .is_some_and(|px| match position.side {
                    Side::Buy => trigger > px,
                    Side::Sell => trigger < px,
                })
        });
        let covers = order.size.value() >= position.qty;
        if tighter && covers {
            changes.push(format!(
                "the bot's stop at {trigger} is tighter than Guard's and covers the {coin} position: Guard's stop is cancelled once it rests"
            ));
            // By the oid read for this request: a modify rests a trigger
            // under a new oid (same client id), and the account is read
            // fresh for every request, so this is the current one. The
            // venue's look-up by client id was seen to answer for the old
            // oid after a modify (testnet, 6 Oct 2026), so not by client id.
            post.push(Action::Cancel(
                guards
                    .iter()
                    .map(|guard| Cancel {
                        asset: order.asset,
                        order: OrderRef::Oid(guard.oid),
                    })
                    .collect(),
            ));
            post_after.push(index);
        } else {
            changes.push(format!(
                "Guard's stop for {coin} stays: the bot's stop at {trigger} is not tighter or does not cover the whole position"
            ));
        }
    }
    (post, post_after)
}

struct JudgedEntry {
    entry: Order,
    /// The bot's TP/SL with their index in its action, sized to the entry.
    children: Vec<(usize, Order)>,
    attached_stop: Option<Order>,
    pre: Vec<Action>,
    plan: EntryPlan,
    changes: Vec<String>,
}

fn px(value: Decimal) -> Judged<Px> {
    Px::from_decimal(value).ok_or_else(overflow)
}

fn judge_entry(
    ctx: &Context<'_>,
    entry: &Order,
    children: &[(usize, &Order)],
    request: &ExchangeRequest,
) -> Judged<JudgedEntry> {
    let policy = ctx.policy;
    let account = ctx.account;
    let asset = asset(ctx, entry.asset)?;
    let coin = asset.name.as_str();
    let side = side_of(entry.is_buy);
    let mut changes = Vec::new();

    // A HIP-3 dex's perp: the dex is one Guard reads (`asset` checked).
    let hip3 = asset.dex != 0;
    if asset.delisted && hip3 {
        return veto(
            "market_halted",
            format!(
                "{coin} is halted: its deployer stopped trading and settled positions (HIP-3 haltTrading), or it was delisted"
            ),
        );
    }
    if asset.delisted {
        return veto("unknown_market", format!("{coin} is delisted"));
    }
    if !policy.markets.allows(coin) {
        return veto(
            "market_not_allowed",
            format!("{coin} is not in the policy's markets"),
        );
    }
    if hip3 {
        match account.dex_account(asset.dex) {
            Some(dex) if dex.usdc => {}
            Some(dex) => {
                return veto(
                    "unsupported_market",
                    format!(
                        "dex {} margins in another token than USDC; Guard sums equity in USDC and opens nothing there",
                        dex.name
                    ),
                );
            }
            None => {
                return veto(
                    "account_unknown",
                    format!("the margin account of {coin}'s dex was not read"),
                );
            }
        }
        if account.at_open_interest_cap.contains(coin) {
            return veto(
                "open_interest_cap",
                format!(
                    "{coin} is at its open-interest cap: the venue takes no order that adds to it"
                ),
            );
        }
    }
    let OrderKind::Limit { tif } = entry.kind else {
        return veto(
            "unsupported_order",
            "an entry must be a limit order (IOC for a market order); trigger entries fill at a price nobody knows in advance",
        );
    };
    let Some(equity) = account.equity.filter(|equity| *equity > Decimal::ZERO) else {
        return veto(
            "account_unknown",
            format!(
                "the account's equity cannot be read in account mode `{}`; Guard needs standard mode (`disabled`) with a positive perp account value",
                account.mode
            ),
        );
    };
    let Some(mid) = account.mid(coin) else {
        return veto("no_price", format!("no mid price for {coin}"));
    };

    // 4. The worst fill.
    let bound = match side {
        Side::Buy => mid
            .checked_mul(Decimal::ONE + policy.entry_price_bound)
            .and_then(|price| asset.round_price(price, false)),
        Side::Sell => mid
            .checked_mul(Decimal::ONE - policy.entry_price_bound)
            .and_then(|price| asset.round_price(price, true)),
    }
    .ok_or_else(overflow)?;
    let sent_price = entry.price.value();
    let worst = match side {
        Side::Buy => sent_price.min(bound),
        Side::Sell => sent_price.max(bound),
    };
    if worst <= Decimal::ZERO {
        return veto("invalid", "the entry's price must be positive");
    }
    let price = if worst == sent_price {
        entry.price.clone()
    } else {
        changes.push(format!(
            "limit price {sent_price} pulled in to {worst}, {} from the mid {mid}",
            percent(policy.entry_price_bound)
        ));
        px(worst)?
    };

    // 5. The stop.
    // The bot's stop: a market stop's trigger (its limit widened above). A
    // stop-limit is forwarded but is no stop.
    let own_stops: Vec<Decimal> = children
        .iter()
        .filter_map(|(_, order)| order.protective_level())
        .collect();
    let stop_reference = match side {
        Side::Buy => worst.min(mid),
        Side::Sell => worst.max(mid),
    };
    let (stop, attached) = match own_stops.as_slice() {
        [] => match policy.stop {
            StopPolicy::Refuse => {
                return veto(
                    "stop_required",
                    "the policy requires every entry to carry a stop loss (a normalTpsl child with tpsl \"sl\")",
                );
            }
            StopPolicy::Attach => {
                let distance = policy.default_stop_distance;
                let stop = match side {
                    // Rounded towards the price: never looser than the
                    // configured distance.
                    Side::Buy => stop_reference
                        .checked_mul(Decimal::ONE - distance)
                        .and_then(|stop| asset.round_price(stop, true)),
                    Side::Sell => stop_reference
                        .checked_mul(Decimal::ONE + distance)
                        .and_then(|stop| asset.round_price(stop, false)),
                }
                .ok_or_else(overflow)?;
                changes.push(format!(
                    "a reduce-only stop at {stop} ({} from {stop_reference}) is attached",
                    percent(distance)
                ));
                (stop, true)
            }
        },
        [stop] => (*stop, false),
        _ => {
            return veto(
                "invalid",
                "the entry carries more than one stop loss; send one",
            );
        }
    };
    let losing_side = match side {
        Side::Buy => stop < stop_reference,
        Side::Sell => stop > stop_reference,
    };
    if !losing_side || stop <= Decimal::ZERO {
        return veto(
            "stop_wrong_side",
            format!(
                "the stop {stop} is not on the losing side of the entry {worst} and the mid {mid}"
            ),
        );
    }

    // 6. Size, by the risk engine.
    let position = account.position(coin);
    let (open_risk, open_notional) = open_exposure(ctx)?;
    let sizing = SizeRequest {
        equity,
        side,
        entry: worst,
        stop,
        round_trip_cost: policy
            .round_trip_cost_scaled(worst, asset.fee_scale)
            .ok_or_else(overflow)?,
        open_risk,
        open_notional,
        qty_step: asset.qty_step(),
        min_notional: MIN_NOTIONAL,
    };
    let sized = ctx.engine.size_entry(&sizing).map_err(engine_veto)?;

    // 7. The position cap.
    let sizing_equity = policy
        .risk_limits()
        .capped(equity.min(ctx.engine.snapshot().last));
    // What the coin's position holds, and what resting entries on the
    // same side could add to it.
    let mut held = position
        .map(|position| position.qty.checked_mul(mid))
        .unwrap_or(Some(Decimal::ZERO))
        .ok_or_else(overflow)?;
    for resting in account
        .open_orders
        .iter()
        .filter(|order| order.coin == coin && order.is_opening() && order.side == side)
    {
        held = resting
            .qty
            .checked_mul(resting.limit_px.max(mid))
            .and_then(|value| held.checked_add(value))
            .ok_or_else(overflow)?;
    }
    let room = sizing_equity
        .checked_mul(policy.max_position_of_account)
        .and_then(|cap| cap.checked_sub(held))
        .ok_or_else(overflow)?;
    if room <= Decimal::ZERO {
        return veto(
            "position_cap",
            format!(
                "the {coin} position is already at the cap of {} of equity",
                percent(policy.max_position_of_account)
            ),
        );
    }
    // Valued at the higher of the fill and the mid, so that the position
    // is within the cap at either price.
    let by_cap = asset.round_qty_down(room.checked_div(worst.max(mid)).ok_or_else(overflow)?);

    // 8. Liquidation.
    let mut pre = Vec::new();
    let leverage = match position {
        None => {
            // The coin's one leverage setting has to suit this entry and
            // every entry already resting on the coin.
            let leverage = isolated_leverage(
                asset.max_leverage,
                policy.max_leverage,
                side,
                worst,
                stop,
                policy.stop_slippage,
                policy.min_liquidation_distance,
            )
            .and_then(|leverage| {
                resting_leverage(ctx, asset).map(|resting| resting.map_or(leverage, |r| r.min(leverage)))
            })
            .ok_or_else(|| {
                Box::new(Decision::veto(
                    "liquidation_too_close",
                    format!(
                        "no isolated leverage of at least 1x puts the liquidation beyond the stop {stop} and {} from the entry",
                        percent(policy.min_liquidation_distance)
                    ),
                ))
            })?;
            // The coin already set to isolated at this leverage or less (as
            // the venue showed moments ago): kept, with no update to send.
            // Less leverage only puts the liquidation further away.
            match account.leverage_settings.get(coin) {
                Some(set) if set.isolated && set.value >= 1 && set.value <= leverage => set.value,
                _ => {
                    pre.push(Action::UpdateLeverage {
                        asset: entry.asset,
                        is_cross: false,
                        leverage,
                    });
                    leverage
                }
            }
        }
        Some(position) => {
            if !position.leverage.isolated {
                return veto(
                    "cross_margin",
                    format!(
                        "the {coin} position is on cross margin; Guard adds only to isolated positions"
                    ),
                );
            }
            let leverage = position.leverage.value;
            // The venue's isolated leverage is a whole number, at least 1x:
            // a fractional cap allows its whole part (the risk engine still
            // holds the position's value to the fractional cap).
            let cap = venue_leverage_cap(policy.max_leverage, asset.max_leverage);
            if Decimal::from(leverage) > cap {
                return veto(
                    "leverage",
                    format!("the {coin} position runs at {leverage}x, above the cap of {cap}x"),
                );
            }
            // Measured at the looser of the new stop and the stop that
            // covers the position now: the combined position must clear
            // both.
            let checked_stop = match (account.covering_stop(coin, &[]), side) {
                (Some(held), Side::Buy) => held.min(stop),
                (Some(held), Side::Sell) => held.max(stop),
                (None, _) => stop,
            };
            let fits = isolated_leverage(
                asset.max_leverage,
                Decimal::from(leverage),
                side,
                worst,
                checked_stop,
                policy.stop_slippage,
                policy.min_liquidation_distance,
            ) == Some(leverage);
            let liquidation_clear = position.liquidation_px.is_none_or(|liquidation| {
                liquidation_clear(side, liquidation, checked_stop, mid, policy)
            });
            if !fits || !liquidation_clear {
                return veto(
                    "liquidation_too_close",
                    format!(
                        "at {leverage}x the {coin} position's liquidation would lie too close to the stop {stop} or the price"
                    ),
                );
            }
            leverage
        }
    };

    // 9. A HIP-3 dex's perp: its own margin account must fund the isolated
    // margin, and its book must be able to take the stop.
    let hip3_caps = if hip3 {
        Some(hip3_caps(ctx, asset, side, worst, stop, leverage)?)
    } else {
        None
    };

    // The quantity: never more than the bot asked for (min of the request
    // and what the rules allow: the verdict can only be allow, a resize
    // down, or a veto), and never more than the bot's own stop covers, so
    // that the stop is not enlarged beyond its request either.
    let sent_qty = entry.size.value();
    let stop_cover = children
        .iter()
        .filter(|(_, child)| child.protective_level().is_some())
        .map(|(_, child)| child.size.value())
        .min();
    let mut qty = asset.round_qty_down(
        sent_qty
            .min(sized)
            .min(by_cap)
            .min(stop_cover.unwrap_or(sent_qty)),
    );
    // Which of the HIP-3 caps bound the size, if one did.
    let mut hip3_bound: Option<(&'static str, String)> = None;
    if let Some(caps) = &hip3_caps {
        for (cap, code, why) in [
            (caps.by_margin, "dex_margin", caps.margin_text.clone()),
            (caps.by_book, "thin_book", caps.book_text.clone()),
        ] {
            let cap = asset.round_qty_down(cap.max(Decimal::ZERO));
            if cap < qty {
                qty = cap;
                hip3_bound = Some((code, why));
            }
        }
    }
    if qty > sent_qty {
        // Cannot happen (a min with the request); kept as a hard stop.
        return veto("invalid", "the forwarded size would exceed the request");
    }
    // The stop must be worth the venue's minimum too, at its worst fill
    // (a long's stop sells as low as stop x (1 - stop slippage)), or it may
    // be refused after the entry filled.
    let stop_floor = match side {
        Side::Buy => stop
            .checked_mul(Decimal::ONE - policy.stop_slippage)
            .and_then(|price| asset.round_price(price, false))
            .ok_or_else(overflow)?,
        Side::Sell => stop,
    };
    let value = qty
        .checked_mul(worst.min(stop_floor))
        .ok_or_else(overflow)?;
    if qty <= Decimal::ZERO || value < MIN_NOTIONAL {
        if let Some((code, why)) = &hip3_bound {
            let text = format!(
                "{why}: the size it allows ({qty} {coin}) is below the venue's minimum order value of {MIN_NOTIONAL} USDC"
            );
            return if *code == "dex_margin" {
                veto("dex_margin", text)
            } else {
                veto("thin_book", text)
            };
        }
        return veto(
            "below_minimum",
            format!(
                "the size the rules allow ({qty} {coin}) is below the venue's minimum order value of {MIN_NOTIONAL} USDC"
            ),
        );
    }
    let size = if qty == sent_qty {
        entry.size.clone()
    } else {
        let why = if let Some((_, why)) = &hip3_bound {
            why.clone()
        } else if qty == asset.round_qty_down(by_cap) && by_cap < sized {
            format!(
                "the position cap of {}",
                percent(policy.max_position_of_account)
            )
        } else {
            format!(
                "a loss at the stop within {} of equity and open risk within {}",
                percent(policy.max_loss_at_stop),
                percent(policy.max_open_risk)
            )
        };
        changes.push(format!("size {sent_qty} cut to {qty} {coin} for {why}"));
        px(qty)?
    };

    let forwarded_entry = Order {
        asset: entry.asset,
        is_buy: entry.is_buy,
        price,
        size: size.clone(),
        reduce_only: false,
        kind: OrderKind::Limit { tif },
        cloid: entry.cloid.clone(),
    };
    let mut forwarded_children = Vec::with_capacity(children.len());
    for (index, child) in children {
        // A child only ever shrinks to the entry's size: a stop the bot sent
        // covers at least the entry (the entry was cut to it above), a take
        // profit larger than the entry is cut to it.
        let mut child = (*child).clone();
        if child.size.value() > qty {
            changes.push(format!(
                "the {} child cut from {} to the entry's {qty}",
                match &child.kind {
                    OrderKind::Trigger { tpsl: Tpsl::Sl, .. } => "stop loss",
                    _ => "take profit",
                },
                child.size
            ));
            child.size = size.clone();
        }
        forwarded_children.push((*index, child));
    }
    let attached_stop = if attached {
        let worst_fill = match side {
            Side::Buy => stop
                .checked_mul(Decimal::ONE - policy.stop_slippage)
                .and_then(|price| asset.round_price(price, false)),
            Side::Sell => stop
                .checked_mul(Decimal::ONE + policy.stop_slippage)
                .and_then(|price| asset.round_price(price, true)),
        }
        .ok_or_else(overflow)?;
        Some(Order {
            asset: entry.asset,
            is_buy: !entry.is_buy,
            price: px(worst_fill)?,
            size: size.clone(),
            reduce_only: true,
            kind: OrderKind::Trigger {
                is_market: true,
                trigger_px: px(stop)?,
                tpsl: Tpsl::Sl,
            },
            cloid: Some(guard_cloid(ctx.salt, request)),
        })
    } else {
        None
    };
    Ok(JudgedEntry {
        entry: forwarded_entry,
        children: forwarded_children,
        attached_stop,
        pre,
        plan: EntryPlan {
            coin: coin.to_owned(),
            side,
            requested_qty: sent_qty,
            qty,
            worst_price: worst,
            stop,
            leverage: Some(leverage),
        },
        changes,
    })
}

/// The share of the book a HIP-3 position may need: its size, with what
/// already rests or is held on the same side of the coin, at most this
/// share of the size the book shows on the side its stop trades against,
/// between the stop's trigger and its worst fill ([`crate::account::Book::exit_depth`]: what
/// rests nearer the price will have traded by the time the stop fires).
/// HIP-3 books are thin, and a
/// market stop fills only what lies within its limit: the rest of the
/// position would stay open, unprotected, beyond the stop.
pub const HIP3_BOOK_SHARE: Decimal = dec!(0.5);

/// The two size caps of a HIP-3 entry, unrounded, with their reasons.
struct Hip3Caps {
    /// What the dex's own margin account can fund at the leverage set.
    by_margin: Decimal,
    margin_text: String,
    /// [`HIP3_BOOK_SHARE`] of the visible exit depth, less what is held or
    /// rests on the same side.
    by_book: Decimal,
    book_text: String,
}

fn hip3_caps(
    ctx: &Context<'_>,
    asset: &AssetInfo,
    side: Side,
    worst: Decimal,
    stop: Decimal,
    leverage: u32,
) -> Judged<Hip3Caps> {
    let account = ctx.account;
    let coin = asset.name.as_str();
    let Some(dex) = account.dex_account(asset.dex) else {
        return veto(
            "account_unknown",
            format!("the margin account of {coin}'s dex was not read"),
        );
    };
    // Each HIP-3 dex margins from its own account: an isolated position
    // there needs its value over its leverage free in that account, whatever
    // the main dex holds.
    let free = dex.withdrawable.unwrap_or(Decimal::ZERO).max(Decimal::ZERO);
    let by_margin = free
        .checked_mul(Decimal::from(leverage))
        .and_then(|notional| notional.checked_div(worst))
        .ok_or_else(overflow)?;
    let margin_text = format!(
        "the {} dex's margin account has {} USDC free, which margins {} {coin} at {leverage}x",
        dex.name,
        free.round_dp(2),
        asset.round_qty_down(by_margin)
    );
    let Some(book) = account.books.get(coin) else {
        return veto(
            "thin_book",
            format!(
                "the order book of {coin} could not be read; Guard sizes a HIP-3 entry to the depth its stop can fill into"
            ),
        );
    };
    let worst_exit = match side {
        Side::Buy => stop.checked_mul(Decimal::ONE - ctx.policy.stop_slippage),
        Side::Sell => stop.checked_mul(Decimal::ONE + ctx.policy.stop_slippage),
    }
    .ok_or_else(overflow)?;
    let depth = book
        .exit_depth(side, stop, worst_exit)
        .ok_or_else(overflow)?;
    let mut held = account
        .position(coin)
        .filter(|position| position.side == side)
        .map_or(Decimal::ZERO, |position| position.qty);
    for resting in account
        .open_orders
        .iter()
        .filter(|order| order.coin == coin && order.is_opening() && order.side == side)
    {
        held = held.checked_add(resting.qty).ok_or_else(overflow)?;
    }
    let by_book = depth
        .checked_mul(HIP3_BOOK_SHARE)
        .and_then(|share| share.checked_sub(held))
        .ok_or_else(overflow)?;
    let book_text = format!(
        "{} of the {depth} {coin} the book shows between the stop {stop} and its worst fill {}, less {held} held or resting, for a stop that can fill on a thin HIP-3 book",
        percent(HIP3_BOOK_SHARE),
        worst_exit.round_dp(6).normalize()
    );
    Ok(Hip3Caps {
        by_margin,
        margin_text,
        by_book,
        book_text,
    })
}

/// The highest isolated leverage every entry resting on `asset`'s coin
/// allows, by its limit and waiting stop: `Some(None)` when none rests,
/// `None` when one rests that no leverage suits (or that has no stop).
fn resting_leverage(ctx: &Context<'_>, asset: &AssetInfo) -> Option<Option<u32>> {
    let mut lowest: Option<u32> = None;
    for order in ctx
        .account
        .open_orders
        .iter()
        .filter(|order| order.coin == asset.name && order.is_opening())
    {
        let stop = order.child_stop()?;
        let fits = isolated_leverage(
            asset.max_leverage,
            ctx.policy.max_leverage,
            order.side,
            order.limit_px,
            stop,
            ctx.policy.stop_slippage,
            ctx.policy.min_liquidation_distance,
        )?;
        lowest = Some(lowest.map_or(fits, |lowest| lowest.min(fits)));
    }
    Some(lowest)
}

/// Whether a position's liquidation price lies beyond its stop's worst
/// fill and at least the policy's distance from the mid.
fn liquidation_clear(
    side: Side,
    liquidation: Decimal,
    stop: Decimal,
    mid: Decimal,
    policy: &Policy,
) -> bool {
    let distance = policy.min_liquidation_distance;
    let (stop_room, price_room) = match side {
        Side::Buy => (Decimal::ONE - policy.stop_slippage, Decimal::ONE - distance),
        Side::Sell => (Decimal::ONE + policy.stop_slippage, Decimal::ONE + distance),
    };
    let (Some(stop_worst), Some(price_bound)) =
        (stop.checked_mul(stop_room), mid.checked_mul(price_room))
    else {
        return false;
    };
    match side {
        Side::Buy => liquidation < stop_worst && liquidation <= price_bound,
        Side::Sell => liquidation > stop_worst && liquidation >= price_bound,
    }
}

/// Open risk and value of positions and resting entries.
fn open_exposure(ctx: &Context<'_>) -> Judged<(Decimal, Decimal)> {
    let combined = ctx
        .engine
        .combined_exposure(&ctx.account.venue_view())
        .map_err(engine_veto)?;
    let resting = ctx.account.resting_entry_exposure().map_err(|oid| {
        Box::new(Decision::veto(
            "unprotected_order",
            format!("order {oid} rests and could open a position without a stop; cancel it or give it a stop first"),
        ))
    })?;
    let risk = combined
        .exposure
        .risk
        .checked_add(resting.risk)
        .ok_or_else(overflow)?;
    let notional = combined
        .exposure
        .notional
        .checked_add(resting.notional)
        .ok_or_else(overflow)?;
    Ok((risk, notional))
}

fn engine_veto(veto: Veto) -> Box<Decision> {
    let code = match veto {
        Veto::HaltedForDay => "daily_loss_stop",
        Veto::Stopped => "drawdown_halt",
        Veto::StopOnWrongSide => "stop_wrong_side",
        Veto::OpenRiskExhausted => "open_risk",
        Veto::LeverageExhausted => "leverage",
        Veto::BelowMinimum => "below_minimum",
        Veto::InvalidRequest | Veto::Overflow => "invalid",
        Veto::UnprotectedPosition => "unprotected_position",
    };
    Box::new(Decision::veto(code, format!("risk engine: {veto}")))
}

/// The isolated leverage for an entry on `side` that may fill at up to
/// `entry`, with its stop at `trigger`: the highest whole number at most
/// the policy's cap (and at least 1) and the venue's maximum whose
/// liquidation lies beyond the stop's worst fill (`trigger` moved by
/// `stop_slippage`) by [`LIQUIDATION_ROOM`] of that distance plus
/// [`FUNDING_ROOM`], and at least `min_distance` from the entry.
///
/// The formula is Zunder's own executor's `isolated_leverage` (Hyperliquid's
/// "Liquidations" page): with maintenance margin `l = 1 / (2 * max)`, an
/// isolated position at leverage `L` is liquidated `(1/L - l) / (1 - l)` of
/// the price below a long's entry and `(1/L - l) / (1 + l)` above a
/// short's. `None` when not even 1x is far enough.
pub fn isolated_leverage(
    venue_max: u32,
    policy_max: Decimal,
    side: Side,
    entry: Decimal,
    trigger: Decimal,
    stop_slippage: Decimal,
    min_distance: Decimal,
) -> Option<u32> {
    if entry <= Decimal::ZERO || trigger <= Decimal::ZERO {
        return None;
    }
    let venue_max = venue_max.max(1);
    let policy_max = policy_max.floor().to_u32().unwrap_or(1).max(1);
    let ceiling = venue_max.min(policy_max);
    let maintenance =
        Decimal::ONE.checked_div(Decimal::from(venue_max).checked_mul(Decimal::TWO)?)?;
    let distance = match side {
        Side::Buy => {
            let worst = trigger.checked_mul(Decimal::ONE.checked_sub(stop_slippage)?)?;
            entry.checked_sub(worst)?.checked_div(entry)?
        }
        Side::Sell => {
            let worst = trigger.checked_mul(Decimal::ONE.checked_add(stop_slippage)?)?;
            worst.checked_sub(entry)?.checked_div(entry)?
        }
    };
    if distance <= Decimal::ZERO {
        return None;
    }
    let needed = distance
        .checked_mul(LIQUIDATION_ROOM)?
        .checked_add(FUNDING_ROOM)?
        .max(min_distance);
    let divisor = match side {
        Side::Buy => Decimal::ONE.checked_sub(maintenance)?,
        Side::Sell => Decimal::ONE.checked_add(maintenance)?,
    };
    (1..=ceiling).rev().find(|leverage| {
        Decimal::ONE
            .checked_div(Decimal::from(*leverage))
            .and_then(|margin| margin.checked_sub(maintenance))
            .and_then(|room| room.checked_div(divisor))
            .is_some_and(|liquidation| liquidation >= needed)
    })
}

/// Cancels may not leave a position or a resting entry unprotected, nor
/// push open risk over its budget.
fn judge_cancels(ctx: &Context<'_>, cancels: &[Cancel]) -> Judged<()> {
    let account = ctx.account;
    let found: Vec<&crate::account::OpenOrderView> = cancels
        .iter()
        .filter_map(|cancel| match &cancel.order {
            OrderRef::Oid(oid) => account.order_by_oid(*oid),
            OrderRef::Cloid(cloid) => account.order_by_cloid(cloid.as_str()),
        })
        .collect();
    if let Some(guard) = found.iter().find(|order| {
        order.is_protective_stop()
            && order.cloid.as_deref().is_some_and(is_guard_cloid)
            && account.position(&order.coin).is_some()
    }) {
        return veto(
            "guard_stop",
            format!(
                "order {} is the stop Guard attached to the {} position; send a tighter stop to replace it",
                guard.oid, guard.coin
            ),
        );
    }
    let cancelled: Vec<u64> = found.iter().map(|order| order.oid).collect();
    stops_still_cover(ctx, &cancelled, None)
}

/// After the orders in `removed` are gone and `replaced` (a coin and a
/// new stop trigger) is in place, every position is still covered and
/// open risk within budget.
fn stops_still_cover(
    ctx: &Context<'_>,
    removed: &[u64],
    replaced: Option<(&str, Decimal, Decimal)>,
) -> Judged<()> {
    let account = ctx.account;
    let mut touched = Vec::new();
    for oid in removed {
        let Some(order) = account.order_by_oid(*oid) else {
            continue;
        };
        if !order.is_protective_stop() {
            continue;
        }
        // A stop waiting for a resting entry: the entry must go with it.
        if let Some(parent) = account.parent_of(*oid)
            && !removed.contains(&parent.oid)
            && parent.child_stop().is_some()
        {
            let remaining = parent
                .children
                .iter()
                .any(|child| child.is_protective_stop() && !removed.contains(&child.oid));
            if !remaining {
                return veto(
                    "stop_removed",
                    format!(
                        "order {oid} is the stop of the resting entry {}; cancel the entry with it",
                        parent.oid
                    ),
                );
            }
        }
        if account.position(&order.coin).is_some() && !touched.contains(&order.coin) {
            touched.push(order.coin.clone());
        }
    }
    if touched.is_empty() {
        return Ok(());
    }
    for position in &account.positions {
        let stop = match replaced {
            Some((coin, trigger, size)) if coin == position.coin => {
                account.covering_stop_with(coin, removed, Some((trigger, size)))
            }
            _ => account.covering_stop(&position.coin, removed),
        };
        if stop.is_none() && touched.contains(&position.coin) {
            return veto(
                "stop_removed",
                format!(
                    "this would leave the {} position without a stop covering all of it",
                    position.coin
                ),
            );
        }
    }
    let risk = open_stop_risk(account, removed, replaced)?;
    // Resting entries count as in sizing, at their limit and waiting stop.
    let resting = account
        .resting_entry_exposure_except(removed)
        .map_err(|oid| {
            Box::new(Decision::veto(
                "unprotected_order",
                format!(
                    "order {oid} rests and could open a position without a stop; cancel it first"
                ),
            ))
        })?;
    let risk = risk.checked_add(resting.risk).ok_or_else(overflow)?;
    let Some(equity) = ctx.account.equity else {
        // Without a known equity there is no budget to measure against:
        // the request may only lower the positions' risk to their stops,
        // never raise it. (Removing orders only lowers the resting entries'
        // part.)
        let before = open_stop_risk(account, &[], None)?;
        let after = open_stop_risk(account, removed, replaced)?;
        if after > before {
            return veto(
                "stop_loosened",
                format!(
                    "the account's equity is unknown, and this would raise the positions' risk to their stops from {} to {} USDC",
                    before.round_dp(2),
                    after.round_dp(2)
                ),
            );
        }
        return Ok(());
    };
    // The same equity sizing uses: the venue's, the engine's last
    // observation, whichever is lower, capped at the trading-equity cap.
    let budget = ctx
        .policy
        .risk_limits()
        .capped(equity.min(ctx.engine.snapshot().last))
        .checked_mul(ctx.policy.max_open_risk)
        .ok_or_else(overflow)?;
    if risk > budget {
        return veto(
            "stop_loosened",
            format!(
                "after this the positions' risk to their stops would be {} USDC, above the open-risk budget of {} USDC ({} of equity)",
                risk.round_dp(2),
                budget.round_dp(2),
                percent(ctx.policy.max_open_risk)
            ),
        );
    }
    Ok(())
}

/// The positions' risk to their covering stops (from the mid), with the
/// orders in `removed` gone and `replaced` in their place. A position no
/// stop covers adds nothing: it was unprotected before, and the caller
/// refuses a request that strips one of its stop.
fn open_stop_risk(
    account: &AccountView,
    removed: &[u64],
    replaced: Option<(&str, Decimal, Decimal)>,
) -> Judged<Decimal> {
    let mut risk = Decimal::ZERO;
    for position in &account.positions {
        let stop = match replaced {
            Some((coin, trigger, size)) if coin == position.coin => {
                account.covering_stop_with(coin, removed, Some((trigger, size)))
            }
            _ => account.covering_stop(&position.coin, removed),
        };
        let Some(stop) = stop else {
            continue;
        };
        let Some(mark) = account.mid(&position.coin) else {
            return veto("no_price", format!("no mid price for {}", position.coin));
        };
        let distance = match position.side {
            Side::Buy => mark.checked_sub(stop),
            Side::Sell => stop.checked_sub(mark),
        }
        .ok_or_else(overflow)?;
        risk = position
            .qty
            .checked_mul(distance.max(Decimal::ZERO))
            .and_then(|position_risk| risk.checked_add(position_risk))
            .ok_or_else(overflow)?;
    }
    Ok(risk)
}

fn judge_modifies(ctx: &Context<'_>, modifies: &[Modify]) -> Judged<()> {
    let account = ctx.account;
    let mut removed = Vec::new();
    for modify in modifies {
        // The market first: an order on a dex Guard does not read is one
        // it cannot see either.
        let asset = asset(ctx, modify.order.asset)?;
        let existing = match &modify.oid {
            OrderRef::Oid(oid) => account.order_by_oid(*oid),
            OrderRef::Cloid(cloid) => account.order_by_cloid(cloid.as_str()),
        };
        let Some(existing) = existing else {
            return veto(
                "unknown_order",
                "the order to modify is not resting; Guard cannot judge a modify of an order it cannot see",
            );
        };
        let new = &modify.order;
        // Guard's client ids stay on Guard's stops: a modify of one keeps
        // its id (Guard knows its stops by it), and no other order takes
        // one.
        let existing_is_guards = existing.cloid.as_deref().is_some_and(is_guard_cloid);
        let new_cloid = new.cloid.as_ref().map(|cloid| cloid.normalized());
        let takes_guards_id = new_cloid.as_deref().is_some_and(is_guard_cloid);
        if (existing_is_guards && new_cloid.as_deref() != existing.cloid.as_deref())
            || (!existing_is_guards && takes_guards_id)
        {
            return veto(
                "invalid",
                "a modify of Guard's stop must keep its client id, and no other order may take one of Guard's (0x7a67…)",
            );
        }
        if asset.name != existing.coin || side_of(new.is_buy) != existing.side {
            return veto(
                "invalid",
                "a modify may not change the order's market or side",
            );
        }
        if let Some(old) = existing.protective_level() {
            // Compared by trigger. A stop-limit is no stop at all.
            let Some(trigger) = new.protective_level() else {
                return veto(
                    "stop_loosened",
                    "a stop loss may only be modified into a reduce-only market stop loss (a stop-limit may never fill)",
                );
            };
            // The order buys back a short (a buy) or sells a long (a sell).
            let tighter = match existing.side {
                Side::Sell => trigger >= old,
                Side::Buy => trigger <= old,
            };
            if !tighter {
                return veto(
                    "stop_loosened",
                    format!("stops only tighten: {old} to {trigger} would loosen it"),
                );
            }
            // A position TP/SL covers the whole position: its new size must
            // too, or the venue may apply it as an ordinary, smaller stop.
            let needed = if existing.is_position_tpsl {
                account
                    .position(&existing.coin)
                    .map_or(existing.qty, |position| position.qty)
            } else {
                existing.qty
            };
            let covers = new.size.value() >= needed;
            if !covers {
                return veto(
                    "stop_loosened",
                    format!(
                        "the stop's size may not shrink from {} to {}",
                        existing.qty, new.size
                    ),
                );
            }
            // A stop still waiting for its entry protects no position yet:
            // tighter, no smaller, and still on the losing side of the
            // entry's price is all it needs.
            if let Some(parent) = account.parent_of(existing.oid) {
                let losing = match parent.side {
                    Side::Buy => trigger < parent.limit_px,
                    Side::Sell => trigger > parent.limit_px,
                };
                if !losing {
                    return veto(
                        "stop_wrong_side",
                        format!(
                            "the stop {trigger} would not be on the losing side of its entry at {}",
                            parent.limit_px
                        ),
                    );
                }
                continue;
            }
            removed.push(existing.oid);
            stops_still_cover(
                ctx,
                &removed,
                Some((&existing.coin, trigger, new.size.value())),
            )?;
        } else if existing.is_opening() {
            // A modify replaces the order on the venue, and whether the
            // stop waiting for it survives that is not established: an
            // entry could rest, and fill, without its stop. Cancel and send
            // a new entry instead; Guard sizes and protects that one.
            return veto(
                "modify_entry",
                "a resting entry cannot be modified through Guard; cancel it and send a new entry instead",
            );
        } else if !new.reduce_only {
            return veto("invalid", "a reduce-only order must stay reduce-only");
        } else if let (Some(level), Some(parent)) =
            (new.protective_level(), account.parent_of(existing.oid))
        {
            // Turned into a stop waiting for an entry: on the losing side.
            let losing = match parent.side {
                Side::Buy => level < parent.limit_px,
                Side::Sell => level > parent.limit_px,
            };
            if !losing {
                return veto(
                    "stop_wrong_side",
                    format!(
                        "the stop {level} would not be on the losing side of its entry at {}",
                        parent.limit_px
                    ),
                );
            }
        }
    }
    Ok(())
}

fn judge_leverage(ctx: &Context<'_>, index: u32, is_cross: bool, leverage: u32) -> Judged<()> {
    let asset = asset(ctx, index)?;
    if is_cross {
        return veto(
            "cross_margin",
            "Guard keeps every position on isolated margin: send isCross false",
        );
    }
    let cap = venue_leverage_cap(ctx.policy.max_leverage, asset.max_leverage);
    if leverage == 0 || Decimal::from(leverage) > cap {
        return veto(
            "leverage",
            format!(
                "leverage {leverage}x is above the cap of {cap}x for {}",
                asset.name
            ),
        );
    }
    let current = ctx.account.position(&asset.name);
    let raising = current
        .is_some_and(|position| !position.leverage.isolated || leverage > position.leverage.value);
    if raising {
        return veto(
            "leverage",
            format!(
                "the {} position is open: its leverage may only be lowered",
                asset.name
            ),
        );
    }
    if current.is_none() {
        if let Some(stopped) = halted(ctx) {
            return Err(Box::new(stopped));
        }
        // Entries resting on the coin fill at this leverage: it must suit
        // each of them.
        match resting_leverage(ctx, asset) {
            Some(None) => {}
            Some(Some(highest)) if leverage <= highest => {}
            _ => {
                return veto(
                    "liquidation_too_close",
                    format!(
                        "an entry resting on {} needs a lower leverage to keep its liquidation beyond its stop",
                        asset.name
                    ),
                );
            }
        }
    }
    Ok(())
}

/// The symbol of a coin, for the risk engine.
pub fn symbol(coin: &str) -> Symbol {
    Symbol::new(coin)
}

#[cfg(test)]
pub(crate) mod tests;

/// Guard's own market stops for the positions no stop covers in full: a
/// reduce-only stop loss for the whole position, one action per coin,
/// `(coin, action)`, at the tighter of the policy's default distance from
/// the mid and the stop the risk engine recorded for the position (when
/// that still lies on the losing side), rounded towards the price. The
/// second vector names the coins that get no stop (the caller closes them):
/// no price, or a recorded stop the price has already gone through. The
/// third says what a person should look at: a stop whose worst fill lies
/// beyond the position's liquidation price (placed all the same), or
/// Guard's own stop resting without counting (none placed on top).
/// `nonce` makes the stops' ids unique per round.
pub fn protect_actions(
    account: &AccountView,
    policy: &Policy,
    engine: &RiskEngine,
    salt: &[u8],
    nonce: u64,
) -> (Vec<(String, Action)>, Vec<String>, Vec<String>) {
    protect_actions_with(account, policy, engine, salt, nonce, &[])
}

/// [`protect_actions`], with `planned`: the stops of entries Guard
/// forwarded that filled while resting (coin, side, stop), which the risk
/// engine does not record. For a position on that coin and side, the
/// tighter of the engine's stop and a planned one the price is not through
/// counts as recorded, so Guard places the stop the entry was sized for,
/// not one at the default distance. A planned stop never makes Guard close
/// a position.
pub fn protect_actions_with(
    account: &AccountView,
    policy: &Policy,
    engine: &RiskEngine,
    salt: &[u8],
    nonce: u64,
    planned: &[(String, Side, Decimal)],
) -> (Vec<(String, Action)>, Vec<String>, Vec<String>) {
    let mut actions = Vec::new();
    let mut unpriced = Vec::new();
    let mut problems = Vec::new();
    for position in &account.positions {
        if account.covering_stop(&position.coin, &[]).is_some() {
            continue;
        }
        // A halted HIP-3 market takes no orders: its deployer settles the
        // positions at the mark. Sending a stop and then a close every round
        // would spend the request budget for nothing; a person looks.
        if account
            .meta
            .by_name(&position.coin)
            .is_some_and(|asset| asset.dex != 0 && asset.delisted)
        {
            problems.push(format!(
                "{}: the market is halted by its deployer and takes no orders; the venue settles the position at the mark",
                position.coin
            ));
            continue;
        }
        // Guard's own stop rests but does not count (its limit, as the
        // venue reports it, leaves no room): never stack another one every
        // round; a person looks.
        // Only a full-size reduce-only market stop of Guard's that fails
        // on its limit alone: a partial one gets a full-size stop beside it.
        let own_stop_rests = account.open_orders.iter().any(|order| {
            order.coin == position.coin
                && order.side != position.side
                && order.reduce_only
                && order.is_market
                && matches!(order.trigger, Some((_, Tpsl::Sl)))
                && order.qty >= position.qty
                && order.protective_level().is_none()
                && order.cloid.as_deref().is_some_and(is_guard_cloid)
        });
        if own_stop_rests {
            problems.push(format!(
                "{}: Guard's own stop rests but does not count as protection (the venue reports its limit within 5% of its trigger); check it",
                position.coin
            ));
            continue;
        }
        let recorded = engine
            .positions()
            .iter()
            .find(|tracked| {
                tracked.symbol.as_str() == position.coin && tracked.side == position.side
            })
            .and_then(|tracked| tracked.stop);
        let tighter = |a: Decimal, b: Decimal| match position.side {
            Side::Buy => a.max(b),
            Side::Sell => a.min(b),
        };
        // A planned stop only ever places a stop: one the price is already
        // through is ignored (never a reason to close), unlike a stop the
        // engine recorded.
        // Compared as it would be placed: rounded towards the price.
        let mid = account.mid(&position.coin);
        let asset = account.meta.by_name(&position.coin);
        let usable = |stop: &Decimal| {
            let placed =
                asset.and_then(|asset| asset.round_price(*stop, position.side == Side::Buy));
            mid.zip(placed)
                .is_some_and(|(mid, placed)| match position.side {
                    Side::Buy => placed < mid,
                    Side::Sell => placed > mid,
                })
        };
        let mut through = Vec::new();
        let planned_here: Vec<Decimal> = planned
            .iter()
            .filter(|(coin, side, _)| *coin == position.coin && *side == position.side)
            .map(|(_, _, stop)| *stop)
            .filter(|stop| {
                let ok = usable(stop);
                if !ok {
                    through.push(*stop);
                }
                ok
            })
            .collect();
        for stop in through {
            problems.push(format!(
                "{}: the price is through the stop {stop} a resting entry was sized for (its own stop was not active); Guard places one at the default distance instead, so the loss can exceed what the entry was sized for",
                position.coin
            ));
        }
        let recorded = planned_here.into_iter().chain(recorded).reduce(tighter);
        match protective_stop(account, policy, salt, nonce, position, recorded) {
            Some((action, worst)) => {
                let beyond_liquidation =
                    position
                        .liquidation_px
                        .is_some_and(|liquidation| match position.side {
                            Side::Buy => worst <= liquidation,
                            Side::Sell => worst >= liquidation,
                        });
                if beyond_liquidation {
                    problems.push(format!(
                        "{}: the stop's worst fill {worst} lies beyond the liquidation price; add margin or reduce the position",
                        position.coin
                    ));
                }
                actions.push((position.coin.clone(), action));
            }
            None => unpriced.push(position.coin.clone()),
        }
    }
    (actions, unpriced, problems)
}

fn protective_stop(
    account: &AccountView,
    policy: &Policy,
    salt: &[u8],
    nonce: u64,
    position: &crate::account::PositionView,
    recorded: Option<Decimal>,
) -> Option<(Action, Decimal)> {
    let asset = account.meta.by_name(&position.coin)?;
    let mid = account.mid(&position.coin)?;
    let (stop, worst) = match position.side {
        Side::Buy => {
            let default = mid.checked_mul(Decimal::ONE - policy.default_stop_distance)?;
            // A recorded stop the price has gone through is not widened
            // to the default: the caller closes the position instead.
            let stop = match recorded {
                Some(recorded) if recorded < mid => default.max(recorded),
                Some(_) => return None,
                None => default,
            };
            let stop = asset.round_price(stop, true)?;
            if stop >= mid {
                return None;
            }
            let worst = asset.round_price(
                stop.checked_mul(Decimal::ONE - policy.stop_slippage)?,
                false,
            )?;
            (stop, worst)
        }
        Side::Sell => {
            let default = mid.checked_mul(Decimal::ONE + policy.default_stop_distance)?;
            let stop = match recorded {
                Some(recorded) if recorded > mid => default.min(recorded),
                Some(_) => return None,
                None => default,
            };
            let stop = asset.round_price(stop, false)?;
            if stop <= mid {
                return None;
            }
            let worst =
                asset.round_price(stop.checked_mul(Decimal::ONE + policy.stop_slippage)?, true)?;
            (stop, worst)
        }
    };
    if stop <= Decimal::ZERO || worst <= Decimal::ZERO {
        return None;
    }
    let mut data = nonce.to_be_bytes().to_vec();
    data.extend_from_slice(position.coin.as_bytes());
    let action = Action::Order(OrderAction {
        orders: vec![Order {
            asset: asset.index,
            is_buy: position.side == Side::Sell,
            price: Px::from_decimal(worst)?,
            size: Px::from_decimal(position.qty)?,
            reduce_only: true,
            kind: OrderKind::Trigger {
                is_market: true,
                trigger_px: Px::from_decimal(stop)?,
                tpsl: Tpsl::Sl,
            },
            cloid: Some(guard_cloid_of(salt, &data)),
        }],
        grouping: Grouping::Na,
        builder: None,
    });
    Some((action, worst))
}
