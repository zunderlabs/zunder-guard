// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! The `/exchange` requests a bot sends, decoded strictly, and encoded
//! again in the venue's field order.
//!
//! Decoded: `order` (with grouping `na`, `normalTpsl` or `positionTpsl`
//! and an optional builder), `cancel`, `cancelByCloid`, `modify`,
//! `batchModify`, `updateLeverage`, `updateIsolatedMargin` and
//! `scheduleCancel`, in the shapes the official SDKs and ccxt build. Every
//! other action is refused by name; actions that move funds or grant
//! permissions (transfers, withdrawals, `approveAgent`,
//! `approveBuilderFee`, vaults, staking) get their own reason, since Guard
//! never forwards them.
//!
//! Decoding is strict: an unknown field, a float where an integer belongs,
//! a number where Hyperliquid wants a string, or a malformed price is an
//! error, never a guess. Prices and sizes keep the exact text the bot sent,
//! because that text is what it signed ([`Action::to_wire`] reproduces the
//! bot's hash input), and are parsed as exact decimals for judging.

use std::{fmt, str::FromStr};

use rust_decimal::{Decimal, dec};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{sign::Signature, wire::Wire};

/// Most orders, cancels or modifies one action may carry. Hyperliquid's
/// own batches are far smaller in practice; this bounds the work per
/// request.
pub const MAX_BATCH: usize = 64;

/// How far beyond its trigger a market stop's limit (`p`) must lie, as a
/// fraction of the trigger, for the stop to count as protection: the
/// smallest stop slippage a policy may set. A market stop whose limit sits
/// at its trigger may be capped there and not fill in a gap, like a
/// stop-limit. Guard widens the limit of every market stop it forwards to
/// the policy's stop slippage (`judge`), so this only decides about stops
/// placed elsewhere.
pub const MIN_STOP_ROOM: Decimal = dec!(0.05);

/// Whether a stop's limit `limit` lies at least [`MIN_STOP_ROOM`] beyond
/// its `trigger` on the side it fills: below for a sell, above for a buy.
pub fn limit_leaves_room(is_buy: bool, trigger: Decimal, limit: Decimal) -> bool {
    if is_buy {
        trigger
            .checked_mul(Decimal::ONE + MIN_STOP_ROOM)
            .is_some_and(|bound| limit >= bound)
    } else {
        trigger
            .checked_mul(Decimal::ONE - MIN_STOP_ROOM)
            .is_some_and(|bound| limit <= bound)
    }
}

/// Actions that move funds or grant permissions. Guard never forwards
/// them; they get [`DecodeError::FundsOrPermissions`].
pub const FUND_AND_PERMISSION_ACTIONS: &[&str] = &[
    "usdSend",
    "spotSend",
    "withdraw3",
    "usdClassTransfer",
    "sendAsset",
    "subAccountTransfer",
    "subAccountSpotTransfer",
    "vaultTransfer",
    "approveAgent",
    "approveBuilderFee",
    "setReferrer",
    "cDeposit",
    "cWithdraw",
    "tokenDelegate",
    "createVault",
    "vaultModify",
    "vaultDistribute",
    "createSubAccount",
    "convertToMultiSigUser",
    "multiSig",
    "spotUser",
    "evmUserModify",
    "userDexAbstraction",
    "userSetAbstraction",
    "agentSetAbstraction",
    "perpDeploy",
    "spotDeploy",
    "registerReferrer",
    "claimRewards",
    "borrowLend",
];

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("the request is not JSON: {0}")]
    NotJson(String),
    #[error("{0}")]
    Malformed(String),
    #[error(
        "`{0}` moves funds or grants permissions; Zunder Guard never forwards such actions: do this in the Hyperliquid app with the main wallet"
    )]
    FundsOrPermissions(String),
    #[error(
        "`{0}` is not supported by Zunder Guard (supported: order, cancel, cancelByCloid, modify, batchModify, updateLeverage, updateIsolatedMargin, scheduleCancel)"
    )]
    Unsupported(String),
    #[error(
        "requests for a vault or sub-account (vaultAddress) are not supported: Guard trades the configured account only"
    )]
    Vault,
}

fn malformed(text: impl Into<String>) -> DecodeError {
    DecodeError::Malformed(text.into())
}

/// A price or size: the exact text sent and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Px {
    raw: String,
    value: Decimal,
}

impl Px {
    /// Plain decimal digits with an optional fraction, as Hyperliquid's
    /// prices and sizes are written: no sign, no exponent, no spaces.
    pub fn parse(raw: &str) -> Option<Self> {
        let (whole, fraction) = match raw.split_once('.') {
            Some((whole, fraction)) => (whole, Some(fraction)),
            None => (raw, None),
        };
        let digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
        if !digits(whole) || fraction.is_some_and(|fraction| !digits(fraction)) || raw.len() > 40 {
            return None;
        }
        let value = Decimal::from_str(raw).ok()?;
        Some(Self {
            raw: raw.to_owned(),
            value,
        })
    }

    /// A value Guard writes itself: without trailing zeros, as the Python
    /// SDK's `float_to_wire` normalises. `None` for a negative value or one
    /// with more than 8 decimals.
    pub fn from_decimal(value: Decimal) -> Option<Self> {
        let normalized = value.normalize();
        (normalized >= Decimal::ZERO && normalized.scale() <= 8).then(|| Self {
            raw: normalized.to_string(),
            value: normalized,
        })
    }

    pub fn value(&self) -> Decimal {
        self.value
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for Px {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// A client order id: `0x` and 32 hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cloid(String);

impl Cloid {
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.strip_prefix("0x")?;
        (digits.len() == 32 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A cloid Guard built itself as `0x` and 32 hex digits.
    pub(crate) fn from_hex_digits(text: String) -> Self {
        debug_assert!(Self::parse(&text).is_some());
        Self(text)
    }

    /// Lowercase, for comparing with what the venue reports.
    pub fn normalized(&self) -> String {
        self.0.to_ascii_lowercase()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tif {
    Alo,
    Ioc,
    Gtc,
}

impl Tif {
    fn name(self) -> &'static str {
        match self {
            Tif::Alo => "Alo",
            Tif::Ioc => "Ioc",
            Tif::Gtc => "Gtc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpsl {
    Tp,
    Sl,
}

impl Tpsl {
    fn name(self) -> &'static str {
        match self {
            Tpsl::Tp => "tp",
            Tpsl::Sl => "sl",
        }
    }
}

/// `t` of an order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderKind {
    Limit {
        tif: Tif,
    },
    Trigger {
        is_market: bool,
        trigger_px: Px,
        tpsl: Tpsl,
    },
}

/// One order of an `order` action, or the new order of a modify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub asset: u32,
    pub is_buy: bool,
    pub price: Px,
    pub size: Px,
    pub reduce_only: bool,
    pub kind: OrderKind,
    pub cloid: Option<Cloid>,
}

impl Order {
    pub fn to_wire(&self) -> Wire {
        let kind = match &self.kind {
            OrderKind::Limit { tif } => Wire::Map(vec![(
                "limit",
                Wire::Map(vec![("tif", Wire::str(tif.name()))]),
            )]),
            OrderKind::Trigger {
                is_market,
                trigger_px,
                tpsl,
            } => Wire::Map(vec![(
                "trigger",
                Wire::Map(vec![
                    ("isMarket", Wire::Bool(*is_market)),
                    ("triggerPx", Wire::str(trigger_px.raw())),
                    ("tpsl", Wire::str(tpsl.name())),
                ]),
            )]),
        };
        let mut fields = vec![
            ("a", Wire::UInt(u64::from(self.asset))),
            ("b", Wire::Bool(self.is_buy)),
            ("p", Wire::str(self.price.raw())),
            ("s", Wire::str(self.size.raw())),
            ("r", Wire::Bool(self.reduce_only)),
            ("t", kind),
        ];
        if let Some(cloid) = &self.cloid {
            fields.push(("c", Wire::str(cloid.as_str())));
        }
        Wire::Map(fields)
    }

    /// A stop loss: a trigger order with `tpsl: "sl"`.
    pub fn stop_trigger(&self) -> Option<Decimal> {
        match &self.kind {
            OrderKind::Trigger {
                trigger_px,
                tpsl: Tpsl::Sl,
                ..
            } => Some(trigger_px.value()),
            _ => None,
        }
    }

    /// The trigger at which this order, as a reduce-only market stop loss
    /// whose limit leaves room to fill ([`limit_leaves_room`]), bounds a
    /// loss. `None` for anything else: a stop-limit is no protection, since
    /// once triggered its limit may rest on the wrong side of a falling (or
    /// rising) market and never fill; it is forwarded like any reduce-only
    /// order but never counts as a stop.
    pub fn protective_level(&self) -> Option<Decimal> {
        match &self.kind {
            OrderKind::Trigger {
                is_market: true,
                trigger_px,
                tpsl: Tpsl::Sl,
            } if self.reduce_only
                && limit_leaves_room(self.is_buy, trigger_px.value(), self.price.value()) =>
            {
                Some(trigger_px.value())
            }
            _ => None,
        }
    }

    /// A reduce-only market stop loss whatever its limit: what Guard widens.
    pub fn is_market_stop(&self) -> bool {
        self.reduce_only
            && matches!(
                self.kind,
                OrderKind::Trigger {
                    is_market: true,
                    tpsl: Tpsl::Sl,
                    ..
                }
            )
    }

    pub fn is_trigger(&self) -> bool {
        matches!(self.kind, OrderKind::Trigger { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grouping {
    Na,
    NormalTpsl,
    PositionTpsl,
}

impl Grouping {
    pub fn name(self) -> &'static str {
        match self {
            Grouping::Na => "na",
            Grouping::NormalTpsl => "normalTpsl",
            Grouping::PositionTpsl => "positionTpsl",
        }
    }
}

/// `{"b": address, "f": fee in tenths of a basis point}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Builder {
    /// As sent; the SDKs send it lowercase.
    pub address: String,
    pub fee_tenths_bp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderAction {
    pub orders: Vec<Order>,
    pub grouping: Grouping,
    pub builder: Option<Builder>,
}

/// The order a modify or cancel names: by venue id or client id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderRef {
    Oid(u64),
    Cloid(Cloid),
}

impl OrderRef {
    fn to_wire(&self) -> Wire {
        match self {
            OrderRef::Oid(oid) => Wire::UInt(*oid),
            OrderRef::Cloid(cloid) => Wire::str(cloid.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Modify {
    pub oid: OrderRef,
    pub order: Order,
}

impl Modify {
    fn to_wire(&self) -> Wire {
        Wire::Map(vec![
            ("oid", self.oid.to_wire()),
            ("order", self.order.to_wire()),
        ])
    }
}

/// A cancel: the asset and the order, by venue id (`cancel`) or client id
/// (`cancelByCloid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cancel {
    pub asset: u32,
    pub order: OrderRef,
}

/// An action Guard understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Order(OrderAction),
    /// `cancel`: every entry names an oid.
    Cancel(Vec<Cancel>),
    /// `cancelByCloid`: every entry names a cloid.
    CancelByCloid(Vec<Cancel>),
    Modify(Modify),
    BatchModify(Vec<Modify>),
    UpdateLeverage {
        asset: u32,
        is_cross: bool,
        leverage: u32,
    },
    UpdateIsolatedMargin {
        asset: u32,
        is_buy: bool,
        /// USD times 10^6; negative removes margin.
        ntli: i64,
    },
    ScheduleCancel {
        time: Option<u64>,
    },
}

impl Action {
    /// The action's `type`.
    pub fn kind(&self) -> &'static str {
        match self {
            Action::Order(_) => "order",
            Action::Cancel(_) => "cancel",
            Action::CancelByCloid(_) => "cancelByCloid",
            Action::Modify(_) => "modify",
            Action::BatchModify(_) => "batchModify",
            Action::UpdateLeverage { .. } => "updateLeverage",
            Action::UpdateIsolatedMargin { .. } => "updateIsolatedMargin",
            Action::ScheduleCancel { .. } => "scheduleCancel",
        }
    }

    /// The action in Hyperliquid's field order, with the exact text of
    /// every price and size: what the signature covers.
    pub fn to_wire(&self) -> Wire {
        let kind = ("type", Wire::str(self.kind()));
        match self {
            Action::Order(action) => {
                let mut fields = vec![
                    kind,
                    (
                        "orders",
                        Wire::Array(action.orders.iter().map(Order::to_wire).collect()),
                    ),
                    ("grouping", Wire::str(action.grouping.name())),
                ];
                if let Some(builder) = &action.builder {
                    fields.push((
                        "builder",
                        Wire::Map(vec![
                            ("b", Wire::str(builder.address.clone())),
                            ("f", Wire::UInt(builder.fee_tenths_bp)),
                        ]),
                    ));
                }
                Wire::Map(fields)
            }
            Action::Cancel(cancels) => Wire::Map(vec![
                kind,
                (
                    "cancels",
                    Wire::Array(
                        cancels
                            .iter()
                            .map(|cancel| {
                                Wire::Map(vec![
                                    ("a", Wire::UInt(u64::from(cancel.asset))),
                                    ("o", cancel.order.to_wire()),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]),
            Action::CancelByCloid(cancels) => Wire::Map(vec![
                kind,
                (
                    "cancels",
                    Wire::Array(
                        cancels
                            .iter()
                            .map(|cancel| {
                                Wire::Map(vec![
                                    ("asset", Wire::UInt(u64::from(cancel.asset))),
                                    ("cloid", cancel.order.to_wire()),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]),
            Action::Modify(modify) => Wire::Map(vec![
                kind,
                ("oid", modify.oid.to_wire()),
                ("order", modify.order.to_wire()),
            ]),
            Action::BatchModify(modifies) => Wire::Map(vec![
                kind,
                (
                    "modifies",
                    Wire::Array(modifies.iter().map(Modify::to_wire).collect()),
                ),
            ]),
            Action::UpdateLeverage {
                asset,
                is_cross,
                leverage,
            } => Wire::Map(vec![
                kind,
                ("asset", Wire::UInt(u64::from(*asset))),
                ("isCross", Wire::Bool(*is_cross)),
                ("leverage", Wire::UInt(u64::from(*leverage))),
            ]),
            Action::UpdateIsolatedMargin {
                asset,
                is_buy,
                ntli,
            } => Wire::Map(vec![
                kind,
                ("asset", Wire::UInt(u64::from(*asset))),
                ("isBuy", Wire::Bool(*is_buy)),
                ("ntli", Wire::Int(*ntli)),
            ]),
            Action::ScheduleCancel { time } => {
                let mut fields = vec![kind];
                if let Some(time) = time {
                    fields.push(("time", Wire::UInt(*time)));
                }
                Wire::Map(fields)
            }
        }
    }
}

/// A decoded `/exchange` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeRequest {
    pub action: Action,
    pub nonce: u64,
    pub signature: Signature,
    pub expires_after: Option<u64>,
}

/// Decode the JSON body of a `/exchange` request.
pub fn decode_request(body: &[u8]) -> Result<ExchangeRequest, DecodeError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|error| DecodeError::NotJson(error.to_string()))?;
    decode_request_value(&value)
}

/// Decode a `/exchange` request already parsed as JSON (the payload of a
/// WebSocket `post`).
pub fn decode_request_value(value: &Value) -> Result<ExchangeRequest, DecodeError> {
    let fields = object(value, "the request")?;
    // The action's type first: a refused action is named as such even when
    // the rest of the request is something Guard cannot read.
    let action_value = fields
        .get("action")
        .ok_or_else(|| malformed("the request has no `action`"))?;
    let action = decode_action(action_value)?;
    only_keys(
        fields,
        &[
            "action",
            "nonce",
            "signature",
            "vaultAddress",
            "expiresAfter",
        ],
        "the request",
    )?;
    match fields.get("vaultAddress") {
        None | Some(Value::Null) => {}
        Some(_) => return Err(DecodeError::Vault),
    }
    let nonce = uint(fields.get("nonce"), "nonce")?;
    let expires_after = match fields.get("expiresAfter") {
        None | Some(Value::Null) => None,
        Some(value) => Some(uint(Some(value), "expiresAfter")?),
    };
    let signature = decode_signature(
        fields
            .get("signature")
            .ok_or_else(|| malformed("the request has no `signature`"))?,
    )?;
    Ok(ExchangeRequest {
        action,
        nonce,
        signature,
        expires_after,
    })
}

fn object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, DecodeError> {
    value
        .as_object()
        .ok_or_else(|| malformed(format!("{what} must be a JSON object")))
}

fn only_keys(fields: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<(), DecodeError> {
    match fields.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(malformed(format!("{what} has an unknown field `{key}`"))),
        None => Ok(()),
    }
}

fn field<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a Value, DecodeError> {
    fields
        .get(key)
        .ok_or_else(|| malformed(format!("`{key}` is missing")))
}

fn uint(value: Option<&Value>, what: &str) -> Result<u64, DecodeError> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed(format!("`{what}` must be a non-negative integer")))
}

fn uint32(value: &Value, what: &str) -> Result<u32, DecodeError> {
    u32::try_from(uint(Some(value), what)?)
        .map_err(|_| malformed(format!("`{what}` is out of range")))
}

fn boolean(value: &Value, what: &str) -> Result<bool, DecodeError> {
    value
        .as_bool()
        .ok_or_else(|| malformed(format!("`{what}` must be true or false")))
}

fn string<'a>(value: &'a Value, what: &str) -> Result<&'a str, DecodeError> {
    value
        .as_str()
        .ok_or_else(|| malformed(format!("`{what}` must be a string")))
}

fn px(value: &Value, what: &str) -> Result<Px, DecodeError> {
    Px::parse(string(value, what)?).ok_or_else(|| {
        malformed(format!(
            "`{what}` must be a plain decimal number in a string"
        ))
    })
}

fn array<'a>(value: &'a Value, what: &str) -> Result<&'a Vec<Value>, DecodeError> {
    let items = value
        .as_array()
        .ok_or_else(|| malformed(format!("`{what}` must be an array")))?;
    if items.is_empty() {
        return Err(malformed(format!("`{what}` is empty")));
    }
    if items.len() > MAX_BATCH {
        return Err(malformed(format!(
            "`{what}` holds {} entries; Guard accepts at most {MAX_BATCH}",
            items.len()
        )));
    }
    Ok(items)
}

fn hex32(text: &str, what: &str) -> Result<[u8; 32], DecodeError> {
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| malformed(format!("`{what}` must start with 0x")))?;
    if digits.is_empty() || digits.len() > 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(malformed(format!("`{what}` must be at most 64 hex digits")));
    }
    let padded = format!("{digits:0>64}");
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let pair = padded
            .get(2 * index..2 * index + 2)
            .ok_or_else(|| malformed(format!("`{what}` is malformed")))?;
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|_| malformed(format!("`{what}` is malformed")))?;
    }
    Ok(out)
}

/// A request's `{"r", "s", "v"}` signature, strictly.
pub fn decode_signature(value: &Value) -> Result<Signature, DecodeError> {
    let fields = object(value, "`signature`")?;
    only_keys(fields, &["r", "s", "v"], "`signature`")?;
    let r = hex32(string(field(fields, "r")?, "signature.r")?, "signature.r")?;
    let s = hex32(string(field(fields, "s")?, "signature.s")?, "signature.s")?;
    let v = uint(fields.get("v"), "signature.v")?;
    let v = match v {
        27 | 28 => v as u8,
        _ => return Err(malformed("`signature.v` must be 27 or 28")),
    };
    Ok(Signature { r, s, v })
}

/// Decode an action alone, without nonce or signature: what Guard's
/// read-only preview endpoint judges.
pub fn decode_action_value(value: &Value) -> Result<Action, DecodeError> {
    decode_action(value)
}

fn decode_action(value: &Value) -> Result<Action, DecodeError> {
    let fields = object(value, "`action`")?;
    let kind = string(field(fields, "type")?, "action.type")?;
    let keys = |allowed: &[&str]| only_keys(fields, allowed, "the action");
    match kind {
        "order" => {
            keys(&["type", "orders", "grouping", "builder"])?;
            let orders = array(field(fields, "orders")?, "orders")?
                .iter()
                .map(decode_order)
                .collect::<Result<Vec<_>, _>>()?;
            let grouping = match string(field(fields, "grouping")?, "grouping")? {
                "na" => Grouping::Na,
                "normalTpsl" => Grouping::NormalTpsl,
                "positionTpsl" => Grouping::PositionTpsl,
                other => return Err(malformed(format!("unknown grouping `{other}`"))),
            };
            let builder = match fields.get("builder") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let builder = object(value, "`builder`")?;
                    only_keys(builder, &["b", "f"], "`builder`")?;
                    Some(Builder {
                        address: string(field(builder, "b")?, "builder.b")?.to_owned(),
                        fee_tenths_bp: uint(builder.get("f"), "builder.f")?,
                    })
                }
            };
            Ok(Action::Order(OrderAction {
                orders,
                grouping,
                builder,
            }))
        }
        "cancel" => {
            keys(&["type", "cancels"])?;
            let cancels = array(field(fields, "cancels")?, "cancels")?
                .iter()
                .map(|cancel| {
                    let cancel = object(cancel, "a cancel")?;
                    only_keys(cancel, &["a", "o"], "a cancel")?;
                    Ok(Cancel {
                        asset: uint32(field(cancel, "a")?, "a")?,
                        order: OrderRef::Oid(uint(cancel.get("o"), "o")?),
                    })
                })
                .collect::<Result<Vec<_>, DecodeError>>()?;
            Ok(Action::Cancel(cancels))
        }
        "cancelByCloid" => {
            keys(&["type", "cancels"])?;
            let cancels = array(field(fields, "cancels")?, "cancels")?
                .iter()
                .map(|cancel| {
                    let cancel = object(cancel, "a cancel")?;
                    only_keys(cancel, &["asset", "cloid"], "a cancel")?;
                    let cloid = string(field(cancel, "cloid")?, "cloid")?;
                    Ok(Cancel {
                        asset: uint32(field(cancel, "asset")?, "asset")?,
                        order: OrderRef::Cloid(
                            Cloid::parse(cloid)
                                .ok_or_else(|| malformed("`cloid` must be 0x and 32 hex digits"))?,
                        ),
                    })
                })
                .collect::<Result<Vec<_>, DecodeError>>()?;
            Ok(Action::CancelByCloid(cancels))
        }
        "modify" => {
            keys(&["type", "oid", "order"])?;
            Ok(Action::Modify(decode_modify_fields(fields)?))
        }
        "batchModify" => {
            keys(&["type", "modifies"])?;
            let modifies = array(field(fields, "modifies")?, "modifies")?
                .iter()
                .map(|modify| {
                    let modify = object(modify, "a modify")?;
                    only_keys(modify, &["oid", "order"], "a modify")?;
                    decode_modify_fields(modify)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Action::BatchModify(modifies))
        }
        "updateLeverage" => {
            keys(&["type", "asset", "isCross", "leverage"])?;
            Ok(Action::UpdateLeverage {
                asset: uint32(field(fields, "asset")?, "asset")?,
                is_cross: boolean(field(fields, "isCross")?, "isCross")?,
                leverage: uint32(field(fields, "leverage")?, "leverage")?,
            })
        }
        "updateIsolatedMargin" => {
            keys(&["type", "asset", "isBuy", "ntli"])?;
            Ok(Action::UpdateIsolatedMargin {
                asset: uint32(field(fields, "asset")?, "asset")?,
                is_buy: boolean(field(fields, "isBuy")?, "isBuy")?,
                ntli: field(fields, "ntli")?
                    .as_i64()
                    .ok_or_else(|| malformed("`ntli` must be an integer"))?,
            })
        }
        "scheduleCancel" => {
            keys(&["type", "time"])?;
            let time = match fields.get("time") {
                None | Some(Value::Null) => None,
                Some(value) => Some(uint(Some(value), "time")?),
            };
            Ok(Action::ScheduleCancel { time })
        }
        other if FUND_AND_PERMISSION_ACTIONS.contains(&other) => {
            Err(DecodeError::FundsOrPermissions(other.to_owned()))
        }
        other => Err(DecodeError::Unsupported(clip(other))),
    }
}

/// An action type as shown back in an error: at most 40 characters.
fn clip(text: &str) -> String {
    text.chars().take(40).collect()
}

fn decode_modify_fields(fields: &Map<String, Value>) -> Result<Modify, DecodeError> {
    let oid = match field(fields, "oid")? {
        Value::String(text) => OrderRef::Cloid(
            Cloid::parse(text).ok_or_else(|| malformed("`oid` must be an integer or a cloid"))?,
        ),
        other => OrderRef::Oid(uint(Some(other), "oid")?),
    };
    Ok(Modify {
        oid,
        order: decode_order(field(fields, "order")?)?,
    })
}

fn decode_order(value: &Value) -> Result<Order, DecodeError> {
    let fields = object(value, "an order")?;
    only_keys(fields, &["a", "b", "p", "s", "r", "t", "c"], "an order")?;
    let kind_fields = object(field(fields, "t")?, "`t`")?;
    let kind = match (kind_fields.get("limit"), kind_fields.get("trigger")) {
        (Some(limit), None) if kind_fields.len() == 1 => {
            let limit = object(limit, "`t.limit`")?;
            only_keys(limit, &["tif"], "`t.limit`")?;
            let tif = match string(field(limit, "tif")?, "tif")? {
                "Alo" => Tif::Alo,
                "Ioc" => Tif::Ioc,
                "Gtc" => Tif::Gtc,
                other => return Err(malformed(format!("unknown tif `{}`", clip(other)))),
            };
            OrderKind::Limit { tif }
        }
        (None, Some(trigger)) if kind_fields.len() == 1 => {
            let trigger = object(trigger, "`t.trigger`")?;
            only_keys(trigger, &["isMarket", "triggerPx", "tpsl"], "`t.trigger`")?;
            let tpsl = match string(field(trigger, "tpsl")?, "tpsl")? {
                "tp" => Tpsl::Tp,
                "sl" => Tpsl::Sl,
                other => return Err(malformed(format!("unknown tpsl `{}`", clip(other)))),
            };
            OrderKind::Trigger {
                is_market: boolean(field(trigger, "isMarket")?, "isMarket")?,
                trigger_px: px(field(trigger, "triggerPx")?, "triggerPx")?,
                tpsl,
            }
        }
        _ => {
            return Err(malformed(
                "`t` must hold exactly one of `limit` or `trigger`",
            ));
        }
    };
    let cloid = match fields.get("c") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            Cloid::parse(string(value, "c")?)
                .ok_or_else(|| malformed("`c` must be 0x and 32 hex digits"))?,
        ),
    };
    Ok(Order {
        asset: uint32(field(fields, "a")?, "a")?,
        is_buy: boolean(field(fields, "b")?, "b")?,
        price: px(field(fields, "p")?, "p")?,
        size: px(field(fields, "s")?, "s")?,
        reduce_only: boolean(field(fields, "r")?, "r")?,
        kind,
        cloid,
    })
}

#[cfg(test)]
mod tests {
    use rust_decimal::dec;
    use serde_json::json;

    use super::*;
    use crate::sign::tests::{gtc, sdk_order};

    fn request(action: Value) -> Value {
        json!({
            "action": action,
            "nonce": 1_791_000_000_000u64,
            "signature": {"r": "0x1", "s": "0x2", "v": 27},
            "vaultAddress": null,
            "expiresAfter": null,
        })
    }

    fn decode(action: Value) -> Result<Action, DecodeError> {
        decode_request_value(&request(action)).map(|request| request.action)
    }

    #[test]
    fn an_sdk_order_decodes_and_encodes_to_the_bytes_the_sdk_hashes() {
        // The Python SDK's order_request_to_order_wire and
        // order_wires_to_order_action: ETH (1), buy 100 at 100, Gtc, cloid 1.
        let sent = json!({
            "type": "order",
            "orders": [{"a": 1, "b": true, "p": "100", "s": "100", "r": false,
                        "t": {"limit": {"tif": "Gtc"}},
                        "c": "0x00000000000000000000000000000001"}],
            "grouping": "na",
        });
        let action = decode(sent).unwrap();
        assert_eq!(
            action.to_wire().to_msgpack().unwrap(),
            sdk_order(gtc(), Some("0x00000000000000000000000000000001"))
                .to_msgpack()
                .unwrap()
        );
    }

    #[test]
    fn key_order_in_the_json_does_not_change_the_encoding() {
        // Hyperliquid hashes its own typed structure, not the JSON's order.
        let shuffled = json!({
            "grouping": "na",
            "orders": [{"t": {"limit": {"tif": "Gtc"}}, "r": false, "s": "100", "p": "100", "b": true, "a": 1}],
            "type": "order",
        });
        assert_eq!(
            decode(shuffled).unwrap().to_wire().to_msgpack().unwrap(),
            sdk_order(gtc(), None).to_msgpack().unwrap()
        );
    }

    #[test]
    fn prices_keep_their_exact_text() {
        let action = decode(json!({
            "type": "order",
            "orders": [{"a": 0, "b": false, "p": "65000.0", "s": "0.00100", "r": true,
                        "t": {"trigger": {"isMarket": true, "triggerPx": "64000", "tpsl": "sl"}}}],
            "grouping": "normalTpsl",
            "builder": {"b": "0x0000000000000000000000000000000000000001", "f": 10},
        }))
        .unwrap();
        let Action::Order(order) = &action else {
            panic!("{action:?}")
        };
        assert_eq!(order.orders[0].price.raw(), "65000.0");
        assert_eq!(order.orders[0].price.value(), dec!(65000));
        assert_eq!(order.orders[0].size.value(), dec!(0.001));
        assert_eq!(order.orders[0].stop_trigger(), Some(dec!(64000)));
        assert_eq!(order.grouping, Grouping::NormalTpsl);
        assert_eq!(
            String::from_utf8(action.to_wire().to_json().unwrap()).unwrap(),
            concat!(
                r#"{"type":"order","orders":[{"a":0,"b":false,"p":"65000.0","s":"0.00100","r":true,"#,
                r#""t":{"trigger":{"isMarket":true,"triggerPx":"64000","tpsl":"sl"}}}],"#,
                r#""grouping":"normalTpsl","builder":{"b":"0x0000000000000000000000000000000000000001","f":10}}"#
            )
        );
    }

    #[test]
    fn every_supported_action_round_trips_in_sdk_order() {
        let cases = [
            json!({"type": "cancel", "cancels": [{"a": 3, "o": 77738308}]}),
            json!({"type": "cancelByCloid", "cancels": [{"asset": 3, "cloid": "0x7a6e6472010300000000000000000001"}]}),
            json!({"type": "modify", "oid": 5, "order": {"a": 1, "b": true, "p": "100", "s": "1", "r": false, "t": {"limit": {"tif": "Alo"}}}}),
            json!({"type": "batchModify", "modifies": [{"oid": "0x7a6e6472010300000000000000000001", "order": {"a": 1, "b": true, "p": "100", "s": "1", "r": false, "t": {"limit": {"tif": "Gtc"}}}}]}),
            json!({"type": "updateLeverage", "asset": 3, "isCross": false, "leverage": 5}),
            json!({"type": "updateIsolatedMargin", "asset": 3, "isBuy": true, "ntli": -1000000}),
            json!({"type": "scheduleCancel", "time": 1791000000000u64}),
            json!({"type": "scheduleCancel"}),
        ];
        for case in cases {
            let action = decode(case.clone()).unwrap();
            // The canonical encoding, read back as JSON, is the SDK's dict.
            assert_eq!(action.to_wire().to_value(), case, "{case}");
        }
    }

    #[test]
    fn fund_movements_and_permissions_are_refused_by_name() {
        for kind in [
            "withdraw3",
            "usdSend",
            "approveAgent",
            "approveBuilderFee",
            "vaultTransfer",
            "tokenDelegate",
            "setReferrer",
        ] {
            assert_eq!(
                decode(json!({"type": kind, "amount": "1"})),
                Err(DecodeError::FundsOrPermissions(kind.to_owned()))
            );
        }
        assert_eq!(
            decode(json!({"type": "twapOrder"})),
            Err(DecodeError::Unsupported("twapOrder".to_owned()))
        );
        let error = decode(json!({"type": "approveAgent"}))
            .unwrap_err()
            .to_string();
        assert!(error.contains("never forwards"), "{error}");
    }

    #[test]
    fn malformed_requests_are_refused() {
        let order = |patch: Value| {
            let mut order = json!({"a": 1, "b": true, "p": "100", "s": "1", "r": false, "t": {"limit": {"tif": "Gtc"}}});
            for (key, value) in patch.as_object().unwrap() {
                order[key] = value.clone();
            }
            json!({"type": "order", "orders": [order], "grouping": "na"})
        };
        let refused = [
            order(json!({"p": 100})),
            order(json!({"p": "-1"})),
            order(json!({"p": "1e3"})),
            order(json!({"s": " 1"})),
            order(json!({"a": 1.0})),
            order(json!({"a": -1})),
            order(json!({"b": "true"})),
            order(json!({"x": 1})),
            order(json!({"c": "0x01"})),
            order(json!({"t": {"limit": {"tif": "Fok"}}})),
            order(json!({"t": {"limit": {"tif": "Gtc"}, "trigger": {}}})),
            json!({"type": "order", "orders": [], "grouping": "na"}),
            json!({"type": "order", "orders": [{"a": 1}], "grouping": "na", "extra": 1}),
            json!({"type": "updateIsolatedMargin", "asset": 1, "isBuy": true, "ntli": 1.5}),
            json!("order"),
        ];
        for action in refused {
            assert!(
                matches!(decode(action.clone()), Err(DecodeError::Malformed(_))),
                "{action}"
            );
        }
        // Too many orders.
        let many: Vec<Value> = (0..=MAX_BATCH)
            .map(|_| json!({"a": 1, "b": true, "p": "100", "s": "1", "r": false, "t": {"limit": {"tif": "Gtc"}}}))
            .collect();
        assert!(decode(json!({"type": "order", "orders": many, "grouping": "na"})).is_err());
    }

    #[test]
    fn the_envelope_is_strict() {
        let action = json!({"type": "scheduleCancel"});
        let mut vault = request(action.clone());
        vault["vaultAddress"] = json!("0x0000000000000000000000000000000000000001");
        assert_eq!(decode_request_value(&vault), Err(DecodeError::Vault));
        let mut extra = request(action.clone());
        extra["isFrontend"] = json!(true);
        assert!(decode_request_value(&extra).is_err());
        let mut bad_v = request(action.clone());
        bad_v["signature"]["v"] = json!(1);
        assert!(decode_request_value(&bad_v).is_err());
        let mut float_nonce = request(action.clone());
        float_nonce["nonce"] = json!(1.5);
        assert!(decode_request_value(&float_nonce).is_err());
        // ccxt and nktkas leave the optional fields out entirely.
        let bare =
            json!({"action": action, "nonce": 5, "signature": {"r": "0x1", "s": "0x2", "v": 28}});
        let decoded = decode_request_value(&bare).unwrap();
        assert_eq!(decoded.nonce, 5);
        assert_eq!(decoded.expires_after, None);
        assert_eq!(decoded.signature.r[31], 1);
        assert!(matches!(
            decode_request(b"not json"),
            Err(DecodeError::NotJson(_))
        ));
    }

    #[test]
    fn px_parses_only_plain_decimals() {
        assert_eq!(Px::parse("0.0147").unwrap().value(), dec!(0.0147));
        for bad in [
            "", ".5", "5.", "-1", "+1", "1e3", "1,5", " 1", "1 ", "0x10", "NaN",
        ] {
            assert!(Px::parse(bad).is_none(), "{bad}");
        }
        assert_eq!(Px::from_decimal(dec!(1670.10)).unwrap().raw(), "1670.1");
        assert_eq!(Px::from_decimal(dec!(100.000)).unwrap().raw(), "100");
        assert!(Px::from_decimal(dec!(0.000000001)).is_none());
    }
}
