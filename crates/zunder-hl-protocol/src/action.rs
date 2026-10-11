// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Hyperliquid's L1 actions as types, encoded once in the venue's field
//! order: what Zunder's executor sends, what Zunder Guard decodes, judges
//! and re-signs, and what Guard's MCP server signs for Guard.
//!
//! Hyperliquid deserialises an action into its own typed structure and
//! hashes that structure's MessagePack, so the field order of
//! [`Action::to_wire`] decides the signed bytes. It follows the official
//! Python SDK (`order_request_to_order_wire`, `order_wires_to_order_action`,
//! `exchange.py`) field for field; the SDK's signing vectors
//! (`tests/sdk_vectors.rs`) and every caller's golden bytes pin it.
//!
//! Prices and sizes are [`Px`]: the exact text that is signed and its exact
//! value. A [`Px`] written from a decimal ([`Px::from_decimal`]) has the
//! Python SDK's `float_to_wire` form; one read from a bot's request
//! ([`Px::parse`]) keeps the bot's text, trailing zeros included, because
//! that text is what the bot signed. A [`Cloid`] is `0x` and 32 hex
//! digits. Neither can be built unchecked.
//!
//! Only the order-path actions are modelled: `order`, `cancel`,
//! `cancelByCloid`, `modify`, `batchModify`, `updateLeverage`,
//! `updateIsolatedMargin` and `scheduleCancel`. Nothing that moves funds or
//! grants permissions has a type here.

use std::{fmt, str::FromStr};

use rust_decimal::Decimal;

use crate::{Signature, Wire, wire::minimal_hex};

/// A price or size: the exact text sent and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Px {
    raw: String,
    value: Decimal,
}

impl Px {
    /// Plain decimal digits with an optional fraction, as Hyperliquid's
    /// prices and sizes are written: no sign, no exponent, no spaces, at
    /// most 40 characters. The text is kept as it is.
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

    /// A value written from a decimal: without trailing zeros, as the
    /// Python SDK's `float_to_wire` normalises. `None` for a negative value
    /// or one with more than 8 decimals, which the SDK refuses too.
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

/// A client order id: `0x` and 32 hex digits, in the case it was written.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cloid(String);

impl Cloid {
    /// `0x` and exactly 32 hex digits, either case; the text is kept.
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.strip_prefix("0x")?;
        (digits.len() == 32 && digits.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| Self(text.to_owned()))
    }

    /// The id of 16 bytes: `0x` and their 32 lowercase hex digits.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        let mut text = String::with_capacity(34);
        text.push_str("0x");
        for byte in bytes {
            text.push_str(&format!("{byte:02x}"));
        }
        Self(text)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Lowercase, for comparing with what the venue reports.
    pub fn normalized(&self) -> String {
        self.0.to_ascii_lowercase()
    }
}

/// A limit order's time in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tif {
    /// Add liquidity only (post-only).
    Alo,
    Ioc,
    Gtc,
}

impl Tif {
    pub fn name(self) -> &'static str {
        match self {
            Tif::Alo => "Alo",
            Tif::Ioc => "Ioc",
            Tif::Gtc => "Gtc",
        }
    }
}

/// A trigger order's kind: take profit or stop loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tpsl {
    Tp,
    Sl,
}

impl Tpsl {
    pub fn name(self) -> &'static str {
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
    /// `{a, b, p, s, r, t, c?}`, `c` only with a cloid.
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

    /// The trigger of a stop loss (a trigger order with `tpsl: "sl"`).
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

    pub fn is_trigger(&self) -> bool {
        matches!(self.kind, OrderKind::Trigger { .. })
    }
}

/// How the orders of one `order` action belong together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grouping {
    /// Independent orders.
    Na,
    /// An entry followed by its take profit and stop loss.
    NormalTpsl,
    /// Take profit and stop loss for the whole position.
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

/// An L1 action on the order path.
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
    /// every price and size: what the signature covers and what is sent.
    ///
    /// The optional fields are left out when absent, never written as
    /// null or false: `builder` of an order, `time` of a `scheduleCancel`,
    /// and the `f` flag of a `cancelByCloid` (the venue rejects actions
    /// hashed with `f: false`).
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

/// A request's `{"r", "s", "v"}`, `r` and `s` without leading zeros as the
/// SDKs write them.
pub fn signature_wire(signature: &Signature) -> Wire {
    Wire::Map(vec![
        ("r", Wire::str(minimal_hex(&signature.r))),
        ("s", Wire::str(minimal_hex(&signature.s))),
        ("v", Wire::UInt(u64::from(signature.v))),
    ])
}

/// The fields of a request to `/exchange`, in the Python SDK's order:
/// action, nonce, signature, vaultAddress (always null: no vault or
/// sub-account), expiresAfter (null without an expiry). A caller may add
/// fields of its own after these.
pub fn exchange_request_fields(
    action: Wire,
    nonce: u64,
    signature: &Signature,
    expires_after: Option<u64>,
) -> Vec<(&'static str, Wire)> {
    vec![
        ("action", action),
        ("nonce", Wire::UInt(nonce)),
        ("signature", signature_wire(signature)),
        ("vaultAddress", Wire::Null),
        ("expiresAfter", expires_after.map_or(Wire::Null, Wire::UInt)),
    ]
}

/// The body of a request to `/exchange` ([`exchange_request_fields`]).
pub fn exchange_request(
    action: Wire,
    nonce: u64,
    signature: &Signature,
    expires_after: Option<u64>,
) -> Wire {
    Wire::Map(exchange_request_fields(
        action,
        nonce,
        signature,
        expires_after,
    ))
}

#[cfg(test)]
mod tests {
    use rust_decimal::dec;

    use super::*;

    fn px(text: &str) -> Px {
        Px::parse(text).unwrap()
    }

    fn json(wire: &Wire) -> String {
        String::from_utf8(wire.to_json().unwrap()).unwrap()
    }

    #[test]
    fn px_parses_only_plain_decimals_and_keeps_the_text() {
        assert_eq!(px("0.0147").value(), dec!(0.0147));
        assert_eq!(px("65000.0").raw(), "65000.0");
        assert_eq!(px("65000.0").value(), dec!(65000));
        for bad in [
            "", ".5", "5.", "-1", "+1", "1e3", "1,5", " 1", "1 ", "0x10", "NaN",
        ] {
            assert!(Px::parse(bad).is_none(), "{bad}");
        }
        assert!(Px::parse(&"1".repeat(41)).is_none());
        assert_eq!(Px::from_decimal(dec!(1670.10)).unwrap().raw(), "1670.1");
        assert_eq!(Px::from_decimal(dec!(100.000)).unwrap().raw(), "100");
        assert!(Px::from_decimal(dec!(0.000000001)).is_none());
        assert!(Px::from_decimal(dec!(-1)).is_none());
    }

    #[test]
    fn cloids_are_0x_and_32_hex_digits() {
        let upper = "0xABCDEF0123456789abcdef0123456789";
        assert_eq!(Cloid::parse(upper).unwrap().as_str(), upper);
        assert_eq!(
            Cloid::parse(upper).unwrap().normalized(),
            upper.to_ascii_lowercase()
        );
        for bad in [
            "0x01",
            "00000000000000000000000000000001",
            "0x0000000000000000000000000000000g",
            "0x000000000000000000000000000000001",
        ] {
            assert!(Cloid::parse(bad).is_none(), "{bad}");
        }
        let mut bytes = [0u8; 16];
        bytes[0] = 0x7a;
        bytes[1] = 0x67;
        bytes[15] = 0xab;
        let built = Cloid::from_bytes(bytes);
        assert_eq!(built.as_str(), format!("0x7a67{}ab", "0".repeat(26)));
        assert_eq!(Cloid::parse(built.as_str()), Some(built));
    }

    #[test]
    fn an_order_is_written_in_the_sdk_field_order() {
        // order_request_to_order_wire: a, b, p, s, r, t, then c.
        let order = Order {
            asset: 1,
            is_buy: true,
            price: px("100"),
            size: px("100"),
            reduce_only: false,
            kind: OrderKind::Trigger {
                is_market: true,
                trigger_px: px("103"),
                tpsl: Tpsl::Sl,
            },
            cloid: Cloid::parse("0x00000000000000000000000000000001"),
        };
        let action = Action::Order(OrderAction {
            orders: vec![order.clone()],
            grouping: Grouping::Na,
            builder: None,
        });
        assert_eq!(
            json(&action.to_wire()),
            concat!(
                r#"{"type":"order","orders":[{"a":1,"b":true,"p":"100","s":"100","r":false,"#,
                r#""t":{"trigger":{"isMarket":true,"triggerPx":"103","tpsl":"sl"}},"#,
                r#""c":"0x00000000000000000000000000000001"}],"grouping":"na"}"#
            )
        );
        assert_eq!(order.stop_trigger(), Some(dec!(103)));
        assert!(order.is_trigger());
        let builder = Action::Order(OrderAction {
            orders: vec![Order {
                kind: OrderKind::Limit { tif: Tif::Alo },
                cloid: None,
                ..order
            }],
            grouping: Grouping::PositionTpsl,
            builder: Some(Builder {
                address: "0x0000000000000000000000000000000000000001".into(),
                fee_tenths_bp: 10,
            }),
        });
        assert_eq!(
            json(&builder.to_wire()),
            concat!(
                r#"{"type":"order","orders":[{"a":1,"b":true,"p":"100","s":"100","r":false,"#,
                r#""t":{"limit":{"tif":"Alo"}}}],"grouping":"positionTpsl","#,
                r#""builder":{"b":"0x0000000000000000000000000000000000000001","f":10}}"#
            )
        );
    }

    #[test]
    fn every_other_action_is_written_in_the_sdk_field_order() {
        let cloid = Cloid::parse("0x7a6e6472010300000000000000000001").unwrap();
        let limit = Order {
            asset: 1,
            is_buy: true,
            price: px("100"),
            size: px("1"),
            reduce_only: false,
            kind: OrderKind::Limit { tif: Tif::Gtc },
            cloid: None,
        };
        let cases = [
            (
                Action::Cancel(vec![Cancel {
                    asset: 3,
                    order: OrderRef::Oid(77_738_308),
                }]),
                r#"{"type":"cancel","cancels":[{"a":3,"o":77738308}]}"#,
            ),
            (
                Action::CancelByCloid(vec![Cancel {
                    asset: 3,
                    order: OrderRef::Cloid(cloid.clone()),
                }]),
                r#"{"type":"cancelByCloid","cancels":[{"asset":3,"cloid":"0x7a6e6472010300000000000000000001"}]}"#,
            ),
            (
                Action::Modify(Modify {
                    oid: OrderRef::Oid(5),
                    order: limit.clone(),
                }),
                r#"{"type":"modify","oid":5,"order":{"a":1,"b":true,"p":"100","s":"1","r":false,"t":{"limit":{"tif":"Gtc"}}}}"#,
            ),
            (
                Action::BatchModify(vec![Modify {
                    oid: OrderRef::Cloid(cloid),
                    order: limit,
                }]),
                r#"{"type":"batchModify","modifies":[{"oid":"0x7a6e6472010300000000000000000001","order":{"a":1,"b":true,"p":"100","s":"1","r":false,"t":{"limit":{"tif":"Gtc"}}}}]}"#,
            ),
            (
                Action::UpdateLeverage {
                    asset: 3,
                    is_cross: false,
                    leverage: 5,
                },
                r#"{"type":"updateLeverage","asset":3,"isCross":false,"leverage":5}"#,
            ),
            (
                Action::UpdateIsolatedMargin {
                    asset: 3,
                    is_buy: true,
                    ntli: -1_000_000,
                },
                r#"{"type":"updateIsolatedMargin","asset":3,"isBuy":true,"ntli":-1000000}"#,
            ),
            (
                Action::ScheduleCancel {
                    time: Some(1_791_000_000_000),
                },
                r#"{"type":"scheduleCancel","time":1791000000000}"#,
            ),
            (
                Action::ScheduleCancel { time: None },
                r#"{"type":"scheduleCancel"}"#,
            ),
        ];
        for (action, expected) in cases {
            assert_eq!(json(&action.to_wire()), expected);
        }
    }

    #[test]
    fn update_leverage_is_the_msgpack_packb_bytes() {
        // msgpack.packb({"type": "updateLeverage", "asset": 3,
        // "isCross": False, "leverage": 5}).
        let action = Action::UpdateLeverage {
            asset: 3,
            is_cross: false,
            leverage: 5,
        };
        let expected: Vec<u8> = [
            &[0x84][..],
            &[0xa4],
            b"type",
            &[0xae],
            b"updateLeverage",
            &[0xa5],
            b"asset",
            &[0x03],
            &[0xa7],
            b"isCross",
            &[0xc2],
            &[0xa8],
            b"leverage",
            &[0x05],
        ]
        .concat();
        assert_eq!(action.to_wire().to_msgpack().unwrap(), expected);
    }

    #[test]
    fn a_request_body_is_in_the_sdk_field_order() {
        let mut r = [0u8; 32];
        r[31] = 1;
        let mut s = [0u8; 32];
        s[30] = 2;
        let signature = Signature { r, s, v: 27 };
        let action = Action::ScheduleCancel { time: None }.to_wire();
        assert_eq!(
            json(&exchange_request(action.clone(), 5, &signature, None)),
            r#"{"action":{"type":"scheduleCancel"},"nonce":5,"signature":{"r":"0x1","s":"0x200","v":27},"vaultAddress":null,"expiresAfter":null}"#
        );
        assert_eq!(
            json(&exchange_request(action, 5, &signature, Some(9))),
            r#"{"action":{"type":"scheduleCancel"},"nonce":5,"signature":{"r":"0x1","s":"0x200","v":27},"vaultAddress":null,"expiresAfter":9}"#
        );
    }
}
