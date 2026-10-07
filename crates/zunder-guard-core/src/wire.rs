// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Values in the exact shape Hyperliquid hashes and accepts.
//!
//! An action is built once, as a [`Wire`] value, and that one value is both
//! hashed for the signature (MessagePack) and sent in the request body
//! (JSON), so what is signed is what is sent, field for field and in the
//! same order. Hyperliquid deserialises an action into its own typed
//! structure and hashes that structure's MessagePack encoding, so the field
//! order is the venue's, which the official SDKs follow; [`crate::action`]
//! encodes every action in that order whatever order a bot's JSON used.
//!
//! The same encoding as Zunder's own executor's, extended by
//! signed integers (`updateIsolatedMargin`'s `ntli` may be negative). Both
//! are pinned against the official Python SDK's signing vectors.

use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

/// A value inside an action or request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wire {
    Null,
    Bool(bool),
    UInt(u64),
    /// A signed integer. Non-negative values encode exactly like
    /// [`Wire::UInt`], as Python's `msgpack.packb` and Rust's `rmp` do.
    Int(i64),
    Str(String),
    Array(Vec<Wire>),
    /// Keys in the order they are encoded.
    Map(Vec<(&'static str, Wire)>),
}

/// Something too large for MessagePack's 32-bit lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLarge;

impl Wire {
    pub fn str(text: impl Into<String>) -> Self {
        Wire::Str(text.into())
    }

    /// MessagePack, with the smallest encoding for every integer, string,
    /// array and map length, as Python's `msgpack.packb` writes it.
    pub fn to_msgpack(&self) -> Result<Vec<u8>, TooLarge> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<(), TooLarge> {
        match self {
            Wire::Null => out.push(0xc0),
            Wire::Bool(false) => out.push(0xc2),
            Wire::Bool(true) => out.push(0xc3),
            Wire::UInt(value) => encode_uint(*value, out),
            Wire::Int(value) => encode_int(*value, out),
            Wire::Str(text) => encode_str(text, out)?,
            Wire::Array(items) => {
                encode_len(items.len(), 0x90, 0xdc, 0xdd, out)?;
                for item in items {
                    item.encode(out)?;
                }
            }
            Wire::Map(entries) => {
                encode_len(entries.len(), 0x80, 0xde, 0xdf, out)?;
                for (key, value) in entries {
                    encode_str(key, out)?;
                    value.encode(out)?;
                }
            }
        }
        Ok(())
    }

    /// The JSON text of this value.
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// The same value as a `serde_json::Value`, for embedding in a reply.
    pub fn to_value(&self) -> serde_json::Value {
        match self {
            Wire::Null => serde_json::Value::Null,
            Wire::Bool(value) => serde_json::Value::Bool(*value),
            Wire::UInt(value) => serde_json::Value::from(*value),
            Wire::Int(value) => serde_json::Value::from(*value),
            Wire::Str(text) => serde_json::Value::String(text.clone()),
            Wire::Array(items) => {
                serde_json::Value::Array(items.iter().map(Wire::to_value).collect())
            }
            Wire::Map(entries) => serde_json::Value::Object(
                entries
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), value.to_value()))
                    .collect(),
            ),
        }
    }
}

fn encode_uint(value: u64, out: &mut Vec<u8>) {
    if value < 0x80 {
        out.push(value as u8);
    } else if let Ok(byte) = u8::try_from(value) {
        out.push(0xcc);
        out.push(byte);
    } else if let Ok(short) = u16::try_from(value) {
        out.push(0xcd);
        out.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(word) = u32::try_from(value) {
        out.push(0xce);
        out.extend_from_slice(&word.to_be_bytes());
    } else {
        out.push(0xcf);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// A signed integer: non-negative values as unsigned ones, negative values
/// as a negative fixint from -32, then int8, int16, int32 and int64.
fn encode_int(value: i64, out: &mut Vec<u8>) {
    if let Ok(unsigned) = u64::try_from(value) {
        encode_uint(unsigned, out);
    } else if value >= -32 {
        // Negative fixint: the value's two's complement byte, 0xe0..=0xff.
        out.push(value.to_be_bytes()[7]);
    } else if let Ok(byte) = i8::try_from(value) {
        out.push(0xd0);
        out.extend_from_slice(&byte.to_be_bytes());
    } else if let Ok(short) = i16::try_from(value) {
        out.push(0xd1);
        out.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(word) = i32::try_from(value) {
        out.push(0xd2);
        out.extend_from_slice(&word.to_be_bytes());
    } else {
        out.push(0xd3);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_str(text: &str, out: &mut Vec<u8>) -> Result<(), TooLarge> {
    let bytes = text.as_bytes();
    let len = bytes.len();
    if len < 32 {
        out.push(0xa0 | len as u8);
    } else if let Ok(len) = u8::try_from(len) {
        out.push(0xd9);
        out.push(len);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(0xda);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        let len = u32::try_from(len).map_err(|_| TooLarge)?;
        out.push(0xdb);
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// Length header of an array or a map: a fix form below 16, then 16 and 32
/// bits.
fn encode_len(
    len: usize,
    fix: u8,
    marker16: u8,
    marker32: u8,
    out: &mut Vec<u8>,
) -> Result<(), TooLarge> {
    if len < 16 {
        out.push(fix | len as u8);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(marker16);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        let len = u32::try_from(len).map_err(|_| TooLarge)?;
        out.push(marker32);
        out.extend_from_slice(&len.to_be_bytes());
    }
    Ok(())
}

impl Serialize for Wire {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Wire::Null => serializer.serialize_unit(),
            Wire::Bool(value) => serializer.serialize_bool(*value),
            Wire::UInt(value) => serializer.serialize_u64(*value),
            Wire::Int(value) => serializer.serialize_i64(*value),
            Wire::Str(text) => serializer.serialize_str(text),
            Wire::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Wire::Map(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

/// A 256-bit big-endian number as `0x` and hex without leading zeros, the
/// way the official SDKs send `r` and `s`.
pub fn minimal_hex(bytes: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(66);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_use_the_smallest_encoding() {
        let cases: [(u64, &[u8]); 7] = [
            (0, &[0x00]),
            (127, &[0x7f]),
            (128, &[0xcc, 0x80]),
            (255, &[0xcc, 0xff]),
            (256, &[0xcd, 0x01, 0x00]),
            (65_536, &[0xce, 0x00, 0x01, 0x00, 0x00]),
            (
                100_000_000_000,
                &[0xcf, 0x00, 0x00, 0x00, 0x17, 0x48, 0x76, 0xe8, 0x00],
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(Wire::UInt(value).to_msgpack().unwrap(), expected, "{value}");
        }
    }

    #[test]
    fn signed_integers_follow_msgpack_packb() {
        // msgpack.packb(n) for each n, Python msgpack 1.x.
        let cases: [(i64, &[u8]); 10] = [
            (5, &[0x05]),
            (1_000_000, &[0xce, 0x00, 0x0f, 0x42, 0x40]),
            (-1, &[0xff]),
            (-32, &[0xe0]),
            (-33, &[0xd0, 0xdf]),
            (-128, &[0xd0, 0x80]),
            (-129, &[0xd1, 0xff, 0x7f]),
            (-32_769, &[0xd2, 0xff, 0xff, 0x7f, 0xff]),
            (-1_000_000, &[0xd2, 0xff, 0xf0, 0xbd, 0xc0]),
            (
                -2_147_483_649,
                &[0xd3, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff],
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(Wire::Int(value).to_msgpack().unwrap(), expected, "{value}");
        }
        assert_eq!(Wire::Int(-5).to_value(), serde_json::json!(-5));
    }

    #[test]
    fn strings_switch_to_str8_at_32_bytes() {
        let short = Wire::str("a".repeat(31)).to_msgpack().unwrap();
        assert_eq!(short[0], 0xa0 | 31);
        let long = Wire::str("a".repeat(32)).to_msgpack().unwrap();
        assert_eq!(&long[..2], &[0xd9, 32]);
    }

    #[test]
    fn maps_keep_their_key_order_in_both_encodings() {
        let map = Wire::Map(vec![
            ("type", Wire::str("dummy")),
            ("num", Wire::UInt(1)),
            ("on", Wire::Bool(true)),
            ("none", Wire::Null),
        ]);
        let expected: Vec<u8> = [
            &[0x84][..],
            &[0xa4],
            b"type",
            &[0xa5],
            b"dummy",
            &[0xa3],
            b"num",
            &[0x01],
            &[0xa2],
            b"on",
            &[0xc3],
            &[0xa4],
            b"none",
            &[0xc0],
        ]
        .concat();
        assert_eq!(map.to_msgpack().unwrap(), expected);
        assert_eq!(
            String::from_utf8(map.to_json().unwrap()).unwrap(),
            r#"{"type":"dummy","num":1,"on":true,"none":null}"#
        );
    }

    #[test]
    fn signature_numbers_drop_leading_zeros() {
        let mut bytes = [0u8; 32];
        bytes[31] = 0x0f;
        assert_eq!(minimal_hex(&bytes), "0xf");
        assert_eq!(minimal_hex(&[0u8; 32]), "0x0");
    }
}
