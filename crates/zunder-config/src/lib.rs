// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! What every Zunder TOML config refuses before it is deserialised.
//!
//! Money and limits must not pass through floating point on their way in, so
//! a config refuses floats outright, wherever they are: at the top level, in
//! a table, in an array or in a table inside an array. Decimals are written
//! as strings and integers stay allowed. Some configs refuse TOML dates as
//! well, because times are UTC epoch milliseconds or quoted text.
//!
//! The helpers return the path of the first offending value, such as
//! `book[2].risk.risk_per_trade` or `grid.atr_stop_mult[1]`, for the error.
//! No I/O.

use toml::{Table, Value};

/// Path of the first floating-point value in `table`, if any.
pub fn first_float(table: &Table) -> Option<String> {
    first_match(table, &|value| matches!(value, Value::Float(_)))
}

/// Path of the first TOML date or time in `table`, if any.
pub fn first_datetime(table: &Table) -> Option<String> {
    first_match(table, &|value| matches!(value, Value::Datetime(_)))
}

/// Path of the first value in `table` that `matches`, searching tables and
/// arrays at any depth, in key order. Keys are joined with `.`, array
/// positions written as `[index]`.
pub fn first_match(table: &Table, matches: &dyn Fn(&Value) -> bool) -> Option<String> {
    table
        .iter()
        .find_map(|(key, value)| first_in(value, matches).map(|path| format!("{key}{path}")))
}

/// The path below `value` of the first match: empty when `value` itself
/// matches.
fn first_in(value: &Value, matches: &dyn Fn(&Value) -> bool) -> Option<String> {
    if matches(value) {
        return Some(String::new());
    }
    match value {
        Value::Table(table) => first_match(table, matches).map(|path| format!(".{path}")),
        Value::Array(items) => items.iter().enumerate().find_map(|(index, item)| {
            first_in(item, matches).map(|path| format!("[{index}]{path}"))
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> Table {
        toml::from_str(text).expect("test TOML parses")
    }

    #[test]
    fn floats_are_found_at_every_depth_with_their_path() {
        let cases = [
            ("a = 0.5\n", "a"),
            ("[risk]\nrisk_per_trade = 0.02\n", "risk.risk_per_trade"),
            ("[a.b]\nc = 1e3\n", "a.b.c"),
            ("levels = [1, 2.5]\n", "levels[1]"),
            ("levels = [[1, 2], [3, 4.0]]\n", "levels[1][1]"),
            ("rows = [{ x = 1 }, { x = 1.5 }]\n", "rows[1].x"),
            (
                "[[book]]\nname = \"a\"\n[[book]]\nname = \"b\"\n[book.risk]\nstop = 0.1\n",
                "book[1].risk.stop",
            ),
            (
                "[grid]\natr_stop_mult = [\"2\", 3.0]\n",
                "grid.atr_stop_mult[1]",
            ),
            ("x = inf\n", "x"),
            ("x = nan\n", "x"),
        ];
        for (text, path) in cases {
            assert_eq!(first_float(&table(text)).as_deref(), Some(path), "{text}");
        }
    }

    #[test]
    fn strings_integers_and_other_values_pass() {
        let text = "a = \"0.02\"\nb = 3\nc = [1, 2, \"2.5\"]\nd = true\n[e]\nf = [{ g = \"1.5\" }]\nwhen = 2026-10-11\n";
        assert_eq!(first_float(&table(text)), None);
        assert_eq!(first_float(&Table::new()), None);
    }

    #[test]
    fn dates_are_found_at_every_depth_with_their_path() {
        assert_eq!(first_datetime(&table("a = 1\n")), None);
        assert_eq!(
            first_datetime(&table("[x]\nstart = 2026-01-01\n")).as_deref(),
            Some("x.start")
        );
        assert_eq!(
            first_datetime(&table("times = [\"t\", 2026-01-01T00:00:00Z]\n")).as_deref(),
            Some("times[1]")
        );
    }
}
