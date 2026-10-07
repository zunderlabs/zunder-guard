// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
//! Guard's reason codes: the list in `zunder_guard_core::codes` is exactly
//! the set of codes the sources can answer with, and the documentation shows
//! that list as generated from it.
//!
//! The sources are scanned for the places a code is written: `veto("…"`,
//! `veto_reply("…"`, `code: "…"`, `.code = "…"`, `Verdict::…, "…"` and the
//! match arms of `Refusal`, `AuthError` and `Veto` that name codes. A code
//! added there without a line in the list (or the other way round) fails
//! here.
//!
//! The documentation's generated blocks are rewritten from the list with
//! `ZUNDER_GUARD_WRITE_DOCS=1 cargo test -p zunder-guard --test codes`.

#![allow(clippy::unwrap_used)]

use std::{collections::BTreeSet, path::PathBuf};

use zunder_guard_core::codes::{CODES, markdown_table};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// The source without its inline test modules (`#[cfg(test)] mod x { … }`
/// to the end of the file, where they always are).
fn without_tests(text: &str) -> &str {
    let mut cut = text.len();
    for (index, _) in text.match_indices("#[cfg(test)]") {
        let rest = text[index + "#[cfg(test)]".len()..].trim_start();
        let rest = rest.strip_prefix("pub(crate) ").unwrap_or(rest);
        if let Some(after) = rest.strip_prefix("mod ") {
            let name_end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            if after[name_end..].trim_start().starts_with('{') {
                cut = cut.min(index);
            }
        }
    }
    &text[..cut]
}

/// The string literal right after `at` (skipping whitespace), if it looks
/// like a code.
fn literal_after(text: &str, at: usize) -> Option<&str> {
    let rest = text[at..].trim_start().strip_prefix('"')?;
    let end = rest.find('"')?;
    let code = &rest[..end];
    (!code.is_empty() && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')).then_some(code)
}

fn codes_in(text: &str) -> BTreeSet<String> {
    let text = without_tests(text);
    let mut out = BTreeSet::new();
    for pattern in ["veto(", "veto_reply(", "code: ", ".code = "] {
        for (index, _) in text.match_indices(pattern) {
            if let Some(code) = literal_after(text, index + pattern.len()) {
                out.insert(code.to_owned());
            }
        }
    }
    // `(Verdict::Allow, "allowed", …)` in `Decision::pass`.
    for (index, _) in text.match_indices("Verdict::") {
        let rest = &text[index..];
        if let Some(comma) = rest.find(',')
            && rest[..comma]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'_')
            && let Some(code) = literal_after(rest, comma + 1)
        {
            out.insert(code.to_owned());
        }
    }
    // Match arms naming codes: `Refusal::… => "…"`, `AuthError::… => "…"`,
    // `Veto::… => "…"`.
    for line in text.lines() {
        let line = line.trim();
        let arm = ["Refusal::", "AuthError::", "Veto::"]
            .iter()
            .any(|prefix| line.starts_with(prefix));
        if arm
            && let Some(at) = line.find("=>")
            && let Some(code) = literal_after(line, at + 2)
        {
            out.insert(code.to_owned());
        }
    }
    out
}

/// Every `.rs` file under `dir`, recursively.
fn sources(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn source_codes() -> BTreeSet<String> {
    let repo = repo();
    let mut files = Vec::new();
    for dir in ["crates/zunder-guard-core/src", "crates/zunder-guard/src"] {
        sources(&repo.join(dir), &mut files);
    }
    let mut out = BTreeSet::new();
    for path in files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let in_tests_dir = path.components().any(|part| part.as_os_str() == "tests");
        // The list itself, and test-only files (`judge/tests.rs`).
        if in_tests_dir
            || name == "tests.rs"
            || ["codes.rs", "bench.rs", "properties.rs", "testdir.rs"].contains(&name.as_str())
        {
            continue;
        }
        out.extend(codes_in(&std::fs::read_to_string(&path).unwrap()));
    }
    out
}

#[test]
fn the_agent_kit_knows_every_code() {
    // The MCP kit explains Guard's codes to agents in its own words; a
    // code it does not know reaches them as "other".
    let unknown: Vec<&str> = CODES
        .iter()
        .map(|(code, _, _)| *code)
        .filter(|code| zunder_guard_mcp::contract::known_code(code) == "other")
        .collect();
    assert!(
        unknown.is_empty(),
        "codes the agent kit does not know: {unknown:?}"
    );
}

#[test]
fn the_list_is_exactly_the_codes_the_sources_answer_with() {
    let listed: BTreeSet<String> = CODES
        .iter()
        .map(|(code, _, _)| (*code).to_owned())
        .collect();
    let used = source_codes();
    let unlisted: Vec<&String> = used.difference(&listed).collect();
    let unused: Vec<&String> = listed.difference(&used).collect();
    assert!(
        unlisted.is_empty() && unused.is_empty(),
        "codes in the sources but not in zunder_guard_core::codes::CODES: {unlisted:?}; listed but never answered: {unused:?}"
    );
}

#[test]
fn the_scanner_finds_codes_where_they_are_written() {
    let sample = r#"
        fn a() { veto("one", "x"); Decision::veto(
            "two", "y"); veto_reply("three", &t); Decision { code: "four" };
            decision.code = "five"; (Verdict::Allow, "six", t);
            Refusal::Decode(_) => "seven",
            AuthError::BadSignature => "eight",
            Veto::Stopped => "nine",
            other => "not_a_code", veto(code, text) }
        #[cfg(test)]
        mod tests { fn t() { veto("in_a_test", "z"); } }
    "#;
    let found: Vec<String> = codes_in(sample).into_iter().collect();
    assert_eq!(
        found,
        [
            "eight", "five", "four", "nine", "one", "seven", "six", "three", "two"
        ]
    );
}

/// Replace the block between `start` and `end` in `path` with `body`, or
/// check that it holds it.
fn generated_block(path: &str, start: &str, end: &str, body: &str) {
    let path = repo().join(path);
    let text = std::fs::read_to_string(&path).unwrap();
    let from = text
        .find(start)
        .unwrap_or_else(|| panic!("{start} in {}", path.display()));
    let to = text
        .find(end)
        .unwrap_or_else(|| panic!("{end} in {}", path.display()));
    let head = &text[..from + start.len()];
    let tail = &text[to..];
    let wanted = format!("{head}\n\n{body}\n{tail}");
    if std::env::var_os("ZUNDER_GUARD_WRITE_DOCS").is_some() {
        std::fs::write(&path, wanted).unwrap();
        return;
    }
    assert!(
        text == wanted,
        "{} is out of date with zunder_guard_core::codes; run ZUNDER_GUARD_WRITE_DOCS=1 cargo test -p zunder-guard --test codes",
        path.display()
    );
}

#[test]
fn the_documentation_lists_exactly_these_codes() {
    let table = markdown_table();
    generated_block(
        "docs/guard.md",
        "<!-- GENERATED:codes:start (crates/zunder-guard/tests/codes.rs) -->",
        "<!-- GENERATED:codes:end -->",
        &table,
    );
    generated_block(
        "web/docs-content/docs/reference/veto-codes.mdx",
        "{/* GENERATED:guard-codes:start (crates/zunder-guard/tests/codes.rs); do not edit by hand */}",
        "{/* GENERATED:guard-codes:end */}",
        &table,
    );
}
