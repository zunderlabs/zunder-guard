// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
// Tests for zr1.ts against the vectors and schema shared with the Rust crate.
// Run: node --test deploy/guard/rules/zr1.test.ts   (Node 22.18+ strips the types)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  allowsMarket,
  decode,
  defaults,
  encode,
  FIELDS,
  MAX_ENCODED_LEN,
  MAX_MARKETS,
  NUMBER_BOUNDS,
  PREFIX,
  RulesError,
  validate,
} from "./zr1.ts";

const here = new URL(".", import.meta.url);
const vectors = JSON.parse(readFileSync(new URL("vectors.json", here), "utf8"));
const schema = JSON.parse(readFileSync(new URL("schema-v1.json", here), "utf8"));

const b64 = (json: string): string => PREFIX + Buffer.from(json, "utf8").toString("base64url");

function codeOf(fn: () => unknown): { code: string; field: string | undefined } {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof RulesError, `not a RulesError: ${e}`);
    return { code: e.code, field: e.field };
  }
  assert.fail("expected a RulesError");
}

test("valid vectors decode and re-encode to the canonical string", () => {
  assert.ok(vectors.valid.length >= 5);
  for (const c of vectors.valid) {
    const rules = decode(b64(c.json));
    assert.equal(encode(rules), c.canonical, c.name);
    assert.deepEqual(decode(c.canonical), rules, c.name);
  }
});

test("invalid vectors are refused with the same code and field as in Rust", () => {
  assert.ok(vectors.invalid.length >= 20);
  for (const c of vectors.invalid) {
    const input = c.input !== undefined ? c.input : b64(c.json);
    const got = codeOf(() => decode(input));
    assert.equal(got.code, c.code, c.name);
    if (c.field !== undefined) assert.equal(got.field, c.field, c.name);
  }
});

test("defaults are the reconciled schema v1 and validate", () => {
  // 5x, 2% at the stop, attach a stop 2% away, liquidation 10% away, positions up to 200%,
  // 6% open risk, 6% daily loss, 25% drawdown, every market.
  const d = defaults();
  assert.deepEqual(d, {
    maxLeverage: 5, maxLossAtStopPct: 2, stopPolicy: "attach", defaultStopDistancePct: 2,
    minLiqDistancePct: 10, maxPositionPct: 200, maxOpenRiskPct: 6, dailyLossStopPct: 6,
    drawdownHaltPct: 25, markets: ["*"],
  });
  // Every market of the main dex; a HIP-3 dex's only when named.
  assert.ok(allowsMarket(d, "BTC"));
  assert.ok(!allowsMarket(d, "xyz:XYZ100"));
  assert.ok(!allowsMarket({ ...d, markets: ["BTC"] }, "ETH"));
  validate(d);
  for (const b of NUMBER_BOUNDS) assert.equal(d[b.field], b.default, b.field);
});

test("HIP-3 dexes are allowed by name, as in the Rust crate", () => {
  const both = { ...defaults(), markets: ["*", "xyz:*"] };
  validate(both);
  assert.ok(allowsMarket(both, "BTC"));
  assert.ok(allowsMarket(both, "xyz:GOLD"));
  assert.ok(!allowsMarket(both, "flx:GOLD"));
  const gold = { ...defaults(), markets: ["xyz:GOLD", "ETH"] };
  assert.ok(allowsMarket(gold, "xyz:GOLD") && allowsMarket(gold, "ETH"));
  assert.ok(!allowsMarket(gold, "xyz:TSLA") && !allowsMarket(gold, "BTC"));
  for (const markets of [["*", "xyz:*", "BTC"], ["xyz:*", "xyz:GOLD"], ["*:*"], [":*"], ["xyz:**"], ["x.y:*"], ["*", "*"]]) {
    assert.throws(() => validate({ ...defaults(), markets }), (e: unknown) => (e as { code: string }).code === "markets", markets.join(","));
  }
});

test("schema-v1.json matches the bounds in code", () => {
  const props = schema.properties;
  assert.deepEqual(Object.keys(props).sort(), ["v", ...FIELDS].sort());
  for (const b of NUMBER_BOUNDS) {
    const p = props[b.field];
    assert.equal(p.default, b.default, b.field);
    assert.equal(p.maximum, b.max, b.field);
    assert.equal(b.minInclusive ? p.minimum : p.exclusiveMinimum, b.min, b.field);
    assert.equal(p.multipleOf, 0.0001, b.field);
  }
  const d = defaults();
  assert.equal(props.requireStop, undefined);
  assert.equal(props.stopPolicy.default, d.stopPolicy);
  assert.deepEqual(props.markets.default, d.markets);
  assert.equal(props.markets.maxItems, MAX_MARKETS);
});

test("one step beyond every bound is refused, as is a fifth decimal", () => {
  for (const b of NUMBER_BOUNDS) {
    const over = { ...defaults(), [b.field]: b.max + 0.0001 };
    assert.equal(codeOf(() => validate(over)).code, "out_of_range", b.field);
    const under = { ...defaults(), [b.field]: b.minInclusive ? b.min - 0.0001 : b.min };
    assert.equal(codeOf(() => validate(under)).code, "out_of_range", b.field);
    const fine = { ...defaults(), [b.field]: b.default + 0.00001 };
    assert.equal(codeOf(() => validate(fine)).code, "precision", b.field);
  }
});

test("the encoder refuses invalid rules and over-long strings are refused first", () => {
  assert.equal(codeOf(() => encode({ ...defaults(), markets: ["*", "BTC"] })).code, "markets");
  assert.equal(codeOf(() => decode(PREFIX + "A".repeat(MAX_ENCODED_LEN))).code, "too_long");
});
