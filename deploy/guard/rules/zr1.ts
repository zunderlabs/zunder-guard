// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
// Guard rules schema v1: the zr1_ string the website, the docs and the CLI share.
//
// The TypeScript twin of deploy/guard/rules/src/lib.rs. Both pass vectors.json; schema-v1.json
// documents the same defaults and bounds. Values ending in Pct are percent (2 means 2%).
// Defaults are the reconciled schema v1; bounds are provisional until the Guard core's policy
// configuration lands, and never beyond zunder-risk's aggressive frame. No dependencies; runs in browsers and in Node 22.18+ (type stripping: erasable syntax only).
// Specification, including the order of checks: deploy/guard/README.md, "Rules schema v1".

export const PREFIX = "zr1_";
export const MAX_ENCODED_LEN = 4096;
export const MAX_DECIMALS = 4;
export const MAX_MARKETS = 32;
export const MAX_MARKET_LEN = 32;
/** The market entry that allows every market of Hyperliquid's main dex (never a HIP-3 one). */
export const ALL_MARKETS = "*";

export type StopPolicy = "attach" | "refuse";

export interface Rules {
  maxLeverage: number;
  maxLossAtStopPct: number;
  stopPolicy: StopPolicy;
  /** Optional in a rules string; always written by the encoder. */
  defaultStopDistancePct: number;
  minLiqDistancePct: number;
  maxPositionPct: number;
  maxOpenRiskPct: number;
  dailyLossStopPct: number;
  drawdownHaltPct: number;
  markets: string[];
}

export type NumberField =
  | "maxLeverage"
  | "maxLossAtStopPct"
  | "defaultStopDistancePct"
  | "minLiqDistancePct"
  | "maxPositionPct"
  | "maxOpenRiskPct"
  | "dailyLossStopPct"
  | "drawdownHaltPct";

export interface NumberBounds {
  field: NumberField;
  default: number;
  min: number;
  minInclusive: boolean;
  max: number;
}

/** The fields in canonical order. */
export const FIELDS: readonly (keyof Rules)[] = [
  "maxLeverage",
  "maxLossAtStopPct",
  "stopPolicy",
  "defaultStopDistancePct",
  "minLiqDistancePct",
  "maxPositionPct",
  "maxOpenRiskPct",
  "dailyLossStopPct",
  "drawdownHaltPct",
  "markets",
];

/** Numeric fields in canonical order. Kept equal to the Rust crate by vectors.json and schema-v1.json. */
export const NUMBER_BOUNDS: readonly NumberBounds[] = [
  { field: "maxLeverage", default: 5, min: 0, minInclusive: false, max: 10 },
  { field: "maxLossAtStopPct", default: 2, min: 0, minInclusive: false, max: 5 },
  { field: "defaultStopDistancePct", default: 2, min: 0, minInclusive: false, max: 50 },
  { field: "minLiqDistancePct", default: 10, min: 1, minInclusive: true, max: 50 },
  { field: "maxPositionPct", default: 200, min: 0, minInclusive: false, max: 1000 },
  { field: "maxOpenRiskPct", default: 6, min: 0, minInclusive: false, max: 20 },
  { field: "dailyLossStopPct", default: 6, min: 0, minInclusive: false, max: 15 },
  { field: "drawdownHaltPct", default: 25, min: 0, minInclusive: false, max: 50 },
];

export function defaults(): Rules {
  return {
    maxLeverage: 5,
    maxLossAtStopPct: 2,
    stopPolicy: "attach",
    defaultStopDistancePct: 2,
    minLiqDistancePct: 10,
    maxPositionPct: 200,
    maxOpenRiskPct: 6,
    dailyLossStopPct: 6,
    drawdownHaltPct: 25,
    markets: [ALL_MARKETS],
  };
}

export type ErrorCode =
  | "too_long"
  | "prefix"
  | "base64"
  | "json"
  | "not_object"
  | "unknown_field"
  | "version"
  | "type"
  | "out_of_range"
  | "precision"
  | "stop_policy"
  | "markets"
  | "open_risk_below_trade_risk"
  | "position_above_leverage"
  | "liq_not_beyond_stop";

export class RulesError extends Error {
  readonly code: ErrorCode;
  readonly field: string | undefined;
  constructor(code: ErrorCode, message: string, field?: string) {
    super(message);
    this.name = "RulesError";
    this.code = code;
    this.field = field;
  }
}

const MARKET = /^[A-Za-z0-9@][A-Za-z0-9:/@._-]*$/;
/** A HIP-3 dex's name, as "dex:*" uses it. */
const DEX = /^[A-Za-z0-9]+$/;
const B64URL = /^[A-Za-z0-9_-]*$/;

// Exact for numbers with at most four decimal places (checked before this is used).
const units = (x: number): number => Math.round(x * 10_000);

function checkNumber(b: NumberBounds, x: number): void {
  const below = b.minInclusive ? x < b.min : x <= b.min;
  if (!Number.isFinite(x) || below || x > b.max) {
    const lower = b.minInclusive ? "at least" : "above";
    throw new RulesError("out_of_range", `${b.field} must be ${lower} ${b.min} and at most ${b.max}, got ${x}`, b.field);
  }
  if (Math.round(x * 10_000) / 10_000 !== x) {
    throw new RulesError("precision", `${b.field} may have at most ${MAX_DECIMALS} decimal places`, b.field);
  }
}

function checkMarkets(markets: string[]): void {
  const fail = (why: string) => new RulesError("markets", `markets: ${why}`, "markets");
  if (markets.length === 0) throw fail('at least one market is required ("*" for all)');
  if (markets.length > MAX_MARKETS) throw fail("at most 32 markets");
  // "*" is every market of the main dex: beside it only HIP-3 entries ("dex:…") may stand.
  if (markets.includes(ALL_MARKETS) && markets.some((m) => m !== ALL_MARKETS && !m.includes(":"))) {
    throw fail('"*" (every main-dex market) stands alone among the main dex\'s markets');
  }
  markets.forEach((m, i) => {
    if (m === ALL_MARKETS) {
      if (markets.slice(0, i).includes(m)) throw fail("a market is listed twice");
      return;
    }
    if (m.endsWith(":*")) {
      // "dex:*": every market of a HIP-3 dex.
      const dex = m.slice(0, -2);
      if (dex.length === 0 || dex.length > MAX_MARKET_LEN - 2 || !DEX.test(dex)) {
        throw fail("dex:* names a HIP-3 dex by its letters and digits");
      }
      if (markets.slice(0, i).includes(m)) throw fail("a market is listed twice");
      return;
    }
    const colon = m.indexOf(":");
    if (colon >= 0 && markets.includes(`${m.slice(0, colon)}:*`)) {
      throw fail("a market of a dex listed as dex:* is listed again");
    }
    if (m.length > MAX_MARKET_LEN || !MARKET.test(m)) {
      throw fail("a market name is 1 to 32 characters: letters, digits and : / @ . _ -");
    }
    if (markets.slice(0, i).includes(m)) throw fail("a market is listed twice");
  });
}

/**
 * Whether `market` may be traded under these rules: "*" is every market of Hyperliquid's main
 * dex, "dex:*" every market of that HIP-3 dex, any other entry that market alone. A HIP-3 market
 * ("dex:COIN") is never covered by "*".
 */
export function allowsMarket(rules: Rules, market: string): boolean {
  return rules.markets.some(
    (m) =>
      m === market ||
      (m === ALL_MARKETS && !market.includes(":")) ||
      (m.endsWith(":*") && market.startsWith(m.slice(0, -1))),
  );
}

/** Refuses out-of-bounds values, in the same order as the Rust crate. */
export function validate(rules: Rules): void {
  for (const b of NUMBER_BOUNDS) checkNumber(b, rules[b.field]);
  if (rules.stopPolicy !== "attach" && rules.stopPolicy !== "refuse") {
    throw new RulesError("stop_policy", 'stopPolicy must be "attach" or "refuse"', "stopPolicy");
  }
  checkMarkets(rules.markets);
  if (units(rules.maxOpenRiskPct) < units(rules.maxLossAtStopPct)) {
    throw new RulesError("open_risk_below_trade_risk", "maxOpenRiskPct must not be below maxLossAtStopPct");
  }
  if (units(rules.maxPositionPct) > units(rules.maxLeverage) * 100) {
    throw new RulesError("position_above_leverage", "maxPositionPct must not exceed maxLeverage × 100");
  }
  if (units(rules.minLiqDistancePct) <= units(rules.defaultStopDistancePct)) {
    throw new RulesError(
      "liq_not_beyond_stop",
      "minLiqDistancePct must be above defaultStopDistancePct (the liquidation lies beyond the stop)",
    );
  }
}

/** The canonical JSON: every field, in schema order. */
export function toJson(rules: Rules): string {
  const parts = ['"v":1'];
  for (const key of FIELDS) parts.push(`${JSON.stringify(key)}:${JSON.stringify(rules[key])}`);
  return `{${parts.join(",")}}`;
}

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(text: string): Uint8Array {
  if (!B64URL.test(text) || text.length % 4 === 1) throw new RulesError("base64", "the rules string is not valid base64url (no padding)");
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  // Only the canonical encoding: no stray bits in the last character.
  if (toBase64Url(bytes) !== text) throw new RulesError("base64", "the rules string is not valid base64url (no padding)");
  return bytes;
}

/** The zr1_ string. Throws RulesError for rules that do not validate. */
export function encode(rules: Rules): string {
  validate(rules);
  return PREFIX + toBase64Url(new TextEncoder().encode(toJson(rules)));
}

/** Reads and validates a zr1_ string. Throws RulesError. */
export function decode(text: string): Rules {
  if (text.length > MAX_ENCODED_LEN) throw new RulesError("too_long", `the rules string is longer than ${MAX_ENCODED_LEN} characters`);
  if (!text.startsWith(PREFIX)) throw new RulesError("prefix", `a rules string starts with ${PREFIX}`);
  const bytes = fromBase64Url(text.slice(PREFIX.length));
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new RulesError("json", "the rules are not valid JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new RulesError("not_object", "the rules must be a JSON object");
  }
  const obj = value as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (key !== "v" && !(FIELDS as readonly string[]).includes(key)) throw new RulesError("unknown_field", `unknown field ${key}`);
  }
  if (obj.v !== 1) throw new RulesError("version", "v must be 1 (this build reads rules schema v1 only)");
  const rules = defaults();
  for (const key of FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(obj, key)) continue;
    const v = obj[key];
    const wrongType = () => new RulesError("type", `${key} has the wrong type`, key);
    if (key === "stopPolicy") {
      if (typeof v !== "string") throw wrongType();
      if (v !== "attach" && v !== "refuse") throw new RulesError("stop_policy", 'stopPolicy must be "attach" or "refuse"', "stopPolicy");
      rules.stopPolicy = v;
    } else if (key === "markets") {
      if (!Array.isArray(v) || !v.every((m) => typeof m === "string")) throw wrongType();
      rules.markets = v as string[];
    } else {
      const b = NUMBER_BOUNDS.find((n) => n.field === key);
      if (b === undefined || typeof v !== "number") throw wrongType();
      checkNumber(b, v);
      rules[b.field] = v;
    }
  }
  validate(rules);
  return rules;
}
