// Licence checkout: the pure parts (no I/O). Prices, VAT, the unique USDC amount, validation of
// an order, the licence's dates and the one command Jonas runs to issue a key.
//
// Decisions: docs/decisions.md, "Licence sales: businesses only, paid in USDC, self-service";
// design: research/business/crypto-licence-payments.md, 5.2. Money is integer: EUR in cents, USDC
// in micro-units (6 decimals, as USDC itself), rates as integers of micro-EUR per USDC; BigInt
// where a product could pass 2^53.

export type Plan = "pro" | "fund";
export type Term = "month" | "year";
export type PayNetwork = "hyperliquid" | "arbitrum" | "base";

/** Net prices in EUR cents and the accounts a plan covers (web/site/src/lib/pricing.ts, the same). */
export const PLANS: Record<Plan, { name: string; month: number; year: number; maxAccounts: number }> = {
  pro: { name: "Pro", month: 14_900, year: 149_000, maxAccounts: 3 },
  fund: { name: "Fund", month: 69_000, year: 690_000, maxAccounts: 20 },
};

export const PAY_NETWORKS: PayNetwork[] = ["hyperliquid", "arbitrum", "base"];
export const NETWORK_LABEL: Record<PayNetwork, string> = { hyperliquid: "Hyperliquid", arbitrum: "Arbitrum One", base: "Base" };

/** EU member states (ISO 3166 alpha-2). VIES writes Greece as EL. */
export const EU = new Set(["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE"]);

/**
 * Countries no licence is sold to (research 5.6: EU and US sanctions, simplest answer). The
 * occupied regions of Ukraine cannot be told from a country code; the address check by a person
 * on delivery covers them.
 */
export const BLOCKED = new Set(["RU", "BY", "IR", "KP", "CU", "SY"]);

/** Every ISO 3166-1 alpha-2 code that is a country or territory one can be based in. */
export const COUNTRIES = new Set(
  ("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
    "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR " +
    "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP " +
    "KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT " +
    "MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW " +
    "SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG " +
    "UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW").split(" "),
);

export interface Vat {
  /** Basis points: 1900 = 19%. */
  rateBp: number;
  netCents: number;
  vatCents: number;
  grossCents: number;
  /** What the invoice says about the VAT. */
  note: string;
  kind: "de" | "reverse_charge" | "outside_eu";
}

/**
 * VAT for a business customer (licences are sold to businesses only): Germany 19%; another EU
 * country, with a VAT ID VIES confirmed, 0% under the reverse charge; outside the EU 0%, not
 * taxable in Germany (place of supply: the customer's country, §3a(2) UStG). Half a cent rounds up.
 */
export function vatFor(country: string, netCents: number): Vat {
  if (country === "DE") {
    const vatCents = Math.floor((netCents * 1900 + 5000) / 10_000);
    return { rateBp: 1900, netCents, vatCents, grossCents: netCents + vatCents, note: "German VAT 19%.", kind: "de" };
  }
  if (EU.has(country)) {
    return {
      rateBp: 0, netCents, vatCents: 0, grossCents: netCents, kind: "reverse_charge",
      note: "Reverse charge: the recipient is liable for the VAT (Art. 196 Directive 2006/112/EC; Steuerschuldnerschaft des Leistungsempfängers).",
    };
  }
  return {
    rateBp: 0, netCents, vatCents: 0, grossCents: netCents, kind: "outside_eu",
    note: "Not taxable in Germany: the place of supply is the recipient's country (§3a(2) UStG).",
  };
}

/** A rate string such as "0.85510000" (EUR per USDC) as micro-EUR per USDC; null if not sane. */
export function parseRate(raw: unknown): number | null {
  if (typeof raw !== "string" || !/^\d{1,3}(\.\d{1,12})?$/.test(raw)) return null;
  const [whole, frac = ""] = raw.split(".");
  const micro = Number(whole) * 1_000_000 + Number((frac + "000000").slice(0, 6));
  // USDC trades near $1, so between 0.5 and 1.5 EUR; anything else is a broken feed.
  return micro >= 500_000 && micro <= 1_500_000 ? micro : null;
}

/** The gross price in USDC cents at `microEurPerUsdc`, rounded up to the cent. */
export function usdcCentsFor(grossEurCents: number, microEurPerUsdc: number): number {
  const num = BigInt(grossEurCents) * 1_000_000n;
  const den = BigInt(microEurPerUsdc);
  return Number((num + den - 1n) / den);
}

/** The amount the customer sends: the price plus a tag of 1 to 99 cents, in micro-USDC. */
export function amountMicro(usdcCents: number, tagCents: number): number {
  if (!Number.isInteger(tagCents) || tagCents < 1 || tagCents > 99) throw new Error("tag out of range");
  return (usdcCents + tagCents) * 10_000;
}

/** "205.47" from micro-USDC (always two decimals; amounts are whole cents). */
export function usdcText(micro: number | bigint): string {
  const m = BigInt(micro);
  const cents = m / 10_000n;
  const rest = m % 10_000n;
  const s = (cents / 100n).toString() + "." + (cents % 100n).toString().padStart(2, "0");
  return rest === 0n ? s : (Number(m) / 1_000_000).toFixed(6);
}

/** A decimal amount from Hyperliquid ("205.47", "205.470000") as micro-USDC; null if malformed. */
export function parseUsdc(raw: unknown): bigint | null {
  if (typeof raw !== "string" || !/^\d{1,12}(\.\d{1,8})?$/.test(raw)) return null;
  const [whole = "0", frac = ""] = raw.split(".");
  if (frac.length > 6 && /[1-9]/.test(frac.slice(6))) return null; // finer than USDC's 6 decimals
  return BigInt(whole) * 1_000_000n + BigInt((frac + "000000").slice(0, 6));
}

export function eurText(cents: number): string {
  return "€" + (cents / 100).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

// ---------------------------------------------------------------- order validation

export const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
/** Company, street and city: letters (any script), digits, spaces and plain punctuation. No quotes. */
const TEXT_RE = /^[\p{L}\p{M}\p{N} .,&()\/+\-]+$/u;
const POSTCODE_RE = /^[A-Za-z0-9 \-]{1,16}$/;

export interface OrderInput {
  plan: Plan;
  term: Term;
  accounts: string[];
  company: string;
  street: string;
  postcode: string;
  city: string;
  country: string;
  /** Normalised: upper case, no separators, with its country prefix ("DE123456789", "EL…"); or null. */
  vatId: string | null;
  email: string;
  network: PayNetwork;
  termsVersion: string;
}

export type OrderError =
  | "bad_plan" | "bad_term" | "bad_accounts" | "too_many_accounts" | "bad_company" | "bad_street" | "bad_postcode" | "bad_city"
  | "bad_country" | "blocked_country" | "vat_id_required" | "bad_vat_id" | "bad_email" | "bad_network" | "business_required" | "terms_required";

function cleanText(v: unknown, max: number): string | null {
  if (typeof v !== "string") return null;
  const s = v.normalize("NFC").trim().replace(/\s+/g, " ");
  return s.length >= 1 && [...s].length <= max && TEXT_RE.test(s) ? s : null;
}

/** "DE 123.456.789" → "DE123456789"; Greece's "GR" prefix written as VIES wants it, "EL". */
export function normaliseVatId(raw: string, country: string): string | null {
  let s = raw.toUpperCase().replace(/[\s.\-]/g, "");
  if (country === "GR" && s.startsWith("GR")) s = "EL" + s.slice(2);
  const prefix = country === "GR" ? "EL" : country;
  if (!s.startsWith(prefix)) s = prefix + s;
  return /^[A-Z]{2}[A-Z0-9+*]{2,12}$/.test(s) ? s : null;
}

/** Checks an order request. `email` is normalised by the caller's email check (validate.ts). */
export function parseOrder(data: Record<string, unknown>, email: string | null): OrderInput | OrderError {
  const plan = data.plan;
  if (plan !== "pro" && plan !== "fund") return "bad_plan";
  const term = data.term;
  if (term !== "month" && term !== "year") return "bad_term";
  if (!Array.isArray(data.accounts) || data.accounts.length < 1) return "bad_accounts";
  const accounts = [...new Set(data.accounts.map((a) => (typeof a === "string" ? a.trim().toLowerCase() : "")))];
  if (accounts.some((a) => !ADDRESS_RE.test(a))) return "bad_accounts";
  if (accounts.length > PLANS[plan].maxAccounts) return "too_many_accounts";
  const company = cleanText(data.company, 120);
  if (!company || company.length < 2) return "bad_company";
  const street = cleanText(data.street, 120);
  if (!street || street.length < 2) return "bad_street";
  const postcode = typeof data.postcode === "string" ? data.postcode.trim() : "";
  if (!POSTCODE_RE.test(postcode)) return "bad_postcode";
  const city = cleanText(data.city, 80);
  if (!city) return "bad_city";
  const country = typeof data.country === "string" ? data.country.trim().toUpperCase() : "";
  if (!COUNTRIES.has(country)) return "bad_country";
  if (BLOCKED.has(country)) return "blocked_country";
  const rawVat = typeof data.vatId === "string" ? data.vatId.trim() : "";
  let vatId: string | null = null;
  if (rawVat !== "") {
    if (rawVat.length > 20) return "bad_vat_id";
    // A VAT ID is checked for EU countries only; elsewhere it is printed as given (a tax number).
    vatId = EU.has(country) ? normaliseVatId(rawVat, country) : rawVat.toUpperCase().replace(/[^A-Z0-9\-.\/ ]/g, "") || null;
    if (vatId === null) return "bad_vat_id";
  }
  // Businesses only: in the EU outside Germany the reverse charge needs a VAT ID VIES confirms.
  if (EU.has(country) && country !== "DE" && vatId === null) return "vat_id_required";
  if (email === null) return "bad_email";
  const network = data.network;
  if (network !== "hyperliquid" && network !== "arbitrum" && network !== "base") return "bad_network";
  if (data.business !== true) return "business_required";
  if (data.terms !== true || typeof data.termsVersion !== "string" || !/^[A-Za-z0-9._-]{1,32}$/.test(data.termsVersion)) return "terms_required";
  return { plan, term, accounts, company, street, postcode, city, country, vatId, email, network, termsVersion: data.termsVersion };
}

// ---------------------------------------------------------------- licence dates and the command

/** YYYY-MM-DD of `ms` (UTC). */
export function ymd(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

/**
 * The provisional end on payment, or final end when delivered: one calendar month/year from
 * that day plus one UTC day of buffer. Delivery recomputes it; payment is never the final start.
 * A month from the 31st ends on the last day of the next month.
 */
export function licenceEnd(paidAtMs: number, term: Term): string {
  const d = new Date(paidAtMs);
  const y = d.getUTCFullYear(), m = d.getUTCMonth(), day = d.getUTCDate();
  const months = term === "month" ? 1 : 12;
  const lastOfTarget = new Date(Date.UTC(y, m + months + 1, 0)).getUTCDate();
  const end = Date.UTC(y, m + months, Math.min(day, lastOfTarget)) + 86_400_000;
  return ymd(end);
}

/** A renewal that starts on `startYmd` (the old key's end): one month or year later, the day clamped. */
export function termFrom(startYmd: string, term: Term): string {
  const [y, m, d] = startYmd.split("-").map(Number) as [number, number, number];
  const months = term === "month" ? 1 : 12;
  const last = new Date(Date.UTC(y, m - 1 + months + 1, 0)).getUTCDate();
  return ymd(Date.UTC(y, m - 1 + months, Math.min(d, last)));
}

/** Final delivery dates. Reservations are floors; no delivery consumes paid time before it
 * is usable. Calendar terms start at delivery, a later booked start, or existing coverage. */
export function deliveryTerm(term: Term, bookedStart: string | null, bookedEnd: string | null, deliveredUntil: string | null, now: number): { start: string; end: string } {
  const today = ymd(now);
  const start = [today, bookedStart ?? "", deliveredUntil ?? ""].sort().at(-1)!;
  const end = start > today ? termFrom(start, term) : licenceEnd(now, term);
  return { start, end: end > (bookedEnd ?? "") ? end : bookedEnd! };
}

/** Activation contract: `command` is a TOML snippet (legacy field name), not a shell command.
 * Guard reads a top-level licence setting at startup; it has no `licence set` command.
 */
export function activation(key: string): { command: string; guide: string } {
  return { command: `licence = "${key}"`, guide: "/docs/start/licence" };
}

/** The licensee as the key carries it: the company (already restricted to safe characters) and the order number. */
export function licensee(company: string, number: string): string {
  // zunder-license refuses a licensee over 200 bytes: the name is cut to 160 bytes of UTF-8.
  let name = company.replace(/[^\p{L}\p{M}\p{N} .,&()\/+\-]/gu, "").trim();
  const enc = new TextEncoder();
  while (enc.encode(name).length > 160) name = [...name].slice(0, -1).join("");
  return name.trim() + " · " + number;
}

/**
 * The command Jonas runs to issue and deliver a paid order's key: a reviewed script in the repo
 * (deploy/licence/issue.sh) that takes only the order number. The script fetches the licensee
 * and expiry as data, pipes the private key from SSM into zunder-license and posts the signed
 * key back; no customer text is ever part of a command line.
 */
export function issueCommand(number: string): string {
  if (!/^ZL-\d{4}-\d{6}$/.test(number)) throw new Error("not an order number");
  return `deploy/licence/issue.sh ${number}`;
}
