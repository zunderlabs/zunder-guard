// The licence checkout's routes and its payment watcher. Routes (all JSON):
//
//   GET  /api/licence/status            open or not (receiving addresses set), networks, chain
//   POST /api/licence/quote             an order: plan, term, accounts, the business, network → amount, address, expiry
//   POST /api/licence/order             {id, token}: the order's status (the customer's page)
//   POST /api/licence/order/check       {id, token}: "I've paid": looks for the payment now
//   POST /api/licence/renew             {token}: what a renewal keeps (plan, accounts, the business)
//   POST /api/licence/renewal           {token, account}: the newest key of that licence (Guard's auto-update)
//   GET  /api/licence/admin/orders      paid orders and unmatched payments, for the books   }
//   GET  /api/licence/admin/order       ?number=ZL-…&format=issue: what the key must say     } ADMIN_TOKEN
//   POST /api/licence/admin/deliver     ?order=ZL-…, body: the licence key Jonas issued      }
//
// The cron (every minute) looks for payments to our receiving addresses through public APIs, marks
// orders paid for the isolated AWS issuer, and emails an operator receipt. The Worker has no
// private signing key. Manual recovery uses deploy/licence/issue.sh; customer text is never code.

import type { Deps } from "../app.ts";
import { adminGate, allowedFor, logError } from "../app.ts";
import { json } from "../pages.ts";
import { constantTimeEqual, randomToken, sha256Hex } from "../tokens.ts";
import { normaliseEmail } from "../validate.ts";
import {
  EU, PLANS, activation, amountMicro, deliveryTerm, issueCommand, licenceEnd, licensee, parseOrder, termFrom, usdcCentsFor, usdcText, vatFor, ymd, type OrderError, type PayNetwork,
} from "./core.ts";
import { OWN_ADDRESSES, openNetworks, type LicenceConfig } from "./config.ts";
import { heldNotice, issueNotice, keyMail, orderMail, paidMail, reminderMail, unmatchedNotice } from "./mail.ts";
import { openKey, renewalToken, renewalTokenHash, sealKey } from "./secrets.ts";
import { checkVat, evmIncoming, finalizedBlock, hyperliquidIncoming, usdcBlacklisted, usdcEurRate, type Fetch, type Incoming } from "./sources.ts";
import { LicenceStore, type OrderRow } from "./store.ts";
import { verifyLicence } from "./verify.ts";

export const LICENCE_PATH = "/api/licence";
const MAX_BODY = 8_192;
const EVM_CHUNK = 2_000;
const EVM_MAX_CHUNKS = 10;
/** Order emails per UTC day for everyone together, and open orders per email address. */
const MAX_ORDER_MAILS_PER_DAY = 200;
const MAX_OPEN_PER_EMAIL = 3;
/** Orders per visitor (IP) and UTC day. */
const MAX_ORDERS_PER_IP_DAY = 10;
/** A customer's "I've paid" scans a network at most this often, for all customers together. */
const CHECK_GAP_MS = 20_000;
/** Transfers below 1 USDC are ignored (dust): never an order, never a notice. */
const MIN_PAYMENT_MICRO = 1_000_000n;

export interface LicenceDeps {
  config: LicenceConfig;
  store: LicenceStore;
  fetch: Fetch;
}

const MESSAGES: Record<OrderError | string, string> = {
  bad_plan: "Choose Pro or Fund.",
  bad_term: "Choose a month or a year.",
  bad_accounts: "Enter at least one Hyperliquid account address (0x and 40 hex digits).",
  too_many_accounts: "That plan covers fewer accounts.",
  bad_company: "Enter the company name.",
  bad_street: "Enter the street address.",
  bad_postcode: "Enter the postcode.",
  bad_city: "Enter the city.",
  bad_country: "Choose the country.",
  blocked_country: "We cannot sell licences to customers in this country.",
  vat_id_required: "Businesses in the EU outside Germany need their VAT ID (reverse charge).",
  bad_vat_id: "That VAT ID does not look right.",
  vat_id_invalid: "VIES does not confirm this VAT ID. Check it, or contact us.",
  vat_check_unavailable: "The EU's VAT ID check (VIES) is not answering right now. Please try again in a few minutes.",
  bad_email: "Enter a valid email address.",
  bad_network: "Choose how you pay.",
  network_closed: "That way to pay is not open.",
  business_required: "Licences are sold to businesses only: please confirm you buy for a business.",
  terms_required: "Please accept the terms of use.",
  rate_unavailable: "We cannot get a USDC price right now. Please try again in a minute.",
  closed: "Checkout opens when the sales wallet is set.",
  busy: "Too many open orders at this price. Please try again in a few minutes.",
  too_many_open: "You have open orders already: pay one, or wait until its quote runs out.",
  renewal_invalid: "This renewal link is not valid. Use the link from your licence email, or write to us.",
};

/** Open: a receiving address, an email provider for the customer, and Jonas's notifications. */
function isOpen(deps: Deps, lic: LicenceDeps): boolean {
  return openNetworks(lic.config).length > 0 && deps.mailer !== null && deps.notifier !== null;
}

function fail(status: number, code: string): Response {
  return json(status, { ok: false, code, message: MESSAGES[code] ?? "That did not work." });
}

async function readJson(req: Request): Promise<Record<string, unknown> | null> {
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_BODY) return null;
  const text = await req.text();
  if (new TextEncoder().encode(text).length > MAX_BODY) return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/**
 * What the customer's page shows, to the holder of the order's token: the order, and once it is
 * delivered, its key with the command that turns it on (as the email has them).
 */
async function view(o: OrderRow, secret: string) {
  const key = o.status === "delivered" && o.licence_key_enc ? await openKey(secret, o.licence_id, o.id, o.licence_key_enc) : null;
  return {
    id: o.id,
    number: o.number,
    status: o.status,
    plan: o.plan,
    planName: PLANS[o.plan].name,
    term: o.term,
    accounts: JSON.parse(o.accounts) as string[],
    company: o.company,
    country: o.country,
    vatId: o.vat_id,
    netCents: o.net_cents,
    vatCents: o.vat_cents,
    vatRateBp: o.vat_rate_bp,
    grossCents: o.gross_cents,
    vatNote: o.vat_note,
    usdc: usdcText(o.amount_micro),
    network: o.pay_network,
    chain: o.chain,
    payTo: o.pay_to,
    quoteExpiresAt: o.quote_expires_at,
    paidAt: o.paid_at,
    paidUsdc: o.paid_micro === null ? null : usdcText(o.paid_micro),
    licenceExpiresOn: o.status === "delivered" ? o.licence_expires_on : null,
    termStart: o.status === "delivered" ? o.term_start : null,
    licenceNumber: o.licence_number,
    renewal: o.renews_order_id !== null,
    delivered: o.status === "delivered",
    key,
    activation: key ? activation(key) : null,
  };
}

// ---------------------------------------------------------------- quote

async function quote(req: Request, deps: Deps, lic: LicenceDeps): Promise<Response> {
  const { config } = deps;
  const origin = req.headers.get("origin");
  if (origin === null || !config.allowedOrigins.includes(origin)) return fail(403, "origin_not_allowed");
  if ((req.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase() !== "application/json") return fail(415, "bad_request");
  if (!(await allowedFor(deps, req, "licence"))) return fail(429, "rate_limited");
  const mailer = deps.mailer;
  if (!isOpen(deps, lic)) return fail(503, "closed");
  if (mailer === null) return fail(503, "closed");
  const body = await readJson(req);
  if (body === null) return fail(400, "bad_request");
  if ("chain" in body && body.chain !== lic.config.chain) return fail(400, "bad_request");
  // A renewal keeps the licence's plan, accounts and business; only the term and the network are chosen.
  let renews: OrderRow | null = null;
  if (body.renewal !== undefined) {
    renews = await renewalOf(lic, body.renewal);
    if (!renews) return fail(404, "renewal_invalid");
  }
  const data: Record<string, unknown> = renews
    ? { ...body, plan: renews.plan, accounts: JSON.parse(renews.accounts), company: renews.company, street: renews.street, postcode: renews.postcode, city: renews.city, country: renews.country, vatId: renews.vat_id ?? "", email: renews.email }
    : body;
  const input = parseOrder(data, normaliseEmail(data.email));
  if (typeof input === "string") return fail(400, input);
  const payTo = lic.config.payTo[input.network];
  if (payTo === undefined) return fail(400, "network_closed");
  // The cheap limit before any outside call (VIES runs under our own VAT ID). A renewal counts
  // against its licence instead of the email, so new orders under that email cannot block it.
  if (renews ? (await lic.store.openRenewals(renews.licence_id, deps.now())) >= 2 : (await lic.store.openFor(input.email, deps.now())) >= MAX_OPEN_PER_EMAIL) return fail(429, "too_many_open");

  // An EU VAT ID (required outside Germany, optional in Germany) must be valid in VIES.
  let vatCheck: string | null = null;
  if (input.vatId !== null && EU.has(input.country)) {
    try {
      const r = await checkVat(lic.fetch, input.vatId, lic.config.sellerVatId);
      if (!r.valid) return fail(400, "vat_id_invalid");
      vatCheck = JSON.stringify({ ...r, checkedAt: new Date(deps.now()).toISOString() });
    } catch (err) {
      logError("licence vies", err);
      return fail(503, "vat_check_unavailable");
    }
  }

  let rate: { microEur: number; source: string };
  try {
    rate = await usdcEurRate(lic.fetch);
  } catch (err) {
    logError("licence rate", err);
    return fail(503, "rate_unavailable");
  }
  const now = deps.now();
  const net = PLANS[input.plan][input.term];
  const vat = vatFor(input.country, net);
  const usdcCents = usdcCentsFor(vat.grossCents, rate.microEur);
  // Counted only for orders that are made: per visitor (a salted daily hash of the IP, never the
  // address) and for everyone together, so one visitor cannot close the checkout for the day.
  const day = new Date(now).toISOString().slice(0, 10);
  const ipHash = await sha256Hex(`${deps.config.unsubscribeSecret}:${day}:${req.headers.get("cf-connecting-ip") ?? "unknown"}`);
  if (!(await lic.store.takeIpQuota(day, ipHash, MAX_ORDERS_PER_IP_DAY))) return fail(429, "rate_limited");
  if (!(await lic.store.takeQuota(day, MAX_ORDER_MAILS_PER_DAY))) {
    if (await deps.store.takeSlot("notify", now, deps.config.notifyMaxPerDay)) {
      await notifyJonas(deps, { subject: "Licence checkout: the day's order cap is reached", text: `${MAX_ORDER_MAILS_PER_DAY} orders today; new orders are refused until 00:00 UTC. Look for abuse in /api/licence/admin/orders and the Worker's logs.` });
    }
    return fail(503, "busy");
  }
  // Watching this address starts no later than its first order, so the order's payment is seen.
  await lic.store.watchStart(input.network, lic.config.chain, payTo, now);
  const token = randomToken();
  const number = await lic.store.nextNumber(new Date(now).getUTCFullYear());
  const base = {
    id: deps.newId(),
    number,
    token_hash: await sha256Hex(token),
    created_at: now,
    quote_expires_at: now + lic.config.quoteMs,
    reserved_until: now + lic.config.quoteMs + lic.config.reserveMs,
    plan: input.plan,
    term: input.term,
    accounts: JSON.stringify(input.accounts),
    company: input.company,
    street: input.street,
    postcode: input.postcode,
    city: input.city,
    country: input.country,
    vat_id: input.vatId,
    vat_check: vatCheck,
    email: input.email,
    net_cents: vat.netCents,
    vat_rate_bp: vat.rateBp,
    vat_cents: vat.vatCents,
    gross_cents: vat.grossCents,
    vat_kind: vat.kind,
    vat_note: vat.note,
    rate_micro_eur: rate.microEur,
    rate_source: rate.source,
    rate_at: now,
    pay_network: input.network,
    chain: lic.config.chain,
    pay_to: payTo,
    terms_version: input.termsVersion,
    business_confirmed: 1,
  };
  const licenceFields = renews
    ? { licence_id: renews.licence_id, licence_number: renews.licence_number, renews_order_id: renews.id }
    : { licence_id: base.id, licence_number: number, renews_order_id: null };
  // A random cent tag that no other open order on this network holds at this price.
  const tags = Array.from({ length: 99 }, (_, i) => i + 1).sort(() => Math.random() - 0.5);
  let inserted = false;
  for (const tag of tags.slice(0, 40)) {
    if (await lic.store.insert({ ...base, ...licenceFields, amount_micro: amountMicro(usdcCents, tag) })) {
      inserted = true;
      break;
    }
  }
  if (!inserted) return fail(503, "busy");
  const order = await lic.store.byId(base.id);
  if (!order) return fail(500, "server_error");
  const statusUrl = `${config.siteUrl}/licence#order=${order.id}.${token}`;
  try {
    await mailer.send(orderMail(config, order, statusUrl));
  } catch (err) {
    logError("licence order mail", err);
  }
  return json(200, { ok: true, token, order: await view(order, deps.config.unsubscribeSecret) });
}

// ---------------------------------------------------------------- the customer's order

async function authed(req: Request, lic: LicenceDeps): Promise<OrderRow | null> {
  const data = await readJson(req);
  if (!data || typeof data.id !== "string" || typeof data.token !== "string" || data.id.length > 64 || data.token.length > 128) return null;
  const o = await lic.store.byId(data.id);
  if (!o || o.chain !== lic.config.chain) return null;
  return constantTimeEqual(await sha256Hex(data.token), o.token_hash) ? o : null;
}

async function orderStatus(req: Request, deps: Deps, lic: LicenceDeps, check: boolean): Promise<Response> {
  if (!(await allowedFor(deps, req, check ? "licence-check" : "licence-status"))) return fail(429, "rate_limited");
  const o = await authed(req, lic);
  if (!o) return fail(404, "not_found");
  // "I've paid" scans Hyperliquid now (instant transfers), at most every CHECK_GAP_MS for everyone
  // together. EVM payments count only once final, which the minute cron sees first; there the
  // check just reads the status.
  if (check && o.status === "awaiting_payment" && o.pay_network === "hyperliquid" && (await lic.store.takeScan(o.pay_network, o.chain, deps.now(), CHECK_GAP_MS))) {
    try {
      await watchNetwork(deps, lic, o.pay_network);
    } catch (err) {
      logError("licence check", err);
    }
    const fresh = await lic.store.byId(o.id);
    return json(200, { ok: true, order: await view(fresh ?? o, deps.config.unsubscribeSecret) });
  }
  return json(200, { ok: true, order: await view(o, deps.config.unsubscribeSecret) });
}

// Issuer-only capability: never accepts ADMIN_TOKEN or exposes customer/contact credentials.
async function issuerGate(req: Request, deps: Deps): Promise<Response | null> {
  const expected = deps.config.issuerToken;
  if (!expected) return json(404, { ok: false, code: "not_found" });
  const auth = req.headers.get("authorization") ?? "";
  if (!constantTimeEqual(auth, `Bearer ${expected}`)) return json(401, { ok: false, code: "unauthorized" });
  return null;
}

async function issuanceJobs(deps: Deps, lic: LicenceDeps): Promise<Response> {
  const jobs = [];
  for (const o of await lic.store.issuanceCandidates(deps.now(), lic.config.chain)) {
    if (o.chain !== lic.config.chain) continue;
    const context = await lic.store.deliveryContext(o);
    if (context.blocked && o.status !== "delivering") continue;
    const term = deliveryTerm(o.term, o.term_start, o.licence_expires_on, context.until, deps.now());
    jobs.push({ number: o.number, chain: o.chain, plan: o.plan, licensee: licensee(o.company, o.licence_number),
      accounts: JSON.parse(o.accounts), start: term.start, end: term.end, term: o.term });
  }
  return json(200, { ok: true, jobs });
}

// ---------------------------------------------------------------- admin: deliver a key

async function deliver(req: Request, deps: Deps, lic: LicenceDeps, url: URL, automatic = false): Promise<Response> {
  const number = url.searchParams.get("order") ?? "";
  if (!/^ZL-\d{4}-\d{6}$/.test(number)) return json(400, { ok: false, code: "bad_order" });
  const o = await lic.store.byNumber(number);
  if (!o) return json(404, { ok: false, code: "not_found" });
  if (o.status !== "paid" && o.status !== "delivering") return json(409, { ok: false, code: "not_paid", status: o.status });
  if (automatic && (o.held_reason !== null || o.paid_at === null || o.paid_micro !== o.amount_micro || !o.payment_ref)) return json(409, { ok: false, code: "not_eligible" });
  if (o.chain !== lic.config.chain) return json(409, { ok: false, code: "wrong_chain", message: `a ${o.chain} order, and this checkout runs on ${lic.config.chain}` });
  const mailer = deps.mailer;
  if (mailer === null) return json(503, { ok: false, code: "no_mailer" });
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > 4_096) return json(400, { ok: false, code: "bad_key" });
  const key = (await req.text()).trim();
  if (key.length > 4_096) return json(400, { ok: false, code: "bad_key" });
  const terms = await verifyLicence(key, lic.config.publicKeyHex);
  if (!terms) return json(400, { ok: false, code: "bad_key", message: "The key does not verify against Guard's public key." });
  const now = deps.now();
  const context = await lic.store.deliveryContext(o);
  if (context.blocked && o.status !== "delivering") return json(409, { ok: false, code: "prior_delivery_pending" });
  const finalTerm = deliveryTerm(o.term, o.term_start, o.licence_expires_on, context.until, now);
  const expected = Date.parse(`${finalTerm.end}T00:00:00Z`);
  const problems: string[] = [];
  if (terms.licensee !== licensee(o.company, o.licence_number)) problems.push("licensee is not " + licensee(o.company, o.licence_number));
  const expectedAccounts = (JSON.parse(o.accounts) as string[]).map((a) => a.toLowerCase()).sort();
  if (JSON.stringify([...terms.accounts].sort()) !== JSON.stringify(expectedAccounts)) problems.push("accounts do not match the order");
  if (!terms.features.includes("fee_free")) problems.push("no fee_free feature");
  if (terms.builder !== undefined) problems.push("a builder override, which a licence sale does not carry");
  // Recompute on actual delivery: a key issued before midnight may now be too short.
  if (terms.expires_at_ms !== expected) problems.push("expiry must be " + finalTerm.end + "; issue the key again");
  if (terms.expires_at_ms <= now) problems.push("the key has expired");
  if (problems.length) return json(400, { ok: false, code: "wrong_key", problems });
  // paid → delivering first, so two runs at once cannot both email the customer.
  if (!(await lic.store.startDelivery(o, now, finalTerm, context.until))) return json(409, { ok: false, code: "not_paid" });
  const delivered: OrderRow = { ...o, status: "delivered", delivered_at: now, term_start: finalTerm.start, licence_expires_on: finalTerm.end };
  const secret = deps.config.unsubscribeSecret;
  const token = await currentRenewalToken(deps, lic, o.licence_id, now);
  try {
    await mailer.send(keyMail(deps.config, delivered, key, renewLink(deps, token)));
  } catch (err) {
    logError("licence key mail", err);
    await lic.store.abortDelivery(o.id, now);
    return json(502, { ok: false, code: "send_failed", message: "Not delivered; run the command again." });
  }
  if (!(await lic.store.markDelivered(o.id, await sha256Hex(key), await sealKey(secret, o.licence_id, o.id, key), now))) return json(409, { ok: false, code: "delivery_lease_changed" });
  return json(200, { ok: true, delivered: o.number, to: "the customer's email" });
}

/** Issuer protocol v3: licensee, expiry, chain, accounts, final start, purchased term. */
async function adminOrder(deps: Deps, lic: LicenceDeps, url: URL): Promise<Response> {
  const number = url.searchParams.get("number") ?? "";
  if (!/^ZL-\d{4}-\d{6}$/.test(number)) return json(400, { ok: false, code: "bad_order" });
  const o = await lic.store.byNumber(number);
  if (!o) return json(404, { ok: false, code: "not_found" });
  if (url.searchParams.get("format") !== "issue") return json(200, { ok: true, order: { ...o, accounts: JSON.parse(o.accounts) } });
  const staleOwnLease = o.status === "delivering" && o.delivering_at !== null && o.delivering_at < deps.now() - 600_000;
  if ((o.status !== "paid" && !staleOwnLease) || !o.licence_expires_on) return json(409, { ok: false, code: "not_paid", status: o.status });
  const context = await lic.store.deliveryContext(o);
  if (context.blocked && !staleOwnLease) return json(409, { ok: false, code: "prior_delivery_pending" });
  const finalTerm = deliveryTerm(o.term, o.term_start, o.licence_expires_on, context.until, deps.now());
  return new Response(`${licensee(o.company, o.licence_number)}\n${finalTerm.end}\n${o.chain}\n${(JSON.parse(o.accounts) as string[]).join(",")}\n${finalTerm.start}\n${o.term}\n`, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

async function adminOrders(lic: LicenceDeps): Promise<Response> {
  const orders = (await lic.store.paidOrders()).map((o) => ({ ...o, accounts: JSON.parse(o.accounts), vat_check: o.vat_check ? JSON.parse(o.vat_check) : null }));
  return json(200, { ok: true, orders, unmatched: await lic.store.unmatchedPayments() });
}

// ---------------------------------------------------------------- renewal

export function renewLink(deps: Deps, token: string): string {
  return `${deps.config.siteUrl}/licence#renew=${token}`;
}

/** The licence's newest delivered order for a renewal token; null for any token that is not one. */
async function renewalOf(lic: LicenceDeps, token: unknown): Promise<OrderRow | null> {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const licenceId = await lic.store.licenceByTokenHash(await renewalTokenHash(token));
  // Only a licence of the chain this checkout runs on: a testnet licence never renews on mainnet.
  return licenceId ? lic.store.latestDelivered(licenceId, lic.config.chain) : null;
}

/** The licence's current renewal token (its generation from D1), with its hash stored. */
async function currentRenewalToken(deps: Deps, lic: LicenceDeps, licenceId: string, now: number): Promise<string> {
  const token = await renewalToken(deps.config.unsubscribeSecret, licenceId, await lic.store.renewalGeneration(licenceId));
  await lic.store.setRenewalToken(licenceId, await renewalTokenHash(token), now);
  return token;
}

/** What a renewal keeps, for the renewal form (the token holder sees their own licence only). */
async function renewInfo(req: Request, deps: Deps, lic: LicenceDeps): Promise<Response> {
  if (!(await allowedFor(deps, req, "licence-renew"))) return fail(429, "rate_limited");
  const body = await readJson(req);
  const o = body ? await renewalOf(lic, body.token) : null;
  if (!o) return fail(404, "renewal_invalid");
  return json(200, {
    ok: true,
    renewal: {
      licenceNumber: o.licence_number, plan: o.plan, planName: PLANS[o.plan].name, term: o.term, accounts: JSON.parse(o.accounts) as string[],
      company: o.company, country: o.country, vatId: o.vat_id,
      // Paid time, renewals paid but not yet delivered included, so nobody pays twice by mistake.
      expiresOn: (await lic.store.paidUntil(o.licence_id, o.chain, "")) ?? o.licence_expires_on,
      pendingDelivery: await lic.store.hasPendingDelivery(o.licence_id, o.chain),
    },
  });
}

/**
 * Guard's auto-update: the newest key issued for the licence, if the account is one it covers.
 * Nothing else is returned, and every failure answers the same 404.
 */
async function renewalKey(req: Request, deps: Deps, lic: LicenceDeps): Promise<Response> {
  if (!(await allowedFor(deps, req, "licence-renewal"))) return fail(429, "rate_limited");
  const body = await readJson(req);
  const account = typeof body?.account === "string" ? body.account.trim().toLowerCase() : "";
  const o = body && /^0x[0-9a-f]{40}$/.test(account) ? await renewalOf(lic, body.token) : null;
  const key = o && (JSON.parse(o.accounts) as string[]).includes(account) && o.licence_key_enc
    ? await openKey(deps.config.unsubscribeSecret, o.licence_id, o.id, o.licence_key_enc)
    : null;
  if (!key) return json(404, { ok: false, code: "not_found" });
  return json(200, { ok: true, key });
}

/** Expiry reminders: 14, 7 and 1 days before the key runs out, and once after; each at most once. */
const STAGES: { bit: number; days: number; label: "14" | "7" | "1" | "expired" }[] = [
  { bit: 8, days: 0, label: "expired" },
  { bit: 4, days: 1, label: "1" },
  { bit: 2, days: 7, label: "7" },
  { bit: 1, days: 14, label: "14" },
];

async function sendExpiryReminders(deps: Deps, lic: LicenceDeps): Promise<void> {
  if (deps.mailer === null) return;
  const now = deps.now();
  for (const o of await lic.store.expiring(now, lic.config.chain)) {
    if (!o.licence_expires_on) continue;
    const left = (Date.parse(`${o.licence_expires_on}T00:00:00Z`) - now) / 86_400_000;
    // The most urgent stage reached; earlier stages it skipped are marked too, never sent late.
    const stage = STAGES.find((st) => (st.label === "expired" ? left <= 0 : left <= st.days));
    if (!stage) continue;
    const bits = STAGES.filter((st) => st.bit <= stage.bit).reduce((a, st) => a | st.bit, 0) | stage.bit;
    if ((o.reminders & stage.bit) !== 0) continue;
    if (!(await lic.store.markReminded(o.id, stage.bit, bits))) continue;
    const token = await currentRenewalToken(deps, lic, o.licence_id, now);
    try {
      await deps.mailer.send(reminderMail(deps.config, o, stage.label, renewLink(deps, token)));
    } catch (err) {
      // At most once: the bit is set. Jonas hears of a reminder that did not go out.
      logError("licence reminder", err);
      await notifyJonas(deps, { subject: `Licence reminder not sent: ${o.licence_number}`, text: `The ${stage.label === "expired" ? "after-expiry" : stage.label + "-day"} reminder for ${o.licence_number} could not be sent.` });
    }
  }
}

// ---------------------------------------------------------------- the watcher

async function notifyJonas(deps: Deps, n: { subject: string; text: string; html?: string }): Promise<void> {
  if (deps.notifier === null) {
    console.error(`[licence] no NOTIFY_TO: ${n.subject}`);
    return;
  }
  try {
    await deps.notifier.notify(n.subject, n.text, undefined, { name: "Zunder Guard", html: n.html });
  } catch (err) {
    logError("licence notify", err);
  }
}

/**
 * Handles one transfer: recorded once; matched to an order, or reported as unmatched. It is
 * marked handled only at the end, so a failure in between is retried on the next run.
 */
async function handleIncoming(deps: Deps, lic: LicenceDeps, network: PayNetwork, p: Incoming, blacklisted: () => Promise<boolean>): Promise<void> {
  if (p.amountMicro < MIN_PAYMENT_MICRO) return;
  const chain = lic.config.chain;
  const payTo = lic.config.payTo[network];
  if (payTo === undefined) return;
  if (!(await lic.store.recordPayment({ ref: p.ref, network, chain, amountMicro: p.amountMicro, payer: p.payer, seenAt: deps.now(), paidAt: p.time }))) return;
  // One run at a time per transfer (the minute cron and an "I've paid" scan may overlap).
  if (!(await lic.store.claimPayment(network, chain, p.ref, deps.now()))) return;
  // A run that failed after marking the order paid: finish that order, do not report it unmatched.
  const already = await lic.store.orderByPayment(network, chain, p.ref);
  if (already) {
    await sendPaidNotices(deps, lic, already, network);
    await lic.store.paymentHandled(network, chain, p.ref, already.id);
    return;
  }
  const o = await lic.store.matching(network, chain, payTo, p.amountMicro, p.time);
  if (!o && OWN_ADDRESSES.includes(p.payer)) {
    // From one of our own addresses (funding, a test): internal, logged, never alerted.
    console.log(`[licence] internal transfer: ${usdcText(p.amountMicro)} USDC on ${network} (${chain}) from ${p.payer}, ${p.ref}`);
    await lic.store.paymentHandled(network, chain, p.ref, null, true);
    return;
  }
  if (!o) {
    // Capped with the other notifications to Jonas, so dust or spam cannot flood the inbox.
    if (await deps.store.takeSlot("notify", deps.now(), deps.config.notifyMaxPerDay)) {
      await notifyJonas(deps, unmatchedNotice({ network, chain, ref: p.ref, payer: p.payer, amountMicro: p.amountMicro, time: p.time }));
    }
    await lic.store.paymentHandled(network, chain, p.ref, null);
    return;
  }
  // The sanctions signal fails closed: if the check cannot run, the order is held for a person.
  let heldReason: string | null = null;
  try {
    if (await blacklisted()) heldReason = "the payer is on USDC's blocklist";
  } catch {
    heldReason = "the USDC blocklist check could not run; check the payer by hand";
  }
  // A renewal paid before the old key runs out starts at its end; otherwise the term starts on payment.
  // Computed from the paid time read, and marked only if that is still the paid time (a renewal
  // paid at the same moment in another run makes this one compute again).
  let marked = false;
  for (let attempt = 0; attempt < 3 && !marked; attempt++) {
    const paidUntil = await lic.store.paidUntil(o.licence_id, o.chain, o.id);
    const paidDay = ymd(p.time);
    const early = paidUntil !== null && paidUntil > paidDay;
    const termStart = early ? paidUntil : paidDay;
    const expiresOn = early ? termFrom(paidUntil, o.term) : licenceEnd(p.time, o.term);
    marked = await lic.store.markPaid(o.id, { status: heldReason ? "held" : "paid", heldReason, paidAt: p.time, paidMicro: p.amountMicro, ref: p.ref, payer: p.payer, termStart, expiresOn, paidUntilSeen: paidUntil });
    if (!marked && (await lic.store.byId(o.id))?.status !== "awaiting_payment") break;
  }
  if (marked) {
    await sendPaidNotices(deps, lic, (await lic.store.byId(o.id)) as OrderRow, network);
  }
  await lic.store.paymentHandled(network, chain, p.ref, o.id);
}

/** The "paid" (or "held") notice to Jonas and the receipt notice to the customer, once per order. */
async function sendPaidNotices(deps: Deps, lic: LicenceDeps, paid: OrderRow, network: PayNetwork): Promise<void> {
  if (paid.status !== "paid" && paid.status !== "held") return;
  if (!(await lic.store.takePaidNotice(paid.id, deps.now()))) return;
  if (paid.status === "held") {
    await notifyJonas(deps, heldNotice(paid, paid.held_reason ?? "held"));
    return;
  }
  await notifyJonas(deps, issueNotice(paid, issueCommand(paid.number), network === "hyperliquid", !!deps.config.issuerToken));
  if (deps.mailer) {
    try {
      await deps.mailer.send(paidMail(deps.config, paid));
    } catch (err) {
      logError("licence paid mail", err);
    }
  }
}

/** Looks for payments on one network. */
export async function watchNetwork(deps: Deps, lic: LicenceDeps, network: PayNetwork): Promise<void> {
  const to = lic.config.payTo[network];
  if (to === undefined) return;
  const now = deps.now();
  // Only transfers after watching this address began (the first run for it): the history before
  // the checkout opened, such as funding the account, is never looked at.
  const start = await lic.store.watchStart(network, lic.config.chain, to, now);
  if (network === "hyperliquid") {
    // The last day, from the start at the earliest: catches late payments for expired quotes too.
    const since = Math.max(start.startMs, now - 86_400_000);
    for (const p of await hyperliquidIncoming(lic.fetch, lic.config.hyperliquidApi, to, since)) {
      if (p.time < start.startMs) continue;
      await handleIncoming(deps, lic, network, p, async () => false);
    }
    return;
  }
  const rpc = lic.config.rpc[network];
  const usdc = lic.config.usdc[network];
  const finalized = await finalizedBlock(lic.fetch, rpc);
  // A new address (or the first run): from the finalized block on, never earlier.
  if (start.fresh) {
    await lic.store.setCursor(network, lic.config.chain, finalized.number);
    return;
  }
  const cursor = await lic.store.cursor(network, lic.config.chain);
  let from = cursor === null ? finalized.number : cursor.block + 1;
  for (let i = 0; i < EVM_MAX_CHUNKS && from <= finalized.number; i++) {
    const toBlock = Math.min(finalized.number, from + EVM_CHUNK - 1);
    for (const p of await evmIncoming(lic.fetch, rpc, usdc, to, from, toBlock)) {
      if (p.time < start.startMs) continue;
      await handleIncoming(deps, lic, network, p, () => usdcBlacklisted(lic.fetch, rpc, usdc, p.payer));
    }
    await lic.store.setCursor(network, lic.config.chain, toBlock);
    from = toBlock + 1;
  }
  if (cursor === null && from > finalized.number) await lic.store.setCursor(network, lic.config.chain, finalized.number);
}

/** The minute cron: every open network; one failing source does not stop the others. */
export async function watchPayments(deps: Deps, lic: LicenceDeps): Promise<void> {
  for (const n of openNetworks(lic.config)) {
    try {
      await watchNetwork(deps, lic, n);
    } catch (err) {
      logError(`licence watch ${n}`, err);
    }
  }
  try {
    await sendExpiryReminders(deps, lic);
  } catch (err) {
    logError("licence reminders", err);
  }
  // Automatic fulfilment overdue by ten minutes (manual: one day): alert Jonas, at most daily.
  for (const o of await lic.store.undelivered(deps.now(), !!deps.config.issuerToken)) {
    await notifyJonas(deps, o.status === "held"
      ? { subject: `Reminder: licence payment ${o.number} is held`, text: `${o.number} is held (${o.held_reason ?? "held"}); decide by hand.` }
      : { subject: `Reminder: licence ${o.number} is paid and waits for its key`, text: `Run, from the repository: ${issueCommand(o.number)}` });
    await lic.store.reminded(o.id, deps.now());
  }
  await lic.store.purge(deps.now());
}

// ---------------------------------------------------------------- routing

export async function licenceRoute(req: Request, deps: Deps, path: string, url: URL): Promise<Response | null> {
  if (!path.startsWith(LICENCE_PATH)) return null;
  const method = req.method.toUpperCase();
  const lic = deps.licence;
  if (path === `${LICENCE_PATH}/status` && method === "GET") {
    const open = lic !== null && lic !== undefined && isOpen(deps, lic);
    return json(200, { ok: true, open, networks: open && lic ? openNetworks(lic.config) : [], chain: lic?.config.chain ?? "mainnet", message: open ? null : MESSAGES.closed });
  }
  if (!lic) return fail(503, "closed");
  if (path === `${LICENCE_PATH}/quote` && method === "POST") return quote(req, deps, lic);
  if (path === `${LICENCE_PATH}/order` && method === "POST") return orderStatus(req, deps, lic, false);
  if (path === `${LICENCE_PATH}/order/check` && method === "POST") return orderStatus(req, deps, lic, true);
  if (path === `${LICENCE_PATH}/renew` && method === "POST") return renewInfo(req, deps, lic);
  if (path === `${LICENCE_PATH}/renewal` && method === "POST") return renewalKey(req, deps, lic);
  if (path === `${LICENCE_PATH}/issuer/jobs` && method === "GET") return (await issuerGate(req, deps)) ?? issuanceJobs(deps, lic);
  if (path === `${LICENCE_PATH}/issuer/deliver` && method === "POST") return (await issuerGate(req, deps)) ?? deliver(req, deps, lic, url, true);
  if (path === `${LICENCE_PATH}/admin/orders` && method === "GET") return (await adminGate(req, deps)) ?? adminOrders(lic);
  if (path === `${LICENCE_PATH}/admin/order` && method === "GET") return (await adminGate(req, deps)) ?? adminOrder(deps, lic, url);
  if (path === `${LICENCE_PATH}/admin/deliver` && method === "POST") return (await adminGate(req, deps)) ?? deliver(req, deps, lic, url);
  return json(404, { ok: false, code: "not_found" });
}
