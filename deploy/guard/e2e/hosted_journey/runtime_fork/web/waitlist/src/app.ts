// Request handling. Routes (all under /api/waitlist):
//
//   POST /api/waitlist                    sign-up (JSON from the site's script, or a plain form post)
//   GET  /api/waitlist/confirm            page with a confirm button (scanners that open links confirm nothing)
//   POST /api/waitlist/confirm            confirms: the consent timestamp
//   GET  /api/waitlist/unsubscribe        page with a remove button
//   POST /api/waitlist/unsubscribe        removes the row (also RFC 8058 one-click from mail clients)
//   GET  /api/waitlist/admin/export       CSV or JSON for Jonas            } need ADMIN_TOKEN;
//   GET  /api/waitlist/admin/stats        counts                           } 404 when it is
//   POST /api/waitlist/admin/send-pending confirmation emails for sign-ups } not configured
//                                         stored while no provider was set
//
//   POST /api/contact                     the Impressum's contact form (src/contact.ts)
//   /api/licence/…                        the licence checkout (src/licence/handlers.ts)

import type { Config } from "./config.ts";
import { CONTACT_PATH, contact } from "./contact.ts";
import { licenceRoute, type LicenceDeps } from "./licence/handlers.ts";
import { LAUNCH_OFFER, confirmationMail, type Mailer, type Notifier } from "./mail.ts";
import { escapeHtml, json, page, postButton } from "./pages.ts";
import type { RateLimiter } from "./platform.ts";
import type { ExportRow, Store } from "./store.ts";
import { constantTimeEqual, randomToken, sha256Hex, unsubscribeSignature, verifyUnsubscribeSignature } from "./tokens.ts";
import { MAX_BODY_BYTES, honeypotTripped, normaliseEmail, parseConsent, parseSignupBody, parseSource, type BodyKind } from "./validate.ts";

export const BASE_PATH = "/api/waitlist";
/** No second confirmation email to the same address within this interval. */
export const RESEND_INTERVAL_MS = 10 * 60_000;
/** At most this many confirmation emails per address until the request is purged. */
export const MAX_SENDS_PER_ADDRESS = 3;
/** Largest batch for admin/send-pending. */
export const MAX_BATCH = 200;

export interface Deps {
  config: Config;
  store: Store;
  /** The outbound provider for confirmation emails; null while none is configured (CONFIRM_PROVIDER=none). */
  mailer: Mailer | null;
  /** Notifications to Jonas through Email Routing; null when NOTIFY_TO is empty. */
  notifier: Notifier | null;
  limiter: RateLimiter | null;
  /** Stricter limiter for the contact form (CONTACT_LIMITER). */
  contactLimiter: RateLimiter | null;
  now: () => number;
  newId: () => string;
  /** Static images for the emails (e.g. the header animation), served from /api/waitlist/assets/. */
  assets?: Record<string, { body: ArrayBuffer; type: string }>;
  /** The licence checkout; null when its settings are missing or wrong (then it says it is closed). */
  licence?: LicenceDeps | null;
}

export const ACCEPTED_MESSAGE =
  "Check your inbox: we sent you a link to confirm. If nothing arrives within a few minutes, look in your spam folder.";
export const STORED_MESSAGE =
  "Thank you. We have your request and will email you a link to confirm it soon. You are on the list once you confirm.";

function clientKey(req: Request, scope: string): string {
  return `${scope}:${req.headers.get("cf-connecting-ip") ?? "unknown"}`;
}

export async function allowedFor(deps: Deps, req: Request, scope: string): Promise<boolean> {
  return allowed(deps, req, scope);
}

async function allowed(deps: Deps, req: Request, scope: string): Promise<boolean> {
  if (deps.limiter === null) return true;
  const { success } = await deps.limiter.limit({ key: clientKey(req, scope) });
  return success;
}

function bodyKind(req: Request): BodyKind | null {
  const type = (req.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (type === "application/json") return "json";
  if (type === "application/x-www-form-urlencoded") return "form";
  return null;
}

/** Reads the body up to MAX_BODY_BYTES; null if it is larger. */
async function readBody(req: Request): Promise<string | null> {
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return null;
  const text = await req.text();
  return new TextEncoder().encode(text).length > MAX_BODY_BYTES ? null : text;
}

function corsHeaders(deps: Deps, origin: string | null): Record<string, string> {
  if (origin === null || !deps.config.allowedOrigins.includes(origin)) return {};
  return { "access-control-allow-origin": origin, vary: "Origin" };
}

export async function unsubscribeUrl(config: Config, id: string): Promise<string> {
  const sig = await unsubscribeSignature(config.unsubscribeSecret, id);
  return `${config.siteUrl}${BASE_PATH}/unsubscribe?id=${encodeURIComponent(id)}&sig=${encodeURIComponent(sig)}`;
}

/** Logs an error without personal data: our messages never contain addresses or tokens. */
export function logError(where: string, err: unknown): void {
  const name = err instanceof Error ? err.name : typeof err;
  const message = err instanceof Error ? err.message.slice(0, 200) : "";
  console.error(`[waitlist] ${where}: ${name} ${message}`);
}

// ---------------------------------------------------------------- sending

type SendResult = "sent" | "capped" | "failed";

/** Sends one confirmation email to a pending row: a fresh token, within the daily cap. */
async function sendConfirmation(deps: Deps, mailer: Mailer, row: { id: string; email: string; requestedAt: number }): Promise<SendResult> {
  const { config, store } = deps;
  const now = deps.now();
  if (!(await store.takeSlot("confirm", now, config.maxSendsPerDay))) return "capped";
  const token = randomToken();
  if (!(await store.setToken(row.id, await sha256Hex(token), now + config.confirmTtlMs))) {
    await store.returnSlot("confirm", now);
    return "failed";
  }
  const mail = confirmationMail({
    config,
    to: row.email,
    confirmUrl: `${config.siteUrl}${BASE_PATH}/confirm?token=${encodeURIComponent(token)}`,
    unsubscribeUrl: await unsubscribeUrl(config, row.id),
    ttlHours: Math.round(config.confirmTtlMs / 3_600_000),
    requestedAt: row.requestedAt,
  });
  try {
    await mailer.send(mail);
  } catch (err) {
    await store.returnSlot("confirm", now);
    logError(`mail (${mailer.name})`, err);
    return "failed";
  }
  await store.markSent(row.id, now);
  return "sent";
}

/** Tells Jonas about a sign-up or confirmation. Never fails the request; capped per day. */
async function notifyJonas(deps: Deps, event: "new" | "confirmed", info: { source: string; email: string; delivery?: string }): Promise<void> {
  const { config, store, notifier } = deps;
  if (notifier === null) return;
  try {
    const now = deps.now();
    if (!(await store.takeSlot("notify", now, config.notifyMaxPerDay))) return;
    const totals = await store.counts();
    const subject = event === "new" ? `Zunder waitlist: new sign-up (${info.source})` : `Zunder waitlist: sign-up confirmed (${info.source})`;
    const lines = [
      event === "new" ? "A new sign-up arrived." : "A sign-up was confirmed.",
      "",
      `Time:   ${new Date(now).toISOString()}`,
      `Page:   ${info.source}`,
    ];
    if (config.notifyIncludeEmail) lines.push(`Email:  ${info.email}`);
    if (info.delivery !== undefined) lines.push(`Status: ${info.delivery}`);
    lines.push(
      "",
      `Totals: ${totals.confirmed} confirmed, ${totals.pending} pending (${totals.unsent} not yet sent a confirmation email).`,
      "",
      `At most ${config.notifyMaxPerDay} of these notifications are sent per day.`,
    );
    await notifier.notify(subject, lines.join("\n"));
  } catch (err) {
    logError("notify", err);
  }
}

// ---------------------------------------------------------------- sign-up

async function signup(req: Request, deps: Deps): Promise<Response> {
  const { config, store, mailer } = deps;
  const origin = req.headers.get("origin");
  const kind = bodyKind(req);
  const cors = corsHeaders(deps, origin);
  const reply = (status: number, code: string, message: string): Response =>
    kind === "form"
      ? page(status, status < 300 ? "Almost there" : "That did not work", `<p>${escapeHtml(message)}</p>`, config.siteUrl)
      : json(status, { ok: status < 300, code, message }, cors);
  const accepted = (): Response => reply(202, "accepted", mailer === null ? STORED_MESSAGE : ACCEPTED_MESSAGE);

  // Browsers always send Origin on POST; scripts that do not are not our visitors.
  if (origin === null || !config.allowedOrigins.includes(origin)) {
    return reply(403, "origin_not_allowed", "Please use the form on zunderlabs.com.");
  }
  if (kind === null) return reply(415, "unsupported_media_type", "Send JSON or a form.");
  if (!(await allowed(deps, req, "signup"))) {
    return reply(429, "rate_limited", "Too many attempts. Please wait a minute and try again.");
  }
  const text = await readBody(req);
  if (text === null) return reply(413, "too_large", "That request is too large.");
  const input = parseSignupBody(kind, text);
  if (input === null) return reply(400, "bad_request", "That request could not be read.");

  // A filled honeypot gets the normal answer and nothing happens.
  if (honeypotTripped(input.honeypot)) return accepted();

  const email = normaliseEmail(input.email);
  if (email === null) return reply(400, "invalid_email", "Please enter a valid email address.");
  if (!parseConsent(input.consent)) {
    return reply(400, "consent_required", "Please tick the box to agree that we may email you about the waitlist.");
  }
  const source = parseSource(input.source);
  const now = deps.now();
  const request = { source, consentVersion: config.consentVersion, now };

  // From here on every outcome that depends on the address answers the same way, so the form
  // does not reveal who is on the list.
  const existing = await store.findByEmail(email);
  if (existing !== null && existing.status === "confirmed") return accepted();

  if (mailer === null) {
    // No provider yet: store the request as pending; nobody is emailed except Jonas.
    if (existing !== null) {
      await store.refreshRequest({ id: existing.id, ...request });
      return accepted();
    }
    const id = deps.newId();
    if (await store.insertPending({ id, email, ...request })) {
      await notifyJonas(deps, "new", { source, email, delivery: "pending; no confirmation provider is configured, so nobody was emailed" });
    }
    return accepted();
  }

  let id: string;
  let isNew = false;
  if (existing !== null) {
    const recentlySent = existing.last_sent_at !== null && now - existing.last_sent_at < RESEND_INTERVAL_MS;
    if (recentlySent || existing.confirm_sends >= MAX_SENDS_PER_ADDRESS) return accepted();
    id = existing.id;
    await store.refreshRequest({ id, ...request });
  } else {
    id = deps.newId();
    if (!(await store.insertPending({ id, email, ...request }))) return accepted();
    isNew = true;
  }

  const result = await sendConfirmation(deps, mailer, { id, email, requestedAt: now });
  if (isNew) {
    const delivery = {
      sent: "pending; confirmation email sent",
      capped: "pending; daily cap reached, confirmation email not sent yet",
      failed: "pending; the confirmation email could not be sent",
    }[result];
    await notifyJonas(deps, "new", { source, email, delivery });
  }
  if (result === "capped") return reply(503, "busy", "We cannot send more confirmation emails today. Please try again tomorrow.");
  if (result === "failed") return reply(502, "send_failed", "We could not send the confirmation email. Please try again in a few minutes.");
  return accepted();
}

// ---------------------------------------------------------------- confirm

const INVALID_CONFIRM =
  "This confirmation link is invalid, already used or expired. You can sign up again on zunderlabs.com.";

function invalidConfirm(config: Config): Response {
  return page(404, "Link not valid", `<p>${escapeHtml(INVALID_CONFIRM)}</p>`, config.siteUrl);
}

async function confirmPage(_req: Request, deps: Deps, url: URL): Promise<Response> {
  const { config } = deps;
  const token = url.searchParams.get("token") ?? "";
  if (token === "" || token.length > 128) return invalidConfirm(config);
  const row = await deps.store.findPendingByTokenHash(await sha256Hex(token), deps.now());
  if (row === null) return invalidConfirm(config);
  return page(
    200,
    "One click, and you're in.",
    `<p>Confirm your place on the Zunder waitlist. We'll email you about Zunder Guard's beta and launch, nothing else.</p>${postButton(
      `${BASE_PATH}/confirm`,
      { token },
      "Count me in →",
    )}`,
    config.siteUrl,
    "cta",
  );
}

async function confirmPost(req: Request, deps: Deps, url: URL): Promise<Response> {
  const { config } = deps;
  if (!(await allowed(deps, req, "token"))) return page(429, "Too many attempts", "<p>Please wait a minute and try again.</p>", config.siteUrl);
  const text = (await readBody(req)) ?? "";
  const token = new URLSearchParams(text).get("token") ?? url.searchParams.get("token") ?? "";
  if (token === "" || token.length > 128) return invalidConfirm(config);
  const row = await deps.store.confirm(await sha256Hex(token), deps.now());
  if (row === null) return invalidConfirm(config);
  await notifyJonas(deps, "confirmed", { source: row.source, email: row.email });
  const leave = await unsubscribeUrl(config, row.id);
  return page(
    200,
    "You're on the list.",
    `<p>Thank you. You'll hear from us when the Zunder Guard beta opens, and about nothing else.</p>
<p class="offer"><strong>Launch offer</strong><br>On the list before Guard 1.0.0, you get ${escapeHtml(LAUNCH_OFFER)}. Available at the first release. <a href="${escapeHtml(config.siteUrl)}/pricing">Prices</a></p>
<p class="muted">Every email has a link to leave the list. You can also <a href="${escapeHtml(leave)}">leave it now</a>.</p>`,
    config.siteUrl,
    "success",
  );
}

// ---------------------------------------------------------------- unsubscribe

function unsubscribeParams(url: URL, bodyText: string | null): { id: string; sig: string } {
  const body = new URLSearchParams(bodyText ?? "");
  return {
    id: url.searchParams.get("id") ?? body.get("id") ?? "",
    sig: url.searchParams.get("sig") ?? body.get("sig") ?? "",
  };
}

async function signatureOk(deps: Deps, id: string, sig: string): Promise<boolean> {
  if (id === "" || sig === "" || id.length > 64 || sig.length > 64) return false;
  return verifyUnsubscribeSignature(deps.config.unsubscribeSecret, id, sig);
}

const INVALID_UNSUBSCRIBE = "This link is not valid. Write to the address in our legal notice and we will remove you by hand.";

async function unsubscribePage(_req: Request, deps: Deps, url: URL): Promise<Response> {
  const { config } = deps;
  const { id, sig } = unsubscribeParams(url, null);
  if (!(await signatureOk(deps, id, sig))) return page(400, "Link not valid", `<p>${escapeHtml(INVALID_UNSUBSCRIBE)}</p>`, config.siteUrl);
  const action = `${BASE_PATH}/unsubscribe?id=${encodeURIComponent(id)}&sig=${encodeURIComponent(sig)}`;
  return page(
    200,
    "Leave the waitlist",
    `<p>This deletes your address from the Zunder waitlist. Nothing about you is kept.</p>${postButton(action, {}, "Delete my address")}`,
    config.siteUrl,
  );
}

async function unsubscribePost(req: Request, deps: Deps, url: URL): Promise<Response> {
  const { config } = deps;
  if (!(await allowed(deps, req, "token"))) return page(429, "Too many attempts", "<p>Please wait a minute and try again.</p>", config.siteUrl);
  const { id, sig } = unsubscribeParams(url, await readBody(req));
  if (!(await signatureOk(deps, id, sig))) return page(400, "Link not valid", `<p>${escapeHtml(INVALID_UNSUBSCRIBE)}</p>`, config.siteUrl);
  await deps.store.remove(id);
  return page(200, "You've left the list.", "<p>Your address is deleted. You won't hear from us again.</p><p class=\"muted\">Changed your mind? You can join again any time on zunderlabs.com.</p>", config.siteUrl);
}

// ---------------------------------------------------------------- admin

/** One CSV cell: quoted, and neutralised if a spreadsheet would read it as a formula. */
export function csvCell(value: string): string {
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${safe.replace(/"/g, '""')}"`;
}

function iso(ms: number | null): string {
  return ms === null ? "" : new Date(ms).toISOString();
}

/** null when the request may proceed, otherwise the response to send. */
export async function adminGate(req: Request, deps: Deps): Promise<Response | null> {
  const { config } = deps;
  if (config.adminToken === null) return json(404, { ok: false, code: "not_found" });
  if (!(await allowed(deps, req, "admin"))) return json(429, { ok: false, code: "rate_limited" });
  const auth = req.headers.get("authorization") ?? "";
  const presented = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!constantTimeEqual(presented, config.adminToken)) return json(401, { ok: false, code: "unauthorized" });
  return null;
}

async function exportList(deps: Deps, url: URL): Promise<Response> {
  const { config } = deps;
  const rows: ExportRow[] = await deps.store.listForExport(url.searchParams.get("include") === "pending");
  const out = await Promise.all(
    rows.map(async (r) => ({
      email: r.email,
      source: r.source,
      status: r.status,
      consent_version: r.consent_version,
      requested_at: iso(r.requested_at),
      confirmed_at: iso(r.confirmed_at),
      confirmation_emails_sent: String(r.confirm_sends),
      unsubscribe_url: await unsubscribeUrl(config, r.id),
    })),
  );
  const day = new Date(deps.now()).toISOString().slice(0, 10);
  if (url.searchParams.get("format") === "json") {
    return json(200, { ok: true, exported_at: new Date(deps.now()).toISOString(), count: out.length, subscribers: out });
  }
  const header = [
    "email",
    "source",
    "status",
    "consent_version",
    "requested_at",
    "confirmed_at",
    "confirmation_emails_sent",
    "unsubscribe_url",
  ] as const;
  const lines = [header.join(","), ...out.map((o) => header.map((h) => csvCell(o[h])).join(","))];
  return new Response(`${lines.join("\r\n")}\r\n`, {
    status: 200,
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": `attachment; filename="zunder-waitlist-${day}.csv"`,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

async function sendPending(deps: Deps, url: URL): Promise<Response> {
  if (deps.mailer === null) {
    return json(409, { ok: false, code: "no_provider", message: "Set CONFIRM_PROVIDER to ses or resend first." });
  }
  const raw = url.searchParams.get("limit") ?? "50";
  if (!/^\d+$/.test(raw) || Number(raw) < 1 || Number(raw) > MAX_BATCH) {
    return json(400, { ok: false, code: "bad_limit", message: `limit must be 1 to ${MAX_BATCH}` });
  }
  let sent = 0;
  let stopped: string | null = null;
  for (const row of await deps.store.listUnsent(Number(raw))) {
    const result = await sendConfirmation(deps, deps.mailer, { id: row.id, email: row.email, requestedAt: row.requested_at });
    if (result === "sent") sent++;
    else {
      stopped = result === "capped" ? "daily_cap" : "send_failed";
      break;
    }
  }
  const totals = await deps.store.counts();
  return json(200, { ok: true, sent, stopped, still_unsent: totals.unsent });
}

// ---------------------------------------------------------------- entry points

export async function handle(req: Request, deps: Deps): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "");
  const method = req.method.toUpperCase();
  try {
    const licence = await licenceRoute(req, deps, path, url);
    if (licence !== null) return licence;
    if (path === CONTACT_PATH) {
      if (method === "POST") return await contact(req, deps);
      return json(405, { ok: false, code: "method_not_allowed" }, { allow: "POST" });
    }
    if (path === BASE_PATH) {
      if (method === "POST") return await signup(req, deps);
      if (method === "OPTIONS") {
        const cors = corsHeaders(deps, req.headers.get("origin"));
        return new Response(null, {
          status: 204,
          headers: { ...cors, "access-control-allow-methods": "POST", "access-control-allow-headers": "content-type", "access-control-max-age": "86400" },
        });
      }
      return json(405, { ok: false, code: "method_not_allowed" }, { allow: "POST, OPTIONS" });
    }
    if (path.startsWith(`${BASE_PATH}/assets/`) && (method === "GET" || method === "HEAD")) {
      const asset = deps.assets?.[path.slice(`${BASE_PATH}/assets/`.length)];
      if (asset === undefined) return json(404, { ok: false, code: "not_found" });
      return new Response(method === "HEAD" ? null : asset.body, {
        status: 200,
        headers: { "content-type": asset.type, "cache-control": "public, max-age=31536000, immutable", "x-content-type-options": "nosniff" },
      });
    }
    if (path === `${BASE_PATH}/confirm`) {
      if (method === "GET" || method === "HEAD") return await confirmPage(req, deps, url);
      if (method === "POST") return await confirmPost(req, deps, url);
    }
    if (path === `${BASE_PATH}/unsubscribe`) {
      if (method === "GET" || method === "HEAD") return await unsubscribePage(req, deps, url);
      if (method === "POST") return await unsubscribePost(req, deps, url);
    }
    const admin: Record<string, [string, () => Promise<Response>]> = {
      [`${BASE_PATH}/admin/export`]: ["GET", () => exportList(deps, url)],
      [`${BASE_PATH}/admin/stats`]: ["GET", async () => json(200, { ok: true, ...(await deps.store.counts()), provider: deps.config.confirmProvider })],
      [`${BASE_PATH}/admin/send-pending`]: ["POST", () => sendPending(deps, url)],
    };
    const route = admin[path];
    if (route !== undefined && route[0] === method) {
      const refused = await adminGate(req, deps);
      return refused ?? (await route[1]());
    }
    return json(404, { ok: false, code: "not_found" });
  } catch (err) {
    logError("request", err);
    return json(500, { ok: false, code: "server_error" });
  }
}

export async function housekeeping(deps: Deps): Promise<{ pending: number; counters: number }> {
  return deps.store.purge(deps.now(), deps.config.pendingRetentionMs, deps.config.unsentRetentionMs);
}
