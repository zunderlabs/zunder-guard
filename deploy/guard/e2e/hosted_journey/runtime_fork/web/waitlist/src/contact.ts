// POST /api/contact: the contact form linked from the Impressum (the site publishes no phone
// number). The message is forwarded to Jonas through Email Routing with Reply-To set to the
// sender, and nothing is stored.
//
// JSON {name?, email, topic?, message, consentVersion, hp} answers 204, 400, 403, 429, 502 or 503.
// `topic` is what the form's "About" list says (/contact?plan=pro preselects it); it only labels
// the forwarded email, and a value not on the list is dropped, not refused.
// A form-encoded post (no JavaScript) answers 303 to /contact?sent=1, or /contact?error=<code>.

import { logError, type Deps } from "./app.ts";
import { json } from "./pages.ts";
import { honeypotTripped, normaliseEmail } from "./validate.ts";

export const CONTACT_PATH = "/api/contact";
export const MAX_MESSAGE_CHARS = 5_000;
export const MAX_NAME_CHARS = 100;
/** Larger than the sign-up's 4 KB: 5,000 characters of up to 4 bytes each, percent-encoded in a form post. */
export const MAX_CONTACT_BODY_BYTES = 64 * 1_024;

// Letters, marks, digits, spaces and a little punctuation: enough for names, nothing for headers.
const NAME = /^[\p{L}\p{M}\p{N} .,'’()&-]+$/u;
const CONSENT_VERSION = /^[A-Za-z0-9._-]{1,32}$/;
// Control characters other than tab, line feed and carriage return.
const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;

/** The form's topics, with the label the forwarded email carries. */
export const CONTACT_TOPICS: Record<string, string> = {
  general: "Question",
  pro: "Pro licence",
  fund: "Fund licence",
  platform: "Platform",
  press: "Press",
  other: "Other",
};

export interface ContactMessage {
  name: string | null;
  email: string;
  /** A key of CONTACT_TOPICS, or null when none (or an unknown one) was sent. */
  topic: string | null;
  message: string;
  consentVersion: string;
}

export type ContactError =
  | "bad_request"
  | "invalid_email"
  | "invalid_name"
  | "message_required"
  | "message_too_long"
  | "consent_required";

/** Checks the fields. Returns the message, "honeypot" for a filled trap, or an error code. */
export function parseContact(data: Record<string, unknown>): ContactMessage | "honeypot" | ContactError {
  if (honeypotTripped(data.hp)) return "honeypot";

  const email = normaliseEmail(data.email);
  if (email === null) return "invalid_email";

  let name: string | null = null;
  if (data.name !== undefined && data.name !== null && data.name !== "") {
    if (typeof data.name !== "string") return "invalid_name";
    const n = data.name.trim().replace(/\s+/g, " ");
    if (n !== "" && ([...n].length > MAX_NAME_CHARS || !NAME.test(n))) return "invalid_name";
    name = n === "" ? null : n;
  }

  if (typeof data.message !== "string") return "message_required";
  const message = data.message.replace(/\r\n?/g, "\n").trim();
  if (message === "") return "message_required";
  if ([...message].length > MAX_MESSAGE_CHARS) return "message_too_long";
  if (CONTROL.test(message)) return "bad_request";

  if (typeof data.consentVersion !== "string" || !CONSENT_VERSION.test(data.consentVersion.trim())) return "consent_required";

  const topic = typeof data.topic === "string" && Object.hasOwn(CONTACT_TOPICS, data.topic) ? data.topic : null;

  return { name, email, topic, message, consentVersion: data.consentVersion.trim() };
}

export async function contact(req: Request, deps: Deps): Promise<Response> {
  const { config } = deps;
  const type = (req.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  const form = type === "application/x-www-form-urlencoded";
  const isJson = type === "application/json";

  const redirect = (query: string): Response =>
    new Response(null, { status: 303, headers: { location: `${config.siteUrl}/contact?${query}`, "cache-control": "no-store" } });
  const fail = (status: number, code: string): Response => (form ? redirect(`error=${code}`) : json(status, { ok: false, code }));
  const done = (): Response => (form ? redirect("sent=1") : new Response(null, { status: 204, headers: { "cache-control": "no-store" } }));

  const origin = req.headers.get("origin");
  if (origin === null || !config.allowedOrigins.includes(origin)) return fail(403, "origin_not_allowed");
  if (!form && !isJson) return fail(400, "bad_request");

  // Per visitor and, on the same binding, for everyone together, so a spammer with many
  // addresses still cannot flood Jonas's inbox.
  if (deps.contactLimiter !== null) {
    const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
    const [own, all] = await Promise.all([
      deps.contactLimiter.limit({ key: `contact:${ip}` }),
      deps.contactLimiter.limit({ key: "contact:all" }),
    ]);
    if (!own.success || !all.success) return fail(429, "rate_limited");
  }

  const declared = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_CONTACT_BODY_BYTES) return fail(400, "message_too_long");
  const text = await req.text();
  if (new TextEncoder().encode(text).length > MAX_CONTACT_BODY_BYTES) return fail(400, "message_too_long");

  let data: Record<string, unknown>;
  if (form) {
    data = Object.fromEntries(new URLSearchParams(text));
  } else {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return fail(400, "bad_request");
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return fail(400, "bad_request");
    data = parsed as Record<string, unknown>;
  }

  const result = parseContact(data);
  if (result === "honeypot") return done(); // the normal answer, and nothing happens
  if (typeof result === "string") return fail(400, result);

  if (deps.notifier === null) return fail(503, "unavailable");

  const who = result.name === null ? result.email : `${result.name} <${result.email}>`;
  const body = [
    `From:            ${who}`,
    `Received:        ${new Date(deps.now()).toISOString()}`,
    ...(result.topic === null ? [] : [`About:           ${CONTACT_TOPICS[result.topic]}`]),
    `Privacy notice:  version ${result.consentVersion}`,
    "",
    "Reply to this email to answer the sender directly.",
    "",
    "----------------------------------------------------------------------",
    result.message,
    "----------------------------------------------------------------------",
    "",
    "Sent through the contact form on zunderlabs.com. Nothing was stored.",
  ].join("\n");
  const label = result.topic === null || result.topic === "general" ? "" : ` (${CONTACT_TOPICS[result.topic]})`;
  const subject = `Contact form${label}: ${result.name ?? result.email}`;
  try {
    await deps.notifier.notify(subject, body, result.name === null ? { email: result.email } : { email: result.email, name: result.name });
  } catch (err) {
    logError("contact", err);
    return fail(502, "send_failed");
  }
  return done();
}
