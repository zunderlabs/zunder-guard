// Input checks for the sign-up form. Strict on purpose: anything odd is refused, never repaired.

/** Pages that may carry the form. Anything else is recorded as "other". */
export const SOURCES = ["home", "backtest", "connect", "faq", "guard", "docs", "other"] as const;
export type Source = (typeof SOURCES)[number];

/** Name of the honeypot field: hidden from people by CSS, filled in by naive bots. */
export const HONEYPOT_FIELD = "company";

/** Largest request body accepted, in bytes. A valid sign-up is well under 1 KB. */
export const MAX_BODY_BYTES = 4_096;

const LOCAL_PART = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Normalises and checks an email address. Returns the lower-cased address or null.
 * ASCII only (internationalised addresses are refused rather than half-supported); no quoted
 * local parts, no IP-literal domains, nothing that could break a mail header.
 */
export function normaliseEmail(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const email = raw.trim().toLowerCase();
  if (email.length < 6 || email.length > 254) return null;
  const at = email.lastIndexOf("@");
  if (at <= 0 || at !== email.indexOf("@")) return null;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (local.length > 64) return null;
  if (!LOCAL_PART.test(local) || !DOMAIN.test(domain)) return null;
  return email;
}

/** The consent checkbox. Only an explicit yes counts; a missing field is no. */
export function parseConsent(raw: unknown): boolean {
  if (raw === true) return true;
  if (typeof raw !== "string") return false;
  return ["true", "on", "yes", "1"].includes(raw.trim().toLowerCase());
}

export function parseSource(raw: unknown): Source {
  if (typeof raw !== "string") return "other";
  const s = raw.trim().toLowerCase();
  return (SOURCES as readonly string[]).includes(s) ? (s as Source) : "other";
}

export interface SignupInput {
  email: unknown;
  consent: unknown;
  source: unknown;
  honeypot: unknown;
}

export type BodyKind = "json" | "form";

/** Reads a sign-up body, JSON or url-encoded form. Returns null if the body is unusable. */
export function parseSignupBody(kind: BodyKind, text: string): SignupInput | null {
  if (kind === "json") {
    let data: unknown;
    try {
      data = JSON.parse(text);
    } catch {
      return null;
    }
    if (typeof data !== "object" || data === null || Array.isArray(data)) return null;
    const d = data as Record<string, unknown>;
    return { email: d.email, consent: d.consent, source: d.source, honeypot: d[HONEYPOT_FIELD] };
  }
  const p = new URLSearchParams(text);
  return { email: p.get("email"), consent: p.get("consent"), source: p.get("source"), honeypot: p.get(HONEYPOT_FIELD) };
}

/** True if the honeypot field carries anything at all. */
export function honeypotTripped(value: unknown): boolean {
  return typeof value === "string" ? value.trim() !== "" : value !== null && value !== undefined && value !== false;
}
