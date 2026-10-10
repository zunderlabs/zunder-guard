import type { Env } from "./platform.ts";

/**
 * Who carries confirmation emails to subscribers. "cloudflare" (Email Service, the primary) or the
 * fallbacks "ses" and "resend". "none": sign-ups are stored as pending and nobody is emailed.
 * "log" is development only.
 */
export type ConfirmProvider = "none" | "cloudflare" | "ses" | "resend" | "log";

export interface Config {
  production: boolean;
  siteUrl: string; // origin of the public site, no trailing slash, e.g. https://zunderlabs.com
  allowedOrigins: string[];
  confirmProvider: ConfirmProvider;
  mailFrom: string;
  mailFromName: string;
  mailReplyTo: string | null;
  sesRegion: string;
  sesConfigurationSet: string | null;
  notifyTo: string | null; // null: notifications off
  notifyFrom: string;
  notifyIncludeEmail: boolean;
  notifyMaxPerDay: number;
  consentVersion: string;
  maxSendsPerDay: number;
  confirmTtlMs: number;
  pendingRetentionMs: number; // pending rows that were mailed: deleted this long after the last mail
  unsentRetentionMs: number; // pending rows never mailed (no provider yet): deleted this long after the request
  unsubscribeSecret: string;
  adminToken: string | null;
  issuerToken: string | null;
  awsAccessKeyId: string | null;
  awsSecretAccessKey: string | null;
  resendApiKey: string | null;
}

export class ConfigError extends Error {}

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

/** Bounds for the numeric settings: refused outside them, upper bounds included. */
export const LIMITS = {
  maxSendsPerDay: { min: 1, max: 2_000 },
  notifyMaxPerDay: { min: 1, max: 500 },
  confirmTtlHours: { min: 1, max: 168 },
  pendingRetentionDays: { min: 1, max: 30 },
  unsentRetentionDays: { min: 1, max: 180 },
  secretMinLength: 32,
} as const;

const ADDRESS = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/;

function intSetting(raw: string | undefined, name: string, fallback: number, min: number, max: number): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  if (!/^\d+$/.test(raw.trim())) throw new ConfigError(`${name} must be a whole number`);
  const value = Number(raw.trim());
  if (value < min || value > max) throw new ConfigError(`${name} must be between ${min} and ${max}`);
  return value;
}

function originOf(raw: string, name: string): string {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new ConfigError(`${name} is not a URL`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new ConfigError(`${name} must be http(s)`);
  return url.origin;
}

function address(raw: string | undefined, name: string): string {
  const value = (raw ?? "").trim();
  if (!ADDRESS.test(value)) throw new ConfigError(`${name} is not an address`);
  return value;
}

function optional(raw: string | undefined): string | null {
  const value = (raw ?? "").trim();
  return value === "" ? null : value;
}

function secret(raw: string | undefined, name: string, minLength = 1): string {
  const value = raw ?? "";
  if (value.length < minLength) throw new ConfigError(`${name} is missing or too short`);
  return value;
}

/**
 * Reads and checks the configuration. Fails closed: a missing secret or an out-of-range value
 * makes every request answer 500 rather than run with a weaker setting.
 */
export function loadConfig(env: Env): Config {
  const production = (env.ENVIRONMENT ?? "production") === "production";
  const siteUrl = originOf(env.SITE_URL ?? "", "SITE_URL");
  if (production && !siteUrl.startsWith("https://")) throw new ConfigError("SITE_URL must be https in production");

  const allowedOrigins = (env.ALLOWED_ORIGINS ?? siteUrl)
    .split(",")
    .map((o) => o.trim())
    .filter((o) => o !== "")
    .map((o) => originOf(o, "ALLOWED_ORIGINS"));
  if (allowedOrigins.length === 0) throw new ConfigError("ALLOWED_ORIGINS is empty");

  const provider = (env.CONFIRM_PROVIDER ?? "none").trim();
  if (provider !== "none" && provider !== "cloudflare" && provider !== "ses" && provider !== "resend" && provider !== "log") {
    throw new ConfigError("CONFIRM_PROVIDER must be none, cloudflare, ses, resend or log");
  }
  if (provider === "cloudflare" && env.EMAIL === undefined) throw new ConfigError("CONFIRM_PROVIDER=cloudflare needs the EMAIL binding");
  if (production && provider === "log") throw new ConfigError("CONFIRM_PROVIDER=log is for development only");

  const mailFromName = (env.MAIL_FROM_NAME ?? "Zunder").trim();
  // ASCII only, so the name can go into a From header without RFC 2047 encoding.
  if (!/^[A-Za-z0-9 .\-]{1,64}$/.test(mailFromName)) throw new ConfigError("MAIL_FROM_NAME must be 1-64 plain ASCII characters");

  const sesRegion = (env.SES_REGION ?? "eu-central-1").trim();
  if (!/^[a-z]{2}(-[a-z]+)+-\d$/.test(sesRegion)) throw new ConfigError("SES_REGION is not an AWS region");

  let awsAccessKeyId: string | null = null;
  let awsSecretAccessKey: string | null = null;
  let resendApiKey: string | null = null;
  if (provider === "ses") {
    awsAccessKeyId = secret(env.AWS_ACCESS_KEY_ID, "AWS_ACCESS_KEY_ID", 16);
    awsSecretAccessKey = secret(env.AWS_SECRET_ACCESS_KEY, "AWS_SECRET_ACCESS_KEY", 30);
  }
  if (provider === "resend") resendApiKey = secret(env.RESEND_API_KEY, "RESEND_API_KEY", 10);

  const notifyTo = optional(env.NOTIFY_TO);
  if (notifyTo !== null) {
    address(notifyTo, "NOTIFY_TO");
    if (env.NOTIFY_EMAIL === undefined) throw new ConfigError("NOTIFY_TO is set but the NOTIFY_EMAIL binding is missing");
  }
  const includeEmail = (env.NOTIFY_INCLUDE_EMAIL ?? "false").trim();
  if (includeEmail !== "true" && includeEmail !== "false") throw new ConfigError("NOTIFY_INCLUDE_EMAIL must be true or false");

  const unsubscribeSecret = secret(env.UNSUBSCRIBE_SECRET, "UNSUBSCRIBE_SECRET", LIMITS.secretMinLength);
  const adminToken = env.ADMIN_TOKEN === undefined ? null : secret(env.ADMIN_TOKEN, "ADMIN_TOKEN", LIMITS.secretMinLength);

  const consentVersion = (env.CONSENT_VERSION ?? "").trim();
  if (!/^[A-Za-z0-9._-]{1,32}$/.test(consentVersion)) throw new ConfigError("CONSENT_VERSION must be a short identifier");

  const confirmTtlMs =
    intSetting(env.CONFIRM_TTL_HOURS, "CONFIRM_TTL_HOURS", 48, LIMITS.confirmTtlHours.min, LIMITS.confirmTtlHours.max) * HOUR_MS;
  const pendingRetentionMs =
    intSetting(env.PENDING_RETENTION_DAYS, "PENDING_RETENTION_DAYS", 7, LIMITS.pendingRetentionDays.min, LIMITS.pendingRetentionDays.max) *
    DAY_MS;
  if (pendingRetentionMs < confirmTtlMs) throw new ConfigError("PENDING_RETENTION_DAYS must cover CONFIRM_TTL_HOURS");
  const unsentRetentionMs =
    intSetting(env.UNSENT_RETENTION_DAYS, "UNSENT_RETENTION_DAYS", 60, LIMITS.unsentRetentionDays.min, LIMITS.unsentRetentionDays.max) *
    DAY_MS;

  return {
    production,
    siteUrl,
    allowedOrigins,
    confirmProvider: provider,
    mailFrom: address(env.MAIL_FROM, "MAIL_FROM"),
    mailFromName,
    mailReplyTo: env.MAIL_REPLY_TO === undefined || env.MAIL_REPLY_TO.trim() === "" ? null : address(env.MAIL_REPLY_TO, "MAIL_REPLY_TO"),
    sesRegion,
    sesConfigurationSet: optional(env.SES_CONFIGURATION_SET),
    notifyTo,
    notifyFrom: address(env.NOTIFY_FROM ?? "waitlist@zunderlabs.com", "NOTIFY_FROM"),
    notifyIncludeEmail: includeEmail === "true",
    notifyMaxPerDay: intSetting(env.NOTIFY_MAX_PER_DAY, "NOTIFY_MAX_PER_DAY", 50, LIMITS.notifyMaxPerDay.min, LIMITS.notifyMaxPerDay.max),
    consentVersion,
    maxSendsPerDay: intSetting(env.MAX_SENDS_PER_DAY, "MAX_SENDS_PER_DAY", 200, LIMITS.maxSendsPerDay.min, LIMITS.maxSendsPerDay.max),
    confirmTtlMs,
    pendingRetentionMs,
    unsentRetentionMs,
    unsubscribeSecret,
    adminToken,
    issuerToken: env.LICENCE_ISSUER_TOKEN === undefined ? null : secret(env.LICENCE_ISSUER_TOKEN, "LICENCE_ISSUER_TOKEN", LIMITS.secretMinLength),
    awsAccessKeyId,
    awsSecretAccessKey,
    resendApiKey,
  };
}
