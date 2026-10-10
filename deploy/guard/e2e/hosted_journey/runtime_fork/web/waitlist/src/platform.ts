// The small part of the Cloudflare Workers runtime this Worker uses, declared here so the source
// type-checks without @cloudflare/workers-types and the tests can supply fakes with the same shape.
// Shapes follow developers.cloudflare.com (D1 client API, Rate Limiting binding, Workers email
// `send_email` binding), read 6 Oct 2026.

export interface D1Result<T = unknown> {
  results: T[];
  success: boolean;
  meta: { changes: number };
}

export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  run(): Promise<D1Result>;
  all<T = Record<string, unknown>>(): Promise<D1Result<T>>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
}

/** Workers Rate Limiting binding (`[[ratelimits]]` in wrangler.toml). */
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

export interface EmailAddress {
  email: string;
  name?: string;
}

/**
 * The `send_email` binding. Used twice: as EMAIL for Cloudflare Email Service (any recipient,
 * Workers Paid, domain onboarded for sending) and as NOTIFY_EMAIL for Email Routing (only the
 * account's verified destination addresses). Errors carry a `code` (E_SENDER_NOT_VERIFIED, ...).
 */
export interface SendEmailBinding {
  send(message: {
    to: string | EmailAddress;
    from: string | EmailAddress;
    subject: string;
    text?: string;
    html?: string;
    replyTo?: string | EmailAddress;
    headers?: Record<string, string>;
  }): Promise<{ messageId: string }>;
}

export interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}

export interface ScheduledController {
  scheduledTime: number;
  cron: string;
}

/** Bindings, vars and secrets as the Worker receives them. Vars are strings; see src/config.ts. */
export interface Env {
  DB: D1Database;
  SIGNUP_LIMITER?: RateLimiter;
  CONTACT_LIMITER?: RateLimiter;
  /** Cloudflare Email Service: confirmation emails to any address (CONFIRM_PROVIDER=cloudflare). */
  EMAIL?: SendEmailBinding;
  /** Email Routing: notifications and contact-form messages to Jonas's verified destination only. */
  NOTIFY_EMAIL?: SendEmailBinding;

  DEPLOYMENT_PROFILE?: string;
  ENVIRONMENT?: string;
  SITE_URL?: string;
  ALLOWED_ORIGINS?: string;
  CONFIRM_PROVIDER?: string;
  MAIL_FROM?: string;
  MAIL_FROM_NAME?: string;
  MAIL_REPLY_TO?: string;
  SES_REGION?: string;
  SES_CONFIGURATION_SET?: string;
  NOTIFY_TO?: string;
  NOTIFY_FROM?: string;
  NOTIFY_INCLUDE_EMAIL?: string;
  NOTIFY_MAX_PER_DAY?: string;
  CONSENT_VERSION?: string;
  MAX_SENDS_PER_DAY?: string;
  CONFIRM_TTL_HOURS?: string;
  PENDING_RETENTION_DAYS?: string;
  UNSENT_RETENTION_DAYS?: string;

  // Licence checkout (src/licence/config.ts): public addresses and URLs only.
  LICENCE_CHAIN?: string;
  SALES_HYPERLIQUID_ADDRESS?: string;
  SALES_EVM_ADDRESS?: string;
  SALES_EVM_NETWORKS?: string;
  LICENCE_PUBLIC_KEY?: string;
  LICENCE_QUOTE_MINUTES?: string;
  ARBITRUM_RPC_URL?: string;
  BASE_RPC_URL?: string;
  SELLER_VAT_ID?: string;

  // Secrets (wrangler secret put). Never in wrangler.toml, never logged.
  UNSUBSCRIBE_SECRET?: string;
  ADMIN_TOKEN?: string;
  LICENCE_ISSUER_TOKEN?: string;
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
  RESEND_API_KEY?: string;
}
