// Outgoing email. Two separate paths:
//
// - Confirmation emails to subscribers go through a pluggable outbound provider (Mailer):
//   Cloudflare Email Service through the EMAIL binding (primary, from hello@zunderlabs.com),
//   or the fallbacks Amazon SES and Resend (from waitlist@mail.zunderlabs.com). With
//   CONFIRM_PROVIDER=none there is no Mailer and nobody is emailed.
// - Notifications and contact-form messages to Jonas go through the NOTIFY_EMAIL binding and
//   Cloudflare Email Routing, which can only reach the account's verified destinations (Notifier).

import type { Config } from "./config.ts";
import { escapeHtml } from "./pages.ts";
import type { SendEmailBinding } from "./platform.ts";
import { signV4 } from "./sigv4.ts";

export interface OutgoingMail {
  to: string;
  subject: string;
  text: string;
  html: string;
  headers: Record<string, string>;
}

/** An outbound provider for confirmation emails. */
export interface Mailer {
  readonly name: string;
  send(mail: OutgoingMail): Promise<void>;
}

/** Internal messages to Jonas. `replyTo` lets him answer a contact-form sender directly. */
export interface Notifier {
  notify(subject: string, text: string, replyTo?: { email: string; name?: string }, presentation?: { html?: string; name: string }): Promise<void>;
}

export class MailError extends Error {}

function fromHeader(config: Config): string {
  return `${config.mailFromName} <${config.mailFrom}>`;
}

function errorCode(err: unknown): string {
  return typeof err === "object" && err !== null && "code" in err ? String((err as { code: unknown }).code) : "unknown";
}

/**
 * Cloudflare Email Service through the EMAIL `send_email` binding: no API key. Needs Workers Paid
 * and the sending domain onboarded (README, "Cloudflare Email Service"). List-Unsubscribe and
 * List-Unsubscribe-Post are on Email Service's header allowlist.
 */
export function cloudflareMailer(binding: SendEmailBinding, config: Config): Mailer {
  return {
    name: "cloudflare",
    async send(mail) {
      try {
        await binding.send({
          to: mail.to,
          from: { email: config.mailFrom, name: config.mailFromName },
          ...(config.mailReplyTo === null ? {} : { replyTo: config.mailReplyTo }),
          subject: mail.subject,
          text: mail.text,
          html: mail.html,
          headers: mail.headers,
        });
      } catch (err) {
        // The error code is useful (E_SENDER_NOT_VERIFIED, E_RATE_LIMIT_EXCEEDED, ...); the
        // message may name the recipient, so it is not passed on.
        throw new MailError(`cloudflare: ${errorCode(err)}`);
      }
    },
  };
}

/**
 * Amazon SES, API v2 SendEmail (POST /v2/email/outbound-emails), signed with SigV4. The IAM key
 * should be allowed `ses:SendEmail` on the mail.zunderlabs.com identity only (README).
 */
export function sesMailer(config: Config, fetchImpl: typeof fetch = fetch, now: () => number = Date.now): Mailer {
  const accessKeyId = config.awsAccessKeyId ?? "";
  const secretAccessKey = config.awsSecretAccessKey ?? "";
  const endpoint = `https://email.${config.sesRegion}.amazonaws.com/v2/email/outbound-emails`;
  return {
    name: "ses",
    async send(mail) {
      const utf8 = (data: string) => ({ Data: data, Charset: "UTF-8" });
      const body = JSON.stringify({
        FromEmailAddress: fromHeader(config),
        Destination: { ToAddresses: [mail.to] },
        ReplyToAddresses: config.mailReplyTo ? [config.mailReplyTo] : undefined,
        Content: {
          Simple: {
            Subject: utf8(mail.subject),
            Body: { Text: utf8(mail.text), Html: utf8(mail.html) },
            Headers: Object.entries(mail.headers).map(([Name, Value]) => ({ Name, Value })),
          },
        },
        ConfigurationSetName: config.sesConfigurationSet ?? undefined,
      });
      const headers = await signV4({
        method: "POST",
        url: endpoint,
        headers: { "content-type": "application/json" },
        body,
        accessKeyId,
        secretAccessKey,
        region: config.sesRegion,
        service: "ses",
        now: now(),
      });
      const response = await fetchImpl(endpoint, { method: "POST", headers, body });
      if (!response.ok) throw new MailError(`ses: HTTP ${response.status}`);
    },
  };
}

/** Resend, POST https://api.resend.com/emails with a sending-only API key. */
export function resendMailer(config: Config, fetchImpl: typeof fetch = fetch): Mailer {
  const apiKey = config.resendApiKey ?? "";
  return {
    name: "resend",
    async send(mail) {
      const response = await fetchImpl("https://api.resend.com/emails", {
        method: "POST",
        headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
        body: JSON.stringify({
          from: fromHeader(config),
          to: [mail.to],
          reply_to: config.mailReplyTo ?? undefined,
          subject: mail.subject,
          text: mail.text,
          html: mail.html,
          headers: mail.headers,
        }),
      });
      if (!response.ok) throw new MailError(`resend: HTTP ${response.status}`);
    },
  };
}

/** Development only (refused in production by loadConfig): sends nothing, logs no address. */
export function logMailer(): Mailer {
  return {
    name: "log",
    async send(mail) {
      console.log(`[waitlist] CONFIRM_PROVIDER=log: would send "${mail.subject}"`);
    },
  };
}

export function mailerFor(config: Config, bindings: { email?: SendEmailBinding }, fetchImpl: typeof fetch = fetch): Mailer | null {
  switch (config.confirmProvider) {
    case "cloudflare":
      if (bindings.email === undefined) throw new MailError("the EMAIL binding is missing");
      return cloudflareMailer(bindings.email, config);
    case "ses":
      return sesMailer(config, fetchImpl);
    case "resend":
      return resendMailer(config, fetchImpl);
    case "log":
      return logMailer();
    case "none":
      return null;
  }
}

/** Email Routing through the `send_email` binding, to the verified destination in NOTIFY_TO. */
export function routingNotifier(binding: SendEmailBinding, from: string, to: string): Notifier {
  return {
    async notify(subject, text, replyTo, presentation) {
      try {
        await binding.send({
          from: { email: from, name: presentation?.name ?? (replyTo === undefined ? "Zunder waitlist" : "Zunder contact form") },
          to,
          subject,
          text,
          html: presentation?.html ?? brandedMailHtml({ subject, site: "https://zunderlabs.com", preheader: subject,
            eyebrow: replyTo === undefined ? "Zunder · operator notification" : "Zunder · contact form",
            heading: subject, body: `<p style="font:400 16px/1.6 Arial,sans-serif;color:#3F3F45;overflow-wrap:anywhere;word-break:break-word">${escapeHtml(text).replaceAll("\n", "<br>")}</p>` }),
          // A Reply-To object without a name is refused by the binding ("notify: unknown" on 6 Oct 2026); send a bare address then.
          ...(replyTo === undefined ? {} : { replyTo: replyTo.name === undefined ? replyTo.email : replyTo }),
        });
      } catch (err) {
        throw new MailError(`notify: ${errorCode(err)}`);
      }
    },
  };
}

/** The launch offer (pricing accepted by Jonas, 6 Oct 2026; Terms of use 17.7). */
export const LAUNCH_OFFER = "Pro free for 3 months (no builder fee, up to 3 accounts)";

/** Shared double-opt-in design for customer and operator mail. Body is escaped by each template. */
export function brandedMailHtml(args: { subject: string; site: string; preheader: string; eyebrow: string; heading: string; body: string }): string {
  const { subject, site, preheader, eyebrow, heading, body } = args;
  const F = "'Schibsted Grotesk',-apple-system,'Segoe UI',Helvetica,Arial,sans-serif";
  const M = "'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><title>${escapeHtml(subject)}</title>
<style>
/* Clients that run CSS animation (Apple Mail, iOS Mail) get a soft ember pulse on the button; others ignore this. */
@media screen and (prefers-reduced-motion:no-preference){.cta{animation:zpulse 2.4s ease-out .9s 2 both}}
@keyframes zpulse{0%{box-shadow:0 0 0 0 rgba(255,74,28,0)}30%{box-shadow:0 0 0 6px rgba(255,74,28,.28)}100%{box-shadow:0 0 0 14px rgba(255,74,28,0)}}
</style></head>
<body style="margin:0;padding:0;background:#F2F0EB">
<div style="display:none;max-height:0;overflow:hidden;opacity:0">${escapeHtml(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F2F0EB">
<tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px">
<tr><td style="padding:0 0 12px 0"><img src="${escapeHtml(site)}/api/waitlist/assets/strike.gif" width="560" height="140" alt="zunder" style="display:block;width:100%;max-width:560px;height:auto;border:0;outline:none;text-decoration:none;font:700 22px/1 ${F};color:#111113"></td></tr>
<tr><td style="background:#FBFAF7;border:1px solid #DCD9D1;border-radius:24px;padding:40px 36px">
<div style="font:500 11px/1 ${M};letter-spacing:1px;text-transform:uppercase;color:#55555C"><span style="color:#FF4A1C">&#9679;</span>&nbsp;${escapeHtml(eyebrow)}</div>
<h1 style="margin:18px 0 14px;font:600 36px/1.05 ${F};letter-spacing:-1.2px;color:#111113">${escapeHtml(heading)}</h1>
${body}
</td></tr>
<tr><td style="padding:20px 4px 0 4px;font:400 11px/1.6 ${M};color:#8A8A90">Zunder Labs · a brand of orcastrate UG (haftungsbeschränkt)<br><a href="${escapeHtml(site)}/impressum" style="color:#8A8A90">Legal notice</a> &nbsp;·&nbsp; <a href="${escapeHtml(site)}/privacy" style="color:#8A8A90">Privacy</a> &nbsp;·&nbsp; <a href="${escapeHtml(site)}" style="color:#8A8A90">zunderlabs.com</a></td></tr>
</table>
</td></tr></table>
</body></html>`;
}

export function confirmationMail(args: {
  config: Config;
  to: string;
  confirmUrl: string;
  unsubscribeUrl: string;
  ttlHours: number;
  requestedAt: number;
}): OutgoingMail {
  const { config, to, confirmUrl, unsubscribeUrl, ttlHours } = args;
  const site = config.siteUrl;
  const day = new Date(args.requestedAt).toISOString().slice(0, 10);
  const subject = "Confirm your place on the Zunder waitlist";
  const text = [
    "Hello,",
    "",
    `on ${day} (UTC) someone, hopefully you, asked to join the Zunder waitlist at ${site} with this address.`,
    "",
    `Count me in: open this link within ${ttlHours} hours:`,
    confirmUrl,
    "",
    "We will then email you about Zunder Guard's beta and launch, nothing else, and every email",
    "has a link to leave the list.",
    "",
    `Launch offer: on the list before Guard 1.0.0, you get ${LAUNCH_OFFER}.`,
    `Available at the first release. Prices: ${site}/pricing`,
    "",
    "If this was not you, ignore this email: without confirmation the address is deleted",
    "within a week and you will not hear from us. Or delete it right now:",
    unsubscribeUrl,
    "",
    "--",
    "Zunder Labs · a project of orcastrate UG (haftungsbeschränkt)",
    `Legal notice: ${site}/impressum`,
    `Privacy: ${site}/privacy`,
  ].join("\n");

  // Email-safe: tables and inline styles, no SVG, no web fonts required. The mark is the four-point
  // star in ember, the site's spark. Light scheme only, so clients do not invert the brand.
  const F = `'Schibsted Grotesk',-apple-system,'Segoe UI',Helvetica,Arial,sans-serif`;
  const M = `'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace`;
  const html = brandedMailHtml({ subject, site, preheader: "One click to confirm your place on the Zunder waitlist.",
    eyebrow: "Zunder waitlist", heading: "One click, and you're in.", body: `<p style="margin:0 0 24px;font:400 16px/1.55 ${F};color:#3F3F45">On ${escapeHtml(day)} (UTC) someone, hopefully you, asked to join the Zunder waitlist with this address. Confirm within ${ttlHours} hours and we'll email you about Zunder Guard's beta and launch. Nothing else.</p>
<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td class="cta" style="border-radius:999px;background:#FF4A1C"><a href="${escapeHtml(confirmUrl)}" style="display:inline-block;padding:16px 28px;font:700 16px/1 ${F};color:#111113;text-decoration:none;border-radius:999px">Count me in &rarr;</a></td></tr></table>
<p style="margin:24px 0 0;padding:12px 16px;border:1px solid #FFC9B6;background:#FFF1EB;border-radius:14px;font:400 14px/1.5 ${F};color:#111113"><span style="font:500 11px/1 ${M};letter-spacing:1px;text-transform:uppercase;color:#B32E0A">Launch offer</span><br>On the list before Guard 1.0.0, you get ${escapeHtml(LAUNCH_OFFER)}. Available at the first release. <a href="${escapeHtml(site)}/pricing" style="color:#111113">Prices</a></p>
<p style="margin:24px 0 0;font:400 13px/1.5 ${F};color:#6A6A71">Button not working? Paste this into your browser:<br><a href="${escapeHtml(confirmUrl)}" style="color:#6A6A71;word-break:break-all">${escapeHtml(confirmUrl)}</a></p>
<div style="margin:28px 0 0;padding-top:20px;border-top:1px solid #ECE9E2;font:400 13px/1.5 ${F};color:#6A6A71">Not you? Ignore this email: without confirmation the address is deleted within a week. Or <a href="${escapeHtml(unsubscribeUrl)}" style="color:#6A6A71">delete it right now</a>.</div>` });

  return {
    to,
    subject,
    text,
    html,
    headers: {
      // RFC 2369 and RFC 8058: one-click removal from the mail client. Our endpoint accepts the POST.
      "List-Unsubscribe": `<${unsubscribeUrl}>`,
      "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
    },
  };
}
