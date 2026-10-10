// The checkout's emails: to the customer (the order with how to pay, payment received, the key
// with a provisional receipt) and to Jonas (a paid order with the command to issue its key, a
// payment held for a sanctions signal, a payment that matched no order).

import type { Config } from "../config.ts";
import { brandedMailHtml, type OutgoingMail } from "../mail.ts";
import { escapeHtml } from "../pages.ts";
import { NETWORK_LABEL, PLANS, activation, eurText, usdcText } from "./core.ts";
import type { OrderRow } from "./store.ts";

/** The seller, as on the Impressum (web/site/src/copy/impressum.md). */
export const SELLER = [
  "orcastrate UG (haftungsbeschränkt)",
  "Plinganserstr. 55, 81369 München, Germany",
  "Amtsgericht München, HRB 263777 · Managing director: Jonas Grosch",
];

const iso = (ms: number | null) => (ms === null ? "" : new Date(ms).toISOString().replace(".000Z", "Z"));

export function item(o: Pick<OrderRow, "plan" | "term" | "accounts">): string {
  const n = (JSON.parse(o.accounts) as string[]).length;
  return `Zunder Guard ${PLANS[o.plan].name} licence, 1 ${o.term}, ${n} Hyperliquid account${n === 1 ? "" : "s"}`;
}

type MailPresentation = { heading: string; operator?: boolean; action?: { label: string; url: string } };

/** Email-safe tables and inline styles; every dynamic value is escaped, including private links. */
export function licenceEmailHtml(subject: string, text: string, presentation: MailPresentation): string {
  const font = "'Schibsted Grotesk',-apple-system,'Segoe UI',Helvetica,Arial,sans-serif";
  const mono = "ui-monospace,Menlo,Consolas,monospace";
  const paragraphs = text.split(/\n\s*\n/).filter(Boolean).map((paragraph) => {
    const code = /^\s*(?:zgl1_|licence\s*=|deploy\/licence\/)/.test(paragraph);
    return `<p style="margin:0 0 20px;font:400 ${code ? '13' : '15'}px/1.65 ${code ? mono : font};color:#3F3F45;overflow-wrap:anywhere;word-break:break-word;${code ? 'padding:16px;background:#F2F0EB;border:1px solid #DCD9D1;border-radius:10px;' : ''}">${escapeHtml(paragraph).replaceAll("\n", "<br>")}</p>`;
  });
  const action = presentation.action;
  if (action && !/^https:\/\//.test(action.url)) throw new Error("Email action must use HTTPS");
  const button = action ? `<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td class="cta" style="background:#FF4A1C;border-radius:999px"><a href="${escapeHtml(action.url)}" style="display:inline-block;padding:16px 24px;font:600 16px/1.2 ${font};color:#111113;text-decoration:none">${escapeHtml(action.label)} &#8594;</a></td></tr></table>` : "";
  return brandedMailHtml({ subject, site: "https://zunderlabs.com", preheader: presentation.heading,
    eyebrow: presentation.operator ? "Zunder Guard · operator · fulfilment pending" : "Zunder Guard · licences",
    heading: presentation.heading, body: [...paragraphs.slice(0, 2), button ? `<div style="margin:4px 0 24px">${button}</div>` : "", ...paragraphs.slice(2)].join("") });
}

function mail(config: Config, to: string, subject: string, lines: string[], presentation: MailPresentation): OutgoingMail {
  const text = [...lines, "", "--", "Zunder Labs · a brand of orcastrate UG (haftungsbeschränkt)", `${config.siteUrl}/impressum`].join("\n");
  const html = licenceEmailHtml(subject, lines.join("\n"), presentation);
  return { to, subject, text, html, headers: {} };
}

function amounts(o: OrderRow): string[] {
  return [
    `  Net          ${eurText(o.net_cents)}`,
    o.vat_cents > 0 ? `  VAT ${(o.vat_rate_bp / 100).toFixed(0)}%      ${eurText(o.vat_cents)}` : `  VAT          €0.00  (${o.vat_note})`,
    `  Total        ${eurText(o.gross_cents)}`,
  ];
}

export function orderMail(config: Config, o: OrderRow, statusUrl: string): OutgoingMail {
  return mail(config, o.email, `Your Zunder Guard licence order ${o.number}`, [
    `Order ${o.number}: ${item(o)}.`,
    `For ${o.company}, ${o.country}${o.vat_id ? ", VAT ID " + o.vat_id : ""}.`,
    "",
    ...amounts(o),
    "",
    `To pay, send exactly ${usdcText(o.amount_micro)} USDC`,
    `  on ${NETWORK_LABEL[o.pay_network]}${o.chain === "testnet" ? " TESTNET" : ""}`,
    `  to ${o.pay_to}`,
    `  by ${iso(o.quote_expires_at)} (UTC).`,
    "The cents identify your order: send the exact amount, in one transfer.",
    "",
    `Order status: ${statusUrl}`,
    "Keep this link private: once the key is sent, the page it opens shows the key.",
    "",
    "We email your licence key and a provisional receipt once the payment has arrived; the invoice follows.",
  ], { heading: "Your order is ready.", action: { label: "View order & pay", url: statusUrl } });
}

export function paidMail(config: Config, o: OrderRow): OutgoingMail {
  return mail(config, o.email, `Payment received: Zunder Guard licence ${o.number}`, [
    `We received ${usdcText(o.paid_micro ?? 0)} USDC for order ${o.number} (${item(o)}).`,
    "",
    "Your licence key follows automatically in a separate email after payment verification, usually within a few minutes. Your purchased term starts when the key is delivered, or after your existing booked term for an early renewal. The invoice follows after that.",
  ], { heading: "Payment received." });
}

/** The key, with a provisional receipt: everything the invoice will show, marked as not an invoice. */
export function keyMail(config: Config, o: OrderRow, key: string, renewUrl: string): OutgoingMail {
  const accounts = JSON.parse(o.accounts) as string[];
  const a = activation(key);
  return mail(config, o.email, `Your Zunder Guard licence key (${o.number})`, [
    `Your licence key for ${item(o)}, valid ${o.term_start && o.renews_order_id ? "from " + o.term_start + " " : ""}until ${o.licence_expires_on} (00:00 UTC):`,
    "",
    key,
    "",
    "In guard.toml, set or replace this top-level setting before any [section] headings:",
    "",
    `  ${a.command}`,
    "",
    "Keep your existing account, rules and mode. Restart Guard using your existing service, then check its status reports fee.mode = fee_free.",
    `Activation steps for your installation: ${config.siteUrl}${a.guide}`,
    "Guard checks the key on your machine; nothing is sent to us. When it expires, Guard falls back to the 0.02% builder fee and keeps protecting you.",
    "",
    `Renew it, any time before or after it ends (the same plan, accounts and business): ${renewUrl}`,
    "We remind you 14, 7 and 1 days before it ends. Keep this link: it renews this licence.",
    "",
    "PROVISIONAL RECEIPT (not an invoice; the invoice follows by email)",
    "",
    "Seller:",
    ...SELLER.map((l) => "  " + l),
    "",
    "Customer:",
    `  ${o.company}`,
    `  ${o.street}, ${o.postcode} ${o.city}, ${o.country}`,
    ...(o.vat_id ? [`  VAT ID ${o.vat_id}`] : []),
    "",
    `Order ${o.number} of ${iso(o.created_at).slice(0, 10)}`,
    `  ${item(o)}`,
    `  Accounts: ${accounts.join(", ")}`,
    `  Licence period: ${o.renews_order_id && o.term_start ? o.term_start : iso(o.delivered_at ?? o.paid_at).slice(0, 10)} to ${o.licence_expires_on}`,
    ...amounts(o),
    "",
    `Paid ${iso(o.paid_at)}: ${usdcText(o.paid_micro ?? 0)} USDC on ${NETWORK_LABEL[o.pay_network]}${o.chain === "testnet" ? " TESTNET" : ""}`,
    `  transfer ${o.payment_ref}`,
    `  from ${o.payer}`,
    `  EUR value at the quoted rate: ${(o.rate_micro_eur / 1_000_000).toFixed(4)} EUR per USDC (${o.rate_source}, ${iso(o.rate_at)})`,
  ], { heading: "Your Guard licence is ready.", action: { label: "Activate Guard", url: config.siteUrl + a.guide } });
}

export function issueNotice(o: OrderRow, command: string, payerUnchecked: boolean, automatic = false): { subject: string; text: string; html: string } {
  const vies = o.vat_check ? (JSON.parse(o.vat_check) as { name?: string | null; address?: string | null; requestIdentifier?: string | null }) : null;
  const subject = `${o.chain === "testnet" ? "TESTNET " : ""}Licence paid: ${o.number} (${PLANS[o.plan].name}, ${o.term}): ${automatic ? "queued for delivery" : "issue the key"}`;
  const text = [
      `${o.number} is paid: ${usdcText(o.paid_micro ?? 0)} USDC on ${o.pay_network} (${o.chain}), ${o.payment_ref}, from ${o.payer}.`,
      `${item(o)} for ${o.company}, ${o.street}, ${o.postcode} ${o.city}, ${o.country}${o.vat_id ? ", VAT ID " + o.vat_id : ""}. Provisional booked end ${o.licence_expires_on}; the issuer recalculates the full term on delivery.`,
      ...(vies ? [`VIES: ${vies.name ?? "(no name given)"}, ${vies.address ?? "(no address given)"}${vies.requestIdentifier ? ", consultation " + vies.requestIdentifier : ""}. Retain this business-validation record.`] : []),
      ...(payerUnchecked ? [automatic ? "The payer is a Hyperliquid account; no EVM token-blocklist check applies. Checkout country and business validation passed." : "The payer is a Hyperliquid account: no blocklist check exists there. Look at the company and country before issuing."] : []),
      `Accounts: ${(JSON.parse(o.accounts) as string[]).join(", ")}`,
      "",
      automatic ? "Automatic delivery is queued. Only if fulfilment fails, use the recovery command from the repository:" : "Issue and deliver the key on your machine, from the repository:",
      "",
      `  ${command}`,
      "",
      "The script reads the licensee, delivery-based date and exact paid accounts from the Worker, pipes the signing key from SSM into zunder-license and posts only the signed key; the Worker rechecks the date and accounts before delivery. If midnight passed, reissue the key.",
    ].join("\n");
  return { subject, text, html: licenceEmailHtml(subject, text, { heading: "Payment in. Key next.", operator: true }) };
}

export function heldNotice(o: OrderRow, why: string): { subject: string; text: string } {
  return {
    subject: `Licence payment HELD: ${o.number}`,
    text: `${o.number}: payment ${o.payment_ref} from ${o.payer} is held (${why}). No key was sent. Do not refund; check the sanctions process (research/business/crypto-licence-payments.md, 5.6).`,
  };
}

export function unmatchedNotice(p: { network: string; chain: string; ref: string; payer: string; amountMicro: bigint; time: number }): { subject: string; text: string } {
  return {
    subject: `Licence payment without an order: ${usdcText(p.amountMicro)} USDC`,
    text: `${usdcText(p.amountMicro)} USDC arrived on ${p.network} (${p.chain}) at ${iso(p.time)} from ${p.payer} (${p.ref}) and matches no open order: a wrong amount, a late payment, or a second transfer. Settle it by hand.`,
  };
}

/** Before and after the key runs out: the renewal link, and what happens at expiry. */
export function reminderMail(config: Config, o: OrderRow, stage: "14" | "7" | "1" | "expired", renewUrl: string): OutgoingMail {
  const when = stage === "expired" ? `ran out on ${o.licence_expires_on}` : stage === "1" ? `runs out tomorrow, ${o.licence_expires_on} (00:00 UTC)` : `runs out in ${stage} days, on ${o.licence_expires_on} (00:00 UTC)`;
  const subject = stage === "expired"
    ? `Your Zunder Guard licence ${o.licence_number} has ended: Guard is on the 0.02% fee`
    : `Your Zunder Guard licence ${o.licence_number} ends ${stage === "1" ? "tomorrow" : "in " + stage + " days"}`;
  return mail(config, o.email, subject, [
    `Your licence ${o.licence_number} (${item(o)}) ${when}.`,
    "",
    stage === "expired"
      ? "Guard keeps protecting your accounts: it has fallen back to the 0.02% builder fee on its orders. If you have not approved the fee, Guard opens no new positions until you do or renew; closing orders always go."
      : "Renew now and the new term starts when this one ends, so no day is lost. If you do not renew, Guard keeps protecting you and falls back to the 0.02% builder fee.",
    "",
    `Renew (the same plan, accounts and business; you pick a month or a year): ${renewUrl}`,
  ], { heading: stage === "expired" ? "Time to renew." : "Keep your Guard licence running.", action: { label: "Renew licence", url: renewUrl } });
}
