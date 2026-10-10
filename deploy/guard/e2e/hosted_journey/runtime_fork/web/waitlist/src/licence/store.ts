// All licence SQL. The schema is migrations/0002_licences.sql.

import type { D1Database } from "../platform.ts";
import type { PayNetwork, Plan, Term } from "./core.ts";

export type Chain = "mainnet" | "testnet";
export type OrderStatus = "awaiting_payment" | "paid" | "held" | "delivering" | "delivered" | "expired";

export interface OrderRow {
  id: string;
  number: string;
  token_hash: string;
  status: OrderStatus;
  created_at: number;
  quote_expires_at: number;
  reserved_until: number;
  plan: Plan;
  term: Term;
  accounts: string;
  company: string;
  street: string;
  postcode: string;
  city: string;
  country: string;
  vat_id: string | null;
  vat_check: string | null;
  email: string;
  net_cents: number;
  vat_rate_bp: number;
  vat_cents: number;
  gross_cents: number;
  vat_kind: "de" | "reverse_charge" | "outside_eu";
  vat_note: string;
  rate_micro_eur: number;
  rate_source: string;
  rate_at: number;
  pay_network: PayNetwork;
  chain: Chain;
  pay_to: string;
  amount_micro: number;
  terms_version: string;
  business_confirmed: number;
  paid_at: number | null;
  paid_micro: number | null;
  payment_ref: string | null;
  payer: string | null;
  licence_expires_on: string | null;
  licence_key_sha256: string | null;
  delivered_at: number | null;
  reminded_at: number | null;
  paid_notified_at: number | null;
  delivering_at: number | null;
  held_reason: string | null;
  invoice_status: "to_follow" | "issued";
  /** The licence this order is for: its first order's id and number (renewals inherit them). */
  licence_id: string;
  licence_number: string;
  renews_order_id: string | null;
  term_start: string | null;
  licence_key_enc: string | null;
  reminders: number;
}

export type NewOrder = Omit<OrderRow, "number" | "status" | "paid_at" | "paid_micro" | "payment_ref" | "payer" | "licence_expires_on" | "licence_key_sha256" | "delivered_at" | "reminded_at" | "paid_notified_at" | "delivering_at" | "held_reason" | "invoice_status" | "term_start" | "licence_key_enc" | "reminders">;

const DAY_MS = 86_400_000;

export class LicenceStore {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  /** The next order number of the year: ZL-2026-000001. */
  async nextNumber(year: number): Promise<string> {
    const row = await this.db
      .prepare("INSERT INTO licence_counter (year, last) VALUES (?, 1) ON CONFLICT(year) DO UPDATE SET last = last + 1 RETURNING last")
      .bind(year)
      .first<{ last: number }>();
    if (!row) throw new Error("no order number");
    return `ZL-${year}-${String(row.last).padStart(6, "0")}`;
  }

  /** Inserts an order; false when its amount is taken by another open order (pick another tag). */
  async insert(o: NewOrder & { number: string }): Promise<boolean> {
    try {
      const r = await this.db
        .prepare(
          `INSERT INTO licence_orders (id, number, token_hash, status, created_at, quote_expires_at, reserved_until, plan, term, accounts,
             company, street, postcode, city, country, vat_id, vat_check, email, net_cents, vat_rate_bp, vat_cents, gross_cents, vat_kind,
             vat_note, rate_micro_eur, rate_source, rate_at, pay_network, chain, pay_to, amount_micro, terms_version, business_confirmed,
             licence_id, licence_number, renews_order_id)
           VALUES (?, ?, ?, 'awaiting_payment', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
           ON CONFLICT DO NOTHING`,
        )
        .bind(
          o.id, o.number, o.token_hash, o.created_at, o.quote_expires_at, o.reserved_until, o.plan, o.term, o.accounts,
          o.company, o.street, o.postcode, o.city, o.country, o.vat_id, o.vat_check, o.email, o.net_cents, o.vat_rate_bp, o.vat_cents,
          o.gross_cents, o.vat_kind, o.vat_note, o.rate_micro_eur, o.rate_source, o.rate_at, o.pay_network, o.chain, o.pay_to,
          o.amount_micro, o.terms_version, o.licence_id, o.licence_number, o.renews_order_id,
        )
        .run();
      return r.meta.changes === 1;
    } catch (err) {
      // SQLite reports the partial unique index as a constraint error rather than a conflict to ignore.
      if (err instanceof Error && /UNIQUE|constraint/i.test(err.message)) return false;
      throw err;
    }
  }

  byId(id: string): Promise<OrderRow | null> {
    return this.db.prepare("SELECT * FROM licence_orders WHERE id = ?").bind(id).first<OrderRow>();
  }

  byNumber(number: string): Promise<OrderRow | null> {
    return this.db.prepare("SELECT * FROM licence_orders WHERE number = ?").bind(number).first<OrderRow>();
  }

  /** Orders whose amount is still reserved on a network, oldest first. */
  async open(network: PayNetwork, chain: Chain, now: number): Promise<OrderRow[]> {
    const r = await this.db
      .prepare("SELECT * FROM licence_orders WHERE status = 'awaiting_payment' AND pay_network = ? AND chain = ? AND reserved_until > ? ORDER BY created_at")
      .bind(network, chain, now)
      .all<OrderRow>();
    return r.results;
  }

  /**
   * Records a transfer seen on chain, once. true while it still needs handling (new, or a run
   * failed between recording and matching it); false once it was matched or reported.
   */
  async recordPayment(p: { ref: string; network: PayNetwork; chain: Chain; amountMicro: bigint; payer: string; seenAt: number; paidAt: number }): Promise<boolean> {
    await this.db
      .prepare(
        `INSERT INTO licence_payments (ref, pay_network, chain, amount_micro, payer, seen_at, paid_at) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT DO NOTHING`,
      )
      .bind(p.ref, p.network, p.chain, Number(p.amountMicro), p.payer, p.seenAt, p.paidAt)
      .run();
    const row = await this.db
      .prepare("SELECT handled FROM licence_payments WHERE pay_network = ? AND chain = ? AND ref = ?")
      .bind(p.network, p.chain, p.ref)
      .first<{ handled: number }>();
    return row !== null && row.handled === 0;
  }

  /** Claims an unhandled transfer for this run: false if another run holds it (for 5 minutes). */
  async claimPayment(network: PayNetwork, chain: Chain, ref: string, now: number): Promise<boolean> {
    const r = await this.db
      .prepare(
        `UPDATE licence_payments SET claimed_at = ? WHERE pay_network = ? AND chain = ? AND ref = ? AND handled = 0
           AND (claimed_at IS NULL OR claimed_at < ?)`,
      )
      .bind(now, network, chain, ref, now - 300_000)
      .run();
    return r.meta.changes === 1;
  }

  /** The order a transfer already paid (a run that failed after marking it). */
  orderByPayment(network: PayNetwork, chain: Chain, ref: string): Promise<OrderRow | null> {
    return this.db
      .prepare("SELECT * FROM licence_orders WHERE pay_network = ? AND chain = ? AND payment_ref = ?")
      .bind(network, chain, ref)
      .first<OrderRow>();
  }

  /** Done with a transfer; an order link once set is never cleared. */
  async paymentHandled(network: PayNetwork, chain: Chain, ref: string, orderId: string | null, internal = false): Promise<void> {
    await this.db
      .prepare("UPDATE licence_payments SET handled = 1, internal = ?, order_id = COALESCE(order_id, ?) WHERE pay_network = ? AND chain = ? AND ref = ?")
      .bind(internal ? 1 : 0, orderId, network, chain, ref)
      .run();
  }

  /**
   * When watching `address` on this network began: written on the first call (now), read after.
   * `fresh` is true on that first call, so the caller can skip everything before it.
   */
  async watchStart(network: PayNetwork, chain: Chain, address: string, now: number): Promise<{ startMs: number; fresh: boolean }> {
    const r = await this.db
      .prepare("INSERT INTO licence_watch_start (pay_network, chain, address, start_ms) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING")
      .bind(network, chain, address, now)
      .run();
    const row = await this.db
      .prepare("SELECT start_ms FROM licence_watch_start WHERE pay_network = ? AND chain = ? AND address = ?")
      .bind(network, chain, address)
      .first<{ start_ms: number }>();
    return { startMs: row?.start_ms ?? now, fresh: r.meta.changes === 1 };
  }

  /** Marks the paid (or held) notice as sent; false if it was sent before. */
  async takePaidNotice(id: string, now: number): Promise<boolean> {
    const r = await this.db.prepare("UPDATE licence_orders SET paid_notified_at = ? WHERE id = ? AND paid_notified_at IS NULL").bind(now, id).run();
    return r.meta.changes === 1;
  }

  /** One more order today for this visitor (a salted daily hash of the IP), if under `max`. */
  async takeIpQuota(day: string, ipHash: string, max: number): Promise<boolean> {
    const r = await this.db
      .prepare("INSERT INTO licence_ip_quota (day, ip_hash, n) VALUES (?, ?, 1) ON CONFLICT(day, ip_hash) DO UPDATE SET n = n + 1 WHERE licence_ip_quota.n < ?")
      .bind(day, ipHash, max)
      .run();
    return r.meta.changes === 1;
  }

  /**
   * The open order a payment pays: same network and chain, the exact amount, made while the quote
   * ran (up to 5 minutes late, for clocks and block times). null when none.
   */
  matching(network: PayNetwork, chain: Chain, payTo: string, amountMicro: bigint, paidAt: number): Promise<OrderRow | null> {
    return this.db
      .prepare(
        `SELECT * FROM licence_orders WHERE status = 'awaiting_payment' AND pay_network = ? AND chain = ? AND pay_to = ? AND amount_micro = ?
           AND created_at - 60000 <= ? AND quote_expires_at + 300000 >= ?`,
      )
      .bind(network, chain, payTo, Number(amountMicro), paidAt, paidAt)
      .first<OrderRow>();
  }

  /** Marks an order paid (or held, for a sanctions hit); false if it was not awaiting payment. */
  /**
   * Marks an order paid with its term. `paidUntilSeen` is the licence's paid time the term was
   * computed from: if another renewal was marked paid meanwhile, nothing changes (false) and the
   * caller computes again, so two renewals paid at once never get the same term.
   */
  async markPaid(id: string, p: { status: "paid" | "held"; heldReason: string | null; paidAt: number; paidMicro: bigint; ref: string; payer: string; termStart: string; expiresOn: string; paidUntilSeen?: string | null }): Promise<boolean> {
    const r = await this.db
      .prepare(
        `UPDATE licence_orders SET status = ?, held_reason = ?, paid_at = ?, paid_micro = ?, payment_ref = ?, payer = ?, term_start = ?, licence_expires_on = ?
         WHERE id = ? AND status = 'awaiting_payment'
           AND COALESCE((SELECT MAX(o2.licence_expires_on) FROM licence_orders o2 WHERE o2.licence_id = licence_orders.licence_id
             AND o2.chain = licence_orders.chain AND o2.id <> licence_orders.id AND o2.status IN ('paid', 'held', 'delivering', 'delivered')), '') = ?`,
      )
      .bind(p.status, p.heldReason, p.paidAt, Number(p.paidMicro), p.ref, p.payer, p.termStart, p.expiresOn, id, p.paidUntilSeen ?? "")
      .run();
    return r.meta.changes === 1;
  }

  /** All delivered coverage matters: payments may be discovered out of timestamp order. */
  async deliveryContext(o: OrderRow): Promise<{ until: string | null; blocked: boolean }> {
    const r = await this.db.prepare(`SELECT
      MAX(CASE WHEN status = 'delivered' THEN licence_expires_on END) AS until,
      MAX(CASE WHEN status = 'delivering' OR (status IN ('paid', 'held') AND
        (paid_at < ? OR (paid_at = ? AND number < ?))) THEN 1 ELSE 0 END) AS blocked
      FROM licence_orders WHERE licence_id = ? AND chain = ? AND id <> ?`)
      .bind(o.paid_at, o.paid_at, o.number, o.licence_id, o.chain, o.id)
      .first<{ until: string | null; blocked: number | null }>();
    return { until: r?.until ?? null, blocked: r?.blocked === 1 };
  }

  /** Claim and persist final dates atomically. Other delivery claims and newly delivered
   * coverage invalidate this attempt. A stale own lease may finish before newly found older
   * payments; otherwise those payments and the old lease could deadlock each other. */
  async startDelivery(o: OrderRow, now: number, term: { start: string; end: string }, deliveredUntil: string | null): Promise<boolean> {
    const r = await this.db.prepare(`UPDATE licence_orders
      SET status = 'delivering', delivering_at = ?, term_start = ?, licence_expires_on = ?
      WHERE id = ? AND term_start IS ? AND licence_expires_on IS ?
        AND (status = 'paid' OR (status = 'delivering' AND delivering_at < ?))
        AND NOT EXISTS (SELECT 1 FROM licence_orders other WHERE other.licence_id = licence_orders.licence_id
          AND other.chain = licence_orders.chain AND other.id <> licence_orders.id AND other.status = 'delivering')
        AND (status = 'delivering' OR NOT EXISTS (SELECT 1 FROM licence_orders other
          WHERE other.licence_id = licence_orders.licence_id AND other.chain = licence_orders.chain
          AND other.id <> licence_orders.id AND other.status IN ('paid', 'held')
          AND (other.paid_at < licence_orders.paid_at OR (other.paid_at = licence_orders.paid_at AND other.number < licence_orders.number))))
        AND COALESCE((SELECT MAX(other.licence_expires_on) FROM licence_orders other
          WHERE other.licence_id = licence_orders.licence_id AND other.chain = licence_orders.chain
          AND other.id <> licence_orders.id AND other.status = 'delivered'), '') = ?`)
      .bind(now, term.start, term.end, o.id, o.term_start, o.licence_expires_on, now - 600_000, deliveredUntil ?? "").run();
    return r.meta.changes === 1;
  }

  async abortDelivery(id: string, now: number): Promise<void> {
    // Keep the extended reservation; a failed send never shortens booked time.
    await this.db.prepare("UPDATE licence_orders SET status = 'paid' WHERE id = ? AND status = 'delivering' AND delivering_at = ?").bind(id, now).run();
  }

  async markDelivered(id: string, keySha256: string, keyEnc: string, now: number): Promise<boolean> {
    const r = await this.db
      .prepare("UPDATE licence_orders SET status = 'delivered', licence_key_sha256 = ?, licence_key_enc = ?, delivered_at = ? WHERE id = ? AND status = 'delivering' AND delivering_at = ?")
      .bind(keySha256, keyEnc, now, id, now)
      .run();
    return r.meta.changes === 1;
  }

  async hasPendingDelivery(licenceId: string, chain: Chain): Promise<boolean> {
    const r = await this.db.prepare("SELECT COUNT(*) AS n FROM licence_orders WHERE licence_id = ? AND chain = ? AND status IN ('paid', 'held', 'delivering')")
      .bind(licenceId, chain).first<{ n: number }>();
    return (r?.n ?? 0) > 0;
  }

  // ---- renewal ----

  /** The licence's renewal token generation (1 unless raised by hand to revoke links). */
  async renewalGeneration(licenceId: string): Promise<number> {
    const r = await this.db.prepare("SELECT generation FROM licence_renewal_tokens WHERE licence_id = ?").bind(licenceId).first<{ generation: number }>();
    return r?.generation ?? 1;
  }

  /** Stores the hash of the current token (a rotated secret replaces the old hash). */
  async setRenewalToken(licenceId: string, tokenHash: string, now: number): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO licence_renewal_tokens (licence_id, token_hash, created_at) VALUES (?, ?, ?)
         ON CONFLICT(licence_id) DO UPDATE SET token_hash = excluded.token_hash`,
      )
      .bind(licenceId, tokenHash, now)
      .run();
  }

  async licenceByTokenHash(tokenHash: string): Promise<string | null> {
    const r = await this.db.prepare("SELECT licence_id FROM licence_renewal_tokens WHERE token_hash = ?").bind(tokenHash).first<{ licence_id: string }>();
    return r?.licence_id ?? null;
  }

  /** The licence's newest delivered order on this chain (the one whose key runs longest). */
  latestDelivered(licenceId: string, chain: Chain): Promise<OrderRow | null> {
    return this.db
      .prepare("SELECT * FROM licence_orders WHERE licence_id = ? AND chain = ? AND status = 'delivered' ORDER BY licence_expires_on DESC, delivered_at DESC LIMIT 1")
      .bind(licenceId, chain)
      .first<OrderRow>();
  }

  /** When the licence's paid time on this chain runs out, other orders than `exceptId` counted (YYYY-MM-DD), or null. */
  async paidUntil(licenceId: string, chain: Chain, exceptId: string): Promise<string | null> {
    const r = await this.db
      .prepare("SELECT MAX(licence_expires_on) AS until FROM licence_orders WHERE licence_id = ? AND chain = ? AND id <> ? AND status IN ('paid', 'held', 'delivering', 'delivered')")
      .bind(licenceId, chain, exceptId)
      .first<{ until: string | null }>();
    return r?.until ?? null;
  }

  /** Open renewal orders of a licence. */
  async openRenewals(licenceId: string, now: number): Promise<number> {
    const r = await this.db
      .prepare("SELECT COUNT(*) AS n FROM licence_orders WHERE licence_id = ? AND renews_order_id IS NOT NULL AND status = 'awaiting_payment' AND reserved_until > ?")
      .bind(licenceId, now)
      .first<{ n: number }>();
    return r?.n ?? 0;
  }

  /**
   * Delivered orders whose key runs out within 14 days or ran out within the last 30, and for which
   * no later order of the same licence is paid: candidates for an expiry reminder.
   */
  async expiring(now: number, chain: Chain): Promise<OrderRow[]> {
    const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
    const r = await this.db
      .prepare(
        `SELECT o.* FROM licence_orders o WHERE o.status = 'delivered' AND o.chain = ? AND o.licence_expires_on <= ? AND o.licence_expires_on >= ?
           AND NOT EXISTS (SELECT 1 FROM licence_orders n WHERE n.licence_id = o.licence_id AND n.chain = o.chain AND n.id <> o.id
             AND n.status IN ('paid', 'held', 'delivering', 'delivered')
             AND (n.licence_expires_on > o.licence_expires_on OR (n.licence_expires_on = o.licence_expires_on AND n.id > o.id)))`,
      )
      .bind(chain, day(now + 15 * DAY_MS), day(now - 30 * DAY_MS))
      .all<OrderRow>();
    return r.results;
  }

  /** Sets the stage's bit (and the skipped ones'); false if the stage was sent already (another run). */
  async markReminded(id: string, stageBit: number, bits: number): Promise<boolean> {
    const r = await this.db.prepare("UPDATE licence_orders SET reminders = reminders | ? WHERE id = ? AND (reminders & ?) = 0").bind(bits, id, stageBit).run();
    return r.meta.changes === 1;
  }

  /** Paid, held or stuck orders without a key for a day (and not reminded for a day): Jonas gets a reminder. */
  async undelivered(now: number, automatic = false): Promise<OrderRow[]> {
    const r = await this.db
      .prepare(
        `SELECT * FROM licence_orders WHERE status IN ('paid', 'held', 'delivering') AND paid_at < ?
           AND (reminded_at IS NULL OR reminded_at < ?) ORDER BY paid_at`,
      )
      .bind(now - (automatic ? 600_000 : 86_400_000), now - 86_400_000)
      .all<OrderRow>();
    return r.results;
  }

  async reminded(id: string, now: number): Promise<void> {
    await this.db.prepare("UPDATE licence_orders SET reminded_at = ? WHERE id = ?").bind(now, id).run();
  }

  /** True if no scan of this network ran in the last `gapMs` (and records this one). */
  async takeScan(network: PayNetwork, chain: Chain, now: number, gapMs: number): Promise<boolean> {
    const r = await this.db
      .prepare(
        `INSERT INTO licence_scans (pay_network, chain, at) VALUES (?, ?, ?)
         ON CONFLICT(pay_network, chain) DO UPDATE SET at = excluded.at WHERE licence_scans.at <= ?`,
      )
      .bind(network, chain, now, now - gapMs)
      .run();
    return r.meta.changes === 1;
  }

  /** One order email more today, if under `max`. */
  async takeQuota(day: string, max: number): Promise<boolean> {
    const r = await this.db
      .prepare("INSERT INTO licence_quota (day, sent) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET sent = sent + 1 WHERE licence_quota.sent < ?")
      .bind(day, max)
      .run();
    return r.meta.changes === 1;
  }

  /** Open orders for one email address (at most a few at a time). */
  async openFor(email: string, now: number): Promise<number> {
    const r = await this.db
      .prepare("SELECT COUNT(*) AS n FROM licence_orders WHERE email = ? AND status = 'awaiting_payment' AND reserved_until > ?")
      .bind(email, now)
      .first<{ n: number }>();
    return r?.n ?? 0;
  }

  cursor(network: PayNetwork, chain: Chain): Promise<{ block: number } | null> {
    return this.db.prepare("SELECT block FROM licence_cursors WHERE pay_network = ? AND chain = ?").bind(network, chain).first<{ block: number }>();
  }

  async setCursor(network: PayNetwork, chain: Chain, block: number): Promise<void> {
    await this.db
      .prepare("INSERT INTO licence_cursors (pay_network, chain, block) VALUES (?, ?, ?) ON CONFLICT(pay_network, chain) DO UPDATE SET block = excluded.block")
      .bind(network, chain, block)
      .run();
  }

  /** Only actionable issuance candidates, oldest first, with no customer export. */
  async issuanceCandidates(now: number, chain: Chain): Promise<OrderRow[]> {
    const r = await this.db.prepare(`SELECT * FROM licence_orders o
      WHERE o.chain = ? AND (status = 'paid' OR (status = 'delivering' AND delivering_at < ?))
        AND held_reason IS NULL AND paid_at IS NOT NULL AND paid_micro = amount_micro
        AND payment_ref IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM licence_orders earlier
          WHERE earlier.licence_id = o.licence_id AND earlier.chain = o.chain AND earlier.id <> o.id
          AND (earlier.status = 'delivering' OR (o.status <> 'delivering' AND earlier.status IN ('paid', 'held') AND
            (earlier.paid_at < o.paid_at OR (earlier.paid_at = o.paid_at AND earlier.number < o.number)))))
      ORDER BY paid_at, number LIMIT 10`).bind(chain, now - 600_000).all<OrderRow>();
    return r.results;
  }

  /** Paid and delivered orders for the books (admin export). */
  async paidOrders(): Promise<OrderRow[]> {
    const r = await this.db.prepare("SELECT * FROM licence_orders WHERE status IN ('paid', 'held', 'delivering', 'delivered') ORDER BY number").all<OrderRow>();
    return r.results;
  }

  async unmatchedPayments(): Promise<Record<string, unknown>[]> {
    const r = await this.db.prepare("SELECT * FROM licence_payments WHERE order_id IS NULL AND internal = 0 ORDER BY paid_at").all<Record<string, unknown>>();
    return r.results;
  }

  /** Expired quotes stop reserving their amount; unpaid orders are deleted 30 days after expiry. */
  async purge(now: number): Promise<{ expired: number; deleted: number }> {
    const expired = await this.db.prepare("UPDATE licence_orders SET status = 'expired' WHERE status = 'awaiting_payment' AND reserved_until <= ?").bind(now).run();
    const deleted = await this.db.prepare("DELETE FROM licence_orders WHERE status = 'expired' AND quote_expires_at < ?").bind(now - 30 * DAY_MS).run();
    // Transfers that paid no order: kept 400 days (a year of questions), then deleted.
    await this.db.prepare("DELETE FROM licence_payments WHERE order_id IS NULL AND handled = 1 AND seen_at < ?").bind(now - 400 * DAY_MS).run();
    await this.db.prepare("DELETE FROM licence_quota WHERE day < ?").bind(new Date(now - 7 * DAY_MS).toISOString().slice(0, 10)).run();
    await this.db.prepare("DELETE FROM licence_ip_quota WHERE day < ?").bind(new Date(now - 7 * DAY_MS).toISOString().slice(0, 10)).run();
    return { expired: expired.meta.changes, deleted: deleted.meta.changes };
  }
}
