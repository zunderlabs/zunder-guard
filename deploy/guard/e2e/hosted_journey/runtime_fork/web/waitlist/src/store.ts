// All SQL lives here. The schema is migrations/0001_init.sql.

import type { D1Database } from "./platform.ts";

export interface Subscriber {
  id: string;
  email: string;
  source: string;
  status: "pending" | "confirmed";
  consent_version: string;
  requested_at: number;
  confirmed_at: number | null;
  confirm_token_hash: string | null;
  confirm_expires_at: number | null;
  confirm_sends: number;
  last_sent_at: number | null;
}

export type ExportRow = Pick<
  Subscriber,
  "id" | "email" | "source" | "status" | "consent_version" | "requested_at" | "confirmed_at" | "confirm_sends"
>;

export type SendKind = "confirm" | "notify";

const DAY_MS = 24 * 3_600_000;

export function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

export class Store {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  findByEmail(email: string): Promise<Subscriber | null> {
    return this.db.prepare("SELECT * FROM subscribers WHERE email = ?").bind(email).first<Subscriber>();
  }

  findPendingByTokenHash(hash: string, now: number): Promise<Subscriber | null> {
    return this.db
      .prepare("SELECT * FROM subscribers WHERE confirm_token_hash = ? AND status = 'pending' AND confirm_expires_at > ?")
      .bind(hash, now)
      .first<Subscriber>();
  }

  /** Inserts a pending row without a token. Returns false if the address appeared meanwhile (a race). */
  async insertPending(row: { id: string; email: string; source: string; consentVersion: string; now: number }): Promise<boolean> {
    const result = await this.db
      .prepare(
        `INSERT INTO subscribers (id, email, source, status, consent_version, requested_at)
         VALUES (?, ?, ?, 'pending', ?, ?)
         ON CONFLICT(email) DO NOTHING`,
      )
      .bind(row.id, row.email, row.source, row.consentVersion, row.now)
      .run();
    return result.meta.changes === 1;
  }

  /** Records a repeated submission of a pending address (latest page, wording and time). */
  async refreshRequest(row: { id: string; source: string; consentVersion: string; now: number }): Promise<boolean> {
    const result = await this.db
      .prepare("UPDATE subscribers SET source = ?, consent_version = ?, requested_at = ? WHERE id = ? AND status = 'pending'")
      .bind(row.source, row.consentVersion, row.now, row.id)
      .run();
    return result.meta.changes === 1;
  }

  /** A new confirmation token for a pending row; any earlier token stops working. */
  async setToken(id: string, tokenHash: string, expiresAt: number): Promise<boolean> {
    const result = await this.db
      .prepare("UPDATE subscribers SET confirm_token_hash = ?, confirm_expires_at = ? WHERE id = ? AND status = 'pending'")
      .bind(tokenHash, expiresAt, id)
      .run();
    return result.meta.changes === 1;
  }

  async markSent(id: string, now: number): Promise<void> {
    await this.db.prepare("UPDATE subscribers SET last_sent_at = ?, confirm_sends = confirm_sends + 1 WHERE id = ?").bind(now, id).run();
  }

  /** Confirms by token. Returns the row as it was, or null if the token is unknown, used or expired. */
  async confirm(tokenHash: string, now: number): Promise<{ id: string; source: string; email: string } | null> {
    return this.db
      .prepare(
        `UPDATE subscribers
         SET status = 'confirmed', confirmed_at = ?, confirm_token_hash = NULL, confirm_expires_at = NULL
         WHERE confirm_token_hash = ? AND status = 'pending' AND confirm_expires_at > ?
         RETURNING id, source, email`,
      )
      .bind(now, tokenHash, now)
      .first<{ id: string; source: string; email: string }>();
  }

  /** Deletes the row entirely: unsubscribing leaves nothing behind. Idempotent. */
  async remove(id: string): Promise<void> {
    await this.db.prepare("DELETE FROM subscribers WHERE id = ?").bind(id).run();
  }

  /**
   * Takes one slot of today's budget for a kind of email. Atomic: the counter only moves while it
   * is below the cap, so concurrent requests cannot overshoot it. Returns false at the cap.
   */
  async takeSlot(kind: SendKind, now: number, maxPerDay: number): Promise<boolean> {
    const row = await this.db
      .prepare(
        `INSERT INTO send_counter (day, kind, sent) VALUES (?, ?, 1)
         ON CONFLICT(day, kind) DO UPDATE SET sent = sent + 1 WHERE sent < ?
         RETURNING sent`,
      )
      .bind(utcDay(now), kind, maxPerDay)
      .first<{ sent: number }>();
    return row !== null;
  }

  /** Gives a slot back when the email could not be sent. */
  async returnSlot(kind: SendKind, now: number): Promise<void> {
    await this.db
      .prepare("UPDATE send_counter SET sent = sent - 1 WHERE day = ? AND kind = ? AND sent > 0")
      .bind(utcDay(now), kind)
      .run();
  }

  /** Pending rows that never got a confirmation email (stored while no provider was set), oldest first. */
  async listUnsent(limit: number): Promise<Subscriber[]> {
    const result = await this.db
      .prepare("SELECT * FROM subscribers WHERE status = 'pending' AND confirm_sends = 0 ORDER BY requested_at LIMIT ?")
      .bind(limit)
      .all<Subscriber>();
    return result.results;
  }

  async counts(): Promise<{ confirmed: number; pending: number; unsent: number }> {
    const row = await this.db
      .prepare(
        `SELECT
           COALESCE(SUM(status = 'confirmed'), 0) AS confirmed,
           COALESCE(SUM(status = 'pending'), 0) AS pending,
           COALESCE(SUM(status = 'pending' AND confirm_sends = 0), 0) AS unsent
         FROM subscribers`,
      )
      .first<{ confirmed: number; pending: number; unsent: number }>();
    return { confirmed: Number(row?.confirmed ?? 0), pending: Number(row?.pending ?? 0), unsent: Number(row?.unsent ?? 0) };
  }

  async listForExport(includePending: boolean): Promise<ExportRow[]> {
    const columns = "id, email, source, status, consent_version, requested_at, confirmed_at, confirm_sends";
    const sql = includePending
      ? `SELECT ${columns} FROM subscribers ORDER BY requested_at`
      : `SELECT ${columns} FROM subscribers WHERE status = 'confirmed' ORDER BY confirmed_at`;
    const result = await this.db.prepare(sql).all<ExportRow>();
    return result.results;
  }

  /**
   * Daily housekeeping. Pending rows that were mailed go `pendingRetentionMs` after the last
   * email; pending rows never mailed (no provider yet) go `unsentRetentionMs` after the request.
   * Counters older than a week go too. Returns the rows removed.
   */
  async purge(now: number, pendingRetentionMs: number, unsentRetentionMs: number): Promise<{ pending: number; counters: number }> {
    const pending = await this.db
      .prepare(
        `DELETE FROM subscribers WHERE status = 'pending' AND (
           (confirm_sends > 0 AND last_sent_at < ?) OR (confirm_sends = 0 AND requested_at < ?))`,
      )
      .bind(now - pendingRetentionMs, now - unsentRetentionMs)
      .run();
    const counters = await this.db.prepare("DELETE FROM send_counter WHERE day < ?").bind(utcDay(now - 7 * DAY_MS)).run();
    return { pending: pending.meta.changes, counters: counters.meta.changes };
  }
}
