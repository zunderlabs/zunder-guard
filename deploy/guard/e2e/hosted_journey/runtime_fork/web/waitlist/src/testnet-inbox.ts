// Isolated Email Routing destination. Never import into the production Worker.
import type { D1Database } from './platform.ts';
export const INBOX_ORIGIN = 'https://staging.zunderlabs.com';
export const MAX_MAIL_BYTES = 262144;
const DAY = 86400000;
export interface InboxEnv {
  DEPLOYMENT_PROFILE?: string;
  DB_INBOX_TESTNET: D1Database;
  TESTNET_INBOX_ENABLED?: string;
  TESTNET_INBOX_TO?: string;
  TESTNET_INBOX_TOKEN?: string;
}
interface IncomingMail {
  from: string; to: string; rawSize: number; raw: ReadableStream<Uint8Array>;
  setReject(reason: string): void;
}
function configured(env: InboxEnv): boolean {
  return env.DEPLOYMENT_PROFILE === 'staging' && env.TESTNET_INBOX_ENABLED === 'explicitly-provisioned'
    && !!env.DB_INBOX_TESTNET && !('DB' in env)
    && /^[A-Za-z0-9._%+-]+@zunderlabs\.com$/.test(env.TESTNET_INBOX_TO ?? '')
    && /^[A-Za-z0-9_-]{43,128}$/.test(env.TESTNET_INBOX_TOKEN ?? '');
}
function json(status: number, value: unknown): Response {
  return Response.json(value, { status, headers: { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' } });
}
async function authorized(request: Request, env: InboxEnv): Promise<boolean> {
  const supplied = request.headers.get('authorization') ?? '';
  if (supplied.length > 140) return false;
  const digest = (s: string) => crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  const [left, right] = await Promise.all([digest(supplied), digest(`Bearer ${env.TESTNET_INBOX_TOKEN}`)]);
  const a = new Uint8Array(left), b = new Uint8Array(right);
  let different = 0;
  for (let i = 0; i < a.length; i++) different |= a[i]! ^ b[i]!;
  return different === 0;
}
export default {
  async email(message: IncomingMail, env: InboxEnv): Promise<void> {
    if (!configured(env) || message.to !== env.TESTNET_INBOX_TO || message.from !== 'hello@zunderlabs.com'
      || message.rawSize < 1 || message.rawSize > MAX_MAIL_BYTES) {
      message.setReject('Isolated test inbox only'); return;
    }
    const reader = message.raw.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_MAIL_BYTES) { await reader.cancel(); message.setReject('Message too large'); return; }
        chunks.push(value);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      // Raw UTF-8 RFC822 is retained for MIME parsing by the test process, not rendered.
      const raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      const now = Date.now();
      await env.DB_INBOX_TESTNET.prepare('DELETE FROM testnet_mail WHERE received_at < ?').bind(now - DAY).run();
      const count = await env.DB_INBOX_TESTNET.prepare('SELECT COUNT(*) AS n FROM testnet_mail').first<{n: number}>();
      if (!count || count.n >= 100) { message.setReject('Test inbox capacity reached'); return; }
      await env.DB_INBOX_TESTNET.prepare('INSERT INTO testnet_mail (id, recipient, received_at, raw) VALUES (?, ?, ?, ?)')
        .bind(crypto.randomUUID(), message.to, now, raw).run();
    } finally { reader.releaseLock(); }
  },
  async fetch(request: Request, env: InboxEnv): Promise<Response> {
    const url = new URL(request.url);
    if (!configured(env) || url.origin !== INBOX_ORIGIN || url.pathname !== '/api/testnet-inbox/messages'
      || request.method !== 'POST' || url.search || request.headers.has('origin')
      || !(await authorized(request, env))) return json(404, { ok: false });
    if (Number(request.headers.get('content-length') ?? 0) > 1024) return json(400, { ok: false });
    const reader = request.body?.getReader();
    if (!reader) return json(400, { ok: false });
    let body = '';
    try {
      for (;;) {
        const { value, done } = await reader.read(); if (done) break;
        if (body.length + value.byteLength > 1024) { await reader.cancel(); return json(400, { ok: false }); }
        body += new TextDecoder().decode(value);
      }
    } finally { reader.releaseLock(); }
    let data: { after?: number; recipient?: string };
    try { data = JSON.parse(body) as typeof data; } catch { return json(400, { ok: false }); }
    if (!data || Object.keys(data).sort().join(',') !== 'after,recipient'
      || data.recipient !== env.TESTNET_INBOX_TO || !Number.isSafeInteger(data.after)
      || data.after! < Date.now() - DAY || data.after! > Date.now()) return json(400, { ok: false });
    const rows = await env.DB_INBOX_TESTNET.prepare('SELECT id, recipient, received_at, raw FROM testnet_mail WHERE recipient = ? AND received_at >= ? ORDER BY received_at DESC LIMIT 10')
      .bind(data.recipient, data.after).all();
    return json(200, { ok: true, messages: rows.results });
  },
  async scheduled(_controller: unknown, env: InboxEnv): Promise<void> {
    if (configured(env)) await env.DB_INBOX_TESTNET.prepare('DELETE FROM testnet_mail WHERE received_at < ?').bind(Date.now() - DAY).run();
  },
};
