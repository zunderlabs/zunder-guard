// Node-only actual inbox polling and native Rust verification. Never imported by the site.
import PostalMime from 'postal-mime';
import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
const SITE = 'https://staging.zunderlabs.com';
const MAX_RAW = 262144;
const PRODUCTION_KEY = '7e298d8aa9921205f1ef0995b8dc6fedd86a4365fe183825127f8cd56a82af46';
const refused = (): never => { throw new Error('Isolated inbox or verifier check failed'); };
export interface InboxQuery { token: string; recipient: string; orderNumber: string; after: number }
/** Both Playwright and the protected root-native adapter implement this narrow ABI. */
export interface InboxRequest {
  post(url: string, options: { headers: { authorization: string }; data: { recipient: string; after: number }; maxRedirects: number; timeout: number }): Promise<{
    ok(): boolean; body(): Promise<Buffer>; dispose(): Promise<void>;
  }>;
}
export async function parseLicenceMail(raw: string, recipient: string, orderNumber: string) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > MAX_RAW || !/^ZL-\d{4}-\d{6}$/.test(orderNumber)) refused();
  const mail = await PostalMime.parse(raw, { maxNestingDepth: 10, maxHeadersSize: 16384 });
  if (mail.from?.address !== 'hello@zunderlabs.com' || mail.to?.length !== 1 || mail.to[0]?.address !== recipient
    || !mail.subject?.startsWith('[TESTNET]') || !mail.text?.includes(orderNumber)) return null;
  const keys = [...new Set(mail.text.match(/zgl1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g) ?? [])];
  const links = [...new Set(mail.text.match(/https:\/\/staging\.zunderlabs\.com\/licence#order=[A-Za-z0-9_-]{1,100}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g) ?? [])];
  if (!keys.length && !links.length) return null;
  if (keys.length > 1 || links.length > 1) refused();
  return { rawSha256: createHash('sha256').update(raw).digest('hex'), recoveryUrl: links[0] ?? null, licenceKey: keys[0] ?? null };
}
export async function preflightInbox(request: InboxRequest, query: InboxQuery) {
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(query.token) || !/^[A-Za-z0-9._%+-]+@zunderlabs\.com$/.test(query.recipient)
    || !Number.isSafeInteger(query.after) || query.after < Date.now() - 86400000 || query.after > Date.now()) refused();
  const response = await request.post(`${SITE}/api/testnet-inbox/messages`, {
    headers: { authorization: `Bearer ${query.token}` }, data: { recipient: query.recipient, after: query.after }, maxRedirects: 0, timeout: 10000,
  });
  try {
    if (!response.ok()) refused();
    const bytes = await response.body();
    if (bytes.length > MAX_RAW * 11) refused();
    const result = JSON.parse(bytes.toString()) as {ok?: boolean; messages?: unknown[]};
    if (result.ok !== true || !Array.isArray(result.messages) || result.messages.length > 10) refused();
  } finally { await response.dispose(); }
}
export async function receiveLicenceMail(request: InboxRequest, query: InboxQuery, timeoutMs = 180000) {
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(query.token) || !/^[A-Za-z0-9._%+-]+@zunderlabs\.com$/.test(query.recipient)
    || !/^ZL-\d{4}-\d{6}$/.test(query.orderNumber) || !Number.isSafeInteger(query.after)
    || query.after < Date.now() - 86400000 || query.after > Date.now()
    || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000) refused();
  const until = Date.now() + timeoutMs;
  let keyMail: Awaited<ReturnType<typeof parseLicenceMail>> = null;
  let orderMail: Awaited<ReturnType<typeof parseLicenceMail>> = null;
  while (Date.now() < until) {
    const response = await request.post(`${SITE}/api/testnet-inbox/messages`, {
      headers: { authorization: `Bearer ${query.token}` }, data: { recipient: query.recipient, after: query.after }, maxRedirects: 0, timeout: 10000,
    });
    try {
      if (!response.ok()) refused();
      const bytes = await response.body();
      if (bytes.length > MAX_RAW * 11) refused();
      const result = JSON.parse(bytes.toString()) as { ok?: boolean; messages?: { recipient: string; received_at: number; raw: string }[] };
      if (result.ok !== true || !Array.isArray(result.messages) || result.messages.length > 10) refused();
      for (const message of result.messages!) {
        if (message.recipient !== query.recipient || !Number.isSafeInteger(message.received_at) || message.received_at < query.after) refused();
        const mail = await parseLicenceMail(message.raw, query.recipient, query.orderNumber);
        if (mail?.licenceKey) {
          if (keyMail && keyMail.licenceKey !== mail.licenceKey) refused();
          keyMail = mail;
        }
        if (mail?.recoveryUrl) {
          if (orderMail && orderMail.recoveryUrl !== mail.recoveryUrl) refused();
          orderMail = mail;
        }
      }
      if (keyMail?.licenceKey && orderMail?.recoveryUrl) {
        const messageHashes = { order: orderMail.rawSha256, key: keyMail.rawSha256 };
        return { rawSha256: createHash('sha256').update(JSON.stringify(messageHashes)).digest('hex'),
          messageHashes, recoveryUrl: orderMail.recoveryUrl, licenceKey: keyMail.licenceKey };
      }
    } finally { await response.dispose(); }
    await new Promise(resolve => setTimeout(resolve, 3000));
  }
  throw new Error('Actual test inbox delivery not observed before deadline');
}
export async function verifyTestnetLicence(input: { key: string; publicKey: string; owner: string; expectedLicensee: string }, verifierFile: string, expectedSha256: string, assertOriginalAuthority: () => void) {
  const guard = () => { if (typeof assertOriginalAuthority !== 'function') refused(); try { assertOriginalAuthority(); } catch { refused(); } };
  guard();
  // Serialize before the final authority check: no input getter/string conversion runs
  // between that synchronous check and the actual private stdin write.
  const payload = JSON.stringify(input);
  if (!/^[0-9a-f]{64}$/.test(input.publicKey) || input.publicKey === PRODUCTION_KEY
    || !/^0x[0-9a-f]{40}$/.test(input.owner) || !/^[0-9a-f]{64}$/.test(expectedSha256)
    || !path.isAbsolute(verifierFile) || Buffer.byteLength(payload) > 16384) refused();
  const stat = await lstat(verifierFile);
  guard();
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) || stat.size > 100_000_000) refused();
  const verifierBytes = await readFile(verifierFile);
  guard();
  if (createHash('sha256').update(verifierBytes).digest('hex') !== expectedSha256) refused();
  await new Promise<void>((resolve, reject) => {
    guard(); // Final synchronous original authority, immediately before native spawn.
    const child = spawn(verifierFile, [], { env: { PATH: '/usr/bin:/bin' }, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '', bytes = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Rust verifier timed out')); }, 10000);
    child.stdout.on('data', (chunk: Buffer) => { bytes += chunk.length; if (bytes > 1024) child.kill('SIGKILL'); else stdout += chunk.toString(); });
    child.stderr.on('data', (chunk: Buffer) => { bytes += chunk.length; if (bytes > 1024) child.kill('SIGKILL'); });
    child.once('error', () => { clearTimeout(timer); reject(new Error('Rust verifier unavailable')); });
    child.once('close', code => { clearTimeout(timer); try { guard(); if (code === 0 && stdout.trim() === '{"ok":true}' && bytes <= 1024) resolve(); else reject(new Error('Rust licence verification failed')); } catch { reject(new Error('Rust licence verification authority expired')); } });
    child.stdin.on('error', () => {});
    try { guard(); child.stdin.end(payload); } // Final synchronous original authority before private bytes.
    catch { clearTimeout(timer); child.kill('SIGKILL'); reject(new Error('Rust licence verification authority expired')); }
  });
  guard();
}
