// Scheduled, private AWS signer. No HTTP handler, arbitrary signing input or customer email access.
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';

export const PUBLIC_KEY = '7e298d8aa9921205f1ef0995b8dc6fedd86a4365fe183825127f8cd56a82af46';
const SITE = 'https://zunderlabs.com';
export interface Job { number: string; chain: string; plan: string; licensee: string; accounts: string[]; start: string; end: string; term: string }

function date(value: unknown): Date {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new Error('Invalid date');
  const d = new Date(`${value}T00:00:00Z`);
  if (!Number.isFinite(d.getTime()) || d.toISOString().slice(0, 10) !== value) throw new Error('Invalid date');
  return d;
}

export function validateJob(value: unknown, now: number): Job {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid job');
  const j = value as Job;
  if (Object.keys(j).sort().join(',') !== 'accounts,chain,end,licensee,number,plan,start,term'
    || !/^ZL-\d{4}-\d{6}$/.test(j.number) || j.chain !== 'mainnet'
    || !['pro', 'fund'].includes(j.plan) || !['month', 'year'].includes(j.term)
    || typeof j.licensee !== 'string' || !j.licensee.trim() || Buffer.byteLength(j.licensee) > 200
    || /[\x00-\x1f\x7f]/.test(j.licensee)
    || !Array.isArray(j.accounts) || j.accounts.length < 1 || j.accounts.length > (j.plan === 'pro' ? 3 : 20)
    || !j.accounts.every(a => typeof a === 'string' && /^0x[0-9a-f]{40}$/.test(a))
    || new Set(j.accounts).size !== j.accounts.length) throw new Error('Invalid entitlement');
  const start = date(j.start); const end = date(j.end);
  const months = j.term === 'month' ? 1 : 12;
  const next = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + months, 1));
  const last = new Date(Date.UTC(next.getUTCFullYear(), next.getUTCMonth() + 1, 0)).getUTCDate();
  next.setUTCDate(Math.min(start.getUTCDate(), last));
  // Calendar anniversary, with at most the established one-day delivery buffer.
  if (![next.getTime(), next.getTime() + 86_400_000].includes(end.getTime()) || end.getTime() <= now) throw new Error('Invalid purchased period');
  return j;
}

export function signingIdentity(secret: string, expectedPublicKey = PUBLIC_KEY) {
  const seed = secret.trim().replace(/^0x/, '');
  if (!/^[a-fA-F0-9]{64}$/.test(seed)) throw new Error('Invalid signing configuration');
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed, 'hex')]);
  let key;
  try { key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }); }
  finally { der.fill(0); }
  const publicKey = createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  if (publicKey !== expectedPublicKey) throw new Error('Unexpected signing identity');
  return key;
}

export function issue(job: Job, secret: string, expectedPublicKey = PUBLIC_KEY): string {
  const key = signingIdentity(secret, expectedPublicKey);
  const payload = Buffer.from(JSON.stringify({ licensee: job.licensee, expires_at_ms: date(job.end).getTime(),
    features: ['fee_free'], accounts: job.accounts }));
  return `zgl1_${payload.toString('base64url')}.${sign(null, payload, key).toString('base64url')}`;
}

export interface IssuerDeps {
  readSecret: (name: string) => Promise<string>;
  fetch: typeof fetch;
  now: () => number;
  publicKey?: string; // Dependency injection only for isolated synthetic tests, never Lambda input.
}

export async function run(deps: IssuerDeps): Promise<{ delivered: number; deferred: number; failed: number }> {
  const token = await deps.readSecret('/zunder/license/issuer-token');
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(token)) throw new Error('Invalid issuer credential');
  const request = async (path: string, init: RequestInit = {}) => deps.fetch(`${SITE}/api/licence/issuer/${path}`, {
    ...init, headers: { authorization: `Bearer ${token}`, 'content-type': 'text/plain' },
    redirect: 'error', signal: AbortSignal.timeout(8_000),
  });
  const response = await request('jobs');
  if (!response.ok) throw new Error('Issuance queue unavailable');
  const body = await response.json() as { ok?: boolean; jobs?: unknown[] };
  if (body.ok !== true || !Array.isArray(body.jobs) || body.jobs.length > 10) throw new Error('Invalid issuance queue');
  const result = { delivered: 0, deferred: 0, failed: 0 };
  if (!body.jobs.length) return result;
  // Validate every job before reading the production key; never sign arbitrary queue JSON.
  const jobs = body.jobs.map(j => validateJob(j, deps.now()));
  const secret = await deps.readSecret('/zunder/license/signing-key');
  const began = deps.now();
  for (const job of jobs) {
    if (deps.now() - began > 30_000) { result.deferred++; continue; }
    try {
      const key = issue(job, secret, deps.publicKey ?? PUBLIC_KEY);
      const sent = await request(`deliver?order=${encodeURIComponent(job.number)}`, { method: 'POST', body: key });
      if (sent.status === 409) { result.deferred++; continue; } // Concurrent/manual delivery or changed term: reread next tick.
      if (!sent.ok) { result.failed++; continue; }
      const receipt = await sent.json() as { ok?: boolean; delivered?: string };
      if (receipt.ok !== true || receipt.delivered !== job.number) { result.failed++; continue; }
      result.delivered++;
    } catch { result.failed++; } // Never include secrets, URLs, response bodies or keys in logs/errors.
  }
  return result;
}

export async function handler(event?: { healthcheck?: boolean }): Promise<{ delivered: number; deferred: number; failed: number; signingIdentityVerified?: boolean }> {
  try {
    // AWS supplies SDK v3 with its Node runtime. No runtime package download.
    const sdkName = '@aws-sdk/client-ssm';
    const { SSMClient, GetParameterCommand } = await import(sdkName);
    const client = new SSMClient({ region: 'eu-central-1', maxAttempts: 2 });
    const readSecret = async (name: string): Promise<string> => {
      const r = await client.send(new GetParameterCommand({ Name: name, WithDecryption: true }));
      if (typeof r.Parameter?.Value !== 'string') throw new Error('Secret unavailable');
      return r.Parameter.Value;
    };
    if (event?.healthcheck === true) signingIdentity(await readSecret('/zunder/license/signing-key'));
    const result = await run({ now: Date.now, fetch, readSecret });
    console.log(JSON.stringify(result));
    if (result.failed) throw new Error('Issuance incomplete');
    return event?.healthcheck === true ? { ...result, signingIdentityVerified: true } : result;
  } catch { throw new Error('Automatic licence issuance failed; inspect queue and service health'); }
}
