// Separate local testnet signer. No AWS SDK, SSM access, mainnet queue, or production key path.
import { issue, PUBLIC_KEY, signingIdentity, validateJob, type Job } from '../auto-issuer/issuer.ts';

export const SITE = 'https://staging.zunderlabs.com';
const PREFIX = '/api/licence/testnet-issuer/';
export interface TestnetIssuerConfig {
  enabled: string;
  site: string;
  publicKey: string;
  issuerToken: string;
  signingSeed: string;
}
export interface TestnetIssuerDeps { fetch: typeof fetch; now: () => number }

export function validateTestnetJob(value: unknown, now: number): Job {
  if (!value || typeof value !== 'object' || Array.isArray(value) || (value as Job).chain !== 'testnet') {
    throw new Error('Testnet entitlement required');
  }
  // Reuse the strict calendar/account/field validator without widening the production signer.
  const job = validateJob({ ...value, chain: 'mainnet' }, now);
  return { ...job, chain: 'testnet' };
}

export async function runTestnet(config: TestnetIssuerConfig, deps: TestnetIssuerDeps) {
  if (config.enabled !== 'explicitly-provisioned' || config.site !== SITE
    || !/^[0-9a-f]{64}$/.test(config.publicKey) || config.publicKey === PUBLIC_KEY
    || !/^[A-Za-z0-9_-]{43,128}$/.test(config.issuerToken)) throw new Error('Isolated testnet issuer configuration required');
  signingIdentity(config.signingSeed, config.publicKey); // Before network: never send credentials with a wrong identity.
  const request = (path: string, init: RequestInit = {}) => deps.fetch(`${SITE}${PREFIX}${path}`, {
    ...init, headers: { authorization: `Bearer ${config.issuerToken}`, 'content-type': 'text/plain' },
    redirect: 'error', signal: AbortSignal.timeout(8_000),
  });
  const response = await request('jobs');
  if (!response.ok) throw new Error('Testnet issuance queue unavailable');
  const body = await response.json() as { ok?: boolean; jobs?: unknown[] };
  if (body.ok !== true || !Array.isArray(body.jobs) || body.jobs.length > 10) throw new Error('Invalid testnet queue');
  const jobs = body.jobs.map(j => validateTestnetJob(j, deps.now()));
  const result = { delivered: 0, deferred: 0, failed: 0 };
  // This rehearsal fulfils at most one order per pass. Any delivery outcome ends the pass;
  // uncertain results must never trigger a second submission in the same invocation.
  const job = jobs[0];
  if (!job) return result;
  try {
    const key = issue(job, config.signingSeed, config.publicKey);
    const sent = await request(`deliver?order=${encodeURIComponent(job.number)}`, { method: 'POST', body: key });
    if (sent.status === 409) { result.deferred++; return result; }
    if (!sent.ok) { result.failed++; return result; }
    const receipt = await sent.json() as { ok?: boolean; delivered?: string };
    if (receipt.ok !== true || receipt.delivered !== job.number) { result.failed++; return result; }
    result.delivered++;
  } catch { result.failed++; }
  return result;
}
