// Source preparation only. Integrate in the trusted root proxy after fresh review.
// No environment reads, network requests, browser configuration or token persistence.
export const CURRENT_STAGING_HOST = 'zunder-testnet-journey.pages.dev';
export const FUTURE_STAGING_HOST = 'staging.zunderlabs.com';
export type StagingHost = typeof CURRENT_STAGING_HOST | typeof FUTURE_STAGING_HOST;
export interface AccessLease { stagingHost: StagingHost; startedAt: number; deadline: number; tokenExpiresAt: number }
export interface UpstreamTarget { protocol: 'https:'; host: string; port: 443 }
const refuse = (): never => { throw new Error('Staging Access credential refused'); };
const otherHosts = new Set(['api.hyperliquid-testnet.xyz', 'sepolia-rollup.arbitrum.io']);
const empty: Readonly<Record<string,string>> = Object.freeze({});

/** Root memory closure only. Nothing returned belongs in browser, logs or receipts. */
export function createRootAccessHeaders(input: AccessLease, clientId: Buffer, clientSecret: Buffer) {
  const lease = Object.freeze({ ...input });
  const now = Date.now();
  if (![CURRENT_STAGING_HOST,FUTURE_STAGING_HOST].includes(lease.stagingHost)
    || ![lease.startedAt,lease.deadline,lease.tokenExpiresAt].every(Number.isSafeInteger)
    || lease.startedAt > now || lease.deadline <= now || lease.deadline <= lease.startedAt
    || lease.deadline - lease.startedAt > 20 * 60_000 || lease.tokenExpiresAt < lease.deadline
    || !Buffer.isBuffer(clientId) || !Buffer.isBuffer(clientSecret)
    || clientId.length < 16 || clientId.length > 256 || clientSecret.length < 32 || clientSecret.length > 256
    || !/^[A-Za-z0-9._-]+$/.test(clientId.toString('ascii'))
    || !/^[A-Za-z0-9._-]+$/.test(clientSecret.toString('ascii'))
    || [...clientId,...clientSecret].some(byte=>byte>127)) refuse();
  const id = Buffer.from(clientId), secret = Buffer.from(clientSecret);
  let disposed = false;
  return Object.freeze({
    /** Called synchronously after exact upstream admission, directly before https.request. */
    forUpstream(target: UpstreamTarget): Readonly<Record<string,string>> {
      if (disposed || Date.now() >= lease.deadline || Date.now() >= lease.tokenExpiresAt
        || target.protocol !== 'https:' || target.port !== 443) refuse();
      if (target.host === lease.stagingHost) return Object.freeze({
        'CF-Access-Client-Id': id.toString('ascii'),
        'CF-Access-Client-Secret': secret.toString('ascii'),
      });
      if (otherHosts.has(target.host)) return empty;
      return refuse();
    },
    dispose(): void { disposed = true; id.fill(0); secret.fill(0); },
  });
}
