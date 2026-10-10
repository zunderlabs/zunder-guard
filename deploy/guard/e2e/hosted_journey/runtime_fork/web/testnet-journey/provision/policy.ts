// Exact rehearsal resource identities. No production resource can enter the write plan.
export const ACCOUNT = 'a54357c24cdda7169fb77f53e9df1ddf';
export const DOMAIN = 'zunderlabs.com';
export const SITE = 'zunder-testnet-journey';
export const STAGING_ORIGIN = 'https://staging.zunderlabs.com';
export const WORKERS = ['zunder-testnet-journey-api', 'zunder-testnet-journey-inbox'] as const;
export const DATABASES = ['zunder-testnet-journey', 'zunder-testnet-inbox'] as const;
export const RECIPIENT = 'guard-e2e-20261009@zunderlabs.com';
export const PRODUCTION_DB = '2fac8130-d2e1-4a80-ad6d-2f651fcd98ab';
export const OLD_PREVIEW_DB = 'f3a4acdb-9d5c-42ca-9e17-1d5987fa9f5d';
export const API = 'https://api.cloudflare.com/client/v4';
export const MAX_REQUESTS = 24;
export function readPaths(zone?: string): Set<string> {
  const a='/accounts/'+ACCOUNT;
  const paths=[`/zones?name=${DOMAIN}&account.id=${ACCOUNT}`,`${a}/subscriptions`,`${a}/entitlements`,`${a}/workers/account-settings`,
    `${a}/workers/scripts`,`${a}/d1/database?per_page=100&page=1`,`${a}/pages/projects?per_page=10&page=1`,
    `${a}/email/sending/zones`];
  if(zone && /^[0-9a-f]{32}$/.test(zone)) paths.push(...[
    `/zones/${zone}/email/routing`, `/zones/${zone}/email/routing/dns`,
    `/zones/${zone}/email/routing/rules?per_page=50&page=1`, `/zones/${zone}/email/routing/rules?per_page=50&page=2`,
    `/zones/${zone}/email/routing/rules/catch_all`, `/zones/${zone}/email/sending/subdomains`,
    `/zones/${zone}/dns_records?type=MX&name=${DOMAIN}&per_page=100`,
  ]);
  return new Set(paths);
}
export function requireRead(path:string, zone?:string, method='GET') {
  if(method!=='GET'||!readPaths(zone).has(path)) throw new Error('Read-only Cloudflare scope refused');
}
export function freshDatabaseId(id:unknown): id is string {
  return typeof id==='string' && /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(id)
    && ![PRODUCTION_DB,OLD_PREVIEW_DB,'00000000-0000-0000-0000-000000000000'].includes(id);
}
