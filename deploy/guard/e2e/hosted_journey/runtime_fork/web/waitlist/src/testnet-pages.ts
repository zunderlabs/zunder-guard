// Separate Pages adapter. No production service binding or origin canonicalisation.
const SITE = 'https://staging.zunderlabs.com';
interface FetchBinding { fetch(request: Request): Promise<Response> }
export interface TestnetPagesEnv {
  DEPLOYMENT_PROFILE?: string;
  TESTNET_SITE_ENABLED?: string;
  TESTNET_JOURNEY_API: FetchBinding;
  TESTNET_INBOX: FetchBinding;
  ASSETS: FetchBinding;
}
const writes = new Set(['quote', 'order', 'order/check', 'renew', 'renewal'].map(p => '/api/licence/' + p));
const issuer = new Set(['jobs', 'deliver'].map(p => '/api/licence/testnet-issuer/' + p));
const refused = () => new Response('Not available', { status: 404, headers: { 'cache-control': 'no-store' } });
export default {
  async fetch(request: Request, env: TestnetPagesEnv): Promise<Response> {
    const url = new URL(request.url);
    if (url.origin !== SITE || env.DEPLOYMENT_PROFILE !== 'staging' || env.TESTNET_SITE_ENABLED !== 'explicitly-provisioned'
      || 'CUSTOMER_API' in env || !env.TESTNET_JOURNEY_API || !env.TESTNET_INBOX) return refused();
    const walletAlias = /^\/(approve|licence)(?:\.html|\/)$/.exec(url.pathname);
    if (walletAlias) {
      url.pathname = '/' + walletAlias[1];
      return new Response(null, { status: 308, headers: { location: url.toString(), 'cache-control': 'no-store', 'x-robots-tag': 'noindex, nofollow' } });
    }
    if (!url.pathname.startsWith('/api/')) {
      const assetHeaders=new Headers(request.headers);
      for(const name of [...assetHeaders.keys()])if(name.toLowerCase().startsWith('cf-access-'))assetHeaders.delete(name);
      assetHeaders.delete('cookie');assetHeaders.delete('authorization');
      const original = await env.ASSETS.fetch(new Request(request,{headers:assetHeaders}));
      const response = new Response(original.body, original);
      response.headers.set('x-robots-tag', 'noindex, nofollow');
      response.headers.set('referrer-policy', 'no-referrer');
      return response;
    }
    const inbox = url.pathname === '/api/testnet-inbox/messages';
    const privileged = inbox || issuer.has(url.pathname);
    if (privileged) {
      const methodOk = inbox ? request.method === 'POST' && !url.search
        : url.pathname.endsWith('/jobs') ? request.method === 'GET' && !url.search
        : request.method === 'POST' && /^\?order=ZL-\d{4}-\d{6}$/.test(url.search);
      if (!methodOk || request.headers.has('origin')
        || !/^Bearer [A-Za-z0-9_-]{43,128}$/.test(request.headers.get('authorization') ?? '')) return refused();
    } else {
      if (url.search) return refused();
      const read = request.method === 'GET' && url.pathname === '/api/licence/status';
      const write = request.method === 'POST' && writes.has(url.pathname) && request.headers.get('origin') === SITE;
      if (!read && !write) return refused();
    }
    const headers = new Headers(request.headers);
    for(const name of [...headers.keys()])if(name.toLowerCase().startsWith('cf-access-'))headers.delete(name);
    for (const name of ['cookie', 'host', 'referer']) headers.delete(name);
    if (!privileged) headers.delete('authorization');
    const upstream = new Request(request, { headers, redirect: 'error' });
    return (inbox ? env.TESTNET_INBOX : env.TESTNET_JOURNEY_API).fetch(upstream);
  },
};
