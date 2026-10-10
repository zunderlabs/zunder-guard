// Pure test harness boundaries shared by orchestration and offline regression tests.
const ORIGIN = 'https://staging.zunderlabs.com';
export function validTestnetInboxConfig(recipient: unknown, token: unknown): boolean {
  return typeof recipient === 'string' && /^[A-Za-z0-9._%+-]+@zunderlabs\.com$/.test(recipient)
    && typeof token === 'string' && /^[A-Za-z0-9_-]{43,128}$/.test(token);
}
export function testnetCheckoutRequest(url: string, method: string): 'status' | 'quote' | 'order' | 'check' | null {
  try {
    const u = new URL(url);
    if (u.origin !== ORIGIN || u.username || u.password || u.search || u.hash) return null;
    if (u.pathname === '/api/licence/status' && method === 'GET') return 'status';
    if (method !== 'POST') return null;
    if (u.pathname === '/api/licence/quote') return 'quote';
    if (u.pathname === '/api/licence/order') return 'order';
    if (u.pathname === '/api/licence/order/check') return 'check';
    return null;
  } catch { return null; }
}
