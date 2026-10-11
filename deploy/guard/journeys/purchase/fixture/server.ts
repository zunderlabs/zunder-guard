// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
/** C4 endpoint stand-in. Loopback only; no issuer, wallet or checkout source. */
import { createServer, type ServerResponse } from 'node:http';

const networks = ['hyperliquid', 'arbitrum', 'base'] as const;
const states = ['quoted', 'paid', 'held', 'issued', 'delivered', 'expired'] as const;
type State = typeof states[number];
interface Order {
  state: State;
  network: typeof networks[number];
  amount_micro: number;
  key_issued: boolean;
}
const orders = new Map<string, Order>();
const emailDomain = process.env['GUARD_EMAIL_DOMAIN'] ?? 'example.test';
const token = 'fixture-only-order-token';
const inboxToken = 'fixture-only-inbox-token';

function reply(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  response.end(JSON.stringify(value));
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? '/', 'http://127.0.0.1:4173');
  if (request.method === 'GET' && url.pathname === '/api/licence/status') {
    reply(response, 200, { ok: true, open: true, networks, chain: 'testnet', message: null,
      profile: 'staging', priceDivisor: 1000, emailDomain,
      payTo: Object.fromEntries(networks.map(network =>
        [network, '0x0000000000000000000000000000000000000001'])) });
    return;
  }
  if (request.method === 'POST' && url.pathname === '/api/licence/quote') {
    let body = '';
    for await (const chunk of request) {
      body += String(chunk);
      if (body.length > 4096) { reply(response, 413, { ok: false }); return; }
    }
    try {
      const input = JSON.parse(body) as Record<string, unknown>;
      if (request.headers.origin !== 'http://127.0.0.1:4173' || input['chain'] !== 'testnet') {
        reply(response, 400, { ok: false, code: 'origin_not_allowed' }); return;
      }
      // Finite C4 examples, deliberately not a checkout or payment implementation.
      const cases: Record<string, { vatId: string; vat: number; rate: number } | string> = {
        DE: { vatId: '', vat: 3, rate: 1900 },
        FR: { vatId: 'FRE2EVALID', vat: 0, rate: 0 },
        US: { vatId: '', vat: 0, rate: 0 },
        AT: 'vat_id_invalid', KP: 'blocked_country',
      };
      const row = cases[String(input['country'])];
      if (typeof row === 'string') {
        reply(response, 400, { ok: false, code: row }); return;
      }
      if (!row || input['vatId'] !== row.vatId || input['plan'] !== 'pro'
        || input['term'] !== 'month' || input['network'] !== 'hyperliquid') {
        reply(response, 400, { ok: false, code: 'invalid_fixture_quote' }); return;
      }
      const number = `ZL-2026-${String(orders.size + 1).padStart(6, '0')}`;
      orders.set(number, { state: 'quoted', network: 'hyperliquid', amount_micro: 180000, key_issued: false });
      reply(response, 200, { ok: true, token: 'fixture-only-quote-token', order: {
        number, plan: 'pro', term: 'month', country: input['country'],
        netCents: 15, vatCents: row.vat, vatRateBp: row.rate, grossCents: 15 + row.vat,
        status: 'awaiting_payment', chain: 'testnet', network: 'hyperliquid',
        delivered: false, key: null, usdc: '0.180001',
      } });
    } catch { reply(response, 400, { ok: false, code: 'bad_request' }); }
    return;
  }
  if (url.pathname.startsWith('/api/licence/test/order/')) {
    if (request.headers.authorization !== `Bearer ${token}`) {
      reply(response, 401, { error: 'unauthorized' });
      return;
    }
    const path = url.pathname.slice('/api/licence/test/order/'.length);
    if (request.method === 'POST' && path.endsWith('/expire')) {
      const order = orders.get(path.slice(0, -'/expire'.length));
      if (!order) {
        reply(response, 404, { ok: false, code: 'not_found', message: 'Order not found' });
      } else if (order.state !== 'quoted') {
        reply(response, 409, { ok: false, code: 'not_open', message: 'Order is not open' });
      } else {
        order.state = 'expired';
        reply(response, 200, { ok: true, state: 'expired' });
      }
      return;
    }
    const number = path;
    if (request.method === 'GET') {
      const order = orders.get(number);
      reply(response, order ? 200 : 404, order ?? { error: 'not_found' });
      return;
    }
  }
  if (request.method === 'GET' && url.pathname === '/messages') {
    if (request.headers.authorization !== `Bearer ${inboxToken}`) {
      reply(response, 401, { error: 'unauthorized' });
      return;
    }
    const to = url.searchParams.get('to');
    const since = Number(url.searchParams.get('since'));
    if (!to?.endsWith(`@${emailDomain}`) || !url.searchParams.has('since') || !Number.isSafeInteger(since) || since < 0) {
      reply(response, 400, { error: 'invalid_query' });
      return;
    }
    const message = {
      id: '00000000-0000-4000-8000-000000000001', to: to.toLowerCase(), subject: 'Fixture contract message', received_at_ms: 1,
      text: 'Synthetic fixture content; no licence key.', html: '<p>Synthetic fixture content.</p>',
    };
    reply(response, 200, since <= message.received_at_ms ? [message] : []);
    return;
  }
  // Fixture-only seed route, deliberately separate from the staging API contract.
  if (request.method === 'POST' && url.pathname === '/__fixture/order') {
    let body = '';
    for await (const chunk of request) {
      body += String(chunk);
      if (body.length > 4096) {
        reply(response, 413, { error: 'too_large' });
        return;
      }
    }
    try {
      const input: unknown = JSON.parse(body);
      if (!input || typeof input !== 'object') throw new Error('invalid');
      const record = input as Record<string, unknown>;
      if (typeof record['number'] !== 'string' || !/^[A-Za-z0-9-]+$/.test(record['number'])) throw new Error('invalid');
      if (!states.includes(record['state'] as State)) throw new Error('invalid');
      if (!networks.includes(record['network'] as Order['network'])) throw new Error('invalid');
      if (typeof record['amount_micro'] !== 'number' || !Number.isSafeInteger(record['amount_micro']) || record['amount_micro'] < 0) throw new Error('invalid');
      const state = record['state'] as State;
      orders.set(record['number'], {
        state, network: record['network'] as Order['network'], amount_micro: record['amount_micro'],
        key_issued: state === 'issued' || state === 'delivered',
      });
      reply(response, 201, { ok: true });
    } catch {
      reply(response, 400, { error: 'invalid_fixture_order' });
    }
    return;
  }
  reply(response, 404, { error: 'not_found' });
});
server.listen(4173, '127.0.0.1');
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => server.close());
}
