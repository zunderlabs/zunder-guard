// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { createServer } from 'node:http';
import type { APIRequestContext } from '@playwright/test';
import { test, expect } from '@playwright/test';
import { checkQuotes, checkRenewal, checkHeartbeat } from '../monitor/checks.js';

async function fixture(
  request: APIRequestContext, status: number, body: unknown,
  check: (client: APIRequestContext) => Promise<void>,
): Promise<string[]> {
  const payloads: string[] = [];
  const server = createServer((incoming, response) => {
    let data = '';
    incoming.on('data', chunk => { data += String(chunk); });
    incoming.on('end', () => {
      payloads.push(data);
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(body));
    });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('fixture address missing');
  // A real local HTTP client; no production/staging credentials or requests.
  const wrapped = { ...request,
    get: (url: string, options: Parameters<APIRequestContext['get']>[1]) =>
      request.get(`http://127.0.0.1:${address.port}${url}`, options),
    post: (url: string, options: Parameters<APIRequestContext['post']>[1]) =>
      request.post(`http://127.0.0.1:${address.port}${url}`, options),
  } as APIRequestContext;
  try {
    await check(wrapped);
    return payloads;
  } finally {
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

test('monitor sends only explicit dry-run quotes and refuses a stored order response', async ({ request }) => {
  // First response falsely contains a real order identity/token; no second quote is sent.
  let payload: unknown;
  await fixture(request, 200, { ok: true, dryRun: false, token: 'synthetic-token', order: { id: 'stored' } },
    async client => {
      const observed = client.post.bind(client);
      client.post = async (url, options) => {
        payload = options?.data;
        return observed(url, options);
      };
      await expect(checkQuotes(client)).rejects.toThrow();
    });
  expect(payload).toMatchObject({ dry_run: true, email: 'monitor@e2e.zunderlabs.com', network: 'hyperliquid' });
});

test('monitor pins malformed renewal to C5 HTTP 404 not_found', async ({ request }) => {
  const payloads = await fixture(request, 404, { ok: false, code: 'not_found' }, checkRenewal);
  expect(payloads.map(value => JSON.parse(value))).toEqual([{ token: '!' }]);
  await fixture(request, 400, { ok: false, code: 'bad_request' }, async client => {
    await expect(checkRenewal(client)).rejects.toThrow();
  });
});

for (const age of [0, 299_999, 300_000, -1]) {
  test(`monitor heartbeat freshness at ${age} milliseconds`, async ({ request }) => {
    await fixture(request, 200, { ok: true, fresh: true, chain: 'mainnet', age_ms: age,
      last_poll_at_ms: Date.now() }, async client => {
      if (age >= 0 && age < 300_000) await checkHeartbeat(client);
      else await expect(checkHeartbeat(client)).rejects.toThrow();
    });
  });
}
test('monitor rejects a future issuer timestamp even when the server claims fresh', async ({ request }) => {
  await fixture(request, 200, { ok: true, fresh: true, chain: 'mainnet', age_ms: 0,
    last_poll_at_ms: Date.now() + 600_000 }, async client => {
    await expect(checkHeartbeat(client)).rejects.toThrow();
  });
});

for (const code of ['bad_request', undefined]) {
  test(`monitor refuses a malformed-renewal body with wrong code ${code}`, async ({ request }) => {
    await fixture(request, 404, { ok: false, code }, async client => {
      await expect(checkRenewal(client)).rejects.toThrow();
    });
  });
}
