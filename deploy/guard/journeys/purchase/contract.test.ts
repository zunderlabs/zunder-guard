// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { test, expect } from '@playwright/test';
import { safe, get, post, validInboxMessage } from './safe.js';

const email = `contract@${process.env['GUARD_EMAIL_DOMAIN'] ?? 'example.test'}`;
const remote = Boolean(process.env['GUARD_STAGING_URL']);
const orderToken = process.env['GUARD_ORDER_TOKEN'] ?? 'fixture-only-order-token';
const inboxToken = process.env['GUARD_INBOX_TOKEN'] ?? 'fixture-only-inbox-token';

// Real staging runs only non-mutating checks; seeded state coverage is fixture-only.
test('order-state endpoint requires authentication', async ({ request }) => {
  const response = await get(request, '/api/licence/test/order/contract-missing', {}, 'order auth check');
  expect(response.status()).toBe(401);
});

test('unknown order is not an empty success', async ({ request }) => {
  const response = await get(request, '/api/licence/test/order/contract-missing', {
    headers: { Authorization: `Bearer ${orderToken}` },
  }, 'missing order check');
  expect(response.status()).toBe(404);
});

test('inbox requires authentication', async ({ request }) => {
  const url = process.env['GUARD_INBOX_URL'] ?? '/messages';
  const response = await get(request, url, { params: { to: email, since: '0' } }, 'inbox auth check');
  expect(response.status()).toBe(401);
});

test('inbox returns the C4 message shape', async ({ request }) => {
  const url = process.env['GUARD_INBOX_URL'] ?? '/messages';
  const since = remote ? Date.now() : 0;
  const response = await get(request, url, {
    params: { to: email, since: String(since) },
    headers: { Authorization: `Bearer ${inboxToken}` },
  }, 'inbox request');
  expect(response.status()).toBe(200);
  const messages: unknown = await safe(() => response.json(), 'inbox JSON');
  expect(Array.isArray(messages)).toBe(true);
  if (!remote) expect((messages as unknown[]).length === 1, 'nonempty fixture inbox control').toBe(true);
  let previousTimestamp = since;
  for (const message of messages as unknown[]) {
    // Boolean assertions prevent a failed shape check printing a licence email/key.
    expect(validInboxMessage(message, email, previousTimestamp), 'C4 inbox metadata, body types and oldest-first order').toBe(true);
    previousTimestamp = (message as { received_at_ms: number }).received_at_ms;
  }
});

for (const state of ['quoted', 'paid', 'held', 'issued', 'delivered', 'expired']) {
  test(`order contract preserves ${state}`, async ({ request }) => {
    test.skip(remote, 'state seeding belongs only to the local fixture');
    const seed = await post(request, '/__fixture/order', { data: {
      number: `contract-${state}`, state, network: 'base', amount_micro: 149_000,
    } }, 'fixture order seed');
    expect(seed.status()).toBe(201);
    const response = await get(request, `/api/licence/test/order/contract-${state}`, {
      headers: { Authorization: `Bearer ${orderToken}` },
    }, 'order state request');
    expect(response.status()).toBe(200);
    expect(await safe(() => response.json(), 'order JSON')).toEqual({
      state, network: 'base', amount_micro: 149_000,
      key_issued: state === 'issued' || state === 'delivered',
    });
  });
}

test('inbox filters messages before the requested timestamp', async ({ request }) => {
  test.skip(remote, 'fixture message timestamp is deterministic');
  const response = await get(request, '/messages', {
    params: { to: email, since: '2' },
    headers: { Authorization: `Bearer ${inboxToken}` },
  }, 'inbox request');
  expect(response.status()).toBe(200);
  expect(await safe(() => response.json(), 'order JSON')).toEqual([]);
});


test('checkout status advertises the C4 testnet profile', async ({ request }) => {
  const response = await get(request, '/api/licence/status', {}, 'checkout status');
  expect(response.status()).toBe(200);
  const value: unknown = await safe(() => response.json(), 'checkout status JSON');
  const status = value as Record<string, unknown> | null;
  // Boolean assertions avoid dumping runtime addresses or sensitive response fields.
  expect(Boolean(status && status['ok'] === true && status['open'] === true &&
    status['chain'] === 'testnet' && status['profile'] === 'staging' &&
    status['priceDivisor'] === 1000 && status['emailDomain'] === email.split('@')[1]),
  'C4 staging checkout profile').toBe(true);
  const networks = status?.['networks'];
  const payTo = status?.['payTo'] as Record<string, unknown> | undefined;
  expect(Array.isArray(networks) && networks.length > 0 &&
    new Set(networks).size === networks.length && networks.every(network =>
      ['hyperliquid', 'arbitrum', 'base'].includes(network) &&
      typeof payTo?.[network] === 'string' && /^0x[0-9a-fA-F]{40}$/.test(payTo[network] as string)),
  'C4 network identifiers and payment addresses').toBe(true);
});

test('expiry control requires authentication', async ({ request }) => {
  const response = await post(request, '/api/licence/test/order/contract-missing/expire',
    { data: {} }, 'expiry auth check');
  expect(response.status()).toBe(401);
});

test('expiry control changes a quoted order once and preserves other states', async ({ request }) => {
  test.skip(remote, 'mutating test controls remain fixture-only');
  for (const state of ['quoted', 'paid', 'held', 'issued', 'delivered', 'expired']) {
    const number = `expiry-${state}`;
    const seed = await post(request, '/__fixture/order', { data: {
      number, state, network: 'hyperliquid', amount_micro: 150_000,
    } }, 'fixture expiry seed');
    expect(seed.status()).toBe(201);
    const options = { headers: { Authorization: `Bearer ${orderToken}` }, data: {} };
    const response = await post(request, `/api/licence/test/order/${number}/expire`,
      options, 'fixture expiry control');
    expect(response.status()).toBe(state === 'quoted' ? 200 : 409);
    const readback = await get(request, `/api/licence/test/order/${number}`, {
      headers: options.headers,
    }, 'fixture expiry readback');
    const body = await safe(() => readback.json(), 'fixture expiry JSON');
    expect(body.state === (state === 'quoted' ? 'expired' : state), 'expiry state preserved').toBe(true);
    if (state === 'quoted') {
      const repeat = await post(request, `/api/licence/test/order/${number}/expire`,
        options, 'fixture repeat expiry');
      expect(repeat.status()).toBe(409);
    }
  }
});
