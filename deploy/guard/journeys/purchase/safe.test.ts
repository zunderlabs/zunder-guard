// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { createServer } from 'node:http';
import { test, expect } from '@playwright/test';
import { safe, get, validInboxMessage, Unanswered } from './safe.js';

test('HTTP failure does not retain secret headers or bodies', async () => {
  const credential = 'fixture-private-header';
  const body = 'fixture-licence-mail';
  let failure: unknown;
  try {
    await safe(async () => { throw new Error(`Authorization: Bearer ${credential}\n${body}`); }, 'inbox');
  } catch (error) {
    failure = error;
  }
  expect(failure instanceof Error).toBe(true);
  const error = failure as Error;
  expect(error.message.includes(credential) || error.message.includes(body)).toBe(false);
  expect(error.stack?.includes(credential) || error.stack?.includes(body)).toBe(false);
  expect(error.cause).toBeUndefined();
  expect(error.message).toContain('inbox failed');
  // Only a request without a response is Unanswered; a failed body read is not.
  expect(error instanceof Unanswered).toBe(false);
});

test('actual request failure does not print bearer headers', async ({ request }) => {
  test.skip(Boolean(process.env['GUARD_STAGING_URL']), 'negative socket control is local only');
  const credential = 'fixture-network-header';
  let failure: unknown;
  try {
    await get(request, 'http://127.0.0.1:1/', {
      headers: { Authorization: `Bearer ${credential}` }, timeout: 1000,
    }, 'loopback negative control');
  } catch (error) {
    failure = error;
  }
  expect(failure instanceof Unanswered).toBe(true);
  expect(String(failure)).toBe('Error: loopback negative control failed; sensitive HTTP diagnostics withheld');
  expect((failure as Error).cause).toBeUndefined();
  expect(String(failure).includes(credential)).toBe(false);
});

test('valid inbox bodies stay available to the licence extractor', async () => {
  const message = {
    id: '00000000-0000-4000-8000-000000000001', to: 'contract@example.test', subject: 'Licence', received_at_ms: 1,
    text: 'fixture-body', html: '<p>fixture-body</p>',
  };
  expect(await safe(async () => message, 'inbox')).toBe(message);
  expect(validInboxMessage(message, 'contract@example.test', 0)).toBe(true);
});

for (const [index, changes] of [
  { id: '' }, { id: 'arbitrary-nonempty-id' }, { to: 'Contract@example.test' }, { to: 'other@example.test' }, { received_at_ms: -1 },
  { received_at_ms: 0.5 }, { text: { private: 'fixture-body' } },
].entries()) {
  test(`inbox shape refuses invalid ${Object.keys(changes)[0]} case ${index}`, async () => {
    const message = {
      id: '00000000-0000-4000-8000-000000000001', to: 'contract@example.test', subject: 'Licence', received_at_ms: 1,
      text: 'fixture-body', html: '<p>fixture-body</p>', ...changes,
    };
    expect(validInboxMessage(message, 'contract@example.test', 0)).toBe(false);
  });
}


test('redirects never forward bearer headers to a second endpoint', async ({ request }) => {
  test.skip(Boolean(process.env['GUARD_STAGING_URL']), 'redirect control is local only');
  const paths: string[] = [];
  const server = createServer((incoming, response) => {
    paths.push(incoming.url ?? '');
    response.writeHead(302, { Location: '/must-not-receive-credentials' });
    response.end();
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('missing fixture port');
    const response = await get(request, `http://127.0.0.1:${address.port}/redirect`, {
      headers: { Authorization: 'Bearer fixture-redirect-header' },
    }, 'redirect control');
    expect(response.status()).toBe(302);
    expect(paths).toEqual(['/redirect']);
  } finally {
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
});
