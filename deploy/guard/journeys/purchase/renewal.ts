// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { expect, type Page, type APIRequestContext } from '@playwright/test';
import { get, post, safe, validInboxMessage } from './safe.js';
import { command } from './subprocess.js';

export async function renewPurchase(page: Page, request: APIRequestContext, input: {
  origin: string; domain: string; since: number; email: string; token: string; oldKey: string;
  root: string; paymentEnv: NodeJS.ProcessEnv;
}): Promise<string> {
  // The delivered order is remembered per tab; renewal starts a fresh customer session.
  await safe(() => page.evaluate(() => sessionStorage.clear()), 'fresh renewal session');
  await safe(() => page.goto(`/licence#renew=${input.token}`), 'emailed renewal link');
  await safe(() => page.getByTestId('renewal-panel').waitFor({ state: 'visible' }), 'renewal panel');
  const licenceNumber = await safe(() => page.getByTestId('renewal-licence-number').textContent(), 'renewal licence identity');
  expect(Boolean(licenceNumber?.trim()), 'renewal licence shown').toBe(true);
  const [quote] = await safe(() => Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname === '/api/licence/quote' && response.request().method() === 'POST'),
    (async () => {
      await page.getByTestId('checkout-term-month').check();
      await page.getByTestId('checkout-network-hyperliquid').check();
      await page.getByTestId('checkout-business').check();
      await page.getByTestId('checkout-terms').check();
      await page.getByTestId('checkout-quote-submit').click();
    })(),
  ]), 'renewal browser quote');
  const body = await safe(() => quote.json(), 'renewal quote JSON');
  const order = body.order;
  expect(quote.status() === 200 && body.ok === true && typeof body.token === 'string'
    && /^ZL-\d{4}-\d{6}$/.test(order?.number ?? '') && order.renewal === true
    && order.chain === 'testnet' && order.network === 'hyperliquid' && order.status === 'awaiting_payment'
    && order.key === null && order.accounts?.length === 1
    && order.accounts[0]?.toLowerCase() === process.env['GUARD_LICENSE_ACCOUNT']?.toLowerCase(),
  'renewal quote retains original covered account').toBe(true);
  const work = join(input.root, 'renewal-payment');
  await mkdir(work, { mode: 0o700 });
  await command('guard_harness.purchase_payment', ['--order', order.number, '--amount', order.usdc, '--work', work], {
    ...input.paymentEnv, E2E_PAYER_HYPERLIQUID_TESTNET_KEY: process.env['E2E_PAYER_HYPERLIQUID_TESTNET_KEY'],
  });
  const deadline = Date.now() + 10 * 60_000;
  while (Date.now() < deadline) {
    const scan = await post(request, '/api/licence/order/check', { headers: { Origin: input.origin }, data: { id: order.id, token: body.token } }, 'renewal scan');
    expect(scan.status() === 200, 'renewal scan HTTP').toBe(true);
    const stateResponse = await get(request, `/api/licence/test/order/${order.number}`, { headers: { Authorization: `Bearer ${process.env['GUARD_ORDER_TOKEN'] ?? ''}` } }, 'renewal state');
    const state = await safe(() => stateResponse.json(), 'renewal state JSON');
    expect(stateResponse.status() === 200 && ['quoted', 'paid', 'issued', 'delivered'].includes(state.state), 'renewal progresses normally').toBe(true);
    const inboxResponse = await get(request, process.env['GUARD_INBOX_URL'] ?? '', {
      params: { to: input.email, since: String(input.since) }, headers: { Authorization: `Bearer ${process.env['GUARD_INBOX_TOKEN'] ?? ''}` },
    }, 'renewal inbox');
    const inbox = await safe(() => inboxResponse.json(), 'renewal inbox JSON');
    expect(inboxResponse.status() === 200 && Array.isArray(inbox), 'renewal inbox list').toBe(true);
    for (const message of inbox) {
      expect(validInboxMessage(message, input.email, input.since), 'renewal email metadata').toBe(true);
      const key: string | undefined = message.text.match(/\bzgl1_[A-Za-z0-9_-]+/)?.[0];
      if (key && key !== input.oldKey && state.state === 'delivered' && state.key_issued === true) {
        return JSON.stringify({ old_key: input.oldKey, new_key: key, token: input.token });
      }
    }
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  throw new Error('distinct renewed key did not arrive by email');
}
