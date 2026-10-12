// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { randomUUID } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test, expect } from '@playwright/test';
import { safe, get, post, validInboxMessage } from './safe.js';
import { command } from './subprocess.js';

import { edgeAmount } from './edge-amount.js';
import { matchEdgePayment } from './edge-payment.js';

test.skip(process.env['GUARD_PAID_JOURNEY'] !== 'P5', 'explicit hosted P5 admission required');
for (const scenario of ['under', 'over', 'late', 'blocked']) {
  test(`P5 ${scenario} payment disposition and operator notice`, async ({ request }) => {
    test.setTimeout(15 * 60_000);
    const origin = process.env['GUARD_STAGING_URL'] ?? '';
    const domain = process.env['GUARD_EMAIL_DOMAIN'] ?? '';
    const root = process.env['GUARD_PURCHASE_WORK'] ?? '';
    expect(Boolean(origin && domain && root), 'complete P5 inputs').toBe(true);
    const pinnedPayTo = process.env['GUARD_PAY_TO_HYPERLIQUID'] ?? '';
    expect(/^0x[0-9a-fA-F]{40}$/.test(pinnedPayTo), 'independently pinned staging merchant').toBe(true);
    const statusResponse = await get(request, '/api/licence/status', {}, 'edge staging admission');
    const status = await safe(() => statusResponse.json(), 'edge staging JSON');
    expect(statusResponse.status() === 200 && status.ok === true && status.open === true
      && status.chain === 'testnet' && status.profile === 'staging' && status.priceDivisor === 1000
      && status.emailDomain === domain && typeof status.payTo?.hyperliquid === 'string'
      && status.payTo.hyperliquid.toLowerCase() === pinnedPayTo.toLowerCase(), 'C4 admission before quote').toBe(true);
    const since = Date.now();
    const email = `edge-${randomUUID()}@${domain}`;
    const quote = await post(request, '/api/licence/quote', { headers: { Origin: origin }, data: {
      plan: 'pro', term: 'month', accounts: [process.env['GUARD_LICENSE_ACCOUNT']], company: 'Synthetic journey business',
      street: 'Test street 1', postcode: '10000', city: 'Test city', country: 'DE', vatId: '', email,
      network: 'hyperliquid', chain: 'testnet', business: true, terms: true,
      termsVersion: process.env['GUARD_TERMS_VERSION'] ?? 'guard-1.0',
    } }, 'edge quote');
    const body = await safe(() => quote.json(), 'edge quote JSON');
    const order = body.order;
    expect(quote.status() === 200 && body.ok === true && typeof body.token === 'string'
      && /^ZL-\d{4}-\d{6}$/.test(order?.number ?? '') && order.status === 'awaiting_payment'
      && order.chain === 'testnet' && order.network === 'hyperliquid' && order.key === null
      && order.payTo === status.payTo?.hyperliquid, 'fresh bound edge quote').toBe(true);
    const headers = { Origin: origin, Authorization: `Bearer ${process.env['GUARD_ORDER_TOKEN'] ?? ''}` };
    if (scenario === 'late') {
      const expired = await post(request, `/api/licence/test/order/${order.number}/expire`, { headers }, 'explicit C4 expiry');
      const value = await safe(() => expired.json(), 'expiry JSON');
      expect(expired.status() === 200 && value.state === 'expired', 'explicit expiry before late payment').toBe(true);
    }
    await mkdir(root, { mode: 0o700, recursive: true });
    const work = join(root, scenario);
    await mkdir(work, { mode: 0o700 });
    await command('guard_harness.purchase_payment', ['--order', order.number, '--amount', edgeAmount(order.usdc, scenario),
      '--scenario', scenario, '--work', work], { PATH: process.env['PATH'], HOME: root,
      GUARD_STAGING_URL: origin, GUARD_PAY_TO_HYPERLIQUID: pinnedPayTo, GUARD_ORDER_TOKEN: process.env['GUARD_ORDER_TOKEN'],
      GUARD_ACCESS_CLIENT_ID: process.env['GUARD_ACCESS_CLIENT_ID'], GUARD_ACCESS_CLIENT_SECRET: process.env['GUARD_ACCESS_CLIENT_SECRET'],
      ...(scenario === 'blocked' ? { E2E_PAYER_BLOCKED_KEY: process.env['E2E_PAYER_BLOCKED_KEY'] }
        : { E2E_PAYER_HYPERLIQUID_TESTNET_KEY: process.env['E2E_PAYER_HYPERLIQUID_TESTNET_KEY'] }),
    });
    const receipt = JSON.parse(await safe(() => readFile(join(work, 'payment-receipt.json'), 'utf8'), 'private payment receipt')) as { nonce: number; payer: string };
    expect(Number.isSafeInteger(receipt.nonce) && /^0x[0-9a-f]{40}$/.test(receipt.payer), 'bounded payment identity').toBe(true);
    let observedRef: string | undefined;
    let found = false;
    const deadline = Date.now() + 10 * 60_000;
    while (Date.now() < deadline) {
      const scan = await post(request, '/api/licence/order/check', { headers: { Origin: origin }, data: { id: order.id, token: body.token } }, 'edge payment scan');
      expect(scan.status() === 200, 'edge scan HTTP').toBe(true);
      const paymentResponse = await get(request, '/api/licence/test/payments', { headers, params: { since: String(since) } }, 'edge payment list');
      const payments = await safe(() => paymentResponse.json(), 'edge payments JSON');
      expect(paymentResponse.status() === 200 && payments.ok === true && Array.isArray(payments.payments), 'C4 payments list').toBe(true);
      const amount = Number(BigInt(edgeAmount(order.usdc, scenario).slice(2)));
      const row = matchEdgePayment(payments.payments, {
        amountMicro: amount, payer: receipt.payer, nonce: receipt.nonce, network: 'hyperliquid',
        orderNumber: scenario === 'blocked' ? order.number : null, observedAt: Date.now(),
      });
      if (row) {
        expect(observedRef === undefined || observedRef === row.ref, 'same unique transfer throughout observation').toBe(true);
        observedRef = row.ref;
      }
      const stateResponse = await get(request, `/api/licence/test/order/${order.number}`, { headers }, 'edge state');
      const state = await safe(() => stateResponse.json(), 'edge state JSON');
      expect(stateResponse.status() === 200 && state.key_issued === false, 'edge never issues licence').toBe(true);
      if (row && row.handled === true && row.internal === false) {
        expect(state.state === (scenario === 'blocked' ? 'held' : scenario === 'late' ? 'expired' : 'quoted'), 'exact edge disposition').toBe(true);
        if (scenario === 'blocked') { found = true; break; }
        const operator = `operator@${domain}`;
        const inboxResponse = await get(request, process.env['GUARD_INBOX_URL'] ?? '', { params: { to: operator, since: String(since) },
          headers: { Authorization: `Bearer ${process.env['GUARD_INBOX_TOKEN'] ?? ''}` } }, 'edge operator inbox');
        const inbox = await safe(() => inboxResponse.json(), 'operator inbox JSON');
        expect(inboxResponse.status() === 200 && Array.isArray(inbox), 'operator inbox list').toBe(true);
        for (const message of inbox) {
          expect(validInboxMessage(message, operator, since), 'operator message metadata').toBe(true);
          if ((message.subject + '\n' + message.text).includes('Licence payment without an order:')
            && message.text.includes(row.ref)) found = true;
        }
        if (found) break;
      }
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
    expect(found, 'edge payment observed with required operator notice or held state').toBe(true);
    if (scenario === 'under' || scenario === 'over') {
      const expired = await post(request, `/api/licence/test/order/${order.number}/expire`, { headers }, 'unmatched quote cleanup');
      expect(expired.status() === 200, 'unmatched quote expired').toBe(true);
    }
  });
}
