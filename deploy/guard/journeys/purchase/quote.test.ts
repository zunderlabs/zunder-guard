// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { randomUUID } from 'node:crypto';
import { test, expect } from '@playwright/test';
import { safe, get, post } from './safe.js';

const origin = new URL(process.env['GUARD_STAGING_URL'] ?? 'http://127.0.0.1:4173').origin;
const domain = process.env['GUARD_EMAIL_DOMAIN'] ?? 'example.test';
const orderToken = process.env['GUARD_ORDER_TOKEN'] ?? 'fixture-only-order-token';

// C4: Pro/month 149 EUR / 1000 rounds to 15 cents. VAT 19% rounds to 3 cents.
for (const row of [
  { label: 'German business', country: 'DE', vatId: '', rate: 1900, vat: 3 },
  { label: 'EU reverse charge', country: 'FR', vatId: 'FRE2EVALID', rate: 0, vat: 0 },
  { label: 'non-EU business', country: 'US', vatId: '', rate: 0, vat: 0 },
  { label: 'invalid VAT ID', country: 'AT', vatId: 'ATE2EINVALID', code: 'vat_id_invalid' },
  { label: 'blocked country', country: 'KP', vatId: '', code: 'blocked_country' },
]) {
  test(`${row.code === 'blocked_country' ? 'P7' : 'P4'} quote: ${row.label}`, async ({ request }) => {
    const status = await get(request, '/api/licence/status', {}, 'quote staging admission');
    expect(status.status()).toBe(200);
    const admission = await safe(() => status.json(), 'quote staging admission JSON');
    expect(admission.ok === true && admission.open === true && admission.chain === 'testnet'
      && admission.profile === 'staging' && admission.priceDivisor === 1000
      && admission.emailDomain === domain && Array.isArray(admission.networks)
      && admission.networks.includes('hyperliquid'), 'open C4 staging required before quote').toBe(true);
    const response = await post(request, '/api/licence/quote', {
      headers: { Origin: origin },
      data: {
        plan: 'pro', term: 'month', accounts: ['0x0000000000000000000000000000000000000001'],
        company: 'Synthetic journey business', street: 'Test street 1', postcode: '10000', city: 'Test city',
        country: row.country, vatId: row.vatId, email: `quote-${randomUUID()}@${domain}`,
        network: 'hyperliquid', chain: 'testnet', business: true, terms: true,
        termsVersion: process.env['GUARD_TERMS_VERSION'] ?? 'guard-1.0',
      },
    }, 'staging quote');
    const body = await safe(() => response.json(), 'staging quote JSON');
    if (row.code) {
      expect(response.status() >= 400 && response.status() < 500, 'quote refused').toBe(true);
      expect(body.ok === false && body.code === row.code && !body.order && !body.token,
        'expected refusal creates no order or token').toBe(true);
      return;
    }
    const order = body.order;
    const number: unknown = order?.number;
    expect(typeof number === 'string' && /^ZL-\d{4}-\d{6}$/.test(number), 'C4 order identity').toBe(true);
    try {
      expect(response.status()).toBe(200);
      expect(body.ok === true && typeof body.token === 'string' && body.token.length > 0,
        'real quote, not dry run').toBe(true);
      expect(order.plan === 'pro' && order.term === 'month' && order.country === row.country
        && order.netCents === 15 && order.vatRateBp === row.rate
        && order.vatCents === row.vat && order.grossCents === 15 + (row.vat ?? 0),
      'C4 hand-computed net, VAT and gross cents').toBe(true);
      expect(order.status === 'awaiting_payment' && order.chain === 'testnet'
        && order.network === 'hyperliquid' && order.delivered === false && order.key === null,
      'unpaid quote, no licence issued').toBe(true);
      expect(typeof order.usdc === 'string' && /^\d+\.\d{1,6}$/.test(order.usdc)
        && Number(order.usdc) > 0, 'positive exact USDC quote').toBe(true);
    } finally {
      const cleanup = await post(request, `/api/licence/test/order/${number}/expire`, {
        headers: { Origin: origin, Authorization: `Bearer ${orderToken}` },
      }, 'quote cleanup');
      expect(cleanup.status()).toBe(200);
      const expired = await safe(() => cleanup.json(), 'quote cleanup JSON');
      expect(expired.ok === true && expired.state === 'expired', 'quote expired without payment').toBe(true);
    }
  });
}
