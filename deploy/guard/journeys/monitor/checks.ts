// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import type { APIRequestContext } from '@playwright/test';
import { expect } from '@playwright/test';
import { get, post, safe } from '../purchase/safe.js';

// This covers the checkout/issuer subset of P9. Canonical signed release admission
// is a separate required check; these passing tests cannot establish whole P9.
export async function checkPages(request: APIRequestContext): Promise<void> {
  for (const path of ['/', '/pricing', '/licence']) {
    const response = await get(request, path, {}, 'production page');
    const html = await safe(() => response.text(), 'production page HTML');
    expect(response.status() === 200 && response.headers()['content-type']?.includes('text/html')
      && /<title[^>]*>[^<]*Zunder/i.test(html) && /<main(?:\s|>)/i.test(html),
    'production page serves branded main content').toBe(true);
  }
}

export async function checkCheckout(request: APIRequestContext): Promise<void> {
  const admission = await get(request, '/api/licence/status', {}, 'production checkout');
  const status = await safe(() => admission.json(), 'production checkout JSON');
  expect(admission.status() === 200 && status.ok === true && status.open === true
    && status.chain === 'mainnet' && Array.isArray(status.networks)
    && ['hyperliquid', 'arbitrum', 'base'].every(network => status.networks.includes(network)),
  'production checkout open on all three networks').toBe(true);
}

export async function checkQuotes(request: APIRequestContext): Promise<void> {
  for (const network of ['hyperliquid', 'arbitrum', 'base']) {
    const response = await post(request, '/api/licence/quote', {
      headers: { Origin: 'https://zunderlabs.com' },
      data: { dry_run: true, email: 'monitor@e2e.zunderlabs.com', plan: 'pro', term: 'month',
        accounts: ['0x0000000000000000000000000000000000000001'], company: 'Synthetic monitor',
        street: 'Test street 1', postcode: '10000', city: 'Test city', country: 'DE', vatId: '',
        network, chain: 'mainnet', business: true, terms: true, termsVersion: 'guard-1.0' },
    }, 'production dry-run quote');
    const body = await safe(() => response.json(), 'production dry-run quote JSON');
    const order = body.order;
    // EUR 14900 cents; 19% German VAT = 2831 cents; gross = 17731 cents.
    // USDC varies with the current EUR rate, so only exact positive decimal shape is fixed.
    expect(response.status() === 200 && body.ok === true && body.dryRun === true
      && !('token' in body) && order && !('id' in order) && !('number' in order)
      && order.network === network && order.chain === 'mainnet' && order.plan === 'pro'
      && order.term === 'month' && order.netCents === 14900 && order.vatRateBp === 1900
      && order.vatCents === 2831 && order.grossCents === 17731
      && typeof order.usdc === 'string' && /^[1-9]\d*\.\d{1,6}$/.test(order.usdc),
    'dry-run response has exact quote arithmetic and no stored-order identity or token').toBe(true);
  }
}

export async function checkRenewal(request: APIRequestContext): Promise<void> {
  const renewal = await post(request, '/api/licence/renewal', {
    headers: { Origin: 'https://zunderlabs.com' }, data: { token: '!' },
  }, 'production malformed renewal');
  const refused = await safe(() => renewal.json(), 'production malformed renewal JSON');
  expect(renewal.status(), 'C5 malformed renewal HTTP status').toBe(404);
  expect(refused.ok === false && refused.code === 'not_found' && !refused.order && !refused.key,
    'malformed renewal refused without a licence').toBe(true);
}

export async function checkHeartbeat(request: APIRequestContext): Promise<void> {
  const heartbeat = await get(request, '/api/licence/issuer/heartbeat', {}, 'production issuer heartbeat');
  const pulse = await safe(() => heartbeat.json(), 'production issuer heartbeat JSON');
  expect(heartbeat.status() === 200 && pulse.ok === true && pulse.fresh === true
    && pulse.chain === 'mainnet' && Number.isSafeInteger(pulse.age_ms)
    && pulse.age_ms >= 0 && pulse.age_ms < 300_000
    && Number.isSafeInteger(pulse.last_poll_at_ms)
    && Math.abs(Date.now() - pulse.last_poll_at_ms) < 300_000,
  'issuer polled within five minutes by server age and local clock').toBe(true);
}
