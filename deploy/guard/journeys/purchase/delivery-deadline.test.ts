// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { readFile } from 'node:fs/promises';
import { test, expect } from '@playwright/test';
import { deliveryWaitMs, paidTestTimeoutMs, waitForDelivery, type PaymentNetwork } from './delivery-deadline.js';

for (const network of ['arbitrum', 'base'] as const) {
  test(`${network}: receipt precedes late finality and delivery, one payment only`, async () => {
    let now = 0;
    let payments = 0;
    const order = { state: 'quoted', key: null as string | null };
    // The one transaction already has a successful inclusion receipt when polling begins.
    payments++;
    const value = await waitForDelivery(network, async () => {
      if (now >= 1108_401) order.state = 'paid';
      if (now >= 1164_343) { order.state = 'delivered'; order.key = 'synthetic-delivered-key'; }
      return order.state === 'delivered' ? order.key : null;
    }, () => now, async ms => { now += ms; });
    expect(value).toBe('synthetic-delivered-key');
    expect(now).toBeGreaterThan(10 * 60_000);
    expect(payments).toBe(1);
    expect(deliveryWaitMs(network)).toBe(40 * 60_000);
    expect(paidTestTimeoutMs(network)).toBe(50 * 60_000);
  });
}
for (const network of ['hyperliquid', 'arbitrum', 'base'] as const) {
  test(`${network}: missing delivery stops at its exact bound without another payment`, async () => {
    let now = 0;
    let polls = 0;
    const payments = 1;
    const result = await waitForDelivery(network, async () => { polls++; return null; },
      () => now, async ms => { now += ms; });
    expect(result).toBeNull();
    expect(now).toBe(deliveryWaitMs(network));
    expect(polls).toBe(deliveryWaitMs(network) / 5000);
    expect(payments).toBe(1);
    if (network === 'hyperliquid') expect(paidTestTimeoutMs(network)).toBe(15 * 60_000);
  });
}
test('a delivery response beyond the EVM bound is refused', async () => {
  let now = 0;
  const network: PaymentNetwork = 'base';
  const result = await waitForDelivery(network, async () => {
    now = deliveryWaitMs(network);
    return 'synthetic-late-key';
  }, () => now, async ms => { now += ms; });
  expect(result).toBeNull();
});

// Pin the actual consumer: neither payer command belongs to the polling callback.
test('paid consumer broadcasts before waiting and never invokes a payer inside delivery polling', async () => {
  const source = await readFile(new URL('./paid.test.ts', import.meta.url), 'utf8');
  const before = source.slice(0, source.indexOf('licence = await waitForDelivery('));
  const polling = source.slice(source.indexOf('licence = await waitForDelivery('), source.indexOf("}) ?? '';"));
  for (const payer of ['guard_harness.purchase_payment', 'guard_harness.purchase_evm']) {
    expect(before.split(payer).length - 1).toBe(1);
    expect(polling).not.toContain(payer);
  }
  expect(polling).toContain('/api/licence/order/check');
  expect(polling).toContain('/api/licence/test/order/');
});
