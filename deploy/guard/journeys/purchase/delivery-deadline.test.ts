// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { readFile } from 'node:fs/promises';
import { test, expect } from '@playwright/test';
import { deliveryWaitMs, paidTestTimeoutMs, toleratedUnansweredPolls, waitForDelivery, type PaymentNetwork } from './delivery-deadline.js';
import { Unanswered, safe } from './safe.js';

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

// A request that got no HTTP response, as `get`/`post` report it: the fixed label only.
const unanswered = (label: string) => new Unanswered(`${label} failed; sensitive HTTP diagnostics withheld`);

test('one unanswered read counts as not yet and the next poll delivers', async () => {
  let now = 0;
  let polls = 0;
  const result = await waitForDelivery('base', async () => {
    polls++;
    if (polls === 1) throw unanswered('paid inbox');
    return 'synthetic-key';
  }, () => now, async ms => { now += ms; });
  expect(result).toBe('synthetic-key');
  expect(polls).toBe(2);
  expect(now).toBe(5000);
});

test('three unanswered polls in a row are tolerated', async () => {
  let now = 0;
  let polls = 0;
  expect(toleratedUnansweredPolls).toBe(3);
  const result = await waitForDelivery('arbitrum', async () => {
    polls++;
    if (polls <= 3) throw unanswered('paid order check');
    return 'synthetic-key';
  }, () => now, async ms => { now += ms; });
  expect(result).toBe('synthetic-key');
  expect(polls).toBe(4);
});

test('a fourth unanswered poll in a row fails with the fixed label', async () => {
  let now = 0;
  let polls = 0;
  let failure: unknown;
  try {
    await waitForDelivery('base', async () => {
      polls++;
      throw unanswered('paid inbox');
    }, () => now, async ms => { now += ms; });
  } catch (error) {
    failure = error;
  }
  expect(polls).toBe(4);
  expect(failure instanceof Unanswered).toBe(true);
  expect((failure as Error).message).toBe('paid inbox failed; sensitive HTTP diagnostics withheld');
  expect((failure as Error).cause).toBeUndefined();
});

test('an answered poll resets the count of unanswered ones', async () => {
  let now = 0;
  let polls = 0;
  // Pattern: 3 unanswered, 1 answered "not yet", 3 unanswered, then delivery.
  const result = await waitForDelivery('base', async () => {
    polls++;
    if (polls === 4) return null;
    if (polls <= 7) throw unanswered('paid order state');
    return 'synthetic-key';
  }, () => now, async ms => { now += ms; });
  expect(result).toBe('synthetic-key');
  expect(polls).toBe(8);
});

test('a response is judged at once: a failed status or JSON check is never retried', async () => {
  for (const failure of [
    // What `expect(...)` throws on a non-200 status: an ordinary error, not Unanswered.
    () => { throw new Error('paid inbox list'); },
    // Bad JSON goes through `safe`, which never reports Unanswered.
    () => safe(async () => { throw new SyntaxError('fixture-body'); }, 'paid inbox JSON'),
  ]) {
    let now = 0;
    let polls = 0;
    let thrown: unknown;
    try {
      await waitForDelivery('base', async () => { polls++; await failure(); return null; },
        () => now, async ms => { now += ms; });
    } catch (error) {
      thrown = error;
    }
    expect(polls).toBe(1);
    expect(thrown instanceof Error && !(thrown instanceof Unanswered)).toBe(true);
    expect(now).toBe(0);
  }
});

test('unanswered polls do not extend the delivery bound', async () => {
  let now = 0;
  let polls = 0;
  const network: PaymentNetwork = 'hyperliquid';
  // Every fourth poll answers "not yet", so the tolerance never runs out; each read hangs 1 s.
  const result = await waitForDelivery(network, async () => {
    polls++;
    now += 1000;
    if (polls % 4 === 0) return null;
    throw unanswered('paid inbox');
  }, () => now, async ms => { now += ms; });
  expect(result).toBeNull();
  expect(now).toBe(deliveryWaitMs(network));
  expect(polls).toBe(deliveryWaitMs(network) / 6000);
});

test('after an unanswered read, a delivery past the bound is still refused', async () => {
  let now = 0;
  let polls = 0;
  const network: PaymentNetwork = 'base';
  const result = await waitForDelivery(network, async () => {
    polls++;
    if (polls === 1) throw unanswered('paid inbox');
    now = deliveryWaitMs(network);
    return 'synthetic-late-key';
  }, () => now, async ms => { now += ms; });
  expect(result).toBeNull();
  expect(polls).toBe(2);
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
  // Only the read-only helpers can report a request without a response; no other request call.
  expect(polling).not.toContain('request.');
  expect(polling).not.toContain('Unanswered');
});
