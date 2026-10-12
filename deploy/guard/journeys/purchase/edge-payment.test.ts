// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { test, expect } from '@playwright/test';
import { EDGE_EVENT_WINDOW_MS, matchEdgePayment, type EdgePayment } from './edge-payment.js';

const nonce = 1_700_000_000_000;
const input = { payer: '0x' + '1'.repeat(40), network: 'hyperliquid', amountMicro: 180002,
  orderNumber: null, nonce, observedAt: nonce + 180_000 };
const payment: EdgePayment = { ref: '0x' + 'a'.repeat(64), network: 'hyperliquid', payer: input.payer,
  amount_micro: 180002, order_number: null, paid_at_ms: nonce + 2300,
  seen_at_ms: nonce + 60_000, handled: true, internal: false };

test('P5 unique correct chain event is accepted when its timestamp differs from nonce', () => {
  expect(matchEdgePayment([payment], input)).toBe(payment);
  expect(payment.paid_at_ms).not.toBe(nonce);
  const unrelated = { ...payment, payer: '0x' + '2'.repeat(40), ref: '0x' + 'b'.repeat(64) };
  expect(matchEdgePayment([unrelated, payment], input)).toBe(payment);
});
for (const [label, change] of Object.entries({
  payer: { payer: '0x' + '2'.repeat(40) }, amount: { amount_micro: 180001 },
  network: { network: 'base' }, order: { order_number: 'ZL-2026-000002' },
  stale: { paid_at_ms: nonce - 1 }, late: { paid_at_ms: nonce + EDGE_EVENT_WINDOW_MS + 1 },
  future: { paid_at_ms: input.observedAt + 1 },
})) {
  test(`P5 chain observation rejects ${label}`, () => {
    expect(matchEdgePayment([{ ...payment, ...change }], input)).toBeUndefined();
  });
}

test('P5 blocked payment requires its particular order', () => {
  const order = 'ZL-2026-000001';
  const blocked = { ...payment, order_number: order };
  expect(matchEdgePayment([blocked], { ...input, orderNumber: order })).toBe(blocked);
  expect(matchEdgePayment([payment], { ...input, orderNumber: order })).toBeUndefined();
});

test('P5 duplicate or conflicting matching events fail closed instead of selecting first', () => {
  expect(() => matchEdgePayment([payment, { ...payment }], input)).toThrow('Ambiguous');
  expect(() => matchEdgePayment([payment, { ...payment, ref: '0x' + 'b'.repeat(64) }], input)).toThrow('Ambiguous');
});

test('P5 full latest-event page cannot claim a unique event', () => {
  expect(() => matchEdgePayment(Array.from({ length: 50 }, () => payment), input)).toThrow('Truncated');
});

test('P5 empty or malformed observations never match', () => {
  expect(matchEdgePayment([], input)).toBeUndefined();
  expect(matchEdgePayment([null, [], 'value', {}], input)).toBeUndefined();
});


test('P5 accepts opaque namespaced references without imposing clock ordering', () => {
  const row = { ...payment, ref: 'hyperliquid:transfer/event-42', seen_at_ms: nonce };
  expect(matchEdgePayment([row], input)).toBe(row);
});
for (const [label, change] of Object.entries({
  emptyRef: { ref: '' }, blankRef: { ref: ' ' }, paddedRef: { ref: ' event-42 ' }, oversizedRef: { ref: 'x'.repeat(257) }, controlRef: { ref: 'event\n42' },
  missingRef: { ref: undefined }, fractionalPaid: { paid_at_ms: nonce + 0.5 },
  malformedSeen: { seen_at_ms: 'unknown' }, negativeSeen: { seen_at_ms: -1 },
  malformedHandled: { handled: 'true' }, malformedInternal: { internal: undefined },
})) {
  test(`P5 malformed matching candidate ${label} fails alone and beside valid event`, () => {
    const malformed = { ...payment, ...change };
    expect(() => matchEdgePayment([malformed], input)).toThrow('Malformed edge payment candidate');
    expect(() => matchEdgePayment([payment, malformed], input)).toThrow('Malformed edge payment candidate');
  });
}
