// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { test, expect } from '@playwright/test';
import { edgeAmount } from './edge-amount.js';

test('P5 arithmetic changes exactly one micro-USDC without floating point', () => {
  expect(edgeAmount('0.180001', 'under')).toBe('0.180000');
  expect(edgeAmount('0.180001', 'over')).toBe('0.180002');
  expect(edgeAmount('0.18', 'late')).toBe('0.180000');
  expect(edgeAmount('0.18', 'blocked')).toBe('0.180000');
});
for (const amount of ['0.000001', '0.999999', '1.0', '0', 'NaN', '0.0000001']) {
  test(`P5 arithmetic refuses unbounded edge ${amount}`, () => {
    const scenario = amount === '0.999999' ? 'over' : 'under';
    expect(() => edgeAmount(amount, scenario)).toThrow();
  });
}
