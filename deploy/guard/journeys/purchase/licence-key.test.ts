// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { test, expect } from '@playwright/test';
import { emailedLicence } from './licence-key.js';

const key = `zgl1_payload.${'A'.repeat(86)}`;
test('complete signed token survives the actual email paragraph', () => {
  expect(emailedLicence(`Your licence:\n\n${key}\n\nKeep this key.`)).toBe(key);
  expect(emailedLicence('Delivery pending')).toBeUndefined();
});
for (const [index, token] of ['zgl1_payload', `${key}.extra`, `${key}A`, key.slice(0, -1),
  `zgl1_${'A'.repeat(4005)}.${'A'.repeat(86)}`, `${key}"`, `${key}\n${key}`].entries()) {
  test(`malformed or ambiguous token refused ${index}`, () => {
    expect(() => emailedLicence(token)).toThrow('Emailed licence token malformed or ambiguous');
  });
}
test('maximum complete token accepted without truncation', () => {
  const maximum = `zgl1_${'A'.repeat(4004)}.${'A'.repeat(86)}`;
  expect(maximum.length).toBe(4096);
  expect(emailedLicence(maximum)).toBe(maximum);
});
