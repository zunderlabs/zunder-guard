// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { readFile } from 'node:fs/promises';
import { test, expect, type APIRequestContext } from '@playwright/test';
import { quoteMailWaitMs, requireQuoteMail } from './quote-mail-admission.js';

const input = { inboxUrl: 'https://inbox.example.test/messages', token: 'fixture-private-token',
  email: 'quote@example.test', since: 1000, order: 'ZL-2026-000123' };
const message = { id: '00000000-0000-4000-8000-000000000001', to: input.email,
  subject: `Your Zunder Guard licence order ${input.order}`, received_at_ms: 1001,
  text: `Order ${input.order}: synthetic purchase.\nPRIVATE-BODY-SENTINEL`, html: '<p>PRIVATE-BODY-SENTINEL</p>' };

function fixture(messages: unknown, status = 200, delay = 0) {
  let now = 0;
  let reads = 0;
  let payers = 0;
  const request = { async get(_url: string, options: Record<string, unknown>) {
    reads++;
    expect(options['maxRedirects']).toBe(0);
    expect(options['timeout']).toBeLessThanOrEqual(5000);
    expect(options['timeout']).toBeGreaterThan(0);
    now += delay;
    return { status: () => status, json: async () => messages };
  } } as unknown as APIRequestContext;
  return { clock: () => now, advance: (ms: number) => { now += ms; }, reads: () => reads, payers: () => payers,
    async attempt() {
      await requireQuoteMail(request, input, () => now, async ms => { now += ms; });
      payers++;
    } };
}

for (const status of [200, 503, 429]) {
  test(`empty or unavailable quote inbox prevents payer at HTTP ${status}`, async () => {
    const subject = fixture([], status);
    await expect(subject.attempt()).rejects.toThrow('quoted order email unavailable; payment not attempted');
    expect(subject.payers()).toBe(0);
    expect(subject.clock()).toBe(status === 200 ? quoteMailWaitMs : 0);
    expect(subject.reads()).toBe(status === 200 ? 12 : 1);
  });
}

test('genuine fresh quote email admits the payer once', async () => {
  const subject = fixture([message]);
  await subject.attempt();
  expect(subject.payers()).toBe(1);
  expect(subject.reads()).toBe(1);
});

for (const [index, changes] of [
  { subject: 'Your Zunder Guard licence order ZL-2026-000124' },
  { text: 'Order ZL-2026-000124: another purchase.' },
  { text: `Order ${input.order}0: prefix collision.` },
  { text: `Your licence key for ${input.order}` },
].entries()) {
  test(`unrelated or non-quote mail cannot admit payer ${index}`, async () => {
    const subject = fixture([{ ...message, ...changes }]);
    await expect(subject.attempt()).rejects.toThrow('payment not attempted');
    expect(subject.payers()).toBe(0);
    expect(subject.clock()).toBe(quoteMailWaitMs);
  });
}

for (const [index, changes] of [
  { to: 'other@example.test' }, { received_at_ms: 999 }, { id: 'not-a-uuid' },
  { text: { secret: 'PRIVATE-BODY-SENTINEL' } }, { html: null },
].entries()) {
  test(`bad inbox metadata refuses the whole response ${index}`, async () => {
    const subject = fixture([message, { ...message, ...changes }]);
    await expect(subject.attempt()).rejects.toThrow('payment not attempted');
    expect(subject.payers()).toBe(0);
    expect(subject.reads()).toBe(1);
  });
}

test('late genuine email cannot admit a payer beyond the exact bound', async () => {
  const subject = fixture([message], 200, quoteMailWaitMs);
  await expect(subject.attempt()).rejects.toThrow('payment not attempted');
  expect(subject.payers()).toBe(0);
});

test('message validation crossing the deadline cannot admit a payer', async () => {
  const mail = { ...message };
  const subject = fixture([mail], 200, quoteMailWaitMs - 1);
  Object.defineProperty(mail, 'subject', { get() {
    subject.advance(2);
    return message.subject;
  } });
  await expect(subject.attempt()).rejects.toThrow('payment not attempted');
  expect(subject.payers()).toBe(0);
  expect(subject.reads()).toBe(1);
});

test('expiry before request admission never starts an unlimited read or payer', async () => {
  const times = [0, quoteMailWaitMs - 1, quoteMailWaitMs];
  let reads = 0;
  let payers = 0;
  const request = { async get() { reads++; throw new Error('unexpected read'); } } as unknown as APIRequestContext;
  const attempt = async () => {
    await requireQuoteMail(request, input, () => times.shift() ?? quoteMailWaitMs);
    payers++;
  };
  await expect(attempt()).rejects.toThrow('payment not attempted');
  expect(reads).toBe(0);
  expect(payers).toBe(0);
});

test('HTTP failure exposes only a fixed label without email or credentials', async () => {
  const request = { async get() {
    throw new Error(`${input.token} ${input.email} ${input.order} PRIVATE-BODY-SENTINEL`);
  } } as unknown as APIRequestContext;
  let failure: unknown;
  try { await requireQuoteMail(request, input); } catch (error) { failure = error; }
  expect(failure instanceof Error).toBe(true);
  const error = failure as Error;
  expect(error.message).toBe('quoted order email unavailable; payment not attempted');
  expect(error.cause).toBeUndefined();
  for (const privateValue of [input.token, input.email, input.order, 'PRIVATE-BODY-SENTINEL']) {
    expect(error.stack?.includes(privateValue)).toBe(false);
  }
});

test('actual paid consumer validates quote and observes quote mail before payer credentials or commands', async () => {
  const source = await readFile(new URL('./paid.test.ts', import.meta.url), 'utf8');
  const admission = source.indexOf('await requireQuoteMail(');
  expect(admission).toBeGreaterThan(source.indexOf("'unpaid exact testnet browser quote bound to covered account and merchant'"));
  expect(admission).toBeGreaterThan(source.indexOf("await mkdir(join(privateWork, 'payment')"));
  expect(admission).toBeLessThan(source.indexOf('const paymentEnv ='));
  for (const payer of ['guard_harness.purchase_payment', 'guard_harness.purchase_evm']) {
    expect(admission).toBeLessThan(source.indexOf(payer));
  }
  expect(source.split('await requireQuoteMail(').length - 1).toBe(1);
});

test('admission never creates mail, logs bodies or writes evidence', async () => {
  const source = await readFile(new URL('./quote-mail-admission.ts', import.meta.url), 'utf8');
  expect(source).not.toContain('console.');
  expect(source).not.toContain('writeFile');
  expect(source).not.toContain('post(');
  expect(source).not.toContain('command(');
});
