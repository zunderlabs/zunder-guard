// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { mkdtemp, mkdir, writeFile, readFile, stat, rm, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { test, expect } from '@playwright/test';
import { admitPaymentDiagnostic, completePaymentDiagnostic } from './payment-diagnostic.js';

const admitted = { GUARD_PAYMENT_DIAGNOSTIC: '1', GUARD_PAYMENT_DIAGNOSTIC_PROFILE: 'payment',
  GUARD_PAID_JOURNEY: 'P2', GUARD_DIAGNOSTIC_HARNESS_COMMIT: 'a'.repeat(40),
  GUARD_RELEASE_COMMIT: 'b'.repeat(40) };
const order = 'ZL-2026-000123';
const amount = '0.180001';
const refused = 'payment diagnostic admission refused; no payment or gate credit';
const evidenceRefused = 'payment diagnostic evidence refused; reconcile receipt, never retry';

for (const journey of ['P2', 'P3']) {
  test(`${journey} admits only explicit diagnostic payment identity`, () => {
    const mode = admitPaymentDiagnostic({ ...admitted, GUARD_PAID_JOURNEY: journey });
    expect(mode?.network).toBe(journey === 'P2' ? 'arbitrum' : 'base');
    expect(mode?.harnessCommit).toBe(admitted.GUARD_DIAGNOSTIC_HARNESS_COMMIT);
    expect(Object.isFrozen(mode)).toBe(true);
  });
}
for (const [index, changes] of [
  { GUARD_PAYMENT_DIAGNOSTIC: 'true' }, { GUARD_PAYMENT_DIAGNOSTIC: '0' },
  { GUARD_PAYMENT_DIAGNOSTIC_PROFILE: 'all' }, { GUARD_PAYMENT_DIAGNOSTIC_PROFILE: 'nightly' },
  { PROFILE: 'all' }, { PROFILE: 'nightly' }, { GUARD_PAID_JOURNEY: 'P1' },
  { GUARD_PAID_JOURNEY: 'P6' }, { GUARD_PAID_JOURNEY: 'P8' },
  { GUARD_DIAGNOSTIC_HARNESS_COMMIT: '' }, { GUARD_DIAGNOSTIC_HARNESS_COMMIT: 'PRIVATE-SECRET' },
  { GUARD_RELEASE_COMMIT: 'bad' }, { GUARD_CHECKOUT_DIAGNOSTIC: '1' },
  { GUARD_CHECKOUT_DIAGNOSTIC: '' },
].entries()) {
  test(`invalid payment-only input ${index} refuses before any quote or payer`, () => {
    let quotes = 0;
    let payers = 0;
    const attempt = () => {
      admitPaymentDiagnostic({ ...admitted, ...changes });
      quotes++;
      payers++;
    };
    expect(attempt).toThrow(refused);
    expect(quotes).toBe(0);
    expect(payers).toBe(0);
  });
}
test('ordinary formal mode and nightly retain ordinary admission', () => {
  expect(admitPaymentDiagnostic({ PROFILE: 'all' })).toBeNull();
  expect(admitPaymentDiagnostic({ PROFILE: 'nightly', GUARD_PAYMENT_DIAGNOSTIC: '' })).toBeNull();
  expect(() => admitPaymentDiagnostic({ GUARD_DIAGNOSTIC_HARNESS_COMMIT: 'a'.repeat(40) })).toThrow(refused);
});

async function fixture(changes: Record<string, unknown> = {}) {
  const work = await mkdtemp(join(tmpdir(), 'guard-payment-diagnostic-'));
  await mkdir(join(work, 'payment'), { mode: 0o700 });
  const mode = admitPaymentDiagnostic(admitted)!;
  await writeFile(join(work, 'payment/payment-receipt.json'), JSON.stringify({
    order, network: 'arbitrum', amount_micro: 180001, nonce: 1,
    transaction_hash: '0x' + 'c'.repeat(64), accepted: true,
    private_body: 'PRIVATE-SECRET-ACCOUNT', ...changes,
  }), { mode: 0o600, flag: 'wx' });
  return { work, mode };
}

test('successful private receipt creates only finite evidence without email or network calls', async () => {
  const { work, mode } = await fixture();
  const fetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls++; throw new Error('network forbidden'); };
  try {
    await completePaymentDiagnostic(work, mode, order, amount);
    const body = await readFile(join(work, 'payment-diagnostic.json'), 'utf8');
    expect(JSON.parse(body)).toEqual({ schema: 1, diagnostic: true, gate_eligible: false,
      network: 'arbitrum', journey: 'P2', harness_commit: 'a'.repeat(40),
      released_commit: 'b'.repeat(40), payment_confirmed: true });
    for (const value of [order, 'PRIVATE', 'transaction_hash', 'nonce', 'account', 'email', 'token']) {
      expect(body.includes(value)).toBe(false);
    }
    expect((await stat(join(work, 'payment-diagnostic.json'))).mode & 0o777).toBe(0o600);
    expect(calls).toBe(0);
    await expect(completePaymentDiagnostic(work, mode, order, amount)).rejects.toThrow(evidenceRefused);
  } finally { globalThis.fetch = fetch; await rm(work, { recursive: true, force: true }); }
});
for (const [index, changes] of [
  { accepted: false }, { accepted: 1 }, { order: 'ZL-2026-000124' }, { network: 'base' },
  { amount_micro: 180000 }, { nonce: -1 }, { transaction_hash: 'PRIVATE-SECRET' },
].entries()) {
  test(`failed or different receipt ${index} never reports confirmed payment`, async () => {
    const { work, mode } = await fixture(changes);
    try {
      await expect(completePaymentDiagnostic(work, mode, order, amount)).rejects.toThrow(evidenceRefused);
      await expect(stat(join(work, 'payment-diagnostic.json'))).rejects.toThrow();
    } finally { await rm(work, { recursive: true, force: true }); }
  });
}
test('missing receipt, public directory and symlink cannot confirm a payment', async () => {
  const { work, mode } = await fixture();
  const receipt = join(work, 'payment/payment-receipt.json');
  try {
    await chmod(work, 0o755);
    await expect(completePaymentDiagnostic(work, mode, order, amount)).rejects.toThrow(evidenceRefused);
    await chmod(work, 0o700);
    const saved = join(work, 'saved.json');
    await writeFile(saved, await readFile(receipt), { mode: 0o600 });
    await rm(receipt);
    await expect(completePaymentDiagnostic(work, mode, order, amount)).rejects.toThrow(evidenceRefused);
    await symlink(saved, receipt);
    await expect(completePaymentDiagnostic(work, mode, order, amount)).rejects.toThrow(evidenceRefused);
  } finally { await rm(work, { recursive: true, force: true }); }
});
test('receipt mismatch error carries no private fields or original exception', async () => {
  const { work, mode } = await fixture({ order: 'PRIVATE-SECRET' });
  try {
    let error: unknown;
    try { await completePaymentDiagnostic(work, mode, order, amount); } catch (caught) { error = caught; }
    expect(error instanceof Error).toBe(true);
    expect((error as Error).message).toBe(evidenceRefused);
    expect((error as Error).cause).toBeUndefined();
    expect((error as Error).stack?.includes('PRIVATE-SECRET')).toBe(false);
  } finally { await rm(work, { recursive: true, force: true }); }
});

test('actual consumer pays once from one fresh browser quote and returns before any email or licence work', async () => {
  const source = await readFile(new URL('./paid.test.ts', import.meta.url), 'utf8');
  expect(source).toContain('payment diagnostic only; no gate credit');
  expect(source.split("page.getByTestId('checkout-quote-submit').click").length - 1).toBe(1);
  expect(source).toContain('if (!paymentDiagnostic) await requireQuoteMail(');
  const mail = source.indexOf('await requireQuoteMail(');
  expect(mail).toBeLessThan(source.indexOf('const paymentEnv ='));
  const receipt = source.indexOf('await completePaymentDiagnostic(');
  const diagnosticReturn = source.indexOf('return; // Explicit payment diagnostic', receipt);
  expect(receipt).toBeGreaterThan(source.indexOf("await command('guard_harness.purchase_evm'"));
  expect(diagnosticReturn).toBeLessThan(source.indexOf('licence = await waitForDelivery('));
  expect(diagnosticReturn).toBeLessThan(source.indexOf("'paid inbox'"));
  expect(diagnosticReturn).toBeLessThan(source.indexOf("await command('guard_harness.purchase_licence'"));
  for (const payer of ['guard_harness.purchase_payment', 'guard_harness.purchase_evm']) {
    expect(source.split(payer).length - 1).toBe(1);
  }
  expect(source).toContain("await mkdir(privateWork, { mode: 0o700 })");
  expect(source).not.toContain("mkdir(privateWork, { recursive: true");
  expect(source).not.toContain('process.env[\'E2E_TESTNET_OWNER_KEY\']');
  expect(source).not.toContain('predicate.json');
});

test('shared config omits inbox only for fully admitted payment diagnostic', async () => {
  const execute = promisify(execFile);
  const env = { PATH: process.env['PATH'] ?? '', HOME: tmpdir(), GUARD_STAGING_URL: 'https://staging.zunderlabs.com',
    GUARD_ORDER_TOKEN: 'fixture-token', GUARD_EMAIL_DOMAIN: 'fixture.example',
    GUARD_ACCESS_CLIENT_ID: 'fixture-access', GUARD_ACCESS_CLIENT_SECRET: 'fixture-secret' };
  const program = "await import('./playwright.config.ts')";
  await execute(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', program], {
    cwd: process.cwd(), env: { ...env, ...admitted }, timeout: 10_000 });
  for (const profile of ['all', 'nightly']) {
    await expect(execute(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', program], {
      cwd: process.cwd(), env: { ...env, PROFILE: profile }, timeout: 10_000 })).rejects.toThrow('GUARD_INBOX_TOKEN');
  }
});
