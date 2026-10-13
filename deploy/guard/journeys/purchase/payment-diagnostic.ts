// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { open, lstat, readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

type Environment = Record<string, string | undefined>;
export type PaymentDiagnostic = Readonly<{
  journey: 'P2' | 'P3'; network: 'arbitrum' | 'base'; harnessCommit: string; releasedCommit: string;
}>;
const refused = 'payment diagnostic admission refused; no payment or gate credit';
const evidenceRefused = 'payment diagnostic evidence refused; reconcile receipt, never retry';
const sha = /^[0-9a-f]{40}$/;

/** Explicit standalone payment profile only; formal and checkout inputs cannot enable it. */
export function admitPaymentDiagnostic(env: Environment): PaymentDiagnostic | null {
  const enabled = env['GUARD_PAYMENT_DIAGNOSTIC'] ?? '';
  const profile = env['GUARD_PAYMENT_DIAGNOSTIC_PROFILE'] ?? '';
  const harness = env['GUARD_DIAGNOSTIC_HARNESS_COMMIT'] ?? '';
  if (!enabled) {
    if (profile || harness) throw new Error(refused);
    return null;
  }
  const journey = env['GUARD_PAID_JOURNEY'];
  const released = env['GUARD_RELEASE_COMMIT'] ?? '';
  if (enabled !== '1' || profile !== 'payment' || (journey !== 'P2' && journey !== 'P3')
      || !sha.test(harness) || !sha.test(released) || env['GUARD_CHECKOUT_DIAGNOSTIC'] !== undefined
      || (env['PROFILE'] && env['PROFILE'] !== 'payment')) throw new Error(refused);
  return Object.freeze({ journey, network: journey === 'P2' ? 'arbitrum' : 'base',
    harnessCommit: harness, releasedCommit: released });
}

/** The existing single payer must have completed its fresh private receipt; no network calls. */
export async function completePaymentDiagnostic(work: string, mode: PaymentDiagnostic,
  order: string, usdc: string): Promise<void> {
  try {
    if (!isAbsolute(work) || !/^ZL-\d{4}-\d{6}$/.test(order) || !/^0\.\d{1,6}$/.test(usdc)
        || !sha.test(mode.harnessCommit) || !sha.test(mode.releasedCommit)
        || (mode.journey === 'P2' ? mode.network !== 'arbitrum'
          : mode.journey !== 'P3' || mode.network !== 'base')) throw new Error();
    const parent = await lstat(work);
    if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o077) !== 0) throw new Error();
    const payment = await lstat(join(work, 'payment'));
    if (!payment.isDirectory() || payment.isSymbolicLink() || (payment.mode & 0o077) !== 0) throw new Error();
    const path = join(work, 'payment', 'payment-receipt.json');
    const receiptFile = await lstat(path);
    if (!receiptFile.isFile() || receiptFile.isSymbolicLink() || (receiptFile.mode & 0o077) !== 0
        || receiptFile.size <= 0 || receiptFile.size > 4096) throw new Error();
    const receipt: unknown = JSON.parse(await readFile(path, 'utf8'));
    const micro = Number((usdc.slice(2) + '000000').slice(0, 6));
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) throw new Error();
    const value = receipt as Record<string, unknown>;
    if (value['accepted'] !== true || value['order'] !== order || value['network'] !== mode.network
        || !Number.isSafeInteger(value['amount_micro']) || value['amount_micro'] !== micro
        || !(micro > 0 && micro < 1_000_000) || !Number.isSafeInteger(value['nonce'])
        || Number(value['nonce']) < 0 || typeof value['transaction_hash'] !== 'string'
        || !/^0x[0-9a-f]{64}$/.test(value['transaction_hash'])) throw new Error();
    const output = { schema: 1, diagnostic: true, gate_eligible: false, network: mode.network,
      journey: mode.journey, harness_commit: mode.harnessCommit,
      released_commit: mode.releasedCommit, payment_confirmed: true };
    const stream = await open(join(work, 'payment-diagnostic.json'), 'wx', 0o600);
    try { await stream.writeFile(JSON.stringify(output) + '\n'); await stream.sync(); }
    finally { await stream.close(); }
    const directory = await open(work, 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  } catch {
    throw new Error(evidenceRefused);
  }
}
