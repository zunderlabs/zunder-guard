// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { test, expect } from '@playwright/test';
import type { FullResult, TestCase, TestResult } from '@playwright/test/reporter';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import ProofReporter from '../proof-reporter.js';

for (const diagnostic of [false, true]) {
  test(`proof preserves admission boundary for diagnostic=${diagnostic}`, () => {
    const work = mkdtempSync(join(tmpdir(), 'guard-proof-'));
    const oldProof = process.env['GUARD_TEST_PROOF'];
    const oldDiagnostic = process.env['GUARD_CHECKOUT_DIAGNOSTIC'];
    try {
      process.env['GUARD_TEST_PROOF'] = join(work, 'proof.json');
      if (diagnostic) process.env['GUARD_CHECKOUT_DIAGNOSTIC'] = '1';
      else delete process.env['GUARD_CHECKOUT_DIAGNOSTIC'];
      const reporter = new ProofReporter();
      reporter.onTestEnd({ title: 'P1 checkout' } as TestCase, { status: 'passed' } as TestResult);
      reporter.onEnd({ status: 'passed' } as FullResult);
      const proof = JSON.parse(readFileSync(join(work, 'proof.json'), 'utf8'));
      expect(proof.status).toBe(diagnostic ? 'diagnostic_only' : 'passed');
      expect(proof.tests).toEqual([{ title: 'P1 checkout', status: 'passed' }]);
    } finally {
      if (oldProof === undefined) delete process.env['GUARD_TEST_PROOF']; else process.env['GUARD_TEST_PROOF'] = oldProof;
      if (oldDiagnostic === undefined) delete process.env['GUARD_CHECKOUT_DIAGNOSTIC']; else process.env['GUARD_CHECKOUT_DIAGNOSTIC'] = oldDiagnostic;
      rmSync(work, { recursive: true, force: true });
    }
  });
}

for (const journey of ['P2', 'P3']) {
  test(`admitted ${journey} payment diagnostic proof never claims ordinary pass`, () => {
    const work = mkdtempSync(join(tmpdir(), 'guard-payment-proof-'));
    const fields = { GUARD_TEST_PROOF: join(work, 'proof.json'), GUARD_PAYMENT_DIAGNOSTIC: '1',
      GUARD_PAYMENT_DIAGNOSTIC_PROFILE: 'payment', PROFILE: 'payment', GUARD_PAID_JOURNEY: journey,
      GUARD_DIAGNOSTIC_HARNESS_COMMIT: 'a'.repeat(40), GUARD_RELEASE_COMMIT: 'b'.repeat(40) };
    const old = { ...process.env };
    try {
      delete process.env['GUARD_CHECKOUT_DIAGNOSTIC'];
      Object.assign(process.env, fields);
      const reporter = new ProofReporter();
      reporter.onTestEnd({ title: `${journey} payment diagnostic only; no gate credit` } as TestCase,
        { status: 'passed', error: { message: 'PRIVATE_SENTINEL' }, attachments: [{ body: 'PRIVATE_SENTINEL' }] } as unknown as TestResult);
      reporter.onEnd({ status: 'passed' } as FullResult);
      const bytes = readFileSync(join(work, 'proof.json'), 'utf8');
      expect(JSON.parse(bytes)).toEqual({ status: 'diagnostic_only', tests: [
        { title: `${journey} payment diagnostic only; no gate credit`, status: 'passed' }] });
      expect(bytes).not.toContain('PRIVATE_SENTINEL');
    } finally {
      for (const field of Object.keys(fields)) {
        if (old[field] === undefined) delete process.env[field]; else process.env[field] = old[field];
      }
      if (old['GUARD_CHECKOUT_DIAGNOSTIC'] === undefined) delete process.env['GUARD_CHECKOUT_DIAGNOSTIC'];
      else process.env['GUARD_CHECKOUT_DIAGNOSTIC'] = old['GUARD_CHECKOUT_DIAGNOSTIC'];
      rmSync(work, { recursive: true, force: true });
    }
  });
}
