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
