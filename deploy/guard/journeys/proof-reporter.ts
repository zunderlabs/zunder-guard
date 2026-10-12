// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
// Only public test identity and outcome; never serialize API steps/errors/attachments.
import { writeFileSync } from 'node:fs';
import type { FullResult, Reporter, TestCase, TestResult } from '@playwright/test/reporter';
export default class ProofReporter implements Reporter {
  private tests: { title: string; status: string }[] = [];
  onTestEnd(test: TestCase, result: TestResult): void {
    this.tests.push({ title: test.title, status: result.status });
  }
  onEnd(result: FullResult): void {
    const path = process.env['GUARD_TEST_PROOF'];
    if (path) writeFileSync(path, JSON.stringify({ status: process.env['GUARD_CHECKOUT_DIAGNOSTIC'] === '1' ? 'diagnostic_only' : result.status, tests: this.tests }) + '\n', { flag: 'wx', mode: 0o600 });
  }
}
