// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { test } from '@playwright/test';
import { checkPages, checkCheckout, checkQuotes, checkRenewal, checkHeartbeat } from './checks.js';

// Run only through monitor.config.ts, never the default staging/fixture suite.
// Checkout/issuer subset only; signed canonical metadata remains required for P9.
test('P9 branded public page content', async ({ request }) => checkPages(request));
test('P9 production checkout open', async ({ request }) => checkCheckout(request));
test('P9 dry-run quote on every payment network', async ({ request }) => checkQuotes(request));
test('P9 malformed renewal refused', async ({ request }) => checkRenewal(request));
test('P9 issuer heartbeat within five minutes', async ({ request }) => checkHeartbeat(request));
