// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { defineConfig } from '@playwright/test';

const remote = process.env['GUARD_STAGING_URL'];
const headers: Record<string, string> = {};
if (remote) {
  if (process.env['DEBUG'] || process.env['PWDEBUG']) {
    throw new Error('remote journeys require debug logging disabled to protect credentials');
  }
  requireHttps(remote, 'staging');
  const approvalOnly = process.env['GUARD_PAID_JOURNEY'] === 'P8';
  const required = approvalOnly
    ? ['GUARD_ACCESS_CLIENT_ID', 'GUARD_ACCESS_CLIENT_SECRET']
    : ['GUARD_ORDER_TOKEN', 'GUARD_INBOX_TOKEN', 'GUARD_INBOX_URL', 'GUARD_EMAIL_DOMAIN', 'GUARD_ACCESS_CLIENT_ID', 'GUARD_ACCESS_CLIENT_SECRET'];
  for (const name of required) {
    if (!process.env[name]) throw new Error(`missing environment variable: ${name}`);
  }
  if (!approvalOnly) requireHttps(process.env['GUARD_INBOX_URL'] ?? '', 'inbox');
  headers['CF-Access-Client-Id'] = process.env['GUARD_ACCESS_CLIENT_ID'] ?? '';
  headers['CF-Access-Client-Secret'] = process.env['GUARD_ACCESS_CLIENT_SECRET'] ?? '';
}
function requireHttps(value: string, label: string): void {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
      throw new Error();
    }
  } catch {
    // URL parser errors may include userinfo; never attach the original error/input.
    throw new Error(`${label} requires HTTPS without URL credentials, query or fragment`);
  }
}
export default defineConfig({
  testDir: './purchase',
  forbidOnly: true,
  timeout: 30_000,
  retries: 0,
  workers: 1,
  // HTML/JSON reporters serialize failed API step errors even after callers catch them.
  // Keep only sanitized terminal output, which CI retains on failure.
  reporter: [['list'], ['./proof-reporter.ts']],
  use: { baseURL: remote ?? 'http://127.0.0.1:4173', extraHTTPHeaders: headers,
    // API traces persist bearer and Access headers. Keep credential-bearing traces off.
    trace: 'off', serviceWorkers: 'block', launchOptions: { env: { PATH: process.env['PATH'] ?? '', HOME: process.env['HOME'] ?? '' } } },
  ...(remote ? {} : {
    webServer: {
      command: 'npm run fixture',
      url: 'http://127.0.0.1:4173/api/licence/status',
      timeout: 15_000,
      reuseExistingServer: false,
    },
  }),
});
