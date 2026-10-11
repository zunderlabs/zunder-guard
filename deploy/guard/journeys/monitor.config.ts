// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { defineConfig } from '@playwright/test';

// C5 production endpoints only, no staging credentials, browser assets or retries.
export default defineConfig({
  testDir: './monitor', timeout: 60_000, retries: 0, workers: 1,
  reporter: [['list']],
  use: { baseURL: 'https://zunderlabs.com', extraHTTPHeaders: {}, trace: 'off' },
});
