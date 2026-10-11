// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import type { BrowserContext } from '@playwright/test';

/** Never let a redirect carry the staging Access token to another origin. */
export async function restrictAccessHeaders(
  context: BrowserContext, stagingOrigin: string, access: { id: string; secret: string },
): Promise<void> {
  // route.fetch merges context defaults back into its request. Clear them first;
  // Access credentials are injected solely into an admitted single staging hop.
  await context.setExtraHTTPHeaders({});
  await context.route('**/*', async route => {
    try {
      const headers = route.request().headers();
      delete headers['cf-access-client-id'];
      delete headers['cf-access-client-secret'];
      if (new URL(route.request().url()).origin === stagingOrigin) {
        headers['cf-access-client-id'] = access.id;
        headers['cf-access-client-secret'] = access.secret;
      }
      // continue({headers}) retains overrides across un-routed redirect hops.
      // Fetch exactly one hop and refuse redirects before the browser sees them.
      const response = await route.fetch({ headers, maxRedirects: 0, maxRetries: 0 });
      try {
        if (response.status() >= 300 && response.status() < 400) {
          await route.abort('blockedbyclient');
        } else {
          await route.fulfill({ response });
        }
      } finally {
        await response.dispose();
      }
    } catch {
      // Network diagnostics can contain credentials; expose only an aborted load.
      try { await route.abort('failed'); } catch { /* request already finished */ }
    }
  });
}
