// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import type { BrowserContext, Page } from '@playwright/test';

type Diagnosis = { status: number; title: 'access' | 'challenge' | 'guard' | 'other' | 'unavailable';
  mitigation: 'challenge' | 'other' | 'none' };
const documents = new WeakMap<Page, Diagnosis>();
function titleCategory(value: string): Diagnosis['title'] {
  if (/cloudflare access|access denied|unauthorized|forbidden/i.test(value)) return 'access';
  if (/just a moment|challenge|attention required/i.test(value)) return 'challenge';
  if (/zunder|guard/i.test(value)) return 'guard';
  return 'other';
}
function mitigation(value: string | undefined): Diagnosis['mitigation'] {
  return value === undefined ? 'none' : value.toLowerCase() === 'challenge' ? 'challenge' : 'other';
}

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
        const stagingDocument = new URL(route.request().url()).origin === stagingOrigin
          && route.request().isNavigationRequest() && route.request().resourceType() === 'document';
        if (stagingDocument) {
          const diagnosis: Diagnosis = { status: response.status(), title: 'unavailable',
            mitigation: mitigation(response.headers()['cf-mitigated']) };
          if (response.status() < 200 || response.status() >= 300) {
            // Only a category escapes this scope; never retain an Access page or its title.
            if ((response.headers()['content-type'] ?? '').includes('text/html')) {
              try {
                const body = await response.text();
                const title = body.length <= 65_536 ? /<title[^>]*>([^<]{0,512})<\/title>/i.exec(body) : null;
                if (title?.[1]) diagnosis.title = titleCategory(title[1]);
              } catch { /* unavailable is an explicit diagnostic, never raw HTTP failure */ }
            }
          }
          documents.set(route.request().frame().page(), diagnosis);
        }
        if ((response.status() >= 300 && response.status() < 400)
          || (stagingDocument && (response.status() < 200 || response.status() >= 300))) {
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

/** Admission must finish before any purchase or wallet control is clicked. */
export async function admitStagingDocument(page: Page, path: string, stagingOrigin: string): Promise<void> {
  documents.delete(page);
  let profile: 'staging' | 'production' | 'missing' | 'duplicate' | 'other' | 'unavailable' = 'unavailable';
  let diagnosis: Diagnosis = { status: 0, title: 'unavailable', mitigation: 'none' };
  try {
    const target = new URL(path, stagingOrigin);
    if (target.origin !== stagingOrigin || target.username || target.password) throw new Error();
    const response = await page.goto(target.href, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    diagnosis = documents.get(page) ?? diagnosis;
    if (response) diagnosis = { status: response.status(), title: titleCategory(await page.title()),
      mitigation: mitigation(response.headers()['cf-mitigated']) };
    const marker = page.locator('meta[name="zunder-deployment-profile"]');
    const count = await marker.count();
    const content = count === 1 ? await marker.getAttribute('content') : null;
    profile = count === 0 ? 'missing' : count > 1 ? 'duplicate'
      : content === 'staging' || content === 'production' ? content : 'other';
    if (response?.status() === 200 && new URL(page.url()).origin === stagingOrigin
      && profile === 'staging' && diagnosis.mitigation === 'none') return;
  } catch { diagnosis = documents.get(page) ?? diagnosis; }
  throw new Error(`staging document admission failed: status=${diagnosis.status} title=${diagnosis.title} cf-mitigated=${diagnosis.mitigation} profile=${profile}`);
}

/** Two read-only, same-origin single hops; credentials and response bodies never reach output. */
export async function pricingPreflight(page: Page, stagingOrigin: string,
  access: { id: string; secret: string }): Promise<void> {
  if (stagingOrigin !== 'https://staging.zunderlabs.com') throw new Error('pricing preflight requires C4 staging origin');
  let browserAgent: string;
  try { browserAgent = await page.evaluate(() => navigator.userAgent); }
  catch { throw new Error('pricing preflight browser identity unavailable'); }
  if (!/HeadlessChrome\/\d/.test(browserAgent)) throw new Error('pricing preflight requires actual HeadlessChrome identity');
  for (const [agent, userAgent] of [['headless', browserAgent], ['curl', 'curl/8.5.0']] as const) {
    let status = 0;
    let blocked: Diagnosis['mitigation'] = 'none';
    try {
      const response = await page.context().request.get(stagingOrigin + '/pricing', {
        headers: { 'User-Agent': userAgent, 'CF-Access-Client-Id': access.id,
          'CF-Access-Client-Secret': access.secret }, maxRedirects: 0, maxRetries: 0,
        timeout: 20_000, failOnStatusCode: false,
      });
      try { status = response.status(); blocked = mitigation(response.headers()['cf-mitigated']); }
      finally { await response.dispose(); }
    } catch { /* fixed codes only; API errors can include Access headers */ }
    console.log(`pricing preflight agent=${agent} status=${status} cf-mitigated=${blocked}`);
  }
}
