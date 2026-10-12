// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { createServer, type Server } from 'node:http';
import { test, expect, type APIResponse } from '@playwright/test';
import { admitStagingDocument, pricingPreflight, restrictAccessHeaders } from './browser-access.js';

async function listen(server: Server): Promise<string> {
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('fixture address unavailable');
  return `http://127.0.0.1:${address.port}`;
}
async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

test.skip(process.env['GUARD_BROWSER_BOUNDARY_TEST'] !== '1', 'requires installed Chromium');
for (const sample of [
  { status: 401, profile: 'staging', title: 'Cloudflare Access', mitigation: '' },
  { status: 403, profile: 'staging', title: 'Just a moment', mitigation: 'challenge' },
  { status: 404, profile: 'staging', title: 'Private fixture', mitigation: '' },
  { status: 302, profile: 'staging', title: 'Private fixture', mitigation: '' },
  { status: 202, profile: 'staging', title: 'Guard', mitigation: '' },
  { status: 200, profile: 'production', title: 'Guard', mitigation: '' },
  { status: 200, profile: '', title: 'Guard', mitigation: '' },
  { status: 200, profile: 'duplicate', title: 'Guard', mitigation: '' },
  { status: 200, profile: 'staging', title: 'Guard', mitigation: 'challenge' },
  { status: 200, profile: 'staging', title: 'Guard', mitigation: '' },
]) {
  test(`document admission status=${sample.status} profile=${sample.profile || 'missing'} mitigation=${sample.mitigation || 'none'}`, async ({ browser }) => {
    let clicks = 0;
    let leaked = 0;
    const external = createServer((_request, response) => { leaked++; response.end('unexpected'); });
    const externalOrigin = await listen(external);
    const server = createServer((request, response) => {
      if (request.url === '/click') { clicks++; response.end('ok'); return; }
      const metas = sample.profile === 'duplicate'
        ? '<meta name="zunder-deployment-profile" content="staging"><meta name="zunder-deployment-profile" content="staging">'
        : sample.profile ? `<meta name="zunder-deployment-profile" content="${sample.profile}">` : '';
      const body = `<html><head><title>${sample.title} private-output-needle</title>${metas}</head><body>
        <button onclick="fetch('/click')">Purchase</button><div>synthetic-secret-needle</div></body></html>`;
      response.writeHead(sample.status, { 'Content-Type': 'text/html', 'Content-Length': Buffer.byteLength(body),
        ...(sample.mitigation ? { 'cf-mitigated': sample.mitigation } : {}),
        ...(sample.status === 302 ? { Location: externalOrigin + '/forbidden' } : {}),
      });
      response.end(body);
    });
    const origin = await listen(server);
    const context = await browser.newContext({ serviceWorkers: 'block' });
    try {
      await restrictAccessHeaders(context, origin, { id: 'synthetic-id', secret: 'synthetic-secret-needle' });
      const page = await context.newPage();
      if (sample.status === 200 && sample.profile === 'staging' && !sample.mitigation) {
        await admitStagingDocument(page, '/pricing', origin);
        await page.getByRole('button', { name: 'Purchase' }).click();
        await expect.poll(() => clicks).toBe(1);
      } else {
        let message = '';
        try { await admitStagingDocument(page, '/pricing', origin); }
        catch (error) { message = error instanceof Error ? error.message : ''; }
        expect(message).toContain(`status=${sample.status}`);
        expect(message).not.toContain('private-output-needle');
        expect(message).not.toContain('synthetic-secret-needle');
        expect(message).not.toContain('<html>');
        expect(clicks).toBe(0);
        if (sample.status === 401) expect(message).toContain('title=access');
        if (sample.mitigation) expect(message).toContain('cf-mitigated=challenge');
      }
      expect(leaked).toBe(0);
    } finally { await context.close(); await close(server); await close(external); }
  });
}

test('pricing preflight uses actual browser UA and curl UA on two isolated C4 GETs', async ({ page }) => {
  const agent = await page.evaluate(() => navigator.userAgent);
  const request = page.context().request;
  const previous = request.get;
  const calls: string[] = [];
  const messages: string[] = [];
  const log = console.log;
  console.log = (message: string): void => { messages.push(message); };
  request.get = async (url, options) => {
    expect(url).toBe('https://staging.zunderlabs.com/pricing');
    expect(options?.maxRedirects).toBe(0);
    expect(options?.maxRetries).toBe(0);
    expect(options?.timeout).toBe(20_000);
    expect(options?.headers?.['CF-Access-Client-Id'] === 'synthetic-id').toBe(true);
    expect(options?.headers?.['CF-Access-Client-Secret'] === 'synthetic-secret-needle').toBe(true);
    const userAgent = options?.headers?.['User-Agent'] ?? '';
    calls.push(userAgent);
    return { status: () => userAgent === agent ? 403 : 200,
      headers: () => userAgent === agent ? { 'cf-mitigated': 'challenge' } : {},
      dispose: async () => {} } as unknown as APIResponse;
  };
  try {
    await pricingPreflight(page, 'https://staging.zunderlabs.com', { id: 'synthetic-id', secret: 'synthetic-secret-needle' });
    expect(calls).toEqual([agent, 'curl/8.5.0']);
    expect(messages).toEqual(['pricing preflight agent=headless status=403 cf-mitigated=challenge',
      'pricing preflight agent=curl status=200 cf-mitigated=none']);
    await expect(pricingPreflight(page, 'https://zunderlabs.com', { id: 'synthetic-id', secret: 'synthetic-secret-needle' })).rejects.toThrow('C4 staging origin');
    expect(calls.length).toBe(2);
  } finally { request.get = previous; console.log = log; }
});

test('pricing preflight transport errors expose only fixed codes and mitigation categories', async ({ page }) => {
  const request = page.context().request;
  const previous = request.get;
  const messages: string[] = [];
  const log = console.log;
  console.log = (message: string): void => { messages.push(message); };
  request.get = async () => { throw new Error('synthetic-secret-needle private HTTP headers'); };
  try {
    await pricingPreflight(page, 'https://staging.zunderlabs.com', { id: 'synthetic-id', secret: 'synthetic-secret-needle' });
    expect(messages).toEqual(['pricing preflight agent=headless status=0 cf-mitigated=none',
      'pricing preflight agent=curl status=0 cf-mitigated=none']);
  } finally { request.get = previous; console.log = log; }
});
