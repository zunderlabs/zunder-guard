// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import { test, expect } from '@playwright/test';
import { restrictAccessHeaders } from './browser-access.js';

async function listen(server: Server): Promise<string> {
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('test server address missing');
  return `http://127.0.0.1:${address.port}`;
}
async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

test.skip(process.env['GUARD_BROWSER_BOUNDARY_TEST'] !== '1', 'requires installed Chromium');
test('Access headers stay at staging and redirects are never followed', async ({ browser }) => {
  const externalRequests: IncomingHttpHeaders[] = [];
  const stagingRequests: IncomingHttpHeaders[] = [];
  const external = createServer((request, response) => {
    externalRequests.push(request.headers);
    response.end('external');
  });
  const externalOrigin = await listen(external);
  const staging = createServer((request, response) => {
    stagingRequests.push(request.headers);
    if (request.url === '/redirect') {
      response.writeHead(302, { Location: `${externalOrigin}/leaked` });
      response.end();
    } else {
      response.setHeader('Content-Type', 'text/html');
      response.end(`<html><body>staging<img src="${externalOrigin}/resource"></body></html>`);
    }
  });
  const stagingOrigin = await listen(staging);
  const context = await browser.newContext({ serviceWorkers: 'block', extraHTTPHeaders: {
    'CF-Access-Client-Id': 'synthetic-id', 'CF-Access-Client-Secret': 'synthetic-secret',
  } });
  try {
    await restrictAccessHeaders(context, stagingOrigin, { id: 'synthetic-id', secret: 'synthetic-secret' });
    const page = await context.newPage();
    await page.goto(stagingOrigin);
    expect(stagingRequests.length).toBeGreaterThan(0);
    expect(stagingRequests.every(headers => headers['cf-access-client-id'] === 'synthetic-id'
      && headers['cf-access-client-secret'] === 'synthetic-secret')).toBe(true);
    expect(externalRequests.length).toBe(1);
    expect(externalRequests.every(headers => !headers['cf-access-client-id']
      && !headers['cf-access-client-secret'])).toBe(true);
    await expect(page.goto(`${stagingOrigin}/redirect`)).rejects.toThrow();
    expect(externalRequests.length).toBe(1);
  } finally {
    await context.close();
    await close(staging);
    await close(external);
  }
});
