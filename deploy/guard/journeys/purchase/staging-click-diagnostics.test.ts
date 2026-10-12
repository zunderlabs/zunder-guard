// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { mkdtemp, readFile, readdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test, expect, type Page } from '@playwright/test';
import { admitStagingDocument } from './browser-access.js';
import { redactDiagnostic, stagingClickDiagnostics } from './staging-click-diagnostics.js';

test.skip(process.env['GUARD_BROWSER_BOUNDARY_TEST'] !== '1', 'requires installed Chromium');
const ORIGIN = 'https://staging.zunderlabs.com';
type Target = 'pricing-buy-pro' | 'approve-network-testnet';

function fastFixtureClick(page: Page, target: Target): void {
  const get = page.getByTestId.bind(page);
  page.getByTestId = id => {
    const locator = get(id);
    if (id === target) {
      const click = locator.click.bind(locator);
      locator.click = options => {
        expect(options?.timeout).toBe(30_000);
        return click({ ...options, timeout: 250 }); // Actual browser actionability failure, bounded fixture.
      };
    }
    return locator;
  };
}

async function fixture(page: Page, target: Target, secret: string,
  kind: 'hidden' | 'occluded' | 'csp' | 'private-input' | 'private-container',
  split: boolean | 'mixed' | 'pseudo-mixed' = false) {
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== ORIGIN || !['/pricing', '/approve'].includes(url.pathname)) {
      await route.abort('blockedbyclient'); return;
    }
    await route.fulfill({ status: 200, contentType: 'text/html',
      headers: kind === 'csp' ? { 'Content-Security-Policy': "script-src 'none'" } : {},
      body: `<html class="public-root" data-zg-diagnostic-node="0"><head><meta name="zunder-deployment-profile" content="staging"></head><body>
        <div id="secret" style="width:300px;height:40px">${split
          ? (split === 'mixed' ? '<span>' + secret + '</span>' : '')
            + (split === 'pseudo-mixed' ? '<style>#pseudo::before{content:"' + secret + '"}</style><span id="pseudo"></span>' : '')
            + '<span>' + secret.slice(0, -4) + '</span><span>' + secret.slice(-4) + '</span>' : secret}</div>
        <input value="unknown-input-private"><textarea>unknown-textarea-private</textarea>
        <button data-testid="${target}" style="${kind === 'hidden' || kind === 'csp' ? 'display:none' : ''}">Public control</button>
        ${kind === 'occluded' ? '<div id="occluder" style="position:fixed;inset:0;background:gray;z-index:99">Public blocker</div>' : ''}
        ${kind === 'private-input' ? '<input value="unknown-occluding-input" style="position:fixed;inset:0;width:100%;height:100%;z-index:99">' : ''}
        ${kind === 'private-container' ? '<div data-sensitive token="unknown-private-attribute" style="position:fixed;inset:0;z-index:99"><span>unknown-private-container</span></div>' : ''}
        <a href="/pricing?secret=${secret}#private-fragment">Public link</a>
        <script>console.log('${secret} https://staging.zunderlabs.com/pricing?secret=${secret}#private-fragment');
        fetch('/aborted.js?secret=${secret}');throw new Error('${secret}');</script>
        </body></html>` });
  });
}

for (const [target, kind] of [
  ['pricing-buy-pro', 'hidden'], ['approve-network-testnet', 'occluded'], ['pricing-buy-pro', 'csp'],
  ['pricing-buy-pro', 'private-input'], ['approve-network-testnet', 'private-container'],
] as const) {
  test(`capture actual pre-action ${target} ${kind} refusal with redaction`, async ({ page }) => {
    const root = await mkdtemp(join(tmpdir(), 'guard-click-fixture-'));
    const old = process.env['GUARD_BROWSER_DIAGNOSTICS'];
    const secret = 'known-secret-private-sentinel';
    process.env['GUARD_BROWSER_DIAGNOSTICS'] = root;
    process.env['GUARD_ACCESS_CLIENT_SECRET'] = secret;
    const capture = stagingClickDiagnostics(page, target);
    delete process.env['GUARD_ACCESS_CLIENT_SECRET']; // Same lifetime as the P8 owner credential.
    try {
      await fixture(page, target, secret, kind);
      await admitStagingDocument(page, target === 'pricing-buy-pro' ? '/pricing' : '/approve', ORIGIN);
      fastFixtureClick(page, target);
      await expect(capture.click()).rejects.toThrow();
      const directory = join(root, target);
      expect((await readdir(directory)).sort()).toEqual(['diagnostics.json', 'page.html', 'screenshot.png']);
      const html = await readFile(join(directory, 'page.html'), 'utf8');
      const text = await readFile(join(directory, 'diagnostics.json'), 'utf8');
      expect(html + text).not.toContain(secret);
      expect(html + text).not.toContain('private-fragment');
      expect(html).not.toContain('unknown-input-private');
      expect(html).not.toContain('unknown-textarea-private');
      const details = JSON.parse(text);
      expect(details.target.rootClass).toBe('public-root');
      expect(details.target.hitOuterHTML.length).toBeLessThanOrEqual(200);
      if (kind === 'occluded') expect(details.target.hitOuterHTML).toContain('occluder');
      else if (kind.startsWith('private-')) {
        expect(details.target.hitOuterHTML).toBe('[REDACTED]');
        expect(html + text).not.toContain('unknown-occluding-input');
        expect(html + text).not.toContain('unknown-private-attribute');
        expect(html + text).not.toContain('unknown-private-container');
      }
      else expect(details.target.visible).toBe(false);
      if (kind === 'csp') expect(details.console.some((line: string) => /Content Security Policy/i.test(line))).toBe(true);
      else {
        expect(details.pageErrors).toContain('[REDACTED]');
        expect(details.aborted).toContainEqual({ path: '/aborted.js', reason: 'net::ERR_BLOCKED_BY_CLIENT' });
      }
      for (const name of ['page.html', 'diagnostics.json', 'screenshot.png']) {
        expect((await stat(join(directory, name))).mode & 0o777).toBe(0o600);
      }
    } finally { capture.dispose(); if (old === undefined) delete process.env['GUARD_BROWSER_DIAGNOSTICS'];
      else process.env['GUARD_BROWSER_DIAGNOSTICS'] = old; await rm(root, { recursive: true, force: true }); }
  });
}

for (const split of [false, true, 'mixed', 'pseudo-mixed'] as const) test(`masked screenshots hide changed private text (split=${split}) and inputs`, async ({ browser }) => {
  const screenshots: Buffer[] = [];
  const root = await mkdtemp(join(tmpdir(), 'guard-click-pixels-'));
  try {
    for (const secret of ['private-secret-AAAA', 'private-secret-BBBB']) {
      const context = await browser.newContext();
      const page = await context.newPage();
      // Inspect real calls: neither evaluate arguments nor screenshot selectors
      // may serialize a credential into the page's JavaScript realm.
      page.evaluate = new Proxy(page.evaluate, { apply(method, receiver, args) {
        expect(JSON.stringify(args.slice(1))).not.toContain(secret);
        return Reflect.apply(method, receiver, args);
      } });
      page.screenshot = new Proxy(page.screenshot, { apply(method, receiver, args) {
        for (const mask of args[0]?.mask ?? []) expect(String(mask)).not.toContain(secret);
        return Reflect.apply(method, receiver, args);
      } });
      process.env['GUARD_BROWSER_DIAGNOSTICS'] = join(root, secret.slice(-4));
      process.env['GUARD_ACCESS_CLIENT_SECRET'] = secret;
      const capture = stagingClickDiagnostics(page, 'pricing-buy-pro');
      try {
        await fixture(page, 'pricing-buy-pro', secret, 'hidden', split);
        await admitStagingDocument(page, '/pricing', ORIGIN);
        await page.locator('input').fill(secret);
        fastFixtureClick(page, 'pricing-buy-pro');
        await expect(capture.click()).rejects.toThrow();
        screenshots.push(await readFile(join(root, secret.slice(-4), 'pricing-buy-pro/screenshot.png')));
        const html = await readFile(join(root, secret.slice(-4), 'pricing-buy-pro/page.html'), 'utf8');
        expect(html).not.toContain(secret);
        expect(html).not.toContain('<span>' + secret.slice(-4) + '</span>');
      } finally { capture.dispose(); await context.close(); }
    }
    expect(screenshots[0]?.equals(screenshots[1] ?? Buffer.alloc(0))).toBe(true);
  } finally { delete process.env['GUARD_BROWSER_DIAGNOSTICS']; delete process.env['GUARD_ACCESS_CLIENT_SECRET'];
    await rm(root, { recursive: true, force: true }); }
});

test('checkout, renewal and non-staging pages cannot produce captures', async ({ page }) => {
  const root = await mkdtemp(join(tmpdir(), 'guard-click-scope-'));
  process.env['GUARD_BROWSER_DIAGNOSTICS'] = root;
  await page.route('**/*', route => route.fulfill({ status: 200, contentType: 'text/html',
    body: '<meta name="zunder-deployment-profile" content="staging"><button data-testid="pricing-buy-pro">Public</button>' }));
  try {
    for (const path of ['/licence?plan=pro', '/licence#renew=private-token', '/pricing#private']) {
      const capture = stagingClickDiagnostics(page, 'pricing-buy-pro');
      await page.goto(ORIGIN + path);
      await expect(capture.click()).rejects.toThrow('scope refused');
      expect(await readdir(root)).toEqual([]);
    }
    const capture = stagingClickDiagnostics(page, 'pricing-buy-pro');
    await page.goto('https://other.example/pricing');
    await expect(capture.click()).rejects.toThrow('scope refused');
    expect(await readdir(root)).toEqual([]);
  } finally { delete process.env['GUARD_BROWSER_DIAGNOSTICS']; await rm(root, { recursive: true, force: true }); }
});

test('visible split 40hex account pins mask only their field, preserving public layout', async ({ browser }) => {
  const root = await mkdtemp(join(tmpdir(), 'guard-click-address-'));
  const screenshots: Buffer[] = [];
  try {
    for (const digit of ['a', 'b']) {
      const account = '0x' + digit.repeat(40);
      process.env['GUARD_BROWSER_DIAGNOSTICS'] = join(root, digit);
      if (digit === 'a') process.env['GUARD_LICENSE_ACCOUNT'] = account;
      else delete process.env['GUARD_LICENSE_ACCOUNT']; // Generic masking protects unlisted pins too.
      const context = await browser.newContext();
      const page = await context.newPage();
      const capture = stagingClickDiagnostics(page, 'pricing-buy-pro');
      const screenshot = page.screenshot.bind(page);
      page.screenshot = async options => {
        for (const mask of options?.mask ?? []) {
          if (String(mask).includes('data-zg-diagnostic-node')) {
            expect(await mask.evaluate(element => element.tagName)).not.toBe('BODY');
            expect(await mask.getAttribute('id')).toBe('account-field');
          }
        }
        return screenshot(options);
      };
      try {
        await page.route('**/*', route => route.fulfill({ status: 200, contentType: 'text/html',
          body: '<meta name="zunder-deployment-profile" content="staging"><h1>Public layout remains visible</h1>'
            + '<div id="account-field" style="width:400px;height:30px"><span>' + account.slice(0, 22)
            + '</span><span>' + account.slice(22) + '</span></div>'
            + '<button data-testid="pricing-buy-pro" style="display:none">Public control</button>' }));
        await admitStagingDocument(page, '/pricing', ORIGIN);
        fastFixtureClick(page, 'pricing-buy-pro');
        await expect(capture.click()).rejects.toThrow();
        screenshots.push(await readFile(join(root, digit, 'pricing-buy-pro/screenshot.png')));
        const html = await readFile(join(root, digit, 'pricing-buy-pro/page.html'), 'utf8');
        expect(html).toContain('Public layout remains visible');
        expect(html).not.toContain(account.slice(22));
      } finally { capture.dispose(); await context.close(); }
    }
    expect(screenshots[0]?.equals(screenshots[1] ?? Buffer.alloc(0))).toBe(true);
  } finally { delete process.env['GUARD_BROWSER_DIAGNOSTICS']; delete process.env['GUARD_LICENSE_ACCOUNT'];
    await rm(root, { recursive: true, force: true }); }
});

test('successful public first click never writes a capture', async ({ page }) => {
  const root = await mkdtemp(join(tmpdir(), 'guard-click-success-'));
  process.env['GUARD_BROWSER_DIAGNOSTICS'] = root;
  const capture = stagingClickDiagnostics(page, 'pricing-buy-pro');
  try {
    await page.route('**/*', route => route.fulfill({ status: 200, contentType: 'text/html',
      body: '<meta name="zunder-deployment-profile" content="staging"><button data-testid="pricing-buy-pro">Public</button>' }));
    await admitStagingDocument(page, '/pricing', ORIGIN);
    await capture.click();
    expect(await readdir(root)).toEqual([]);
  } finally { capture.dispose(); delete process.env['GUARD_BROWSER_DIAGNOSTICS'];
    await rm(root, { recursive: true, force: true }); }
});

test('text redaction removes encoded credentials and all URL query/fragment suffixes', () => {
  expect(redactDiagnostic('secret/value https://example/path?token=secret%2Fvalue#fragment /path?unknown=body',
    ['secret/value', 'secret%2Fvalue'])).toBe('[REDACTED] https://example/path /path');
});
