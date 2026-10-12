// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { chmod, lstat, mkdir, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import type { ConsoleMessage, Page, Request, Response } from '@playwright/test';

type Target = 'pricing-buy-pro' | 'approve-network-testnet';
type Candidate = { index: number; parent: number; text: string; pseudo: string };
const ORIGIN = 'https://staging.zunderlabs.com';
const PATHS = { 'pricing-buy-pro': '/pricing', 'approve-network-testnet': '/approve' };
const LIMIT = 2 * 1024 * 1024;

function credentials(): string[] {
  return Object.entries(process.env).filter(([name, value]) =>
    /SECRET|TOKEN|KEY|CLIENT_ID|ACCOUNT|WALLET/i.test(name) && Boolean(value),
  ).flatMap(([, value]) => {
    const text = value ?? '';
    const entities: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
    return [text, encodeURIComponent(text), text.replace(/[&<>"']/g, char => entities[char] ?? char)];
  }).sort((a, b) => b.length - a.length);
}

export function redactDiagnostic(value: string, secrets: readonly string[]): string {
  for (const secret of secrets) if (secret) value = value.replaceAll(secret, '[REDACTED]');
  return value.replace(/0x[0-9a-fA-F]{40,128}|\b[0-9a-fA-F]{64}\b|zgl1_[A-Za-z0-9_-]+/g, '[REDACTED]')
    .replace(/((?:https?:\/\/|\/)[^\s"'<>?#]*)[?#][^\s"'<>]*/g, '$1')
    .replace(/(["'])[?#][^"']*\1/g, '$1$1');
}

async function admitted(page: Page, target: Target, documentStatus: number): Promise<boolean> {
  try {
    const url = new URL(page.url());
    const marker = page.locator('meta[name="zunder-deployment-profile"]');
    return documentStatus === 200 && url.origin === ORIGIN && url.pathname === PATHS[target]
      && !url.hash && await marker.count() === 1 && await marker.getAttribute('content') === 'staging';
  } catch { return false; }
}

async function outputDirectory(target: Target): Promise<string | null> {
  const base = process.env['GUARD_BROWSER_DIAGNOSTICS'];
  if (!base || !isAbsolute(base)) return null;
  await mkdir(base, { recursive: true, mode: 0o700 });
  const info = await lstat(base);
  if (!info.isDirectory() || info.isSymbolicLink()) return null;
  const output = join(base, target);
  await mkdir(output, { mode: 0o700 }); // Existing captures/links are never replaced.
  return output;
}

function maskIndices(candidates: Candidate[], secrets: string[]): number[] {
  const selected = new Set<number>();
  const counters = secrets.filter(Boolean).map(value => (text: string) => text.split(value).length - 1);
  // Uploaded evidence must not expose account identities or key-length hex.
  // Occurrence accounting masks the smallest sufficient subtree, not the page.
  counters.push(text => (text.match(/0x[0-9a-fA-F]{40,128}|\b[0-9a-fA-F]{64}\b/g) ?? []).length);
  for (const count of counters) {
    const occurrences = candidates.map(candidate => count(candidate.text) + count(candidate.pseudo));
    const covered = candidates.map(() => 0);
    for (const candidate of candidates) {
      if (candidate.parent >= 0 && candidate.parent < candidate.index) {
        // Parent textContent includes child text, but not child pseudo content.
        covered[candidate.parent] = (covered[candidate.parent] ?? 0) + count(candidate.text);
      }
    }
    // A parent is retained when any occurrence spans child nodes; one complete
    // child occurrence must not hide another split occurrence in that parent.
    for (const candidate of candidates) {
      if ((occurrences[candidate.index] ?? 0) > (covered[candidate.index] ?? 0)) selected.add(candidate.index);
    }
  }
  return [...selected];
}

async function sanitizedHTML(page: Page, indices: number[]): Promise<string> {
  return page.evaluate(masked => {
    const copy = document.documentElement.cloneNode(true) as HTMLElement;
    for (const index of masked) {
      const element = copy.querySelector(`[data-zg-diagnostic-node="${index}"]`);
      if (element) element.textContent = '[REDACTED]';
    }
    for (const field of copy.querySelectorAll('input, textarea, select, [contenteditable], [data-private], [data-sensitive]')) {
      const privateField = field.matches('[data-private], [data-sensitive]');
      field.removeAttribute('value');
      for (const attribute of [...field.attributes]) {
        if (privateField || attribute.name.startsWith('data-') || attribute.name === 'title') field.removeAttribute(attribute.name);
      }
      if (field.tagName !== 'INPUT') field.textContent = '[REDACTED]';
    }
    return '<!DOCTYPE html>\n' + copy.outerHTML;
  }, indices); // Only opaque integers enter the page, never a credential or private HTML.
}

async function collect(page: Page, target: Target, secrets: string[]) {
  const locator = page.getByTestId(target).first();
  const visible = await locator.isVisible();
  const box = await locator.boundingBox({ timeout: 1000 }).catch(() => null);
  const details = await page.evaluate(({ testId, bounds }) => {
    const element = document.querySelector(`[data-testid="${testId}"]`);
    const style = element ? getComputedStyle(element) : null;
    const hit = bounds ? document.elementFromPoint(bounds.x + bounds.width / 2,
      bounds.y + bounds.height / 2) : null;
    const sensitive = 'input, textarea, select, [contenteditable], [data-private], [data-sensitive]';
    const privateHit = hit?.closest(sensitive);
    const clone = hit?.cloneNode(true) as HTMLElement | undefined;
    for (const field of clone?.querySelectorAll(sensitive) ?? []) field.replaceWith('[REDACTED]');
    return { display: style?.display ?? null, visibility: style?.visibility ?? null,
      opacity: style?.opacity ?? null, pointerEvents: style?.pointerEvents ?? null,
      rootClass: document.documentElement.className,
      hitText: hit?.textContent ?? '',
      hitOuterHTML: privateHit ? '[REDACTED]' : clone?.outerHTML ?? null };
  }, { testId: target, bounds: box });
  const originalHTML = await page.content();
  if (Buffer.byteLength(originalHTML) > LIMIT) throw new Error('diagnostic HTML exceeds bound');
  // Candidate text travels out of the page; credentials never travel into it.
  const candidates = await page.evaluate(() => {
    const elements = [...document.querySelectorAll('body, body *')];
    const identifiers = new Map(elements.map((element, index) => [element, index]));
    return elements.map((element, index) => {
      const pseudo = getComputedStyle(element, '::before').content
        + getComputedStyle(element, '::after').content;
      element.setAttribute('data-zg-diagnostic-node', String(index));
      const parent = element.parentElement ? identifiers.get(element.parentElement) ?? -1 : -1;
      return { index, parent, text: element.textContent ?? '', pseudo };
    });
  });
  if (candidates.length > 10000 || Buffer.byteLength(JSON.stringify(candidates)) > LIMIT) {
    throw new Error('diagnostic DOM exceeds bound');
  }
  const indices = maskIndices(candidates, secrets);
  const html = await sanitizedHTML(page, indices);
  const masks = indices.map(index => page.locator(`[data-zg-diagnostic-node="${index}"]`));
  const screenshot = await page.screenshot({ fullPage: true, timeout: 8000, mask: [
    page.locator('input, textarea, select, [contenteditable], [data-private], [data-sensitive]'), ...masks,
  ] });
  if (screenshot.length > 8 * LIMIT) throw new Error('diagnostic screenshot exceeds bound');
  const { hitText, ...publicDetails } = details;
  if (secrets.some(value => value && hitText.includes(value))
    || /0x[0-9a-fA-F]{40,128}|\b[0-9a-fA-F]{64}\b/.test(hitText)) publicDetails.hitOuterHTML = '[REDACTED]';
  return { html, screenshot, target: { visible, boundingBox: box, ...publicDetails } };
}

async function bounded<T>(operation: Promise<T>): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([operation, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('diagnostic capture deadline')), 10_000);
    })]);
  } finally { clearTimeout(timer); }
}

/** Attach before navigation; detach after the first pre-quote/pre-signature click. */
export function stagingClickDiagnostics(page: Page, target: Target) {
  const secrets = credentials();
  const consoleMessages: string[] = [], pageErrors: string[] = [], aborted: object[] = [];
  let documentStatus = 0, navigation = 0;
  const clean = (text: string) => redactDiagnostic(text, secrets);
  const onConsole = (message: ConsoleMessage) => {
    if (consoleMessages.length < 100) consoleMessages.push(clean(message.text()).slice(0, 2048));
  };
  const onError = (error: Error) => {
    if (pageErrors.length < 100) pageErrors.push(clean(error.message).slice(0, 2048));
  };
  const onAbort = (request: Request) => {
    if (aborted.length >= 100) return;
    try {
      const failure = request.failure()?.errorText ?? '';
      aborted.push({ path: clean(new URL(request.url()).pathname).slice(0, 512),
        reason: /^net::ERR_[A-Z_]+(?:\.Inspector)?$/.test(failure) ? failure.split('.')[0] : 'unknown' });
    } catch { /* no URL/error dump */ }
  };
  const onResponse = (response: Response) => {
    if (response.request().isNavigationRequest() && response.request().frame() === page.mainFrame()) {
      documentStatus = response.status(); navigation++;
    }
  };
  page.on('console', onConsole); page.on('pageerror', onError);
  page.on('requestfailed', onAbort); page.on('response', onResponse);
  const dispose = () => {
    page.off('console', onConsole); page.off('pageerror', onError);
    page.off('requestfailed', onAbort); page.off('response', onResponse);
  };
  return { dispose, async click() {
    try {
      if (!await admitted(page, target, documentStatus)) throw new Error('staging control scope refused');
      await page.getByTestId(target).click({ timeout: 30_000 });
    } catch (error) {
      try {
        await bounded((async () => {
          const generation = navigation;
          if (await admitted(page, target, documentStatus)) {
            const capture = await collect(page, target, secrets);
            if (generation === navigation && await admitted(page, target, documentStatus)) {
              const output = await outputDirectory(target);
              if (output) {
                const details = { target: capture.target, console: consoleMessages, pageErrors, aborted };
                details.target.hitOuterHTML = clean(details.target.hitOuterHTML ?? '').slice(0, 200);
                details.target.rootClass = clean(details.target.rootClass);
                await writeFile(join(output, 'page.html'), clean(capture.html), { mode: 0o600, flag: 'wx' });
                await writeFile(join(output, 'diagnostics.json'), JSON.stringify(details), { mode: 0o600, flag: 'wx' });
                await writeFile(join(output, 'screenshot.png'), capture.screenshot, { mode: 0o600, flag: 'wx' });
                await chmod(output, 0o700);
              }
            }
          }
        })());
      } catch { /* Fixed diagnostics must never replace the original click failure. */ }
      throw error;
    } finally { dispose(); }
  } };
}
