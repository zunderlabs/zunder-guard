// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { renewPurchase } from './renewal.js';
import { emailedLicence } from './licence-key.js';
import { paidTestTimeoutMs, waitForDelivery } from './delivery-deadline.js';
import { test, expect, type Page } from '@playwright/test';
import { safe, get, post, validInboxMessage } from './safe.js';
import { command } from './subprocess.js';
import { admitStagingDocument, pricingPreflight, restrictAccessHeaders } from './browser-access.js';
import { stagingClickDiagnostics } from './staging-click-diagnostics.js';


// Read-only, scalar diagnostics only: never serialize DOM, input values, URLs,
// response bodies or Playwright's original action errors into paid evidence.
async function checkoutState(page: Page) {
  return page.evaluate(() => {
    const ids = ['checkout-plan-pro', 'checkout-term-month', 'checkout-accounts', 'checkout-company',
      'checkout-street', 'checkout-postcode', 'checkout-city', 'checkout-country', 'checkout-vat-id',
      'checkout-email', 'checkout-network-hyperliquid', 'checkout-network-arbitrum', 'checkout-network-base',
      'checkout-business', 'checkout-terms', 'checkout-quote-submit'] as const;
    const controls = ids.map(id => {
      const element = document.querySelector<HTMLInputElement>(`[data-testid="${id}"]`);
      const bounds = element?.getBoundingClientRect();
      const style = element ? getComputedStyle(element) : null;
      const hit = bounds ? document.elementFromPoint(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2) : null;
      return { id, present: !!element, visible: !!bounds && bounds.width > 0 && bounds.height > 0
        && style?.visibility === 'visible' && style.display !== 'none' && element!.getClientRects().length > 0,
        enabled: !!element && !element.matches(':disabled'), checked: element?.checked === true,
        centerHitsControl: !!element && hit === element,
        centerHitsLabel: !!element && !!hit && !hit.closest('a') && hit.closest('label') === element.closest('label') && !!element.closest('label') };
    });
    const form = document.querySelector<HTMLFormElement>('[data-form]');
    const invalidFields = ids.filter(id => {
      const element = document.querySelector<HTMLInputElement>(`[data-testid="${id}"]`);
      return element?.validity?.valid === false;
    });
    const reason = document.querySelector('[data-testid="checkout-submit-why"]')?.textContent ?? '';
    const reasonCategory = !reason.trim() ? 'none' : reason.startsWith('Checking whether') ? 'checking'
      : reason.startsWith('Checkout is unavailable') ? 'unavailable' : reason.startsWith('Can’t reach') ? 'unreachable'
      : reason.startsWith('Checkout is closed') ? 'closed' : 'other';
    return { checkoutDocument: location.origin === 'https://staging.zunderlabs.com' && location.pathname === '/licence',
      stagingMarker: document.querySelector('meta[name="zunder-deployment-profile"]')?.getAttribute('content') === 'staging',
      formPresent: !!form, noValidate: form?.noValidate === true,
      formValid: !!form && Array.from(form.elements).every(element => !('validity' in element) || (element as HTMLInputElement).validity.valid),
      invalidFields, reasonCategory, controls };
  });
}

const journey = process.env['GUARD_PAID_JOURNEY'] ?? 'P1';
const network = journey === 'P2' ? 'arbitrum' : journey === 'P3' ? 'base' : 'hyperliquid';
const checkoutDiagnostic = process.env['GUARD_CHECKOUT_DIAGNOSTIC'] === '1';
if (process.env['GUARD_CHECKOUT_DIAGNOSTIC'] !== undefined && !checkoutDiagnostic) throw new Error('invalid checkout diagnostic switch');
if (checkoutDiagnostic && !['P1', 'P2', 'P3'].includes(journey)) throw new Error('checkout diagnostics require P1, P2 or P3');
test.skip(!['P1', 'P2', 'P3', 'P6'].includes(process.env['GUARD_PAID_JOURNEY'] ?? ''), 'paid journey requires explicit hosted release inputs');

test(`${journey} pricing to paid email to installed released licence`, async ({ page, request }) => {
  test.setTimeout(checkoutDiagnostic ? 2 * 60_000 : paidTestTimeoutMs(network));
  const clickDiagnostics = stagingClickDiagnostics(page, 'pricing-buy-pro');
  const root = process.env['GUARD_PURCHASE_WORK'];
  const assets = process.env['GUARD_RELEASE_ASSETS'];
  const tag = process.env['GUARD_RELEASE_TAG'];
  const commit = process.env['GUARD_RELEASE_COMMIT'];
  const account = process.env['GUARD_LICENSE_ACCOUNT'];
  const origin = process.env['GUARD_STAGING_URL'];
  expect(origin === 'https://staging.zunderlabs.com', 'literal C4 staging origin before navigation').toBe(true);
  const domain = process.env['GUARD_EMAIL_DOMAIN'];
  expect(Boolean(account && origin && domain && (checkoutDiagnostic || (root && assets && tag && commit))), 'complete checkout or paid release inputs').toBe(true);
  expect(/^0x[0-9a-fA-F]{40}$/.test(account ?? ''), 'covered account shape').toBe(true);
  const pinnedPayTo = process.env['GUARD_PAY_TO_' + network.toUpperCase()] ?? '';
  expect(/^0x[0-9a-fA-F]{40}$/.test(pinnedPayTo), 'independently pinned staging merchant').toBe(true);
  const statusResponse = await get(request, '/api/licence/status', {}, 'paid staging admission');
  const status = await safe(() => statusResponse.json(), 'paid staging JSON');
  expect(statusResponse.status() === 200 && status.ok === true && status.open === true
    && status.chain === 'testnet' && status.profile === 'staging' && status.priceDivisor === 1000
    && status.emailDomain === domain && status.networks?.includes(network)
    && typeof status.payTo?.[network] === 'string' && status.payTo[network].toLowerCase() === pinnedPayTo.toLowerCase(), 'C4 testnet admission before quote or payer key').toBe(true);
  await restrictAccessHeaders(page.context(), new URL(origin ?? '').origin, {
    id: process.env['GUARD_ACCESS_CLIENT_ID'] ?? '', secret: process.env['GUARD_ACCESS_CLIENT_SECRET'] ?? '',
  });
  const since = Date.now();
  const email = `paid-${randomUUID()}@${domain}`;
  if (journey === 'P1') await pricingPreflight(page, new URL(origin ?? '').origin, {
    id: process.env['GUARD_ACCESS_CLIENT_ID'] ?? '', secret: process.env['GUARD_ACCESS_CLIENT_SECRET'] ?? '',
  });
  await admitStagingDocument(page, '/pricing', new URL(origin ?? '').origin);
  await safe(() => clickDiagnostics.click(), 'pricing purchase link');
  const checkoutTimeout = 10_000;
  let quoteRequested = false;
  let quoteResponded = false;
  page.on('request', request => {
    if (new URL(request.url()).pathname === '/api/licence/quote' && request.method() === 'POST') quoteRequested = true;
  });
  page.on('response', response => {
    if (new URL(response.url()).pathname === '/api/licence/quote' && response.request().method() === 'POST') quoteResponded = true;
  });
  const checkoutStep = async <T>(phase: string, operation: () => Promise<T>): Promise<T> => {
    try { return await operation(); }
    catch {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const state = await Promise.race([checkoutState(page), new Promise<null>(resolve => {
          timer = setTimeout(() => resolve(null), 2000);
        })]);
        console.log('checkout-phase ' + JSON.stringify({ phase, quoteRequested, quoteResponded, state }));
      } catch { console.log('checkout-phase ' + JSON.stringify({ phase, quoteRequested, quoteResponded, state: null })); }
      finally { clearTimeout(timer); }
      throw new Error(`${phase} failed; sensitive browser diagnostics withheld`);
    }
  };
  await checkoutStep('checkout-plan-pro', () => page.getByTestId('checkout-plan-pro').check({ timeout: checkoutTimeout }));
  await checkoutStep('checkout-term-month', () => page.getByTestId('checkout-term-month').check({ timeout: checkoutTimeout }));
  for (const [field, value] of Object.entries({ accounts: account ?? '', company: 'Synthetic journey business',
    street: 'Test street 1', postcode: '10000', city: 'Test city', email })) {
    await checkoutStep(`checkout-${field}`, () => page.getByTestId(`checkout-${field}`).fill(value, { timeout: checkoutTimeout }));
  }
  await checkoutStep('checkout-country', () => page.getByTestId('checkout-country').selectOption('DE', { timeout: checkoutTimeout }));
  await checkoutStep('checkout-network', () => page.getByTestId(`checkout-network-${network}`).check({ timeout: checkoutTimeout }));
  await checkoutStep('checkout-business', () => page.getByTestId('checkout-business').check({ timeout: checkoutTimeout }));
  await checkoutStep('checkout-terms', () => page.getByTestId('checkout-terms').check({ timeout: checkoutTimeout }));
  const [response] = await checkoutStep('checkout-quote', () => Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname === '/api/licence/quote'
      && response.request().method() === 'POST', { timeout: 30_000 }),
    page.getByTestId('checkout-quote-submit').click({ timeout: checkoutTimeout }),
  ]));
  const body = await safe(() => response.json(), 'browser quote JSON');
  const order = body.order;
  expect(response.status() === 200 && body.ok === true && typeof body.token === 'string'
    && /^ZL-\d{4}-\d{6}$/.test(order?.number ?? '') && typeof order?.id === 'string'
    && order.chain === 'testnet' && order.network === network
    && order.status === 'awaiting_payment' && order.key === null
    && order.accounts?.length === 1 && order.accounts[0]?.toLowerCase() === account?.toLowerCase()
    && /^0\.\d{1,6}$/.test(order.usdc ?? '') && order.payTo === status.payTo?.[network],
  'unpaid exact testnet browser quote bound to covered account and merchant').toBe(true);
  if (checkoutDiagnostic) {
    console.log('checkout-diagnostic ' + JSON.stringify({ journey, network, result: 'passed', paymentAttempted: false }));
    return;
  }
  const privateWork = root ?? '';
  await mkdir(privateWork, { mode: 0o700 });
  const clean = { PATH: process.env['PATH'], HOME: privateWork };
  await mkdir(join(privateWork, 'payment'), { mode: 0o700 });
  const paymentEnv = { ...clean, GUARD_STAGING_URL: origin,
    ['GUARD_PAY_TO_' + network.toUpperCase()]: pinnedPayTo,
    GUARD_ACCESS_CLIENT_ID: process.env['GUARD_ACCESS_CLIENT_ID'],
    GUARD_ACCESS_CLIENT_SECRET: process.env['GUARD_ACCESS_CLIENT_SECRET'],
    GUARD_ORDER_TOKEN: process.env['GUARD_ORDER_TOKEN'],
  };
  const paymentArgs = ['--order', order.number, '--amount', order.usdc, '--work', join(privateWork, 'payment')];
  if (network === 'hyperliquid') {
    await command('guard_harness.purchase_payment', paymentArgs, { ...paymentEnv,
      E2E_PAYER_HYPERLIQUID_TESTNET_KEY: process.env['E2E_PAYER_HYPERLIQUID_TESTNET_KEY'],
    });
  } else {
    await command('guard_harness.purchase_evm', ['--network', network, ...paymentArgs], { ...paymentEnv,
      E2E_PAYER_EVM_SEPOLIA_KEY: process.env['E2E_PAYER_EVM_SEPOLIA_KEY'],
    });
  }
  let licence = '';
  let renewalToken = '';
  const deliveryProgress = { paid: false, issued: false, delivered: false };
  licence = await waitForDelivery(network, async () => {
    const scan = await post(request, '/api/licence/order/check', {
      headers: { Origin: origin ?? '' }, data: { id: order.id, token: body.token },
    }, 'paid order check');
    expect(scan.status() === 200, 'paid order check HTTP').toBe(true);
    const stateResponse = await get(request, `/api/licence/test/order/${order.number}`, {
      headers: { Authorization: `Bearer ${process.env['GUARD_ORDER_TOKEN'] ?? ''}` },
    }, 'paid order state');
    const state = await safe(() => stateResponse.json(), 'paid order state JSON');
    expect(stateResponse.status() === 200 && state.network === network
      && ['quoted', 'paid', 'issued', 'delivered'].includes(state.state), 'expected paid delivery states').toBe(true);
    deliveryProgress.paid ||= state.state === 'paid';
    deliveryProgress.issued ||= state.state === 'issued';
    deliveryProgress.delivered ||= state.state === 'delivered';
    const inbox = await get(request, process.env['GUARD_INBOX_URL'] ?? '', {
      params: { to: email, since: String(since) },
      headers: { Authorization: `Bearer ${process.env['GUARD_INBOX_TOKEN'] ?? ''}` },
    }, 'paid inbox');
    const messages: unknown = await safe(() => inbox.json(), 'paid inbox JSON');
    expect(inbox.status() === 200 && Array.isArray(messages), 'paid inbox list').toBe(true);
    for (const value of messages as unknown[]) {
      expect(validInboxMessage(value, email, since), 'paid inbox metadata').toBe(true);
      const text = (value as { text: string }).text;
      const key = emailedLicence(text);
      const renew = text.match(/\/licence#renew=([A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/);
      if (renew) renewalToken = renew[1] ?? '';
      if (key && state.state === 'delivered' && state.key_issued === true) licence = key;
    }
    return licence || null;
  }) ?? '';
  if (!licence) console.log('paid-delivery-deadline ' + JSON.stringify({ journey, network, ...deliveryProgress, emailedKey: false }));
  expect(Boolean(licence), 'licence arrived by email after delivered order').toBe(true);
  let renewalInput = '';
  if (journey === 'P6') {
    expect(Boolean(renewalToken), 'emailed renewal token required').toBe(true);
    renewalInput = await renewPurchase(page, request, { origin: origin ?? '', domain: domain ?? '',
      since: Date.now(), email, token: renewalToken, oldKey: licence, root: privateWork, paymentEnv });
  }
  await mkdir(join(privateWork, 'licensed'), { mode: 0o700 });
  await command('guard_harness.purchase_licence', ['--assets', assets ?? '', '--work', join(privateWork, 'licensed'),
    '--tag', tag ?? '', '--commit', commit ?? '', '--account', account ?? '', '--journey', journey], clean, (renewalInput || licence) + '\n');
});
