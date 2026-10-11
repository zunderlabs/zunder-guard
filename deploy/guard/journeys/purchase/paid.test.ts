// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { test, expect } from '@playwright/test';
import { safe, get, post, validInboxMessage } from './safe.js';
import { restrictAccessHeaders } from './browser-access.js';

function command(module: string, args: string[], env: NodeJS.ProcessEnv, input = ''): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.env['GUARD_PYTHON'] ?? 'python', ['-m', module, ...args], {
      env, detached: true, stdio: ['pipe', 'ignore', 'ignore'],
    });
    const timer = setTimeout(() => {
      if (child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* exited */ } }
    }, 180_000);
    child.stdin.on('error', () => { /* exit handler returns only a fixed error */ });
    child.stdin.end(input);
    child.once('error', () => { clearTimeout(timer); reject(new Error('Purchase subprocess could not start')); });
    child.once('close', code => {
      clearTimeout(timer);
      if (code === 0) resolve(); else reject(new Error('Purchase subprocess failed; reconcile private receipts; never retry payment'));
    });
  });
}

const journey = process.env['GUARD_PAID_JOURNEY'] ?? 'P1';
const network = journey === 'P2' ? 'arbitrum' : journey === 'P3' ? 'base' : 'hyperliquid';
test.skip(!['P1', 'P2', 'P3'].includes(process.env['GUARD_PAID_JOURNEY'] ?? ''), 'paid journey requires explicit hosted release inputs');

test(`${journey} pricing to paid email to installed released licence`, async ({ page, request }) => {
  test.setTimeout(15 * 60_000);
  const root = process.env['GUARD_PURCHASE_WORK'];
  const assets = process.env['GUARD_RELEASE_ASSETS'];
  const tag = process.env['GUARD_RELEASE_TAG'];
  const commit = process.env['GUARD_RELEASE_COMMIT'];
  const account = process.env['GUARD_LICENSE_ACCOUNT'];
  const origin = process.env['GUARD_STAGING_URL'];
  const domain = process.env['GUARD_EMAIL_DOMAIN'];
  expect(Boolean(root && assets && tag && commit && account && origin && domain), 'complete paid release inputs').toBe(true);
  expect(/^0x[0-9a-fA-F]{40}$/.test(account ?? ''), 'covered account shape').toBe(true);
  const statusResponse = await get(request, '/api/licence/status', {}, 'paid staging admission');
  const status = await safe(() => statusResponse.json(), 'paid staging JSON');
  expect(statusResponse.status() === 200 && status.ok === true && status.open === true
    && status.chain === 'testnet' && status.profile === 'staging' && status.priceDivisor === 1000
    && status.emailDomain === domain && status.networks?.includes(network), 'C4 testnet admission before quote or payer key').toBe(true);
  await restrictAccessHeaders(page.context(), new URL(origin ?? '').origin, {
    id: process.env['GUARD_ACCESS_CLIENT_ID'] ?? '', secret: process.env['GUARD_ACCESS_CLIENT_SECRET'] ?? '',
  });
  const since = Date.now();
  const email = `paid-${randomUUID()}@${domain}`;
  await safe(() => page.goto('/pricing'), 'pricing page');
  await safe(() => page.getByTestId('pricing-buy-pro').click(), 'pricing purchase link');
  await safe(() => page.getByTestId('checkout-plan-pro').check(), 'checkout selection');
  await safe(() => page.getByTestId('checkout-term-month').check(), 'checkout selection');
  for (const [field, value] of Object.entries({ accounts: account ?? '', company: 'Synthetic journey business',
    street: 'Test street 1', postcode: '10000', city: 'Test city', email })) {
    await safe(() => page.getByTestId(`checkout-${field}`).fill(value), 'checkout field');
  }
  await safe(() => page.getByTestId('checkout-country').selectOption('DE'), 'checkout country');
  await safe(() => page.getByTestId(`checkout-network-${network}`).check(), 'checkout selection');
  await safe(() => page.getByTestId('checkout-business').check(), 'checkout selection');
  await safe(() => page.getByTestId('checkout-terms').check(), 'checkout selection');
  const [response] = await safe(() => Promise.all([
    page.waitForResponse(response => new URL(response.url()).pathname === '/api/licence/quote'
      && response.request().method() === 'POST'),
    page.getByTestId('checkout-quote-submit').click(),
  ]), 'browser quote');
  const body = await safe(() => response.json(), 'browser quote JSON');
  const order = body.order;
  expect(response.status() === 200 && body.ok === true && typeof body.token === 'string'
    && /^ZL-\d{4}-\d{6}$/.test(order?.number ?? '') && typeof order?.id === 'string'
    && order.chain === 'testnet' && order.network === network
    && order.status === 'awaiting_payment' && order.key === null
    && order.accounts?.length === 1 && order.accounts[0]?.toLowerCase() === account?.toLowerCase()
    && /^0\.\d{1,6}$/.test(order.usdc ?? '') && order.payTo === status.payTo?.[network],
  'unpaid exact testnet browser quote bound to covered account and merchant').toBe(true);
  const privateWork = root ?? '';
  await mkdir(privateWork, { mode: 0o700 });
  const clean = { PATH: process.env['PATH'], HOME: privateWork };
  await mkdir(join(privateWork, 'payment'), { mode: 0o700 });
  const paymentEnv = { ...clean, GUARD_STAGING_URL: origin,
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
  const deadline = Date.now() + 10 * 60_000;
  let licence = '';
  while (Date.now() < deadline) {
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
    const inbox = await get(request, process.env['GUARD_INBOX_URL'] ?? '', {
      params: { to: email, since: String(since) },
      headers: { Authorization: `Bearer ${process.env['GUARD_INBOX_TOKEN'] ?? ''}` },
    }, 'paid inbox');
    const messages: unknown = await safe(() => inbox.json(), 'paid inbox JSON');
    expect(inbox.status() === 200 && Array.isArray(messages), 'paid inbox list').toBe(true);
    for (const value of messages as unknown[]) {
      expect(validInboxMessage(value, email, since), 'paid inbox metadata').toBe(true);
      const text = (value as { text: string }).text;
      const match = text.match(/\bzgl1_[A-Za-z0-9_-]+/);
      if (match && state.state === 'delivered' && state.key_issued === true) licence = match[0];
    }
    if (licence) break;
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  expect(Boolean(licence), 'licence arrived by email after delivered order').toBe(true);
  await mkdir(join(privateWork, 'licensed'), { mode: 0o700 });
  await command('guard_harness.purchase_licence', ['--assets', assets ?? '', '--work', join(privateWork, 'licensed'),
    '--tag', tag ?? '', '--commit', commit ?? '', '--account', account ?? '', '--journey', journey], clean, licence + '\n');
});
