// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { spawn } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test, expect } from '@playwright/test';
import { restrictAccessHeaders } from './browser-access.js';
import { get, safe } from './safe.js';
import { STAGING_ORIGIN, TESTNET_ORIGIN, WALLET_CHAIN,
  admittedDescriptor, approvalBody, canonical, validateApproval } from './approval-policy.js';

function sign(input: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.env['GUARD_PYTHON'] ?? 'python', ['-m', 'guard_harness.builder_approval'], {
      env: { PATH: process.env['PATH'], HOME: process.env['GUARD_PURCHASE_WORK'] },
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    let output = '';
    let oversized = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), 20_000);
    child.stdout.on('data', (chunk: Buffer) => {
      if (output.length + chunk.length > 256) { oversized = true; child.kill('SIGKILL'); }
      else output += chunk.toString('utf8');
    });
    child.stdin.on('error', () => { /* fixed failure is returned by close */ });
    child.stdin.end(input);
    child.once('error', () => { clearTimeout(timer); reject(new Error('Private approval signer unavailable')); });
    child.once('close', code => {
      clearTimeout(timer);
      const signature = output.trim();
      if (code === 0 && !oversized && /^0x[0-9a-fA-F]{128}(1b|1c)$/.test(signature)) resolve(signature);
      else reject(new Error('Private approval signer refused; no signing retry'));
    });
  });
}

test.skip(process.env['GUARD_PAID_JOURNEY'] !== 'P8', 'explicit staged P8 owner-approval admission required');

test('P8 staging approve page signs one pinned testnet builder approval', async ({ page, request }) => {
  test.setTimeout(120_000);
  expect(process.env['GUARD_STAGING_URL'], 'literal isolated C4 origin').toBe(STAGING_ORIGIN);
  const account = (process.env['GUARD_BUILDER_APPROVAL_ACCOUNT'] ?? '').toLowerCase();
  const builder = (process.env['GUARD_BUILDER_APPROVAL_ADDRESS'] ?? '').toLowerCase();
  expect(/^0x[0-9a-f]{40}$/.test(account) && /^0x[0-9a-f]{40}$/.test(builder), 'runtime C6 account and admitted builder').toBe(true);
  const descriptorPath = process.env['GUARD_BUILDER_APPROVAL_DESCRIPTOR'] ?? '';
  expect(descriptorPath.startsWith('/'), 'root-admitted released descriptor required').toBe(true);
  const descriptor: unknown = await safe(async () => JSON.parse(await readFile(descriptorPath, 'utf8')), 'P8 admitted descriptor');
  expect(admittedDescriptor(descriptor, account, builder, process.env['GUARD_RELEASE_COMMIT'] ?? ''),
    'released Guard or C4 descriptor binds runtime pins').toBe(true);
  const root = process.env['GUARD_PURCHASE_WORK'] ?? '';
  expect(root.startsWith('/'), 'fresh absolute private P8 work required').toBe(true);
  const statusResponse = await get(request, '/api/licence/status', {}, 'P8 C4 admission');
  const status = await safe(() => statusResponse.json(), 'P8 C4 JSON');
  expect(statusResponse.status() === 200 && status.ok === true && status.chain === 'testnet'
    && status.profile === 'staging' && status.priceDivisor === 1000, 'C4 testnet profile').toBe(true);
  await mkdir(root, { mode: 0o700 });
  let ownerKey = process.env['GUARD_BUILDER_APPROVAL_OWNER_KEY'] ?? '';
  delete process.env['GUARD_BUILDER_APPROVAL_OWNER_KEY'];
  expect(/^(0x)?[0-9a-fA-F]{64}$/.test(ownerKey), 'purpose-specific owner approval credential').toBe(true);
  let attempted = false;
  let submitted = false;
  let accepted = false;
  let readback = false;
  let refused = false;
  let ownerAdmitted = false;
  let expectedBody: ReturnType<typeof approvalBody> | undefined;
  let nonce = 0;
  await restrictAccessHeaders(page.context(), STAGING_ORIGIN, {
    id: process.env['GUARD_ACCESS_CLIENT_ID'] ?? '', secret: process.env['GUARD_ACCESS_CLIENT_SECRET'] ?? '',
  });
  await page.exposeBinding('guardApprovalRpc', async (source, input: unknown) => {
    try {
      if (source.frame !== page.mainFrame() || new URL(source.frame.url()).origin !== STAGING_ORIGIN
        || new URL(source.frame.url()).pathname !== '/approve') throw new Error();
      const rpc = input as { method?: unknown; params?: unknown };
      if (rpc.method === 'eth_requestAccounts' || rpc.method === 'eth_accounts') return [account];
      if (rpc.method === 'eth_chainId') return WALLET_CHAIN;
      if (rpc.method !== 'eth_signTypedData_v4' || !ownerAdmitted || attempted || !Array.isArray(rpc.params)
        || rpc.params.length !== 2 || rpc.params[0] !== account
        || typeof rpc.params[1] !== 'string' || rpc.params[1].length > 4096) throw new Error();
      attempted = true;
      const typed = validateApproval(JSON.parse(rpc.params[1]), Date.now(), builder);
      nonce = typed.message.nonce;
      await writeFile(join(root, 'approval-attempt.json'), JSON.stringify({ schema: 1, account: account,
        builder: builder, network: 'testnet', nonce, fee_tenths_bp: 20 }) + '\n', { mode: 0o600, flag: 'wx' });
      const signature = await sign(JSON.stringify({ key: ownerKey, account, expected_builder: builder, typed }));
      ownerKey = '';
      expectedBody = approvalBody(typed, signature);
      return signature;
    } catch {
      ownerKey = '';
      refused = true;
      throw new Error('P8 wallet refused; sensitive signing diagnostics withheld');
    }
  });
  await page.addInitScript(() => {
    const provider = { request: (input: unknown) => (window as unknown as {
      guardApprovalRpc: (input: unknown) => Promise<unknown>;
    }).guardApprovalRpc(input) };
    Object.defineProperty(window, 'ethereum', { value: provider, configurable: false });
    addEventListener('eip6963:requestProvider', () => dispatchEvent(new CustomEvent('eip6963:announceProvider', {
      detail: { info: { uuid: '20d4b0a5-aef7-4bbb-b30e-a5df214898e4', name: 'P8 testnet wallet',
        icon: '', rdns: 'com.zunderlabs.e2e' }, provider },
    })));
  });
  await page.route('**/*', async route => {
    try {
      const url = new URL(route.request().url());
      if (url.origin === STAGING_ORIGIN) { await route.fallback(); return; }
      if (url.origin !== TESTNET_ORIGIN || route.request().method() !== 'POST'
        || url.search || url.hash || url.username || url.password) throw new Error();
      const body: unknown = route.request().postDataJSON();
      if (url.pathname === '/exchange') {
        if (submitted || !expectedBody || canonical(body) !== canonical(expectedBody)) throw new Error();
        submitted = true; // reserve before HTTP; ambiguous failure cannot retry.
      } else if (url.pathname === '/info') {
        const info = body as { type?: unknown };
        if (canonical(body) !== canonical(info.type === 'userRole'
          ? { type: 'userRole', user: account }
          : { type: 'maxBuilderFee', user: account, builder: builder })) throw new Error();
      } else throw new Error();
      const headers = route.request().headers();
      delete headers['cf-access-client-id']; delete headers['cf-access-client-secret'];
      const response = await route.fetch({ headers, maxRedirects: 0, maxRetries: 0, timeout: 20_000 });
      try {
        if (response.status() !== 200) throw new Error();
        const value: unknown = await response.json();
        if (url.pathname === '/exchange') {
          const reply = value as { status?: unknown; response?: { type?: unknown } };
          if (reply.status !== 'ok' || reply.response?.type !== 'default') throw new Error();
          accepted = true;
        } else if (canonical(body) === canonical({ type: 'userRole', user: account })) {
          if ((value as { role?: unknown } | null)?.role !== 'user') throw new Error();
          ownerAdmitted = true;
        } else if (accepted && canonical(body) === canonical({ type: 'maxBuilderFee', user: account,
          builder: builder }) && value === 20) readback = true;
        await route.fulfill({ response });
      } finally { await response.dispose(); }
    } catch {
      refused = true;
      try { await route.abort('blockedbyclient'); } catch { /* request ended */ }
    }
  });
  try {
    await safe(() => page.goto(`/approve?builder=${builder}`), 'P8 isolated approval page');
    await safe(() => page.getByTestId('approve-network-testnet').click(), 'P8 testnet selection');
    expect((await safe(() => page.getByTestId('approve-builder-address').textContent(), 'P8 builder display'))?.trim()
      .toLowerCase() === builder, 'displayed pinned builder').toBe(true);
    await safe(() => page.getByTestId('approve-wallets').getByRole('button').first().click(), 'P8 connect injected wallet');
    await safe(() => page.getByTestId('approve-fee').click(), 'P8 exact approval click');
    await expect.poll(() => accepted && readback, { timeout: 30_000, message: 'actual testnet approval and exact readback' }).toBe(true);
    expect(attempted && submitted && !refused, 'one signature and one approved testnet send only').toBe(true);
    // Approval is partial P8 evidence. Only root's correlated fee-bearing T fill completes P8.
    await writeFile(join(root, 'approval-receipt.json'), JSON.stringify({ schema: 1, journey: 'P8',
      account: account, builder: builder, network: 'testnet', nonce, fee_tenths_bp: 20,
      approval_accepted: true, approval_readback: true, completed: false,
      fee_correlation_required: true }) + '\n', { mode: 0o600, flag: 'wx' });
  } finally { ownerKey = ''; }
});
