// Explicit isolated testnet rehearsal only. Never selected by ordinary fixture tests.
import { test, type BrowserContext, type Page } from '@playwright/test';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { Wallet } from 'ethers';
import { canonicalUsdc, usdcUnits, type PaymentQuote } from '../src/lib/licence-wallet';
import { TERMS_VERSION } from '../src/lib/checkout';
import { createTestnetPaymentWallet, PAYMENT_API, PAYMENT_ORIGIN, PRODUCTION_MERCHANT,
  RETIRED_PAYMENT_OWNERS, matchingPaymentLedger, validPaymentPage, type PaymentPolicy } from './testnet-payment-wallet';
import { testnetCheckoutRequest, validTestnetInboxConfig } from './testnet-purchase-policy';
import { claimPrivateInput, type Claim } from './private-input-broker.ts';
import { readPublicSetup, privateSocketPath, newReceipt } from './private-test-setup.ts';
import { preflightInbox, receiveLicenceMail, verifyTestnetLicence } from './testnet-inbox';

type Setup = Claim & { merchant: string; inboxRecipient: string;
  company: { name: string; street: string; postcode: string; city: string; country: string; vatId?: string };
  maxUsdc: string; publicKey: string; token: string; outputFile: string; verifierFile: string; verifierSha256: string };
type Order = PaymentPolicy['quote'] & { number: string; licenceNumber: string; company: string;
  paidAt: number | null; paidUsdc: string | null; key: string | null };
const PRODUCTION_KEY = '7e298d8aa9921205f1ef0995b8dc6fedd86a4365fe183825127f8cd56a82af46';
function assert(condition: unknown): asserts condition { if (!condition) throw new Error('Isolated testnet prerequisite or boundary failed'); }
async function readSetup(): Promise<Setup> {
  assert(process.env.ZUNDER_TESTNET_PURCHASE === '1');
  const setup = await readPublicSetup('purchase', ['version','purpose','runId','owner','merchant','inboxRecipient','company',
    'maxUsdc','publicKey','token','outputFile','verifierFile','verifierSha256']) as Setup;
  assert(![PRODUCTION_MERCHANT, ...RETIRED_PAYMENT_OWNERS].includes(setup.owner)
    && /^0x[0-9a-f]{40}$/.test(setup.merchant) && ![PRODUCTION_MERCHANT, setup.owner, ...RETIRED_PAYMENT_OWNERS].includes(setup.merchant)
    && !/^0x0{40}$/.test(setup.merchant) && /^[A-Za-z0-9._%+-]+@zunderlabs\.com$/.test(setup.inboxRecipient)
    && /^[0-9a-f]{64}$/.test(setup.publicKey) && setup.publicKey !== PRODUCTION_KEY
    && /^USDC:0x[0-9a-f]{32}$/.test(setup.token) && usdcUnits(setup.maxUsdc) > 0n && usdcUnits(setup.maxUsdc) <= 355610000n
    && path.isAbsolute(setup.verifierFile) && /^[0-9a-f]{64}$/.test(setup.verifierSha256)
    && typeof setup.company === 'object' && setup.company !== null
    && Object.keys(setup.company).every(key => ['name','street','postcode','city','country','vatId'].includes(key)));
  for (const field of ['name', 'street', 'postcode', 'city', 'country'] as const)
    assert(typeof setup.company[field] === 'string' && setup.company[field].length > 0 && setup.company[field].length <= 120);
  assert(/^[A-Z]{2}$/.test(setup.company.country));
  assert(typeof setup.company.vatId === 'undefined' || /^[A-Z0-9]{0,20}$/.test(setup.company.vatId));
  return setup;
}
async function reveal(page: Page) {
  const details = page.locator('details.lc-key-raw');
  if (await details.count() && await details.getAttribute('open') === null) await details.locator('summary').click();
  return (await page.locator('[data-key]').innerText()).trim();
}

// The sole live test is skipped even if manually selected unless the exact opt-in is present.
test('isolated testnet: actual quote, one payment, test issuer, inbox and fresh recovery', async ({ browser, request }) => {
  test.skip(process.env.ZUNDER_TESTNET_PURCHASE !== '1', 'Explicit isolated testnet handoff required');
  test.setTimeout(12 * 60_000);
  const start = Date.now();
  const startedMono = process.hrtime.bigint(), originalDeadline = start + 12 * 60_000;
  let checkpoint = 'private setup';
  let signer: ReturnType<typeof createTestnetPaymentWallet> | null = null;
  let context: BrowserContext | null = null;
  let recoveryContext: BrowserContext | null = null;
  let output: Awaited<ReturnType<typeof open>> | null = null;
  let quote: Order | null = null;
  let session: { id: string; token: string } | null = null;
  let violation = false;
  let closing = false;
  const stages: string[] = [];
  let mailHash: string | null = null;
  let ledgerHash: string | null = null;
  let pendingSave = Promise.resolve();
  const save = async (status: string) => {
    if (!output) return;
    const data = JSON.stringify({ version: 1, target: PAYMENT_ORIGIN, status, checkpoint, stages,
      payment: signer?.outcome() ?? 'not-submitted', paymentIntent: signer?.evidence() ?? null, order: session ? { id: session.id, number: quote?.number ?? null } : null, rawMailSha256: mailHash, ledgerHash,
      licenceNumber: quote?.licenceNumber ?? null, licenceSha256: quote?.key ? createHash('sha256').update(quote.key).digest('hex') : null });
    const target = output;
    pendingSave = pendingSave.then(async () => { await target.write(data + '\n'); await target.sync(); });
    await pendingSave;
  };
  try {
    const setup = await readSetup();
    // Exclusive persistent checkpoint blocks accidental reruns, including unknown transfer outcomes.
    output = await newReceipt(setup.outputFile);
    await save('in_progress');
    const privateInput = await claimPrivateInput(privateSocketPath(), { version: 1, purpose: 'purchase', runId: setup.runId, owner: setup.owner });
    assert(validTestnetInboxConfig(setup.inboxRecipient, privateInput.inboxToken));
    const wallet = new Wallet(privateInput.ownerPrivateKey);
    privateInput.ownerPrivateKey = '';
    const inboxToken = privateInput.inboxToken!; privateInput.inboxToken = '';
    assert(wallet.address.toLowerCase() === setup.owner);
    const expectedQuoteBody = { plan: 'pro', term: 'month', accounts: [setup.owner], company: setup.company.name,
      street: setup.company.street, postcode: setup.company.postcode, city: setup.company.city, country: setup.company.country,
      vatId: setup.company.vatId ?? '', email: setup.inboxRecipient, network: 'hyperliquid', business: true, terms: true, termsVersion: TERMS_VERSION };
    let quoteStarted = false;
    async function boundary(ctx: BrowserContext, mayPay: boolean) {
      await ctx.routeWebSocket('**/*', socket => { violation = true; socket.close(); });
      await ctx.route('**/*', async route => {
        let submitted = false;
        try {
          const req = route.request(), u = new URL(req.url());
          const checkout = testnetCheckoutRequest(req.url(), req.method());
          assert(!u.username && !u.password && !u.search && !u.hash && req.frame() === req.frame().page().mainFrame());
          if (u.origin === PAYMENT_ORIGIN && req.method() === 'GET' && !u.pathname.startsWith('/api/')) {
            assert(!req.isNavigationRequest() || validPaymentPage(req.url()));
          } else if (checkout === 'status') {
            const response = await route.fetch({ maxRedirects: 0, maxRetries: 0, timeout: 15_000 });
            const body = await response.json();
            assert(response.ok() && body.ok === true && body.open === true && body.chain === 'testnet'
              && isDeepStrictEqual(body.networks, ['hyperliquid']));
            return await route.fulfill({ response });
          } else if (checkout === 'quote' || checkout === 'order' || checkout === 'check') {
            if (checkout === 'quote') {
              assert(mayPay && !quoteStarted && isDeepStrictEqual(req.postDataJSON(), expectedQuoteBody)); quoteStarted = true;
            } else assert(session && isDeepStrictEqual(req.postDataJSON(), session));
            const response = await route.fetch({ maxRedirects: 0, maxRetries: 0, timeout: 15_000 });
            assert(response.ok());
            const body = await response.json();
            assert(body.ok === true && body.order?.chain === 'testnet' && body.order.network === 'hyperliquid'
              && body.order.payTo === setup.merchant && isDeepStrictEqual(body.order.accounts, [setup.owner])
              && typeof body.order.id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(body.order.id)
              && /^ZL-\d{4}-\d{6}$/.test(body.order.number) && /^ZL-\d{4}-\d{6}$/.test(body.order.licenceNumber));
            if (checkout === 'quote') {
              assert(/^[A-Za-z0-9_-]{43}$/.test(body.token) && body.order.status === 'awaiting_payment'
                && usdcUnits(body.order.usdc) <= usdcUnits(setup.maxUsdc));
              quote = body.order; session = { id: body.order.id, token: body.token };
              await save('in_progress');
            } else {
              assert(quote && body.order.id === quote.id && body.order.number === quote.number && body.order.usdc === quote.usdc);
              quote = body.order;
            }
            return await route.fulfill({ response });
          } else if (mayPay && u.origin === PAYMENT_API && req.method() === 'POST'
              && ['/info', '/exchange'].includes(u.pathname)) {
            assert(validPaymentPage(req.frame().url()) && signer);
            const body = req.postDataJSON();
            if (u.pathname === '/exchange') { signer.authorizeExchange(body); submitted = true; await save('in_progress'); }
            else assert(isDeepStrictEqual(body, { type: 'spotMeta' })
              || isDeepStrictEqual(body, { type: 'clearinghouseState', user: setup.owner }));
            const response = await route.fetch({ maxRedirects: 0, maxRetries: 0, timeout: 15_000 });
            if (submitted) { signer.recordOutcome(response.status(), await response.json().catch(() => null)); await save('in_progress'); }
            assert(response.status() < 300 || response.status() >= 400);
            return await route.fulfill({ response });
          } else assert(false);
          const response = await route.fetch({ maxRedirects: 0, maxRetries: 0, timeout: 15_000 });
          assert(response.status() < 300 || response.status() >= 400);
          return await route.fulfill({ response });
        } catch {
          if (closing) { await route.abort(); return; }
          if (submitted && signer?.outcome() === 'submitted') signer.markUnknown();
          violation = true; await save('failed'); await route.abort();
        }
      });
    }
    // Test-only verifier and canonical token are validated before any quote or payment.
    const verifier = await open(setup.verifierFile, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { const stat = await verifier.stat(); assert(stat.isFile() && stat.uid === process.getuid?.() && stat.size <= 100_000_000 && (stat.mode & 0o022) === 0
      && createHash('sha256').update(await verifier.readFile()).digest('hex') === setup.verifierSha256); }
    finally { await verifier.close(); }
    const meta = await request.post(PAYMENT_API + '/info', { data: { type: 'spotMeta' }, maxRedirects: 0, timeout: 15_000 });
    assert(meta.ok() && canonicalUsdc(await meta.json()) === setup.token);
    checkpoint = 'actual inbox preflight';
    await preflightInbox(request, { token: inboxToken, recipient: setup.inboxRecipient, orderNumber: 'ZL-2026-000000', after: start });
    checkpoint = 'browser quote';
    context = await browser.newContext({ serviceWorkers: 'block' });
    await boundary(context, true);
    const page = await context.newPage(); await page.goto(PAYMENT_ORIGIN + '/licence');
    await page.locator('[name=plan][value=pro]').check(); await page.locator('[name=term][value=month]').check();
    for (const [field, value] of Object.entries({ accounts: setup.owner, company: setup.company.name, street: setup.company.street,
      postcode: setup.company.postcode, city: setup.company.city, email: setup.inboxRecipient, vatId: setup.company.vatId ?? '' }))
      await page.locator(`[name=${field}]`).fill(value);
    await page.locator('[name=country]').selectOption(setup.company.country);
    await page.locator('[name=network][value=hyperliquid]').check();
    await page.locator('[name=business]').check(); await page.locator('[name=terms]').check();
    await page.locator('[data-submit]').click();
    await page.locator('[data-pay]').waitFor({ state: 'visible' });
    assert(quote && session && !violation);
    // Snapshot the actual server quote into the Node signer, then reload to install its bridge.
    const pinned = structuredClone(quote) as Order;
    signer = createTestnetPaymentWallet(wallet, { owner: setup.owner, merchant: setup.merchant,
      expires: Date.now() + 300_000, quote: pinned, token: setup.token });
    await signer.install(page); await page.reload();
    stages.push('actual-browser-quote'); checkpoint = 'single wallet payment'; await save('in_progress');
    const pay = page.locator('[data-wallet-pay]'); await pay.click();
    await page.waitForFunction(() => document.querySelector('[data-wallet-pay]')?.textContent?.startsWith('Pay '));
    await pay.click();
    // No retry, including a venue rejection. The persisted output records the sole attempt.
    const paymentDeadline = Date.now() + 30_000;
    while (signer.outcome() === 'not-submitted' || signer.outcome() === 'submitted') {
      assert(Date.now() < paymentDeadline && !violation); await new Promise(r => setTimeout(r, 250));
    }
    assert(signer.outcome() === 'accepted'); signer.assertNoViolation();
    stages.push('venue-accepted-testnet-sendasset'); checkpoint = 'server paid and delivered'; await save('in_progress');
    await page.waitForFunction(() => document.querySelector('[data-pay-title]')?.textContent === 'Licence sent', undefined, { timeout: 8 * 60_000 });
    const delivered = quote as Order | null;
    assert(delivered && delivered.status === 'delivered' && typeof delivered.paidAt === 'number' && delivered.paidAt > 0
      && typeof delivered.paidUsdc === 'string' && usdcUnits(delivered.paidUsdc) === usdcUnits(pinned.usdc) && delivered.key);
    assert(await reveal(page) === delivered.key && !violation);
    checkpoint = 'actual testnet ledger receipt';
    const ledgerResponse = await request.post(PAYMENT_API + '/info', { data: {
      type: 'userNonFundingLedgerUpdates', user: setup.merchant, startTime: start }, maxRedirects: 0, maxRetries: 0, timeout: 15_000 });
    try {
      const ledgerBytes = await ledgerResponse.body();
      assert(ledgerResponse.ok() && ledgerBytes.length <= 1_000_000);
      ledgerHash = matchingPaymentLedger(JSON.parse(ledgerBytes.toString()), { owner: setup.owner,
        merchant: setup.merchant, amount: pinned.usdc, after: start, before: Date.now() });
    } finally { await ledgerResponse.dispose(); }
    stages.push('actual-testnet-ledger-transfer-hash');
    stages.push('actual-backend-paid-delivered'); checkpoint = 'actual inbox'; await save('in_progress');
    const mail = await receiveLicenceMail(request, { token: inboxToken, recipient: setup.inboxRecipient,
      orderNumber: delivered.number, after: start });
    assert(mail.licenceKey === delivered.key && validPaymentPage(mail.recoveryUrl));
    const expectedFragment = '#order=' + (session as { id: string; token: string }).id + '.' + (session as { id: string; token: string }).token;
    assert(new URL(mail.recoveryUrl).hash === expectedFragment); mailHash = mail.rawSha256;
    checkpoint = 'fresh browser email recovery';
    recoveryContext = await browser.newContext({ serviceWorkers: 'block' }); await boundary(recoveryContext, false);
    const recovered = await recoveryContext.newPage(); await recovered.goto(mail.recoveryUrl);
    await recovered.waitForFunction(() => document.querySelector('[data-pay-title]')?.textContent === 'Licence sent');
    assert(await reveal(recovered) === delivered.key && await recovered.evaluate(() => location.hash === '') && !violation);
    stages.push('actual-inbox-fresh-browser-recovery'); checkpoint = 'test-key Rust verification';
    let licensee = delivered.company.replace(/[^\p{L}\p{M}\p{N} .,&()\/+\-]/gu, '').trim();
    while (Buffer.byteLength(licensee) > 160) licensee = [...licensee].slice(0, -1).join('');
    await verifyTestnetLicence({ key: delivered.key!, publicKey: setup.publicKey, owner: setup.owner,
      expectedLicensee: licensee.trim() + ' · ' + delivered.licenceNumber }, setup.verifierFile, setup.verifierSha256, () => {
        assert(!closing && Date.now() < originalDeadline && process.hrtime.bigint() - startedMono < 12n * 60n * 1_000_000_000n);
      });
    stages.push('test-key-rust-verification'); checkpoint = 'complete';
    await save('passed-isolated-testnet-only');
  } catch {
    await save('failed');
    throw new Error(`Isolated testnet journey stopped at ${checkpoint}. No automatic retry; inspect the sanitized checkpoint before any new payment.`);
  } finally { closing = true; signer?.dispose(); await recoveryContext?.close(); await context?.close(); await output?.close(); }
});
