// Node-only, test-only SendAsset wallet. Never imported by the site or the approval wallet.
// The caller supplies an explicitly authorized test owner; this module never reads/generates keys.
import { isDeepStrictEqual } from 'node:util';
import { createHash } from 'node:crypto';
import { Signature, type Wallet } from 'ethers';
import type { Page } from '@playwright/test';

import {PAYMENT_ORIGIN,PAYMENT_CHAIN,paymentData,validatePaymentPolicy,validatePaymentData,validatePaymentRpc,paymentAttempt,paymentOutcome,refusePayment,validPaymentPage,type PaymentPolicy,type PaymentOutcome} from './testnet-payment-policy.ts';
export * from './testnet-payment-policy.ts';
// The capability may be the admitted remote signer. It need not expose a private key.
export type TestnetPaymentSigner = Pick<Wallet, 'address' | 'signTypedData'>;
export function createTestnetPaymentWallet(ownerWallet: TestnetPaymentSigner, inputPolicy: PaymentPolicy, now = () => Date.now()) {
  const policy: PaymentPolicy = structuredClone(inputPolicy);
  validatePaymentPolicy(policy, now());
  if (ownerWallet.address.toLowerCase() !== policy.owner) refusePayment();
  let wallet: TestnetPaymentSigner | null = ownerWallet;
  const attempt = paymentAttempt();
  let pending: unknown = null;
  let outcome: PaymentOutcome = 'not-submitted';
  let signedNonce: number | null = null;
  let violation = false;
  return {
    owner: policy.owner,
    async install(page: Page) {
      await page.exposeBinding('__zunderTestnetPaymentWallet', async (source, request: unknown) => {
        try {
          if (!wallet || source.page !== page || source.frame !== page.mainFrame() || !validPaymentPage(source.frame.url())) refusePayment();
          validatePaymentPolicy(policy, now());
          const rpc = validatePaymentRpc(request, policy.owner);
          if (rpc.method === 'eth_chainId') return PAYMENT_CHAIN;
          if (rpc.method === 'eth_accounts' || rpc.method === 'eth_requestAccounts') return [policy.owner];
          const data = validatePaymentData(rpc.data, policy, now());
          attempt.take(); // Set before awaiting; no second signature, even after a failure.
          signedNonce = data.message.nonce;
          const signature = await wallet.signTypedData(data.domain, { [data.primaryType]: data.types[data.primaryType as keyof typeof data.types] }, data.message);
          if (!wallet) refusePayment();
          const { r, s, v } = Signature.from(signature);
          pending = { action: { type: 'sendAsset', signatureChainId: PAYMENT_CHAIN, ...data.message },
            nonce: data.message.nonce, signature: { r, s, v } };
          return signature;
        } catch { violation = true; throw new Error('Testnet payment request refused'); }
      });
      await page.addInitScript(() => {
        const provider = Object.freeze({ request: (request: unknown) =>
          (window as unknown as { __zunderTestnetPaymentWallet(r: unknown): Promise<unknown> }).__zunderTestnetPaymentWallet(request) });
        Object.defineProperty(window, 'ethereum', { value: provider, configurable: false, writable: false });
      });
    },
    // Parent network boundary MUST call this before forwarding the browser request; exact body only.
    authorizeExchange(candidate: unknown) {
      if (!wallet || !pending || outcome !== 'not-submitted' || !isDeepStrictEqual(candidate, pending)) refusePayment();
      validatePaymentPolicy(policy, now());
      const nonce = (pending as { nonce: number }).nonce;
      if (now() - nonce > 10_000 || nonce > now() + 1_000) refusePayment();
      pending = null; outcome = 'submitted';
    },
    // Root native proxy has independently verified this exact signed request before
    // handing out these hashes. No pending body/signature or private key leaves Node.
    authorizeHeldPayment(held: { owner: string; merchant: string; amount: string; chain: string;
      nonce: number; bodySha256: string; typedDataSha256: string; expires: number }) {
      if (!wallet || !pending || outcome !== 'not-submitted') refusePayment();
      validatePaymentPolicy(policy, now());
      const nonce = (pending as { nonce: number }).nonce;
      const digest = (text: string) => createHash('sha256').update(text).digest('hex');
      if (held.owner !== policy.owner || held.merchant !== policy.merchant || held.amount !== policy.quote.usdc
        || held.chain !== 'testnet' || held.nonce !== nonce || nonce < now() - 10_000 || nonce > now() + 1_000
        || held.bodySha256 !== digest(JSON.stringify(pending))
        || held.typedDataSha256 !== digest(JSON.stringify(paymentData(policy, nonce)))
        || held.expires !== Math.min(policy.expires, nonce + 10_000) || now() >= held.expires) refusePayment();
      pending = null; outcome = 'submitted';
    },
    recordOutcome(status: number, reply: unknown) {
      if (outcome !== 'submitted') refusePayment();
      outcome = paymentOutcome(status, reply);
    },
    markUnknown() { if (outcome !== 'submitted') refusePayment(); outcome = 'unknown'; },
    outcome: () => outcome,
    evidence: () => ({ owner: policy.owner, merchant: policy.merchant, quoteId: policy.quote.id,
      amount: policy.quote.usdc, token: policy.token, chain: 'testnet' as const, network: 'hyperliquid' as const,
      signatureChainId: PAYMENT_CHAIN, nonce: signedNonce, quoteExpiresAt: policy.quote.quoteExpiresAt }),
    assertNoViolation() { if (violation) refusePayment(); },
    dispose() { wallet = null; pending = null; },
  };
}
