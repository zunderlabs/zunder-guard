// Shared Node testnet purchase policy. No key, signing, browser or network operation.
import {isDeepStrictEqual} from 'node:util';
import {verifyTypedData} from '../node_modules/ethers/lib.esm/index.js';
import {usdcUnits,type PaymentQuote} from '../src/lib/usdc.ts';
export const PAYMENT_ORIGIN = 'https://staging.zunderlabs.com';
export const PAYMENT_API = 'https://api.hyperliquid-testnet.xyz';
export const PAYMENT_CHAIN = '0x66eee';
export const PRODUCTION_MERCHANT = '0x0f50112710913b51a5d037795e5f4efc08debf2a';
export const RETIRED_PAYMENT_OWNERS = ['0x7f85c4539b36fa6666d5fc69ccb3eba528046f99',
  '0x29856629fa13e639727a5167834ce51fc283151a', '0xa9860ba817e405d17ef0acbc790cc68de030c5d3'];
const ZERO = '0x0000000000000000000000000000000000000000';
const ADDRESS = /^0x[0-9a-f]{40}$/;
const fields = [{ name: 'hyperliquidChain', type: 'string' }, { name: 'destination', type: 'string' },
  { name: 'sourceDex', type: 'string' }, { name: 'destinationDex', type: 'string' },
  { name: 'token', type: 'string' }, { name: 'amount', type: 'string' },
  { name: 'fromSubAccount', type: 'string' }, { name: 'nonce', type: 'uint64' }];
const domainFields = [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
  { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }];
export interface PaymentPolicy {
  owner: string;
  merchant: string;
  expires: number;
  // Quote must come from the isolated server, not from browser-supplied signing data.
  quote: PaymentQuote & { accounts: string[] };
  // Obtained independently by Node from testnet spotMeta's canonical USDC entry.
  token: string;
}
export function refusePayment(): never { throw new Error('Testnet payment policy refused'); }
export function validPaymentPage(url: string): boolean {
  try {
    const u = new URL(url);
    return u.origin === PAYMENT_ORIGIN && u.pathname === '/licence' && !u.username && !u.password
      && !u.search && (!u.hash || /^#order=[A-Za-z0-9_-]{1,100}\.[A-Za-z0-9_-]{43}$/.test(u.hash));
  } catch { return false; }
}
export function paymentData(policy: PaymentPolicy, nonce: number) {
  return {
    domain: { name: 'HyperliquidSignTransaction', version: '1', chainId: 421614, verifyingContract: ZERO },
    types: { EIP712Domain: domainFields.map(f => ({ ...f })), 'HyperliquidTransaction:SendAsset': fields.map(f => ({ ...f })) },
    primaryType: 'HyperliquidTransaction:SendAsset',
    message: { hyperliquidChain: 'Testnet', destination: policy.merchant, sourceDex: '', destinationDex: '',
      token: policy.token, amount: policy.quote.usdc, fromSubAccount: '', nonce },
  };
}
export function validatePaymentPolicy(policy: PaymentPolicy, now: number): void {
  const q = policy.quote;
  if (!Number.isSafeInteger(now) || !ADDRESS.test(policy.owner) || [ZERO, PRODUCTION_MERCHANT, policy.merchant, ...RETIRED_PAYMENT_OWNERS].includes(policy.owner)
      || !ADDRESS.test(policy.merchant) || [ZERO, PRODUCTION_MERCHANT, ...RETIRED_PAYMENT_OWNERS].includes(policy.merchant)
      || !Number.isSafeInteger(policy.expires) || now >= policy.expires || policy.expires - now > 300_000
      || !q || !/^[A-Za-z0-9_-]{1,100}$/.test(q.id) || q.chain !== 'testnet' || q.network !== 'hyperliquid'
      || q.status !== 'awaiting_payment' || q.payTo !== policy.merchant
      || !Array.isArray(q.accounts) || q.accounts.length !== 1 || q.accounts[0] !== policy.owner
      || !Number.isSafeInteger(q.quoteExpiresAt) || q.quoteExpiresAt - now < 120_000
      || !/^USDC:0x[0-9a-f]{32}$/.test(policy.token)) refusePayment();
  try { if (usdcUnits(q.usdc) <= 0n) refusePayment(); } catch { refusePayment(); }
}
export function validatePaymentData(input: unknown, policy: PaymentPolicy, now: number) {
  validatePaymentPolicy(policy, now);
  const nonce = (input as { message?: { nonce?: unknown } } | null)?.message?.nonce;
  if (typeof nonce !== 'number' || !Number.isSafeInteger(nonce) || nonce < now - 10_000 || nonce > now + 1_000) refusePayment();
  const expected = paymentData(policy, nonce);
  if (!isDeepStrictEqual(input, expected)) refusePayment();
  return expected;
}
export function validatePaymentRpc(raw: unknown, owner: string): { method: string; data?: unknown } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) refusePayment();
  const rpc = raw as { method?: string; params?: unknown[] };
  if (Object.keys(raw).some(k => !['method', 'params'].includes(k))) refusePayment();
  if (['eth_requestAccounts', 'eth_accounts', 'eth_chainId'].includes(rpc.method ?? '') && rpc.params === undefined)
    return { method: rpc.method! };
  if (rpc.method !== 'eth_signTypedData_v4' || !Array.isArray(rpc.params) || rpc.params.length !== 2
      || rpc.params[0] !== owner || typeof rpc.params[1] !== 'string' || rpc.params[1].length > 4000) refusePayment();
  try { return { method: rpc.method, data: JSON.parse(rpc.params[1]) }; } catch { return refusePayment(); }
}
/** Irreversible single-use latch; even signing failure or ambiguous submission consumes it. */
export function paymentAttempt() {
  let spent = false;
  return { take() { if (spent) refusePayment(); spent = true; }, spent: () => spent };
}
/** Verify the exact genuine-wallet SendAsset body; never asks for a key or signs. */
export function validatePaymentExchange(value:unknown,policy:PaymentPolicy,now:number){
  validatePaymentPolicy(policy,now);
  const b=value as {action?:unknown;nonce?:unknown;signature?:{r?:unknown;s?:unknown;v?:unknown}}|null;
  if(!b||Object.keys(b).sort().join(',')!=='action,nonce,signature'||typeof b.nonce!=='number')refusePayment();
  const data=validatePaymentData(paymentData(policy,b.nonce),policy,now),sig=b.signature;
  if(!sig||Object.keys(sig).sort().join(',')!=='r,s,v'||typeof sig.r!=='string'||typeof sig.s!=='string'
    ||!/^0x[0-9a-f]{64}$/.test(sig.r)||!/^0x[0-9a-f]{64}$/.test(sig.s)||![27,28].includes(Number(sig.v))||typeof sig.v!=='number')refusePayment();
  const n=BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
  if(BigInt(sig.r!)<=0n||BigInt(sig.r!)>=n||BigInt(sig.s!)<=0n||BigInt(sig.s!)>n/2n
    ||!isDeepStrictEqual(b.action,{type:'sendAsset',signatureChainId:PAYMENT_CHAIN,...data.message}))refusePayment();
  try{
    const recovered=verifyTypedData(data.domain,{'HyperliquidTransaction:SendAsset':data.types['HyperliquidTransaction:SendAsset']},data.message,{r:sig.r as string,s:sig.s as string,v:sig.v as number});
    if(recovered.toLowerCase()!==policy.owner)refusePayment();
  }catch{return refusePayment();}
  return data;
}
export type PaymentOutcome = 'not-submitted' | 'submitted' | 'accepted' | 'rejected' | 'unknown';
export function paymentOutcome(status: number, reply: unknown): PaymentOutcome {
  const r = reply as { status?: string; response?: { type?: string } | string } | null;
  if (status === 200 && r?.status === 'ok' && typeof r.response === 'object' && r.response?.type === 'default') return 'accepted';
  if (status === 200 && r?.status === 'err' && typeof r.response === 'string') return 'rejected';
  return 'unknown';
}
/** Independent receipt check: only one exact recent SendAsset credit can prove this payment. */
export function matchingPaymentLedger(rows: unknown, expected: { owner: string; merchant: string; amount: string; after: number; before: number }): string {
  if (!Array.isArray(rows) || rows.length >= 500 || !Number.isSafeInteger(expected.after)
      || !Number.isSafeInteger(expected.before) || expected.before < expected.after) refusePayment();
  const matches: string[] = [];
  for (const raw of rows) {
    const row = raw as { time?: unknown; hash?: unknown; delta?: Record<string, unknown> } | null;
    const d = row?.delta;
    if (!d || d.type !== 'send' || d.user !== expected.owner || d.destination !== expected.merchant
        || d.token !== 'USDC' || typeof d.amount !== 'string' || typeof row?.time !== 'number'
        || !Number.isSafeInteger(row.time) || row.time < expected.after || row.time > expected.before
        || typeof row.hash !== 'string' || !/^0x[0-9a-f]{64}$/.test(row.hash)) continue;
    try { if (usdcUnits(d.amount) === usdcUnits(expected.amount)) matches.push(row.hash); } catch { /* Invalid receipt is not proof. */ }
  }
  if (matches.length !== 1) refusePayment();
  return matches[0]!;
}
