import { STAGING } from './deployment';
import { usdcUnits } from './usdc.ts';
export { usdcUnits } from './usdc.ts';
import type { PaymentQuote } from './usdc.ts';
export type { PaymentQuote } from './usdc.ts';
// Customer-initiated payments only. Exact decimal strings become integer USDC units.
// No signing key, allowance, permit, automatic retry or payment-confirmation authority here.
export interface WalletProvider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}
export { splitSignature } from './approve';
export const SALES_ADDRESS = '0x0f50112710913b51a5d037795e5f4efc08debf2a';
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
export const TESTNET_PAYMENT_ORIGIN = 'https://staging.zunderlabs.com';
export const TESTNET_RETIRED_ADDRESSES = ['0x7f85c4539b36fa6666d5fc69ccb3eba528046f99',
  '0x29856629fa13e639727a5167834ce51fc283151a', '0xa9860ba817e405d17ef0acbc790cc68de030c5d3'];
export interface PaymentEnvironment { readonly chain: 'testnet'; readonly origin: typeof TESTNET_PAYMENT_ORIGIN; readonly merchant: string }
/** Explicit compile-time opt-in plus exact isolated origin. Production callers omit this. */
export function testnetPaymentEnvironment(flag: unknown, origin: string, merchant: unknown): PaymentEnvironment | undefined {
  return flag === '1' && origin === TESTNET_PAYMENT_ORIGIN && typeof merchant === 'string'
    && /^0x[0-9a-f]{40}$/.test(merchant) && merchant !== SALES_ADDRESS && !TESTNET_RETIRED_ADDRESSES.includes(merchant) && !/^0x0{40}$/.test(merchant)
    ? { chain: 'testnet', origin: TESTNET_PAYMENT_ORIGIN, merchant } : undefined;
}
function isTestnet(environment?: PaymentEnvironment): boolean {
  return environment?.chain === 'testnet' && !!testnetPaymentEnvironment('1', environment.origin, environment.merchant);
}
export const EVM_PAYMENTS = {
  arbitrum: { chainId: '0xa4b1', token: '0xaf88d065e77c8cc2239327c5edb3a432268e5831' },
  base: { chainId: '0x2105', token: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913' },
} as const;
export function validatePayment(quote: PaymentQuote, now = Date.now(), environment?: PaymentEnvironment): void {
  if (!STAGING && environment !== undefined) throw new Error('Production checkout cannot use a testnet payment environment.');
  const testnet = isTestnet(environment);
  if (STAGING && !testnet) throw new Error('Staging cannot sign mainnet payments.');
  if (environment && !testnet) throw new Error('Invalid payment environment.');
  if (quote.chain !== (testnet ? 'testnet' : 'mainnet') || quote.status !== 'awaiting_payment'
      || quote.payTo.toLowerCase() !== (testnet ? environment!.merchant : SALES_ADDRESS)
      || !(testnet ? ['hyperliquid'] : ['hyperliquid', 'arbitrum', 'base']).includes(quote.network))
    throw new Error('This order cannot be paid through the wallet button.');
  if (!Number.isSafeInteger(quote.quoteExpiresAt) || quote.quoteExpiresAt - now < 120_000)
    throw new Error('This quote is too close to expiry. Get fresh payment details before paying.');
  if (usdcUnits(quote.usdc) === 0n) throw new Error('Invalid USDC quote.');
}
export function samePayment(a: PaymentQuote, b: PaymentQuote): boolean {
  return a.id === b.id && a.chain === b.chain && a.network === b.network
    && a.payTo.toLowerCase() === b.payTo.toLowerCase() && a.usdc === b.usdc
    && a.quoteExpiresAt === b.quoteExpiresAt;
}
export function tokenTransfer(quote: PaymentQuote, from: string) {
  validatePayment(quote);
  const network = EVM_PAYMENTS[quote.network as keyof typeof EVM_PAYMENTS];
  if (!network || !ADDRESS.test(from)) throw new Error('Invalid wallet or network.');
  // ERC-20 transfer(address,uint256), not approve/permit. value=0 sends no native token.
  return { from, to: network.token, chainId: network.chainId, value: '0x0',
    data: '0xa9059cbb' + quote.payTo.slice(2).toLowerCase().padStart(64, '0')
      + usdcUnits(quote.usdc).toString(16).padStart(64, '0') };
}
/** Resolve the canonical USDC identity from Hyperliquid, rather than an obsolete token ID. */
export function canonicalUsdc(meta: unknown): string {
  const tokens = meta && typeof meta === 'object' ? (meta as { tokens?: unknown }).tokens : null;
  if (!Array.isArray(tokens)) throw new Error('Invalid token metadata.');
  const matches = tokens.filter(t => t && typeof t === 'object' && t.name === 'USDC' && t.index === 0 && t.isCanonical === true);
  if (matches.length !== 1 || typeof matches[0].tokenId !== 'string' || !/^0x[0-9a-f]{32}$/i.test(matches[0].tokenId))
    throw new Error('Canonical USDC could not be verified.');
  return 'USDC:' + matches[0].tokenId.toLowerCase();
}

/** EIP-712 schema matches the official SDK's SEND_ASSET_SIGN_TYPES. No legacy usdSend fallback. */
export function hyperliquidTransfer(quote: PaymentQuote, signatureChainId: string, token: string, now = Date.now(), environment?: PaymentEnvironment) {
  validatePayment(quote, now, environment);
  if (quote.network !== 'hyperliquid' || (isTestnet(environment) && signatureChainId !== '0x66eee') || !/^0x[0-9a-f]+$/i.test(signatureChainId)
      || BigInt(signatureChainId) <= 0n || BigInt(signatureChainId) > BigInt(Number.MAX_SAFE_INTEGER)
      || !/^USDC:0x[0-9a-f]{32}$/.test(token))
    throw new Error('Invalid signing network.');
  const message = { hyperliquidChain: isTestnet(environment) ? 'Testnet' : 'Mainnet', destination: quote.payTo.toLowerCase(),
    sourceDex: '', destinationDex: '', token, amount: quote.usdc, fromSubAccount: '', nonce: now };
  const action = { type: 'sendAsset', signatureChainId, ...message };
  const typedData = {
    domain: { name: 'HyperliquidSignTransaction', version: '1', chainId: Number(BigInt(signatureChainId)),
      verifyingContract: '0x0000000000000000000000000000000000000000' },
    types: {
      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
      'HyperliquidTransaction:SendAsset': [{ name: 'hyperliquidChain', type: 'string' },
        { name: 'destination', type: 'string' }, { name: 'sourceDex', type: 'string' },
        { name: 'destinationDex', type: 'string' }, { name: 'token', type: 'string' },
        { name: 'amount', type: 'string' }, { name: 'fromSubAccount', type: 'string' }, { name: 'nonce', type: 'uint64' }],
    },
    primaryType: 'HyperliquidTransaction:SendAsset',
    message,
  };
  return { action, typedData, nonce: now };
}
