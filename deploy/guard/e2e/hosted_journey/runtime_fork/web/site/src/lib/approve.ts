import { STAGING } from './deployment';
// The one action /approve can sign: Hyperliquid's ApproveBuilderFee, an EIP-712 "user-signed
// action" (hyperliquid-python-sdk, utils/signing.py: sign_approve_builder_fee,
// sign_user_signed_action, user_signed_payload; exchange.py: approve_builder_fee, _post_action).
// Pure functions: the page builds the typed data here, shows it, has the wallet sign it, and posts
// exactly that action. Nothing in it can be changed by the visitor except the network and which of
// the two rates is signed: Guard's fee (approve) or 0% (withdraw the approval).
import { FEE_PERCENT, type FeeNetwork } from './builder';

export const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

/** The only two rates the page signs: Guard's fee, and 0% to withdraw the approval. */
export const WITHDRAW_PERCENT = '0%';
export type ApproveRate = typeof FEE_PERCENT | typeof WITHDRAW_PERCENT;
export const APPROVE_RATES: readonly string[] = [FEE_PERCENT, WITHDRAW_PERCENT];

export interface ApproveAction {
  type: 'approveBuilderFee';
  hyperliquidChain: 'Mainnet' | 'Testnet';
  signatureChainId: string;
  maxFeeRate: string;
  builder: string;
  nonce: number;
}

/** The action, for one builder, network and wallet chain (the domain's chainId must match it). */
export function approveAction(builder: string, network: FeeNetwork, walletChainIdHex: string, nonce: number, rate: ApproveRate = FEE_PERCENT): ApproveAction {
  if (STAGING && network !== 'testnet') throw new Error('Staging cannot sign mainnet approvals.');
  if (!ADDRESS_RE.test(builder)) throw new Error('not an address');
  if (!APPROVE_RATES.includes(rate)) throw new Error('not a rate this page signs');
  // At most 13 hex digits, so the chain id stays exact as a JS number in the EIP-712 domain.
  if (!/^0x[0-9a-fA-F]{1,13}$/.test(walletChainIdHex)) throw new Error('not a chain id');
  return {
    type: 'approveBuilderFee',
    hyperliquidChain: network === 'mainnet' ? 'Mainnet' : 'Testnet',
    signatureChainId: '0x' + BigInt(walletChainIdHex).toString(16),
    maxFeeRate: rate,
    builder: builder.toLowerCase(),
    nonce,
  };
}

/** The EIP-712 typed data the wallet signs (eth_signTypedData_v4). */
export function typedData(a: ApproveAction) {
  if (STAGING && a.hyperliquidChain !== 'Testnet') throw new Error('Staging cannot sign mainnet approvals.');
  return {
    domain: {
      name: 'HyperliquidSignTransaction',
      version: '1',
      chainId: Number(BigInt(a.signatureChainId)),
      verifyingContract: '0x0000000000000000000000000000000000000000',
    },
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      'HyperliquidTransaction:ApproveBuilderFee': [
        { name: 'hyperliquidChain', type: 'string' },
        { name: 'maxFeeRate', type: 'string' },
        { name: 'builder', type: 'address' },
        { name: 'nonce', type: 'uint64' },
      ],
    },
    primaryType: 'HyperliquidTransaction:ApproveBuilderFee' as const,
    message: { hyperliquidChain: a.hyperliquidChain, maxFeeRate: a.maxFeeRate, builder: a.builder, nonce: a.nonce },
  };
}

/** A 65-byte signature (0x + 130 hex) as Hyperliquid wants it: r and s hex, v 27 or 28. */
export function splitSignature(sig: string): { r: string; s: string; v: number } {
  if (!/^0x[0-9a-fA-F]{130}$/.test(sig)) throw new Error('unexpected signature from the wallet');
  let v = parseInt(sig.slice(130, 132), 16);
  if (v < 27) v += 27;
  if (v !== 27 && v !== 28) throw new Error('unexpected signature from the wallet');
  return { r: '0x' + sig.slice(2, 66), s: '0x' + sig.slice(66, 130), v };
}

/** The body for POST /exchange, as the official SDK sends a user-signed action. */
export function exchangeBody(a: ApproveAction, signature: { r: string; s: string; v: number }) {
  if (STAGING && a.hyperliquidChain !== 'Testnet') throw new Error('Staging cannot submit mainnet approvals.');
  return { action: a, nonce: a.nonce, signature, vaultAddress: null, expiresAfter: null };
}
