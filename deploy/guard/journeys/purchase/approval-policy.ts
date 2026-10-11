// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
/** Public contract constants only; no imports from the private website or signer source. */
export const STAGING_ORIGIN = 'https://staging.zunderlabs.com';
export const TESTNET_ORIGIN = 'https://api.hyperliquid-testnet.xyz';
export const WALLET_CHAIN = '0x66eee'; // Arbitrum Sepolia, distinct from HL's action network.

/** Root supplies this only after authenticating the release and reading its Guard/C4 descriptor. */
export function admittedDescriptor(value: unknown, account: string, builder: string, commit: string): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const descriptor = value as Record<string, unknown>;
  return /^0x[0-9a-f]{40}$/.test(account) && /^0x[0-9a-f]{40}$/.test(builder)
    && /^[0-9a-f]{40}$/.test(commit) && descriptor['network'] === 'testnet'
    && descriptor['account'] === account && descriptor['builder'] === builder
    && descriptor['fee_tenths_bp'] === 20 && descriptor['release_commit'] === commit
    && typeof descriptor['manifest_sha256'] === 'string' && /^[0-9a-f]{64}$/.test(descriptor['manifest_sha256']);
}

export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonical(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'undefined';
}

export function approvalTyped(nonce: number, builder: string) {
  return {
    domain: { name: 'HyperliquidSignTransaction', version: '1', chainId: 421614,
      verifyingContract: `0x${'0'.repeat(40)}` },
    types: {
      EIP712Domain: [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' }],
      'HyperliquidTransaction:ApproveBuilderFee': [{ name: 'hyperliquidChain', type: 'string' },
        { name: 'maxFeeRate', type: 'string' }, { name: 'builder', type: 'address' }, { name: 'nonce', type: 'uint64' }],
    },
    primaryType: 'HyperliquidTransaction:ApproveBuilderFee',
    message: { hyperliquidChain: 'Testnet', maxFeeRate: '0.02%', builder, nonce },
  };
}

export function validateApproval(value: unknown, now: number, builder: string): ReturnType<typeof approvalTyped> {
  if (!/^0x[0-9a-f]{40}$/.test(builder)) throw new Error('Admitted testnet builder required');
  const nonce = (value as { message?: { nonce?: unknown } } | null)?.message?.nonce;
  if (typeof nonce !== 'number' || !Number.isSafeInteger(nonce) || Math.abs(nonce - now) > 60_000
    || canonical(value) !== canonical(approvalTyped(nonce, builder))) throw new Error('Exact fresh testnet builder approval required');
  return approvalTyped(nonce, builder);
}

export function approvalBody(typed: ReturnType<typeof approvalTyped>, signature: string) {
  if (!/^0x[0-9a-fA-F]{128}(1b|1c)$/.test(signature)) throw new Error('Approval signature shape refused');
  return {
    action: { type: 'approveBuilderFee', signatureChainId: WALLET_CHAIN, ...typed.message },
    nonce: typed.message.nonce,
    signature: { r: signature.slice(0, 66), s: `0x${signature.slice(66, 130)}`, v: parseInt(signature.slice(130), 16) },
    vaultAddress: null, expiresAfter: null,
  };
}
