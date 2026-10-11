// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { test, expect } from '@playwright/test';
import { WALLET_CHAIN, admittedDescriptor, approvalBody, approvalTyped, validateApproval } from './approval-policy.js';

const builder = `0x${'2'.repeat(40)}`;
const now = 1_800_000_000_000;
test('P8 runtime pins must match the root-admitted released descriptor', () => {
  const account = `0x${'1'.repeat(40)}`;
  const commit = 'a'.repeat(40);
  const descriptor = { network: 'testnet', account, builder, release_commit: commit,
    manifest_sha256: 'b'.repeat(64), fee_tenths_bp: 20 };
  expect(admittedDescriptor(descriptor, account, builder, commit)).toBe(true);
  for (const value of [null, {}, { ...descriptor, network: 'mainnet' }, { ...descriptor, account: builder },
    { ...descriptor, builder: account }, { ...descriptor, release_commit: 'b'.repeat(40) },
    { ...descriptor, fee_tenths_bp: 21 }, { ...descriptor, manifest_sha256: '' }]) {
    expect(admittedDescriptor(value, account, builder, commit)).toBe(false);
  }
});
test('P8 signs only the exact testnet approval and formats its matching exchange body', () => {
  const typed = validateApproval(approvalTyped(now, builder), now, builder);
  const signature = `0x${'a'.repeat(64)}${'b'.repeat(64)}1b`;
  expect(approvalBody(typed, signature)).toEqual({
    action: { type: 'approveBuilderFee', hyperliquidChain: 'Testnet', signatureChainId: WALLET_CHAIN,
      maxFeeRate: '0.02%', builder, nonce: now },
    nonce: now, signature: { r: `0x${'a'.repeat(64)}`, s: `0x${'b'.repeat(64)}`, v: 27 },
    vaultAddress: null, expiresAfter: null,
  });
});
for (const mutation of ['mainnet', 'builder', 'higher-fee', 'withdraw', 'chain', 'type', 'extra', 'old', 'future']) {
  test(`P8 rejects ${mutation} before private signing`, () => {
    const typed: ReturnType<typeof approvalTyped> & { extra?: boolean } = approvalTyped(now, builder);
    if (mutation === 'mainnet') typed.message.hyperliquidChain = 'Mainnet';
    if (mutation === 'builder') typed.message.builder = `0x${'1'.repeat(40)}`;
    if (mutation === 'higher-fee') typed.message.maxFeeRate = '0.03%';
    if (mutation === 'withdraw') typed.message.maxFeeRate = '0%';
    if (mutation === 'chain') typed.domain.chainId = 42161;
    if (mutation === 'type') typed.primaryType = 'HyperliquidTransaction:ApproveAgent';
    if (mutation === 'extra') typed.extra = true;
    if (mutation === 'old') typed.message.nonce = now - 60_001;
    if (mutation === 'future') typed.message.nonce = now + 60_001;
    expect(() => validateApproval(typed, now, builder)).toThrow('Exact fresh testnet builder approval required');
  });
}
for (const [index, signature] of ['', `0x${'a'.repeat(128)}00`, `0x${'a'.repeat(128)}1d`].entries()) {
  test(`P8 rejects malformed signature case ${index}`, () => {
    expect(() => approvalBody(approvalTyped(now, builder), signature)).toThrow('Approval signature shape refused');
  });
}
