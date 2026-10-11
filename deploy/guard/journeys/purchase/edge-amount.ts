// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
// Every edge has its own fresh quote and one payment attempt; one micro-USDC off is
// deliberately unmatched. Never round a Number or retry an ambiguous payment.
export function edgeAmount(amount: string, scenario: string): string {
  if (!/^0\.\d{1,6}$/.test(amount)) throw new Error('bounded quoted decimal required');
  const micro = BigInt(amount.slice(2).padEnd(6, '0')) + (scenario === 'under' ? -1n : scenario === 'over' ? 1n : 0n);
  if (micro <= 0n || micro >= 1_000_000n) throw new Error('edge amount outside sub-dollar bound');
  return `0.${micro.toString().padStart(6, '0')}`;
}

