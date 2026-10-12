// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
// Transaction inclusion is not EVM finality. Poll the existing purchase; never pay again.
export type PaymentNetwork = 'hyperliquid' | 'arbitrum' | 'base';
export const deliveryWaitMs = (network: PaymentNetwork): number =>
  (network === 'hyperliquid' ? 10 : 30) * 60_000;
export const paidTestTimeoutMs = (network: PaymentNetwork): number =>
  (network === 'hyperliquid' ? 15 : 40) * 60_000;

export async function waitForDelivery<T>(network: PaymentNetwork, poll: () => Promise<T | null>,
  clock: () => number = () => performance.now(),
  sleep: (ms: number) => Promise<void> = ms => new Promise(resolve => setTimeout(resolve, ms)),
): Promise<T | null> {
  const deadline = clock() + deliveryWaitMs(network);
  while (clock() < deadline) {
    const result = await poll();
    // A response arriving after the bound cannot turn a timeout into acceptance.
    if (clock() >= deadline) return null;
    if (result !== null) return result;
    await sleep(Math.min(5000, deadline - clock()));
  }
  return null;
}
