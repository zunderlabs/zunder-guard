// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { Unanswered } from './safe.js';

// Transaction inclusion is not EVM finality. Poll the existing purchase; never pay again.
// Both Sepolia chains reached finality and delivery 17-21 minutes after payment (staging, 12-13 Oct),
// so the EVM bound is 40 minutes: about twice the observed time.
export type PaymentNetwork = 'hyperliquid' | 'arbitrum' | 'base';
export const deliveryWaitMs = (network: PaymentNetwork): number =>
  (network === 'hyperliquid' ? 10 : 40) * 60_000;
export const paidTestTimeoutMs = (network: PaymentNetwork): number =>
  (network === 'hyperliquid' ? 15 : 50) * 60_000;

// A poll's reads are idempotent, so a request that got no HTTP response at all counts as
// "not yet" up to this many times in a row; the next one fails with its fixed label.
// Anything that did respond (non-200, bad JSON, invalid inbox metadata) still fails at once.
export const toleratedUnansweredPolls = 3;

export async function waitForDelivery<T>(network: PaymentNetwork, poll: () => Promise<T | null>,
  clock: () => number = () => performance.now(),
  sleep: (ms: number) => Promise<void> = ms => new Promise(resolve => setTimeout(resolve, ms)),
): Promise<T | null> {
  const deadline = clock() + deliveryWaitMs(network);
  let unanswered = 0;
  while (clock() < deadline) {
    let result: T | null;
    try {
      result = await poll();
      unanswered = 0;
    } catch (error) {
      if (!(error instanceof Unanswered) || ++unanswered > toleratedUnansweredPolls) throw error;
      result = null;
    }
    // A response arriving after the bound cannot turn a timeout into acceptance.
    if (clock() >= deadline) return null;
    if (result !== null) return result;
    await sleep(Math.min(5000, deadline - clock()));
  }
  return null;
}
