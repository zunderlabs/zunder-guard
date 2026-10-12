// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
/** C4's ref is an opaque transfer identity, not a recoverable signed nonce.
 * The payer receipt has no ref, so admission requires one unique bounded event.
 */
export interface EdgePayment {
  ref: string; network: string; amount_micro: number; payer: string;
  paid_at_ms: number; seen_at_ms: number; order_number: string | null;
  handled: boolean; internal: boolean;
}
export const EDGE_EVENT_WINDOW_MS = 120_000;

export function matchEdgePayment(payments: unknown[], input: {
  payer: string; network: string; amountMicro: number; orderNumber: string | null;
  nonce: number; observedAt: number;
}): EdgePayment | undefined {
  if (!/^0x[0-9a-fA-F]{40}$/.test(input.payer) || input.network !== 'hyperliquid'
    || !Number.isSafeInteger(input.amountMicro) || input.amountMicro <= 0 || input.amountMicro >= 1_000_000
    || !Number.isSafeInteger(input.nonce) || input.nonce <= 0
    || !Number.isSafeInteger(input.observedAt) || input.observedAt < input.nonce
    || (input.orderNumber !== null && !/^ZL-\d{4}-\d{6}$/.test(input.orderNumber))) {
    throw new Error('Invalid private edge payment identity');
  }
  // The endpoint returns only the newest 50; a full page cannot prove uniqueness.
  if (payments.length >= 50) throw new Error('Truncated edge observations cannot prove unique payment');
  const matches: EdgePayment[] = [];
  for (const value of payments) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) continue;
    const row = value as Record<string, unknown>;
    const candidate = typeof row['payer'] === 'string' && row['payer'].toLowerCase() === input.payer.toLowerCase()
      && row['network'] === input.network && row['amount_micro'] === input.amountMicro
      && row['order_number'] === input.orderNumber;
    if (!candidate) continue;
    // Never discard a malformed candidate and present another candidate as unique.
    if (typeof row['ref'] !== 'string' || row['ref'].length === 0 || row['ref'].length > 256
      || row['ref'].trim() !== row['ref'] || /[\u0000-\u001f\u007f-\u009f]/.test(row['ref'])
      || typeof row['paid_at_ms'] !== 'number' || !Number.isSafeInteger(row['paid_at_ms']) || row['paid_at_ms'] < 0
      || typeof row['seen_at_ms'] !== 'number' || !Number.isSafeInteger(row['seen_at_ms']) || row['seen_at_ms'] < 0
      || typeof row['handled'] !== 'boolean' || typeof row['internal'] !== 'boolean') {
      throw new Error('Malformed edge payment candidate; reconcile without retry');
    }
    if (row['paid_at_ms'] >= input.nonce && row['paid_at_ms'] <= input.nonce + EDGE_EVENT_WINDOW_MS
      && row['paid_at_ms'] <= input.observedAt) matches.push(row as unknown as EdgePayment);
  }
  if (matches.length > 1) throw new Error('Ambiguous edge payment identity; reconcile without retry');
  return matches[0];
}
