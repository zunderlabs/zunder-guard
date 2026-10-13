// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import type { APIRequestContext } from '@playwright/test';
import { get, safe, validInboxMessage } from './safe.js';

export const quoteMailWaitMs = 60_000;
const failure = 'quoted order email unavailable; payment not attempted';

/** Observe the quote's existing email before any payer receives a key or broadcasts. */
export async function requireQuoteMail(request: APIRequestContext,
  input: { inboxUrl: string; token: string; email: string; since: number; order: string },
  clock: () => number = () => performance.now(),
  sleep: (ms: number) => Promise<void> = ms => new Promise(resolve => setTimeout(resolve, ms)),
): Promise<void> {
  try {
    if (!/^ZL-\d{4}-\d{6}$/.test(input.order) || !Number.isSafeInteger(input.since) || input.since <= 0) {
      throw new Error(failure);
    }
    const deadline = clock() + quoteMailWaitMs;
    while (clock() < deadline) {
      const remaining = deadline - clock();
      // Playwright treats timeout=0 as unlimited; an expired budget never starts a read.
      if (remaining <= 0) throw new Error(failure);
      const inbox = await get(request, input.inboxUrl, {
        params: { to: input.email, since: String(input.since) },
        headers: { Authorization: `Bearer ${input.token}` },
        timeout: Math.min(5000, remaining),
      }, 'quote email admission');
      const messages: unknown = await safe(() => inbox.json(), 'quote email admission JSON');
      if (clock() >= deadline || inbox.status() !== 200 || !Array.isArray(messages) || messages.length > 50) {
        throw new Error(failure);
      }
      let matched = false;
      for (const value of messages) {
        if (!validInboxMessage(value, input.email, input.since)) throw new Error(failure);
        const message = value as { subject: string; text: string };
        matched ||= message.subject === `Your Zunder Guard licence order ${input.order}`
          && message.text.split(/\r?\n/).some(line => line.startsWith(`Order ${input.order}: `));
      }
      if (matched) {
        if (clock() >= deadline) throw new Error(failure);
        return;
      }
      await sleep(Math.min(5000, deadline - clock()));
    }
  } catch {
    // Requests, metadata and email bodies can contain credentials or customer data.
    throw new Error(failure);
  }
  throw new Error(failure);
}
