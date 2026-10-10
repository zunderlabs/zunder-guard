import type { APIRequestContext } from '@playwright/test';

// Both browser navigation and bearer-bearing API requests use this exact allowlist.
export function realPurchaseTarget(value = process.env.ZUNDER_REAL_SITE): string {
  const target = value ?? 'https://zunder-design-preview.pages.dev';
  if (target !== 'https://zunder-design-preview.pages.dev' && target !== 'https://zunderlabs.com')
    throw new Error('ZUNDER_REAL_SITE must be the exact canonical or design-preview origin');
  return target;
}

export const REAL_PURCHASE_TARGET = realPurchaseTarget();

export function readExistingOrder(request: Pick<APIRequestContext, 'post'>, target: string,
  session: { id: string; token: string }) {
  const origin = realPurchaseTarget(target);
  return request.post(`${origin}/api/licence/order`, {
    headers: { Origin: origin }, data: session, maxRedirects: 0,
  });
}
