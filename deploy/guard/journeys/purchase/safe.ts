// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import type { APIRequestContext, APIResponse } from '@playwright/test';

/** Keep bearer/Access credentials and licence email bodies out of failure reports. */
export async function safe<T>(operation: () => Promise<T>, label: string): Promise<T> {
  try {
    return await operation();
  } catch {
    // API errors can include headers, and JSON errors can include bodies.
    // Omit the original error/cause while retaining a fixed operation label.
    throw new Error(`${label} failed; sensitive HTTP diagnostics withheld`);
  }
}

export function validInboxMessage(value: unknown, email: string, since: number): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const message = value as Record<string, unknown>;
  return typeof message['id'] === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(message['id'])
    && message['to'] === email.toLowerCase()
    && typeof message['subject'] === 'string'
    && typeof message['received_at_ms'] === 'number'
    && Number.isSafeInteger(message['received_at_ms']) && message['received_at_ms'] >= since
    && typeof message['text'] === 'string' && typeof message['html'] === 'string';
}

export function get(
  request: APIRequestContext, url: string,
  options: NonNullable<Parameters<APIRequestContext['get']>[1]>, label: string,
): Promise<APIResponse> {
  return safe(() => request.get(url, { ...options, maxRedirects: 0 }), label);
}

export function post(
  request: APIRequestContext, url: string,
  options: NonNullable<Parameters<APIRequestContext['post']>[1]>, label: string,
): Promise<APIResponse> {
  return safe(() => request.post(url, { ...options, maxRedirects: 0 }), label);
}
