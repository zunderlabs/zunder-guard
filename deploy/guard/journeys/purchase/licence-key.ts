// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
// Preserve the complete signed wire token; Rust performs signature/account/expiry admission.
export function emailedLicence(text: string): string | undefined {
  const candidates = text.split(/\s+/).filter(token => token.startsWith('zgl1_'));
  if (candidates.length === 0) return undefined;
  if (candidates.length !== 1 || !/^zgl1_[A-Za-z0-9_-]{1,4004}\.[A-Za-z0-9_-]{86}$/.test(candidates[0] ?? '')) {
    throw new Error('Emailed licence token malformed or ambiguous');
  }
  return candidates[0];
}
