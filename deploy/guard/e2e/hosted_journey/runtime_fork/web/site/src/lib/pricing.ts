// Guard's prices (research/business/pricing-proposal.md, accepted by Jonas on 6 Oct 2026;
// docs/decisions.md) and the one comparison the pricing calculator makes. Pure: the page, the
// homepage section, the Markdown twin and the calculator all read these.
//
// Licences are priced in euros and the builder fee is paid in USDC on Hyperliquid's dollar
// values, so comparing them needs a rate. EUR_USD is the rate the proposal's break-even figures
// were worked out at ("about $870k" = 149 / 0.0002 × 1.17); it is a fixed assumption, said next to
// every number that uses it, not a live rate.
import { FEE_TENTHS_BP } from './builder';

// The fee is 0.02% of each order Guard sends, stops and take profits included (BUILDER_ON_TRIGGERS
// in crates/zunder-guard-core/src/licence.rs is on since the testnet experiment of 6 Oct 2026). The
// places that say so: legal/terms-of-use.md 13.2 (and web/site/src/copy/terms.md,
// legal/terms-of-use-for-review.md), PRICING.calc.note in web/site/src/copy/pricing.ts,
// web/docs-content/docs/concepts/builder-fees.mdx and docs/guard.md.
/** The builder fee as a fraction: 20 tenths of a basis point = 0.0002 = 0.02%. */
export const FEE_RATE = FEE_TENTHS_BP / 100_000;
export const EUR_USD = 1.17;

export type PlanKey = 'per-order' | 'pro' | 'fund' | 'platform';

export interface Licence {
  key: 'pro' | 'fund';
  name: string;
  monthEur: number;
  yearEur: number;
  maxAccounts: number;
}

export const LICENCES: Licence[] = [
  { key: 'pro', name: 'Pro', monthEur: 149, yearEur: 1490, maxAccounts: 3 },
  { key: 'fund', name: 'Fund', monthEur: 690, yearEur: 6900, maxAccounts: 20 },
];

/** Monthly traded value above which a licence's monthly price is less than the fee, in USD. */
export function breakEvenUsd(l: Licence): number {
  return (l.monthEur * EUR_USD) / FEE_RATE;
}

export interface Comparison {
  /** The builder fee for this traded value, USD a month. */
  feeUsd: number;
  /** The cheapest licence the account count allows, or null above 20 accounts. */
  licence: Licence | null;
  /** That licence's monthly price in USD at EUR_USD. */
  licenceUsd: number | null;
  /** Which is cheaper: the fee, the licence, or neither fits (more accounts than Fund covers). */
  cheaper: 'fee' | 'licence' | 'talk';
  /** How much the cheaper option saves a month, USD. */
  savingUsd: number;
}

/**
 * Fee or licence, for a monthly traded value (USD, entries and exits together, every account
 * added up) and a number of accounts. Monthly licence prices; the yearly price is ten months'.
 */
export function compare(monthlyUsd: number, accounts: number): Comparison {
  const value = Number.isFinite(monthlyUsd) && monthlyUsd > 0 ? monthlyUsd : 0;
  const feeUsd = value * FEE_RATE;
  const licence = LICENCES.find((l) => accounts <= l.maxAccounts) ?? null;
  if (!licence) return { feeUsd, licence: null, licenceUsd: null, cheaper: 'talk', savingUsd: 0 };
  const licenceUsd = licence.monthEur * EUR_USD;
  const cheaper = licenceUsd < feeUsd ? 'licence' : 'fee';
  return { feeUsd, licence, licenceUsd, cheaper, savingUsd: Math.abs(feeUsd - licenceUsd) };
}

/** "$870k", "$4M", "$2.5M", "$174": short dollar amounts for the copy. */
export function usdShort(n: number): string {
  if (n >= 1e6) return '$' + (n / 1e6).toFixed(n >= 1e7 ? 0 : 1).replace(/\.0$/, '') + 'M';
  if (n >= 1e4) return '$' + Math.round(n / 1e3) + 'k';
  return '$' + Math.round(n).toLocaleString('en-US');
}

/** The break-even as the copy says it: two significant figures ("about $870k", "about $4M"). */
export function breakEvenShort(l: Licence): string {
  const n = breakEvenUsd(l);
  const p = 10 ** (Math.floor(Math.log10(n)) - 1);
  return usdShort(Math.round(n / p) * p);
}
