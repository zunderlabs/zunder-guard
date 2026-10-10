// Exact decimal strings to integer micro-units, shared by browser and root checks.
export interface PaymentQuote {
  id: string; status: string; chain: string; network: string; payTo: string;
  usdc: string; quoteExpiresAt: number;
}
export function usdcUnits(amount: string): bigint {
  if (!/^(0|[1-9]\d{0,11})(\.\d{1,6})?$/.test(amount)) throw new Error('Invalid USDC quote.');
  const [whole, fraction = ''] = amount.split('.');
  return BigInt(whole!) * 1_000_000n + BigInt(fraction.padEnd(6, '0'));
}
