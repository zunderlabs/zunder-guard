// The builder fee: the one place the site names Orcastrate's builder addresses and the fee. Keep it
// in step with crates/zunder-guard-core/src/licence.rs (ORCASTRATE_BUILDER,
// ORCASTRATE_TESTNET_BUILDER, BUILDER_FEE_TENTHS_BP).

export type FeeNetwork = 'mainnet' | 'testnet';

/**
 * Orcastrate's builder addresses (licence.rs: ORCASTRATE_BUILDER, ORCASTRATE_TESTNET_BUILDER).
 * Testnet has none yet: with null, /approve cannot approve there, except through a
 * `?builder=0x…` link while the page is unlisted (the fee experiment).
 */
export const BUILDERS: Record<FeeNetwork, string | null> = {
  mainnet: '0x0f50112710913B51A5D037795e5F4EFc08deBf2a',
  testnet: null,
};

/** The fee Guard attaches: 0.02% of each order's value, as Hyperliquid's approval writes it. */
export const FEE_PERCENT = '0.02%';
/** The same in tenths of a basis point, the unit `maxBuilderFee` answers in. */
export const FEE_TENTHS_BP = 20;

export const API: Record<FeeNetwork, string> = {
  mainnet: 'https://api.hyperliquid.xyz',
  testnet: 'https://api.hyperliquid-testnet.xyz',
};
