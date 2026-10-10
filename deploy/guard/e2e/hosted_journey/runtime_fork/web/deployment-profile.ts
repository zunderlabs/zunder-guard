/** Deployment policy shared by the website and its customer backend. */
export type DeploymentProfile = 'staging' | 'production';
export type TradingMode = 'paper' | 'testnet' | 'mainnet';
export const STAGING_ORIGIN = 'https://staging.zunderlabs.com';
export const PRODUCTION_ORIGIN = 'https://zunderlabs.com';

/** Backend callers must supply a value: a missing profile is not production permission. */
export function parseDeploymentProfile(value: unknown): DeploymentProfile {
  if (value !== 'staging' && value !== 'production') throw new Error('Explicit deployment profile required');
  return value;
}
export function checkoutChainForProfile(profile: DeploymentProfile): 'testnet' | 'mainnet' {
  return profile === 'staging' ? 'testnet' : 'mainnet';
}
export function tradingModesForProfile(profile: DeploymentProfile): readonly TradingMode[] {
  return profile === 'staging' ? ['paper', 'testnet'] : ['paper', 'testnet', 'mainnet'];
}
