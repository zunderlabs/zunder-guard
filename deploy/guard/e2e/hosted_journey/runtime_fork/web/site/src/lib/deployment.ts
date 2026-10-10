import { parseDeploymentProfile, checkoutChainForProfile, tradingModesForProfile } from '../../../deployment-profile.ts';

// Ordinary local builds retain production behaviour. Release packaging also authenticates
// the built profile; backend bindings always require an explicit profile of their own.
export const DEPLOYMENT_PROFILE = parseDeploymentProfile(import.meta.env?.PUBLIC_DEPLOYMENT_PROFILE ?? (typeof process !== 'undefined' ? process.env.PUBLIC_DEPLOYMENT_PROFILE : undefined) ?? 'production');
export const STAGING = DEPLOYMENT_PROFILE === 'staging';
export const TRADING_MODES = tradingModesForProfile(DEPLOYMENT_PROFILE);
export const CHECKOUT_CHAIN = checkoutChainForProfile(DEPLOYMENT_PROFILE);

const legacy = import.meta.env?.PUBLIC_TESTNET_JOURNEY ?? (typeof process !== 'undefined' ? process.env.PUBLIC_TESTNET_JOURNEY : undefined);
if (legacy !== undefined && legacy !== (STAGING ? '1' : '0')) throw new Error('Conflicting deployment profile and legacy testnet flag');
