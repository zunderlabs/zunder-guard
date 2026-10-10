// Licence checkout settings. The checkout is open only when a receiving address is set: until
// Jonas gives the company's sales addresses, /api/licence/status says so and no quote is made.
//
// Mainnet: the receiving addresses are constants in this file (MAINNET_SALES), set by a reviewed
// change, so nobody with access to the Worker's settings can redirect real payments; a var that
// names another address is a configuration error. Testnet: the addresses come from vars, and
// testnet orders need a test licence keypair (LICENCE_PUBLIC_KEY not Guard's production key), so
// faucet USDC can never buy a real key.

import { checkoutChainForProfile, parseDeploymentProfile } from "../../../deployment-profile.ts";
import { ConfigError } from "../config.ts";
import type { Env } from "../platform.ts";
import type { PayNetwork } from "./core.ts";
import type { Chain } from "./store.ts";

export interface LicenceConfig {
  chain: Chain;
  /** Receiving addresses (lower case) per network; a network without one is not offered. */
  payTo: Partial<Record<PayNetwork, string>>;
  /** Hyperliquid's API for the chain. */
  hyperliquidApi: string;
  rpc: { arbitrum: string; base: string };
  /** USDC contracts (Circle's native USDC) per EVM network for the chain. */
  usdc: { arbitrum: string; base: string };
  /** The ed25519 public key licence keys verify against (licence.rs, LICENCE_PUBLIC_KEY_HEX), 32 bytes hex. */
  publicKeyHex: string;
  quoteMs: number;
  /** How long after the quote's expiry its amount stays reserved: EVM finality takes minutes. */
  reserveMs: number;
  /** Our own VAT ID, sent to VIES as the requester so a check gets a consultation number; optional. */
  sellerVatId: string | null;
}

/** Circle's USDC contracts (developers.circle.com, "USDC contract addresses", 6 Oct 2026). */
const USDC = {
  mainnet: { arbitrum: "0xaf88d065e77c8cc2239327c5edb3a432268e5831", base: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" },
  testnet: { arbitrum: "0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d", base: "0x036cbd53842c5426634e7929541ec2318f3dcf7e" },
} as const;

const RPC = {
  mainnet: { arbitrum: "https://arb1.arbitrum.io/rpc", base: "https://mainnet.base.org" },
  testnet: { arbitrum: "https://sepolia-rollup.arbitrum.io/rpc", base: "https://sepolia.base.org" },
} as const;

const HL = { mainnet: "https://api.hyperliquid.xyz", testnet: "https://api.hyperliquid-testnet.xyz" } as const;

/** Guard's compiled-in licence public key (crates/zunder-guard-core/src/licence.rs). */
export const GUARD_LICENCE_PUBLIC_KEY = "7e298d8aa9921205f1ef0995b8dc6fedd86a4365fe183825127f8cd56a82af46";

/** The company's sales addresses on mainnet, set by a reviewed change. */
export const MAINNET_SALES: { hyperliquid: string | null; evm: string | null } = {
  // Orcastrate's builder account, also the sales address (Jonas, 6 Oct 2026). EVM networks are on
  // where SALES_EVM_NETWORKS names them (wrangler.toml).
  hyperliquid: "0x0f50112710913B51A5D037795e5F4EFc08deBf2a",
  evm: "0x0f50112710913B51A5D037795e5F4EFc08deBf2a",
};

/**
 * Orcastrate's own addresses (Jonas, 6 Oct 2026): a transfer from one of them to the sales
 * account is internal (funding, testing), never a customer's payment that went wrong. It is
 * recorded, logged and not alerted. It still pays an order if it is exactly an open order's amount.
 */
export const OWN_ADDRESSES: readonly string[] = [
  "0x0f50112710913b51a5d037795e5f4efc08debf2a", // the builder and sales account itself
  "0x4d91ba8f33d2199045ff46dde384f2c49deb3a3f", // the Guard mainnet pilot account
  "0x6b9e773128f453f5c2c60935ee2de2cbc5390a24", // Jonas's funding source
];

const ADDR = /^0x[0-9a-fA-F]{40}$/;

function addressOrNull(raw: string | undefined, name: string): string | null {
  const v = (raw ?? "").trim();
  if (v === "") return null;
  if (!ADDR.test(v)) throw new ConfigError(`${name} is not a 0x address`);
  return v.toLowerCase();
}

function httpsUrl(raw: string | undefined, fallback: string, name: string): string {
  const v = (raw ?? "").trim() || fallback;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    throw new ConfigError(`${name} is not a URL`);
  }
  if (u.protocol !== "https:") throw new ConfigError(`${name} must be https`);
  return u.toString().replace(/\/$/, "");
}

export function loadLicenceConfig(env: Env): LicenceConfig {
  const profile = parseDeploymentProfile(env.DEPLOYMENT_PROFILE);
  const chainRaw = env.LICENCE_CHAIN;
  if (chainRaw !== "mainnet" && chainRaw !== "testnet") throw new ConfigError("LICENCE_CHAIN must be mainnet or testnet");
  if (chainRaw !== checkoutChainForProfile(profile)) throw new ConfigError("Checkout chain does not match deployment profile");
  const chain: Chain = chainRaw;
  let hl = addressOrNull(env.SALES_HYPERLIQUID_ADDRESS, "SALES_HYPERLIQUID_ADDRESS");
  let evm = addressOrNull(env.SALES_EVM_ADDRESS, "SALES_EVM_ADDRESS");
  if (chain === "mainnet") {
    const fixed = { hyperliquid: MAINNET_SALES.hyperliquid?.toLowerCase() ?? null, evm: MAINNET_SALES.evm?.toLowerCase() ?? null };
    if (hl !== null && hl !== fixed.hyperliquid) throw new ConfigError("SALES_HYPERLIQUID_ADDRESS is not the mainnet sales address in the code");
    if (evm !== null && evm !== fixed.evm) throw new ConfigError("SALES_EVM_ADDRESS is not the mainnet sales address in the code");
    hl = fixed.hyperliquid;
    evm = fixed.evm;
  }
  // EVM networks are enabled one by one: never accept a chain the Safe is not deployed on.
  const evmNetworks = (env.SALES_EVM_NETWORKS ?? "").split(",").map((n) => n.trim()).filter(Boolean);
  if (evmNetworks.some((n) => n !== "arbitrum" && n !== "base")) throw new ConfigError("SALES_EVM_NETWORKS lists arbitrum and/or base");
  const payTo: Partial<Record<PayNetwork, string>> = {};
  if (hl) payTo.hyperliquid = hl;
  if (evm) for (const n of evmNetworks as ("arbitrum" | "base")[]) payTo[n] = evm;
  const pk = (env.LICENCE_PUBLIC_KEY ?? GUARD_LICENCE_PUBLIC_KEY).trim().replace(/^0x/, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(pk)) throw new ConfigError("LICENCE_PUBLIC_KEY must be 64 hex digits");
  if (chain === "testnet" && pk === GUARD_LICENCE_PUBLIC_KEY) throw new ConfigError("a testnet checkout needs a test licence key (LICENCE_PUBLIC_KEY), never Guard's production key");
  if (chain === "mainnet" && pk !== GUARD_LICENCE_PUBLIC_KEY) throw new ConfigError("a mainnet checkout verifies against Guard's production licence key only");
  const minutes = (env.LICENCE_QUOTE_MINUTES ?? "30").trim();
  if (!/^\d+$/.test(minutes) || Number(minutes) < 10 || Number(minutes) > 120) throw new ConfigError("LICENCE_QUOTE_MINUTES must be 10 to 120");
  const seller = (env.SELLER_VAT_ID ?? "").trim().toUpperCase();
  if (seller !== "" && !/^DE\d{9}$/.test(seller)) throw new ConfigError("SELLER_VAT_ID must be DE and 9 digits");
  return {
    chain,
    payTo,
    hyperliquidApi: HL[chain],
    rpc: {
      arbitrum: httpsUrl(env.ARBITRUM_RPC_URL, RPC[chain].arbitrum, "ARBITRUM_RPC_URL"),
      base: httpsUrl(env.BASE_RPC_URL, RPC[chain].base, "BASE_RPC_URL"),
    },
    usdc: { ...USDC[chain] },
    publicKeyHex: pk,
    quoteMs: Number(minutes) * 60_000,
    reserveMs: 90 * 60_000,
    sellerVatId: seller === "" ? null : seller,
  };
}

export function openNetworks(c: LicenceConfig): PayNetwork[] {
  return (["hyperliquid", "arbitrum", "base"] as PayNetwork[]).filter((n) => c.payTo[n] !== undefined);
}
