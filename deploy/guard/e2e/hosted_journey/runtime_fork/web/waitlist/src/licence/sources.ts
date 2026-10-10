// What the checkout asks the outside world, all through public APIs and no keys: the USDC/EUR rate
// (Kraken's public ticker), VAT IDs (the EU's VIES REST API), payments to our Hyperliquid account
// (Hyperliquid's info API) and USDC transfers to our address on Arbitrum and Base (JSON-RPC).
// `fetch` is passed in, so the tests answer every call.

import { parseRate, parseUsdc } from "./core.ts";

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

export class SourceError extends Error {}

async function getJson(fetchFn: Fetch, url: string, init?: RequestInit): Promise<unknown> {
  const res = await fetchFn(url, { ...init, signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new SourceError(`${new URL(url).host} answered ${res.status}`);
  return res.json();
}

// ---------------------------------------------------------------- the rate

/**
 * EUR per USDC: Kraken's best bid for USDC/EUR (what selling the USDC brings), as micro-EUR.
 * api.kraken.com/0/public/Ticker?pair=USDCEUR, public, no key.
 */
export async function usdcEurRate(fetchFn: Fetch): Promise<{ microEur: number; source: string }> {
  const body = (await getJson(fetchFn, "https://api.kraken.com/0/public/Ticker?pair=USDCEUR")) as {
    error?: unknown[];
    result?: Record<string, { b?: unknown[] }>;
  };
  if (Array.isArray(body.error) && body.error.length) throw new SourceError("Kraken: " + String(body.error[0]).slice(0, 80));
  const pair = body.result ? Object.values(body.result)[0] : undefined;
  const micro = parseRate(pair?.b?.[0]);
  if (micro === null) throw new SourceError("Kraken: no usable USDC/EUR bid");
  return { microEur: micro, source: "Kraken USDC/EUR bid" };
}

// ---------------------------------------------------------------- VIES

export interface ViesResult {
  valid: boolean;
  name: string | null;
  address: string | null;
  requestDate: string | null;
  requestIdentifier: string | null;
}

/**
 * Checks an EU VAT ID with VIES (ec.europa.eu/taxation_customs/vies/rest-api/check-vat-number).
 * `vatId` carries its prefix ("FR12345678901"). Throws SourceError when VIES or the member state
 * cannot answer (MS_UNAVAILABLE and friends): the order then waits, it is never waved through.
 */
export async function checkVat(fetchFn: Fetch, vatId: string, requester: string | null): Promise<ViesResult> {
  const body: Record<string, string> = { countryCode: vatId.slice(0, 2), vatNumber: vatId.slice(2) };
  if (requester) {
    body.requesterMemberStateCode = requester.slice(0, 2);
    body.requesterNumber = requester.slice(2);
  }
  const r = (await getJson(fetchFn, "https://ec.europa.eu/taxation_customs/vies/rest-api/check-vat-number", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
  })) as Record<string, unknown>;
  if (r.actionSucceed === false || r.errorWrappers) throw new SourceError("VIES could not check the VAT ID now");
  if (typeof r.valid !== "boolean") throw new SourceError("VIES gave no answer");
  const str = (v: unknown) => (typeof v === "string" && v.trim() !== "" && v.trim() !== "---" ? v.trim().slice(0, 300) : null);
  return { valid: r.valid, name: str(r.name), address: str(r.address), requestDate: str(r.requestDate), requestIdentifier: str(r.requestIdentifier) };
}

// ---------------------------------------------------------------- incoming transfers

export interface Incoming {
  /** Unique per transfer: Hyperliquid's hash, or the tx hash and log index. */
  ref: string;
  payer: string;
  amountMicro: bigint;
  /** Ledger or block time, ms. */
  time: number;
}

/**
 * USDC sent to `account` on Hyperliquid since `since` (ms): userNonFundingLedgerUpdates, the
 * sendAsset ("send") and legacy transfers ("internalTransfer", "spotTransfer"), only
 * USDC, only to `account` from someone else. Every other type is ignored, in particular
 * "rewardsClaim" (builder-fee and referral income claimed), "deposit" and "withdraw" (the bridge),
 * "accountClassTransfer" (perp and spot within the account), vault and liquidation entries.
 */
export async function hyperliquidIncoming(fetchFn: Fetch, api: string, account: string, since: number): Promise<Incoming[]> {
  // The API returns a page of updates from startTime on; a full page means there may be more.
  const rows: unknown[] = [];
  let start = since;
  for (let page = 0; page < 10; page++) {
    const batch = await getJson(fetchFn, api + "/info", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ type: "userNonFundingLedgerUpdates", user: account, startTime: start }),
    });
    if (!Array.isArray(batch)) throw new SourceError("Hyperliquid: unexpected ledger answer");
    rows.push(...batch);
    const last = (batch.at(-1) as { time?: unknown } | undefined)?.time;
    if (batch.length < HL_PAGE || typeof last !== "number" || last < start) break;
    // From the last row's time again: rows sharing that millisecond are not lost (refs dedupe).
    if (last === start && batch.length >= HL_PAGE) break;
    start = last;
  }
  const out: Incoming[] = [];
  for (const row of rows as { time?: unknown; hash?: unknown; delta?: Record<string, unknown> }[]) {
    const d = row.delta;
    if (!d || !["send", "internalTransfer", "spotTransfer"].includes(String(d.type))) continue;
    const destination = String(d.destination ?? "").toLowerCase();
    const user = String(d.user ?? "").toLowerCase();
    if (destination !== account || user === account || !/^0x[0-9a-f]{40}$/.test(user)) continue;
    if (d.token !== undefined && d.token !== "USDC") continue;
    const amount = parseUsdc(d.amount ?? d.usdc ?? d.usdcValue);
    if (amount === null || amount <= 0n) continue;
    if (typeof row.time !== "number" || typeof row.hash !== "string" || !/^0x[0-9a-f]{64}$/i.test(row.hash)) continue;
    out.push({ ref: row.hash.toLowerCase(), payer: user, amountMicro: amount, time: row.time });
  }
  return out;
}

/** Updates per page of userNonFundingLedgerUpdates: a page this long may have more after it. */
const HL_PAGE = 500;

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

async function rpc(fetchFn: Fetch, url: string, method: string, params: unknown[]): Promise<unknown> {
  const body = (await getJson(fetchFn, url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  })) as { result?: unknown; error?: { message?: string } };
  if (body.error) throw new SourceError(`${method}: ${String(body.error.message ?? "error").slice(0, 120)}`);
  return body.result;
}

const hexNum = (v: unknown): number => {
  if (typeof v !== "string" || !/^0x[0-9a-f]{1,15}$/i.test(v)) throw new SourceError("not a hex number");
  return Number(BigInt(v));
};
const hexOrNull = (v: unknown): number | null => (typeof v === "string" && /^0x[0-9a-f]{1,15}$/i.test(v) ? Number(BigInt(v)) : null);

/** The chain's finalized block: number and time (ms). */
export async function finalizedBlock(fetchFn: Fetch, url: string): Promise<{ number: number; time: number }> {
  const b = (await rpc(fetchFn, url, "eth_getBlockByNumber", ["finalized", false])) as { number?: unknown; timestamp?: unknown } | null;
  if (!b) throw new SourceError("no finalized block");
  return { number: hexNum(b.number), time: hexNum(b.timestamp) * 1000 };
}

/** USDC `Transfer` events to `to` in blocks from..to (inclusive), with each block's time. */
export async function evmIncoming(fetchFn: Fetch, url: string, usdc: string, to: string, from: number, toBlock: number): Promise<Incoming[]> {
  const logs = (await rpc(fetchFn, url, "eth_getLogs", [{
    fromBlock: "0x" + from.toString(16),
    toBlock: "0x" + toBlock.toString(16),
    address: usdc,
    topics: [TRANSFER_TOPIC, null, "0x" + to.slice(2).padStart(64, "0")],
  }])) as { transactionHash?: unknown; logIndex?: unknown; blockNumber?: unknown; data?: unknown; topics?: unknown[]; removed?: unknown; address?: unknown }[];
  if (!Array.isArray(logs)) throw new SourceError("eth_getLogs: unexpected answer");
  const times = new Map<number, number>();
  const out: Incoming[] = [];
  for (const log of logs) {
    if (log.removed === true || String(log.address ?? "").toLowerCase() !== usdc) continue;
    if (!Array.isArray(log.topics) || log.topics.length !== 3 || String(log.topics[0]).toLowerCase() !== TRANSFER_TOPIC) continue;
    if (String(log.topics[2]).toLowerCase() !== "0x" + to.slice(2).padStart(64, "0")) continue;
    if (typeof log.transactionHash !== "string" || !/^0x[0-9a-f]{64}$/i.test(log.transactionHash)) continue;
    // A malformed log is skipped, never allowed to stop the watcher (the cursor would stall).
    const block = hexOrNull(log.blockNumber);
    const index = hexOrNull(log.logIndex);
    if (block === null || index === null) continue;
    let time = times.get(block);
    if (time === undefined) {
      const b = (await rpc(fetchFn, url, "eth_getBlockByNumber", ["0x" + block.toString(16), false])) as { timestamp?: unknown } | null;
      if (!b) throw new SourceError("block not found");
      time = hexNum(b.timestamp) * 1000;
      times.set(block, time);
    }
    const payer = "0x" + String(log.topics[1]).slice(-40).toLowerCase();
    if (typeof log.data !== "string" || !/^0x[0-9a-f]{1,64}$/i.test(log.data)) continue;
    out.push({ ref: log.transactionHash.toLowerCase() + ":" + index, payer, amountMicro: BigInt(log.data), time });
  }
  return out;
}

/** USDC's own blocklist (`isBlacklisted(address)`, Circle's FiatToken): a sanctions signal for a payer. */
export async function usdcBlacklisted(fetchFn: Fetch, url: string, usdc: string, who: string): Promise<boolean> {
  const r = await rpc(fetchFn, url, "eth_call", [{ to: usdc, data: "0xfe575a87" + who.slice(2).padStart(64, "0") }, "latest"]);
  return typeof r === "string" && /^0x0*1$/.test(r);
}
