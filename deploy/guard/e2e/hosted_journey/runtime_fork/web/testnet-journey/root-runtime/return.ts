import {createHash} from 'node:crypto';
import {
  OWNER,
  API,
  ZERO,
  units,
  decimal,
  exact,
  address,
  hashString,
  fail,
  type FileRef,
} from "./policy.ts";
export interface ReturnPolicy {
  version: 1;
  runId: string;
  merchant: string;
  destination: typeof OWNER;
  amount: string;
  paidUsdc: string;
  token: string;
  paymentHash: string;
  paymentAfter: number;
  startedAt: number;
  expires: number;
  maxFeeUsdc: string;
  maxDebitUsdc: string;
  feeEvidence: FileRef;
  purchaseReceipt: FileRef;
}
export interface Balance {
  withdrawable: string;
  accountValue: string;
}
export interface Snapshot {
  merchant: Balance;
  owner: Balance;
  time: number;
  paymentHash: string;
  token: string;
}
export interface FeeEvidence {
  version: 1;
  scope: "root-reviewed-testnet-sendasset-fee";
  merchant: string;
  destination: string;
  token: string;
  expectedFeeUsdc: string;
  observedAt: number;
  expires: number;
  rootVerified: true;
}
export function validateReturn(
  p: ReturnPolicy,
  merchant: string,
  runId: string,
  deadline: number,
  now: number,
) {
  exact(p, [
    "version",
    "runId",
    "merchant",
    "destination",
    "amount",
    "paidUsdc",
    "token",
    "paymentHash",
    "paymentAfter",
    "startedAt",
    "expires",
    "maxFeeUsdc",
    "maxDebitUsdc",
    "feeEvidence",
    "purchaseReceipt",
  ]);
  if (
    p.version !== 1 ||
    p.runId !== runId ||
    p.merchant !== merchant ||
    !address(merchant) ||
    p.destination !== OWNER ||
    !/^USDC:0x[0-9a-f]{32}$/.test(p.token) ||
    !/^0x[0-9a-f]{64}$/.test(p.paymentHash) ||
    ![p.paymentAfter, p.startedAt, p.expires].every(Number.isSafeInteger) ||
    p.paymentAfter > p.startedAt ||
    p.paymentAfter < now - 1200000 ||
    p.startedAt > now ||
    now >= p.expires ||
    p.expires > deadline ||
    p.expires - p.startedAt > 120000
  )
    fail();
  const amount = units(p.amount),
    paid = units(p.paidUsdc),
    fee = units(p.maxFeeUsdc),
    debit = units(p.maxDebitUsdc);
  if (
    amount <= 0n ||
    amount > paid ||
    paid > 355610000n ||
    fee > 1000000n ||
    debit < amount ||
    debit > 355610000n ||
    debit > amount + fee
  )
    fail();
}
export function validateFee(
  f: unknown,
  p: ReturnPolicy,
  now: number,
): FeeEvidence {
  exact(f, [
    "version",
    "scope",
    "merchant",
    "destination",
    "token",
    "expectedFeeUsdc",
    "observedAt",
    "expires",
    "rootVerified",
  ]);
  if (
    f.version !== 1 ||
    f.scope !== "root-reviewed-testnet-sendasset-fee" ||
    f.rootVerified !== true ||
    f.merchant !== p.merchant ||
    f.destination !== OWNER ||
    f.token !== p.token ||
    !Number.isSafeInteger(f.observedAt) ||
    !Number.isSafeInteger(f.expires) ||
    (f.observedAt as number) > now ||
    (f.observedAt as number) < now - 60000 ||
    (f.expires as number) < p.expires
  )
    fail();
  if (
    units(f.expectedFeeUsdc) > units(p.maxFeeUsdc) ||
    units(p.amount) + units(f.expectedFeeUsdc) > units(p.maxDebitUsdc)
  )
    fail();
  return f as unknown as FeeEvidence;
}
export function canonicalToken(meta: unknown) {
  const tokens = (meta as { tokens?: unknown })?.tokens;
  if (!Array.isArray(tokens)) fail();
  const found = tokens.filter(
    (t) => t && t.name === "USDC" && t.index === 0 && t.isCanonical === true,
  );
  if (
    found.length !== 1 ||
    typeof found[0].tokenId !== "string" ||
    !/^0x[0-9a-f]{32}$/i.test(found[0].tokenId)
  )
    fail();
  return "USDC:" + found[0].tokenId.toLowerCase();
}
export function balance(value: unknown): Balance {
  const v = value as {
    withdrawable?: unknown;
    marginSummary?: { accountValue?: unknown };
    assetPositions?: unknown;
  };
  if (!v || !Array.isArray(v.assetPositions) || v.assetPositions.length !== 0)
    fail();
  units(v.withdrawable);
  units(v.marginSummary?.accountValue);
  return {
    withdrawable: v.withdrawable as string,
    accountValue: v.marginSummary!.accountValue as string,
  };
}
export function ledger(
  rows: unknown,
  sender: string,
  recipient: string,
  amount: string,
  after: number,
  before: number,
  expectedHash?: string,
) {
  if (!Array.isArray(rows) || rows.length >= 500) fail();
  const hashes: string[] = [];
  for (const row of rows) {
    const d = row?.delta;
    if (
      d?.type !== "send" ||
      d.user !== sender ||
      d.destination !== recipient ||
      d.token !== "USDC" ||
      !Number.isSafeInteger(row.time) ||
      row.time < after ||
      row.time > before ||
      !/^0x[0-9a-f]{64}$/.test(row.hash ?? "")
    )
      continue;
    try {
      if (units(d.amount) === units(amount)) hashes.push(row.hash);
    } catch {}
  }
  if (
    hashes.length !== 1 ||
    (expectedHash !== undefined && hashes[0] !== expectedHash)
  )
    fail();
  return hashes[0]!;
}
const fields = [
  { name: "hyperliquidChain", type: "string" },
  { name: "destination", type: "string" },
  { name: "sourceDex", type: "string" },
  { name: "destinationDex", type: "string" },
  { name: "token", type: "string" },
  { name: "amount", type: "string" },
  { name: "fromSubAccount", type: "string" },
  { name: "nonce", type: "uint64" },
];
export function returnData(p: Pick<ReturnPolicy,'token'|'amount'>, nonce: number) {
  return {
    domain: {
      name: "HyperliquidSignTransaction",
      version: "1",
      chainId: 421614,
      verifyingContract: ZERO,
    },
    types: {
      "HyperliquidTransaction:SendAsset": fields.map((f) => ({ ...f })),
    },
    message: {
      hyperliquidChain: "Testnet",
      destination: OWNER,
      sourceDex: "",
      destinationDex: "",
      token: p.token,
      amount: p.amount,
      fromSubAccount: "",
      nonce,
    },
  };
}
export function reconcileBalances(
  before: Snapshot,
  after: Snapshot,
  p: ReturnPolicy,
) {
  const amount = units(p.amount),
    debit =
      units(before.merchant.accountValue) - units(after.merchant.accountValue),
    credit = units(after.owner.accountValue) - units(before.owner.accountValue),
    fee = debit - amount;
  if (
    credit !== amount ||
    fee < 0n ||
    fee > units(p.maxFeeUsdc) ||
    debit > units(p.maxDebitUsdc) ||
    units(after.merchant.withdrawable) !== 0n ||
    units(after.merchant.accountValue) !== 0n
  )
    fail();
  return {
    debit: decimal(debit),
    credit: decimal(credit),
    fee: decimal(fee),
    merchantEmpty: true,
  };
}
/** Exact fixed endpoint; no general fetch API, redirect or retry. */
export async function venueObserved(
  path: "/info" | "/exchange",
  body: unknown,
  deadline: number,
  fetcher: typeof fetch = fetch,
) {
  if (
    (path !== "/info" && path !== "/exchange") ||
    !Number.isSafeInteger(deadline) ||
    Date.now() >= deadline
  )
    fail();
  const response = await fetcher(API + path, {
    method: "POST",
    redirect: "error",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(
      Math.max(1, Math.min(10000, deadline - Date.now())),
    ),
  });
  if (response.status !== 200 || !response.body) fail();
  const reader = response.body.getReader(),
    parts: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const r = await reader.read();
      if (r.done) break;
      length += r.value.length;
      if (length > 1000000) {
        await reader.cancel();
        fail();
      }
      parts.push(r.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let at = 0;
  for (const p of parts) {
    bytes.set(p, at);
    at += p.length;
  }
  const observedAt=Date.now();
  return {value:JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)),
    responseSha256:createHash('sha256').update(bytes).digest('hex'),observedAt};
}
export async function venue(path:'/info'|'/exchange',body:unknown,deadline:number,fetcher:typeof fetch=fetch){
 return (await venueObserved(path,body,deadline,fetcher)).value;
}
export function accepted(v: unknown) {
  return (
    (v as { status?: string; response?: { type?: string } })?.status === "ok" &&
    (v as { response?: { type?: string } }).response?.type === "default"
  );
}
/** One irreversible attempt. Injected operations enable offline tests without real signing. */
export class ReturnAttempt {
  private spent = false;
  private state: "idle" | "signing" | "submitted" | "accepted" | "unknown" =
    "idle";
  status() {
    return { spent: this.spent, state: this.state };
  }
  async execute<T>(
    data: ReturnType<typeof returnData>,
    deps: {
      check: () => void;
      intent: () => Promise<void>;
      sign: (data: ReturnType<typeof returnData>) => Promise<T>;
      send: (signature: T) => Promise<unknown>;
    },
  ) {
    if (this.spent) fail();
    this.spent = true;
    this.state = "signing";
    try {
      deps.check();
      await deps.intent();
      deps.check();
      const signature = await deps.sign(data);
      deps.check();
      this.state = "submitted";
      const reply = await deps.send(signature);
      deps.check();
      if (!accepted(reply)) fail();
      this.state = "accepted";
      return;
    } catch {
      this.state = "unknown";
      fail();
    }
  }
}
/** Fresh merchant may have exactly the purchase credit before return, and no other ledger activity. */
export function exclusiveCredit(
  rows: unknown,
  sender: string,
  recipient: string,
  amount: string,
  after: number,
  before: number,
  hash: string,
) {
  if (!Array.isArray(rows) || rows.length !== 1) fail();
  return ledger(rows, sender, recipient, amount, after, before, hash);
}
