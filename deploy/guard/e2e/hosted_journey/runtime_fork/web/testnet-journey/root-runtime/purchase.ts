import { OWNER, SITE, units, hashString, fail } from "./policy.ts";
import { sha } from "./files.ts";
/** Final public producer receipt plus independent provider cleanup report, never raw mail/key. */
export function purchaseProof(
  raw: Buffer,
  report: unknown,
  expected: { runId: string; merchant: string; startedAt: number; now: number },
) {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  if (!text.endsWith("\n")) fail();
  const receipt = JSON.parse(text.trimEnd().split("\n").at(-1)!);
  const r = report as Record<string, unknown>;
  if (
    !r ||
    r.schema !== 1 ||
    r.kind !== "actual-private-provider-invocation" ||
    r.stage !== "purchase" ||
    r.owner !== OWNER ||
    r.run_id !== expected.runId ||
    r.state !== "observed" ||
    r.broker_claimed !== true ||
    r.broker_socket_removed !== true ||
    r.raw_receipt_sha256 !== sha(raw) ||
    !Number.isSafeInteger(r.started_ms) ||
    !Number.isSafeInteger(r.finished_ms) ||
    (r.started_ms as number) < expected.startedAt ||
    (r.finished_ms as number) < (r.started_ms as number) ||
    (r.finished_ms as number) > expected.now
  )
    fail();
  const p = receipt?.paymentIntent;
  if (
    receipt?.version !== 1 ||
    receipt.target !== SITE ||
    receipt.status !== "passed-isolated-testnet-only" ||
    receipt.payment !== "accepted" ||
    !/^0x[0-9a-f]{64}$/.test(receipt.ledgerHash ?? "") ||
    !hashString(receipt.rawMailSha256) ||
    !hashString(receipt.licenceSha256) ||
    !Array.isArray(receipt.stages) ||
    !receipt.stages.includes("test-key-rust-verification") ||
    !p ||
    p.owner !== OWNER ||
    p.merchant !== expected.merchant ||
    p.chain !== "testnet" ||
    p.network !== "hyperliquid" ||
    p.signatureChainId !== "0x66eee" ||
    !/^USDC:0x[0-9a-f]{32}$/.test(p.token ?? "") ||
    units(p.amount) <= 0n ||
    units(p.amount) > 355610000n ||
    !Number.isSafeInteger(p.nonce) ||
    p.nonce < expected.startedAt ||
    p.nonce > expected.now
  )
    fail();
  return {
    receiptSha256: sha(raw),
    paymentHash: receipt.ledgerHash as string,
    amount: p.amount as string,
    token: p.token as string,
    nonce: p.nonce as number,
  };
}
