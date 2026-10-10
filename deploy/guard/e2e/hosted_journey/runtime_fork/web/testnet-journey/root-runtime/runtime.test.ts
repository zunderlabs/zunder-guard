// Offline only: public inert fixtures and fake I/O; no key generation, wallet, signing or network.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtemp,
  writeFile,
  chmod,
  rm,
  realpath,
  symlink,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  Admission,
  OWNER,
  units,
  cleanDiagnostics,
  type Config,
} from "./policy.ts";
import { sha, pinned, newLog, verifyTree } from "./files.ts";
import { childEnvironment, startOwned } from "./child.ts";
import {
  ReturnAttempt,
  returnData,
  validateReturn,
  validateFee,
  canonicalToken,
  balance,
  ledger,
  exclusiveCredit,
  reconcileBalances,
  venue,
  type ReturnPolicy,
  type Snapshot,
} from "./return.ts";
const NOW = 1800000000000,
  merchant = "0x" + "2".repeat(40),
  token = "USDC:0x" + "3".repeat(32),
  hash = "0x" + "4".repeat(64);
const policy: ReturnPolicy = {
  version: 1,
  runId: "12345678-1234-4234-8234-123456789abc",
  merchant,
  destination: OWNER,
  amount: "100",
  paidUsdc: "100",
  token,
  paymentHash: hash,
  paymentAfter: NOW - 1000,
  startedAt: NOW,
  expires: NOW + 60000,
  maxFeeUsdc: "0",
  maxDebitUsdc: "100",
  feeEvidence: { file: "/public/fee.json", sha256: "a".repeat(64) },
  purchaseReceipt: { file: "/public/paid.json", sha256: "b".repeat(64) },
};
const fee = {
  version: 1,
  scope: "root-reviewed-testnet-sendasset-fee",
  merchant,
  destination: OWNER,
  token,
  expectedFeeUsdc: "0",
  observedAt: NOW,
  expires: policy.expires,
  rootVerified: true,
};
const row = (sender = OWNER, recipient = merchant, amount = "100") => ({
  time: NOW,
  hash,
  delta: {
    type: "send",
    user: sender,
    destination: recipient,
    token: "USDC",
    amount,
  },
});
test("admission serializes and consumes each stage before awaits, forever holds unknown", () => {
  let wall = NOW,
    mono = 0;
  const a = new Admission(
    NOW + 1000,
    () => wall,
    () => mono,
  );
  a.enter("apply");
  assert.throws(() => a.enter("purchase"));
  a.leave();
  assert.throws(() => a.enter("apply"));
  a.hold(true);
  assert.throws(() => a.enter("return"));
  a.enter("readonly", true);
  a.leave();
  assert.equal(a.status().unknown, true);
  assert.throws(() => a.check());
  const tight = new Admission(
    NOW + 1000,
    () => NOW,
    () => 0,
  );
  tight.tighten(NOW + 100);
  assert.equal(tight.deadline(), NOW + 100);
  assert.throws(() => tight.tighten(NOW + 500));
  const b = new Admission(
    NOW + 1000,
    () => wall,
    () => mono,
  );
  wall -= 10000;
  mono = 1000;
  assert.throws(() => b.check());
});
test("decimal amount, total debit ceiling and exact immutable route are bounded", () => {
  validateReturn(policy, merchant, policy.runId, NOW + 120000, NOW);
  assert.equal(units("355.610000"), 355610000n);
  for (const change of [
    { amount: "0" },
    { amount: "101" },
    { paidUsdc: "355.610001" },
    { amount: "1e2" },
    { destination: merchant },
    { token: "USDC" },
    { expires: NOW },
    { expires: NOW + 120001 },
    { maxDebitUsdc: "355.610001" },
    { maxFeeUsdc: "1.000001" },
  ])
    assert.throws(() =>
      validateReturn(
        { ...policy, ...change } as ReturnPolicy,
        merchant,
        policy.runId,
        NOW + 120000,
        NOW,
      ),
    );
  const data = returnData(policy, NOW);
  assert.equal(data.domain.chainId, 421614);
  assert.deepEqual(data.message, {
    hyperliquidChain: "Testnet",
    destination: OWNER,
    sourceDex: "",
    destinationDex: "",
    token,
    amount: "100",
    fromSubAccount: "",
    nonce: NOW,
  });
  assert.deepEqual(Object.keys(data.types), [
    "HyperliquidTransaction:SendAsset",
  ]);
});
test("missing or stale fee evidence does not become a zero-fee assumption", () => {
  assert.equal(validateFee(fee, policy, NOW).expectedFeeUsdc, "0");
  for (const change of [
    { rootVerified: false },
    { expectedFeeUsdc: "1" },
    { observedAt: NOW - 60001 },
    { expires: NOW + 1 },
    { scope: "userFees" },
    { token: "USDC" },
  ])
    assert.throws(() => validateFee({ ...fee, ...change }, policy, NOW));
  assert.throws(() => validateFee(undefined, policy, NOW));
});
test("exact canonical token, no-position balance and complete fresh merchant credit required", () => {
  assert.equal(
    canonicalToken({
      tokens: [
        {
          name: "USDC",
          index: 0,
          isCanonical: true,
          tokenId: "0x" + "3".repeat(32),
        },
      ],
    }),
    token,
  );
  assert.throws(() => canonicalToken({ tokens: [] }));
  assert.throws(() =>
    balance({
      withdrawable: "100",
      marginSummary: { accountValue: "100" },
      assetPositions: [{}],
    }),
  );
  assert.deepEqual(
    balance({
      withdrawable: "100",
      marginSummary: { accountValue: "100" },
      assetPositions: [],
    }),
    { withdrawable: "100", accountValue: "100" },
  );
  assert.equal(
    exclusiveCredit([row()], OWNER, merchant, "100", NOW - 1, NOW + 1, hash),
    hash,
  );
  assert.throws(() =>
    exclusiveCredit(
      [row(), row(merchant, OWNER, "1")],
      OWNER,
      merchant,
      "100",
      NOW - 1,
      NOW + 1,
      hash,
    ),
  );
  assert.throws(() =>
    ledger([row(), row()], OWNER, merchant, "100", NOW - 1, NOW + 1),
  );
  assert.throws(() =>
    ledger(
      [row(OWNER, merchant, "99")],
      OWNER,
      merchant,
      "100",
      NOW - 1,
      NOW + 1,
    ),
  );
  assert.throws(() =>
    ledger(Array(500).fill(row()), OWNER, merchant, "100", NOW - 1, NOW + 1),
  );
});
test("actual balances require exact recipient credit, bounded fee and no merchant residue", () => {
  const before: Snapshot = {
    merchant: { withdrawable: "100", accountValue: "100" },
    owner: { withdrawable: "10", accountValue: "10" },
    time: NOW,
    paymentHash: hash,
    token,
  };
  const after: Snapshot = {
    ...before,
    merchant: { withdrawable: "0", accountValue: "0" },
    owner: { withdrawable: "110", accountValue: "110" },
  };
  assert.deepEqual(reconcileBalances(before, after, policy), {
    debit: "100.000000",
    credit: "100.000000",
    fee: "0.000000",
    merchantEmpty: true,
  });
  assert.throws(() =>
    reconcileBalances(
      before,
      { ...after, owner: { withdrawable: "109", accountValue: "109" } },
      policy,
    ),
  );
  assert.throws(() =>
    reconcileBalances(
      before,
      { ...after, merchant: { withdrawable: "1", accountValue: "1" } },
      policy,
    ),
  );
  const feePolicy = {
    ...policy,
    amount: "99",
    maxFeeUsdc: "1",
    maxDebitUsdc: "100",
  };
  assert.equal(
    reconcileBalances(
      before,
      { ...after, owner: { withdrawable: "109", accountValue: "109" } },
      feePolicy,
    ).fee,
    "1.000000",
  );
});
test("one return attempt consumes before any await, rejects concurrency and never retries unknown", async () => {
  const attempt = new ReturnAttempt(),
    events: string[] = [];
  let release!: () => void;
  const wait = new Promise<void>((r) => (release = r));
  const deps = {
    check() {
      events.push("check");
    },
    async intent() {
      events.push("intent");
      await wait;
    },
    async sign() {
      events.push("fake-sign");
      return "INERT";
    },
    async send() {
      events.push("fake-send");
      return { status: "ok", response: { type: "default" } };
    },
  };
  const running = attempt.execute(returnData(policy, NOW), deps);
  assert.equal(attempt.status().spent, true);
  await assert.rejects(() => attempt.execute(returnData(policy, NOW), deps));
  release();
  await running;
  assert.equal(events.filter((e) => e === "fake-sign").length, 1);
  assert.equal(events.filter((e) => e === "fake-send").length, 1);
  assert.equal(attempt.status().state, "accepted");
  for (const failure of [
    "intent",
    "sign",
    "send",
    "reply",
    "post-sign-deadline",
  ]) {
    const a = new ReturnAttempt();
    let signed = 0,
      sent = 0,
      checks = 0;
    const io = {
      check() {
        checks++;
        if (failure === "post-sign-deadline" && checks === 3)
          throw Error("expired");
      },
      async intent() {
        if (failure === "intent") throw Error("fsync");
      },
      async sign() {
        signed++;
        if (failure === "sign") throw Error("unknown");
        return "INERT";
      },
      async send() {
        sent++;
        if (failure === "send") throw Error("unknown");
        return { status: "err" };
      },
    };
    await assert.rejects(() => a.execute(returnData(policy, NOW), io));
    await assert.rejects(() => a.execute(returnData(policy, NOW), io));
    assert.equal(a.status().state, "unknown");
    assert.ok(signed <= 1 && sent <= 1);
    if (failure === "post-sign-deadline") assert.equal(sent, 0);
  }
});
test("transport uses only fixed Testnet endpoint, no redirects, bounded responses and no retries", async () => {
  let calls = 0;
  const fake: typeof fetch = async (url, options) => {
    calls++;
    assert.equal(url, "https://api.hyperliquid-testnet.xyz/info");
    assert.equal(options?.redirect, "error");
    assert.equal(options?.method, "POST");
    return Response.json({ ok: true });
  };
  assert.deepEqual(
    await venue("/info", { type: "spotMeta" }, Date.now() + 10000, fake),
    { ok: true },
  );
  assert.equal(calls, 1);
  const tooBig: typeof fetch = async () => new Response("x".repeat(1000001));
  await assert.rejects(() => venue("/info", {}, Date.now() + 10000, tooBig));
  const lost: typeof fetch = async () => {
    calls++;
    throw Error("offline");
  };
  await assert.rejects(() => venue("/exchange", {}, Date.now() + 10000, lost));
  assert.equal(calls, 2);
});
test("private public-evidence reader rejects hash changes, symlinks and broad file permissions", async () => {
  const dir = await realpath(
    await mkdtemp(path.join(os.tmpdir(), "root-proof-")),
  );
  await chmod(dir, 0o700);
  const file = path.join(dir, "proof.json");
  await writeFile(file, "{}", { mode: 0o600 });
  try {
    assert.equal((await pinned({ file, sha256: sha("{}") })).toString(), "{}");
    await assert.rejects(() => pinned({ file, sha256: "0".repeat(64) }));
    await chmod(file, 0o644);
    await assert.rejects(() => pinned({ file, sha256: sha("{}") }));
    await chmod(file, 0o600);
    const link = path.join(dir, "link");
    await symlink(file, link);
    await assert.rejects(() => pinned({ file: link, sha256: sha("{}") }));
    const log = await newLog(path.join(dir, "run"));
    await log.append("dummy", { status: "inert" });
    await log.close();
    await assert.rejects(() => newLog(path.join(dir, "run")));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test("clean root diagnostics and child environment never inherit ambient secrets/preloads", () => {
  for (const key of [
    "NODE_OPTIONS",
    "NODE_DEBUG",
    "SSLKEYLOGFILE",
    "LD_PRELOAD",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "DEBUG",
    "PWDEBUG",
    "NODE_V8_COVERAGE",
    "PYTHONPATH",
  ])
    assert.throws(() => cleanDiagnostics({ [key]: "inert" }, []));
  for (const flag of [
    "--require",
    "--import",
    "--inspect",
    "--heap-prof",
    "--tls-keylog=/inert",
    "--use-env-proxy",
    "-rinert",
  ])
    assert.throws(() => cleanDiagnostics({}, [flag]));
  cleanDiagnostics({}, []);
  const env = childEnvironment({
    home: "/owned/home",
    awsConfig: { file: "/public/aws" },
    executables: { node: { file: "/reviewed/node" } },
  } as Config);
  assert.equal(env.NODE_OPTIONS, undefined);
  assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);
  assert.equal(env.PYTHONPATH, undefined);
  assert.equal(env.HOME, "/owned/home");
});
test("owned harmless child stdin and group shutdown are bounded without keys/network", async () => {
  const child = startOwned(
    process.execPath,
    [
      "-e",
      'process.stdin.resume();process.stdin.on("end",()=>process.stdout.write("{}"))',
    ],
    process.cwd(),
    { PATH: "/usr/bin:/bin" },
    Buffer.from("PUBLIC-INERT"),
    Date.now() + 3000,
  );
  const result = await child.done;
  assert.equal(result.code, 0);
  assert.equal(result.groupGone, true);
  assert.equal(result.stdout.toString(), "{}");
  result.stdout.fill(0);
  const sleeper = startOwned(
    process.execPath,
    ["-e", "setInterval(()=>{},1000)"],
    process.cwd(),
    { PATH: "/usr/bin:/bin" },
    Buffer.alloc(0),
    Date.now() + 100,
  );
  const stopped = await sleeper.done;
  assert.equal(stopped.forced, true);
  assert.equal(stopped.groupGone, true);
});

test("source manifest refuses omitted recursive relative imports and changed exact source", async () => {
  const dir = await realpath(
    await mkdtemp(path.join(os.tmpdir(), "root-source-")),
  );
  await chmod(dir, 0o700);
  const entry = path.join(dir, "main.ts"),
    dependency = path.join(dir, "dep.ts"),
    manifest = path.join(dir, "source.json");
  try {
    await writeFile(entry, "import './dep.ts';\n", { mode: 0o600 });
    await writeFile(dependency, "export const inert=1;\n", { mode: 0o600 });
    const save = async (files: Record<string, string>) => {
      const source = JSON.stringify({ schema: 1, files });
      await writeFile(manifest, source, { mode: 0o600 });
      return { root: dir, manifest: { file: manifest, sha256: sha(source) } };
    };
    const incomplete = await save({ "main.ts": sha("import './dep.ts';\n") });
    await assert.rejects(() => verifyTree(incomplete, ["main.ts"]));
    const complete = await save({
      "main.ts": sha("import './dep.ts';\n"),
      "dep.ts": sha("export const inert=1;\n"),
    });
    await verifyTree(complete, ["main.ts"]);
    await writeFile(dependency, "changed");
    await assert.rejects(() => verifyTree(complete, ["main.ts"]));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("purchase proof binds final receipt, provider run and private broker cleanup without key/mail data", async () => {
  const { purchaseProof } = await import("./purchase.ts");
  const value = {
    version: 1,
    target: "https://staging.zunderlabs.com",
    status: "passed-isolated-testnet-only",
    payment: "accepted",
    paymentIntent: {
      owner: OWNER,
      merchant,
      amount: "100",
      token,
      chain: "testnet",
      network: "hyperliquid",
      signatureChainId: "0x66eee",
      nonce: NOW,
    },
    ledgerHash: hash,
    rawMailSha256: "a".repeat(64),
    licenceSha256: "b".repeat(64),
    stages: ["test-key-rust-verification"],
  };
  const raw = Buffer.from(JSON.stringify(value) + "\n");
  const report = {
    schema: 1,
    kind: "actual-private-provider-invocation",
    stage: "purchase",
    owner: OWNER,
    run_id: policy.runId,
    state: "observed",
    broker_claimed: true,
    broker_socket_removed: true,
    raw_receipt_sha256: sha(raw),
    started_ms: NOW - 100,
    finished_ms: NOW + 100,
  };
  const expected = {
    runId: policy.runId,
    merchant,
    startedAt: NOW - 1000,
    now: NOW + 101,
  };
  assert.deepEqual(purchaseProof(raw, report, expected), {
    receiptSha256: sha(raw),
    paymentHash: hash,
    amount: "100",
    token,
    nonce: NOW,
  });
  for (const change of [
    { broker_socket_removed: false },
    { state: "attempted" },
    { run_id: "another" },
    { raw_receipt_sha256: "0".repeat(64) },
    { finished_ms: NOW + 102 },
  ])
    assert.throws(() => purchaseProof(raw, { ...report, ...change }, expected));
  for (const change of [
    { status: "passed" },
    { rawMailSha256: null },
    { stages: [] },
    { paymentIntent: { ...value.paymentIntent, network: "mainnet" } },
    { paymentIntent: { ...value.paymentIntent, amount: "355.610001" } },
  ]) {
    const bad = Buffer.from(JSON.stringify({ ...value, ...change }) + "\n");
    assert.throws(() =>
      purchaseProof(bad, { ...report, raw_receipt_sha256: sha(bad) }, expected),
    );
  }
  assert.throws(() => purchaseProof(raw.subarray(0, -1), report, expected));
});

test("failed child launch wipes stdin and does not emit an unhandled parent error", async () => {
  const input = Buffer.from("PUBLIC-INERT");
  assert.throws(() =>
    startOwned(
      "/nonexistent-inert-executable",
      [],
      process.cwd(),
      {},
      input,
      Date.now() + 1000,
    ),
  );
  assert.deepEqual(input, Buffer.alloc(input.length));
  await new Promise((r) => setTimeout(r, 30));
});

test("actual supervisor safety stops a pending purchase on issuer unknown, without recursive deadlock", async () => {
  const { createCustodySafety } = await import("./safety.ts");
  const admission = new Admission(
    NOW + 1000,
    () => NOW,
    () => 0,
  );
  let children = true,
    stopped = false,
    release!: () => void,
    sends = 0;
  const gate = new Promise<void>((r) => (release = r));
  const safety = createCustodySafety(admission, {
    hasChildren: () => children,
    cleanupComplete: () => true,
    async stopChildren() {
      stopped = true;
      safety.hold(true);
      await gate;
      children = false;
    },
    async readEmpty() {},
    async readReturned() {},
  });
  admission.enter("purchase");
  const pending = (async () => {
    await gate;
    admission.check();
    sends++;
  })();
  safety.hold(true);
  assert.equal(stopped, true);
  assert.equal(safety.status().stopping, true);
  safety.hold(true);
  release();
  await assert.rejects(() => pending);
  assert.equal(sends, 0);
  admission.leave();
  await safety.beforeDispose(false);
  assert.equal(admission.status().unknown, true);
});

test("actual terminal empty proof closes payment admissions and disposal refresh refuses later funds", async () => {
  const { createCustodySafety } = await import("./safety.ts");
  const admission = new Admission(
    NOW + 1000,
    () => NOW,
    () => 0,
  );
  let funds = 0,
    reads = 0,
    clean = true,
    children = false;
  const safety = createCustodySafety(admission, {
    hasChildren: () => children,
    cleanupComplete: () => clean,
    async stopChildren() {
      children = false;
    },
    async readEmpty() {
      reads++;
      assert.equal(funds, 0);
    },
    async readReturned() {
      reads++;
      assert.equal(funds, 0);
    },
  });
  await safety.proveEmpty();
  assert.equal(reads, 1);
  assert.throws(() => admission.enter("purchase"));
  assert.throws(() => admission.enter("provision"));
  funds = 100;
  await assert.rejects(() => safety.beforeDispose(false));
  assert.equal(reads, 2);
  funds = 0;
  clean = false;
  await assert.rejects(() => safety.beforeDispose(false));
  assert.equal(reads, 2);
  clean = true;
  children = true;
  await assert.rejects(() => safety.beforeDispose(true));
  assert.equal(reads, 2);
  children = false;
  await safety.beforeDispose(true);
  assert.equal(reads, 3);
});

test("failed stop retains uncertain custody and cannot be erased by a fresh empty proof", async () => {
  const { createCustodySafety } = await import("./safety.ts");
  const admission = new Admission(
    NOW + 1000,
    () => NOW,
    () => 0,
  );
  let reads = 0;
  const safety = createCustodySafety(admission, {
    hasChildren: () => true,
    cleanupComplete: () => true,
    async stopChildren() {
      throw Error("unknown group");
    },
    async readEmpty() {
      reads++;
    },
    async readReturned() {
      reads++;
    },
  });
  safety.hold(true);
  await assert.rejects(() => safety.beforeDispose(false));
  assert.equal(safety.status().stopUncertain, true);
  assert.equal(reads, 0);
  assert.throws(() => admission.enter("return"));
});

test("synchronous spawn rejection and expired admission wipe private input buffers", () => {
  for (const expired of [false, true]) {
    const input = Buffer.from("PUBLIC-INERT");
    assert.throws(() =>
      startOwned(
        process.execPath,
        ["\0"],
        process.cwd(),
        {},
        input,
        Date.now() + (expired ? -1 : 1000),
      ),
    );
    assert.deepEqual(input, Buffer.alloc(input.length));
  }
});

test("owned-child probe/kill failures settle once as unknown without escaping event callbacks", async () => {
  const input = Buffer.from("PUBLIC-INERT");
  let probes = 0;
  const child = startOwned(
    process.execPath,
    ["-e", "process.stdin.resume();setInterval(()=>{},1000)"],
    process.cwd(),
    {},
    input,
    Date.now() + 30,
    () => {
      probes++;
      throw Object.assign(Error("inert management refusal"), { code: "EPERM" });
    },
  );
  try {
    const result = await child.done;
    assert.equal(result.groupGone, false);
    assert.equal(result.forced, true);
    assert.ok(probes >= 3);
    assert.deepEqual(input, Buffer.alloc(input.length));
    assert.equal(await child.stop(), result);
    result.stdout.fill(0);
  } finally {
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
});
