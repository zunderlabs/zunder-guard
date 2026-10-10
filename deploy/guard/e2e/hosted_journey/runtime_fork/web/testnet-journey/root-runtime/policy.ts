// Root-only control plane; never included in browser/site bundles.
export const OWNER = "0x0d708cfc4316b58f4ab00ee641a54baacc89cb14";
export const SITE = "https://staging.zunderlabs.com";
export const API = "https://api.hyperliquid-testnet.xyz";
export const OPT_IN = "reviewed-root-testnet-runtime-only";
export const ZERO = "0x" + "0".repeat(40);
export const DENIED = [
  ZERO,
  OWNER,
  "0x0f50112710913b51a5d037795e5f4efc08debf2a",
  "0x4d91ba8f33d2199045ff46dde384f2c49deb3a3f",
  "0x6b9e773128f453f5c2c60935ee2de2cbc5390a24",
  "0x7f85c4539b36fa6666d5fc69ccb3eba528046f99",
  "0x29856629fa13e639727a5167834ce51fc283151a",
  "0xa9860ba817e405d17ef0acbc790cc68de030c5d3",
];
export const OFFICIAL_KEY =
  "7e298d8aa9921205f1ef0995b8dc6fedd86a4365fe183825127f8cd56a82af46";
export interface FileRef {
  file: string;
  sha256: string;
}
export interface Tree {
  root: string;
  manifest: FileRef;
}
export interface Config {
  version: 1;
  optIn: typeof OPT_IN;
  runId: string;
  startedAt: number;
  expires: number;
  evidenceDirectory: string;
  website: Tree;
  coordinator: Tree;
  executables: { node: FileRef; python: FileRef };
  home: string;
  memoryPolicy: "mac-encrypted-swap" | "linux-no-swap";
}
export function fail(): never {
  throw new Error("Root testnet runtime refused; inspect public checkpoints");
}
export const hashString = (v: unknown): v is string =>
  typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
export const address = (v: unknown): v is string =>
  typeof v === "string" && /^0x[0-9a-f]{40}$/.test(v);
export function exact(
  v: unknown,
  keys: readonly string[],
): asserts v is Record<string, unknown> {
  if (
    !v ||
    typeof v !== "object" ||
    Array.isArray(v) ||
    Object.keys(v).length !== keys.length ||
    keys.some((k) => !Object.hasOwn(v, k))
  )
    fail();
}
export function units(v: unknown): bigint {
  if (typeof v !== "string" || !/^(0|[1-9]\d{0,11})(\.\d{1,6})?$/.test(v))
    fail();
  const [a, b = ""] = v.split(".");
  return BigInt(a!) * 1000000n + BigInt(b.padEnd(6, "0"));
}
export function decimal(v: bigint): string {
  if (v < 0n) fail();
  return `${v / 1000000n}.${String(v % 1000000n).padStart(6, "0")}`;
}
export function cleanDiagnostics(
  env: NodeJS.ProcessEnv = process.env,
  args: readonly string[] = process.execArgv,
) {
  if (
    [
      "NODE_OPTIONS",
      "NODE_DEBUG",
      "NODE_DEBUG_NATIVE",
      "NODE_REDIRECT_WARNINGS",
      "NODE_EXTRA_CA_CERTS",
      "NODE_TLS_REJECT_UNAUTHORIZED",
      "NODE_USE_ENV_PROXY",
      "SSLKEYLOGFILE",
      "LD_PRELOAD",
      "DYLD_INSERT_LIBRARIES",
      "DEBUG",
      "PWDEBUG",
      "NODE_V8_COVERAGE",
      "PYTHONPATH",
      "PYTHONSTARTUP",
    ].some((k) => !!env[k]) ||
    args.some((a) =>
      /^--(?:require|import|loader|experimental-loader|inspect|heap|prof|cpu-prof|report|diagnostic|trace|record|log|tls-keylog|use-env-proxy|openssl-config|redirect-warnings|perf)|^-r/.test(
        a,
      ),
    )
  )
    fail();
}
export function validateConfig(v: Config, now: number) {
  exact(v, [
    "version",
    "optIn",
    "runId",
    "startedAt",
    "expires",
    "evidenceDirectory",
    "website",
    "coordinator",
    "executables",
    "home",
    "memoryPolicy",
  ]);
  exact(v.executables, ["node", "python"]);
  for (const ref of [
    v.executables.node,
    v.executables.python,
  ]) {
    exact(ref, ["file", "sha256"]);
    if (
      typeof ref.file !== "string" ||
      !ref.file.startsWith("/") ||
      !hashString(ref.sha256)
    )
      fail();
  }
  if (
    v.version !== 1 ||
    v.optIn !== OPT_IN ||
    !/^[0-9a-f]{8}(-[0-9a-f]{4}){2}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      v.runId,
    ) ||
    v.runId[14] !== "4" ||
    !Number.isSafeInteger(v.startedAt) ||
    !Number.isSafeInteger(v.expires) ||
    now < v.startedAt ||
    now >= v.expires ||
    v.expires - v.startedAt > 3600000 ||
    v.startedAt < now - 60000 ||
    v.memoryPolicy !== "linux-no-swap"
  )
    fail();
}
export interface OriginalAdmissionClock {
  readonly domain: "linux-clock-monotonic-ns-v1";
  readonly originWallNs: string;
  readonly originMonoNs: string;
  readonly deadlineMonoNs: string;
}
const nsUint64 = (v: unknown): v is string => typeof v === "string"
  && /^(0|[1-9][0-9]{0,19})$/.test(v) && BigInt(v) <= (1n << 64n) - 1n;
/** Public consistency only. The actual source-pinned P0/probe establishes the
 * clock domain and original capture; these bytes alone grant no authority. */
export function validateOriginalAdmissionClock(clock: unknown, end: number, startedAt?: number): asserts clock is OriginalAdmissionClock {
  exact(clock, ["domain", "originWallNs", "originMonoNs", "deadlineMonoNs"]);
  if (clock.domain !== "linux-clock-monotonic-ns-v1" || !nsUint64(clock.originWallNs)
    || !nsUint64(clock.originMonoNs) || !nsUint64(clock.deadlineMonoNs)
    || !Number.isSafeInteger(end) || end <= 0) fail();
  const wall = BigInt(clock.originWallNs), mono = BigInt(clock.originMonoNs), cutoff = BigInt(clock.deadlineMonoNs);
  const remaining = BigInt(end) * 1000000n - wall;
  if (remaining <= 0n || remaining > 6000000000000n || cutoff !== mono + remaining
    || (startedAt !== undefined && (!Number.isSafeInteger(startedAt) || startedAt < 0
      || BigInt(startedAt) * 1000000n >= BigInt(end) * 1000000n))) fail();
}
/** Irreversible admissions and unknown latch, shared by runtime and offline tests. */
export class Admission {
  private busy = false;
  private held = false;
  private unknown = false;
  private spent = new Set<string>();
  private end: number;
  private wall: () => number;
  private mono: () => number;
  private readonly origin: number;
  private budget: number;
  private readonly wallOrigin: number;
  private readonly originalClock: Readonly<OriginalAdmissionClock> | undefined;
  private continuousEnd: bigint | undefined;
  constructor(end: number, wall: () => number, mono: () => number, original?: {clock: OriginalAdmissionClock}) {
    if (original !== undefined) {
      exact(original, ["clock"]); validateOriginalAdmissionClock(original.clock, end);
      this.originalClock = Object.freeze({...original.clock});
      this.continuousEnd = BigInt(original.clock.deadlineMonoNs);
    }
    this.end = end;
    this.wall = wall;
    this.mono = mono;
    this.origin = mono();
    this.wallOrigin = wall();
    this.budget = end - this.wallOrigin;
  }
  private continuousExpired(end: bigint | undefined) {
    if (end === undefined) return false;
    if (!this.originalClock) fail();
    const now = process.hrtime.bigint();
    return now < BigInt(this.originalClock.originMonoNs) || now >= end;
  }
  check() {
    if (
      this.held ||
      this.unknown ||
      this.wall() >= this.end ||
      this.mono() - this.origin >= this.budget ||
      this.continuousExpired(this.continuousEnd)
    ) {
      this.held = true;
      fail();
    }
  }
  enter(kind: string, readOnly = false) {
    if (this.busy || this.spent.has(kind)) fail();
    if (!readOnly) this.check();
    this.busy = true;
    this.spent.add(kind);
  }
  leave() {
    this.busy = false;
  }
  hold(unknown = false) {
    this.held = true;
    this.unknown ||= unknown;
  }
  deadline() {
    return this.end;
  }
  /** No saved clock can add authority after construction or replace P0's pair. */
  assertOriginalClock(clock: OriginalAdmissionClock) {
    if (!this.originalClock || Object.keys(clock).length !== 4
      || clock.domain !== this.originalClock.domain || clock.originWallNs !== this.originalClock.originWallNs
      || clock.originMonoNs !== this.originalClock.originMonoNs || clock.deadlineMonoNs !== this.originalClock.deadlineMonoNs) fail();
    this.check();
  }
  /** Read-only/cleanup authority derives from the same original clock. It never
   * clears held/unknown or permits signing, and cannot exceed five extra minutes. */
  checkCleanup(end: number) {
    if (!Number.isSafeInteger(end) || end > this.end + 300000
      || end <= this.wallOrigin || this.wall() < this.wallOrigin || this.wall() >= end
      || this.mono() - this.origin >= this.budget + end - this.end
      || this.continuousExpired(this.continuousEnd === undefined ? undefined : this.continuousEnd + BigInt(end - this.end) * 1000000n)) fail();
  }
  /** Claim one cleanup interval, at most five minutes from invocation as well
   * as five minutes past the original effective deadline. Guards reuse this
   * captured monotonic start/budget and never create another cleanup clock. */
  createCleanupGuard(end: number): () => void {
    this.checkCleanup(end);
    const remaining = end - this.wall(), origin = this.mono();
    if (remaining <= 0 || remaining > 300000) fail();
    const guard = () => {
      this.checkCleanup(end);
      if (this.mono() - origin >= remaining) fail();
    };
    guard(); return guard;
  }
  tighten(end: number) {
    this.check();
    if (!Number.isSafeInteger(end) || end > this.end || end <= this.wallOrigin || end <= this.wall())
      fail();
    // Project the shorter cutoff from the FIRST wall/monotonic pair. Sampling
    // another wall origin here could extend the budget after wall-clock rollback.
    this.budget = Math.min(this.budget, end - this.wallOrigin);
    if (this.originalClock && this.continuousEnd !== undefined) {
      const projected = BigInt(this.originalClock.originMonoNs)
        + BigInt(end) * 1000000n - BigInt(this.originalClock.originWallNs);
      if (projected < this.continuousEnd) this.continuousEnd = projected;
    }
    this.end = end;
    this.check();
  }
  status() {
    return Object.freeze({
      held: this.held,
      unknown: this.unknown,
      busy: this.busy,
      spent: [...this.spent],
    });
  }
}
