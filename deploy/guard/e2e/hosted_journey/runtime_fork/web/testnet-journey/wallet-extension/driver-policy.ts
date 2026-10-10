import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
export const OWNER = "0x0d708cfc4316b58f4ab00ee641a54baacc89cb14";
export const SITE = "https://staging.zunderlabs.com";
export const ARCHIVE_SHA =
  "2d02c476491527e88087981bf7cc3395c056a4d1a9ca91b010edfa73a67ac2da";
export const TREE_SHA =
  "6c642ba503b1969bbea0eb355cd898ed6991fe61e3716185a62b4cfae17d0a31";
export const UI_SOURCE_SHA =
  "8a78b1df60b38dd09c51ac4bdc0251f5dbc4bacfb10395a9f5ab351cf91c0fb0";
export type Reason =
  | "policy"
  | "deadline"
  | "control"
  | "ui"
  | "isolation"
  | "source"
  | "private-input"
  | "upstream"
  | "closed";
export class Refused extends Error {
  readonly reason: Reason;
  constructor(reason: Reason) {
    super("Genuine wallet driver stopped");
    this.reason = reason;
  }
}
export function refuse(reason: Reason = "policy"): never {
  throw new Refused(reason);
}
export function exact(
  value: unknown,
  keys: readonly string[],
): asserts value is Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((k) => !Object.hasOwn(value, k))
  )
    refuse();
}
export const sha = (value: string | Uint8Array) =>
  createHash("sha256").update(value).digest("hex");
export const hash = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
export const addr = (value: unknown): value is string =>
  typeof value === "string" && /^0x[0-9a-f]{40}$/.test(value);
export interface Pin {
  path: string;
  sha256: string;
}
export interface Config {
  schema: 1;
  purpose: "genuine-rabby-testnet-builder";
  runId: string;
  owner: typeof OWNER;
  builder: string;
  stagingOrigin: typeof SITE;
  stagingPath: "/approve";
  chainId: 421614;
  signatureChainId: "0x66eee";
  startedAt: number;
  deadline: number;
  authorityDeadline: number;
  authoritySha256: string;
  sourceManifest: Pin;
  dependencyManifest: Pin;
  chromiumManifest: Pin;
  browserLauncher: Pin;
  launcherConfig: Pin;
  rabbyArchive: Pin;
  rabbyTreeManifest: Pin;
  rabbyDirectory: string;
  stagingArtifactManifest: Pin;
  proxyPolicySha256: string;
  wrapperSha256: string;
  profileMountPath: string;
  proxyEndpoint: { ipv4: string; port: number };
  publicCaCertificate: Pin;
}
export function validateConfig(value: unknown, now: number): Config {
  exact(value, [
    "schema",
    "purpose",
    "runId",
    "owner",
    "builder",
    "stagingOrigin",
    "stagingPath",
    "chainId",
    "signatureChainId",
    "startedAt",
    "deadline",
    "authorityDeadline",
    "authoritySha256",
    "sourceManifest",
    "dependencyManifest",
    "chromiumManifest",
    "browserLauncher",
    "launcherConfig",
    "rabbyArchive",
    "rabbyTreeManifest",
    "rabbyDirectory",
    "stagingArtifactManifest",
    "proxyPolicySha256",
    "wrapperSha256",
    "profileMountPath",
    "proxyEndpoint",
    "publicCaCertificate",
  ]);
  const c = value as unknown as Config;
  if (
    c.schema !== 1 ||
    c.purpose !== "genuine-rabby-testnet-builder" ||
    !/^[-0-9a-f]{36}$/.test(c.runId) ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      c.runId,
    ) ||
    c.owner !== OWNER ||
    !addr(c.builder) ||
    c.builder === OWNER ||
    c.builder === "0x" + "0".repeat(40) ||
    c.stagingOrigin !== SITE ||
    c.stagingPath !== "/approve" ||
    c.chainId !== 421614 ||
    c.signatureChainId !== "0x66eee"
  )
    refuse();
  if (
    ![c.startedAt, c.deadline, c.authorityDeadline].every(
      Number.isSafeInteger,
    ) ||
    c.startedAt > now ||
    now >= c.deadline ||
    c.deadline - c.startedAt > 1200000 ||
    c.deadline > c.authorityDeadline
  )
    refuse("deadline");
  for (const h of [c.authoritySha256, c.proxyPolicySha256, c.wrapperSha256])
    if (!hash(h)) refuse();
  for (const p of [
    c.sourceManifest,
    c.dependencyManifest,
    c.chromiumManifest,
    c.browserLauncher,
    c.launcherConfig,
    c.rabbyArchive,
    c.rabbyTreeManifest,
    c.stagingArtifactManifest,
    c.publicCaCertificate,
  ]) {
    exact(p, ["path", "sha256"]);
    if (
      typeof p.path !== "string" ||
      !p.path.startsWith("/") ||
      !hash(p.sha256)
    )
      refuse();
  }
  if (
    c.rabbyArchive.sha256 !== ARCHIVE_SHA ||
    typeof c.profileMountPath !== "string" ||
    c.profileMountPath !== `/run/zunder-wallet-${c.runId}` ||
    typeof c.rabbyDirectory !== "string" ||
    !c.rabbyDirectory.startsWith("/")
  )
    refuse();
  exact(c.proxyEndpoint, ["ipv4", "port"]);
  if (
    !/^169\.254\.\d{1,3}\.\d{1,3}$/.test(c.proxyEndpoint.ipv4) ||
    c.proxyEndpoint.ipv4.split(".").some((n) => Number(n) > 255) ||
    !Number.isSafeInteger(c.proxyEndpoint.port) ||
    c.proxyEndpoint.port < 1024 ||
    c.proxyEndpoint.port > 65535
  )
    refuse();
  return structuredClone(c);
}
export function cleanEnvironment(
  env: NodeJS.ProcessEnv = process.env,
  args: readonly string[] = process.execArgv,
) {
  const allowed = new Set([
    "PATH",
    "HOME",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "LANG",
    "LC_ALL",
    "TZ",
  ]);
  if (
    Object.keys(env).some((key) => env[key] !== undefined && !allowed.has(key))
  )
    refuse("isolation");
  if (
    Object.keys(env).some(
      (k) =>
        /^(NODE_|DEBUG$|PWDEBUG$|PLAYWRIGHT_|SSLKEYLOGFILE$|LD_|DYLD_|HTTP_PROXY$|HTTPS_PROXY$|ALL_PROXY$|NO_PROXY$)/i.test(
          k,
        ) && !!env[k],
    ) ||
    args.some((a) =>
      /^--(?:require|import|loader|experimental-loader|inspect|heap|prof|cpu-prof|report|diagnostic|trace|record|log|tls-keylog|use-env-proxy|openssl-config|redirect-warnings|perf)|^-r/.test(
        a,
      ),
    )
  )
    refuse("isolation");
}
export class Gate {
  private held: Reason | null = null;
  private readonly startMono: number;
  private readonly budget: number;
  private readonly listeners = new Set<(r: Reason) => void>();
  readonly startedAt: number;
  readonly deadline: number;
  private readonly wall: () => number;
  private readonly mono: () => number;
  constructor(
    startedAt: number,
    deadline: number,
    wall: () => number = Date.now,
    mono: () => number = () => performance.now(),
  ) {
    this.startedAt = startedAt;
    this.deadline = deadline;
    this.wall = wall;
    this.mono = mono;
    this.startMono = mono();
    this.budget = deadline - wall();
  }
  check() {
    if (this.held) refuse(this.held);
    if (
      this.wall() < this.startedAt ||
      this.wall() >= this.deadline ||
      this.mono() - this.startMono >= this.budget
    ) {
      this.hold("deadline");
      refuse("deadline");
    }
  }
  hold(reason: Reason) {
    if (this.held) return;
    this.held = reason;
    for (const fn of this.listeners) {
      try {
        fn(reason);
      } catch {}
    }
  }
  onHold(fn: (r: Reason) => void) {
    this.listeners.add(fn);
    if (this.held) {
      try {
        fn(this.held);
      } catch {}
    }
    return () => this.listeners.delete(fn);
  }
  reason() {
    return this.held;
  }
  remaining() {
    this.check();
    return Math.max(
      1,
      Math.min(
        10000,
        this.deadline - this.wall(),
        this.budget - (this.mono() - this.startMono),
      ),
    );
  }
  async step<T>(action: () => Promise<T>): Promise<T> {
    this.check();
    try {
      const result = await action();
      this.check();
      return result;
    } catch (error) {
      this.hold(error instanceof Refused ? error.reason : "ui");
      refuse(this.held!);
    }
  }
}
const PHASES = [
  "NEW",
  "PUBLIC_ADMITTED",
  "NO_KEY_READY",
  "PRIVATE_ADMITTED",
  "IMPORTED",
  "CONNECTED",
  "REJECTED_ZERO_WRITE",
  "APPROVAL_HELD",
  "APPROVAL_ACCEPTED_20",
  "RESTORE_HELD",
  "RESTORED_0",
  "CLOSING",
  "CLOSED",
] as const;
export type Phase = (typeof PHASES)[number];
export class Journey {
  private phase: Phase = "NEW";
  private attempts = new Set<string>();
  private nonces = new Set<number>();
  readonly gate: Gate;
  constructor(gate: Gate) {
    this.gate = gate;
  }
  advance(next: Phase) {
    this.gate.check();
    if (PHASES.indexOf(next) !== PHASES.indexOf(this.phase) + 1) refuse();
    this.phase = next;
  }
  attempt(action: "reject" | "approve" | "restore") {
    this.gate.check();
    const phase = {
      reject: "CONNECTED",
      approve: "REJECTED_ZERO_WRITE",
      restore: "APPROVAL_ACCEPTED_20",
    }[action];
    if (this.phase !== phase || this.attempts.has(action)) refuse();
    this.attempts.add(action);
  }
  nonce(nonce: number) {
    if (this.nonces.has(nonce)) refuse();
    this.nonces.add(nonce);
  }
  status() {
    return { phase: this.phase, hold: this.gate.reason() };
  }
}
const DOMAIN_FIELDS = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
  { name: "verifyingContract", type: "address" },
];
const MESSAGE_FIELDS = [
  { name: "hyperliquidChain", type: "string" },
  { name: "maxFeeRate", type: "string" },
  { name: "builder", type: "address" },
  { name: "nonce", type: "uint64" },
];
export function expectedTyped(
  builder: string,
  rate: "0.02%" | "0%",
  nonce: number,
) {
  return {
    domain: {
      name: "HyperliquidSignTransaction",
      version: "1",
      chainId: 421614,
      verifyingContract: "0x" + "0".repeat(40),
    },
    types: {
      EIP712Domain: structuredClone(DOMAIN_FIELDS),
      "HyperliquidTransaction:ApproveBuilderFee":
        structuredClone(MESSAGE_FIELDS),
    },
    primaryType: "HyperliquidTransaction:ApproveBuilderFee",
    message: { hyperliquidChain: "Testnet", maxFeeRate: rate, builder, nonce },
  };
}
function normalized(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalized);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, normalized(v)]),
    );
  return value;
}
export function checkTyped(
  raw: string,
  builder: string,
  rate: "0.02%" | "0%",
  startedAt: number,
  deadline: number,
  now: number,
) {
  if (Buffer.byteLength(raw) > 8192) refuse();
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    refuse();
  }
  let compact = "",
    quoted = false,
    escaped = false;
  for (const char of raw) {
    if (quoted) {
      compact += char;
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') quoted = false;
    } else if (char === '"') {
      quoted = true;
      compact += char;
    } else if (!/\s/.test(char)) compact += char;
  }
  if (compact !== JSON.stringify(value)) refuse();
  const nonce = (value as { message?: { nonce?: unknown } })?.message?.nonce;
  if (
    !Number.isSafeInteger(nonce) ||
    Number(nonce) < startedAt ||
    Number(nonce) > now ||
    now - Number(nonce) > 120000 ||
    now >= deadline
  )
    refuse();
  const expected = expectedTyped(builder, rate, Number(nonce));
  if (
    JSON.stringify(normalized(value)) !== JSON.stringify(normalized(expected))
  )
    refuse();
  return {
    typedDataSha256: sha(JSON.stringify(expected)),
    nonce: Number(nonce),
    expected,
  };
}
