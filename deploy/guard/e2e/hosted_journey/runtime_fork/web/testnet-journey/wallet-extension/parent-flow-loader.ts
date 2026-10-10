/** Root execution only. Importing this module performs no OS read, process, material or secret operation.
 * The coordinator must independently approve and pin this complete Node/bootstrap source closure
 * BEFORE it starts in a fresh process. Hash equality below is identity, never that approval.
 * The reviewed RootNetworkFlow imports exactly its fixed sibling RootTlsCapability and Node builtins.
 * Both sibling bytes are checked before either dynamic import; no source scanner grants authority.
 */
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath, statfs } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import type { LinuxFlowBoundary } from "./network-linux.ts";
import type { RootTlsCapability } from "./tls-material.ts";

export interface Pin {
  readonly path: string;
  readonly sha256: string;
}
export interface ParentPins {
  readonly networkFlow: Pin;
  readonly tlsCapability: Pin;
  readonly rootTlsConfig: Pin;
}
const refused = (): never => {
  throw new Error("Pinned parent flow loader refused");
};
const sha = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");
function record(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    return refused();
  if (Reflect.ownKeys(value).length !== keys.length) return refused();
  for (const key of keys) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !d.enumerable || !Object.hasOwn(d, "value")) return refused();
  }
  return value as Record<string, unknown>;
}
function pin(value: unknown, prefix: "/opt/" | "/run/"): Pin {
  const p = record(value, ["path", "sha256"]);
  if (
    typeof p.path !== "string" ||
    p.path.length > 1024 ||
    !p.path.startsWith(prefix) ||
    path.posix.normalize(p.path) !== p.path ||
    !/^\/[A-Za-z0-9_./-]+$/.test(p.path) ||
    typeof p.sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(p.sha256)
  )
    return refused();
  return Object.freeze({ path: p.path, sha256: p.sha256 });
}
/** Pure public-path validation only; does not establish any real OS/source authority. */
export function validateParentPins(value: unknown): Readonly<ParentPins> {
  const v = record(value, ["networkFlow", "tlsCapability", "rootTlsConfig"]);
  const n = pin(v.networkFlow, "/opt/"),
    t = pin(v.tlsCapability, "/opt/"),
    c = pin(v.rootTlsConfig, "/run/");
  if (
    path.posix.basename(n.path) !== "root_network_flow.mjs" ||
    path.posix.basename(t.path) !== "root_tls_capability.mjs" ||
    path.posix.dirname(n.path) !== path.posix.dirname(t.path)
  )
    return refused();
  return Object.freeze({ networkFlow: n, tlsCapability: t, rootTlsConfig: c });
}
/** Inert bytes are sufficient to test hash binding. This function grants no import or OS capability. */
export function assertPinnedParentBytes(
  bytes: Uint8Array,
  expected: Pin,
  max: number,
): void {
  if (
    !Number.isSafeInteger(max) ||
    max < 1 ||
    max > 131072 ||
    bytes.byteLength < 1 ||
    bytes.byteLength > max ||
    !/^[0-9a-f]{64}$/.test(expected.sha256) ||
    sha(bytes) !== expected.sha256
  )
    refused();
}
async function bounded(
  file: string,
  max: number,
  config = false,
): Promise<Buffer> {
  if ((await realpath(file)) !== file) return refused();
  const h = await open(
    file,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await h.stat();
    if (
      !before.isFile() ||
      before.uid !== 0 ||
      before.nlink !== 1 ||
      before.mode & 0o022 ||
      (config && (before.mode & 0o777) !== 0o600) ||
      before.size < 1 ||
      before.size > max
    )
      return refused();
    const bytes = Buffer.alloc(before.size + 1);
    let size = 0;
    for (;;) {
      const got = await h.read(bytes, size, bytes.length - size, null);
      if (!got.bytesRead) break;
      size += got.bytesRead;
      if (size === bytes.length) return refused();
    }
    const after = await h.stat(),
      current = await lstat(file);
    if (
      size !== before.size ||
      after.size !== before.size ||
      after.mtimeMs !== before.mtimeMs ||
      after.ctimeMs !== before.ctimeMs ||
      current.dev !== before.dev ||
      current.ino !== before.ino ||
      (await realpath(file)) !== file
    )
      return refused();
    return bytes.subarray(0, size);
  } finally {
    await h.close();
  }
}
/** procfs pseudo-files report zero size, so use a separate bounded reader, never the config reader. */
async function proc(
  file:
    | "/proc/self/mountinfo"
    | "/proc/self/limits"
    | "/proc/self/status"
    | "/proc/swaps",
  max = 262144,
): Promise<string> {
  const h = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for (;;) {
      const chunk = Buffer.alloc(Math.min(4096, max + 1 - size));
      const got = await h.read(chunk, 0, chunk.length, null);
      if (!got.bytesRead) break;
      size += got.bytesRead;
      if (size > max) return refused();
      chunks.push(chunk.subarray(0, got.bytesRead));
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.concat(chunks),
    );
  } finally {
    await h.close();
  }
}
async function protectedAncestors(file: string): Promise<void> {
  let dir = path.dirname(file);
  for (;;) {
    const s = await lstat(dir);
    if (
      !s.isDirectory() ||
      s.uid !== 0 ||
      s.mode & 0o022 ||
      (await realpath(dir)) !== dir
    )
      return refused();
    if (dir === "/") return;
    dir = path.dirname(dir);
  }
}
/** Actual kernel mount read, never a config's readonly flag. Root must prepare this /opt mount. */
async function readonlyRuntime(file: string): Promise<void> {
  const matches = (await proc("/proc/self/mountinfo"))
    .trim()
    .split("\n")
    .map((line) => line.split(" "))
    .filter(
      (row) =>
        typeof row[4] === "string" &&
        (file === row[4] ||
          file.startsWith(row[4] === "/" ? "/" : row[4] + "/")),
    )
    .sort((a, b) => b[4]!.length - a[4]!.length);
  const row = matches[0];
  // Covered/stacked mounts at the same longest prefix are ambiguous: never choose one by row order.
  if (
    row &&
    matches.filter((candidate) => candidate[4] === row[4]).length !== 1
  )
    return refused();
  if (!row || !row[5]?.split(",").includes("ro") || row.indexOf("-") < 6)
    return refused();
  await protectedAncestors(file);
}
function cleanRootProcess(): void {
  if (
    process.platform !== "linux" ||
    process.arch !== "x64" ||
    process.getuid?.() !== 0 ||
    process.geteuid?.() !== 0
  )
    return refused();
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
    Object.keys(process.env).some(
      (key) => process.env[key] !== undefined && !allowed.has(key),
    )
  )
    return refused();
  if (
    process.execArgv.some((a) =>
      /^--(?:require|import|loader|experimental-loader|inspect|heap|prof|cpu-prof|report|diagnostic|trace|record|log|tls-keylog|use-env-proxy|openssl-config|redirect-warnings|perf)|^-r/.test(
        a,
      ),
    )
  )
    return refused();
}
interface ConfigIdentity {
  runId: string;
  startedAt: number;
  deadline: number;
}
function configIdentity(
  raw: Buffer,
  pins: Readonly<ParentPins>,
): ConfigIdentity {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch {
    return refused();
  }
  const c = record(value, [
    "schema",
    "runId",
    "startedAt",
    "deadline",
    "authoritySha256",
    "controlCgroup",
    "watchdog",
    "openssl",
    "sourcePins",
  ]);
  if (
    c.schema !== 1 ||
    typeof c.runId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      c.runId,
    ) ||
    !Number.isSafeInteger(c.startedAt) ||
    !Number.isSafeInteger(c.deadline) ||
    Number(c.startedAt) <= 0 ||
    Number(c.deadline) <= Number(c.startedAt) ||
    Number(c.deadline) - Number(c.startedAt) > 1200000 ||
    typeof c.authoritySha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(c.authoritySha256) ||
    !Array.isArray(c.sourcePins) ||
    !c.sourcePins.length ||
    c.sourcePins.length > 1000
  )
    return refused();
  // A reference in JSON is only a consistency constraint, not independent source approval.
  for (const expected of [pins.networkFlow, pins.tlsCapability]) {
    const matches = c.sourcePins.filter(
      (item) => item && typeof item === "object" && item.path === expected.path,
    );
    if (matches.length !== 1) return refused();
    const actual = record(matches[0], ["path", "sha256"]);
    if (actual.sha256 !== expected.sha256) return refused();
  }
  return {
    runId: c.runId,
    startedAt: Number(c.startedAt),
    deadline: Number(c.deadline),
  };
}
async function actualSharedTmpfs(identity: ConfigIdentity): Promise<void> {
  if (
    (await proc("/proc/swaps")).trim().split("\n").length !== 1 ||
    !/^Max core file size\s+0\s+0\s+bytes$/m.test(
      await proc("/proc/self/limits"),
    ) ||
    !/^NoNewPrivs:\s+1$/m.test(await proc("/proc/self/status"))
  )
    return refused();
  const root = "/run/zunder-wallet-" + identity.runId;
  for (const leaf of ["", "home", "tmp", "cache", "profile"]) {
    const dir = leaf ? path.join(root, leaf) : root;
    if ((await realpath(dir)) !== dir) return refused();
    const st = await lstat(dir),
      fs = await statfs(dir);
    if (
      !st.isDirectory() ||
      st.uid !== 62345 ||
      st.gid !== 62345 ||
      (st.mode & 0o777) !== 0o700 ||
      Number(fs.type) !== 0x01021994
    )
      return refused();
  }
  if (
    process.env.HOME !== root + "/home" ||
    process.env.TMPDIR !== root + "/tmp" ||
    process.env.XDG_CACHE_HOME !== root + "/cache"
  )
    return refused();
}
const NETWORK_METHODS = [
  "assertOriginalAuthority",
  "assertDispatchAuthority",
  "assertIndependentWatchdogAndMountPolicy",
  "assertOwnedCgroupDead",
  "authorizeOwnedNetworkCleanup",
  "releaseOwnedNamespaceHandles",
  "hold",
] as const;
const TLS_METHODS = [
  "assertSourceMemoryAndOriginalAuthority",
  "runPinnedOpenSsl",
  "assertMaterialChildDead",
  "hold",
] as const;
function concreteConstructor(
  module: unknown,
  name: string,
  methods: readonly string[],
): new (config: string) => object {
  if (
    !module ||
    typeof module !== "object" ||
    Reflect.ownKeys(module)
      .filter((k) => typeof k === "string")
      .join(",") !== name
  )
    return refused();
  const value = (module as Record<string, unknown>)[name];
  if (typeof value !== "function" || value.name !== name) return refused();
  const prototype = value.prototype as unknown;
  if (!prototype || typeof prototype !== "object") return refused();
  if (
    Object.getOwnPropertyNames(prototype).sort().join(",") !==
    ["constructor", ...methods].sort().join(",")
  )
    return refused();
  for (const method of methods) {
    const d = Object.getOwnPropertyDescriptor(prototype, method);
    if (!d || typeof d.value !== "function" || d.get || d.set) return refused();
  }
  return value as new (config: string) => object;
}
let attempted = false;
/** Returns the real pinned classes. No injected constructor, command adapter or authority predicate exists.
 * Operational watchdog/source approval remains the actual parent coordinator's obligation.
 * Failure never permits retrying this factory in the same process with new capability instances.
 */
export async function loadParentFlow(
  input: ParentPins,
): Promise<
  Readonly<{ networkFlow: LinuxFlowBoundary; tlsCapability: RootTlsCapability }>
> {
  if (attempted) return refused();
  attempted = true;
  try {
    cleanRootProcess();
    const pins = validateParentPins(input);
    await protectedAncestors(pins.rootTlsConfig.path);
    const config = await bounded(pins.rootTlsConfig.path, 16384, true);
    assertPinnedParentBytes(config, pins.rootTlsConfig, 16384);
    const identity = configIdentity(config, pins),
      cutoff = performance.now() + (identity.deadline - Date.now());
    const live = () => {
      if (
        Date.now() < identity.startedAt ||
        Date.now() >= identity.deadline ||
        performance.now() >= cutoff
      )
        return refused();
    };
    const checkSources = async () => {
      for (const p of [pins.networkFlow, pins.tlsCapability]) {
        live();
        await readonlyRuntime(p.path);
        live();
        assertPinnedParentBytes(await bounded(p.path, 131072), p, 131072);
        live();
      }
    };
    live();
    await actualSharedTmpfs(identity);
    live();
    await checkSources();
    live();
    // Both reviewed sibling pins are checked before either import. Fresh-process module cache/source
    // provenance is part of the external bootstrap approval; no URL rewrite or source copy is used.
    const tlsModule: unknown = await import(
      pathToFileURL(pins.tlsCapability.path).href
    );
    live();
    const networkModule: unknown = await import(
      pathToFileURL(pins.networkFlow.path).href
    );
    live();
    const Tls = concreteConstructor(
        tlsModule,
        "RootTlsCapability",
        TLS_METHODS,
      ),
      Network = concreteConstructor(
        networkModule,
        "RootNetworkFlow",
        NETWORK_METHODS,
      );
    await checkSources();
    live();
    assertPinnedParentBytes(
      await bounded(pins.rootTlsConfig.path, 16384, true),
      pins.rootTlsConfig,
      16384,
    );
    live();
    // Constructors only read the root-owned configuration. They do not authorize or generate TLS.
    const tlsCapability = new Tls(pins.rootTlsConfig.path),
      networkFlow = new Network(pins.rootTlsConfig.path);
    live();
    if (
      Object.getPrototypeOf(tlsCapability) !== Tls.prototype ||
      Object.getPrototypeOf(networkFlow) !== Network.prototype
    )
      return refused();
    return Object.freeze({
      networkFlow: networkFlow as LinuxFlowBoundary,
      tlsCapability: tlsCapability as RootTlsCapability,
    });
  } catch {
    return refused();
  }
}
