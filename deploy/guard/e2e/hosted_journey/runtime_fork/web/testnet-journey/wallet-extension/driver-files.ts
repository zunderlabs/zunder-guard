import { validateLauncher } from "./driver-launcher.ts";
import { constants } from "node:fs";
import {
  open,
  realpath,
  lstat,
  readdir,
  readFile,
  statfs,
} from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  exact,
  hash,
  refuse,
  sha,
  TREE_SHA,
  type Pin,
  type Config,
  type Gate,
} from "./driver-policy.ts";
export {canonical,bytes,pinned} from './driver-pin.ts';
import {canonical,bytes,pinned} from './driver-pin.ts';
function json(value: Buffer): unknown {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(value));
  } catch {
    refuse("source");
  }
}
function relative(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length < 512 &&
    /^[A-Za-z0-9_./@+ -]+$/.test(value) &&
    !value.startsWith("/") &&
    !value.split("/").some((v) => !v || v === "." || v === "..")
  );
}
async function digest(file: string) {
  await canonical(file);
  const f = await open(
    file,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const s = await f.stat();
    if (
      !s.isFile() ||
      s.nlink !== 1 ||
      s.uid !== 0 ||
      s.mode & 0o022 ||
      s.size > 1024 * 1024 * 1024
    )
      refuse("source");
    const h = createHash("sha256");
    for await (const b of f.readableWebStream()) h.update(new Uint8Array(b));
    const t = await f.stat();
    const current = await lstat(file);
    if (
      t.mtimeMs !== s.mtimeMs ||
      t.ctimeMs !== s.ctimeMs ||
      t.size !== s.size ||
      current.ino !== s.ino ||
      current.dev !== s.dev
    )
      refuse("source");
    return h.digest("hex");
  } finally {
    await f.close();
  }
}
export async function closure(pin: Pin, gate: Gate, chromium = false) {
  const m = json(await gate.step(() => pinned(pin)));
  exact(
    m,
    chromium
      ? ["schema", "root", "files", "executable"]
      : ["schema", "root", "files"],
  );
  if (
    m.schema !== 1 ||
    typeof m.root !== "string" ||
    !m.files ||
    typeof m.files !== "object" ||
    Array.isArray(m.files)
  )
    refuse("source");
  await canonical(m.root);
  const entries = Object.entries(m.files);
  if (!entries.length || entries.length > 30000) refuse("source");
  for (const [name, value] of entries) {
    if (
      !relative(name) ||
      !hash(value) ||
      (await gate.step(() => digest(path.join(String(m.root), name)))) !== value
    )
      refuse("source");
  }
  if (
    chromium &&
    (!relative(m.executable) || !Object.hasOwn(m.files, m.executable))
  )
    refuse("source");
  return {
    root: m.root,
    files: m.files as Record<string, string>,
    executable: chromium ? path.join(m.root, String(m.executable)) : undefined,
  };
}
async function treeFiles(root: string, prefix = ""): Promise<string[]> {
  const result: string[] = [];
  for (const entry of await readdir(path.join(root, prefix), {
    withFileTypes: true,
  })) {
    const name = path.posix.join(prefix, entry.name);
    if (!relative(name) || entry.isSymbolicLink()) refuse("source");
    if (entry.isDirectory()) result.push(...(await treeFiles(root, name)));
    else if (entry.isFile()) result.push(name);
    else refuse("source");
    if (result.length > 1140) refuse("source");
  }
  return result.sort();
}
export async function verifySources(config: Config, gate: Gate) {
  const source = await closure(config.sourceManifest, gate);
  const dependency = await closure(config.dependencyManifest, gate);
  const chromium = await closure(config.chromiumManifest, gate, true);
  const own = fileURLToPath(import.meta.url);
  if (
    !Object.hasOwn(source.files, path.relative(source.root, own)) ||
    !Object.hasOwn(
      dependency.files,
      path.relative(dependency.root, process.execPath),
    )
  )
    refuse("source");
  await gate.step(() => pinned(config.browserLauncher));
  const launcher = validateLauncher(
    json(await gate.step(() => pinned(config.launcherConfig))),
    config,
    {
      path: chromium.executable!,
      sha256:
        chromium.files[path.relative(chromium.root, chromium.executable!)]!,
    },
  );
  await gate.step(() => pinned(launcher.containmentConfig));
  await gate.step(() => pinned(config.publicCaCertificate));
  await gate.step(() => pinned(config.rabbyArchive, 17000000));
  await gate.step(() => pinned(config.stagingArtifactManifest));
  const rows = json(await gate.step(() => pinned(config.rabbyTreeManifest)));
  if (!Array.isArray(rows) || rows.length !== 1140) refuse("source");
  const names: string[] = [];
  for (const row of rows) {
    exact(row, ["path", "sha256", "size"]);
    if (
      !relative(row.path) ||
      !hash(row.sha256) ||
      !Number.isSafeInteger(row.size) ||
      Number(row.size) < 0
    )
      refuse("source");
    names.push(row.path);
    const p = path.join(config.rabbyDirectory, row.path);
    const b = await gate.step(() =>
      pinned({ path: p, sha256: row.sha256 as string }, 26214400),
    );
    if (b.length !== row.size) refuse("source");
  }
  if (
    new Set(names).size !== 1140 ||
    JSON.stringify(names) !== JSON.stringify([...names].sort()) ||
    JSON.stringify(names) !==
      JSON.stringify(await treeFiles(config.rabbyDirectory))
  )
    refuse("source");
  // Acquisition binds compact JSON with sorted object keys, no final newline.
  const inventory = JSON.stringify(
    rows.map((r) => ({ path: r.path, sha256: r.sha256, size: r.size })),
  );
  // Exact raw manifest is also pinned. Inventory convention must match the reviewed acquisition.
  if (sha(inventory) !== TREE_SHA) refuse("source");
  const manifest = json(
    await bytes(path.join(config.rabbyDirectory, "manifest.json"), 131072),
  ) as { version?: unknown };
  if (manifest.version !== "0.94.11") refuse("source");
  return chromium.executable!;
}
export async function rootProcessPreflight(config: Config) {
  if (
    process.platform !== "linux" ||
    process.arch !== "x64" ||
    process.getuid?.() !== 0 ||
    process.geteuid?.() !== 0
  )
    refuse("isolation");
  const status = await readFile("/proc/self/status", "utf8"),
    limits = await readFile("/proc/self/limits", "utf8"),
    swaps = await readFile("/proc/swaps", "utf8");
  if (
    !/^NoNewPrivs:\s+1$/m.test(status) ||
    !/^Max core file size\s+0\s+0\s+bytes$/m.test(limits) ||
    swaps.trim().split("\n").length !== 1
  )
    refuse("isolation");
  if (
    process.env.HOME !== path.join(config.profileMountPath, "home") ||
    process.env.TMPDIR !== path.join(config.profileMountPath, "tmp") ||
    process.env.XDG_CACHE_HOME !== path.join(config.profileMountPath, "cache")
  )
    refuse("isolation");
  await canonical(config.profileMountPath);
  const dir = await lstat(config.profileMountPath),
    fs = await statfs(config.profileMountPath);
  if (
    !dir.isDirectory() ||
    dir.uid !== 62345 ||
    dir.gid !== 62345 ||
    (dir.mode & 0o777) !== 0o700 ||
    Number(fs.type) !== 0x01021994
  )
    refuse("isolation");
  // Root authenticates the launcher's browser namespace, cgroup watchdog, mount and FD isolation.
  // These local checks deliberately do not assert that external capabilities were established.
}
