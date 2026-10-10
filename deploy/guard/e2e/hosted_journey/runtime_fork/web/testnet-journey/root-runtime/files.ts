import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath, lstat, mkdir } from "node:fs/promises";
import path from "node:path";
import { fail, exact, hashString, type FileRef, type Tree } from "./policy.ts";
export const sha = (v: Uint8Array | string) =>
  createHash("sha256").update(v).digest("hex");
export async function canonical(file: string) {
  if (
    typeof file !== "string" ||
    !path.isAbsolute(file) ||
    path.normalize(file) !== file ||
    (await realpath(file)) !== file
  )
    fail();
  return file;
}
export async function privateParent(file: string) {
  await canonical(path.dirname(file));
  const s = await lstat(path.dirname(file));
  if (
    !s.isDirectory() ||
    s.uid !== process.getuid?.() ||
    (s.mode & 0o777) !== 0o700
  )
    fail();
}
export async function bytes(file: string, max: number, privateFile = true) {
  await canonical(file);
  if (privateFile) await privateParent(file);
  const h = await open(
    file,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await h.stat();
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      before.size < 1 ||
      before.size > max ||
      (before.uid !== process.getuid?.() &&
        (privateFile || before.uid !== 0)) ||
      before.mode & 0o022 ||
      (privateFile && (before.mode & 0o777) !== 0o600)
    )
      fail();
    const b = Buffer.alloc(before.size + 1);
    let n = 0;
    for (;;) {
      const r = await h.read(b, n, b.length - n, null);
      if (!r.bytesRead) break;
      n += r.bytesRead;
      if (n === b.length) fail();
    }
    const after = await h.stat(),
      current = await lstat(file);
    if (
      n !== before.size ||
      after.size !== before.size ||
      after.mtimeMs !== before.mtimeMs ||
      after.ctimeMs !== before.ctimeMs ||
      current.dev !== before.dev ||
      current.ino !== before.ino ||
      (await realpath(file)) !== file
    )
      fail();
    return b.subarray(0, n);
  } finally {
    await h.close();
  }
}
export async function pinned(ref: FileRef, max = 1048576, privateFile = true) {
  exact(ref, ["file", "sha256"]);
  if (!hashString(ref.sha256)) fail();
  const b = await bytes(ref.file, max, privateFile);
  if (sha(b) !== ref.sha256) fail();
  return b;
}
export async function json(ref: FileRef, max = 1048576) {
  return JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(await pinned(ref, max)),
  );
}
export async function verifyTree(tree: Tree, required: readonly string[]) {
  exact(tree, ["root", "manifest"]);
  await canonical(tree.root);
  const m = await json(tree.manifest);
  exact(m, ["schema", "files"]);
  if (
    m.schema !== 1 ||
    !m.files ||
    typeof m.files !== "object" ||
    Array.isArray(m.files)
  )
    fail();
  const rows = Object.entries(m.files);
  if (
    rows.length < required.length ||
    rows.length > 2000 ||
    required.some((k) => !Object.hasOwn(m.files as object, k))
  )
    fail();
  for (const [file, hash] of rows) {
    if (
      !/^[A-Za-z0-9_./@+-]+$/.test(file) ||
      file.startsWith("/") ||
      file.split("/").some((x) => !x || x === "." || x === "..") ||
      !hashString(hash)
    )
      fail();
    const source = await pinned(
      { file: path.join(tree.root, file), sha256: hash },
      26214400,
      false,
    );
    if (/\.(?:ts|mjs|js)$/.test(file)) {
      for (const match of source
        .toString()
        .matchAll(
          /(?:from\s*|import\s*\(?\s*|require\(\s*)['"](\.[^'"]+)['"]/g,
        )) {
        const spec = match[1]!;
        if (spec.includes("/node_modules/")) continue;
        const resolved = path.posix.normalize(
          path.posix.join(path.posix.dirname(file), spec),
        );
        if (resolved.startsWith("../") || resolved.startsWith("/")) fail();
        const variants = [
          resolved,
          resolved + ".ts",
          resolved + ".js",
          resolved + "/index.ts",
          resolved.replace(/\.js$/, ".ts"),
        ];
        if (!variants.some((name) => Object.hasOwn(m.files as object, name)))
          fail();
      }
    }
  }
  return m.files as Record<string, string>;
}
export async function newLog(directory: string) {
  await privateParent(directory);
  if (!path.isAbsolute(directory) || path.normalize(directory) !== directory)
    fail();
  await mkdir(directory, { mode: 0o700 });
  const h = await open(
    path.join(directory, "events.jsonl"),
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_NOFOLLOW,
    0o600,
  );
  for (const dir of [directory, path.dirname(directory)]) {
    const handle = await open(dir, constants.O_RDONLY);
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  }
  let chain = Promise.resolve(),
    count = 0;
  return {
    async append(kind: string, data: Record<string, unknown> = {}) {
      if (!/^[a-z-]{1,50}$/.test(kind) || ++count > 1000) fail();
      const line =
        JSON.stringify({ sequence: count, time: Date.now(), kind, ...data }) +
        "\n";
      if (Buffer.byteLength(line) > 8192) fail();
      chain = chain.then(async () => {
        await h.write(line);
        await h.sync();
      });
      await chain;
    },
    async close() {
      await chain;
      await h.close();
    },
  };
}
