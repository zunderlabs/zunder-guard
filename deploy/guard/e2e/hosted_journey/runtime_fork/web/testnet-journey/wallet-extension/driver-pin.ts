// Shared bounded root-owned public pin reads. Importing performs no file access.
import {constants} from 'node:fs';
import {open,realpath,lstat} from 'node:fs/promises';
import path from 'node:path';
import {refuse,sha,type Pin} from './driver-policy.ts';
export async function canonical(file: string) {
  if (
    !path.isAbsolute(file) ||
    path.normalize(file) !== file ||
    (await realpath(file)) !== file
  )
    refuse("source");
  return file;
}
export async function bytes(file: string, max: number) {
  await canonical(file);
  const handle = await open(
    file,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await handle.stat();
    if (
      !before.isFile() ||
      before.nlink !== 1 ||
      before.uid !== 0 ||
      (before.mode & 0o022) !== 0 ||
      before.size < 1 ||
      before.size > max
    )
      refuse("source");
    const result = Buffer.alloc(before.size + 1);
    let offset = 0;
    for (;;) {
      const { bytesRead } = await handle.read(
        result,
        offset,
        result.length - offset,
        null,
      );
      if (!bytesRead) break;
      offset += bytesRead;
      if (offset === result.length) refuse("source");
    }
    const after = await handle.stat(),
      current = await lstat(file);
    if (
      offset !== before.size ||
      after.mtimeMs !== before.mtimeMs ||
      after.ctimeMs !== before.ctimeMs ||
      after.size !== before.size ||
      current.ino !== before.ino ||
      current.dev !== before.dev
    )
      refuse("source");
    return result.subarray(0, offset);
  } finally {
    await handle.close();
  }
}
export async function pinned(pin: Pin, max = 4 * 1024 * 1024) {
  const value = await bytes(pin.path, max);
  if (sha(value) !== pin.sha256) refuse("source");
  return value;
}
