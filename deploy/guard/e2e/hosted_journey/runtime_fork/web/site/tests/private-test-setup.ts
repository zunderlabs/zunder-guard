import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import path from 'node:path';
import { assertPrivateDiagnostics, privateDirectory, validateClaim, type Claim } from './private-input-broker.ts';
function fail(): never { throw new Error('Public test setup refused'); }
export async function readPublicSetup(purpose: Claim['purpose'], fields: readonly string[]): Promise<Record<string, unknown> & Claim> {
  assertPrivateDiagnostics();
  const file = process.env.ZUNDER_TESTNET_SETUP_FILE;
  if (!file || !path.isAbsolute(file)) fail();
  await privateDirectory(path.dirname(file));
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await fd.stat();
    if (!stat.isFile() || stat.uid !== process.getuid?.() || (stat.mode & 0o077) || stat.size < 1 || stat.size > 8192) fail();
    const bytes = await fd.readFile();
    let value: Record<string, unknown>;
    try { value = JSON.parse(bytes.toString('utf8')); } catch { return fail(); }
    if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).some(key => !fields.includes(key)) || value.purpose !== purpose) fail();
    const claim = validateClaim({ version: value.version, purpose: value.purpose, runId: value.runId, owner: value.owner });
    if (typeof value.outputFile !== 'string' || !path.isAbsolute(value.outputFile) || value.outputFile === file) fail();
    await privateDirectory(path.dirname(value.outputFile));
    return { ...value, ...claim };
  } catch { return fail(); } finally { await fd.close(); }
}
export async function newReceipt(file: string) {
  await privateDirectory(path.dirname(file));
  return open(file, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
}
export function privateSocketPath(): string {
  const socket = process.env.ZUNDER_TESTNET_PRIVATE_SOCKET;
  if (!socket) fail();
  return socket;
}
