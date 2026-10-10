// Node-only, single-claim stdin -> local Unix socket handoff. Never bundled into the site.
import { createServer, createConnection, type Socket } from 'node:net';
import { chmod, lstat, mkdir, realpath, rmdir, unlink } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import type { Readable } from 'node:stream';
export const PRIVATE_INPUT_MAX = 2048;
export const FUNDED_TESTNET_OWNER = '0x0d708cfc4316b58f4ab00ee641a54baacc89cb14';
export const BROKER_LEASE_MS = 120_000;
function fail(): never { throw new Error('Private test input refused'); }
export type Claim = { version: 1; purpose: 'purchase' | 'approval'; runId: string; owner: string };
export type PrivateInput = Claim & { ownerPrivateKey: string; inboxToken?: string };
export function assertPrivateDiagnostics(env: NodeJS.ProcessEnv = process.env, execArgv: readonly string[] = process.execArgv): void {
  if (['DEBUG', 'PWDEBUG', 'NODE_OPTIONS', 'NODE_V8_COVERAGE'].some(key => !!env[key])
    || execArgv.some(arg => {
      // Node 26's test subprocess passes inert default modifiers even with diagnostics off.
      const name = arg.split('=')[0];
      if (['--heap-prof-interval','--cpu-prof-interval','--report-signal','--inspect-publish-uid','--inspect-port','--trace-event-file-pattern'].includes(name!)) return false;
      if (arg === '--heapsnapshot-near-heap-limit=0') return false;
      return /^--(?:inspect|heap|prof|cpu-prof|report|diagnostic|trace|record|log)/.test(arg);
    })) fail();
}
export function validateClaim(value: unknown): Claim {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  const c = value as Claim;
  if (Object.keys(c).sort().join(',') !== 'owner,purpose,runId,version' || c.version !== 1
    || !['purchase', 'approval'].includes(c.purpose)
    || typeof c.runId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(c.runId)
    || c.owner !== FUNDED_TESTNET_OWNER) fail();
  return { version: 1, purpose: c.purpose, runId: c.runId, owner: c.owner };
}
export function validatePrivateInput(value: unknown): PrivateInput {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  const s = value as PrivateInput;
  const claim = validateClaim({ version: s.version, purpose: s.purpose, runId: s.runId, owner: s.owner });
  const expected = claim.purpose === 'purchase' ? 'inboxToken,owner,ownerPrivateKey,purpose,runId,version' : 'owner,ownerPrivateKey,purpose,runId,version';
  if (Object.keys(s).sort().join(',') !== expected || typeof s.ownerPrivateKey !== 'string'
    || !/^0x[0-9a-f]{64}$/.test(s.ownerPrivateKey) || /^0x0{64}$/.test(s.ownerPrivateKey)
    || (claim.purpose === 'purchase' && (typeof s.inboxToken !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(s.inboxToken)))) fail();
  return { ...claim, ownerPrivateKey: s.ownerPrivateKey, ...(claim.purpose === 'purchase' ? { inboxToken: s.inboxToken! } : {}) };
}
export async function privateDirectory(dir: string): Promise<void> {
  if (!path.isAbsolute(dir) || await realpath(dir) !== dir) fail();
  const stat = await lstat(dir);
  if (!stat.isDirectory() || stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0) fail();
}
async function readBounded(stream: Readable, max: number, timeout: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []; let size = 0, settled = false;
    const finish = (ok: boolean) => {
      if (settled) return; settled = true; clearTimeout(timer);
      stream.off('data', data); stream.off('end', end); stream.off('error', error);
      const bytes = ok ? Buffer.concat(chunks) : null;
      for (const chunk of chunks) chunk.fill(0);
      if (bytes) resolve(bytes); else { stream.destroy(); reject(new Error('Private test input refused')); }
    };
    const data = (chunk: Buffer) => { const copy = Buffer.from(chunk); chunks.push(copy); size += copy.length; if (size > max) finish(false); };
    const end = () => finish(size > 0);
    const error = () => finish(false);
    const timer = setTimeout(error, timeout);
    stream.on('data', data); stream.once('end', end); stream.once('error', error);
  });
}
export async function readPrivateStdin(stream: Readable): Promise<PrivateInput> {
  const bytes = await readBounded(stream, PRIVATE_INPUT_MAX, 10_000);
  try { return validatePrivateInput(JSON.parse(bytes.toString('utf8'))); }
  catch { return fail(); } finally { bytes.fill(0); }
}
/** All failure paths consume/close the broker. No retry after a partial or uncertain delivery. */
export async function startPrivateBroker(directory: string, input: PrivateInput, leaseMs = BROKER_LEASE_MS) {
  assertPrivateDiagnostics();
  let secret: PrivateInput | null = validatePrivateInput(input);
  if (!Number.isInteger(leaseMs) || leaseMs < 1 || leaseMs > BROKER_LEASE_MS) fail();
  if (!path.isAbsolute(directory) || path.normalize(directory) !== directory) fail();
  await privateDirectory(path.dirname(directory));
  const socketPath = path.join(directory, 'input.sock');
  if (Buffer.byteLength(socketPath) > 100) fail();
  await mkdir(directory, { mode: 0o700 }); // Exclusive new directory; never reuse/unlink caller files.
  const server = createServer({ allowHalfOpen: true });
  let active: Socket | null = null, closing = false, claimed = false, socketOwned = false;
  type Status = 'claimed' | 'expired' | 'failed' | 'stopped';
  let status: Status = 'failed';
  let doneResolve!: (value: Status) => void;
  const done = new Promise<Status>(resolve => { doneResolve = resolve; });
  const expiresAt = Date.now() + leaseMs;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const stop = async (result: Status) => {
    if (closing) return; closing = true; status = result;
    clearTimeout(timer); secret = null; active?.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
    if (socketOwned) await unlink(socketPath).catch(() => {});
    await rmdir(directory).catch(() => {}); // Never recursively delete unowned contents.
    doneResolve(status);
  };
  server.on('error', () => { void stop('failed'); });
  server.on('connection', socket => {
    if (active || closing || claimed) { socket.destroy(); return; }
    active = socket; claimed = true; // Invalid requests also consume the sole claim.
    socket.on('error', () => { void stop('failed'); });
    void (async () => {
      let bytes: Buffer | undefined;
      try {
        bytes = await readBounded(socket, 512, Math.min(5_000, leaseMs));
        const claim = validateClaim(JSON.parse(bytes.toString('utf8')));
        if (!secret || Date.now() >= expiresAt || claim.purpose !== secret.purpose || claim.runId !== secret.runId || claim.owner !== secret.owner) fail();
        const payload = Buffer.from(JSON.stringify(secret));
        secret = null;
        await new Promise<void>((resolve, reject) => {
          socket.end(payload, () => { payload.fill(0); resolve(); });
          socket.once('error', () => { payload.fill(0); reject(new Error('Private test input refused')); });
        });
        await stop('claimed');
      } catch { await stop('failed'); } finally { bytes?.fill(0); }
    })();
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject); server.listen(socketPath, () => { server.off('error', reject); socketOwned = true; resolve(); });
    });
    await chmod(socketPath, 0o600);
    timer = setTimeout(() => { void stop('expired'); }, leaseMs);
  } catch { await stop('failed'); fail(); }
  return { socketPath, expiresAt, done, stop: () => stop('stopped') };
}
export async function claimPrivateInput(socketPath: string, value: Claim): Promise<PrivateInput> {
  assertPrivateDiagnostics();
  const claim = validateClaim(value);
  if (!path.isAbsolute(socketPath) || Buffer.byteLength(socketPath) > 100) fail();
  await privateDirectory(path.dirname(socketPath));
  const stat = await lstat(socketPath);
  if (!stat.isSocket() || stat.uid !== process.getuid?.() || (stat.mode & 0o777) !== 0o600 || await realpath(socketPath) !== socketPath) fail();
  const socket = createConnection({ path: socketPath, allowHalfOpen: true });
  socket.on('error', () => {}); // readBounded reports a sanitized error; late close errors stay private.
  try {
    const pending = readBounded(socket, PRIVATE_INPUT_MAX, 5_000);
    socket.once('connect', () => socket.end(JSON.stringify(claim)));
    const bytes = await pending;
    try {
      const input = validatePrivateInput(JSON.parse(bytes.toString('utf8')));
      if (input.purpose !== claim.purpose || input.runId !== claim.runId || input.owner !== claim.owner) fail();
      return input;
    } finally { bytes.fill(0); }
  } catch { return fail(); } finally { socket.destroy(); }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let broker: Awaited<ReturnType<typeof startPrivateBroker>> | undefined;
  try {
    assertPrivateDiagnostics();
    if (process.argv.length !== 3) fail();
    const input = await readPrivateStdin(process.stdin);
    broker = await startPrivateBroker(process.argv[2]!, input);
    input.ownerPrivateKey = ''; if (input.inboxToken) input.inboxToken = '';
    for (const signal of ['SIGINT','SIGTERM'] as const) process.once(signal, () => { void broker?.stop(); });
    process.stdout.write(JSON.stringify({ ready: true, socketPath: broker.socketPath, expiresAt: broker.expiresAt }) + '\n');
    if (await broker.done !== 'claimed') process.exitCode = 1;
  } catch { await broker?.stop(); process.stderr.write('Private input broker failed\n'); process.exitCode = 1; }
}
