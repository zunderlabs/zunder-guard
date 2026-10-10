import fs from 'node:fs/promises';
import net from 'node:net';
import { constants } from 'node:fs';
import dgram from 'node:dgram';
import { pathToFileURL } from 'node:url';
import { need, validateConfig, targets, result, UID } from './contract.mjs';

const DENIED = new Set(['EACCES', 'EPERM', 'ENOENT', 'EROFS']);
function denied(error) { return DENIED.has(error?.code) ? 'denied' : 'unknown'; }
export const realIO = Object.freeze({
  identity: () => ({ platform: process.platform, arch: process.arch, uid: process.getuid(), gid: process.getgid() }),
  async isolation(c) {
    const [status, limits, mounts, swaps, profile, mountNs, netNs] = await Promise.all([
      fs.readFile('/proc/self/status', 'utf8'), fs.readFile('/proc/self/limits', 'utf8'),
      fs.readFile('/proc/self/mountinfo', 'utf8'), fs.readFile('/proc/swaps', 'utf8'),
      fs.stat(c.profileMountPath), fs.stat('/proc/self/ns/mnt'), fs.stat('/proc/self/ns/net'),
    ]);
    const rows = mounts.trim().split('\n').map(s => s.split(' '));
    const root = rows.find(r => r[4] === '/'); const own = rows.find(r => r[4] === c.profileMountPath);
    return { noNewPrivs: /^NoNewPrivs:\s+1$/m.test(status), capabilitiesZero: /^CapEff:\s+0+$/m.test(status),
      coreZero: /^Max core file size\s+0\s+0\s+bytes$/m.test(limits), noSwap: swaps.trim().split('\n').length === 1,
      rootReadonly: !!root?.[5].split(',').includes('ro'), ownedTmpfs: !!own && own[own.indexOf('-') + 1] === 'tmpfs' && own[5].split(',').includes('rw'),
      profileDevice: profile.dev, profileInode: profile.ino, mountNamespaceInode: mountNs.ino, networkNamespaceInode: netNs.ino };
  },
  async open(path) { const f = await fs.open(path, 'r'); await f.close(); },
  async write(path) {
    const f = await fs.open(path, 'wx', 0o600);
    let identity;
    try { await f.writeFile('public no-key write probe\n'); identity = await f.stat(); } finally { await f.close(); }
    // Delete only this exact O_EXCL-created inode, never a replacement.
    const actual = await fs.lstat(path); need(actual.dev === identity.dev && actual.ino === identity.ino);
    await fs.unlink(path);
  },
  async socket(path) { return connect({ path }); },
  async tcp(host, port) { return connect({ host, port }); },
  async udp(host, port) {
    const socket = dgram.createSocket('udp4');
    try { await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })), 1000);
      socket.once('error', reject);
      socket.send(Buffer.from('ZUNDER_NO_KEY_TRANSPORT_PROBE'), port, host, error => {
        clearTimeout(timer); if (error) reject(error); else resolve();
      });
    }); return 'sent-callback'; } finally { socket.close(); }
  },
});
async function connect(options) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(options);
    const timer = setTimeout(() => { socket.destroy(); reject(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })); }, 1000);
    socket.once('connect', () => { clearTimeout(timer); socket.destroy(); resolve(); });
    socket.once('error', error => { clearTimeout(timer); socket.destroy(); reject(error); });
  });
}
/** Explicit IO parameter is solely for inert unit fixtures; CLI uses hardwired realIO. */
export async function runLinuxProbe(input, io, now = () => Date.now()) {
  const c = validateConfig(input, now()); const t = targets(c);
  const check = () => need(now() < c.deadline);
  check(); const identity = io.identity();
  need(identity.platform === 'linux' && identity.arch === 'x64' && identity.uid === UID && identity.gid === UID);
  const isolation = await io.isolation(c); check();
  const observations = { identity, isolation, canaries: [], controller: [], forbiddenWrites: [], allowedWrites: [], unixSocket: 'unknown', network: [] };
  async function attempt(op) { check(); try { await op(); check(); return 'accessible'; } catch (e) { check(); return denied(e); } }
  for (const path of t.canaries) observations.canaries.push(await attempt(() => io.open(path)));
  for (const path of t.controller) observations.controller.push(await attempt(() => io.open(path)));
  for (const path of t.forbiddenWrites) observations.forbiddenWrites.push(await attempt(() => io.write(path)));
  for (const path of t.allowedWrites) observations.allowedWrites.push(await attempt(() => io.write(path)));
  observations.unixSocket = await attempt(() => io.socket(t.socket));
  // No external third-party receiver: host-owned denied port, disabled IPv6 route,
  // and namespace loopback. Failures are observations, never firewall proof alone.
  for (const [name, host, port] of [['direct-host', c.network.proxyIpv4, c.network.deniedPort], ['loopback', '127.0.0.1', c.network.deniedPort], ['ipv6-loopback', '::1', c.network.deniedPort], ['ipv6-route', '2001:db8::1', c.network.deniedPort]]) {
    check(); let outcome = 'unknown';
    try { await io.tcp(host, port); outcome = 'connected'; } catch (e) { outcome = ['EACCES','EPERM','ENETUNREACH','EHOSTUNREACH','ECONNREFUSED','ETIMEDOUT'].includes(e?.code) ? 'not-connected' : 'unknown'; }
    check(); observations.network.push({ name, outcome });
  }
  for (const [name, port] of [['dns-udp-transport', 53], ['quic-udp-transport', 443]]) {
    check(); let outcome = 'unknown';
    try { await io.udp(c.network.proxyIpv4, port); outcome = 'sent-callback'; } catch (e) { outcome = denied(e); }
    check(); observations.network.push({ name, outcome });
  }
  return result(c, 'linux-child', observations);
}
// Descriptor reader is exposed only for inert fixture tests; CLI opens the exact
// public path itself. No readFile allocation controlled by a replaceable ancestor.
export async function readBoundedPublicConfig(handle, statPath) {
  const before = await handle.stat();
  const valid = s => s.isFile() && s.uid === 0 && s.nlink === 1 && (s.mode & 0o7777) === 0o444 && Number.isSafeInteger(s.size) && s.size > 0 && s.size <= 8192;
  need(valid(before));
  const bytes = Buffer.alloc(before.size + 1);
  let length = 0;
  while (length < bytes.length) {
    const { bytesRead } = await handle.read(bytes, length, bytes.length - length, length);
    need(Number.isInteger(bytesRead) && bytesRead >= 0 && bytesRead <= bytes.length - length);
    if (bytesRead === 0) break;
    length += bytesRead;
  }
  need(length === before.size);
  const after = await handle.stat(); const current = await statPath();
  for (const actual of [after, current]) {
    need(valid(actual));
    for (const field of ['dev','ino','size','mtimeMs','ctimeMs']) need(actual[field] === before[field]);
  }
  const raw = bytes.subarray(0, length).toString('utf8');
  const parsed = JSON.parse(raw); need(JSON.stringify(parsed) === raw);
  return parsed;
}
// Fixed entry ABI: node linux-probe.mjs <canonical-public-config-path>. No shell,
// environment config, private input, custom operations or child process spawning.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    need(process.argv.length === 3 && /^\/run\/zunder-wallet-[a-f0-9-]+\/home\/no-key-probe\.json$/.test(process.argv[2]));
    const handle = await fs.open(process.argv[2], constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    let c;
    try { c = await readBoundedPublicConfig(handle, () => fs.lstat(process.argv[2])); } finally { await handle.close(); }
    need(process.argv[2] === `${c.profileMountPath}/home/no-key-probe.json`);
    const receipt = await runLinuxProbe(c, realIO);
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch { process.stdout.write('{"schema":1,"status":"REFUSED","privateInput":false}\n'); process.exitCode = 2; }
}
