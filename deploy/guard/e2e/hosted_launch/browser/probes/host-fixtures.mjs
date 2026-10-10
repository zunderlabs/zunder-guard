import fs from 'node:fs/promises';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { exact, need, hash, targets } from './contract.mjs';

/** Fixed public-only root adapter. Importing has no effect; author tests never call it. */
export async function prepareHostFixtures(input, authority) {
  exact(input, ['runId', 'startedAt', 'deadline', 'authoritySha256']);
  need(process.platform === 'linux' && process.arch === 'x64' && process.getuid() === 0
    && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(input.runId)
    && Number.isSafeInteger(input.startedAt) && Number.isSafeInteger(input.deadline)
    && input.startedAt <= Date.now() && Date.now() < input.deadline && input.deadline <= input.startedAt + 1_200_000
    && /^[a-f0-9]{64}$/.test(input.authoritySha256));
  need(authority && typeof authority.assertNoKeyLive === 'function');
  const initialWall=Date.now(),initialMono=performance.now(),inputSha256=hash(JSON.stringify(input));
  const live=()=>{need(Math.max(Date.now(),initialWall+performance.now()-initialMono)<input.deadline);authority.assertNoKeyLive(inputSha256,input.authoritySha256);};
  live();
  const t = targets({ ...input, profileMountPath: `/run/zunder-wallet-${input.runId}`, controller: { pid: process.pid, anonymousFd: 5, netnsFd: 6 } });
  const content = Buffer.from(`PUBLIC_NO_KEY_CANARY_${randomBytes(24).toString('hex')}\n`);
  const created = new Map(); const handles = [];
  let server, connections = 0, closed = false, closing = false;
  const snapshot = () => ({ runId: input.runId, canarySha256: hash(content), canaries: [...created].map(([path, s]) => ({ path, device: s.dev, inode: s.ino })), socketConnections: connections });
  const removeOwned = async path => {
    const expected = created.get(path); if (!expected) return;
    const actual = await fs.lstat(path); need(actual.dev === expected.dev && actual.ino === expected.ino);
    live(); await fs.unlink(path); created.delete(path);
  };
  async function close() {
    if (closed) return; need(!closing); closing = true;
    try {
    if (server?.listening) {
      // net.Server.close removes its bound path; authenticate its current inode and authority first.
      const expected=created.get(t.socket);
      need(expected); const actual=await fs.lstat(t.socket);need(actual.dev===expected.dev && actual.ino===expected.ino);
      live();
      await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('no_key_fixture_cleanup_unknown')), 2000); server.close(() => { clearTimeout(timer); resolve(); }); });
    }
    // Node normally removes its own socket pathname when closing.
    if (created.has(t.socket)) {
      try { await fs.lstat(t.socket); await removeOwned(t.socket); } catch (e) { if (e?.code !== 'ENOENT') throw e; created.delete(t.socket); }
    }
    for (const handle of handles) await handle.close();
    for (const path of [...created.keys()]) await removeOwned(path);
    content.fill(0); closed = true;
    } finally { closing = false; }
  }
  try {
    for (const path of [...t.canaries, t.socket, t.anonymous]) {
      try { await fs.lstat(path); throw new Error('no_key_fixture_collision'); } catch (e) { if (e?.code !== 'ENOENT') throw e; }
    }
    for (const path of t.canaries) {
      live(); const file = await fs.open(path, 'wx', 0o644);
      try { live(); await file.writeFile(content); live(); await file.chmod(0o644); created.set(path, await file.stat()); } finally { await file.close(); }
    }
    live(); const anonymous = await fs.open(t.anonymous, 'wx+', 0o600); handles.push(anonymous);
    live(); await anonymous.writeFile(content); created.set(t.anonymous, await anonymous.stat()); await removeOwned(t.anonymous);
    const ns = await fs.open('/proc/self/ns/net', 'r'); handles.push(ns);
    server = net.createServer(socket => { connections++; socket.destroy(); });
    await new Promise((resolve, reject) => { server.once('error', reject); live(); server.listen(t.socket, resolve); });
    created.set(t.socket, await fs.lstat(t.socket)); live(); await fs.chmod(t.socket, 0o777);
    const stat = await fs.readFile(`/proc/${process.pid}/stat`, 'utf8'); const birth = stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19]; need(/^[0-9]+$/.test(birth));
    for (const path of t.canaries) need(hash(await fs.readFile(path)) === hash(content));
    live();
    return Object.freeze({ controller: Object.freeze({ pid: process.pid, birth, anonymousFd: anonymous.fd, netnsFd: ns.fd, canarySha256: hash(content) }), snapshot, close });
  } catch { await close().catch(() => {}); throw new Error('no_key_fixture_setup_refused'); }
}

/** Root-owned direct-network canaries on the already-owned host veth only.
 * Imported separately by the controller; never runs during author tests. */
export async function prepareNetworkSinks(config, authority) {
  const { validateConfig, lease } = await import('./contract.mjs');
  const { createSocket } = await import('node:dgram');
  const c = validateConfig(config); const check = lease(c, authority); check();
  need(process.platform === 'linux' && process.arch === 'x64' && process.getuid() === 0);
  return networkSinkLifecycle(c, check, { createServer: net.createServer, connect: net.connect, createSocket });
}

/** Lower-level lifecycle exposed for inert fixtures only. The root adapter above
 * hardwires real transport and obtains its check from the authenticated lease. */
export async function networkSinkLifecycle(c, check, io) {
  check();
  const counts = { tcp: 0, dnsUdp: 0, quicUdp: 0 }; let baseline;
  const tcp = io.createServer(socket => { counts.tcp++; socket.destroy(); });
  const dns = io.createSocket('udp4'), quic = io.createSocket('udp4');
  dns.on('message', () => { counts.dnsUdp++; }); quic.on('message', () => { counts.quicUdp++; });
  let closed = false; const started = [];
  async function close() {
    if (closed) return; closed = true;
    for (const [kind, item] of started.reverse()) await new Promise(resolve => {
      if (kind === 'tcp') item.close(resolve); else item.close(resolve);
    });
  }
  try {
    await new Promise((resolve, reject) => { tcp.once('error', reject); check(); tcp.listen(c.network.deniedPort, c.network.proxyIpv4, () => { started.push(['tcp', tcp]); resolve(); }); });
    for (const [socket, port] of [[dns, 53], [quic, 443]]) await new Promise((resolve, reject) => { socket.once('error', reject); check(); socket.bind(port, c.network.proxyIpv4, () => { started.push(['udp', socket]); resolve(); }); });
    check();
    return Object.freeze({
      async verifyPositiveControls() {
        check(); need(!baseline && !closed);
        await new Promise((resolve, reject) => { check(); const s = io.connect({host:c.network.proxyIpv4,port:c.network.deniedPort}); const timer=setTimeout(()=>{s.destroy();reject(new Error('no_key_sink_refused'));},1000); s.once('connect',()=>{clearTimeout(timer);s.destroy();resolve();});s.once('error',()=>{clearTimeout(timer);reject(new Error('no_key_sink_refused'));}); });
        for (const socket of [dns, quic]) await new Promise((resolve, reject) => { check(); socket.send(Buffer.from('PUBLIC_NO_KEY_POSITIVE_CONTROL'), socket===dns?53:443, c.network.proxyIpv4, e=>e?reject(new Error('no_key_sink_refused')):resolve()); });
        const until=Date.now()+1000;
        while (counts.tcp!==1 || counts.dnsUdp!==1 || counts.quicUdp!==1) { check(); need(Date.now()<until); await new Promise(resolve=>setTimeout(resolve,10)); }
        check(); baseline={...counts}; return Object.freeze({...baseline});
      },
      snapshot() { check(); need(!!baseline && !closed); return Object.freeze({ positiveControls: {...baseline}, delta: {tcp:counts.tcp-baseline.tcp,dnsUdp:counts.dnsUdp-baseline.dnsUdp,quicUdp:counts.quicUdp-baseline.quicUdp} }); },
      close,
    });
  } catch { await close().catch(()=>{}); throw new Error('no_key_sink_setup_refused'); }
}
