// Actual privileged Linux command adapter; ROOT EXECUTION ONLY after full review.
// No command or namespace is created on import. No keys enter this module.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import { planRootNetwork, type NetworkConfig, type NamespaceIdentity, type RootNetworkCapability, type NetworkCommand, type NetworkPlan } from './network.ts';
export interface ExecutablePin { path: string; sha256: string }
/** Exact reviewed parent flow object; these methods perform real reads, never accept driver flags. */
export interface LinuxFlowBoundary {
  assertOriginalAuthority(deadline: number): Promise<void>;
  assertDispatchAuthority(deadline: number): void;
  assertIndependentWatchdogAndMountPolicy(): Promise<void>;
  assertOwnedCgroupDead(identity: NamespaceIdentity): Promise<void>;
  authorizeOwnedNetworkCleanup(identity: NamespaceIdentity): Promise<number>;
  releaseOwnedNamespaceHandles(identity: NamespaceIdentity): Promise<void>;
  hold(reason: 'network-unknown'): Promise<void>;
}
const refuse = (): never => { throw new Error('Linux network boundary refused'); };
const equal = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
/** Synchronous dispatch guard: callers must spawn directly after this, without an await. */
export function assertRootDispatchDeadline(deadline: number, authority: (deadline: number) => void): void {
  if (!Number.isSafeInteger(deadline) || Date.now() >= deadline) refuse();
  // Real parent's synchronous UTC + monotonic cutoff check, with no await before spawn.
  authority(deadline);
}
/** Final await boundary shared with inert race regressions; never grants OS authority. */
export async function recheckBeforeRootSpawn(deadline: number, authority: (deadline: number) => Promise<void>,
  resource?: { expected: NamespaceIdentity; read: () => Promise<NamespaceIdentity> }) {
  const expected = resource ? structuredClone(resource.expected) : undefined;
  if (resource && !equal(await resource.read(), expected)) refuse();
  // The parent validates both the original authority and its one minted cleanup
  // cutoff against monotonic time. A shortened deadline must never skip it.
  await authority(deadline);
  if (!Number.isSafeInteger(deadline) || Date.now() >= deadline) refuse();
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return refuse();
  return value as Record<string, unknown>;
}
/** Reject every extra chain/rule, not only the presence of expected accept clauses. */
export function validateNftReadback(value: unknown, plan: NetworkPlan) {
  const rows = object(value).nftables;
  if (!Array.isArray(rows) || rows.length !== 6) return refuse();
  let meta = 0, tables = 0; const chains = new Set<string>(), rules = new Set<string>();
  for (const entry of rows) {
    const row = object(entry), keys = Object.keys(row);
    if (keys.length !== 1) refuse();
    if (keys[0] === 'metainfo') { meta++; continue; }
    const kind = keys[0]!, item = object(row[kind]);
    if (item.family !== 'inet' || (kind === 'table' ? item.name : item.table) !== 'zunder_wallet') refuse();
    if (kind === 'table') { if (Object.keys(item).some(k => !['family','name','handle'].includes(k))) refuse(); tables++; continue; }
    if (kind === 'chain') {
      if ((item.name !== 'input' && item.name !== 'output') || chains.has(item.name as string)
        || item.type !== 'filter' || item.hook !== item.name || item.prio !== 0 || item.policy !== 'drop'
        || Object.keys(item).some(k => !['family','table','name','handle','type','hook','prio','policy'].includes(k))) refuse();
      chains.add(item.name as string); continue;
    }
    if (kind !== 'rule' || (item.chain !== 'input' && item.chain !== 'output') || rules.has(item.chain as string)
      || Object.keys(item).some(k => !['family','table','chain','handle','expr'].includes(k))) refuse();
    const input = item.chain === 'input';
    const expressions = item.expr;
    if (!Array.isArray(expressions)) refuse();
    // Some kernels emit an implicit tcp protocol match; only this exact redundant predicate is allowed.
    const meaningful = (expressions as unknown[]).filter(e => !equal(e, { match: { op: '==', left: { meta: { key: 'l4proto' } }, right: 'tcp' } }));
    const state = input ? 'established' : { set: ['new','established'] };
    const expected = [
      { match: { op: '==', left: { payload: { protocol: 'ip', field: input ? 'saddr' : 'daddr' } }, right: plan.config.hostIpv4 } },
      { match: { op: '==', left: { payload: { protocol: 'tcp', field: input ? 'sport' : 'dport' } }, right: plan.config.proxyPort } },
      { match: { op: 'in', left: { ct: { key: 'state' } }, right: state } }, { accept: null },
    ];
    // nft versions use == for a single state and ==/in for a set; neither widens it.
    if (meaningful.length !== 4) refuse();
    const actualState = object(object(meaningful[2]).match);
    if (actualState.op !== '==' && actualState.op !== 'in') refuse();
    (expected[2]!.match as { op: string }).op = actualState.op as string;
    if (!equal(meaningful, expected)) refuse(); rules.add(item.chain as string);
  }
  if (meta !== 1 || tables !== 1 || chains.size !== 2 || rules.size !== 2) refuse();
}

export async function createLinuxNetworkCapability(input: NetworkConfig, pins: readonly ExecutablePin[], flow: LinuxFlowBoundary): Promise<RootNetworkCapability> {
  if (process.platform !== 'linux' || process.arch !== 'x64' || process.getuid?.() !== 0
    || process.env.NODE_OPTIONS || process.env.DEBUG || process.env.PWDEBUG
    || process.execArgv.some(a => /inspect|require|import|loader|report|trace/i.test(a))) refuse();
  const plan = planRootNetwork(input), executablePins = structuredClone(pins);
  if (executablePins.length !== 3 || new Set(executablePins.map(p => p.path)).size !== 3) refuse();
  for (const p of executablePins) {
    if (!Object.values(plan.config.executables).includes(p.path) || !/^[0-9a-f]{64}$/.test(p.sha256) || await realpath(p.path) !== p.path) refuse();
    const st = await lstat(p.path);
    if (!st.isFile() || st.uid !== 0 || (st.mode & 0o022) || st.nlink !== 1
      || createHash('sha256').update(await readFile(p.path)).digest('hex') !== p.sha256) refuse();
  }
  if ((await readFile('/proc/swaps', 'utf8')).trim().split('\n').length !== 1
    || !/^Max core file size\s+0\s+0\s+bytes$/m.test(await readFile('/proc/self/limits', 'utf8'))) refuse();
  const query = async (command: NetworkCommand, deadline: number): Promise<string> => {
    if (Date.now() >= deadline || command.stdin && Buffer.byteLength(command.stdin) > 8192) refuse();
    const p = executablePins.find(p => p.path === command.executable); if (!p) return refuse();
    // Recheck pinned bytes and ownership before dispatch; parent source/runtime pins cover pre-import trust.
    const st = await lstat(p.path);
    if (st.uid !== 0 || (st.mode & 0o022) || createHash('sha256').update(await readFile(p.path)).digest('hex') !== p.sha256) refuse();
    const deleting = equal(command, { executable:plan.config.executables.ip, argv:['netns','delete',plan.namespace] });
    if (deleting && !capturedIdentity) refuse();
    await recheckBeforeRootSpawn(deadline,
      checkedDeadline => flow.assertOriginalAuthority(checkedDeadline),
      deleting ? { expected:capturedIdentity!, read:()=>namespaceIdentity(plan.namespace) } : undefined);
    return await new Promise<string>((resolve, reject) => {
      let settled = false, size = 0, unknown = false; const chunks: Buffer[] = [];
      const finish = (success: boolean) => {
        if (settled) return; settled = true; clearTimeout(timer);
        if (success && !unknown) resolve(Buffer.concat(chunks).toString('utf8'));
        else reject(new Error('Linux network command uncertain'));
      };
      // The await above resumes in a new microtask. Recheck synchronously at dispatch.
      assertRootDispatchDeadline(deadline, checkedDeadline => flow.assertDispatchAuthority(checkedDeadline));
      const child = spawn(p.path, [...command.argv], { env: { PATH:'/usr/sbin:/usr/bin:/sbin:/bin', LANG:'C', TZ:'UTC' },
        stdio:['pipe','pipe','ignore'], shell:false });
      const kill = () => { unknown = true; try { child.kill('SIGKILL'); } catch { /* uncertain remains latched */ } finish(false); };
      const timer = setTimeout(kill, Math.min(5000, deadline - Date.now()));
      child.on('error', () => finish(false)); child.stdin.on('error', kill);
      child.stdout.on('error', kill);
      child.stdout.on('data', (chunk: Buffer) => { size += chunk.length; if (size > 65_536) kill(); else chunks.push(chunk); });
      child.on('close', code => finish(code === 0)); child.stdin.end(command.stdin || '');
    });
  };
  const ip = (...argv: string[]): NetworkCommand => ({ executable:plan.config.executables.ip, argv });
  let capturedIdentity: NamespaceIdentity | undefined;
  const namespaceIdentity = async (name: string) => {
    if (name !== plan.namespace) refuse(); const st = await lstat(`/run/netns/${name}`, { bigint:true });
    if (!st.isFile() || st.uid !== 0n || (st.mode & 0o022n)) refuse();
    const identity = { name, device:String(st.dev), inode:String(st.ino) };
    if (capturedIdentity && !equal(identity, capturedIdentity)) refuse();
    capturedIdentity ||= Object.freeze(identity); return identity;
  };
  let cleanupDeadline: number | undefined;
  let nextStep = 0, mutationPending = false, mutationUnknown = false, cleanupConsumed = false;
  return {
    assertOriginalAuthority: deadline => flow.assertOriginalAuthority(deadline),
    assertIndependentWatchdogAndMountPolicy: () => flow.assertIndependentWatchdogAndMountPolicy(),
    async assertFreshNamesAndAddresses(namespace, links, addresses) {
      if (namespace !== plan.namespace || !equal(links, plan.links) || !equal(addresses, [plan.config.hostIpv4,plan.config.browserIpv4])) refuse();
      try { await lstat(`/run/netns/${namespace}`); return refuse(); } catch(e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
      const data = JSON.parse(await query(ip('-j','address','show'), plan.config.deadline)) as { ifname?:string; addr_info?:{local?:string}[] }[];
      if (!Array.isArray(data) || data.some(i => links.includes(i.ifname || '') || i.addr_info?.some(a => addresses.includes(a.local || '')))) refuse();
    },
    async runPinned(command, deadline) {
      const fixed = structuredClone(command);
      const known = !mutationUnknown && nextStep < plan.steps.length && equal(plan.steps[nextStep], fixed)
        && deadline === plan.config.deadline;
      const cleanup = equal(fixed, ip('netns','delete',plan.namespace)) && deadline === cleanupDeadline;
      if (mutationPending || (!known && !cleanup) || cleanup && cleanupConsumed) refuse();
      // Admission/latches consumed synchronously, before pin-read or dispatch awaits.
      mutationPending = true; if (cleanup) cleanupConsumed = true; else nextStep++;
      try {
        if (cleanup) {
          if (!capturedIdentity) refuse();
          await namespaceIdentity(plan.namespace); // Exact original dev/inode, never adopt a rebound path.
        }
        await query(fixed, deadline);
      }
      catch { mutationUnknown = true; await flow.hold('network-unknown').catch(() => undefined); throw new Error('Linux network mutation uncertain'); }
      finally { mutationPending = false; }
    },
    readNamespaceIdentity: namespaceIdentity,
    async verifyExactKernelNetworkPolicy(received) {
      if (received.digest !== plan.digest) refuse();
      const dump = JSON.parse(await query(ip('netns','exec',plan.namespace,plan.config.executables.nft,'-j','list','ruleset'),plan.config.deadline));
      validateNftReadback(dump, plan);
      const sys = await query(ip('netns','exec',plan.namespace,plan.config.executables.sysctl,'-n','net.ipv6.conf.all.disable_ipv6','net.ipv6.conf.default.disable_ipv6','net.ipv4.ip_forward'),plan.config.deadline);
      if (sys.trim() !== '1\n1\n0') refuse();
      const routes = JSON.parse(await query(ip('-n',plan.namespace,'-j','route','show','table','all'),plan.config.deadline)) as {dst?:string}[];
      const octets = plan.config.hostIpv4.split('.'); octets[3] = String(Number(octets[3]) - 1);
      const permitted = new Set([octets.join('.')+'/30',plan.config.browserIpv4,octets.join('.'),octets.slice(0,3).join('.')+'.'+(Number(octets[3])+3)]);
      if (!Array.isArray(routes) || routes.some(r => !r.dst || !permitted.has(r.dst))) refuse();
      const links = JSON.parse(await query(ip('-n',plan.namespace,'-j','link','show'),plan.config.deadline)) as {ifname?:string;flags?:string[]}[];
      if (!Array.isArray(links) || links.length !== 2 || !links.some(l => l.ifname === plan.links[1] && l.flags?.includes('UP'))
        || !links.some(l => l.ifname === 'lo' && !l.flags?.includes('UP'))) refuse();
    },
    assertOwnedCgroupDead: identity => flow.assertOwnedCgroupDead(identity),
    async authorizeOwnedNetworkCleanup(identity) { cleanupDeadline = await flow.authorizeOwnedNetworkCleanup(identity); return cleanupDeadline; },
    releaseOwnedNamespaceHandles: identity => flow.releaseOwnedNamespaceHandles(identity),
    async verifyOwnedNetworkAbsent(identity, links) {
      if (identity.name !== plan.namespace || !equal(links, plan.links) || !cleanupDeadline) return refuse();
      try { await lstat(`/run/netns/${plan.namespace}`); return refuse(); } catch(e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
      const data = JSON.parse(await query(ip('-j','link','show'), cleanupDeadline)) as {ifname?:string}[];
      if (!Array.isArray(data) || data.some(i => links.includes(i.ifname || ''))) refuse();
    },
    hold: reason => flow.hold(reason),
  };
}
