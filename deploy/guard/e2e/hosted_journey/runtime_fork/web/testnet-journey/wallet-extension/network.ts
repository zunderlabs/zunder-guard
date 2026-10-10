// Root-only Linux resource plan. No command executes on import or plan creation.
// The reviewed parent supplies the privileged command/identity/death capability;
// this module does not certify cgroup, mount, UID, watchdog or no-key admission.
import { createHash } from 'node:crypto';

export interface NetworkConfig {
  runId: string; attempt: number; startedAt: number; deadline: number;
  hostIpv4: string; browserIpv4: string; proxyPort: number;
  executables: { ip: string; nft: string; sysctl: string };
}
export interface NetworkCommand { executable: string; argv: readonly string[]; stdin?: string }
export interface NamespaceIdentity { device: string; inode: string; name: string }
/** An authenticated parent-owned implementation, never a JSON receipt or driver callback. */
export interface RootNetworkCapability {
  assertOriginalAuthority(deadline: number): Promise<void>;
  assertIndependentWatchdogAndMountPolicy(): Promise<void>;
  assertFreshNamesAndAddresses(namespace: string, links: readonly string[], addresses: readonly string[]): Promise<void>;
  runPinned(command: NetworkCommand, deadline: number): Promise<void>;
  readNamespaceIdentity(namespace: string): Promise<NamespaceIdentity>;
  verifyExactKernelNetworkPolicy(plan: NetworkPlan): Promise<void>;
  assertOwnedCgroupDead(identity: NamespaceIdentity): Promise<void>;
  authorizeOwnedNetworkCleanup(identity: NamespaceIdentity): Promise<number>;
  releaseOwnedNamespaceHandles(identity: NamespaceIdentity): Promise<void>;
  verifyOwnedNetworkAbsent(identity: NamespaceIdentity, links: readonly string[]): Promise<void>;
  hold(reason: 'network-unknown'): Promise<void>;
}
export interface NetworkPlan {
  namespace: string; links: readonly [string, string]; config: Readonly<NetworkConfig>;
  rules: string; digest: string; steps: readonly NetworkCommand[];
}
const fail = (): never => { throw new Error('Root network boundary refused'); };
function ipv4(value: string): number[] {
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value)) fail();
  const parts = value.split('.').map(Number);
  if (parts.some(n => n > 255)) fail(); return parts;
}
export function planRootNetwork(input: NetworkConfig): NetworkPlan {
  const c: NetworkConfig = structuredClone(input);
  if (Object.keys(c).sort().join(',') !== 'attempt,browserIpv4,deadline,executables,hostIpv4,proxyPort,runId,startedAt'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(c.runId)
    || !Number.isSafeInteger(c.attempt) || c.attempt < 1 || c.attempt > 9
    || !Number.isSafeInteger(c.startedAt) || !Number.isSafeInteger(c.deadline)
    || c.startedAt <= 0 || c.deadline <= c.startedAt || c.deadline - c.startedAt > 20 * 60_000
    || !Number.isSafeInteger(c.proxyPort) || c.proxyPort < 1024 || c.proxyPort > 65535
    || !c.executables || Object.keys(c.executables).sort().join(',') !== 'ip,nft,sysctl') fail();
  for (const e of Object.values(c.executables)) {
    if (!/^\/(?:usr\/(?:s?bin)|s?bin)\/[a-z0-9-]+$/.test(e)) fail();
  }
  const a = ipv4(c.hostIpv4), b = ipv4(c.browserIpv4);
  if (a[0] !== 169 || a[1] !== 254 || a[2]! < 1 || a[2]! > 254 || a[3]! % 4 !== 1
    || b[0] !== a[0] || b[1] !== a[1] || b[2] !== a[2] || b[3] !== a[3]! + 1) fail();
  const namespace = `zunder-site-${c.runId}-${c.attempt}`;
  const suffix = c.runId.replaceAll('-', '').slice(0, 8) + c.attempt;
  const links = [`zwh${suffix}`, `zwb${suffix}`] as const;
  const rules = `table inet zunder_wallet {
 chain input { type filter hook input priority 0; policy drop;
  ip saddr ${c.hostIpv4} tcp sport ${c.proxyPort} ct state established accept
 }
 chain output { type filter hook output priority 0; policy drop;
  ip daddr ${c.hostIpv4} tcp dport ${c.proxyPort} ct state { new, established } accept
 }
}
`;
  const ip = (...argv: string[]): NetworkCommand => ({ executable: c.executables.ip, argv });
  const exec = (executable: string, ...argv: string[]): NetworkCommand => ip('netns', 'exec', namespace, executable, ...argv);
  // Peer stays DOWN until namespace-local deny policy and IPv6 settings exist.
  const steps: NetworkCommand[] = [
    ip('netns', 'add', namespace),
    ip('link', 'add', links[0], 'type', 'veth', 'peer', 'name', links[1]),
    ip('link', 'set', links[1], 'netns', namespace),
    ip('address', 'add', `${c.hostIpv4}/30`, 'dev', links[0]),
    ip('-n', namespace, 'address', 'add', `${c.browserIpv4}/30`, 'dev', links[1]),
    exec(c.executables.sysctl, '-w', 'net.ipv6.conf.all.disable_ipv6=1'),
    exec(c.executables.sysctl, '-w', 'net.ipv6.conf.default.disable_ipv6=1'),
    exec(c.executables.sysctl, '-w', 'net.ipv4.ip_forward=0'),
    { ...exec(c.executables.nft, '-f', '-'), stdin: rules },
    ip('link', 'set', links[0], 'up'),
    ip('-n', namespace, 'link', 'set', links[1], 'up'),
  ];
  Object.freeze(c.executables); Object.freeze(c);
  for (const command of steps) { Object.freeze(command.argv); Object.freeze(command); }
  const digest = createHash('sha256').update(JSON.stringify({ namespace, links, config: c, rules, steps })).digest('hex');
  return Object.freeze({ namespace, links: Object.freeze(links), config: c, rules, digest, steps: Object.freeze(steps) });
}

/** Parent integration only; missing capabilities fail rather than grant admission. */
export async function prepareRootNetwork(input: NetworkConfig, root: RootNetworkCapability) {
  const plan = planRootNetwork(input);
  let unknown = false, identity: NamespaceIdentity | undefined, cleanAttempted = false;
  const live = async () => {
    if (unknown || Date.now() < plan.config.startedAt || Date.now() >= plan.config.deadline) fail();
    await root.assertOriginalAuthority(plan.config.deadline);
    if (unknown || Date.now() >= plan.config.deadline) fail();
  };
  await live(); await root.assertIndependentWatchdogAndMountPolicy(); await live();
  await root.assertFreshNamesAndAddresses(plan.namespace, plan.links, [plan.config.hostIpv4, plan.config.browserIpv4]);
  try {
    for (const command of plan.steps) { await live(); await root.runPinned(command, plan.config.deadline); await live(); }
    identity = Object.freeze(structuredClone(await root.readNamespaceIdentity(plan.namespace)));
    if (identity.name !== plan.namespace || !/^\d+$/.test(identity.device) || !/^\d+$/.test(identity.inode)) fail();
    await root.verifyExactKernelNetworkPolicy(plan); await live();
  } catch {
    unknown = true; await root.hold('network-unknown').catch(() => undefined);
    // A partially created resource may exist. Do not adopt/delete on guessed identity.
    throw new Error('Root network setup uncertain; retain exact resource names for reconciliation');
  }
  const ownedIdentity = identity;
  return Object.freeze({
    plan, identity: ownedIdentity,
    async verifyBeforeAdmission() { await live(); await root.verifyExactKernelNetworkPolicy(plan); await live(); },
    async closeAfterVerifiedDeath() {
      if (cleanAttempted) fail(); cleanAttempted = true;
      try {
        await root.assertOwnedCgroupDead(ownedIdentity);
        // Cleanup has its own reviewed root authority; ordinary run deadline grants no writes.
        const cleanupDeadline = await root.authorizeOwnedNetworkCleanup(ownedIdentity);
        if (!Number.isSafeInteger(cleanupDeadline) || cleanupDeadline <= Date.now() || cleanupDeadline > Date.now() + 60_000) fail();
        await root.releaseOwnedNamespaceHandles(ownedIdentity);
        await root.runPinned({ executable: plan.config.executables.ip, argv: ['netns', 'delete', plan.namespace] }, cleanupDeadline);
        // Deleting an owned namespace removes its veth peer iff no process retains it.
        await root.verifyOwnedNetworkAbsent(ownedIdentity, plan.links);
      } catch {
        unknown = true; await root.hold('network-unknown').catch(() => undefined);
        throw new Error('Root network cleanup uncertain');
      }
    },
  });
}
