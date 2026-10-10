// Public root integration contract, not a mount/isolation PASS or an executable sandbox.
// These are SERVICE properties; systemd scopes do not implement them.
import { createHash } from 'node:crypto';
export interface BrowserMountConfig { runId: string; browserUid: 62345; browserGid: 62345; profilePath: string; runtimePath: string }
export function browserMountPolicy(input: BrowserMountConfig) {
  const c = structuredClone(input);
  if (Object.keys(c).sort().join(',') !== 'browserGid,browserUid,profilePath,runId,runtimePath'
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(c.runId)
    || c.browserUid !== 62345 || c.browserGid !== 62345
    || c.profilePath !== `/run/zunder-wallet-${c.runId}`
    || !/^\/opt\/zunder-runtime\/[a-z0-9-]+$/.test(c.runtimePath)) throw new Error('Browser mount policy refused');
  const memory = (path: string, mode: string) => `${path}:rw,nosuid,nodev,noexec,mode=${mode},uid=62345,gid=62345`;
  const properties = Object.freeze({
    User: '62345', Group: '62345', NoNewPrivileges: 'yes', UMask: '0077',
    ProtectSystem: 'strict', ProtectHome: 'yes', PrivateDevices: 'yes', PrivateMounts: 'yes',
    ProtectKernelTunables: 'yes', ProtectKernelModules: 'yes', ProtectControlGroups: 'yes',
    ProtectClock: 'yes', ProtectProc: 'invisible', RestrictSUIDSGID: 'yes', LimitCORE: '0',
    ReadOnlyPaths: Object.freeze([c.runtimePath]),
    // Parent/root driver and browser share this independently verified HOST tmpfs.
    // A child-only replacement would hide parent-precreated profile/CA/temporary paths.
    BindPaths: Object.freeze([c.profilePath]), ReadWritePaths: Object.freeze([c.profilePath]),
    TemporaryFileSystem: Object.freeze([memory('/tmp', '1777'), memory('/var/tmp', '1777'), memory('/dev/shm', '1777')]),
  });
  const requiredActualProbes = Object.freeze([
    'root controller UID0; actual Chromium UID/GID62345; browser runtime immutable',
    'actual mount namespace differs from host; strict host readonly policy and owned tmpfs mounts',
    'shared profile source is actual owned no-swap host tmpfs; root Node temporary artifacts stay there too',
    'host /tmp, /var/tmp, /dev/shm sentinel files inaccessible; no host-home or cloud credential access',
    'host writable file/directory creation denied outside these owned tmpfs mounts',
    'root control FD/memory/proc recovery denied from actual browser UID; only Chromium CDP3/4 inherited',
    'core soft/hard0, no swap, original-deadline independent watchdog and complete browser AND dedicated root-driver death proof',
  ]);
  return Object.freeze({ config: Object.freeze(c), properties, requiredActualProbes,
    digest: createHash('sha256').update(JSON.stringify({ config: c, properties, requiredActualProbes })).digest('hex'),
    executionImplemented: false as const });
}
