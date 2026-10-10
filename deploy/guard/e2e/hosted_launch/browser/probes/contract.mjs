import { createHash } from 'node:crypto';
export const STAGING = 'https://staging.zunderlabs.com/approve';
export const UID = 62345;
export const hash = value => createHash('sha256').update(value).digest('hex');
export const need = value => { if (!value) throw new Error('no_key_probe_refused'); };
export function exact(value, keys) {
  need(value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k)));
}
export function validateConfig(value, now = Date.now()) {
  exact(value, ['schema', 'purpose', 'runId', 'startedAt', 'deadline', 'authoritySha256', 'launcherSha256', 'probeLauncherSha256', 'profileMountPath', 'extensionId', 'controller', 'network']);
  need(value.schema === 1 && value.purpose === 'no-key-boundary-probes'
    && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.runId)
    && Number.isSafeInteger(value.startedAt) && Number.isSafeInteger(value.deadline)
    && value.startedAt <= now && now < value.deadline && value.deadline <= value.startedAt + 1_200_000
    && [value.authoritySha256, value.launcherSha256, value.probeLauncherSha256].every(s => /^[a-f0-9]{64}$/.test(s))
    && value.profileMountPath === `/run/zunder-wallet-${value.runId}` && /^[a-p]{32}$/.test(value.extensionId));
  exact(value.controller, ['pid', 'birth', 'anonymousFd', 'netnsFd', 'canarySha256']);
  need(Number.isSafeInteger(value.controller.pid) && value.controller.pid > 1 && /^[0-9]+$/.test(value.controller.birth)
    && ['anonymousFd', 'netnsFd'].every(k => Number.isInteger(value.controller[k]) && value.controller[k] >= 5 && value.controller[k] <= 1024)
    && value.controller.anonymousFd !== value.controller.netnsFd && /^[a-f0-9]{64}$/.test(value.controller.canarySha256));
  exact(value.network, ['proxyIpv4', 'proxyPort', 'deniedPort']);
  need(/^169\.254\.(?:[0-9]{1,3})\.(?:[0-9]{1,3})$/.test(value.network.proxyIpv4)
    && value.network.proxyIpv4.split('.').every(n => +n <= 255)
    && Number.isInteger(value.network.proxyPort) && value.network.proxyPort >= 1024 && value.network.proxyPort <= 65535
    && value.network.deniedPort === 48731 && value.network.proxyPort !== 48731);
  return structuredClone(value);
}
export function targets(c) {
  const suffix = `zunder-no-key-${c.runId}`;
  return Object.freeze({
    canaries: ['/home', '/root', '/run'].map(p => `${p}/.${suffix}.canary`),
    socket: `/run/.${suffix}.sock`,
    anonymous: `/run/.${suffix}.anonymous`,
    forbiddenWrites: ['/home', '/root', '/run', '/tmp', '/var/tmp', '/dev/shm', '/opt'].map(p => `${p}/.${suffix}.write`),
    allowedWrites: ['profile', 'home', 'tmp', 'cache'].map(p => `${c.profileMountPath}/${p}/.${suffix}.write`),
    controller: [`/proc/${c.controller.pid}/mem`, `/proc/${c.controller.pid}/fd/${c.controller.anonymousFd}`, `/proc/${c.controller.pid}/fd/${c.controller.netnsFd}`, `/proc/${c.controller.pid}/ns/net`],
  });
}
export function lease(c, authority) {
  const startWall = Date.now(), startMono = performance.now();
  const configSha256 = hash(JSON.stringify(c));
  return () => {
    need(Math.max(Date.now(), startWall + performance.now() - startMono) < c.deadline);
    // Actual parent capability, never a config boolean or an HTTP/browser endpoint.
    authority.assertNoKeyLive(configSha256, c.authoritySha256);
  };
}
export function result(c, kind, observations) {
  return { schema: 1, purpose: 'no-key-boundary-probes', runId: c.runId, kind,
    configSha256: hash(JSON.stringify(c)), observations, privateInput: false, runtimeAdmission: false };
}
