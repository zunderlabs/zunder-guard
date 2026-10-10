import path from "node:path";
import { exact, hash, refuse, type Config, type Pin } from "./driver-policy.ts";
export interface LauncherConfig {
  schema: 1;
  runId: string;
  startedAt: number;
  deadline: number;
  authoritySha256: string;
  browserUid: 62345;
  browserGid: 62345;
  chromium: Pin;
  profileMountPath: string;
  paths: { profile: string; home: string; tmp: string; cache: string };
  proxyEndpoint: { ipv4: string; port: number };
  browserControlFds: [3, 4];
  containmentConfig: Pin;
}
/** Public binding only. Root's checked launcher implements and verifies actual isolation. */
export function validateLauncher(
  value: unknown,
  c: Config,
  chromium: Pin,
): LauncherConfig {
  exact(value, [
    "schema",
    "runId",
    "startedAt",
    "deadline",
    "authoritySha256",
    "browserUid",
    "browserGid",
    "chromium",
    "profileMountPath",
    "paths",
    "proxyEndpoint",
    "browserControlFds",
    "containmentConfig",
  ]);
  const v = value as unknown as LauncherConfig;
  for (const [k, want] of Object.entries({
    schema: 1,
    runId: c.runId,
    startedAt: c.startedAt,
    deadline: c.deadline,
    authoritySha256: c.authoritySha256,
    browserUid: 62345,
    browserGid: 62345,
    profileMountPath: c.profileMountPath,
  }))
    if (value[k] !== want) refuse("isolation");
  exact(v.chromium, ["path", "sha256"]);
  if (
    v.chromium.path !== chromium.path ||
    v.chromium.sha256 !== chromium.sha256
  )
    refuse("source");
  exact(v.paths, ["profile", "home", "tmp", "cache"]);
  for (const key of ["profile", "home", "tmp", "cache"] as const)
    if (v.paths[key] !== path.join(c.profileMountPath, key))
      refuse("isolation");
  exact(v.proxyEndpoint, ["ipv4", "port"]);
  if (
    v.proxyEndpoint.ipv4 !== c.proxyEndpoint.ipv4 ||
    v.proxyEndpoint.port !== c.proxyEndpoint.port
  )
    refuse("isolation");
  if (JSON.stringify(v.browserControlFds) !== "[3,4]") refuse("isolation");
  exact(v.containmentConfig, ["path", "sha256"]);
  if (
    typeof v.containmentConfig.path !== "string" ||
    !path.isAbsolute(v.containmentConfig.path) ||
    path.normalize(v.containmentConfig.path) !== v.containmentConfig.path ||
    !hash(v.containmentConfig.sha256)
  )
    refuse("source");
  return structuredClone(v);
}
