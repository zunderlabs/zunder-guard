// Public controller only. The admitted private ZIP is data, never local code.
import { createHash } from 'node:crypto';
import { lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { deployHosted, hostedEnvironment } from './issuer-control.ts';
import type { Aws, Invocation } from './issuer-control.ts';

export const ISSUER_PUBLIC_SUBJECT = 'repo:zunderlabs@338317604/zunder-guard@1409357189:environment:licence-issuer-production';
const hash = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');
function requireValue(ok: unknown, message: string): asserts ok {
  if (!ok) throw new Error(message);
}

export function publicIssuerEnvironment(input: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  requireValue(input.GITHUB_REPOSITORY === 'zunderlabs/zunder-guard'
    && input.GITHUB_REF === 'refs/heads/main' && input.GITHUB_REF_TYPE === 'branch'
    && input.GITHUB_EVENT_NAME === 'workflow_dispatch'
    && input.HOSTED_DELIVERY_TARGET === 'licence-issuer-production', 'Public issuer operation boundary refused');
  // Effective protected-main/environment policy and the real OIDC subject are
  // independently observed by admission/workflow and IAM, not inferred here.
  return hostedEnvironment(input);
}

export interface IssuerAdmission {
  schema: number; kind: string; target: string; inventorySha256: string;
}

export function admittedIssuerBytes(admission: IssuerAdmission, directory: string): Buffer {
  requireValue(admission.schema === 1 && admission.kind === 'licence-issuer'
    && admission.target === 'licence-issuer-production'
    && /^[a-f0-9]{64}$/.test(admission.inventorySha256), 'Issuer admission binding refused');
  const root = lstatSync(directory);
  requireValue(root.isDirectory() && !root.isSymbolicLink(), 'Issuer private payload directory refused');
  const entries = readdirSync(directory);
  requireValue(entries.length === 1 && entries[0] === 'issuer.zip', 'Issuer payload inventory refused');
  const archive = path.join(directory, 'issuer.zip');
  const meta = lstatSync(archive);
  requireValue(meta.isFile() && !meta.isSymbolicLink() && meta.nlink === 1
    && meta.size > 0 && meta.size <= 25 * 1024 * 1024, 'Issuer archive type or size refused');
  const bytes = readFileSync(archive);
  requireValue(bytes.length === meta.size && bytes.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 3, 4])),
    'Issuer archive bytes refused');
  const inventory = [{ path: 'issuer.zip', size: bytes.length, sha256: hash(bytes) }];
  requireValue(hash(JSON.stringify(inventory)) === admission.inventorySha256, 'Issuer admitted inventory changed');
  return bytes;
}

// Only call after acquire() independently re-admits the exact installed public
// admission. A TypeScript object alone is not an artifact authority credential.
export function deployAdmittedIssuer(aws: Aws, admission: IssuerAdmission, directory: string,
  invocation: Invocation, runtimeRole: string, resumePaused: boolean) {
  const bytes = admittedIssuerBytes(admission, directory);
  const temporary = mkdtempSync(path.join(tmpdir(), 'zunder-public-issuer-'));
  try {
    const archive = path.join(temporary, 'issuer.zip');
    writeFileSync(archive, bytes, { mode: 0o600, flag: 'wx' });
    return deployHosted(aws, { path: archive, sha256: createHash('sha256').update(bytes).digest('base64') },
      invocation, runtimeRole, resumePaused);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}
