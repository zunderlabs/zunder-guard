import { execFileSync } from 'node:child_process';
import { lstatSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { deployAdmittedIssuer, publicIssuerEnvironment } from './issuer.ts';

// Admission ID chooses a public-reviewed record, never a private script path.
// Caller must first run the public acquire gate into a new private directory.
const args = process.argv.slice(2);
let temporary: string | undefined;
try {
  if (args.length !== 2 || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(args[0] ?? '')) throw new Error('Invalid operation arguments');
  const env = publicIssuerEnvironment(process.env);
  const pinPath = path.join(import.meta.dirname, 'admissions', `${args[0]}.json`);
  const pinMeta = lstatSync(pinPath);
  if (!pinMeta.isFile() || pinMeta.isSymbolicLink()) throw new Error('Installed admission missing');
  const pin = JSON.parse(readFileSync(pinPath, 'utf8'));
  temporary = mkdtempSync(path.join(tmpdir(), 'zunder-public-issuer-result-'));
  const resultPath = path.join(temporary, 'invocation.json');
  const aws = (parameters: string[]) => {
    try { return execFileSync('aws', [...parameters, '--no-cli-pager'],
      { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch { throw new Error('AWS operation failed; provider output withheld'); }
  };
  const receipt = deployAdmittedIssuer(aws, pin, args[1] as string,
    { path: resultPath, read: () => JSON.parse(readFileSync(resultPath, 'utf8')) },
    env.ISSUER_RUNTIME_ROLE_ARN as string, env.ISSUER_RESUME_PAUSED === 'true');
  console.log(JSON.stringify({ schema: 1, admission: args[0], applied: true, ...receipt }));
} catch {
  // Do not expose provider responses, runtime environment, private filenames or
  // payload parse errors in public logs. Failure never claims the rule is paused.
  console.error('Issuer operation failed or could not be verified; reconcile the existing schedule and version before retrying.');
  process.exitCode = 1;
} finally {
  if (temporary) rmSync(temporary, { recursive: true, force: true });
}
