import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, linkSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { admittedIssuerBytes, deployAdmittedIssuer, publicIssuerEnvironment, ISSUER_PUBLIC_SUBJECT } from './issuer.ts';
import { AWS_SECRET_FIELD, DESTINATION } from './issuer-control.ts';
import type { IssuerAdmission } from './issuer.ts';
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');
const bytes = Buffer.concat([Buffer.from([0x50, 0x4b, 3, 4]), Buffer.from('synthetic inert archive bytes')]);
const pin: IssuerAdmission = { schema: 1, kind: 'licence-issuer', target: 'licence-issuer-production',
  inventorySha256: hash(JSON.stringify([{ path: 'issuer.zip', size: bytes.length, sha256: hash(bytes) }])) };
function fixture(run: (directory: string) => void) {
  const directory = mkdtempSync(path.join(tmpdir(), 'zunder-issuer-test-'));
  try { writeFileSync(path.join(directory, 'issuer.zip'), bytes, { mode: 0o600 }); run(directory); }
  finally { rmSync(directory, { recursive: true, force: true }); }
}
const environment = { AWS_ACCESS_KEY_ID: 'synthetic', [AWS_SECRET_FIELD]: 'synthetic', AWS_SESSION_TOKEN: 'synthetic',
  AWS_REGION: 'eu-central-1', ISSUER_EXPECTED_ACCOUNT: '436632189317',
  ISSUER_RUNTIME_ROLE_ARN: `arn:aws:iam::${DESTINATION.account}:role/issuer-runtime`, GITHUB_REPOSITORY: 'zunderlabs/zunder-guard',
  GITHUB_REF: 'refs/heads/main', GITHUB_REF_TYPE: 'branch', GITHUB_EVENT_NAME: 'workflow_dispatch',
  HOSTED_DELIVERY_TARGET: 'licence-issuer-production' };
test('public operation requires the exact branch dispatch, environment target and temporary existing AWS destination', () => {
  assert.equal(publicIssuerEnvironment(environment).AWS_MAX_ATTEMPTS, '1');
  assert.equal(ISSUER_PUBLIC_SUBJECT, 'repo:zunderlabs@338317604/zunder-guard@1409357189:environment:licence-issuer-production');
  for (const bad of [{ GITHUB_REPOSITORY: 'zunderlabs/zunder' }, { GITHUB_REF: 'refs/tags/main' },
    { GITHUB_REF_TYPE: 'tag' }, { GITHUB_EVENT_NAME: 'push' }, { HOSTED_DELIVERY_TARGET: 'website-production' },
    { AWS_SESSION_TOKEN: '' }, { AWS_PROFILE: 'rejected-profile' }, { AWS_REGION: 'ap-northeast-1' }])
    assert.throws(() => publicIssuerEnvironment({ ...environment, ...bad }));
});
test('only one exact byte-bound ZIP is accepted as inert data', () => fixture(directory => {
  assert.deepEqual(admittedIssuerBytes(pin, directory), bytes);
  for (const bad of [{ schema: 2 }, { kind: 'website' }, { target: 'website-production' },
    { inventorySha256: '0'.repeat(64) }]) assert.throws(() => admittedIssuerBytes({ ...pin, ...bad }, directory));
  writeFileSync(path.join(directory, 'script.ts'), 'throw new Error("never execute");');
  assert.throws(() => admittedIssuerBytes(pin, directory));
}));
test('mutated bytes, links and invalid ZIP prefix fail before even the AWS identity read', () => {
  for (const mutate of [(directory: string) => writeFileSync(path.join(directory, 'issuer.zip'), Buffer.from('changed')),
    (directory: string) => { const zip = path.join(directory, 'issuer.zip'); rmSync(zip); symlinkSync('/nonexistent', zip); },
    (directory: string) => { const zip = path.join(directory, 'issuer.zip'); linkSync(zip, path.join(tmpdir(), `issuer-hardlink-${path.basename(directory)}`)); }]) {
    fixture(directory => {
      const extra = path.join(tmpdir(), `issuer-hardlink-${path.basename(directory)}`);
      try {
        mutate(directory); let calls = 0;
        assert.throws(() => deployAdmittedIssuer(() => { calls++; return ''; }, pin, directory,
          { path: '/unused', read: () => null }, environment.ISSUER_RUNTIME_ROLE_ARN, false));
        assert.equal(calls, 0);
      } finally { rmSync(extra, { force: true }); }
    });
  }
});
test('AWS refusal preserves the original admitted data and never executes it', () => fixture(directory => {
  let calls = 0;
  assert.throws(() => deployAdmittedIssuer(parameters => {
    calls++; assert.deepEqual(parameters, ['sts', 'get-caller-identity', '--query', 'Account', '--output', 'text']);
    return '313260780004';
  }, pin, directory, { path: '/unused', read: () => null }, environment.ISSUER_RUNTIME_ROLE_ARN, false), /Wrong AWS account/);
  assert.equal(calls, 1);
  assert.deepEqual(readFileSync(path.join(directory, 'issuer.zip')), bytes);
}));
test('full inert deployment uploads the byte-bound private copy with Lambda base64 hash and cleans it', () => fixture(directory => {
  const account = '436632189317';
  const name = 'zunder-licence-issuer';
  const arn = `arn:aws:lambda:eu-central-1:${account}:function:${name}`;
  const digest = createHash('sha256').update(bytes).digest('base64');
  let uploadedPath = '';
  let ruleState = 'ENABLED';
  let config = { FunctionArn: arn, Role: environment.ISSUER_RUNTIME_ROLE_ARN, Runtime: 'nodejs24.x',
    Handler: 'issuer.handler', Architectures: ['arm64'], State: 'Active', LastUpdateStatus: 'Successful',
    CodeSha256: 'previous', RevisionId: 'before' };
  const commands: string[] = [];
  const receipt = deployAdmittedIssuer(parameters => {
    const operation = `${parameters[0]} ${parameters[1]}`;
    commands.push(operation);
    if (operation === 'sts get-caller-identity') return account;
    if (operation === 'lambda get-function-configuration') return JSON.stringify(config);
    if (operation === 'events describe-rule') return JSON.stringify({
      Arn: `arn:aws:events:eu-central-1:${account}:rule/${name}`, ScheduleExpression: 'rate(1 minute)', State: ruleState });
    if (operation === 'events list-targets-by-rule') return JSON.stringify({ Targets: [{ Id: 'Issuer', Arn: arn }] });
    if (operation === 'events disable-rule') { ruleState = 'DISABLED'; return '{}'; }
    if (operation === 'events enable-rule') { ruleState = 'ENABLED'; return '{}'; }
    if (operation === 'lambda update-function-code') {
      const encodedPath = parameters[parameters.indexOf('--zip-file') + 1] as string;
      uploadedPath = encodedPath.slice('fileb://'.length);
      assert.notEqual(uploadedPath, path.join(directory, 'issuer.zip'));
      assert.deepEqual(readFileSync(uploadedPath), bytes);
      config = { ...config, CodeSha256: digest, RevisionId: 'after' };
      return JSON.stringify({ ...config, Version: '7' });
    }
    if (operation === 'lambda wait') return '{}';
    if (operation === 'lambda invoke') return JSON.stringify({ StatusCode: 200, ExecutedVersion: '7' });
    throw new Error('Unexpected inert authority');
  }, pin, directory, { path: '/unused', read: () => ({ delivered: 0, deferred: 0, failed: 0, signingIdentityVerified: true }) },
  environment.ISSUER_RUNTIME_ROLE_ARN, false);
  assert.equal(receipt.sha256, digest);
  assert.equal(receipt.version, '7');
  assert.equal(ruleState, 'ENABLED');
  assert.equal(existsSync(uploadedPath), false);
  assert.equal(commands.filter(command => command === 'lambda update-function-code').length, 1);
  assert.deepEqual(readFileSync(path.join(directory, 'issuer.zip')), bytes);
}));
