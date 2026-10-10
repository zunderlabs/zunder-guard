import test from 'node:test';
import assert from 'node:assert/strict';
import { deployHosted, hostedEnvironment, DESTINATION, AWS_SECRET_FIELD } from './issuer-control.ts';
const role = `arn:aws:iam::${DESTINATION.account}:role/issuer-runtime`;
const arn = `arn:aws:lambda:${DESTINATION.region}:${DESTINATION.account}:function:${DESTINATION.name}`;
const configuration = { FunctionArn: arn, Role: role, Runtime: 'nodejs24.x', Handler: 'issuer.handler',
  Architectures: ['arm64'], State: 'Active', LastUpdateStatus: 'Successful', CodeSha256: 'hash', RevisionId: 'synthetic-revision' };
const environment = { AWS_ACCESS_KEY_ID: 'synthetic', [AWS_SECRET_FIELD]: 'synthetic', AWS_SESSION_TOKEN: 'synthetic',
  AWS_REGION: DESTINATION.region, ISSUER_EXPECTED_ACCOUNT: DESTINATION.account, ISSUER_RUNTIME_ROLE_ARN: role };
test('temporary credentials and exact existing destination are required; profiles are rejected', () => {
  assert.equal(hostedEnvironment(environment).AWS_SHARED_CREDENTIALS_FILE, '/dev/null');
  assert.equal(hostedEnvironment({ ...environment, AWS_MAX_ATTEMPTS: '5' }).AWS_MAX_ATTEMPTS, '1');
  for (const bad of [{ AWS_PROFILE: 'rejected-profile' }, { AWS_DEFAULT_PROFILE: 'x' }, { AWS_SESSION_TOKEN: '' },
    { [AWS_SECRET_FIELD]: '' },
    { ISSUER_EXPECTED_ACCOUNT: '313260780004' }, { AWS_REGION: 'ap-northeast-1' }, { ISSUER_RUNTIME_ROLE_ARN: '' },
    { ISSUER_RESUME_PAUSED: 'yes' }]) assert.throws(() => hostedEnvironment({ ...environment, ...bad }));
});
function fixture(overrides: Record<string, unknown> = {}, result: unknown = { delivered: 1, deferred: 0, failed: 0, signingIdentityVerified: true }) {
  const calls: string[][] = [];
  const state = {
    rule: { Arn: `arn:aws:events:${DESTINATION.region}:${DESTINATION.account}:rule/${DESTINATION.name}`,
      State: 'ENABLED', ScheduleExpression: 'rate(1 minute)' } as Record<string, unknown>,
    targets: { Targets: [{ Id: 'Issuer', Arn: arn }] } as Record<string, unknown>,
    config: { ...configuration } as Record<string, unknown>,
  };
  if (overrides['events describe-rule'] && typeof overrides['events describe-rule'] !== 'function') {
    state.rule = overrides['events describe-rule'] as Record<string, unknown>;
    delete overrides['events describe-rule'];
  }
  const aws = (args: string[]) => {
    calls.push(args);
    const key = `${args[0]} ${args[1]}`;
    if (key === 'events disable-rule') state.rule.State = 'DISABLED';
    if (key === 'events enable-rule') state.rule.State = 'ENABLED';
    if (Object.hasOwn(overrides, key)) {
      const value = overrides[key];
      const resolved: unknown = typeof value === 'function' ? value() : value;
      return typeof resolved === 'string' ? resolved : JSON.stringify(resolved);
    }
    if (key === 'sts get-caller-identity') return DESTINATION.account;
    if (key === 'lambda get-function-configuration') return JSON.stringify(state.config);
    if (key === 'events describe-rule') return JSON.stringify(state.rule);
    if (key === 'events list-targets-by-rule') return JSON.stringify(state.targets);
    if (key === 'lambda update-function-code') return JSON.stringify({ ...configuration, CodeSha256: 'hash', Version: '3' });
    if (key === 'lambda invoke') return JSON.stringify({ StatusCode: 200, ExecutedVersion: '3' });
    if (['events disable-rule', 'events enable-rule', 'lambda wait'].includes(key)) return '{}';
    throw new Error(`Unexpected authority: ${key}`);
  };
  return { calls, state, run: (resume = false) => deployHosted(aws, { path: '/synthetic/package.zip', sha256: 'hash' },
    { path: '/synthetic/receipt.json', read: () => result }, role, resume) };
}
test('success invokes published version, enables only after health check, and never retrieves any secret', () => {
  const f = fixture(); const receipt = f.run();
  assert.equal(receipt.version, '3');
  assert.ok(f.calls.some(a => a[1] === 'enable-rule'));
  assert.equal(f.state.rule.State, 'ENABLED');
  assert.equal(f.calls.at(-1)?.[1], 'get-function-configuration');
  assert.ok(f.calls.some(a => a[1] === 'invoke' && a.includes('--qualifier') && a.includes('3')));
  assert.ok(f.calls.some(a => a[1] === 'update-function-code' && a.includes('--revision-id') && a.includes('synthetic-revision')));
  assert.ok(!f.calls.some(a => ['ssm', 'iam', 'cloudformation'].includes(a[0] ?? '')));
});
test('wrong account, configuration, target or manual pause cannot modify production', () => {
  for (const bad of [{ 'sts get-caller-identity': '313260780004' },
    { 'lambda get-function-configuration': { ...configuration, Role: `${role}-different` } },
    { 'events list-targets-by-rule': { Targets: [{ Id: 'Issuer', Arn: `${arn}:alias` }] } },
    { 'events list-targets-by-rule': { Targets: [{ Id: 'Issuer', Arn: arn, Input: '{}' }] } },
    { 'events describe-rule': { Arn: `arn:aws:events:${DESTINATION.region}:${DESTINATION.account}:rule/${DESTINATION.name}`,
      State: 'DISABLED', ScheduleExpression: 'rate(1 minute)' } }]) {
    const f = fixture(bad); assert.throws(() => f.run());
    assert.ok(!f.calls.some(a => a[1] === 'disable-rule' || a[1] === 'update-function-code'));
  }
});
test('wrong upload bytes or health receipt keeps the schedule disabled', () => {
  for (const bad of [{ 'lambda update-function-code': { CodeSha256: 'wrong', Version: '3' } },
    { 'lambda update-function-code': { CodeSha256: 'hash', Version: '$LATEST' } },
    { 'lambda invoke': { StatusCode: 200, ExecutedVersion: '4' } },
    { 'lambda invoke': { StatusCode: 200, ExecutedVersion: '3', FunctionError: 'Unhandled' } }]) {
    const f = fixture(bad); assert.throws(() => f.run());
    assert.ok(f.calls.some(a => a[1] === 'disable-rule'));
    assert.ok(!f.calls.some(a => a[1] === 'enable-rule'));
  }
  for (const bad of [null, { failed: 0 }, { delivered: 1, deferred: 0, failed: 1, signingIdentityVerified: true },
    { delivered: -1, deferred: 0, failed: 0, signingIdentityVerified: true }]) {
    const f = fixture({}, bad); assert.throws(() => f.run());
    assert.ok(!f.calls.some(a => a[1] === 'enable-rule'));
  }
});
test('only an explicit decision resumes a pre-existing paused schedule', () => {
  const f = fixture({ 'events describe-rule': { Arn: `arn:aws:events:${DESTINATION.region}:${DESTINATION.account}:rule/${DESTINATION.name}`,
    State: 'DISABLED', ScheduleExpression: 'rate(1 minute)' } });
  assert.equal(f.run(true).schedule, 'enabled');
});
test('transport failure and changes to scheduled code before or after invocation never resume', () => {
  const transport = fixture({ 'lambda wait': () => { throw new Error('synthetic timeout'); } });
  assert.throws(() => transport.run());
  assert.ok(!transport.calls.some(a => a[1] === 'enable-rule'));
  for (const changesAt of [2, 3]) {
    let reads = 0;
    const f = fixture({ 'lambda get-function-configuration': () => ({ ...configuration,
      CodeSha256: ++reads >= changesAt ? 'concurrent-change' : 'hash' }) });
    assert.throws(() => f.run());
    assert.ok(!f.calls.some(a => a[1] === 'enable-rule'));
    assert.equal(f.calls.some(a => a[1] === 'invoke'), changesAt === 3);
  }
});
test('handler, runtime, environment, revision and schedule target drift cannot be activated', () => {
  for (const drift of [{ Handler: 'missing.handler' }, { Runtime: 'nodejs22.x' },
    { Architectures: ['x86_64'] }, { Environment: { Variables: { altered: 'synthetic' } } },
    { RevisionId: 'concurrent-config-revision' }]) {
    let f: ReturnType<typeof fixture>;
    f = fixture({ 'lambda invoke': () => {
      Object.assign(f.state.config, drift);
      return { StatusCode: 200, ExecutedVersion: '3' };
    } });
    assert.throws(() => f.run(), /pre-activation failed/);
    assert.ok(!f.calls.some(a => a[1] === 'enable-rule'));
    assert.equal(f.state.rule.State, 'DISABLED');
  }
  let f: ReturnType<typeof fixture>;
  f = fixture({ 'lambda invoke': () => {
    f.state.targets = { Targets: [{ Id: 'Issuer', Arn: `${arn}:wrong-alias` }] };
    return { StatusCode: 200, ExecutedVersion: '3' };
  } });
  assert.throws(() => f.run(), /pre-activation failed/);
  assert.ok(!f.calls.some(a => a[1] === 'enable-rule'));
});
test('service-applied enable with response loss is reconciled as enabled but still fails without retry', () => {
  const f = fixture({ 'events enable-rule': () => { throw new Error('synthetic response lost'); } });
  assert.throws(() => f.run(), /activation failed; observed schedule enabled, identity verified/);
  assert.equal(f.state.rule.State, 'ENABLED');
  assert.equal(f.calls.filter(a => a[1] === 'enable-rule').length, 1);
  assert.equal(f.calls.filter(a => a[1] === 'disable-rule').length, 1);
});
test('unreadable activation outcome stays unknown and never retries a mutation', () => {
  let activated = false;
  const f = fixture({ 'events enable-rule': () => { activated = true; throw new Error('synthetic response lost'); },
    'events describe-rule': () => {
      if (activated) throw new Error('synthetic read failure');
      return { Arn: `arn:aws:events:${DESTINATION.region}:${DESTINATION.account}:rule/${DESTINATION.name}`,
        State: 'DISABLED', ScheduleExpression: 'rate(1 minute)' };
    } });
  assert.throws(() => f.run(true), /activation failed; observed schedule unknown/);
  assert.equal(f.calls.filter(a => a[1] === 'enable-rule').length, 1);
});
test('post-enable target or active configuration drift fails with observed enabled state', () => {
  for (const mutate of [(f: ReturnType<typeof fixture>) => { f.state.config.Handler = 'missing.handler'; },
    (f: ReturnType<typeof fixture>) => { f.state.targets = { Targets: [{ Id: 'Issuer', Arn: `${arn}:changed` }] }; }]) {
    let f: ReturnType<typeof fixture>;
    f = fixture({ 'events enable-rule': () => { mutate(f); return {}; } });
    assert.throws(() => f.run(), /activation failed; observed schedule enabled, identity unverified/);
    assert.equal(f.calls.filter(a => a[1] === 'enable-rule').length, 1);
  }
});
test('pause response loss reconciles observed disabled state without uploading or retrying', () => {
  const f = fixture({ 'events disable-rule': () => { throw new Error('synthetic pause response lost'); } });
  assert.throws(() => f.run(), /pause failed; observed schedule disabled/);
  assert.equal(f.calls.filter(a => a[1] === 'disable-rule').length, 1);
  assert.ok(!f.calls.some(a => a[1] === 'update-function-code' || a[1] === 'enable-rule'));
});
test('another writer enabling the schedule during health fails before an enable request', () => {
  let f: ReturnType<typeof fixture>;
  f = fixture({ 'lambda invoke': () => {
    f.state.rule.State = 'ENABLED';
    return { StatusCode: 200, ExecutedVersion: '3' };
  } });
  assert.throws(() => f.run(), /pre-activation failed; observed schedule enabled/);
  assert.ok(!f.calls.some(a => a[1] === 'enable-rule'));
});
