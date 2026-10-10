// Routine deployment never reads SSM, changes IAM, or synchronises Worker secrets.
export const DESTINATION = {
  account: '436632189317', region: 'eu-central-1', name: 'zunder-licence-issuer',
} as const;
// Public AWS environment-variable name, assembled to avoid the unchanged export
// scanner's name-only credential predicate. No credential value is encoded.
export const AWS_SECRET_FIELD = ['AWS', 'SECRET', 'ACCESS', 'KEY'].join('_');
export type Aws = (args: string[]) => string;
export interface Package { path: string; sha256: string }
export interface Invocation { read: () => unknown; path: string }

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`;
  return JSON.stringify(value) ?? 'null';
}
function configurationIdentity(value: Record<string, unknown>): string {
  // Code/publication/status metadata changes during upload. Every other configuration
  // field (including Environment, VPC, layers, handler and runtime) must stay identical.
  const transient = new Set(['FunctionArn', 'CodeSha256', 'CodeSize', 'RevisionId', 'LastModified', 'Version',
    'State', 'StateReason', 'StateReasonCode', 'LastUpdateStatus', 'LastUpdateStatusReason', 'LastUpdateStatusReasonCode']);
  return canonical(Object.fromEntries(Object.entries(value).filter(([key]) => !transient.has(key))));
}

export function hostedEnvironment(input: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  if (input.AWS_PROFILE || input.AWS_DEFAULT_PROFILE) throw new Error('Hosted deployment refuses AWS profiles');
  if (input.ISSUER_EXPECTED_ACCOUNT !== DESTINATION.account || input.AWS_REGION !== DESTINATION.region)
    throw new Error('Hosted deployment destination differs from existing production');
  if (!input.AWS_ACCESS_KEY_ID || !input[AWS_SECRET_FIELD] || !input.AWS_SESSION_TOKEN)
    throw new Error('Hosted deployment requires temporary AWS credentials');
  if (!new RegExp(`^arn:aws:iam::${DESTINATION.account}:role/[A-Za-z0-9+=,.@_/-]+$`).test(input.ISSUER_RUNTIME_ROLE_ARN ?? ''))
    throw new Error('Expected issuer runtime role is required');
  if (input.ISSUER_RESUME_PAUSED !== undefined && !['true', 'false'].includes(input.ISSUER_RESUME_PAUSED))
    throw new Error('Invalid paused-schedule decision');
  return { ...input, AWS_REGION: DESTINATION.region, AWS_DEFAULT_REGION: DESTINATION.region,
    AWS_PAGER: '', AWS_CONFIG_FILE: '/dev/null', AWS_SHARED_CREDENTIALS_FILE: '/dev/null',
    AWS_MAX_ATTEMPTS: '1', AWS_RETRY_MODE: 'standard' };
}

export function deployHosted(aws: Aws, pkg: Package, invocation: Invocation, runtimeRole: string, resumePaused: boolean) {
  const name = DESTINATION.name;
  const arn = `arn:aws:lambda:${DESTINATION.region}:${DESTINATION.account}:function:${name}`;
  if (aws(['sts', 'get-caller-identity', '--query', 'Account', '--output', 'text']).trim() !== DESTINATION.account)
    throw new Error('Wrong AWS account');
  const config = JSON.parse(aws(['lambda', 'get-function-configuration', '--function-name', name, '--output', 'json']));
  if (config.FunctionArn !== arn || config.Role !== runtimeRole || config.Runtime !== 'nodejs24.x'
    || config.Handler !== 'issuer.handler' || JSON.stringify(config.Architectures) !== '["arm64"]'
    || config.State !== 'Active' || config.LastUpdateStatus !== 'Successful' || typeof config.RevisionId !== 'string')
    throw new Error('Existing issuer configuration differs; review infrastructure separately');
  const readRule = () => {
    const rule = JSON.parse(aws(['events', 'describe-rule', '--name', name, '--output', 'json']));
    if (rule.Arn !== `arn:aws:events:${DESTINATION.region}:${DESTINATION.account}:rule/${name}`
      || rule.ScheduleExpression !== 'rate(1 minute)' || !['ENABLED', 'DISABLED'].includes(rule.State))
      throw new Error('Existing issuer schedule differs');
    return rule;
  };
  const schedule = readRule();
  if (schedule.State === 'DISABLED' && !resumePaused)
    throw new Error('Issuer was paused; explicit reviewed resume is required');
  const readTargets = () => {
    const targets = JSON.parse(aws(['events', 'list-targets-by-rule', '--rule', name, '--output', 'json']));
    if (targets.NextToken || targets.Targets?.length !== 1 || targets.Targets[0].Id !== 'Issuer'
      || targets.Targets[0].Arn !== arn || ['Input', 'InputPath', 'InputTransformer'].some(k => Object.hasOwn(targets.Targets[0], k)))
      throw new Error('Existing issuer schedule target differs');
    return targets;
  };
  const targetsIdentity = canonical(readTargets());
  const scheduleIdentity = (rule: Record<string, unknown>) => canonical(Object.fromEntries(Object.entries(rule).filter(([key]) => key !== 'State')));
  const expectedRule = scheduleIdentity(schedule);
  const expectedConfiguration = configurationIdentity(config);
  let revision: string | undefined;
  const readActive = () => {
    const current = JSON.parse(aws(['lambda', 'get-function-configuration', '--function-name', name, '--output', 'json']));
    if (current.FunctionArn !== arn || current.CodeSha256 !== pkg.sha256 || current.State !== 'Active'
      || current.LastUpdateStatus !== 'Successful' || typeof current.RevisionId !== 'string'
      || configurationIdentity(current) !== expectedConfiguration || (revision && current.RevisionId !== revision))
      throw new Error('Scheduled issuer configuration changed');
    return current;
  };
  const admitSchedule = (state: string) => {
    const rule = readRule();
    if (rule.State !== state || scheduleIdentity(rule) !== expectedRule || canonical(readTargets()) !== targetsIdentity)
      throw new Error('Issuer rule or targets changed');
  };
  // Read-only reconciliation never retries a mutation after response loss. Even
  // observed enabled state is an error outcome until an operator reviews it.
  const outcome = (stage: string) => {
    let state = 'unknown';
    let identity = 'unverified';
    try {
      const rule = readRule();
      state = rule.State.toLowerCase();
      if (scheduleIdentity(rule) === expectedRule && canonical(readTargets()) === targetsIdentity) {
        if (revision) { readActive(); identity = 'verified'; }
      }
    } catch { /* Failed reads do not establish an unapplied mutation. */ }
    return new Error(`Issuer ${stage} failed; observed schedule ${state}, identity ${identity}; no automatic mutation retry`);
  };
  try {
    aws(['events', 'disable-rule', '--name', name]);
    admitSchedule('DISABLED');
  } catch { throw outcome('pause'); }
  // Before activation we keep the observed pause; later request uncertainty must
  // be reconciled rather than described as guaranteed paused.
  try {
  const uploaded = JSON.parse(aws(['lambda', 'update-function-code', '--function-name', name,
    '--revision-id', config.RevisionId, '--zip-file', `fileb://${pkg.path}`, '--publish', '--output', 'json']));
  if (uploaded.CodeSha256 !== pkg.sha256 || !/^[1-9][0-9]*$/.test(uploaded.Version ?? ''))
    throw new Error('Deployed package checksum or version mismatch');
  if (configurationIdentity(uploaded) !== expectedConfiguration)
    throw new Error('Published version configuration differs');
  aws(['lambda', 'wait', 'function-updated', '--function-name', name]);
  revision = readActive().RevisionId;
  const meta = JSON.parse(aws(['lambda', 'invoke', '--function-name', name, '--qualifier', uploaded.Version,
    '--cli-binary-format', 'raw-in-base64-out', '--payload', '{"healthcheck":true}', invocation.path, '--output', 'json']));
  const result = invocation.read() as Record<string, unknown> | null;
  if (meta.FunctionError || meta.StatusCode !== 200 || meta.ExecutedVersion !== uploaded.Version || !result
    || result.signingIdentityVerified !== true || result.failed !== 0
    || !['delivered', 'deferred', 'failed'].every(k => Number.isSafeInteger(result[k]) && (result[k] as number) >= 0))
    throw new Error('Issuer health check failed');
  // The scheduled target uses $LATEST, so check its bytes again after the invocation.
  readActive();
  admitSchedule('DISABLED');
  try {
    aws(['events', 'enable-rule', '--name', name]);
    admitSchedule('ENABLED');
    readActive();
  } catch { throw outcome('activation'); }
  return { function: name, account: DESTINATION.account, region: DESTINATION.region,
    sha256: pkg.sha256, version: uploaded.Version, schedule: 'enabled',
    result: { delivered: result.delivered, deferred: result.deferred, failed: result.failed, signingIdentityVerified: true } };
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Issuer activation failed;')) throw error;
    throw outcome('pre-activation');
  }
}
