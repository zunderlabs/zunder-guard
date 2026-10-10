import {canonical, validateBinding, validateEvent, verifyEd25519} from './protocol.mjs';

export function requireTrue(value) { if (!value) throw new Error('Public reboot admission refused'); }
export function exact(value, keys) {
  requireTrue(value && Object.getPrototypeOf(value) === Object.prototype);
  requireTrue(Object.keys(value).sort().join('\0') === [...keys].sort().join('\0'));
}
export const hex = (value, length = 64) => typeof value === 'string' && new RegExp(`^[0-9a-f]{${length}}$`).test(value);
export const number = value => Number.isSafeInteger(value) && value >= 0;
export const phases = ['PREBOOT', 'ARMED', 'POSTBOOT', 'CLEANUP'];
export function bytes(value, length) {
  requireTrue(hex(value, length * 2));
  return Uint8Array.from(value.match(/../g), value => parseInt(value, 16));
}
export async function digest(value) {
  const raw = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', raw)), b => b.toString(16).padStart(2, '0')).join('');
}
const scopes = new WeakSet();
// The release pipeline pins the actual deployment/source after independent provider readback.
// This sealed token is minted only after a fixed HTTPS read; caller JSON cannot
// enable dispatch. The server separately authenticates enrollment with OIDC.
export async function readAppliedScope(expected, {fetchImpl=fetch, now=Date.now}={}) {
  exact(expected, ['origin','deployment_sha256','source','workflow_ref','repository_id','owner_id','audience']);
  expected = JSON.parse(canonical(expected));
  const url = new URL(expected.origin);
  requireTrue(url.protocol === 'https:' && url.username === '' && url.password === '' && url.pathname === '/' && url.search === '' && url.hash === '');
  requireTrue(expected.repository_id === '1409357189' && expected.owner_id === '338317604' && hex(expected.source,40) && hex(expected.deployment_sha256));
  const response = await fetchImpl(url.origin+'/api/waitlist/ci-reboot/scope',{redirect:'error',cache:'no-store',credentials:'omit',signal:AbortSignal.timeout(5000)});
  requireTrue(response.status === 200 && response.headers.get('content-type')?.split(';')[0] === 'application/json');
  const raw = await response.arrayBuffer(); requireTrue(raw.byteLength <= 4096);
  const text = new TextDecoder('utf-8',{fatal:true}).decode(raw); const value = JSON.parse(text);
  exact(value, ['schema','kind','origin','deployment_sha256','source','workflow_ref','repository_id','owner_id','audience','expires_ms','enabled']);
  requireTrue(canonical(value) === text && value.schema === 1 && value.kind === 'applied-public-reboot-relay-scope' && value.enabled === true);
  requireTrue(number(value.expires_ms) && now() < value.expires_ms);
  for(const key of Object.keys(expected)) requireTrue(value[key] === expected[key]);
  const admitted = Object.freeze({...value}); scopes.add(admitted); return admitted;
}
export function requireScope(scope) { requireTrue(scopes.has(scope)); }
export function validateOrigin(value) {
  exact(value,['wall_ms','observe_until_ms','cleanup_until_ms']);
  requireTrue(Object.values(value).every(number) && value.wall_ms > 0);
  requireTrue(value.observe_until_ms === value.wall_ms + 720000 && value.cleanup_until_ms === value.wall_ms + 900000);
  return JSON.parse(canonical(value));
}
export function validateRequest(value) {
  exact(value,['schema','kind','operation','binding','origin','expected_version','expected_sequence','nonce','observer_public_key','event','signature','jwt','controller_public_key','controller_signature']);
  requireTrue(value.schema === 1 && value.kind === 'public-reboot-relay-request');
  requireTrue(['enroll-controller','enroll-target','challenge','event','readback'].includes(value.operation));
  validateBinding(value.binding); validateOrigin(value.origin);
  requireTrue(number(value.expected_version) && number(value.expected_sequence) && value.expected_sequence <= 4);
  requireTrue(value.nonce === null || hex(value.nonce));
  requireTrue(value.observer_public_key === null || hex(value.observer_public_key));
  requireTrue(value.controller_public_key === null || hex(value.controller_public_key));
  requireTrue(value.controller_signature === null || hex(value.controller_signature,128));
  requireTrue(value.signature === null || hex(value.signature,128));
  requireTrue(value.jwt === null || (typeof value.jwt === 'string' && /^[A-Za-z0-9_.-]{1,16384}$/.test(value.jwt)));
  if (value.operation.startsWith('enroll-')) {
    requireTrue(value.jwt !== null && value.event === null && value.signature === null && value.nonce === null && value.expected_version === (value.operation === 'enroll-target' ? 1 : 0) && value.expected_sequence === 0);
    requireTrue(value.operation === 'enroll-target' ? value.observer_public_key !== null && value.controller_public_key === null && value.controller_signature === null : value.observer_public_key === null && value.controller_public_key !== null && value.controller_signature !== null);
  } else {
    if(value.operation === 'challenge') requireTrue(value.controller_public_key !== null && value.controller_signature !== null);
    else if(value.operation === 'event') requireTrue(value.controller_public_key === null && value.controller_signature === null);
    else requireTrue((value.controller_public_key === null) === (value.controller_signature === null));
    requireTrue(value.jwt === null && value.observer_public_key === null);
    if (value.operation === 'event') {
      validateEvent(value.event); requireTrue(value.signature !== null && value.nonce === value.event.nonce);
      requireTrue(canonical(value.event.binding) === canonical(value.binding) && value.event.sequence === value.expected_sequence);
    } else requireTrue(value.event === null && value.signature === null);
    requireTrue(value.operation === 'challenge' ? hex(value.nonce) : value.operation === 'readback' ? value.nonce === null : true);
  }
  return JSON.parse(canonical(value));
}
export function validateResponse(value, request, requestDigest) {
  exact(value,['schema','kind','request_sha256','binding','origin','version','sequence','state','nonce','observer_public_key','event','signature','github_enrollment_verified','jobs_identity_verified']);
  requireTrue(value.schema === 1 && value.kind === 'actual-public-reboot-relay-ack' && value.request_sha256 === requestDigest);
  requireTrue(canonical(value.binding) === canonical(request.binding) && canonical(value.origin) === canonical(request.origin));
  requireTrue(number(value.version) && number(value.sequence) && value.sequence <= 4 && ['ENROLLED',...phases,'UNKNOWN'].includes(value.state));
  requireTrue(value.nonce === null || hex(value.nonce));
  requireTrue(value.observer_public_key === null || hex(value.observer_public_key));
  requireTrue(value.github_enrollment_verified === true && value.jobs_identity_verified === true);
  requireTrue(value.event === null ? value.signature === null : hex(value.signature,128));
  if (value.event !== null) validateEvent(value.event);
  const mutation = request.operation !== 'readback';
  requireTrue(mutation ? value.version === request.expected_version + 1 : value.version === request.expected_version || value.version === request.expected_version + 1);
  if (!mutation && value.version === request.expected_version + 1) {
    const advancedEvent = value.sequence === request.expected_sequence + 1 && value.event !== null && value.state === phases[request.expected_sequence];
    const initialEnrollmentOrChallenge = request.expected_sequence === 0 && value.sequence === 0 && value.state === 'ENROLLED' && value.observer_public_key !== null && value.event === null;
    // A controller challenge increments CAS version without changing sequence
    // or replacing the preceding signed event. Target readback must admit this
    // distinct transition before it can send the next observation.
    const pendingChallenge = value.sequence === request.expected_sequence && value.sequence > 0 && value.sequence < 4 && value.observer_public_key !== null && hex(value.nonce) && value.event !== null && value.event.sequence === value.sequence-1 && value.event.phase === phases[value.sequence-1] && value.state === value.event.phase && value.nonce !== value.event.nonce && canonical(value.event.binding) === canonical(request.binding);
    requireTrue(advancedEvent || initialEnrollmentOrChallenge || pendingChallenge);
  }
  if (!mutation && value.version === request.expected_version) requireTrue(value.sequence === request.expected_sequence);
  if (request.operation === 'challenge') requireTrue(value.sequence === request.expected_sequence && value.nonce === request.nonce);
  if (request.operation === 'event') requireTrue(value.sequence === request.expected_sequence + 1 && value.nonce === null && canonical(value.event) === canonical(request.event) && value.signature === request.signature);
  requireTrue(value.state !== 'UNKNOWN');
  return Object.freeze(JSON.parse(canonical(value)));
}

export function controllerSigningBytes(request) { return new TextEncoder().encode(canonical({...request,controller_signature:null})); }
