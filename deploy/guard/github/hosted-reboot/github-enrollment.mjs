import {exact, requireTrue, number, validateRequest} from './relay-schema.mjs';

import {canonical} from './protocol.mjs';

const issuer = 'https://token.actions.githubusercontent.com';
function decode(value) {
  requireTrue(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value));
  const raw = Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0));
  requireTrue(raw.length <= 16384); return raw;
}
async function jsonGet(fetchImpl,url,headers={}) {
  const response = await fetchImpl(url,{headers,redirect:'error',cache:'no-store',signal:AbortSignal.timeout(5000)});
  requireTrue(response.status === 200); const raw = await response.arrayBuffer(); requireTrue(raw.byteLength <= 131072);
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
}
export async function verifyGithubEnrollment(jwt, request, configuration, {fetchImpl=fetch, now=Date.now}={}) {
  exact(configuration,['repository','repository_id','owner_id','workflow_ref','controller_workflow_ref','target_workflow_ref','audience','environment','target_job_name']);
  configuration = JSON.parse(canonical(configuration)); request = validateRequest(request);
  requireTrue(configuration.repository === 'zunderlabs/zunder-guard' && configuration.repository_id === '1409357189' && configuration.owner_id === '338317604');
  requireTrue(configuration.controller_workflow_ref !== configuration.target_workflow_ref);
  const parts = jwt.split('.'); requireTrue(parts.length === 3);
  const header = JSON.parse(new TextDecoder().decode(decode(parts[0])));
  exact(header,['alg','kid','typ']); requireTrue(header.alg === 'RS256' && header.typ === 'JWT' && typeof header.kid === 'string');
  const keys = await jsonGet(fetchImpl,issuer+'/.well-known/jwks');
  requireTrue(Array.isArray(keys.keys) && keys.keys.length <= 20);
  const found = keys.keys.filter(key=>key.kid === header.kid && key.kty === 'RSA' && key.alg === 'RS256' && key.use === 'sig');
  requireTrue(found.length === 1);
  const key = await crypto.subtle.importKey('jwk',found[0],{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
  requireTrue(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,decode(parts[2]),new TextEncoder().encode(parts[0]+'.'+parts[1])));
  const claims = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(decode(parts[1])));
  const time = now(); requireTrue(number(time) && number(claims.exp) && number(claims.nbf) && number(claims.iat));
  requireTrue(claims.iss === issuer && claims.aud === configuration.audience && time < claims.exp*1000 && time >= claims.nbf*1000 && claims.iat*1000 <= time && time-claims.iat*1000 <= 300000);
  requireTrue(claims.repository === configuration.repository && claims.repository_id === configuration.repository_id && claims.repository_owner_id === configuration.owner_id);
  requireTrue(claims.sha === request.binding.source && claims.run_id === String(request.binding.run_id) && claims.run_attempt === String(request.binding.attempt));
  requireTrue(claims.ref === 'refs/heads/main' && claims.environment === configuration.environment && claims.runner_environment === 'github-hosted');
  requireTrue(claims.workflow_ref === configuration.workflow_ref);
  const role = request.operation === 'enroll-controller' ? configuration.controller_workflow_ref : configuration.target_workflow_ref;
  requireTrue(claims.job_workflow_ref === role && claims.job_workflow_sha === request.binding.source);
  // Separate pinned reusable workflow roles plus one actual target job prevent
  // an audience-only claim from being treated as proof of a caller-supplied ID.
  const endpoint = `https://api.github.com/repos/${configuration.repository}/actions/runs/${request.binding.run_id}/attempts/${request.binding.attempt}/jobs?per_page=100`;
  const jobs = await jsonGet(fetchImpl,endpoint,{'accept':'application/vnd.github+json','x-github-api-version':'2022-11-28'});
  requireTrue(number(jobs.total_count) && jobs.total_count <= 100 && jobs.jobs.length === jobs.total_count);
  const targets = jobs.jobs.filter(job=>job.name === configuration.target_job_name);
  requireTrue(targets.length === 1); const target = targets[0];
  requireTrue(target.id === request.binding.target_job_id && target.run_id === request.binding.run_id && target.head_sha === request.binding.source && target.status === 'in_progress');
  requireTrue(Array.isArray(target.labels) && target.labels.includes(request.binding.label) && typeof target.runner_name === 'string' && target.runner_name.length > 0);
  return Object.freeze({github_enrollment_verified:true,jobs_identity_verified:true});
}
