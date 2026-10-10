import {canonical,validateEvent,verifyEvent,verifyEd25519,evaluateModeledSequence} from './protocol.mjs';
import {exact,requireTrue,hex,number,bytes,digest,validateRequest,controllerSigningBytes} from './relay-schema.mjs';
import {verifyGithubEnrollment} from './github-enrollment.mjs';

const prefix = '/api/waitlist/ci-reboot/';
function response(value,status=200) { return new Response(canonical(value),{status,headers:{'content-type':'application/json','cache-control':'no-store'}}); }
async function boundedJSON(request) {
  const reader = request.body?.getReader(); requireTrue(reader !== undefined); const parts=[]; let size=0;
  try { while(true) { const part=await reader.read(); if(part.done) break; size+=part.value.length; requireTrue(size<=32768); parts.push(part.value); } }
  catch(error) { await reader.cancel(); throw error; }
  const raw=new Uint8Array(size); let offset=0; for(const part of parts){raw.set(part,offset);offset+=part.length;}
  const text=new TextDecoder('utf-8',{fatal:true}).decode(raw), value=JSON.parse(text); requireTrue(canonical(value)===text); return value;
}
function configuration(env) {
  requireTrue(typeof env.PUBLIC_REBOOT_SCOPE === 'string'); const scope=JSON.parse(env.PUBLIC_REBOOT_SCOPE);
  exact(scope,['schema','kind','origin','deployment_sha256','source','workflow_ref','repository_id','owner_id','audience','expires_ms','enabled']);
  requireTrue(scope.schema===1 && scope.kind==='applied-public-reboot-relay-scope' && scope.enabled===true);
  requireTrue(scope.repository_id==='1409357189' && scope.owner_id==='338317604' && hex(scope.source,40) && hex(scope.deployment_sha256) && number(scope.expires_ms) && Date.now()<scope.expires_ms);
  requireTrue(new URL(scope.origin).origin===scope.origin.replace(/\/$/,'') && new URL(scope.origin).protocol==='https:');
  const repository='zunderlabs/zunder-guard';
  requireTrue(scope.workflow_ref===`${repository}/.github/workflows/public-reboot.yml@refs/heads/main` && scope.audience==='zunder-public-reboot');
  return {scope,github:{repository,repository_id:scope.repository_id,owner_id:scope.owner_id,workflow_ref:scope.workflow_ref,
    controller_workflow_ref:`${repository}/.github/workflows/public-reboot-controller.yml@refs/heads/main`,
    target_workflow_ref:`${repository}/.github/workflows/public-reboot-target.yml@refs/heads/main`,
    audience:scope.audience,environment:'release-public-reboot',target_job_name:'target / target-reboot'}};
}
async function one(statement) { const result=await statement.all(); requireTrue(result.success===true && result.results.length===1); return result.results[0]; }
function same(row,request) { requireTrue(row.binding_json===canonical(request.binding) && row.origin_json===canonical(request.origin)); }
function live(origin,sequence) { const now=Date.now(); requireTrue(now>=origin.wall_ms-10000 && now<(sequence>=3?origin.cleanup_until_ms:origin.observe_until_ms)); }
function ack(row,request,hash) {
  const events=JSON.parse(row.events_json),signatures=JSON.parse(row.signatures_json);
  return {schema:1,kind:'actual-public-reboot-relay-ack',request_sha256:hash,binding:request.binding,origin:request.origin,
    version:row.version,sequence:row.sequence,state:row.state,nonce:row.nonce,observer_public_key:row.observer_public_key,
    event:events.at(-1)??null,signature:signatures.at(-1)??null,github_enrollment_verified:true,jobs_identity_verified:true};
}
// Integrate this handler before the existing customer routes. It touches
// only the new public table and ignores customer/email/licence bindings.
export async function handlePublicReboot(request,env) {
  const url=new URL(request.url); if(!url.pathname.startsWith(prefix)) return null;
  try {
    const {scope,github}=configuration(env); requireTrue(url.origin===new URL(scope.origin).origin && url.search==='');
    if(url.pathname===prefix+'scope') { requireTrue(request.method==='GET'); return response(scope); }
    if(url.pathname===prefix+'bootstrap') {
      requireTrue(request.method==='GET');const row=await one(env.DB.withSession('first-primary').prepare('SELECT * FROM ci_reboot_sessions WHERE singleton=1'));
      const binding=JSON.parse(row.binding_json),origin=JSON.parse(row.origin_json);requireTrue(binding.source===scope.source);live(origin,row.sequence);
      return response({schema:1,kind:'actual-original-public-reboot-bootstrap',binding,origin,version:row.version,sequence:row.sequence,github_enrollment_verified:true,jobs_identity_verified:true});
    }
    requireTrue(request.method==='POST' && request.headers.get('content-type')==='application/json');
    const value=validateRequest(await boundedJSON(request)); requireTrue(url.pathname===prefix+value.operation && value.binding.source===scope.source);
    const hash=await digest(canonical(value)); live(value.origin,value.expected_sequence);
    const db=env.DB.withSession('first-primary'); let row;
    if(value.operation==='enroll-controller') {
      requireTrue(Date.now()-value.origin.wall_ms<=60000);
      await verifyGithubEnrollment(value.jwt,value,github);
      requireTrue(await verifyEd25519(controllerSigningBytes(value),bytes(value.controller_signature,64),bytes(value.controller_public_key,32)));
      row=await one(db.prepare('INSERT INTO ci_reboot_sessions(session,singleton,binding_json,origin_json,controller_public_key,observer_public_key,version,sequence,state,nonce,events_json,signatures_json) VALUES(?,1,?,?,?,NULL,1,0,\'ENROLLED\',NULL,\'[]\',\'[]\') RETURNING *').bind(value.binding.session,canonical(value.binding),canonical(value.origin),value.controller_public_key));
    } else {
      row=await one(db.prepare('SELECT * FROM ci_reboot_sessions WHERE session=?').bind(value.binding.session)); same(row,value);
      if(value.operation==='enroll-target') {
        await verifyGithubEnrollment(value.jwt,value,github);
        row=await one(db.prepare('UPDATE ci_reboot_sessions SET observer_public_key=?,version=version+1 WHERE session=? AND binding_json=? AND origin_json=? AND version=1 AND sequence=0 AND state=\'ENROLLED\' AND observer_public_key IS NULL AND nonce IS NULL RETURNING *').bind(value.observer_public_key,value.binding.session,row.binding_json,row.origin_json));
      } else if(value.operation==='readback') {
        // Public read only. It can neither mint a nonce nor alter a phase.
        requireTrue(value.expected_version===row.version || value.expected_version+1===row.version);
      } else {
        requireTrue(row.version===value.expected_version && row.sequence===value.expected_sequence && row.sequence<4 && row.observer_public_key!==null);
        if(value.operation==='challenge') {
          requireTrue(row.nonce===null && value.controller_public_key===row.controller_public_key && !JSON.parse(row.events_json).some(event=>event.nonce===value.nonce));
          requireTrue(await verifyEd25519(controllerSigningBytes(value),bytes(value.controller_signature,64),bytes(row.controller_public_key,32)));
          row=await one(db.prepare('UPDATE ci_reboot_sessions SET nonce=?,version=version+1 WHERE session=? AND binding_json=? AND origin_json=? AND version=? AND sequence=? AND state=? AND nonce IS NULL AND observer_public_key=? RETURNING *').bind(value.nonce,value.binding.session,row.binding_json,row.origin_json,row.version,row.sequence,row.state,row.observer_public_key));
        } else {
          requireTrue(value.operation==='event' && row.nonce===value.nonce);
          // Cryptographic verification precedes the pure transition predicate.
          await verifyEvent(new TextEncoder().encode(canonical(value.event)),bytes(value.signature,64),bytes(row.observer_public_key,32));
          const prior=JSON.parse(row.events_json), signatures=JSON.parse(row.signatures_json); validateEvent(value.event);
          evaluateModeledSequence([...prior,value.event],value.binding,[...prior.map(e=>e.nonce),value.nonce]);
          prior.push(value.event);signatures.push(value.signature);
          row=await one(db.prepare('UPDATE ci_reboot_sessions SET events_json=?,signatures_json=?,state=?,sequence=sequence+1,version=version+1,nonce=NULL WHERE session=? AND binding_json=? AND origin_json=? AND version=? AND sequence=? AND state=? AND nonce=? AND observer_public_key=? RETURNING *').bind(canonical(prior),canonical(signatures),value.event.phase,value.binding.session,row.binding_json,row.origin_json,row.version,row.sequence,row.state,row.nonce,row.observer_public_key));
        }
      }
    }
    same(row,value); live(value.origin,row.sequence); return response(ack(row,value,hash));
  } catch { return response({schema:1,kind:'public-reboot-relay-refused'},409); }
}
