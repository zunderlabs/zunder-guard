import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFile} from 'node:fs/promises';
import {generateKeyPairSync,sign,createPublicKey} from 'node:crypto';
import {canonical} from '../protocol.mjs';
import {controllerSigningBytes,digest,readAppliedScope} from '../relay-schema.mjs';
import {OriginalPublicController} from '../controller.mjs';
import {TargetClient} from '../target-client.mjs';
import {handlePublicReboot} from '../relay-worker.mjs';
// Ephemeral mathematical fixture keys only, held in this inert process. They
// have no native store, provider enrollment, venue or business authority.
const controller=generateKeyPairSync('ed25519'),observer=generateKeyPairSync('ed25519'),jwtKeys=generateKeyPairSync('rsa',{modulusLength:2048});
const publicHex=key=>createPublicKey(key).export({type:'spki',format:'der'}).subarray(-32).toString('hex');
const source='a'.repeat(40),originUrl='https://reboot-fixture.invalid';
const binding={run_id:123,attempt:1,source,target_job_id:456,label:'macos-15',session:'b'.repeat(64),helper_sha256:'c'.repeat(64),inventory_sha256:'d'.repeat(64)};
const start=Date.now(),origin={wall_ms:start,observe_until_ms:start+720000,cleanup_until_ms:start+900000};
const scope={schema:1,kind:'applied-public-reboot-relay-scope',origin:originUrl,deployment_sha256:'e'.repeat(64),source,workflow_ref:'zunderlabs/zunder-guard/.github/workflows/public-reboot.yml@refs/heads/main',repository_id:'1409357189',owner_id:'338317604',audience:'zunder-public-reboot',expires_ms:start+1000000,enabled:true};
function token(role){const header={alg:'RS256',typ:'JWT',kid:'fixture'};const claims={iss:'https://token.actions.githubusercontent.com',aud:scope.audience,exp:Math.floor(start/1000)+300,nbf:Math.floor(start/1000)-10,iat:Math.floor(start/1000),repository:'zunderlabs/zunder-guard',repository_id:scope.repository_id,repository_owner_id:scope.owner_id,sha:source,run_id:'123',run_attempt:'1',ref:'refs/heads/main',environment:'release-public-reboot',runner_environment:'github-hosted',workflow_ref:scope.workflow_ref,job_workflow_ref:`zunderlabs/zunder-guard/.github/workflows/public-reboot-${role}.yml@refs/heads/main`,job_workflow_sha:source};const encoded=[header,claims].map(value=>Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');return encoded+'.'+sign('RSA-SHA256',Buffer.from(encoded),jwtKeys.privateKey).toString('base64url');}
function request(operation,version,sequence,extra={}){const value={schema:1,kind:'public-reboot-relay-request',operation,binding,origin,expected_version:version,expected_sequence:sequence,nonce:null,observer_public_key:null,event:null,signature:null,jwt:null,controller_public_key:null,controller_signature:null,...extra};if(operation==='enroll-controller'||operation==='challenge'){value.controller_public_key=publicHex(controller.privateKey);value.controller_signature=sign(null,controllerSigningBytes(value),controller.privateKey).toString('hex');}return value;}
async function environment(){const sqlite=new DatabaseSync(':memory:');sqlite.exec(await readFile(new URL('../relay-schema.sql',import.meta.url),'utf8'));const DB={withSession(mode){assert.equal(mode,'first-primary');return {prepare(sql){return {bind(...args){return {async all(){return {success:true,results:sqlite.prepare(sql).all(...args)}}}},async all(){return {success:true,results:sqlite.prepare(sql).all()}}}}}}};return {env:{DB,PUBLIC_REBOOT_SCOPE:canonical(scope)},sqlite};}
async function withFakeGithub(body){const prior=globalThis.fetch;globalThis.fetch=async url=>{if(url==='https://token.actions.githubusercontent.com/.well-known/jwks')return Response.json({keys:[{...jwtKeys.publicKey.export({format:'jwk'}),kid:'fixture',alg:'RS256',use:'sig'}]});assert.equal(url,'https://api.github.com/repos/zunderlabs/zunder-guard/actions/runs/123/attempts/1/jobs?per_page=100');return Response.json({total_count:1,jobs:[{id:456,run_id:123,head_sha:source,status:'in_progress',name:'target / target-reboot',labels:['macos-15'],runner_name:'INERT-FIXTURE'}]});};try{return await body();}finally{globalThis.fetch=prior;}}
async function send(env,value){return handlePublicReboot(new Request(originUrl+'/api/waitlist/ci-reboot/'+value.operation,{method:'POST',headers:{'content-type':'application/json'},body:canonical(value)}),env);}
async function setup(env){assert.equal((await send(env,request('enroll-controller',0,0,{jwt:token('controller')}))).status,200);assert.equal((await send(env,request('enroll-target',1,0,{jwt:token('target'),observer_public_key:publicHex(observer.privateKey)}))).status,200);}
test('actual SQL unique insertion refuses duplicate enrollment and preserves original cutoffs',async()=>withFakeGithub(async()=>{const {env,sqlite}=await environment();try{const enrolled=request('enroll-controller',0,0,{jwt:token('controller')});assert.equal((await send(env,enrolled)).status,200);assert.equal((await send(env,enrolled)).status,409);assert.equal(sqlite.prepare('SELECT COUNT(*) AS n FROM ci_reboot_sessions').get().n,1);assert.equal(sqlite.prepare('SELECT origin_json FROM ci_reboot_sessions').get().origin_json,canonical(origin));}finally{sqlite.close();}}));
test('controller challenge requires original enrolled signature and one CAS version',async()=>withFakeGithub(async()=>{const {env,sqlite}=await environment();try{await setup(env);const challenge=request('challenge',2,0,{nonce:'1'.repeat(64)});assert.equal((await send(env,{...challenge,controller_signature:'0'.repeat(128)})).status,409);assert.equal((await send(env,challenge)).status,200);assert.equal((await send(env,challenge)).status,409);assert.equal(sqlite.prepare('SELECT version FROM ci_reboot_sessions').get().version,3);}finally{sqlite.close();}}));
test('modeled four-phase signature/CAS lifecycle never becomes actual OS evidence',async()=>withFakeGithub(async()=>{const {env,sqlite}=await environment();try{await setup(env);let version=2;for(let sequence=0;sequence<4;sequence++){const phase=['PREBOOT','ARMED','POSTBOOT','CLEANUP'][sequence],nonce=String(sequence+1).repeat(64);assert.equal((await send(env,request('challenge',version,sequence,{nonce}))).status,200);version++;const event={schema:1,kind:'public-host-reboot-observation',phase,sequence,nonce,binding,machine_sha256:'2'.repeat(64),marker_sha256:'3'.repeat(64),boot_id:sequence<2?'FIXTURE-PRE':'FIXTURE-POST',boot_time_ms:sequence<2?100000:200000,uptime_ms:1000,observer_pid:sequence<2?100:200,observer_birth:sequence<2?'100:1':'200:2',cleanup:{registration_absent:sequence===3,files_absent:sequence===3,key_store_absent:sequence===3,observer_child_gone:sequence===3,carrier_exit_observed:false}};const signature=sign(null,Buffer.from(canonical(event)),observer.privateKey).toString('hex'),submitted=request('event',version,sequence,{nonce,event,signature});assert.equal((await send(env,{...submitted,signature:'0'.repeat(128)})).status,409);const response=await send(env,submitted);assert.equal(response.status,200);const ack=await response.json();assert.equal(ack.request_sha256,await digest(canonical(submitted)));assert.equal(ack.sequence,sequence+1);assert.equal((await send(env,submitted)).status,409);version++;}assert.equal(sqlite.prepare('SELECT sequence FROM ci_reboot_sessions').get().sequence,4);}finally{sqlite.close();}}));
test('wrong nonce is refused before CAS',async()=>withFakeGithub(async()=>{const {env,sqlite}=await environment();try{await setup(env);assert.equal((await send(env,request('challenge',2,0,{nonce:'1'.repeat(64)}))).status,200);const event={schema:1,kind:'public-host-reboot-observation',phase:'PREBOOT',sequence:0,nonce:'9'.repeat(64),binding,machine_sha256:'2'.repeat(64),marker_sha256:'3'.repeat(64),boot_id:'FIXTURE',boot_time_ms:100000,uptime_ms:1000,observer_pid:100,observer_birth:'100:1',cleanup:{registration_absent:false,files_absent:false,key_store_absent:false,observer_child_gone:false,carrier_exit_observed:false}};const signature=sign(null,Buffer.from(canonical(event)),observer.privateKey).toString('hex');assert.equal((await send(env,request('event',3,0,{nonce:event.nonce,event,signature}))).status,409);assert.equal(sqlite.prepare('SELECT version FROM ci_reboot_sessions').get().version,3);}finally{sqlite.close();}}));
test('missing applied scope refuses every route without DB access',async()=>{const response=await handlePublicReboot(new Request(originUrl+'/api/waitlist/ci-reboot/scope'),{DB:{withSession(){throw new Error('DB must remain unused')}}});assert.equal(response.status,409);});

function modeledEvent(sequence,nonce){return {schema:1,kind:'public-host-reboot-observation',phase:['PREBOOT','ARMED','POSTBOOT','CLEANUP'][sequence],sequence,nonce,binding,machine_sha256:'2'.repeat(64),marker_sha256:'3'.repeat(64),boot_id:sequence<2?'FIXTURE-PRE':'FIXTURE-POST',boot_time_ms:sequence<2?100000:200000,uptime_ms:1000,observer_pid:sequence<2?100:200,observer_birth:sequence<2?'100:1':'200:2',cleanup:{registration_absent:sequence===3,files_absent:sequence===3,key_store_absent:sequence===3,observer_child_gone:sequence===3,carrier_exit_observed:false}};}
async function clientFixture(env,changeResponse=async response=>response) {
  const expected=Object.fromEntries(['origin','deployment_sha256','source','workflow_ref','repository_id','owner_id','audience'].map(key=>[key,scope[key]]));
  const admitted=await readAppliedScope(expected,{fetchImpl:async url=>handlePublicReboot(new Request(url),env)});
  const fetchImpl=async(url,options)=>changeResponse(await handlePublicReboot(new Request(url,options),env),JSON.parse(options.body));
  const journal={append:async()=>{},hold:async()=>{}};
  const original=new OriginalPublicController({scope:admitted,binding,journal,fetchImpl});
  await original.enrollController(token('controller'));
  const target=new TargetClient(admitted,original.publicPlan(),{version:1,sequence:0,fetchImpl});
  await target.enroll(token('target'),publicHex(observer.privateKey));await original.observeEnrollment();
  return {original,target};
}
test('real client to SQL relay completes successive challenges and four modeled phases',async()=>withFakeGithub(async()=>{
  const {env,sqlite}=await environment();try{
    const {original,target}=await clientFixture(env);
    for(let sequence=0;sequence<4;sequence++){
      await original.challenge();const challenge=await target.waitChallenge();
      assert.equal(challenge.sequence,sequence);assert.equal(challenge.version,3+2*sequence);
      if(sequence>0){assert.equal(challenge.state,['PREBOOT','ARMED','POSTBOOT'][sequence-1]);assert.equal(challenge.event.sequence,sequence-1);assert.notEqual(challenge.nonce,challenge.event.nonce);}
      const event=modeledEvent(sequence,challenge.nonce),signature=sign(null,Buffer.from(canonical(event)),observer.privateKey).toString('hex');
      await target.sendEvent({event,signature});await original.poll();
      assert.equal(original.report().observed_sequence,sequence+1);assert.equal(original.report().held,false);
    }
    assert.equal(target.state.sequence,4);assert.equal(original.report().release_ready,false);assert.equal(original.report().native_credential_retention_proven,false);
  }finally{sqlite.close();}
}));
test('second real-client challenge with malformed prior phase holds without adopting or retrying',async()=>withFakeGithub(async()=>{
  const {env,sqlite}=await environment();try{
    let reads=0,tamper=false;
    const {original,target}=await clientFixture(env,async(response,request)=>{
      if(tamper&&request.operation==='readback'&&request.expected_sequence===1){reads++;const ack=await response.json();return new Response(canonical({...ack,state:'ARMED'}),{headers:{'content-type':'application/json'}});}
      return response;
    });
    await original.challenge();const challenge=await target.waitChallenge();const event=modeledEvent(0,challenge.nonce);
    await target.sendEvent({event,signature:sign(null,Buffer.from(canonical(event)),observer.privateKey).toString('hex')});await original.poll();
    assert.deepEqual(target.state,{version:4,sequence:1});await original.challenge();tamper=true;
    await assert.rejects(target.waitChallenge(),/HOLD/);await assert.rejects(target.waitChallenge(),/admission refused/);assert.equal(reads,1);assert.deepEqual(target.state,{version:4,sequence:1});
  }finally{sqlite.close();}
}));
