import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, chmod, rm, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {validateRequest,validateResponse,validateOrigin,requireScope,readAppliedScope,digest} from '../relay-schema.mjs';
import {consumeAck} from '../relay-client.mjs';
import {OriginalJournal} from '../journal.mjs';
import {canonical} from '../protocol.mjs';
const binding = {run_id:123,attempt:1,source:'a'.repeat(40),target_job_id:456,label:'macos-15',session:'b'.repeat(64),helper_sha256:'c'.repeat(64),inventory_sha256:'d'.repeat(64)};
const origin = {wall_ms:1000,observe_until_ms:721000,cleanup_until_ms:901000};
function request(operation='challenge') { return {schema:1,kind:'public-reboot-relay-request',operation,binding,origin,expected_version:2,expected_sequence:0,nonce:'e'.repeat(64),observer_public_key:null,event:null,signature:null,jwt:null,controller_public_key:'2'.repeat(64),controller_signature:'3'.repeat(128)}; }
function ack(r=request()) { return {schema:1,kind:'actual-public-reboot-relay-ack',request_sha256:'f'.repeat(64),binding,origin,version:r.expected_version+1,sequence:0,state:'ENROLLED',nonce:r.nonce,observer_public_key:'1'.repeat(64),event:null,signature:null,github_enrollment_verified:true,jobs_identity_verified:true}; }
test('closed request grammar accepts only fixed challenge operation',()=>assert.deepEqual(validateRequest(request()),request()));
test('request refuses arbitrary endpoint and added property',()=>{assert.throws(()=>validateRequest({...request(),operation:'restart'}));assert.throws(()=>validateRequest({...request(),url:'https://example.org'}));});
test('readback cannot carry a token or nonce',()=>{assert.throws(()=>validateRequest({...request('readback'),jwt:'a.b.c'}));assert.throws(()=>validateRequest(request('readback')));});
test('original cutoffs cannot be renewed',()=>{assert.throws(()=>validateOrigin({...origin,observe_until_ms:721001}));assert.throws(()=>validateOrigin({...origin,cleanup_until_ms:901001}));});
test('controller enrollment is version zero, target enrollment version one',()=>{const a={...request('enroll-controller'),expected_version:0,nonce:null,jwt:'a.b.c'};assert.deepEqual(validateRequest(a),a);const b={...a,operation:'enroll-target',expected_version:1,observer_public_key:'1'.repeat(64),controller_public_key:null,controller_signature:null};assert.deepEqual(validateRequest(b),b);assert.throws(()=>validateRequest({...b,expected_version:0}));});
test('provider ACK binds exact request and original epoch',()=>{assert.deepEqual(validateResponse(ack(),request(),'f'.repeat(64)),ack());assert.throws(()=>validateResponse({...ack(),request_sha256:'0'.repeat(64)},request(),'f'.repeat(64)));assert.throws(()=>validateResponse({...ack(),origin:{...origin,wall_ms:1001}},request(),'f'.repeat(64)));});
test('lost or inconsistent CAS is refused',()=>{assert.throws(()=>validateResponse({...ack(),version:2},request(),'f'.repeat(64)));assert.throws(()=>validateResponse({...ack(),version:4},request(),'f'.repeat(64)));assert.throws(()=>validateResponse({...ack(),state:'UNKNOWN'},request(),'f'.repeat(64)));});
test('job and GitHub enrollment must be actual and explicit',()=>{assert.throws(()=>validateResponse({...ack(),jobs_identity_verified:false},request(),'f'.repeat(64)));assert.throws(()=>validateResponse({...ack(),github_enrollment_verified:false},request(),'f'.repeat(64)));});
test('plain and copied scope or ACK cannot mint sealed admission',()=>{assert.throws(()=>requireScope({enabled:true}));assert.throws(()=>consumeAck({ack:ack()}));});
test('unsigned caller JSON or wrong deployment cannot authorize scope',async()=>{await assert.rejects(readAppliedScope({}));});
test('request digest is exact canonical bytes',async()=>assert.equal(await digest(canonical(request())),await digest(new TextEncoder().encode(canonical(request())))));
test('exclusive journal never adopts an existing original session',async()=>{const parent=await mkdtemp(join(tmpdir(),'public-reboot-inert-'));await chmod(parent,0o700);try{const journal=await OriginalJournal.create(parent,binding.session);await assert.rejects(OriginalJournal.create(parent,binding.session));await journal.append({kind:'INTENT',sequence:0});await journal.hold('inert-timeout');await assert.rejects(journal.append({kind:'ACK'}));assert.equal(JSON.parse(await readFile(join(parent,binding.session,'0002.json'),'utf8')).kind,'UNKNOWN');}finally{await rm(parent,{recursive:true});}});
test('journal refuses a foreign-readable parent',async()=>{const parent=await mkdtemp(join(tmpdir(),'public-reboot-inert-'));try{await chmod(parent,0o755);await assert.rejects(OriginalJournal.create(parent,binding.session));}finally{await rm(parent,{recursive:true});}});
