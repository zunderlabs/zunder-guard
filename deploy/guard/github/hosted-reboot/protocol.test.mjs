import assert from 'node:assert/strict';
import {canonical,validateBinding,validateEvent,evaluateModeledSequence,verifyEd25519,verifyEvent,OriginalControllerProtocol} from './protocol.mjs';
const binding={run_id:7,attempt:1,source:'a'.repeat(40),target_job_id:8,label:'macos-15',session:'b'.repeat(64),helper_sha256:'c'.repeat(64),inventory_sha256:'d'.repeat(64)};
const nonces=['1','2','3','4'].map(v=>v.repeat(64));
const phases=['PREBOOT','ARMED','POSTBOOT','CLEANUP'];
const events=phases.map((phase,sequence)=>({schema:1,kind:'public-host-reboot-observation',phase,sequence,nonce:nonces[sequence],binding:{...binding},machine_sha256:'5'.repeat(64),marker_sha256:'6'.repeat(64),boot_id:sequence<2?'old-boot':'new-boot',boot_time_ms:sequence<2?1000:2000,uptime_ms:sequence<2?900000:30000,observer_pid:sequence<2?42:43,observer_birth:sequence<2?'100':'200',cleanup:{registration_absent:sequence===3,files_absent:sequence===3,key_store_absent:sequence===3,observer_child_gone:sequence===3,carrier_exit_observed:false}}));
let count=0;
function test(name,fn){fn();count++;console.log('PASS '+name);}
function bad(mutator){const e=structuredClone(events);mutator(e);assert.throws(()=>evaluateModeledSequence(e,binding,nonces));}
test('modeled complete is explicitly unauthenticated',()=>{const r=evaluateModeledSequence(events,binding,nonces);assert.equal(r.sequence_complete,true);assert.equal(r.authenticated,false);assert.equal(r.actual_reboot,false);});
test('same boot refuses',()=>bad(e=>e[2].boot_id=e[0].boot_id));
test('same boot time refuses',()=>bad(e=>e[2].boot_time_ms=e[0].boot_time_ms));
test('different target hardware refuses',()=>bad(e=>e[2].machine_sha256='7'.repeat(64)));
test('different owned marker refuses',()=>bad(e=>e[2].marker_sha256='7'.repeat(64)));
test('copied source/job identity refuses',()=>bad(e=>e[2].binding.target_job_id=9));
test('different attempt refuses',()=>bad(e=>e[2].binding.attempt=2));
test('wrong challenge refuses',()=>bad(e=>e[2].nonce='9'.repeat(64)));
test('phase replay refuses',()=>bad(e=>e[2]=e[1]));
test('old observer process refuses',()=>bad(e=>{e[2].observer_pid=e[0].observer_pid;e[2].observer_birth=e[0].observer_birth;}));
test('same birth with new PID refuses',()=>bad(e=>{e[2].observer_pid=43;e[2].observer_birth=e[0].observer_birth;}));
test('not fresh boot uptime refuses',()=>bad(e=>e[2].uptime_ms=120001));
test('missing cleanup refuses',()=>bad(e=>e[3].cleanup.key_store_absent=false));
test('self terminal exit proof refuses',()=>bad(e=>e[3].cleanup.carrier_exit_observed=true));
test('private/unknown fields refuse',()=>{const e=structuredClone(events[0]);e.oidc_token='public-inert-sentinel';assert.throws(()=>validateEvent(e));});
test('unknown runner label refuses',()=>assert.throws(()=>validateBinding({...binding,label:'self-hosted'})));
let wall=3000,mono=1000000000n;
const origin={wall_ms:3000,mono_ns:mono,observe_until_ms:723000,cleanup_until_ms:903000};
const clocks={wall_ms:()=>wall,mono_ns:()=>mono};
test('missing enrolled observer public key refuses',()=>assert.throws(()=>new OriginalControllerProtocol(binding,origin,clocks)));
test('dictionary cannot mint verified token',()=>{const p=new OriginalControllerProtocol(binding,origin,clocks,'f'.repeat(64));p.armChallenge(nonces[0]);assert.throws(()=>p.acceptVerified({event:events[0],observer_public_key:'f'.repeat(64)}));assert.equal(p.report().release_ready,false);assert.equal(p.report().cryptographic_event_verification,false);});
test('wall rollback refuses',()=>{const p=new OriginalControllerProtocol(binding,origin,clocks,'f'.repeat(64));wall=2999;assert.throws(()=>p.armChallenge(nonces[0]));wall=3000;});
test('original monotonic cutoff refuses under wall rollback',()=>{const p=new OriginalControllerProtocol(binding,origin,clocks,'f'.repeat(64));mono=721000000000n;assert.throws(()=>p.armChallenge(nonces[0]));mono=1000000000n;});
for (const [name,nextWall,nextMono] of [['combined above-origin rollback',4000,2000000000n],['independent wall rollback',4000,4000000000n],['independent monotonic rollback',6000,2000000000n]]) {
  test(name+' refuses',()=>{
    wall=3000;mono=1000000000n;
    const p=new OriginalControllerProtocol(binding,origin,clocks,'f'.repeat(64));
    wall=5000;mono=3000000000n;p.assertLive();
    wall=nextWall;mono=nextMono;assert.throws(()=>p.assertLive());
    // A failed validation must not lower either last observation.
    wall=5000;mono=3000000000n;p.assertLive();
    assert.equal(p.report().cryptographic_event_verification,false);
    wall=3000;mono=1000000000n;
  });
}
// RFC8032 section7.1 TEST1, publicly documented verify-only vector. No private key read/generated, no signature generated.
const bytes=h=>Uint8Array.from(h.match(/../g)||[],v=>parseInt(v,16));
const pub=bytes('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
const sig=bytes('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
assert.equal(await verifyEd25519(new Uint8Array(),sig,pub),true);count++;console.log('PASS actual crypto verify PUBLIC RFC8032 vector');
const wrong=sig.slice();wrong[0]^=1;assert.equal(await verifyEd25519(new Uint8Array(),wrong,pub),false);count++;console.log('PASS public forged signature refuses');
await assert.rejects(()=>verifyEvent(new TextEncoder().encode(canonical(events[0])),sig,pub));count++;console.log('PASS valid vector does not authenticate another payload');
console.log(JSON.stringify({kind:'INERT_ONLY',passed:count,key_generation:false,signature_generation:false,hardware:false,reboot:false,network:false}));
