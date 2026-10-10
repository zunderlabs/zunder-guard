import test from 'node:test';
import assert from 'node:assert/strict';
import { validateNssInput, nssArguments, nssAdmission } from './nss-trust.ts';
const runId='12345678-1234-4234-8234-123456789abc';
const input=()=>({runId,startedAt:1000,deadline:2000,profileMountPath:`/run/zunder-wallet-${runId}`,certutil:{path:'/usr/bin/certutil',sha256:'a'.repeat(64)},certificate:{path:`/run/zunder-wallet-${runId}/public-ca.pem`,sha256:'b'.repeat(64)},certificateSha256:'b'.repeat(64)});
test('only exact public paths, pins and original finite window accepted',()=>{
 const c=validateNssInput(input());assert.equal(c.deadline,2000);assert(Object.isFrozen(c));assert(Object.isFrozen(c.certutil));
 for(const patch of [{profileMountPath:'/tmp/profile'},{deadline:1_201_001},{startedAt:2000},{certificateSha256:'c'.repeat(64)},{extra:true},{runId:'../../etc'}])assert.throws(()=>validateNssInput({...input(),...patch}));
 for(const certificate of [{path:`/run/zunder-wallet-${runId}/home/key.pem`,sha256:'b'.repeat(64)},{path:'/run/other/ca.pem',sha256:'b'.repeat(64)},{path:`/run/zunder-wallet-${runId}/x/../ca.pem`,sha256:'b'.repeat(64)}])assert.throws(()=>validateNssInput({...input(),certificate}));
});
test('input mutation cannot change pinned CA or argument destinations',()=>{
 const original=input(),fixed=validateNssInput(original);original.certutil.path='/tmp/evil';original.certificate.path='/tmp/evil';original.deadline=5000;
 assert.equal(fixed.certutil.path,'/usr/bin/certutil');assert.equal(fixed.deadline,2000);
 const args=nssArguments(fixed);assert.deepEqual(args,[['-N','-d',`sql:/run/zunder-wallet-${runId}/home/.pki/nssdb`,'--empty-password'],['-A','-d',`sql:/run/zunder-wallet-${runId}/home/.pki/nssdb`,'-n',`Zunder public no-key ${runId}`,'-t','C,,','-i',`/run/zunder-wallet-${runId}/public-ca.pem`]]);
 assert(Object.isFrozen(args[0]));assert(!args.flat().includes('-K'));
});
test('sequential single-use commands require successful prior close',()=>{
 const state=nssAdmission(1000,2000);let calls=0;
 assert.throws(()=>state.dispatch(1,1200,()=>calls++));state.dispatch(0,1200,()=>calls++);
 assert.throws(()=>state.dispatch(1,1201,()=>calls++));assert.equal(calls,1);
 state.closed(0);state.dispatch(1,1400,()=>calls++);state.closed(0);assert.equal(calls,2);assert.equal(state.state().complete,true);
 assert.throws(()=>state.dispatch(1,1500,()=>calls++));assert.throws(()=>state.dispatch(2,1500,()=>calls++));
});
test('original deadline and future starts deny authority callback',()=>{
 for(const time of [999,2000,2001]){let called=false;assert.throws(()=>nssAdmission(1000,2000).dispatch(0,time,()=>{called=true;}));assert.equal(called,false);}
 const s=nssAdmission(1000,2000);s.dispatch(0,1000,()=>{});s.closed(0);assert.throws(()=>s.dispatch(1,2000,()=>{}));assert.equal(s.state().complete,false);
});
test('failed actual authority consumes admission and prevents retry',()=>{
 const s=nssAdmission(1000,2000);assert.throws(()=>s.dispatch(0,1200,()=>{throw Error('inert refusal');}));assert.equal(s.state().unknown,true);assert.throws(()=>s.dispatch(0,1201,()=>{}));assert.throws(()=>s.dispatch(1,1201,()=>{}));
});
test('unknown or bad close permanently prevents second mutation and success',()=>{
 for(const code of [null,1]){const s=nssAdmission(1000,2000);s.dispatch(0,1200,()=>{});s.closed(code);assert.throws(()=>s.dispatch(1,1300,()=>{}));assert.equal(s.state().complete,false);}
 const s=nssAdmission(1000,2000);s.dispatch(0,1200,()=>{});s.uncertain();s.closed(0);assert.throws(()=>s.dispatch(1,1300,()=>{}));assert.equal(s.state().complete,false);
});
