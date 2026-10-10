import test from 'node:test';
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import {launchCollectorsForBoot} from '../boot-wrapper.mjs';
import {originalBootCollector} from '../boot-collector.mjs';
import {waitForOriginalCleanup,disposeOriginalPlan} from '../expiry-collector.mjs';
import {canonical} from '../protocol.mjs';
import {readAppliedScope} from '../relay-schema.mjs';
import {publicKey} from '../macos-owned.mjs';

// Entirely modeled boot/process/store/file state. No native command, filesystem,
// OS credential, reboot, applied enrollment or external fetch executes here.
const started=Date.now()-1000;
const origin={wall_ms:started,observe_until_ms:started+720000,cleanup_until_ms:started+900000};
const expected={origin:'https://reboot-fixture.invalid',deployment_sha256:'d'.repeat(64),source:'a'.repeat(40),workflow_ref:'zunderlabs/zunder-guard/.github/workflows/public-reboot.yml@refs/heads/main',repository_id:'1409357189',owner_id:'338317604',audience:'zunder-public-reboot'};
const seed=Buffer.alloc(32,7);
const plan={directory:'/FIXTURE/owned',runtime:'/FIXTURE/owned/node',helper:'/FIXTURE/owned/helper',plist_sha256:'c'.repeat(64),binding:{run_id:123,attempt:1,source:expected.source,target_job_id:456,label:'macos-15',session:'b'.repeat(64),helper_sha256:'c'.repeat(64),inventory_sha256:'d'.repeat(64)},observer_public_key:publicKey(seed),initial_boot_id:'FIXTURE-PRE',initial_boot_time_ms:100,origin,expected_scope:expected,sequence:2,version:6,nonce:'6'.repeat(64)};
const after={boot_id:'FIXTURE-POST',boot_time_ms:200,uptime_ms:500};
function child(spawns,file,fail=false){const value=new EventEmitter();value.unref=()=>spawns.push('unref:'+file);queueMicrotask(()=>value.emit(fail?'error':'spawn',fail?new Error('INERT-spawn-failure'):undefined));return value;}
function disposal(order){const refs=[{path:'/FIXTURE/owned/module',dev:1,ino:2,sha256:'a'.repeat(64)}];return {
  capture:async original=>{assert.equal(original,plan);order.push('capture');return refs;},
  native:async(helper,operation,session,value)=>{assert.equal(helper,plan.helper);assert.equal(session,plan.binding.session);order.push(operation);if(operation==='read')return {output:Buffer.from(seed)};assert.equal(operation,'delete');assert.equal(value.toString('hex'),plan.observer_public_key);return {output:Buffer.alloc(0)};},
  removeRegistration:async(original,digest)=>{assert.equal(original,plan);assert.equal(digest,plan.plist_sha256);order.push('registration');},
  removeFiles:async(files,directory)=>{assert.equal(files,refs);assert.equal(directory,plan.directory);order.push('files');},
};}
for(const fault of ['scope-refused','scope-network-lost','POSTBOOT-ack-lost'])test('on-time modeled reboot '+fault+' retains independent original-deadline disposal',async()=>{
  let now=started+2000,mono=1000000n,resume,failed=false;const spawns=[],order=[],tasks=[];
  const wait=waitForOriginalCleanup(origin,{wall:()=>now,mono:()=>mono,sleep:()=>new Promise(resolve=>{resume=resolve;})});
  const spawnImpl=(runtime,args,options)=>{
    assert.equal(runtime,plan.runtime);assert.equal(options.detached,true);assert.deepEqual(options.env,{PATH:'/usr/bin:/bin',LANG:'C'});assert.equal(args[1],plan.directory+'/plan.json');
    const file=args[0].split('/').at(-1);spawns.push(file);
    if(file==='expiry-collector.mjs')tasks.push(wait.then(()=>disposeOriginalPlan(plan,disposal(order))));
    else tasks.push(originalBootCollector(args[1],{
      hostCheck(){},read:async()=>plan,
      scopeRead:value=>readAppliedScope(value,{fetchImpl:async()=>{
        if(fault==='scope-network-lost')throw new Error('INERT-network');
        if(fault==='scope-refused')return new Response(null,{status:409});
        return new Response(canonical({schema:1,kind:'applied-public-reboot-relay-scope',...expected,expires_ms:Date.now()+1000000,enabled:true}),{headers:{'content-type':'application/json'}});
      }}),
      native:async(helper,operation)=>{assert.equal(operation,'read');return {output:Buffer.from(seed)};},
      collect:async()=>({event:{schema:1,kind:'public-host-reboot-observation',phase:'POSTBOOT',sequence:2,nonce:plan.nonce,binding:plan.binding,machine_sha256:'2'.repeat(64),marker_sha256:'3'.repeat(64),boot_id:after.boot_id,boot_time_ms:after.boot_time_ms,uptime_ms:after.uptime_ms,observer_pid:200,observer_birth:'200:2',cleanup:{registration_absent:false,files_absent:false,key_store_absent:false,observer_child_gone:false,carrier_exit_observed:false}}}),
      targetFactory:()=>({sendEvent:async()=>{assert.equal(fault,'POSTBOOT-ack-lost');throw new Error('INERT-lost-POSTBOOT-write');},waitChallenge:()=>{throw new Error('Must not retry/adopt');}}),
    }).catch(()=>{failed=true;}));
    return child(spawns,file);
  };
  await launchCollectorsForBoot(plan,after,{spawnImpl,wall:()=>now});
  await tasks[1];assert.equal(failed,true);assert.equal(spawns[0],'expiry-collector.mjs');assert.equal(spawns[2],'boot-collector.mjs');assert.deepEqual(order,[]);
  // A replacement watcher uses the original absolute cutoff, never birth+15min.
  now=origin.cleanup_until_ms;mono+=BigInt(now-(started+2000))*1000000n;resume();await Promise.all(tasks);
  assert.deepEqual(order,['capture','read','registration','delete','files']);assert.equal(spawns.filter(name=>name==='expiry-collector.mjs').length,1);
});
test('expired or slow modeled boot starts only disposal, initial boot starts none',async()=>{
  for(const actual of [after,{...after,uptime_ms:120001}]){
    const spawns=[];await launchCollectorsForBoot(plan,actual,{wall:()=>actual.uptime_ms>120000?started+2000:origin.observe_until_ms,spawnImpl:(runtime,args)=>{const file=args[0].split('/').at(-1);spawns.push(file);return child([],file);}});assert.deepEqual(spawns,['expiry-collector.mjs']);
  }
  const spawns=[];await launchCollectorsForBoot(plan,{boot_id:plan.initial_boot_id,boot_time_ms:plan.initial_boot_time_ms},{spawnImpl:()=>spawns.push('forbidden')});assert.deepEqual(spawns,[]);
  await assert.rejects(launchCollectorsForBoot(plan,{boot_id:'CHANGED',boot_time_ms:plan.initial_boot_time_ms},{spawnImpl:()=>spawns.push('forbidden')}));assert.deepEqual(spawns,[]);
});
test('unknown disposal watcher launch refuses observation collector and never retries',async()=>{
  const spawns=[];await assert.rejects(launchCollectorsForBoot(plan,after,{wall:()=>started+2000,spawnImpl:(runtime,args)=>{const file=args[0].split('/').at(-1);spawns.push(file);return child([],file,true);}}));assert.deepEqual(spawns,['expiry-collector.mjs']);
});
test('original disposal cutoff handles wall and monotonic expiry or rollback without renewal',async()=>{
  for(const fault of ['wall-expiry','mono-expiry','wall-rollback','mono-rollback']){
    let now=started+2000,mono=100n,sleeps=0;
    await waitForOriginalCleanup(origin,{wall:()=>now,mono:()=>mono,sleep:async()=>{sleeps++;if(fault==='wall-expiry')now=origin.cleanup_until_ms;else if(fault==='mono-expiry')mono+=BigInt(origin.cleanup_until_ms-(started+2000))*1000000n;else if(fault==='wall-rollback')now--;else mono--;}});
    assert.equal(sleeps,1);
  }
  await waitForOriginalCleanup(origin,{wall:()=>origin.wall_ms-1,mono:()=>100n,sleep:()=>{throw new Error('Cannot renew before original origin');}});
});
test('unknown ownership or wrong receipt public key refuses destructive cleanup',async()=>{
  const order=[];await assert.rejects(disposeOriginalPlan(plan,{...disposal(order),capture:async()=>{throw new Error('INERT-foreign');}}));assert.deepEqual(order,[]);
  const wrong=[];await assert.rejects(disposeOriginalPlan({...plan,observer_public_key:'0'.repeat(64)},{...disposal(wrong),capture:async()=>[],native:async()=>({output:Buffer.from(seed)})}));assert.deepEqual(wrong,[]);
});
