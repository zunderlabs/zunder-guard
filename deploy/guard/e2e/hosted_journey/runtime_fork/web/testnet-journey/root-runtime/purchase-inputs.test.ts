// Inert execution of actual policy only: dummy buffers, no factory/key/cloud use.
import test from 'node:test';import assert from 'node:assert/strict';
import {Admission} from './policy.ts';
import {guardedChildStdout} from './child.ts';
import {createPurchaseInputStore,validatePurchaseBinding,purchaseParameterNames,purchaseParameterTags,PURCHASE_ACCOUNT,PURCHASE_KMS,
 type PurchaseBinding,type PurchaseCleanupApproval} from './purchase-inputs.ts';
const now=1791576000000,hash='a'.repeat(64);
function fixture(t:any){
 let wall=now,mono=0,account=PURCHASE_ACCOUNT,failAt='',expireAt='',checkpointFailure='',readMismatch='';
 t.mock.method(Date,'now',()=>wall);
 const binding:PurchaseBinding={schema:1,run:123456,attempt:1,source:'b'.repeat(40),runId:'12345678-1234-4234-8234-123456789abc',
  startedAt:now-1000,deadline:now+60000,merchant:'0x'+'2'.repeat(40),issuerPublicKey:'3'.repeat(64)};
 const identity={runId:binding.runId,startedAt:binding.startedAt,merchant:binding.merchant,issuerPublicKey:binding.issuerPublicKey};
 const admission=new Admission(binding.deadline,()=>wall,()=>mono),calls:any[]=[],inputs:Buffer[]=[],outputs:Buffer[]=[],events:any[]=[];
 const parameters=new Map<string,any>();
 const store=createPurchaseInputStore(identity,admission,{
  checkpoint:async(kind,data)=>{events.push({kind,...data});if(kind===checkpointFailure)throw Error('inert checkpoint');},
  execute:async(kind,service,action,input,deadline,guard)=>{
   guard();inputs.push(input);const data=JSON.parse(input.toString());calls.push({kind,service,action,deadline,data});
   if(action===failAt)throw Error('inert lost response');let result:any;
   if(action==='get-caller-identity')result={Account:account,Arn:'arn:aws:iam::'+account+':role/test',UserId:'inert-id'};
   else if(action==='put-parameter'){
    assert.equal(data.Overwrite,false);assert.equal(data.KeyId,PURCHASE_KMS);assert.equal(data.Type,'SecureString');assert.equal(data.Tier,'Standard');
    assert(!parameters.has(data.Name));parameters.set(data.Name,{Name:data.Name,Type:data.Type,Tier:data.Tier,Version:1,KeyId:data.KeyId,tags:data.Tags});
    result={Version:1,Tier:'Standard'};
   }else if(action==='describe-parameters'){
    const name=data.ParameterFilters[0].Values[0],row=parameters.get(name);let observed=row?{...row,tags:undefined}:undefined;
    if(observed&&readMismatch==='Name')observed.Name='unrelated';
    if(observed&&readMismatch==='Version')observed.Version=2;
    if(observed&&readMismatch==='Type')observed.Type='String';
    if(observed&&readMismatch==='Tier')observed.Tier='Advanced';
    if(observed&&readMismatch==='KeyId')observed.KeyId='alias/unrelated';
    if(readMismatch==='absent')observed=undefined;
    result={Parameters:observed?[observed]:[]};
   }else if(action==='list-tags-for-resource')result={TagList:readMismatch==='tags'?[{Key:'Source',Value:'wrong'}]:parameters.get(data.ResourceId)?.tags};
   else if(action==='delete-parameter'){parameters.delete(data.Name);result=null;}
   else throw Error('Unexpected inert action');
   if(action===expireAt){wall=binding.deadline;mono=60000;}
   const bytes=result===null?Buffer.alloc(0):Buffer.from(JSON.stringify(result));outputs.push(bytes);return bytes;
  },
 });
 const values=()=>[Buffer.from('i'.repeat(43)),Buffer.from('m'.repeat(43)),Buffer.from('0x'+'1'.repeat(64))];
 const approval=():PurchaseCleanupApproval=>({schema:1,purpose:'cleanup-purchase-inputs',bindingSha256:hash,approved:true,deadline:Math.min(wall+300000,binding.deadline+300000)});
 return{binding,identity,admission,store,calls,inputs,outputs,events,parameters,values,approval,
  wrongAccount:()=>{account='111111111111';},fail:(action:string)=>{failAt=action;},clearFailure:()=>{failAt='';},
  expireDuring:(action:string)=>{expireAt=action;},failCheckpoint:(kind:string)=>{checkpointFailure=kind;},
  mismatchRead:(kind:string)=>{readMismatch=kind;},
  clock:(w:number,m:number)=>{wall=w;mono=m;}};
}
test('fixed three Version1 secure writes bind paths/KMS/tags and wipe private stdin/stdout',async t=>{
 const f=fixture(t);await f.store.store(f.binding,hash,f.values());
 assert.deepEqual(f.calls.map(c=>c.action),['get-caller-identity',...Array(3).fill(['put-parameter','describe-parameters','list-tags-for-resource']).flat()]);
 const puts=f.calls.filter(c=>c.action==='put-parameter');assert.deepEqual(puts.map(c=>c.data.Name),purchaseParameterNames(f.binding));
 for(const c of puts)assert.deepEqual(c.data.Tags,purchaseParameterTags(f.binding));
 assert.equal(puts[2].data.Value,'0x'+'1'.repeat(64));assert(f.inputs.every(b=>b.every(v=>v===0)));assert(f.outputs.every(b=>b.every(v=>v===0)));
 assert.equal(f.store.state().unresolved,true);assert(!JSON.stringify(f.store.state()).includes('i'.repeat(43)));
 assert(!f.calls.some(c=>/get-parameter|decrypt/.test(c.action)));assert.equal(f.events[0].kind,'purchase-input-store-consumed');
 await assert.rejects(f.store.store(f.binding,hash,f.values()));assert.equal(f.calls.length,10);
});
test('pure binding rejects changed original identity, clock, paths and over twenty minutes',t=>{
 const f=fixture(t);validatePurchaseBinding(f.binding,f.identity,f.binding.deadline,now);
 for(const change of [{run:0},{attempt:101},{source:'bad'},{merchant:'0x'+'0'.repeat(40)},{issuerPublicKey:'4'.repeat(64)},
  {runId:'changed'},{startedAt:now},{deadline:f.binding.deadline+1},{extra:true}])
  assert.throws(()=>validatePurchaseBinding({...f.binding,...change}as any,f.identity,f.binding.deadline,now));
 assert.throws(()=>validatePurchaseBinding({...f.binding,deadline:now+1200000},f.identity,now+1200000,now));assert.equal(f.calls.length,0);
});
test('wrong AWS account holds without any SSM write and consumes store attempt',async t=>{
 const f=fixture(t);f.wrongAccount();await assert.rejects(f.store.store(f.binding,hash,f.values()));
 assert.deepEqual(f.calls.map(c=>c.action),['get-caller-identity']);assert.equal(f.admission.status().unknown,true);
 await assert.rejects(f.store.store(f.binding,hash,f.values()));
});
test('invalid private inputs are consumed before dispatch and never enter checkpoints',async t=>{
 const f=fixture(t);await assert.rejects(f.store.store(f.binding,hash,[Buffer.alloc(0),...f.values().slice(1)]));
 assert.equal(f.calls.length,0);assert.equal(f.store.state().attempted,true);assert.equal(f.admission.status().unknown,true);
});
test('lost write result retains all public names and cannot retry; checkpoint precedes put',async t=>{
 const f=fixture(t);f.fail('put-parameter');await assert.rejects(f.store.store(f.binding,hash,f.values()));
 assert.equal(f.calls.length,2);assert.equal(f.store.state().unresolved,true);assert.deepEqual(f.store.state().parameters,purchaseParameterNames(f.binding));
 assert(f.events.some(v=>v.kind==='purchase-input-put-attempted'));assert(f.inputs.every(b=>b.every(v=>v===0)));
});
test('original expiry after first actual put prevents second write without renewed clock',async t=>{
 const f=fixture(t);f.expireDuring('put-parameter');await assert.rejects(f.store.store(f.binding,hash,f.values()));
 assert.equal(f.calls.filter(c=>c.action==='put-parameter').length,1);assert.equal(f.store.state().unresolved,true);
});
test('store verifies actual metadata and all tags after each acknowledged write before confirming',async t=>{
 for(const mismatch of ['Name','Type','Tier','Version','KeyId','tags','absent']){
  const f=fixture(t);f.mismatchRead(mismatch);await assert.rejects(f.store.store(f.binding,hash,f.values()));
  assert.equal(f.calls.filter(c=>c.action==='put-parameter').length,1);assert.equal(f.store.state().unresolved,true);
  assert.equal(f.admission.status().unknown,true);assert(!f.events.some(v=>v.kind==='purchase-input-put-confirmed'));
  assert(f.outputs.every(b=>b.every(v=>v===0)));await assert.rejects(f.store.store(f.binding,hash,f.values()));
 }
});
test('lost metadata readback consumes store and keeps acknowledged parameter and all public names',async t=>{
 const f=fixture(t);f.fail('describe-parameters');await assert.rejects(f.store.store(f.binding,hash,f.values()));
 assert.equal(f.parameters.size,1);assert.equal(f.store.state().unresolved,true);assert.equal(f.admission.status().unknown,true);
 assert.deepEqual(f.calls.map(c=>c.action),['get-caller-identity','put-parameter','describe-parameters']);
 assert.deepEqual(f.store.state().parameters,purchaseParameterNames(f.binding));assert(f.inputs.every(b=>b.every(v=>v===0)));
});
test('original expiry during metadata readback wipes output and prevents tag read or next write',async t=>{
 const f=fixture(t);f.expireDuring('describe-parameters');await assert.rejects(f.store.store(f.binding,hash,f.values()));
 assert.deepEqual(f.calls.map(c=>c.action),['get-caller-identity','put-parameter','describe-parameters']);
 assert.equal(f.store.state().unresolved,true);assert(f.outputs.every(b=>b.every(v=>v===0)));
});
test('failure to preserve consumed checkpoint prevents all AWS dispatch',async t=>{
 const f=fixture(t);f.failCheckpoint('purchase-input-store-consumed');await assert.rejects(f.store.store(f.binding,hash,f.values()));
 assert.equal(f.calls.length,0);assert.equal(f.store.state().unresolved,true);
});
test('cleanup reads exact metadata and tags before deletes, confirms absence and wipes output',async t=>{
 const f=fixture(t);await f.store.store(f.binding,hash,f.values());f.admission.hold(true);
 await f.store.cleanup(f.binding,hash,f.approval());assert.equal(f.parameters.size,0);assert.equal(f.store.state().unresolved,false);
 assert.equal(f.store.state().clean,true);assert.equal(f.admission.status().unknown,true);assert.throws(()=>f.admission.check());
 for(const name of purchaseParameterNames(f.binding)){
  const rows=f.calls.filter(c=>c.service==='ssm'&&(c.data.Name===name||c.data.ResourceId===name||c.data.ParameterFilters?.[0]?.Values?.[0]===name));
  assert.deepEqual(rows.map(c=>c.action),['put-parameter','describe-parameters','list-tags-for-resource',
    'describe-parameters','list-tags-for-resource','delete-parameter','describe-parameters']);
 }
 assert(f.outputs.every(b=>b.every(v=>v===0)));await assert.rejects(f.store.cleanup(f.binding,hash,f.approval()));
});
test('cleanup partial/absent parameters requires readback without deleting unrelated resources',async t=>{
 const f=fixture(t);f.fail('put-parameter');await assert.rejects(f.store.store(f.binding,hash,f.values()));f.clearFailure();
 await f.store.cleanup(f.binding,hash,f.approval());assert.equal(f.store.state().clean,true);
 assert.equal(f.calls.filter(c=>c.action==='delete-parameter').length,0);
 assert.equal(f.calls.filter(c=>c.action==='describe-parameters').length,6);
});
test('wrong metadata or tags refuses deletion and retains unresolved state',async t=>{
 for(const mutation of ['version','tags']){
  const f=fixture(t);await f.store.store(f.binding,hash,f.values());const row=f.parameters.get(purchaseParameterNames(f.binding)[0]!);
  if(mutation==='version')row.Version=2;else row.tags=[{Key:'Scope',Value:'unrelated'}];
  await assert.rejects(f.store.cleanup(f.binding,hash,f.approval()));assert.equal(f.store.state().unresolved,true);
  assert.equal(f.calls.filter(c=>c.action==='delete-parameter').length,0);
 }
});
test('cleanup cannot change binding or create a new five-minute window',async t=>{
 const f=fixture(t);await f.store.store(f.binding,hash,f.values());
 await assert.rejects(f.store.cleanup({...f.binding,attempt:2},hash,f.approval()));
 await assert.rejects(f.store.cleanup(f.binding,hash,{...f.approval(),deadline:f.binding.deadline+300001}));
 await assert.rejects(f.store.cleanup(f.binding,hash,{...f.approval(),deadline:now+300001}));
 f.clock(f.binding.deadline+300000,360000);await assert.rejects(f.store.cleanup(f.binding,hash,f.approval()));
 assert.equal(f.calls.filter(c=>c.action==='delete-parameter').length,0);
});
test('cleanup cannot begin with a twenty-five-minute grant before ordinary epoch ends',t=>{
 const f=fixture(t);const admission=new Admission(now+1200000,()=>Date.now(),()=>0);
 assert.throws(()=>admission.createCleanupGuard(now+1500000));assert.equal(f.calls.length,0);
});
test('cleanup guard keeps one captured five-minute interval through wall rollback and repeated checks',t=>{
 const f=fixture(t);f.admission.hold(true);f.clock(now+10000,0);
 const guard=f.admission.createCleanupGuard(now+300000);guard();
 f.clock(now+15000,100000);guard();guard();
 // Original epoch check alone still admits; the captured cleanup budget has
 // elapsed after rollback and must not be reset by those intermediate checks.
 f.clock(now,290000);f.admission.checkCleanup(now+300000);assert.throws(guard);assert.throws(()=>f.admission.check());
});
test('cleanup guard refuses wall-clock expiry and cannot authorize beyond original plus five minutes',t=>{
 const f=fixture(t),guard=f.admission.createCleanupGuard(now+300000);
 f.clock(now+300000,1);assert.throws(guard);
 assert.throws(()=>f.admission.createCleanupGuard(f.binding.deadline+300001));
});
test('a lost cleanup result consumes the interval; retry cannot claim a fresh clock',async t=>{
 const f=fixture(t);await f.store.store(f.binding,hash,f.values());f.fail('describe-parameters');
 await assert.rejects(f.store.cleanup(f.binding,hash,f.approval()));const count=f.calls.length;f.clearFailure();
 f.clock(now+1000,1000);await assert.rejects(f.store.cleanup(f.binding,hash,f.approval()));assert.equal(f.calls.length,count);
 assert.equal(f.store.state().cleanupAttempted,true);assert.equal(f.store.state().unresolved,true);
});
test('original monotonic cleanup budget survives wall rollback and remains signing-held',t=>{
 const f=fixture(t);f.admission.hold(true);f.clock(now,360000);
 assert.throws(()=>f.admission.checkCleanup(f.binding.deadline+300000));assert.throws(()=>f.admission.check());
});
test('deadline after actual child completion wipes output before it can escape to consumer',t=>{
 const f=fixture(t),output=Buffer.from('inert-child-output');f.clock(f.binding.deadline,60000);
 assert.throws(()=>guardedChildStdout(output,()=>f.admission.check()));assert(output.every(v=>v===0));
 const accepted=Buffer.from('inert-public-output');assert.equal(guardedChildStdout(accepted,()=>{}),accepted);
});
