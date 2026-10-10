// Inert regression of the exact nested production branch. No runtime factory,
// keys, signer, clock lease, venue/network, cloud or private operation is invoked.
import {test,type TestContext} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {stripTypeScriptTypes} from 'node:module';
import {Admission} from './policy.ts';
const source=readFileSync(new URL('./index.ts',import.meta.url),'utf8');
const first=source.indexOf('  async function reconcile()'),last=source.indexOf('  async function proveEmpty()',first);
assert.ok(first>=0&&last>first);
const branch=stripTypeScriptTypes(source.slice(first,last));
const build=new Function('deps',
 'const {admission,ensure,armed,before,returnNonce,merchant,OWNER,venue,ledger,returnInterval,inspectAccounts,reconcileBalances,checkpoint,hold,fail}=deps;'+
 'let returnProven=deps.returnProven;'+branch+';return {reconcile,status:()=>returnProven};') as
 (deps:Record<string,unknown>)=>{reconcile:()=>Promise<void>;status:()=>boolean};
function fixture(t:TestContext,cross?:'ledger'|'accounts',alreadyProven=false){
 const start=1000,end=start+1200000,origin=9000000000000n,cutoff=origin+1200000000000n;
 let continuous=origin,reads=0,accountReads=0;
 t.mock.method(process.hrtime,'bigint',()=>continuous);
 // Wall stays behind the deadline while ONLY the inherited continuous cutoff
 // crosses. The local performance clock also remains live in this fixture.
 t.mock.method(Date,'now',()=>1100000);
 const clock={domain:'linux-clock-monotonic-ns-v1' as const,originWallNs:String(BigInt(start)*1000000n),
  originMonoNs:String(origin),deadlineMonoNs:String(origin+3600000000000n)};
 const admission=new Admission(start+3600000,()=>start,()=>0,{clock});admission.tighten(end);
 continuous=cutoff-1n;admission.check();
 const checkpoints:{kind:string;data:unknown}[]=[];
 const actual=build({admission,ensure:()=>{},armed:{amount:'354.61'},before:{},returnNonce:6000,
  merchant:'0x'+'2'.repeat(40),OWNER:'0x'+'1'.repeat(40),returnProven:alreadyProven,
  venue:async()=>({}),ledger:()=> '0x'+'f'.repeat(64),returnInterval:()=>{reads++;if(cross==='ledger')continuous=cutoff+1n;return '0x'+'f'.repeat(64);},
  inspectAccounts:async()=>{accountReads++;if(cross==='accounts')continuous=cutoff+1n;return {merchantLedger:[],ownerLedger:[],completedAt:1100000};},
  reconcileBalances:()=>({debit:'355.61',credit:'354.61',fee:'1',merchantEmpty:true}),
  checkpoint:async(kind:string,data:unknown)=>{checkpoints.push({kind,data});},hold:async()=>admission.hold(true),
  fail:()=>{throw Error('inert reconciliation refused');}});
 return{actual,admission,checkpoints,cutoff,setContinuous:(n:bigint)=>{continuous=n;},reads:()=>({ledger:reads,accounts:accountReads})};
}
test('first proof is admitted one nanosecond before inherited original cutoff',async t=>{
 const f=fixture(t);await f.actual.reconcile();assert.equal(f.actual.status(),true);
 assert.deepEqual(f.checkpoints.map(v=>v.kind),['return-proven']);assert.deepEqual(f.reads(),{ledger:2,accounts:1});
});
test('first proof is refused at the exact inherited cutoff despite unexpired wall timestamp',async t=>{
 const f=fixture(t);f.setContinuous(f.cutoff);await assert.rejects(f.actual.reconcile());
 assert.equal(f.actual.status(),false);assert.equal(f.checkpoints.length,0);
});
for(const cross of['ledger','accounts']as const)test('first proof cannot cross inherited cutoff during '+cross+' reads with wall behind',async t=>{
 const f=fixture(t,cross);await assert.rejects(f.actual.reconcile());
 assert.equal(f.actual.status(),false);assert.equal(f.checkpoints.length,0);assert.equal(f.admission.status().held,true);
 assert.deepEqual(f.reads(),{ledger:2,accounts:1});
});
test('later read-only reconciliation remains available after cutoff and unknown HOLD when already proved',async t=>{
 const f=fixture(t);await f.actual.reconcile();assert.equal(f.actual.status(),true);
 f.setContinuous(f.cutoff+1n);f.admission.hold(true);await f.actual.reconcile();
 assert.equal(f.actual.status(),true);assert.equal(f.checkpoints.length,2);assert.equal(f.admission.status().unknown,true);
});
test('already-proved return is not newly admitted when reads begin after inherited cutoff',async t=>{
 const f=fixture(t,'accounts',true);f.setContinuous(f.cutoff+1n);f.admission.hold(true);
 await f.actual.reconcile();assert.equal(f.actual.status(),true);assert.equal(f.checkpoints.length,1);
 assert.equal(f.admission.status().unknown,true);
});
