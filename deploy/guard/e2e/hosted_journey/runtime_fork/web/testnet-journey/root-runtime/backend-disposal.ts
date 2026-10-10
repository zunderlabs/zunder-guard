// Separate public-only original25 admission. It cannot sign or read inputs.
import {isDeepStrictEqual} from 'node:util';
import {Admission,exact,fail,hashString,validateOriginalAdmissionClock,type OriginalAdmissionClock} from './policy.ts';
import type {OriginalParentGate} from './completion-parent.ts';
const SEAL=Symbol('original backend disposal');const live=new WeakSet<object>();let attempted=false;
export interface DisposalContinuation {
 schema:1;kind:'original-hosted-backend-disposal-only';bindingSha256:string;runId:string;startedAt:number;deadline:number;
 planSha256:string;returnProofSha256:string;sourceManifestSha256:string;runtimeManifestSha256:string;
 backendSequence:number;ownedJournalSha256:string;
 parent:{pid:number;start_ticks:number;boot_id:string;uid:number};clock:OriginalAdmissionClock;
}
export class OriginalBackendDisposalAdmission {
 private held=false;private readonly original:Admission;private readonly prior:Readonly<OriginalAdmissionClock>;
 readonly continuation:Readonly<DisposalContinuation>;
 private constructor(seal:symbol,original:Admission,prior:Readonly<OriginalAdmissionClock>,continuation:Readonly<DisposalContinuation>){
  if(seal!==SEAL)fail();this.original=original;this.prior=prior;this.continuation=continuation;live.add(this);this.check();}
 static fromOriginalPipe(raw:unknown,ready:{runId:string;returnProofSha256:string;planSha256:string},
  gate:OriginalParentGate,admission:Admission,custodyBinding:string):OriginalBackendDisposalAdmission {
  if(attempted)fail();attempted=true;admission.assertOriginalClock(gate.clock);
  exact(raw,['schema','kind','bindingSha256','runId','startedAt','deadline','planSha256','returnProofSha256',
   'sourceManifestSha256','runtimeManifestSha256','parent','clock','backendSequence','ownedJournalSha256']);
  const c=raw as unknown as DisposalContinuation;
  exact(c.parent,['pid','start_ticks','boot_id','uid']);
  if(c.schema!==1||c.kind!=='original-hosted-backend-disposal-only'||c.runId!==gate.runId||c.runId!==ready.runId
   ||c.bindingSha256!==custodyBinding||!hashString(c.bindingSha256)||c.planSha256!==ready.planSha256||!hashString(c.planSha256)
   ||c.returnProofSha256!==ready.returnProofSha256||!hashString(c.returnProofSha256)||c.startedAt!==gate.startedAt
   ||!Number.isSafeInteger(c.backendSequence)||c.backendSequence<1||c.backendSequence>192||!hashString(c.ownedJournalSha256)
   ||c.deadline<=admission.deadline()||c.deadline>gate.startedAt+1500000
   ||c.sourceManifestSha256!==gate.sourceManifestSha256||c.runtimeManifestSha256!==gate.runtimeManifest.sha256
   ||!isDeepStrictEqual(c.parent,Object.fromEntries(['pid','start_ticks','boot_id','uid'].map(k=>[k,gate.parent[k as keyof typeof gate.parent]]))))fail();
  validateOriginalAdmissionClock(c.clock,c.deadline,c.startedAt);
  if(c.clock.originWallNs!==gate.clock.originWallNs||c.clock.originMonoNs!==gate.clock.originMonoNs)fail();
  admission.checkCleanup(c.deadline);const result=new OriginalBackendDisposalAdmission(SEAL,admission,Object.freeze({...gate.clock}),
   Object.freeze({...structuredClone(c),clock:Object.freeze({...c.clock}),parent:Object.freeze({...c.parent})}));
  // Signing/input authority ends here, even before its original expiry.
  admission.hold();result.check();return result;
 }
 deadline(){this.check();return this.continuation.deadline;}
 check(){
  if(!live.has(this)||this.held||this.original.status().unknown)fail();
  this.original.checkCleanup(this.continuation.deadline);
  const c=this.continuation.clock,now=process.hrtime.bigint();
  if(now<BigInt(c.originMonoNs)||now>=BigInt(c.deadlineMonoNs)||BigInt(Date.now())*1000000n>=BigInt(this.continuation.deadline)*1000000n)fail();
 }
 assertOriginalClock(clock:OriginalAdmissionClock){if(!isDeepStrictEqual(clock,this.prior))fail();this.check();}
 assertDispose(action:string,planSha256:string){this.check();if(action!=='dispose'||planSha256!==this.continuation.planSha256)fail();}
 hold(unknown=false){this.held=true;live.delete(this);this.original.hold(unknown);}
}
