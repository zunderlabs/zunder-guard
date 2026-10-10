// Inert clock regressions: no runtime, source, private or cloud operations.
import {test} from 'node:test';import assert from 'node:assert/strict';
import {Admission,validateOriginalAdmissionClock,type OriginalAdmissionClock} from './policy.ts';
const START=1791600000000,TWENTY=1200000,SIXTY=3600000;
test('sixty to twenty-minute tightening keeps the first monotonic cutoff after wall rollback',()=>{
 let wall=START,mono=0;const a=new Admission(START+SIXTY,()=>wall,()=>mono);
 wall=START-600000;mono=300000;a.tighten(START+TWENTY);
 assert.equal(a.deadline(),START+TWENTY);mono=TWENTY-1;a.check();
 mono=1200001;assert.throws(()=>a.check());assert.equal(a.status().held,true);
 wall=START;mono=0;assert.throws(()=>a.check()); // expiration is irreversible
});
test('tightening immediately refuses if the first projected shorter monotonic cutoff already elapsed',()=>{
 let wall=START,mono=54321;const origin=mono,a=new Admission(START+SIXTY,()=>wall,()=>mono);
 wall=START-600000;mono=origin+1200001;
 assert.throws(()=>a.tighten(START+TWENTY));assert.equal(a.status().held,true);
});
test('repeated shortening never resets first origins or permits extension',()=>{
 let wall=START,mono=9000;const origin=mono,a=new Admission(START+SIXTY,()=>wall,()=>mono);
 mono=origin+1000;a.tighten(START+TWENTY);wall=START-100000;mono=origin+2000;a.tighten(START+600000);
 assert.throws(()=>a.tighten(START+TWENTY));assert.equal(a.deadline(),START+600000);
 mono=origin+600000;assert.throws(()=>a.check());
});
test('wall expiry and unknown latches remain effective when monotonic time has not expired',()=>{
 let wall=START,mono=0;const a=new Admission(START+SIXTY,()=>wall,()=>mono);
 a.tighten(START+TWENTY);wall=START+TWENTY;assert.throws(()=>a.check());
 const b=new Admission(START+SIXTY,()=>START,()=>0);b.hold(true);
 assert.throws(()=>b.tighten(START+TWENTY));assert.equal(b.status().unknown,true);
});
test('cleanup cutoff continues to derive from the same first projected deadline after tightening',()=>{
 let wall=START,mono=0;const a=new Admission(START+SIXTY,()=>wall,()=>mono);
 mono=300000;a.tighten(START+TWENTY);a.hold(true);
 wall=START+TWENTY;mono=TWENTY+299999;a.checkCleanup(START+TWENTY+300000);
 mono=TWENTY+300000;assert.throws(()=>a.checkCleanup(START+TWENTY+300000));
 assert.throws(()=>a.check());assert.equal(a.status().unknown,true);
});
const originalClock=(end=START+SIXTY):OriginalAdmissionClock=>({domain:'darwin-mach-continuous-time-ns-v1',originWallNs:String(BigInt(START)*1000000n+123n),
 originMonoNs:'9000000000000',deadlineMonoNs:String(9000000000000n+BigInt(end)*1000000n-(BigInt(START)*1000000n+123n))});
test('inherited P0 continuous cutoff expires despite later P1 wall rollback and locally live performance budget',t=>{
 const c=originalClock();let continuous=BigInt(c.originMonoNs)+300000000000n;
 t.mock.method(process.hrtime,'bigint',()=>continuous);
 const a=new Admission(START+SIXTY,()=>START,()=>300000,{clock:c});a.check();
 continuous=BigInt(c.deadlineMonoNs);assert.throws(()=>a.check());assert.equal(a.status().held,true);
});
test('protected shortening uses exact first P0 nano pair, never integer rounding or renewed origin',t=>{
 const c=originalClock();let continuous=BigInt(c.originMonoNs)+1000000000n,wall=START,mono=1000;
 t.mock.method(process.hrtime,'bigint',()=>continuous);
 const a=new Admission(START+SIXTY,()=>wall,()=>mono,{clock:c});
 wall=START-600000;a.tighten(START+TWENTY);
 const cutoff=BigInt(c.originMonoNs)+BigInt(START+TWENTY)*1000000n-BigInt(c.originWallNs);
 continuous=cutoff-1n;a.check();continuous=cutoff;assert.throws(()=>a.check());
});
test('inherited clock is copied and immutable and cannot be added, offset, or replaced after admission',t=>{
 const c=originalClock();t.mock.method(process.hrtime,'bigint',()=>BigInt(c.originMonoNs));
 const saved={...c},a=new Admission(START+SIXTY,()=>START,()=>0,{clock:c});
 Object.assign(c,{deadlineMonoNs:String(BigInt(c.deadlineMonoNs)+100n)});
 a.assertOriginalClock(saved);assert.throws(()=>a.assertOriginalClock(c));
 const ordinary=new Admission(START+SIXTY,()=>START,()=>0);assert.throws(()=>ordinary.assertOriginalClock(saved));
 assert.throws(()=>new Admission(START+SIXTY,()=>START,()=>0,{clock:saved,readContinuousNs:()=>0n} as {clock:OriginalAdmissionClock}));
});
test('incompatible continuous origin refuses instead of computing or adopting a cross-domain offset',t=>{
 const c=originalClock();t.mock.method(process.hrtime,'bigint',()=>BigInt(c.originMonoNs)-1n);
 const a=new Admission(START+SIXTY,()=>START,()=>0,{clock:c});assert.throws(()=>a.check());
});
test('both local performance and inherited continuous bounds stay active, including inherited cleanup ceiling',t=>{
 const c=originalClock();let continuous=BigInt(c.originMonoNs),mono=0;
 t.mock.method(process.hrtime,'bigint',()=>continuous);
 const a=new Admission(START+SIXTY,()=>START,()=>mono,{clock:c});mono=SIXTY;assert.throws(()=>a.check());
 mono=0;const b=new Admission(START+SIXTY,()=>START,()=>mono,{clock:c});b.tighten(START+TWENTY);b.hold(true);
 const cutoff=BigInt(c.originMonoNs)+BigInt(START+TWENTY)*1000000n-BigInt(c.originWallNs)+300000000000n;
 continuous=cutoff-1n;b.checkCleanup(START+TWENTY+300000);continuous=cutoff;assert.throws(()=>b.checkCleanup(START+TWENTY+300000));
 assert.equal(b.status().unknown,true);
});
test('public inherited clock validates exact uint64 range and nano projection without floating point',()=>{
 const c=originalClock();validateOriginalAdmissionClock(c,START+SIXTY,START);
 for(const change of[{domain:'python-monotonic'},{originWallNs:'1e18'},{originMonoNs:'01'},
  {deadlineMonoNs:String(BigInt(c.deadlineMonoNs)+1n)},{originWallNs:String(BigInt(START)*1000000n-1n)},
  {deadlineMonoNs:'18446744073709551616'},{extra:true}])assert.throws(()=>validateOriginalAdmissionClock({...c,...change},START+SIXTY,START));
});
