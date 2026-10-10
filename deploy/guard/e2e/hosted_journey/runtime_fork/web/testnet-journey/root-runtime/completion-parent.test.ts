// Inert public fixtures only. These validators never mint actual admission.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync,realpathSync} from 'node:fs';
import {sha} from './files.ts';
import {validateOriginalParentGate,validateActualParentGateReceipt,validateCompletionRuntimeManifest,
 validateOriginalKeeperMetadata,completionEnvironmentSha256,assertCompletionParentDeadline,
 type OriginalParentGate,type ActualParentGateReceipt} from './completion-parent.ts';
import {OPT_IN,Admission,type Config,type OriginalAdmissionClock} from './policy.ts';
const NOW=1800000000000,h='a'.repeat(64),f=(file:string)=>({file,sha256:h});
const config:Config={version:1,optIn:OPT_IN,runId:'11111111-2222-4333-8444-555555555555',startedAt:NOW,expires:NOW+1200000,
 evidenceDirectory:'/public/evidence',website:{root:'/website',manifest:f('/public/website.json')},
 coordinator:{root:'/coordinator',manifest:f('/public/coordinator.json')},
 executables:{node:f('/public/node'),python:f('/public/python'),aws:f('/public/aws')},
 awsConfig:f('/public/aws-config'),awsProfile:'inert',home:'/public/home',memoryPolicy:'mac-encrypted-swap'};
const clock=(end:number=config.expires):OriginalAdmissionClock=>({domain:'darwin-mach-continuous-time-ns-v1',originWallNs:String(BigInt(NOW)*1000000n+123n),
 originMonoNs:'9000000000000',deadlineMonoNs:String(9000000000000n+BigInt(end)*1000000n-(BigInt(NOW)*1000000n+123n))});
const gate:OriginalParentGate={schema:1,kind:'original-stable-mac-completion-parent',runId:config.runId,startedAt:NOW,deadline:config.expires,
 clock:clock(),
 parent:{pid:123,start_sec:1799999900,start_usec:12345,uid:501,path:config.executables.python.file,
 argv:['/public/python','-I','-S','-B','/coordinator/deploy/guard/e2e/keeper_parent.py'],environmentSha256:h},
 entrypoint:f('/coordinator/deploy/guard/e2e/keeper_parent.py'),sourceManifestSha256:h,runtimeManifest:f('/public/runtime.json'),
 gateProbe:f('/coordinator/deploy/guard/e2e/keeper_parent_gate.py'),pipe:{fd:3,device:'1',inode:'18446744073709551615',uid:501},challenge:h,
 controller:{instance:'i-'+'a'.repeat(17),boot:'11111111-2222-3333-4444-555555555555',hostKeySha256:h,
 controlSource:'b'.repeat(40),planSha256:h,runNumber:12345,attempt:1,parentPid:10,parentBirth:'123456'}};
const actual={platform:'darwin',ppid:123,uid:501};
const receipt:ActualParentGateReceipt={schema:1,kind:'actual-stable-mac-keeper-gate',runId:gate.runId,startedAt:NOW,deadline:gate.deadline,
 clock:gate.clock,
 parent:gate.parent,pipe:gate.pipe,sourceManifestSha256:h,runtimeManifestSha256:h,coreDumpsDisabled:true,encryptedSwap:true,fileVault:true};
const check=(v:unknown=gate,c=config,a=actual,now=NOW)=>validateOriginalParentGate(v,c,a,now);
test('exact public gate and receipt validate without minting or I/O',()=>{check();validateActualParentGateReceipt(receipt,gate);});
test('original run, start, absolute end and original sixty minute gate cannot be rebased',()=>{
 for(const v of[{...gate,runId:'22222222-2222-4333-8444-555555555555'},{...gate,startedAt:NOW+1},
  {...gate,deadline:gate.deadline-1},{...gate,deadline:NOW+1200001}])assert.throws(()=>check(v));
 assert.throws(()=>check(gate,config,actual,NOW-1));assert.throws(()=>check(gate,config,actual,gate.deadline));
 const original={...gate,deadline:NOW+3600000,clock:clock(NOW+3600000)};
 check(original,{...config,expires:original.deadline});
 assert.throws(()=>check({...gate,deadline:NOW+3600001},{...config,expires:NOW+3600001}));
});
test('same original admission may tighten before receive but cannot extend or revive expiry',()=>{
 let wall=NOW,mono=0;
 const a=new Admission(NOW+3600000,()=>wall,()=>mono);
 assertCompletionParentDeadline(NOW+3600000,a,true);
 a.tighten(NOW+1200000);assertCompletionParentDeadline(NOW+3600000,a);
 assert.equal(a.deadline(),NOW+1200000);
 assert.throws(()=>assertCompletionParentDeadline(NOW+3600000,a,true));
 assert.throws(()=>assertCompletionParentDeadline(NOW+1199999,a));
 assert.throws(()=>a.tighten(NOW+3600000));
 wall=NOW+1200000;mono=1200000;
 assert.throws(()=>assertCompletionParentDeadline(NOW+3600000,a));
});
test('equal UTC deadline alone cannot satisfy the inherited-clock assertion used by direct admission',t=>{
 t.mock.method(process.hrtime,'bigint',()=>BigInt(gate.clock.originMonoNs));
 const ordinary=new Admission(gate.deadline,()=>NOW,()=>0);
 assertCompletionParentDeadline(gate.deadline,ordinary,true);
 assert.throws(()=>ordinary.assertOriginalClock(gate.clock));
 const protectedAdmission=new Admission(gate.deadline,()=>NOW,()=>0,{clock:gate.clock});
 protectedAdmission.assertOriginalClock(gate.clock);
 assert.throws(()=>protectedAdmission.assertOriginalClock({...gate.clock,originMonoNs:String(BigInt(gate.clock.originMonoNs)+1n)}));
});
test('Mac memory policy and actual direct parent UID/PID are mandatory',()=>{
 for(const a of[{...actual,platform:'linux'},{...actual,uid:0},{...actual,ppid:124}])assert.throws(()=>check(gate,config,a));
 assert.throws(()=>check(gate,{...config,memoryPolicy:'linux-no-swap'}));
 assert.throws(()=>check({...gate,parent:{...gate.parent,path:'/usr/bin/python3'}}));
});
test('birth, bounded public argv and exact environment digest are strict',()=>{
 for(const p of[{...gate.parent,start_sec:0},{...gate.parent,start_usec:1000000},{...gate.parent,start_usec:0.5},
  {...gate.parent,argv:[]},{...gate.parent,argv:['bad\nargv']},{...gate.parent,argv:['x'.repeat(4097)]},
  {...gate.parent,environmentSha256:'wrong'},{...gate.parent,extra:true}])assert.throws(()=>check({...gate,parent:p}));
});
test('source manifest, fixed probe and declared coordinator entrypoint cannot move',()=>{
 for(const v of[{...gate,sourceManifestSha256:'c'.repeat(64)},
  {...gate,gateProbe:f('/coordinator/deploy/guard/e2e/other.py')},{...gate,entrypoint:f('/elsewhere/start.py')},
  {...gate,entrypoint:f('/coordinator/../start.py')},{...gate,entrypoint:gate.gateProbe},
  {...gate,runtimeManifest:{...gate.runtimeManifest,sha256:'bad'}}])assert.throws(()=>check(v));
});
test('pipe identity is exact fixed fd3 and canonical unsigned64',()=>{
 for(const p of[{...gate.pipe,fd:4},{...gate.pipe,device:'01'},{...gate.pipe,inode:'-1'},
  {...gate.pipe,inode:'18446744073709551616'},{...gate.pipe,uid:502},{...gate.pipe,extra:true}])assert.throws(()=>check({...gate,pipe:p}));
});
test('controller enrollment and challenge have exact shapes and positive identifiers',()=>{
 for(const c of[{...gate.controller,attempt:101},{...gate.controller,parentBirth:'01'},{...gate.controller,runNumber:0},
  {...gate.controller,hostKeySha256:'bad'},{...gate.controller,extra:true}])assert.throws(()=>check({...gate,controller:c}));
 assert.throws(()=>check({...gate,challenge:'bad'}));assert.throws(()=>check({...gate,extra:true}));
});
test('fresh receipt cannot change original parent, pipe, scope, source or runtime',()=>{
 for(const v of[{...receipt,parent:{...receipt.parent,start_usec:receipt.parent.start_usec+1}},
  {...receipt,parent:{...receipt.parent,argv:[...receipt.parent.argv,'changed']}},{...receipt,pipe:{...receipt.pipe,inode:'2'}},
  {...receipt,deadline:receipt.deadline+1},{...receipt,sourceManifestSha256:'b'.repeat(64)},
  {...receipt,runtimeManifestSha256:'b'.repeat(64)},{...receipt,runId:'wrong'},{...receipt,extra:true}])assert.throws(()=>validateActualParentGateReceipt(v,gate));
});
test('original clock requires exact continuous domain, canonical uint64 nanoseconds and original range/projection',()=>{
 for(const change of[{domain:'python-monotonic'},{originWallNs:'01'},{originWallNs:String(BigInt(NOW)*1000000n-1n)},
  {originWallNs:String(BigInt(gate.deadline)*1000000n)},{originMonoNs:'-1'},{originMonoNs:'18446744073709551616'},
  {deadlineMonoNs:String(BigInt(gate.clock.deadlineMonoNs)+1n)},{originMonoNs:9000},{extra:true}])assert.throws(()=>check({...gate,clock:{...gate.clock,...change}}));
 for(const key of Object.keys(gate.clock)){const c={...gate.clock}as Record<string,unknown>;delete c[key];assert.throws(()=>check({...gate,clock:c}));}
 const missing={...gate}as Record<string,unknown>;delete missing.clock;assert.throws(()=>check(missing));
});
test('actual source/domain receipt must preserve the exact original clock, with no rebasing or offset',()=>{
 for(const change of[{domain:'python-monotonic'},{originMonoNs:String(BigInt(gate.clock.originMonoNs)+1n)},
  {originWallNs:String(BigInt(gate.clock.originWallNs)+1n)},{deadlineMonoNs:String(BigInt(gate.clock.deadlineMonoNs)+1n)},
  {offset:'0'}])assert.throws(()=>validateActualParentGateReceipt({...receipt,clock:{...gate.clock,...change}},gate));
 const missing={...receipt}as Record<string,unknown>;delete missing.clock;assert.throws(()=>validateActualParentGateReceipt(missing,gate));
});
test('all three actual OS protections must be true in the exact receipt',()=>{
 for(const key of['coreDumpsDisabled','encryptedSwap','fileVault'])for(const value of[false,1,'true',undefined])
  assert.throws(()=>validateActualParentGateReceipt({...receipt,[key]:value},gate));
});
const runtime={schema:1,files:{'/public/node':h,'/public/python':h,'/bin/ps':h,'/usr/sbin/sysctl':h,'/usr/bin/fdesetup':h}};
test('runtime manifest pins both executables and all actual Mac gate tools',()=>{
 validateCompletionRuntimeManifest(runtime,config);
 for(const key of Object.keys(runtime.files)){
  const missing:Record<string,string>={...runtime.files};delete missing[key];
  assert.throws(()=>validateCompletionRuntimeManifest({...runtime,files:missing},config));
  if(key==='/public/node'||key==='/public/python')assert.throws(()=>validateCompletionRuntimeManifest({...runtime,files:{...runtime.files,[key]:'b'.repeat(64)}},config));
 }
});
test('runtime inventory refuses relative/traversal paths, malformed hashes and extra fields',()=>{
 for(const v of[{...runtime,extra:true},{...runtime,files:{...runtime.files,'relative':h}},
  {...runtime,files:{...runtime.files,'/public/../bad':h}},{...runtime,files:{...runtime.files,'/public/other':'bad'}}])
  assert.throws(()=>validateCompletionRuntimeManifest(v,config));
});
test('keeper metadata matches supplied original argv, executable, pinned launcher and actual environment digest',()=>{
 const argv=['/public/node','--no-global-search-paths','--no-addons','/coordinator/keeper-launcher.mjs','/public/config.json'];
 const keeper={executable:config.executables.node,entrypoint:f(argv[3]!),argv,environmentSha256:h};
 validateOriginalKeeperMetadata(keeper,config,{argv,environmentSha256:h});
 for(const v of[{...keeper,argv:[...argv,'new']},{...keeper,executable:f('/other/node')},
  {...keeper,entrypoint:f('/other/keeper.mjs')},{...keeper,environmentSha256:'b'.repeat(64)},
  {...keeper,argv:[argv[0],'/coordinator/other.mjs']},{...keeper,extra:true}])
  assert.throws(()=>validateOriginalKeeperMetadata(v,config,{argv,environmentSha256:h}));
});
test('full OS keeper argv requires exact fixed flag prefix and exactly one public config path',()=>{
 const argv=['/public/node','--no-global-search-paths','--no-addons','/coordinator/keeper-launcher.mjs','/public/config.json'];
 const keeper={executable:config.executables.node,entrypoint:f(argv[3]!),argv,environmentSha256:h};
 for(const wrong of[argv.filter(v=>v!=='--no-addons'),[argv[0],argv[2],argv[1],...argv.slice(3)],
  [...argv,'--extra'],[argv[0],'--no-global-search-paths','--no-addons=false',...argv.slice(3)],
  [...argv.slice(0,4),'relative-config.json'],[argv[0],...argv.slice(3)]])
  assert.throws(()=>validateOriginalKeeperMetadata({...keeper,argv:wrong},config,{argv:wrong as string[],environmentSha256:h}));
});
test('environment digest is order independent and matches compact sorted ASCII Python JSON bytes',()=>{
 const a=completionEnvironmentSha256({Z:'ä😀\u007f',A:'line\nquote"'});
 assert.equal(a,completionEnvironmentSha256({A:'line\nquote"',Z:'ä😀\u007f'}));
 // Independently computed with /usr/bin/python3 json.dumps; public fixture only.
 assert.equal(a,'26db99088ffe4e86491afdfe2b66153461c6751802b079fce7e7179b7fda131c');
 assert.notEqual(a,completionEnvironmentSha256({A:'changed',Z:'ä😀\u007f'}));
 assert.throws(()=>completionEnvironmentSha256({'nön-ascii-key':'value'}));
});
test('actual public pipe checks do not consume and only explicitly scoped probe inherits fd3',()=>{
 const node=realpathSync(process.execPath),digest=sha(readFileSync(node));
 const pipeUrl=new URL('./completion-pipe.ts',import.meta.url).href,childUrl=new URL('./child.ts',import.meta.url).href;
 const code=[
  'import fs from "node:fs";',
  'import{assertCompletionPipeIdentity}from'+JSON.stringify(pipeUrl)+';',
  'import{startOwned}from'+JSON.stringify(childUrl)+';',
  'const identity=JSON.parse(process.argv[1]);assertCompletionPipeIdentity(identity);assertCompletionPipeIdentity(identity);',
  'const source="import os,json\\ntry: s=os.fstat(3); ok=s.st_ino=="+identity.inode+" and s.st_dev=="+identity.device+"\\nexcept OSError: ok=False\\nprint(json.dumps({\\\"inherited\\\":ok}))";',
  'const run=async(inherit)=>{const r=await startOwned("/usr/bin/python3",["-I","-S","-B","-c",source],"/",{PATH:"/usr/bin:/bin"},Buffer.alloc(0),Date.now()+2000,process.kill.bind(process),inherit).done;try{if(r.code!==0||!r.groupGone||r.forced||!r.bounded)throw Error("probe failed");return JSON.parse(r.stdout.toString()).inherited;}finally{r.stdout.fill(0);}};',
  'const defaultClosed=!(await run(undefined)),explicitInherited=await run(3);assertCompletionPipeIdentity(identity);fs.closeSync(3);console.log(JSON.stringify({defaultClosed,explicitInherited}));',
 ].join('\n');
 const python=[
  'import os,sys,json,hashlib,subprocess',
  'node,digest,code=sys.argv[1:];assert hashlib.sha256(open(node,"rb").read()).hexdigest()==digest',
  'r,w=os.pipe()',
  'if r!=3: os.dup2(r,3)',
  's=os.fstat(3);identity={"fd":3,"device":str(s.st_dev),"inode":str(s.st_ino),"uid":s.st_uid}',
  'p=subprocess.run([node,"--input-type=module","-e",code,json.dumps(identity)],pass_fds=(3,),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=6)',
  'os.close(w);os.close(3);assert p.returncode==0,p.stderr.decode();print(p.stdout.decode(),end="")',
 ].join('\n');
 const result=spawnSync('/usr/bin/python3',['-I','-S','-B','-c',python,node,digest,code],{encoding:'utf8',timeout:10000,maxBuffer:16384});
 assert.equal(result.status,0,result.stderr);
 assert.deepEqual(JSON.parse(result.stdout.trim()),{defaultClosed:true,explicitInherited:true});
});
