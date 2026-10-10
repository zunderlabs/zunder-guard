// Root-only admission. A supplied record is expected public metadata, never a
// saved receipt or authority. Only a fresh owned source-pinned probe can mint.
import path from 'node:path';
import {isDeepStrictEqual} from 'node:util';
import {Admission,exact,hashString,fail,validateOriginalAdmissionClock,type OriginalAdmissionClock,type Config,type FileRef} from './policy.ts';
import {pinned,json,verifyTree,sha,canonical} from './files.ts';
import {startOwned,childEnvironment,guardedChildStdout} from './child.ts';
import {assertCompletionPipeIdentity,type CompletionPipeIdentity} from './completion-pipe.ts';
import type {ProtectedPurchaseController} from './protected-purchase.ts';

export interface OriginalParentIdentity {
 readonly pid:number;readonly start_ticks:number;readonly boot_id:string;readonly uid:number;
 readonly path:string;readonly argv:readonly string[];readonly environmentSha256:string;
}
export interface OriginalParentGate {
 readonly schema:1;readonly kind:'original-hosted-linux-completion-parent';
 readonly runId:string;readonly startedAt:number;readonly deadline:number;
 readonly clock:OriginalAdmissionClock;
 readonly parent:OriginalParentIdentity;readonly entrypoint:FileRef;
 readonly sourceManifestSha256:string;readonly runtimeManifest:FileRef;readonly gateProbe:FileRef;
 readonly pipe:CompletionPipeIdentity;readonly challenge:string;readonly controller:ProtectedPurchaseController;
}
export interface ActualParentGateReceipt {
 readonly schema:1;readonly kind:'actual-hosted-linux-keeper-gate';readonly runId:string;
 readonly startedAt:number;readonly deadline:number;readonly parent:OriginalParentIdentity;
 readonly clock:OriginalAdmissionClock;
 readonly pipe:CompletionPipeIdentity;readonly sourceManifestSha256:string;readonly runtimeManifestSha256:string;
 readonly coreDumpsDisabled:true;readonly noSwap:true;
}
export interface OriginalKeeperMetadata {
 readonly executable:FileRef;readonly entrypoint:FileRef;readonly argv:readonly string[];readonly environmentSha256:string;
}
export interface CompletionParentProbeInput {
 readonly schema:1;readonly gate:Readonly<OriginalParentGate>;readonly keeper:Readonly<OriginalKeeperMetadata>;
 readonly sourceManifest:FileRef;readonly sourceRoot:string;
}
const BRAND:unique symbol=Symbol('actual completion parent');
const admitted=new WeakSet<object>();
let parentClaimed=false;
export interface AdmittedCompletionParent {
 readonly [BRAND]:true;
 readonly binding:Readonly<OriginalParentGate>;
 /** Valid only while the original public pipe is still open. */
 assertAdmitted():void;
 recheckBeforeReceive():Promise<void>;
}
const safeInt=(v:unknown,min=0):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=min;
const uint64=(v:unknown):v is string=>typeof v==='string'&&/^(0|[1-9]\d*)$/.test(v)&&v.length<=20&&BigInt(v)<=(1n<<64n)-1n;
function ref(v:unknown):asserts v is FileRef {
 exact(v,['file','sha256']);
 if(typeof v.file!=='string'||!path.isAbsolute(v.file)||path.normalize(v.file)!==v.file||!hashString(v.sha256))fail();
}
function controller(v:unknown):asserts v is ProtectedPurchaseController {
 exact(v,['kind','boot','controlSource','planSha256','runNumber','attempt','parentPid','parentBirth']);
 if(v.kind!=='github-hosted'
  ||typeof v.boot!=='string'||!(/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/).test(v.boot)
  ||!hashString(v.planSha256)||typeof v.controlSource!=='string'||!(/^[0-9a-f]{40}$/).test(v.controlSource)
  ||!safeInt(v.runNumber,1)||!safeInt(v.attempt,1)||v.attempt>100||!safeInt(v.parentPid,1)
  ||typeof v.parentBirth!=='string'||!(/^[1-9][0-9]{0,19}$/).test(v.parentBirth))fail();
}
/** Pure shape/scope check only; this function cannot mint or run a gate. */
export function validateOriginalParentGate(raw:unknown,c:Config,
 actual:{platform:string;ppid:number;uid:number},now:number):asserts raw is OriginalParentGate {
 exact(raw,['schema','kind','runId','startedAt','deadline','clock','parent','entrypoint','sourceManifestSha256','runtimeManifest','gateProbe','pipe','challenge','controller']);
 exact(raw.parent,['pid','start_ticks','boot_id','uid','path','argv','environmentSha256']);
 exact(raw.pipe,['fd','device','inode','uid']);ref(raw.entrypoint);ref(raw.runtimeManifest);ref(raw.gateProbe);controller(raw.controller);
 const p=raw.parent;
 if(actual.platform!=='linux'||c.memoryPolicy!=='linux-no-swap'||raw.schema!==1||raw.kind!=='original-hosted-linux-completion-parent'
  ||raw.runId!==c.runId||raw.startedAt!==c.startedAt||raw.deadline!==c.expires
  ||!safeInt(raw.startedAt)||!safeInt(raw.deadline)||!safeInt(now)||now<raw.startedAt||now>=raw.deadline
  ||raw.deadline<=raw.startedAt||raw.deadline-raw.startedAt>3600000||raw.sourceManifestSha256!==c.coordinator.manifest.sha256
  ||!hashString(raw.challenge)||!safeInt(p.pid,1)||p.pid!==actual.ppid||!safeInt(p.start_ticks,1)||p.boot_id!==raw.controller.boot
  ||!safeInt(p.uid)||p.uid!==actual.uid||p.path!==c.executables.python.file||!hashString(p.environmentSha256)
  ||!Array.isArray(p.argv)||p.argv.length<1||p.argv.length>32||p.argv.some(v=>typeof v!=='string'||v.length<1||v.length>4096||!/^[\x20-\x7e]+$/.test(v))
  ||raw.pipe.fd!==3||!uint64(raw.pipe.device)||!uint64(raw.pipe.inode)||raw.pipe.uid!==actual.uid
  ||raw.gateProbe.file!==path.join(c.coordinator.root,'deploy/guard/e2e/hosted_journey/keeper_gate.py')
  ||!raw.entrypoint.file.startsWith(c.coordinator.root+'/')||raw.entrypoint.file===raw.gateProbe.file)fail();
 validateOriginalAdmissionClock(raw.clock,raw.deadline,raw.startedAt);
}
/** Exact fresh-probe output comparison; no saved receipt can grant admission. */
export function validateActualParentGateReceipt(raw:unknown,g:OriginalParentGate):void {
 exact(raw,['schema','kind','runId','startedAt','deadline','clock','parent','pipe','sourceManifestSha256','runtimeManifestSha256','coreDumpsDisabled','noSwap']);
 if(raw.schema!==1||raw.kind!=='actual-hosted-linux-keeper-gate'||raw.runId!==g.runId||raw.startedAt!==g.startedAt||raw.deadline!==g.deadline
  ||!isDeepStrictEqual(raw.clock,g.clock)||!isDeepStrictEqual(raw.parent,g.parent)||!isDeepStrictEqual(raw.pipe,g.pipe)||raw.sourceManifestSha256!==g.sourceManifestSha256
  ||raw.runtimeManifestSha256!==g.runtimeManifest.sha256||raw.coreDumpsDisabled!==true||raw.noSwap!==true)fail();
}
function freezeGate(g:OriginalParentGate):Readonly<OriginalParentGate> {
 return Object.freeze({...g,parent:Object.freeze({...g.parent,argv:Object.freeze([...g.parent.argv])}),
  entrypoint:Object.freeze({...g.entrypoint}),runtimeManifest:Object.freeze({...g.runtimeManifest}),gateProbe:Object.freeze({...g.gateProbe}),
  pipe:Object.freeze({...g.pipe}),controller:Object.freeze({...g.controller}),clock:Object.freeze({...g.clock})});
}
/** Python json.dumps(sort_keys=True, ensure_ascii=True, separators=(',',':')).
 * Only the digest crosses the public pipe; environment values never do. */
export function completionEnvironmentSha256(values:Record<string,string>):string {
 if(!values||typeof values!=='object'||Array.isArray(values))fail();
 for(const[key,value]of Object.entries(values))if(!/^[\x20-\x7e]+$/.test(key)||typeof value!=='string')fail();
 const sorted=Object.fromEntries(Object.keys(values).sort().map(key=>[key,values[key]]));
 return sha(JSON.stringify(sorted).replace(/[\u007f-\uffff]/g,ch=>'\\u'+ch.charCodeAt(0).toString(16).padStart(4,'0')));
}
/** Supplied original public metadata must match the actual keeper. It is not
 * inferred from currently running argv, and cannot alone admit the parent. */
export function validateOriginalKeeperMetadata(raw:unknown,c:Config,actual:{argv:readonly string[];environmentSha256:string}):asserts raw is OriginalKeeperMetadata {
 exact(raw,['executable','entrypoint','argv','environmentSha256']);ref(raw.executable);ref(raw.entrypoint);
 const entrypoint=raw.entrypoint.file;
 if(!isDeepStrictEqual(raw.executable,c.executables.node)||!hashString(raw.environmentSha256)
  ||raw.environmentSha256!==actual.environmentSha256||!Array.isArray(raw.argv)||raw.argv.length!==5
  ||raw.argv.some(v=>typeof v!=='string'||v.length<1||v.length>4096||!/^[\x20-\x7e]+$/.test(v))
  ||raw.argv[0]!==c.executables.node.file||raw.argv[1]!=='--no-global-search-paths'||raw.argv[2]!=='--no-addons'
  ||raw.argv[3]!==raw.entrypoint.file||!path.isAbsolute(raw.argv[4])||path.normalize(raw.argv[4])!==raw.argv[4]
  ||!isDeepStrictEqual(raw.argv,actual.argv)
  ||![c.website.root,c.coordinator.root].some(root=>entrypoint.startsWith(root+'/')))fail();
}
/** Initial gate is exact; later checks retain it while the SAME admission may
 * irreversibly tighten to the shorter purchase budget. No extension is valid. */
export function assertCompletionParentDeadline(original:number,a:Admission,initial=false):void {
 a.check();
 if(!safeInt(original)||a.deadline()>original||(initial&&a.deadline()!==original))fail();
}
const keeperArgv=()=>[process.execPath,...process.execArgv,...process.argv.slice(1)];
/** Runtime inventory validation is inert; caller still hashes every actual file. */
export function validateCompletionRuntimeManifest(raw:unknown,c:Config):asserts raw is {schema:1;files:Record<string,string>;roots:{python:string;node:string;packages:string}} {
 exact(raw,['schema','files','roots']);
 if(raw.schema!==1||!raw.files||typeof raw.files!=='object'||Array.isArray(raw.files))fail();
 const rows=Object.entries(raw.files);
 if(rows.length<5||rows.length>20000)fail();
 for(const expected of[c.executables.node,c.executables.python])if((raw.files as Record<string,unknown>)[expected.file]!==expected.sha256)fail();
 exact(raw.roots,['python','node','packages']);for(const value of Object.values(raw.roots))if(typeof value!=='string'||!path.isAbsolute(value))fail();
 for(const[file,hash]of rows)if(!path.isAbsolute(file)||path.normalize(file)!==file||!hashString(hash))fail();
}
/** Source-only implementation: production admission requires the actual Flow
 * probe in the authenticated coordinator closure, never an injected callback. */
export async function admitCompletionParent(raw:OriginalParentGate,cfg:Config,a:Admission,originalKeeper:OriginalKeeperMetadata):Promise<AdmittedCompletionParent> {
 let gate:Readonly<OriginalParentGate>,c:Config,keeper:Readonly<OriginalKeeperMetadata>;
 try {
  if(parentClaimed)fail();parentClaimed=true;
  c=structuredClone(cfg);gate=freezeGate(structuredClone(raw));
  const k=structuredClone(originalKeeper);
  keeper=Object.freeze({...k,executable:Object.freeze({...k.executable}),entrypoint:Object.freeze({...k.entrypoint}),argv:Object.freeze([...k.argv])});
  if(!(a instanceof Admission))fail();
  validateOriginalParentGate(gate,c,{platform:process.platform,ppid:process.ppid,uid:process.getuid?.()??-1},Date.now());
  validateOriginalKeeperMetadata(keeper,c,{argv:keeperArgv(),environmentSha256:completionEnvironmentSha256(process.env as Record<string,string>)});
  assertCompletionParentDeadline(gate.deadline,a,true);
  a.assertOriginalClock(gate.clock);
 }catch{a.hold(true);fail();}
 const guard=()=>{
  try {
  assertCompletionParentDeadline(gate.deadline,a);
  a.assertOriginalClock(gate.clock);
  if(process.ppid!==gate.parent.pid||process.getuid?.()!==gate.parent.uid)fail();
  validateOriginalKeeperMetadata(keeper,c,{argv:keeperArgv(),environmentSha256:completionEnvironmentSha256(process.env as Record<string,string>)});
  assertCompletionPipeIdentity(gate.pipe);a.check();
  }catch{a.hold(true);fail();}
 };
 const source=async()=>{
  guard();
  const entry=path.relative(c.coordinator.root,gate.entrypoint.file),probe=path.relative(c.coordinator.root,gate.gateProbe.file);
  const files=await verifyTree(c.coordinator,[entry,probe,'deploy/guard/e2e/hosted_journey/linux_identity.py']);guard();
  if(files[entry]!==gate.entrypoint.sha256||files[probe]!==gate.gateProbe.sha256)fail();
  if((await canonical(process.execPath))!==keeper.executable.file||(await canonical(process.argv[1]!))!==keeper.entrypoint.file)fail();guard();
  let keeperFiles=files,keeperRoot=c.coordinator.root;
  if(!keeper.entrypoint.file.startsWith(keeperRoot+'/')){
   keeperRoot=c.website.root;keeperFiles=await verifyTree(c.website,[path.relative(keeperRoot,keeper.entrypoint.file)]);guard();
  }
  if(keeperFiles[path.relative(keeperRoot,keeper.entrypoint.file)]!==keeper.entrypoint.sha256)fail();
  await pinned(keeper.entrypoint,26214400,false);guard();
  await pinned(gate.entrypoint,26214400,false);guard();await pinned(gate.gateProbe,26214400,false);guard();
  const manifest:unknown=await json(gate.runtimeManifest);guard();validateCompletionRuntimeManifest(manifest,c);
  for(const[file,sha256]of Object.entries(manifest.files)){await pinned({file,sha256},200000000,false);guard();}
 };
 const probe=async()=>{
  try {
   await source();guard();
   const wrapper:CompletionParentProbeInput={schema:1,gate,keeper,sourceManifest:c.coordinator.manifest,sourceRoot:c.coordinator.root};
   const input=Buffer.from(JSON.stringify(wrapper));
   const child=startOwned(c.executables.python.file,['-I','-S','-B',gate.gateProbe.file],c.coordinator.root,
    childEnvironment(c),input,a.deadline(),process.kill.bind(process),3);
   const result=await child.done;
   try {
    guardedChildStdout(result.stdout,guard);
    if(result.code!==0||result.signal!==null||!result.bounded||!result.groupGone||result.forced)fail();
    const receipt:unknown=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(result.stdout));
    validateActualParentGateReceipt(receipt,gate);guard();
   }finally{result.stdout.fill(0);}
   await source();guard();
  }catch{a.hold(true);fail();}
 };
 await probe();guard();
 const value:AdmittedCompletionParent=Object.freeze({[BRAND]:true as const,binding:gate,
  assertAdmitted(){if(!admitted.has(value))fail();guard();},
  async recheckBeforeReceive(){if(!admitted.has(value))fail();await probe();guard();}});
 admitted.add(value);return value;
}
