// Data-only original assembly. These validators never authenticate an original parent.
import {createHash} from 'node:crypto';
import {constants} from 'node:fs';
import {lstat,mkdir,open,realpath} from 'node:fs/promises';
import path from 'node:path';
import {ACCOUNT,PROTOCOL,digest,makePlan,validateContext,validatePlan,validateSnapshot,type Context,type Snapshot,type RetainedPlan} from './plan.ts';
import {parseReleasePin,assertPublishedReleaseProfile} from '../runtime_fork/web/release-pin.ts';
import {verifyStagingManifest,verifyStagingWalletPage} from '../runtime_fork/web/testnet-journey/provision/wallet-policy.ts';

export interface ByteSubject {path:string;bytes:Uint8Array}
export interface ArtifactManifest {version:1;merchant:string;publicKey:string;files:{path:string;sha256:string}[]}
export interface ControllerManifest {schema:1;protocol:typeof PROTOCOL;files:{path:string;sha256:string}[]}
export interface DraftReference {receiptFile:string;receiptSha256:string}
export interface Approval {planHash:string;account:typeof ACCOUNT;rootApproved:true;noPlanUpgrade:true;prerequisitesVerified:true;artifactManifestSha256:string;controllerManifestSha256:string;maxIncrementalCents:500;expires:number;draftReleaseAcceptance?:DraftReference}
export interface PreparedAssembly {context:Context;snapshot:Snapshot;plan:RetainedPlan;approval:Approval;artifactManifest:ArtifactManifest;controllerManifest:ControllerManifest;artifacts:ByteSubject[];controllerSources:ByteSubject[]}
export interface FileRef {file:string;sha256:string}
export interface ProvisionInput {plan:FileRef;approval:FileRef;artifactDirectory:string;artifactManifest:FileRef;controllerManifest:FileRef;journalDirectory:string}
export const CONTROLLER_REQUIRED=Object.freeze(['plan.ts','readback.ts','assemble.ts','run.ts','transport.ts','driver.ts','journal-port.ts','journal-frame.ts',
 '@runtime/policy.ts','@runtime/release-pin.ts','@runtime/wallet-policy.ts','@runtime/draft-release.ts',
 '@public-tools/package.json','@public-tools/package-lock.json','@noble/blake3.js','@noble/_md.js','@noble/_u64.js','@noble/blake2.js','@noble/_blake.js','@noble/utils.js','@noble/package.json','@noble/LICENSE']);
export const ARTIFACT_REQUIRED=Object.freeze(['api.js','inbox.js','migrations/0001_init.sql','migrations/0002_licences.sql','migrations/0003_licence_watch_start.sql','migrations/0004_licence_renewal.sql','migrations/0001_inbox.sql',
 'pages/_worker.js','pages/_headers','pages/_routes.json','pages/index.html','pages/licence.html','pages/approve.html','pages/deployment-profile.json','pages/release-pin.json']);
const MAX_FILE=8*1024*1024,MAX_TOTAL=32*1024*1024,MAX_FILES=1024;
function refuse():never{throw new Error('Original retained backend assembly refused');}
function require(ok:unknown):asserts ok{if(!ok)refuse();}
function object(v:unknown):Record<string,unknown>{require(v&&typeof v==='object'&&!Array.isArray(v)&&Object.getPrototypeOf(v)===Object.prototype);return v as Record<string,unknown>;}
function exact(v:unknown,keys:readonly string[]){const o=object(v);require(Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k)));return o;}
function hash(v:unknown):asserts v is string{require(typeof v==='string'&&/^[0-9a-f]{64}$/.test(v)&&!/^0{64}$/.test(v));}
export function sha(bytes:Uint8Array):string{return createHash('sha256').update(bytes).digest('hex');}
export function jsonBytes(value:unknown):Uint8Array{return new TextEncoder().encode(JSON.stringify(value));}
function relative(v:unknown):asserts v is string{
 require(typeof v==='string'&&v.length<=512&&!v.startsWith('/')&&v.split('/').every(p=>/^[A-Za-z0-9_@][A-Za-z0-9_.@-]*$/.test(p)
  &&!['node_modules','functions','__proto__','prototype','constructor'].includes(p.toLowerCase())&&!p.toLowerCase().startsWith('.env')&&!p.toLowerCase().endsWith('.pem')&&!p.toLowerCase().endsWith('.key')));
}
function decode(bytes:Uint8Array){return new TextDecoder('utf-8',{fatal:true}).decode(bytes);}
function inventory(raw:unknown,subjects:readonly ByteSubject[],required:readonly string[],controller=false):ByteSubject[]{
 require(Array.isArray(raw)&&raw.length>=required.length&&raw.length<=MAX_FILES&&Array.isArray(subjects)&&subjects.length===raw.length);
 const supplied=new Map<string,Uint8Array>();let total=0;
 for(const rawSubject of subjects){const s=exact(rawSubject,['path','bytes']);relative(s.path);require(s.bytes instanceof Uint8Array&&s.bytes.byteLength>0&&s.bytes.byteLength<=MAX_FILE&&!supplied.has(s.path));
  total+=s.bytes.byteLength;require(total<=MAX_TOTAL);supplied.set(s.path,new Uint8Array(s.bytes));}
 const seen=new Set<string>(),result:ByteSubject[]=[];
 for(const row of raw){const f=exact(row,['path','sha256']);relative(f.path);hash(f.sha256);require(!seen.has(f.path.toLowerCase()));seen.add(f.path.toLowerCase());
  require(controller?CONTROLLER_REQUIRED.includes(f.path):ARTIFACT_REQUIRED.includes(f.path)||f.path.startsWith('pages/'));
  const bytes=supplied.get(f.path);require(bytes&&sha(bytes)===f.sha256);result.push({path:f.path,bytes});}
 require(required.every(p=>result.some(f=>f.path===p)));
 for(const f of result){let parent='';for(const part of f.path.split('/').slice(0,-1)){parent=parent?parent+'/'+part:part;require(!seen.has(parent.toLowerCase()));}}
 return result;
}
/** Shape/hash binding only; actual source and release authentication belong to the parent/driver. */
export function prepareAssembly(input:{context:unknown;snapshot:unknown;artifactManifest:unknown;controllerManifest:unknown;artifacts:readonly ByteSubject[];controllerSources:readonly ByteSubject[];draftReleaseAcceptance?:DraftReference},nowMs:number):PreparedAssembly{
 exact(input,Object.hasOwn(input,'draftReleaseAcceptance')?['context','snapshot','artifactManifest','controllerManifest','artifacts','controllerSources','draftReleaseAcceptance']:['context','snapshot','artifactManifest','controllerManifest','artifacts','controllerSources']);
 const context=validateContext(input.context),manifest=exact(input.artifactManifest,['version','merchant','publicKey','files']);
 require(manifest.version===1&&manifest.merchant===context.merchant&&manifest.publicKey===context.publicKey&&sha(jsonBytes(manifest))===context.artifact_sha256);
 const controller=exact(input.controllerManifest,['schema','protocol','files']);require(controller.schema===1&&controller.protocol===PROTOCOL&&sha(jsonBytes(controller))===context.controller_sha256);
 const artifacts=inventory(manifest.files,input.artifacts,ARTIFACT_REQUIRED),controllerSources=inventory(controller.files,input.controllerSources,CONTROLLER_REQUIRED,true);
 const files=new Map(artifacts.map(s=>[s.path,s.bytes])),profile=JSON.parse(decode(files.get('pages/deployment-profile.json')!));verifyStagingManifest(profile);
 const pin=JSON.parse(decode(files.get('pages/release-pin.json')!));parseReleasePin(pin);
 if(!Object.hasOwn(input,'draftReleaseAcceptance'))assertPublishedReleaseProfile(pin,profile);
 else{const ref=exact(input.draftReleaseAcceptance,['receiptFile','receiptSha256']);hash(ref.receiptSha256);require(typeof ref.receiptFile==='string'&&path.isAbsolute(ref.receiptFile)&&path.normalize(ref.receiptFile)===ref.receiptFile);
  require(pin.published===false&&profile.releasePublished===false&&profile.releaseVersion===pin.version&&pin.sourceCommit&&pin.releaseId&&pin.image&&Object.keys(pin.assets).length>0&&Object.values(pin.signedAssetManifest).every(v=>v!==null)
   &&Object.entries(pin.channels).every(([name,v])=>v===(name==='homebrewReady'?false:null)));}
 const headers=decode(files.get('pages/_headers')!);
 for(const route of ['approve','licence'] as const)verifyStagingWalletPage(decode(files.get('pages/'+route+'.html')!),headers,route);
 const licence=decode(files.get('pages/licence.html')!),scripts=[...licence.matchAll(/<script[^>]*src="(\/_astro\/licence[^"]+\.js)"/g)].map(m=>'pages'+m[1]);
 require(scripts.some(s=>files.has(s)&&decode(files.get(s)!).includes(context.merchant)));
 const snapshot=validateSnapshot(input.snapshot,context,nowMs),plan=makePlan(snapshot,context,nowMs),approval:Approval={planHash:digest(plan),account:ACCOUNT,rootApproved:true,noPlanUpgrade:true,prerequisitesVerified:true,
  artifactManifestSha256:context.artifact_sha256,controllerManifestSha256:context.controller_sha256,maxIncrementalCents:500,expires:context.deadline_ms,
  ...(input.draftReleaseAcceptance===undefined?{}:{draftReleaseAcceptance:structuredClone(input.draftReleaseAcceptance)})};
 return{context,snapshot,plan,approval,artifactManifest:structuredClone(manifest) as unknown as ArtifactManifest,controllerManifest:structuredClone(controller) as unknown as ControllerManifest,artifacts,controllerSources};
}
function absolute(file:string){require(path.isAbsolute(file)&&path.normalize(file)===file&&!/[\x00-\x1f\x7f]/.test(file));}
async function privateDirectory(file:string){absolute(file);const s=await lstat(file);require(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid?.()&&(s.mode&0o777)===0o700&&await realpath(file)===file);return s;}
/** Saved original snapshot bytes must match Plan, without treating loading as renewal. */
export function parseOriginalReadback(bytes:Uint8Array,rawPlan:RetainedPlan,now:number):Snapshot{
 const plan=validatePlan(rawPlan,now);require(bytes instanceof Uint8Array&&bytes.byteLength>0&&bytes.byteLength<=2*1024*1024&&sha(bytes)===plan.readbackSha256);
 const raw=JSON.parse(decode(bytes)),r=object(raw);require(Number.isSafeInteger(r.checked_ms)&&(r.checked_ms as number)>=plan.start&&(r.checked_ms as number)<=now);
 const snapshot=validateSnapshot(raw,plan.context,r.checked_ms as number);require(sha(jsonBytes(snapshot))===plan.readbackSha256&&digest(makePlan(snapshot,plan.context,snapshot.checked_ms))===digest(plan));return snapshot;
}
function canonical(raw:unknown):unknown{if(Array.isArray(raw))return raw.map(canonical);if(raw&&typeof raw==='object')return Object.fromEntries(Object.entries(raw).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>[k,canonical(v)]));return raw;}
/** Fresh HTTP proof may change its observed time only. This never replaces Plan. */
export function assertFreshReadbackMatches(original:Snapshot,fresh:Snapshot,context:Context,now:number):void{
 const saved=validateSnapshot(original,context,original.checked_ms),current=validateSnapshot(fresh,context,now);
 require(saved.checked_ms>=context.started_ms&&saved.checked_ms<=current.checked_ms&&now>=context.started_ms&&now<context.deadline_ms);
 const {checked_ms:oldTime,...old}=saved,{checked_ms:newTime,...next}=current;require(digest(canonical(old))===digest(canonical(next)));
}
/** Create-only local output. This writes reviewable data, not an apply authorization. */
export async function writeAssembly(prepared:PreparedAssembly,parent:string,nowMs:number):Promise<ProvisionInput>{
 exact(prepared,['context','snapshot','plan','approval','artifactManifest','controllerManifest','artifacts','controllerSources']);
 exact(prepared.approval,Object.hasOwn(prepared.approval,'draftReleaseAcceptance')?['planHash','account','rootApproved','noPlanUpgrade','prerequisitesVerified','artifactManifestSha256','controllerManifestSha256','maxIncrementalCents','expires','draftReleaseAcceptance']:['planHash','account','rootApproved','noPlanUpgrade','prerequisitesVerified','artifactManifestSha256','controllerManifestSha256','maxIncrementalCents','expires']);
 const parentBefore=await privateDirectory(parent);validatePlan(prepared.plan,nowMs);
 const checked=prepareAssembly({context:prepared.context,snapshot:prepared.snapshot,artifactManifest:prepared.artifactManifest,controllerManifest:prepared.controllerManifest,artifacts:prepared.artifacts,controllerSources:prepared.controllerSources,
  ...(prepared.approval.draftReleaseAcceptance===undefined?{}:{draftReleaseAcceptance:prepared.approval.draftReleaseAcceptance})},nowMs);
 require(digest(checked.plan)===digest(prepared.plan)&&digest(checked.approval)===digest(prepared.approval));
 const output=path.join(parent,'retained-backend');await mkdir(output,{mode:0o700});await privateDirectory(output);
 const artifactDirectory=path.join(output,'artifacts'),journalDirectory=path.join(output,'journal');await mkdir(artifactDirectory,{mode:0o700});await mkdir(journalDirectory,{mode:0o700});
 async function write(file:string,data:Uint8Array):Promise<FileRef>{
  const directory=path.dirname(file);await privateDirectory(directory);
  const handle=await open(file,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{const st=await handle.stat();require(st.isFile()&&st.uid===process.getuid?.()&&(st.mode&0o777)===0o600&&st.nlink===1);await handle.writeFile(data);await handle.sync();}
  finally{await handle.close();}
  return{file,sha256:sha(data)};
 }
 for(const subject of checked.artifacts){const file=path.join(artifactDirectory,subject.path),directories=subject.path.split('/').slice(0,-1);let current=artifactDirectory;
  for(const part of directories){current=path.join(current,part);try{await mkdir(current,{mode:0o700});}catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw e;}await privateDirectory(current);}
  await write(file,subject.bytes);
 }
 await write(path.join(output,'readback.json'),jsonBytes(checked.snapshot));
 require(sha(jsonBytes(checked.snapshot))===checked.plan.readbackSha256);
 const plan=await write(path.join(output,'plan.json'),jsonBytes(checked.plan)),approval=await write(path.join(output,'approval.json'),jsonBytes(checked.approval)),
  artifactManifest=await write(path.join(output,'artifact-manifest.json'),jsonBytes(checked.artifactManifest)),controllerManifest=await write(path.join(output,'controller-manifest.json'),jsonBytes(checked.controllerManifest));
 const parentAfter=await privateDirectory(parent);require(parentAfter.dev===parentBefore.dev&&parentAfter.ino===parentBefore.ino&&plan.sha256===checked.approval.planHash
  &&artifactManifest.sha256===checked.approval.artifactManifestSha256&&controllerManifest.sha256===checked.approval.controllerManifestSha256);
 return{plan,approval,artifactDirectory,artifactManifest,controllerManifest,journalDirectory};
}
