// ROOT-ONLY explicit public-CA operation. Importing this module performs no I/O.
// Full source/OS admission and exclusive pre-browser ownership remain parent gates.
import { spawn, type ChildProcess } from 'node:child_process';
import { constants } from 'node:fs';
import { open, lstat, realpath, readFile, statfs, mkdir, readdir } from 'node:fs/promises';
import { createHash, X509Certificate } from 'node:crypto';
import path from 'node:path';
import type { LinuxFlowBoundary } from '../../../hosted_journey/runtime_fork/web/testnet-journey/wallet-extension/network-linux.ts';
export interface Pin { path: string; sha256: string }
export interface NssTrustInput { runId:string; startedAt:number; deadline:number; profileMountPath:string; certutil:Pin; certificate:Pin; certificateSha256:string }
const fail=():never=>{throw new Error('Public NSS trust refused');};
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{64}$/.test(v);
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===keys.sort().join(',');
export function validateNssInput(value:NssTrustInput):Readonly<NssTrustInput>{
 if(!exact(value,['runId','startedAt','deadline','profileMountPath','certutil','certificate','certificateSha256']))fail();
 const c=structuredClone(value);
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(c.runId)||!Number.isSafeInteger(c.startedAt)||!Number.isSafeInteger(c.deadline)||c.startedAt<=0||c.deadline<=c.startedAt||c.deadline-c.startedAt>1_200_000||c.profileMountPath!==`/run/zunder-wallet-${c.runId}`)fail();
 for(const p of [c.certutil,c.certificate]){
  if(!exact(p,['path','sha256'])||typeof p.path!=='string'||!path.isAbsolute(p.path)||path.normalize(p.path)!==p.path||!hash(p.sha256))fail();
  Object.freeze(p);
 }
 if(!hash(c.certificateSha256)||c.certificateSha256!==c.certificate.sha256||!c.certificate.path.startsWith(c.profileMountPath+'/')||c.certificate.path.startsWith(c.profileMountPath+'/home/')||c.certutil.path.startsWith('/run/'))fail();
 return Object.freeze(c);
}
export function nssArguments(c:Readonly<NssTrustInput>):readonly (readonly string[])[]{
 const db=`sql:${c.profileMountPath}/home/.pki/nssdb`;
 return Object.freeze([Object.freeze(['-N','-d',db,'--empty-password']),Object.freeze(['-A','-d',db,'-n',`Zunder public no-key ${c.runId}`,'-t','C,,','-i',c.certificate.path])]);
}
/** Pure one-use ordering/deadline state, also used by the concrete installer. */
export function nssAdmission(startedAt:number,deadline:number){
 let next=0,pending=false,unknown=false;
 return Object.freeze({
  dispatch(index:number,now:number,authority:()=>void){
   if(unknown||pending||index!==next||index>1||now<startedAt||now>=deadline)fail();
   // Consume before calling authority: a failed synchronous admission cannot retry.
   pending=true;next++;try{authority();}catch{unknown=true;throw new Error('Public NSS trust refused');}
  },
  closed(code:number|null){if(!pending)fail();pending=false;if(code!==0)unknown=true;},
  uncertain(){unknown=true;},
  state(){return Object.freeze({next,pending,unknown,complete:next===2&&!pending&&!unknown});}
 });
}
export interface NssOwnedState { pid:number|null; closed:boolean; unknown:boolean }
export class NssTrustFailure extends Error {
 readonly ownership:Readonly<{status:()=>NssOwnedState; stop:()=>void}>;
 constructor(ownership:Readonly<{status:()=>NssOwnedState;stop:()=>void}>){super('Public NSS trust uncertain; root reconciliation required');this.name='NssTrustFailure';this.ownership=ownership;}
}
const consumed=new Set<string>();
async function stablePin(pin:Pin,max:number,executable=false):Promise<Buffer>{
 if(await realpath(pin.path)!==pin.path)fail();
 // Executable ancestors cannot be writable by the browser/provider UID.
 if(executable)for(let p=path.dirname(pin.path);;p=path.dirname(p)){
  const st=await lstat(p);if(!st.isDirectory()||st.uid!==0||(st.mode&0o022))fail();if(p==='/')break;
 }
 const fd=await open(pin.path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const a=await fd.stat();if(!a.isFile()||a.nlink!==1||a.uid!==0||(a.mode&0o022)||a.size<1||a.size>max||(executable&&!(a.mode&0o111)))fail();
  const b=Buffer.alloc(a.size+1);let n=0;
  for(;;){const r=await fd.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;if(n===b.length)fail();}
  const z=await fd.stat(),current=await lstat(pin.path);
  if(n!==a.size||a.dev!==current.dev||a.ino!==current.ino||a.size!==z.size||a.mtimeMs!==z.mtimeMs||a.ctimeMs!==z.ctimeMs||createHash('sha256').update(b.subarray(0,n)).digest('hex')!==pin.sha256)fail();
  return b.subarray(0,n);
 }finally{await fd.close();}
}
export async function installNssTrust(input:NssTrustInput,actualFlow:LinuxFlowBoundary){
 const c=validateNssInput(input);
 if(consumed.has(c.runId))fail();consumed.add(c.runId); // No retry/reinitialization, including failed admissions.
 if(process.platform!=='linux'||process.arch!=='x64'||process.getuid?.()!==0||process.execArgv.length||Object.keys(process.env).some(k=>!['PATH','LANG','LC_ALL','TZ','HOME','TMPDIR','XDG_CACHE_HOME'].includes(k)))fail();
 const db=c.profileMountPath+'/home/.pki/nssdb',pki=path.dirname(db),commands=nssArguments(c),policy=nssAdmission(c.startedAt,c.deadline);
 let child:ChildProcess|undefined,closed=true,unknown=false,mutated=false;
 const stop=()=>{unknown=true;policy.uncertain();try{if(child&&!closed)child.kill('SIGKILL');}catch{/* Retain unresolved ownership; never claim death. */}};
 const ownership=Object.freeze({status:()=>Object.freeze({pid:child?.pid??null,closed,unknown}),stop});
 const live=async()=>{if(Date.now()<c.startedAt||Date.now()>=c.deadline)fail();await actualFlow.assertOriginalAuthority(c.deadline);if(Date.now()>=c.deadline)fail();};
 const identity=new Map<string,{dev:number;ino:number}>();
 async function dir(p:string,uid:number,fresh=false){
  if(await realpath(p)!==p)fail();const st=await lstat(p),fs=await statfs(p);
  if(!st.isDirectory()||st.uid!==uid||st.gid!==uid||(st.mode&0o777)!==0o700||fs.type!==0x01021994)fail();
  const old=identity.get(p);if(old&&(old.dev!==st.dev||old.ino!==st.ino))fail();identity.set(p,{dev:st.dev,ino:st.ino});
  if(fresh&&(await readdir(p)).length)fail();return st.dev;
 }
 async function shared(){
  const dev=await dir(c.profileMountPath,62345);
  for(const name of ['home','profile','tmp','cache'])if(await dir(c.profileMountPath+'/'+name,62345,name==='profile')!==dev)fail();
 }
 async function execute(index:number){
  await shared();await dir(pki,0);await dir(db,0);
  await stablePin(c.certutil,64*1024*1024,true);await stablePin(c.certificate,20_000);
  await live();
  await new Promise<void>((resolve,reject)=>{
   let settled=false,grace:ReturnType<typeof setTimeout>|undefined;
   const finish=(ok:boolean)=>{if(settled)return;settled=true;clearTimeout(timer);if(grace)clearTimeout(grace);ok?resolve():reject(new Error('NSS child uncertain'));};
   // No await occurs between the actual parent's synchronous cutoff and spawn.
   policy.dispatch(index,Date.now(),()=>actualFlow.assertDispatchAuthority(c.deadline));
   child=spawn(c.certutil.path,[...commands[index]!],{shell:false,stdio:'ignore',env:{PATH:'/usr/bin:/bin',LANG:'C',TZ:'UTC',HOME:c.profileMountPath+'/home',TMPDIR:c.profileMountPath+'/tmp'},detached:false});closed=false;
   const timer=setTimeout(()=>{stop();grace=setTimeout(()=>finish(false),1000);},Math.max(1,Math.min(5000,c.deadline-Date.now())));
   child.once('error',()=>{stop();grace??=setTimeout(()=>finish(false),1000);});
   child.once('close',code=>{closed=true;policy.closed(code);if(unknown||Date.now()>=c.deadline||code!==0){unknown=true;policy.uncertain();}finish(!unknown);});
  });
  await live();
 }
 try{
  await live();await actualFlow.assertIndependentWatchdogAndMountPolicy();await live();
  if((await readFile('/proc/swaps','utf8')).trim().split('\n').length!==1||!/^Max core file size\s+0\s+0\s+bytes$/m.test(await readFile('/proc/self/limits','utf8'))||!/^NoNewPrivs:\s+1$/m.test(await readFile('/proc/self/status','utf8')))fail();
  for(const [key,name] of [['HOME','home'],['TMPDIR','tmp'],['XDG_CACHE_HOME','cache']])if(process.env[key!]!==c.profileMountPath+'/'+name)fail();
  await shared();await dir(c.profileMountPath+'/home',62345,true);
  const cert=new X509Certificate(await stablePin(c.certificate,20_000));
  if(!cert.ca||!cert.verify(cert.publicKey)||Date.parse(cert.validFrom)>Date.now()||Date.parse(cert.validTo)<c.deadline)fail();
  await stablePin(c.certutil,64*1024*1024,true);await live();
  // mkdir without recursive/exist_ok: any existing path fails; no adoption.
  actualFlow.assertDispatchAuthority(c.deadline);await mkdir(pki,{mode:0o700});mutated=true;await live();
  actualFlow.assertDispatchAuthority(c.deadline);await mkdir(db,{mode:0o700});await live();
  await execute(0);await execute(1);
  const names=(await readdir(db)).sort();
  if(JSON.stringify(names)!==JSON.stringify(['cert9.db','key4.db','pkcs11.txt']))fail();
  for(const name of names){
   const file=path.join(db,name),fd=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
   try{const st=await fd.stat();if(!st.isFile()||st.nlink!==1||st.uid!==0||st.size>4*1024*1024)fail();await live();actualFlow.assertDispatchAuthority(c.deadline);await fd.chmod(0o600);await live();actualFlow.assertDispatchAuthority(c.deadline);await fd.chown(62345,62345);const now=await lstat(file);if(now.ino!==st.ino||now.dev!==st.dev||now.uid!==62345||now.gid!==62345||(now.mode&0o777)!==0o600)fail();}finally{await fd.close();}
  }
  for(const p of [db,pki]){
   await dir(p,0);const fd=await open(p,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_DIRECTORY);
   try{const st=await fd.stat(),id=identity.get(p)!;if(st.dev!==id.dev||st.ino!==id.ino)fail();await live();actualFlow.assertDispatchAuthority(c.deadline);await fd.chmod(0o700);await live();actualFlow.assertDispatchAuthority(c.deadline);await fd.chown(62345,62345);await dir(p,62345);}finally{await fd.close();}
  }
  await live();if(!policy.state().complete||!closed||unknown)fail();
  return Object.freeze({installedCertificateSha256:c.certificateSha256,tlsVerificationDisabled:false as const,childCloseObserved:true as const,nssDirectory:db,rootCleanupProven:false as const});
 }catch{
  stop();if(mutated||child){try{void actualFlow.hold('network-unknown').catch(()=>undefined);}catch{/* Root still receives retained ownership. */}}
  throw new NssTrustFailure(ownership);
 }
}
