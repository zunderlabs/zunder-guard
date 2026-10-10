// Root credential pipe only. No browser, environment, file or argv credential input.
import fs from 'node:fs';
import net from 'node:net';
import {createRootAccessHeaders,FUTURE_STAGING_HOST,type AccessLease,type UpstreamTarget} from '../access/headers.ts';
import type {LinuxFlowBoundary} from './network-linux.ts';
export type CanonicalProxyAccess=ReturnType<typeof createCanonicalProxyAccess>;
function refuse():never{throw new Error('Root staging credential refused');}
/** Called only by the root pipe reader. Inert fixtures use generated dummy frames. */
export function createCanonicalProxyAccess(input:AccessLease,raw:Buffer,flow:Pick<LinuxFlowBoundary,'assertDispatchAuthority'>){
 const lease=Object.freeze({...input});
 if(lease.stagingHost!==FUTURE_STAGING_HOST||!Buffer.isBuffer(raw)||raw.length<1||raw.length>1024)refuse();
 flow.assertDispatchAuthority(lease.deadline);
 let value:unknown;try{const text=raw.toString('utf8');if(!Buffer.from(text).equals(raw))refuse();value=JSON.parse(text);}catch{return refuse();}
 if(!value||typeof value!=='object'||Array.isArray(value))refuse();
 const v=value as Record<string,unknown>;
 if(Object.keys(v).sort().join(',')!=='clientId,clientSecret'||typeof v.clientId!=='string'||typeof v.clientSecret!=='string')refuse();
 const id=Buffer.from(v.clientId,'utf8'),secret=Buffer.from(v.clientSecret,'utf8');
 let held:ReturnType<typeof createRootAccessHeaders>;
 try{held=createRootAccessHeaders(lease,id,secret);}finally{id.fill(0);secret.fill(0);}
 return Object.freeze({
  forUpstream(target:UpstreamTarget){
   // Frozen helper enforces canonical HTTPS443 or empty venue headers.
   const headers=held.forUpstream(target);
   // Actual parent's original UTC+monotonic authority, synchronously before dispatch.
   flow.assertDispatchAuthority(lease.deadline);return headers;
  },
  assertNoReflection(body:Buffer){
   const values=held.forUpstream({protocol:'https:',host:lease.stagingHost,port:443});
   flow.assertDispatchAuthority(lease.deadline);
   for(const value of Object.values(values))for(const encoded of [value,encodeURIComponent(value),Buffer.from(value).toString('base64'),Buffer.from(value).toString('hex')]){
    if(body.includes(Buffer.from(encoded)))refuse();
   }
  },
  dispose(){held.dispose();},
 });
}
/** FD4 is a dedicated parent-owned anonymous pipe, separate from FD3 control and wallet stdin.
 * Parent closes its writer after one bounded JSON frame; this reader closes FD4 before any child spawn. */
export async function readCanonicalProxyAccessPipe(lease:AccessLease,flow:LinuxFlowBoundary):Promise<CanonicalProxyAccess>{
 if(process.platform!=='linux'||process.arch!=='x64'||process.getuid?.()!==0
  ||process.env.NODE_OPTIONS||process.env.NODE_EXTRA_CA_CERTS||process.env.DEBUG||process.env.PWDEBUG
  ||process.execArgv.some(a=>/inspect|require|import|loader|report|trace/i.test(a)))refuse();
 flow.assertDispatchAuthority(lease.deadline);
 const st=fs.fstatSync(4);if(!st.isFIFO()||st.uid!==0||(st.mode&0o777)!==0o600)refuse();
 return new Promise((resolve,reject)=>{
  const pipe=new net.Socket({fd:4,readable:true,writable:false});let raw=Buffer.alloc(0),done=false,loaded:CanonicalProxyAccess|undefined;
  const timer=setTimeout(()=>fail(),Math.max(1,Math.min(10_000,lease.deadline-Date.now())));
  const fail=()=>{if(done)return;done=true;clearTimeout(timer);raw.fill(0);loaded?.dispose();pipe.destroy();reject(new Error('Root staging credential pipe refused'));};
  pipe.on('error',fail);pipe.on('close',()=>{if(done)return;if(!loaded)return fail();
   try{fs.fstatSync(4);return fail();}catch(e){if((e as NodeJS.ErrnoException).code!=='EBADF')return fail();}
   done=true;clearTimeout(timer);resolve(loaded);
  });
  pipe.on('data',(chunk:Buffer)=>{try{
   flow.assertDispatchAuthority(lease.deadline);if(raw.length+chunk.length>1024)return fail();
   const prior=raw;raw=Buffer.concat([raw,chunk]);prior.fill(0);chunk.fill(0);
  }catch{fail();}});
  pipe.on('end',()=>{try{
   flow.assertDispatchAuthority(lease.deadline);loaded=createCanonicalProxyAccess(lease,raw,flow);
   raw.fill(0);pipe.destroy(); // Resolve only after actual FD close, before any child spawn.
  }catch{fail();}});
 });
}
