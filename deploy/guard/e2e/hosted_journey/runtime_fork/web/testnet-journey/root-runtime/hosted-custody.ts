// Intentional Linux fork: fixed anonymous parent channels, no injected callbacks.
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import net from 'node:net';
import {Admission, exact, fail, hashString, type Config} from './policy.ts';
let escrowAttempted=false, brokerSequence=0, busy=false;
const channels=new Map<number,net.Socket>();
function channel(fd:number,writable:boolean):net.Socket {
 if(process.platform!=='linux'||process.getuid?.()!==0)fail();
 const st=fs.fstatSync(fd,{bigint:true});
 if(!st.isFIFO()||st.nlink!==1n||fs.readlinkSync('/proc/self/fd/'+fd)!=='pipe:['+String(st.ino)+']'||st.uid!==0n||(st.mode&0o777n)!==0o600n)fail();
 let result=channels.get(fd);
 if(!result){result=new net.Socket({fd,readable:!writable,writable,allowHalfOpen:true});result.on('error',()=>{});channels.set(fd,result);}
 return result;
}
async function output(fd:number,raw:Buffer,a:Admission,guard:()=>void){
 guard();a.check();const c=channel(fd,true);
 await new Promise<void>((resolve,reject)=>{
  const timer=setInterval(()=>{try{guard();a.check();}catch{c.destroy();reject(Error('Original hosted custody output refused'));}},25);
  c.write(raw,error=>{clearInterval(timer);try{if(error)fail();guard();a.check();resolve();}catch{reject(Error('Original hosted custody output refused'));}});
 }).finally(()=>raw.fill(0));guard();a.check();
}
async function input(fd:number,max:number,a:Admission,guard:()=>void):Promise<Buffer>{
 guard();a.check();const c=channel(fd,false);let raw=Buffer.alloc(0);
 return new Promise((resolve,reject)=>{
  let done=false;
  const cleanup=()=>{clearInterval(timer);c.off('data',data);c.off('error',bad);c.off('end',bad);c.pause();};
  const bad=()=>{if(done)return;done=true;cleanup();raw.fill(0);a.hold(true);reject(Error('Original hosted custody input refused'));};
  const data=(chunk:Buffer)=>{try{
   guard();a.check();if(done||raw.length+chunk.length>max)fail();const before=raw;raw=Buffer.concat([before,chunk]);before.fill(0);chunk.fill(0);
   const lf=raw.indexOf(10);if(lf>=0){if(lf!==raw.length-1||raw.subarray(0,lf).includes(10))fail();
    guard();a.check();done=true;cleanup();const result=raw;raw=Buffer.alloc(0);resolve(result);}
  }catch{chunk.fill(0);bad();}};
  const timer=setInterval(()=>{try{guard();a.check();}catch{bad();}},25);
  c.on('data',data);c.once('error',bad);c.once('end',bad);c.resume();
 });
}
export async function escrowOriginalMerchant(c:Config,a:Admission,merchant:string,key:Buffer):Promise<string>{
 if(escrowAttempted)fail();escrowAttempted=true;a.check();
 if(c.memoryPolicy!=='linux-no-swap'||key.length!==32||!/^0x[0-9a-f]{40}$/.test(merchant))fail();
 const guard=()=>a.check();
 const frame=Buffer.from(JSON.stringify({schema:1,kind:'original-hosted-merchant-escrow',runId:c.runId,
  startedAt:c.startedAt,deadline:Math.min(c.expires,c.startedAt+1200000),merchant,
  secret:{merchant_private_key:'0x'+key.toString('hex')}})+'\n');
 try{
  await output(5,frame,a,guard);const raw=await input(6,4096,a,guard);
  try{const ack=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
   exact(ack,['schema','kind','runId','startedAt','deadline','merchant','bindingSha256']);
   if(ack.schema!==1||ack.kind!=='actual-original-merchant-custody-ack'||ack.runId!==c.runId
    ||ack.startedAt!==c.startedAt||ack.deadline!==Math.min(c.expires,c.startedAt+1200000)
    ||ack.merchant!==merchant||!hashString(ack.bindingSha256))fail();
   a.check();a.tighten(ack.deadline);a.check();return ack.bindingSha256;
  }finally{raw.fill(0);}
 }catch{a.hold(true);fail();}finally{frame.fill(0);channels.get(5)?.destroy();channels.get(6)?.destroy();}
 return fail();
}
export async function originalInputCall(c:Config,a:Admission,kind:string,service:'sts'|'ssm',action:string,
 raw:Buffer,deadline:number,guard:()=>void):Promise<Buffer>{
 if(!escrowAttempted||busy)fail();busy=true;
 try{
  guard();a.check();const sequence=++brokerSequence;
  if(!Number.isSafeInteger(sequence)||sequence>64||deadline>a.deadline())fail();
  const payload=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
  const frame=Buffer.from(JSON.stringify({schema:1,kind:'original-hosted-input-operation',runId:c.runId,
   startedAt:c.startedAt,deadline,sequence,operation:kind,service,action,payload})+'\n');
  await output(7,frame,a,guard);const response=await input(8,16384,a,guard);
  try{const ack=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(response));
   exact(ack,['schema','kind','runId','sequence','result']);if(ack.schema!==1||ack.kind!=='actual-hosted-input-readback'
    ||ack.runId!==c.runId||ack.sequence!==sequence)fail();guard();a.check();return Buffer.from(JSON.stringify(ack.result));
  }finally{response.fill(0);}
 }catch{a.hold(true);fail();}finally{raw.fill(0);busy=false;}
}

/** Same original fixed FD7/8, dedicated public return action. Parent persists
 * intent/readback and consumes dispatch before this ACK permits signing. */
export async function originalReturnDispatch(c:Config,a:Admission,p:import('./full-return.ts').FullBalanceReturnPolicy,
 nonce:number,data:unknown,guard:()=>void):Promise<void>{
 if(!escrowAttempted||busy)fail();busy=true;
 const sorted=(v:unknown):unknown=>Array.isArray(v)?v.map(sorted):v&&typeof v==='object'?Object.fromEntries(
  Object.keys(v).sort().map(k=>[k,sorted((v as Record<string,unknown>)[k])])):v;
 const hash=(v:unknown)=>createHash('sha256').update(JSON.stringify(sorted(v))).digest('hex');
 const sequence=++brokerSequence,actionSha256=hash(data);let raw:Buffer|undefined;
 try{
  guard();a.check();if(sequence>64)fail();
  const frame=Buffer.from(JSON.stringify({schema:1,kind:'original-hosted-return-dispatch',runId:c.runId,startedAt:c.startedAt,
   deadline:a.deadline(),sequence,nonce,policySha256:hash(p),actionSha256,data})+'\n');
  await output(7,frame,a,guard);raw=await input(8,4096,a,guard);
  const ack=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));
  exact(ack,['schema','kind','runId','sequence','nonce','actionSha256','intentSha256']);
  if(ack.schema!==1||ack.kind!=='actual-original-hosted-return-dispatch-ack'||ack.runId!==c.runId
   ||ack.sequence!==sequence||ack.nonce!==nonce||ack.actionSha256!==actionSha256||!hashString(ack.intentSha256))fail();
  guard();a.check();
 }catch{a.hold(true);fail();}finally{raw?.fill(0);busy=false;}
}
