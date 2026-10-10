// Low-level public-frame reader only. Stable-parent/source/transport admission is
// established separately by the root; a descriptor or frame grants no authority.
import fs from 'node:fs';
import net from 'node:net';
import {Admission,exact} from './policy.ts';
export interface CompletionPipeIdentity {fd:3;device:string;inode:string;uid:number}
let claimed=false;
function refused():never{throw new Error('Protected completion pipe refused');}
function anonymous(stat:fs.BigIntStats){
 return stat.isFIFO()&&(process.platform==='linux'
  ?stat.nlink===1n&&fs.readlinkSync('/proc/self/fd/3')==='pipe:['+String(stat.ino)+']'
  :process.platform==='darwin'&&stat.nlink===0n);
}
/** Non-consuming kernel check. Expected metadata alone never admits a parent. */
export function assertCompletionPipeIdentity(identity:CompletionPipeIdentity):void {
 exact(identity,['fd','device','inode','uid']);
 const uint64=(v:unknown):v is string=>typeof v==='string'&&/^(0|[1-9]\d*)$/.test(v)
   &&v.length<=20&&BigInt(v)<=(1n<<64n)-1n;
 if(identity.fd!==3||!uint64(identity.device)||!uint64(identity.inode)
   ||!Number.isSafeInteger(identity.uid)||identity.uid<0||identity.uid!==process.getuid?.())refused();
 const stat=fs.fstatSync(3,{bigint:true});
 if(!anonymous(stat)||stat.uid!==BigInt(identity.uid)
   ||BigInt.asUintN(64,stat.dev).toString()!==identity.device
   ||BigInt.asUintN(64,stat.ino).toString()!==identity.inode)refused();
}
export async function readProtectedCompletionPipe(expected:CompletionPipeIdentity,admission:Admission):Promise<Buffer>{
 if(claimed){admission.hold(true);refused();}claimed=true;
 let identity:CompletionPipeIdentity;
 try{identity=structuredClone(expected);}catch{admission.hold(true);refused();}
 let raw:Buffer=Buffer.alloc(0),socket:net.Socket|undefined,owned=false,settled=false,closing=false;
 let timer:ReturnType<typeof setTimeout>|undefined;
 const matched=()=>{
   const stat=fs.fstatSync(3,{bigint:true});
   return anonymous(stat)&&stat.uid===BigInt(identity.uid)
     // Darwin exposes the same ino_t bits signed in Node and unsigned in Python.
     // Descriptor identity uses canonical unsigned64 kernel values in both cases.
     &&BigInt.asUintN(64,stat.dev).toString()===identity.device
     &&BigInt.asUintN(64,stat.ino).toString()===identity.inode;
 };
 const check=()=>{admission.check();if(!matched())refused();admission.check();};
 const closeOwned=()=>{
   if(!owned)return;
   try{if(matched()){if(socket)socket.destroy();else fs.closeSync(3);}}
   catch{/* An absent/replaced descriptor is never closed speculatively. */}
   socket?.pause();socket?.unref();
 };
 try{
   assertCompletionPipeIdentity(identity);
   if(!(admission instanceof Admission))refused();
   check();owned=true;
 }catch{admission.hold(true);closeOwned();raw.fill(0);refused();}
 return new Promise<Buffer>((resolve,reject)=>{
   const fail=()=>{
     if(settled)return;settled=true;clearTimeout(timer);admission.hold(true);raw.fill(0);raw=Buffer.alloc(0);
     closeOwned();reject(new Error('Protected completion pipe refused'));
   };
   const poll=()=>{
     if(settled)return;
     try{if(closing)admission.check();else check();}
     catch{fail();return;}
     timer=setTimeout(poll,Math.max(1,Math.min(5000,admission.deadline()-Date.now())));
   };
   try{
     check();socket=new net.Socket({fd:3,readable:true,writable:false,allowHalfOpen:true});
     socket.on('error',fail);
     socket.on('data',(chunk:Buffer)=>{
       try{
         check();if(settled||closing||raw.length+chunk.length>8192)refused();
         const previous=raw;raw=Buffer.concat([previous,chunk]);previous.fill(0);chunk.fill(0);
         const lf=raw.indexOf(10);
         if((lf!==-1&&lf!==raw.length-1)||raw.some((b,i)=>(b<32||b>126)&&!(b===10&&i===raw.length-1)))refused();
         check();
       }catch{chunk.fill(0);fail();}
     });
     socket.once('end',()=>{
       try{
         check();if(settled||closing||raw.length<2||raw.at(-1)!==10||raw.indexOf(10)!==raw.length-1)refused();
         check();closing=true;socket!.destroy();
       }catch{fail();}
     });
     socket.once('close',()=>{
       if(settled)return;
       try{
         if(!closing)refused();admission.check();
         try{fs.fstatSync(3);refused();}catch(error){if((error as NodeJS.ErrnoException).code!=='EBADF')throw error;}
         admission.check();settled=true;clearTimeout(timer);
         const result=raw;raw=Buffer.alloc(0);resolve(result);
       }catch{fail();}
     });
     poll();
   }catch{fail();}
 });
}
