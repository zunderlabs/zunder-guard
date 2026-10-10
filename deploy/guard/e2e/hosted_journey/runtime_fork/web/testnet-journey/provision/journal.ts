// Append-only, fsynced records. A fresh directory is the single-use run claim.
import {mkdir,open,lstat,readFile,readdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import path from 'node:path';
import {digest} from './controller.ts';
import {DATABASES,WORKERS,SITE,RECIPIENT} from './policy.ts';
export interface RecordEntry {sequence:number;previous:string;kind:string;data:unknown}
export async function createJournal(directory:string){
 if(!path.isAbsolute(directory))throw new Error('Absolute new journal directory required');
 await mkdir(directory,{mode:0o700});
 const st=await lstat(directory);if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o077))throw new Error('Private journal required');
 let sequence=0,previous='0'.repeat(64),failed=false;
 async function append(kind:string,data:unknown){
  if(failed)throw new Error('Journal previously failed');
  const entry:RecordEntry={sequence:++sequence,previous,kind,data};
  try{const f=await open(path.join(directory,String(sequence).padStart(6,'0')+'.json'),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
   try{await f.writeFile(JSON.stringify(entry)+'\n');await f.sync();}finally{await f.close();}
   const d=await open(directory,'r');try{await d.sync();}finally{await d.close();}
   previous=digest(entry);
  }catch{failed=true;throw new Error('Journal persistence failed; stop');}
 }
 return{append};
}
export async function readJournal(directory:string):Promise<RecordEntry[]>{
 const st=await lstat(directory);if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o077))throw new Error('Private journal required');
 const files=(await readdir(directory)).sort();if(!files.length||files.length>512)throw new Error('Invalid journal size');
 let previous='0'.repeat(64);const result:RecordEntry[]=[];
 for(const [i,name]of files.entries()){
  if(name!==String(i+1).padStart(6,'0')+'.json')throw new Error('Invalid journal sequence');
  const f=await open(path.join(directory,name),constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const stat=await f.stat();if(!stat.isFile()||stat.size>1048576||(stat.mode&0o077))throw new Error('Invalid journal record');
   const entry=JSON.parse(await f.readFile('utf8')) as RecordEntry;
   if(entry.sequence!==i+1||entry.previous!==previous||typeof entry.kind!=='string')throw new Error('Journal chain mismatch');
   previous=digest(entry);result.push(entry);
  }finally{await f.close();}
 }
 return result;
}

/** HTTP success does not prove a durable creation identity or completed operation. */
export function unresolvedOutcomes(records:readonly Pick<RecordEntry,'kind'|'data'>[]):number{
 const acknowledged=new Set<number>(),unknown=new Set<string>();
 for(const r of records){if(r.kind==='http-acknowledged')acknowledged.add((r.data as {serial:number}).serial);}
 for(const r of records){if(r.kind==='http-unknown'||r.kind==='http-started'&&!acknowledged.has((r.data as {serial:number}).serial))unknown.add('http:'+String((r.data as {serial:number}).serial));}
 const creations:Record<string,{kind:string;resource:string}>={'database-0':{kind:'create-d1',resource:DATABASES[0]},'database-1':{kind:'create-d1',resource:DATABASES[1]},'worker-0':{kind:'upload-worker',resource:WORKERS[0]},'worker-1':{kind:'upload-worker',resource:WORKERS[1]},pages:{kind:'configure-pages',resource:SITE},recipient:{kind:'create-recipient',resource:RECIPIENT}};
 const ownership=records.filter(r=>r.kind==='owned').map(r=>r.data as {kind?:string;resource?:string;id?:string});
 const controller=records.filter(r=>r.kind==='controller').at(-1)?.data as {entries?:{id:string;state:string}[]}|undefined;
 if(controller){
  if(!Array.isArray(controller.entries))throw new Error('Invalid controller journal');
  for(const entry of controller.entries){if(!entry||typeof entry.id!=='string'||!['started','created','unknown'].includes(entry.state))throw new Error('Invalid operation journal');
   const creation=creations[entry.id];
   if(entry.state!=='created'||creation&&!ownership.some(o=>o.kind===creation.kind&&o.resource===creation.resource&&typeof o.id==='string'&&o.id.length>0))unknown.add('operation:'+entry.id);
  }
 }else if(records.some(r=>r.kind.startsWith('http-')))unknown.add('missing-controller-journal');
 return unknown.size;
}
