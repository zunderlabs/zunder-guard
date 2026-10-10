// Fixed P1 -> P3 -> read-only helper join. No alternate executable/entrypoint.
import fs from 'node:fs';
import path from 'node:path';
import {fail,type Config,type FileRef} from './policy.ts';
import {sha,json,pinned} from './files.ts';
import {startOwned,childEnvironment,type OwnedChild} from './child.ts';
import {completionEnvironmentSha256,type OriginalParentGate,type OriginalKeeperMetadata} from './completion-parent.ts';
import type {DisposalContinuation} from './backend-disposal.ts';
const fixed='deploy/guard/e2e/hosted_journey/backend_successor/run.ts';
function kernelBirth(pid:number){
 const text=fs.readFileSync('/proc/'+pid+'/stat','ascii');const fields=text.slice(text.lastIndexOf(')')+1).trim().split(/\s+/);
 if(!text.startsWith(pid+' (')||fields.length<20||['Z','X','x'].includes(fields[0]!))fail();
 const status=fs.readFileSync('/proc/'+pid+'/status','ascii');const uid=status.split('\n').filter(x=>x.startsWith('Uid:'));
 if(uid.length!==1||uid[0]!.trim().split(/\s+/).slice(1).some(x=>x!=='0'))fail();
 return{pid,start_ticks:Number(fields[19]),boot_id:fs.readFileSync('/proc/sys/kernel/random/boot_id','ascii').trim(),uid:0};
}
function sorted(v:unknown):unknown{return Array.isArray(v)?v.map(sorted):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,sorted((v as Record<string,unknown>)[k])])):v;}
function wire(v:unknown){return Buffer.from(JSON.stringify(sorted(v)).replace(/[\u007f-\uffff]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0')));}
/** The PRIVATE bootstrap is source-built by the original keeper. A caller JSON
 * cannot instantiate a witness; P3 executes the fixed helper before reading it. */
export async function startOriginalBackend(config:Config,gate:OriginalParentGate,keeper:OriginalKeeperMetadata,
 operation:'apply'|'dispose',args:readonly string[],plan:FileRef,bootstrap:Buffer,
 disposal:Readonly<DisposalContinuation>|null,guard:()=>void,deadline:number):Promise<OwnedChild>{
 let joined:Buffer|undefined;
 try{
  guard();if(process.platform!=='linux'||process.geteuid?.()!==0||!['apply','dispose'].includes(operation)
   ||(operation==='apply'&&disposal!==null)||(operation==='dispose'&&disposal===null)
   ||bootstrap.length<2||bootstrap.length>16384||bootstrap.includes(10)||args.length!==7||args[0]!==operation
   ||args[1]!==plan.file)fail();
  const source=await json(config.coordinator.manifest) as {schema:number;files:Record<string,string>};guard();
  if(source.schema!==1||gate.sourceManifestSha256!==config.coordinator.manifest.sha256)fail();
  const helper:FileRef={file:path.join(config.coordinator.root,'deploy/guard/e2e/hosted_journey/backend_child_gate.py'),
   sha256:source.files['deploy/guard/e2e/hosted_journey/backend_child_gate.py']!};
  const entrypoint:FileRef={file:path.join(config.coordinator.root,fixed),sha256:source.files[fixed]!};
  await pinned(helper);guard();await pinned(entrypoint);guard();await pinned(config.executables.python);guard();await pinned(plan);guard();
  const group=fs.readFileSync('/proc/self/cgroup','ascii').trim();
  if(!/^0::\/zunder-hosted-keeper-[0-9a-f]{64}$/.test(group))fail();
  const cgroupPath='/sys/fs/cgroup'+group.slice(3),st=fs.lstatSync(cgroupPath);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==0)fail();
  const env=childEnvironment(config);const argv=[config.executables.node.file,'--no-global-search-paths','--no-addons',entrypoint.file,...args];
  const first=wire({schema:1,kind:'original-hosted-backend-child-gate',gate,
   keeper:{...keeper,identity:kernelBirth(process.pid)},provider:{executable:config.executables.node,entrypoint,argv,
    environmentSha256:completionEnvironmentSha256(env as Record<string,string>)},
   sourceRoot:config.coordinator.root,sourceManifest:config.coordinator.manifest,
   cgroup:{path:cgroupPath,device:st.dev,inode:st.ino},operation,planSha256:plan.sha256,
   python:config.executables.python,helper,disposal,bootstrapSha256:sha(bootstrap)});
  if(first.length+1>2097152)fail();joined=Buffer.concat([first,Buffer.from('\n'),bootstrap,Buffer.from('\n')]);first.fill(0);
  guard();return startOwned(config.executables.node.file,argv.slice(1),config.coordinator.root,env,joined,deadline,
   process.kill.bind(process),undefined,true,guard);
 }catch{joined?.fill(0);fail();}finally{bootstrap.fill(0);}
}
