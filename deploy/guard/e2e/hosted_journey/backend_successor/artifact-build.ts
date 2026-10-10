// Fixed original post-custody source build. No standalone CLI or credential carrier.
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {constants} from 'node:fs';
import {lstat,mkdir,open,readdir,realpath} from 'node:fs/promises';
import path from 'node:path';
import {Admission,DENIED,OFFICIAL_KEY,validateOriginalAdmissionClock,type OriginalAdmissionClock} from '../runtime_fork/web/testnet-journey/root-runtime/policy.ts';
import {parseReleasePin} from '../runtime_fork/web/release-pin.ts';
import {verifyStagingManifest,verifyStagingWalletPage,stagingNavigationOrigins} from '../runtime_fork/web/testnet-journey/provision/wallet-policy.ts';
import type {ArtifactManifest,ByteSubject,FileRef} from './assemble.ts';

export interface BuildContext {run_id:string;attempt:number;binding_sha256:string;started_ms:number;deadline_ms:number}
export interface PublicIdentity {merchant:string;publicKey:string}
export interface BuildTree {root:string;manifest:FileRef}
export interface BuildInput {context:BuildContext;identity:PublicIdentity;website:BuildTree;tools:BuildTree;executable:FileRef;releasePin:FileRef;outputParent:string}
export interface BuiltArtifacts {artifactDirectory:string;artifactManifest:FileRef}
export interface FixedCommand {kind:'node'|'esbuild';entry:string;args:string[]}
const SITE='https://staging.zunderlabs.com';
const FLAGS=Object.freeze(['--no-global-search-paths','--no-addons']);
const ROLLDOWN='@rolldown/binding-linux-x64-gnu';
const ROLLDOWN_NATIVE='node_modules/'+ROLLDOWN+'/rolldown-binding.linux-x64-gnu.node';
const SCRIPTS=Object.freeze(['copy-fonts.mjs','engine-defaults.mjs','sample-snapshot.mjs','sync-docs.mjs','licenses.mjs']);
const AFTER=Object.freeze(['after-paint.mjs','approve-csp.mjs','check-pages.mjs','check-placeholders.mjs','deployment-build.ts']);
const MIGRATIONS=Object.freeze(['0001_init.sql','0002_licences.sql','0003_licence_watch_start.sql','0004_licence_renewal.sql']);
export const BUILD_SOURCE_REQUIRED=Object.freeze(['web/site/package.json','web/site/package-lock.json','web/site/astro.config.mjs','web/site/LICENSES.md','web/site/LICENSES.wasm.md',
 ...[...SCRIPTS,...AFTER].map(f=>'web/site/scripts/'+f),'web/site/public/live/src/engine.js','web/site/public/live/pkg/zunder_risk_wasm_bg.wasm',
 'web/release-pin.ts','web/deployment-profile.ts',...MIGRATIONS.map(f=>'web/waitlist/migrations/'+f),'web/waitlist/testnet-inbox-migrations/0001_inbox.sql',
 ...['api','inbox','pages'].map(f=>'web/testnet-journey/provision/'+f+'.entry.ts'),'web/testnet-journey/provision/lease.ts',
 'web/waitlist/src/testnet-index.ts','web/waitlist/src/testnet-inbox.ts','web/waitlist/src/testnet-pages.ts']);
export const BUILD_TOOL_REQUIRED=Object.freeze(['node_modules/astro/package.json','node_modules/astro/bin/astro.mjs','node_modules/esbuild/package.json','node_modules/esbuild/bin/esbuild',
 'node_modules/vite/package.json','node_modules/rolldown/package.json','node_modules/rolldown/dist/index.mjs','node_modules/rolldown/dist/shared/binding-B4m_2rFW.mjs',
 'node_modules/'+ROLLDOWN+'/package.json',ROLLDOWN_NATIVE]);
const ARTIFACT_REQUIRED=Object.freeze(['api.js','inbox.js',...MIGRATIONS.map(f=>'migrations/'+f),'migrations/0001_inbox.sql',
 'pages/_worker.js','pages/_headers','pages/_routes.json','pages/index.html','pages/licence.html','pages/approve.html','pages/deployment-profile.json','pages/release-pin.json']);
const MAX_FILE=8*1024*1024,MAX_TOTAL=32*1024*1024,MAX_FILES=1024;
function refused():never{throw Error('Original artifact build held');}
function require(ok:unknown):asserts ok{if(!ok)refused();}
function exact(raw:unknown,keys:readonly string[]){require(raw&&typeof raw==='object'&&!Array.isArray(raw)&&Object.getPrototypeOf(raw)===Object.prototype);const r=raw as Record<string,unknown>;require(Object.keys(r).length===keys.length&&keys.every(k=>Object.hasOwn(r,k)));return r;}
function hash(v:unknown):asserts v is string{require(typeof v==='string'&&/^[0-9a-f]{64}$/.test(v)&&!/^0{64}$/.test(v));}
function absolute(v:unknown):asserts v is string{require(typeof v==='string'&&path.isAbsolute(v)&&path.normalize(v)===v&&!/[\x00-\x1f\x7f]/.test(v));}
function relative(v:unknown):asserts v is string{require(typeof v==='string'&&v.length<=512&&!v.startsWith('/')&&v.split('/').every(p=>/^[A-Za-z0-9_.@+$\[\]-]+$/.test(p)&&!['.','..','.git','.npmrc','.netrc','.ssh','.aws','__proto__','prototype','constructor'].includes(p.toLowerCase())&&!p.toLowerCase().startsWith('.env')&&!/\.(pem|key)$/i.test(p)));}
const sha=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const json=(value:unknown)=>new TextEncoder().encode(JSON.stringify(value));
const decode=(bytes:Uint8Array)=>new TextDecoder('utf-8',{fatal:true}).decode(bytes);
function ref(raw:unknown){const r=exact(raw,['file','sha256']);absolute(r.file);hash(r.sha256);return r as unknown as FileRef;}

/** Shape only. Actual source/runtime and post-custody authority remain with P1. */
export function validateBuildInput(raw:unknown):BuildInput{
 const r=exact(raw,['context','identity','website','tools','executable','releasePin','outputParent']),c=exact(r.context,['run_id','attempt','binding_sha256','started_ms','deadline_ms']);
 require(typeof c.run_id==='string'&&/^[1-9][0-9]{0,19}$/.test(c.run_id)&&Number.isSafeInteger(c.attempt)&&(c.attempt as number)>=1&&(c.attempt as number)<=999);
 hash(c.binding_sha256);require(Number.isSafeInteger(c.started_ms)&&Number.isSafeInteger(c.deadline_ms)&&(c.started_ms as number)>0&&(c.deadline_ms as number)>(c.started_ms as number)&&(c.deadline_ms as number)-(c.started_ms as number)<=1200000);
 const i=exact(r.identity,['merchant','publicKey']);require(typeof i.merchant==='string'&&/^0x[0-9a-f]{40}$/.test(i.merchant)&&!DENIED.includes(i.merchant));hash(i.publicKey);require(i.publicKey!==OFFICIAL_KEY);
 for(const k of ['website','tools']){const t=exact(r[k],['root','manifest']);absolute(t.root);ref(t.manifest);}
 ref(r.executable);ref(r.releasePin);absolute(r.outputParent);
 const roots=[(r.website as BuildTree).root,(r.tools as BuildTree).root,r.outputParent];
 require(roots.every((a,n)=>roots.every((b,m)=>n===m||a!==b&&!a.startsWith(b+'/'))));
 return structuredClone(r) as unknown as BuildInput;
}

/** Existing inventory dialect, with a finite source/tool namespace and no executable hooks. */
export function validateBuildInventory(raw:unknown,role:'source'|'tools'):Record<string,string>{
 const r=exact(raw,['schema','files']);require(r.schema===1&&r.files&&typeof r.files==='object'&&!Array.isArray(r.files)&&Object.getPrototypeOf(r.files)===Object.prototype);
 const rows=Object.entries(r.files as Record<string,unknown>);require(rows.length>0&&rows.length<=(role==='source'?12000:50000));
 const names=new Set<string>();for(const [p,h]of rows){relative(p);hash(h);require(!names.has(p.toLowerCase()));names.add(p.toLowerCase());
  require(role==='tools'?p.startsWith('node_modules/')&&!p.split('/').includes('.bin'):
   p.startsWith('web/site/src/')||p.startsWith('web/site/public/')||p.startsWith('web/site/scripts/')||p.startsWith('web/site/stubs/')
   ||p.startsWith('web/docs-content/')||p.startsWith('web/waitlist/src/')||p.startsWith('web/waitlist/migrations/')||p.startsWith('web/waitlist/testnet-inbox-migrations/')
   ||['web/site/package.json','web/site/package-lock.json','web/site/astro.config.mjs','web/site/tsconfig.json','web/site/LICENSES.md','web/site/LICENSES.wasm.md','web/site/LICENSES.generated.md','web/release-pin.ts','web/deployment-profile.ts',
    'web/testnet-journey/provision/lease.ts',...['api','inbox','pages'].map(f=>'web/testnet-journey/provision/'+f+'.entry.ts')].includes(p));
 }
 for(const p of names){let prefix='';for(const part of p.split('/').slice(0,-1)){prefix=prefix?prefix+'/'+part:part;require(!names.has(prefix));}}
 require((role==='source'?BUILD_SOURCE_REQUIRED:BUILD_TOOL_REQUIRED).every(p=>Object.hasOwn(r.files as object,p)));
 return Object.fromEntries(rows.sort(([a],[b])=>a.localeCompare(b))) as Record<string,string>;
}

/** Recover the retained parent's exact projection, without a new capture/carrier.
 * Admission may already be tightened; that never changes its original clock. */
export function validateBuildClock(context:BuildContext,clock:OriginalAdmissionClock,effectiveDeadline:number):number{
 const c=exact(context,['run_id','attempt','binding_sha256','started_ms','deadline_ms']),k=exact(clock,['domain','originWallNs','originMonoNs','deadlineMonoNs']);
 require(k.domain==='linux-clock-monotonic-ns-v1');
 for(const n of [k.originWallNs,k.originMonoNs,k.deadlineMonoNs])require(typeof n==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(n)&&BigInt(n)<=(1n<<64n)-1n);
 const wall=BigInt(k.originWallNs as string),mono=BigInt(k.originMonoNs as string),cutoff=BigInt(k.deadlineMonoNs as string),endNs=wall+cutoff-mono;
 require(cutoff>mono&&endNs>0n&&endNs%1000000n===0n&&endNs/1000000n<=BigInt(Number.MAX_SAFE_INTEGER));
 const originalEnd=Number(endNs/1000000n);
 require(Number.isSafeInteger(c.started_ms)&&Number.isSafeInteger(c.deadline_ms)&&(c.started_ms as number)>0&&(c.deadline_ms as number)>(c.started_ms as number)
  &&(c.deadline_ms as number)-(c.started_ms as number)<=1200000&&originalEnd>=(c.deadline_ms as number)&&originalEnd-(c.started_ms as number)<=3600000
  &&Number.isSafeInteger(effectiveDeadline)&&effectiveDeadline>(c.started_ms as number)&&effectiveDeadline<=(c.deadline_ms as number)&&effectiveDeadline-(c.started_ms as number)<=1200000);
 validateOriginalAdmissionClock(clock,originalEnd,c.started_ms as number);return originalEnd;
}

/** Public-only environment, never merged with process.env. */
export function buildEnvironment(identity:PublicIdentity,pin:unknown,scope:string):Record<string,string>{
 const i=exact(identity,['merchant','publicKey']);require(typeof i.merchant==='string'&&/^0x[0-9a-f]{40}$/.test(i.merchant)&&!DENIED.includes(i.merchant));hash(i.publicKey);require(i.publicKey!==OFFICIAL_KEY);absolute(scope);
 const p=parseReleasePin(pin);
 return{HOME:path.join(scope,'home'),TMPDIR:path.join(scope,'tmp'),LANG:'C',LC_ALL:'C',CI:'1',ASTRO_TELEMETRY_DISABLED:'1',
  PUBLIC_GUARD_RELEASE_MANIFEST:JSON.stringify(p),PUBLIC_DEPLOYMENT_PROFILE:'staging',PUBLIC_TESTNET_JOURNEY:'1',PUBLIC_GUARD_RELEASED:p.published?'1':'0',
  PUBLIC_TESTNET_MERCHANT:i.merchant,ZUNDER_APPROVE:'1',SNAPSHOT:'skip'};
}

/** Fixed argv; paths derive from the fresh scope only, never a caller command. */
export function fixedBuildCommands(scope:string):FixedCommand[]{
 absolute(scope);const site=path.join(scope,'web/site'),artifact=path.join(scope,'artifacts');
 const commands:FixedCommand[]=SCRIPTS.map(f=>({kind:'node',entry:path.join(site,'scripts',f),args:f==='licenses.mjs'?['--check']:[]}));
 commands.push({kind:'node',entry:path.join(site,'node_modules/astro/bin/astro.mjs'),args:['build']});
 commands.push(...AFTER.map(f=>({kind:'node' as const,entry:path.join(site,'scripts',f),args:[]})));
 for(const [entry,out]of [['api','api.js'],['inbox','inbox.js'],['pages','pages/_worker.js']] as const)commands.push({kind:'esbuild',entry:path.join(site,'node_modules/esbuild/bin/esbuild'),
  args:[path.join(scope,'web/testnet-journey/provision/'+entry+'.entry.ts'),'--bundle','--format=esm','--platform=browser','--external:cloudflare:email','--log-level=error','--outfile='+path.join(artifact,out)]});
 return commands;
}

/** Only the exact uncredentialled Astro build needs its admitted Rolldown addon.
 * Privileged actors and the other fixed build scripts retain --no-addons. */
export function fixedNodeBuildArguments(scope:string,command:FixedCommand):string[]{
 const expected=fixedBuildCommands(scope).find(c=>c.kind==='node'&&JSON.stringify(c)===JSON.stringify(command));require(expected);
 const astro=expected.entry===path.join(scope,'web/site/node_modules/astro/bin/astro.mjs');
 return[...(astro?['--no-global-search-paths']:FLAGS),expected.entry,...expected.args];
}

/** Existing navigation policy; executable script blocks remain byte-identical. */
export function normalizeStagingNavigation(content:string):string{
 const scripts:string[]=[];const masked=content.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,s=>{scripts.push(s);return `<!--ORIGINAL_BUILD_SCRIPT_${scripts.length-1}-->`;});
 require(!/<!--ORIGINAL_BUILD_SCRIPT_\d+-->/.test(content));
 return stagingNavigationOrigins(masked,SITE).replace(/<!--ORIGINAL_BUILD_SCRIPT_(\d+)-->/g,(_,n)=>scripts[Number(n)]!);
}

/** Actual output bytes, profile/CSP and merchant binding; no provider/custody proof. */
export function artifactManifestFromBytes(identity:PublicIdentity,subjects:readonly ByteSubject[],expectedPin:unknown):ArtifactManifest{
 const i=exact(identity,['merchant','publicKey']);require(typeof i.merchant==='string'&&/^0x[0-9a-f]{40}$/.test(i.merchant)&&!DENIED.includes(i.merchant));hash(i.publicKey);require(i.publicKey!==OFFICIAL_KEY);
 require(Array.isArray(subjects)&&subjects.length>=ARTIFACT_REQUIRED.length&&subjects.length<=MAX_FILES);const files=new Map<string,Uint8Array>();const seen=new Set<string>();let total=0;
 for(const raw of subjects){const s=exact(raw,['path','bytes']);relative(s.path);require(s.path.split('/').every(p=>/^[A-Za-z0-9_@][A-Za-z0-9_.@-]*$/.test(p)&&!['node_modules','functions'].includes(p.toLowerCase()))
  &&(ARTIFACT_REQUIRED.includes(s.path)||s.path.startsWith('pages/'))&&!seen.has(s.path.toLowerCase())&&s.bytes instanceof Uint8Array&&s.bytes.byteLength>0&&s.bytes.byteLength<=MAX_FILE);
  seen.add(s.path.toLowerCase());total+=s.bytes.byteLength;require(total<=MAX_TOTAL);files.set(s.path,new Uint8Array(s.bytes));}
 require(ARTIFACT_REQUIRED.every(f=>files.has(f)));for(const p of seen){let prefix='';for(const part of p.split('/').slice(0,-1)){prefix=prefix?prefix+'/'+part:part;require(!seen.has(prefix));}}
 const profile=JSON.parse(decode(files.get('pages/deployment-profile.json')!));verifyStagingManifest(profile);
 const pin=JSON.parse(decode(files.get('pages/release-pin.json')!));parseReleasePin(pin);require(JSON.stringify(parseReleasePin(pin))===JSON.stringify(parseReleasePin(expectedPin))&&profile.releaseVersion===pin.version&&profile.releasePublished===pin.published);
 const routes=JSON.parse(decode(files.get('pages/_routes.json')!));require(JSON.stringify(routes)===JSON.stringify({version:1,include:['/*'],exclude:[]}));
 const headers=decode(files.get('pages/_headers')!);for(const route of ['approve','licence'] as const)verifyStagingWalletPage(decode(files.get('pages/'+route+'.html')!),headers,route);
 const licence=decode(files.get('pages/licence.html')!),scripts=[...licence.matchAll(/<script[^>]*src="(\/_astro\/licence[^"]+\.js)"/g)].map(m=>'pages'+m[1]);
 require(scripts.some(s=>files.has(s)&&decode(files.get(s)!).includes(i.merchant as string)));
 return{version:1,merchant:i.merchant,publicKey:i.publicKey,files:[...files].sort(([a],[b])=>a.localeCompare(b)).map(([p,b])=>({path:p,sha256:sha(b)}))};
}

async function regularBytes(file:string,max:number):Promise<{bytes:Uint8Array;executable:boolean}>{
 absolute(file);require(await realpath(file)===file);const h=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const before=await h.stat();require(before.isFile()&&before.nlink===1&&before.uid===process.getuid?.()&&!(before.mode&0o022)&&before.size>0&&before.size<=max);
  const b=Buffer.alloc(before.size+1);let n=0;for(;;){const r=await h.read(b,n,b.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;require(n<b.length);}
  const after=await h.stat(),current=await lstat(file);require(n===before.size&&after.size===before.size&&after.mtimeMs===before.mtimeMs&&after.ctimeMs===before.ctimeMs&&current.dev===before.dev&&current.ino===before.ino&&await realpath(file)===file);
  return{bytes:b.subarray(0,n),executable:!!(before.mode&0o100)};
 }finally{await h.close();}
}
async function privateDirectory(file:string){absolute(file);const s=await lstat(file);require(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid?.()&&(s.mode&0o777)===0o700&&await realpath(file)===file);return s;}
async function writeNew(file:string,bytes:Uint8Array,executable=false){await privateDirectory(path.dirname(file));const h=await open(file,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,executable?0o700:0o600);
 try{const s=await h.stat();require(s.isFile()&&s.nlink===1&&s.uid===process.getuid?.()&&(s.mode&0o777)===(executable?0o700:0o600));await h.writeFile(bytes);await h.sync();}finally{await h.close();}}
async function privateOutputFile(file:string){await privateDirectory(path.dirname(file));require(await realpath(file)===file);const h=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const s=await h.stat();require(s.isFile()&&s.nlink===1&&s.uid===process.getuid?.());await h.chmod(0o600);const after=await h.stat(),current=await lstat(file);require((after.mode&0o777)===0o600&&current.dev===s.dev&&current.ino===s.ino&&await realpath(file)===file);}finally{await h.close();}}
async function directories(root:string,relativeFile:string){let current=root;for(const segment of relativeFile.split('/').slice(0,-1)){current=path.join(current,segment);try{await mkdir(current,{mode:0o700});}catch(e){require((e as NodeJS.ErrnoException).code==='EEXIST');}await privateDirectory(current);}}

/** Only the source-joined original coordinator may call this post-custody lane. */
export async function buildOriginalArtifacts(raw:BuildInput,admission:Admission,clock:OriginalAdmissionClock):Promise<BuiltArtifacts>{
 require(process.platform==='linux'&&process.arch==='x64'&&process.geteuid?.()===0&&Object.getPrototypeOf(admission)===Admission.prototype);
 let entered=false;
 try{
 const input=validateBuildInput(raw);validateBuildClock(input.context,clock,admission.deadline());
 require(admission.deadline()<=input.context.deadline_ms&&process.execPath===input.executable.file&&(/^(24|26)\./.test(process.versions.node)));
 const guard=()=>{admission.assertOriginalClock(clock);require(Date.now()>=input.context.started_ms&&Date.now()<input.context.deadline_ms);};
 guard();admission.enter('original-artifact-build');entered=true;
  const parent=await privateDirectory(input.outputParent);guard();
  const pinned=async(r:FileRef,max:number)=>{guard();const b=(await regularBytes(r.file,max)).bytes;guard();require(sha(b)===r.sha256);return b;};
  await pinned(input.executable,128*1024*1024);
  const sourceBytes=await pinned(input.website.manifest,8*1024*1024),toolBytes=await pinned(input.tools.manifest,16*1024*1024),pinBytes=await pinned(input.releasePin,1024*1024);
  const source=validateBuildInventory(JSON.parse(decode(sourceBytes)),'source'),tools=validateBuildInventory(JSON.parse(decode(toolBytes)),'tools'),pin=JSON.parse(decode(pinBytes));parseReleasePin(pin);
  require(await realpath(input.website.root)===input.website.root&&await realpath(input.tools.root)===input.tools.root);guard();
  const scope=path.join(input.outputParent,'original-artifact-build');await mkdir(scope,{mode:0o700});await privateDirectory(scope);guard();
  for(const d of ['home','tmp','artifacts']){await mkdir(path.join(scope,d),{mode:0o700});guard();}
  let copied=0;const copyInventory=async(rows:Record<string,string>,root:string,role:'source'|'tools')=>{
   for(const [p,h]of Object.entries(rows)){guard();const data=await regularBytes(path.join(root,p),64*1024*1024);guard();require(sha(data.bytes)===h);copied+=data.bytes.byteLength;require(copied<=768*1024*1024);
    const target=role==='source'?p:'web/site/'+p;await directories(scope,target);guard();await writeNew(path.join(scope,target),data.bytes,role==='tools'&&data.executable);guard();}
  };
  await copyInventory(source,input.website.root,'source');await copyInventory(tools,input.tools.root,'tools');
  for(const [name,version]of [['astro','7.3.5'],['esbuild','0.28.2'],['vite','8.3.2'],['rolldown','1.2.12'],[ROLLDOWN,'1.2.12']]){const p='node_modules/'+name+'/package.json',bytes=(await regularBytes(path.join(scope,'web/site',p),1024*1024)).bytes;require(sha(bytes)===tools[p]);
   const pkg=JSON.parse(decode(bytes));require(pkg.name===name&&pkg.version===version&&pkg.license==='MIT');guard();}
  const native=(await regularBytes(path.join(scope,'web/site/node_modules/esbuild/bin/esbuild'),64*1024*1024)).bytes;
  require(native[0]===0x7f&&native[1]===0x45&&native[2]===0x4c&&native[3]===0x46);guard();
  const addon=(await regularBytes(path.join(scope,'web/site',ROLLDOWN_NATIVE),64*1024*1024)).bytes;
  require(sha(addon)===tools[ROLLDOWN_NATIVE]&&addon[0]===0x7f&&addon[1]===0x45&&addon[2]===0x4c&&addon[3]===0x46&&addon[4]===2&&addon[5]===1&&addon[18]===62&&addon[19]===0);guard();
  const env=buildEnvironment(input.identity,pin,scope),commands=fixedBuildCommands(scope),site=path.join(scope,'web/site');
  const run=async(command:FixedCommand)=>{
   guard();await pinned(input.executable,128*1024*1024);const relativeEntry=path.relative(scope,command.entry).split(path.sep).join('/');
   const expected=command.kind==='esbuild'||relativeEntry.includes('/node_modules/')?tools[relativeEntry.slice('web/site/'.length)]:source[relativeEntry];require(expected);
   require(sha((await regularBytes(command.entry,64*1024*1024)).bytes)===expected);guard();
   await new Promise<void>((resolve,reject)=>{
    const child=spawn(command.kind==='node'?input.executable.file:command.entry,command.kind==='node'?fixedNodeBuildArguments(scope,command):command.args,
     {cwd:site,env,stdio:['ignore','ignore','ignore'],shell:false,detached:true});let settled=false;
    const finish=(ok:boolean)=>{if(settled)return;settled=true;clearInterval(timer);if(!ok){admission.hold();try{if(child.pid)process.kill(-child.pid,'SIGKILL');}catch{}reject(Error('Original artifact build held'));}else resolve();};
    const timer=setInterval(()=>{try{guard();}catch{finish(false);}},50);
    child.once('error',()=>finish(false));child.once('close',(code,signal)=>{try{guard();finish(code===0&&signal===null);}catch{finish(false);}});
   });guard();
  };
  // First generate the site. Worker commands target the packaging directory below.
  for(const command of commands.filter(c=>c.kind==='node'))await run(command);
  const artifactDirectory=path.join(scope,'artifacts');await mkdir(path.join(artifactDirectory,'pages'),{mode:0o700});await mkdir(path.join(artifactDirectory,'migrations'),{mode:0o700});guard();
  const subjects:ByteSubject[]=[];let outputTotal=0;
  const collect=async(dir:string,prefix:string)=>{guard();for(const entry of (await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))){guard();const p=prefix+'/'+entry.name;relative(p);require(!entry.isSymbolicLink());
    if(entry.isDirectory()){await collect(path.join(dir,entry.name),p);continue;}require(entry.isFile());const data=(await regularBytes(path.join(dir,entry.name),MAX_FILE)).bytes;guard();
    const bytes=/\.(html|xml|txt|md)$/i.test(entry.name)&&entry.name!=='_headers'?new TextEncoder().encode(normalizeStagingNavigation(decode(data))):data;
    outputTotal+=bytes.byteLength;require(bytes.byteLength<=MAX_FILE&&outputTotal<=MAX_TOTAL&&subjects.length<MAX_FILES);subjects.push({path:p,bytes});
   }};
  await collect(path.join(site,'dist'),'pages');for(const s of subjects){await directories(artifactDirectory,s.path);await writeNew(path.join(artifactDirectory,s.path),s.bytes);guard();}
  await writeNew(path.join(artifactDirectory,'pages/_routes.json'),json({version:1,include:['/*'],exclude:[]}));guard();
  for(const f of [...MIGRATIONS,'0001_inbox.sql']){const p=f==='0001_inbox.sql'?'web/waitlist/testnet-inbox-migrations/'+f:'web/waitlist/migrations/'+f;const b=(await regularBytes(path.join(scope,p),MAX_FILE)).bytes;require(sha(b)===source[p]);await writeNew(path.join(artifactDirectory,'migrations',f),b);guard();}
  for(const command of commands.filter(c=>c.kind==='esbuild'))await run(command);
  // Re-read packaged bytes (including native bundler output); do not hash a precursor.
  const packaged:ByteSubject[]=[];let packagedTotal=0;const readOutput=async(dir:string,prefix='')=>{guard();for(const e of (await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))){guard();const p=prefix?prefix+'/'+e.name:e.name;relative(p);require(!e.isSymbolicLink());
    if(e.isDirectory()){await privateDirectory(path.join(dir,e.name));await readOutput(path.join(dir,e.name),p);continue;}require(e.isFile());const file=path.join(dir,e.name),data=(await regularBytes(file,MAX_FILE)).bytes;guard();
    await privateOutputFile(file);guard();const after=(await regularBytes(file,MAX_FILE)).bytes;require(sha(after)===sha(data));packagedTotal+=after.byteLength;require(packagedTotal<=MAX_TOTAL);packaged.push({path:p,bytes:after});require(packaged.length<=MAX_FILES);guard();}};
  await readOutput(artifactDirectory);const manifest=artifactManifestFromBytes(input.identity,packaged,pin),bytes=json(manifest),manifestFile=path.join(scope,'artifact-manifest.json');
  await pinned(input.website.manifest,8*1024*1024);await pinned(input.tools.manifest,16*1024*1024);await pinned(input.releasePin,1024*1024);
  const after=await privateDirectory(input.outputParent);require(after.dev===parent.dev&&after.ino===parent.ino);guard();await writeNew(manifestFile,bytes);guard();
  return{artifactDirectory,artifactManifest:{file:manifestFile,sha256:sha(bytes)}};
 }catch{admission.hold();return refused();}finally{if(entered)admission.leave();}
}
