// Pure new-plan policy. No I/O, credentials, controller callbacks or mutation authority.
import {createHash} from 'node:crypto';

export const ACCOUNT='a54357c24cdda7169fb77f53e9df1ddf';
export const PROJECT='zunder-testnet-journey';
export const BRANCH='testnet-rehearsal';
export const RECIPIENT='guard-e2e-20261009@zunderlabs.com';
export const PROTOCOL='retained-pages-v1';
const HASH=/^[a-f0-9]{64}$/;
const ID=/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const ZERO_ID='00000000-0000-0000-0000-000000000000';
const OWN_ADDRESSES=new Set(['0x0f50112710913b51a5d037795e5f4efc08debf2a','0x4d91ba8f33d2199045ff46dde384f2c49deb3a3f','0x6b9e773128f453f5c2c60935ee2de2cbc5390a24','0x7f85c4539b36fa6666d5fc69ccb3eba528046f99']);
const PRODUCTION_LICENCE_KEY='7e298d8aa9921205f1ef0995b8dc6fedd86a4365fe183825127f8cd56a82af46';

export interface Context {
 run_id:string;attempt:number;binding_sha256:string;started_ms:number;deadline_ms:number;
 merchant:string;publicKey:string;artifact_sha256:string;controller_sha256:string;
}
export interface BaselineConfig {
 compatibility_date:string;compatibility_flags:string[];
 env_vars:Record<string,{type:'plain_text';value:string}>;
 service_bindings:Record<string,{service:string;environment:'production'}>;
 limits:{cpu_ms:number}|null;fail_open:boolean;
}
export interface Retained {
 id:string;name:typeof PROJECT;production_branch:typeof BRANCH;domains:string[];source:null;
 deployment_configs:{production:BaselineConfig;preview:BaselineConfig};
 active:{id:string;environment:'production';branch:typeof BRANCH;content_sha256:string;configuration_sha256:string;
  artifact_manifest_sha256:string;deployment_observation_sha256:string;response_probe_sha256:string};
}
export interface Snapshot {
 account:typeof ACCOUNT;zone:string;checked_ms:number;
 inventory:{complete:true;workers:string[];databases:{name:string;id:string}[];recipientRules:string[]};
 retained:Retained;
 preserve:{rules:string;catchAll:string;dns:string};
 prerequisites:{workers:true;d1:true;emailSending:true;routingReady:true};
}
export interface Operation {id:string;kind:'create-d1'|'migrate-d1'|'upload-worker'|'patch-retained-pages'|'upload-pages'|'create-recipient'|'schedule';resource:string;details:Record<string,unknown>}
export interface RetainedPlan {
 version:2;protocol:typeof PROTOCOL;account:typeof ACCOUNT;zone:string;start:number;end:number;
 context:Context;readbackSha256:string;retained:Retained;preserve:Snapshot['preserve'];
 recipient:typeof RECIPIENT;budgetCapCents:500;incrementalEstimateCents:5;maxProvisioningSteps:11;
 operations:Operation[];
}

function fail():never{throw new Error('Retained Pages successor data refused');}
function object(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype)fail();
 return value as Record<string,unknown>;
}
function exact(value:unknown,keys:readonly string[]):Record<string,unknown>{
 const v=object(value);
 if(Object.keys(v).length!==keys.length||keys.some(key=>!Object.hasOwn(v,key)))fail();
 return v;
}
function integer(v:unknown,min:number,max:number):asserts v is number{if(!Number.isSafeInteger(v)||(v as number)<min||(v as number)>max)fail();}
function hash(v:unknown):asserts v is string{if(typeof v!=='string'||!HASH.test(v)||/^0{64}$/.test(v))fail();}
function id(v:unknown):asserts v is string{if(typeof v!=='string'||!ID.test(v)||v===ZERO_ID)fail();}
function strings(v:unknown,max=128):asserts v is string[]{
 if(!Array.isArray(v)||v.length>max||v.some(x=>typeof x!=='string'||x.length===0||x.length>256)||new Set(v).size!==v.length)fail();
}
/** Matches the keeper's existing JSON.stringify digest; caller object order is preserved. */
export function digest(value:unknown):string{return createHash('sha256').update(JSON.stringify(value)).digest('hex');}

export function validateContext(raw:unknown):Context{
 const c=exact(raw,['run_id','attempt','binding_sha256','started_ms','deadline_ms','merchant','publicKey','artifact_sha256','controller_sha256']);
 if(typeof c.run_id!=='string'||!/^[1-9][0-9]{0,19}$/.test(c.run_id))fail();
 integer(c.attempt,1,999);integer(c.started_ms,1,Number.MAX_SAFE_INTEGER);integer(c.deadline_ms,1,Number.MAX_SAFE_INTEGER);
 if(c.deadline_ms<=c.started_ms||c.deadline_ms-c.started_ms>1200000)fail();
 for(const key of ['binding_sha256','artifact_sha256','controller_sha256'])hash(c[key]);
 if(typeof c.merchant!=='string'||!/^0x[0-9a-f]{40}$/.test(c.merchant)||/^0x0{40}$/.test(c.merchant)||OWN_ADDRESSES.has(c.merchant))fail();
 hash(c.publicKey);if(c.publicKey===PRODUCTION_LICENCE_KEY)fail();
 return structuredClone(c) as unknown as Context;
}
export function epochNames(context:Context){
 const c=validateContext(context),suffix='-r'+c.run_id+'-a'+c.attempt;
 return{workers:['zunder-testnet-journey-api'+suffix,'zunder-testnet-journey-inbox'+suffix],
 databases:['zunder-testnet-journey'+suffix,'zunder-testnet-inbox'+suffix]};
}
function config(raw:unknown):BaselineConfig{
 const c=exact(raw,['compatibility_date','compatibility_flags','env_vars','service_bindings','limits','fail_open']);
 if(typeof c.compatibility_date!=='string'||!/^20[0-9]{2}-[01][0-9]-[0-3][0-9]$/.test(c.compatibility_date)||!Number.isFinite(Date.parse(c.compatibility_date)))fail();
 strings(c.compatibility_flags,16);
 if(c.compatibility_flags.some(f=>!/^[a-z0-9_]{1,64}$/.test(f)))fail();
 const vars=object(c.env_vars),allowed=new Set(['DEPLOYMENT_PROFILE','TESTNET_SITE_ENABLED','TESTNET_LEASE_START','TESTNET_LEASE_END']);
 for(const [name,rawVar]of Object.entries(vars)){
  if(!allowed.has(name))fail();const v=exact(rawVar,['type','value']);
  if(v.type!=='plain_text'||typeof v.value!=='string'||v.value.length>128)fail();
  if(name==='DEPLOYMENT_PROFILE'&&v.value!=='staging'||name==='TESTNET_SITE_ENABLED'&&v.value!=='explicitly-provisioned'||name.startsWith('TESTNET_LEASE_')&&!/^[1-9][0-9]{0,15}$/.test(v.value))fail();
 }
 const services=object(c.service_bindings);
 for(const [name,rawService]of Object.entries(services)){
  if(!['TESTNET_JOURNEY_API','TESTNET_INBOX'].includes(name))fail();
  const s=exact(rawService,['service','environment']);
  if(s.environment!=='production'||typeof s.service!=='string'||
   !(name==='TESTNET_JOURNEY_API'?/^zunder-testnet-journey-api(?:-r[1-9][0-9]{0,19}-a[1-9][0-9]{0,2})?$/:/^zunder-testnet-journey-inbox(?:-r[1-9][0-9]{0,19}-a[1-9][0-9]{0,2})?$/).test(s.service))fail();
 }
 if(c.limits!==null){const limits=exact(c.limits,['cpu_ms']);integer(limits.cpu_ms,1,50);}
 if(typeof c.fail_open!=='boolean')fail();
 // Only an idle public static baseline may retain provider fail-open/default limits.
 if((c.fail_open||c.limits===null)&&(Object.keys(vars).length!==0||Object.keys(services).length!==0))fail();return structuredClone(c) as unknown as BaselineConfig;
}
export function validateRetained(raw:unknown):Retained{
 const p=exact(raw,['id','name','production_branch','domains','source','deployment_configs','active']);
 id(p.id);if(p.name!==PROJECT||p.production_branch!==BRANCH||p.source!==null||!Array.isArray(p.domains)||p.domains.length!==2||new Set(p.domains).size!==2||!['zunder-testnet-journey.pages.dev','staging.zunderlabs.com'].every(d=>(p.domains as unknown[]).includes(d)))fail();
 const configs=exact(p.deployment_configs,['production','preview']);config(configs.production);config(configs.preview);
 const active=exact(p.active,['id','environment','branch','content_sha256','configuration_sha256','artifact_manifest_sha256','deployment_observation_sha256','response_probe_sha256']);id(active.id);
 if(active.environment!=='production'||active.branch!==BRANCH)fail();hash(active.content_sha256);hash(active.configuration_sha256);
 for(const key of ['artifact_manifest_sha256','deployment_observation_sha256','response_probe_sha256'])hash(active[key]);
 if(active.configuration_sha256!==digest(configs.production))fail();
 return structuredClone(p) as unknown as Retained;
}
function preserve(raw:unknown):Snapshot['preserve']{
 const p=exact(raw,['rules','catchAll','dns']);for(const v of Object.values(p))hash(v);return structuredClone(p) as unknown as Snapshot['preserve'];
}
export function validateSnapshot(raw:unknown,context:Context,now:number):Snapshot{
 const s=exact(raw,['account','zone','checked_ms','inventory','retained','preserve','prerequisites']);
 integer(now,1,Number.MAX_SAFE_INTEGER);integer(s.checked_ms,1,Number.MAX_SAFE_INTEGER);
 if(s.account!==ACCOUNT||typeof s.zone!=='string'||!/^[0-9a-f]{32}$/.test(s.zone)||now<s.checked_ms||now-s.checked_ms>60000)fail();
 validateRetained(s.retained);preserve(s.preserve);
 const inv=exact(s.inventory,['complete','workers','databases','recipientRules']);if(inv.complete!==true)fail();strings(inv.workers);strings(inv.recipientRules);
 if(!Array.isArray(inv.databases)||inv.databases.length>=100)fail();
 const dbs=inv.databases.map(db=>{const d=exact(db,['name','id']);if(typeof d.name!=='string'||!/^[a-zA-Z0-9_-]{1,63}$/.test(d.name))fail();id(d.id);return d;});
 if(new Set(dbs.map(d=>d.name)).size!==dbs.length||new Set(dbs.map(d=>d.id)).size!==dbs.length)fail();
 const names=epochNames(context),workers=inv.workers;
 if(names.workers.some(n=>workers.includes(n))||names.databases.some(n=>dbs.some(d=>d.name===n))||inv.recipientRules.some(r=>r.toLowerCase()===RECIPIENT))fail();
 const prereq=exact(s.prerequisites,['workers','d1','emailSending','routingReady']);if(Object.values(prereq).some(v=>v!==true))fail();
 return structuredClone(s) as unknown as Snapshot;
}
export function operations(context:Context):Operation[]{
 const c=validateContext(context),n=epochNames(c);
 return[
  ...n.databases.map((resource,i)=>({id:'database-'+i,kind:'create-d1' as const,resource,details:{readReplication:'disabled'}})),
  ...n.databases.map((resource,i)=>({id:'schema-'+i,kind:'migrate-d1' as const,resource,details:{database:'owned-create-only',migrationSet:i===0?'licence-0001..0004':'inbox-0001',admittedBytesOnly:true}})),
  ...n.workers.map((resource,i)=>({id:'worker-'+i,kind:'upload-worker' as const,resource,details:{database:n.databases[i],binding:i===0?'DB_TESTNET_JOURNEY':'DB_INBOX_TESTNET',workersDev:false,previews:false,routes:[],cpuMs:50,leaseStart:c.started_ms,leaseEnd:c.deadline_ms}})),
  {id:'pages',kind:'patch-retained-pages',resource:PROJECT,details:{requireRetainedIdentity:true,productionBranch:BRANCH,service_bindings:{TESTNET_JOURNEY_API:{service:n.workers[0],environment:'production'},TESTNET_INBOX:{service:n.workers[1],environment:'production'}},leaseStart:c.started_ms,leaseEnd:c.deadline_ms}},
  {id:'assets',kind:'upload-pages',resource:PROJECT,details:{maxDeployments:1,branch:BRANCH,admittedBytesOnly:true}},
  {id:'recipient',kind:'create-recipient',resource:RECIPIENT,details:{enabled:true,matchers:[{type:'literal',field:'to',value:RECIPIENT}],actions:[{type:'worker',value:[n.workers[1]]}],catchAll:false}},
  {id:'watcher',kind:'schedule',resource:n.workers[0]!,details:{crons:['* * * * *'],expires:c.deadline_ms}},
  {id:'purge',kind:'schedule',resource:n.workers[1]!,details:{crons:['0 * * * *'],expires:c.deadline_ms}},
 ];
}
export function makePlan(rawSnapshot:unknown,rawContext:unknown,now:number):RetainedPlan{
 const c=validateContext(rawContext),s=validateSnapshot(rawSnapshot,c,now);
 if(now<c.started_ms||now>=c.deadline_ms)fail();
 return{version:2,protocol:PROTOCOL,account:ACCOUNT,zone:s.zone,start:c.started_ms,end:c.deadline_ms,
  context:c,readbackSha256:digest(s),retained:s.retained,preserve:s.preserve,recipient:RECIPIENT,
  budgetCapCents:500,incrementalEstimateCents:5,maxProvisioningSteps:11,operations:operations(c)};
}
export function validatePlan(raw:unknown,now:number):RetainedPlan{
 const p=exact(raw,['version','protocol','account','zone','start','end','context','readbackSha256','retained','preserve','recipient','budgetCapCents','incrementalEstimateCents','maxProvisioningSteps','operations']);
 const c=validateContext(p.context);integer(now,1,Number.MAX_SAFE_INTEGER);
 if(p.version!==2||p.protocol!==PROTOCOL||p.account!==ACCOUNT||p.recipient!==RECIPIENT||typeof p.zone!=='string'||!/^[a-f0-9]{32}$/.test(p.zone)||p.start!==c.started_ms||p.end!==c.deadline_ms||now<c.started_ms||now>=c.deadline_ms||p.budgetCapCents!==500||p.incrementalEstimateCents!==5||p.maxProvisioningSteps!==11)fail();
 hash(p.readbackSha256);validateRetained(p.retained);preserve(p.preserve);
 if(digest(p.operations)!==digest(operations(c)))fail();return structuredClone(p) as unknown as RetainedPlan;
}
