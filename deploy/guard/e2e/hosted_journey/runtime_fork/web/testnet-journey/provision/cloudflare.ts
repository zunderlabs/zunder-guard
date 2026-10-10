// Concrete Cloudflare transport. Only exact rehearsal resources; no retries or credential fallback.
import {ACCOUNT,API,SITE,STAGING_ORIGIN,WORKERS,DATABASES,RECIPIENT,freshDatabaseId} from './policy.ts';
import {digest,validateOperation,type Plan,type Approval,type Adapter,type Operation} from './controller.ts';
import {assertAcceptanceMode} from './draft-release.ts';
import type {Artifacts} from './artifacts.ts';
import {uploadPages,reviewedPagesManifest} from './pages-upload.ts';
// Public deny-list copied from reviewed licence configuration; no external executable import.
const GUARD_LICENCE_PUBLIC_KEY='7e298d8aa9921205f1ef0995b8dc6fedd86a4365fe183825127f8cd56a82af46';
const OWN_ADDRESSES=['0x0f50112710913b51a5d037795e5f4efc08debf2a','0x4d91ba8f33d2199045ff46dde384f2c49deb3a3f','0x6b9e773128f453f5c2c60935ee2de2cbc5390a24'];
export interface Credentials {oauth:string;unsubscribe:string;issuer:string;inbox:string}
export interface Owned {kind:Operation['kind'];resource:string;id:string;fingerprint?:string;createdOn?:string;configuration?:string}
export interface Log {append(kind:string,data:unknown):Promise<void>}
const obj=(v:unknown):Record<string,unknown>=>{if(!v||typeof v!=='object'||Array.isArray(v))throw new Error('Invalid API object');return v as Record<string,unknown>;};
const arr=(v:unknown):Record<string,unknown>[]=>{if(!Array.isArray(v))throw new Error('Invalid API inventory');return v.map(obj);};
const A='/accounts/'+ACCOUNT;
export function validateIdentity(artifacts:Artifacts,credentials:Credentials){
 const {merchant,publicKey}=artifacts.manifest;
 if(!/^0x[0-9a-f]{40}$/.test(merchant)||/^0x0{40}$/.test(merchant)||[...OWN_ADDRESSES,'0x7f85c4539b36fa6666d5fc69ccb3eba528046f99'].includes(merchant)
  ||!/^[a-f0-9]{64}$/.test(publicKey)||/^0{64}$/.test(publicKey)||publicKey===GUARD_LICENCE_PUBLIC_KEY)throw new Error('Disposable identities required');
 const secrets=[credentials.unsubscribe,credentials.issuer,credentials.inbox];
 if(secrets.some(s=>typeof s!=='string'||!/^[A-Za-z0-9_-]{43,128}$/.test(s))||new Set(secrets).size!==3
  ||typeof credentials.oauth!=='string'||credentials.oauth.length<20||credentials.oauth.length>8192||/[\r\n]/.test(credentials.oauth))throw new Error('Independent disposable secrets and authorized OAuth required');
}
export function createCloudflareAdapter(p:Plan,approval:Approval,artifacts:Artifacts,credentials:Credentials,log:Log,fetcher:typeof fetch=fetch,now=()=>Date.now()){
 validateIdentity(artifacts,credentials);
 // Capture verified bounds; callers cannot reclassify cleanup artifacts or extend a draft lease.
 const acceptanceMode=artifacts.acceptanceMode,draftExpires=artifacts.draftReleaseExpires;
 assertAcceptanceMode(acceptanceMode);
 if(draftExpires!==undefined&&(!Number.isSafeInteger(draftExpires)||draftExpires>approval.expires))throw new Error('Invalid draft artifact lease');
 const applyDeadline=Math.min(p.end,approval.expires,draftExpires??Infinity);
 for(const bytes of [artifacts.api,artifacts.inbox,...artifacts.migrations,...artifacts.pages.map(f=>f.bytes)]){const text=new TextDecoder().decode(bytes);if(Object.values(credentials).some(secret=>text.includes(secret)))throw new Error('Credentials found in upload artifact');}
 if(approval.planHash!==digest(p)||approval.artifactManifestSha256!==digest(artifacts.manifest))throw new Error('Adapter approval mismatch');
 const owned=new Map<string,Owned>();let requests=0,mutation=0,activeDeadline=applyDeadline,cleanup=false,poisoned=false;
 const ruleBase=`/zones/${p.zone}/email/routing/rules`;
 const rulePages=[`${ruleBase}?per_page=50&page=1`,`${ruleBase}?per_page=50&page=2`];
 const reads=new Set([`${A}/workers/scripts`,`${A}/d1/database?per_page=100&page=1`,`${A}/pages/projects?per_page=10&page=1`,...rulePages,`${ruleBase}/catch_all`,`/zones/${p.zone}/email/routing/dns`,`${A}/pages/projects/${SITE}/upload-token`,...WORKERS.map(w=>`${A}/workers/scripts/${w}/settings`)]);
 function allowed(path:string,method:string,jwt?:string){
  if(jwt)return method==='POST'&&['/pages/assets/check-missing','/pages/assets/upload','/pages/assets/upsert-hashes'].includes(path)&&owned.has(SITE);
  if(path.startsWith('/pages/assets/'))return false;
  if(method==='GET')return reads.has(path)||[...owned.values()].some(o=>path===resourcePath(o));
  if(cleanup)return method==='DELETE'&&[...owned.values()].some(o=>path===resourcePath(o))||method==='PUT'&&WORKERS.some(w=>owned.has(w)&&path===`${A}/workers/scripts/${w}/schedules`);
  if(method==='POST')return path===`${A}/d1/database`||path===`${A}/pages/projects`||path===ruleBase
   ||path===`${A}/pages/projects/${SITE}/deployments`&&owned.has(SITE)
   ||DATABASES.some(d=>{const o=owned.get('d1:'+d);return o&&freshDatabaseId(o.id)&&path===`${A}/d1/database/${o.id}/query`;});
  return method==='PUT'&&WORKERS.some(w=>path===`${A}/workers/scripts/${w}`||owned.has(w)&&[`${A}/workers/scripts/${w}/subdomain`,`${A}/workers/scripts/${w}/schedules`].includes(path));
 }
 function resourcePath(o:Owned){
  if(o.kind==='create-d1')return `${A}/d1/database/${o.id}`;
  if(o.kind==='upload-worker')return `${A}/workers/scripts/${o.resource}`;
  if(o.kind==='configure-pages')return `${A}/pages/projects/${SITE}`;
  if(o.kind==='create-recipient')return `${ruleBase}/${o.id}`;
  throw new Error('Unowned resource kind');
 }
 async function request(path:string,method:string,body?:string|FormData,jwt?:string):Promise<unknown>{
  if(!cleanup)activeDeadline=Math.min(activeDeadline,applyDeadline);
  if(poisoned||!allowed(path,method,jwt)||++requests>120||now()>=activeDeadline)throw new Error('Transport scope, request budget or deadline refused');
  if(jwt&&(!/^[A-Za-z0-9_.-]{20,8192}$/.test(jwt)))throw new Error('Invalid upload credential');
  const writes=method!=='GET',serial=writes?++mutation:0;
  if(writes)await log.append('http-started',{serial,path,method});
  if(now()>=activeDeadline)throw new Error('Lease expired before HTTP dispatch');
  try{
   const res=await fetcher(API+path,{method,body,redirect:'error',headers:{authorization:'Bearer '+(jwt??credentials.oauth),...(typeof body==='string'?{'content-type':'application/json'}:{})},signal:AbortSignal.timeout(Math.max(1,Math.min(15000,activeDeadline-now())))});
   const reader=res.body?.getReader();if(!reader)throw new Error('Empty API response');const chunks:Uint8Array[]=[];let length=0;
   try{for(;;){const r=await reader.read();if(r.done)break;length+=r.value.length;if(length>2097152){await reader.cancel();throw new Error('API response bound exceeded');}chunks.push(r.value);}}finally{reader.releaseLock();}
   const all=new Uint8Array(length);let offset=0;for(const c of chunks){all.set(c,offset);offset+=c.length;}
   const envelope=obj(JSON.parse(new TextDecoder().decode(all)));
   if(!res.ok||envelope.success!==true)throw new Error('API request refused');
   // No response bodies, SQL results, email contents, or upload JWTs are journaled.
   if(writes)await log.append('http-acknowledged',{serial,path,method,status:res.status});
   return envelope.result;
  }catch{if(writes){poisoned=true;await log.append('http-unknown',{serial,path,method});}throw new Error('Cloudflare request failed; no retry');}
 }
 async function inventory(path:string,size?:number){
  // A strictly short page proves completeness without relying on unavailable totals. Full page blocks.
  const rows=arr(await request(path,'GET'));if(size!==undefined&&rows.length>=size)throw new Error('Inventory may be incomplete');return rows;
 }
 async function rules(){const rows=await inventory(rulePages[0]!,50);for(const r of rows){if(!/^[a-f0-9]{32}$/.test(String(r.id??r.tag))||!Array.isArray(r.matchers)||!Array.isArray(r.actions))throw new Error('Malformed routing rule');}return rows;}
 async function absent(op:Operation){
  validateOperation(op,p);
  if(op.kind==='create-d1')return !(await inventory(`${A}/d1/database?per_page=100&page=1`,100)).some(r=>{if(typeof r.name!=='string'||typeof r.uuid!=='string'||!/^([a-f0-9]{8})(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(r.uuid))throw new Error('Malformed D1 inventory');return r.name===op.resource;});
  if(op.kind==='upload-worker')return !(await inventory(`${A}/workers/scripts`)).some(r=>{if(typeof r.id!=='string')throw new Error('Malformed worker inventory');return r.id===op.resource;});
  if(op.kind==='configure-pages')return !(await inventory(`${A}/pages/projects?per_page=10&page=1`,10)).some(r=>{if(typeof r.name!=='string'||typeof r.id!=='string')throw new Error('Malformed Pages inventory');return r.name===SITE;});
  if(op.kind==='create-recipient')return !(await rules()).some(r=>arr(r.matchers).some(m=>m.type==='all'&&r.enabled!==false||m.field==='to'&&typeof m.value==='string'&&m.value.toLowerCase()===RECIPIENT.toLowerCase()));
  throw new Error('Unexpected absence check');
 }
 async function recordOwned(op:Operation,id:string,fingerprint?:string,createdOn?:string,configuration?:string){
  if(owned.has(op.kind==='create-d1'?'d1:'+op.resource:op.resource))throw new Error('Cannot replace ownership');
  const o={kind:op.kind,resource:op.resource,id,...(fingerprint?{fingerprint}:{}),...(createdOn?{createdOn}:{}),...(configuration?{configuration}:{})};
  await log.append('owned',o);owned.set(op.kind==='create-d1'?'d1:'+op.resource:op.resource,o);return{id,resource:op.resource};
 }
 async function verifyUnchanged(baseline:Plan['preserve']){
  const list=await rules(),mine=owned.get(RECIPIENT);
  const filtered=list.filter(r=>String(r.id??r.tag)!==mine?.id);
  if(mine){const current=list.find(r=>String(r.id??r.tag)===mine.id);if(current&&digest(current)!==mine.fingerprint)return false;}
  return digest(filtered)===baseline.rules&&digest(await request(`${ruleBase}/catch_all`,'GET'))===baseline.catchAll&&digest(await request(`/zones/${p.zone}/email/routing/dns`,'GET'))===baseline.dns;
 }
 async function perform(op:Operation,created:ReadonlyMap<string,string>,deadline:number){
  if(acceptanceMode!=='apply'||cleanup)throw new Error('Cleanup artifacts cannot provision resources');
  validateOperation(op,p);activeDeadline=Math.min(deadline,applyDeadline);
  const lease={TESTNET_LEASE_START:String(p.start),TESTNET_LEASE_END:String(p.end)};
  if(op.kind==='create-d1'){
   const r=obj(await request(`${A}/d1/database`,'POST',JSON.stringify({name:op.resource,read_replication:{mode:'disabled'}})));
   if(r.name!==op.resource||!freshDatabaseId(r.uuid)||[...owned.values()].some(o=>o.id===r.uuid))throw new Error('D1 creation identity refused');return recordOwned(op,r.uuid);
  }
  if(op.kind==='migrate-d1'){
   const id=owned.get('d1:'+op.resource)?.id;if(!freshDatabaseId(id)||created.get('d1:'+op.resource)!==id)throw new Error('D1 ownership mismatch');
   const chunks=op.resource===DATABASES[0]?artifacts.migrations.slice(0,4):artifacts.migrations.slice(4);
   const sql=chunks.map(b=>new TextDecoder('utf-8',{fatal:true}).decode(b)).join('\n');
   const r=arr(await request(`${A}/d1/database/${id}/query`,'POST',JSON.stringify({sql})));
   if(!r.length||r.some(row=>row.success!==true))throw new Error('Migration failure');return{id,resource:op.resource};
  }
  if(op.kind==='upload-worker'){
   const api=op.resource===WORKERS[0],dbName=DATABASES[api?0:1],db=owned.get('d1:'+dbName)?.id;
   if(!freshDatabaseId(db)||created.get('d1:'+dbName)!==db)throw new Error('Worker binding must be own fresh D1');
   const vars:Record<string,string>=api?{...lease,DEPLOYMENT_PROFILE:'staging',TESTNET_JOURNEY_ENABLED:'explicitly-provisioned',ENVIRONMENT:'testnet-journey',SITE_URL:STAGING_ORIGIN,ALLOWED_ORIGINS:STAGING_ORIGIN,LICENCE_CHAIN:'testnet',LICENCE_PUBLIC_KEY:artifacts.manifest.publicKey,SALES_HYPERLIQUID_ADDRESS:artifacts.manifest.merchant,SALES_EVM_NETWORKS:'',CONFIRM_PROVIDER:'cloudflare',TESTNET_DELIVERY_TO:RECIPIENT,MAIL_FROM:'hello@zunderlabs.com',MAIL_FROM_NAME:'Zunder Testnet',CONSENT_VERSION:'2026-10-06',MAX_SENDS_PER_DAY:'5'}:{...lease,DEPLOYMENT_PROFILE:'staging',TESTNET_INBOX_ENABLED:'explicitly-provisioned',TESTNET_INBOX_TO:RECIPIENT};
   const bindings:unknown[]=[...Object.entries(vars).map(([name,text])=>({type:'plain_text',name,text})),{type:'d1',name:api?'DB_TESTNET_JOURNEY':'DB_INBOX_TESTNET',id:db},...(api?[{type:'secret_text',name:'UNSUBSCRIBE_SECRET',text:credentials.unsubscribe},{type:'secret_text',name:'LICENCE_ISSUER_TOKEN',text:credentials.issuer},{type:'send_email',name:'EMAIL',allowed_destination_addresses:[RECIPIENT]}]:[{type:'secret_text',name:'TESTNET_INBOX_TOKEN',text:credentials.inbox}])];
   const form=new FormData();form.set('metadata',JSON.stringify({main_module:'worker.js',compatibility_date:'2026-10-01',bindings,limits:{cpu_ms:50},observability:{enabled:false},logpush:false}));
   form.set('worker.js',new Blob([new Uint8Array(api?artifacts.api:artifacts.inbox)],{type:'application/javascript+module'}),'worker.js');
   const r=obj(await request(`${A}/workers/scripts/${op.resource}`,'PUT',form));
   if(r.id!==op.resource||typeof r.etag!=='string'||!r.etag||typeof r.created_on!=='string'||!Number.isFinite(Date.parse(r.created_on)))throw new Error('Worker identity unavailable');
   const settings=await request(`${A}/workers/scripts/${op.resource}/settings`,'GET');
   const result=await recordOwned(op,op.resource,r.etag,r.created_on,digest(settings));
   await request(`${A}/workers/scripts/${op.resource}/subdomain`,'PUT',JSON.stringify({enabled:false,previews_enabled:false}));return result;
  }
  if(op.kind==='configure-pages'){
   const services=Object.fromEntries(WORKERS.map((service,i)=>[i===0?'TESTNET_JOURNEY_API':'TESTNET_INBOX',{service}]));
   const config={compatibility_date:'2026-10-01',env_vars:Object.fromEntries(Object.entries({...lease,DEPLOYMENT_PROFILE:'staging',TESTNET_SITE_ENABLED:'explicitly-provisioned'}).map(([k,value])=>[k,{type:'plain_text',value}])),services,limits:{cpu_ms:50},fail_open:false};
   const r=obj(await request(`${A}/pages/projects`,'POST',JSON.stringify({name:SITE,production_branch:'testnet-rehearsal',deployment_configs:{production:config,preview:config}})));
   if(r.name!==SITE||typeof r.id!=='string'||!/^[a-f0-9-]{32,36}$/.test(r.id))throw new Error('Pages identity refused');return recordOwned(op,r.id);
  }
  if(op.kind==='upload-pages'){
   if(!owned.has(SITE))throw new Error('Pages ownership required');
   const result=await uploadPages(request,{files:artifacts.pages,manifestSha256:reviewedPagesManifest(artifacts.pages)});
   return{id:result.deploymentId,resource:SITE};
  }
  if(op.kind==='create-recipient'){
   const {name,enabled,matchers,actions}=op.details;
   const r=obj(await request(ruleBase,'POST',JSON.stringify({name,enabled,matchers,actions})));
   const id=String(r.id??r.tag);if(!/^[a-f0-9]{32}$/.test(id)||digest(r.matchers)!==digest(matchers)||digest(r.actions)!==digest(actions)||r.enabled!==true)throw new Error('Recipient rule identity refused');return recordOwned(op,id,digest(r));
  }
  if(op.kind==='schedule'){
   if(!owned.has(op.resource)||created.get(op.resource)!==op.resource)throw new Error('Schedule ownership required');
   await request(`${A}/workers/scripts/${op.resource}/schedules`,'PUT',JSON.stringify((op.details.crons as string[]).map(cron=>({cron}))));return{id:op.resource,resource:op.resource};
  }
  throw new Error('Unknown operation');
 }
 const adapter:Adapter={absent,perform,persist:j=>log.append('controller',j),verifyUnchanged};
 // Cleanup uses the durable owned receipts, never a resource inferred from name after failure.
 // It requires separate approval bound to the complete saved journal. No automatic retry/resume.
 async function cleanupOwned(receipts:Owned[],cleanupDeadline:number){
  if(!Number.isSafeInteger(cleanupDeadline)||cleanupDeadline<=now()||cleanupDeadline>now()+300000)throw new Error('Bounded cleanup deadline required');
  cleanup=true;activeDeadline=cleanupDeadline;poisoned=false;requests=0;
  for(const o of receipts){
   const expected=p.operations.find(op=>op.kind===o.kind&&op.resource===o.resource);
   if(!expected||!['create-d1','upload-worker','configure-pages','create-recipient'].includes(o.kind)||owned.has(o.kind==='create-d1'?'d1:'+o.resource:o.resource)&&digest(owned.get(o.kind==='create-d1'?'d1:'+o.resource:o.resource))!==digest(o))throw new Error('Cleanup ownership refused');
   if(o.kind==='create-d1'&&!freshDatabaseId(o.id)||o.kind==='upload-worker'&&(o.id!==o.resource||!o.fingerprint||!o.createdOn||!o.configuration)||o.kind==='configure-pages'&&!/^[a-f0-9-]{32,36}$/.test(o.id)||o.kind==='create-recipient'&&(!/^[a-f0-9]{32}$/.test(o.id)||!o.fingerprint))throw new Error('Invalid cleanup receipt');
   owned.set(o.kind==='create-d1'?'d1:'+o.resource:o.resource,o);
  }
  const verify=async(o:Owned)=>{
   // Worker GET is source, not JSON; compare its immutable content ETag via list metadata.
   const raw=o.kind==='upload-worker'?(await inventory(`${A}/workers/scripts`)).find(r=>r.id===o.resource):await request(resourcePath(o),'GET');
   const r=obj(raw);
   if(o.kind==='upload-worker'&&(r.etag!==o.fingerprint||r.created_on!==o.createdOn||digest(await request(`${A}/workers/scripts/${o.resource}/settings`,'GET'))!==o.configuration)||o.kind==='create-d1'&&(r.uuid!==o.id||r.name!==o.resource)||o.kind==='configure-pages'&&(r.id!==o.id||r.name!==SITE)||o.kind==='create-recipient'&&digest(r)!==o.fingerprint)throw new Error('Remote identity changed; cleanup stopped');
  };
  for(const w of WORKERS){const o=owned.get(w);if(o){await verify(o);await request(`${A}/workers/scripts/${w}/schedules`,'PUT','[]');}}
  const order=[RECIPIENT,SITE,...WORKERS,...DATABASES.map(d=>'d1:'+d)];
  for(const name of order){const o=owned.get(name);if(!o)continue;await verify(o);await request(resourcePath(o),'DELETE');await log.append('deleted',o);owned.delete(name);}
  if(!await verifyUnchanged(p.preserve))throw new Error('Cleanup baseline mismatch');
  for(const receipt of receipts){const op=p.operations.find(o=>o.kind===receipt.kind&&o.resource===receipt.resource)!;if(!await absent(op))throw new Error('Cleanup absence not verified');}
  await log.append('known-resources-cleaned',{account:ACCOUNT,planHash:digest(p)});
 }
 return{adapter,cleanupOwned};
}
