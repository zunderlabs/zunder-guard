// Read-only account inspection. Credentials stay in child-process memory and HTTPS headers.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { mkdir, open, lstat } from 'node:fs/promises';
import { resolveMx, resolveTxt } from 'node:dns/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ACCOUNT,API,DOMAIN,SITE,WORKERS,DATABASES,RECIPIENT,MAX_REQUESTS,requireRead } from './policy.ts';
const exec=promisify(execFile);
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const hash=(v:unknown)=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
type Result={status:number;ok:boolean;result:unknown;info?:unknown;errorCodes:unknown[]};
const object=(v:unknown):Record<string,unknown>=>v&&typeof v==='object'&&!Array.isArray(v)?v as Record<string,unknown>:{};
const record=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=256&&v.trim()===v&&!/[\x00-\x1f\x7f]/.test(v);
const integer=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;
function collection(r:Result,identity:(row:Record<string,unknown>)=>unknown):Record<string,unknown>[] {
  if(!r.ok)return [];
  if(!Array.isArray(r.result)||!r.result.every(record))throw new Error('Malformed inspection collection');
  const ids=r.result.map(identity);
  if(!ids.every(text)||new Set(ids).size!==ids.length)throw new Error('Malformed or duplicate inventory identity');
  return r.result;
}
type Page={complete:boolean;totalPages?:number;totalCount?:number};
function page(r:Result,length:number,number:number,size:number):Page {
  if(!r.ok)return {complete:false};
  if(length>size)throw new Error('Oversized inspection page');
  if(r.info===undefined)return {complete:length<size};
  if(!record(r.info))throw new Error('Malformed inspection pagination');
  const v=r.info;
  if(Object.keys(v).some(k=>!['page','per_page','count','total_count','total_pages'].includes(k)))throw new Error('Unsupported inspection pagination');
  if(!integer(v.page)||v.page!==number||!integer(v.per_page)||v.per_page!==size
    ||!integer(v.count)||v.count!==length
    ||(v.total_count!==undefined&&!integer(v.total_count))
    ||(v.total_pages!==undefined&&(!integer(v.total_pages)||v.total_pages<1))
    ||(v.total_count===undefined&&v.total_pages===undefined))throw new Error('Invalid inspection pagination');
  const totalCount=v.total_count as number|undefined;
  const totalPages=totalCount===undefined?v.total_pages as number:Math.max(1,Math.ceil(totalCount/size));
  if((v.total_pages!==undefined&&v.total_pages!==totalPages)||number>totalPages
    ||(number<totalPages&&length!==size)
    ||(totalCount!==undefined&&length!==Math.min(size,Math.max(0,totalCount-(number-1)*size)))) {
    throw new Error('Inconsistent inspection pagination');
  }
  return {complete:number===totalPages,totalPages,totalCount};
}
// Wrangler 4.147.0 bundles Cloudflare SDK 5.2.0: workers.scripts.list uses
// ScriptsSinglePage (not V4PagePagination). A valid result array is complete under
// that endpoint contract. If metadata is nevertheless supplied, validate it.
function singlePage(r:Result,length:number):boolean {
  if(!r.ok)return false;
  if(r.info===undefined)return true;
  if(!record(r.info)||!integer(r.info.per_page)||r.info.per_page<1)throw new Error('Malformed single-page metadata');
  return page(r,length,1,r.info.per_page).complete;
}
function ruleIdentity(row:Record<string,unknown>):unknown {
  if(!Array.isArray(row.matchers)||row.matchers.length===0||!row.matchers.every(m=>record(m)
    &&(m.type==='all'||(m.type==='literal'&&m.field==='to'&&text(m.value))))) {
    throw new Error('Malformed routing matchers');
  }
  return row.tag??row.id;
}
export async function existingOAuth():Promise<string>{
  // Use the authorized CLI session, not the global key in .env. Disable Wrangler's disk log
  // before asking its credential API so it cannot persist the captured token output.
  const r=await exec(process.execPath,[path.join(root,'waitlist/node_modules/wrangler/bin/wrangler.js'),'auth','token','--json'],{
    cwd:path.join(root,'waitlist'),env:{PATH:process.env.PATH,HOME:process.env.HOME,WRANGLER_SEND_METRICS:'false',WRANGLER_WRITE_LOGS:'false'},
    timeout:15000,maxBuffer:16384,
  }).catch(()=>{throw new Error('Existing Wrangler session unavailable; no fallback credentials');});
  let v:Record<string,unknown>;
  try{v=object(JSON.parse(r.stdout));}catch{throw new Error('Existing Wrangler credential response invalid');}
  if(v.type!=='oauth'||typeof v.token!=='string'||!v.token||v.token.length>8192)throw new Error('Only existing OAuth session supported');
  return v.token;
}
export async function inspect(token:string, fetcher:typeof fetch=fetch, dnsLookup={resolveMx,resolveTxt}){
  let count=0,zone:string|undefined;
  const receipts:{path:string;status:number;ok:boolean;errorCodes:unknown[]}[]=[];
  async function get(p:string):Promise<Result>{
    requireRead(p,zone);if(++count>MAX_REQUESTS)throw new Error('Read-only request budget exceeded');
    const res=await fetcher(API+p,{method:'GET',headers:{authorization:`Bearer ${token}`},redirect:'error',signal:AbortSignal.timeout(15000)});
    const reader=res.body?.getReader();if(!reader)throw new Error('Empty Cloudflare response');
    let body='',bytes=0;try{for(;;){const {value,done}=await reader.read();if(done)break;bytes+=value.length;
      if(bytes>2097152){await reader.cancel();throw new Error('Cloudflare response exceeds inspection bound');}body+=new TextDecoder().decode(value);
    }}finally{reader.releaseLock();}
    let v:Record<string,unknown>;try{const parsed:unknown=JSON.parse(body);if(!record(parsed))throw new Error();v=parsed;}catch{throw new Error('Invalid inspection response');}
    const result={status:res.status,ok:res.ok&&v.success===true,result:v.result,
      info:v.result_info,errorCodes:Array.isArray(v.errors)?v.errors.filter(record).map(e=>e.code):[]};
    receipts.push({path:p,status:result.status,ok:result.ok,errorCodes:result.errorCodes});return result;
  }
  const z=await get(`/zones?name=${DOMAIN}&account.id=${ACCOUNT}`);
  const found=collection(z,r=>r.id);
  if(!z.ok||found.length!==1||found[0]?.name!==DOMAIN||object(found[0]?.account).id!==ACCOUNT||!/^[0-9a-f]{32}$/.test(String(found[0]?.id)))
    throw new Error('Exact account/domain not confirmed; inspection stopped');
  zone=String(found[0]!.id);
  const a='/accounts/'+ACCOUNT;
  const entitlements=await get(`${a}/entitlements`);
  const subs=await get(`${a}/subscriptions`), settings=await get(`${a}/workers/account-settings`);
  const scripts=await get(`${a}/workers/scripts`), db=await get(`${a}/d1/database?per_page=100&page=1`);
  const pages=await get(`${a}/pages/projects?per_page=10&page=1`);
  const routing=await get(`/zones/${zone}/email/routing`), dns=await get(`/zones/${zone}/email/routing/dns`);
  const rules=await get(`/zones/${zone}/email/routing/rules?per_page=50&page=1`);
  const allRules=collection(rules,ruleIdentity),firstPage=page(rules,allRules.length,1,50);
  let rulesComplete=firstPage.complete;
  if(rules.ok&&!rulesComplete&&(firstPage.totalPages===undefined||firstPage.totalPages===2)){
    const next=await get(`/zones/${zone}/email/routing/rules?per_page=50&page=2`);
    const nextRules=collection(next,ruleIdentity),nextPage=page(next,nextRules.length,2,50);
    if(next.ok&&((firstPage.totalPages!==undefined&&nextPage.totalPages!==undefined&&firstPage.totalPages!==nextPage.totalPages)
      ||(firstPage.totalCount!==undefined&&nextPage.totalCount!==undefined&&firstPage.totalCount!==nextPage.totalCount))) {
      throw new Error('Routing inventory changed between pages');
    }
    // Metadata known on the first page cannot be discarded by the second response.
    if(next.ok&&firstPage.totalPages===2&&nextRules.length===0)throw new Error('Missing final routing page');
    if(next.ok&&firstPage.totalCount!==undefined
      &&nextRules.length!==Math.max(0,firstPage.totalCount-50))throw new Error('Incomplete routing inventory');
    allRules.push(...nextRules);
    if(new Set(allRules.map(ruleIdentity)).size!==allRules.length)throw new Error('Duplicate routing identity across pages');
    rulesComplete=nextPage.complete;
  }
  const catchAll=await get(`/zones/${zone}/email/routing/rules/catch_all`);
  const sending=await get(`/zones/${zone}/email/sending/subdomains`);
  const mxApi=await get(`/zones/${zone}/dns_records?type=MX&name=${DOMAIN}&per_page=100`);
  const mx=await dnsLookup.resolveMx(DOMAIN).catch(()=>null), txt=await dnsLookup.resolveTxt(DOMAIN).catch(()=>null);
  const matches=allRules.filter(r=>(r.matchers as Record<string,unknown>[]).some(m=>(m.type==='all'&&r.enabled!==false)||(m.field==='to'&&String(m.value).toLowerCase()===RECIPIENT.toLowerCase())));
  const workerRows=collection(scripts,r=>r.id),databaseRows=collection(db,r=>text(r.uuid)&&text(r.name)?r.uuid:undefined);
  const pageRows=collection(pages,r=>text(r.id)&&text(r.name)?r.id:undefined);
  const entitlementRows=collection(entitlements,r=>r.id),sendingRows=collection(sending,r=>r.name);
  collection(mxApi,r=>r.id); // A malformed DNS array must not become an apparently valid hash.
  const subscriptionRows=collection(subs,r=>r.id);
  const subscriptionSummary=subscriptionRows.map(s=>({status:s.status??null,currency:s.currency??null,price:s.price??null,frequency:s.frequency??null,
    ratePlan:{id:object(s.rate_plan).id??null,publicName:object(s.rate_plan).public_name??null}}));
  return {version:1,checkedAt:new Date().toISOString(),account:ACCOUNT,zone,domain:DOMAIN,methods:['GET'],requestCount:count,
    entitlements:{available:singlePage(entitlements,entitlementRows.length),items:entitlementRows.filter(e=>/worker|d1|pages|email|sending/i.test(String(e.id)+' '+JSON.stringify(e.feature))).map(e=>({id:e.id,allocation:e.allocation,deletedDate:e.deleted_date,feature:e.feature}))},
    subscriptions:{available:singlePage(subs,subscriptionRows.length),items:subscriptionSummary},workersSettings:{available:settings.ok,settings:settings.ok?settings.result:null},
    zonePlan:found[0]!.plan??null,
    names:{workers:{available:singlePage(scripts,workerRows.length),collisions:WORKERS.filter(n=>workerRows.some(r=>r.id===n))},
      databases:{available:db.ok,complete:page(db,databaseRows.length,1,100).complete,count:databaseRows.length,collisions:DATABASES.filter(n=>databaseRows.some(r=>r.name===n))},
      pages:{available:pages.ok,complete:page(pages,pageRows.length,1,10).complete,collisions:pageRows.filter(r=>r.name===SITE).map(r=>r.name)}},
    routing:{available:routing.ok,settings:routing.ok?routing.result:null,rulesComplete,ruleCount:allRules.length,recipient:RECIPIENT,recipientAlreadyExists:matches.length>0,
      rulesSha256:hash(allRules),catchAll:{available:catchAll.ok,enabled:object(catchAll.result).enabled??null,sha256:hash(catchAll.result)},
      dns:{available:dns.ok,sha256:hash(dns.result)},mxApiAvailable:mxApi.ok,mxApiSha256:hash(mxApi.result)},
    sending:{available:singlePage(sending,sendingRows.length),domains:sendingRows.filter(s=>s.name===DOMAIN).map(s=>({name:s.name,enabled:s.enabled,tag:s.tag,dkimSelector:s.dkim_selector,returnPath:s.return_path_domain}))},
    publicDns:{mx,spf:txt?.map(parts=>parts.join('')).filter(t=>t.startsWith('v=spf1'))??null},receipts};
}
async function main(){
  if(process.argv.length!==3||!path.isAbsolute(process.argv[2]!))throw new Error('Provide one absolute private inspection output directory');
  const output=process.argv[2]!;await mkdir(output,{mode:0o700});
  const st=await lstat(output);if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o077))throw new Error('Private directory required');
  const snapshot=await inspect(await existingOAuth());
  const f=await open(path.join(output,'account-readback.json'),'wx',0o600);
  try{await f.writeFile(JSON.stringify(snapshot,null,2)+'\n');}finally{await f.close();}
  console.log(JSON.stringify({output:path.join(output,'account-readback.json'),sha256:hash(snapshot),account:snapshot.account,
    requestCount:snapshot.requestCount,names:snapshot.names,routing:{available:snapshot.routing.available,settings:snapshot.routing.settings,
    rulesComplete:snapshot.routing.rulesComplete,recipientAlreadyExists:snapshot.routing.recipientAlreadyExists},subscriptions:snapshot.subscriptions,
    entitlements:snapshot.entitlements,workersSettings:snapshot.workersSettings,sending:snapshot.sending,publicDns:snapshot.publicDns}));
}
if(import.meta.main)main().catch(()=>{console.error('Read-only account inspection failed; no credentials or response bodies logged');process.exitCode=1;});
