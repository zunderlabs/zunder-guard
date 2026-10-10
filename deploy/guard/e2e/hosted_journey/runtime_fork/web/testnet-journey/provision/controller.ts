// Reviewable provisioning controller core. No credential loading, fetch, CLI apply or hidden
// deployment transport: root supplies an explicitly authorized adapter after reviewing the plan.
import {createHash} from 'node:crypto';
import type {DraftReleaseAcceptance} from './draft-release.ts';
import {readFile,writeFile} from 'node:fs/promises';
import {ACCOUNT,DOMAIN,SITE,WORKERS,DATABASES,RECIPIENT,freshDatabaseId} from './policy.ts';
export type Operation={id:string;kind:'create-d1'|'migrate-d1'|'upload-worker'|'configure-pages'|'upload-pages'|'create-recipient'|'schedule';resource:string;details:Record<string,unknown>};
export interface Snapshot{
 account:string;zone:string;checkedAt:string;
 names:{workers:{available:boolean;collisions:string[]};databases:{available:boolean;complete:boolean;collisions:string[]};pages:{available:boolean;complete:boolean;collisions:string[]}};
 entitlements:{available:boolean;items:{id:unknown;allocation:unknown;deletedDate:unknown}[]};
 routing:{available:boolean;settings:unknown;rulesComplete:boolean;recipient:string;recipientAlreadyExists:boolean;rulesSha256:string;catchAll:{available:boolean;sha256:string};dns:{available:boolean;sha256:string}};
 sending:{available:boolean;domains:{name:unknown;enabled:unknown}[]};
}
export interface Plan{version:2;account:string;zone:string;start:number;end:number;readbackSha256:string;recipient:string;maxProvisioningSteps:11;budgetCapCents:500;incrementalEstimateCents:5;approval:'pending-root-review';blocked:string[];operations:Operation[];preserve:{rules:string;catchAll:string;dns:string}}
export const digest=(v:unknown)=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
export function plan(snapshot:Snapshot,start:number):Plan{
 if(snapshot.account!==ACCOUNT||!/^[0-9a-f]{32}$/.test(snapshot.zone)||!Number.isSafeInteger(start))throw new Error('Wrong account or invalid lease');
 const blocked:string[]=[];
 if(!Number.isFinite(Date.parse(snapshot.checkedAt))||start<Date.parse(snapshot.checkedAt)||start-Date.parse(snapshot.checkedAt)>900000)blocked.push('Read-only snapshot must be refreshed within 15 minutes of the run');
 for(const [kind,state]of Object.entries(snapshot.names)){if(!state.available||('complete'in state&&!state.complete))blocked.push(`${kind} inventory incomplete`);if(state.collisions.length)blocked.push(`${kind} name collision: never replace/reuse`);}
 const value=(id:string)=>snapshot.entitlements.items.find(e=>e.id===id&&!e.deletedDate)?.allocation as {value?:unknown}|undefined;
 if(!snapshot.entitlements.available||['email.sending.enabled','workers.enabled','d1.enabled'].some(id=>value(id)?.value!==true))blocked.push('Existing sending/Workers/D1 entitlement not confirmed; never upgrade automatically');
 const routing=snapshot.routing.settings as {enabled?:boolean;status?:string}|null;
 if(!snapshot.routing.available||!routing?.enabled||routing.status!=='ready'||!snapshot.routing.rulesComplete||snapshot.routing.recipient!==RECIPIENT||snapshot.routing.recipientAlreadyExists)blocked.push('Routing not ready or exact new recipient not proven absent');
 if(!snapshot.routing.catchAll.available||!snapshot.routing.dns.available)blocked.push('Existing routing/DNS baseline not captured');
 if(!snapshot.sending.available||!snapshot.sending.domains.some(d=>d.name===DOMAIN&&d.enabled===true))blocked.push('Existing sending domain is not enabled');
 blocked.push('Root must approve controller/source/cost plan; no external writes are authorized by this file');
 blocked.push('Funded eligible Testnet owner, fresh merchant, disposable issuer identity and native verifier not yet provisioned');
 const operations:Operation[]=[
  ...DATABASES.map((name,i)=>({id:`database-${i}`,kind:'create-d1' as const,resource:name,details:{name,readReplication:{mode:'disabled'}}})),
  ...DATABASES.map((name,i)=>({id:`schema-${i}`,kind:'migrate-d1' as const,resource:name,details:{databaseId:'from-own-create-receipt-only',migrationSet:i===0?'web/waitlist/migrations/0001..0004':'web/waitlist/testnet-inbox-migrations/0001_inbox.sql',requireReviewedHashes:true}})),
  ...WORKERS.map((name,i)=>({id:`worker-${i}`,kind:'upload-worker' as const,resource:name,details:{requireFreshName:true,entry:i===0?'leased-testnet-index':'leased-testnet-inbox',workersDev:false,previewUrls:false,routes:[],observability:false,cpuMs:50,
    databaseBinding:i===0?'DB_TESTNET_JOURNEY':'DB_INBOX_TESTNET',secretBindings:i===0?['UNSUBSCRIBE_SECRET','LICENCE_ISSUER_TOKEN']:['TESTNET_INBOX_TOKEN'],
    email:i===0?{binding:'EMAIL',allowedDestinationAddresses:[RECIPIENT]}:null,leaseStart:start,leaseEnd:start+1200000}})),
  {id:'pages',kind:'configure-pages',resource:SITE,details:{requireFreshName:true,productionBranch:'testnet-rehearsal',customDomains:[],gitIntegration:null,builds:false,cpuMs:50,
    services:{TESTNET_JOURNEY_API:WORKERS[0],TESTNET_INBOX:WORKERS[1]},DEPLOYMENT_PROFILE:'staging',TESTNET_SITE_ENABLED:'explicitly-provisioned',leaseStart:start,leaseEnd:start+1200000}},
  {id:'assets',kind:'upload-pages',resource:SITE,details:{maxDeployments:1,requireManifest:true,worker:'leased-testnet-pages',secretsForbidden:true}},
  {id:'recipient',kind:'create-recipient',resource:RECIPIENT,details:{name:'Zunder isolated rehearsal 20261009',enabled:true,matchers:[{type:'literal',field:'to',value:RECIPIENT}],actions:[{type:'worker',value:[WORKERS[1]]}],catchAll:false}},
  {id:'watcher',kind:'schedule',resource:WORKERS[0],details:{crons:['* * * * *'],expires:start+1200000}},
  {id:'purge',kind:'schedule',resource:WORKERS[1],details:{crons:['0 * * * *'],expires:start+1200000}},
 ];
 return{version:2,account:ACCOUNT,zone:snapshot.zone,start,end:start+1200000,readbackSha256:digest(snapshot),recipient:RECIPIENT,maxProvisioningSteps:11,budgetCapCents:500,incrementalEstimateCents:5,approval:'pending-root-review',blocked,operations,preserve:{rules:snapshot.routing.rulesSha256,catchAll:snapshot.routing.catchAll.sha256,dns:snapshot.routing.dns.sha256}};
}
export interface Journal{account:string;planHash:string;entries:{id:string;state:'started'|'created'|'unknown';resource:string;remoteId?:string}[]}
export interface Approval{draftReleaseAcceptance?:DraftReleaseAcceptance;planHash:string;account:string;rootApproved:true;noPlanUpgrade:true;prerequisitesVerified:true;artifactManifestSha256:string;controllerManifestSha256:string;maxIncrementalCents:number;expires:number}
export interface Adapter{
 // The adapter must verify current absence before creates; never translate a collision into update.
 absent(operation:Operation):Promise<boolean>;
 perform(operation:Operation,created:ReadonlyMap<string,string>,deadline:number):Promise<{id:string;resource:string}>;
 persist(journal:Journal):Promise<void>;
 verifyUnchanged(preserve:Plan['preserve']):Promise<boolean>;
}
export async function applyReviewedPlan(p:Plan,approval:Approval,adapter:Adapter,now=()=>Date.now()):Promise<Journal>{
 // Runtime assertions bind the exact reviewed operation graph and explicit prerequisites.
 if(!Number.isSafeInteger(approval.maxIncrementalCents)||!Number.isSafeInteger(approval.expires)||!Number.isSafeInteger(p.start)||!Number.isSafeInteger(p.end)
   ||p.budgetCapCents!==500||p.incrementalEstimateCents!==5||p.maxProvisioningSteps!==11
   ||approval.prerequisitesVerified!==true||!/^[a-f0-9]{64}$/.test(approval.artifactManifestSha256)||!/^[a-f0-9]{64}$/.test(approval.controllerManifestSha256)
   ||approval.rootApproved!==true||approval.noPlanUpgrade!==true||approval.account!==ACCOUNT||p.account!==ACCOUNT||approval.planHash!==digest(p)
   ||approval.maxIncrementalCents< p.incrementalEstimateCents||approval.maxIncrementalCents>500||approval.expires>p.end||approval.expires<=now()
   ||p.version!==2||digest(p.operations)!==digest(planForValidation(p))
   ||p.end-p.start!==1200000||now()<p.start||now()>=p.end)throw new Error('Provisioning approval or lease refused');
 // Even an approved plan cannot bypass inventory/identity blockers. Review/provision prerequisites
 // are explicit external assertions; all other blockers require a new actual readback.
 if(p.blocked.some(b=>!b.startsWith('Root must approve')&&!b.startsWith('Funded eligible')))throw new Error('Unresolved readback blocker');
 const journal:Journal={account:ACCOUNT,planHash:digest(p),entries:[]};const created=new Map<string,string>();
 if(!await adapter.verifyUnchanged(p.preserve))throw new Error('Protected routing/DNS state changed');
 for(const op of p.operations){
   if(now()>=Math.min(p.end,approval.expires))throw new Error('Provisioning lease expired');
   validateOperation(op,p);
   if(['create-d1','upload-worker','configure-pages','create-recipient'].includes(op.kind)&&!await adapter.absent(op))throw new Error('Resource exists; refusing replacement');
   const entry:Journal['entries'][number]={id:op.id,resource:op.resource,state:'started'};journal.entries.push(entry);await adapter.persist(structuredClone(journal));
   if(now()>=Math.min(p.end,approval.expires))throw new Error('Provisioning lease expired before dispatch; started receipt requires read-only reconciliation');
   try{const result=await adapter.perform(op,new Map(created),Math.min(p.end,approval.expires));if(result.resource!==op.resource||!result.id)throw new Error('Wrong created resource');
     if(op.kind==='create-d1'&&(!freshDatabaseId(result.id)||[...created.values()].includes(result.id)))throw new Error('Database identity refused');
     if(op.kind==='migrate-d1'&&result.id!==created.get('d1:'+op.resource))throw new Error('Migration changed owned database identity');
     entry.state='created';entry.remoteId=result.id;
     if(['create-d1','upload-worker','configure-pages','create-recipient'].includes(op.kind)){const key=op.kind==='create-d1'?'d1:'+op.resource:op.resource;if(created.has(key))throw new Error('Ownership identity cannot be replaced');created.set(key,result.id);}
     await adapter.persist(structuredClone(journal));
   }catch{entry.state='unknown';await adapter.persist(structuredClone(journal));throw new Error('Provisioning outcome unknown; stop, reconcile read-only, never retry automatically');}
 }
 if(!await adapter.verifyUnchanged(p.preserve))throw new Error('Protected routing/DNS state changed');
 return journal;
}
export function validateOperation(op:Operation,p:Plan){
 const expected=planForValidation(p).find(x=>x.id===op.id);
 if(!expected||digest(expected)!==digest(op))throw new Error('Unlisted provisioning operation');
}
function planForValidation(p:Plan):Operation[]{
 // Recreate immutable operation templates; caller-controlled readback cannot add operations.
 const snapshot={account:ACCOUNT,zone:p.zone,checkedAt:new Date(p.start).toISOString(),names:{workers:{available:true,collisions:[]},databases:{available:true,complete:true,collisions:[]},pages:{available:true,complete:true,collisions:[]}},entitlements:{available:true,items:[]},routing:{available:true,settings:{enabled:true,status:'ready'},rulesComplete:true,recipient:RECIPIENT,recipientAlreadyExists:false,rulesSha256:p.preserve.rules,catchAll:{available:true,sha256:p.preserve.catchAll},dns:{available:true,sha256:p.preserve.dns}},sending:{available:true,domains:[]}};
 return plan(snapshot,p.start).operations;
}
export function cleanupPlan(p:Plan,journal:Journal){
 if(journal.account!==ACCOUNT||journal.planHash!==digest(p))throw new Error('Wrong cleanup ownership');
 const out:{operation:string;resource:string;remoteId:string;requiresReadback:true}[]=[];
 for(const entry of [...journal.entries].reverse()){
  const op=p.operations.find(o=>o.id===entry.id);if(!op||op.resource!==entry.resource)throw new Error('Unknown cleanup resource');validateOperation(op,p);
  if(entry.state!=='created'||!entry.remoteId)continue;
  if(op.kind==='create-d1'&&!freshDatabaseId(entry.remoteId))throw new Error('Protected database');
  if(['create-d1','upload-worker','configure-pages','create-recipient'].includes(op.kind))out.push({operation:'delete-exact-owned-resource',resource:entry.resource,remoteId:entry.remoteId,requiresReadback:true});
 }
 return{first:['stop-owned-issuer','disable-exact-owned-schedules','remove-only-owned-recipient-rule','remove-only-owned-Pages-project'],resources:out,
   unresolved:journal.entries.filter(e=>e.state!=='created').map(e=>({id:e.id,resource:e.resource})),forbidden:['delete-by-name-after-unknown','DNS/MX/SPF edits','catch-all edits','production D1/Worker/issuer/token edits','delete pre-existing resources'],final:'Read back absence of each owned ID and compare original routing/DNS/catch-all baselines; then remove disposable credentials locally'};
}
if(import.meta.main){
 try{if(process.argv.length!==4)throw new Error('Provide snapshot JSON path and output plan path; no apply mode exists');
 const snapshot=JSON.parse(await readFile(process.argv[2]!,'utf8')) as Snapshot;
 const prepared=plan(snapshot,Date.now());await writeFile(process.argv[3]!,JSON.stringify(prepared,null,2)+'\n',{flag:'wx',mode:0o600});
 console.log(JSON.stringify({planHash:digest(prepared),operations:prepared.operations.length,blocked:prepared.blocked,externalWrites:0}));
 }catch{console.error('Provisioning plan preparation failed; no external write performed');process.exitCode=1;}
}
