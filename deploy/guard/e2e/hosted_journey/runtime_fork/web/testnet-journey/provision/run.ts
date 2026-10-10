// Explicit operator entry point. Preparing files never invokes this command.
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {existingOAuth,inspect} from './inspect.ts';
import {plan as makePlan,digest,applyReviewedPlan,type Plan,type Approval,type Snapshot} from './controller.ts';
import {loadArtifacts,verifyController,type Manifest} from './artifacts.ts';
import {createJournal,readJournal,unresolvedOutcomes} from './journal.ts';
import {createCloudflareAdapter,type Credentials,type Owned} from './cloudflare.ts';
const base=path.dirname(fileURLToPath(import.meta.url));
async function json(file:string){const bytes=await readFile(file);if(bytes.length>1048576)throw new Error('Oversized input');return JSON.parse(bytes.toString('utf8'));}
async function disposableSecrets():Promise<Omit<Credentials,'oauth'>>{
 if(process.stdin.isTTY)throw new Error('Disposable runtime secrets must arrive through private stdin');
 let value='';for await(const chunk of process.stdin){value+=chunk.toString();if(value.length>1024)throw new Error('Secret input too large');}
 const parsed=JSON.parse(value);if(!parsed||Object.keys(parsed).sort().join(',')!=='inbox,issuer,unsubscribe')throw new Error('Unexpected secret fields');return parsed;
}
async function main(){
 const [mode,planFile,approvalFile,artifactDirectory,artifactManifestFile,controllerManifestFile,journalDirectory,priorJournalDirectory]=process.argv.slice(2);
 if(!['apply','cleanup'].includes(mode??'')||![planFile,approvalFile,artifactDirectory,artifactManifestFile,controllerManifestFile,journalDirectory].every(p=>p&&path.isAbsolute(p))
  ||process.argv.length!==(mode==='apply'?9:10)||mode==='cleanup'&&(!priorJournalDirectory||!path.isAbsolute(priorJournalDirectory)))throw new Error('Explicit mode and absolute plan/approval/artifact/source/journal paths required');
 const p=await json(planFile!) as Plan,approval=await json(approvalFile!) as Approval&{cleanup?:{journalHash:string;approved:true;expires:number}};
 const source=await json(controllerManifestFile!);
 await verifyController(base,source,approval.controllerManifestSha256);
 const artifacts=await loadArtifacts(artifactDirectory!,await json(artifactManifestFile!) as Manifest,approval,mode as 'apply'|'cleanup');
 // The reviewed draft exception can shorten, never extend, the operator's lease.
 if(mode==='apply'&&artifacts.draftReleaseExpires!==undefined)approval.expires=Math.min(approval.expires,artifacts.draftReleaseExpires);
 const secrets=await disposableSecrets();const oauth=await existingOAuth();
 const log=await createJournal(journalDirectory!);
 await log.append('run',{mode,planHash:digest(p),account:p.account,artifactManifestSha256:approval.artifactManifestSha256,controllerManifestSha256:approval.controllerManifestSha256,draftReleaseReceiptSha256:approval.draftReleaseAcceptance?.receiptSha256??null,draftReleaseExpires:artifacts.draftReleaseExpires??null});
 let unresolvedOutcomeCount=0;
 const transport=createCloudflareAdapter(p,approval,artifacts,{...secrets,oauth},log);
 if(mode==='apply'){
  // Re-read actual account immediately before applying. Any state change requires a new reviewed plan.
  const snapshot=await inspect(oauth) as Snapshot;
  const refreshed=makePlan(snapshot,p.start);
  if(refreshed.blocked.some(b=>!b.startsWith('Root must approve')&&!b.startsWith('Funded eligible')&&!b.startsWith('Read-only snapshot'))
   ||digest(refreshed.operations)!==digest(p.operations)||digest(refreshed.preserve)!==digest(p.preserve)||snapshot.account!==p.account||snapshot.zone!==p.zone)throw new Error('Preflight changed; obtain a fresh reviewed plan');
  await applyReviewedPlan(p,approval,transport.adapter);
  await log.append('apply-completed',{planHash:digest(p)});
 }else{
  const records=await readJournal(priorJournalDirectory!);
  if(!approval.cleanup||approval.cleanup.approved!==true||approval.cleanup.journalHash!==digest(records)||approval.planHash!==digest(p))throw new Error('Separate exact-journal cleanup approval required');
  const initial=records[0]?.data as {mode?:string;account?:string;planHash?:string;artifactManifestSha256?:string;draftReleaseReceiptSha256?:string|null;draftReleaseExpires?:number|null};
  if(initial?.mode!=='apply'||initial.account!==p.account||initial.planHash!==digest(p)||initial.artifactManifestSha256!==approval.artifactManifestSha256
   ||(initial.draftReleaseReceiptSha256??null)!==(approval.draftReleaseAcceptance?.receiptSha256??null)||(initial.draftReleaseExpires??null)!==(artifacts.draftReleaseExpires??null))throw new Error('Cleanup journal belongs to another run');
  // Unknown writes are never converted to guessed resources. Report them separately for read-only
  // reconciliation; cleanup can still remove resources with durable successful ownership receipts.
  unresolvedOutcomeCount=unresolvedOutcomes(records);
  const receipts=records.filter(r=>r.kind==='owned').map(r=>r.data as Owned);
  const deleted=new Set(records.filter(r=>r.kind==='deleted').map(r=>digest(r.data)));
  await transport.cleanupOwned(receipts.filter(r=>!deleted.has(digest(r))),approval.cleanup.expires);
 }
 console.log(JSON.stringify({mode,completed:unresolvedOutcomeCount===0,unresolvedOutcomeCount,journal:journalDirectory}));
 if(unresolvedOutcomeCount)process.exitCode=2;
}
if(import.meta.main)main().catch(()=>{console.error('Isolated provisioning stopped. Inspect the private journal; never retry an uncertain write. No credentials or API bodies logged.');process.exitCode=1;});
