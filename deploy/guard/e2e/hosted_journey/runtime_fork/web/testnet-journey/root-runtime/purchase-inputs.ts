// Fixed store/cleanup policy for three disposable issuer inputs. No owner or
// merchant private-key access, no SSM decryption and no network on import.
import {isDeepStrictEqual} from 'node:util';
import {exact,fail,hashString,DENIED,OWNER,type Admission} from './policy.ts';
export const PURCHASE_ACCOUNT='436632189317',PURCHASE_REGION='eu-central-1';
export const PURCHASE_KMS='arn:aws:kms:eu-central-1:436632189317:key/20d7fdda-950b-4101-a391-b3749f892939';
const KINDS=['issuer-token','inbox-token','signing-seed'] as const;
export interface PurchaseBinding {
 // source is the candidate PRODUCT commit, matching OneClaimInputs.Source tags;
 // controller identity and exact workflow admission remain the root's contract.
 schema:1;run:number;attempt:number;source:string;runId:string;startedAt:number;deadline:number;merchant:string;issuerPublicKey:string;
}
export interface PurchaseCleanupApproval {
 schema:1;purpose:'cleanup-purchase-inputs';bindingSha256:string;approved:true;deadline:number;
}
interface Identity {runId:string;startedAt:number;merchant:string;issuerPublicKey:string}
export interface PurchaseInputIO {
 // Runtime supplies its existing pinned, supervised AWS child; public action and
 // private stdin are separate. Returned stdout is consumed/wiped by this policy.
 execute(kind:string,service:'sts'|'ssm',action:string,input:Buffer,deadline:number,guard:()=>void):Promise<Buffer>;
 checkpoint(kind:string,data:Record<string,unknown>):Promise<void>;
}
export function validatePurchaseBinding(value:PurchaseBinding,expected:Identity,deadline:number,now:number){
 exact(value,['schema','run','attempt','source','runId','startedAt','deadline','merchant','issuerPublicKey']);
 if(value.schema!==1||!Number.isSafeInteger(value.run)||value.run<=0||!Number.isSafeInteger(value.attempt)||value.attempt<1||value.attempt>100
   ||! /^[0-9a-f]{40}$/.test(value.source)||value.runId!==expected.runId||value.startedAt!==expected.startedAt
   ||value.merchant!==expected.merchant||DENIED.includes(value.merchant)||value.issuerPublicKey!==expected.issuerPublicKey
   ||value.deadline!==deadline||!Number.isSafeInteger(value.startedAt)||!Number.isSafeInteger(deadline)
   ||value.startedAt>now||now>=deadline||deadline<=value.startedAt||deadline-value.startedAt>1200000)fail();
}
export function purchaseParameterNames(binding:PurchaseBinding){
 return KINDS.map(kind=>'/zunder/testnet/e2e/purchase/'+binding.run+'-'+binding.attempt+'/'+kind);
}
export function purchaseParameterTags(b:PurchaseBinding){
 return Object.entries({Scope:'isolated-testnet-purchase-inputs',Run:String(b.run),Attempt:String(b.attempt),Source:b.source,
   Owner:OWNER,Merchant:b.merchant,Expires:String(b.deadline)})
   .sort(([a],[c])=>a.localeCompare(c)).map(([Key,Value])=>({Key,Value}));
}
/** Parameter custody bookkeeping only; existing root owns keys/processes/cloud
 * and original Admission. An uncertain Put is consumed and retains all names. */
export function createPurchaseInputStore(identity:Identity,admission:Admission,io:PurchaseInputIO){
 let attempted=false,clean=false,cleanupAttempted=false,binding:PurchaseBinding|undefined,bindingHash:string|undefined;
 const names=()=>binding?purchaseParameterNames(binding):[];
 const state=()=>Object.freeze({attempted,clean,cleanupAttempted,unresolved:attempted&&!clean,parameters:names()});
 const call=async(kind:string,service:'sts'|'ssm',action:string,data:unknown,end:number,guard:()=>void)=>{
   guard();const input=Buffer.from(JSON.stringify(data));let output:Buffer|undefined;
   try{guard();output=await io.execute(kind,service,action,input,end,guard);guard();
     return output.length===0&&service==='ssm'&&action==='delete-parameter'?{}
       :JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(output)) as Record<string,unknown>;
   }finally{input.fill(0);output?.fill(0);}
 };
 const account=async(end:number,guard:()=>void)=>{
   const value=await call('purchase-input-identity','sts','get-caller-identity',{},end,guard);
   if(value.Account!==PURCHASE_ACCOUNT||typeof value.Arn!=='string'||!value.Arn.startsWith('arn:aws:')
     ||value.Arn.split(':')[4]!==PURCHASE_ACCOUNT||typeof value.UserId!=='string')fail();
   await io.checkpoint('purchase-input-identity',{account:PURCHASE_ACCOUNT,arn:value.Arn});guard();
 };
 const describe=async(name:string,index:number,phase:string,end:number,guard:()=>void)=>{
   const result=await call('purchase-input-'+phase+'-'+index,'ssm','describe-parameters',{
     ParameterFilters:[{Key:'Name',Option:'Equals',Values:[name]}],MaxResults:10},end,guard);
   if(!Array.isArray(result.Parameters)||result.Parameters.length>1||result.NextToken!==undefined)fail();
   return result.Parameters as Record<string,unknown>[];
 };
 const metadata=async(name:string,index:number,phase:string,b:PurchaseBinding,end:number,guard:()=>void)=>{
   const rows=await describe(name,index,phase,end,guard);
   if(!rows.length)return false;
   const row=rows[0]!;
   if(row.Name!==name||row.Type!=='SecureString'||row.Tier!=='Standard'||row.Version!==1
     ||![PURCHASE_KMS,PURCHASE_KMS.split('/').at(-1)].includes(String(row.KeyId)))fail();
   const tagged=await call('purchase-input-'+phase+'-tags-'+index,'ssm','list-tags-for-resource',{
     ResourceType:'Parameter',ResourceId:name},end,guard);
   if(!Array.isArray(tagged.TagList)||!tagged.TagList.every(v=>v&&typeof v==='object'&&Object.keys(v).sort().join(',')==='Key,Value')
     ||!isDeepStrictEqual([...tagged.TagList].sort((a,b)=>String(a.Key).localeCompare(String(b.Key))),purchaseParameterTags(b)))fail();
   return true;
 };
 return Object.freeze({state,
   // values are root's privately owned one-call snapshots, never a caller/browser
   // handoff. index.ts creates them locally and wipes them on every exit.
   async store(raw:PurchaseBinding,hash:string,values:readonly Buffer[]){
     const b=structuredClone(raw);admission.check();
     if(attempted||!hashString(hash))fail();
     validatePurchaseBinding(b,identity,admission.deadline(),Date.now());
     // Consume before private validation or first asynchronous step.
     attempted=true;binding=b;bindingHash=hash;
     const guard=()=>admission.check(),end=b.deadline;
     try{
       if(values.length!==3||!values.every(Buffer.isBuffer)
         ||!values.slice(0,2).every(v=>/^[A-Za-z0-9_-]{43,128}$/.test(v.toString('ascii'))&&Buffer.from(v.toString('ascii')).equals(v))
         ||values[0]!.equals(values[1]!)||! /^0x[0-9a-f]{64}$/.test(values[2]!.toString('ascii')))fail();
       await io.checkpoint('purchase-input-store-consumed',{...b,bindingSha256:hash,parameters:names()});guard();
       await account(end,guard);
       for(const [index,name]of names().entries()){
         await io.checkpoint('purchase-input-put-attempted',{name,run:b.run,attempt:b.attempt});guard();
         const result=await call('purchase-input-put-'+index,'ssm','put-parameter',{
           Name:name,Value:values[index]!.toString('ascii'),Type:'SecureString',Tier:'Standard',KeyId:PURCHASE_KMS,
           Overwrite:false,Tags:purchaseParameterTags(b)},end,guard);
         exact(result,['Version','Tier']);if(result.Version!==1||result.Tier!=='Standard')fail();
         if(!await metadata(name,index,'store-readback',b,end,guard))fail();
         await io.checkpoint('purchase-input-put-confirmed',{name,version:1,tier:'Standard'});guard();
       }
     }catch{admission.hold(true);fail();}
   },
   async cleanup(raw:PurchaseBinding,hash:string,approval:PurchaseCleanupApproval){
     const b=structuredClone(raw),a=structuredClone(approval);
     if(!attempted||clean||cleanupAttempted||hash!==bindingHash||!isDeepStrictEqual(b,binding))fail();
     exact(a,['schema','purpose','bindingSha256','approved','deadline']);
     if(a.schema!==1||a.purpose!=='cleanup-purchase-inputs'||a.approved!==true||a.bindingSha256!==hash)fail();
     const guard=admission.createCleanupGuard(a.deadline),end=a.deadline;
     cleanupAttempted=true;
     try{
       await io.checkpoint('purchase-input-cleanup-consumed',{bindingSha256:hash,deadline:end,parameters:names()});guard();
       await account(end,guard);
       for(const [index,name]of names().entries()){
         if(await metadata(name,index,'cleanup-metadata',b,end,guard)){
           await io.checkpoint('purchase-input-delete-attempted',{name});guard();
           const deleted=await call('purchase-input-delete-'+index,'ssm','delete-parameter',{Name:name},end,guard);exact(deleted,[]);
         }
         if((await describe(name,index,'absence',end,guard)).length!==0)fail();
         await io.checkpoint('purchase-input-absence-confirmed',{name});guard();
       }
       clean=true;
     }catch{admission.hold(true);fail();}
   },
 });
}
