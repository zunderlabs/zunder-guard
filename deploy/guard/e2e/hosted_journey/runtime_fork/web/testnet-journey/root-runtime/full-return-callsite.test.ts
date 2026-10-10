// Exact nested production account parser, fake fixed HTTPS read seam only.
// No runtime factory, SDK, key, signing, process or provider operation.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {stripTypeScriptTypes} from 'node:module';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {OWNER,units} from './policy.ts';
import {balance,canonicalToken} from './return.ts';
import {PROPOSAL_SHA,RETURN_POLICY,paymentInterval,returnInterval,reconcileFullBalances,freshSnapshot,type FullBalanceReturnPolicy} from './full-return.ts';
const source=readFileSync(new URL('./index.ts',import.meta.url),'utf8');
const a=source.indexOf('  async function inspectAccounts('),b=source.indexOf('  async function checkReturn',a);
assert.ok(a>0&&b>a);const body=stripTypeScriptTypes(source.slice(a,b));
const build=new Function('deps','const {venueObserved,canonicalToken,fail,merchant,OWNER,balance,units,config,sha,paymentInterval,isDeepStrictEqual}=deps;'+body+';return inspectAccounts;');
const start=1800000000000,merchant='0x'+'2'.repeat(40),paymentHash='0x'+'3'.repeat(64),returnHash='0x'+'4'.repeat(64);
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
const p:FullBalanceReturnPolicy={version:2,policy:RETURN_POLICY,proposalSha256:PROPOSAL_SHA,signedAmountLimitUsdc:'355.61',runId:'uuid',
 merchant,destination:OWNER,amount:'199.14',paidUsdc:'199.14',token:'USDC:0x'+'5'.repeat(32),paymentHash,paymentAfter:start+1000,
 startedAt:start,expires:start+1200000,purchaseReceipt:{file:'/public',sha256:'6'.repeat(64)},ownerInitialUsdc:'400',ownerBaselineSha256:'7'.repeat(64)};
const row=(hash:string,user:string,destination:string,time:number)=>({hash,time,delta:{type:'send',user,destination,amount:'199.14',token:'USDC'}});
const payment=row(paymentHash,OWNER,merchant,start+1000),returned=row(returnHash,merchant,OWNER,start+2000);
function fixture(after=false,mutation?:(body:any,value:any)=>any){
 const requests:unknown[]=[];
 const venueObserved=async(_path:string,body:any)=>{
  requests.push(body);const isMerchant=body.user===merchant;let value:any;
  switch(body.type){
   case'spotMeta':value={tokens:[{name:'USDC',index:0,isCanonical:true,tokenId:'0x'+'5'.repeat(32)}]};break;
   case'perpDexs':value=[null,{name:'fixture'}];break;
   case'userRole':value={role:'user'};break;
   case'userAbstraction':value='disabled';break;
   case'extraAgents':case'openOrders':case'userFunding':case'userFillsByTime':value=[];break;
   case'spotClearinghouseState':value={balances:[]};break;
   case'clearinghouseState':{
    const amount=body.dex!==''?'0':isMerchant?(after?'0':'199.14'):(after?'400':'200.86');
    value={withdrawable:amount,marginSummary:{accountValue:amount},assetPositions:[]};break;
   }
   case'userNonFundingLedgerUpdates':value=after?[payment,returned]:[payment];break;
   default:throw Error('unexpected fixed read');
  }
  value=mutation?mutation(body,value):value;return {value,responseSha256:sha(JSON.stringify(value)),observedAt:start+3000};
 };
 const inspect=build({venueObserved,canonicalToken,fail:()=>{throw Error('inert HOLD');},merchant,OWNER,balance,units,
  config:{startedAt:start},sha,paymentInterval,isDeepStrictEqual});return{inspect,requests};
}
test('actual parser observes both accounts and every DEX, then two-account same transaction completes',async t=>{
 t.mock.method(Date,'now',()=>start+3000);const before=fixture(),after=fixture(true);
 const first=await before.inspect(p,p.expires,true),last=await after.inspect(p,p.expires,false);
 freshSnapshot(first,start+3000,process.hrtime.bigint());
 assert.equal(returnInterval(last.merchantLedger,p,start+2000,start+3000),returnInterval(last.ownerLedger,p,start+2000,start+3000));
 assert.equal(reconcileFullBalances(first,last,p).credit,'199.140000');
 for(const user of[merchant,OWNER])for(const dex of['','fixture'])
  assert.ok(before.requests.some((r:any)=>r.type==='clearinghouseState'&&r.user===user&&r.dex===dex));
 assert.equal(first.observations.length,before.requests.length);assert.ok(first.observations.every((v:any)=>/^[0-9a-f]{64}$/.test(v.responseSha256)));
});
for(const defect of['agent','nondefault-collateral','spot-hold','abstraction','unknown-ledger','funding','duplicate-dex']as const)
 test('actual parser refuses '+defect+' before signing',async t=>{
  t.mock.method(Date,'now',()=>start+3000);const f=fixture(false,(body,value)=>{
   if(defect==='agent'&&body.type==='extraAgents'&&body.user===OWNER)return[{}];
   if(defect==='nondefault-collateral'&&body.type==='clearinghouseState'&&body.dex==='fixture')return{...value,withdrawable:'20',marginSummary:{accountValue:'20'}};
   if(defect==='spot-hold'&&body.type==='spotClearinghouseState')return{balances:[{token:0,total:'0',hold:'1'}]};
   if(defect==='abstraction'&&body.type==='userAbstraction')return'unifiedAccount';
   if(defect==='unknown-ledger'&&body.type==='userNonFundingLedgerUpdates')return[payment,{unknown:true}];
   if(defect==='funding'&&body.type==='userFunding')return[{}];
   if(defect==='duplicate-dex'&&body.type==='perpDexs')return[null,{name:'fixture'},{name:'fixture'}];return value;
  });await assert.rejects(f.inspect(p,p.expires,true));
 });
