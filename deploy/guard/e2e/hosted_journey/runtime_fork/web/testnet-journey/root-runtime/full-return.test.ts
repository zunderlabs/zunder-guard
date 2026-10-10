// Pure hand-computed regressions. No keeper factory, wallet, signature, POST,
// provider client, material, key or protection process is created.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {OWNER} from './policy.ts';
import {ReturnAttempt,returnData} from './return.ts';
import {PROPOSAL_SHA,RETURN_POLICY,validateFullReturn,reconcileFullBalances,paymentInterval,returnInterval,freshSnapshot,
 type FullBalanceReturnPolicy,type FullSnapshot} from './full-return.ts';
const start=1800000000000,merchant='0x'+'2'.repeat(40),payHash='0x'+'3'.repeat(64),returnHash='0x'+'4'.repeat(64);
const p:FullBalanceReturnPolicy={version:2,policy:RETURN_POLICY,proposalSha256:PROPOSAL_SHA,signedAmountLimitUsdc:'355.61',
 runId:'12345678-1234-4234-8234-123456789abc',merchant,destination:OWNER,amount:'199.14',paidUsdc:'199.14',
 token:'USDC:0x'+'5'.repeat(32),paymentHash:payHash,paymentAfter:start+1000,startedAt:start,expires:start+1200000,
 purchaseReceipt:{file:'/public/original.json',sha256:'6'.repeat(64)},ownerInitialUsdc:'400',ownerBaselineSha256:'7'.repeat(64)};
const snap=(m:string,o:string):FullSnapshot=>({merchant:{accountValue:m,withdrawable:m},owner:{accountValue:o,withdrawable:o},
 time:start+2000,completedAt:start+3000,monoStartNs:'1000000000',monoEndNs:'2000000000',paymentHash:payHash,token:p.token,merchantLedger:[],ownerLedger:[],observations:[],observationsSha256:'a'.repeat(64)});
const send=(hash:string,user:string,destination:string,amount:string,time:number)=>({time,hash,delta:{type:'send',user,destination,token:'USDC',amount}});
const payment=send(payHash,OWNER,merchant,'199.14',start+1000),returned=send(returnHash,merchant,OWNER,'199.14',start+2000);
test('approved full signed credit retains original20 and exact canonical Testnet payload',()=>{
 validateFullReturn(p,merchant,p.runId,p.expires,start+4000);const data=returnData(p,start+5000);
 assert.equal(data.domain.chainId,421614);assert.deepEqual(data.message,{hyperliquidChain:'Testnet',destination:OWNER,sourceDex:'',destinationDex:'',
  token:p.token,amount:'199.14',fromSubAccount:'',nonce:start+5000});
});
test('no advance fee fields, maxDebit guarantee or altered approval admitted',()=>{
 for(const value of[{...p,feeEvidence:{}},{...p,maxFeeUsdc:'0'},{...p,maxDebitUsdc:'355.61'},
  {...p,proposalSha256:'0'.repeat(64)},{...p,amount:'355.610001',paidUsdc:'355.610001'},
  {...p,amount:'198.14'},{...p,startedAt:start+1200},{...p,expires:start+1200001}])
  assert.throws(()=>validateFullReturn(value as FullBalanceReturnPolicy,merchant,p.runId,start+1200001,start+4000));
});
test('hand calculation full return: M199.14→0; O200.86→400; D=C=A199.14',()=>{
 const result=reconcileFullBalances(snap('199.14','200.86'),snap('0','400'),p);
 assert.equal(result.debit,'199.140000');assert.equal(result.credit,'199.140000');assert.equal(result.fee,'0');
});
for(const [label,m,o]of[['residual','1','398.999999'],['receiver deduction unknown','0','399'],['excess owner credit','0','400.000001'],
 ['negative merchant debt','-1','400'],['negative owner','0','-1'],['missing credit','0','200.86']]as const)
 test(label+' refuses actual completion',()=>assert.throws(()=>reconcileFullBalances(snap('199.14','200.86'),snap(m,o),p)));
test('unknown fee/payer variant is HOLD even if a caller labels the difference',()=>{
 const row={...returned,delta:{...returned.delta,fee:'1',feePayer:OWNER}};
 assert.throws(()=>returnInterval([payment,row],p,start+2000,start+4000));
});
test('complete both-account send intervals bind original purchase and ONE identical return hash',()=>{
 assert.equal(paymentInterval([payment],p,start+4000),payHash);
 assert.equal(returnInterval([payment,returned],p,start+2000,start+4000),returnHash);
 for(const rows of[[returned],[payment,payment,returned],[payment,{...returned,delta:{...returned.delta,amount:'198.14'}}],
  [payment,{...returned,time:start+1999}],[payment,{...returned,delta:{...returned.delta,destination:merchant}}]])
  assert.throws(()=>returnInterval(rows,p,start+2000,start+4000));
});
for(const mode of['rejection','timeout','signature-error','expiry-after-sign','expiry-after-send']as const)
 test(mode+' durably consumes before sign; no retry/signature/POST replacement',async()=>{
  const attempt=new ReturnAttempt();let intents=0,signatures=0,posts=0,live=true;
  const deps={check:()=>{if(!live)throw Error('inert expired');},intent:async()=>{intents++;},
   sign:async()=>{signatures++;if(mode==='signature-error')throw Error('inert sign refusal');if(mode==='expiry-after-sign')live=false;return 'inert';},
   send:async()=>{posts++;if(mode==='timeout')throw Error('inert timeout');if(mode==='expiry-after-send')live=false;return{status:mode==='rejection'?'err':'ok',response:{type:'default'}};}};
  await assert.rejects(attempt.execute(returnData(p,start+5000),deps));await assert.rejects(attempt.execute(returnData(p,start+5001),deps));
  assert.equal(intents,1);assert.equal(signatures,1);assert.ok(posts<=1);assert.equal(attempt.status().state,'unknown');
 });
test('missing durable intent ACK yields zero signatures and POSTs',async()=>{
 const a=new ReturnAttempt();let signed=0,sent=0;
 await assert.rejects(a.execute(returnData(p,start+5000),{check:()=>{},intent:async()=>{throw Error('unknown durable ACK');},
  sign:async()=>{signed++;return 'inert';},send:async()=>{sent++;return{status:'ok',response:{type:'default'}};}}));
 assert.equal(signed,0);assert.equal(sent,0);assert.equal(a.status().spent,true);
});

test('freshness derives before first read and cannot renew under wall rollback',()=>{
 const s=snap('199.14','200.86');freshSnapshot(s,start+3000,2000000000n);
 assert.throws(()=>freshSnapshot(s,start+3000,61000000001n));
 assert.throws(()=>freshSnapshot(s,start+60001+2000,2000000000n));
 assert.throws(()=>freshSnapshot(s,start+1999,2000000000n));
});
