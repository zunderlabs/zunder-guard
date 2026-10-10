// Exact returnOnce production branch. No wallet factory/SDK/crypto/network.
import{test}from'node:test';import assert from'node:assert/strict';import fs from'node:fs';import{stripTypeScriptTypes}from'node:module';
import{OWNER}from'./policy.ts';import{ReturnAttempt,returnData}from'./return.ts';
import{RETURN_POLICY,PROPOSAL_SHA,freshSnapshot,validateFullReturn}from'./full-return.ts';
const source=fs.readFileSync(new URL('./index.ts',import.meta.url),'utf8'),a=source.indexOf('    returnOnce: () =>'),b=source.indexOf('    reconcileEmptyMerchant:',a);
assert.ok(a>0&&b>a);let body=source.slice(a+'    returnOnce: '.length,b).trim();assert.ok(body.endsWith(','));body=stripTypeScriptTypes(body.slice(0,-1));
const start=1800000000000;
for(const mode of['valid','wall-ack-expired','mono-ack-expired','sign-expired','post-expired'])
 test('actual returnOnce '+mode+' keeps SAME snapshot across irreversible awaits',async t=>{
  let now=start+200000,mono=60000000000n,intents=0,signs=0,posts=0;
  const p={version:2,policy:RETURN_POLICY,proposalSha256:PROPOSAL_SHA,signedAmountLimitUsdc:'355.61',runId:'uuid',merchant:'0x'+'2'.repeat(40),destination:OWNER,
   amount:'199.14',paidUsdc:'199.14',token:'USDC:0x'+'3'.repeat(32),paymentHash:'0x'+'4'.repeat(64),paymentAfter:start+1000,startedAt:start,expires:start+1200000,
   purchaseReceipt:{file:'/public',sha256:'5'.repeat(64)},ownerInitialUsdc:'400',ownerBaselineSha256:'6'.repeat(64)};
  const snapshot={merchant:{accountValue:'199.14',withdrawable:'199.14'},owner:{accountValue:'200.86',withdrawable:'200.86'},time:now-59000,completedAt:now,
   monoStartNs:'1000000000',monoEndNs:String(mono)};
  const admission={check:()=>assert.ok(now<p.expires),deadline:()=>p.expires};
  const dependencies={armed:p,before:snapshot,children:new Map(),checkReturn:async()=>validateFullReturn(p,p.merchant,p.runId,p.expires,now),sourceCheck:async()=>{},
   inspectAccounts:async()=>snapshot,freshSnapshot,process,returnData,returnAttempt:new ReturnAttempt(),config:{runId:p.runId},admission,
   originalReturnDispatch:async()=>{intents++;if(mode==='wall-ack-expired')now+=9000;if(mode==='mono-ack-expired')mono+=9000000000n;},
   checkpoint:async()=>{},merchant:p.merchant,OWNER,
   merchantWallet:{signTypedData:async()=>{signs++;if(mode==='sign-expired'){now+=2000;mono+=2000000000n;}return'inert-signature';}},
   Signature:{from:()=>({r:'inert',s:'inert',v:27})},venue:async()=>{posts++;if(mode==='post-expired'){now+=2000;mono+=2000000000n;}return{status:'ok',response:{type:'default'}};},reconcile:async()=>{},
   invocation:async(_kind,action)=>action(),validateReturn:validateFullReturn,fail:()=>{throw Error('inert refused');}};
  const build=new Function('deps','const{'+Object.keys(dependencies).join(',')+'}=deps;let returnNonce;return ('+body+');');
  t.mock.method(Date,'now',()=>now);t.mock.method(process.hrtime,'bigint',()=>mono);
  const fn=build(dependencies);if(mode==='valid')await fn();else await assert.rejects(fn());
  assert.equal(intents,1);assert.equal(signs,mode.includes('ack')?0:1);assert.equal(posts,mode.includes('ack')||mode==='sign-expired'?0:1);
  await assert.rejects(fn());assert.equal(intents,1);assert.equal(signs,mode.includes('ack')?0:1);
 });
