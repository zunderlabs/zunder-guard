import {test} from 'node:test';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
import {parseCompletedPurchasePublication,type ProtectedPurchaseExpected,type CompletedPurchasePublication} from './protected-purchase.ts';
import {OWNER} from './policy.ts';
const START=1791600000000,NOW=START+1000;
function fixture(){
 const expected:ProtectedPurchaseExpected={challenge:'e'.repeat(64),controller:{instance:'i-'+'a'.repeat(17),boot:'11111111-2222-3333-4444-555555555555',
  hostKeySha256:'f'.repeat(64),controlSource:'1'.repeat(40),planSha256:'2'.repeat(64),runNumber:12345,attempt:1,parentPid:1234,parentBirth:'456789'},
  runId:'12345678-1234-4234-8234-123456789abc',startedAt:START,deadline:START+1200000,owner:OWNER,
  merchant:'0x'+'2'.repeat(40),candidate:{tag:'v1.0.4',source:'a'.repeat(40),manifest_sha256:'b'.repeat(64)},originalWatchdogPinsSha256:'c'.repeat(64),
  purchaseBinding:{schema:1,run:12345,attempt:1,source:'a'.repeat(40),runId:'12345678-1234-4234-8234-123456789abc',startedAt:START,deadline:START+1200000,merchant:'0x'+'2'.repeat(40),issuerPublicKey:'d'.repeat(64)}};
 const value:CompletedPurchasePublication={schema:1,kind:'live-protected-purchase-completion',sequence:1,challenge:expected.challenge,controller:{...expected.controller},
  purchase:{runId:expected.runId,candidate:{...expected.candidate},startedAt:START,deadline:expected.deadline,owner:OWNER,merchant:expected.merchant,
  publicKey:expected.purchaseBinding.issuerPublicKey,token:'USDC:0x'+'3'.repeat(32),nonce:START+500,amount:'199.14',ledgerHash:'0x'+'4'.repeat(64),
  mailSha256:'5'.repeat(64),recoverySha256:'6'.repeat(64),receiptSha256:'7'.repeat(64),purchaseSha256:'8'.repeat(64),
  paymentHeldSha256:'9'.repeat(64),teardownSha256:'a'.repeat(64),originalWatchdogPinsSha256:expected.originalWatchdogPinsSha256}};
 return{expected,value};
}
const sorted=(v:unknown):unknown=>v&&typeof v==='object'?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a<b?-1:1).map(([k,x])=>[k,sorted(x)])):v;
const frame=(v:unknown)=>new TextEncoder().encode(JSON.stringify(sorted(v))+'\n');
const parse=(v:unknown,e:ProtectedPurchaseExpected,now=NOW)=>parseCompletedPurchasePublication(frame(v),e,now);
test('exact public publication is deep frozen, copied, with SHA excluding only final LF',()=>{
 const {expected,value}=fixture(),before=JSON.stringify(expected),raw=frame(value),out=parseCompletedPurchasePublication(raw,expected,NOW);
 assert.deepEqual(out.publication,value);for(const v of[out,out.publication,out.publication.controller,out.publication.purchase,out.publication.purchase.candidate])assert.ok(Object.isFrozen(v));
 assert.equal(out.canonicalSha256,createHash('sha256').update(raw.subarray(0,-1)).digest('hex'));
 assert.notEqual(out.canonicalSha256,createHash('sha256').update(raw).digest('hex'));assert.equal(JSON.stringify(expected),before);
 Object.assign(value.purchase.candidate,{source:'f'.repeat(40)});Object.assign(value.controller,{parentBirth:'999'});
 assert.equal(out.publication.purchase.candidate.source,expected.candidate.source);assert.equal(out.publication.controller.parentBirth,expected.controller.parentBirth);
});
test('sorted compact ASCII single-LF framing refuses aliases, whitespace, extra frames and invalid UTF8',()=>{
 const {expected,value}=fixture(),valid=frame(value),text=new TextDecoder().decode(valid);
 for(const raw of[new TextEncoder().encode(JSON.stringify(value)+'\n'),new TextEncoder().encode(text.slice(0,-1)),new TextEncoder().encode(text+'\n'),
  new TextEncoder().encode(text+'{}\n'),new TextEncoder().encode(' '+text),new TextEncoder().encode(text.replace('"amount":','"nonce":1,"amount":')),
  new TextEncoder().encode(text.replace('"owner"','"\\u006fwner"')),new TextEncoder().encode(text.replace(/\n$/,'\r\n')),
  new Uint8Array([239,187,191,...valid]),new Uint8Array([255,...valid]),new Uint8Array(8193)])assert.throws(()=>parseCompletedPurchasePublication(raw,expected,NOW));
});
test('all approved controller identity fields and challenge must match exactly',()=>{
 const {expected,value}=fixture();
 for(const [k,wrong]of Object.entries({instance:'i-'+'b'.repeat(17),boot:'21111111-2222-3333-4444-555555555555',hostKeySha256:'e'.repeat(64),
  controlSource:'2'.repeat(40),planSha256:'3'.repeat(64),runNumber:12346,attempt:2,parentPid:1235,parentBirth:'456790'})){
  assert.throws(()=>parse({...value,controller:{...value.controller,[k]:wrong}},expected));
 }
 for(const wrong of['a'.repeat(64),null,1])assert.throws(()=>parse({...value,challenge:wrong},expected));
});
test('controller shapes, types and approved expected identities are strict',()=>{
 const {expected,value}=fixture();
 for(const [k,wrong]of Object.entries({instance:'i-a',boot:'bad',hostKeySha256:'F'.repeat(64),controlSource:'a'.repeat(64),planSha256:null,
  runNumber:'12345',attempt:0,parentPid:1.5,parentBirth:456789})){
  assert.throws(()=>parse({...value,controller:{...value.controller,[k]:wrong}},expected));
  assert.throws(()=>parse(value,{...expected,controller:{...expected.controller,[k]:wrong}} as ProtectedPurchaseExpected));
 }
 for(const parentBirth of['0','01','-1','1.2','1e3','9'.repeat(21)])assert.throws(()=>parse({...value,controller:{...value.controller,parentBirth}},expected));
 for(const attempt of[101,NaN,Infinity])assert.throws(()=>parse(value,{...expected,controller:{...expected.controller,attempt}}));
});
test('all purchase identities, issuer public key and candidate match independently pinned bindings',()=>{
 const {expected,value}=fixture();
 for(const [k,wrong]of Object.entries({runId:'22345678-1234-4234-8234-123456789abc',startedAt:START-1,deadline:START+1199999,
  owner:'0x'+'1'.repeat(40),merchant:'0x'+'3'.repeat(40),publicKey:'e'.repeat(64),originalWatchdogPinsSha256:'d'.repeat(64)}))assert.throws(()=>parse({...value,purchase:{...value.purchase,[k]:wrong}},expected));
 for(const [k,wrong]of Object.entries({tag:'v1.0.3',source:'e'.repeat(40),manifest_sha256:'e'.repeat(64)}))assert.throws(()=>parse({...value,purchase:{...value.purchase,candidate:{...value.purchase.candidate,[k]:wrong}}},expected));
 const e={...expected,candidate:{...expected.candidate,tag:'v1.0.4-rc.1'}};
 assert.equal(parse({...value,purchase:{...value.purchase,candidate:e.candidate}},e).publication.purchase.candidate.tag,e.candidate.tag);
 assert.throws(()=>parse(value,e));
});
test('every envelope and nested key is required; alternate location and extras fail',()=>{
 const {expected,value}=fixture();
 for(const k of Object.keys(value)){const v={...value} as Record<string,unknown>;delete v[k];assert.throws(()=>parse(v,expected));}
 for(const part of['controller','purchase']as const)for(const k of Object.keys(value[part])){
  const child={...value[part]} as Record<string,unknown>;delete child[k];assert.throws(()=>parse({...value,[part]:child},expected));
 }
 for(const k of Object.keys(value.purchase.candidate)){const c={...value.purchase.candidate}as Record<string,unknown>;delete c[k];assert.throws(()=>parse({...value,purchase:{...value.purchase,candidate:c}},expected));}
 for(const v of[{...value,extra:true},{...value,kind:'saved-receipt'},{...value,schema:2},{...value,sequence:2},{...value,sequence:'1'},
  {...value,controller:{...value.controller,extra:true}},{...value,purchase:{...value.purchase,runNumber:12345}},
  {...value,purchase:{...value.purchase,schema:1}},{...value,purchase:{...value.purchase,kind:value.kind}},
  {...value,purchase:{...value.purchase,attempt:1}},{...value,purchase:{...value.purchase,candidate:{...value.purchase.candidate,extra:true}}}])assert.throws(()=>parse(v,expected));
});
test('decimal accounting uses exact units at minimum and cumulative maximum boundaries',()=>{
 const {expected,value}=fixture();
 for(const amount of['0.000001','355.61','355.610000'])assert.equal(parse({...value,purchase:{...value.purchase,amount}},expected).publication.purchase.amount,amount);
 for(const amount of['0','0.000000','355.610001','356','-1','+1','01','1e2','1.0000001',199.14,null])assert.throws(()=>parse({...value,purchase:{...value.purchase,amount}},expected));
});
test('nonce and original twenty-minute deadline refuse clock extension and malformed times',()=>{
 const {expected,value}=fixture();
 for(const nonce of[START-1,NOW+1,START+0.5,'123',null])assert.throws(()=>parse({...value,purchase:{...value.purchase,nonce}},expected));
 assert.equal(parse({...value,purchase:{...value.purchase,nonce:START}},expected,START).publication.purchase.nonce,START);
 for(const now of[expected.deadline,START-1,NaN,Infinity,NOW+.5])assert.throws(()=>parse(value,expected,now));
 const e={...expected,deadline:expected.deadline+1,purchaseBinding:{...expected.purchaseBinding,deadline:expected.deadline+1}};
 assert.throws(()=>parse({...value,purchase:{...value.purchase,deadline:e.deadline}},e));
});
test('canonical tokens, ledger and all SHA fields refuse malformed or misplaced values',()=>{
 const {expected,value}=fixture();
 for(const [k,wrong]of Object.entries({token:'USDC:0x'+'a'.repeat(40),ledgerHash:'a'.repeat(64),mailSha256:'F'.repeat(64),recoverySha256:'x',
  receiptSha256:1,purchaseSha256:null,paymentHeldSha256:'0x'+'a'.repeat(64),teardownSha256:'a'.repeat(63)}))assert.throws(()=>parse({...value,purchase:{...value.purchase,[k]:wrong}},expected));
});
test('caller expectations refuse altered binding metadata and extra expected fields',()=>{
 const {expected,value}=fixture();
 for(const change of[{schema:2},{run:12346},{attempt:2},{source:'e'.repeat(40)},{runId:'22345678-1234-4234-8234-123456789abc'},
  {startedAt:START-1},{deadline:expected.deadline-1},{merchant:OWNER},{issuerPublicKey:'bad'},{extra:true}])assert.throws(()=>parse(value,{...expected,purchaseBinding:{...expected.purchaseBinding,...change}} as ProtectedPurchaseExpected));
 for(const change of[{challenge:'bad'},{owner:'0x'+'1'.repeat(40)},{merchant:OWNER},{runId:'bad'},{originalWatchdogPinsSha256:'bad'},
  {extra:true}])assert.throws(()=>parse(value,{...expected,...change}as ProtectedPurchaseExpected));
});
