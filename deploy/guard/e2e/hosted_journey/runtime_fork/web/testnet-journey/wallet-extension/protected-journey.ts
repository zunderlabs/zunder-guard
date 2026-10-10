// Root-only protected backend capability. No browser/global auth, key input or signer.
import type {Socket} from 'node:net';
import {isDeepStrictEqual} from 'node:util';
import {createPublicKey,verify} from 'node:crypto';
import {PolicyError,OWNER,MAX_LEASE_MS,STAGING_HOST,TESTNET_HOST,RPC_HOST,RPC_PATH,digest,canonicalJson,validateHeaders,type AssetPin,type UpstreamResponse,type SafeResponse} from './proxy-policy.ts';
import {makeProtectedStagingUpstream,makeRootUpstream} from './root-upstream.ts';
import type {CanonicalProxyAccess} from './proxy-access.ts';
import type {InboxRequest} from '../../site/tests/testnet-inbox.ts';
import {usdcUnits} from '../../site/src/lib/usdc.ts';
import {matchingPaymentLedger,paymentOutcome,validatePaymentExchange,PRODUCTION_MERCHANT,RETIRED_PAYMENT_OWNERS,type PaymentPolicy} from '../../site/tests/testnet-payment-policy.ts';
import {validateTestnetJob} from '../../../deploy/licence/testnet-issuer/issuer.ts';
import {PUBLIC_KEY,type Job} from '../../../deploy/licence/auto-issuer/issuer.ts';
import {licensee} from '../../waitlist/src/licence/core.ts';

const SITE='https://'+STAGING_HOST,RECIPIENT='guard-e2e-20261009@zunderlabs.com';
const ID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const NUMBER=/^ZL-\d{4}-\d{6}$/,TOKEN=/^[A-Za-z0-9_-]{43,128}$/;
export interface JourneyQuote {
 plan:'pro';term:'month';accounts:[typeof OWNER];company:string;street:string;postcode:string;city:string;country:string;
 vatId:'';email:typeof RECIPIENT;network:'hyperliquid';business:true;terms:true;termsVersion:'2026-10-06';
}
export interface ProtectedJourneyScope {
 schema:1;purpose:'private-testnet-purchase';runId:string;owner:typeof OWNER;merchant:string;publicKey:string;
 recipient:typeof RECIPIENT;startedAt:number;deadline:number;maxUsdc:string;quote:JourneyQuote;
 assets:Readonly<Record<string,AssetPin>>;
}
export interface HeldPayment {
 owner:typeof OWNER;merchant:string;amount:string;chain:'testnet';nonce:number;bodySha256:string;typedDataSha256:string;expires:number;
}
export interface JourneyCallbacks {armExactPayment(held:Readonly<HeldPayment>,signal:AbortSignal):Promise<{bodySha256:string;expires:number}>}
interface Order extends Record<string,unknown> {
 id:string;number:string;licenceNumber:string;status:string;chain:string;network:string;payTo:string;
 accounts:string[];usdc:string;plan:string;term:string;company:string;quoteExpiresAt:number;
}
function requireValue(v:unknown):asserts v {if(!v)throw new PolicyError('request');}
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');
const json=(r:UpstreamResponse)=>{requireValue(r.status===200&&/^application\/json(?:;\s*charset=utf-8)?$/i.test(String(r.headers['content-type'])));const text=r.body.toString('utf8');requireValue(Buffer.from(text).equals(r.body));return JSON.parse(text) as Record<string,unknown>;};
function safe(r:UpstreamResponse){
 requireValue(r.headers.location===undefined&&r.headers['set-cookie']===undefined
  &&r.headers['www-authenticate']===undefined&&r.headers['proxy-authenticate']===undefined
  &&(r.headers['content-encoding']===undefined||r.headers['content-encoding']==='identity')
  &&!Object.keys(r.headers).some(k=>k.toLowerCase().startsWith('cf-access-')));
 return r;
}
function tokenCopy(b:Buffer){requireValue(Buffer.isBuffer(b)&&TOKEN.test(b.toString('ascii'))&&Buffer.from(b.toString('ascii')).equals(b));return Buffer.from(b);}
/** Root retains original scope and both existing scoped tokens; no environment/file/argv reads.
 * Flow must pass its actual original authority, same private FD4 Access holder and native queue.
 * Browser admission and genuine wallet payment remain separately owned by the native parent. */
export function validateProtectedJourneyScope(input:ProtectedJourneyScope):ProtectedJourneyScope {
 const scope=structuredClone(input),now=Date.now();
 requireValue(exact(scope,['schema','purpose','runId','owner','merchant','publicKey','recipient','startedAt','deadline','maxUsdc','quote','assets'])
  &&scope.schema===1&&scope.purpose==='private-testnet-purchase'&&ID.test(scope.runId)&&scope.owner===OWNER
  &&/^0x[0-9a-f]{40}$/.test(scope.merchant)&&![OWNER,PRODUCTION_MERCHANT,'0x'+'0'.repeat(40),...RETIRED_PAYMENT_OWNERS].includes(scope.merchant)
  &&scope.recipient===RECIPIENT&&Number.isSafeInteger(scope.startedAt)&&scope.startedAt<=now
  &&/^[0-9a-f]{64}$/.test(scope.publicKey)&&scope.publicKey!==PUBLIC_KEY
  &&Number.isSafeInteger(scope.deadline)&&scope.deadline>now&&scope.deadline>scope.startedAt&&scope.deadline-scope.startedAt<=MAX_LEASE_MS
  &&usdcUnits(scope.maxUsdc)>0n&&usdcUnits(scope.maxUsdc)<=usdcUnits('355.61'));
 const q=scope.quote;
 requireValue(exact(q,['plan','term','accounts','company','street','postcode','city','country','vatId','email','network','business','terms','termsVersion'])
  &&q.plan==='pro'&&q.term==='month'&&isDeepStrictEqual(q.accounts,[OWNER])&&q.email===RECIPIENT&&q.network==='hyperliquid'
  &&q.business===true&&q.terms===true&&q.termsVersion==='2026-10-06'&&q.vatId===''
  &&[q.company,q.street,q.postcode,q.city].every(v=>typeof v==='string'&&v.trim().length>0&&Buffer.byteLength(v)<=200&&!/[\x00-\x1f\x7f]/.test(v))&&/^[A-Z]{2}$/.test(q.country));
 requireValue(scope.assets&&typeof scope.assets==='object'&&!Array.isArray(scope.assets)&&Object.keys(scope.assets).length<=512
  &&['/','/licence','/connect'].every(p=>scope.assets[p]?.contentType==='text/html; charset=utf-8'));
 for(const [path,pin]of Object.entries(scope.assets))requireValue(/^\/[A-Za-z0-9_./-]*$/.test(path)&&!path.includes('..')&&!path.includes('//')&&!path.startsWith('/api/')
  &&exact(pin,['sha256','contentType','csp'])&&/^[0-9a-f]{64}$/.test(pin.sha256)&&/^[\x20-\x7e]{1,160}$/.test(pin.contentType)&&/^[\x20-\x7e]{1,4096}$/.test(pin.csp));
 return scope;
}
export function makeProtectedJourney(input:ProtectedJourneyScope,privateTokens:{issuer:Buffer;inbox:Buffer},
 sockets:Set<Socket>,state:{active:number},access:CanonicalProxyAccess,authority:(deadline:number)=>void,callbacks:JourneyCallbacks){
 const scope=validateProtectedJourneyScope(input),q=scope.quote;
 authority(scope.deadline);
 let issuer:Buffer|undefined,inbox:Buffer|undefined;
 try{issuer=tokenCopy(privateTokens.issuer);inbox=tokenCopy(privateTokens.inbox);requireValue(!issuer.equals(inbox));}
 catch{issuer?.fill(0);inbox?.fill(0);throw new PolicyError('config');}
 const heldIssuer=issuer,heldInbox=inbox;
 const protectedSend=makeProtectedStagingUpstream(sockets,state,access),venueSend=makeRootUpstream(sockets,state,access);
 let closed=false,failed=false,active=0,quoteUsed=false,statusUsed=false,statusReads=0,checks=0,inboxReads=0,jobsUsed=false,deliveryUsed=false,paymentUsed=false,paymentAccepted=false;
 let canonicalToken:string|undefined,paymentExpires:number|undefined;
 let session:{id:string;token:string}|undefined,order:Order|undefined,ledgerHash:string|undefined,expectedJob:Job|undefined;
 const controller=new AbortController();
 const guard=()=>{requireValue(!closed&&!failed&&Date.now()<scope.deadline);authority(scope.deadline);};
 const operation=async<T>(work:()=>Promise<T>):Promise<T>=>{
  let admitted=false;
  try{guard();requireValue(active<8);active++;admitted=true;const result=await work();guard();return result;}
  catch{failed=true;controller.abort();throw new PolicyError('upstream');}finally{if(admitted)active--;}
 };
 const response=(r:UpstreamResponse)=>{
  for(const token of [heldIssuer,heldInbox])for(const encoded of [token.toString('ascii'),encodeURIComponent(token.toString('ascii')),token.toString('base64'),token.toString('hex')])requireValue(!r.body.includes(Buffer.from(encoded)));
  return new Response(new Uint8Array(r.body),{status:r.status,headers:{'content-type':String(r.headers['content-type']??'application/json'),'cache-control':'no-store'}});
 };
 function bindOrder(value:unknown,initial:boolean):Order{
  requireValue(value&&typeof value==='object'&&!Array.isArray(value));const v=value as Order;
  requireValue(ID.test(v.id)&&NUMBER.test(v.number)&&NUMBER.test(v.licenceNumber)&&v.chain==='testnet'&&v.network==='hyperliquid'
   &&v.payTo===scope.merchant&&isDeepStrictEqual(v.accounts,[OWNER])&&v.plan==='pro'&&v.term==='month'&&v.company===q.company
   &&typeof v.usdc==='string'&&usdcUnits(v.usdc)>0n&&usdcUnits(v.usdc)<=usdcUnits(scope.maxUsdc)
   &&Number.isSafeInteger(v.quoteExpiresAt)&&['awaiting_payment','paid','delivering','delivered'].includes(v.status));
  if(initial)requireValue(v.status==='awaiting_payment'&&v.quoteExpiresAt-Date.now()>=120_000);
  else{requireValue(order);const statuses=['awaiting_payment','paid','delivering','delivered'];requireValue(statuses.indexOf(v.status)>=statuses.indexOf(order.status));for(const field of ['id','number','licenceNumber','chain','network','payTo','accounts','usdc','plan','term','company','country','netCents','vatCents','vatRateBp','grossCents','quoteExpiresAt'])requireValue(isDeepStrictEqual(v[field],order[field]));}
  return structuredClone(v);
 }
 const customer=async(action:'status'|'quote'|'order'|'check',raw?:Buffer)=>operation(async()=>{
  let r:UpstreamResponse;
  if(action==='status'){requireValue(++statusReads<=4&&raw===undefined);r=safe(await protectedSend({kind:'status'},controller.signal,8192));const b=json(r);requireValue(b.ok===true&&b.open===true&&b.chain==='testnet'&&isDeepStrictEqual(b.networks,['hyperliquid']));statusUsed=true;return response(r);}
  requireValue(statusUsed&&Buffer.isBuffer(raw));const body=canonicalJson(raw);
  if(action==='quote'){requireValue(!quoteUsed&&isDeepStrictEqual(body,q));quoteUsed=true;}
  else requireValue(session&&isDeepStrictEqual(body,session)&&++checks<=80);
  r=safe(await protectedSend({kind:'customer',action,body:Buffer.from(raw)},controller.signal,32768));const b=json(r);requireValue(b.ok===true);
  const updated=bindOrder(b.order,action==='quote');
  if(action==='quote'){requireValue(typeof b.token==='string'&&/^[A-Za-z0-9_-]{43}$/.test(b.token));session={id:updated.id,token:b.token};}
  else requireValue(b.token===undefined);
  if(action==='quote')paymentExpires=Math.min(scope.deadline,updated.quoteExpiresAt,Date.now()+300000);
  order=updated;return response(r);
 });
 return Object.freeze({
  asset:(path:string)=>operation(async()=>{
   const pin=scope.assets[path];requireValue(pin);const r=safe(await protectedSend({kind:'asset',path},controller.signal,8*1024*1024));
   requireValue(r.status===200&&digest(r.body)===pin.sha256&&r.headers['content-type']===pin.contentType&&r.headers['content-security-policy']===pin.csp);
   return new Response(new Uint8Array(r.body),{headers:{'content-type':pin.contentType,'content-security-policy':pin.csp,'cache-control':'no-store','x-robots-tag':'noindex, nofollow'}});
  }),
  customer,
  // Public, root-only binding for the genuine checkout UI producer. Never includes
  // the order recovery token, issuer/inbox credential or delivered licence key.
  checkoutBinding:()=>{
   guard();requireValue(order&&paymentExpires&&statusUsed);
   return Object.freeze({number:order.number,quote:Object.freeze({id:order.id,status:order.status,
    chain:order.chain,network:order.network,payTo:order.payTo,usdc:order.usdc,
    quoteExpiresAt:order.quoteExpiresAt,accounts:[...order.accounts]}),
    expires:paymentExpires,token:canonicalToken??null});
  },
  paymentInfo:(raw:Buffer)=>operation(async()=>{
   requireValue(statusUsed&&!paymentUsed);const b=canonicalJson(raw);
   requireValue(isDeepStrictEqual(b,{type:'spotMeta'})||isDeepStrictEqual(b,{type:'clearinghouseState',user:OWNER}));
   const r=safe(await venueSend({host:TESTNET_HOST,path:'/info',method:'POST',body:Buffer.from(raw)},controller.signal,262144)),v=json(r);
   if(isDeepStrictEqual(b,{type:'spotMeta'})){
    requireValue(Array.isArray(v.tokens));const tokens=v.tokens.filter((x:any)=>x?.name==='USDC'&&x.index===0&&x.isCanonical===true);
    requireValue(tokens.length===1&&typeof tokens[0].tokenId==='string'&&/^0x[0-9a-f]{32}$/i.test(tokens[0].tokenId));
    const actual='USDC:'+tokens[0].tokenId.toLowerCase();requireValue(!canonicalToken||canonicalToken===actual);canonicalToken=actual;
   }
   return response(r);
  }),
  submitPayment:(raw:Buffer)=>operation(async()=>{
   requireValue(!paymentUsed&&order&&canonicalToken&&paymentExpires);paymentUsed=true;
   const submitted=Buffer.from(raw);
   const policy:PaymentPolicy={owner:OWNER,merchant:scope.merchant,expires:paymentExpires,quote:order,token:canonicalToken};
   const data=validatePaymentExchange(canonicalJson(submitted),policy,Date.now()),expires=Math.min(paymentExpires,data.message.nonce+10000);
   requireValue(data.message.nonce>=scope.startedAt);
   const held:HeldPayment=Object.freeze({owner:OWNER,merchant:scope.merchant,amount:order.usdc,chain:'testnet',nonce:data.message.nonce,bodySha256:digest(submitted),typedDataSha256:digest(JSON.stringify(data)),expires});
   const armSignal=AbortSignal.any([controller.signal,AbortSignal.timeout(Math.max(1,Math.min(10000,expires-Date.now())))]);
   const arm=await new Promise<{bodySha256:string;expires:number}>((resolve,reject)=>{
    const abort=()=>{armSignal.removeEventListener('abort',abort);reject(new PolicyError('arm'));};armSignal.addEventListener('abort',abort,{once:true});
    if(armSignal.aborted){abort();return;}
    callbacks.armExactPayment(held,armSignal).then(value=>{armSignal.removeEventListener('abort',abort);resolve(value);},()=>{armSignal.removeEventListener('abort',abort);reject(new PolicyError('arm'));});
   });guard();requireValue(exact(arm,['bodySha256','expires'])&&arm.bodySha256===held.bodySha256&&arm.expires===expires&&Date.now()<expires);
   const r=safe(await venueSend({host:TESTNET_HOST,path:'/exchange',method:'POST',body:submitted},controller.signal,8192));
   const reply=json(r);requireValue(exact(reply,['status','response'])&&exact(reply.response,['type'])&&paymentOutcome(r.status,reply)==='accepted');paymentAccepted=true;return response(r);
  }),
  chainId:(raw:Buffer)=>operation(async()=>{
   const b=canonicalJson(raw,1024);requireValue(exact(b,['jsonrpc','id','method','params'])&&b.jsonrpc==='2.0'&&Number.isInteger(b.id)&&Number(b.id)>=0&&Number(b.id)<4294967295&&b.method==='eth_chainId'&&isDeepStrictEqual(b.params,[]));
   const r=safe(await venueSend({host:RPC_HOST,path:RPC_PATH,method:'POST',body:Buffer.from(raw)},controller.signal,1024)),v=json(r);
   requireValue(exact(v,['jsonrpc','id','result'])&&v.jsonrpc==='2.0'&&v.id===b.id&&v.result==='0x66eee');return response(r);
  }),
  // Root independently reads both the server and Testnet ledger; caller cannot inject a receipt.
  confirmPaid:()=>operation(async()=>{
   requireValue(session&&order&&!ledgerHash&&paymentAccepted);
   const checked=safe(await protectedSend({kind:'customer',action:'check',body:Buffer.from(JSON.stringify(session))},controller.signal,32768));
   const b=json(checked);requireValue(b.ok===true);const updated=bindOrder(b.order,false);
   requireValue(['paid','delivering','delivered'].includes(updated.status)&&typeof updated.paidUsdc==='string'&&usdcUnits(updated.paidUsdc)===usdcUnits(updated.usdc)
    &&Number.isSafeInteger(updated.paidAt)&&Number(updated.paidAt)>=scope.startedAt&&Number(updated.paidAt)<=Date.now());
   const before=Date.now(),body=Buffer.from(JSON.stringify({type:'userNonFundingLedgerUpdates',user:scope.merchant,startTime:scope.startedAt}));
   const r=safe(await venueSend({host:TESTNET_HOST,method:'POST',path:'/info',body},controller.signal,262144));
   ledgerHash=matchingPaymentLedger(json(r),{owner:OWNER,merchant:scope.merchant,amount:updated.usdc,after:scope.startedAt,before});order=updated;
   return Object.freeze({number:updated.number,ledgerHash,amount:updated.usdc,chain:'testnet' as const});
  }),
  // Feed only to existing runTestnet(config,{fetch:issuerFetch,now:Date.now}) in root.
  issuerFetch:(async(url:RequestInfo|URL,init?:RequestInit)=>operation(async()=>{
   requireValue(typeof url==='string'&&init&&init.redirect==='error'&&init.signal&&!init.signal.aborted&&ledgerHash&&order);
   const h=new Headers(init.headers);requireValue([...h.keys()].sort().join(',')==='authorization,content-type'&&h.get('authorization')==='Bearer '+heldIssuer.toString('ascii')&&h.get('content-type')==='text/plain');
   requireValue(Object.keys(init).every(k=>['method','body','headers','redirect','signal'].includes(k)));
   const signal=AbortSignal.any([controller.signal,init.signal]);let r:UpstreamResponse;
   if(url===SITE+'/api/licence/testnet-issuer/jobs'){
    requireValue(!jobsUsed&&!deliveryUsed&&(init.method===undefined||init.method==='GET')&&init.body===undefined);jobsUsed=true;
    r=safe(await protectedSend({kind:'issuer-jobs',token:heldIssuer},signal,8192));const b=json(r);
    requireValue(exact(b,['ok','jobs'])&&b.ok===true&&Array.isArray(b.jobs)&&b.jobs.length===1);
    const job=validateTestnetJob(b.jobs[0],Date.now());requireValue(job.number===order.number&&job.plan==='pro'&&job.term==='month'&&isDeepStrictEqual(job.accounts,[OWNER])&&job.licensee===licensee(q.company,order.number));expectedJob=structuredClone(job);
   }else{
    requireValue(url===SITE+'/api/licence/testnet-issuer/deliver?order='+order.number&&jobsUsed&&!deliveryUsed&&init.method==='POST'
     &&typeof init.body==='string'&&Buffer.byteLength(init.body)<=4096&&/^zgl1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(init.body)&&expectedJob);deliveryUsed=true;
    const [encoded,encodedSignature]=init.body.slice(5).split('.'),payload=Buffer.from(encoded!,'base64url'),signature=Buffer.from(encodedSignature!,'base64url');
    requireValue(payload.toString('base64url')===encoded&&signature.toString('base64url')===encodedSignature&&signature.length===64
     &&isDeepStrictEqual(canonicalJson(payload),{licensee:expectedJob.licensee,expires_at_ms:Date.parse(expectedJob.end+'T00:00:00Z'),features:['fee_free'],accounts:[OWNER]})
     &&verify(null,payload,createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(scope.publicKey,'hex')]),format:'der',type:'spki'}),signature));
    r=safe(await protectedSend({kind:'issuer-deliver',token:heldIssuer,order:order.number,body:Buffer.from(init.body)},signal,8192));
    const b=json(r);requireValue(b.ok===true&&b.delivered===order.number);
   }
   return response(r);
  })) as typeof fetch,
  inboxRequest:Object.freeze({post:(async(url,options)=>operation(async()=>{
   requireValue(url===SITE+'/api/testnet-inbox/messages'&&exact(options,['headers','data','maxRedirects','timeout'])
    &&exact(options.headers,['authorization'])&&options.headers.authorization==='Bearer '+heldInbox.toString('ascii')
    &&isDeepStrictEqual(options.data,{recipient:RECIPIENT,after:scope.startedAt})&&options.maxRedirects===0&&options.timeout===10000&&++inboxReads<=100);
   const r=safe(await protectedSend({kind:'inbox',token:heldInbox,body:Buffer.from(JSON.stringify(options.data))},controller.signal,262144*11));const b=json(r);
   requireValue(exact(b,['ok','messages'])&&b.ok===true&&Array.isArray(b.messages)&&b.messages.length<=10);
   for(const row of b.messages)requireValue(exact(row,['id','recipient','received_at','raw'])&&typeof row.id==='string'&&ID.test(row.id)&&row.recipient===RECIPIENT&&Number.isSafeInteger(row.received_at)
    &&Number(row.received_at)>=scope.startedAt&&Number(row.received_at)<=Date.now()&&typeof row.raw==='string'&&Buffer.byteLength(row.raw)<=262144);
   let bytes:Buffer|undefined=Buffer.from(r.body);
   return{ok:()=>true,body:async()=>{requireValue(bytes);return Buffer.from(bytes);},dispose:async()=>{bytes?.fill(0);bytes=undefined;}};
  })) as InboxRequest['post']}),
  snapshot:()=>Object.freeze({closed,failed,active,quoteUsed,statusUsed,statusReads,checks,inboxReads,jobsUsed,deliveryUsed,paymentUsed,paymentAccepted,paidLedgerProved:!!ledgerHash}),
  dispose:()=>{closed=true;controller.abort();heldIssuer.fill(0);heldInbox.fill(0);session=undefined;order=undefined;expectedJob=undefined;},
 });
}
export type ProtectedJourney=ReturnType<typeof makeProtectedJourney>;
/** Native listener adapter uses the existing framing grammar. It reserves exchange at
 * header arrival and never gives a browser any issuer/inbox or Access-token route. */
export function journeyBrowserPolicy(input:ProtectedJourneyScope,cap:ProtectedJourney,extensionId:string,authority:(deadline:number)=>void){
 const scope=structuredClone(input);
 requireValue(/^[a-p]{32}$/.test(extensionId));let exchangeReserved=false,rpcReads=0;
 const headers={'cache-control':'no-store','content-type':'application/json; charset=utf-8','access-control-allow-origin':SITE,vary:'Origin'};
 const check=()=>{authority(scope.deadline);const s=cap.snapshot();requireValue(!s.closed&&!s.failed&&Date.now()<scope.deadline);};
 const disarm=()=>cap.dispose();
 return{
  disarm,close:disarm,
  openRequest(host:string,method:string,path:string,rawHeaders:readonly string[]):{length:number;complete(raw:Buffer):Promise<SafeResponse>}{
   try{
    check();const raw=[...rawHeaders];
    for(let i=0;i<raw.length;i+=2)if(raw[i]!.toLowerCase()==='referer'){
     requireValue([SITE+'/',SITE+'/licence',SITE+'/connect'].includes(raw[i+1]!));raw[i+1]=SITE+'/approve';
    }
    const length=validateHeaders(raw,host,method,path,extensionId);
    const staging=host===STAGING_HOST,venue=host===TESTNET_HOST,rpc=host===RPC_HOST;
    requireValue(staging&&(method==='GET'&&(Object.hasOwn(scope.assets,path)||path==='/api/licence/status')||method==='POST'&&['/api/licence/quote','/api/licence/order','/api/licence/order/check'].includes(path))
     ||venue&&['POST','OPTIONS'].includes(method)&&['/info','/exchange'].includes(path)
     ||rpc&&method==='POST'&&path===RPC_PATH&&++rpcReads<=4);
    if(venue&&method==='POST'&&path==='/exchange'){requireValue(!exchangeReserved);exchangeReserved=true;}
    let completed=false;
    return{length,complete:async(body:Buffer)=>{
     try{
      check();requireValue(!completed&&body.length===length);completed=true;
      if(method==='OPTIONS')return{status:204,headers:{...headers,'access-control-allow-methods':'POST','access-control-allow-headers':'content-type'},body:Buffer.alloc(0)};
      let r:Response;
      if(staging&&method==='GET')r=path==='/api/licence/status'?await cap.customer('status'):await cap.asset(path);
      else if(staging)r=await cap.customer(path.endsWith('/quote')?'quote':path.endsWith('/check')?'check':'order',body);
      else if(rpc)r=await cap.chainId(body);
      else r=path==='/info'?await cap.paymentInfo(body):await cap.submitPayment(body);
      check();return{status:r.status,headers:{...Object.fromEntries(r.headers),...(venue?headers:{}),...(rpc?{'access-control-allow-origin':'chrome-extension://'+extensionId,vary:'Origin'}:{})},body:Buffer.from(await r.arrayBuffer())};
     }catch{disarm();throw new PolicyError('request');}
    }};
   }catch{disarm();throw new PolicyError('request');}
  },
 };
}
