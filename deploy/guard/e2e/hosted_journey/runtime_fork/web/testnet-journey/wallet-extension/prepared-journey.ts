// A single actual listener policy transitions from public assets to one private journey.
import type {Socket} from 'node:net';
import {PolicyError,STAGING_HOST,digest,validateHeaders,type SafeResponse} from './proxy-policy.ts';
import {makeProtectedStagingUpstream} from './root-upstream.ts';
import type {CanonicalProxyAccess} from './proxy-access.ts';
import {makeProtectedJourney,journeyBrowserPolicy,validateProtectedJourneyScope,
 type ProtectedJourneyScope,type ProtectedJourney,type JourneyCallbacks} from './protected-journey.ts';

export function makePreparedJourney(input:ProtectedJourneyScope,sockets:Set<Socket>,state:{active:number},
 access:CanonicalProxyAccess,authority:(deadline:number)=>void,extensionId:string){
 const scope=validateProtectedJourneyScope(input);
 if(typeof authority!=='function'||!/^[a-p]{32}$/.test(extensionId))throw new PolicyError('config');
 const send=makeProtectedStagingUpstream(sockets,state,access),controller=new AbortController();
 let cap:ProtectedJourney|undefined,privatePolicy:ReturnType<typeof journeyBrowserPolicy>|undefined;
 let claimed=false,closed=false,pending=0,assetReads=0;
 const guard=()=>{if(closed||Date.now()<scope.startedAt||Date.now()>=scope.deadline)throw new PolicyError('closed');authority(scope.deadline);};
 const stop=()=>{closed=true;controller.abort();cap?.dispose();};
 const privateCap=()=>{guard();if(!cap)throw new PolicyError('arm');return cap;};
 const asset=async(path:string):Promise<Response>=>{
  guard();if(cap)return cap.asset(path);
  const pin=scope.assets[path];if(!pin||++assetReads>512)throw new PolicyError('request');
  const r=await send({kind:'asset',path},controller.signal,8*1024*1024);guard();
  if(r.status!==200||digest(r.body)!==pin.sha256||r.headers['content-type']!==pin.contentType
   ||r.headers['content-security-policy']!==pin.csp||r.headers.location!==undefined||r.headers['set-cookie']!==undefined
   ||r.headers['www-authenticate']!==undefined||r.headers['proxy-authenticate']!==undefined
   ||(r.headers['content-encoding']!==undefined&&r.headers['content-encoding']!=='identity')
   ||Object.keys(r.headers).some(k=>k.toLowerCase().startsWith('cf-access-')))throw new PolicyError('upstream');
  return new Response(new Uint8Array(r.body),{headers:{'content-type':pin.contentType,'content-security-policy':pin.csp,'cache-control':'no-store','x-robots-tag':'noindex, nofollow'}});
 };
 const journey:ProtectedJourney=Object.freeze({
  asset,customer:(...args)=>privateCap().customer(...args),checkoutBinding:()=>privateCap().checkoutBinding(),
  paymentInfo:(...args)=>privateCap().paymentInfo(...args),submitPayment:(...args)=>privateCap().submitPayment(...args),
  chainId:(...args)=>privateCap().chainId(...args),confirmPaid:()=>privateCap().confirmPaid(),
  issuerFetch:((...args:Parameters<typeof fetch>)=>privateCap().issuerFetch(...args)) as typeof fetch,
  inboxRequest:Object.freeze({post:(...args:Parameters<ProtectedJourney['inboxRequest']['post']>)=>privateCap().inboxRequest.post(...args)}),
  snapshot:()=>cap?cap.snapshot():Object.freeze({closed,failed:false,active:pending,quoteUsed:false,statusUsed:false,statusReads:0,
   checks:0,inboxReads:0,jobsUsed:false,deliveryUsed:false,paymentUsed:false,paymentAccepted:false,paidLedgerProved:false}),
  dispose:stop,
 });
 const policy={disarm:stop,close:stop,
  assertNoKeyPreflight(){
   try{guard();if(claimed||cap||privatePolicy)throw new PolicyError('phase');return Date.now();}
   catch{stop();throw new PolicyError('phase');}
  },
  openRequest(host:string,method:string,path:string,rawHeaders:readonly string[]){
   guard();if(privatePolicy)return privatePolicy.openRequest(host,method,path,rawHeaders);
   // Reuse the exact credential/framing grammar even for denied public-stage requests.
   const raw=[...rawHeaders];
   for(let i=0;i<raw.length;i+=2)if(raw[i]!.toLowerCase()==='referer'){
    if(!['https://'+STAGING_HOST+'/','https://'+STAGING_HOST+'/licence','https://'+STAGING_HOST+'/connect'].includes(raw[i+1]!))throw new PolicyError('request');
    raw[i+1]='https://'+STAGING_HOST+'/approve';
   }
   const length=validateHeaders(raw,host,method,path,extensionId);pending++;
   let complete=false;
   return{length,complete:async(body:Buffer):Promise<SafeResponse>=>{
    if(complete){stop();throw new PolicyError('request');}complete=true;
    try{
     guard();if(body.length!==length||cap)throw new PolicyError('request');
     // A correctly framed negative write probe is refused without making a write.
     if(host!==STAGING_HOST||method!=='GET'||!Object.hasOwn(scope.assets,path))return{status:403,headers:{'content-type':'text/plain','cache-control':'no-store'},body:Buffer.alloc(0)};
     const r=await asset(path);guard();
     return{status:r.status,headers:Object.fromEntries(r.headers),body:Buffer.from(await r.arrayBuffer())};
    }catch{stop();throw new PolicyError('request');}finally{pending--;}
   }};
  },
 };
 return Object.freeze({journey,policy,activate(tokens:{issuer:Buffer;inbox:Buffer},callbacks:JourneyCallbacks){
  // Invalid and uncertain attempts consume the same activation, never create a fresh epoch.
  if(claimed){stop();throw new PolicyError('arm');}claimed=true;
  try{
   guard();if(pending!==0||state.active!==0||!callbacks||Object.keys(callbacks).join(',')!=='armExactPayment'
    ||typeof callbacks.armExactPayment!=='function')throw new PolicyError('arm');
   cap=makeProtectedJourney(scope,tokens,sockets,state,access,authority,Object.freeze({armExactPayment:callbacks.armExactPayment}));
   guard();privatePolicy=journeyBrowserPolicy(scope,cap,extensionId,authority);guard();
  }catch{stop();throw new PolicyError('arm');}
 }});
}
