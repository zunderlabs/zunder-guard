// Root-only real recovery producer. The parent admits a fresh isolated Page and
// retains its original authority; no browser, credential reader or response mock.
import type {Page, Route} from '../../site/node_modules/playwright-core/index.js';
import {createPublicKey, verify} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {digest, STAGING_HOST} from './proxy-policy.ts';
import {licensee} from '../../waitlist/src/licence/core.ts';
import {usdcUnits} from '../../site/src/lib/usdc.ts';
import {validateProtectedJourneyScope,type ProtectedJourneyScope} from './protected-journey.ts';
import type {completeProtectedPurchase} from './private-journey-entry.ts';
const SITE='https://'+STAGING_HOST;
function refused():never{throw new Error('Protected browser recovery refused');}
type Completion=Awaited<ReturnType<typeof completeProtectedPurchase>>;
/** Completion must be the actual root continuation result (ledger, received MIME
 * and pinned native verifier), not caller-fabricated data. This producer recovers
 * those exact verified key bytes using the received link and real browser fetch. */
export async function recoverProtectedPurchase(page:Page,input:ProtectedJourneyScope,
 completed:Completion,assertOriginalAuthority:(deadline:number)=>void){
 let scope:ProtectedJourneyScope;
 try{scope=validateProtectedJourneyScope(input);}catch{refused();}
 const result=structuredClone(completed);
 const guard=()=>{if(typeof assertOriginalAuthority!=='function'||Date.now()<scope.startedAt
   ||Date.now()>=scope.deadline)refused();assertOriginalAuthority(scope.deadline);};
 const step=async<T>(work:()=>Promise<T>)=>{
   guard();let timer:ReturnType<typeof setTimeout>|undefined;
   try{
     const value=await Promise.race([work(),new Promise<never>((_,reject)=>{
       timer=setTimeout(()=>reject(new Error('Protected browser recovery refused')),Math.max(1,scope.deadline-Date.now()));
     })]);guard();return value;
   }finally{clearTimeout(timer);}
 };
 const timeout=()=>{guard();return Math.max(1,Math.min(10000,scope.deadline-Date.now()));};
 let routeInstalled=false,violation=false,orderRequests=0,finished=false;
 const checked=()=>{guard();if(violation)refused();};
 let session:{id:string;token:string},expiresOn:string;
 const route=async(r:Route)=>{
   try{
     checked();const request=r.request(),url=new URL(request.url());
     if(url.origin!==SITE||url.search||url.hash||request.frame()!==page.mainFrame())refused();
     const path=url.pathname,method=request.method();
     if(request.isNavigationRequest()&&(method!=='GET'||path!=='/licence'||request.redirectedFrom()))refused();
     if(method==='POST'&&path==='/api/licence/order'){
       const body=JSON.parse(request.postData()??'null');
       if(++orderRequests!==1||!isDeepStrictEqual(body,session))refused();
     }else if(method!=='GET'||!(path==='/api/licence/status'||Object.hasOwn(scope.assets,path)))refused();
     checked();await r.continue();checked();
   }catch{violation=true;await r.abort().catch(()=>{});}
 };
 try{
   guard();
   if(page.url()!=='about:blank'
     ||page.frames().length!==1||page.context().pages().length!==1)refused();
   const storage=await step(()=>page.context().storageState());
   if(storage.cookies.length||storage.origins.length)refused();
   const {payment,mail}=result;
   if(payment.chain!=='testnet'||!/^ZL-\d{4}-\d{6}$/.test(payment.number)
     ||!/^0x[0-9a-f]{64}$/.test(payment.ledgerHash)||usdcUnits(payment.amount)<=0n
     ||usdcUnits(payment.amount)>usdcUnits(scope.maxUsdc)
     ||!mail.messageHashes||Object.keys(mail.messageHashes).sort().join(',')!=='key,order'
     ||!Object.values(mail.messageHashes).every(v=>/^[0-9a-f]{64}$/.test(v))
     ||mail.rawSha256!==digest(JSON.stringify(mail.messageHashes)))refused();
   const match=/^https:\/\/staging\.zunderlabs\.com\/licence#order=([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/.exec(mail.recoveryUrl);
   if(!match||typeof mail.licenceKey!=='string'||mail.licenceKey.length>4096)refused();
   session={id:match[1]!,token:match[2]!};
   const key=/^zgl1_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(mail.licenceKey);
   if(!key)refused();
   const bytes=Buffer.from(key[1]!,'base64url'),signature=Buffer.from(key[2]!,'base64url');
   if(bytes.toString('base64url')!==key[1]||signature.toString('base64url')!==key[2]||signature.length!==64
     ||!verify(null,bytes,createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(scope.publicKey,'hex')]),format:'der',type:'spki'}),signature))refused();
   const payload=JSON.parse(bytes.toString('utf8'));
   if(!Number.isSafeInteger(payload.expires_at_ms)||payload.expires_at_ms<=Date.now()
     ||!isDeepStrictEqual(payload,{licensee:licensee(scope.quote.company,payment.number),
       expires_at_ms:payload.expires_at_ms,features:['fee_free'],accounts:[scope.owner]}))refused();
   expiresOn=new Date(payload.expires_at_ms).toISOString().slice(0,10);
   if(Date.parse(expiresOn+'T00:00:00Z')!==payload.expires_at_ms)refused();
   routeInstalled=true;await step(()=>page.route('**/*',route));
   // Subscribe before navigating: this response must come from the page's actual
   // received-token POST, not a separate root fetch or fabricated completion.
   const pending=page.waitForResponse(r=>r.url()===SITE+'/api/licence/order'
     &&r.request().method()==='POST',{timeout:timeout()});
   void pending.catch(()=>{});
   const navigation=await step(()=>page.goto(mail.recoveryUrl,{waitUntil:'domcontentloaded',timeout:timeout()}));
   checked();if(!navigation||navigation.status()!==200||navigation.url()!==SITE+'/licence')refused();
   const response=await step(()=>pending);checked();
   if(orderRequests!==1||response.status()!==200||response.fromServiceWorker()
     ||!/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers()['content-type']??''))refused();
   const body=await step(()=>response.body());if(body.length>32768)refused();
   const recovered=JSON.parse(body.toString('utf8'));
   const order=recovered.order;
   if(recovered.ok!==true||recovered.token!==undefined||!order||order.id!==session.id
     ||order.number!==payment.number||order.licenceNumber!==payment.number||order.status!=='delivered'
     ||order.delivered!==true||order.chain!=='testnet'||order.network!=='hyperliquid'
     ||order.payTo!==scope.merchant||order.company!==scope.quote.company||order.plan!=='pro'||order.term!=='month'
     ||!isDeepStrictEqual(order.accounts,[scope.owner])||order.key!==mail.licenceKey
     ||order.licenceExpiresOn!==expiresOn||!Number.isSafeInteger(order.paidAt)
     ||order.paidAt<scope.startedAt||order.paidAt>Date.now()
     ||usdcUnits(order.usdc)!==usdcUnits(payment.amount)||usdcUnits(order.paidUsdc)!==usdcUnits(payment.amount))refused();
   const root=page.locator('[data-licence]');
   await step(()=>page.locator('[data-pay-title]').filter({hasText:'Licence sent'}).waitFor({state:'visible',timeout:timeout()}));
   if(await step(()=>root.count())!==1||await step(()=>root.getAttribute('data-testnet-journey'))!=='1'
     ||await step(()=>root.getAttribute('data-status'))!=='delivered'
     ||(await step(()=>page.locator('[data-pay-title]').textContent()))?.trim()!=='Licence sent'
     ||(await step(()=>page.locator('[data-pay-number]').textContent()))?.trim()!=='ORDER '+payment.number+' · TESTNET')refused();
   const details=page.locator('.lc-key-raw');
   if(await step(()=>details.count())!==1)refused();
   if(await step(()=>details.getAttribute('open'))===null)await step(()=>details.locator('summary').click({timeout:timeout()}));
   const shown=page.locator('[data-key]');
   if(await step(()=>shown.count())!==1||!await step(()=>shown.isVisible())
     ||await step(()=>shown.textContent())!==mail.licenceKey||page.url()!==SITE+'/licence'
     ||!await step(()=>page.evaluate(()=>location.hash===''&&location.search==='')))refused();
   checked();finished=true;
   return Object.freeze({schema:1 as const,kind:'protected-fresh-browser-recovered' as const,
     runId:scope.runId,startedAt:scope.startedAt,deadline:scope.deadline,orderNumber:payment.number,
     mailSha256:mail.rawSha256,keySha256:digest(mail.licenceKey),responseSha256:digest(body),
     issuerPublicKey:scope.publicKey,owner:scope.owner,expiresOn});
 }catch{refused();}
 finally{
   if(routeInstalled){
     // Begin cleanup even after expiry, but never renew authority or wait beyond
     // the original deadline. Parent owns Page/process cancellation if it hangs.
     let cleanup:Promise<void>;
     try{cleanup=page.unroute('**/*',route);}catch{refused();}
     void cleanup.catch(()=>{});
     if(Date.now()>=scope.deadline)refused();
     try{await step(()=>cleanup);}catch{refused();}
   }
   if(finished)try{checked();}catch{refused();}
 }
}
