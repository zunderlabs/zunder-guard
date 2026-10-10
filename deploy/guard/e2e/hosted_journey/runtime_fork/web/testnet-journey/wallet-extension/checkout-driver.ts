// Root-only producer: ordinary protected checkout UI plus the admitted machine
// EIP1193 bridge. No browser/context launch, extension import, key reader or venue fetch.
import type {Page, Locator} from '../../site/node_modules/playwright-core/index.js';
import {isDeepStrictEqual} from 'node:util';
import {createTestnetPaymentWallet, type TestnetPaymentSigner} from '../../site/tests/testnet-payment-wallet.ts';
import {validatePaymentPolicy, validPaymentPage, type PaymentPolicy} from '../../site/tests/testnet-payment-policy.ts';
import {usdcUnits} from '../../site/src/lib/usdc.ts';
import {digest, OWNER, STAGING_HOST} from './proxy-policy.ts';
import type {HeldPayment, ProtectedJourneyScope, JourneyQuote} from './protected-journey.ts';
import type {RootJourneyProxy} from './proxy.ts';
const SITE='https://'+STAGING_HOST;
function fail():never{throw new Error('Protected checkout driver refused');}
export interface CheckoutDriverBinding {
  source:string;sourceManifestSha256:string;rootScopeSha256:string;
  runId:string;startedAt:number;deadline:number;
}
export function validateCheckoutBinding(scope:ProtectedJourneyScope,binding:CheckoutDriverBinding){
  if(!binding||Object.keys(binding).sort().join(',')!=='deadline,rootScopeSha256,runId,source,sourceManifestSha256,startedAt'
    ||!/^[0-9a-f]{40}$/.test(binding.source)||! /^[0-9a-f]{64}$/.test(binding.sourceManifestSha256)
    ||binding.rootScopeSha256!==digest(JSON.stringify(scope))||binding.runId!==scope.runId
    ||binding.startedAt!==scope.startedAt||binding.deadline!==scope.deadline
    ||scope.schema!==1||scope.purpose!=='private-testnet-purchase'||scope.owner!==OWNER
    ||!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(scope.runId)
    ||!Number.isSafeInteger(scope.startedAt)||!Number.isSafeInteger(scope.deadline)
    ||scope.deadline<=scope.startedAt||scope.deadline-scope.startedAt>1200000
    ||usdcUnits(scope.maxUsdc)<=0n||usdcUnits(scope.maxUsdc)>355610000n)fail();
}
type RootQuote=ReturnType<RootJourneyProxy['checkoutBinding']>;
/** DOM values can corroborate the root quote; they can never create an order/receipt. */
export function checkCheckoutObservation(root:RootQuote,scope:ProtectedJourneyScope,observed:{number:string;amount:string;merchant:string;network:string;status:string},now:number){
  if(root.number!==observed.number||root.quote.usdc!==observed.amount||root.quote.payTo!==observed.merchant
    ||observed.merchant!==scope.merchant||observed.network!=='Hyperliquid · TESTNET'
    ||observed.status!=='awaiting_payment'||root.quote.status!=='awaiting_payment'
    ||root.quote.chain!=='testnet'||root.quote.network!=='hyperliquid'
    ||!isDeepStrictEqual(root.quote.accounts,[scope.owner])||root.expires>scope.deadline||now>=root.expires
    ||root.quote.quoteExpiresAt-now<120000||usdcUnits(root.quote.usdc)>usdcUnits(scope.maxUsdc)
    ||usdcUnits(root.quote.usdc)<=0n)fail();
}
/** Actual caller owns the Page's authenticated sandbox/proxy/source admission and
 * machine signer custody. This class performs only locator operations on that Page. */
class CheckoutUI {
  private page:Page;private quote:JourneyQuote;private guard:()=>void;
  constructor(page:Page,quote:JourneyQuote,guard:()=>void){this.page=page;this.quote=quote;this.guard=guard;}
  private async step<T>(work:()=>Promise<T>){this.guard();const value=await work();this.guard();return value;}
  private async unique(locator:Locator){
    await this.step(()=>locator.waitFor({state:'visible',timeout:5000}));
    if(await this.step(()=>locator.count())!==1||!await this.step(()=>locator.isVisible()))fail();
    return locator;
  }
  async identity(){
    this.guard();if(!validPaymentPage(this.page.url())||this.page.frames().length!==1)fail();
    const root=this.page.locator('[data-licence]');await this.unique(root);
    if(await this.step(()=>root.getAttribute('data-testnet-journey'))!=='1'
      ||await this.step(()=>root.getAttribute('data-terms'))!==this.quote.termsVersion)fail();
  }
  private async text(selector:string){
    const locator=this.page.locator(selector);await this.unique(locator);
    const value=await this.step(()=>locator.textContent({timeout:5000}));
    if(value===null||Buffer.byteLength(value)>512)fail();return value.trim();
  }
  async click(selector:string){
    await this.identity();const locator=this.page.locator(selector);await this.unique(locator);
    if(!await this.step(()=>locator.isEnabled()))fail();await this.step(()=>locator.click({timeout:5000}));
  }
  async quoteForm(){
    this.guard();if(this.page.url()!=='about:blank')fail();
    await this.step(()=>this.page.goto(SITE+'/licence',{waitUntil:'domcontentloaded',timeout:10000}));
    await this.identity();
    const form=this.page.locator('[data-form]');await this.unique(form);
    for(const [name,value]of [['plan','pro'],['term','month'],['network','hyperliquid']]as const){
      const field=form.locator(`[name=${name}][value=${value}]`);await this.unique(field);
      await this.step(()=>field.check({timeout:5000}));if(!await this.step(()=>field.isChecked()))fail();
    }
    for(const [name,value]of Object.entries({accounts:this.quote.accounts.join('\n'),company:this.quote.company,
      street:this.quote.street,postcode:this.quote.postcode,city:this.quote.city,email:this.quote.email,vatId:this.quote.vatId})){
      const field=form.locator(`[name=${name}]`);await this.unique(field);
      await this.step(()=>field.fill(value,{timeout:5000}));if(await this.step(()=>field.inputValue())!==value)fail();
    }
    const country=form.locator('[name=country]');await this.unique(country);
    await this.step(()=>country.selectOption(this.quote.country,{timeout:5000}));
    if(await this.step(()=>country.inputValue())!==this.quote.country)fail();
    for(const name of ['business','terms']){
      const field=form.locator(`[name=${name}]`);await this.unique(field);
      await this.step(()=>field.check({timeout:5000}));if(!await this.step(()=>field.isChecked()))fail();
    }
    await this.click('[data-submit]');await this.unique(this.page.locator('[data-pay]'));
  }
  async observation(){
    await this.identity();
    const number=await this.text('[data-pay-number]');
    if(!/^ORDER ZL-\d{4}-\d{6} · TESTNET$/.test(number))fail();
    return{number:number.slice(6,-10),amount:await this.text('[data-pay-amount]'),merchant:await this.text('[data-pay-to]'),
      network:await this.text('[data-pay-network]'),status:await this.step(()=>this.page.locator('[data-licence]').getAttribute('data-status'))??''};
  }
  async reload(){await this.identity();await this.step(()=>this.page.reload({waitUntil:'domcontentloaded',timeout:10000}));await this.unique(this.page.locator('[data-pay]'));}
  async connect(amount:string,owner:string){
    const options=this.page.locator('[data-wallet-provider] option');
    // The production checkout hides a singleton select; its option is not visible.
    if(await this.step(()=>options.count())!==1
      ||(await this.step(()=>options.textContent({timeout:5000})))?.trim()!=='Browser wallet')fail();
    if(await this.text('[data-wallet-pay]')!=='Connect wallet to pay')fail();
    await this.click('[data-wallet-pay]');
    await this.step(()=>this.page.locator('[data-wallet-pay]').filter({hasText:'Pay '+amount+' USDC'}).waitFor({state:'visible',timeout:5000}));
    if(await this.text('[data-wallet-pay]')!=='Pay '+amount+' USDC'
      ||!(await this.text('[data-wallet-status]')).startsWith('From '+owner+'.'))fail();
  }
}
/** One producer for one original epoch. Keys stay in the caller's real signer.
 * Native parent must bind source/run/t0 packet before invoking and provide the SAME
 * original UTC+monotonic assertion used by startPrivateJourneyProxy/continuation.
 * run() is UI submission evidence only. It cannot replace confirmPaid/ledger/mail/Rust.
 * Parent installs armHeldPayment as its proxy's explicit arm callback, with the real
 * current-stage permit; no automatic permit callback exists here. */
export function createProtectedCheckoutDriver(input:ProtectedJourneyScope,inputBinding:CheckoutDriverBinding,
  signer:TestnetPaymentSigner,assertOriginalAuthority:(deadline:number)=>void){
  const scope=structuredClone(input),binding=structuredClone(inputBinding);
  validateCheckoutBinding(scope,binding);
  const guard=()=>{if(typeof assertOriginalAuthority!=='function'||Date.now()<scope.startedAt||Date.now()>=scope.deadline)fail();assertOriginalAuthority(scope.deadline);};
  guard();if(signer?.address?.toLowerCase()!==scope.owner||typeof signer.signTypedData!=='function')fail();
  let used=false,closed=false,broker:ReturnType<typeof createTestnetPaymentWallet>|undefined,paymentExpires=0;
  const check=()=>{guard();if(closed)fail();};
  const wrapped:TestnetPaymentSigner={address:scope.owner,signTypedData:async(domain,types,message)=>{
    check();if(Number(message.nonce)<scope.startedAt)fail();
    const signature=await signer.signTypedData(domain,types,message);check();return signature;
  }};
  return Object.freeze({
    binding:Object.freeze({...binding}),
    async armHeldPayment(held:Readonly<HeldPayment>,signal:AbortSignal,
      permit:(held:Readonly<HeldPayment>,signal:AbortSignal)=>Promise<{bodySha256:string;expires:number}>){
      check();if(!broker||!used||signal.aborted||typeof permit!=='function'||held.nonce<scope.startedAt||held.expires>scope.deadline)fail();
      broker.authorizeHeldPayment(held);
      const result=await permit(held,signal);check();
      if(signal.aborted||result.bodySha256!==held.bodySha256||result.expires!==held.expires||Date.now()>=held.expires)fail();
      return result;
    },
    async run(page:Page,proxy:RootJourneyProxy){
      check();if(used)fail();used=true;
      const step=async<T>(work:()=>Promise<T>)=>{check();const value=await work();check();return value;};
      const ui=new CheckoutUI(page,scope.quote,check);
      try{
        await step(()=>ui.quoteForm());
        const quoted=proxy.checkoutBinding();check();
        checkCheckoutObservation(quoted,scope,await step(()=>ui.observation()),Date.now());
        // Canonical token is independently read through the already admitted root
        // native transport. It is never accepted from the page or signer.
        const meta=await step(()=>proxy.paymentInfo(Buffer.from(JSON.stringify({type:'spotMeta'}))));
        await step(()=>meta.arrayBuffer());
        const root=proxy.checkoutBinding();check();if(!root.token)fail();
        const policy:PaymentPolicy={owner:scope.owner,merchant:scope.merchant,expires:root.expires,quote:root.quote,token:root.token};
        validatePaymentPolicy(policy,Date.now());paymentExpires=root.expires;
        broker=createTestnetPaymentWallet(wrapped,policy,()=>{check();return Date.now();});
        await step(()=>broker!.install(page));await step(()=>ui.reload());
        checkCheckoutObservation(root,scope,await step(()=>ui.observation()),Date.now());
        await step(()=>ui.connect(root.quote.usdc,scope.owner));
        checkCheckoutObservation(root,scope,await step(()=>ui.observation()),Date.now());
        await step(()=>ui.click('[data-wallet-pay]'));
        // No retry/re-sign/new quote. Only the actual native proxy's accepted
        // response state can advance this producer; that still is not paid credit.
        for(;;){
          check();broker.assertNoViolation();const state=proxy.snapshot();
          if(state.failed||state.closed||Date.now()>=paymentExpires)fail();
          if(state.paymentAccepted){
            if(broker.outcome()!=='submitted')fail();
            const evidence=broker.evidence();if(evidence.nonce===null||evidence.nonce<scope.startedAt)fail();
            return Object.freeze({schema:1 as const,kind:'protected-checkout-ui-submitted' as const,
              walletAdapter:'admitted-machine-eip1193' as const,...binding,
              orderNumber:root.number,quoteId:root.quote.id,owner:scope.owner,merchant:scope.merchant,
              amount:root.quote.usdc,nonce:evidence.nonce,paidProof:false as const});
          }
          await step(()=>new Promise<void>(resolve=>setTimeout(resolve,100)));
        }
      }catch{proxy.disarm();fail();}
      finally{broker?.dispose();}
    },
    dispose(){closed=true;broker?.dispose();},
  });
}
