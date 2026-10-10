// Closed bundle entry for the native parent. Importing performs no network/key operation.
import {startPrivateJourneyProxy,type RootJourneyProxy} from './proxy.ts';
import {runTestnet,type TestnetIssuerConfig} from '../../../deploy/licence/testnet-issuer/issuer.ts';
import {receiveLicenceMail,verifyTestnetLicence,type InboxQuery} from '../../site/tests/testnet-inbox.ts';
import {licensee} from '../../waitlist/src/licence/core.ts';
import type {ProtectedJourneyScope} from './protected-journey.ts';
export {startPrivateJourneyProxy};
export {createProtectedCheckoutDriver} from './checkout-driver.ts';
export {recoverProtectedPurchase} from './recovery-driver.ts';
export {LinuxRootWalletRuntime} from './linux-runtime.ts';
export {validateNoKeyDenialReceipt} from './proxy-no-key.ts';
export type {RootJourneyProxy,ProtectedJourneyScope,TestnetIssuerConfig};
/** Root-only continuation after the genuine browser wallet accepted its exact payment.
 * Existing signer, real mailbox parser and pinned native verifier run without mocked responses.
 * The returned key/recovery URL stays in root memory for activation/recovery; never journal it.
 * Native parent owns cancellation, secret custody and subsequent Guard install/activation. */
export async function completeProtectedPurchase(proxy:RootJourneyProxy,input:ProtectedJourneyScope,issuer:TestnetIssuerConfig,
 inbox:Omit<InboxQuery,'orderNumber'>,verifier:{path:string;sha256:string},assertOriginalAuthority:(deadline:number)=>void){
 const scope=structuredClone(input);
 const guard=()=>{if(typeof assertOriginalAuthority!=='function'||Date.now()>=scope.deadline)throw new Error('Protected purchase authority expired');assertOriginalAuthority(scope.deadline);};
 guard();
 if(issuer.publicKey!==scope.publicKey||issuer.site!=='https://staging.zunderlabs.com'
  ||inbox.recipient!==scope.recipient||inbox.after!==scope.startedAt)throw new Error('Protected purchase continuation refused');
 const payment=await proxy.confirmPaid();
 guard();
 const issued=await runTestnet(issuer,{fetch:proxy.issuerFetch,now:()=>{guard();return Date.now();}});
 guard();
 if(issued.delivered!==1||issued.failed!==0||issued.deferred!==0)throw new Error('Protected delivery did not complete');
 const mail=await receiveLicenceMail(proxy.inboxRequest,{...inbox,orderNumber:payment.number},Math.min(180000,scope.deadline-Date.now()));
 guard();
 await verifyTestnetLicence({key:mail.licenceKey,publicKey:scope.publicKey,owner:scope.owner,expectedLicensee:licensee(scope.quote.company,payment.number)},verifier.path,verifier.sha256,guard);
 guard();
 return{payment,mail};
}
