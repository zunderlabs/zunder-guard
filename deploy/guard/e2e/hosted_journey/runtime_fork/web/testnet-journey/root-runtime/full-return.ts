// Intentional hosted Linux policy fork. Existing legacy exact-fee helpers are
// not the active return admission. No provider or key operation on import.
import {OWNER,units,decimal,exact,address,fail,type FileRef} from './policy.ts';
import type {Snapshot} from './return.ts';
export const PROPOSAL_SHA='72f89eeb82b29892d2c42b178dc2116aa1dcfa3738df1561315cad2e591444e9';
export const RETURN_POLICY='approved-testnet-single-full-balance-return';
export interface FullBalanceReturnPolicy {
 version:2;policy:typeof RETURN_POLICY;proposalSha256:typeof PROPOSAL_SHA;signedAmountLimitUsdc:string;
 runId:string;merchant:string;destination:typeof OWNER;amount:string;paidUsdc:string;token:string;
 paymentHash:string;paymentAfter:number;startedAt:number;expires:number;purchaseReceipt:FileRef;ownerInitialUsdc:string;ownerBaselineSha256:string;
}
export interface FullSnapshot extends Snapshot {
 merchantLedger:unknown;ownerLedger:unknown;observations:unknown[];observationsSha256:string;completedAt:number;monoStartNs:string;monoEndNs:string;
}
export function validateFullReturn(p:FullBalanceReturnPolicy,merchant:string,runId:string,deadline:number,now:number){
 exact(p,['version','policy','proposalSha256','signedAmountLimitUsdc','runId','merchant','destination','amount','paidUsdc','token',
  'paymentHash','paymentAfter','startedAt','expires','purchaseReceipt','ownerInitialUsdc','ownerBaselineSha256']);
 if(p.version!==2||p.policy!==RETURN_POLICY||p.proposalSha256!==PROPOSAL_SHA||p.runId!==runId||p.merchant!==merchant
  ||!address(merchant)||merchant===OWNER||p.destination!==OWNER||!/^USDC:0x[0-9a-f]{32}$/.test(p.token)
  ||!/^0x[0-9a-f]{64}$/.test(p.paymentHash)||![p.paymentAfter,p.startedAt,p.expires].every(Number.isSafeInteger)
  ||p.paymentAfter<p.startedAt||p.paymentAfter>now||p.startedAt>now||now>=p.expires||p.expires>deadline
  ||p.expires<=p.startedAt||p.expires-p.startedAt>1200000)fail();
 const amount=units(p.amount),limit=units(p.signedAmountLimitUsdc);
 if(amount<=0n||amount!==units(p.paidUsdc)||amount>limit||limit>355610000n||units(p.ownerInitialUsdc)<amount
  ||!/^([0-9a-f]{64})$/.test(p.ownerBaselineSha256))fail();
 exact(p.purchaseReceipt,['file','sha256']);
}
/** Current supported send variant has no authenticated fee/payer mapping.
 * Strict complete intervals admit only exact ordinary sends; any extra or fee
 * field is HOLD. A receiver deduction cannot supply its own fee authority. */
export function exactSend(row:unknown,sender:string,destination:string,amount:string,start:number,end:number,hash?:string){
 exact(row,['time','hash','delta']);exact(row.delta,['type','user','destination','amount','token']);
 if(!Number.isSafeInteger(row.time)||(row.time as number)<start||(row.time as number)>end
  ||typeof row.hash!=='string'||!/^0x[0-9a-f]{64}$/.test(row.hash)||(hash!==undefined&&row.hash!==hash)
  ||row.delta.type!=='send'||row.delta.user!==sender||row.delta.destination!==destination||row.delta.token!=='USDC'
  ||units(row.delta.amount)!==units(amount))fail();return row.hash;
}
export function paymentInterval(rows:unknown,p:FullBalanceReturnPolicy,now:number){
 if(!Array.isArray(rows)||rows.length!==1)fail();
 return exactSend(rows[0],OWNER,p.merchant,p.paidUsdc,p.paymentAfter,now,p.paymentHash);
}
export function returnInterval(rows:unknown,p:FullBalanceReturnPolicy,nonce:number,now:number){
 if(!Array.isArray(rows)||rows.length!==2)fail();
 const pay=rows.filter(r=>r?.hash===p.paymentHash),returned=rows.filter(r=>r?.hash!==p.paymentHash);
 if(pay.length!==1||returned.length!==1)fail();
 exactSend(pay[0],OWNER,p.merchant,p.paidUsdc,p.paymentAfter,now,p.paymentHash);
 return exactSend(returned[0],p.merchant,OWNER,p.amount,nonce,now);
}
export function reconcileFullBalances(before:FullSnapshot,after:FullSnapshot,p:FullBalanceReturnPolicy){
 const a=units(p.amount),m0=units(before.merchant.accountValue),m1=units(after.merchant.accountValue),
  o0=units(before.owner.accountValue),o1=units(after.owner.accountValue),debit=m0-m1,credit=o1-o0;
 if(o0!==units(p.ownerInitialUsdc)-a||o1!==units(p.ownerInitialUsdc)||m0!==a||units(before.merchant.withdrawable)!==a||m1!==0n||units(after.merchant.withdrawable)!==0n
  ||o0!==units(before.owner.withdrawable)||o1!==units(after.owner.withdrawable)
  ||debit!==a||credit<=0n||credit>a)fail();
 // Nonzero receiver deduction lacks an admitted provider fee/payer variant.
 // Refuse rather than fabricate one. Full credit follows from both actual
 // balances plus complete same-transaction ledgers checked by the caller.
 if(credit!==a)fail();
 return{debit:decimal(debit),credit:decimal(credit),fee:'0',merchantEmpty:true,
  signedAmount:decimal(a),beforeReadbacksSha256:before.observationsSha256,afterReadbacksSha256:after.observationsSha256,
  beforeObservedAt:before.time,afterObservedAt:after.completedAt,beforeReadbacks:before.observations,afterReadbacks:after.observations};
}

export function freshSnapshot(snapshot:FullSnapshot,now:number,mono:bigint){
 if(!Number.isSafeInteger(snapshot.time)||!Number.isSafeInteger(snapshot.completedAt)||snapshot.time>snapshot.completedAt
  ||snapshot.completedAt>now||now-snapshot.time>60000||!/^[1-9][0-9]{0,23}$/.test(snapshot.monoStartNs)
  ||!/^[1-9][0-9]{0,23}$/.test(snapshot.monoEndNs)||BigInt(snapshot.monoEndNs)<BigInt(snapshot.monoStartNs)
  ||mono<BigInt(snapshot.monoEndNs)||mono-BigInt(snapshot.monoStartNs)>60000000000n)fail();
}
