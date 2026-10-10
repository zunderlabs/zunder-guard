// Pure public-frame parser. Parsing grants no saved-receipt, channel, kernel,
// source or payment authority and does not consume a live publication.
import {createHash} from 'node:crypto';
import {OWNER,DENIED,exact,hashString,units,fail} from './policy.ts';
import type {PurchaseBinding} from './purchase-inputs.ts';
export interface ProtectedPurchaseCandidate {
 readonly tag:string;readonly source:string;readonly manifest_sha256:string;
}
export interface ProtectedPurchaseController {
 readonly kind:"github-hosted";readonly boot:string;
 readonly controlSource:string;readonly planSha256:string;readonly runNumber:number;
 readonly attempt:number;readonly parentPid:number;readonly parentBirth:string;
}
export interface ProtectedPurchaseExpected {
 readonly challenge:string;readonly controller:ProtectedPurchaseController;
 readonly runId:string;readonly startedAt:number;readonly deadline:number;
 readonly owner:typeof OWNER;readonly merchant:string;
 /** Caller must authenticate these binding bytes/hash independently. */
 readonly purchaseBinding:Readonly<PurchaseBinding>;
 readonly candidate:ProtectedPurchaseCandidate;readonly originalWatchdogPinsSha256:string;
}
export interface ProtectedPurchaseProof {
 readonly runId:string;readonly candidate:ProtectedPurchaseCandidate;
 readonly startedAt:number;readonly deadline:number;readonly owner:typeof OWNER;
 readonly merchant:string;readonly publicKey:string;readonly token:string;readonly nonce:number;
 readonly amount:string;readonly ledgerHash:string;readonly mailSha256:string;
 readonly recoverySha256:string;readonly receiptSha256:string;readonly purchaseSha256:string;
 readonly paymentHeldSha256:string;readonly teardownSha256:string;readonly originalWatchdogPinsSha256:string;
}
export interface CompletedPurchasePublication {
 readonly schema:1;readonly kind:'live-protected-purchase-completion';readonly sequence:1;
 readonly challenge:string;readonly controller:ProtectedPurchaseController;readonly purchase:ProtectedPurchaseProof;
}
export interface ParsedPurchasePublication {
 readonly publication:CompletedPurchasePublication;
 /** SHA256 of canonical compact sorted ASCII JSON, excluding the frame's LF. */
 readonly canonicalSha256:string;
}
const CONTROLLER=['kind','boot','controlSource','planSha256','runNumber','attempt','parentPid','parentBirth'] as const;
const PURCHASE=['runId','candidate','startedAt','deadline','owner','merchant','publicKey','token','nonce','amount','ledgerHash',
 'mailSha256','recoverySha256','receiptSha256','purchaseSha256','paymentHeldSha256','teardownSha256','originalWatchdogPinsSha256'];
const HASHES=['mailSha256','recoverySha256','receiptSha256','purchaseSha256','paymentHeldSha256','teardownSha256','originalWatchdogPinsSha256'] as const;
const runUuid=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
const bootUuid=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const positiveInt=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>0;
function candidate(v:unknown):asserts v is ProtectedPurchaseCandidate {
 exact(v,['tag','source','manifest_sha256']);
 if(typeof v.tag!=='string'||!/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?$/.test(v.tag)||v.tag.length>128
  ||typeof v.source!=='string'||!/^[0-9a-f]{40}$/.test(v.source)||!hashString(v.manifest_sha256))fail();
}
function controller(v:unknown):asserts v is ProtectedPurchaseController {
 exact(v,CONTROLLER);
 if(v.kind!=='github-hosted'||!bootUuid(v.boot)
  ||typeof v.controlSource!=='string'||!/^[0-9a-f]{40}$/.test(v.controlSource)
  ||!hashString(v.planSha256)||!positiveInt(v.runNumber)||!positiveInt(v.attempt)||v.attempt>100
  ||!positiveInt(v.parentPid)||typeof v.parentBirth!=='string'||!/^[1-9][0-9]{0,19}$/.test(v.parentBirth))fail();
}
function sorted(v:unknown):unknown {
 if(v&&typeof v==='object')return Object.fromEntries(Object.keys(v).sort().map(k=>[k,sorted((v as Record<string,unknown>)[k])]));
 return v;
}
/** Agreed source ABI: exactly one sorted compact ASCII JSON frame and one LF,
 * <=8192 bytes total. Caller must establish live authenticated channel custody.
 * No I/O, clock reads, callbacks, signatures or state consumption occur here. */
export function parseCompletedPurchasePublication(raw:Uint8Array,expected:ProtectedPurchaseExpected,now:number):Readonly<ParsedPurchasePublication> {
 if(!(raw instanceof Uint8Array)||raw.byteLength===0||raw.byteLength>8192||raw.at(-1)!==10)fail();
 exact(expected,['challenge','controller','runId','startedAt','deadline','owner','merchant','purchaseBinding','candidate','originalWatchdogPinsSha256']);
 candidate(expected.candidate);controller(expected.controller);
 const b=expected.purchaseBinding;
 exact(b,['schema','run','attempt','source','runId','startedAt','deadline','merchant','issuerPublicKey']);
 if(!hashString(expected.challenge)||!runUuid(expected.runId)||expected.owner!==OWNER
  ||typeof expected.merchant!=='string'||!/^0x[0-9a-f]{40}$/.test(expected.merchant)||DENIED.includes(expected.merchant)
  ||!hashString(expected.originalWatchdogPinsSha256)||![expected.startedAt,expected.deadline,now].every(Number.isSafeInteger)
  ||expected.startedAt<0||expected.startedAt>now||now>=expected.deadline||expected.deadline<=expected.startedAt
  ||expected.deadline-expected.startedAt>1200000||b.schema!==1||b.run!==expected.controller.runNumber||b.attempt!==expected.controller.attempt
  ||b.source!==expected.candidate.source||b.runId!==expected.runId||b.startedAt!==expected.startedAt||b.deadline!==expected.deadline
  ||b.merchant!==expected.merchant||!hashString(b.issuerPublicKey))fail();
 let decoded:unknown;
 const bytes=raw.subarray(0,-1);
 try{decoded=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{fail();}
 exact(decoded,['schema','kind','sequence','challenge','controller','purchase']);controller(decoded.controller);
 exact(decoded.purchase,PURCHASE);candidate(decoded.purchase.candidate);
 const envelope=decoded as unknown as CompletedPurchasePublication,p=envelope.purchase;
 if(envelope.schema!==1||envelope.kind!=='live-protected-purchase-completion'||envelope.sequence!==1
  ||envelope.challenge!==expected.challenge||CONTROLLER.some(k=>envelope.controller[k]!==expected.controller[k])
  ||p.runId!==expected.runId||p.candidate.tag!==expected.candidate.tag||p.candidate.source!==expected.candidate.source
  ||p.candidate.manifest_sha256!==expected.candidate.manifest_sha256||p.startedAt!==expected.startedAt||p.deadline!==expected.deadline
  ||p.owner!==OWNER||p.merchant!==expected.merchant||p.publicKey!==b.issuerPublicKey
  ||typeof p.token!=='string'||!/^USDC:0x[0-9a-f]{32}$/.test(p.token)||typeof p.ledgerHash!=='string'||!/^0x[0-9a-f]{64}$/.test(p.ledgerHash)
  ||!Number.isSafeInteger(p.nonce)||p.nonce<p.startedAt||p.nonce>now||units(p.amount)<=0n||units(p.amount)>355610000n
  ||HASHES.some(k=>!hashString(p[k]))||p.originalWatchdogPinsSha256!==expected.originalWatchdogPinsSha256)fail();
 const canonical=new TextEncoder().encode(JSON.stringify(sorted(envelope))+'\n');
 if(canonical.length!==raw.length||canonical.some((byte,i)=>byte!==raw[i]))fail();
 const publication=Object.freeze({...envelope,controller:Object.freeze({...envelope.controller}),
  purchase:Object.freeze({...p,candidate:Object.freeze({...p.candidate})})});
 return Object.freeze({publication,canonicalSha256:createHash('sha256').update(bytes).digest('hex')});
}
