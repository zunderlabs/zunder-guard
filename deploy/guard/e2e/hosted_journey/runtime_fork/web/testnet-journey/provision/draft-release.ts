/** Local coordinator attestation, never a publication or signature-verification bypass.
 * Root authenticates release evidence separately; this gate binds those exact private
 * receipts to one reviewed staging artifact and plan. Same-UID coordinator trust applies.
 */
import {constants} from 'node:fs';
import {open,lstat,realpath} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {parseReleasePin,assertSignedAssetInventory,type ReleasePin} from '../../release-pin.ts';
// The consumer needs only these existing approval fields. Keeping this type
// local avoids pulling the provision CLI into the source-pinned ESM caller.
interface Approval {
 draftReleaseAcceptance?:DraftReleaseAcceptance;rootApproved:boolean;
 planHash:string;artifactManifestSha256:string;expires:number;
}
export type AcceptanceMode='apply'|'cleanup';
export function assertAcceptanceMode(mode:unknown):asserts mode is AcceptanceMode{
 if(mode!=='apply'&&mode!=='cleanup')throw new Error('Unsupported artifact acceptance mode');
}
export interface DraftReleaseAcceptance {receiptFile:string;receiptSha256:string}
export interface ProofReference {file:string;sha256:string}
export interface DraftReleaseReceipt {
 schema:1;scope:'signed-draft-staging';rootVerified:true;
 releasePinSha256:string;sourceCommit:string;signedAssetManifestSha256:string;
 releaseId:number;version:string;artifactManifestSha256:string;planHash:string;expires:number;
 proofs:Record<'signature'|'provenance'|'inventory'|'imageDescriptor',ProofReference>;
}
const hash=(bytes:Uint8Array|string)=>createHash('sha256').update(bytes).digest('hex');
const isHash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
function exact(value:unknown,keys:string[]):asserts value is Record<string,unknown>{
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==keys.length||keys.some(k=>!Object.hasOwn(value,k)))throw new Error('Invalid draft receipt shape');
}
/** Canonical private regular file, bounded before and during read; never follows symlinks. */
export async function readDraftProof(reference:ProofReference):Promise<unknown>{
 exact(reference,['file','sha256']);
 if(typeof reference.file!=='string'||!path.isAbsolute(reference.file)||path.normalize(reference.file)!==reference.file||!isHash(reference.sha256))throw new Error('Invalid draft proof reference');
 const file=reference.file,parent=path.dirname(file),uid=process.getuid?.();
 if(uid===undefined||await realpath(file)!==file||await realpath(parent)!==parent)throw new Error('Noncanonical draft proof');
 const parentStat=await lstat(parent);
 if(!parentStat.isDirectory()||parentStat.uid!==uid||(parentStat.mode&0o777)!==0o700)throw new Error('Draft proof parent must be owned and private');
 const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const before=await handle.stat(),limit=131072;
  if(!before.isFile()||before.uid!==uid||(before.mode&0o777)!==0o600||before.nlink!==1||before.size<2||before.size>limit)throw new Error('Draft proof file must be owned, private and bounded');
  const buffer=Buffer.alloc(limit+1);let offset=0;
  while(offset<buffer.length){const result=await handle.read(buffer,offset,buffer.length-offset,null);if(result.bytesRead===0)break;offset+=result.bytesRead;}
  const after=await handle.stat(),current=await lstat(file),parentAfter=await lstat(parent);
  if(offset!==before.size||offset>limit||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs
   ||current.isSymbolicLink()||current.dev!==before.dev||current.ino!==before.ino||parentAfter.dev!==parentStat.dev||parentAfter.ino!==parentStat.ino
   ||await realpath(file)!==file||hash(buffer.subarray(0,offset))!==reference.sha256)throw new Error('Draft proof changed or hash mismatch');
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buffer.subarray(0,offset)));
 }finally{await handle.close();}
}
const common=['schema','scope','kind','verified','sourceCommit','releaseId','version','signedAssetManifestSha256'];
function proofIdentity(value:unknown,kind:string,pin:ReleasePin,fields:string[]):asserts value is Record<string,unknown>{
 exact(value,[...common,...fields]);
 if(value.schema!==1||value.scope!=='signed-draft-proof'||value.kind!==kind||value.verified!==true
  ||value.sourceCommit!==pin.sourceCommit||value.releaseId!==pin.releaseId||value.version!==pin.version||value.signedAssetManifestSha256!==pin.signedAssetManifest.sha256)throw new Error('Draft verification proof identity differs');
}
/** All four proofs are root verification receipts, not unverified parser assertions. */
export async function acceptSignedDraft(pinBytes:Uint8Array,profile:unknown,approval:Approval,now=()=>Date.now(),mode:AcceptanceMode='apply'):Promise<number>{
 assertAcceptanceMode(mode);
 const acceptance=approval.draftReleaseAcceptance;
 if(!acceptance)throw new Error('Explicit signed draft acceptance required');
 exact(acceptance,['receiptFile','receiptSha256']);
 const receipt=await readDraftProof({file:acceptance.receiptFile,sha256:acceptance.receiptSha256});
 exact(receipt,['schema','scope','rootVerified','releasePinSha256','sourceCommit','signedAssetManifestSha256','releaseId','version','artifactManifestSha256','planHash','expires','proofs']);
 const pin=parseReleasePin(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(pinBytes)));
 const p=profile as {profile?:unknown;releaseVersion?:unknown;releasePublished?:unknown}|null;
 if(p?.profile!=='staging'||p.releaseVersion!==pin.version||p.releasePublished!==false||pin.published!==false||pin.publishedAt!==null
  ||!pin.sourceCommit||!pin.releaseId||Object.values(pin.signedAssetManifest).some(v=>v===null)||!pin.image||!Object.keys(pin.assets).length
  ||Object.entries(pin.channels).some(([name,value])=>value!==(name==='homebrewReady'?false:null)))throw new Error('Draft must be complete, unpublished and staging-only with all public channels disabled');
 if(receipt.schema!==1||receipt.scope!=='signed-draft-staging'||receipt.rootVerified!==true||approval.rootApproved!==true
  ||receipt.releasePinSha256!==hash(pinBytes)||receipt.sourceCommit!==pin.sourceCommit||receipt.signedAssetManifestSha256!==pin.signedAssetManifest.sha256
  ||receipt.releaseId!==pin.releaseId||receipt.version!==pin.version||!isHash(approval.planHash)||receipt.planHash!==approval.planHash
  ||!isHash(approval.artifactManifestSha256)||receipt.artifactManifestSha256!==approval.artifactManifestSha256)throw new Error('Draft acceptance is not bound to reviewed plan, pin and artifacts');
 const expires=receipt.expires;
 const checkLease=()=>{const time=now();if(!Number.isSafeInteger(expires)||!Number.isSafeInteger(approval.expires)||!Number.isSafeInteger(time)||(expires as number)<=0
  ||(expires as number)>approval.expires||(mode==='apply'&&(expires as number)<=time)||(expires as number)>time+1200000)throw new Error('Draft acceptance lease refused');};
 checkLease();exact(receipt.proofs,['signature','provenance','inventory','imageDescriptor']);
 // Read separately so each exact hash and semantic proof is checked; never fetch a URL.
 const signature=await readDraftProof(receipt.proofs.signature as ProofReference);
 proofIdentity(signature,'signature',pin,['manifestUrl','bundleUrl']);
 if(signature.manifestUrl!==pin.signedAssetManifest.url||signature.bundleUrl!==pin.signedAssetManifest.sigstoreBundleUrl)throw new Error('Draft signature verification URL differs');
 const provenance=await readDraftProof(receipt.proofs.provenance as ProofReference);
 proofIdentity(provenance,'provenance',pin,['provenanceUrl']);
 if(provenance.provenanceUrl!==pin.signedAssetManifest.provenanceUrl)throw new Error('Draft provenance verification URL differs');
 const inventory=await readDraftProof(receipt.proofs.inventory as ProofReference);
 proofIdentity(inventory,'inventory',pin,['checksums']);
 if(typeof inventory.checksums!=='string'||hash(inventory.checksums)!==pin.signedAssetManifest.sha256)throw new Error('Draft checksum manifest differs');
 assertSignedAssetInventory(pin,inventory.checksums);
 const image=await readDraftProof(receipt.proofs.imageDescriptor as ProofReference);
 proofIdentity(image,'imageDescriptor',pin,['asset','contents','reference']);
 if(image.asset!==pin.image.descriptorAsset||image.reference!==pin.image.reference||typeof image.contents!=='string'
  ||image.contents.trim()!==pin.image.reference||hash(image.contents)!==pin.assets[pin.image.descriptorAsset]!.sha256)throw new Error('Draft signed image descriptor differs');
 checkLease();return expires as number;
}
