import {readPlan,captureOwnedFiles,removeExactFiles,removeExactRegistration,publicKey} from './macos-owned.mjs';
import {nativeCall} from './observer.mjs';
import {requireTrue} from './relay-schema.mjs';

export async function originalExpiryCollector(path) {
  requireTrue(process.platform==='darwin'&&process.getuid()===0);
  const initial=await readPlan(path);await waitForOriginalCleanup(initial.origin);
  // Disposal only. It never signs a phase, funds an account or reboots. This
  // watcher is also launched independently on actual boot before network I/O.
  const plan=await readPlan(path);await disposeOriginalPlan(plan);
}
export async function waitForOriginalCleanup(origin,{wall=Date.now,mono=()=>process.hrtime.bigint(),sleep=()=>new Promise(resolve=>setTimeout(resolve,1000))}={}) {
  const bornMono=mono(),bornWall=wall();let last=bornWall;
  // Disposal is conservative on a bad clock: cease waiting, never extend an
  // observation/signing deadline or renew the original 15-minute cutoff.
  if(!Number.isSafeInteger(bornWall)||bornWall<origin.wall_ms)return;
  while(true){const now=wall(),elapsed=mono()-bornMono;
    if(!Number.isSafeInteger(now)||now<last||elapsed<0n||now>=origin.cleanup_until_ms||elapsed>=BigInt(origin.cleanup_until_ms-bornWall)*1000000n)return;
    last=now;await sleep();}
}
export async function disposeOriginalPlan(plan,{capture=captureOwnedFiles,native=nativeCall,removeRegistration=removeExactRegistration,removeFiles=removeExactFiles}={}) {
  const files=await capture(plan);
  const receipt=(await native(plan.helper,'read',plan.binding.session)).output;try{requireTrue(publicKey(receipt)===plan.observer_public_key);}finally{receipt.fill(0);}
  await removeRegistration(plan,plan.plist_sha256);await native(plan.helper,'delete',plan.binding.session,Buffer.from(plan.observer_public_key,'hex'));await removeFiles(files,plan.directory);
}
if(import.meta.url===`file://${process.argv[1]}`){try{await originalExpiryCollector(process.argv[2]);}catch{process.exitCode=1;}}
