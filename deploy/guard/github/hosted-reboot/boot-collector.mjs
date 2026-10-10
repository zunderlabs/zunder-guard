import {readAppliedScope,requireTrue} from './relay-schema.mjs';
import {TargetClient} from './target-client.mjs';
import {collectEvent,nativeCall} from './observer.mjs';
import {readPlan,captureOwnedFiles,removeExactFiles,removeExactRegistration,signed,publicKey} from './macos-owned.mjs';

const emptyCleanup=()=>({registration_absent:false,files_absent:false,key_store_absent:false,observer_child_gone:false,carrier_exit_observed:false});
const requireActualHost=()=>requireTrue(process.platform==='darwin'&&process.arch==='arm64'&&process.getuid()===0);
export async function originalBootCollector(path,{hostCheck=requireActualHost,read=readPlan,scopeRead=readAppliedScope,native=nativeCall,collect=collectEvent,targetFactory=(scope,plan,state)=>new TargetClient(scope,plan,state)}={}) {
  hostCheck();
  const plan=await read(path);const scope=await scopeRead(plan.expected_scope);
  requireTrue(plan.sequence===2&&plan.nonce!==null&&Date.now()<plan.origin.observe_until_ms);
  const target=targetFactory(scope,plan,{version:plan.version,sequence:plan.sequence});
  const receipt=(await native(plan.helper,'read',plan.binding.session)).output;requireTrue(receipt.length===32&&publicKey(receipt)===plan.observer_public_key);
  let post;
  try {
    post=await collect({helper:plan.helper,helperSha256:plan.helper_sha256,session:plan.binding.session,binding:plan.binding,phase:'POSTBOOT',nonce:plan.nonce,markerSha256:plan.marker_sha256,cleanup:emptyCleanup()});
    requireTrue(post.event.boot_id!==plan.initial_boot_id&&post.event.boot_time_ms!==plan.initial_boot_time_ms&&post.event.uptime_ms<=120000);
    await target.sendEvent(signed(receipt,post.event));
    const challenge=await target.waitChallenge();requireTrue(challenge.sequence===3);
    // Capture the actual cleanup sender's OS facts before unlinking its exact
    // executable. The original native facts child is reaped before the flags.
    const cleanup=await collect({helper:plan.helper,helperSha256:plan.helper_sha256,session:plan.binding.session,binding:plan.binding,phase:'CLEANUP',nonce:challenge.nonce,markerSha256:plan.marker_sha256,cleanup:{registration_absent:true,files_absent:true,key_store_absent:true,observer_child_gone:true,carrier_exit_observed:false}});
    requireTrue(cleanup.original_child_exit_observed);
    const files=await captureOwnedFiles(plan);
    await removeExactRegistration(plan,plan.plist_sha256);
    await native(plan.helper,'delete',plan.binding.session,Buffer.from(plan.observer_public_key,'hex'));
    await removeExactFiles(files,plan.directory);
    await target.sendEvent(signed(receipt,cleanup.event));
  } finally {receipt.fill(0);}
}
if(import.meta.url===`file://${process.argv[1]}`){try{await originalBootCollector(process.argv[2]);}catch{process.exitCode=1;}}
