import {mkdir,lstat,writeFile,readFile,chmod,open} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {canonical} from './protocol.mjs';
import {readAppliedScope,requireTrue,digest,exact} from './relay-schema.mjs';
import {nativeCall,collectEvent,verifyOwnedFile} from './observer.mjs';
import {TargetClient} from './target-client.mjs';
import {fixedCommand,publicKey,signed,replacePublicPlan,registrationAbsent,registrationMatches,removeExactFiles,removeExactRegistration} from './macos-owned.mjs';

export const ownedModules=['protocol.mjs','relay-schema.mjs','relay-client.mjs','target-client.mjs','observer.mjs','macos-owned.mjs','boot-wrapper.mjs','boot-collector.mjs','expiry-collector.mjs'];
export function plistText(plan) {
  return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>${plan.label}</string><key>ProgramArguments</key><array><string>${plan.runtime}</string><string>${plan.directory}/boot-wrapper.mjs</string><string>${plan.directory}/plan.json</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><false/><key>AbandonProcessGroup</key><true/><key>WorkingDirectory</key><string>/</string><key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/bin:/bin</string><key>LANG</key><string>C</string></dict></dict></plist>`;
}
async function absent(path){try{await lstat(path);throw new Error('Preexisting resource refused');}catch(error){requireTrue(error.code==='ENOENT');}}
async function create(path,data,mode,owned){const fd=await open(path,'wx',mode);try{await fd.writeFile(data);await fd.sync();}finally{await fd.close();}await chmod(path,mode);if(owned){const stat=await lstat(path);owned.push({path,dev:stat.dev,ino:stat.ino,sha256:await digest(data)});}}
export async function originalMacBootstrap(input) {
  requireTrue(process.platform==='darwin'&&process.arch==='arm64'&&process.getuid()===0&&process.geteuid()===0);
  exact(input,['plan','expected_scope','source_directory','source_files','helper_path','helper_sha256','runtime_path','runtime_sha256','target_jwt']);
  const scope=await readAppliedScope(input.expected_scope);const {binding,origin}=input.plan;requireTrue(scope.expires_ms>=origin.cleanup_until_ms);
  requireTrue(binding.label==='macos-15'&&binding.source===scope.source&&binding.helper_sha256===input.helper_sha256&&Date.now()<origin.observe_until_ms);
  requireTrue(input.source_files.map(f=>f.name).sort().join('\0')===[...ownedModules].sort().join('\0')&&await digest(canonical(input.source_files))===binding.inventory_sha256);
  // The reviewed runtime inventory supplies an exact binary digest. An empty
  // variable, different toolcache binary or source substitute refuses bootstrap.
  requireTrue(await digest(await readFile(input.runtime_path))===input.runtime_sha256&&await digest(await readFile(input.helper_path))===input.helper_sha256);
  const base='/Library/ZunderPublicReboot';try{await mkdir(base,{mode:0o700});}catch(error){requireTrue(error.code==='EEXIST');}
  const baseStat=await lstat(base);requireTrue(baseStat.uid===0&&baseStat.isDirectory()&&!baseStat.isSymbolicLink()&&(baseStat.mode&0o077)===0);
  const directory=base+'/'+binding.session,label='com.zunder.public-reboot.'+binding.session,plist='/Library/LaunchDaemons/'+label+'.plist';
  await absent(directory);await absent(plist);const control=await fixedCommand('/bin/launchctl',['print','system/com.apple.logd']);requireTrue(control.code===0);const registration=await fixedCommand('/bin/launchctl',['print','system/'+label]);requireTrue(registrationAbsent(registration,label));
  const seed=randomBytes(32);let publicReceipt=publicKey(seed);
  const target=new TargetClient(scope,input.plan,{version:1,sequence:0});
  try{await target.enroll(input.target_jwt,publicReceipt);input.target_jwt='';}catch(error){seed.fill(0);throw error;}
  const owned=[];let keyAttempted=false,installedPlan=null;
  try {
  await mkdir(directory,{mode:0o700});
  for(const entry of input.source_files){exact(entry,['name','sha256']);const content=await readFile(input.source_directory+'/'+entry.name);requireTrue(await digest(content)===entry.sha256);await create(directory+'/'+entry.name,content,0o600,owned);}
  const runtime=directory+'/node',helper=directory+'/native-helper';await create(runtime,await readFile(input.runtime_path),0o500,owned);await create(helper,await readFile(input.helper_path),0o500,owned);
  await verifyOwnedFile(runtime,input.runtime_sha256,true);await verifyOwnedFile(helper,input.helper_sha256,true);
  const marker=Buffer.from(canonical({binding,origin}));await create(directory+'/marker',marker,0o600,owned);
  try{await nativeCall(helper,'absent',binding.session);keyAttempted=true;await nativeCall(helper,'store',binding.session,seed);const actual=(await nativeCall(helper,'read',binding.session)).output;try{requireTrue(actual.equals(seed));}finally{actual.fill(0);}}finally{seed.fill(0);}
  const facts=JSON.parse((await nativeCall(helper,'facts',binding.session)).output.toString('utf8'));
  const plan={schema:1,kind:'original-public-macos-reboot-plan',binding,origin,expected_scope:input.expected_scope,directory,label,plist,helper,helper_sha256:input.helper_sha256,runtime,runtime_sha256:input.runtime_sha256,source_files:input.source_files,marker_sha256:await digest(marker),initial_boot_id:facts.boot_id,initial_boot_time_ms:facts.boot_time_ms,observer_public_key:publicReceipt,version:1,sequence:0,nonce:null,plist_sha256:''};
  const plistBytes=plistText(plan);plan.plist_sha256=await digest(plistBytes);await create(directory+'/plan.json',canonical(plan),0o600,owned);await create(plist,plistBytes,0o600);installedPlan=plan;
  const loaded=await fixedCommand('/bin/launchctl',['bootstrap','system',plist]);requireTrue(loaded.code===0);
  const watcher=spawn(runtime,[directory+'/expiry-collector.mjs',directory+'/plan.json'],{detached:true,env:{PATH:'/usr/bin:/bin',LANG:'C'},cwd:'/',stdio:'ignore'});await new Promise((resolve,reject)=>{watcher.once('spawn',resolve);watcher.once('error',reject);});watcher.unref();
  for(const phase of ['PREBOOT','ARMED']){
    const challenge=await target.waitChallenge();const observed=await collectEvent({helper,helperSha256:input.helper_sha256,session:binding.session,binding,phase,nonce:challenge.nonce,markerSha256:plan.marker_sha256,cleanup:{registration_absent:false,files_absent:false,key_store_absent:false,observer_child_gone:false,carrier_exit_observed:false}});
    const receipt=(await nativeCall(helper,'read',binding.session)).output;try{requireTrue(publicKey(receipt)===publicReceipt);await target.sendEvent(signed(receipt,observed.event));}finally{receipt.fill(0);}
  }
  const postChallenge=await target.waitChallenge();requireTrue(postChallenge.sequence===2);Object.assign(plan,{version:postChallenge.version,sequence:2,nonce:postChallenge.nonce});await replacePublicPlan(directory+'/plan.json',plan);const checkpoint=owned.find(file=>file.path===directory+'/plan.json');checkpoint.sha256=await digest(canonical(plan));
  await verifyOwnedFile(plist,plan.plist_sha256);const registered=await fixedCommand('/bin/launchctl',['print','system/'+label]);requireTrue(registered.code===0&&registrationMatches(registered.output,plan));
  requireTrue(Date.now()<origin.observe_until_ms);await create(directory+'/reboot-dispatched',canonical({kind:'ONE-ORIGINAL-REBOOT',binding}),0o600,owned);
  // The create-only marker is durable BEFORE the one command. Never retry after
  // command error, lost process or an unknown response.
  const reboot=await fixedCommand('/sbin/shutdown',['-r','now']);requireTrue(reboot.code===0);
  return {kind:'public-original-reboot-dispatched',release_ready:false};
  } catch(error) {
    // Bounded disposal on partial setup failure. This never retries reboot,
    // enrollment or a lost relay mutation and never adopts foreign resources.
    try {
      if(installedPlan) {
        const registration=await fixedCommand('/bin/launchctl',['print','system/'+label]);
        if(registration.code===0)await removeExactRegistration(installedPlan,installedPlan.plist_sha256);
        else {requireTrue(registrationAbsent(registration,label));await verifyOwnedFile(plist,installedPlan.plist_sha256);await (await import('node:fs/promises')).unlink(plist);}
      }
      if(keyAttempted){
        const helperPath=directory+'/native-helper';await verifyOwnedFile(helperPath,input.helper_sha256,true);
        try{await nativeCall(helperPath,'absent',binding.session);}catch{await nativeCall(helperPath,'delete',binding.session,Buffer.from(publicReceipt,'hex'));}
      }
      if(owned.length)await removeExactFiles(owned,directory);
    } catch { /* unresolved ownership remains UNKNOWN; no broad deletion */ }
    throw error;
  } finally {seed.fill(0);}
}

