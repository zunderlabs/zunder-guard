import {spawn} from 'node:child_process';
import {lstat,readFile,unlink,rmdir,open} from 'node:fs/promises';
import {createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {canonical,validateEvent,validateBinding} from './protocol.mjs';
import {requireTrue,digest,hex,exact,validateOrigin} from './relay-schema.mjs';
import {verifyOwnedFile,nativeCall} from './observer.mjs';

export async function fixedCommand(path,args) {
  const child=spawn(path,args,{env:{PATH:'/usr/bin:/bin:/usr/sbin:/sbin',LANG:'C'},cwd:'/',stdio:['ignore','pipe','pipe'],timeout:10000,killSignal:'SIGKILL'});
  let length=0;const parts=[];const errors=[];child.stdout.on('data',data=>{length+=data.length;if(length>65536)child.kill('SIGKILL');else parts.push(data);});child.stderr.on('data',data=>{length+=data.length;if(length>65536)child.kill('SIGKILL');else errors.push(data);});
  const code=await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',(code,signal)=>signal===null?resolve(code):reject(new Error('Owned command UNKNOWN')));});
  return {code,output:Buffer.concat(parts).toString('utf8'),stderr:Buffer.concat(errors).toString('utf8')};
}
export function signingKey(seed) {requireTrue(Buffer.isBuffer(seed)&&seed.length===32);return createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),type:'pkcs8',format:'der'});}
export function publicKey(seed){return createPublicKey(signingKey(seed)).export({type:'spki',format:'der'}).subarray(-32).toString('hex');}
export function signed(seed,event){return {event:validateEvent(event),signature:sign(null,Buffer.from(canonical(event)),signingKey(seed)).toString('hex'),observer_public_key:publicKey(seed)};}
export async function readPlan(path) {
  const stat=await lstat(path);requireTrue(stat.uid===0&&stat.isFile()&&!stat.isSymbolicLink()&&(stat.mode&0o077)===0);
  const value=JSON.parse(await readFile(path,'utf8'));
  exact(value,['schema','kind','binding','origin','expected_scope','directory','label','plist','helper','helper_sha256','runtime','runtime_sha256','source_files','marker_sha256','initial_boot_id','initial_boot_time_ms','observer_public_key','version','sequence','nonce','plist_sha256']);
  validateBinding(value.binding);validateOrigin(value.origin);
  requireTrue(hex(value.observer_public_key)&&value.binding.helper_sha256===value.helper_sha256&&value.binding.source===value.expected_scope.source);
  requireTrue(value.schema===1&&value.kind==='original-public-macos-reboot-plan'&&hex(value.binding.session));
  requireTrue(value.directory===`/Library/ZunderPublicReboot/${value.binding.session}`&&value.label===`com.zunder.public-reboot.${value.binding.session}`&&value.plist===`/Library/LaunchDaemons/${value.label}.plist`);
  requireTrue(value.runtime===value.directory+'/node'&&value.helper===value.directory+'/native-helper'&&path===value.directory+'/plan.json');
  await verifyOwnedFile(value.directory+'/marker',value.marker_sha256);
  await verifyOwnedFile(value.runtime,value.runtime_sha256,true);await verifyOwnedFile(value.helper,value.helper_sha256,true);
  requireTrue(await digest(canonical(value.source_files))===value.binding.inventory_sha256);
  for(const entry of value.source_files){exact(entry,['name','sha256']);requireTrue(/^[a-z][a-z0-9-]*\.mjs$/.test(entry.name));await verifyOwnedFile(value.directory+'/'+entry.name,entry.sha256);}
  return value;
}
export async function replacePublicPlan(path,plan) {
  // Only the original bootstrap writes the post-challenge public checkpoint.
  const stat=await lstat(path);requireTrue(stat.uid===0&&stat.isFile()&&(stat.mode&0o077)===0);
  const fd=await open(path,'r+');try{const current=await fd.stat();requireTrue(current.ino===stat.ino&&current.dev===stat.dev);await fd.truncate(0);await fd.writeFile(canonical(plan));await fd.sync();}finally{await fd.close();}
}
export async function captureOwnedFiles(plan) {
  const names=[...plan.source_files.map(entry=>entry.name),'node','native-helper','marker','plan.json','reboot-dispatched'];
  const files=[];for(const name of names){const path=plan.directory+'/'+name;try{const stat=await lstat(path);requireTrue(stat.uid===0&&stat.isFile()&&!stat.isSymbolicLink()&&(stat.mode&0o022)===0);files.push({path,dev:stat.dev,ino:stat.ino,sha256:await digest(await readFile(path))});}catch(error){if(error.code==='ENOENT'&&name==='reboot-dispatched')continue;throw error;}}
  return files;
}
export async function removeExactFiles(files,directory) {
  for(const file of files){const stat=await lstat(file.path);requireTrue(stat.dev===file.dev&&stat.ino===file.ino&&stat.uid===0&&!stat.isSymbolicLink()&&await digest(await readFile(file.path))===file.sha256);}
  for(const file of files)await unlink(file.path);
  await rmdir(directory);for(const file of files){try{await lstat(file.path);throw new Error('Owned file remains');}catch(error){requireTrue(error.code==='ENOENT');}}
}
export async function removeExactRegistration(plan,expectedPlistSha256) {
  await verifyOwnedFile(plan.plist,expectedPlistSha256);
  const before=await fixedCommand('/bin/launchctl',['print','system/'+plan.label]);requireTrue(before.code===0);
  // Only a now-inactive boot wrapper is removable. Never stop a foreign/live job.
  requireTrue(!/^\s*pid\s*=\s*\d+/m.test(before.output)&&registrationMatches(before.output,plan));
  const removed=await fixedCommand('/bin/launchctl',['bootout','system',plan.plist]);requireTrue(removed.code===0);
  const control=await fixedCommand('/bin/launchctl',['print','system/com.apple.logd']);requireTrue(control.code===0);
  const after=await fixedCommand('/bin/launchctl',['print','system/'+plan.label]);requireTrue(registrationAbsent(after,plan.label));
  await verifyOwnedFile(plan.plist,expectedPlistSha256);await unlink(plan.plist);
  try{await lstat(plan.plist);throw new Error('Owned registration remains');}catch(error){requireTrue(error.code==='ENOENT');}
}

export function registrationAbsent(result,label) { return result.code===113 && result.stderr.includes('Could not find service "'+label+'"') && result.stderr.includes('in domain for system'); }
export function registrationMatches(output,plan) {
  const program=output.match(/^\s*program = (.+)$/m), argumentsBlock=output.match(/^\s*arguments = \{\n([\s\S]*?)^\s*\}/m), path=output.match(/^\s*path = (.+)$/m);
  if(!program||!argumentsBlock||!path)return false;
  const argumentsList=argumentsBlock[1].split('\n').map(v=>v.trim()).filter(Boolean);
  return program[1].trim()===plan.runtime && path[1].trim()===plan.plist && canonical(argumentsList)===canonical([plan.runtime,plan.directory+'/boot-wrapper.mjs',plan.directory+'/plan.json']);
}
