import {spawn} from 'node:child_process';
import {createPrivateKey, createPublicKey, sign} from 'node:crypto';
import {lstat, readFile} from 'node:fs/promises';
import {canonical, validateEvent} from './protocol.mjs';
import {exact, requireTrue, hex, digest} from './relay-schema.mjs';

export async function verifyOwnedFile(path, hash, executable=false) {
  requireTrue(path.startsWith('/') && hex(hash)); const before = await lstat(path);
  requireTrue(before.isFile() && !before.isSymbolicLink() && before.uid === 0 && (before.mode & 0o022) === 0 && (!executable || (before.mode & 0o111) !== 0));
  const data = await readFile(path); const after = await lstat(path);
  requireTrue(before.dev === after.dev && before.ino === after.ino && before.size === after.size && before.mtimeMs === after.mtimeMs && await digest(data) === hash);
  return data;
}
export async function nativeCall(path, mode, session, input=null) {
  requireTrue(['facts','store','read','delete','absent'].includes(mode) && hex(session));
  const child = spawn(path,[mode,session],{stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/bin:/bin',LANG:'C'},cwd:'/',timeout:5000,killSignal:'SIGKILL'});
  const result = []; let length = 0; let failed = false;
  child.stdout.on('data',part=>{ length += part.length; if(length > 4096) { failed=true; child.kill('SIGKILL'); } else result.push(part); });
  child.stderr.on('data',()=>{}); child.stdin.end(input??undefined);
  await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',(code,signal)=> code === 0 && signal === null && !failed ? resolve() : reject(new Error('Native receipt helper refused')));});
  return {output:Buffer.concat(result),original_pid:child.pid,original_exit_observed:true};
}
export async function collectEvent({helper,helperSha256,session,binding,phase,nonce,markerSha256,cleanup}) {
  await verifyOwnedFile(helper,helperSha256,true);
  const result = await nativeCall(helper,'facts',session);
  const actual = JSON.parse(result.output.toString('utf8'));
  exact(actual,['schema','kind','machine_sha256','boot_id','boot_time_ms','uptime_ms','observer_pid','observer_birth']);
  requireTrue(actual.schema === 1 && actual.kind === 'actual-macos-kernel-facts' && actual.observer_pid === process.pid);
  const event = validateEvent({schema:1,kind:'public-host-reboot-observation',phase,sequence:['PREBOOT','ARMED','POSTBOOT','CLEANUP'].indexOf(phase),nonce,binding,marker_sha256:markerSha256,
    machine_sha256:actual.machine_sha256,boot_id:actual.boot_id,boot_time_ms:actual.boot_time_ms,uptime_ms:actual.uptime_ms,observer_pid:actual.observer_pid,observer_birth:actual.observer_birth,cleanup});
  return {event,original_child_exit_observed:result.original_exit_observed};
}
export async function signCollectedEvent(helper,helperSha256,session,event) {
  await verifyOwnedFile(helper,helperSha256,true);
  const result = await nativeCall(helper,'read',session); requireTrue(result.output.length === 32);
  const seed = result.output;
  try {
    const privateKey = createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
    const publicKey = createPublicKey(privateKey).export({type:'spki',format:'der'}).subarray(-32).toString('hex');
    return {event:validateEvent(event),signature:sign(null,Buffer.from(canonical(event)),privateKey).toString('hex'),observer_public_key:publicKey};
  } finally { seed.fill(0); } // JS/runtime object copies are not claimed zeroized.
}
