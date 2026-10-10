// Public-only protocol prototype. No network, key generation, OS process or reboot.
// Endpoint enrollment and native observer collectors are NOT implemented here.
const encoder = new TextEncoder();
const admitted = new WeakSet();
function freeze(v) { if(v && typeof v === 'object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v; }
const phases = ['PREBOOT', 'ARMED', 'POSTBOOT', 'CLEANUP'];
const bindingKeys = ['run_id','attempt','source','target_job_id','label','session','helper_sha256','inventory_sha256'];
const eventKeys = ['schema','kind','phase','sequence','nonce','binding','machine_sha256','marker_sha256','boot_id','boot_time_ms','uptime_ms','observer_pid','observer_birth','cleanup'];
const cleanupKeys = ['registration_absent','files_absent','key_store_absent','observer_child_gone','carrier_exit_observed'];
const hex = (s,n) => typeof s === 'string' && new RegExp(`^[0-9a-f]{${n}}$`).test(s);
const integer = n => Number.isSafeInteger(n) && n >= 0;
function need(ok) { if (!ok) throw new Error('Public reboot protocol refused'); }
function exact(v, keys) { need(v && Object.getPrototypeOf(v) === Object.prototype && Object.keys(v).sort().join() === [...keys].sort().join()); }
export function canonical(v) {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number') { need(integer(v)); return JSON.stringify(v); }
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  need(v && Object.getPrototypeOf(v) === Object.prototype);
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k)+':'+canonical(v[k])).join(',') + '}';
}
export function validateBinding(b) {
  exact(b,bindingKeys);
  need(integer(b.run_id) && b.run_id > 0 && integer(b.attempt) && b.attempt > 0 && b.attempt <= 100);
  need(integer(b.target_job_id) && b.target_job_id > 0 && ['macos-15','macos-15-intel','windows-2025'].includes(b.label));
  for (const k of ['session','helper_sha256','inventory_sha256']) need(hex(b[k],64));
  need(hex(b.source,40)); return JSON.parse(canonical(b));
}
export function validateEvent(e) {
  exact(e,eventKeys);validateBinding(e.binding);
  need(e.schema === 1 && e.kind === 'public-host-reboot-observation' && phases.includes(e.phase));
  need(integer(e.sequence) && e.sequence === phases.indexOf(e.phase) && hex(e.nonce,64));
  need(hex(e.machine_sha256,64) && hex(e.marker_sha256,64));
  need(typeof e.boot_id === 'string' && /^[A-Za-z0-9:._-]{1,128}$/.test(e.boot_id));
  need(integer(e.boot_time_ms) && e.boot_time_ms > 0 && integer(e.uptime_ms) && e.uptime_ms <= 86400000);
  need(integer(e.observer_pid) && e.observer_pid > 0 && typeof e.observer_birth === 'string' && /^[0-9:._-]{1,128}$/.test(e.observer_birth));
  exact(e.cleanup,cleanupKeys);need(cleanupKeys.every(k => typeof e.cleanup[k] === 'boolean'));
  if(e.phase !== 'CLEANUP') need(cleanupKeys.every(k => e.cleanup[k] === false));
  // The final sender cannot attest its own observed terminal death.
  need(e.cleanup.carrier_exit_observed === false);
  return JSON.parse(canonical(e));
}
export async function verifyEd25519(raw,signature,publicKey) {
  need(raw instanceof Uint8Array && raw.length <= 8192 && signature instanceof Uint8Array && signature.length === 64);
  need(publicKey instanceof Uint8Array && publicKey.length === 32);
  const key = await crypto.subtle.importKey('raw',publicKey,{name:'Ed25519'},false,['verify']);
  return crypto.subtle.verify({name:'Ed25519'},key,signature,raw);
}
export async function verifyEvent(raw,signature,publicKey) {
  need(raw instanceof Uint8Array && signature instanceof Uint8Array && publicKey instanceof Uint8Array);
  raw=raw.slice();signature=signature.slice();publicKey=publicKey.slice();
  need(await verifyEd25519(raw,signature,publicKey));
  const text = new TextDecoder('utf-8',{fatal:true}).decode(raw);
  const e = validateEvent(JSON.parse(text));need(canonical(e) === text);
  const token = freeze({event:e,observer_public_key:Array.from(publicKey,b=>b.toString(16).padStart(2,'0')).join('')});admitted.add(token);return token;
}
function transition(prior,event,binding,nonce) {
  const e=validateEvent(event);need(canonical(e.binding) === canonical(binding) && e.nonce === nonce);
  need(e.sequence === prior.length && e.phase === phases[prior.length]);
  if(prior.length){
    const first=prior[0];need(e.machine_sha256 === first.machine_sha256 && e.marker_sha256 === first.marker_sha256);
    if(e.phase === 'ARMED') need(e.boot_id === first.boot_id && e.boot_time_ms === first.boot_time_ms);
    if(e.phase === 'POSTBOOT') {
      need(e.boot_id !== first.boot_id && e.boot_time_ms !== first.boot_time_ms && e.uptime_ms <= 120000);
      need(e.observer_birth !== first.observer_birth);
    }
    if(e.phase === 'CLEANUP') {
      const post=prior[2];need(e.boot_id === post.boot_id && e.boot_time_ms === post.boot_time_ms);
      need(['registration_absent','files_absent','key_store_absent','observer_child_gone'].every(k => e.cleanup[k]));
    }
  }
  return [...prior,e];
}
export class OriginalControllerProtocol {
  #binding;#events=[];#nonce;#origin;#mono;#wall;#usedNonces=new Set();#observerKey;#lastWall;#lastMono;
  constructor(binding,origin,clocks,observerPublicKey) {
    need(hex(observerPublicKey,64));this.#observerKey=observerPublicKey;
    this.#binding=validateBinding(binding);exact(origin,['wall_ms','mono_ns','observe_until_ms','cleanup_until_ms']);
    need(integer(origin.wall_ms) && integer(origin.observe_until_ms) && integer(origin.cleanup_until_ms));
    need(origin.wall_ms < origin.observe_until_ms && origin.observe_until_ms <= origin.wall_ms+720000);
    need(origin.observe_until_ms < origin.cleanup_until_ms && origin.cleanup_until_ms <= origin.wall_ms+900000);
    need(typeof origin.mono_ns === 'bigint' && origin.mono_ns > 0n);
    need(typeof clocks.wall_ms === 'function' && typeof clocks.mono_ns === 'function');
    this.#origin=Object.freeze({...origin});this.#wall=clocks.wall_ms;this.#mono=clocks.mono_ns;
    this.#lastWall=origin.wall_ms;this.#lastMono=origin.mono_ns;
  }
  #live() {
    const end=this.#events.length < 3 ? this.#origin.observe_until_ms : this.#origin.cleanup_until_ms;
    const wall=this.#wall(), mono=this.#mono();
    need(integer(wall) && wall >= this.#lastWall && wall < end && typeof mono === 'bigint');
    need(mono >= this.#lastMono && mono < this.#origin.mono_ns+BigInt(end-this.#origin.wall_ms)*1000000n);
    // Update both only after the entire independent clock predicate passed.
    this.#lastWall=wall;this.#lastMono=mono;
  }
  assertLive() { this.#live(); } // read-only deadline check; never mints an event
  armChallenge(nonce) { this.#live();need(this.#nonce === undefined && hex(nonce,64) && !this.#usedNonces.has(nonce) && this.#events.length < 4);this.#usedNonces.add(nonce);this.#nonce=nonce; }
  acceptVerified(token) {
    need(admitted.has(token));admitted.delete(token); // consume before validation
    need(token.observer_public_key === this.#observerKey);
    this.#live();need(this.#nonce !== undefined);
    this.#events=transition(this.#events,token.event,this.#binding,this.#nonce);this.#nonce=undefined;
  }
  report() {
    return {kind:'public-reboot-protocol-state',observed_phases:this.#events.map(e=>e.phase),
      cryptographic_event_verification:this.#events.length>0,github_enrollment_implemented:false,
      target_OS_collectors_implemented:false,provider_atomic_CAS_implemented:false,
      release_ready:false,native_credential_retention_proven:false,
      reboot_protocol_sequence_complete:this.#events.length===4,all_owned_processes_gone:false};
  }
}
// Clearly modeled fixture path: never produces the sealed crypto token above.
export function evaluateModeledSequence(events,binding,nonces) {
  need(Array.isArray(events) && events.length <= 4 && Array.isArray(nonces) && nonces.length === events.length);
  let prior=[];events.forEach((e,i)=>{prior=transition(prior,e,validateBinding(binding),nonces[i]);});
  return {kind:'INERT-MODELED-ONLY',sequence_complete:prior.length===4,authenticated:false,actual_reboot:false,release_ready:false};
}
