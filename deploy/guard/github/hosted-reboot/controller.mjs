import {randomBytes, generateKeyPairSync, sign} from 'node:crypto';
import {OriginalControllerProtocol, canonical, verifyEvent, validateBinding} from './protocol.mjs';
import {RelayClient, consumeAck} from './relay-client.mjs';
import {requireScope, requireTrue, validateOrigin, bytes, controllerSigningBytes} from './relay-schema.mjs';

const origins=new WeakSet();
export function sampleOriginalOrigin() {const value=Object.freeze({wall:Date.now(),mono:process.hrtime.bigint()});origins.add(value);return value;}

export class OriginalPublicController {
  #binding; #origin; #mono; #wall; #lastWall; #lastMono; #relay; #journal; #version = 0; #sequence = 0; #protocol; #observerKey; #originMono; #controllerKey; #controllerPublicKey; #held = false;
  constructor({scope,binding,journal,fetchImpl,firstOrigin=sampleOriginalOrigin(),clocks={wall:()=>Date.now(),mono:()=>process.hrtime.bigint()}}) {
    // The sole actual origin is sampled before any enrollment or network call.
    requireScope(scope); this.#wall = clocks.wall; this.#mono = clocks.mono;
    requireTrue(origins.has(firstOrigin));origins.delete(firstOrigin);
    const wall = firstOrigin.wall, mono = firstOrigin.mono; requireTrue(Number.isSafeInteger(wall) && wall > 0 && typeof mono === 'bigint' && mono > 0n);
    this.#origin = validateOrigin({wall_ms:wall,observe_until_ms:wall+720000,cleanup_until_ms:wall+900000});
    requireTrue(scope.expires_ms>=this.#origin.cleanup_until_ms);
    this.#lastWall = wall; this.#lastMono = mono; this.#originMono = mono;
    this.#binding = validateBinding(binding); requireTrue(binding.source === scope.source);
    const keys = generateKeyPairSync('ed25519'); this.#controllerKey = keys.privateKey; this.#controllerPublicKey = keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
    this.#journal = journal; this.#relay = new RelayClient(scope,{fetchImpl,assertLive:()=>this.assertLive()});
  }
  assertLive() {
    requireTrue(!this.#held); const wall = this.#wall(), mono = this.#mono();
    const end = this.#sequence >= 3 ? this.#origin.cleanup_until_ms : this.#origin.observe_until_ms;
    try {requireTrue(Number.isSafeInteger(wall) && wall >= this.#lastWall && wall < end && typeof mono === 'bigint' && mono >= this.#lastMono && mono < this.#originMono + BigInt(end-this.#origin.wall_ms)*1000000n);}catch{this.#held=true;throw new Error('Original controller clock HOLD');}
    this.#lastWall = wall; this.#lastMono = mono;
  }
  publicPlan() { return Object.freeze({binding:JSON.parse(canonical(this.#binding)),origin:{...this.#origin}}); }
  async #send(operation,extra={}) {
    try {
      this.assertLive(); const request = {schema:1,kind:'public-reboot-relay-request',operation,binding:this.#binding,origin:this.#origin,expected_version:this.#version,expected_sequence:this.#sequence,nonce:null,observer_public_key:null,event:null,signature:null,jwt:null,controller_public_key:this.#controllerPublicKey,controller_signature:null,...extra};
      request.controller_signature = sign(null,controllerSigningBytes(request),this.#controllerKey).toString('hex');
      await this.#journal.append({kind:'INTENT',operation,version:this.#version,sequence:this.#sequence});
      const ack = consumeAck(await this.#relay.request(request));
      await this.#journal.append({kind:'ACK',ack}); this.#version = ack.version; return ack;
    } catch { this.#held = true; await this.#journal.hold('original-controller-action-unknown'); throw new Error('Original controller HOLD'); }
  }
  async enrollController(jwt) { requireTrue(this.#version === 0); return this.#send('enroll-controller',{jwt}); }
  async observeEnrollment() {
    requireTrue(this.#version === 1 && this.#protocol === undefined);
    const ack = await this.#send('readback'); if(ack.observer_public_key === null) return ack;
    this.#observerKey = ack.observer_public_key;
    this.#protocol = new OriginalControllerProtocol(this.#binding,{...this.#origin,mono_ns:this.#originMono},{wall_ms:this.#wall,mono_ns:this.#mono},this.#observerKey);
    return ack;
  }
  async challenge() {
    requireTrue(this.#protocol !== undefined && this.#sequence < 4);
    const nonce = randomBytes(32).toString('hex'); this.#protocol.armChallenge(nonce);
    return this.#send('challenge',{nonce});
  }
  async #acceptObserved(ack) {
    // Call only with an ACK consumed inside #send. This method is intentionally
    // private at the relay boundary: callers cannot supply a saved event.
    requireTrue(ack.observer_public_key === this.#observerKey && ack.event !== null);
    const raw = new TextEncoder().encode(canonical(ack.event));
    this.#protocol.acceptVerified(await verifyEvent(raw,bytes(ack.signature,64),bytes(this.#observerKey,32)));
    this.#sequence++; this.#version = ack.version;
    await this.#journal.append({kind:'PHASE',report:this.#protocol.report()});
  }
  async poll() {
    const ack = await this.#send('readback');
    if(ack.sequence === this.#sequence+1) await this.#acceptObserved(ack);
    else requireTrue(ack.sequence === this.#sequence);
    return this.report();
  }
  report() { return {kind:'original-public-reboot-controller',held:this.#held,observed_sequence:this.#sequence,original_origin:this.#origin,protocol:this.#protocol?.report()??null,release_ready:false,native_credential_retention_proven:false,all_owned_processes_gone:false}; }
}
