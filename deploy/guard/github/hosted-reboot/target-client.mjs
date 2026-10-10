import {RelayClient,consumeAck} from './relay-client.mjs';
import {requireTrue} from './relay-schema.mjs';

export class TargetClient {
  #relay; #binding; #origin; #version; #sequence; #lastWall; #held=false; #monoOrigin; #wallOrigin;
  constructor(scope,plan,{version,sequence,fetchImpl,clocks={wall:()=>Date.now(),mono:()=>process.hrtime.bigint()}}) {
    this.#binding=plan.binding;this.#origin=plan.origin;this.#version=version;this.#sequence=sequence;
    this.#wallOrigin=clocks.wall();this.#monoOrigin=clocks.mono();this.#lastWall=this.#wallOrigin;
    const live=()=>{requireTrue(!this.#held);const now=clocks.wall(),mono=clocks.mono(); const end=this.#sequence>=3?this.#origin.cleanup_until_ms:this.#origin.observe_until_ms;
      requireTrue(Number.isSafeInteger(now)&&now>=this.#lastWall&&now<end&&mono>=this.#monoOrigin&&mono<this.#monoOrigin+BigInt(end-this.#wallOrigin)*1000000n);this.#lastWall=now;};
    this.#relay=new RelayClient(scope,{fetchImpl,assertLive:live});
  }
  get state(){return {version:this.#version,sequence:this.#sequence};}
  async #request(operation,extra={}) {
    requireTrue(!this.#held);
    try {const ack=consumeAck(await this.#relay.request({schema:1,kind:'public-reboot-relay-request',operation,binding:this.#binding,origin:this.#origin,expected_version:this.#version,expected_sequence:this.#sequence,nonce:null,observer_public_key:null,event:null,signature:null,jwt:null,controller_public_key:null,controller_signature:null,...extra}));this.#version=ack.version;this.#sequence=ack.sequence;return ack;}
    catch {this.#held=true;throw new Error('Original target HOLD');}
  }
  async enroll(jwt,publicKey){requireTrue(this.#version===1&&this.#sequence===0);return this.#request('enroll-target',{jwt,observer_public_key:publicKey});}
  async waitChallenge() {for(let count=0;count<180;count++){const ack=await this.#request('readback');if(ack.nonce!==null)return ack;await new Promise(resolve=>setTimeout(resolve,3000));}this.#held=true;throw new Error('Original target challenge UNKNOWN');}
  async sendEvent(value){return this.#request('event',{nonce:value.event.nonce,event:value.event,signature:value.signature});}
}
