import {canonical} from './protocol.mjs';
import {requireScope, requireTrue, digest, validateRequest, validateResponse} from './relay-schema.mjs';

const tokens = new WeakSet();
export class RelayUnknown extends Error { constructor() { super('Public reboot relay outcome UNKNOWN'); } }
export class RelayClient {
  #scope; #fetch; #live; #used = new Set(); #reads = 0;
  constructor(scope, {fetchImpl = fetch, assertLive}) {
    requireScope(scope); requireTrue(typeof fetchImpl === 'function' && typeof assertLive === 'function');
    this.#scope = scope; this.#fetch = fetchImpl; this.#live = assertLive;
  }
  async request(input) {
    this.#live(); requireTrue(Date.now()<this.#scope.expires_ms);
    const request = validateRequest(input);
    const body = canonical(request); requireTrue(new TextEncoder().encode(body).length <= 24576);
    const hash = await digest(body); this.#live();
    if (request.operation === 'readback') requireTrue(++this.#reads <= 180);
    else { requireTrue(!this.#used.has(hash)); this.#used.add(hash); } // consumed before network, including lost writes
    const timer = new AbortController(); const timeout = setTimeout(() => timer.abort(), 5000);
    try {
      const response = await this.#fetch(`${this.#scope.origin.replace(/\/$/,'')}/api/waitlist/ci-reboot/${request.operation}`, {
        method:'POST', body, redirect:'error', cache:'no-store', credentials:'omit',
        headers:{'content-type':'application/json'}, signal:timer.signal,
      });
      this.#live(); requireTrue(response.status === 200 && response.headers.get('content-type')?.split(';')[0] === 'application/json');
      const reader = response.body.getReader(); const chunks = []; let size = 0;
      while (true) { const part = await reader.read(); this.#live(); if(part.done) break; size += part.value.length; requireTrue(size <= 16384); chunks.push(part.value); }
      const raw = new Uint8Array(size); let position = 0; for(const part of chunks) { raw.set(part,position); position += part.length; }
      const text = new TextDecoder('utf-8',{fatal:true}).decode(raw); const parsed = JSON.parse(text);
      requireTrue(canonical(parsed) === text); const ack = validateResponse(parsed,request,hash);
      const token = Object.freeze({ack, request_sha256:hash}); tokens.add(token); return token;
    } catch { throw new RelayUnknown(); } finally { clearTimeout(timeout); }
  }
}
export function consumeAck(token) { requireTrue(tokens.has(token)); tokens.delete(token); return token.ack; }
