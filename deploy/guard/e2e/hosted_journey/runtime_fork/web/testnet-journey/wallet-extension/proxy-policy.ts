import { createHash } from 'node:crypto';
import { verifyTypedData } from '../../site/node_modules/ethers/lib.esm/index.js';

export const STAGING_HOST = 'staging.zunderlabs.com';
export const STAGING_ORIGIN = `https://${STAGING_HOST}`;
export const TESTNET_HOST = 'api.hyperliquid-testnet.xyz';
export const RPC_HOST = 'sepolia-rollup.arbitrum.io';
export const RPC_PATH = '/rpc';
export const OWNER = '0x0d708cfc4316b58f4ab00ee641a54baacc89cb14';
export const MAX_LEASE_MS = 20 * 60_000;
export const MAX_NONCE_AGE_MS = 120_000;
export const MAX_BODY = 8192;
export const MAX_ASSET = 8 * 1024 * 1024;
export type Action = 'approve' | 'restore';
export type Phase = 'PREFLIGHT' | 'PREFLIGHT_PENDING' | 'REJECTION' | 'REJECTED' | 'APPROVE_READY' | 'APPROVE_HELD' | 'APPROVE_SENT' | 'APPROVED_20' | 'RESTORE_READY' | 'RESTORE_HELD' | 'RESTORE_SENT' | 'RESTORED_0' | 'HOLD' | 'CLOSED';
export type Reason = 'config' | 'deadline' | 'request' | 'phase' | 'signature' | 'arm' | 'upstream' | 'readback' | 'transport' | 'closed';
export class PolicyError extends Error {
  readonly reason: Reason;
  constructor(reason: Reason) { super(`proxy_${reason}`); this.reason = reason; }
}
export const digest = (value: string | Uint8Array) => createHash('sha256').update(value).digest('hex');
const hashRE = /^[a-f0-9]{64}$/;
const addressRE = /^0x[a-f0-9]{40}$/;
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
export function canonicalJson(raw: Buffer, max = MAX_BODY): unknown {
  if (!raw.length || raw.length > max) throw new PolicyError('request');
  const text = raw.toString('utf8');
  if (!Buffer.from(text).equals(raw)) throw new PolicyError('request');
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { throw new PolicyError('request'); }
  if (JSON.stringify(parsed) !== text) throw new PolicyError('request');
  return parsed;
}
export interface AssetPin { sha256: string; contentType: string; csp: string }
export interface ProxyConfig {
  runId: string;
  extensionId: string;
  owner: typeof OWNER;
  builder: string;
  startedAt: number;
  deadline: number;
  assets: Readonly<Record<string, AssetPin>>;
}
export function validateConfig(c: ProxyConfig, now: number): void {
  if (!exact(c, ['runId', 'extensionId', 'owner', 'builder', 'startedAt', 'deadline', 'assets'])
    || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(c.runId)
    || !/^[a-p]{32}$/.test(c.extensionId) || c.owner !== OWNER || !addressRE.test(c.builder) || /^0x0{40}$/.test(c.builder)
    || !Number.isSafeInteger(c.startedAt) || !Number.isSafeInteger(c.deadline)
    || c.startedAt > now || c.deadline <= now || c.deadline - c.startedAt > MAX_LEASE_MS
    || c.deadline <= c.startedAt || !c.assets || typeof c.assets !== 'object' || Array.isArray(c.assets)
    || !Object.hasOwn(c.assets, '/approve') || Object.keys(c.assets).length > 128) throw new PolicyError('config');
  for (const [path, pin] of Object.entries(c.assets)) {
    if (!/^\/[a-zA-Z0-9_./-]+$/.test(path) || path.includes('..') || path.includes('//')
      || !exact(pin, ['sha256', 'contentType', 'csp']) || !hashRE.test(pin.sha256)
      || !/^[\x20-\x7e]{1,160}$/.test(pin.contentType) || !/^[\x20-\x7e]{1,4096}$/.test(pin.csp)) throw new PolicyError('config');
  }
  if (c.assets['/approve']?.contentType !== 'text/html; charset=utf-8') throw new PolicyError('config');
}
export interface PublicHeld {
  action: Action; owner: typeof OWNER; builder: string; rate: '0.02%' | '0%'; nonce: number;
  bodySha256: string; typedDataSha256: string; signatureSha256: string; expires: number;
}
export interface Arm { bodySha256: string; expires: number }
export interface Counters { exchangeAttempts: number; heldBodies: number; upstreamDispatches: number; accepted: number; denials: number }
/** State-only transitions. This cannot dispatch. Production admission always verifies signatures first. */
export class ExchangeGate {
  phase: Phase = 'PREFLIGHT';
  readonly counters: Counters = { exchangeAttempts: 0, heldBodies: 0, upstreamDispatches: 0, accepted: 0, denials: 0 };
  private usedNonces = new Set<number>();
  hold(): void { if (this.phase !== 'CLOSED') this.phase = 'HOLD'; }
  preflight(role: unknown, cap: unknown): void {
    if (this.phase !== 'PREFLIGHT' || role !== 'user' || cap !== 0) return this.fail();
    this.phase = 'REJECTION';
  }
  verifyRejection(): void {
    if (this.phase !== 'REJECTION' || this.counters.exchangeAttempts || this.counters.heldBodies || this.counters.upstreamDispatches) return this.fail();
    this.phase = 'REJECTED';
  }
  start(action: Action): void {
    if (action === 'approve' && this.phase === 'REJECTED') this.phase = 'APPROVE_READY';
    else if (action === 'restore' && this.phase === 'APPROVED_20') this.phase = 'RESTORE_READY';
    else this.fail();
  }
  attempt(): Action {
    this.counters.exchangeAttempts++;
    if (this.phase === 'APPROVE_READY') { this.phase = 'APPROVE_HELD'; return 'approve'; }
    if (this.phase === 'RESTORE_READY') { this.phase = 'RESTORE_HELD'; return 'restore'; }
    return this.fail();
  }
  verified(nonce: number): void {
    if (!['APPROVE_HELD', 'RESTORE_HELD'].includes(this.phase) || this.usedNonces.has(nonce)) return this.fail();
    this.usedNonces.add(nonce); this.counters.heldBodies++;
  }
  consume(action: Action): void {
    if (this.phase !== (action === 'approve' ? 'APPROVE_HELD' : 'RESTORE_HELD') || this.counters.upstreamDispatches >= 2) return this.fail();
    this.phase = action === 'approve' ? 'APPROVE_SENT' : 'RESTORE_SENT';
    this.counters.upstreamDispatches++;
  }
  accepted(action: Action, cap: unknown): void {
    if (this.phase !== (action === 'approve' ? 'APPROVE_SENT' : 'RESTORE_SENT') || cap !== (action === 'approve' ? 20 : 0)) return this.fail();
    this.counters.accepted++;
    this.phase = action === 'approve' ? 'APPROVED_20' : 'RESTORED_0';
  }
  private fail(): never { this.hold(); throw new PolicyError('phase'); }
}
export const domain = Object.freeze({ name: 'HyperliquidSignTransaction', version: '1', chainId: 421614, verifyingContract: `0x${'0'.repeat(40)}` });
export const types = Object.freeze({ 'HyperliquidTransaction:ApproveBuilderFee': [
  { name: 'hyperliquidChain', type: 'string' }, { name: 'maxFeeRate', type: 'string' },
  { name: 'builder', type: 'address' }, { name: 'nonce', type: 'uint64' },
] });
for (const fields of Object.values(types)) { for (const field of fields) Object.freeze(field); Object.freeze(fields); }
export function typedPayload(builder: string, nonce: number, action: Action) {
  return { domain, types: { EIP712Domain: [
    { name: 'name', type: 'string' }, { name: 'version', type: 'string' },
    { name: 'chainId', type: 'uint256' }, { name: 'verifyingContract', type: 'address' },
  ], ...types }, primaryType: 'HyperliquidTransaction:ApproveBuilderFee', message: {
    hyperliquidChain: 'Testnet', maxFeeRate: action === 'approve' ? '0.02%' : '0%', builder, nonce,
  } };
}
function nonceValid(n: unknown, c: ProxyConfig, now: number): n is number {
  return Number.isSafeInteger(n) && Number(n) >= c.startedAt && Number(n) <= now && now - Number(n) <= MAX_NONCE_AGE_MS && Number(n) < c.deadline;
}
export function validateExchange(raw: Buffer, c: ProxyConfig, action: Action, now: number): PublicHeld {
  const b = canonicalJson(raw);
  if (!exact(b, ['action', 'nonce', 'signature', 'vaultAddress', 'expiresAfter'])
    || b.vaultAddress !== null || b.expiresAfter !== null
    || !exact(b.action, ['type', 'hyperliquidChain', 'signatureChainId', 'maxFeeRate', 'builder', 'nonce'])
    || !exact(b.signature, ['r', 's', 'v'])) throw new PolicyError('request');
  const a = b.action, sig = b.signature;
  if (a.type !== 'approveBuilderFee' || a.hyperliquidChain !== 'Testnet' || a.signatureChainId !== '0x66eee'
    || a.maxFeeRate !== (action === 'approve' ? '0.02%' : '0%') || a.builder !== c.builder
    || b.nonce !== a.nonce || !nonceValid(a.nonce, c, now)
    || typeof sig.r !== 'string' || !/^0x[a-f0-9]{64}$/.test(sig.r)
    || typeof sig.s !== 'string' || !/^0x[a-f0-9]{64}$/.test(sig.s) || ![27, 28].includes(Number(sig.v))
    || typeof sig.v !== 'number') throw new PolicyError('request');
  const n = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
  if (BigInt(sig.r) <= 0n || BigInt(sig.r) >= n || BigInt(sig.s) <= 0n || BigInt(sig.s) > n / 2n) throw new PolicyError('signature');
  const typed = typedPayload(c.builder, a.nonce, action);
  const signature = `${sig.r}${sig.s.slice(2)}${sig.v.toString(16)}`;
  try {
    if (verifyTypedData(domain, types, typed.message, signature).toLowerCase() !== OWNER) throw new Error();
  } catch { throw new PolicyError('signature'); }
  return { action, owner: OWNER, builder: c.builder, rate: a.maxFeeRate as PublicHeld['rate'], nonce: a.nonce,
    bodySha256: digest(raw), typedDataSha256: digest(JSON.stringify(typed)), signatureSha256: digest(Buffer.from(signature.slice(2), 'hex')),
    expires: Math.min(c.deadline, a.nonce + MAX_NONCE_AGE_MS) };
}
export interface UpstreamRequest { host: string; method: 'GET' | 'POST'; path: string; body?: Buffer }
export interface UpstreamResponse { status: number; headers: Readonly<Record<string, string | string[] | undefined>>; body: Buffer }
export type Transport = (request: UpstreamRequest, signal: AbortSignal, max: number) => Promise<UpstreamResponse>;
export interface PublicEvent { type: 'hold' | 'held' | 'accepted' | 'rejection-verified'; phase: Phase; counters: Readonly<Counters>; held?: PublicHeld; cap?: 0 | 20; reason?: Reason }
export interface RootCallbacks {
  /** Runs in the root process only. Never export this function over the browser/control channel. */
  armExactBody(meta: Readonly<PublicHeld>, signal: AbortSignal): Promise<Arm>;
  event(event: Readonly<PublicEvent>): void;
}
export interface SafeResponse { status: number; headers: Readonly<Record<string, string>>; body: Buffer }
const safeHeaders = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' };
const corsHeaders = { ...safeHeaders, 'access-control-allow-origin': STAGING_ORIGIN, vary: 'Origin', 'content-type': 'application/json; charset=utf-8' };
function parseUpstream(r: UpstreamResponse): unknown {
  if (r.status !== 200 || r.body.length > MAX_BODY || r.headers['location'] || r.headers['set-cookie'] || r.headers['www-authenticate'] || r.headers['proxy-authenticate']) throw new PolicyError('upstream');
  if (!Buffer.from(r.body.toString('utf8')).equals(r.body) || (r.headers['content-encoding'] && r.headers['content-encoding'] !== 'identity')) throw new PolicyError('upstream');
  try { return JSON.parse(r.body.toString('utf8')); } catch { throw new PolicyError('upstream'); }
}
/** Pure HTTP framing/authority admission, used before collecting request bytes. */
export function validateHeaders(raw: readonly string[], host: string, method: string, path: string, extensionId?: string): number {
  if (raw.length > 64 || raw.reduce((n, v) => n + Buffer.byteLength(v), 0) > 8192 || raw.length % 2) throw new PolicyError('request');
  const h = new Map<string, string>();
  for (let i = 0; i < raw.length; i += 2) {
    const k = raw[i]!.toLowerCase(), v = raw[i + 1]!;
    if (h.has(k) || !/^[a-z0-9-]+$/.test(k) || /[^\x20-\x7e]/.test(v)) throw new PolicyError('request');
    h.set(k, v);
  }
  if (h.get('host') !== host && h.get('host') !== `${host}:443`) throw new PolicyError('request');
  const allowed = new Set(['host', 'connection', 'accept', 'accept-encoding', 'accept-language', 'user-agent', 'origin', 'referer', 'content-type', 'content-length', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'priority', 'cache-control', 'pragma', 'access-control-request-method', 'access-control-request-headers']);
  if ([...h.keys()].some(k => !allowed.has(k)) || (h.has('connection') && !['keep-alive', 'close'].includes(h.get('connection')!))) throw new PolicyError('request');
  if (!['GET', 'POST', 'OPTIONS'].includes(method) || !path.startsWith('/') || path.startsWith('//') || /[?#\\\s]/.test(path)) throw new PolicyError('request');
  if (host === RPC_HOST) {
    if (!extensionId || !/^[a-p]{32}$/.test(extensionId) || method !== 'POST' || path !== RPC_PATH
      || (h.has('origin') && h.get('origin') !== `chrome-extension://${extensionId}`)
      || h.has('referer')) throw new PolicyError('request');
  } else {
    if (h.has('origin') && h.get('origin') !== STAGING_ORIGIN) throw new PolicyError('request');
    if (h.has('referer') && h.get('referer') !== `${STAGING_ORIGIN}/approve`) throw new PolicyError('request');
    if (method !== 'GET' && h.get('origin') !== STAGING_ORIGIN) throw new PolicyError('request');
  }
  if (method === 'POST' && h.get('content-type') !== 'application/json') throw new PolicyError('request');
  if (method === 'OPTIONS' && (h.get('access-control-request-method') !== 'POST' || h.get('access-control-request-headers') !== 'content-type')) throw new PolicyError('request');
  const cl = h.get('content-length');
  if (cl !== undefined && !/^(0|[1-9][0-9]{0,3})$/.test(cl)) throw new PolicyError('request');
  const length = Number(cl ?? 0);
  if (length > MAX_BODY || (method === 'POST' ? length === 0 : length !== 0)) throw new PolicyError('request');
  return length;
}
export class PrivateProxyPolicy {
  private readonly gate = new ExchangeGate();
  private readonly aborter = new AbortController();
  private readonly begunMono = performance.now();
  private readonly begunUTC = Date.now();
  private readonly config: ProxyConfig;
  private readonly root: RootCallbacks;
  private readonly transport: Transport;
  private rpcReads = 0;
  constructor(c: ProxyConfig, root: RootCallbacks, transport: Transport) {
    validateConfig(c, Date.now()); this.config = structuredClone(c); this.root = root; this.transport = transport;
  }
  snapshot() { return { phase: this.gate.phase, counters: { ...this.gate.counters } }; }
  /** Original public-only phase. This never advances or resets the exchange gate. */
  assertNoKeyPreflight():number {
    this.live();
    if(this.gate.phase!=='PREFLIGHT'||this.gate.counters.exchangeAttempts
      ||this.gate.counters.heldBodies||this.gate.counters.upstreamDispatches)this.deny('phase');
    return Math.floor(this.now());
  }
  private now() { return Math.max(Date.now(), this.begunUTC + performance.now() - this.begunMono); }
  private live() {
    if (this.now() >= this.config.deadline) this.disarm('deadline');
    if (['HOLD', 'CLOSED'].includes(this.gate.phase)) throw new PolicyError('phase');
  }
  disarm(reason: Reason): void {
    if (this.gate.phase === 'CLOSED') return;
    const alreadyHeld = this.gate.phase === 'HOLD';
    this.gate.hold(); this.aborter.abort();
    if (alreadyHeld) return;
    try { this.root.event({ type: 'hold', ...this.snapshot(), reason }); } catch { /* Public observer cannot undo HOLD. */ }
  }
  deny(reason: Reason = 'request'): never { this.gate.counters.denials++; this.disarm(reason); throw new PolicyError(reason); }
  private async bounded<T>(p: Promise<T>): Promise<T> {
    this.live(); let timer: ReturnType<typeof setTimeout> | undefined; let listener: (() => void) | undefined;
    try {
      return await Promise.race([p, new Promise<never>((_, reject) => {
        listener = () => reject(new PolicyError('phase'));
        this.aborter.signal.addEventListener('abort', listener, { once: true });
        timer = setTimeout(() => { this.disarm('deadline'); reject(new PolicyError('deadline')); }, Math.max(1, Math.min(10_000, this.config.deadline - this.now())));
      })]);
    } finally { if (timer) clearTimeout(timer); if (listener) this.aborter.signal.removeEventListener('abort', listener); }
  }
  private async send(req: UpstreamRequest, max = MAX_BODY) {
    this.live(); const r = await this.bounded(this.transport(req, this.aborter.signal, max)); this.live(); return r;
  }
  private async info(type: 'userRole' | 'maxBuilderFee') {
    const body = type === 'userRole' ? { type, user: OWNER } : { type, user: OWNER, builder: this.config.builder };
    return parseUpstream(await this.send({ host: TESTNET_HOST, method: 'POST', path: '/info', body: Buffer.from(JSON.stringify(body)) }));
  }
  async beginRejection(): Promise<void> {
    try {
      if (this.gate.phase !== 'PREFLIGHT') this.deny('phase');
      // Latch before awaits; simultaneous preflight is not another admission.
      this.gate.phase = 'PREFLIGHT_PENDING';
      const role = await this.info('userRole'); const cap = await this.info('maxBuilderFee');
      this.live();
      if (!role || typeof role !== 'object' || !('role' in role) || role.role !== 'user' || cap !== 0 || this.gate.counters.exchangeAttempts) this.deny('readback');
      this.gate.phase = 'REJECTION';
    } catch { this.deny('readback'); }
  }
  verifyRejection(): void {
    try { this.live(); this.gate.verifyRejection(); this.root.event({ type: 'rejection-verified', ...this.snapshot() }); } catch { this.deny('phase'); }
  }
  start(action: Action): void { try { this.live(); this.gate.start(action); } catch { this.deny('phase'); } }
  private async exchange(raw: Buffer, action: Action): Promise<SafeResponse> {
    const held = validateExchange(raw, this.config, action, this.now()); this.gate.verified(held.nonce);
    this.root.event({ type: 'held', ...this.snapshot(), held: { ...held } });
    const arm = await this.bounded(this.root.armExactBody(Object.freeze({ ...held }), this.aborter.signal));
    this.live();
    if (!exact(arm, ['bodySha256', 'expires']) || arm.bodySha256 !== held.bodySha256 || !Number.isSafeInteger(arm.expires)
      || arm.expires > held.expires || arm.expires <= this.now() || !nonceValid(held.nonce, this.config, this.now())) this.deny('arm');
    this.gate.consume(action); // One-use arm is consumed before any upstream write.
    const response = await this.send({ host: TESTNET_HOST, path: '/exchange', method: 'POST', body: raw });
    const parsed = parseUpstream(response);
    if (!exact(parsed, ['status', 'response']) || parsed.status !== 'ok' || !exact(parsed.response, ['type']) || parsed.response.type !== 'default') this.deny('upstream');
    const cap = await this.info('maxBuilderFee'); this.live(); this.gate.accepted(action, cap);
    this.root.event({ type: 'accepted', ...this.snapshot(), held: { ...held }, cap: cap as 0 | 20 });
    return { status: 200, headers: corsHeaders, body: response.body };
  }
  /** Called synchronously at header arrival, before reading or awaiting any body bytes. */
  openRequest(host: string, method: string, path: string, rawHeaders: readonly string[]): { length: number; complete(raw: Buffer): Promise<SafeResponse> } {
    try {
      this.live();
      const action = host === TESTNET_HOST && method === 'POST' && path === '/exchange' ? this.gate.attempt() : undefined;
      const length = validateHeaders(rawHeaders, host, method, path, this.config.extensionId);
      if (!(host === STAGING_HOST && method === 'GET' && Object.hasOwn(this.config.assets, path))
        && !(host === TESTNET_HOST && ['POST', 'OPTIONS'].includes(method) && ['/info', '/exchange'].includes(path))
        && !(host === RPC_HOST && method === 'POST' && path === RPC_PATH)) this.deny();
      let completed = false;
      return { length, complete: async (raw: Buffer) => {
        if (completed) this.deny('phase'); completed = true;
        return this.complete(host, method, path, length, raw, action);
      } };
    } catch (e) { this.disarm(e instanceof PolicyError ? e.reason : 'request'); throw new PolicyError(e instanceof PolicyError ? e.reason : 'request'); }
  }
  async handle(host: string, method: string, path: string, rawHeaders: readonly string[], raw: Buffer): Promise<SafeResponse> {
    return this.openRequest(host, method, path, rawHeaders).complete(raw);
  }
  private async complete(host: string, method: string, path: string, length: number, raw: Buffer, action?: Action): Promise<SafeResponse> {
    try {
      this.live();
      if (raw.length !== length) this.deny();
      if (host === STAGING_HOST && method === 'GET') {
        const pin = this.config.assets[path]; if (!pin) this.deny();
        const r = await this.send({ host, method: 'GET', path }, MAX_ASSET);
        if (r.status !== 200 || r.body.length > MAX_ASSET || digest(r.body) !== pin.sha256
          || r.headers['location'] || r.headers['set-cookie'] || r.headers['www-authenticate'] || r.headers['proxy-authenticate']
          || (r.headers['content-encoding'] && r.headers['content-encoding'] !== 'identity')) this.deny('upstream');
        return { status: 200, headers: { ...safeHeaders, 'content-type': pin.contentType, 'content-security-policy': pin.csp }, body: r.body };
      }
      if (host === RPC_HOST && method === 'POST' && path === RPC_PATH) {
        const b = canonicalJson(raw, 1024);
        if (!exact(b, ['jsonrpc', 'id', 'method', 'params']) || b.jsonrpc !== '2.0'
          || !Number.isInteger(b.id) || Number(b.id) < 0 || Number(b.id) >= 4_294_967_295
          || b.method !== 'eth_chainId' || !Array.isArray(b.params) || b.params.length !== 0
          || ++this.rpcReads > 4) this.deny();
        const r = await this.send({ host, method: 'POST', path, body: raw }, 1024);
        parseUpstream(r);
        const result = canonicalJson(r.body, 1024);
        if (!exact(result, ['jsonrpc', 'id', 'result']) || result.jsonrpc !== '2.0' || result.id !== b.id || result.result !== '0x66eee') this.deny('upstream');
        return { status: 200, headers: { ...safeHeaders, 'content-type': 'application/json; charset=utf-8',
          'access-control-allow-origin': `chrome-extension://${this.config.extensionId}`, vary: 'Origin' }, body: r.body };
      }
      if (host !== TESTNET_HOST || !['/info', '/exchange'].includes(path)) this.deny();
      if (method === 'OPTIONS') return { status: 204, headers: { ...corsHeaders, 'access-control-allow-methods': 'POST', 'access-control-allow-headers': 'content-type' }, body: Buffer.alloc(0) };
      if (method !== 'POST') this.deny();
      if (path === '/exchange') { if (!action) this.deny('phase'); return await this.exchange(raw, action); }
      const b = canonicalJson(raw);
      if (!(exact(b, ['type', 'user']) && b.type === 'userRole' && b.user === OWNER)
        && !(exact(b, ['type', 'user', 'builder']) && b.type === 'maxBuilderFee' && b.user === OWNER && b.builder === this.config.builder)) this.deny();
      const r = await this.send({ host, method: 'POST', path, body: raw }); parseUpstream(r);
      return { status: 200, headers: corsHeaders, body: r.body };
    } catch (e) { this.disarm(e instanceof PolicyError ? e.reason : 'request'); throw new PolicyError(e instanceof PolicyError ? e.reason : 'request'); }
  }
  close(): void { this.disarm('closed'); this.gate.phase = 'CLOSED'; }
}
