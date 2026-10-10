import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import tls from 'node:tls';
import { isIPv4, type Socket } from 'node:net';
import { randomUUID, X509Certificate } from 'node:crypto';
import {
  MAX_BODY, STAGING_HOST, TESTNET_HOST, RPC_HOST, PrivateProxyPolicy, PolicyError,
  type ProxyConfig, type RootCallbacks, type Action,
} from './proxy-policy.ts';
import {makeRootUpstream} from './root-upstream.ts';
import type {CanonicalProxyAccess} from './proxy-access.ts';
import {makeProtectedJourney,journeyBrowserPolicy,type ProtectedJourneyScope,type ProtectedJourney,type JourneyCallbacks} from './protected-journey.ts';
import {makePreparedJourney} from './prepared-journey.ts';
import {NoKeyProbeWindow,validateNoKeyDenialReceipt,type NoKeyDenialRequest,type NoKeyDenialReceipt} from './proxy-no-key.ts';
import type {NoKeyBrowserProbeInputs} from './proxy-no-key.ts';
import {pinned} from './driver-pin.ts';

const MAX_CONNECTIONS = 8;
const MAX_REQUESTS = 128;
const TIMEOUT_MS = 10_000;
const MAX_HEADERS = 8192;

export interface ProxyEndpoint { ipv4: string; port: number }
export interface RootTlsMaterial { privateKey: Buffer; certificate: Buffer }
export interface DrainedProof {
  readonly instanceId: string;
  readonly listenerClosed: true;
  readonly sockets: 0;
  readonly outstandingRequests: 0;
}
export interface NativeNoKeyProbes {
  beginNoKeyProbeWindow(input:NoKeyBrowserProbeInputs):Promise<void>;
  finishNoKeyProbeWindow():Promise<Readonly<NoKeyDenialReceipt>>;
}
export interface RootProxy extends NativeNoKeyProbes {
  readonly instanceId: string;
  readonly endpoint: Readonly<ProxyEndpoint>;
  snapshot(): ReturnType<PrivateProxyPolicy['snapshot']>;
  beginRejection(): Promise<void>;
  verifyRejection(): void;
  start(action: Action): void;
  disarm(): void;
  closeDrained(): Promise<DrainedProof>;
}
/** CONNECT has a separate grammar; nothing is forwarded verbatim. */
export function connectHost(method: string, authority: string, raw: readonly string[], headLength: number): string {
  if (method !== 'CONNECT' || headLength !== 0 || raw.length > 32 || raw.length % 2
    || raw.reduce((n, v) => n + Buffer.byteLength(v), 0) > MAX_HEADERS) throw new PolicyError('request');
  if (![`${STAGING_HOST}:443`, `${TESTNET_HOST}:443`, `${RPC_HOST}:443`].includes(authority)) throw new PolicyError('request');
  const h = new Map<string, string>();
  for (let i = 0; i < raw.length; i += 2) {
    const key = raw[i]!.toLowerCase(), value = raw[i + 1]!;
    if (h.has(key) || !['host', 'proxy-connection', 'user-agent'].includes(key) || /[^\x20-\x7e]/.test(value)) throw new PolicyError('request');
    h.set(key, value);
  }
  // Chromium's ordinary CONNECT sends this local-only keep-alive hint. Never forwarded.
  if (h.get('host') !== authority || (h.has('proxy-connection') && h.get('proxy-connection') !== 'keep-alive')) throw new PolicyError('request');
  return authority.slice(0, -4);
}

/** Root process only. Constructing does not start listening; explicit call below does. */
type NativeProxy = Pick<RootProxy,'instanceId'|'endpoint'|'disarm'|'closeDrained'> & NativeNoKeyProbes;
type NativeCore = NativeProxy & {assertPrivateTransition():void};
type BrowserPolicy = Pick<PrivateProxyPolicy,'openRequest'|'disarm'|'close'> & {assertNoKeyPreflight?:()=>number};
export type RootJourneyProxy = NativeProxy & ProtectedJourney;
export interface PreparedJourneyProxy {
  proxy:RootJourneyProxy;
  activate(tokens:{issuer:Buffer;inbox:Buffer},callbacks:JourneyCallbacks):RootJourneyProxy;
}
/** Same native listener serves public pinned assets before a one-use private activation. */
export async function startPreparedJourneyProxy(scope:ProtectedJourneyScope,endpoint:ProxyEndpoint,material:RootTlsMaterial,
 access:CanonicalProxyAccess,authority:(deadline:number)=>void,extensionId:string):Promise<PreparedJourneyProxy>{
  let holder:ReturnType<typeof makePreparedJourney>|undefined;
  const core=await startNativeProxy(scope.deadline,512,endpoint,material,access,(sockets,state)=>{
    holder=makePreparedJourney(scope,sockets,state,access,authority,extensionId);return holder.policy;
  },{runId:scope.runId,startedAt:scope.startedAt,deadline:scope.deadline,extensionId});
  const held=holder!,{assertPrivateTransition,...publicCore}=core,proxy=Object.freeze({...held.journey,...publicCore});
  return Object.freeze({proxy,activate:(tokens:{issuer:Buffer;inbox:Buffer},callbacks:JourneyCallbacks)=>{
    assertPrivateTransition();held.activate(tokens,callbacks);return proxy;
  }});
}
export async function startRootProxy(config: ProxyConfig, endpoint: ProxyEndpoint, material: RootTlsMaterial, callbacks: RootCallbacks, access:CanonicalProxyAccess): Promise<RootProxy> {
  let policy:PrivateProxyPolicy|undefined;
  const core=await startNativeProxy(config.deadline,MAX_REQUESTS,endpoint,material,access,(sockets,state)=>{
    policy=new PrivateProxyPolicy(config,callbacks,makeRootUpstream(sockets,state,access));return policy;
  },config);
  const held=policy!,{assertPrivateTransition,...publicCore}=core;
  return Object.freeze({...publicCore,snapshot:()=>held.snapshot(),beginRejection:()=>{assertPrivateTransition();return held.beginRejection();},verifyRejection:()=>held.verifyRejection(),start:(action:Action)=>held.start(action)});
}
/** Separate private journey profile; never changes the approval/no-key policy. */
export async function startPrivateJourneyProxy(scope:ProtectedJourneyScope,endpoint:ProxyEndpoint,material:RootTlsMaterial,
  tokens:{issuer:Buffer;inbox:Buffer},access:CanonicalProxyAccess,authority:(deadline:number)=>void,callbacks:JourneyCallbacks,extensionId:string):Promise<RootJourneyProxy>{
  if(!/^[a-p]{32}$/.test(extensionId))throw new PolicyError('config');
  let cap:ProtectedJourney|undefined;
  const core=await startNativeProxy(scope.deadline,512,endpoint,material,access,(sockets,state)=>{
    cap=makeProtectedJourney(scope,tokens,sockets,state,access,authority,callbacks);
    return journeyBrowserPolicy(scope,cap,extensionId,authority);
  });
  const {assertPrivateTransition:_unused,...publicCore}=core;
  return Object.freeze({...cap!,...publicCore});
}
async function startNativeProxy(deadline:number,maxRequests:number,endpoint:ProxyEndpoint,material:RootTlsMaterial,access:CanonicalProxyAccess,
  createPolicy:(sockets:Set<Socket>,state:{active:number})=>BrowserPolicy,
  noKeyScope?:Pick<ProxyConfig,'runId'|'startedAt'|'deadline'|'extensionId'>):Promise<NativeCore>{
  if (!isIPv4(endpoint.ipv4) || !endpoint.ipv4.startsWith('169.254.') || !Number.isInteger(endpoint.port) || endpoint.port < 1024 || endpoint.port > 65535
    || !Buffer.isBuffer(material.privateKey) || !Buffer.isBuffer(material.certificate) || !material.privateKey.length || material.privateKey.length > 16384
    || !material.certificate.length || material.certificate.length > 16384) throw new PolicyError('config');
  // Inspect only the explicitly supplied root certificate; never install global trust.
  let secureContext: tls.SecureContext;
  try {
    const cert = new X509Certificate(material.certificate);
    const names = cert.subjectAltName?.split(', ').sort();
    const expected = [`DNS:${STAGING_HOST}`, `DNS:${TESTNET_HOST}`, `DNS:${RPC_HOST}`].sort();
    const from = Date.parse(cert.validFrom), to = Date.parse(cert.validTo);
    if (JSON.stringify(names) !== JSON.stringify(expected) || !Number.isFinite(from) || !Number.isFinite(to)
      || from > Date.now() || to <= Date.now() || to - from > 86_400_000
      || cert.publicKey.asymmetricKeyType !== 'rsa' || cert.publicKey.asymmetricKeyDetails?.modulusLength !== 2048) throw new PolicyError('config');
    secureContext = tls.createSecureContext({ key: material.privateKey, cert: material.certificate, minVersion: 'TLSv1.2' });
  } catch { throw new PolicyError('config'); }
  const upstreamSockets = new Set<Socket>();
  const upstreamState = { active: 0 };
  const policy = createPolicy(upstreamSockets,upstreamState);
  const instanceId = randomUUID();
  const sockets = new Set<Socket>();
  const pending = new Set<Promise<void>>();
  const deniedSockets=new Set<Socket>(),deniedOperations=new Set<Promise<void>>();
  const originalNoKeyScope=noKeyScope?Object.freeze(structuredClone(noKeyScope)):undefined;
  const noKey=originalNoKeyScope?new NoKeyProbeWindow(originalNoKeyScope,endpoint):undefined;
  let noKeyClaimed=false,noKeyAdmitted=false,noKeyFinished=false,noKeyFinishClaimed=false;
  const publicGuard=()=>{
    if(closing||!noKey||!policy.assertNoKeyPreflight)throw new PolicyError('phase');
    return policy.assertNoKeyPreflight();
  };
  const assertPrivateTransition=()=>{
    if(noKeyClaimed&&!noKeyFinished){policy.disarm('phase');throw new PolicyError('phase');}
  };
  const expectedDenial=(request:NoKeyDenialRequest)=>{
    if(!noKeyAdmitted)return false;
    try{return noKey!.expectedDenial(request,publicGuard());}
    catch{noKey!.close();return false;}
  };
  const trackDenial=(socket:Socket)=>{
    if(deniedSockets.has(socket)){policy.disarm('request');throw new PolicyError('request');}
    deniedSockets.add(socket);socket.once('close',()=>deniedSockets.delete(socket));
  };
  let closing = false, listenerClosed = false, totalRequests = 0;
  let closePromise: Promise<DrainedProof> | undefined;
  const track = (socket: Socket) => {
    sockets.add(socket);
    const totalTimer = setTimeout(() => { policy.disarm('transport'); socket.destroy(); }, TIMEOUT_MS);
    socket.once('close', () => { clearTimeout(totalTimer); sockets.delete(socket); });
    socket.setTimeout(TIMEOUT_MS, () => { policy.disarm('transport'); socket.destroy(); });
    socket.on('error', () => { policy.disarm('transport'); socket.destroy(); });
  };
  const reject = (socket: Socket) => { policy.disarm('request'); socket.destroy(); };
  const deniedResponse = (response: ServerResponse) => {
    if (!response.headersSent && !response.destroyed) response.writeHead(403, { 'content-type': 'text/plain', 'cache-control': 'no-store', connection: 'close', 'content-length': '0' });
    response.end();
  };
  async function serve(request: IncomingMessage, response: ServerResponse, host: string): Promise<void> {
    try {
      if (closing || ++totalRequests > maxRequests) throw new PolicyError('request');
      // Admission and exchange reservation occur before the first body await.
      const admission = policy.openRequest(host, request.method ?? '', request.url ?? '', request.rawHeaders);
      const chunks: Buffer[] = []; let size = 0;
      for await (const value of request) {
        const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
        size += chunk.length;
        if (size > admission.length || size > MAX_BODY) throw new PolicyError('request');
        chunks.push(chunk);
      }
      if (request.rawTrailers.length || size !== admission.length) throw new PolicyError('request');
      const body = Buffer.concat(chunks, size); chunks.length = 0;
      try {
        const result = await admission.complete(body);
        response.writeHead(result.status, { ...result.headers, 'content-length': String(result.body.length), connection: 'close' });
        response.end(result.body);
      } finally { body.fill(0); }
    } catch { policy.disarm('request'); deniedResponse(response); }
  }
  async function denyOuterProbe(request:IncomingMessage,response:ServerResponse):Promise<void>{
    try{
      if(closing||++totalRequests>maxRequests||!expectedDenial({kind:'outer',method:request.method??'',target:request.url??'',
        rawHeaders:request.rawHeaders,headLength:0,bodyLength:0,trailersLength:request.rawTrailers.length}))throw new PolicyError('request');
      trackDenial(request.socket);
      // Headers prohibit framing a body; still consume the actual message and check trailers.
      for await(const value of request)if(value.length!==0)throw new PolicyError('request');
      if(request.rawTrailers.length||!request.complete)throw new PolicyError('request');
      publicGuard();deniedResponse(response);
    }catch{policy.disarm('request');deniedResponse(response);}
  }
  const outer = http.createServer({ maxHeaderSize: MAX_HEADERS, requestTimeout: TIMEOUT_MS, headersTimeout: TIMEOUT_MS }, (request, response) => {
    const operation=denyOuterProbe(request,response);
    pending.add(operation);deniedOperations.add(operation);
    void operation.finally(()=>{pending.delete(operation);deniedOperations.delete(operation);});
  });
  outer.maxHeadersCount = 0;
  outer.on('connection', socket => {
    if (closing || sockets.size >= MAX_CONNECTIONS) { reject(socket); return; }
    track(socket);
  });
  outer.on('clientError', (_error, socket) => reject(socket as Socket));
  outer.on('upgrade', (_request, socket) => reject(socket as Socket));
  outer.on('connect', (request, duplex, head) => {
    const socket = duplex as Socket;
    try {
      if (closing) throw new PolicyError('closed');
      let host:string;
      try{host=connectHost(request.method??'',request.url??'',request.rawHeaders,head.length);}
      catch{
        if(++totalRequests>maxRequests||!expectedDenial({kind:'connect',method:request.method??'',target:request.url??'',
          rawHeaders:request.rawHeaders,headLength:head.length,bodyLength:0,trailersLength:request.rawTrailers.length}))throw new PolicyError('request');
        trackDenial(socket);
        // Expected blocked CONNECT receives denial only: no tunnel, TLS or upstream.
        socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n');
        return;
      }
      const termination = tls.createServer({
        key: material.privateKey, cert: material.certificate, minVersion: 'TLSv1.2',
        ALPNProtocols: ['http/1.1'], handshakeTimeout: TIMEOUT_MS,
        SNICallback: (name, callback) => {
          if (name !== host || closing) { policy.disarm('request'); callback(new PolicyError('request')); }
          else callback(null, secureContext);
        },
      });
      termination.on('tlsClientError', () => reject(socket));
      termination.on('error', () => reject(socket));
      termination.once('secureConnection', secure => {
        if (closing || secure.servername !== host || (secure.alpnProtocol && secure.alpnProtocol !== 'http/1.1')) { reject(secure); return; }
        track(secure);
        let requests = 0;
        const inner = http.createServer({ maxHeaderSize: MAX_HEADERS, requestTimeout: TIMEOUT_MS, headersTimeout: TIMEOUT_MS }, (req, res) => {
          if (++requests !== 1 || closing) { reject(secure); return; }
          const operation = serve(req, res, host);
          pending.add(operation); void operation.finally(() => pending.delete(operation));
        });
        inner.maxHeadersCount = 0;
        inner.on('clientError', () => reject(secure));
        inner.on('upgrade', () => reject(secure));
        inner.on('connect', () => reject(secure));
        inner.on('checkContinue', (_req, res) => { policy.disarm('request'); deniedResponse(res); });
        inner.on('checkExpectation', (_req, res) => { policy.disarm('request'); deniedResponse(res); });
        secure.once('close', () => { inner.close(); termination.close(); });
        inner.emit('connection', secure);
      });
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      termination.emit('connection', socket);
    } catch { reject(socket); }
  });
  try { await new Promise<void>((resolve, fail) => {
    const error = () => fail(new PolicyError('transport'));
    outer.once('error', error);
    outer.listen(endpoint.port, endpoint.ipv4, () => { outer.off('error', error); resolve(); });
  }); } catch { policy.close(); access.dispose(); throw new PolicyError('transport'); }
  outer.on('error', () => { policy.disarm('transport'); });
  const deadlineTimer = setTimeout(() => { policy.disarm('deadline'); for (const socket of sockets) socket.destroy(); }, Math.max(1, deadline - Date.now()));
  return Object.freeze({
    instanceId, endpoint: Object.freeze({ ...endpoint }),assertPrivateTransition,
    beginNoKeyProbeWindow:async(input:NoKeyBrowserProbeInputs)=>{
      // Consume before the first await. Actual matching stays disabled until both pins pass.
      if(noKeyClaimed){noKey?.close();policy.disarm('phase');throw new PolicyError('phase');}
      noKeyClaimed=true;
      try{
        const snapshot=structuredClone(input);
        noKey!.begin(snapshot,publicGuard());
        await pinned(snapshot.modulePin,131072);publicGuard();
        await pinned(snapshot.contractPin,131072);publicGuard();
        noKeyAdmitted=true;
      }catch{noKey?.close();policy.disarm('phase');throw new PolicyError('phase');}
    },
    finishNoKeyProbeWindow:async()=>{
      if(noKeyFinishClaimed||!noKeyAdmitted){noKey?.close();policy.disarm('phase');throw new PolicyError('phase');}
      noKeyFinishClaimed=true;noKeyAdmitted=false;
      try{
        const now=publicGuard();noKey!.beginClosing(now);
        // Only the denied cohort drains here. Keep the SAME listener/context for later phases.
        await new Promise<void>((resolve,fail)=>{
          let poll:ReturnType<typeof setInterval>;
          const timer=setTimeout(()=>{clearInterval(poll);fail(new PolicyError('transport'));},Math.min(TIMEOUT_MS,deadline-now));
          const check=()=>{
            try{publicGuard();if(deniedSockets.size===0&&deniedOperations.size===0){clearTimeout(timer);clearInterval(poll);resolve();}}
            catch{clearTimeout(timer);clearInterval(poll);fail(new PolicyError('phase'));}
          };
          poll=setInterval(check,10);check();
        });
        const counters=noKey!.finish(publicGuard());
        const expected={instanceId,runId:originalNoKeyScope!.runId,startedAt:originalNoKeyScope!.startedAt,deadline};
        const receipt=validateNoKeyDenialReceipt({schema:1,purpose:'no-key-proxy-denials-drained',...expected,
          closed:true,matchingDisabled:true,sockets:0,outstandingRequests:0,total:counters.total,counts:counters.counts},expected);
        noKeyFinished=true;return receipt;
      }catch{noKey?.close();policy.disarm('phase');throw new PolicyError('phase');}
    },
    disarm: () => {noKey?.close();policy.disarm('closed');},
    closeDrained: () => {
      if (closePromise) return closePromise;
      closing = true;noKey?.close();noKeyAdmitted=false; clearTimeout(deadlineTimer); policy.close();access.dispose();
      closePromise = new Promise<DrainedProof>((resolve, fail) => {
        const timer = setTimeout(() => { clearInterval(poll); fail(new PolicyError('closed')); }, TIMEOUT_MS);
        const check = () => {
          if (listenerClosed && sockets.size === 0 && upstreamSockets.size === 0 && upstreamState.active === 0 && pending.size === 0) {
            clearTimeout(timer); clearInterval(poll); resolve(Object.freeze({ instanceId, listenerClosed: true, sockets: 0, outstandingRequests: 0 }));
          }
        };
        const poll = setInterval(check, 10);
        for (const socket of [...sockets, ...upstreamSockets]) { socket.once('close', check); socket.destroy(); }
        for (const operation of pending) void operation.finally(check);
        outer.close(error => { if (error) { clearTimeout(timer); clearInterval(poll); fail(new PolicyError('closed')); return; } listenerClosed = true; check(); });
        outer.closeAllConnections(); check();
      });
      return closePromise;
    },
  });
}
