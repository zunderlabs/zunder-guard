// Explicit root bootstrap only. Import/constructor performs no kernel or material work.
import { loadParentFlow, type ParentPins } from './parent-flow-loader.ts';
import { planRootNetwork, prepareRootNetwork, type NetworkConfig } from './network.ts';
import { createLinuxNetworkCapability, type ExecutablePin, type LinuxFlowBoundary } from './network-linux.ts';
import { createRootTlsMaterial, type RootTlsCapability } from './tls-material.ts';
import { startRootProxy, startPreparedJourneyProxy, type RootProxy, type RootJourneyProxy, type DrainedProof } from './proxy.ts';
import {validateProtectedJourneyScope,type ProtectedJourneyScope,type JourneyCallbacks} from './protected-journey.ts';
import { validateConfig, type ProxyConfig, type RootCallbacks } from './proxy-policy.ts';
import {readCanonicalProxyAccessPipe,type CanonicalProxyAccess} from './proxy-access.ts';
import {FUTURE_STAGING_HOST} from '../access/headers.ts';

export interface LinuxRuntimeConfig {
  network: NetworkConfig;
  executablePins: readonly ExecutablePin[];
  opensslSha256: string;
  parent: ParentPins;
  proxy: ProxyConfig;
  accessTokenExpiresAt:number;
}
function refuse():never {throw new Error('Root wallet runtime reconciliation required');}
function copyJourneyInputs(tokens:{issuer:Buffer;inbox:Buffer},callbacks:JourneyCallbacks){
  if(!callbacks||Object.keys(callbacks).join(',')!=='armExactPayment'||typeof callbacks.armExactPayment!=='function'
    ||!tokens||Object.keys(tokens).sort().join(',')!=='inbox,issuer')refuse();
  for(const token of [tokens.issuer,tokens.inbox]){
    if(!Buffer.isBuffer(token)||token.length<43||token.length>128||!/^[A-Za-z0-9_-]+$/.test(token.toString('ascii'))
      ||!Buffer.from(token.toString('ascii')).equals(token))refuse();
  }
  if(tokens.issuer.equals(tokens.inbox))refuse();
  return{issuer:Buffer.from(tokens.issuer),inbox:Buffer.from(tokens.inbox),callbacks:Object.freeze({armExactPayment:callbacks.armExactPayment})};
}
/** Public bindings only; does not prove approval, operating-system state or custody. */
export function validateRuntimeBindings(input: LinuxRuntimeConfig, now: number): LinuxRuntimeConfig {
  const c=structuredClone(input);
  if (Object.keys(c).sort().join(',')!=='accessTokenExpiresAt,executablePins,network,opensslSha256,parent,proxy'
    || !/^[0-9a-f]{64}$/.test(c.opensslSha256)||!Number.isSafeInteger(c.accessTokenExpiresAt)||c.accessTokenExpiresAt<c.network.deadline) refuse();
  const plan=planRootNetwork(c.network); validateConfig(c.proxy,now);
  if (c.network.startedAt>now || c.network.deadline<=now
    || c.proxy.runId!==c.network.runId || c.proxy.startedAt!==c.network.startedAt || c.proxy.deadline!==c.network.deadline
    || !Array.isArray(c.executablePins) || c.executablePins.length!==3
    || new Set(c.executablePins.map(p=>p.path)).size!==3) refuse();
  for (const p of c.executablePins) if (Object.keys(p).sort().join(',')!=='path,sha256'
    || !Object.values(plan.config.executables).includes(p.path) || !/^[0-9a-f]{64}$/.test(p.sha256)) refuse();
  return c;
}
type Network=Awaited<ReturnType<typeof prepareRootNetwork>>;
type Material=Awaited<ReturnType<typeof createRootTlsMaterial>>;
export type RuntimePhase='NEW'|'PREPARING'|'READY'|'CLOSING'|'PARENT_CUSTODY_CLEANUP_REQUIRED'|'HOLD';

/** Root's authenticated controller retains this object on failures for reconciliation. */
export class LinuxRootWalletRuntime {
  #config: LinuxRuntimeConfig;
  #callbacks: RootCallbacks;
  #phase: RuntimePhase='NEW';
  #flow: LinuxFlowBoundary|undefined;
  #tlsChild: RootTlsCapability|undefined;
  #network: Network|undefined;
  #material: Material|undefined;
  #proxy: RootProxy|RootJourneyProxy|undefined;
  #access:CanonicalProxyAccess|undefined;
  #originalAuthority:((deadline:number)=>void)|undefined;
  constructor(config: LinuxRuntimeConfig, callbacks: RootCallbacks) {
    this.#config=validateRuntimeBindings(config,Date.now());this.#callbacks=callbacks;
  }
  snapshot() {return Object.freeze({phase:this.#phase,networkName:this.#network?.identity.name,
    proxyInstanceId:this.#proxy?.instanceId,rootGuardianDeathProven:false as const});}
  async #live() {
    const flow=this.#flow;
    if (!flow || !['PREPARING','READY','CLOSING'].includes(this.#phase)) refuse();
    this.#originalAuthority?.(this.#config.network.deadline);
    await flow.assertOriginalAuthority(this.#config.network.deadline);
    this.#originalAuthority?.(this.#config.network.deadline);
    if (Date.now()>=this.#config.network.deadline) refuse();
  }
  async #hold() {
    this.#phase='HOLD';this.#proxy?.disarm();this.#access?.dispose();
    await this.#flow?.hold('network-unknown').catch(()=>undefined);
    await this.#tlsChild?.hold('tls-material-unknown').catch(()=>undefined);
  }
  /** ROOT EXECUTION ONLY after full source review; actual adapters, no predicate substitutes. */
  async initialize(): Promise<{proxy:RootProxy;publicCertificate:Buffer;publicCertificateSha256:string;network:Network}> {
    return this.#initialize(material=>startRootProxy(this.#config.proxy,
      {ipv4:this.#config.network.hostIpv4,port:this.#config.network.proxyPort},
      {privateKey:material.key,certificate:material.cert},this.#callbacks,this.#access!));
  }
  /** Prepare the actual no-key namespace/Page before the owner/private input handoff. */
  async prepareProtectedJourney(input:ProtectedJourneyScope,originalAuthority:(deadline:number)=>void){
    if(this.#phase!=='NEW')refuse();
    try{
      const scope=validateProtectedJourneyScope(input),c=this.#config.network;
      if(typeof originalAuthority!=='function'||scope.runId!==c.runId||scope.startedAt!==c.startedAt
        ||scope.deadline!==c.deadline||scope.owner!==this.#config.proxy.owner)refuse();
      this.#originalAuthority=(deadline)=>{
        if(deadline!==c.deadline||Date.now()<c.startedAt||Date.now()>=c.deadline)refuse();
        originalAuthority(deadline);this.#flow?.assertDispatchAuthority(deadline);
      };
      this.#originalAuthority(c.deadline);
      let activateProxy:Awaited<ReturnType<typeof startPreparedJourneyProxy>>['activate']|undefined;
      const prepared=await this.#initialize(async material=>{
        this.#originalAuthority!(c.deadline);
        const result=await startPreparedJourneyProxy(scope,{ipv4:c.hostIpv4,port:c.proxyPort},
          {privateKey:material.key,certificate:material.cert},this.#access!,this.#originalAuthority!,this.#config.proxy.extensionId);
        activateProxy=result.activate;return result.proxy;
      });
      let used=false;
      return Object.freeze({...prepared,activate:async(privateTokens:{issuer:Buffer;inbox:Buffer},callbacks:JourneyCallbacks):Promise<RootJourneyProxy>=>{
        if(used){await this.#hold();refuse();}used=true;
        let issuer:Buffer|undefined,inbox:Buffer|undefined;
        try{
          if(this.#phase!=='READY'||!activateProxy)refuse();
          this.#originalAuthority!(c.deadline);
          const held=copyJourneyInputs(privateTokens,callbacks);issuer=held.issuer;inbox=held.inbox;
          await this.#live();
          const proxy=activateProxy({issuer,inbox},held.callbacks);
          if(proxy!==prepared.proxy||proxy!==this.#proxy)refuse();
          await this.#live();return proxy;
        }catch{await this.#hold();throw new Error('Protected activation uncertain; retain owned state for parent reconciliation');}
        finally{issuer?.fill(0);inbox?.fill(0);}
      }});
    }catch{
      if(this.#phase==='NEW')this.#phase='HOLD';
      throw new Error('Root protected preparation uncertain; retain owned state for parent reconciliation');
    }
  }
  /** Compatibility only; actual composed callers must finish no-key probes before activate. */
  async initializeProtectedJourney(input:ProtectedJourneyScope,privateTokens:{issuer:Buffer;inbox:Buffer},
    originalAuthority:(deadline:number)=>void,callbacks:JourneyCallbacks){
    let held:ReturnType<typeof copyJourneyInputs>|undefined;
    try{
      if(this.#phase!=='NEW'||typeof originalAuthority!=='function')refuse();
      const scope=validateProtectedJourneyScope(input),c=this.#config.network;
      if(scope.runId!==c.runId||scope.startedAt!==c.startedAt||scope.deadline!==c.deadline
        ||scope.owner!==this.#config.proxy.owner)refuse();
      originalAuthority(c.deadline);held=copyJourneyInputs(privateTokens,callbacks);
      const prepared=await this.prepareProtectedJourney(scope,originalAuthority);
      await prepared.activate({issuer:held.issuer,inbox:held.inbox},held.callbacks);
      return Object.freeze({proxy:prepared.proxy,network:prepared.network,
        publicCertificate:prepared.publicCertificate,publicCertificateSha256:prepared.publicCertificateSha256});
    }catch{await this.#hold();throw new Error('Root protected initialization uncertain; retain owned state for parent reconciliation');}
    finally{held?.issuer.fill(0);held?.inbox.fill(0);}
  }
  async #initialize<T extends RootProxy|RootJourneyProxy>(create:(material:{key:Buffer;cert:Buffer})=>Promise<T>):Promise<{proxy:T;publicCertificate:Buffer;publicCertificateSha256:string;network:Network}> {
    if (this.#phase!=='NEW' || process.platform!=='linux' || process.arch!=='x64' || process.getuid?.()!==0) refuse();
    this.#phase='PREPARING';
    try {
      const parent=await loadParentFlow(this.#config.parent);
      this.#flow=parent.networkFlow;this.#tlsChild=parent.tlsCapability;
      await this.#live();
      const c=this.#config.network;
      this.#access=await readCanonicalProxyAccessPipe({stagingHost:FUTURE_STAGING_HOST,startedAt:c.startedAt,
        deadline:c.deadline,tokenExpiresAt:this.#config.accessTokenExpiresAt},this.#flow);
      await this.#live();
      // Bind the real parent's UUID/start/deadline/OpenSSL identity before any namespace mutation.
      await this.#tlsChild.assertSourceMemoryAndOriginalAuthority({runId:c.runId,startedAt:c.startedAt,
        deadline:c.deadline,opensslSha256:this.#config.opensslSha256});
      await this.#live();
      const capability=await createLinuxNetworkCapability(this.#config.network,this.#config.executablePins,this.#flow);
      await this.#live();
      this.#network=await prepareRootNetwork(this.#config.network,capability);
      await this.#live();
      this.#material=await createRootTlsMaterial({runId:c.runId,startedAt:c.startedAt,deadline:c.deadline,
        opensslSha256:this.#config.opensslSha256},this.#tlsChild);
      await this.#live();
      await this.#network.verifyBeforeAdmission();await this.#live();
      const proxy=await this.#material.useForRootProxy(create);this.#proxy=proxy;
      await this.#live();this.#phase='READY';
      return Object.freeze({proxy,publicCertificate:this.#material.publicCertificate(),
        publicCertificateSha256:this.#material.publicCertificateSha256,network:this.#network});
    } catch {await this.#hold();throw new Error('Root wallet bootstrap uncertain; retain owned state for parent reconciliation');}
  }
  /** Browser/provider death is checked by actual parent flow. Root guardian remains alive. */
  async closeForParentCustodyCleanup():Promise<{proxy:DrainedProof;networkRemoved:true;rootGuardianDeathProven:false}> {
    const flow=this.#flow,network=this.#network,material=this.#material,proxy=this.#proxy;
    if (this.#phase!=='READY' || !flow || !network || !material || !proxy) refuse();
    this.#phase='CLOSING';
    try {
      await this.#live();await flow.assertOwnedCgroupDead(network.identity);
      const proof=await proxy.closeDrained();
      await network.closeAfterVerifiedDeath();
      await material.disposeAfterProxyAndChildDeath(async()=>{
        if (proof.listenerClosed!==true || proof.sockets!==0 || proof.outstandingRequests!==0) refuse();
      });
      this.#phase='PARENT_CUSTODY_CLEANUP_REQUIRED';
      return Object.freeze({proxy:proof,networkRemoved:true,rootGuardianDeathProven:false});
    } catch {await this.#hold();throw new Error('Root wallet cleanup uncertain; parent reconciliation required');}
  }
}
