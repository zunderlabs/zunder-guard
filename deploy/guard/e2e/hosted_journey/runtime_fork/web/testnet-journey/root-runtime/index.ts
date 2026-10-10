import {OriginalBackendDisposalAdmission} from './backend-disposal.ts';

export function backendDisposableSecrets(operation:'apply'|'dispose',tokens:{unsubscribe:string;issuer:string;inbox:string}){
  if(operation==='apply')return tokens;
  if(operation==='dispose')return null;
  return fail();
}
import {startOriginalBackend} from './backend-launch.ts';
import {assembleOriginalBackend as assembleBackend,type OriginalAssemblyInput} from '../../../../backend_successor/assembly-entry.ts';
import type {BuildInput} from '../../../../backend_successor/artifact-build.ts';
import type {Context} from '../../../../backend_successor/plan.ts';
import { escrowOriginalMerchant, originalInputCall } from './hosted-custody.ts';
import { randomBytes, createPrivateKey, createPublicKey } from "node:crypto";
import { createRequire } from "node:module";
import path from "node:path";
import { homedir } from "node:os";
import { performance } from "node:perf_hooks";
import { isDeepStrictEqual } from "node:util";
import {
  OWNER,
  SITE,
  OPT_IN,
  DENIED,
  OFFICIAL_KEY,
  Admission,
  cleanDiagnostics,
  validateConfig,
  exact,
  units,
  fail,
  type Config,
  type FileRef,
} from "./policy.ts";
import {
  sha,
  canonical,
  pinned,
  json,
  bytes,
  verifyTree,
  newLog,
} from "./files.ts";
import {
  startOwned,
  childEnvironment,
  memoryPreflight,
  guardedChildStdout,
  type OwnedChild,
} from "./child.ts";
import {
  ReturnAttempt,
  exclusiveCredit,
  canonicalToken,
  balance,
  ledger,
  returnData,
  venue,
  venueObserved,
  accepted,
} from "./return.ts";
import {validateFullReturn as validateReturn,reconcileFullBalances as reconcileBalances,paymentInterval,returnInterval,freshSnapshot,type FullBalanceReturnPolicy as ReturnPolicy,type FullSnapshot as Snapshot} from './full-return.ts';
import {originalReturnDispatch} from './hosted-custody.ts';
import { createCustodySafety } from "./safety.ts";
import { purchaseProof } from "./purchase.ts";
import {createPurchaseInputStore,PURCHASE_REGION,type PurchaseBinding,type PurchaseCleanupApproval} from './purchase-inputs.ts';
import {admitCompletionParent,type OriginalParentGate,type OriginalKeeperMetadata} from './completion-parent.ts';
import {readProtectedCompletionPipe} from './completion-pipe.ts';
import {parseCompletedPurchasePublication,type ProtectedPurchaseExpected,type ParsedPurchasePublication} from './protected-purchase.ts';
const localRoot = path.resolve(import.meta.dirname, "../../..");
const ROOT_FILES = [
  "index.ts",
  "policy.ts",
  "files.ts",
  "child.ts",
  "return.ts",
  "full-return.ts",
  "purchase.ts",
  "safety.ts",
  "purchase-inputs.ts",
  "completion-parent.ts",
  "completion-pipe.ts",
  "protected-purchase.ts",
  "hosted-custody.ts",
  "backend-disposal.ts",
  "backend-launch.ts",
].map((f) => "web/testnet-journey/root-runtime/" + f);
const PROVISION = [
  "policy.ts",
  "inspect.ts",
  "controller.ts",
  "cloudflare.ts",
  "run.ts",
  "artifacts.ts",
  "journal.ts",
  "pages-upload.ts",
  "lease.ts",
  "api.entry.ts",
  "inbox.entry.ts",
  "pages.entry.ts",
  "wallet-policy.ts",
  "draft-release.ts",
].map((f) => "web/testnet-journey/provision/" + f);
const WEBSITE_REQUIRED = [
  ...ROOT_FILES,
  ...PROVISION,
  "web/release-pin.ts",
  "deploy/licence/testnet-issuer/run.ts",
  "deploy/licence/testnet-issuer/issuer.ts",
  "deploy/licence/auto-issuer/issuer.ts",
  "web/site/package.json",
  "web/site/package-lock.json",
  "web/site/playwright.config.ts",
  "web/site/tests/real-testnet-purchase.spec.ts",
  "web/site/tests/testnet-payment-wallet.ts",
  "web/site/tests/testnet-inbox.ts",
  "web/site/tests/private-input-broker.ts",
  "web/site/tests/private-test-setup.ts",
  "web/site/tests/testnet-purchase-policy.ts",
  "web/site/src/lib/licence-wallet.ts",
  "web/site/src/lib/checkout.ts",
  "web/deployment-profile.ts",
];
const COORD_REQUIRED = [
  "run_testnet_provider.py",
  "run_producers.py",
  "release_flow.py",
  "private_broker_driver.mjs",
].map((f) => "deploy/guard/e2e/" + f);
interface ProvisionInput {
  plan: FileRef;
  approval: FileRef;
  artifactDirectory: string;
  artifactManifest: FileRef;
  controllerManifest: FileRef;
  journalDirectory: string;
}
interface PurchaseInput {
  setup: FileRef;
  outputDirectory: string;
}
let runtimeClaimed = false;
/** Root must import only a hash-reviewed copy using the pinned clean Node executable. */
export async function createRootRuntime(raw: Config, originalParentGate?:OriginalParentGate, originalKeeper?:OriginalKeeperMetadata) {
  if (runtimeClaimed) fail();
  runtimeClaimed = true;
  cleanDiagnostics();
  const config: Config = structuredClone(raw);
  validateConfig(config, Date.now());
  if (
    config.website.root !== localRoot ||
    (await canonical(config.home)) !== (await canonical(homedir())) ||
    (await canonical(process.execPath)) !== config.executables.node.file
  )
    fail();
  const admission = new Admission(config.expires, Date.now, () =>
    performance.now(), originalParentGate ? {clock: originalParentGate.clock} : undefined,
  );
  async function sourceCheck() {
    cleanDiagnostics();
    await verifyTree(config.website, WEBSITE_REQUIRED);
    await verifyTree(config.coordinator, COORD_REQUIRED);
    for (const e of Object.values(config.executables))
      await pinned(e, 200000000, false);

  }
  await sourceCheck();
  admission.check();
  await memoryPreflight(config, admission.deadline());
  admission.check();
  if(Boolean(originalParentGate)!==Boolean(originalKeeper))fail();
  // This actual probe completes before the existing generator touches randomness.
  const completionParent=originalParentGate&&originalKeeper
    ?await admitCompletionParent(originalParentGate,config,admission,originalKeeper):undefined;
  admission.check();
  const log = await newLog(config.evidenceDirectory);
  await log.append("runtime-claimed", {
    runId: config.runId,
    expires: config.expires,
  });
  admission.check();
  // Dependencies are reviewed installed lockfile prerequisites; no global package resolution.
  const { Wallet, Signature } = createRequire(
    path.join(config.website.root, "web/site/package.json"),
  )(
    "ethers",
  ) as typeof import("../../site/node_modules/ethers/lib.esm/index.js");
  const order = BigInt(
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  );
  let merchantKey: Buffer | null = null;
  let merchantWallet: InstanceType<typeof Wallet> | null = null;
  for (let attempt = 0; attempt < 8; attempt++) {
    const candidate = randomBytes(32),
      n = BigInt("0x" + candidate.toString("hex"));
    if (n > 0n && n < order) {
      merchantKey = candidate;
      merchantWallet = new Wallet("0x" + candidate.toString("hex"));
      break;
    }
    candidate.fill(0);
  }
  if (!merchantWallet || !merchantKey) fail();
  const merchant = merchantWallet.address.toLowerCase();
  if (DENIED.includes(merchant)) fail();
  // Durable create-only account + original version1 custody ACK precede any funding.
  const custodyBinding=await escrowOriginalMerchant(config, admission, merchant, merchantKey);
  let backendDisposal:OriginalBackendDisposalAdmission|undefined;
  let backendInput:{context:Context;priorBaseline:FileRef;cloudflareBearer:string;protectedSiteAccess:{clientId:string;clientSecret:string}}|undefined;
  let ownedBackendJournal:FileRef|undefined;
  admission.check();
  let seed: Buffer | null = randomBytes(32);
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed,
  ]);
  const ed = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  der.fill(0);
  const publicKey = createPublicKey(ed)
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("hex");
  if (publicKey === OFFICIAL_KEY) fail();
  let tokens: { unsubscribe: string; issuer: string; inbox: string } | null = {
    unsubscribe: randomBytes(32).toString("base64url"),
    issuer: randomBytes(32).toString("base64url"),
    inbox: randomBytes(32).toString("base64url"),
  };
  if (new Set(Object.values(tokens)).size !== 3) fail();
  let disposed = false,
    cloudApplyAttempted = false,
    cloudProvisioned = false,
    cloudClean = false,
    purchaseLaunched = false,
    paymentProven = false,
    returnProven = false,
    noPaymentProven = false,
    issuerDone = false;
  let assembledInput: ProvisionInput | undefined;
  let assemblyAttempted=false;
  let planInput: ProvisionInput | undefined,
    armed: ReturnPolicy | undefined,
    before: Snapshot | undefined,
    returnNonce: number | undefined,
    purchaseInput: PurchaseInput | undefined;
  const returnAttempt = new ReturnAttempt();
  let storedPurchaseBinding:Readonly<PurchaseBinding>|undefined;
  let completionClaimed=false;
  let completedPublication:Readonly<ParsedPurchasePublication>|undefined;
  let completedFrameSha256:string|undefined;
  // A live handle deliberately retains custody after finite write admission expires.
  const custodyKeepalive = setInterval(() => {}, 60000);
  const children = new Map<string, OwnedChild>();
  let stopPromise: Promise<void> | undefined;
  const ensure = () => {
    if (disposed || !merchantWallet || !tokens || !seed) fail();
  };
  async function checkpoint(kind: string, data: Record<string, unknown> = {}) {
    await log.append(kind, data);
  }
  const safety = createCustodySafety(admission, {
    hasChildren: () => children.size > 0,
    cleanupComplete: () => (!cloudApplyAttempted || cloudClean) && !purchaseStore.state().unresolved,
    stopChildren,
    readEmpty: proveEmpty,
    readReturned: reconcile,
  });
  async function hold(unknown = true) {
    safety.hold(unknown);
    await checkpoint("readonly-hold", {
      unknown: admission.status().unknown,
      custodyRetained: true,
    });
  }
  async function stopChildren() {
    if (stopPromise) return stopPromise;
    stopPromise = (async () => {
      // Signal every owned group before waiting for any one group to terminate.
      const outcomes = await Promise.allSettled(
        [...children].map(async ([kind, child]) => {
          const result = await child.stop();
          result.stdout.fill(0);
          if (result.forced || !result.groupGone) await hold();
          await checkpoint("child-stopped", {
            kind,
            pid: child.pid,
            groupGone: result.groupGone,
          });
          if (result.groupGone) children.delete(kind);
        }),
      );
      if (outcomes.some((result) => result.status === "rejected")) fail();
    })();
    try {
      await stopPromise;
    } finally {
      stopPromise = undefined;
    }
  }
  let deadlineTimer = setTimeout(
    () => {
      admission.hold();
      void stopChildren()
        .then(() =>
          checkpoint("custody-open", {
            reason: "admission-expired",
            retained: true,
          }),
        )
        .catch(() => {
          safety.hold(true);
        });
    },
    Math.max(1, config.expires - Date.now()),
  );
  async function execute(
    kind: string,
    args: string[],
    input: Buffer,
    executable = config.executables.node.file,
    deadline = admission.deadline(),
    guard: () => void = () => admission.check(),
  ) {
    try {
      guard();
      await sourceCheck();
      guard();
    } catch {
      input.fill(0);
      throw new Error("Root testnet child admission refused");
    }
    const child = startOwned(
      executable,
      args,
      config.website.root,
      childEnvironment(config),
      input,
      deadline,
      process.kill.bind(process),
      undefined,
      (kind === "provision" || kind === "cleanup") ? true : undefined,
    );
    children.set(kind, child);
    await checkpoint("child-started", { kind, pid: child.pid });
    return child;
  }
  async function completed(kind: string, child: OwnedChild) {
    const result = await child.done;
    try {
      if (result.groupGone) children.delete(kind);
      await checkpoint("child-finished", {
        kind, code: result.code, forced: result.forced,
        bounded: result.bounded, groupGone: result.groupGone,
      });
      if (result.code !== 0 || result.forced || !result.bounded || !result.groupGone) {
        await hold(); fail();
      }
      return result;
    } catch {
      result.stdout.fill(0); fail();
    }
  }
  async function invocation<T>(
    kind: string,
    action: () => Promise<T>,
    readOnly = false,
  ) {
    ensure();
    admission.enter(kind, readOnly);
    try {
      return await action();
    } catch {
      await hold();
      if (children.size) await stopChildren();
      fail();
    } finally {
      admission.leave();
    }
  }
  const purchaseStore=createPurchaseInputStore({runId:config.runId,startedAt:config.startedAt,merchant,issuerPublicKey:publicKey},admission,{
    checkpoint,
    async execute(kind,service,action,input,deadline,guard){
      return originalInputCall(config, admission, kind, service, action, input, deadline, guard);
    },
  });
  async function checkedProvision(input: ProvisionInput, cleanup = false) {
    exact(input, [
      "plan",
      "approval",
      "artifactDirectory",
      "artifactManifest",
      "controllerManifest",
      "journalDirectory",
    ]);
    await canonical(input.artifactDirectory);
    const [p, a, m, c] = await Promise.all([
      json(input.plan),
      json(input.approval),
      json(input.artifactManifest),
      json(input.controllerManifest),
    ]);
    if (
      p.version !== 2 ||
      !Number.isSafeInteger(p.end) ||
      p.end > config.expires ||
      p.start < config.startedAt ||
      a.planHash !== sha(JSON.stringify(p)) ||
      a.artifactManifestSha256 !== sha(JSON.stringify(m)) ||
      a.controllerManifestSha256 !== sha(JSON.stringify(c)) ||
      m.merchant !== merchant ||
      m.publicKey !== publicKey ||
      (!cleanup && a.expires > config.expires)
    )
      fail();
    return { p, a, m };
  }
  async function executeBackend(operation:'apply'|'dispose',input:ProvisionInput){
    if(!originalParentGate||!originalKeeper||!backendInput||!tokens||!planInput)fail();
    const guard=operation==='apply'?()=>admission.check():()=>backendDisposal!.check();guard();
    if(operation==='dispose'&&(!backendDisposal||!ownedBackendJournal
      ||ownedBackendJournal.sha256!==backendDisposal.continuation.ownedJournalSha256))fail();
    const end=Math.min(originalParentGate.deadline,originalParentGate.startedAt+1200000);
    const clock={...originalParentGate.clock,deadlineMonoNs:String(BigInt(originalParentGate.clock.originMonoNs)+BigInt(end)*1000000n-BigInt(originalParentGate.clock.originWallNs))};
    const bootstrap=Buffer.from(JSON.stringify({schema:1,kind:'original-retained-pages-child',keeperRunId:config.runId,
      context:backendInput.context,clock,parentDeadlineMs:end,planSha256:input.plan.sha256,priorBaseline:backendInput.priorBaseline,
      cloudflareBearer:backendInput.cloudflareBearer,protectedSiteAccess:backendInput.protectedSiteAccess,disposableSecrets:backendDisposableSecrets(operation,tokens)}));
    const child=await startOriginalBackend(config,originalParentGate,originalKeeper,operation,
      [operation,input.plan.file,input.approval.file,input.artifactDirectory,input.artifactManifest.file,input.controllerManifest.file,input.journalDirectory],
      input.plan,bootstrap,operation==='dispose'?backendDisposal!.continuation:null,guard,
      operation==='dispose'?backendDisposal!.deadline():admission.deadline());
    const kind=operation==='apply'?'provision':'cleanup';children.set(kind,child);guard();
    const result=await completed(kind,child);
    try{
      guard();const r=JSON.parse(result.stdout.toString());
      exact(r,operation==='apply'?['mode','completed','unresolvedOutcomeCount','journal']:['mode','completed','unresolvedOutcomeCount']);
      if(r.mode!==operation||r.completed!==true||r.unresolvedOutcomeCount!==0)fail();
      if(operation==='apply'){
        exact(r.journal,['file','sha256']);if(r.journal.file!==path.join(input.journalDirectory,'owned.json')||typeof r.journal.sha256!=='string'||!/^[0-9a-f]{64}$/.test(r.journal.sha256))fail();
        const owned:FileRef={file:r.journal.file as string,sha256:r.journal.sha256};await pinned(owned);guard();ownedBackendJournal=Object.freeze(owned);
      }
    }finally{result.stdout.fill(0);}
  }
  async function inspectAccounts(
    p: ReturnPolicy,
    deadline: number,
    verifyPayment: boolean,
  ): Promise<Snapshot> {
    const monoStartNs=String(process.hrtime.bigint()),time=Date.now(),observations:unknown[]=[];
    const read=async(body:unknown)=>{const observed=await venueObserved('/info',body,deadline);
      observations.push({requestSha256:sha(JSON.stringify(body)),responseSha256:observed.responseSha256,observedAt:observed.observedAt});
      return observed.value;};
    const token=canonicalToken(await read({type:'spotMeta'}));if(token!==p.token)fail();
    const inventory=await read({type:'perpDexs'});
    if(!Array.isArray(inventory)||inventory.length<1||inventory.length>32||inventory[0]!==null)fail();
    const dexes=[''];for(const row of inventory.slice(1)){
      if(typeof row?.name!=='string'||!/^[a-z][a-z0-9_-]{0,31}$/.test(row.name)||dexes.includes(row.name))fail();dexes.push(row.name);
    }
    const accounts=new Map<string,ReturnType<typeof balance>>();
    for(const user of[merchant,OWNER]){
      if((await read({type:'userRole',user}))?.role!=='user'||await read({type:'userAbstraction',user})!=='disabled')fail();
      const agents=await read({type:'extraAgents',user});if(!Array.isArray(agents)||agents.length!==0)fail();
      const spot=await read({type:'spotClearinghouseState',user});
      if(!Array.isArray(spot?.balances)||spot.balances.length>64)fail();
      const seen=new Set<number>();for(const row of spot.balances){
        if(!Number.isSafeInteger(row?.token)||row.token<0||seen.has(row.token)||units(row.total)!==0n||units(row.hold)!==0n)fail();seen.add(row.token);
      }
      for(const dex of dexes){
        const orders=await read({type:'openOrders',user,dex});if(!Array.isArray(orders)||orders.length!==0)fail();
        const actual=balance(await read({type:'clearinghouseState',user,dex}));
        if(units(actual.accountValue)!==units(actual.withdrawable)||(dex!==''&&units(actual.accountValue)!==0n))fail();
        if(dex==='')accounts.set(user,actual);
      }
    }
    const completedAt=Date.now(),endTime=completedAt;
    for(const user of[merchant,OWNER]){
      for(const type of['userFillsByTime','userFunding']){
        const events=await read({type,user,startTime:config.startedAt,endTime,...(type==='userFillsByTime'?{aggregateByTime:false}:{})});
        if(!Array.isArray(events)||events.length!==0)fail();
      }
    }
    const merchantLedger=await read({type:'userNonFundingLedgerUpdates',user:merchant,startTime:config.startedAt,endTime});
    const ownerLedger=await read({type:'userNonFundingLedgerUpdates',user:OWNER,startTime:config.startedAt,endTime});
    if(verifyPayment){paymentInterval(merchantLedger,p,Date.now());paymentInterval(ownerLedger,p,Date.now());}
    if(!isDeepStrictEqual(await read({type:'perpDexs'}),inventory))fail();
    return {merchant:accounts.get(merchant)!,owner:accounts.get(OWNER)!,time,paymentHash:p.paymentHash,token,
      completedAt:Date.now(),monoStartNs,monoEndNs:String(process.hrtime.bigint()),merchantLedger,ownerLedger,observations,observationsSha256:sha(JSON.stringify(observations))};
  }
  async function checkReturn(p: ReturnPolicy) {
    ensure();
    admission.check();
    validateReturn(p, merchant, config.runId, admission.deadline(), Date.now());
  }
  async function reconcile() {
    ensure();
    if (!armed || !before || returnNonce === undefined) fail();
    const p = armed,
      deadline = Date.now() + 15000;
    let outcome: Record<string, unknown> | undefined;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const after=await inspectAccounts(p,deadline,false);
        const merchantHash=returnInterval(after.merchantLedger,p,returnNonce,after.completedAt),
          ownerHash=returnInterval(after.ownerLedger,p,returnNonce,after.completedAt);
        if(merchantHash!==ownerHash)fail();
        const amounts=reconcileBalances(before,after,p);
        outcome={hash:merchantHash,...amounts};
        break;
      } catch {
        if (attempt < 2) await new Promise((r) => setTimeout(r, 250));
      }
    }
    if (!outcome) {
      await hold();
      fail();
    }
    // The first proof grants a state transition after asynchronous public reads:
    // recheck the inherited cutoff before granting it. Already-proved returns
    // may still be reconciled read-only for retained custody/disposal.
    if (!returnProven) admission.check();
    returnProven = true;
    await checkpoint("return-proven", outcome);
  }
  async function proveEmpty() {
    if (children.size) fail();
    admission.hold();
    const deadline = Date.now() + 15000;
    const actual = balance(
      await venue(
        "/info",
        { type: "clearinghouseState", user: merchant },
        deadline,
      ),
    );
    const spot = await venue(
      "/info",
      { type: "spotClearinghouseState", user: merchant },
      deadline,
    );
    const rows = await venue(
      "/info",
      {
        type: "userNonFundingLedgerUpdates",
        user: merchant,
        startTime: config.startedAt,
      },
      deadline,
    );
    if (
      units(actual.accountValue) !== 0n ||
      units(actual.withdrawable) !== 0n ||
      !Array.isArray(spot?.balances) ||
      spot.balances.some(
        (b: unknown) =>
          !b ||
          typeof b !== "object" ||
          units((b as { total?: unknown }).total) !== 0n,
      ) ||
      !Array.isArray(rows) ||
      rows.length !== 0
    )
      fail();
    noPaymentProven = true;
    await checkpoint("merchant-empty-proven", {
      merchant,
      received: false,
    });
  }
  return Object.freeze({
    assertOriginalAssemblyAuthority: () => { ensure(); admission.check(); if (returnProven || completedPublication || admission.status().unknown) fail(); },
    assertOriginalReturnAuthority: () => { ensure(); admission.check(); if (!returnProven || !completedPublication || admission.status().unknown) fail(); },
    completedPurchasePublic: () => { ensure(); admission.check(); if (!completedPublication) fail(); return structuredClone(completedPublication.publication.purchase); },
    publicIdentity: () =>
      Object.freeze({
        runId: config.runId,
        merchant,
        publicKey,
        originalExpires: config.expires,
        expires: admission.deadline(),
      }),
    status: () =>
      Object.freeze({
        ...admission.status(),
        ...safety.status(),
        disposed,
        custodyRetained: !disposed,
        cloudApplyAttempted,
        cloudProvisioned,
        cloudClean,
        purchaseLaunched,
        paymentProven,
        returnProven,
        noPaymentProven,
        issuerDone,
        completionClaimed,
        protectedCompletionReceived:Boolean(completedPublication),
        purchaseInputs: purchaseStore.state(),
        children: [...children.keys()],
      }),
    assembleOriginalBackend: async (raw:unknown)=>{
      ensure();admission.check();if(!completionParent||!originalParentGate||backendInput||cloudApplyAttempted||assemblyAttempted)fail();
      assemblyAttempted=true;
      try{
        exact(raw,['build','priorBaseline','readTarget','cloudflareBearer','protectedSiteAccess']);
        exact(raw.build,['website','tools','executable','releasePin','outputParent']);
        exact(raw.priorBaseline,['file','sha256']);exact(raw.protectedSiteAccess,['clientId','clientSecret']);
        if(!isDeepStrictEqual(raw.build.executable,config.executables.node)
          ||typeof raw.cloudflareBearer!=='string'||!/^[A-Za-z0-9._-]{16,1024}$/.test(raw.cloudflareBearer)
          ||typeof raw.protectedSiteAccess.clientId!=='string'||!/^[A-Za-z0-9._-]{16,256}$/.test(raw.protectedSiteAccess.clientId)
          ||typeof raw.protectedSiteAccess.clientSecret!=='string'||!/^[A-Za-z0-9._-]{32,256}$/.test(raw.protectedSiteAccess.clientSecret))fail();
        await sourceCheck();admission.check();
        const context={run_id:String(originalParentGate.controller.runNumber),attempt:originalParentGate.controller.attempt,
          binding_sha256:custodyBinding,started_ms:config.startedAt,deadline_ms:admission.deadline()};
        const staticBuild=raw.build as unknown as Omit<BuildInput,'context'|'identity'>;
        const prior=raw.priorBaseline as unknown as FileRef;
        const access=raw.protectedSiteAccess as unknown as OriginalAssemblyInput['protectedSiteAccess'];
        const result=await assembleBackend({build:{...structuredClone(staticBuild),context,identity:{merchant,publicKey}},
          priorBaseline:structuredClone(prior),readTarget:structuredClone(raw.readTarget) as OriginalAssemblyInput['readTarget'],
          cloudflareBearer:raw.cloudflareBearer,protectedSiteAccess:structuredClone(access)},admission,originalParentGate.clock,config.runId);
        admission.check();await sourceCheck();admission.check();
        backendInput={context:structuredClone(result.context),priorBaseline:structuredClone(prior),
          cloudflareBearer:raw.cloudflareBearer,protectedSiteAccess:structuredClone(access)};
        assembledInput=structuredClone(result.provision);return structuredClone(result);
      }catch{admission.hold(true);fail();}
    },
    admitOriginalBackendDisposal: (continuation:unknown,ready:{runId:string;returnProofSha256:string;planSha256:string})=>{
      ensure();admission.check();
      if(!originalParentGate||!returnProven||!completedPublication||children.size||backendDisposal||!planInput
       ||ready.planSha256!==planInput.plan.sha256)fail();
      backendDisposal=OriginalBackendDisposalAdmission.fromOriginalPipe(continuation,ready,originalParentGate,admission,custodyBinding);
      if(!ownedBackendJournal||ownedBackendJournal.sha256!==backendDisposal.continuation.ownedJournalSha256)fail();
      clearTimeout(deadlineTimer);
      deadlineTimer=setTimeout(()=>{backendDisposal?.hold();void stopChildren().catch(()=>safety.hold(true));},
       Math.max(1,backendDisposal.deadline()-Date.now()));
    },
    provision: (rawInput: ProvisionInput) => {
      const input = structuredClone(rawInput);
      return invocation("provision", async () => {
        if(!assembledInput||!isDeepStrictEqual(input,assembledInput))fail();
        const verified = await checkedProvision(input);
        admission.check();
        admission.tighten(verified.p.end);
        clearTimeout(deadlineTimer);
        deadlineTimer = setTimeout(
          () => {
            admission.hold();
            void stopChildren().catch(() => safety.hold(true));
          },
          Math.max(1, admission.deadline() - Date.now()),
        );
        planInput = structuredClone(input);
        cloudApplyAttempted = true;
        if(!backendInput||!isDeepStrictEqual(verified.p.context,backendInput.context))fail();
        await executeBackend('apply',input);
        cloudProvisioned = true;
        admission.check();
      });
    },
    storePurchaseInputs: (bindingRef: FileRef) => {
      const ref=structuredClone(bindingRef);
      return invocation('store-purchase-inputs',async()=>{
        if(!cloudProvisioned||children.has('issuer')||purchaseLaunched||issuerDone)fail();
        const binding=await json(ref) as PurchaseBinding;admission.check();
        const values=[Buffer.from(tokens!.issuer),Buffer.from(tokens!.inbox),Buffer.from('0x'+seed!.toString('hex'))];
        try{await purchaseStore.store(binding,ref.sha256,values);admission.check();
          storedPurchaseBinding=Object.freeze(structuredClone(binding));}
        finally{for(const value of values)value.fill(0);}
      });
    },
    cleanupPurchaseInputs: (bindingRef: FileRef,approvalRef: FileRef) => {
      const ref=structuredClone(bindingRef),approval=structuredClone(approvalRef);
      return invocation('cleanup-purchase-inputs',async()=>{
        if(children.size)fail();
        await sourceCheck();
        const binding=await json(ref) as PurchaseBinding,approved=await json(approval) as PurchaseCleanupApproval;
        await purchaseStore.cleanup(binding,ref.sha256,approved);
      },true);
    },
    receiveCompletedPurchasePublication:(rawExpected:ProtectedPurchaseExpected)=>{
      const expected=structuredClone(rawExpected);
      return invocation('protected-purchase-completion',async()=>{
        if(completionClaimed||!completionParent||!storedPurchaseBinding||children.size||purchaseLaunched||issuerDone)fail();
        // Consume before the first await. A failed/uncertain receive has no retry
        // or saved-file fallback, and retains the existing merchant custody.
        completionClaimed=true;purchaseLaunched=true;
        const gate=completionParent.binding;
        if(expected.challenge!==gate.challenge||!isDeepStrictEqual(expected.controller,gate.controller)
          ||expected.runId!==config.runId||expected.startedAt!==config.startedAt
          ||expected.deadline!==admission.deadline()||expected.deadline>gate.deadline
          ||expected.owner!==OWNER||expected.merchant!==merchant
          ||!isDeepStrictEqual(expected.purchaseBinding,storedPurchaseBinding)
          ||storedPurchaseBinding.issuerPublicKey!==publicKey)fail();
        await sourceCheck();admission.check();
        await completionParent.recheckBeforeReceive();admission.check();
        const frame=await readProtectedCompletionPipe(gate.pipe,admission);
        try{
          const parsed=parseCompletedPurchasePublication(frame,expected,Date.now());
          admission.check();
          await checkpoint('protected-purchase-completion-received',{
            canonicalSha256:parsed.canonicalSha256,frameSha256:sha(frame),
            purchaseSha256:parsed.publication.purchase.purchaseSha256,
            paymentHeldSha256:parsed.publication.purchase.paymentHeldSha256,
            ledgerHash:parsed.publication.purchase.ledgerHash,
          });
          admission.check();
          completedFrameSha256=sha(frame);completedPublication=parsed;issuerDone=true;
          return parsed;
        }finally{frame.fill(0);}
      });
    },
    async stopChildren() {
      safety.hold(true);
      await stopChildren();
    },
    armReturn: (rawPolicy: ReturnPolicy) =>
      invocation("arm-return", async () => {
        if (children.size || (!purchaseInput&&!completedPublication) || !issuerDone) fail();
        const p: ReturnPolicy = structuredClone(rawPolicy);
        await checkReturn(p);
        const receipt = await pinned(p.purchaseReceipt);
        let proof:{paymentHash:string;amount:string;token:string;nonce:number};
        if(completedPublication){
          // The receipt file only corroborates bytes already consumed from the
          // admitted live pipe; it cannot manufacture completion authority.
          if(!completedFrameSha256||sha(receipt)!==completedFrameSha256)fail();
          const p=completedPublication.publication.purchase;
          proof={paymentHash:p.ledgerHash,amount:p.amount,token:p.token,nonce:p.nonce};
        }else{
        if (
          p.purchaseReceipt.file !==
          path.join(purchaseInput!.outputDirectory, "actual-stage.jsonl")
        )
          fail();
        const report = JSON.parse(
          (
            await bytes(
              path.join(purchaseInput!.outputDirectory, "result.json"),
              65536,
            )
          ).toString(),
        );
        proof = purchaseProof(receipt, report, {
          runId: config.runId,
          merchant,
          startedAt: config.startedAt,
          now: Date.now(),
        });
        }
        if (
          proof.paymentHash !== p.paymentHash ||
          proof.amount !== p.paidUsdc ||
          proof.token !== p.token ||
          p.paymentAfter !== proof.nonce
        )
          fail();
        await checkReturn(p);
        const snapshot = await inspectAccounts(p, p.expires, true);
        await checkReturn(p);
        freshSnapshot(snapshot,Date.now(),process.hrtime.bigint());
        if(units(snapshot.merchant.accountValue)!==units(p.amount)||units(snapshot.merchant.withdrawable)!==units(p.amount)
          ||units(snapshot.owner.accountValue)!==units(p.ownerInitialUsdc)-units(p.amount))fail();
        armed = Object.freeze(p);
        before = snapshot;
        paymentProven = true;
        await checkpoint("return-armed", {
          amount: p.amount,
          policy: p.policy,
          signedAmountLimitUsdc: p.signedAmountLimitUsdc,
          token: p.token,
          paymentHash: p.paymentHash,
          expires: p.expires,
          merchantBalance: snapshot.merchant,
          beforeReadbacksSha256:snapshot.observationsSha256,
        });
        await checkReturn(p);
      }),
    returnOnce: () =>
      invocation("return", async () => {
        if (!armed || !before || children.size) fail();
        const p = armed;
        await checkReturn(p);
        await sourceCheck();
        await checkReturn(p);
        const current = await inspectAccounts(p, p.expires, true);
        await checkReturn(p);
        freshSnapshot(current,Date.now(),process.hrtime.bigint());
        if (
          current.merchant.accountValue !== before.merchant.accountValue ||
          current.owner.accountValue !== before.owner.accountValue ||
          current.owner.withdrawable !== before.owner.withdrawable ||
          current.merchant.withdrawable !== before.merchant.withdrawable
        )
          fail();
        returnNonce = Date.now();
        const data = returnData(p, returnNonce);
        await returnAttempt.execute(data, {
          check: () => {
            admission.check();
            freshSnapshot(current,Date.now(),process.hrtime.bigint());
            validateReturn(
              p,
              merchant,
              config.runId,
              admission.deadline(),
              Date.now(),
            );
            if (Date.now() - returnNonce! > 10000 || Date.now() < returnNonce!)
              fail();
          },
          intent: async () => {
            await originalReturnDispatch(config,admission,p,returnNonce!,data,()=>admission.check());
            await checkpoint("return-consumed", {merchant,destination:OWNER,amount:p.amount,token:p.token,nonce:returnNonce});
          },
          sign: async (typed) =>
            merchantWallet!.signTypedData(
              typed.domain,
              typed.types,
              typed.message,
            ),
          send: async (signature) => {
            const { r, s, v } = Signature.from(signature);
            return venue(
              "/exchange",
              {
                action: {
                  type: "sendAsset",
                  signatureChainId: "0x66eee",
                  ...data.message,
                },
                nonce: returnNonce,
                signature: { r, s, v },
              },
              p.expires,
            );
          },
        });
        await checkpoint("return-accepted");
        await reconcile();
      }),
    reconcileEmptyMerchant: () =>
      invocation("reconcile-empty", () => safety.proveEmpty(), true),
    reconcileReturn: () => invocation("reconcile-return", reconcile, true),
    cleanup: (rawInput: ProvisionInput, originalJournal: string) => {
      const input = structuredClone(rawInput);
      return invocation(
        "cleanup",
        async () => {
          if (
            children.size ||
            !planInput ||
            originalJournal !== planInput.journalDirectory
          )
            fail();
          if(!backendDisposal)fail();backendDisposal.assertDispose('dispose',input.plan.sha256);
          await sourceCheck();backendDisposal.check();
          await checkedProvision(input, true);backendDisposal.check();
          if (
            input.plan.sha256 !== planInput.plan.sha256 ||
            input.artifactManifest.sha256 !==
              planInput.artifactManifest.sha256 ||
            input.controllerManifest.sha256 !==
              planInput.controllerManifest.sha256 ||
            input.artifactDirectory !== planInput.artifactDirectory
          )
            fail();
          backendDisposal.check();await executeBackend('dispose',input);backendDisposal.check();
          backendInput!.cloudflareBearer='';backendInput!.protectedSiteAccess={clientId:'',clientSecret:''};
          cloudClean = true;
          await checkpoint("cloud-cleaned");
        },
        true,
      );
    },
    async dispose() {
      ensure();
      if (
        admission.status().busy ||
        children.size ||
        (!returnProven && !noPaymentProven) ||
        (cloudApplyAttempted && !cloudClean) ||
        purchaseStore.state().unresolved ||
        (purchaseLaunched && !returnProven && !noPaymentProven) ||
        (admission.status().unknown && !returnProven && !noPaymentProven)
      )
        fail();
      admission.enter("dispose", true);
      // Close every ordinary admission and read final balances again after cleanup.
      // A prior proof boolean is not permission to destroy custody.
      admission.hold();
      try {
        await safety.beforeDispose(returnProven);
      } catch {
        admission.leave();
        await hold();
        fail();
      }
      clearTimeout(deadlineTimer);
      await checkpoint("custody-disposed", {
        returnProven,
        noPaymentProven,
        cloudClean,
      });
      merchantWallet = null;
      merchantKey?.fill(0);
      merchantKey = null;
      seed?.fill(0);
      seed = null;
      tokens = null;
      disposed = true;
      clearInterval(custodyKeepalive);
      admission.leave();
      await log.close();
    },
  });
}
