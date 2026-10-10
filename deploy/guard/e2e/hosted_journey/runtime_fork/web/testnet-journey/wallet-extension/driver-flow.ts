import {
  Gate,
  Journey,
  OWNER,
  SITE,
  Refused,
  checkTyped,
  refuse,
  sha,
  type Config,
  type Reason,
} from "./driver-policy.ts";
import type { Control, PrivateInput, Command } from "./driver-control.ts";
export type Action = "approve" | "restore";
/** UI implementations contain ordinary locator operations only. Production creates GenuineUI. */
export interface WalletUI {
  prepare(): Promise<{ extensionId: string; observationSha256: string }>;
  import(input: PrivateInput): Promise<void>;
  configureNetwork(): Promise<void>;
  connect(): Promise<void>;
  prompt(action: "reject" | Action): Promise<void>;
  inspect(): Promise<string>;
  cancel(): Promise<void>;
  sign(): Promise<void>;
  confirm(): Promise<void>;
  rejected(): Promise<void>;
  cap(value: 0 | 20): Promise<void>;
  close(): Promise<void>;
}
export interface FlowResult {
  completedRoundtrip: boolean;
  reason: Reason | null;
}
function bind(command: Command, fields: Record<string, unknown>) {
  for (const [k, v] of Object.entries(fields))
    if (command[k] !== v) refuse("control");
}
/** One invocation only. Parent admissions are authenticated by the dedicated descriptor/OS boundary. */
const consumed = new WeakSet<Gate>();
export async function runFlow(
  inputConfig: Config,
  configSha256: string,
  control: Control,
  ui: WalletUI,
  readPrivate: (journey: Journey) => Promise<PrivateInput>,
  gate: Gate,
): Promise<FlowResult> {
  if (consumed.has(gate)) refuse("policy");
  consumed.add(gate);
  const config = structuredClone(inputConfig);
  if (gate.startedAt !== config.startedAt || gate.deadline !== config.deadline)
    refuse("policy");
  const journey = new Journey(gate);
  let complete = false;
  let closing: Promise<void> | undefined;
  const close = () =>
    (closing ??= ui.close().catch(() => {
      gate.hold("closed");
    }));
  const unsubscribe = gate.onHold(() => {
    void close();
  });
  const timer = setTimeout(
    () => gate.hold("deadline"),
    Math.max(1, config.deadline - Date.now()),
  );
  const emit = (type: string, fields: Record<string, unknown> = {}) =>
    gate.step(() => control.emit(type, fields));
  const receive = (type: string) => gate.step(() => control.receive(type));
  try {
    await emit("public-ready", { configSha256 });
    const pub = await receive("public-admitted");
    bind(pub, { configSha256, deadline: config.deadline });
    journey.advance("PUBLIC_ADMITTED");
    const ready = await gate.step(() => ui.prepare());
    if (
      !/^[a-p]{32}$/.test(ready.extensionId) ||
      !/^[0-9a-f]{64}$/.test(ready.observationSha256)
    )
      refuse("source");
    journey.advance("NO_KEY_READY");
    await emit("no-key-ui-ready", { ...ready, version: "0.94.11" });
    const admission = await receive("private-admitted");
    bind(admission, {
      configSha256,
      deadline: config.deadline,
      proxyPrivatePolicySha256: config.proxyPolicySha256,
    });
    journey.advance("PRIVATE_ADMITTED");
    let privateInput: PrivateInput | undefined = await gate.step(() =>
      readPrivate(journey),
    );
    try {
      await gate.step(() => ui.import(privateInput!));
    } finally {
      if (privateInput) {
        privateInput.ownerPrivateKey = "";
        privateInput.vaultPassword = "";
      }
      privateInput = undefined;
    }
    journey.advance("IMPORTED");
    await emit("imported", { owner: OWNER });
    const baseline = await receive("baseline");
    bind(baseline, { role: "user", cap: 0 });
    await gate.step(() => ui.configureNetwork());
    await gate.step(() => ui.connect());
    await gate.step(() => ui.cap(0));
    journey.advance("CONNECTED");
    await emit("connected", {
      owner: OWNER,
      origin: SITE,
      extensionId: ready.extensionId,
    });
    journey.attempt("reject");
    await gate.step(() => ui.prompt("reject"));
    const rejected = checkTyped(
      await gate.step(() => ui.inspect()),
      config.builder,
      "0.02%",
      config.startedAt,
      config.deadline,
      Date.now(),
    );
    journey.nonce(rejected.nonce);
    await gate.step(() => ui.cancel());
    await gate.step(() => ui.rejected());
    await emit("rejection-observed", {
      publicObservationSha256: sha("genuine-cancel:site-rejected:cap0"),
    });
    const counters = await receive("rejection-verified");
    bind(counters, {
      exchangeAttempts: 0,
      heldBodies: 0,
      upstreamDispatches: 0,
    });
    journey.advance("REJECTED_ZERO_WRITE");
    for (const action of ["approve", "restore"] as const) {
      const rate = action === "approve" ? "0.02%" : "0%";
      const cap = action === "approve" ? 20 : 0;
      journey.attempt(action);
      await gate.step(() => ui.prompt(action));
      const inspect = async () =>
        checkTyped(
          await gate.step(() => ui.inspect()),
          config.builder,
          rate,
          config.startedAt,
          config.deadline,
          Date.now(),
        );
      const prompt = await inspect();
      journey.nonce(prompt.nonce);
      await emit("prompt-ready", {
        action,
        typedDataSha256: prompt.typedDataSha256,
        owner: OWNER,
        builder: config.builder,
        rate,
        nonce: prompt.nonce,
      });
      const permit = await receive("permit-confirm");
      bind(permit, {
        action,
        typedDataSha256: prompt.typedDataSha256,
        nonce: prompt.nonce,
      });
      const permission = () => {
        gate.check();
        if (
          !Number.isSafeInteger(permit.expires) ||
          Number(permit.expires) > config.deadline ||
          Date.now() >= Number(permit.expires)
        )
          refuse("deadline");
      };
      permission();
      const beforeSign = await inspect();
      permission();
      if (beforeSign.typedDataSha256 !== prompt.typedDataSha256) refuse("ui");
      await gate.step(() => ui.sign());
      permission();
      const beforeConfirm = await inspect();
      permission();
      if (beforeConfirm.typedDataSha256 !== prompt.typedDataSha256)
        refuse("ui");
      await gate.step(() => ui.confirm());
      permission();
      await emit("confirmed", {
        action,
        typedDataSha256: prompt.typedDataSha256,
      });
      const held = await receive("held-body");
      bind(held, {
        action,
        typedDataSha256: prompt.typedDataSha256,
        owner: OWNER,
        builder: config.builder,
        rate,
        nonce: prompt.nonce,
      });
      if (
        !Number.isSafeInteger(held.expires) ||
        Number(held.expires) > config.deadline ||
        Date.now() >= Number(held.expires)
      )
        refuse("deadline");
      journey.advance(action === "approve" ? "APPROVAL_HELD" : "RESTORE_HELD");
      const accepted = await receive("accepted-readback");
      bind(accepted, { action, bodySha256: held.bodySha256, cap });
      await gate.step(() => ui.cap(cap));
      journey.advance(
        action === "approve" ? "APPROVAL_ACCEPTED_20" : "RESTORED_0",
      );
      await emit("ui-cap-observed", { cap });
    }
    complete = true;
    journey.advance("CLOSING");
    await receive("close");
  } catch (error) {
    gate.hold(error instanceof Refused ? error.reason : "ui");
    try {
      await control.emit("hold", {
        stage: journey.status().phase,
        reason: gate.reason()!,
      });
    } catch {}
  } finally {
    unsubscribe();
    // Context close cannot prove descendant death. Parent still must kill/read cgroup and remove tmpfs.
    let finished = false;
    let closeTimer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([
      close().then(() => {
        finished = true;
      }),
      new Promise<void>((r) => {
        closeTimer = setTimeout(r, 3000);
      }),
    ]);
    if (closeTimer) clearTimeout(closeTimer);
    try {
      gate.check();
    } catch {
      /* Original authority remains expired during cleanup. */
    }
    if (!finished) gate.hold("closed");
    complete = complete && !gate.reason();
    try {
      await control.emit("context-closed", { completedRoundtrip: complete });
    } catch {
      complete = false;
      gate.hold("control");
    }
    try {
      control.close();
    } catch {
      complete = false;
      gate.hold("control");
    } finally {
      clearTimeout(timer);
    }
  }
  return { completedRoundtrip: complete, reason: gate.reason() };
}
