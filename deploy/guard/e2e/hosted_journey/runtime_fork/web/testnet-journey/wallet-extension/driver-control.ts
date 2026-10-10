import { Socket } from "node:net";
import { fstatSync } from "node:fs";
import {
  Gate,
  Refused,
  exact,
  hash,
  refuse,
  type Config,
  type Journey,
} from "./driver-policy.ts";
export interface Command {
  schema: 1;
  runId: string;
  sequence: number;
  type: string;
  [key: string]: unknown;
}
const COMMON = ["schema", "runId", "sequence", "type"];
const KEYS: Record<string, readonly string[]> = {
  "public-admitted": [
    "configSha256",
    "deadline",
    "osEvidenceSha256",
    "sourceEvidenceSha256",
  ],
  "private-admitted": [
    "configSha256",
    "deadline",
    "noKeyEvidenceSha256",
    "namespaceEvidenceSha256",
    "proxyPrivatePolicySha256",
  ],
  baseline: ["role", "cap", "evidenceSha256"],
  "rejection-verified": [
    "exchangeAttempts",
    "heldBodies",
    "upstreamDispatches",
    "evidenceSha256",
  ],
  "permit-confirm": ["action", "typedDataSha256", "nonce", "expires"],
  "held-body": [
    "action",
    "bodySha256",
    "typedDataSha256",
    "signatureSha256",
    "owner",
    "builder",
    "rate",
    "nonce",
    "expires",
  ],
  "accepted-readback": ["action", "bodySha256", "cap", "evidenceSha256"],
  hold: ["reason"],
  close: [],
};
export function decodeCommand(
  line: string,
  runId: string,
  sequence: number,
): Command {
  if (Buffer.byteLength(line) > 8192) refuse("control");
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    refuse("control");
  }
  const type = (value as { type?: unknown })?.type;
  if (typeof type !== "string" || !Object.hasOwn(KEYS, type)) refuse("control");
  exact(value, [...COMMON, ...KEYS[type]!]);
  if (
    value.schema !== 1 ||
    value.runId !== runId ||
    value.sequence !== sequence ||
    JSON.stringify(value) !== line
  )
    refuse("control");
  for (const [key, item] of Object.entries(value))
    if (key.endsWith("Sha256") && !hash(item)) refuse("control");
  for (const [k, v] of Object.entries(value)) {
    if (
      ["deadline", "nonce", "expires"].includes(k) &&
      (!Number.isSafeInteger(v) || Number(v) <= 0)
    )
      refuse("control");
    if (k === "action" && v !== "approve" && v !== "restore") refuse("control");
    if (k === "rate" && v !== "0.02%" && v !== "0%") refuse("control");
    if (k === "owner" && v !== "0x0d708cfc4316b58f4ab00ee641a54baacc89cb14")
      refuse("control");
    if (
      k === "builder" &&
      (typeof v !== "string" || !/^0x[0-9a-f]{40}$/.test(v))
    )
      refuse("control");
    if (k === "role" && v !== "user") refuse("control");
    if (k === "cap" && v !== 0 && v !== 20) refuse("control");
    if (
      ["exchangeAttempts", "heldBodies", "upstreamDispatches"].includes(k) &&
      v !== 0
    )
      refuse("control");
  }
  return value as Command;
}
const EVENTS: Record<string, readonly string[]> = {
  "public-ready": ["configSha256"],
  "no-key-ui-ready": ["extensionId", "observationSha256", "version"],
  imported: ["owner"],
  connected: ["owner", "origin", "extensionId"],
  "rejection-observed": ["publicObservationSha256"],
  "prompt-ready": [
    "action",
    "typedDataSha256",
    "owner",
    "builder",
    "rate",
    "nonce",
  ],
  confirmed: ["action", "typedDataSha256"],
  "ui-cap-observed": ["cap"],
  hold: ["stage", "reason"],
  "context-closed": ["completedRoundtrip"],
};
export function encodeEvent(
  runId: string,
  sequence: number,
  type: string,
  fields: Record<string, unknown>,
): string {
  if (!Object.hasOwn(EVENTS, type)) refuse("control");
  exact(fields, EVENTS[type]!);
  for (const [k, v] of Object.entries(fields)) {
    if (k.endsWith("Sha256")) {
      if (!hash(v)) refuse("control");
    } else if (
      k === "owner" &&
      v !== "0x0d708cfc4316b58f4ab00ee641a54baacc89cb14"
    )
      refuse("control");
    else if (k === "origin" && v !== "https://staging.zunderlabs.com")
      refuse("control");
    else if (
      k === "extensionId" &&
      (typeof v !== "string" || !/^[a-p]{32}$/.test(v))
    )
      refuse("control");
    else if (
      k === "builder" &&
      (typeof v !== "string" || !/^0x[0-9a-f]{40}$/.test(v))
    )
      refuse("control");
    else if (k === "action" && v !== "approve" && v !== "restore")
      refuse("control");
    else if (k === "rate" && v !== "0.02%" && v !== "0%") refuse("control");
    else if (k === "nonce" && (!Number.isSafeInteger(v) || Number(v) < 0))
      refuse("control");
    else if (k === "cap" && v !== 0 && v !== 20) refuse("control");
    else if (k === "version" && v !== "0.94.11") refuse("control");
    else if (k === "completedRoundtrip" && typeof v !== "boolean")
      refuse("control");
    else if (
      k === "reason" &&
      ![
        "policy",
        "deadline",
        "control",
        "ui",
        "isolation",
        "source",
        "private-input",
        "upstream",
        "closed",
      ].includes(String(v))
    )
      refuse("control");
    else if (
      k === "stage" &&
      !/^(NEW|PUBLIC_ADMITTED|NO_KEY_READY|PRIVATE_ADMITTED|IMPORTED|CONNECTED|REJECTED_ZERO_WRITE|APPROVAL_HELD|APPROVAL_ACCEPTED_20|RESTORE_HELD|RESTORED_0|CLOSING|CLOSED)$/.test(
        String(v),
      )
    )
      refuse("control");
  }
  return JSON.stringify({ schema: 1, runId, sequence, type, ...fields }) + "\n";
}
export interface Control {
  receive: (type: string) => Promise<Command>;
  emit: (type: string, fields?: Record<string, unknown>) => Promise<void>;
  close: () => void;
}
/** Parent-spawned private descriptor; authentication is the externally reviewed OS capability. */
export function inheritedControl(config: Config, gate: Gate): Control {
  if (!fstatSync(3).isSocket()) refuse("control");
  const socket = new Socket({ fd: 3, readable: true, writable: true });
  let bytes = Buffer.alloc(0),
    received = 0,
    sent = 0,
    closed = false;
  const queue: Command[] = [];
  let waiter:
    | {
        type: string;
        resolve: (v: Command) => void;
        reject: (e: Refused) => void;
      }
    | undefined;
  const stop = () => {
    gate.hold("control");
    waiter?.reject(new Refused("control"));
    waiter = undefined;
    bytes.fill(0);
    socket.destroy();
  };
  socket.on("error", stop);
  socket.on("end", () => {
    if (!closed) stop();
  });
  socket.on("data", (chunk: Buffer) => {
    try {
      if (bytes.length + chunk.length > 16384) refuse("control");
      bytes = Buffer.concat([bytes, chunk]);
      for (;;) {
        const end = bytes.indexOf(10);
        if (end < 0) {
          if (bytes.length > 8192) refuse("control");
          break;
        }
        if (++received > 128) refuse("control");
        const line = new TextDecoder("utf-8", { fatal: true }).decode(
          bytes.subarray(0, end),
        );
        bytes = Buffer.from(bytes.subarray(end + 1));
        const command = decodeCommand(line, config.runId, received);
        if (
          command.type === "hold" ||
          (command.type === "close" && waiter?.type !== "close")
        ) {
          stop();
          return;
        }
        gate.check();
        if (waiter) {
          if (waiter.type !== command.type) refuse("control");
          const current = waiter;
          waiter = undefined;
          current.resolve(command);
        } else {
          if (queue.length >= 4) refuse("control");
          queue.push(command);
        }
      }
    } catch {
      stop();
    }
  });
  gate.onHold(() => {
    waiter?.reject(new Refused("control"));
    waiter = undefined;
    socket.destroy(); // Settles pending writes; EOF permanently disarms parent proxy.
  });
  return {
    receive(type) {
      gate.check();
      if (waiter) refuse("control");
      const existing = queue.shift();
      if (existing) {
        if (existing.type !== type) {
          stop();
          refuse("control");
        }
        return Promise.resolve(existing);
      }
      return new Promise<Command>((resolve, reject) => {
        waiter = { type, resolve, reject };
      });
    },
    async emit(type, fields = {}) {
      if (closed || !socket.writable || ++sent > 128) refuse("control");
      const line = encodeEvent(config.runId, sent, type, fields);
      if (Buffer.byteLength(line) > 8192) refuse("control");
      await new Promise<void>((resolve, reject) =>
        socket.write(line, (error) =>
          error ? reject(new Refused("control")) : resolve(),
        ),
      );
    },
    close() {
      closed = true;
      bytes.fill(0);
      socket.destroy();
    },
  };
}
export interface PrivateInput {
  schema: 1;
  purpose: "genuine-rabby-testnet-builder";
  runId: string;
  owner: string;
  ownerPrivateKey: string;
  vaultPassword: string;
}
export function validatePrivate(value: unknown, config: Config): PrivateInput {
  exact(value, [
    "schema",
    "purpose",
    "runId",
    "owner",
    "ownerPrivateKey",
    "vaultPassword",
  ]);
  if (
    value.schema !== 1 ||
    value.purpose !== config.purpose ||
    value.runId !== config.runId ||
    value.owner !== config.owner ||
    typeof value.ownerPrivateKey !== "string" ||
    !/^0x[0-9a-f]{64}$/.test(value.ownerPrivateKey) ||
    typeof value.vaultPassword !== "string" ||
    !/^[-_a-zA-Z0-9]{43}$/.test(value.vaultPassword)
  )
    refuse("private-input");
  return value as unknown as PrivateInput;
}
export async function privateStdin(
  config: Config,
  journey: Journey,
): Promise<PrivateInput> {
  if (journey.status().phase !== "PRIVATE_ADMITTED" || journey.gate.reason())
    refuse("private-input");
  journey.gate.check();
  const input = process.stdin;
  let pieces: Buffer[] = [];
  let size = 0;
  let settled = false;
  const raw = await new Promise<Buffer>((resolve, reject) => {
    let offHold = () => {};
    const timer = setTimeout(
      () => done(new Refused("private-input")),
      Math.min(5000, journey.gate.remaining()),
    );
    function cleanup() {
      offHold();
      clearTimeout(timer);
      input.off("data", data);
      input.off("end", end);
      input.off("error", error);
      input.pause();
    }
    function done(problem?: Refused) {
      if (settled) return;
      settled = true;
      cleanup();
      if (problem) {
        for (const b of pieces) b.fill(0);
        pieces = [];
        reject(problem);
      } else {
        const result = Buffer.concat(pieces);
        for (const b of pieces) b.fill(0);
        pieces = [];
        resolve(result);
      }
    }
    function data(chunk: Buffer) {
      size += chunk.length;
      if (size > 2048) {
        chunk.fill(0);
        done(new Refused("private-input"));
        return;
      }
      pieces.push(Buffer.from(chunk));
      chunk.fill(0);
    }
    function end() {
      done();
    }
    function error() {
      done(new Refused("private-input"));
    }
    offHold = journey.gate.onHold(() => done(new Refused("private-input")));
    if (!settled) {
      input.on("data", data);
      input.once("end", end);
      input.once("error", error);
    }
  });
  try {
    journey.gate.check();
    if (
      raw.length === 0 ||
      raw.at(-1) !== 10 ||
      raw.subarray(0, -1).includes(10)
    )
      refuse("private-input");
    let value: unknown;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(
        raw.subarray(0, -1),
      );
      value = JSON.parse(text);
      if (JSON.stringify(value) !== text) refuse("private-input");
    } catch {
      refuse("private-input");
    }
    return validatePrivate(value, config);
  } finally {
    raw.fill(0);
  }
}
