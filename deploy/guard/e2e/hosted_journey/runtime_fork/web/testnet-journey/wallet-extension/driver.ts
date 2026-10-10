import { pathToFileURL } from "node:url";
import {
  cleanEnvironment,
  validateConfig,
  Gate,
  sha,
  refuse,
} from "./driver-policy.ts";
import { bytes, verifySources, rootProcessPreflight } from "./driver-files.ts";
import { inheritedControl, privateStdin } from "./driver-control.ts";
import { runFlow } from "./driver-flow.ts";
import { GenuineUI } from "./driver-ui.ts";
/** Root must authenticate Node/import closure before launching this process. No private material at import. */
let invoked = false;
export async function main() {
  if (invoked) refuse("policy");
  invoked = true;
  cleanEnvironment();
  if (process.argv.length !== 3) refuse("policy");
  const raw = await bytes(process.argv[2]!, 16384);
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch {
    refuse("policy");
  }
  const config = validateConfig(value, Date.now()),
    gate = new Gate(config.startedAt, config.deadline);
  await gate.step(() => rootProcessPreflight(config));
  await verifySources(config, gate);
  const control = inheritedControl(config, gate),
    ui = new GenuineUI(config, gate);
  // No private reader exists until authenticated private-admitted arrives through the owned descriptor.
  return runFlow(
    config,
    sha(raw),
    control,
    ui,
    (journey) => privateStdin(config, journey),
    gate,
  );
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  // Never serialize a Playwright/crypto/parser error or an unhandled private promise.
  process.on("uncaughtException", () => {
    process.exitCode = 1;
    process.exit(1);
  });
  process.on("unhandledRejection", () => {
    process.exitCode = 1;
    process.exit(1);
  });
  void main().then(
    (result) => {
      process.exitCode = result.completedRoundtrip ? 0 : 1;
    },
    () => {
      process.exitCode = 1;
    },
  );
}
