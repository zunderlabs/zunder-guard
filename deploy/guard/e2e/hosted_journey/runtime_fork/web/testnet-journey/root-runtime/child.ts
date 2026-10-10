import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import { fail, type Config } from "./policy.ts";
export interface ChildResult {
  code: number | null;
  signal: string | null;
  stdout: Buffer;
  bounded: boolean;
  groupGone: boolean;
  forced: boolean;
}
export interface OwnedChild {
  pid: number;
  done: Promise<ChildResult>;
  stop: () => Promise<ChildResult>;
}
/** A completion can arrive after original authority expired. Do not strand its
 * output outside the consumer's wiping finally when the post-child guard fails. */
export function guardedChildStdout(output: Buffer, guard: () => void): Buffer {
  try { guard(); return output; }
  catch { output.fill(0); throw new Error('Root testnet child admission refused'); }
}
export function childEnvironment(c: Config): NodeJS.ProcessEnv {
  return {
    PATH:
      path.dirname(c.executables.node.file) + ":/usr/bin:/bin:/usr/sbin:/sbin",
    HOME: c.home,
    PYTHONDONTWRITEBYTECODE: "1",
    AWS_CONFIG_FILE: "/dev/null",
    AWS_SHARED_CREDENTIALS_FILE: "/dev/null",
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_MAX_ATTEMPTS: "1",
    AWS_RETRY_MODE: "standard",
    AWS_PAGER: "",
    AWS_CLI_AUTO_PROMPT: "off",
    WRANGLER_SEND_METRICS: "false",
    WRANGLER_LOG: "error",
    ASTRO_TELEMETRY_DISABLED: "1",
    PLAYWRIGHT_NO_COPY_PROMPT: "1",
  };
}
const wait = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
export type ProcessSignal = (
  pid: number,
  signal: NodeJS.Signals | 0,
) => boolean;
export function startOwned(
  executable: string,
  args: readonly string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  input: Buffer,
  deadline: number,
  processSignal: ProcessSignal = process.kill.bind(process),
  inheritedPublicPipe?: 3,
  inheritedBackendJournal?: true,
  originalGuard?: () => void,
): OwnedChild {
  if (process.platform === "win32" || deadline <= Date.now() ||
      (inheritedPublicPipe !== undefined && inheritedPublicPipe !== 3) ||
      (inheritedBackendJournal !== undefined && inheritedBackendJournal !== true) ||
      (inheritedBackendJournal && inheritedPublicPipe !== undefined)) {
    input.fill(0);
    fail();
  }
  let child: ChildProcess;
  try {
    originalGuard?.();
    child = spawn(executable, [...args], {
      cwd,
      env,
      stdio: inheritedBackendJournal ? ["pipe", "pipe", "pipe", 10, 11] : inheritedPublicPipe === 3 ? ["pipe", "pipe", "pipe", 3] : ["pipe", "pipe", "pipe"],
      detached: true,
      shell: false,
    });
  } catch {
    input.fill(0);
    fail();
  }
  // Failed async spawn emits error later; never let it terminate custody's process.
  child.on("error", () => {});
  if (!child.pid) {
    input.fill(0);
    child.stdin?.destroy();
    child.stdout?.destroy();
    child.stderr?.destroy();
    fail();
  }
  const pid = child.pid;
  let forced = false,
    bounded = true,
    settled = false,
    managementUnknown = false,
    total = 0;
  const chunks: Buffer[] = [];
  const gone = () => {
    try {
      processSignal(-pid, 0);
      return false;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return true;
      managementUnknown = true;
      return false;
    }
  };
  const signal = (value: NodeJS.Signals) => {
    try {
      processSignal(-pid, value);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH")
        managementUnknown = true;
    }
  };
  let resolveDone!: (result: ChildResult) => void;
  const done = new Promise<ChildResult>((resolve) => {
    resolveDone = resolve;
  });
  const finish = (code: number | null, signal: string | null) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    clearInterval(originalTimer);
    input.fill(0);
    const absent = gone();
    const stdout = Buffer.concat(chunks);
    for (const chunk of chunks) chunk.fill(0);
    chunks.length = 0;
    resolveDone({
      code,
      signal,
      stdout,
      bounded,
      groupGone: absent && !managementUnknown,
      forced: forced || managementUnknown,
    });
  };
  let stopping: Promise<ChildResult> | undefined;
  const stop = () => {
    if (stopping) return stopping;
    if (settled) return done;
    forced = true;
    stopping = (async () => {
      signal("SIGTERM");
      await wait(250);
      if (!gone()) {
        signal("SIGKILL");
        await wait(50);
      }
      finish(child.exitCode, child.signalCode);
      return done;
    })().catch(() => {
      managementUnknown = true;
      finish(null, "management-error");
      return done;
    });
    return stopping;
  };
  const timer = setTimeout(
    () => {
      void stop();
    },
    Math.max(1, deadline - Date.now()),
  );
  // Preserve the caller's original monotonic authority across pending private
  // pipe output and child work; no later wall projection replaces that guard.
  const originalTimer = setInterval(() => {
    try { originalGuard?.(); } catch { bounded=false;void stop(); }
  }, 25);
  const record = (chunk: Buffer, keep: boolean) => {
    if (settled) return;
    total += chunk.length;
    if (total > 16384) {
      bounded = false;
      void stop();
      return;
    }
    if (keep) chunks.push(Buffer.from(chunk));
  };
  child.stdout!.on("data", (chunk: Buffer) => record(chunk, true));
  child.stderr!.on("data", (chunk: Buffer) => record(chunk, false));
  child.stdin!.on("error", () => {
    bounded = false;
    void stop();
  });
  try {
    originalGuard?.();
    child.stdin!.end(input, () => input.fill(0));
  } catch {
    input.fill(0);
    bounded = false;
    void stop();
  }
  child.once("error", () => {
    managementUnknown = true;
    void stop();
  });
  child.once("close", (code, value) => {
    if (settled) return;
    if (gone() && !managementUnknown) finish(code, value);
    else void stop();
  });
  return { pid, done, stop };
}

/** Harmless read-only subprocess inherits the root process core limit before generation. */
export async function memoryPreflight(c: Config, deadline: number) {
  const source =
    "import json,resource,sys,subprocess,pathlib\n" +
    "assert resource.getrlimit(resource.RLIMIT_CORE)==(0,0)\n" +
    "mode=sys.argv[1]\n" +
    "if mode=='linux-no-swap':\n assert sys.platform=='linux' and len(pathlib.Path('/proc/swaps').read_text().splitlines())==1\n" +
    "elif mode=='mac-encrypted-swap':\n assert sys.platform=='darwin' and b'(encrypted)' in subprocess.check_output(['/usr/sbin/sysctl','vm.swapusage'],timeout=3,stderr=subprocess.DEVNULL)\n" +
    "else: raise ValueError('refused')\n" +
    "print(json.dumps({'policy':mode,'coreDumpsDisabled':True,'verified':True}))\n";
  const child = startOwned(
    c.executables.python.file,
    ["-I", "-S", "-B", "-c", source, c.memoryPolicy],
    c.website.root,
    childEnvironment(c),
    Buffer.alloc(0),
    Math.min(deadline, Date.now() + 5000),
  );
  const result = await child.done;
  try {
    if (
      result.code !== 0 ||
      result.forced ||
      !result.bounded ||
      !result.groupGone
    )
      fail();
    const value = JSON.parse(result.stdout.toString());
    if (
      value.policy !== c.memoryPolicy ||
      value.coreDumpsDisabled !== true ||
      value.verified !== true
    )
      fail();
  } finally {
    result.stdout.fill(0);
  }
}
