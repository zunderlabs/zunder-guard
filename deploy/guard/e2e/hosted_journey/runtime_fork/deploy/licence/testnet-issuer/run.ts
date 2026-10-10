// Bounded automatic rehearsal: private stdin once, no scheduler or AWS resources.
import { setTimeout as delay } from 'node:timers/promises';
import { runTestnet, type TestnetIssuerConfig } from './issuer.ts';

export const MAX_RUN_MS = 20 * 60_000;
export const POLL_MS = 15_000;
interface PollDeps { now: () => number; wait: (ms: number) => Promise<void>; signal: AbortSignal }
interface Outcome { delivered: number; deferred: number; failed: number }

export async function pollTestnet(run: () => Promise<Outcome>, deps: PollDeps) {
  const until = deps.now() + MAX_RUN_MS;
  let polls = 0;
  const finish = (status: string, outcome: Outcome = { delivered: 0, deferred: 0, failed: 0 }) => ({ status, polls, ...outcome });
  while (polls < MAX_RUN_MS / POLL_MS && deps.now() < until) {
    if (deps.signal.aborted) return finish(deps.signal.reason === 'timed_out' ? 'timed_out' : 'stopped');
    try {
      polls++;
      const result = await run();
      if (!result || Object.keys(result).sort().join(',') !== 'deferred,delivered,failed'
        || ![result.delivered, result.deferred, result.failed].every(n => n === 0 || n === 1)
        || result.delivered + result.deferred + result.failed > 1) return finish('failed', { delivered: 0, deferred: 0, failed: 1 });
      if (result.failed) return finish('failed', result);
      if (result.deferred) return finish('deferred', result); // Includes delivery conflict: stop for review, never resubmit.
      if (result.delivered) return finish('delivered', result);
      if (deps.signal.aborted) return finish(deps.signal.reason === 'timed_out' ? 'timed_out' : 'stopped');
      const remaining = until - deps.now();
      if (remaining <= 0) break;
      try { await deps.wait(Math.min(POLL_MS, remaining)); }
      catch {
        if (deps.signal.aborted) return finish(deps.signal.reason === 'timed_out' ? 'timed_out' : 'stopped');
        return finish('failed', { delivered: 0, deferred: 0, failed: 1 });
      }
    } catch {
      // A request may have delivered before its response was lost. Never retry uncertainty.
      return finish('failed', { delivered: 0, deferred: 0, failed: 1 });
    }
  }
  return finish('timed_out');
}

async function main() {
  const controller = new AbortController();
  let reading = true;
  const stop = (reason: string) => { controller.abort(reason); if (reading) process.stdin.destroy(); };
  const interrupted = () => stop('stopped');
  process.on('SIGTERM', interrupted);
  process.on('SIGINT', interrupted);
  const timer = setTimeout(() => stop('timed_out'), MAX_RUN_MS);
  try {
    if (process.argv.length !== 2) throw new Error('Stdin only');
    let input = '';
    for await (const chunk of process.stdin) {
      input += chunk.toString();
      if (Buffer.byteLength(input) > 4_096) throw new Error('Input too large');
    }
    reading = false;
    controller.signal.throwIfAborted();
    const config = JSON.parse(input) as TestnetIssuerConfig;
    input = '';
    const result = await pollTestnet(() => runTestnet(config, {
      now: Date.now,
      fetch: (async (url, init) => {
        controller.signal.throwIfAborted();
        return fetch(url, { ...init, signal: AbortSignal.any([controller.signal, ...(init?.signal ? [init.signal] : [])]) });
      }) as typeof fetch,
    }), { now: Date.now, signal: controller.signal, wait: ms => delay(ms, undefined, { signal: controller.signal }) });
    console.log(JSON.stringify(result));
    if (result.status !== 'delivered') process.exitCode = 1;
  } catch {
    console.error('Isolated testnet issuance stopped; credentials and response bodies omitted');
    process.exitCode = 1;
  } finally {
    clearTimeout(timer);
    process.off('SIGTERM', interrupted);
    process.off('SIGINT', interrupted);
  }
}

if (import.meta.main) await main();
