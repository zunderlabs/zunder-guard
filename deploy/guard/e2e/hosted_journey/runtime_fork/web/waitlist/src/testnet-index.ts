import { watchPayments } from './licence/handlers.ts';
import { json } from './pages.ts';
import type { ExecutionContext, ScheduledController } from './platform.ts';
import { handleTestnet, testnetDeps, type TestnetEnv } from './testnet-journey.ts';

export default {
  async fetch(request: Request, env: TestnetEnv): Promise<Response> {
    try { return await handleTestnet(request, testnetDeps(env)); }
    catch { return json(503, { ok: false, code: 'testnet_rehearsal_disabled' }); }
  },
  async scheduled(_controller: ScheduledController, env: TestnetEnv, ctx: ExecutionContext): Promise<void> {
    // Checked-in config has no schedule. Enable only after isolated resources are provisioned.
    const deps = testnetDeps(env);
    if (deps.licence) ctx.waitUntil(watchPayments(deps, deps.licence));
  },
};
