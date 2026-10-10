// Separate checkout rehearsal runtime. Never imported by the production entry point.
import { handle, type Deps } from './app.ts';
import { ConfigError, loadConfig } from './config.ts';
import { loadLicenceConfig, MAINNET_SALES } from './licence/config.ts';
import { LicenceStore } from './licence/store.ts';
import { brandedMailHtml, mailerFor, routingNotifier } from './mail.ts';
import { escapeHtml, json } from './pages.ts';
import type { D1Database, Env } from './platform.ts';
import { Store } from './store.ts';

export const TESTNET_SITE = 'https://staging.zunderlabs.com';
export const TESTNET_ISSUER_PATH = '/api/licence/testnet-issuer/';
export interface TestnetEnv extends Omit<Env, 'DB'> {
  DB_TESTNET_JOURNEY: D1Database;
  TESTNET_JOURNEY_ENABLED?: string;
  TESTNET_DELIVERY_TO?: string;
}

export function testnetDeps(env: TestnetEnv): Deps {
  if (env.DEPLOYMENT_PROFILE !== 'staging' || env.TESTNET_JOURNEY_ENABLED !== 'explicitly-provisioned'
    || env.ENVIRONMENT !== 'testnet-journey' || env.LICENCE_CHAIN !== 'testnet'
    || env.SITE_URL !== TESTNET_SITE || env.ALLOWED_ORIGINS !== TESTNET_SITE
    || !env.DB_TESTNET_JOURNEY || 'DB' in env
    || env.ADMIN_TOKEN || env.NOTIFY_TO || env.NOTIFY_EMAIL
    || env.CONFIRM_PROVIDER !== 'cloudflare' || !env.EMAIL
    || env.AWS_ACCESS_KEY_ID || env.AWS_SECRET_ACCESS_KEY || env.RESEND_API_KEY
    || env.SALES_EVM_ADDRESS || env.SALES_EVM_NETWORKS || env.ARBITRUM_RPC_URL || env.BASE_RPC_URL
    || !env.SALES_HYPERLIQUID_ADDRESS || !/^[A-Za-z0-9_-]{43,128}$/.test(env.LICENCE_ISSUER_TOKEN ?? '')
    || env.LICENCE_ISSUER_TOKEN === env.UNSUBSCRIBE_SECRET) throw new ConfigError('Isolated testnet configuration required');
  if (!/^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/.test(env.TESTNET_DELIVERY_TO ?? '')) {
    throw new ConfigError('A single test inbox must be provisioned');
  }
  const mapped = { ...env, DB: env.DB_TESTNET_JOURNEY };
  const config = loadConfig(mapped);
  const licence = loadLicenceConfig(mapped);
  if (Object.values(MAINNET_SALES).some(a => a?.toLowerCase() === licence.payTo.hyperliquid)
    || /^0x0{40}$/.test(licence.payTo.hyperliquid!)) throw new ConfigError('Separate testnet recipient required');
  const mailer = mailerFor(config, { email: env.EMAIL });
  if (!mailer) throw new ConfigError('Test inbox delivery must be configured');
  const warning = 'TESTNET REHEARSAL: disposable test licence. This key does not activate the official Guard release.';
  const notifier = routingNotifier(env.EMAIL, config.mailFrom, env.TESTNET_DELIVERY_TO!);
  return {
    config, store: new Store(env.DB_TESTNET_JOURNEY), notifier: { async notify(subject, text) {
      await notifier.notify(`[TESTNET] ${subject}`, `${warning}\n\n${text}`);
    } },
    limiter: env.SIGNUP_LIMITER ?? null, contactLimiter: null,
    now: Date.now, newId: () => crypto.randomUUID(),
    mailer: { name: 'isolated-testnet', async send(mail) {
      if (mail.to !== env.TESTNET_DELIVERY_TO) throw new Error('Test inbox recipient mismatch');
      const subject = `[TESTNET] ${mail.subject}`;
      const text = `${warning}\n\n${mail.text.replace(/In guard\.toml[\s\S]*?(?=Renew it,)/,
        'Verify this disposable key only with the isolated Rust test verifier and its test public key. No official Guard activation is possible.\n\n')}`;
      await mailer.send({ ...mail, subject, text, html: brandedMailHtml({ subject, site: TESTNET_SITE,
        preheader: warning, eyebrow: 'Isolated testnet rehearsal', heading: subject,
        body: `<p style="white-space:pre-wrap;overflow-wrap:anywhere">${escapeHtml(text)}</p>` }) });
    } },
    licence: { config: licence, store: new LicenceStore(env.DB_TESTNET_JOURNEY), fetch: (input, init) => fetch(input, init) },
  };
}

/** Called only after testnetDeps validates the isolated bindings and signing identity. */
export async function handleTestnet(request: Request, deps: Deps): Promise<Response> {
  const url = new URL(request.url);
  if (url.origin !== TESTNET_SITE || deps.config.siteUrl !== TESTNET_SITE || deps.licence?.config.chain !== 'testnet') {
    return json(404, { ok: false, code: 'not_found' });
  }
  const path = url.pathname;
  if (path === `${TESTNET_ISSUER_PATH}jobs` || path === `${TESTNET_ISSUER_PATH}deliver`) {
    url.pathname = path.replace(TESTNET_ISSUER_PATH, '/api/licence/issuer/');
    return handle(new Request(url, request), deps);
  }
  if (!['status', 'quote', 'order', 'order/check', 'renew', 'renewal'].some(p => path === `/api/licence/${p}`)) {
    return json(404, { ok: false, code: 'not_found' });
  }
  return handle(request, deps);
}
