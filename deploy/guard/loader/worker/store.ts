// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
/** Atomic C2 publication store. The authenticated publisher verifies Sigstore before writing. */
interface Transaction {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
}
interface State { storage: Transaction & { transaction<T>(operation: (txn: Transaction) => Promise<T>): Promise<T> } }
interface Stub { fetch(request: Request): Promise<Response> }
interface Environment {
  RELEASE_STATE: { idFromName(name: string): unknown; get(id: unknown): Stub };
  INSTALLER_PUBLISH_TOKEN: string;
  STAGING_INSTALLER_PUBLISH_TOKEN: string;
}
type Stage = 'staged' | 'gated' | 'promoted' | 'withdrawn';
type Channel = 'staging' | 'canonical';
interface Predicate {
  version: string; tag: string; manifest_sha256: string; revision: number; previous: string | null; stage: Stage;
}
interface Capsule {
  channel: Channel; expected: string | null; predicate: string; bundle: string;
  unix: string; windows: string;
}
interface Stored extends Capsule { digest: string; state: Predicate; canonicalPrevious?: string | null }
const transitions: Record<Stage, readonly Stage[]> = {
  staged: ['gated', 'withdrawn'], gated: ['promoted', 'withdrawn'],
  promoted: ['withdrawn'], withdrawn: [],
};
const hex = /^[0-9a-f]{64}$/;
function response(body: string | null, status = 200, type = 'application/json'): Response {
  return new Response(body, { status, headers: { 'content-type': `${type}; charset=utf-8`,
    'cache-control': 'no-cache', 'access-control-allow-origin': '*', 'x-content-type-options': 'nosniff' } });
}
async function digest(value: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('');
}
async function readBody(request: Request, limit: number): Promise<string> {
  const reader = request.body?.getReader();
  if (!reader) throw new Error();
  const chunks: Uint8Array[] = []; let size = 0;
  while (true) {
    const part = await reader.read(); if (part.done) break;
    size += part.value.length;
    if (size > limit) { await reader.cancel(); throw new RangeError(); }
    chunks.push(part.value);
  }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
function parse(value: unknown): { capsule: Capsule; state: Predicate } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
  const v = value as Record<string, unknown>;
  if (Object.keys(v).sort().join(',') !== 'bundle,channel,expected,predicate,unix,windows' ||
    !['staging', 'canonical'].includes(String(v['channel'])) ||
    !(v['expected'] === null || (typeof v['expected'] === 'string' && hex.test(v['expected']))) ||
    ['predicate', 'bundle', 'unix', 'windows'].some(key => typeof v[key] !== 'string' || !(v[key] as string).length)) throw new Error();
  const state = JSON.parse(v['predicate'] as string) as Predicate;
  if (!state || !hex.test(state.manifest_sha256) || !Number.isSafeInteger(state.revision) ||
    state.revision < 1 || typeof state.stage !== 'string' || !Object.hasOwn(transitions, state.stage) ||
    !(state.previous === null || (typeof state.previous === 'string' && hex.test(state.previous)))) throw new Error();
  const capsule = v as unknown as Capsule;
  if (state.stage === 'promoted' && (capsule.channel !== 'canonical' ||
    !/^\d+\.\d+\.\d+$/.test(state.version) || state.tag !== `v${state.version}`)) throw new Error();
  if (['staged', 'gated'].includes(state.stage) && capsule.channel !== 'staging') throw new Error();
  return { capsule, state };
}

export class ReleaseStore {
  constructor(private readonly ctx: State) {}
  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (request.method === 'POST' && path === '/guard/restore') {
      let expected: string; let restore: string;
      try {
        const text = await readBody(request, 1024);
        const value = JSON.parse(text) as Record<string, unknown>;
        if (Object.keys(value).sort().join(',') !== 'expected,restore' ||
          typeof value['expected'] !== 'string' || !hex.test(value['expected']) ||
          typeof value['restore'] !== 'string' || !hex.test(value['restore'])) throw new Error();
        expected = value['expected']; restore = value['restore'];
      } catch (error) { return response(null, error instanceof RangeError ? 413 : 400); }
      return this.ctx.storage.transaction(async txn => {
        const head = await txn.get<Stored>('canonical');
        if (head?.digest !== expected || head.state.stage !== 'withdrawn' || !head.state.previous) return response(null, 409);
        const withdrawal = await txn.get<Stored>(`build:${head.state.manifest_sha256}`);
        const promotion = await txn.get<Stored>(`capsule:${head.state.previous}`);
        const prior = await txn.get<Stored>(`capsule:${restore}`);
        const priorHead = prior && await txn.get<Stored>(`build:${prior.state.manifest_sha256}`);
        if (withdrawal?.digest !== expected || promotion?.state.stage !== 'promoted' ||
          promotion.state.manifest_sha256 !== head.state.manifest_sha256 ||
          promotion.canonicalPrevious !== restore || prior?.state.stage !== 'promoted' ||
          prior.channel !== 'canonical' || priorHead?.digest !== restore) return response(null, 409);
        // Restore only the exact immutable capsule replaced by this failed promotion.
        // The failed build stays withdrawn; no build revision or evidence is rewound.
        await txn.put('canonical', prior);
        return response(JSON.stringify({ digest: restore }), 201);
      });
    }
    if (request.method === 'POST' && path === '/guard/publish') {
      let incoming: { capsule: Capsule; state: Predicate };
      try {
        incoming = parse(JSON.parse(await readBody(request, 2 * 1024 * 1024)));
      } catch (error) { return response(null, error instanceof RangeError ? 413 : 400); }
      const { capsule, state } = incoming;
      const currentDigest = await digest(capsule.predicate);
      return this.ctx.storage.transaction(async txn => {
        const head = await txn.get<Stored>(capsule.channel);
        const previous = await txn.get<Stored>(`build:${state.manifest_sha256}`);
        if ((head?.digest ?? null) !== capsule.expected) return response(null, 409);
        if (!previous) {
          if (state.revision !== 1 || state.previous !== null || state.stage !== 'staged') return response(null, 409);
        } else {
          if (state.revision !== previous.state.revision + 1 || state.previous !== previous.digest ||
            !transitions[previous.state.stage].includes(state.stage)) return response(null, 409);
          if (state.stage === 'withdrawn' && (head?.digest !== previous.digest ||
            capsule.channel !== (previous.state.stage === 'promoted' ? 'canonical' : 'staging'))) return response(null, 409);
          if (state.stage === 'gated' && head?.digest !== previous.digest) return response(null, 409);
          if (state.stage === 'promoted') {
            const staged = await txn.get<Stored>('staging');
            if (staged?.digest !== previous.digest) return response(null, 409);
          }
        }
        const stored: Stored = { ...capsule, digest: currentDigest, state };
        if (state.stage === 'promoted') {
          stored.canonicalPrevious = head?.state.stage === 'promoted' ? head.digest : null;
          // Capture an existing canonical capsule too, including heads accepted before
          // this archive extension was deployed.
          if (head) await txn.put(`capsule:${head.digest}`, head);
        }
        // One capsule contains both metadata and bundle plus the associated loader bytes.
        await txn.put(capsule.channel, stored);
        if (state.stage === 'withdrawn' && capsule.channel === 'canonical') {
          const staging = await txn.get<Stored>('staging');
          // Keep any newer candidate. The same failed build must be unavailable on both loaders.
          if (staging?.state.manifest_sha256 === state.manifest_sha256) {
            await txn.put('staging', stored);
          }
        }
        await txn.put(`build:${state.manifest_sha256}`, stored);
        await txn.put(`capsule:${currentDigest}`, stored);
        return response(JSON.stringify({ digest: currentDigest }), 201);
      });
    }
    const staging = ['/i-staging', '/i-staging.ps1', '/guard/release-staging.json', '/guard/release-staging.json.sigstore'];
    const canonical = ['/i', '/i.ps1', '/guard/release.json', '/guard/release.json.sigstore'];
    if (!staging.includes(path) && !canonical.includes(path)) return response(null, 404);
    if (!['GET', 'HEAD'].includes(request.method)) return response(null, 405);
    const stored = await this.ctx.storage.get<Stored>(staging.includes(path) ? 'staging' : 'canonical');
    if (!stored) return response(null, 404);
    const index = (staging.includes(path) ? staging : canonical).indexOf(path);
    if (index < 2 && stored.state.stage === 'withdrawn') return response(null, 410);
    const body = [stored.unix, stored.windows, stored.predicate, stored.bundle][index] ?? null;
    const result = response(request.method === 'HEAD' ? null : body, 200, index < 2 ? 'text/plain' : 'application/json');
    result.headers.set('x-zunder-state-sha256', stored.digest);
    return result;
  }
}

export default {
  async fetch(request: Request, env: Environment): Promise<Response> {
    const url = new URL(request.url);
    if (url.hostname !== 'zunderlabs.com') return response(null, 404);
    if (['/guard/publish', '/guard/restore'].includes(url.pathname)) {
      let body: string; let channel: Channel;
      try {
        body = await readBody(request, url.pathname === '/guard/restore' ? 1024 : 2 * 1024 * 1024);
        channel = url.pathname === '/guard/restore' ? 'canonical' : parse(JSON.parse(body)).capsule.channel;
      } catch (error) { return response(null, error instanceof RangeError ? 413 : 400); }
      const token = channel === 'staging' ? env.STAGING_INSTALLER_PUBLISH_TOKEN : env.INSTALLER_PUBLISH_TOKEN;
      if (!token || request.headers.get('authorization') !== `Bearer ${token}`) return response(null, 401);
      request = new Request(request.url, { method: request.method, headers: request.headers, body });
    }
    return env.RELEASE_STATE.get(env.RELEASE_STATE.idFromName('release-publication-v1')).fetch(request);
  },
};
