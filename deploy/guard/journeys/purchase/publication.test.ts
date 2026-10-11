// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { test, expect } from '@playwright/test';
import { Miniflare } from 'miniflare';
import { build } from 'esbuild';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let runtime: Miniflare;
let source: string;
let persistedDirectory: string | undefined;
const secret = 'synthetic-publication-fixture';
test.beforeAll(async () => {
  const result = await build({ entryPoints: ['../loader/worker/store.ts'], bundle: true, write: false,
    format: 'esm', platform: 'neutral', target: 'es2022' });
  source = result.outputFiles[0]?.text ?? '';
});
test.beforeEach(async () => {
  test.skip(Boolean(process.env['GUARD_STAGING_URL']), 'publication storage tests are local only');
  runtime = new Miniflare({ modules: true, script: source, compatibilityDate: '2026-08-06',
    bindings: { INSTALLER_PUBLISH_TOKEN: secret },
    durableObjects: { RELEASE_STATE: { className: 'ReleaseStore', useSQLite: true } } });
});
test.afterEach(async () => {
  await runtime?.dispose();
  if (persistedDirectory) { await rm(persistedDirectory, { recursive: true, force: true }); persistedDirectory = undefined; }
});
function capsule(revision = 1, previous: string | null = null, stage = 'staged', expected: string | null = null) {
  return { channel: stage === 'promoted' || stage === 'withdrawn' ? 'canonical' : 'staging', expected,
    predicate: JSON.stringify({ manifest_sha256: 'a'.repeat(64), revision, previous, stage }),
    bundle: `synthetic-fixture-bundle-${revision}`, unix: `fixture-unix-${revision}`, windows: `fixture-windows-${revision}` };
}
function publish(value: ReturnType<typeof capsule>, authenticated = true) {
  return runtime.dispatchFetch('https://zunderlabs.com/guard/publish', { method: 'POST',
    headers: authenticated ? { authorization: `Bearer ${secret}` } : {}, body: JSON.stringify(value) });
}
async function publishDigest(value: ReturnType<typeof capsule>): Promise<string> {
  const response = await publish(value); expect(response.status).toBe(201);
  const result = await response.json() as { digest: string };
  expect(result.digest).toMatch(/^[0-9a-f]{64}$/); return result.digest;
}
test('unauthenticated requests never create a public head', async () => {
  expect((await publish(capsule(), false)).status).toBe(401);
  expect((await runtime.dispatchFetch('https://zunderlabs.com/guard/release-staging.json')).status).toBe(404);
});
test('competing genesis proposals have one winner and serve a matched capsule', async () => {
  const proposals = [capsule(), { ...capsule(), unix: 'competing-loader', bundle: 'competing-bundle' }];
  const responses = await Promise.all(proposals.map(value => publish(value)));
  expect(responses.map(r => r.status).sort()).toEqual([201, 409]);
  const winner = proposals[responses.findIndex(r => r.status === 201)];
  const state = await runtime.dispatchFetch('https://zunderlabs.com/guard/release-staging.json');
  const bundle = await runtime.dispatchFetch('https://zunderlabs.com/guard/release-staging.json.sigstore');
  const loader = await runtime.dispatchFetch('https://zunderlabs.com/i-staging');
  expect(await state.text()).toBe(winner?.predicate); expect(await bundle.text()).toBe(winner?.bundle);
  expect(await loader.text()).toBe(winner?.unix);
  expect(state.headers.get('x-zunder-state-sha256')).toBe(bundle.headers.get('x-zunder-state-sha256'));
  expect(state.headers.get('cache-control')).toBe('no-cache');
  expect(state.headers.get('access-control-allow-origin')).toBe('*');
});
test('stage gate promotion withdrawal refuses replay and competing revisions', async () => {
  const staged = await publishDigest(capsule());
  const gated = await publishDigest(capsule(2, staged, 'gated', staged));
  expect((await publish(capsule(2, staged, 'gated', gated))).status).toBe(409);
  const promoted = await publishDigest(capsule(3, gated, 'promoted'));
  expect((await runtime.dispatchFetch('https://zunderlabs.com/i')).status).toBe(200);
  const withdrawn = await publishDigest(capsule(4, promoted, 'withdrawn', promoted));
  expect((await runtime.dispatchFetch('https://zunderlabs.com/i')).status).toBe(410);
  const metadata = await runtime.dispatchFetch('https://zunderlabs.com/guard/release.json');
  expect(metadata.headers.get('x-zunder-state-sha256')).toBe(withdrawn);
  expect((await metadata.json() as { stage: string }).stage).toBe('withdrawn');
  expect((await publish(capsule(5, withdrawn, 'promoted', withdrawn))).status).toBe(409);
});
test('stale head and wrong predecessor preserve published bytes', async () => {
  const staged = await publishDigest(capsule());
  expect((await publish(capsule(2, 'b'.repeat(64), 'gated', staged))).status).toBe(409);
  expect((await publish(capsule(2, staged, 'gated', null))).status).toBe(409);
  expect(await (await runtime.dispatchFetch('https://zunderlabs.com/i-staging')).text()).toBe('fixture-unix-1');
});
test('invalid stage and wrong channel fail before storage', async () => {
  expect((await publish(capsule(1, null, '__proto__'))).status).toBe(400);
  expect((await publish({ ...capsule(), channel: 'canonical' })).status).toBe(400);
  expect((await runtime.dispatchFetch('https://zunderlabs.com/guard/release.json')).status).toBe(404);
});
test('unsupported paths methods and hosts cannot expose or change publication', async () => {
  await publishDigest(capsule());
  expect((await runtime.dispatchFetch('https://other.example/i-staging')).status).toBe(404);
  expect((await runtime.dispatchFetch('https://zunderlabs.com/unrelated')).status).toBe(404);
  expect((await runtime.dispatchFetch('https://zunderlabs.com/i-staging', { method: 'POST' })).status).toBe(405);
  const head = await runtime.dispatchFetch('https://zunderlabs.com/i-staging', { method: 'HEAD' });
  expect(head.status).toBe(200); expect(await head.text()).toBe('');
});

test('durable head survives a runtime restart and still rejects a stale publisher', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'guard-publication-'));
  persistedDirectory = directory;
  const options = { modules: true, script: source, compatibilityDate: '2026-08-06',
    bindings: { INSTALLER_PUBLISH_TOKEN: secret }, durableObjectsPersist: directory,
    durableObjects: { RELEASE_STATE: { className: 'ReleaseStore', useSQLite: true } } };
  await runtime.dispose(); runtime = new Miniflare(options);
    const staged = await publishDigest(capsule());
    await runtime.dispose(); runtime = new Miniflare(options);
    expect(await (await runtime.dispatchFetch('https://zunderlabs.com/i-staging')).text()).toBe('fixture-unix-1');
    expect((await publish(capsule())).status).toBe(409);
    await publishDigest(capsule(2, staged, 'gated', staged));

});
test('superseded staging builds cannot gate or promote over the current head', async () => {
  const original = await publishDigest(capsule());
  const replacement = capsule(1, null, 'staged', original);
  replacement.predicate = replacement.predicate.replace('a'.repeat(64), 'b'.repeat(64));
  const current = await publishDigest(replacement);
  expect((await publish(capsule(2, original, 'gated', current))).status).toBe(409);
  expect((await runtime.dispatchFetch('https://zunderlabs.com/guard/release-staging.json')).headers.get('x-zunder-state-sha256')).toBe(current);
});
