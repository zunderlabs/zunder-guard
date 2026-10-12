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
const stagingSecret = 'synthetic-staging-fixture';
test.beforeAll(async () => {
  const result = await build({ entryPoints: ['../loader/worker/store.ts'], bundle: true, write: false,
    format: 'esm', platform: 'neutral', target: 'es2022' });
  source = result.outputFiles[0]?.text ?? '';
});
test.beforeEach(async () => {
  test.skip(Boolean(process.env['GUARD_STAGING_URL']), 'publication storage tests are local only');
  runtime = new Miniflare({ modules: true, script: source, compatibilityDate: '2026-08-06',
    bindings: { INSTALLER_PUBLISH_TOKEN: secret, STAGING_INSTALLER_PUBLISH_TOKEN: stagingSecret },
    durableObjects: { RELEASE_STATE: { className: 'ReleaseStore', useSQLite: true } } });
});
test.afterEach(async () => {
  await runtime?.dispose();
  if (persistedDirectory) { await rm(persistedDirectory, { recursive: true, force: true }); persistedDirectory = undefined; }
});
function capsule(revision = 1, previous: string | null = null, stage = 'staged', expected: string | null = null) {
  return { channel: stage === 'promoted' || stage === 'withdrawn' ? 'canonical' : 'staging', expected,
    predicate: JSON.stringify({ version: '1.0.0', tag: 'v1.0.0', manifest_sha256: 'a'.repeat(64), revision, previous, stage }),
    bundle: `synthetic-fixture-bundle-${revision}`, unix: `fixture-unix-${revision}`, windows: `fixture-windows-${revision}` };
}
function publish(value: ReturnType<typeof capsule>, authenticated = true) {
  return runtime.dispatchFetch('https://zunderlabs.com/guard/publish', { method: 'POST',
    headers: authenticated ? { authorization: `Bearer ${value.channel === 'staging' ? stagingSecret : secret}` } : {}, body: JSON.stringify(value) });
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
  const stateBody = await state.text();
  const bundle = await runtime.dispatchFetch('https://zunderlabs.com/guard/release-staging.json.sigstore');
  const bundleBody = await bundle.text();
  const loader = await runtime.dispatchFetch('https://zunderlabs.com/i-staging');
  const loaderBody = await loader.text();
  expect([state.status, bundle.status, loader.status]).toEqual([200, 200, 200]);
  expect(stateBody).toBe(winner?.predicate); expect(bundleBody).toBe(winner?.bundle);
  expect(loaderBody).toBe(winner?.unix);
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
  expect((await runtime.dispatchFetch('https://zunderlabs.com/i-staging')).status).toBe(410);
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
    bindings: { INSTALLER_PUBLISH_TOKEN: secret, STAGING_INSTALLER_PUBLISH_TOKEN: stagingSecret }, durableObjectsPersist: directory,
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

function restore(expected: string | null, target: string | null, authenticated = true) {
  return runtime.dispatchFetch('https://zunderlabs.com/guard/restore', { method: 'POST',
    headers: authenticated ? { authorization: `Bearer ${secret}` } : {},
    body: JSON.stringify({ expected, restore: target }) });
}
async function promoteBuild(build: string, staging: string | null, canonical: string | null) {
  const proposal = (revision: number, previous: string | null, stage: string, expected: string | null) => {
    const value = capsule(revision, previous, stage, expected);
    value.predicate = value.predicate.replace('a'.repeat(64), build.repeat(64));
    value.unix = `${build}-unix-${revision}`; value.windows = `${build}-windows-${revision}`;
    return value;
  };
  const first = await publishDigest(proposal(1, null, 'staged', staging));
  const gate = await publishDigest(proposal(2, first, 'gated', first));
  const value = proposal(3, gate, 'promoted', canonical);
  const promoted = await publishDigest(value);
  return { gate, promoted, value,
    withdrawal: () => proposal(4, promoted, 'withdrawn', promoted) };
}
test('authenticated rollback restores exact prior capsule without resurrecting failed build', async () => {
  const old = await promoteBuild('a', null, null);
  const next = await promoteBuild('b', old.gate, old.promoted);
  const withdrawal = await publishDigest(next.withdrawal());
  expect((await restore(withdrawal, old.promoted, false)).status).toBe(401);
  expect((await restore(next.promoted, old.promoted)).status).toBe(409);
  const results = await Promise.all([restore(withdrawal, old.promoted), restore(withdrawal, old.promoted)]);
  expect(results.map(value => value.status).sort()).toEqual([201, 409]);
  for (const [path, body] of [['/i', old.value.unix], ['/i.ps1', old.value.windows],
    ['/guard/release.json', old.value.predicate], ['/guard/release.json.sigstore', old.value.bundle]]) {
    const read = await runtime.dispatchFetch(`https://zunderlabs.com${path}`);
    expect(read.status).toBe(200); expect(await read.text()).toBe(body);
    expect(read.headers.get('x-zunder-state-sha256')).toBe(old.promoted);
  }
  expect((await publish(next.value)).status).toBe(409);
});
test('restore admits only the exact prior head recorded by the failed promotion', async () => {
  const first = await promoteBuild('a', null, null);
  const second = await promoteBuild('b', first.gate, first.promoted);
  const third = await promoteBuild('c', second.gate, second.promoted);
  const withdrawn = await publishDigest(third.withdrawal());
  expect((await restore(withdrawn, first.promoted)).status).toBe(409);
  expect((await restore(withdrawn, 'd'.repeat(64))).status).toBe(409);
  expect((await restore(withdrawn, third.gate)).status).toBe(409);
  expect((await restore(withdrawn, second.promoted)).status).toBe(201);
});
test('first promotion has no rollback target and remains truthfully withdrawn', async () => {
  const first = await promoteBuild('a', null, null);
  expect((await restore(first.promoted, first.promoted)).status).toBe(409);
  const withdrawn = await publishDigest(first.withdrawal());
  expect((await restore(withdrawn, null)).status).toBe(400);
  expect((await restore(null, first.promoted)).status).toBe(400);
  expect((await restore(withdrawn, first.promoted)).status).toBe(409);
  expect((await runtime.dispatchFetch('https://zunderlabs.com/i')).status).toBe(410);
});
test('a withdrawn prior channel is never a rollback target', async () => {
  const first = await promoteBuild('a', null, null);
  const oldWithdrawal = await publishDigest(first.withdrawal());
  const next = await promoteBuild('b', oldWithdrawal, oldWithdrawal);
  const withdrawn = await publishDigest(next.withdrawal());
  expect((await restore(withdrawn, first.promoted)).status).toBe(409);
});
test('restore payloads are bounded and cannot accept caller replacement bytes', async () => {
  expect((await runtime.dispatchFetch('https://zunderlabs.com/guard/restore', { method: 'POST',
    headers: { authorization: `Bearer ${secret}` },
    body: JSON.stringify({ expected: 'a'.repeat(64), restore: 'b'.repeat(64), unix: 'replacement' }) })).status).toBe(400);
  expect((await runtime.dispatchFetch('https://zunderlabs.com/guard/restore', { method: 'POST',
    headers: { authorization: `Bearer ${secret}` }, body: 'x'.repeat(1025) })).status).toBe(413);
});

test('staging publisher cannot publish or restore canonical state', async () => {
  const staged = await publishDigest(capsule());
  const gated = await publishDigest(capsule(2, staged, 'gated', staged));
  for (const token of [stagingSecret, secret]) {
    const wrong = token === secret ? capsule(2, staged, 'gated', staged) : capsule(3, gated, 'promoted');
    expect((await runtime.dispatchFetch('https://zunderlabs.com/guard/publish', {method: 'POST',
      headers: {authorization: `Bearer ${token}`}, body: JSON.stringify(wrong)})).status).toBe(401);
  }
  expect((await runtime.dispatchFetch('https://zunderlabs.com/guard/restore', {method: 'POST',
    headers: {authorization: `Bearer ${stagingSecret}`},
    body: JSON.stringify({expected: 'a'.repeat(64), restore: 'b'.repeat(64)})})).status).toBe(401);
});
test('release candidate cannot become promoted even with canonical authority', async () => {
  const candidate = capsule();
  candidate.predicate = JSON.stringify({...JSON.parse(candidate.predicate), version: '1.0.0-rc.7', tag: 'v1.0.0-rc.7'});
  const staged = await publishDigest(candidate);
  const next = capsule(2, staged, 'gated', staged);
  next.predicate = JSON.stringify({...JSON.parse(next.predicate), version: '1.0.0-rc.7', tag: 'v1.0.0-rc.7'});
  const gated = await publishDigest(next);
  const promoted = capsule(3, gated, 'promoted');
  promoted.predicate = JSON.stringify({...JSON.parse(promoted.predicate), version: '1.0.0-rc.7', tag: 'v1.0.0-rc.7'});
  expect((await publish(promoted)).status).toBe(400);
});
