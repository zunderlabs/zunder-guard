// Public fixture key only. This verifies the offline staging example, never Guard activation.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const binary = process.argv[2];
const receiptPath = process.argv[3];
assert.equal(process.argv.length, 4, 'Expected verifier binary and receipt destination');
const owner = `0x${'1'.repeat(40)}`;
const production = '7e298d8aa9921205f1ef0995b8dc6fedd86a4365fe183825127f8cd56a82af46';
// The fixed [7;32] seed is already public in licence::test_key::SEED.
const fixtureKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]),
  format: 'der', type: 'pkcs8',
});
const publicKey = createPublicKey(fixtureKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
assert.notEqual(publicKey, production);
const terms = {
  licensee: 'Public staging verifier fixture',
  expires_at_ms: Date.now() + 86_400_000,
  features: ['fee_free'], accounts: [owner],
};
function issue(overrides = {}) {
  const payload = Buffer.from(JSON.stringify({ ...terms, ...overrides }));
  return `zgl1_${payload.toString('base64url')}.${sign(null, payload, fixtureKey).toString('base64url')}`;
}
const input = { key: issue(), publicKey, owner, expectedLicensee: terms.licensee };
const cases = [
  ['valid', true, JSON.stringify(input), []],
  ['wrong-owner', false, JSON.stringify({ ...input, owner: `0x${'2'.repeat(40)}` }), []],
  ['wrong-licensee', false, JSON.stringify({ ...input, expectedLicensee: 'Someone else' }), []],
  ['wrong-public-key', false, JSON.stringify({ ...input, publicKey: '00'.repeat(32) }), []],
  ['production-public-key', false, JSON.stringify({ ...input, publicKey: production }), []],
  ['expired', false, JSON.stringify({ ...input, key: issue({ expires_at_ms: 1 }) }), []],
  ['no-fee-free', false, JSON.stringify({ ...input, key: issue({ features: [] }) }), []],
  ['builder-override', false, JSON.stringify({ ...input, key: issue({ builder: { address: owner, fee_tenths_bp: 10 } }) }), []],
  ['forged', false, JSON.stringify({ ...input, key: input.key.slice(0, input.key.lastIndexOf('.') + 1) + Buffer.alloc(64).toString('base64url') }), []],
  ['unknown-input-field', false, JSON.stringify({ ...input, unexpected: true }), []],
  ['oversized-input', false, ' '.repeat(16 * 1024 + 1), []],
  ['argv-refused', false, JSON.stringify(input), ['public-unexpected-argument']],
];
const results = [];
for (const [name, expected, stdin, args] of cases) {
  const result = spawnSync(binary, args, { input: stdin, encoding: 'utf8', timeout: 10_000, maxBuffer: 4096 });
  assert.equal(result.error, undefined, `${name}: process failed`);
  assert.equal(result.signal, null, `${name}: process interrupted`);
  assert.equal(result.status, expected ? 0 : 1, `${name}: wrong exit status`);
  assert.equal(result.stdout, JSON.stringify({ ok: expected }) + '\n', `${name}: wrong receipt`);
  assert.equal(result.stderr, '', `${name}: unexpected diagnostics`);
  results.push({ name, expected, passed: true });
}
function digest(path) { return createHash('sha256').update(readFileSync(path)).digest('hex'); }
const receipt = {
  schema: 1, kind: 'offline-staging-licence-verifier',
  source: process.env.GITHUB_SHA || null,
  runId: process.env.GITHUB_RUN_ID || null,
  runAttempt: process.env.GITHUB_RUN_ATTEMPT || null,
  binarySha256: digest(binary),
  cargoLockSha256: digest('Cargo.lock'),
  exampleSha256: digest('crates/zunder-guard-core/examples/verify_testnet_licence.rs'),
  fixtureSha256: digest('deploy/guard/test/licence-verifier.mjs'),
  cases: results, passed: true,
  officialGuardActivation: false, paymentOrDeliveryExecuted: false,
};
writeFileSync(receiptPath, JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx' });
console.log(`Passed ${results.length} offline staging verifier cases.`);
