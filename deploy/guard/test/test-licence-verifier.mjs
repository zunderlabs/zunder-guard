// Local orchestration checks only. The fixture executable is not native Rust evidence.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const harness = resolve('deploy/guard/test/licence-verifier.mjs');
const shim = `#!${process.execPath}
const fs = require('node:fs');
const crypto = require('node:crypto');
let ok = false;
try {
  const raw = fs.readFileSync(0);
  const input = JSON.parse(raw);
  if (process.argv.length !== 2 || raw.length > 16384 ||
      Object.keys(input).sort().join() !== 'expectedLicensee,key,owner,publicKey' ||
      input.publicKey === '7e298d8aa9921205f1ef0995b8dc6fedd86a4365fe183825127f8cd56a82af46') throw Error();
  const [payload, signature] = input.key.slice(5).split('.');
  if (!input.key.startsWith('zgl1_')) throw Error();
  const pub = crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(input.publicKey,'hex')]),format:'der',type:'spki'});
  const bytes = Buffer.from(payload,'base64url');
  const terms = JSON.parse(bytes);
  ok = crypto.verify(null,bytes,pub,Buffer.from(signature,'base64url')) &&
       terms.expires_at_ms > Date.now() && terms.accounts.includes(input.owner) &&
       terms.licensee === input.expectedLicensee && terms.features.includes('fee_free') && !terms.builder;
} catch {}
process.stdout.write(JSON.stringify({ok})+'\\n');
process.exit(ok ? 0 : 1);
`;

function temporary(fn) {
  const directory = mkdtempSync(join(tmpdir(), 'public-verifier-test-'));
  try { return fn(directory); } finally { rmSync(directory, { recursive: true, force: true }); }
}
test('public fixture harness records twelve outcomes and explicit proof limits', () => temporary((directory) => {
  const executable = join(directory, 'fixture.cjs');
  const receipt = join(directory, 'receipt.json');
  writeFileSync(executable, shim, { mode: 0o700 });
  const result = spawnSync(process.execPath, [harness, executable, receipt], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const evidence = JSON.parse(readFileSync(receipt, 'utf8'));
  assert.equal(evidence.cases.length, 12);
  assert.ok(evidence.cases.every((value) => value.passed));
  assert.equal(evidence.officialGuardActivation, false);
  assert.equal(evidence.paymentOrDeliveryExecuted, false);
  assert.match(evidence.binarySha256, /^[0-9a-f]{64}$/);
  assert.match(evidence.exampleSha256, /^[0-9a-f]{64}$/);
}));
test('harness refuses a blanket success executable', () => temporary((directory) => {
  const executable = join(directory, 'fixture.cjs');
  writeFileSync(executable, `#!${process.execPath}\nprocess.stdout.write('{"ok":true}\\n');\n`, { mode: 0o700 });
  const result = spawnSync(process.execPath, [harness, executable, join(directory, 'receipt.json')], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
}));
