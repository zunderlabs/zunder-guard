#!/usr/bin/env python3
"""Publication gate regressions. Fake GitHub/cosign; real process and checksum checks.

This proves fail-closed wiring, not real OIDC, signatures, native builds or provenance.
Run: python3 deploy/guard/test/release-policy.py
"""
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest

from distribution import InstallerNotices, ReleaseRendering

SCRIPT = Path(__file__).resolve().parents[1] / 'github/verify-release.sh'
TAG = 'v1.0.0'
SHA = 'a' * 40
REF = 'ghcr.io/zunderlabs/zunder-guard@sha256:' + 'b' * 64


class PublicationGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / 'assets'
        self.assets.mkdir()
        for name in ['zunder-guard.rb', 'ZunderLabs.ZunderGuard.yaml',
                     'ZunderLabs.ZunderGuard.installer.yaml', 'ZunderLabs.ZunderGuard.locale.en-US.yaml']:
            (self.assets / name).write_text('release fixture\n')
        (self.assets / f'zunder-guard-{TAG}.image.txt').write_text(REF + '\n')
        (self.assets / f'zunder-guard-{TAG}.intoto.jsonl').write_text('provenance fixture\n')
        self.checksums()
        (self.assets / 'SHA256SUMS.sigstore.json').write_text('{}\n')
        fakebin = self.root / 'bin'
        fakebin.mkdir()
        gh = fakebin / 'gh'
        gh.write_text('''#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
if args[0] == 'api':
    if any('/commits/' in a for a in args):
        print(os.environ['TEST_SHA'])
    else:
        workflow = 'release' if any('/release.yml/' in a for a in args) else 'ci'
        run = dict(head_sha=os.environ['TEST_SHA'], head_branch='v1.0.0' if workflow == 'release' else 'main', status='completed', conclusion='success')
        run.update(json.loads(os.environ.get('TEST_RUN_' + workflow.upper(), '{}')))
        print(json.dumps({'workflow_runs': [run]}))
elif args[:2] == ['release', 'download']:
    out = pathlib.Path(args[args.index('--dir') + 1])
    for p in pathlib.Path(os.environ['TEST_ASSETS']).iterdir():
        shutil.copyfile(p, out / p.name)
else:
    raise SystemExit('unexpected gh invocation')
''')
        cosign = fakebin / 'cosign'
        cosign.write_text('''#!/usr/bin/env python3
import os, sys
with open(os.environ['TEST_COSIGN_LOG'], 'a') as f:
    f.write(' '.join(sys.argv[1:]) + '\\n')
if os.environ.get('TEST_FAIL_COSIGN') == sys.argv[1]:
    raise SystemExit(1)
''')
        verifier = fakebin / 'slsa-verifier'
        verifier.write_text('''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
command = args[0]
with open(os.environ['TEST_SLSA_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\\n')
if os.environ.get('TEST_FAIL_SLSA') == command:
    raise SystemExit(1)
statement = dict(predicate=dict(invocation=dict(configSource=dict(
    digest=dict(sha1=os.environ['TEST_SHA']), entryPoint='.github/workflows/release.yml'))))
source = statement['predicate']['invocation']['configSource']
source.update(json.loads(os.environ.get('TEST_SLSA_SOURCE_' + command.upper().replace('-', '_'), '{}')))
if os.environ.get('TEST_EMPTY_SLSA') != command:
    print(json.dumps(statement))
if os.environ.get('TEST_FAIL_AFTER_SLSA') == command:
    raise SystemExit(1)
''')
        verifier.chmod(0o755)
        gh.chmod(0o755)
        cosign.chmod(0o755)
        self.env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ['PATH'],
                        GITHUB_REPOSITORY='zunderlabs/zunder-guard', TEST_SHA=SHA,
                        TEST_ASSETS=str(self.assets), TEST_COSIGN_LOG=str(self.root / 'cosign.log'),
                        TEST_SLSA_LOG=str(self.root / 'slsa.log'))

    def checksums(self):
        files = sorted(p for p in self.assets.iterdir() if p.name not in {
            'SHA256SUMS', 'SHA256SUMS.sigstore.json', f'zunder-guard-{TAG}.intoto.jsonl'})
        (self.assets / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))

    def run_gate(self, tag=TAG):
        return subprocess.run(['bash', str(SCRIPT), tag, str(self.root / 'download')],
                              env=self.env, capture_output=True, text=True)

    def test_complete_release_uses_signed_immutable_digest(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        log = (self.root / 'cosign.log').read_text()
        self.assertIn('verify ' + REF + ' ', log)
        self.assertIn('/release.yml@refs/tags/v1.0.0', log)
        calls = [json.loads(line) for line in (self.root / 'slsa.log').read_text().splitlines()]
        self.assertEqual([call[0] for call in calls], ['verify-artifact', 'verify-image'])
        for call, builder in zip(calls, ['generic', 'container']):
            self.assertIn('--source-uri', call)
            self.assertEqual(call[call.index('--source-uri') + 1], 'github.com/zunderlabs/zunder-guard')
            self.assertEqual(call[call.index('--source-tag') + 1], TAG)
            self.assertEqual(call[call.index('--builder-id') + 1],
                             'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/'
                             f'generator_{builder}_slsa3.yml@refs/tags/v2.1.0')
            self.assertIn('--print-provenance', call)
        subjects = calls[0][1:calls[0].index('--provenance-path')]
        self.assertEqual(subjects, [line.split()[1] for line in (self.assets / 'SHA256SUMS').read_text().splitlines()])
        self.assertEqual(calls[1][1], REF)

    def test_incomplete_or_wrong_source_runs_refuse_before_download(self):
        for workflow in ['CI', 'RELEASE']:
            for patch in [{'status': 'in_progress'}, {'conclusion': 'failure'},
                          {'head_sha': 'c' * 40}, {'head_branch': 'unrelated'}]:
                with self.subTest(workflow=workflow, patch=patch):
                    self.env['TEST_RUN_' + workflow] = json.dumps(patch)
                    self.assertNotEqual(self.run_gate().returncode, 0)
                    self.assertFalse((self.root / 'download').exists())
            del self.env['TEST_RUN_' + workflow]

    def test_malformed_tag_refuses_before_download(self):
        for tag in ['v1.0.0oops', 'v1.2.3/other', 'v1.2.3-rc1', 'v1.2.3\n']:
            with self.subTest(tag=tag):
                self.assertNotEqual(self.run_gate(tag).returncode, 0)
                self.assertFalse((self.root / 'download').exists())

    def test_tampered_formula_refuses(self):
        (self.assets / 'zunder-guard.rb').write_text('tampered\n')
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_missing_checksummed_asset_refuses(self):
        (self.assets / 'zunder-guard.rb').unlink()
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_unsigned_image_reference_refuses(self):
        image = f'zunder-guard-{TAG}.image.txt'
        sums = self.assets / 'SHA256SUMS'
        sums.write_text(''.join(l for l in sums.read_text().splitlines(True) if image not in l))
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_signed_mutable_image_reference_refuses(self):
        (self.assets / f'zunder-guard-{TAG}.image.txt').write_text('ghcr.io/zunderlabs/zunder-guard:v1.0.0\n')
        self.checksums()
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_missing_provenance_refuses(self):
        (self.assets / f'zunder-guard-{TAG}.intoto.jsonl').unlink()
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_unverifiable_checksum_signature_refuses(self):
        self.env['TEST_FAIL_COSIGN'] = 'verify-blob'
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_unverifiable_image_refuses(self):
        self.env['TEST_FAIL_COSIGN'] = 'verify'
        self.assertNotEqual(self.run_gate().returncode, 0)


    def test_invalid_generic_or_image_provenance_refuses(self):
        for command in ['verify-artifact', 'verify-image']:
            with self.subTest(command=command):
                self.env['TEST_FAIL_SLSA'] = command
                self.assertNotEqual(self.run_gate().returncode, 0)
                shutil.rmtree(self.root / 'download')

    def test_wrong_verified_source_or_caller_refuses(self):
        for command in ['verify-artifact', 'verify-image']:
            key = 'TEST_SLSA_SOURCE_' + command.upper().replace('-', '_')
            for patch in [{'digest': {'sha1': 'c' * 40}},
                          {'entryPoint': '.github/workflows/untrusted.yml'}]:
                with self.subTest(command=command, patch=patch):
                    self.env[key] = json.dumps(patch)
                    self.assertNotEqual(self.run_gate().returncode, 0)
                    shutil.rmtree(self.root / 'download')
            del self.env[key]

    def test_empty_or_failed_after_json_provenance_refuses(self):
        for flag in ['TEST_EMPTY_SLSA', 'TEST_FAIL_AFTER_SLSA']:
            for command in ['verify-artifact', 'verify-image']:
                with self.subTest(flag=flag, command=command):
                    self.env[flag] = command
                    self.assertNotEqual(self.run_gate().returncode, 0)
                    shutil.rmtree(self.root / 'download')
            del self.env[flag]

    def test_windows_installer_fixture_supplies_descriptor_before_rendering(self):
        workflow = (SCRIPT.parent / 'workflows/ci.yml').read_text()
        self.assertLess(workflow.index('>"rel/$v/zunder-guard-$v.image.txt"'),
                        workflow.index('deploy/guard/packaging/render.sh "$v"'))

    def test_unavailable_verifier_refuses(self):
        (self.root / 'bin/slsa-verifier').write_text('#!/bin/sh\nexit 127\n')
        self.assertNotEqual(self.run_gate().returncode, 0)


if __name__ == '__main__':
    unittest.main()
