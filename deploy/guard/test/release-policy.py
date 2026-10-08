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
from unittest.mock import patch

import yaml

from distribution import InstallerNotices, ReleaseRendering

SCRIPT = Path(__file__).resolve().parents[1] / 'github/verify-release-assets.sh'
TAG = 'v1.0.0'
SHA = 'a' * 40
REF = 'ghcr.io/zunderlabs/zunder-guard@sha256:' + 'b' * 64
SERVICE_ASSETS = ['install-windows-service.ps1', 'install-macos-service.sh', 'install-container.py', 'container-supervisor.py',
                  'container-operations.py', 'zunder-guard-container.service',
                  'zunder-guard-setup-guardian.service']


class PublicationGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / 'assets'
        self.assets.mkdir()
        for name in ['zunder-guard.rb', 'ZunderLabs.ZunderGuard.yaml',
                     'ZunderLabs.ZunderGuard.installer.yaml', 'ZunderLabs.ZunderGuard.locale.en-US.yaml'] + SERVICE_ASSETS:
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

    def test_windows_helper_must_be_unique_signed_subject(self):
        helper = self.assets / 'install-windows-service.ps1'
        helper.unlink()
        self.checksums()
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('install-windows-service.ps1 is missing or repeated', result.stderr)

    def test_windows_helper_duplicate_subject_refuses(self):
        sums = self.assets / 'SHA256SUMS'
        line = next(line for line in sums.read_text().splitlines() if line.endswith('  install-windows-service.ps1'))
        sums.write_text(sums.read_text() + line + '\n')
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('install-windows-service.ps1 is missing or repeated', result.stderr)

    def test_windows_helper_tampering_refuses(self):
        (self.assets / 'install-windows-service.ps1').write_text('tampered helper\n')
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_tampered_formula_refuses(self):
        (self.assets / 'zunder-guard.rb').write_text('tampered\n')
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_missing_checksummed_asset_refuses(self):
        (self.assets / 'zunder-guard.rb').unlink()
        self.assertNotEqual(self.run_gate().returncode, 0)

    def test_signed_manifest_cannot_omit_required_service_asset(self):
        for asset in SERVICE_ASSETS:
            with self.subTest(asset=asset):
                path = self.assets / asset
                original = path.read_bytes()
                path.unlink()
                self.checksums()
                result = self.run_gate()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(asset + ' is missing or repeated', result.stderr)
                shutil.rmtree(self.root / 'download')
                path.write_bytes(original)
                self.checksums()

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


class HomebrewPublication(unittest.TestCase):
    """No tap write token before verified release; no owner-wide token or PAT fallback."""

    def setUp(self):
        self.workflow = yaml.safe_load((SCRIPT.parent / 'workflows/publish.yml').read_text())
        self.job = self.workflow['jobs']['homebrew']
        self.steps = self.job['steps']

    def test_release_verification_is_a_required_successful_predecessor(self):
        self.assertEqual(self.job['needs'], 'verify')
        self.assertEqual(self.job['concurrency'], {'group': 'guard-homebrew-publication', 'cancel-in-progress': False})
        self.assertNotIn('always(', self.job.get('if', ''))
        self.assertFalse(self.job.get('continue-on-error', False))
        verify = self.workflow['jobs']['verify']
        self.assertIn('github.event.release.prerelease == false', verify['if'])
        self.assertTrue(any('verify-release.sh "$TAG" rel' in step.get('run', '')
                            for step in verify['steps']))
        for step in verify['steps'] + self.steps:
            self.assertFalse(step.get('continue-on-error', False))
        upload = next(step for step in verify['steps'] if 'actions/upload-artifact@' in step.get('uses', ''))
        download = next(step for step in self.steps if 'actions/download-artifact@' in step.get('uses', ''))
        self.assertEqual(upload['with']['name'], download['with']['name'])
        self.assertEqual(download['with']['path'], 'rel')

    def test_token_is_short_lived_and_scoped_to_only_the_tap(self):
        token = next(step for step in self.steps if step.get('id') == 'tap-token')
        self.assertRegex(token['uses'], r'^actions/create-github-app-token@[a-f0-9]{40}$')
        settings = token['with']
        self.assertEqual(settings['owner'], 'zunderlabs')
        self.assertEqual(settings['repositories'], 'homebrew-tap')
        self.assertEqual({k: v for k, v in settings.items() if k.startswith('permission-')},
                         {'permission-contents': 'write', 'permission-pull-requests': 'write'})
        self.assertIs(settings['skip-token-revoke'], False)
        self.assertEqual(settings['client-id'], '${{ vars.HOMEBREW_APP_CLIENT_ID }}')
        self.assertEqual(settings['private-key'], '${{ secrets.HOMEBREW_APP_PRIVATE_KEY }}')
        self.assertEqual(self.job['permissions'], {'contents': 'read'})
        checkout = next(step for step in self.steps if 'actions/checkout@' in step.get('uses', '')
                        and step.get('with', {}).get('repository') == 'zunderlabs/homebrew-tap')
        self.assertEqual(checkout['with']['repository'], 'zunderlabs/homebrew-tap')
        self.assertEqual(checkout['with']['token'], '${{ steps.tap-token.outputs.token }}')
        pr = next(step for step in self.steps if 'gh pr create' in step.get('run', ''))
        self.assertEqual(pr['env']['GH_TOKEN'], '${{ steps.tap-token.outputs.token }}')
        self.assertIn('--repo zunderlabs/homebrew-tap', pr['run'])
        self.assertNotIn('HOMEBREW_TAP_TOKEN', json.dumps(self.job))
        self.assertNotIn('secrets.', json.dumps(checkout))

    def test_paper_fixture_requires_standard_mode_and_positive_equity(self):
        from contextlib import redirect_stdout
        from io import BytesIO, StringIO
        import urllib.request
        import re
        template = SCRIPT.parent.parent / 'packaging/homebrew/tap-verify.yml'
        steps = yaml.safe_load(template.read_text())['jobs']['verified-native-install']['steps']
        preflight = next(s for s in steps if s.get('name', '').startswith('Check the controlled paper'))
        install = next(s for s in steps if 'brew install' in s.get('run', ''))
        self.assertLess(steps.index(preflight), steps.index(install))
        fixture_source = (SCRIPT.parent.parent / 'test/installer_test.py').read_text()
        account = re.search(r'^PAPER_ACCOUNT = "(0x[0-9a-f]{40})"$', fixture_source, re.MULTILINE)[1]
        self.assertEqual(preflight['env']['PAPER_ACCOUNT'], account)
        self.assertEqual(install['env']['PAPER_ACCOUNT'], account)
        self.assertIn('--account "$PAPER_ACCOUNT"', install['run'])
        source = preflight['run'].split("<<'PYCODE'\n", 1)[1].rsplit('\nPYCODE', 1)[0]
        for mode, equity, succeeds in [('disabled', '100', True), ('default', '100', False),
                                      ('disabled', '0', False), ('disabled', '-1', False),
                                      ('disabled', 'NaN', False)]:
            responses = [BytesIO(json.dumps(mode).encode()),
                         BytesIO(json.dumps({'marginSummary': {'accountValue': equity}}).encode())]
            with self.subTest(mode=mode, equity=equity), patch.dict(os.environ, {'PAPER_ACCOUNT': account}), \
                    patch.object(urllib.request, 'urlopen', side_effect=responses) as request, redirect_stdout(StringIO()):
                if succeeds:
                    exec(compile(source, 'paper-fixture-preflight', 'exec'), {})
                else:
                    with self.assertRaises(SystemExit):
                        exec(compile(source, 'paper-fixture-preflight', 'exec'), {})
                for call in request.call_args_list:
                    payload = json.loads(call.args[0].data)
                    self.assertEqual(call.args[0].full_url, 'https://api.hyperliquid.xyz/info')
                    self.assertIn(payload['type'], ['userAbstraction', 'clearinghouseState'])
                    self.assertEqual(payload['user'], account)

    def test_formula_recheck_precedes_any_write_credentials(self):
        check = next(step for step in self.steps if step.get('id') == 'formula-check')
        token = next(step for step in self.steps if step.get('id') == 'tap-token')
        self.assertLess(self.steps.index(check), self.steps.index(token))
        self.assertFalse(check.get('continue-on-error', False))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            rel = root / 'rel'
            rel.mkdir()
            fakebin = root / 'bin'
            fakebin.mkdir()
            curl = fakebin / 'curl'
            curl.write_text('#!/usr/bin/env python3\nimport json,os\nprint(json.dumps({"tag_name":os.environ.get("TEST_LATEST","v1.0.0"),"draft":False,"prerelease":False}))\n')
            curl.chmod(0o755)
            env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ['PATH'], TAG=TAG)
            formula = rel / 'zunder-guard.rb'
            formula.write_text('verified formula fixture\n')
            entry = hashlib.sha256(formula.read_bytes()).hexdigest() + '  zunder-guard.rb\n'
            cases = [('valid', entry, True), ('missing', '', False),
                     ('duplicate', entry + entry, False), ('wrong digest', 'a' * 64 + '  zunder-guard.rb\n', False)]
            for label, text, succeeds in cases:
                with self.subTest(label=label):
                    (rel / 'SHA256SUMS').write_text(text)
                    result = subprocess.run(['bash', '-c', check['run']], cwd=root,
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, succeeds, result.stderr)
            (rel / 'SHA256SUMS').write_text(entry)
            env['TEST_LATEST'] = 'v1.0.1'
            result = subprocess.run(['bash', '-c', check['run']], cwd=root,
                                    env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            env['TEST_LATEST'] = TAG
            formula.write_text('tampered after artifact download\n')
            result = subprocess.run(['bash', '-c', check['run']], cwd=root,
                                    env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


    def test_tap_ci_has_no_secrets_and_checks_before_executing_formula(self):
        template = SCRIPT.parent.parent / 'packaging/homebrew/tap-verify.yml'
        workflow = yaml.safe_load(template.read_text())
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertNotIn('secrets.', template.read_text())
        steps = workflow['jobs']['verified-native-install']['steps']
        check = next(step for step in steps if 'cosign verify-blob' in step.get('run', ''))
        install = next(step for step in steps if 'brew install' in step.get('run', ''))
        self.assertLess(steps.index(check), steps.index(install))
        self.assertIn('brew test zunderlabs/tap/zunder-guard', install['run'])
        for step in steps:
            self.assertFalse(step.get('continue-on-error', False))
        self.assertIn('--certificate-identity "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/$TAG"', check['run'])
        self.assertIn('--certificate-oidc-issuer https://token.actions.githubusercontent.com', check['run'])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'Formula').mkdir()
            formula = root / 'Formula/zunder-guard.rb'
            text = 'class ZunderGuard < Formula\n  version "1.0.0"\nend\n'
            formula.write_text(text)
            assets = root / 'assets'
            assets.mkdir()
            (assets / 'zunder-guard.rb').write_text(text)
            digest = hashlib.sha256(text.encode()).hexdigest()
            (assets / 'SHA256SUMS').write_text(digest + '  zunder-guard.rb\n')
            (assets / 'SHA256SUMS.sigstore.json').write_text('{}\n')
            fakebin = root / 'bin'
            fakebin.mkdir()
            curl = fakebin / 'curl'
            curl.write_text('#!/usr/bin/env python3\nimport json,os\nprint(json.dumps({"tag_name":os.environ.get("TEST_LATEST","v1.0.0"),"draft":False,"prerelease":False}))\n')
            curl.chmod(0o755)
            gh = fakebin / 'gh'
            gh.write_text('#!/bin/sh\nmkdir verified && cp assets/* verified/\n')
            cosign = fakebin / 'cosign'
            cosign.write_text('#!/bin/sh\nexit "${TEST_SIGNATURE_EXIT:-0}"\n')
            gh.chmod(0o755)
            cosign.chmod(0o755)
            env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ['PATH'])
            for label, signature_exit, candidate, succeeds in [
                ('valid fixture', '0', text, True),
                ('invalid signature', '1', text, False),
                ('candidate differs', '0', text + '# tampered\n', False),
                ('unparseable version', '0', text.replace('1.0.0', '1.0.0-rc1'), False),
            ]:
                with self.subTest(label=label):
                    shutil.rmtree(root / 'verified', ignore_errors=True)
                    formula.write_text(candidate)
                    env['TEST_SIGNATURE_EXIT'] = signature_exit
                    result = subprocess.run(['bash', '-c', check['run']], cwd=root,
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, succeeds, result.stderr)
            shutil.rmtree(root / 'verified', ignore_errors=True)
            formula.write_text(text)
            env.update(TEST_LATEST='v1.0.1', TEST_SIGNATURE_EXIT='0')
            result = subprocess.run(['bash', '-c', check['run']], cwd=root,
                                    env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / 'verified').exists())



    def test_publication_retry_reuses_branch_and_pr_then_noops_after_merge(self):
        step = next(step for step in self.steps if 'gh pr create' in step.get('run', ''))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            remote = root / 'remote.git'
            seed = root / 'seed'
            def git(*args, cwd=root):
                return subprocess.run(['git', *args], cwd=cwd, capture_output=True,
                                      text=True, check=True).stdout.strip()
            git('init', '--bare', '--initial-branch=main', str(remote))
            git('clone', str(remote), str(seed))
            git('config', 'user.name', 'release-test', cwd=seed)
            git('config', 'user.email', 'release-test@example.invalid', cwd=seed)
            (seed / 'README.md').write_text('tap fixture\n')
            git('add', 'README.md', cwd=seed)
            git('commit', '-m', 'bootstrap', cwd=seed)
            git('push', 'origin', 'main', cwd=seed)
            rel = root / 'rel'
            rel.mkdir()
            (rel / 'zunder-guard.rb').write_text('  version "1.0.0"\n# verified fixture\n')
            fakebin = root / 'bin'
            fakebin.mkdir()
            curl = fakebin / 'curl'
            curl.write_text('#!/usr/bin/env python3\nimport json,os\nprint(json.dumps({"tag_name":os.environ.get("TEST_LATEST","v1.0.0"),"draft":False,"prerelease":False}))\n')
            curl.chmod(0o755)
            gh = fakebin / 'gh'
            gh.write_text("#!/usr/bin/env python3\nimport os, pathlib, sys\np=pathlib.Path(os.environ['TEST_PR'])\n"
                          "if sys.argv[1:3] == ['pr', 'list']: print('1' if p.exists() else '0')\n"
                          "elif sys.argv[1:3] == ['pr', 'create']:\n"
                          "    if p.exists(): raise SystemExit('duplicate PR')\n"
                          "    p.write_text('created')\n"
                          "else: raise SystemExit('unexpected gh command')\n")
            install = fakebin / 'install'
            install.write_text("#!/usr/bin/env python3\nimport pathlib, shutil, sys\n"
                               "dst=pathlib.Path(sys.argv[-1]); dst.parent.mkdir(parents=True,exist_ok=True)\n"
                               "shutil.copyfile(sys.argv[-2],dst)\n")
            gh.chmod(0o755)
            install.chmod(0o755)
            env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ['PATH'],
                       TAG=TAG, TEST_PR=str(root / 'pr'))
            def publish():
                shutil.rmtree(root / 'tap', ignore_errors=True)
                git('clone', str(remote), str(root / 'tap'))
                result = subprocess.run(['bash', '-c', step['run']], cwd=root,
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            publish()
            first = git('rev-parse', 'refs/heads/zunder-guard-' + TAG, cwd=remote)
            self.assertTrue((root / 'pr').exists())
            publish()
            self.assertEqual(git('rev-parse', 'refs/heads/zunder-guard-' + TAG, cwd=remote), first)
            git('fetch', 'origin', cwd=seed)
            git('merge', '--ff-only', 'origin/zunder-guard-' + TAG, cwd=seed)
            git('push', 'origin', 'main', cwd=seed)
            git('push', 'origin', '--delete', 'zunder-guard-' + TAG, cwd=seed)
            (root / 'pr').unlink()
            publish()
            self.assertFalse((root / 'pr').exists())
            self.assertEqual(git('show', 'main:Formula/zunder-guard.rb', cwd=remote), 'version "1.0.0"\n# verified fixture')
            # Even if GitHub latest were moved backwards, a newer tap must not downgrade.
            (seed / 'Formula/zunder-guard.rb').write_text('  version "2.0.0"\n')
            git('add', 'Formula/zunder-guard.rb', cwd=seed)
            git('commit', '-m', 'newer release', cwd=seed)
            git('push', 'origin', 'main', cwd=seed)
            shutil.rmtree(root / 'tap')
            git('clone', str(remote), str(root / 'tap'))
            result = subprocess.run(['bash', '-c', step['run']], cwd=root,
                                    env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / 'pr').exists())
            self.assertEqual(git('show', 'main:Formula/zunder-guard.rb', cwd=remote), 'version "2.0.0"')


class FakeCosignBinding(unittest.TestCase):
    def test_file_names_do_not_change_the_content_binding(self):
        helper = SCRIPT.parent.parent / 'test/fake-cosign'
        identity = 'https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/' + TAG
        issuer = 'https://token.actions.githubusercontent.com'
        content = b'checksum fixture\n'
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            bundle = root / 'bundle.json'
            for name in ['SHA256SUMS', 'sums with spaces', r'C:\Users\runneradmin\Temp\SHA256SUMS', 'sums\nwith-newline']:
                with self.subTest(name=name):
                    sums = root / name
                    sums.write_bytes(content)
                    bundle.write_text(json.dumps({'identity': identity, 'sha256': hashlib.sha256(content).hexdigest()}))

                    def verify(claimed_identity=identity, claimed_issuer=issuer):
                        return subprocess.run([str(helper), 'verify-blob', '--bundle', str(bundle),
                            '--certificate-identity', claimed_identity, '--certificate-oidc-issuer', claimed_issuer,
                            str(sums)], capture_output=True, text=True, timeout=10).returncode

                    self.assertEqual(verify(), 0)
                    sums.write_bytes(content + b'tampered')
                    self.assertNotEqual(verify(), 0)
                    sums.write_bytes(content)
                    self.assertNotEqual(verify(identity + '-wrong'), 0)
                    self.assertNotEqual(verify(claimed_issuer=issuer + '-wrong'), 0)


class ImagePublication(unittest.TestCase):
    def test_stale_release_cannot_move_latest(self):
        workflow = yaml.safe_load((SCRIPT.parent / 'workflows/publish.yml').read_text())
        job = workflow['jobs']['latest']
        self.assertEqual(job['needs'], 'verify')
        self.assertEqual(job['concurrency'], {'group': 'guard-image-latest-publication', 'cancel-in-progress': False})
        promote = next(s for s in job['steps'] if 'imagetools create' in s.get('run', ''))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'rel').mkdir()
            (root / f'rel/zunder-guard-{TAG}.image.txt').write_text(REF + '\n')
            fakebin = root / 'bin'; fakebin.mkdir()
            curl = fakebin / 'curl'
            curl.write_text('#!/usr/bin/env python3\nimport json,os\nprint(json.dumps({"tag_name":os.environ["TEST_LATEST"],"draft":False,"prerelease":False}))\n')
            docker = fakebin / 'docker'
            docker.write_text('#!/usr/bin/env python3\nimport json,os,pathlib,sys\npathlib.Path(os.environ["TEST_CALL"]).write_text(json.dumps(sys.argv[1:]))\n')
            curl.chmod(0o755); docker.chmod(0o755)
            env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ['PATH'],
                       TAG=TAG, IMAGE='ghcr.io/zunderlabs/zunder-guard', TEST_CALL=str(root/'call'))
            for latest, succeeds in [('v1.0.1', False), (TAG, True)]:
                env['TEST_LATEST'] = latest
                result = subprocess.run(['bash', '-c', promote['run']], cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                self.assertEqual((root/'call').exists(), succeeds)
            self.assertEqual(json.loads((root/'call').read_text()),
                             ['buildx', 'imagetools', 'create', '-t', 'ghcr.io/zunderlabs/zunder-guard:latest', REF])

class DistributionRecovery(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load((SCRIPT.parent / 'workflows/publish.yml').read_text())
        self.jobs = self.workflow['jobs']
        self.tap = yaml.safe_load((SCRIPT.parent.parent / 'packaging/homebrew/tap-verify.yml').read_text())

    def test_recovery_selects_one_existing_channel_and_fresh_verification(self):
        events = self.workflow.get('on', self.workflow.get(True))
        self.assertEqual(events['workflow_dispatch']['inputs']['channel']['options'],
                         ['homebrew', 'aws-template', 'installers', 'latest'])
        for name in ['homebrew', 'aws-template', 'installers', 'latest']:
            job = self.jobs[name]
            self.assertEqual(job['needs'], 'verify')
            self.assertIn("github.event_name == 'release'", job['if'])
            self.assertIn("inputs.channel == '" + name + "'", job['if'])
            for other in {'homebrew', 'aws-template', 'installers', 'latest'} - {name}:
                self.assertNotIn("inputs.channel == '" + other + "'", job['if'])
            self.assertNotIn('always(', job['if'])
        self.assertEqual(self.jobs['winget']['if'], "github.event_name == 'release' && vars.WINGET == 'enabled'")
        verify = self.jobs['verify']['steps']
        self.assertIn('exact public stable release', verify[0]['name'])
        self.assertTrue(any('bash deploy/guard/github/verify-release.sh "$TAG" rel' in s.get('run', '') for s in verify))
        self.assertFalse(any('download-artifact@' in s.get('uses', '') for s in verify))
        for job in self.jobs.values():
            for step in job.get('steps', []):
                if 'actions/checkout@' in step.get('uses', '') and step.get('with', {}).get('repository') is None:
                    self.assertEqual(step['with']['ref'], '${{ github.sha }}')
        self.assertEqual(self.jobs['aws-template']['environment'], 'aws-template-publish')
        self.assertEqual(self.jobs['installers']['environment'], 'installer-publish')

    def test_source_binding_precedes_execution_and_write_credentials(self):
        verify = self.jobs['verify']['steps']
        check = next(s for s in verify if 'verify-release.sh' in s.get('run', ''))
        self.assertEqual(check['env']['SOURCE_SHA'], '${{ github.sha }}')
        self.assertLess(check['run'].index('git rev-parse HEAD'), check['run'].index('bash deploy/guard'))
        self.assertLess(check['run'].index('bash deploy/guard'), check['run'].index('jq -e'))
        for name in ['homebrew', 'aws-template', 'installers']:
            steps = self.jobs[name]['steps']
            binding = next(s for s in steps if s.get('name') == 'Bind verified release source to immutable checkout')
            self.assertEqual(binding['env']['SOURCE_SHA'], '${{ github.sha }}')
            bind_at = steps.index(binding)
            self.assertTrue(any('download-artifact@' in s.get('uses', '') for s in steps[:bind_at]))
            for index, step in enumerate(steps):
                if ('--channel ' in step.get('run', '') or 'publish-loaders.py' in step.get('run', '') or
                        'create-github-app-token@' in step.get('uses', '') or
                        'configure-aws-credentials@' in step.get('uses', '')):
                    self.assertLess(bind_at, index)

    def test_same_named_branch_cannot_supply_verified_checkout_source(self):
        verify = next(s for s in self.jobs['verify']['steps'] if 'verify-release.sh' in s.get('run', ''))
        binding = next(s for s in self.jobs['aws-template']['steps']
                       if s.get('name') == 'Bind verified release source to immutable checkout')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL, text=True).strip()
            git('init', '-q')
            (root/'README.md').write_text('trusted tag source\n')
            git('add', '.')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'trusted')
            source = git('rev-parse', 'HEAD'); git('tag', TAG)
            git('switch', '-c', TAG)
            (root/'README.md').write_text('same-name branch source\n')
            git('add', '.')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'branch')
            other = git('rev-parse', 'HEAD')
            self.assertNotEqual(source, other)
            self.assertEqual(git('rev-parse', 'refs/tags/' + TAG), source)
            self.assertEqual(git('rev-parse', 'refs/heads/' + TAG), other)
            # Model the pinned checkout's immutable SHA input, not an ambiguous short ref.
            git('checkout', '--detach', source)
            fixture = root/'deploy/guard/github/verify-release.sh'
            fixture.parent.mkdir(parents=True)
            fixture.write_text('#!/bin/sh\nset -eu\nmkdir -p rel\nprintf x > verifier-called\n'
                               'printf \'{"tag":"%s","source":"%s"}\\n\' "$TAG" "$TEST_SOURCE" > rel/.verified-release-source.json\n')
            env = dict(os.environ, SOURCE_SHA=source, TEST_SOURCE=source, TAG=TAG)
            for script in [verify['run'], binding['run']]:
                result = subprocess.run(['bash', '-c', script], cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            # A verifier authenticated a different commit: neither producer nor consumer admits it.
            result = subprocess.run(['bash', '-c', verify['run']], cwd=root,
                                    env=dict(env, TEST_SOURCE=other), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            result = subprocess.run(['bash', '-c', binding['run']], cwd=root, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            # Even a matching-looking marker cannot authorize executing the wrong checkout.
            git('checkout', '--detach', other)
            (root/'verifier-called').unlink()
            for script in [verify['run'], binding['run']]:
                result = subprocess.run(['bash', '-c', script], cwd=root, env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root/'verifier-called').exists())

    def test_dispatch_admission_executes_and_refuses_invalid_release_or_ref(self):
        step = self.jobs['verify']['steps'][0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gh = root / 'gh'
            gh.write_text('#!/usr/bin/env python3\nimport os\nprint(os.environ["RELEASE_JSON"])\n')
            gh.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       TAG=TAG, EVENT='workflow_dispatch', REF_TYPE='tag', CHANNEL='homebrew',
                       GITHUB_REPOSITORY='zunderlabs/zunder-guard')
            base = {'tag_name': TAG, 'draft': False, 'prerelease': False}
            cases = [({}, {}, True), ({'REF_TYPE': 'branch'}, {}, False),
                     ({'CHANNEL': 'winget'}, {}, False), ({'TAG': 'main'}, {}, False),
                     ({}, {'tag_name': 'v9.0.0'}, False), ({}, {'draft': True}, False),
                     ({}, {'prerelease': True}, False), ({}, {'draft': None}, False),
                     ({'EVENT': 'release', 'CHANNEL': ''}, {}, True)]
            for change, release, succeeds in cases:
                with self.subTest(change=change, release=release):
                    result = subprocess.run(['bash', '-c', step['run']], cwd=root,
                        env=dict(env, **change, RELEASE_JSON=json.dumps(dict(base, **release))),
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, succeeds, result.stderr)

    def test_tap_all_prs_keep_four_checks_and_gate_every_install_step(self):
        events = self.tap.get('on', self.tap.get(True))
        self.assertIsNone(events['pull_request'])
        self.assertEqual(events['push'], {'branches': ['main']})
        job = self.tap['jobs']['verified-native-install']
        self.assertEqual(job['strategy']['matrix']['os'],
                         ['macos-15', 'macos-15-intel', 'ubuntu-24.04', 'ubuntu-24.04-arm'])
        steps = job['steps']
        self.assertEqual(steps[0]['with']['fetch-depth'], 0)
        self.assertEqual(steps[1]['id'], 'scope')
        self.assertEqual(steps[1]['env']['BASE_SHA'], '${{ github.event.pull_request.base.sha || github.event.before }}')
        for step in steps[2:]:
            self.assertEqual(step['if'], "steps.scope.outputs.formula == 'true'")
        self.assertIn('no formula installation was tested', steps[1]['run'])

    def test_tap_admission_runs_against_real_git_base_and_head(self):
        script = self.tap['jobs']['verified-native-install']['steps'][1]['run']
        cases = [('bootstrap docs', False, 'absent', True, False),
                 ('formula first PR', False, 'file', True, True),
                 ('formula docs PR', True, 'file', True, True),
                 ('formula deletion', True, 'absent', False, False),
                 ('formula directory', False, 'directory', False, False),
                 ('formula symlink', False, 'symlink', False, False),
                 ('missing base commit', False, 'missing-base', False, False),
                 ('first push', False, 'zero-base', True, False),
                 ('invalid base', False, 'invalid-base', False, False)]
        for label, had_formula, head, succeeds, tested in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                def git(*args):
                    return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL, text=True).strip()
                git('init', '-q')
                (root/'README.md').write_text('fixture\n')
                (root/'Formula').mkdir()
                formula = root/'Formula/zunder-guard.rb'
                if had_formula: formula.write_text('base formula\n')
                git('add', '.')
                git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    'commit', '-qm', 'fixture')
                base = git('rev-parse', 'HEAD')
                if formula.exists(): formula.unlink()
                if head == 'file': formula.write_text('candidate formula\n')
                if head == 'directory': formula.mkdir()
                if head == 'symlink': formula.symlink_to('../README.md')
                if head == 'missing-base': base = 'f' * 40
                if head == 'zero-base': base = '0' * 40
                if head == 'invalid-base': base = 'main'
                output, summary = root/'output', root/'summary'
                result = subprocess.run(['bash', '-c', script], cwd=root,
                    env=dict(os.environ, BASE_SHA=base, GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary)),
                    capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, succeeds, result.stderr)
                if succeeds:
                    self.assertEqual(output.read_text(), 'formula=' + str(tested).lower() + '\n')
                    self.assertEqual(summary.exists(), not tested)
                else:
                    self.assertFalse(output.exists())

    def test_manual_recovery_requires_channel_gate_before_formula_copy(self):
        source = (SCRIPT.parent.parent / 'packaging/homebrew/README.md').read_text()
        manual = source.split('The initial/recovery manual path', 1)[1]
        self.assertLess(manual.index('verify-release.sh'), manual.index('--channel homebrew'))
        self.assertLess(manual.index('--channel homebrew'), manual.index('Copy only the verified'))



if __name__ == '__main__':
    unittest.main()
