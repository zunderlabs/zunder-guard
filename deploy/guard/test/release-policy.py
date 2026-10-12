#!/usr/bin/env python3
"""Publication gate regressions. Fake GitHub/cosign; real process and checksum checks.

This proves fail-closed wiring, not real OIDC, signatures, native builds or provenance.
Run: python3 deploy/guard/test/release-policy.py
"""
import hashlib
import json
import os
import shutil
import runpy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from distribution import InstallerNotices, ReleaseRendering

SCRIPT = Path(__file__).resolve().parents[1] / 'github/verify-release-assets.sh'
WORKFLOWS = SCRIPT.parent / "workflows"
if not WORKFLOWS.is_dir():
    WORKFLOWS = Path(__file__).resolve().parents[3] / ".github/workflows"
TAG = 'v1.0.0'
SHA = 'a' * 40
REF = 'ghcr.io/zunderlabs/zunder-guard@sha256:' + 'b' * 64
SERVICE_ASSETS = ['install-windows-service.ps1', 'install-macos-service.sh', 'uninstall-macos-testnet.py', 'install-container.py', 'container-supervisor.py',
                  'container-operations.py', 'zunder-guard-container.service',
                  'zunder-guard-setup-guardian.service']


class WorkflowQueue(unittest.TestCase):
    def test_shared_queue_keeps_every_pending_job_without_interrupting_protection(self):
        validate = runpy.run_path(str(SCRIPT.parent.parent / "test/workflow-concurrency.py"))["validate"]
        validate(list(WORKFLOWS.glob("*.yml")))
        for patch_value in ({"queue": "single"}, {"queue": "invalid"}, {"cancel-in-progress": True}):
            with tempfile.TemporaryDirectory() as directory:
                paths = []
                for source in WORKFLOWS.glob("*.yml"):
                    document = yaml.safe_load(source.read_text())
                    if source.name == "verify.yml":
                        document["concurrency"].update(patch_value)
                    target = Path(directory) / source.name
                    target.write_text(yaml.safe_dump(document))
                    paths.append(target)
                with self.assertRaises(ValueError):
                    validate(paths)

    def test_run_owner_covers_exact_custody_and_successful_trader_order(self):
        validate = runpy.run_path(str(SCRIPT.parent.parent / "test/workflow-concurrency.py"))["validate"]
        for mutation in ("owner", "inner-lock", "early-reader", "early-T2", "extra-trader", "missing-custody"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                paths = []
                for source in WORKFLOWS.glob("*.yml"):
                    document = yaml.safe_load(source.read_text())
                    if source.name == "verify.yml":
                        if mutation == "owner":
                            del document["concurrency"]
                        elif mutation == "early-reader":
                            document["jobs"]["install-matrix"]["needs"] = "staging"
                    if source.name == "install-matrix.yml":
                        if mutation == "inner-lock":
                            document["jobs"]["native"]["concurrency"] = {
                                "group": "guard-e2e-testnet", "queue": "max", "cancel-in-progress": False,
                            }
                        elif mutation == "missing-custody":
                            for step in document["jobs"]["native"]["steps"]:
                                for key, value in list(step.get("env", {}).items()):
                                    if "secrets.E2E_TESTNET_" in str(value):
                                        step["env"][key] = "unit-no-custody"
                    if source.name == "journey.yml":
                        if mutation == "early-T2":
                            document["jobs"]["testnet-systemd"]["needs"] = "purchase"
                        elif mutation == "extra-trader":
                            document["jobs"]["extra-trader"] = {"runs-on": "ubuntu-24.04", "steps": []}
                    target = Path(directory) / source.name
                    target.write_text(yaml.safe_dump(document))
                    paths.append(target)
                with self.assertRaises(ValueError):
                    validate(paths)


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
                try:
                    path.unlink()
                    self.checksums()
                    result = self.run_gate()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(asset + ' is missing or repeated', result.stderr)
                finally:
                    shutil.rmtree(self.root / 'download', ignore_errors=True)
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
        workflow = (WORKFLOWS / 'ci.yml').read_text()
        self.assertLess(workflow.index('>"rel/$v/zunder-guard-$v.image.txt"'),
                        workflow.index('deploy/guard/packaging/render.sh "$v"'))

    def test_unavailable_verifier_refuses(self):
        (self.root / 'bin/slsa-verifier').write_text('#!/bin/sh\nexit 127\n')
        self.assertNotEqual(self.run_gate().returncode, 0)


class HomebrewPublication(unittest.TestCase):
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



class DistributionRecovery(unittest.TestCase):
    def setUp(self):
        self.tap = yaml.safe_load((SCRIPT.parent.parent / "packaging/homebrew/tap-verify.yml").read_text())

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


if __name__ == '__main__':
    unittest.main()
